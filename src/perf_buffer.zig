usingnamespace std.os.linux;
usingnamespace @import("user.zig");
usingnamespace @import("common.zig");

const std = @import("std");
const perf = @import("perf.zig");

const mem = std.mem;
const Channel = std.event.Channel;

allocator: *mem.Allocator,
fd: fd_t,
contexts: std.ArrayListUnmanaged(Context),
channel: Channel(Payload),
channel_buf: [256]Payload,
running: std.atomic.Bool,

const Self = @This();

const Tag = enum {
    sample,
    lost,
};

pub const Event = union(Tag) {
    sample: std.ArrayList(u8),
    lost: usize,
};

pub const Payload = struct {
    cpu: u32,
    event: Event,
};

const Context = struct {
    cpubuf: CpuBuf,
    frame: @Frame(CpuBuf.process),
};

const RingBuffer = struct {
    mmap: []align(4096) u8,

    pub fn init(fd: fd_t, mmap_size: usize) !RingBuffer {
        return RingBuffer{
            .mmap = try std.os.mmap(
                null,
                mmap_size + mem.page_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd,
                0,
            ),
        };
    }

    pub fn deinit(self: RingBuffer) void {
        std.os.munmap(self.mmap);
    }

    pub fn read_event(self: RingBuffer, allocator: *mem.Allocator) !?Event {
        const header = @as(*volatile perf.MmapPage, @ptrCast(self.mmap.ptr));
        const head = header.data_head;
        const tail = header.data_tail;

        if (head == tail) return null;

        const size = self.mmap.len - mem.page_size;
        const start = tail % size;
        const ehdr = @as(*perf.EventHeader, @ptrCast(@alignCast(@alignOf(*perf.EventHeader), &self.mmap[mem.page_size + start])));
        defer header.data_tail += ehdr.size;

        return switch (ehdr.type) {
            perf.RECORD_SAMPLE => blk: {
                const offset = mem.page_size + ((start + @byteOffsetOf(perf.SampleRaw, "size")) % size);
                const sample_size = @as(*const u32, @ptrCast(@alignCast(@alignOf(*const u32), &self.mmap[offset]))).*;
                const sample_start = mem.page_size + ((start + @sizeOf(perf.SampleRaw)) % size);

                var sample = try std.ArrayList(u8).initCapacity(allocator, sample_size);
                if (sample_start + sample_size > self.mmap.len) {
                    const first_len = self.mmap.len - sample_start;
                    const second_len = sample_size - first_len;
                    sample.appendSliceAssumeCapacity(self.mmap[sample_start..]);
                    sample.appendSliceAssumeCapacity(self.mmap[mem.page_size .. mem.page_size + second_len]);
                } else {
                    sample.appendSliceAssumeCapacity(self.mmap[sample_start .. sample_start + sample_size]);
                }

                break :blk .{ .sample = sample };
            },
            perf.RECORD_LOST => blk: {
                const offset = mem.page_size + ((start + @byteOffsetOf(perf.SampleLost, "lost")) % size);
                break :blk .{ .lost = @as(*const u64, @ptrCast(@alignCast(@alignOf(*const u64), &self.mmap[offset]))).* };
            },
            else => error.UnknownEvent,
        };
    }
};

const CpuBuf = struct {
    cpu: u32,
    fd: fd_t,
    ring_buffer: RingBuffer,

    pub fn init(cpu: u32, mmap_size: usize) !CpuBuf {
        var attr: perf.EventAttr = undefined;
        mem.set(u8, mem.asBytes(&attr), 0);

        attr.config = perf.COUNT_SW_BPF_OUTPUT;
        attr.type = perf.TYPE_SOFTWARE;
        attr.sample_type = perf.SAMPLE_RAW;
        attr.sample.period = 1;
        attr.wakeup.events = 1;
        attr.size = @sizeOf(perf.EventAttr);

        const rc = std.os.linux.syscall5(
            .perf_event_open,
            @intFromPtr(&attr),
            @as(usize, @bitCast(@as(isize, -1))),
            @as(usize, @intCast(cpu)),
            @as(usize, @bitCast(@as(isize, -1))),
            perf.FLAG_FD_CLOEXEC,
        );
        const fd = try switch (std.os.linux.getErrno(rc)) {
            0 => @as(fd_t, @intCast(rc)),
            else => |err| std.os.unexpectedErrno(err),
        };
        errdefer std.os.close(fd);

        const ring_buffer = try RingBuffer.init(fd, mmap_size);
        errdefer ring_buffer.deinit();

        const status = ioctl(fd, perf.EVENT_IOC_ENABLE, 0);
        if (status != 0) return error.GoFixIoctlHandling;

        return CpuBuf{
            .cpu = cpu,
            .fd = fd,
            .ring_buffer = ring_buffer,
        };
    }

    pub fn read(self: CpuBuf, allocator: *mem.Allocator) !?Payload {
        return Payload{
            .cpu = self.cpu,
            .event = ((try self.ring_buffer.read_event(allocator)) orelse return null),
        };
    }

    pub fn process(
        self: CpuBuf,
        allocator: *mem.Allocator,
        running: *std.atomic.Bool,
        channel: *Channel(Payload),
    ) callconv(.Async) void {
        while (running.load(.SeqCst)) {
            std.event.Loop.instance.?.waitUntilFdReadable(self.fd);

            // TODO: might need to panic here instead of returning null
            while (self.read(allocator) catch null) |payload| {
                channel.put(payload);
            }
        }
    }

    pub fn deinit(self: CpuBuf) void {
        self.ring_buffer.deinit();
        const status = ioctl(self.fd, perf.EVENT_IOC_DISABLE, 0);
        if (status != 0) unreachable;
        std.os.close(self.fd);
    }
};

pub fn init(allocator: *mem.Allocator, map: PerfEventArray, page_cnt: usize) !Self {
    // page count must be power of two
    if (@popCount(usize, page_cnt) != 1) {
        return error.PageCountSize;
    }

    const cpu_count = std.math.min(map.map.def.max_entries, try std.Thread.cpuCount());

    var ret: Self = undefined;
    ret.allocator = allocator;
    ret.channel.init(&ret.channel_buf);
    ret.running = std.atomic.Bool.init(false);
    errdefer ret.channel.deinit();

    ret.contexts = try std.ArrayListUnmanaged(Context).initCapacity(allocator, cpu_count);
    errdefer for (ret.contexts.items) |ctx| ctx.cpubuf.deinit();

    var i: u32 = 0;
    while (i < cpu_count) : (i += 1) {
        ret.contexts.appendAssumeCapacity(.{
            .cpubuf = try CpuBuf.init(i, mem.page_size * page_cnt),
            .frame = undefined,
        });
        try map_update_elem(map.map.fd, mem.asBytes(&i), mem.asBytes(&ret.contexts.items[i].cpubuf.fd), 0);
    }

    return ret;
}

pub fn stop(self: *Self) void {
    self.running.set(false);
}

pub fn deinit(self: *Self) void {
    self.channel.deinit();
    for (self.contexts.items) |ctx| ctx.cpubuf.deinit();

    self.contexts.deinit(self.allocator);
    self.channel.deinit();
}

/// The PerfBuffer emits the Payload type which either reports a "raw
/// sample" (regular data from BPF program) or "lost sample" -- a report of
/// how many events were overwritten. In the case of the raw sample, the
/// data is allocated and ownership is transfered with this call, so it is the
/// responsibility of the caller to clean it up
pub fn get(self: *Self) Payload {
    return self.channel.get();
}

pub fn run(self: *Self) callconv(.Async) void {
    self.running.store(true, .SeqCst);
    for (self.contexts.items) |*ctx| {
        ctx.frame = async ctx.cpubuf.process(self.allocator, &self.running, &self.channel);
    }
}

test "perf buffer" {
    if (!std.io.is_async) return error.SkipZigTest;

    const perf_event_array = try PerfEventArray.init(MapInfo{
        .name = "",
        .fd = null,
        .def = @import("kern.zig").MapDef{
            .type = @intFromEnum(MapType.perf_event_array),
            .key_size = @sizeOf(u32),
            .value_size = @sizeOf(u32),
            .max_entries = 64,
            .map_flags = 0,
        },
    });

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var perf_buffer = try Self.init(&gpa.allocator, perf_event_array, 64);
    defer perf_buffer.deinit();
}
