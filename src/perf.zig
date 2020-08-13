usingnamespace @import("ioctl.zig");
const std = @import("std");
const bpf = @import("user.zig");
const os = std.os;
const expect = std.testing.expect;

const fd_t = std.os.fd_t;
const pid_t = std.os.pid_t;
const Allocator = std.mem.Allocator;

// TODO: implement fully
const SwId = extern enum(u64) {
    count_sw_cpu_clock = 0,
    count_sw_bpf_output = 10,
};

const Flag = extern enum(u32) {
    fd_no_group = 1 << 0,
    fd_output = 1 << 1,
    pid_cgroup = 1 << 2,
    fd_cloexec = 1 << 3,
};

const TypeId = extern enum(u32) {
    hardware = 0,
    software = 1,
};

pub const event = struct {
    const SampleFormat = extern enum(u64) {
        invalid = 0,
        raw = 1 << 10,
    };

    pub const Attr = extern struct {
        type: TypeId = .hardware,
        size: u32 = 0,
        config: SwId = .count_sw_cpu_clock,
        sample: extern union { period: u64, frequency: u64 } = .{ .period = 0 },
        sample_type: SampleFormat = .invalid,
        read_format: u64 = 0,

        flags: u64 = 0,
        //disabled: u1 = 0,
        //inherit: u1 = 0,
        //pinned: u1 = 0,
        //exlusive: u1 = 0,
        //exlude_user: u1 = 0,
        //exclude_kernel: u1 = 0,
        //exclude_hv: u1 = 0,
        //exclude_idle: u1 = 0,
        //mmap: u1 = 0,
        //comm: u1 = 0,
        //freq: u1 = 0,
        //inherit_stat: u1 = 0,
        //enable_on_exec: u1 = 0,
        //task: u1 = 0,
        //watermark: u1 = 0,
        //precise_ip: u2 = 0,
        //mmap_data: u1 = 0,
        //sample_id_all: u1 = 0,
        //exclude_host: u1 = 0,
        //exclude_guest: u1 = 0,
        //exclude_callchain_kernel: u1 = 0,
        //exclude_callchain_user: u1 = 0,
        //mmap2: u1 = 0,
        //comm_exec: u1 = 0,
        //use_clockid: u1 = 0,
        //context_switch: u1 = 0,
        //_reserved_1: u37 = 0,

        wakeup: extern union { events: u32, watermark: u32 } = .{ .events = 0 },
        bp_type: u32 = 0,

        unnamed_1: extern union {
            bp_addr: u64,
            kprobe_func: u64,
            uprobe_path: u64,
            config1: u64,
        } = .{ .bp_addr = 0 },

        unnamed_2: extern union {
            bp_len: u64,
            kprobe_addr: u64,
            probe_offset: u64,
            config2: u64,
        } = .{ .bp_len = 0 },

        branch_sample_type: u64 = 0,
        sample_regs_user: u64 = 0,
        sample_stack_user: u64 = 0,

        clockid: i32 = 0,
        sample_regs_intr: u64 = 0,
        aux_watermark: u32 = 0,
        sample_max_stack: u16 = 0,
        _reserved_2: u16 = 0,
    };

    pub const MmapPage = packed struct {
        version: u32,
        compat_version: u32,
        lock: u32,
        index: u32,
        offset: i64,
        time_enabled: u64,
        time_running: u64,
        capabilities: u64,
        pmc_width: u16,
        time_shift: u16,
        time_mult: u32,
        time_offset: u64,
        time_zero: u64,
        size: u32,
        __reserved: [118 * 8 * 4]u8,

        data_head: u64,
        data_tail: u64,
        data_offset: u64,
        data_size: u64,

        aux_head: u64,
        aux_tail: u64,
        aux_offset: u64,
        aux_size: u64,
    };

    pub const Header = packed struct {
        type: Type,
        misc: u16,
        size: u16,

        const Type = packed enum(u32) {
            lost = 2,
            sample = 9,
        };
    };

    pub fn open(attr: *const Attr, pid: pid_t, cpu: i32, group_fd: i32) !fd_t {
        const rc = std.os.linux.syscall5(
            .perf_event_open,
            @ptrToInt(attr),
            if (pid == -1) std.math.maxInt(usize) else @intCast(usize, pid),
            @intCast(usize, cpu),
            if (group_fd == -1) std.math.maxInt(usize) else @intCast(usize, group_fd),
            @enumToInt(Flag.fd_cloexec),
        );
        switch (rc) {
            0 => return @intCast(fd_t, rc),
            else => return std.os.unexpectedErrno(rc),
        }
    }
};

pub const RawSample = packed struct {
    header: event.Header,
    size: u32,
};

pub const LostSample = packed struct {
    header: event.Header,
    id: u64,
    lost: u64,
    sample_id: u64,
};

pub const Buffer = struct {
    allocator: *Allocator,
    event: ?EventFn,
    sample: ?SampleFn,
    lost: ?LostFn,
    ctx: usize,

    mmap_size: usize,
    cpu_bufs: []CpuBuf,
    events: []std.os.linux.epoll_event,
    epoll: fd_t,
    map: fd_t,

    const Self = @This();

    pub fn init(
        allocator: *Allocator,
        map: fd_t,
        page_cnt: usize,
        event_cb: ?EventFn,
        sample_cb: ?SampleFn,
        lost_cb: ?LostFn,
        ctx: usize,
    ) !*Buffer {
        const cpus_cnt = try std.Thread.cpuCount();
        const epoll = try std.os.epoll_create1(std.c.EPOLL_CLOEXEC);

        var ret = try allocator.create(Buffer);
        errdefer allocator.destroy(ret);

        var cpu_bufs = try allocator.alloc(CpuBuf, cpus_cnt);
        errdefer allocator.free(cpu_bufs);

        var events = try allocator.alloc(std.os.linux.epoll_event, cpus_cnt);
        errdefer allocator.free(events);

        var i: usize = 0;
        while (i < cpus_cnt) : (i += 1) {
            cpu_bufs[i] = try CpuBuf.init(
                std.heap.page_allocator,
                ret,
                @intCast(i32, i),
            );
            errdefer cpu_bufs[i].deinit();

            try bpf.map_update_elem(
                map,
                std.mem.asBytes(&cpu_bufs[i].cpu),
                std.mem.asBytes(&cpu_bufs[i].fd),
                0,
            );
            events[i] = std.os.linux.epoll_event{
                .events = std.os.EPOLLIN,
                .data = .{
                    .ptr = @ptrToInt(&cpu_bufs[i]),
                },
            };

            try std.os.epoll_ctl(epoll, std.c.EPOLL_CTL_ADD, cpu_bufs[i].fd, &events[i]);
        }

        ret.* = .{
            .allocator = allocator,
            .event = event_cb,
            .sample = sample_cb,
            .lost = lost_cb,
            .ctx = ctx,
            .mmap_size = std.mem.page_size * page_cnt,
            .map = map,
            .epoll = epoll,
            .cpu_bufs = cpu_bufs,
            .events = events,
        };

        return ret;
    }

    pub fn deinit(self: *Self) void {
        // TODO: what to do with map?
        for (self.cpu_bufs) |*cpu_buf| {
            cpu_buf.deinit();
        }

        self.allocator.free(self.cpu_bufs);
        self.allocator.free(self.events);
        os.close(self.epoll);
        self.allocator.destroy(self);
    }

    fn process_record(header: *Header, ctx: usize) anyerror!bool {
        const cpu_buf = @intToPtr(*CpuBuf, ctx);
        const pb = cpu_buf.pb;

        if (pb.event_cb) |cb| return cb(pb.ctx, cpu_buf.cpu, header);

        switch (header.type) {
            .sample => {
                const s = @ptrCast(*RawSample, header);
                if (pb.sample_cb) |cb| cb(pb.ctx, cpu_buf.cpu, s.data, s.size);
            },
            .lost => {
                const s = @ptrCast(*LostSample, header);
                if (pb.sample_cb) |cb| cb(pb.ctx, cpu_buf.cpu, s.data, s.size);
            },
            else => return error.InvalidType,
        }

        return .cont;
    }

    fn process_records(self: *Self, cpu_buf: *CpuBuf) !bool {
        return event_read_simple(
            cpu_buf.base,
            self.mmap_size,
            cpu_buf.buf,
            cpu_buf.buf_size,
            process_record,
            @ptrToInt(cpu_buf),
        );
    }

    pub fn poll(self: *Self, timeout_ms: i32) !void {
        const cnt = try os.epoll_wait(self.epoll, self.events, timeout_ms);

        var i: usize = 0;
        while (i < cnt) : (i += 1) {
            const cpu_buf = @intToPtr(*CpuBuf, self.events[i].data.ptr);
            try process_records(self, cpu_buf);
        }
    }

    pub const EventFn = fn (ctx: usize, cpu: i32, header: *event.Header) anyerror!bool;
    pub const SampleFn = fn (ctx: usize, cpu: i32, data: []u8) void;
    pub const LostFn = fn (ctx: usize, cpu: i32, cnt: u64) void;
};

pub const CpuBuf = struct {
    allocator: *Allocator,
    fd: fd_t,
    pb: *Buffer,
    base: []align(4096) u8, // mmaped memory
    buf: ?[]u8, // TODO: figure out, for reconstructing segmented data
    cpu: i32,

    const Self = @This();

    pub fn init(allocator: *Allocator, pb: *Buffer, cpu: i32) !CpuBuf {
        const attr = event.Attr{
            .config = .count_sw_bpf_output,
            .type = .software,
            .sample_type = .raw,
            .sample = .{ .period = 1 },
            .wakeup = .{ .events = 1 },
        };

        const fd = try event.open(&attr, -1, cpu, -1);
        errdefer os.close(fd);

        try event_enable(fd);
        return CpuBuf{
            .allocator = allocator,
            .fd = fd,
            .pb = pb,
            .base = try os.mmap(
                null,
                pb.mmap_size + std.mem.page_size,
                std.c.PROT_READ | std.c.PROT_WRITE,
                std.c.MAP_SHARED,
                fd,
                0,
            ),
            .buf = null,
            .cpu = cpu,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.buf) |b| {
            self.allocator.free(b);
        }

        os.munmap(self.base);
        event_disable(self.fd) catch {};
        os.close(self.fd);
    }
};

const enable = io('$', 0);
const disable = io('$', 1);
const set_bpf = iow('$', 8, fd_t);

pub fn event_disable(fd: fd_t) !void {
    return ioctl(fd, disable, @intCast(u32, 0));
}

pub fn event_set_bpf(fd: fd_t, prog_fd: fd_t) !void {
    return ioctl(fd, set_bpf, prog_fd);
}

pub fn event_enable(fd: fd_t) !void {
    return ioctl(fd, enable, @intCast(u32, 0));
}

fn determine_kprobe_perf_type() !u32 {
    return parse_uint_from_file("/sys/bus/event_source/devices/kprobe/type", "{}\n");
}

fn determine_uprobe_perf_type() !u32 {
    return parse_uint_from_file("/sys/bus/event_source/devices/uprobe/type", "{}\n");
}

fn determine_kprobe_retprobe_bit() !u32 {
    return parse_uint_from_file("/sys/bus/event_source/devices/kprobe/format/retprobe", "config:{}\n");
}

fn determine_uprobe_retprobe_bit() !u32 {
    return parse_uint_from_file("/sys/bus/event_source/devices/uprobe/format/retprobe", "config:{}\n");
}

pub fn event_open_probe(
    uprobe: bool,
    retprobe: bool,
    name: []const u8,
    offset: u64,
    pid: pid_t,
) !fd_t {
    const type = if (uprobe)
        try determine_uprobe_perf_type()
    else
        try determine_kprobe_perf_type();

    if (retprobe) {
        const bit = if (uprobe)
            try determine_uprobe_retprobe_bit()
        else
            try determine_kprobe_retprobe_bit();
    }

    const attr = Event.Attr{
        .size = @sizeOf(Event.Attr),
        .type = type,
        // TODO: ensure null terminated
        .config1 = @ptrToInt(u64, name.ptr),
        .config2 = offset,
    };

    return event_open(
        &attr,
        if (pid < 0) -1 else pid,
        if (pid == -1) 0 else -1,
        -1,
        c.PERF_FLAG_FD_CLOEXEC,
    );
}

fn determine_tracepoint_id(category: []const u8, name: []const u8) !void {
    var buf: [PATH_MAX]u8 = undefined;

    try std.fmt.bufPrint(&buf, "/sys/kernel/debug/tracing/events/{}/{}/id", .{
        category, name,
    });

    const file = std.fs.File{
        .handle = try std.os.open(buf, 0, 0),
    };
    defer file.close();

    // read line from file
}

pub fn event_open_tracepoint(category: []const u8, name: []const u8) !fd_t {
    const id = try determine_tracepoint_id(category, name);

    const attr = Event.Attr{
        .type = c.PERF_TYPE_TRACEPOINT,
        .size = @sizeOf(Event.Attr),
        .config = id,
    };

    return event_open(&attr, -1, 0, -1, c.PERF_FLAG_FD_CLOEXEC);
}

// TODO: return null when there are no more events in the ring buffer
pub fn event_read_simple(
    allocator: *Allocator,
    mmap_mem: []u8,
    callback: fn (*Event.Header, usize) !bool,
    private_data: usize,
) !?[]u8 {
    // making header a volatile pointer might be what we need
    const header = @ptrCast(*volatile Event.MmapPage, mmap_mem.ptr);
    const data_head = header.data_head;
    const data_tail = header.data_tail;
    const base = @ptrCast(*u8, header) + std.mem.page_size;
    var ret = false;
    var ehdr: *Event.Header = undefined;
    var ehdr_size: usize = undefined;

    while (data_head != data_tail) {
        ehdr = base + (data_tail & (mmap_size - 1));
        ehdr_size = ehdr.size;

        if (ehdr + ehdr_size > base + mmap_size) {}

        ret = cb(header, data_tail);
        data_tail += ehdr_size;
    }

    header.data_tail = data_tail;
    return ret;
}

test "Event.Attr size" {
    expect(@bitSizeOf(Event.Attr) % 8 == 0);
}
