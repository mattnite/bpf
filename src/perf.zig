usingnamespace @import("ioctl.zig");
const std = @import("std");
const expect = std.testing.expect;

const fd_t = std.os.fd_t;
const pid_t = std.os.pid_t;

pub const Event = struct {
    pub const Attr = packed struct {
        type: u32,
        size: u32,
        config: u64,
        sample: packed union { period: u64, frequency: u64 },
        sample_type: u64,
        read_format: u64,

        disabled: u1,
        inherit: u1,
        pinned: u1,
        exlusive: u1,
        exlude_user: u1,
        exclude_kernel: u1,
        exclude_hv: u1,
        exclude_idle: u1,
        mmap: u1,
        comm: u1,
        freq: u1,
        inherit_stat: u1,
        enable_on_exec: u1,
        task: u1,
        watermark: u1,
        precise_ip: u2,
        mmap_data: u1,
        sample_id_all: u1,
        exclude_host: u1,
        exclude_guest: u1,
        exclude_callchain_kernel: u1,
        exclude_callchain_user: u1,
        mmap2: u1,
        comm_exec: u1,
        use_clockid: u1,
        context_switch: u1,
        _reserved_1: u37,

        wakeup: packed union { events: u32, watermark: u32 },
        bp_type: u32,

        unnamed_1: packed union {
            bp_addr: u64,
            kprobe_func: u64,
            uprobe_path: u64,
            config1: u64,
        },

        unnamed_2: packed union {
            bp_len: u64,
            kprobe_addr: u64,
            probe_offset: u64,
            config2: u64,
        },

        branch_sample_type: u64,
        sample_regs_user: u64,
        sample_stack_user: u64,

        clockid: i32,
        sample_regs_intr: u64,
        aux_watermark: u32,
        sample_max_stack: u16,
        _reserved_2: u16,
    };
};

pub fn event_open(attr: *Event.Attr, pid: pid_t, cpu: i32, group_fd: i32, flags: PerfFlags) !fd_t {
    const rc = std.os.linux.syscall5(.perf_event_open, attr, pid, cpu, group_fd, flags);
    switch (rc) {
        0 => return @intCast(fd_t, rc),
        else => return std.os.unexpectedErrno(rc),
    }
}

const enable = io('$', 0);
const disable = io('$', 1);
const set_bpf = iow('$', 8, fd_t);

pub fn event_disable(fd: fd_t) !void {
    return try ioctl(fd, disable, null);
}

pub fn event_set_bpf(fd: fd_t, prog_fd: fd_t) !void {
    return try ioctl(fd, set_bpf, prog_fd);
}

pub fn event_enable(fd: fd_t) !void {
    return try ioctl(fd, enable, null);
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

pub fn event_open_tracepoint(category: []const u8, name: []const u8) !fd_t {
    const id = try determine_tracepoint_id(category, name);

    const attr = Event.Attr{
        .type = c.PERF_TYPE_TRACEPOINT,
        .size = @sizeOf(Event.Attr),
        .config = id,
    };

    return event_open(&attr, -1, 0, -1, c.PERF_FLAG_FD_CLOEXEC);
}

test "Event.Attr size" {
    expect(@bitSizeOf(Event.Attr) % 8 == 0);
}
