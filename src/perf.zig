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

test "Event.Attr size" {
    expect(@bitSizeOf(Event.Attr) % 8 == 0);
}
