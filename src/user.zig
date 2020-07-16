usingnamespace @import("common.zig");
usingnamespace std.os;
const builtin = @import("builtin");
const std = @import("std");
const syscall3 = std.os.linux.syscall3;
const expectEqual = std.testing.expectEqual;
const expect = std.testing.expect;

pub const Cmd = enum(i32) {
    map_create,
    map_lookup_elem,
    map_update_elem,
    map_delete_elem,
    map_get_next_key,
    prog_load,
    obj_pin,
    obj_get,
    prog_attach,
    prog_detach,
    prog_test_run,
    prog_get_next_id,
    map_get_next_id,
    prog_get_fd_by_id,
    map_get_fd_by_id,
    obj_get_info_by_fd,
    prog_query,
    raw_tracepoint_open,
    btf_load,
    btf_get_fd_by_id,
    task_fd_query,
    map_lookup_and_delete_elem,
    map_freeze,
    btf_get_next_id,
    map_lookup_batch,
    map_lookup_and_delete_batch,
    map_update_batch,
    map_delete_batch,
};

pub const ProgType = enum(u32) {
    unspec,
    socket_filter,
    kprobe,
    sched_cls,
    sched_act,
    tracepoint,
    xdp,
    perf_event,
    cgroup_skb,
    cgroup_sock,
    lwt_in,
    lwt_out,
    lwt_xmit,
    sock_ops,
    sk_skb,
    cgroup_device,
    sk_msg,
    raw_tracepoint,
    cgroup_sock_addr,
    lwt_seg6local,
    lirc_mode2,
    sk_reuseport,
    flow_dissector,
    cgroup_sysctl,
    raw_tracepoint_writable,
    cgroup_sockopt,
    tracing,
    struct_ops,
    ext,
};

pub const AttachType = enum(u32) {
    CGroupInetIngress,
    CGroupInetEgress,
    CGroupInetSockCreate,
    CGroupSockOps,
    SkSkbStreamParser,
    SkSkbStreamVerdict,
    CGroupDevice,
    SkMsgVerdict,
    CGroupInet4Bind,
    CGroupInet6Bind,
    CGroupInet4Connect,
    CGroupInet6Connect,
    CGroupInet4PostBind,
    CGroupInet6PostBind,
    CGroupUdp4SendMsg,
    CGroupUdp6SendMsg,
    LircMode2,
    FlowDissector,
    CGroupSysctl,
    CGroupUdp4RecvMsg,
    CGroupUdp6RecvMsg,
    CGroupGetSockOpt,
    CGroupSetSockOpt,
    RawTp,
    FEntry,
    FExit,
    ModifyReturn,
    LsmMac,
    TraceIter,
    CGroupInet4GetPeerName,
    CGroupInet6GetPeerName,
    CGroupInet4GetSockName,
    CGroupInet6GetSockName,
    XdpDevMap,
    CGroupInetSockRelease,
};

const tag_size = 8;

const ObjFlags = enum(u32) {
    ReadWrite = 0, ReadOnly = c.BPF_F_RDONLY, WriteOnly = c.BPF_F_WRONLY, ZeroSeed
};

const ProgInfo = extern struct {
    prog_type: u32,
    id: u32,
    tag: [tag_size]u8,
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [obj_name_len]u8,
    ifindex: u32,
    gpl_compatible: u32,
    netns_dev: u64,
    netns_ino: u64,
    nr_jited_ksyms: u32,
    nr_jited_func_lens: u32,
    jited_ksyms: u64,
    jited_func_lens: u64,
    btf_id: u32,
    func_info_rec_size: u32,
    func_info: u64,
    nr_func_info: u32,
    nr_line_info: u32,
    line_info: u64,
    jited_line_info: u64,
    nr_jited_line_info: u32,
    line_info_rec_size: u32,
    nr_prog_tags: u32,
    prog_tags: u64,
    run_time_ns: u64,
    run_cnt: u64,
};

const obj_name_len = 16;

pub const MapCreateAttr = extern struct {
    map_type: u32 = 0,
    key_size: u32 = 0,
    value_size: u32 = 0,
    max_entries: u32 = 0,
    map_flags: u32 = 0,
    inner_map_fd: u32 = 0,
    numa_node: u32 = 0,
    map_name: [obj_name_len]u8 = [_]u8{0} ** obj_name_len,
    map_ifindex: u32 = 0,
    btf_fd: u32 = 0,
    btf_key_type_id: u32 = 0,
    bpf_value_type_id: u32 = 0,
};

pub const MapElemAttr = extern struct {
    map_fd: u32 = 0,
    key: u32 = 0,
    result: extern union {
        value: u64,
        next_key: u64,
    },
    flags: u64 = 0,
};

pub const ProgLoadAttr = extern struct {
    prog_type: u32 = 0,
    insn_cnt: u32 = 0,
    insns: u64 = 0,
    license: u64 = 0,
    log_level: u32 = 0,
    log_size: u32 = 0,
    log_buf: u64 = 0,
    kern_version: u32 = 0,
    prog_flags: u32 = 0,
    prog_name: [obj_name_len]u8 = [_]u8{0} ** obj_name_len,
    prog_ifindex: u32 = 0,
    expected_attach_type: u32 = 0,
};

pub const ObjAttr = extern struct {
    pathname: u64 = 0,
    bpf_fd: u32 = 0,
    file_flags: u32 = 0,
};

pub const ProgAttachAttr = extern struct {
    target_fd: u32 = 0,
    attach_bpf_fd: u32 = 0,
    attach_type: u32 = 0,
    attach_flags: u32 = 0,
};

pub const TestRunAttr = extern struct {
    prog_fd: u32 = 0,
    retval: u32 = 0,
    data_size_in: u32 = 0,
    data_size_out: u32 = 0,
    data_in: u64 = 0,
    data_out: u64 = 0,
    repeat: u32 = 0,
    duration: u32 = 0,
};

pub const GetIdAttr = extern struct {
    id: extern union {
        start_id: u32,
        prog_id: u32,
        map_id: u32,
        btf_id: u32,
    },
    next_id: u32 = 0,
    open_flags: u32 = 0,
};

pub const InfoAttr = extern struct {
    bpf_fd: u32 = 0,
    info_len: u32 = 0,
    info: u64 = 0,
};

pub const QueryAttr = extern struct {
    target_fd: u32 = 0,
    attach_type: u32 = 0,
    query_flags: u32 = 0,
    attach_flags: u32 = 0,
    prog_ids: u64 = 0,
    prog_cnt: u32 = 0,
};

pub const RawTracepointAttr = extern struct {
    name: u64 = 0,
    prog_fd: u32 = 0,
};

pub const BtfLoadAttr = extern struct {
    btf: u64 = 0,
    btf_log_buf: u64 = 0,
    btf_size: u32 = 0,
    btf_log_size: u32 = 0,
    btf_log_level: u32 = 0,
};

pub const TaskFdQueryAttr = extern struct {
    pid: u32 = 0,
    fd: u32 = 0,
    flags: u32 = 0,
    buf_len: u32 = 0,
    buf: u64 = 0,
    prog_id: u32 = 0,
    fd_type: u32 = 0,
    probe_offset: u64 = 0,
    prove_addr: u64 = 0,
};

pub const Attr = extern union {
    map_create: MapCreateAttr,
    map_elem: MapElemAttr,
    prog_load: ProgLoadAttr,
    obj: ObjAttr,
    prog_attach: ProgAttachAttr,
    test_run: TestRunAttr,
    get_id: GetIdAttr,
    info: InfoAttr,
    query: QueryAttr,
    raw_tracepoint: RawTracepointAttr,
    btf_load: BtfLoadAttr,
    task_fd_query: TaskFdQueryAttr,
};

pub const StackBuildIdStatus = enum(u32) {
    Empty,
    Valid,
    Ip,
};

pub const StackBuildId = extern struct {
    status: i32,
    build_id: [20]u8,
    val: extern union {
        offset: u64,
        ip: u64,
    },
};

pub const Log = struct {
    level: u32,
    buf: []u8,
};

pub fn Hash(comptime Key: type, comptime Value: type) var {
    return struct {};
}

// key size must be 4 bytes, so it is a u32
pub fn Array(comptime Value: type) var {
    return struct {};
}

// key and value size are 4 bytes
pub const ProgArray = struct {};

pub fn bpf(cmd: i32, attr: *Attr, size: u32) usize {
    return syscall3(.bpf, @bitCast(usize, @as(isize, cmd)), @ptrToInt(attr), size);
}

pub fn map_create(map_type: MapType, key_size: u32, value_size: u32, max_entries: u32) !fd_t {
    var attr = Attr{
        .map_create = MapCreateAttr{
            .map_type = @enumToInt(map_type),
            .key_size = key_size,
            .value_size = value_size,
            .max_entries = max_entries,
        },
    };

    const rc = bpf(@enumToInt(Cmd.MapCreate), &attr, @sizeOf(MapCreateAttr));
    switch (errno(rc)) {
        0 => return @intCast(fd_t, rc),
        EINVAL => return error.MapTypeOrAttrInvalid,
        ENOMEM => return error.SystemResources,
        EPERM => return error.AccessDenied,
        else => |err| return unexpectedErrno(rc),
    }
}

pub fn map_lookup_elem(fd: fd_t, key: []const u8, value: []u8) !void {
    var attr = c.bpf_attr{
        .map_elem = MapElemAttr{
            .map_fd = fd,
            .key = @ptrToInt(u64, key.ptr),
            .value = @ptrToInt(u64, value.ptr),
        },
    };

    const rc = bpf(BPF_MAP_LOOKUP_ELEM, &attr, @sizeOf(MapElemAttr));
    switch (errno(rc)) {
        0 => return,
        EBADF => return error.BadFd,
        EFAULT => unreachable,
        EINVAL => return error.FieldInAttrNeedsZeroing,
        ENOENT => return error.NotFound,
        EPERM => return error.AccessDenied,
        else => |err| return unexpectedErrno(rc),
    }
}

pub fn map_update_elem(fd: fd_t, key: []const u8, value: []const u8, flags: u64) !void {
    var attr = Attr{
        .map_elem = MapElemAttr{
            .map_fd = fd,
            .key = @ptrToInt(u64, key.ptr),
            .value = @ptrToInt(u64, value.ptr),
            .flags = flags,
        },
    };

    const rc = bpf(BPF_MAP_UPDATE_ELEM, &attr, @sizeOf(MapElemAttr));
    switch (errno(rc)) {
        0 => return,
        E2BIG => return error.ReachedMaxEntries,
        EBADF => return error.BadFd,
        EFAULT => unreachable,
        EINVAL => return error.FieldInAttrNeedsZeroing,
        ENOMEM => return error.SystemResources,
        EPERM => return error.AccessDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn map_delete_elem(fd: fd_t, key: []const u8) !void {
    var attr = Attr{
        .map_elem = MapElemAttr{
            .map_fd = fd,
            .key = @ptrToInt(u64, key.ptr),
        },
    };

    const rc = bpf(BPF_MAP_DELETE_ELEM, &attr, @sizeOf(MapElemAttr));
    switch (errno(rc)) {
        0 => return,
        EBADF => return error.BadFd,
        EFAULT => unreachable,
        EINVAL => return error.FieldInAttrNeedsZeroing,
        ENOENT => return error.NotFound,
        EPERM => return error.AccessDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn map_get_next_key(fd: fd_t, key: []const u8, next_key: []u8) !void {
    var attr = Attr{
        .map_elem = MapElemAttr{
            .map_fd = fd,
            .key = @ptrToInt(u64, key),
            .next_key = @ptrToInt(u64, next_key),
        },
    };

    const rc = bpf(BPF_MAP_GET_NEXT_KEY, &attr, @sizeOf(MapElemAttr));
    switch (errno(rc)) {
        0 => return,
        EBADF => error.BadFd,
        EFAULT => unreachable,
        EFAULT => unreachable,
        EINVAL => unreachable,
        ENOENT => return error.NotFound,
        ENOMEM => return error.SystemResources,
        EPERM => return error.AccessDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn prog_load(prog_type: ProgType, insns: []const Insn, log: ?*Log, license: []const u8) !fd_t {
    var attr = Attr{
        .prog_load = ProgLoadAttr{
            .prog_type = @enumToInt(prog_type),
            .insns = @ptrToInt(insns.ptr),
            .insn_cnt = @intCast(u32, insns.len),
            .license = @ptrToInt(license.ptr),
            .kern_version = c.LINUX_VERSION_CODE,
        },
    };

    if (log) |l| {
        attr.prog_load.log_buf = @ptrToInt(l.buf.ptr);
        attr.prog_load.log_size = @intCast(u32, l.buf.len);
        attr.prog_load.log_level = l.level;
    }

    const rc = bpf(c.BPF_PROG_LOAD, &attr, @sizeOf(ProgLoadAttr));
    switch (errno(rc)) {
        0 => return @intCast(fd_t, rc),
        EACCES => return error.UnsafeProgram,
        EFAULT => unreachable,
        EINVAL => return error.InvalidProgram,
        EPERM => return error.AccessDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn obj_pin(fd: fd_t, pathname: []const u8) !void {
    var attr = Attr{
        .bpf_obj = ObjAttr{
            .bpf_fd = fd,
            .pathname = @ptrToInt(pathname.ptr),
            .file_flags = 0,
        },
    };

    const rc = bpf(c.BPF_OBJ_PIN, &attr, @sizeOf(ObjAttr));
    return switch (errno(rc)) {
        0 => null,
        EOPNOTSUPP => error.OpNotSupported,
        EPERM => error.AccessDenied,
        else => |err| unexpectedErrno(err),
    };
}

pub fn obj_get(pathname: []const u8, flags: ObjFlags) !fd_t {
    var attr = Attr{
        .bpf_obj = .{
            .bpf_fd = 0,
            .pathname = @ptrToInt(pathname.ptr),
            .file_flags = flags,
        },
    };

    const rc = bpf(c.BPF_OBJ_GET, &attr, @sizeOf(ObjAttr));
    return switch (errno(rc)) {
        0 => null,
        EINVAL => error.InvalidArguments,
        EPERM => error.AccessDenied,
        else => |err| unexpectedErrno(err),
    };
}

pub fn prog_attach() void {}
pub fn prog_detach() void {}
pub fn prog_test_run() void {}
pub fn prog_get_next_id() void {}
pub fn map_get_next_id() void {}
pub fn prog_get_fd_by_id() void {}
pub fn map_get_fd_by_id() void {}
pub fn obj_get_info_by_fd() void {}
pub fn prog_query() void {}
pub fn raw_tracepoint_open() void {}
pub fn btf_load() void {}
pub fn btf_get_fd_by_id() void {}
pub fn task_fd_query() void {}
pub fn map_lookup_and_delete_elem() void {}
pub fn map_freeze() void {}
pub fn btf_get_next_id() void {}
pub fn map_lookup_batch() void {}
pub fn map_lookup_and_delete_batch() void {}
pub fn map_update_batch() void {}
pub fn map_delete_batch() void {}
pub fn link_create() void {}
pub fn link_update() void {}
pub fn link_get_fd_by_id() void {}
pub fn link_get_next_id() void {}
pub fn enable_stats() void {}
pub fn iter_create() void {}

fn determine_tracepoint_id() void {}

fn to_upper_literal(comptime str: []const u8) *const [str.len]u8 {
    comptime {
        var tmp: [str.len]u8 = undefined;
        for (tmp) |*c, i| c.* = std.ascii.toUpper(str[i]);
        return &tmp;
    }
}

fn enum_value_in_c(comptime Enum: type, comptime c: type) bool {
    comptime {
        @setEvalBranchQuota(2000);
        var count = 0;
        inline for (std.meta.fields(Cmd)) |field| {
            const enum_literal = "BPF_" ++ to_upper_literal(field.name);
            if (@hasDecl(c, enum_literal)) {
                expectEqual(field.value, @field(c, enum_literal));
                count += 1;
            }
        }

        return count > 0;
    }
}
