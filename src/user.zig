usingnamespace @import("flags.zig");
const std = @import("std");
const mem = std.mem;
const errno = getErrno;
const unexpectedErrno = std.os.unexpectedErrno;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const expect = std.testing.expect;
const fd_t = std.os.fd_t;

pub const elf = @import("elf.zig");
pub const btf = @import("btf.zig");
pub const kern = @import("kern.zig");

pub const Object = @import("object.zig");
pub const PerfBuffer = @import("perf_buffer.zig");
pub const Insn = @import("insn.zig");

/// These values correspond to "syscalls" within the BPF program's environment,
/// each one is documented in std.os.linux.BPF.kern
pub const Helper = enum(i32) {
    unspec,
    map_lookup_elem,
    map_update_elem,
    map_delete_elem,
    probe_read,
    ktime_get_ns,
    trace_printk,
    get_prandom_u32,
    get_smp_processor_id,
    skb_store_bytes,
    l3_csum_replace,
    l4_csum_replace,
    tail_call,
    clone_redirect,
    get_current_pid_tgid,
    get_current_uid_gid,
    get_current_comm,
    get_cgroup_classid,
    skb_vlan_push,
    skb_vlan_pop,
    skb_get_tunnel_key,
    skb_set_tunnel_key,
    perf_event_read,
    redirect,
    get_route_realm,
    perf_event_output,
    skb_load_bytes,
    get_stackid,
    csum_diff,
    skb_get_tunnel_opt,
    skb_set_tunnel_opt,
    skb_change_proto,
    skb_change_type,
    skb_under_cgroup,
    get_hash_recalc,
    get_current_task,
    probe_write_user,
    current_task_under_cgroup,
    skb_change_tail,
    skb_pull_data,
    csum_update,
    set_hash_invalid,
    get_numa_node_id,
    skb_change_head,
    xdp_adjust_head,
    probe_read_str,
    get_socket_cookie,
    get_socket_uid,
    set_hash,
    setsockopt,
    skb_adjust_room,
    redirect_map,
    sk_redirect_map,
    sock_map_update,
    xdp_adjust_meta,
    perf_event_read_value,
    perf_prog_read_value,
    getsockopt,
    override_return,
    sock_ops_cb_flags_set,
    msg_redirect_map,
    msg_apply_bytes,
    msg_cork_bytes,
    msg_pull_data,
    bind,
    xdp_adjust_tail,
    skb_get_xfrm_state,
    get_stack,
    skb_load_bytes_relative,
    fib_lookup,
    sock_hash_update,
    msg_redirect_hash,
    sk_redirect_hash,
    lwt_push_encap,
    lwt_seg6_store_bytes,
    lwt_seg6_adjust_srh,
    lwt_seg6_action,
    rc_repeat,
    rc_keydown,
    skb_cgroup_id,
    get_current_cgroup_id,
    get_local_storage,
    sk_select_reuseport,
    skb_ancestor_cgroup_id,
    sk_lookup_tcp,
    sk_lookup_udp,
    sk_release,
    map_push_elem,
    map_pop_elem,
    map_peek_elem,
    msg_push_data,
    msg_pop_data,
    rc_pointer_rel,
    spin_lock,
    spin_unlock,
    sk_fullsock,
    tcp_sock,
    skb_ecn_set_ce,
    get_listener_sock,
    skc_lookup_tcp,
    tcp_check_syncookie,
    sysctl_get_name,
    sysctl_get_current_value,
    sysctl_get_new_value,
    sysctl_set_new_value,
    strtol,
    strtoul,
    sk_storage_get,
    sk_storage_delete,
    send_signal,
    tcp_gen_syncookie,
    skb_output,
    probe_read_user,
    probe_read_kernel,
    probe_read_user_str,
    probe_read_kernel_str,
    tcp_send_ack,
    send_signal_thread,
    jiffies64,
    read_branch_records,
    get_ns_current_pid_tgid,
    xdp_output,
    get_netns_cookie,
    get_current_ancestor_cgroup_id,
    sk_assign,
    ktime_get_boot_ns,
    seq_printf,
    seq_write,
    sk_cgroup_id,
    sk_ancestor_cgroup_id,
    ringbuf_output,
    ringbuf_reserve,
    ringbuf_submit,
    ringbuf_discard,
    ringbuf_query,
    csum_level,
    skc_to_tcp6_sock,
    skc_to_tcp_sock,
    skc_to_tcp_timewait_sock,
    skc_to_tcp_request_sock,
    skc_to_udp6_sock,
    get_task_stack,
    _,
};

pub const Cmd = extern enum(usize) {
    /// Create  a map and return a file descriptor that refers to the map.  The
    /// close-on-exec file descriptor flag is automatically enabled for the new
    /// file descriptor.
    ///
    /// uses MapCreateAttr
    map_create,

    /// Look up an element by key in a specified map and return its value.
    ///
    /// uses MapElemAttr
    map_lookup_elem,

    /// Create or update an element (key/value pair) in a specified map.
    ///
    /// uses MapElemAttr
    map_update_elem,

    /// Look up and delete an element by key in a specified map.
    ///
    /// uses MapElemAttr
    map_delete_elem,

    /// Look up an element by key in a specified map and return the key of the
    /// next element.
    map_get_next_key,

    /// Verify and load an eBPF program, returning a new file descriptor
    /// associated with  the  program.   The close-on-exec file descriptor flag
    /// is automatically enabled for the new file descriptor.
    ///
    /// uses ProgLoadAttr
    prog_load,

    /// Pin a map or eBPF program to a path within the minimal BPF filesystem
    ///
    /// uses ObjAttr
    obj_pin,

    /// Get the file descriptor of a BPF object pinned to a certain path
    ///
    /// uses ObjAttr
    obj_get,

    /// uses ProgAttachAttr
    prog_attach,

    /// uses ProgAttachAttr
    prog_detach,

    /// uses TestRunAttr
    prog_test_run,

    /// uses GetIdAttr
    prog_get_next_id,

    /// uses GetIdAttr
    map_get_next_id,

    /// uses GetIdAttr
    prog_get_fd_by_id,

    /// uses GetIdAttr
    map_get_fd_by_id,

    /// uses InfoAttr
    obj_get_info_by_fd,

    /// uses QueryAttr
    prog_query,

    /// uses RawTracepointAttr
    raw_tracepoint_open,

    /// uses BtfLoadAttr
    btf_load,

    /// uses GetIdAttr
    btf_get_fd_by_id,

    /// uses TaskFdQueryAttr
    task_fd_query,

    /// uses MapElemAttr
    map_lookup_and_delete_elem,
    map_freeze,

    /// uses GetIdAttr
    btf_get_next_id,

    /// uses MapBatchAttr
    map_lookup_batch,

    /// uses MapBatchAttr
    map_lookup_and_delete_batch,

    /// uses MapBatchAttr
    map_update_batch,

    /// uses MapBatchAttr
    map_delete_batch,

    /// uses LinkCreateAttr
    link_create,

    /// uses LinkUpdateAttr
    link_update,

    /// uses GetIdAttr
    link_get_fd_by_id,

    /// uses GetIdAttr
    link_get_next_id,

    /// uses EnableStatsAttr
    enable_stats,

    /// uses IterCreateAttr
    iter_create,
    link_detach,
    _,
};

pub const MapType = extern enum(u32) {
    unspec,
    hash,
    array,
    prog_array,
    perf_event_array,
    percpu_hash,
    percpu_array,
    stack_trace,
    cgroup_array,
    lru_hash,
    lru_percpu_hash,
    lpm_trie,
    array_of_maps,
    hash_of_maps,
    devmap,
    sockmap,
    cpumap,
    xskmap,
    sockhash,
    cgroup_storage,
    reuseport_sockarray,
    percpu_cgroup_storage,
    queue,
    stack,
    sk_storage,
    devmap_hash,
    struct_ops,

    /// An ordered and shared CPU version of perf_event_array. They have
    /// similar semantics:
    ///     - variable length records
    ///     - no blocking: when full, reservation fails
    ///     - memory mappable for ease and speed
    ///     - epoll notifications for new data, but can busy poll
    ///
    /// Ringbufs give BPF programs two sets of APIs:
    ///     - ringbuf_output() allows copy data from one place to a ring
    ///     buffer, similar to bpf_perf_event_output()
    ///     - ringbuf_reserve()/ringbuf_commit()/ringbuf_discard() split the
    ///     process into two steps. First a fixed amount of space is reserved,
    ///     if that is successful then the program gets a pointer to a chunk of
    ///     memory and can be submitted with commit() or discarded with
    ///     discard()
    ///
    /// ringbuf_output() will incurr an extra memory copy, but allows to submit
    /// records of the length that's not known beforehand, and is an easy
    /// replacement for perf_event_outptu().
    ///
    /// ringbuf_reserve() avoids the extra memory copy but requires a known size
    /// of memory beforehand.
    ///
    /// ringbuf_query() allows to query properties of the map, 4 are currently
    /// supported:
    ///     - BPF_RB_AVAIL_DATA: amount of unconsumed data in ringbuf
    ///     - BPF_RB_RING_SIZE: returns size of ringbuf
    ///     - BPF_RB_CONS_POS/BPF_RB_PROD_POS returns current logical position
    ///     of consumer and producer respectively
    ///
    /// key size: 0
    /// value size: 0
    /// max entries: size of ringbuf, must be power of 2
    ringbuf,

    _,
};

pub const ProgType = extern enum(u32) {
    unspec,

    /// context type: __sk_buff
    socket_filter,

    /// context type: bpf_user_pt_regs_t
    kprobe,

    /// context type: __sk_buff
    sched_cls,

    /// context type: __sk_buff
    sched_act,

    /// context type: u64
    tracepoint,

    /// context type: xdp_md
    xdp,

    /// context type: bpf_perf_event_data
    perf_event,

    /// context type: __sk_buff
    cgroup_skb,

    /// context type: bpf_sock
    cgroup_sock,

    /// context type: __sk_buff
    lwt_in,

    /// context type: __sk_buff
    lwt_out,

    /// context type: __sk_buff
    lwt_xmit,

    /// context type: bpf_sock_ops
    sock_ops,

    /// context type: __sk_buff
    sk_skb,

    /// context type: bpf_cgroup_dev_ctx
    cgroup_device,

    /// context type: sk_msg_md
    sk_msg,

    /// context type: bpf_raw_tracepoint_args
    raw_tracepoint,

    /// context type: bpf_sock_addr
    cgroup_sock_addr,

    /// context type: __sk_buff
    lwt_seg6local,

    /// context type: u32
    lirc_mode2,

    /// context type: sk_reuseport_md
    sk_reuseport,

    /// context type: __sk_buff
    flow_dissector,

    /// context type: bpf_sysctl
    cgroup_sysctl,

    /// context type: bpf_raw_tracepoint_args
    raw_tracepoint_writable,

    /// context type: bpf_sockopt
    cgroup_sockopt,

    /// context type: void *
    tracing,

    /// context type: void *
    struct_ops,

    /// context type: void *
    ext,

    /// context type: void *
    lsm,

    /// context type: bpf_sk_lookup
    sk_lookup,
    _,
};

pub const AttachType = extern enum(u32) {
    cgroup_inet_ingress,
    cgroup_inet_egress,
    cgroup_inet_sock_create,
    cgroup_sock_ops,
    sk_skb_stream_parser,
    sk_skb_stream_verdict,
    cgroup_device,
    sk_msg_verdict,
    cgroup_inet4_bind,
    cgroup_inet6_bind,
    cgroup_inet4_connect,
    cgroup_inet6_connect,
    cgroup_inet4_post_bind,
    cgroup_inet6_post_bind,
    cgroup_udp4_sendmsg,
    cgroup_udp6_sendmsg,
    lirc_mode2,
    flow_dissector,
    cgroup_sysctl,
    cgroup_udp4_recvmsg,
    cgroup_udp6_recvmsg,
    cgroup_getsockopt,
    cgroup_setsockopt,
    trace_raw_tp,
    trace_fentry,
    trace_fexit,
    modify_return,
    lsm_mac,
    trace_iter,
    cgroup_inet4_getpeername,
    cgroup_inet6_getpeername,
    cgroup_inet4_getsockname,
    cgroup_inet6_getsockname,
    xdp_devmap,
    cgroup_inet_sock_release,
    xdp_cpumap,
    sk_lookup,
    xdp,
    _,
};

const obj_name_len = 16;
/// struct used by Cmd.map_create command
pub const MapCreateAttr = extern struct {
    /// one of MapType
    map_type: u32,

    /// size of key in bytes
    key_size: u32,

    /// size of value in bytes
    value_size: u32,

    /// max number of entries in a map
    max_entries: u32,

    /// .map_create related flags
    map_flags: u32,

    /// fd pointing to the inner map
    inner_map_fd: fd_t,

    /// numa node (effective only if MapCreateFlags.numa_node is set)
    numa_node: u32,
    map_name: [obj_name_len]u8,

    /// ifindex of netdev to create on
    map_ifindex: u32,

    /// fd pointing to a BTF type data
    btf_fd: fd_t,

    /// BTF type_id of the key
    btf_key_type_id: u32,

    /// BTF type_id of the value
    bpf_value_type_id: u32,

    /// BTF type_id of a kernel struct stored as the map value
    btf_vmlinux_value_type_id: u32,
};

/// struct used by Cmd.map_*_elem commands
pub const MapElemAttr = extern struct {
    map_fd: fd_t,
    key: u64,
    result: extern union {
        value: u64,
        next_key: u64,
    },
    flags: u64,
};

/// struct used by Cmd.map_*_batch commands
pub const MapBatchAttr = extern struct {
    /// start batch, NULL to start from beginning
    in_batch: u64,

    /// output: next start batch
    out_batch: u64,
    keys: u64,
    values: u64,

    /// input/output:
    /// input: # of key/value elements
    /// output: # of filled elements
    count: u32,
    map_fd: fd_t,
    elem_flags: u64,
    flags: u64,
};

/// struct used by Cmd.prog_load command
pub const ProgLoadAttr = extern struct {
    /// one of ProgType
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,

    /// verbosity level of verifier
    log_level: u32,

    /// size of user buffer
    log_size: u32,

    /// user supplied buffer
    log_buf: u64,

    /// not used
    kern_version: u32,
    prog_flags: u32,
    prog_name: [obj_name_len]u8,

    /// ifindex of netdev to prep for.
    prog_ifindex: u32,

    /// For some prog types expected attach type must be known at load time to
    /// verify attach type specific parts of prog (context accesses, allowed
    /// helpers, etc).
    expected_attach_type: u32,

    /// fd pointing to BTF type data
    prog_btf_fd: fd_t,

    /// userspace bpf_func_info size
    func_info_rec_size: u32,
    func_info: u64,

    /// number of bpf_func_info records
    func_info_cnt: u32,

    /// userspace bpf_line_info size
    line_info_rec_size: u32,
    line_info: u64,

    /// number of bpf_line_info records
    line_info_cnt: u32,

    /// in-kernel BTF type id to attach to
    attact_btf_id: u32,

    /// 0 to attach to vmlinux
    attach_prog_id: u32,
};

/// struct used by Cmd.obj_* commands
pub const ObjAttr = extern struct {
    pathname: u64,
    bpf_fd: fd_t,
    file_flags: u32,
};

/// struct used by Cmd.prog_attach/detach commands
pub const ProgAttachAttr = extern struct {
    /// container object to attach to
    target_fd: fd_t,

    /// eBPF program to attach
    attach_bpf_fd: fd_t,

    attach_type: u32,
    attach_flags: u32,

    // TODO: BPF_F_REPLACE flags
    /// previously attached eBPF program to replace if .replace is used
    replace_bpf_fd: fd_t,
};

/// struct used by Cmd.prog_test_run command
pub const TestRunAttr = extern struct {
    prog_fd: fd_t,
    retval: u32,

    /// input: len of data_in
    data_size_in: u32,

    /// input/output: len of data_out. returns ENOSPC if data_out is too small.
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,

    /// input: len of ctx_in
    ctx_size_in: u32,

    /// input/output: len of ctx_out. returns ENOSPC if ctx_out is too small.
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
};

/// struct used by Cmd.*_get_*_id commands
pub const GetIdAttr = extern struct {
    id: extern union {
        start_id: u32,
        prog_id: u32,
        map_id: u32,
        btf_id: u32,
        link_id: u32,
    },
    next_id: u32,
    open_flags: u32,
};

/// struct used by Cmd.obj_get_info_by_fd command
pub const InfoAttr = extern struct {
    bpf_fd: fd_t,
    info_len: u32,
    info: u64,
};

/// struct used by Cmd.prog_query command
pub const QueryAttr = extern struct {
    /// container object to query
    target_fd: fd_t,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
};

/// struct used by Cmd.raw_tracepoint_open command
pub const RawTracepointAttr = extern struct {
    name: u64,
    prog_fd: fd_t,
};

/// struct used by Cmd.btf_load command
pub const BtfLoadAttr = extern struct {
    btf: u64,
    btf_log_buf: u64,
    btf_size: u32,
    btf_log_size: u32,
    btf_log_level: u32,
};

/// struct used by Cmd.task_fd_query
pub const TaskFdQueryAttr = extern struct {
    /// input: pid
    pid: pid_t,

    /// input: fd
    fd: fd_t,

    /// input: flags
    flags: u32,

    /// input/output: buf len
    buf_len: u32,

    /// input/output:
    ///     tp_name for tracepoint
    ///     symbol for kprobe
    ///     filename for uprobe
    buf: u64,

    /// output: prod_id
    prog_id: u32,

    /// output: BPF_FD_TYPE
    fd_type: u32,

    /// output: probe_offset
    probe_offset: u64,

    /// output: probe_addr
    probe_addr: u64,
};

/// struct used by Cmd.link_create command
pub const LinkCreateAttr = extern struct {
    /// eBPF program to attach
    prog_fd: fd_t,

    /// object to attach to
    target_fd: fd_t,
    attach_type: u32,

    /// extra flags
    flags: u32,
};

/// struct used by Cmd.link_update command
pub const LinkUpdateAttr = extern struct {
    link_fd: fd_t,

    /// new program to update link with
    new_prog_fd: fd_t,

    /// extra flags
    flags: u32,

    /// expected link's program fd, it is specified only if BPF_F_REPLACE is
    /// set in flags
    old_prog_fd: fd_t,
};

/// struct used by Cmd.enable_stats command
pub const EnableStatsAttr = extern struct {
    type: u32,
};

/// struct used by Cmd.iter_create command
pub const IterCreateAttr = extern struct {
    link_fd: fd_t,
    flags: u32,
};

/// Mega struct that is passed to the bpf() syscall
pub const Attr = extern union {
    map_create: MapCreateAttr,
    map_elem: MapElemAttr,
    map_batch: MapBatchAttr,
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
    link_create: LinkCreateAttr,
    link_update: LinkUpdateAttr,
    enable_stats: EnableStatsAttr,
    iter_create: IterCreateAttr,
};

pub const Log = struct {
    level: u32,
    buf: []u8,
};

pub fn bpf(cmd: Cmd, attr: *Attr, size: u32) usize {
    return syscall3(.bpf, @enumToInt(cmd), @ptrToInt(attr), size);
}

pub fn map_create(map_type: MapType, key_size: u32, value_size: u32, max_entries: u32) !fd_t {
    var attr = Attr{
        .map_create = mem.zeroes(MapCreateAttr),
    };

    attr.map_create.map_type = @enumToInt(map_type);
    attr.map_create.key_size = key_size;
    attr.map_create.value_size = value_size;
    attr.map_create.max_entries = max_entries;

    const rc = bpf(.map_create, &attr, @sizeOf(MapCreateAttr));
    return switch (errno(rc)) {
        0 => @intCast(fd_t, rc),
        EINVAL => error.MapTypeOrAttrInvalid,
        ENOMEM => error.SystemResources,
        EPERM => error.AccessDenied,
        else => |err| unexpectedErrno(rc),
    };
}

test "map_create" {
    const map = try map_create(.hash, 4, 4, 32);
    defer std.os.close(map);
}

pub fn map_lookup_elem(fd: fd_t, key: []const u8, value: []u8) !void {
    var attr = Attr{
        .map_elem = mem.zeroes(MapElemAttr),
    };

    attr.map_elem.map_fd = fd;
    attr.map_elem.key = @ptrToInt(key.ptr);
    attr.map_elem.result.value = @ptrToInt(value.ptr);

    const rc = bpf(.map_lookup_elem, &attr, @sizeOf(MapElemAttr));
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
        .map_elem = mem.zeroes(MapElemAttr),
    };

    attr.map_elem.map_fd = fd;
    attr.map_elem.key = @ptrToInt(key.ptr);
    attr.map_elem.result = .{ .value = @ptrToInt(value.ptr) };
    attr.map_elem.flags = flags;

    const rc = bpf(.map_update_elem, &attr, @sizeOf(MapElemAttr));
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
        .map_elem = mem.zeroes(MapElemAttr),
    };

    attr.map_elem.map_fd = fd;
    attr.map_elem.key = @ptrToInt(key.ptr);

    const rc = bpf(.map_delete_elem, &attr, @sizeOf(MapElemAttr));
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

test "map lookup, update, and delete" {
    const key_size = 4;
    const value_size = 4;
    const map = try map_create(.hash, key_size, value_size, 1);
    defer std.os.close(map);

    const key = mem.zeroes([key_size]u8);
    var value = mem.zeroes([value_size]u8);

    // fails looking up value that doesn't exist
    expectError(error.NotFound, map_lookup_elem(map, &key, &value));

    // succeed at updating and looking up element
    try map_update_elem(map, &key, &value, 0);
    try map_lookup_elem(map, &key, &value);

    // fails inserting more than max entries
    const second_key = [key_size]u8{ 0, 0, 0, 1 };
    expectError(error.ReachedMaxEntries, map_update_elem(map, &second_key, &value, 0));

    // succeed at deleting an existing elem
    try map_delete_elem(map, &key);
    expectError(error.NotFound, map_lookup_elem(map, &key, &value));

    // fail at deleting a non-existing elem
    expectError(error.NotFound, map_delete_elem(map, &key));
}

pub fn prog_load(
    prog_type: ProgType,
    insns: []const Insn,
    log: ?*Log,
    license: []const u8,
    kern_version: u32,
) !fd_t {
    var attr = Attr{
        .prog_load = mem.zeroes(ProgLoadAttr),
    };

    attr.prog_load.prog_type = @enumToInt(prog_type);
    attr.prog_load.insns = @ptrToInt(insns.ptr);
    attr.prog_load.insn_cnt = @intCast(u32, insns.len);
    attr.prog_load.license = @ptrToInt(license.ptr);
    attr.prog_load.kern_version = kern_version;

    if (log) |l| {
        attr.prog_load.log_buf = @ptrToInt(l.buf.ptr);
        attr.prog_load.log_size = @intCast(u32, l.buf.len);
        attr.prog_load.log_level = l.level;
    }

    const rc = bpf(.prog_load, &attr, @sizeOf(ProgLoadAttr));
    return switch (errno(rc)) {
        0 => @intCast(fd_t, rc),
        EACCES => error.UnsafeProgram,
        EFAULT => unreachable,
        EINVAL => error.InvalidProgram,
        EPERM => error.AccessDenied,
        else => |err| unexpectedErrno(err),
    };
}

test "prog_load" {
    // this should fail because it does not set r0 before exiting
    const bad_prog = [_]Insn{
        Insn.exit(),
    };

    const good_prog = [_]Insn{
        Insn.mov(.r0, 0),
        Insn.exit(),
    };

    const prog = try prog_load(.socket_filter, &good_prog, null, "MIT", 0);
    defer std.os.close(prog);

    expectError(error.UnsafeProgram, prog_load(.socket_filter, &bad_prog, null, "MIT", 0));
}

pub const MapInfo = struct {
    fd: ?fd_t,
    def: kern.MapDef,
};

pub fn Map(comptime Key: type, comptime Value: type) type {
    return struct {
        fd: fd_t,
        def: kern.MapDef,

        const Self = @This();

        pub fn init(info: MapInfo) !Self {
            if (info.def.key_size != @sizeOf(Key)) return error.KeySizeMismatch;
            if (info.def.value_size != @sizeOf(Value)) return error.ValueSizeMismatch;

            if (info.fd == null) {
                return error.MapFdNotCreated;
            }

            return Self{ .fd = info.fd.?, .def = info.def };
        }
    };
}

pub const PerfEventArray = Map(u32, u32);
