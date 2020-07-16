usingnamespace @import("bpf.zig").user;

const AttachFn = fn (sec_def: *SectionDef, prog: *Program) *Link;
const DetachFn = fn (link: *Link) !void;
const DestroyFn = fn (link: *Link) !void;

const Link = struct {
    detach: DetachFn,
    destroy: DestroyFn,
    pin_path: ?[]const u8,
    fd: fd_t,
    disconnected: bool,
};

const RelocType = enum {
    Ld64,
    Call,
    Data,
    Extern,
};

const RelocDesc = struct {
    reloc_type: RelocType,
    insn_idx: i32,
    map_idx: i32,
    sym_off: i32,
};

const Program = struct {
    idx: i32,
    name: []const u8,
    prog_ifindex: i32,
    section_name: []const u8,
    // section_name with / replaced by _; makes recursive pinning in
    // bpf_object__pin_programs easier
    pin_name: []const u8,
    insns: []Insn,
    prog_type: ProgType,
    load: bool,
    reloc_desc: []RelocDesc,
    log_level: LogLevel,
    instances: []fd_t,
    preprocessor: ProgramPrep,
    obj: *Obj,
};

pub const SectionDef = struct {
    section: []const u8,
    prog_type: ProgType,
    expected_attach_type: ?AttachType = null,
    is_attachable: bool = false,
    is_attach_btf: bool = false,
    attach_fn: ?AttachFn = null,
};

const section_defs = [_]SectionDef{
    .{
        .section = "socket",
        .prog_type = .SocketFilter,
    },
    .{
        .section = "sk_reuseport",
        .prog_type = .SkReuseport,
    },
    .{
        .section = "kprobe/",
        .prog_type = .KProbe,
        .attach_fn = attach_kprobe,
    },
    .{
        .section = "uprobe/",
        .prog_type = .KProbe,
        .attach_fn = attach_kprobe,
    },
    .{
        .section = "kretprobe/",
        .prog_type = .KProbe,
        .attach_fn = attach_kprobe,
    },
    .{
        .section = "uretprobe/",
        .prog_type = .KProbe,
    },
    .{
        .section = "classifier",
        .prog_type = .SchedCls,
    },
    .{
        .section = "action",
        .prog_type = .SchedAct,
    },
    .{
        .section = "tracepoint/",
        .prog_type = .Tracepoint,
        .attach_fn = attach_tp,
    },
    .{
        .section = "tp/",
        .prog_type = .Tracepoint,
        .attach_fn = attach_tp,
    },
    .{
        .section = "raw_tracepoint/",
        .prog_type = .RawTracepoint,
        .attach_fn = attach_raw_tp,
    },
    .{
        .section = "raw_tp/",
        .prog_type = .RawTracepoint,
        .attach_fn = attach_raw_tp,
    },
    .{
        .section = "tp_btf/",
        .prog_type = .Tracing,
        .expected_attach_type = .RawTp,
        .is_attach_btf = true,
        .attach_fn = attach_trace,
    },
    .{
        .section = "fentry/",
        .prog_type = .Tracing,
        .expected_attach_type = .FEntry,
        .is_attach_btf = true,
        .attach_fn = attach_trace,
    },
    .{
        .section = "fmod_ret/",
        .prog_type = .Tracing,
        .expected_attach_type = .ModifyReturn,
        .is_attach_btf = true,
        .attach_fn = attach_trace,
    },
    .{
        .section = "fexit/",
        .prog_type = .Tracing,
        .expected_attach_type = .TraceExit,
        .is_attach_btf = true,
        .attach_fn = attach_trace,
    },
    .{
        .section = "freplace/",
        .prog_type = .Ext,
        .is_attach_btf = true,
        .attach_fn = attach_trace,
    },
    .{
        .section = "lsm/",
        .prog_type = .Lsm,
        .is_attach_btf = true,
        .expected_attach_type = .LsmMac,
        .attach_fn = attach_lsm,
    },
    .{
        .section = "iter/",
        .prog_type = .Tracing,
        .expected_attach_type = .TraceIter,
        .is_attach_btf = true,
        .attach_fn = attach_iter,
    },
    .{
        .section = "xdp_devmap/",
        .prog_type = .Xdp,
        .expected_attach_type = .XdpDevMap,
    },
    .{
        .section = "xdp",
        .prog_type = .Xdp,
    },
    .{
        .section = "perf_event",
        .prog_type = .PerfEvent,
    },
    .{
        .section = "lwt_in",
        .prog_type = .LwtIn,
    },
    .{
        .section = "lwt_out",
        .prog_type = .LwtOut,
    },
    .{
        .section = "lwt_xmit",
        .prog_type = .LwtXmit,
    },
    .{
        .section = "lwt_seg6local",
        .prog_type = .LwtSeg6Local,
    },
    .{
        .section = "cgroup_skb/ingress",
        .prog_type = .CGroupSkb,
        .expected_attach_type = .CGroupInetIngress,
    },
    .{
        .section = "cgroup_skb/egress",
        .prog_type = .CGroupSkb,
        .expected_attach_type = .CGroupInetEgress,
    },
    .{
        .section = "cgroup/skb",
        .prog_type = .CGroupSkb,
    },
    .{
        .section = "cgroup/sock_create",
        .prog_type = .CGRoupSock,
        .expected_attach_type = .CGroupInetSockCreate,
    },
    .{
        .section = "cgroup/sock_release",
        .prog_type = .CGroupSock,
        .expected_attach_type = .CGroupInetSockRelease,
    },
    .{
        .section = "cgroup/sock",
        .prog_type = .CGroupSock,
        .expected_attach_type = .CGroupInetSockCreate,
    },
    .{
        .section = "cgroup/post_bind4",
        .prog_type = .CGroupSock,
        .expected_attach_type = .CGroupInet4PostBind,
    },
    .{
        .section = "cgroup/post_bind6",
        .prog_type = .CGroupSock,
        .expected_attach_type = .CGroupInet6PostBind,
    },
    .{
        .section = "cgroup/dev",
        .prog_type = .CGroupDevice,
        .expected_attach_type = .CGroupDevice,
    },
    .{
        .section = "sockops",
        .prog_type = .SockOps,
        .expected_attach_type = .CGroupSockOps,
    },
    .{
        .section = "sk_skb/stream_parser",
        .prog_type = .SkSkb,
        .expected_attach_type = .SkSkbStreamParser,
    },
    .{
        .section = "sk_skb/stream_verdict",
        .prog_type = .SkSkb,
        .expected_attach_type = .SkS,
    },
};

fn attach_kprobe(sec_def: *SectionDef, prog: *Program) *Link {}

fn attach_tp(sec_def: *SectionDef, prog: *Program) *Link {}

fn attach_raw_tp(sec_def: *SectionDef, prog: *Program) *Link {}

fn attach_trace(sec_def: *SectionDef, prog: *Program) *Link {}

fn attach_lsm(sec_def: *SectionDef, prog: *Program) *Link {}

fn attach_iter(sec_def: *SectionDef, prog: *Program) *Link {}

fn attach_kprobe(sec_def: *SectionDef, prog: *Program) *Link {}
