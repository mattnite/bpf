pub const Reg = enum(u4) {
    r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10
};

pub const UpdateFlags = enum(u64) {
    Any = 0,
    NoExist = 1,
    Exist = 2,
};

pub const Insn = packed struct {
    code: u8,
    dst: u4,
    src: u4,
    off: i16,
    imm: i32,

    // namespaced variables
    const alu = 0x04;
    const jmp = 0x05;
    const mov = 0xb0;
    const k = 0;
    const exit_code = 0x90;

    // factory functions
    pub fn load_imm(dst: Reg, imm: i32) Insn {
        return Insn{
            .code = alu | mov | k,
            .dst = @enumToInt(dst),
            .src = 0,
            .off = 0,
            .imm = imm,
        };
    }

    pub fn exit() Insn {
        return Insn{
            .code = jmp | exit_code,
            .dst = 0,
            .src = 0,
            .off = 0,
            .imm = 0,
        };
    }
};

pub const MapType = enum(u32) {
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
    ringbuf,
};

// zig representation of struct bpf_fib_lookup;
pub const FibLookup = extern struct {
    family: u8,
    l4_protocol: u8,

    sport: u16, // big endian
    dport: u16, // big endian
    tot_len: u16,
    ifindex: u32,
    input_output: extern union {
        tos: u8,
        flowinfo: u32, // big endian
        rt_metric: u32,
    },
    src: extern union {
        ipv4: u32, // big endian
        ipv6: [4]u32, // network order
    },
    dst: extern union {
        ipv4: u32, // big endian
        ipv6: [4]u32, // network order
    },
    h_vlan_proto: u16, // big endian
    h_vlan_tci: u16, // big endian
    smac: [6]u8,
    dmac: [6]u8,
};

// zig representation of struct bpf_perf_event_data;
pub const PerfEventData = extern struct {
    regs: c.bpf_user_pt_regs_t,
    sample_period: u64,
    addr: u64,
};

// zig representation of struct bpf_perf_event_value;
pub const PerfEventValue = extern struct {
    counter: u64,
    enabled: u64,
    running: u64,
};

// zig representation of struct bpf_pidns_info;
pub const PidNsInfo = extern struct {};

// zig representation of struct bpf_sock;
pub const Sock = extern struct {};

// zig representation of struct bpf_sock_addr;
pub const BpfSockAddr = extern struct {};

// zig representation of struct bpf_sock_ops;
pub const SockOps = extern struct {
    op: u32,
    reply: extern union {
        args: [4]u32,
        reply: u32,
        replylong: u32,
    },
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [4]u32,
    local_ip6: [4]u32,
    remote_port: u32,
    local_port: u32,
    is_fullsock: u32,
    sn_cwnd: u32,
    srtt_us: u32,
    bpf_sock_ops_cb_flags: u32,
    state: u32,
    rtt_min: u32,
    snd_ssthresh: u32,
    rcv_nxt: u32,
    snd_nxt: u32,
    snd_una: u32,
    mss_cache: u32,
    ecn_flags: u32,
    rate_delivered: u32,
    rate_interval_us: u32,
    packets_out: u32,
    retrans_out: u32,
    total_retrans: u32,
    segs_in: u32,
    data_segs_in: u32,
    segs_out: u32,
    data_segs_out: u32,
    lost_out: u32,
    sacked_out: u32,
    sk_txhash: u32,
    bytes_received: u64,
    bytes_acked: u64,
    sk: u64,
};

// zig representation of struct bpf_sock_tuple;
pub const SockTuple = extern struct {};

// zig representation of struct bpf_spin_lock;
pub const SpinLock = extern struct {};

// zig representation of struct bpf_sysctl;
pub const SysCtl = extern struct {};

// zig representation of struct bpf_tcp_sock;
pub const TcpSock = extern struct {};

// zig representation of struct bpf_tunnel_key;
pub const TunnelKey = extern struct {};

// zig representation of struct bpf_xfrm_state;
pub const XfrmState = extern struct {};

// zig representation of struct pt_regs;
pub const PtRegs = extern struct {};

// zig representation of struct sk_reuseport_md;
pub const SkReusePortMd = extern struct {};

// zig representation of struct sockaddr;
pub const SockAddr = extern struct {};

// zig representation of struct tcphdr;
pub const TcpHdr = extern struct {};

// zig representation of struct __sk_buff;
pub const SkBuff = extern struct {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    tc_index: u32,
    cb: [5]u32,
    hash: u32,
    tc_classid: u32,
    data: u32,
    data_end: u32,
    napi_id: u32,

    // access by BPF_PROG_TYPE_sk_skb types from here to...
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [4]u32,
    local_ip6: [4]u32,
    remote_port: u32,
    local_port: u32,
    // ... here

    data_meta: u32,
    flow_keys: u64,
    tstamp: u64,
    wire_len: u32,
    gso_segs: u32,
    sk: u64,
};

// zig representation of struct sk_msg_md;
pub const SkMsgMd = extern struct {};

// zig representation of struct xdp_md;
pub const XdpMd = extern struct {};
