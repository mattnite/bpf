const flags = @import("flags.zig");

pub const MapUpdateType = enum(u64) {
    any = flags.ANY,
    noexist = flags.NOEXIST,
    exist = flags.EXIST,
};

pub const MapDef = extern struct {
    type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
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
