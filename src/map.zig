const fd_t = @import("std").os.fd_t;

// TODO: figure out rest of fields
name: []const u8,
fd: fd_t,
ifindex: isize,
inner_map: fd_t,
def: Def,
mmaped: []u8, // TODO: is this right?
pin_path: ?[]const u8,

pub const Type = enum(u32) {
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

pub const Def = packed struct {
    type: Type,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
};

pub fn Hash(comptime Key: type, comptime Value: type) anytype {
    return struct {
        fd: fd_t,

        const Key = Key;
        const Value = Value;
    };
}

// key size must be 4 bytes, so it is a u32
pub fn Array(comptime Value: type) anytype {
    return struct {
        fd: fd_t,

        const Key = u32;
        const Value = Value;
    };
}

// key and value size are 4 bytes
pub const ProgArray = struct {};
