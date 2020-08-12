usingnamespace @import("common.zig");
const fd_t = @import("std").os.fd_t;

// TODO: figure out rest of fields
pub const Info = struct {
    name: []const u8,
    fd: fd_t,
    ifindex: isize,
    inner_map: fd_t,
    def: Def,
    mmaped: []u8, // TODO: is this right?
    pin_path: ?[]const u8,
};

pub const Def = packed struct {
    type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
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

pub const PerfEventArray = struct {
    fd: fd_t,

    pub const Key = i32;
    pub const Value = i32;
};
