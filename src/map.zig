usingnamespace @import("common.zig");
const std = @import("std");
const fd_t = std.os.fd_t;

pub const Info = struct {
    name: []const u8,
    def: std.os.linux.BPF.kern.MapDef,
    fd: ?fd_t,
};

fn Base(comptime K: type, comptime V: type) type {
    return struct {
        fd: fd_t,

        pub const Key = K;
        pub const Value = V;
    };
}

pub const Hash = Base;

// key size must be 4 bytes, so it is a u32
pub fn Array(comptime Value: type) type {
    return Base(u32, Value);
}

// key and value size are 4 bytes
pub const ProgArray = struct {};
pub const PerfEventArray = Base(i32, fd_t);
