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
        fd: ?fd_t,
        max_entries: u32,
        flags: u32,

        pub const Key = K;
        pub const Value = V;
    };
}

pub const Hash = Base;

// key size must be 4 bytes, so it is a u32
pub fn Array(comptime Value: type) type {
    return Base(u32, Value);
}

pub const ProgArray = @compileError("TODO");
pub const PerfEventArray = @compileError("TODO");
pub const PerCpuHash = @compileError("TODO");
pub const PerCpuArray = @compileError("TODO");
pub const StackTrace = @compileError("TODO");
pub const CGroupArray = @compileError("TODO");
pub const LruHash = @compileError("TODO");
pub const LruPercpuHash = @compileError("TODO");
pub const LpmTrie = @compileError("TODO");
pub const ArrayOfMaps = @compileError("TODO");
pub const HashOfMaps = @compileError("TODO");
pub const DevMap = @compileError("TODO");
pub const SockMap = @compileError("TODO");
pub const CpuMap = @compileError("TODO");
pub const XskMap = @compileError("TODO");
pub const SockHash = @compileError("TODO");
pub const CGroupStorage = @compileError("TODO");
pub const ReuseportSockArray = @compileError("TODO");
pub const PerCpuCGroupStorage = @compileError("TODO");
pub const Queue = @compileError("TODO");
pub const Stack = @compileError("TODO");
pub const SkStorage = @compileError("TODO");
pub const DevMapHash = @compileError("TODO");
pub const StructOps = @compileError("TODO");
pub const RingBuf = @compileError("TODO");
