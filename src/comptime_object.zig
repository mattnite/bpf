usingnamespace std.elf;
const std = @import("std");
const Program = @import("program.zig");
const map = @import("map.zig");
const btf = @import("btf.zig");
const Allocator = std.mem.Allocator;

const ExternDesc = struct {};

const Self = @This();

allocator: ?*Allocator,
name: []const u8,
license: []const u8,
kern_version: u32,

programs: []Program,
maps: []map.Info,
maps_cap: usize,
kconfig: []const u8,
externs: []ExternDesc,
kconfig_map_idx: isize,
loaded: bool,
has_pseudo_calls: bool,
btf: btf.Header,
btf_vmlinux: btf.Header,
btf_ext: btf.ext.Header,
// TODO: later cap: Capabilities,
cap: u64,
path: []const u8,

/// Parse a bpf elf file at comptime
pub fn init(comptime path: []const u8) comptime Self {
    const elf = @embedFile(path);

    const header = @ptrCast(*const Elf64_Ehdr, &elf);

    const ret = std.mem.zeroes(Self);
    return ret;
}

pub fn load() !void {}
pub fn unload() void {}

pub fn get_map(self: *const Self, comptime T: type, comptime name: []const u8) T {
    return for (self.maps) |m| {
        if (std.mem.eql(u8, name, m.name)) {
            if (m.def.key_size != @sizeOf(T.Key))
                @compileError("Key size does not match in " ++ name);

            if (m.def.value_size != @sizeOf(T.Value))
                @compileError("Value size does not match");

            break T{ .fd = m.fd };
        }
    } else @compileError("Failed to get map '" ++ name ++ "'");
}

pub fn get_prog(self: *Self, name: []const u8) *Program {}

pub fn pin(self: *Self, path: []const u8) !void {}
pub fn pin_maps(self: *Self, path: []const u8) !void {}
pub fn unpin_maps(self: *Self, path: []const u8) !void {}
pub fn pin_programs(self: *Self, path: []const u8) !void {}
pub fn unpin_programs(self: *Self, path: []const u8) !void {}
pub fn set_rodata(self: *Self, name: []const u8, val: anytype) void {}
