usingnamespace std.elf;
const std = @import("std");
const Allocator = std.mem.Allocator;

const Self = @This();

allocator: ?*Allocator,
name: []const u8,
license: []const u8,
kern_version: u32,

programs: []Program,
maps: []Map,
maps_cap: usize,
kconfig: []const u8,
externs: []ExternDesc,
kconfig_map_idx: isize,
loaded: bool,
has_pseudo_calls: bool,
btf: Btf,
btf_vmlinux: Btf,
btf_ext: BtfExt,
cap: Capabilities,
path: []const u8,

/// Parse a bpf elf file at comptime
pub fn init(comptime path: []const u8) comptime Self {
    const print = std.debug.print();
    const elf = @embedFile(path);

    const header = @ptrCast(*Elf64_Ehdr, &elf);
}

pub fn load() !void {}
pub fn unload() void {}

pub fn get_map(self: *Self, comptime T: type, comptime name: []const u8) T {
    return for (self.maps) |*map| {
        if (std.mem.eql(u8, name, map.name)) {
            if (map.def.key_size != @sizeOf(T.Key))
                @compileError("Key size does not match");

            if (map.def.value_size != @sizeOf(T.Value))
                @compileError("Value size does not match");

            break T{ .fd = map.fd };
        }
    } else @compileError("Failed to get map '" ++ name ++ "'");
}

pub fn get_prog(self: *Self, name: []const u8) *Program {}

pub fn pin(self: *Self, path: []const u8) !void {}
pub fn pin_maps(self: *Self, path: []const u8) !void {}
pub fn unpin_maps(self: *Self, path: []const u8) !void {}
pub fn pin_programs(self: *Self, path: []const u8) !void {}
pub fn unpin_programs(self: *Self, path: []const u8) !void {}
