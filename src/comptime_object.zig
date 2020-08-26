usingnamespace std.elf;
const std = @import("std");
const Program = @import("program.zig");
const map = @import("map.zig");
const btf = @import("btf.zig");
const Allocator = std.mem.Allocator;

const ExternDesc = struct {};

fn load(self: anytype) !void {
    self.loaded = true;
}
fn unload(self: anytype) void {}

pub fn ComptimeObject(comptime path: []const u8) type {
    return struct {
        allocator: *Allocator,
        name: []const u8,
        license: anytype,
        kern_version: u32,

        //maps_cap: usize,
        //kconfig: []const u8,
        //kconfig_map_idx: isize,
        loaded: bool,
        //has_pseudo_calls: bool,
        //btf: btf.Header,
        //btf_vmlinux: btf.Header,
        //btf_ext: btf.ext.Header,
        // TODO: later cap: Capabilities,
        //cap: u64,
        //path: []const u8,
        maps: anytype,

        const Self = @This();
        pub const programs = [_]Program{};

        pub const externs = [_]ExternDesc{};

        pub fn init(allocator: *Allocator) Self {
            return .{
                .allocator = allocator,
                .name = "",
                .license = "",
                .kern_version = 0,
                .loaded = false,
                .maps = @embedFile(path).*,
            };
        }

        pub fn load(self: *Self) !void {
            return load(self);
        }

        pub fn unload(self: *Self) void {
            return unload(self);
        }

        pub fn get_map(comptime self: *const Self, comptime T: type, comptime name: []const u8) comptime T {
            return for (self.maps) |m| {
                if (std.mem.eql(u8, name, m.name)) {
                    if (m.def.key_size != @sizeOf(T.Key))
                        @compileError("Key size does not match for " ++ name);

                    if (m.def.value_size != @sizeOf(T.Value))
                        @compileError("Value size does not match");

                    break T{ .fd = m.fd };
                }
            } else @compileError("Failed to get map '" ++ name ++ "'");
        }

        pub fn get_prog(comptime self: *Self, comptime name: []const u8) *Program {}
        pub fn set_rodata(self: *Self, name: []const u8, val: anytype) void {}
    };
}

//pub fn pin(self: *Self, path: []const u8) !void {}
//pub fn pin_maps(self: *Self, path: []const u8) !void {}
//pub fn unpin_maps(self: *Self, path: []const u8) !void {}
//pub fn pin_programs(self: *Self, path: []const u8) !void {}
//pub fn unpin_programs(self: *Self, path: []const u8) !void {}
