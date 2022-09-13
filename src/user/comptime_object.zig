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
        license: []const u8,
        kern_version: u32,

        loaded: bool,
        //has_pseudo_calls: bool,
        //btf: btf.Header,
        //btf_vmlinux: btf.Header,
        //btf_ext: btf.ext.Header,
        // TODO: later cap: Capabilities,
        //cap: u64,

        const Self = @This();

        /// initialize members with data known from the elf
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

        /// runtime operations, map_create
        pub fn load(self: *Self) !void {
            inline for (std.meta.fields(self.maps)) |field| {
                try @field(self.maps, field.name).create();
            }
        }

        pub fn unload(self: *Self) void {
            return unload(self);
        }

        pub fn get_map(comptime self: *const Self, comptime T: type, comptime name: []const u8) *MapInfo {
            return &@field(self.maps, name);
        }

        pub fn get_prog(self: *Self, comptime name: []const u8) *Program {
            return &@field(self.progs, name);
        }
        pub fn set_rodata(self: *Self, name: []const u8, val: anytype) void {}
    };
}

//pub fn pin(self: *Self, path: []const u8) !void {}
//pub fn pin_maps(self: *Self, path: []const u8) !void {}
//pub fn unpin_maps(self: *Self, path: []const u8) !void {}
//pub fn pin_programs(self: *Self, path: []const u8) !void {}
//pub fn unpin_programs(self: *Self, path: []const u8) !void {}
