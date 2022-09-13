usingnamespace @import("user.zig");

const std = @import("std");
const perf = @import("perf.zig");
const Link = @import("link.zig");

const fd_t = std.os.fd_t;

name: []const u8,
type: ?ProgType,
insns: []Insn,
fd: ?fd_t,

const Self = @This();

// TODO: name vs title
pub fn load(self: *Self, license: []const u8, kern_version: u32) !void {
    if (self.fd != null) {
        return error.AlreadyLoaded;
    }

    var buf: [0x4000]u8 = undefined;
    buf[0] = 0;

    var log = Log{
        .level = 7,
        .buf = &buf,
    };

    errdefer _ = std.io.getStdErr().outStream().print("{}\n", .{@ptrCast([*:0]u8, &buf)}) catch {};
    self.fd = try prog_load(self.type.?, self.insns, &log, license, kern_version);
}

pub fn unload(self: *Self) void {
    if (self.fd) |fd| std.os.close(fd);
}
