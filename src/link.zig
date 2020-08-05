usingnamespace @import("user.zig");
const std = @import("std");
const fd_t = std.os.fd_t;

const Self = @This();
const DetachFn = fn (link: *Self) !void;
const DestroyFn = DetachFn;

fd: fd_t,
detach: ?DetachFn,
destroy: ?DestroyFn,
pin_path: ?[]const u8,

fn pin(self: *Self, path: []const u8) !void {
    if (self.pin_path) {
        return error.AlreadyPinned;
    } else {
        pin_path = path;
    }

    try obj_pin(self.fd, path);
}

fn unpin(self: *Self) !void {
    if (self.pin_path) |path| {
        try std.os.unlink(path);
    }
}

fn update_program(self: *Self, prog: *Program) !void {
    try link_update(self.fd, prog.fd, null);
}

fn destroy(self: *Self) !void {
    if (self.destroy) |cb| {
        try cb(self);
    }
}
