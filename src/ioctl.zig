const builtin = @import("builtin");
const std = @import("std");

const expectEqual = std.testing.expectEqual;
const bits = switch (builtin.arch) {
    .mips,
    .mipsel,
    .mips64,
    .mips643el,
    .powerpc,
    .powerpc64,
    .powerpc64le,
    .sparc,
    .sparcv9,
    .sparcel,
    => .{ .size = 13, .dir = 3, .none = 1, .read = 2, .write = 4 },
    else => .{ .size = 12, .dir = 2, .none = 0, .read = 1, .write = 2 },
};

const Direction = std.meta.Int(false, bits.dir);

pub const IoctlCmd = packed struct {
    nr: u8,
    type: u8,
    size: std.meta.Int(false, bits.size),
    dir: Direction,
};

test "IoctlCmd size" {
    expectEqual(@bitSizeOf(IoctlCmd), @bitSizeOf(u32));
}

pub fn ioctl(fd: fd_t, cmd: IoctlCmd, arg: anytype) !void {
    // TODO: how to do validation in comptime and runtime?
    if (cmd.dir != bits.none and @sizeOf(arg) != cmd.size) {
        comptime {
            @compileError("ioctl arg size does not match size defined in cmd");
        }
        return error.BadArgsWidth;
    }

    const rc = std.os.linux.ioctl(fd, @as(u32, cmd), @as(usize, arg));
    switch (errno(rc)) {
        0 => return,
        else => |err| return unexpectedErrno(err),
    }
}

fn io_impl(dir: Direction, type: u8, nr: u8, comptime T: type) IoctlCmd {
    return .{
        .dir = dir,
        .size = @sizeOf(T),
        .type = type,
        .nr = nr,
    };
}

pub fn io(type: u8, nr: u8) IoctlCmd {
    return io_impl(bits.none, type, nr, void);
}

pub fn ior(type: u8, nr: u8, comptime T: type) IoctlCmd {
    return io_impl(bits.read, type, nr, T);
}

pub fn iow(type: u8, nr: u8, comptime T: type) IoctlCmd {
    return io_impl(bits.write, type, nr, T);
}

pub fn iowr(type: u8, nr: u8, comptime T: type) IoctlCmd {
    return io_impl(bits.read | bits.write, type, nr, T);
}
