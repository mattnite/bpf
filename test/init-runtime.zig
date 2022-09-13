const std = @import("std");

pub fn main() void {
    while (true) {
        std.os.nanosleep(1, 0);
    }
}
