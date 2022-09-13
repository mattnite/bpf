pub const user = @import("user.zig");
pub const kernel = @import("kernel.zig");
pub const testing = @import("testing.zig");
pub const build = @import("build.zig");

const std = @import("std");

test "all" {
    std.testing.refAllDeclsRecursive(@This());
    std.testing.refAllDeclsRecursive(@import("tests.zig"));
}
