const std = @import("std");

test "all" {
    std.testing.refAllDecls(@import("JustLinux.zig"));
    std.testing.refAllDecls(@import("tests/btf.zig"));
    std.testing.refAllDecls(@import("tests/runtime.zig"));
}
