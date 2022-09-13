const std = @import("std");

test "all" {
    _ = @import("tests/runtime.zig");
    _ = @import("tests/btf.zig");
}
