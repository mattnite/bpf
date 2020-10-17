const builtin = @import("builtin");

pub usingnamespace switch (builtin.arch) {
    .bpfel, .bpfeb => @import("src/kern.zig"),
    else => @import("src/user.zig"),
};

pub usingnamespace @import("src/flags.zig");
pub usingnamespace @import("src/common.zig");

test "main" {
    @import("std").meta.refAllDecls(@This());
}
