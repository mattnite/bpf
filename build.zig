const std = @import("std");

pub fn build(b: *std.Build) void {
    const tests = b.addTest(.{
        .root_source_file = .{ .path = "exports.zig" },
    });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}
