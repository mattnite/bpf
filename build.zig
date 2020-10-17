const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    var userspace_tests = b.addTest("exports.zig");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&userspace_tests.step);
}
