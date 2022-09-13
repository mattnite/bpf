const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const tests = b.addTest("test/tests.zig");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}
