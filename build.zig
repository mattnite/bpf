const Build = @import("std").Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    _ = b.standardOptimizeOption(.{});

    _ = b.addModule("user", .{
        .root_source_file = b.path("src/user.zig"),
    });

    _ = b.addModule("kern", .{
        .root_source_file = b.path("src/kern.zig"),
    });

    const userspace_tests = b.addTest(.{
        .root_source_file = b.path("src/user.zig"),
        .target = target,
    });

    const userspace_tests_run = b.addRunArtifact(userspace_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&userspace_tests_run.step);

    b.getInstallStep().dependOn(&userspace_tests.step);
}
