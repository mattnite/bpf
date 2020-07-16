const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("bpf", "src/bpf.zig");
    lib.setBuildMode(mode);
    lib.install();

    var perf_tests = b.addTest("src/perf.zig");
    perf_tests.setBuildMode(mode);
    perf_tests.addIncludeDir("/usr/include");

    var userspace_tests = b.addTest("src/user.zig");
    userspace_tests.setBuildMode(mode);
    userspace_tests.addIncludeDir("/usr/include");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&userspace_tests.step);
    test_step.dependOn(&perf_tests.step);
}
