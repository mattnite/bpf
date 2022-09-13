const Builder = @import("std").build.Builder;

const bld = @import("src/build.zig");

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();
    const tests = b.addTest("src/main.zig");

    const bpf = bld.libbpf.create(b, target, mode);
    bpf.step.install();

    const z = bld.zlib.create(b, target, mode);
    z.step.install();

    // TODO: libelf

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}
