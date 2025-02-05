const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("user", .{
        .root_source_file = b.path("src/user.zig"),
    });

    _ = b.addModule("kern", .{
        .root_source_file = b.path("src/kern.zig"),
    });

    _ = b.addModule("VM", .{
        .root_source_file = b.path("src/VM.zig"),
        .target = target,
        .optimize = optimize,
    });

    const vm_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/VM.zig"),
    });
    add_bpf_files(b, vm_unit_tests, .{
        .name = "examples",
        .path = b.path("src/insn/examples.bpf.zig"),
        .sections = &.{
            "load",
            "return_one",
        },
    });

    const run_vm_unit_tests = b.addRunArtifact(vm_unit_tests);

    const test_vm_step = b.step("test-vm", "Run unit tests");
    test_vm_step.dependOn(&run_vm_unit_tests.step);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(test_vm_step);
}

const Add_BPF_FileOptions = struct {
    name: []const u8,
    path: std.Build.LazyPath,
    sections: []const []const u8,
};

fn add_bpf_files(
    b: *std.Build,
    compile: *std.Build.Step.Compile,
    opts: Add_BPF_FileOptions,
) void {
    add_bpf_file(b, compile, .little, opts);
    add_bpf_file(b, compile, .big, opts);
}

fn add_bpf_file(
    b: *std.Build,
    compile: *std.Build.Step.Compile,
    endian: std.builtin.Endian,
    opts: Add_BPF_FileOptions,
) void {
    const module_name = b.fmt("{s}-{s}", .{ opts.name, switch (endian) {
        .little => "el",
        .big => "eb",
    } });

    const obj = b.addObject(.{
        .name = module_name,
        .target = b.resolveTargetQuery(.{
            .cpu_arch = switch (endian) {
                .little => .bpfel,
                .big => .bpfeb,
            },
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseSmall,
        .root_source_file = opts.path,
    });
    obj.link_function_sections = true;

    const install = b.addInstallFile(obj.getEmittedBin(), b.fmt("{s}.elf", .{module_name}));
    b.getInstallStep().dependOn(&install.step);

    const options = b.addOptions();
    for (opts.sections) |section| {
        const objcopy = b.addObjCopy(
            obj.getEmittedBin(),
            .{
                .format = .bin,
                .only_section = switch (@import("builtin").os.tag) {
                    .macos => b.fmt(".text.{s}", .{section}),
                    else => b.fmt(".text.{s}", .{section}),
                },
            },
        );
        options.addOptionPath(section, objcopy.getOutput());
    }

    compile.root_module.addOptions(module_name, options);
}
