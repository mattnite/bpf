//! This module allows for running a simple linux system on QEMU, as well as an
//! RPC in order to do different things on the system so that different BPF
//! program hook points can be poked and validated.
//!
//! As opposed to the usual copypasta referring to most linux instances as
//! GNU/Linux, this is called JustLinux because ew I don't like GNU.

const std = @import("std");

const JustLinux = @This();

const EnvInfo = struct {
    zig_exe: []const u8,
    lib_dir: []const u8,
    std_dir: []const u8,
    global_cache_dir: []const u8,
    version: []const u8,
};

fn buildInitProgram(cpu_arch: std.Target.Cpu.Arch, init_path: []const u8) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();

    const result = try std.ChildProcess.exec(.{
        .allocator = gpa.allocator(),
        .argv = &[_][]const u8{ "zig", "env" },
    });
    defer {
        gpa.allocator().free(result.stdout);
        gpa.allocator().free(result.stderr);
    }

    switch (result.term) {
        .Exited => |val| {
            if (val != 0) {
                std.log.err("zig compiler returned error code: {}", .{val});
                return error.ZigCompiler;
            }
        },
        .Signal => |sig| {
            std.log.err("zig compiler interrupted by signal: {}", .{sig});
            return error.ZigCompiler;
        },
        else => return error.UnknownTerm,
    }

    var token_stream = std.json.TokenStream.init(result.stdout);
    const parse_opts = std.json.ParseOptions{ .allocator = gpa.allocator() };
    const env = try std.json.parse(
        EnvInfo,
        &token_stream,
        parse_opts,
    );
    defer std.json.parseFree(EnvInfo, env, parse_opts);

    const builder = try std.build.Builder.create(
        arena.allocator(),
        env.zig_exe,
        ".",
        "zig-cache",
        env.global_cache_dir,
    );
    defer builder.destroy();

    builder.resolveInstallPrefix(null, .{});

    const init = builder.addExecutable("init", init_path);
    init.setTarget(.{
        .cpu_arch = cpu_arch,
        .os_tag = .linux,
        .abi = .musl,
    });
    init.linkLibC();

    try builder.make(&.{"install"});
}

test "build init.x86_64" {
    try buildInitProgram(.x86_64, "test/init-runtime.zig");
}

test "build init.aarch64" {
    try buildInitProgram(.aarch64, "test/init-runtime.zig");
}

// TODO: target
pub fn fromRuntimeBpf(
    cpu_arch: std.Target.Cpu.Arch,
    bpf_source_path: []const u8,
    kernel_path: []const u8,
) !JustLinux {
    _ = cpu_arch;
    _ = bpf_source_path;
    _ = kernel_path;
    return error.Todo;

    // compile bpf probe
    // compile init-runtime (cached)
    // assemble cpio.gz
    // start up qemu
    // wait for rpc to be ready
}

pub fn fromBtfBpf(
    cpu_arch: std.Target.Cpu.Arch,
    bpf_source_path: []const u8,
    kernel_path: []const u8,
) !JustLinux {
    _ = cpu_arch;
    _ = bpf_source_path;
    _ = kernel_path;
    return error.Todo;

    // compile bpf probe
    // generate skel header
    // compile init-btf (cached)
    // assemble cpio.gz
    // start up qemu
    // wait for rpc to be ready
}
