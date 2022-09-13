const std = @import("std");

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse unreachable;
}

const root_path = root() ++ "/";
pub const include_dir = root_path ++ "";
const internal_include = root_path ++ "libbpf/include";
const uapi_include = root_path ++ "libbpf/include/uapi";

pub const Library = struct {
    step: *std.build.LibExeObjStep,

    pub fn link(self: *Library, other: *std.build.LibExeObjStep) void {
        other.addIncludeDir(include_dir);
        other.linkLibrary(self.step);
    }
};

pub fn create(b: *std.build.Builder, target: std.zig.CrossTarget, mode: std.builtin.Mode) Library {
    var ret = b.addStaticLibrary("bpf", null);
    ret.setTarget(target);
    ret.setBuildMode(mode);
    ret.addIncludeDir(internal_include);
    ret.addIncludeDir(uapi_include);
    ret.linkLibC();
    ret.addCSourceFiles(srcs, &.{});

    return Library{ .step = ret };
}

const srcs = &.{
    root_path ++ "libbpf/src/bpf.c",
    root_path ++ "libbpf/src/bpf_prog_linfo.c",
    root_path ++ "libbpf/src/btf.c",
    root_path ++ "libbpf/src/btf_dump.c",
    root_path ++ "libbpf/src/gen_loader.c",
    root_path ++ "libbpf/src/hashmap.c",
    root_path ++ "libbpf/src/libbpf.c",
    root_path ++ "libbpf/src/libbpf_errno.c",
    root_path ++ "libbpf/src/libbpf_probes.c",
    root_path ++ "libbpf/src/linker.c",
    root_path ++ "libbpf/src/netlink.c",
    root_path ++ "libbpf/src/nlattr.c",
    root_path ++ "libbpf/src/relo_core.c",
    root_path ++ "libbpf/src/ringbuf.c",
    root_path ++ "libbpf/src/str_error.c",
    root_path ++ "libbpf/src/strset.c",
    root_path ++ "libbpf/src/usdt.c",
};
