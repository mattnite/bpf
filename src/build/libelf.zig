const std = @import("std");
const Self = @This();

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse unreachable;
}

const root_path = root() ++ "/";
pub const include_dir = root_path ++ "include";
const common_include = root_path ++ "elftoolchain/common";
const musl_include = root_path ++ "musl-include";

pub const Library = struct {
    step: *std.build.LibExeObjStep,

    pub fn link(self: Library, other: *std.build.LibExeObjStep) void {
        other.addIncludeDir(include_dir);
        other.linkLibrary(self.step);
    }
};

pub fn create(b: *std.build.Builder, target: std.zig.CrossTarget, mode: std.builtin.Mode) Library {
    var ret = b.addStaticLibrary("elf", null);
    ret.setTarget(target);
    ret.setBuildMode(mode);
    ret.linkLibC();
    ret.addCSourceFiles(srcs, &.{});
    ret.addIncludeDir(include_dir);
    ret.addIncludeDir(common_include);

    if (target.abi != null and target.abi.? == .musl)
        ret.addIncludeDir(musl_include);

    return Library{ .step = ret };
}

const srcs = &.{
    root_path ++ "elftoolchain/libelf/libelf_extended.c",
    root_path ++ "elftoolchain/libelf/elf_cntl.c",
    root_path ++ "elftoolchain/libelf/elf_getarsym.c",
    root_path ++ "elftoolchain/libelf/libelf_elfmachine.c",
    root_path ++ "elftoolchain/libelf/elf_end.c",
    root_path ++ "elftoolchain/libelf/libelf_ehdr.c",
    root_path ++ "elftoolchain/libelf/elf_getversion.c",
    root_path ++ "elftoolchain/libelf/libelf_allocate.c",
    root_path ++ "elftoolchain/libelf/libelf_ar_util.c",
    root_path ++ "elftoolchain/libelf/libelf_phdr.c",
    root_path ++ "elftoolchain/libelf/elf_begin.c",
    root_path ++ "elftoolchain/libelf/elf_rand.c",
    root_path ++ "elftoolchain/libelf/elf_getbase.c",
    root_path ++ "elftoolchain/libelf/gelf_shdr.c",
    root_path ++ "elftoolchain/libelf/elf_memory.c",
    root_path ++ "elftoolchain/libelf/gelf_move.c",
    root_path ++ "elftoolchain/libelf/libelf_shdr.c",
    root_path ++ "elftoolchain/libelf/elf_getident.c",
    root_path ++ "elftoolchain/libelf/elf_getarhdr.c",
    root_path ++ "elftoolchain/libelf/elf_errmsg.c",
    root_path ++ "elftoolchain/libelf/gelf_checksum.c",
    root_path ++ "elftoolchain/libelf/gelf_getclass.c",
    root_path ++ "elftoolchain/libelf/elf.c",
    root_path ++ "elftoolchain/libelf/elf_phnum.c",
    root_path ++ "elftoolchain/libelf/elf_shnum.c",
    root_path ++ "elftoolchain/libelf/libelf_ar.c",
    root_path ++ "elftoolchain/libelf/gelf_symshndx.c",
    root_path ++ "elftoolchain/libelf/elf_errno.c",
    root_path ++ "elftoolchain/libelf/libelf_data.c",
    root_path ++ "elftoolchain/libelf/gelf_fsize.c",
    root_path ++ "elftoolchain/libelf/gelf_cap.c",
    root_path ++ "elftoolchain/libelf/elf_hash.c",
    root_path ++ "elftoolchain/libelf/elf_next.c",
    root_path ++ "elftoolchain/libelf/elf_update.c",
    root_path ++ "elftoolchain/libelf/elf_data.c",
    root_path ++ "elftoolchain/libelf/elf_version.c",
    root_path ++ "elftoolchain/libelf/gelf_ehdr.c",
    root_path ++ "elftoolchain/libelf/libelf_checksum.c",
    root_path ++ "elftoolchain/libelf/libelf_xlate.c",
    root_path ++ "elftoolchain/libelf/elf_scn.c",
    root_path ++ "elftoolchain/libelf/gelf_syminfo.c",
    root_path ++ "elftoolchain/libelf/elf_rawfile.c",
    root_path ++ "elftoolchain/libelf/libelf_align.c",
    root_path ++ "elftoolchain/libelf/gelf_rela.c",
    root_path ++ "elftoolchain/libelf/gelf_sym.c",
    root_path ++ "elftoolchain/libelf/gelf_phdr.c",
    root_path ++ "elftoolchain/libelf/elf_kind.c",
    root_path ++ "elftoolchain/libelf/elf_strptr.c",
    root_path ++ "elftoolchain/libelf/elf_shstrndx.c",
    root_path ++ "elftoolchain/libelf/elf_open.c",
    root_path ++ "elftoolchain/libelf/libelf_open.c",
    root_path ++ "elftoolchain/libelf/gelf_dyn.c",
    root_path ++ "elftoolchain/libelf/elf_fill.c",
    root_path ++ "elftoolchain/libelf/libelf_memory.c",
    root_path ++ "elftoolchain/libelf/gelf_xlate.c",
    root_path ++ "elftoolchain/libelf/gelf_rel.c",
    root_path ++ "elftoolchain/libelf/elf_flag.c",
};
