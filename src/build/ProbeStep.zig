const std = @import("std");
const Step = std.build.Step;
const Builder = std.build.Builder;
const LibExeObjStep = std.build.LibExeObjStep;
const assert = std.debug.assert;

const Self = @This();

// TODO: install()

step: Step,
builder: *Builder,
probe: *LibExeObjStep,
out_filename: []const u8,

pub fn create(builder: *Builder, name: []const u8, root: []const u8) !*Self {
    var ret = try builder.allocator.create(Self);
    errdefer builder.allocator.destroy(ret);

    ret.* = Self{
        .probe = builder.addObject(name, root),
        .builder = builder,
        .step = Step.init(.custom, "bpf_probe", builder.allocator, make),
        .out_filename = try std.fs.path.join(builder.allocator, &.{
            builder.cache_root,
            "bpf",
            "probes",
            try std.fmt.allocPrint(builder.allocator, "{s}.o", .{name}),
        }),
    };

    const llvm_ir_path = try std.fs.path.join(builder.allocator, &.{
        builder.cache_root,
        "bpf",
        "llvm_ir",
        try std.fmt.allocPrint(builder.allocator, "{s}.ll", .{name}),
    });

    try std.fs.cwd().makePath(std.fs.path.dirname(llvm_ir_path).?);
    ret.probe.emit_llvm_ir = .{ .emit_to = llvm_ir_path };
    ret.probe.setTarget(std.zig.CrossTarget{
        .cpu_arch = .bpfel,
        .os_tag = .freestanding,
    });

    ret.probe.setBuildMode(.ReleaseSmall);
    ret.probe.addPackagePath("bpf", comptime std.fs.path.dirname(@src().file).? ++ std.fs.path.sep_str ++ "kernel.zig");
    ret.probe.link_emit_relocs = true;
    ret.step.dependOn(&ret.probe.step);
    return ret;
}

/// libbpf v0.5 (current latest release) requires the read-only data section to
/// be named '.rodata', where zig (and it seems newer versions of clang)
/// outputs it in a section named '.rodata.str1.1'. There is a patch in libbpf
/// that fixes this, and will probably get released with v0.6.
fn renameRodata(text: []align(@alignOf(std.elf.Ehdr)) u8) !void {
    const elf_header = @ptrCast(*std.elf.Ehdr, @alignCast(@alignOf(*std.elf.Ehdr), text.ptr));
    assert(elf_header.e_ident[std.elf.EI_CLASS] == 2); // only 64-bit (is there 32-bit bpf?)
    const section_headers = std.mem.bytesAsSlice(
        std.elf.Elf64_Shdr,
        text[elf_header.e_shoff .. elf_header.e_shoff + (elf_header.e_shnum * elf_header.e_shentsize)],
    );

    const strtab = for (section_headers) |header| {
        if (header.sh_type == std.elf.SHT_STRTAB)
            break text[header.sh_offset .. header.sh_offset + header.sh_size];
    } else {
        std.log.err("failed to find the strtab section (it contains all the strings)", .{});
        return error.NoStrtab;
    };

    var rodata_count: usize = 0;
    for (section_headers) |header| {
        if (header.sh_type == std.elf.SHT_PROGBITS and header.sh_size > 0) {
            const name = std.mem.span(@ptrCast([*:0]u8, strtab[header.sh_name..].ptr));
            const rodata_sec = ".rodata";
            if (std.mem.startsWith(u8, name, rodata_sec)) {
                assert(rodata_count == 0); // there must only be one section that starts with '.rodata'
                std.mem.set(u8, name[rodata_sec.len..], 0);
                rodata_count += 1;
            }
        }
    }
}

fn make(step: *Step) !void {
    const self = @fieldParentPtr(Self, "step", step);

    const file = try std.fs.openFileAbsolute(self.probe.output_path_source.getPath(), .{});
    defer file.close();

    const text = try file.readToEndAllocOptions(
        self.builder.allocator,
        std.math.maxInt(usize),
        null,
        @alignOf(std.elf.Ehdr),
        null,
    );
    defer self.builder.allocator.free(text);

    // parse ELF here
    try renameRodata(text);
    // TODO: BTF remapping

    const out_dir_path = try std.fs.path.join(self.builder.allocator, &.{
        self.builder.cache_root,
        "bpf",
        "probes",
    });
    defer self.builder.allocator.free(out_dir_path);

    try std.fs.cwd().makePath(out_dir_path);
    const out_file = try std.fs.cwd().createFile(self.out_filename, .{
        .truncate = true,
    });
    defer out_file.close();

    try out_file.writer().writeAll(text);
}
