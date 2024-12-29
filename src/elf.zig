const std = @import("std");
const Elf64_Ehdr = std.elf.Elf64_Ehdr;
const Elf64_Shdr = std.elf.Elf64_Shdr;
const SHT_STRTAB = std.elf.SHT_STRTAB;
const SHT_SYMTAB = std.elf.SHT_SYMTAB;

pub fn offset_to_value(comptime T: type, buf: []const u8, offset: usize) T {
    var ret: T = undefined;
    std.mem.copy(u8, std.mem.asBytes(&ret), buf[offset .. offset + @sizeOf(T)]);
    return ret;
}

fn get_header(comptime elf: []const u8) *const Elf64_Ehdr {
    return @ptrCast(elf.ptr);
}

fn strtab_get_str(strtab: []const u8, offset: usize) []const u8 {
    return for (strtab[offset..], 0..) |c, i| {
        if (c == 0) {
            break strtab[offset .. offset + i];
        }
    } else "";
}

pub fn has_section(comptime elf: []const u8, comptime name: []const u8) bool {
    const header = std.mem.bytesToValue(Elf64_Ehdr, elf[0..@sizeOf(Elf64_Ehdr)]);

    const sections = offset_to_value([header.e_shnum]Elf64_Shdr, elf, header.e_shoff);
    const strtab = for (sections) |section| {
        if (section.sh_type == SHT_STRTAB)
            break offset_to_value([section.sh_size]u8, elf, section.sh_offset);
    } else @compileError("strtab not found");

    return for (sections) |section| {
        const section_name = strtab_get_str(&strtab, section.sh_name);
        if (std.mem.eql(u8, section_name, name)) {
            break true;
        }
    } else false;
}

pub fn has_map(comptime elf: []const u8, comptime name: []const u8) bool {
    _ = name;
    const header = get_header(elf);
    //const header = std.mem.bytesToValue(Elf64_Ehdr, elf[0..@sizeOf(Elf64_Ehdr)]);
    const sections = offset_to_value([header.e_shnum]Elf64_Shdr, elf, header.e_shoff);

    const strtab = for (sections) |section| {
        if (section.sh_type == SHT_STRTAB)
            break offset_to_value([section.sh_size]u8, elf, section.sh_offset);
    } else @compileError("strtab not found");

    const symtab = for (sections) |section| {
        if (section.sh_type == SHT_SYMTAB) {
            break offset_to_value([section.sh_size]u8, elf, section.sh_offset);
        }
    } else @compileError("symtab not found");
    _ = symtab;

    const maps = for (sections) |section| {
        const section_name = strtab_get_str(&strtab, section.sh_name);
        if (std.mem.eql(u8, section_name, "maps") or std.mem.eql(u8, section_name, ".maps")) {
            break offset_to_value([section.sh_size]u8, elf, section.sh_offset);
        }
    } else @compileError(".maps section not found");
    _ = maps;

    const btf = for (sections) |section| {
        const section_name = strtab_get_str(&strtab, section.sh_name);
        if (std.mem.eql(u8, section_name, ".BTF")) {
            break offset_to_value([section.sh_size]u8, elf, section.sh_offset);
        }
    } else @compileError("failed to find .maps section");
    _ = btf;

    // TODO: lookup symbol
}
