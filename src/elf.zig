const std = @import("std");
pub usingnamespace std.elf;

pub fn offset_to_value(comptime T: type, buf: []const u8, offset: usize) T {
    var ret: T = undefined;
    std.mem.copy(u8, std.mem.asBytes(&ret), buf[offset .. offset + @sizeOf(T)]);
    return ret;
}

fn get_header(comptime elf: []u8) *Elf64_Ehdr {
    return @ptrCast(*Elf64_Ehdr, elf.ptr);
}

fn strtab_get_str(strtab: []const u8, offset: usize) []const u8 {
    return for (strtab[offset..]) |c, i| {
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

    for (sections) |section| {
        const section_name = strtab_get_str(&strtab, section.sh_name);
        if (std.mem.eql(u8, section_name, name)) {
            return true;
        }
    } else return false;
}

pub fn has_map(comptime elf: []const u8, comptime name: []const u8) bool {
    const header = get_header(elf);
    //const header = std.mem.bytesToValue(Elf64_Ehdr, elf[0..@sizeOf(Elf64_Ehdr)]);
    const sections = offset_to_value([header.e_shnum]Elf64_Shdr, elf, header.e_shoff);

    const strtab = for (sections) |section| {
        if (section.sh_type == SHT_STRTAB)
            break offset_to_value([section.sh_size]u8, elf, section.sh_offset);
    } else @compileError("strtab not found");

    const symtab = for (sections) |section| {
        if (section.sh_type == SHT_SYMTAB) {
            break offset_to_value([section.sh_size]u8, probe, section.sh_offset);
        }
    } else @compileError("symtab not found");

    const maps = for (sections) |section| {
        const section_name = strtab_get_str(&strtab, section.sh_name);
        if (std.mem.eql(u8, section_name, ".maps")) {
            break offset_to_value([section.sh_size]u8, probe, section.sh_offset);
        }
    } else @compileError(".maps section not found");

    const btf = for (sections) |section| {
        const section_name = strtab_get_str(&strtab, section.sh_name);
        if (std.mem.eql(u8, section_name, ".BTF")) {
            break offset_to_value([section.sh_size]u8, probe, section.sh_offset);
        }
    } else @compileError("failed to find .maps section");

    // TODO: lookup symbol
}
