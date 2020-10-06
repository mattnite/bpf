usingnamespace @import("elf.zig");
const std = @import("std");
const Program = @import("program.zig");

const mem = std.mem;
const os = std.os;
const fd_t = std.os.fd_t;
const BPF = std.os.linux.BPF;
const MapDef = std.os.linux.BPF.kern.MapDef;

allocator: *mem.Allocator,
elf: Elf,
maps: std.ArrayListUnmanaged(MapInfo),
progs: std.ArrayListUnmanaged(Program),

const Self = @This();

const RelocDesc = struct {
    type: Type,
    insn_idx: usize,
    map_idx: usize,
    sym_off: usize,

    const Type = enum {
        ld64,
        data,
        relo_extern,
        call,
    };
};

const MapInfo = struct {
    name: []const u8,
    fd: ?fd_t,
    def: MapDef,
};

const Elf = struct {
    header: Elf64_Ehdr,
    sections: []Section,
    strtab: *Section,
    symtab: *Section,
    relos: std.ArrayListUnmanaged(*Section),
    progs: std.ArrayListUnmanaged(*Section),
    license: ?*Section = null,
    version: ?*Section = null,
    maps: ?*Section = null,
    btf_maps: ?*Section = null,
    btf: ?*Section = null,
    btf_ext: ?*Section = null,
    text: ?*Section = null,
    data: ?*Section = null,
    rodata: ?*Section = null,
    st_ops: ?*Section = null,
    bss: ?*Section = null,

    const BTF_ELF_SEC = ".BTF";
    const BTF_EXT_ELF_SEC = BTF_ELF_SEC ++ ".ext";
    const MAPS_ELF_SEC = ".maps";
    const DATA_SEC = ".data";
    const BSS_SEC = ".bss";
    const RODATA_SEC = ".rodata";
    const KCONFIG_SEC = ".kconfig";
    const KSYMS_SEC = ".ksyms";
    const STRUCT_OPS_SEC = ".struct_ops";

    const Section = struct {
        header: Elf64_Shdr,
        idx: usize,
        data: []u8,
    };

    pub fn get_sym_idx(self: *const @This(), idx: usize) Elf64_Sym {
        return std.mem.bytesAsSlice(Elf64_Sym, self.symtab.data)[idx];
    }

    pub fn get_sym_offset(self: *const @This(), offset: usize) Elf64_Sym {
        return self.get_sym_idx(offset / @sizeOf(Elf64_Sym));
    }

    pub fn get_str(self: *const @This(), offset: usize) []const u8 {
        return for (self.strtab.data[offset..]) |c, i| {
            if (c == 0) {
                break self.strtab.data[offset .. offset + i];
            }
        } else "";
    }

    pub fn get_section_name(self: *const @This(), section: *const Section) []const u8 {
        return self.get_str(section.header.sh_name);
    }

    fn search_sections(self: *@This(), allocator: *mem.Allocator) !void {
        for (self.sections) |*section| {
            const name = self.get_section_name(section);

            if (mem.eql(u8, name, "license")) {
                self.license = section;
            } else if (mem.eql(u8, name, "version")) {
                self.version = section;
            } else if (mem.eql(u8, name, "maps")) {
                self.maps = section;
            } else if (mem.eql(u8, name, MAPS_ELF_SEC)) {
                self.btf_maps = section;
            } else if (mem.eql(u8, name, BTF_ELF_SEC)) {
                self.btf = section;
            } else if (mem.eql(u8, name, BTF_EXT_ELF_SEC)) {
                self.btf_ext = section;
            } else if (section.header.sh_type == SHT_PROGBITS and section.data.len > 0) {
                if ((section.header.sh_flags & SHF_EXECINSTR) > 0) {
                    if (mem.eql(u8, name, ".text")) {
                        self.text = section;
                    } else {
                        try self.progs.append(allocator, section);
                    }
                } else if (mem.eql(u8, name, DATA_SEC)) {
                    self.data = section;
                } else if (mem.eql(u8, name, RODATA_SEC)) {
                    self.rodata = section;
                } else if (mem.eql(u8, name, STRUCT_OPS_SEC)) {
                    self.st_ops = section;
                }
            } else if (section.header.sh_type == SHT_REL) {
                try self.relos.append(allocator, section);
            } else if (section.header.sh_type == SHT_NOBITS and mem.eql(u8, name, BSS_SEC)) {
                self.bss = section;
            }
        }
    }

    pub fn init(allocator: *mem.Allocator, elf_buf: []const u8) !Elf {
        var header = offset_to_value(Elf64_Ehdr, elf_buf, 0);
        var sections = try allocator.alloc(Section, header.e_shnum);
        var strtab: ?*Section = null;
        var symtab: ?*Section = null;

        for (sections) |*section, i| {
            var section_header = offset_to_value(
                Elf64_Shdr,
                elf_buf,
                header.e_shoff + (i * @sizeOf(Elf64_Shdr)),
            );

            section.* = Section{
                .header = section_header,
                .idx = i,
                .data = try allocator.alloc(u8, section_header.sh_size),
            };

            const offset = section_header.sh_offset;
            std.mem.copy(u8, section.data, elf_buf[offset .. offset +
                section_header.sh_size]);

            // search for special sections
            switch (section_header.sh_type) {
                SHT_STRTAB => {
                    if (strtab == null) {
                        strtab = section;
                    } else {
                        return error.MultipleStrtab;
                    }
                },
                SHT_SYMTAB => {
                    if (symtab == null) {
                        symtab = section;
                    } else {
                        return error.MultipleSymtab;
                    }
                },
                else => {},
            }
        }

        if (strtab == null) return error.NoStrtab;
        if (symtab == null) return error.NoSymtab;

        var ret = Elf{
            .header = header,
            .sections = sections,
            .strtab = strtab.?,
            .symtab = symtab.?,
            .relos = std.ArrayListUnmanaged(*Section){},
            .progs = std.ArrayListUnmanaged(*Section){},
        };

        // now that we have the required fields, search through fields
        try ret.search_sections(allocator);
        return ret;
    }

    pub fn deinit(self: *@This(), allocator: *mem.Allocator) void {
        self.relos.deinit(allocator);
        for (self.sections) |section| {
            allocator.free(section.data);
        }

        allocator.free(self.sections);
    }
};

fn init_maps(allocator: *mem.Allocator, elf: *const Elf) !std.ArrayListUnmanaged(MapInfo) {
    var ret = std.ArrayListUnmanaged(MapInfo){};
    errdefer ret.deinit(allocator);

    if (elf.maps) |maps| {
        const maps_idx = for (elf.sections) |*section, i| {
            if (maps.data.ptr == section.data.ptr) {
                break i;
            }
        } else unreachable;

        for (std.mem.bytesAsSlice(Elf64_Sym, elf.symtab.data)) |symbol| {
            if (symbol.st_shndx != maps_idx)
                continue;

            //std.debug.print("got a map symbol\n", .{});
            //std.debug.print("size: {}\n", .{symbol.st_size});
            // size must be a multiple of MapDef size
            //if (symbol.st_size != @sizeOf(MapDef)) {
            //    return error.InvalidMapsSize;
            //}

            try ret.append(allocator, MapInfo{
                .name = elf.get_str(symbol.st_name),
                .def = offset_to_value(MapDef, maps.data, symbol.st_value),
                .fd = null,
            });
        }
    }

    return ret;
}

fn init_progs(allocator: *mem.Allocator, elf: *const Elf) !std.ArrayListUnmanaged(Program) {
    var ret = std.ArrayListUnmanaged(Program){};
    errdefer ret.deinit(allocator);

    for (elf.progs.items) |prog| {
        const name = elf.get_section_name(prog);
        try ret.append(allocator, Program{
            .name = name,
            // TODO: detect program type
            .type = .socket_filter,
            .insns = std.mem.bytesAsSlice(BPF.Insn, prog.data),
            .fd = null,
        });
    }

    return ret;
}

fn collect_st_ops_relos(self: *Self, section: *Elf.Section) !void {
    const name = self.elf.get_section_name(section);
    //std.debug.print("got st ops relo: {}\n", .{name});
}
fn collect_map_relos(self: *Self, section: *Elf.Section) !void {
    const name = self.elf.get_section_name(section);
    //std.debug.print("got btf map relo: {}\n", .{name});
}

fn collect_prog_relos(self: *Self, section: *Elf.Section) !void {
    const name = self.elf.get_section_name(section);
    var target = &self.elf.sections[section.header.sh_info];

    const num = section.header.sh_size / section.header.sh_entsize;
    for (mem.bytesAsSlice(Elf64_Rel, section.data)) |rel, i| {

        // get symbol
        const sym = self.elf.get_sym_idx(@truncate(u32, rel.r_info >> 32));
        //std.debug.print("{x}\n", .{rel.r_info});
        //std.debug.print("{}\n", .{rel});
        const insn_idx = rel.r_offset / @sizeOf(BPF.Insn);

        const sym_name = if (@truncate(u4, rel.r_info) == STT_SECTION and sym.st_name == 0)
            name
        else
            self.elf.get_str(sym.st_name);

        //std.debug.print("sec {}: relo #{}: insn #{} against '{}'\n", .{ name, i, insn_idx, sym_name });
        //std.debug.print("{}\n", .{sym});
    }
}

fn collect_relos(self: *Self) !void {
    //std.debug.print("num relo sections: {}\n", .{self.elf.relos.items.len});
    for (self.elf.relos.items) |section| {
        //std.debug.print("{}\n", .{section.header});
        if (section.header.sh_type != SHT_REL) unreachable;

        const idx = section.header.sh_info;

        if (self.elf.st_ops) |st_ops| {
            if (idx == st_ops.idx) {
                try self.collect_st_ops_relos(section);
                return;
            }
        }

        if (self.elf.btf_maps) |btf_maps| {
            if (idx == btf_maps.idx) {
                try self.collect_map_relos(section);
                return;
            }
        }

        try self.collect_prog_relos(section);

        // sort prog relos for some reason
    }
}

pub fn init(allocator: *mem.Allocator, elf_obj: []const u8) !Self {
    // check endianness
    //     error if it doesn't match
    const elf = try Elf.init(allocator, elf_obj);
    // collect externs
    // finalize btf
    // init maps
    const maps = try init_maps(allocator, &elf);

    //     init user btf maps
    //     init global data maps
    //     init kconfig kconfig map
    //     init struct ops maps
    const progs = try init_progs(allocator, &elf);

    var ret = Self{
        .allocator = allocator,
        .elf = elf,
        .maps = maps,
        .progs = progs,
    };

    try ret.collect_relos();
    return ret;
}

pub fn deinit(self: *Self) void {
    self.elf.deinit(self.allocator);
    self.maps.deinit(self.allocator);
    self.progs.deinit(self.allocator);
}

pub fn load(self: *Self) !void {
    // probe loading
    // probe caps
    // resolve externs
    // sanitize and load btf
    // sanitize maps
    // load vmlinux btf
    // init kern struct ops maps
    for (self.maps.items) |*m| {
        m.fd = try BPF.map_create(@intToEnum(BPF.MapType, m.def.type), m.def.key_size, m.def.value_size, m.def.max_entries);
        //std.debug.print("made map: {}\n", .{m.fd});
        errdefer os.close(m.fd);
    }

    for (self.progs.items) |*prog| {
        const rel_name = try std.mem.join(self.allocator, "", &[_][]const u8{ ".rel", prog.name });
        defer self.allocator.free(rel_name);

        //std.debug.print("rel_name: {}\n", .{rel_name});

        const rel_section: *Elf.Section = for (self.elf.relos.items) |relo| {
            if (mem.eql(u8, self.elf.get_section_name(relo), rel_name)) {
                break relo;
            }
        } else continue;

        for (std.mem.bytesAsSlice(Elf64_Rel, rel_section.data)) |relo| {
            const insn_idx = relo.r_offset / @sizeOf(BPF.Insn);
            const symbol = self.elf.get_sym_idx(@truncate(u32, relo.r_info >> 32));
            // TODO: make get_str return optional
            //std.debug.print("symbol: {}\n", .{symbol});
            const map_name = self.elf.get_str(symbol.st_name);

            const map_fd = for (self.maps.items) |m| {
                if (mem.eql(u8, m.name, map_name)) {
                    break m.fd.?;
                }
            } else continue;

            prog.insns[insn_idx].src = BPF.PSEUDO_MAP_FD;
            prog.insns[insn_idx].imm = map_fd;
        }

        try prog.load("GPL", 0);
    }
}

pub fn unload(self: *Self) void {
    for (self.progs.items) |*prog| {
        prog.unload();
    }

    for (self.maps.items) |*m| {
        os.close(m.fd.?);
    }
}

pub fn find_prog(self: *Self, name: []const u8) ?fd_t {
    return for (self.progs.items) |prog| {
        if (mem.eql(u8, prog.name, name)) {
            break prog.fd;
        }
    } else null;
}

pub fn find_map(self: *Self, name: []const u8) ?fd_t {
    return for (self.maps.items) |m| {
        if (mem.eql(u8, m.name, name)) {
            break m.fd;
        }
    } else null;
}
