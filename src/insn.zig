const std = @import("std");
const Helper = @import("user.zig").Helper;
const expectEqual = std.testing.expectEqual;
const fd_t = std.posix.fd_t;
//const defs = @import("flags.zig");

// instruction classes
pub const LD = 0x00;
pub const LDX = 0x01;
pub const ST = 0x02;
pub const STX = 0x03;
pub const ALU = 0x04;
pub const JMP = 0x05;
pub const RET = 0x06;
pub const MISC = 0x07;

/// 32-bit
pub const W = 0x00;
/// 16-bit
pub const H = 0x08;
/// 8-bit
pub const B = 0x10;
/// 64-bit
pub const DW = 0x18;

pub const IMM = 0x00;
pub const ABS = 0x20;
pub const IND = 0x40;
pub const MEM = 0x60;
pub const LEN = 0x80;
pub const MSH = 0xa0;

// alu fields
pub const ADD = 0x00;
pub const SUB = 0x10;
pub const MUL = 0x20;
pub const DIV = 0x30;
pub const OR = 0x40;
pub const AND = 0x50;
pub const LSH = 0x60;
pub const RSH = 0x70;
pub const NEG = 0x80;
pub const MOD = 0x90;
pub const XOR = 0xa0;

// jmp fields
pub const JA = 0x00;
pub const JEQ = 0x10;
pub const JGT = 0x20;
pub const JGE = 0x30;
pub const JSET = 0x40;

//#define BPF_SRC(code)   ((code) & 0x08)
pub const K = 0x00;
pub const X = 0x08;

pub const MAXINSNS = 4096;

// instruction classes
/// jmp mode in word width
pub const JMP32 = 0x06;

/// alu mode in double word width
pub const ALU64 = 0x07;

// ld/ldx fields
/// exclusive add
pub const XADD = 0xc0;

// alu/jmp fields
/// mov reg to reg
pub const MOV = 0xb0;

/// sign extending arithmetic shift right */
pub const ARSH = 0xc0;

// change endianness of a register
/// flags for endianness conversion:
pub const END = 0xd0;

/// convert to little-endian */
pub const TO_LE = 0x00;

/// convert to big-endian
pub const TO_BE = 0x08;
pub const FROM_LE = TO_LE;
pub const FROM_BE = TO_BE;

// jmp encodings
/// jump != *
pub const JNE = 0x50;

/// LT is unsigned, '<'
pub const JLT = 0xa0;

/// LE is unsigned, '<=' *
pub const JLE = 0xb0;

/// SGT is signed '>', GT in x86
pub const JSGT = 0x60;

/// SGE is signed '>=', GE in x86
pub const JSGE = 0x70;

/// SLT is signed, '<'
pub const JSLT = 0xc0;

/// SLE is signed, '<='
pub const JSLE = 0xd0;

/// function call
pub const CALL = 0x80;

/// function return
pub const EXIT = 0x90;

/// When BPF ldimm64's insn[0].src_reg != 0 then this can have two extensions:
/// insn[0].src_reg:  BPF_PSEUDO_MAP_FD   BPF_PSEUDO_MAP_VALUE
/// insn[0].imm:      map fd              map fd
/// insn[1].imm:      0                   offset into value
/// insn[0].off:      0                   0
/// insn[1].off:      0                   0
/// ldimm64 rewrite:  address of map      address of map[0]+offset
/// verifier type:    CONST_PTR_TO_MAP    PTR_TO_MAP_VALUE
pub const PSEUDO_MAP_FD = 1;
pub const PSEUDO_MAP_VALUE = 2;

pub const Insn = packed struct {
    // TODO: determine that this is the expected bit layout for both little and big
    // endian systems
    /// a single BPF instruction
    code: u8,
    dst: u4,
    src: u4,
    off: i16,
    imm: i32,

    /// r0 - r9 are general purpose 64-bit registers, r10 points to the stack
    /// frame
    pub const Reg = enum(u4) { r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 };
    const Source = enum(u1) { reg, imm };

    const Mode = enum(u8) {
        imm = IMM,
        abs = ABS,
        ind = IND,
        mem = MEM,
        len = LEN,
        msh = MSH,
    };

    const AluOp = enum(u8) {
        add = ADD,
        sub = SUB,
        mul = MUL,
        div = DIV,
        alu_or = OR,
        alu_and = AND,
        lsh = LSH,
        rsh = RSH,
        neg = NEG,
        mod = MOD,
        xor = XOR,
        mov = MOV,
        arsh = ARSH,
    };

    pub const Size = enum(u8) {
        byte = B,
        half_word = H,
        word = W,
        double_word = DW,
    };

    const JmpOp = enum(u8) {
        ja = JA,
        jeq = JEQ,
        jgt = JGT,
        jge = JGE,
        jset = JSET,
        jlt = JLT,
        jle = JLE,
        jne = JNE,
        jsgt = JSGT,
        jsge = JSGE,
        jslt = JSLT,
        jsle = JSLE,
    };

    const ImmOrReg = union(Source) {
        reg: Reg,
        imm: i32,
    };

    fn imm_reg(code: u8, dst: Reg, src: anytype, off: i16) Insn {
        const imm_or_reg = if (@typeInfo(@TypeOf(src)) == .EnumLiteral)
            ImmOrReg{ .reg = @as(Reg, src) }
        else
            ImmOrReg{ .imm = src };

        const src_type = switch (imm_or_reg) {
            .imm => K,
            .reg => X,
        };

        return Insn{
            .code = code | src_type,
            .dst = @intFromEnum(dst),
            .src = switch (imm_or_reg) {
                .imm => 0,
                .reg => |r| @intFromEnum(r),
            },
            .off = off,
            .imm = switch (imm_or_reg) {
                .imm => |i| i,
                .reg => 0,
            },
        };
    }

    fn alu(comptime width: comptime_int, op: AluOp, dst: Reg, src: anytype) Insn {
        const width_bitfield = switch (width) {
            32 => ALU,
            64 => ALU64,
            else => @compileError("width must be 32 or 64"),
        };

        return imm_reg(width_bitfield | @intFromEnum(op), dst, src, 0);
    }

    pub fn mov(dst: Reg, src: anytype) Insn {
        return alu(64, .mov, dst, src);
    }

    pub fn add(dst: Reg, src: anytype) Insn {
        return alu(64, .add, dst, src);
    }

    pub fn sub(dst: Reg, src: anytype) Insn {
        return alu(64, .sub, dst, src);
    }

    pub fn mul(dst: Reg, src: anytype) Insn {
        return alu(64, .mul, dst, src);
    }

    pub fn div(dst: Reg, src: anytype) Insn {
        return alu(64, .div, dst, src);
    }

    pub fn alu_or(dst: Reg, src: anytype) Insn {
        return alu(64, .alu_or, dst, src);
    }

    pub fn alu_and(dst: Reg, src: anytype) Insn {
        return alu(64, .alu_and, dst, src);
    }

    pub fn lsh(dst: Reg, src: anytype) Insn {
        return alu(64, .lsh, dst, src);
    }

    pub fn rsh(dst: Reg, src: anytype) Insn {
        return alu(64, .rsh, dst, src);
    }

    pub fn neg(dst: Reg) Insn {
        return alu(64, .neg, dst, 0);
    }

    pub fn mod(dst: Reg, src: anytype) Insn {
        return alu(64, .mod, dst, src);
    }

    pub fn xor(dst: Reg, src: anytype) Insn {
        return alu(64, .xor, dst, src);
    }

    pub fn arsh(dst: Reg, src: anytype) Insn {
        return alu(64, .arsh, dst, src);
    }

    fn jmp(op: JmpOp, dst: Reg, src: anytype, off: i16) Insn {
        return imm_reg(JMP | @intFromEnum(op), dst, src, off);
    }

    pub fn ja(off: i16) Insn {
        return jmp(.ja, .r0, 0, off);
    }

    pub fn jeq(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jeq, dst, src, off);
    }

    pub fn jgt(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jgt, dst, src, off);
    }

    pub fn jge(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jge, dst, src, off);
    }

    pub fn jlt(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jlt, dst, src, off);
    }

    pub fn jle(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jle, dst, src, off);
    }

    pub fn jset(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jset, dst, src, off);
    }

    pub fn jne(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jne, dst, src, off);
    }

    pub fn jsgt(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jsgt, dst, src, off);
    }

    pub fn jsge(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jsge, dst, src, off);
    }

    pub fn jslt(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jslt, dst, src, off);
    }

    pub fn jsle(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jsle, dst, src, off);
    }

    pub fn xadd(dst: Reg, src: Reg) Insn {
        return Insn{
            .code = STX | XADD | DW,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = 0,
            .imm = 0,
        };
    }

    fn ld(mode: Mode, size: Size, dst: Reg, src: Reg, imm: i32) Insn {
        return Insn{
            .code = @intFromEnum(mode) | @intFromEnum(size) | LD,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = 0,
            .imm = imm,
        };
    }

    pub fn ld_abs(size: Size, dst: Reg, src: Reg, imm: i32) Insn {
        return ld(.abs, size, dst, src, imm);
    }

    pub fn ld_ind(size: Size, dst: Reg, src: Reg, imm: i32) Insn {
        return ld(.ind, size, dst, src, imm);
    }

    pub fn ldx(size: Size, dst: Reg, src: Reg, off: i16) Insn {
        return Insn{
            .code = MEM | @intFromEnum(size) | LDX,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = off,
            .imm = 0,
        };
    }

    fn ld_imm_impl1(dst: Reg, src: Reg, imm: u64) Insn {
        return Insn{
            .code = LD | DW | IMM,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = 0,
            .imm = @intCast(@as(u32, @truncate(imm))),
        };
    }

    fn ld_imm_impl2(imm: u64) Insn {
        return Insn{
            .code = 0,
            .dst = 0,
            .src = 0,
            .off = 0,
            .imm = @intCast(@as(u32, @truncate(imm >> 32))),
        };
    }

    pub fn ld_dw1(dst: Reg, imm: u64) Insn {
        return ld_imm_impl1(dst, .r0, imm);
    }

    pub fn ld_dw2(imm: u64) Insn {
        return ld_imm_impl2(imm);
    }

    pub fn ld_map_fd1(dst: Reg, map_fd: fd_t) Insn {
        return ld_imm_impl1(dst, @enumFromInt(PSEUDO_MAP_FD), @intCast(map_fd));
    }

    pub fn ld_map_fd2(map_fd: fd_t) Insn {
        return ld_imm_impl2(@intCast(map_fd));
    }

    pub fn st(comptime size: Size, dst: Reg, off: i16, imm: i32) Insn {
        if (size == .double_word) @compileError("TODO: need to determine how to correctly handle double words");
        return Insn{
            .code = MEM | @intFromEnum(size) | ST,
            .dst = @intFromEnum(dst),
            .src = 0,
            .off = off,
            .imm = imm,
        };
    }

    pub fn stx(size: Size, dst: Reg, off: i16, src: Reg) Insn {
        return Insn{
            .code = MEM | @intFromEnum(size) | STX,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = off,
            .imm = 0,
        };
    }

    fn endian_swap(endian: std.builtin.Endian, comptime size: Size, dst: Reg) Insn {
        return Insn{
            .code = switch (endian) {
                .big => 0xdc,
                .little => 0xd4,
            },
            .dst = @intFromEnum(dst),
            .src = 0,
            .off = 0,
            .imm = switch (size) {
                .byte => @compileError("can't swap a single byte"),
                .half_word => 16,
                .word => 32,
                .double_word => 64,
            },
        };
    }

    pub fn le(comptime size: Size, dst: Reg) Insn {
        return endian_swap(.little, size, dst);
    }

    pub fn be(comptime size: Size, dst: Reg) Insn {
        return endian_swap(.big, size, dst);
    }

    pub fn call(helper: Helper) Insn {
        return Insn{
            .code = JMP | CALL,
            .dst = 0,
            .src = 0,
            .off = 0,
            .imm = @intFromEnum(helper),
        };
    }

    /// exit BPF program
    pub fn exit() Insn {
        return Insn{
            .code = JMP | EXIT,
            .dst = 0,
            .src = 0,
            .off = 0,
            .imm = 0,
        };
    }
};

test "insn bitsize" {
    try expectEqual(64, @bitSizeOf(Insn));
}

// The opcodes were grabbed from https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
test "opcodes" {
    // instructions that have a name that end with 1 or 2 are consecutive for
    // loading 64-bit immediates (imm is only 32 bits wide)

    // alu instructions
    try expectEqual(0x07, Insn.add(.r1, 0).code);
    try expectEqual(0x0f, Insn.add(.r1, .r2).code);
    try expectEqual(0x17, Insn.sub(.r1, 0).code);
    try expectEqual(0x1f, Insn.sub(.r1, .r2).code);
    try expectEqual(0x27, Insn.mul(.r1, 0).code);
    try expectEqual(0x2f, Insn.mul(.r1, .r2).code);
    try expectEqual(0x37, Insn.div(.r1, 0).code);
    try expectEqual(0x3f, Insn.div(.r1, .r2).code);
    try expectEqual(0x47, Insn.alu_or(.r1, 0).code);
    try expectEqual(0x4f, Insn.alu_or(.r1, .r2).code);
    try expectEqual(0x57, Insn.alu_and(.r1, 0).code);
    try expectEqual(0x5f, Insn.alu_and(.r1, .r2).code);
    try expectEqual(0x67, Insn.lsh(.r1, 0).code);
    try expectEqual(0x6f, Insn.lsh(.r1, .r2).code);
    try expectEqual(0x77, Insn.rsh(.r1, 0).code);
    try expectEqual(0x7f, Insn.rsh(.r1, .r2).code);
    try expectEqual(0x87, Insn.neg(.r1).code);
    try expectEqual(0x97, Insn.mod(.r1, 0).code);
    try expectEqual(0x9f, Insn.mod(.r1, .r2).code);
    try expectEqual(0xa7, Insn.xor(.r1, 0).code);
    try expectEqual(0xaf, Insn.xor(.r1, .r2).code);
    try expectEqual(0xb7, Insn.mov(.r1, 0).code);
    try expectEqual(0xbf, Insn.mov(.r1, .r2).code);
    try expectEqual(0xc7, Insn.arsh(.r1, 0).code);
    try expectEqual(0xcf, Insn.arsh(.r1, .r2).code);

    // atomic instructions: might be more of these not documented in the wild
    try expectEqual(0xdb, Insn.xadd(.r1, .r2).code);

    // TODO: byteswap instructions
    try expectEqual(0xd4, Insn.le(.half_word, .r1).code);
    try expectEqual(16, Insn.le(.half_word, .r1).imm);
    try expectEqual(0xd4, Insn.le(.word, .r1).code);
    try expectEqual(32, Insn.le(.word, .r1).imm);
    try expectEqual(0xd4, Insn.le(.double_word, .r1).code);
    try expectEqual(64, Insn.le(.double_word, .r1).imm);
    try expectEqual(0xdc, Insn.be(.half_word, .r1).code);
    try expectEqual(16, Insn.be(.half_word, .r1).imm);
    try expectEqual(0xdc, Insn.be(.word, .r1).code);
    try expectEqual(32, Insn.be(.word, .r1).imm);
    try expectEqual(0xdc, Insn.be(.double_word, .r1).code);
    try expectEqual(64, Insn.be(.double_word, .r1).imm);

    // memory instructions
    try expectEqual(0x18, Insn.ld_dw1(.r1, 0).code);
    try expectEqual(0x00, Insn.ld_dw2(0).code);

    //   loading a map fd
    try expectEqual(0x18, Insn.ld_map_fd1(.r1, 0).code);
    try expectEqual(PSEUDO_MAP_FD, Insn.ld_map_fd1(.r1, 0).src);
    try expectEqual(0x00, Insn.ld_map_fd2(0).code);

    try expectEqual(0x38, Insn.ld_abs(.double_word, .r1, .r2, 0).code);
    try expectEqual(0x20, Insn.ld_abs(.word, .r1, .r2, 0).code);
    try expectEqual(0x28, Insn.ld_abs(.half_word, .r1, .r2, 0).code);
    try expectEqual(0x30, Insn.ld_abs(.byte, .r1, .r2, 0).code);

    try expectEqual(0x58, Insn.ld_ind(.double_word, .r1, .r2, 0).code);
    try expectEqual(0x40, Insn.ld_ind(.word, .r1, .r2, 0).code);
    try expectEqual(0x48, Insn.ld_ind(.half_word, .r1, .r2, 0).code);
    try expectEqual(0x50, Insn.ld_ind(.byte, .r1, .r2, 0).code);

    try expectEqual(0x79, Insn.ldx(.double_word, .r1, .r2, 0).code);
    try expectEqual(0x61, Insn.ldx(.word, .r1, .r2, 0).code);
    try expectEqual(0x69, Insn.ldx(.half_word, .r1, .r2, 0).code);
    try expectEqual(0x71, Insn.ldx(.byte, .r1, .r2, 0).code);

    try expectEqual(0x62, Insn.st(.word, .r1, 0, 0).code);
    try expectEqual(0x6a, Insn.st(.half_word, .r1, 0, 0).code);
    try expectEqual(0x72, Insn.st(.byte, .r1, 0, 0).code);

    try expectEqual(0x63, Insn.stx(.word, .r1, 0, .r2).code);
    try expectEqual(0x6b, Insn.stx(.half_word, .r1, 0, .r2).code);
    try expectEqual(0x73, Insn.stx(.byte, .r1, 0, .r2).code);
    try expectEqual(0x7b, Insn.stx(.double_word, .r1, 0, .r2).code);

    // branch instructions
    try expectEqual(0x05, Insn.ja(0).code);
    try expectEqual(0x15, Insn.jeq(.r1, 0, 0).code);
    try expectEqual(0x1d, Insn.jeq(.r1, .r2, 0).code);
    try expectEqual(0x25, Insn.jgt(.r1, 0, 0).code);
    try expectEqual(0x2d, Insn.jgt(.r1, .r2, 0).code);
    try expectEqual(0x35, Insn.jge(.r1, 0, 0).code);
    try expectEqual(0x3d, Insn.jge(.r1, .r2, 0).code);
    try expectEqual(0xa5, Insn.jlt(.r1, 0, 0).code);
    try expectEqual(0xad, Insn.jlt(.r1, .r2, 0).code);
    try expectEqual(0xb5, Insn.jle(.r1, 0, 0).code);
    try expectEqual(0xbd, Insn.jle(.r1, .r2, 0).code);
    try expectEqual(0x45, Insn.jset(.r1, 0, 0).code);
    try expectEqual(0x4d, Insn.jset(.r1, .r2, 0).code);
    try expectEqual(0x55, Insn.jne(.r1, 0, 0).code);
    try expectEqual(0x5d, Insn.jne(.r1, .r2, 0).code);
    try expectEqual(0x65, Insn.jsgt(.r1, 0, 0).code);
    try expectEqual(0x6d, Insn.jsgt(.r1, .r2, 0).code);
    try expectEqual(0x75, Insn.jsge(.r1, 0, 0).code);
    try expectEqual(0x7d, Insn.jsge(.r1, .r2, 0).code);
    try expectEqual(0xc5, Insn.jslt(.r1, 0, 0).code);
    try expectEqual(0xcd, Insn.jslt(.r1, .r2, 0).code);
    try expectEqual(0xd5, Insn.jsle(.r1, 0, 0).code);
    try expectEqual(0xdd, Insn.jsle(.r1, .r2, 0).code);
    try expectEqual(0x85, Insn.call(.unspec).code);
    try expectEqual(0x95, Insn.exit().code);
}
