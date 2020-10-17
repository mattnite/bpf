usingnamespace @import("flags.zig");
const std = @import("std");
const Helper = @import("user.zig").Helper;
const expectEqual = std.testing.expectEqual;
const fd_t = std.os.fd_t;

const Insn = @This();

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
pub const Reg = packed enum(u4) { r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 };
const Source = packed enum(u1) { reg, imm };

const Mode = packed enum(u8) {
    imm = IMM,
    abs = ABS,
    ind = IND,
    mem = MEM,
    len = LEN,
    msh = MSH,
};

const AluOp = packed enum(u8) {
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

pub const Size = packed enum(u8) {
    byte = B,
    half_word = H,
    word = W,
    double_word = DW,
};

const JmpOp = packed enum(u8) {
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
    imm: i32,
    reg: Reg,
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
        .dst = @enumToInt(dst),
        .src = switch (imm_or_reg) {
            .imm => 0,
            .reg => |r| @enumToInt(r),
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

    return imm_reg(width_bitfield | @enumToInt(op), dst, src, 0);
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
    return imm_reg(JMP | @enumToInt(op), dst, src, off);
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
        .dst = @enumToInt(dst),
        .src = @enumToInt(src),
        .off = 0,
        .imm = 0,
    };
}

fn ld(mode: Mode, size: Size, dst: Reg, src: Reg, imm: i32) Insn {
    return Insn{
        .code = @enumToInt(mode) | @enumToInt(size) | LD,
        .dst = @enumToInt(dst),
        .src = @enumToInt(src),
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
        .code = MEM | @enumToInt(size) | LDX,
        .dst = @enumToInt(dst),
        .src = @enumToInt(src),
        .off = off,
        .imm = 0,
    };
}

fn ld_imm_impl1(dst: Reg, src: Reg, imm: u64) Insn {
    return Insn{
        .code = LD | DW | IMM,
        .dst = @enumToInt(dst),
        .src = @enumToInt(src),
        .off = 0,
        .imm = @intCast(i32, @truncate(u32, imm)),
    };
}

fn ld_imm_impl2(imm: u64) Insn {
    return Insn{
        .code = 0,
        .dst = 0,
        .src = 0,
        .off = 0,
        .imm = @intCast(i32, @truncate(u32, imm >> 32)),
    };
}

pub fn ld_dw1(dst: Reg, imm: u64) Insn {
    return ld_imm_impl1(dst, .r0, imm);
}

pub fn ld_dw2(imm: u64) Insn {
    return ld_imm_impl2(imm);
}

pub fn ld_map_fd1(dst: Reg, map_fd: fd_t) Insn {
    return ld_imm_impl1(dst, @intToEnum(Reg, PSEUDO_MAP_FD), @intCast(u64, map_fd));
}

pub fn ld_map_fd2(map_fd: fd_t) Insn {
    return ld_imm_impl2(@intCast(u64, map_fd));
}

pub fn st(comptime size: Size, dst: Reg, off: i16, imm: i32) Insn {
    if (size == .double_word) @compileError("TODO: need to determine how to correctly handle double words");
    return Insn{
        .code = MEM | @enumToInt(size) | ST,
        .dst = @enumToInt(dst),
        .src = 0,
        .off = off,
        .imm = imm,
    };
}

pub fn stx(size: Size, dst: Reg, off: i16, src: Reg) Insn {
    return Insn{
        .code = MEM | @enumToInt(size) | STX,
        .dst = @enumToInt(dst),
        .src = @enumToInt(src),
        .off = off,
        .imm = 0,
    };
}

fn endian_swap(endian: std.builtin.Endian, comptime size: Size, dst: Reg) Insn {
    return Insn{
        .code = switch (endian) {
            .Big => 0xdc,
            .Little => 0xd4,
        },
        .dst = @enumToInt(dst),
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
    return endian_swap(.Little, size, dst);
}

pub fn be(comptime size: Size, dst: Reg) Insn {
    return endian_swap(.Big, size, dst);
}

pub fn call(helper: Helper) Insn {
    return Insn{
        .code = JMP | CALL,
        .dst = 0,
        .src = 0,
        .off = 0,
        .imm = @enumToInt(helper),
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

test "insn bitsize" {
    expectEqual(64, @bitSizeOf(Insn));
}

fn expect_opcode(code: u8, insn: Insn) void {
    expectEqual(code, insn.code);
}

// The opcodes were grabbed from https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
test "opcodes" {
    // instructions that have a name that end with 1 or 2 are consecutive for
    // loading 64-bit immediates (imm is only 32 bits wide)

    // alu instructions
    expect_opcode(0x07, Insn.add(.r1, 0));
    expect_opcode(0x0f, Insn.add(.r1, .r2));
    expect_opcode(0x17, Insn.sub(.r1, 0));
    expect_opcode(0x1f, Insn.sub(.r1, .r2));
    expect_opcode(0x27, Insn.mul(.r1, 0));
    expect_opcode(0x2f, Insn.mul(.r1, .r2));
    expect_opcode(0x37, Insn.div(.r1, 0));
    expect_opcode(0x3f, Insn.div(.r1, .r2));
    expect_opcode(0x47, Insn.alu_or(.r1, 0));
    expect_opcode(0x4f, Insn.alu_or(.r1, .r2));
    expect_opcode(0x57, Insn.alu_and(.r1, 0));
    expect_opcode(0x5f, Insn.alu_and(.r1, .r2));
    expect_opcode(0x67, Insn.lsh(.r1, 0));
    expect_opcode(0x6f, Insn.lsh(.r1, .r2));
    expect_opcode(0x77, Insn.rsh(.r1, 0));
    expect_opcode(0x7f, Insn.rsh(.r1, .r2));
    expect_opcode(0x87, Insn.neg(.r1));
    expect_opcode(0x97, Insn.mod(.r1, 0));
    expect_opcode(0x9f, Insn.mod(.r1, .r2));
    expect_opcode(0xa7, Insn.xor(.r1, 0));
    expect_opcode(0xaf, Insn.xor(.r1, .r2));
    expect_opcode(0xb7, Insn.mov(.r1, 0));
    expect_opcode(0xbf, Insn.mov(.r1, .r2));
    expect_opcode(0xc7, Insn.arsh(.r1, 0));
    expect_opcode(0xcf, Insn.arsh(.r1, .r2));

    // atomic instructions: might be more of these not documented in the wild
    expect_opcode(0xdb, Insn.xadd(.r1, .r2));

    // TODO: byteswap instructions
    expect_opcode(0xd4, Insn.le(.half_word, .r1));
    expectEqual(@intCast(i32, 16), Insn.le(.half_word, .r1).imm);
    expect_opcode(0xd4, Insn.le(.word, .r1));
    expectEqual(@intCast(i32, 32), Insn.le(.word, .r1).imm);
    expect_opcode(0xd4, Insn.le(.double_word, .r1));
    expectEqual(@intCast(i32, 64), Insn.le(.double_word, .r1).imm);
    expect_opcode(0xdc, Insn.be(.half_word, .r1));
    expectEqual(@intCast(i32, 16), Insn.be(.half_word, .r1).imm);
    expect_opcode(0xdc, Insn.be(.word, .r1));
    expectEqual(@intCast(i32, 32), Insn.be(.word, .r1).imm);
    expect_opcode(0xdc, Insn.be(.double_word, .r1));
    expectEqual(@intCast(i32, 64), Insn.be(.double_word, .r1).imm);

    // memory instructions
    expect_opcode(0x18, Insn.ld_dw1(.r1, 0));
    expect_opcode(0x00, Insn.ld_dw2(0));

    //   loading a map fd
    expect_opcode(0x18, Insn.ld_map_fd1(.r1, 0));
    expectEqual(@intCast(u4, PSEUDO_MAP_FD), Insn.ld_map_fd1(.r1, 0).src);
    expect_opcode(0x00, Insn.ld_map_fd2(0));

    expect_opcode(0x38, Insn.ld_abs(.double_word, .r1, .r2, 0));
    expect_opcode(0x20, Insn.ld_abs(.word, .r1, .r2, 0));
    expect_opcode(0x28, Insn.ld_abs(.half_word, .r1, .r2, 0));
    expect_opcode(0x30, Insn.ld_abs(.byte, .r1, .r2, 0));

    expect_opcode(0x58, Insn.ld_ind(.double_word, .r1, .r2, 0));
    expect_opcode(0x40, Insn.ld_ind(.word, .r1, .r2, 0));
    expect_opcode(0x48, Insn.ld_ind(.half_word, .r1, .r2, 0));
    expect_opcode(0x50, Insn.ld_ind(.byte, .r1, .r2, 0));

    expect_opcode(0x79, Insn.ldx(.double_word, .r1, .r2, 0));
    expect_opcode(0x61, Insn.ldx(.word, .r1, .r2, 0));
    expect_opcode(0x69, Insn.ldx(.half_word, .r1, .r2, 0));
    expect_opcode(0x71, Insn.ldx(.byte, .r1, .r2, 0));

    expect_opcode(0x62, Insn.st(.word, .r1, 0, 0));
    expect_opcode(0x6a, Insn.st(.half_word, .r1, 0, 0));
    expect_opcode(0x72, Insn.st(.byte, .r1, 0, 0));

    expect_opcode(0x63, Insn.stx(.word, .r1, 0, .r2));
    expect_opcode(0x6b, Insn.stx(.half_word, .r1, 0, .r2));
    expect_opcode(0x73, Insn.stx(.byte, .r1, 0, .r2));
    expect_opcode(0x7b, Insn.stx(.double_word, .r1, 0, .r2));

    // branch instructions
    expect_opcode(0x05, Insn.ja(0));
    expect_opcode(0x15, Insn.jeq(.r1, 0, 0));
    expect_opcode(0x1d, Insn.jeq(.r1, .r2, 0));
    expect_opcode(0x25, Insn.jgt(.r1, 0, 0));
    expect_opcode(0x2d, Insn.jgt(.r1, .r2, 0));
    expect_opcode(0x35, Insn.jge(.r1, 0, 0));
    expect_opcode(0x3d, Insn.jge(.r1, .r2, 0));
    expect_opcode(0xa5, Insn.jlt(.r1, 0, 0));
    expect_opcode(0xad, Insn.jlt(.r1, .r2, 0));
    expect_opcode(0xb5, Insn.jle(.r1, 0, 0));
    expect_opcode(0xbd, Insn.jle(.r1, .r2, 0));
    expect_opcode(0x45, Insn.jset(.r1, 0, 0));
    expect_opcode(0x4d, Insn.jset(.r1, .r2, 0));
    expect_opcode(0x55, Insn.jne(.r1, 0, 0));
    expect_opcode(0x5d, Insn.jne(.r1, .r2, 0));
    expect_opcode(0x65, Insn.jsgt(.r1, 0, 0));
    expect_opcode(0x6d, Insn.jsgt(.r1, .r2, 0));
    expect_opcode(0x75, Insn.jsge(.r1, 0, 0));
    expect_opcode(0x7d, Insn.jsge(.r1, .r2, 0));
    expect_opcode(0xc5, Insn.jslt(.r1, 0, 0));
    expect_opcode(0xcd, Insn.jslt(.r1, .r2, 0));
    expect_opcode(0xd5, Insn.jsle(.r1, 0, 0));
    expect_opcode(0xdd, Insn.jsle(.r1, .r2, 0));
    expect_opcode(0x85, Insn.call(.unspec));
    expect_opcode(0x95, Insn.exit());
}
