pub const Instruction = packed struct(u64) {
    opcode: packed struct(u8) {
        class: Class,
        specific: packed union {
            arithmetic: packed struct(u5) {
                source: Source,
                code: ArithmeticCode,
            },
            jump: packed struct(u5) {
                source: Source,
                code: JumpCode,
            },
            jump32: packed struct(u5) {
                source: Source,
                code: Jump32Code,
            },
            load_and_store: packed struct(u5) {
                sz: LoadStoreSize,
                mode: LoadStoreMode,
            },
        },
    },
    regs: packed struct(u8) {
        src: u4,
        dst: u4,
    },
    offset: u16,
    imm: u32,

    /// This function normalizes instructions given a raw little or big endian
    /// instruction.
    ///
    /// Fields that need byte swapping will be swapped. For whatever reason the
    /// little and big endian variants of BPF swap the source and destination
    /// register fields despite being contained within a byte boundary. This
    /// function fixes that.
    pub fn parse(endian: Endian, insn: u64) Instruction {
        const opcode: u8 = @truncate(insn);
        const reg1: u4 = @truncate(insn >> 8);
        const reg2: u4 = @truncate(insn >> 12);
        const offset: u16 = @truncate(insn >> 16);
        const imm: u32 = @truncate(insn >> 32);

        const class: u3 = @truncate(opcode);
        const specific: u5 = @truncate(opcode >> 3);

        return Instruction{
            .opcode = .{
                .class = @enumFromInt(class),
                .specific = @bitCast(specific),
            },
            .regs = switch (endian) {
                .little => .{
                    .src = reg1,
                    .dst = reg2,
                },
                .big => .{
                    .src = reg2,
                    .dst = reg1,
                },
            },
            .offset = fix_endian(u16, endian, offset),
            .imm = fix_endian(u32, endian, imm),
        };
    }

    fn fix_endian(comptime T: type, runtime: Endian, value: T) T {
        return if (runtime == @import("builtin").cpu.arch.endian())
            value
        else
            @byteSwap(value);
    }

    pub fn disassemble(instruction: *const Instruction, writer: anytype) !void {
        errdefer {
            var buf: [4096]u8 = undefined;
            const message = std.fmt.bufPrint(&buf, "Failed to disassemble instruction: {}", .{instruction}) catch unreachable;
            @panic(message);
        }

        switch (instruction.opcode.class) {
            .LD,
            .LDX,
            .ST,
            .STX,
            .ALU,
            .JMP,
            .JMP32,
            => return error.TODO,
            .ALU64 => switch (instruction.opcode.specific.arithmetic.source) {
                .X => return error.TODO,
                .K => switch (instruction.opcode.specific.arithmetic.code) {
                    .MOV => try writer.print("r{} = {}", .{ instruction.regs.dst, instruction.imm }),
                    else => return error.TODO,
                },
            },
        }
    }

    pub fn format(
        instruction: Instruction,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("class={}", .{instruction.opcode.class});
        switch (instruction.opcode.class) {
            .LD, .LDX, .ST, .STX => {
                const l = instruction.opcode.specific.load_and_store;
                try writer.print(" sz={} mode={}", .{ l.sz, l.mode });
            },
            .ALU, .ALU64 => {
                const a = instruction.opcode.specific.arithmetic;
                try writer.print(" source={} code={}", .{ a.source, a.code });
            },
            .JMP => {
                const j = instruction.opcode.specific.jump;
                try writer.print(" source={} code={}", .{ j.source, j.code });
            },
            .JMP32 => {
                const j = instruction.opcode.specific.jump;
                try writer.print(" source={} code={}", .{ j.source, j.code });
            },
        }

        try writer.print(" dst_reg={} src_reg={} offset=0x{X} imm={}", .{
            instruction.regs.dst,
            instruction.regs.src,
            instruction.offset,
            instruction.imm,
        });
    }
};

pub const LoadStoreSize = enum(u2) {
    /// Word (4-bytes)
    W = 0,
    /// Half-word (2-bytes)
    H = 1,
    /// Byte
    B = 2,
    /// Double-word (8-bytes)
    DW = 3,
};

pub const LoadStoreMode = enum(u3) {
    /// 64-bit immediate instructions
    IMM = 0,
    /// Legacy BPF packet access (absolute)
    ABS = 1,
    /// Legacy BPF packet access (indirect)
    IND = 2,
    /// Regular load and store operations
    MEM = 3,
    /// Sign-extension load and store operations
    MEMSX = 4,
    /// Atomic operations
    ATOMIC = 6,
    _,
};

pub const Source = enum(u1) {
    /// use 32-bit 'imm' value as source operand
    K = 0,
    /// use 'src_reg' register value as source operand
    X = 1,
};

// The byte swap instructions use instruction classes of ALU and ALU64 and a
// 4-bit 'code' field of END.
//
// The byte swap instructions operate on the destination register only and do
// not use a separate source register or immediate value.
//
// For ALU, the 1-bit source operand field in the opcode is used to select what
// byte order the operation converts from or to.  For ALU64, the 1-bit source
// operand field in the opcode is reserved and MUST be set to 0.
pub const ByteSwapSource = enum(u1) {
    /// Convert between host byte order and little endian
    LE = 0,
    /// Convert between host byte order and big endian
    BE = 1,
};

pub const Class = enum(u3) {
    /// Non-standard load operations
    LD = 0x0,
    /// Load into register operations
    LDX = 0x1,
    /// Store from immediate operations
    ST = 0x2,
    /// Store from register operations
    STX = 0x3,
    /// 32-bit arithmetic operations
    ALU = 0x4,
    /// 64-bit jump operations
    JMP = 0x5,
    /// 32-bit jump operations
    JMP32 = 0x6,
    /// 64-bit arithmetic operations
    ALU64 = 0x7,
};

pub const JumpCode = enum(u4) {
    /// PC += offset
    JA = 0x0,
    /// PC += offset if dst == src
    JEQ = 0x1,
    /// PC += offset if dst > src
    JGT = 0x2,
    /// PC += offset if dst >= src
    JGE = 0x3,
    /// PC += offset if dst & src
    JSET = 0x4,
    /// PC += offset if dst != src
    JNE = 0x5,
    /// PC += offset if dst > src
    JSGT = 0x6,
    /// PC += offset if dst >= src
    JSGE = 0x7,

    // For given src_reg values:
    //
    // 0: Call helper function by static ID
    // 1: Call PC += imm
    // 2: Call helper function by BTF ID
    CALL = 0x8,
    EXIT = 0x9,
    /// PC += offset if dst < src
    JLT = 0xA,
    /// PC += offset if dst <= src
    JLE = 0xB,
    /// PC += offset if dst < src
    JSLT = 0xC,
    /// PC += offset if dst <= src
    JSLE = 0xD,
    _,
};

pub const Jump32Code =
    enum(u4) {
        /// PC += imm
        JA = 0x0,
        /// PC += offset if dst == src
        JEQ = 0x1,
        /// PC += offset if dst > src
        JGT = 0x2,
        /// PC += offset if dst >= src
        JGE = 0x3,
        /// PC += offset if dst & src
        JSET = 0x4,
        /// PC += offset if dst != src
        JNE = 0x5,
        /// PC += offset if dst > src
        JSGT = 0x6,
        /// PC += offset if dst >= src
        JSGE = 0x7,
        /// PC += offset if dst < src
        JLT = 0xA,
        /// PC += offset if dst <= src
        JLE = 0xB,
        /// PC += offset if dst < src
        JSLT = 0xC,
        /// PC += offset if dst <= src
        JSLE = 0xD,
        _,
    };

pub const ArithmeticCode = enum(u4) {
    /// dst += src
    ADD = 0x0,
    /// dst -= src
    SUB = 0x1,
    /// dst *= src
    MUL = 0x2,
    /// dst = (src != 0) ? (dst / src) : 0
    /// TODO: there is SDIV too, it uses offset
    DIV = 0x3,
    /// dst |= src
    OR = 0x4,
    /// dst &= src
    AND = 0x5,
    /// dst <<= (src & mask)
    LSH = 0x6,
    /// dst >>= (src & mask)
    RSH = 0x7,
    /// dst = -dst
    NEG = 0x8,
    /// dst = (src != 0) ? (dst % src) : 0
    /// TODO: there is SMOD too, it uses offset
    MOD = 0x9,
    /// dst ^= src
    XOR = 0xA,
    /// dst = src
    /// TODO: there is sign extending MOV too dst = (s8/s16/s32)src
    MOV = 0xB,
    /// Sign extending dst >>= (src & mask)
    ARSH = 0xC,
    /// Byte swap operations
    END = 0xD,
    _,
};

const std = @import("std");
const Endian = std.builtin.Endian;
