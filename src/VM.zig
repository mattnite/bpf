gpa: Allocator,
pc: u32,
r: [11]u64 = undefined,
stack: [512]u8 = undefined,
instructions: std.ArrayListUnmanaged(Instruction) = .{},

pub fn init(allocator: Allocator) VM {
    var ret = VM{
        .gpa = allocator,
        .pc = 0,
    };

    ret.reset();
    return ret;
}

pub fn deinit(vm: *VM) void {
    vm.instructions.deinit(vm.gpa);
}

pub fn reset(vm: *VM) void {
    vm.pc = 0;
    @memset(&vm.r, 0);
    @memset(&vm.stack, 0);
    vm.instructions.clearRetainingCapacity();
}

/// Load program into VM. Clears existing state.
pub fn load(vm: *VM, endian: Endian, instructions: []const u64) !void {
    vm.reset();

    for (instructions) |insn|
        try vm.instructions.append(vm.gpa, Instruction.parse(endian, insn));
}

pub const Fault = error{ InvalidInstruction, TODO };

fn sign_extend(comptime Dst: type, comptime Src: type, src: Src) Dst {
    //Sign Extend:  To sign extend an X-bit number, A, to a Y-bit number,
    //   B, means to
    //
    //   1.  Copy all X bits from A to the lower X bits of B.
    //   2.  Set the value of the remaining Y - X bits of B to the value of
    //       the most significant bit of A.

    const dst_info = @typeInfo(Dst);
    const src_info = @typeInfo(Src);

    comptime {
        assert(dst_info.int.signedness == .unsigned);
        assert(src_info.int.signedness == .signed);
        assert(dst_info.int.bits > src_info.int.bits);
    }

    _ = src;
    assert(false); // TODO
}

fn do_alu64(code: ArithmeticCode, dst: *u64, src: u64, offset: u16) !void {
    switch (code) {
        .ADD => dst.* +%= src,
        .SUB => dst.* -%= src,
        .MUL => dst.* *%= src,
        .DIV => dst.* = if (offset == 0)
            if (src != 0) dst.* / src else 0
        else
            // SDIV
            return error.TODO,
        .OR => dst.* |= src,
        .AND => dst.* &= src,
        .LSH => dst.* <<= @as(u6, @truncate(src)),
        .RSH => dst.* >>= @as(u6, @truncate(src)),
        .NEG => return error.TODO, //dst.* = @bitCast(-@as(i64, @bitCast(src))),
        .XOR => dst.* ^= src,
        .MOD => if (offset == 0)
            return error.TODO
        else
            // SMOD
            return error.TODO,
        .MOV => if (offset == 0) {
            dst.* = src;
        } else
        // MOVSX
        return error.TODO,
        .END => return error.TODO,
        .ARSH => return error.TODO,
        _ => return error.InvalidInstruction,
    }
}

fn do_alu(code: ArithmeticCode, dst: *u64, src: u32) !void {
    _ = dst;
    _ = src;
    switch (code) {
        else => {
            std.log.err("ALU code: {}", .{code});
            return error.TODO;
        },
    }
}

/// Execute a single instruction. If the program has exited, it will return the
/// exit code, otherwise null. A fault error is returned if an instruction does
/// anything illegal.
pub fn step(vm: *VM) Fault!?c_int {
    const next = vm.instructions.items[vm.pc];

    switch (next.opcode.class) {
        .ALU64 => {
            const src = &vm.r[next.regs.src];
            const dst = &vm.r[next.regs.dst];
            switch (next.opcode.specific.arithmetic.source) {
                // K means use 32-bit imm value as source operand
                .K => try do_alu64(next.opcode.specific.arithmetic.code, dst, next.imm, next.offset),
                .X => try do_alu64(next.opcode.specific.arithmetic.code, dst, src.*, next.offset),
            }

            vm.pc += 1;
        },
        .ALU => {
            const src = &vm.r[next.regs.src];
            const dst = &vm.r[next.regs.dst];
            switch (next.opcode.specific.arithmetic.source) {
                // K means use 32-bit imm value as source operand
                .K => try do_alu(next.opcode.specific.arithmetic.code, dst, next.imm),
                .X => try do_alu(next.opcode.specific.arithmetic.code, dst, @truncate(src.*)),
            }

            vm.pc += 1;
        },
        .JMP => switch (next.opcode.specific.jump.code) {
            .EXIT => {
                if (next.opcode.specific.jump.source != .K)
                    return error.InvalidInstruction;

                return @bitCast(@as(c_uint, @truncate(vm.r[0])));
            },
            else => |code| {
                std.log.err("JMP code: {}", .{code});
                return error.TODO;
            },
        },
        else => |class| {
            std.log.err("class: {}", .{class});
            return error.TODO;
        },
    }

    return null;
}

test "return 1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    inline for (&.{ insn_test.el, insn_test.eb }, &.{ .little, .big }) |examples, endian| {
        const program = try insn_test.load_program(arena.allocator(), @field(examples, "return_one"));

        var vm = VM.init(arena.allocator());
        try vm.load(endian, program);

        while (true) {
            if (try vm.step()) |return_code| {
                try std.testing.expectEqual(1, return_code);
                break;
            }
        }
    }
}

test "step.alu64.k.mov" {
    var vm = VM.init(std.testing.allocator);
    defer vm.deinit();

    vm.reset();
    vm.r[2] = 2;
    vm.r[3] = 3;
    try vm.instructions.append(vm.gpa, .{
        .opcode = .{
            .class = .ALU64,
            .specific = .{
                .arithmetic = .{
                    .source = .X,
                    .code = .ADD,
                },
            },
        },
        .regs = .{
            .src = 3,
            .dst = 2,
        },
        .offset = 0,
        .imm = 0,
    });

    _ = try vm.step();

    try std.testing.expectEqual(5, vm.r[2]);
}

test "all" {
    _ = @import("insn.zig");
}

const VM = @This();
const std = @import("std");
const Allocator = std.mem.Allocator;
const Endian = std.builtin.Endian;
const assert = std.debug.assert;

const Instruction = @import("insn.zig").Instruction;
const ArithmeticCode = @import("insn.zig").ArithmeticCode;

const insn_test = @import("insn_test.zig");

const insn_execute_max = 1_000_000;
