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

pub const Fault = error{InvalidInstruction};

/// Execute a single instruction. If the program has exited, it will return the
/// exit code, otherwise null. A fault error is returned if an instruction does
/// anything illegal.
pub fn step(vm: *VM) Fault!?c_int {
    const next = vm.instructions.items[vm.pc];

    switch (next.opcode.class) {
        .ALU64 => switch (next.opcode.specific.arithmetic.code) {
            .MOV => switch (next.opcode.specific.arithmetic.source) {
                .K => {
                    vm.r[next.regs.dst] = next.imm;
                    vm.pc += 1;
                },
                else => @panic("TODO"),
            },
            else => |code| {
                std.log.err("ALU 64 code: {}", .{code});
                @panic("TODO");
            },
        },
        .JMP => switch (next.opcode.specific.jump.code) {
            .EXIT => {
                if (next.opcode.specific.jump.source != .K)
                    return error.InvalidInstruction;

                return @bitCast(@as(c_uint, @truncate(vm.r[0])));
            },
            else => |code| {
                std.log.err("JMP code: {}", .{code});
                @panic("TODO");
            },
        },
        else => |class| {
            std.log.err("class: {}", .{class});
            @panic("TODO");
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

test "all" {
    _ = @import("insn.zig");
}

const VM = @This();
const std = @import("std");
const Allocator = std.mem.Allocator;
const Endian = std.builtin.Endian;

const Instruction = @import("insn.zig").Instruction;

const insn_test = @import("insn_test.zig");

const insn_execute_max = 1_000_000;
