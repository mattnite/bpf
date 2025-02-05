test "serialization" {
    try instruction_test("load", .{
        .opcode = .{
            .class = .ALU64,
            .specific = .{
                .arithmetic = .{
                    .source = .K,
                    .code = .MOV,
                },
            },
        },
        .regs = .{ .src = 1, .dst = 0 },
        .offset = 0,
        .imm = 1,
    });
}

fn instruction_test(comptime program_name: []const u8, expected: insn.Instruction) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    inline for (&.{ el, eb }, &.{ .little, .big }) |examples, endian| {
        const program = try load_program(arena.allocator(), @field(examples, program_name));
        try std.testing.expectEqual(1, program.len);

        expect_instruction(expected, insn.Instruction.parse(endian, program[0])) catch |err| {
            if (endian == .little)
                std.log.err("Little endian failed", .{})
            else
                std.log.err("Big endian failed", .{});

            std.log.err("0x{X:0>16}", .{program[0]});

            return err;
        };
    }
}

const expect_equal = std.testing.expectEqual;

fn expect_instruction(expected: insn.Instruction, actual: insn.Instruction) !void {
    try expect_equal(expected.opcode.class, actual.opcode.class);
    switch (expected.opcode.class) {
        .ALU, .ALU64 => {
            try expect_equal(expected.opcode.specific.arithmetic.source, actual.opcode.specific.arithmetic.source);
            try expect_equal(expected.opcode.specific.arithmetic.code, actual.opcode.specific.arithmetic.code);
        },
        .JMP => {
            try expect_equal(expected.opcode.specific.jump.source, actual.opcode.specific.jump.source);
            try expect_equal(expected.opcode.specific.jump.code, actual.opcode.specific.jump.code);
        },
        .JMP32 => {
            try expect_equal(expected.opcode.specific.jump32.source, actual.opcode.specific.jump32.source);
            try expect_equal(expected.opcode.specific.jump32.code, actual.opcode.specific.jump32.code);
        },
        .LD, .LDX, .ST, .STX => {
            try expect_equal(expected.opcode.specific.load_and_store.sz, actual.opcode.specific.load_and_store.sz);
            try expect_equal(expected.opcode.specific.load_and_store.mode, actual.opcode.specific.load_and_store.mode);
        },
    }

    try std.testing.expectEqual(expected.regs.src, actual.regs.src);
    try std.testing.expectEqual(expected.regs.dst, actual.regs.dst);
    try std.testing.expectEqual(expected.offset, actual.offset);
    try std.testing.expectEqual(expected.imm, actual.imm);
}

const std = @import("std");
const insn = @import("insn.zig");

const Examples = OptionsToStruct(@import("examples-el"));
pub const el = AssignOptions(Examples, @import("examples-el"));
pub const eb = AssignOptions(Examples, @import("examples-eb"));

fn OptionsToStruct(comptime ns: type) type {
    const ti = @typeInfo(ns).Struct;
    var fields: [ti.decls.len]std.builtin.Type.StructField = undefined;

    inline for (ti.decls, &fields) |decl, *field| {
        field.* = std.builtin.Type.StructField{
            .name = decl.name,
            .type = []const u8,
            .alignment = @alignOf([]const u8),
            .default_value = null,
            .is_comptime = false,
        };
    }

    const t = std.builtin.Type{
        .Struct = .{
            .backing_integer = null,
            .decls = &.{},
            .fields = &fields,
            .is_tuple = false,
            .layout = .auto,
        },
    };

    return @Type(t);
}

fn AssignOptions(comptime T: type, comptime ns: type) T {
    const ti = @typeInfo(T).Struct;
    const ns_ti = @typeInfo(ns).Struct;

    var ret: T = undefined;
    inline for (ti.fields, ns_ti.decls) |field, decl| {
        std.debug.assert(std.mem.eql(u8, field.name, decl.name));
        @field(ret, field.name) = @field(ns, decl.name);
    }

    return ret;
}

pub fn load_program(allocator: std.mem.Allocator, path: []const u8) ![]const u64 {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 100 * 1024);
    return @alignCast(std.mem.bytesAsSlice(u64, bytes));
}
