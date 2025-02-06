const std = @import("std");
const builtin = @import("builtin");
const sbpf = @import("sbpf.zig");

const arch = switch (builtin.cpu.arch) {
    .aarch64 => @import("jit/arm64.zig"),
    .x86_64 => @compileError("TODO: x86_64 JIT engine"),
    else => @compileError("unsupported JIT engine target"),
};

const Register = arch.Register;
const Instruction = sbpf.Instruction;

pub const register_map = std.EnumMap(
    sbpf.Instruction.Register,
    Register,
).init(.{
    .r0 = arch.caller_saved_registers[0],

    .r1 = arch.argument_registers[1],
    .r2 = arch.argument_registers[2],
    .r3 = arch.argument_registers[3],
    .r4 = arch.argument_registers[4],
    .r5 = arch.argument_registers[5],

    .r6 = arch.callee_saved_registers[1],
    .r7 = arch.callee_saved_registers[2],
    .r8 = arch.callee_saved_registers[3],
    .r9 = arch.callee_saved_registers[4],
    .r10 = arch.callee_saved_registers[5],
});

pub const Engine = struct {
    allocator: std.mem.Allocator,
    code: std.ArrayListAlignedUnmanaged(u8, std.mem.page_size),
    pc: u64,
    table: Table,

    pub const Error = std.mem.Allocator.Error || error{};

    pub const Operation = enum {
        add,
        mul,
        @"or",
        @"and",
        xor,
        lsh,
        rsh,
    };

    pub const Table = struct {
        loadImmediate: *const fn (*Engine, dst: Register, imm: u64, size: Register.Size) Error!void,
        movReg: *const fn (*Engine, dst: Register, src: Register) Error!void,
        binOpReg: *const fn (
            self: *Engine,
            dst: Register,
            src: Register,
            size: Register.Size,
            op: Operation,
        ) Error!void,
        exit: *const fn (*Engine) Engine.Error!void,
    };

    pub fn init(allocator: std.mem.Allocator) Engine {
        return .{
            .code = .{},
            .allocator = allocator,
            .pc = 0,
            .table = arch.table,
        };
    }

    pub fn deinit(self: *Engine) void {
        self.code.deinit(self.allocator);
    }

    fn loadImmediate(
        self: *Engine,
        dst: Register,
        imm: u64,
        size: Register.Size,
    ) !void {
        try self.table.loadImmediate(self, dst, imm, size);
    }

    fn binOpReg(
        self: *Engine,
        dst: Register,
        src: Register,
        size: Register.Size,
        op: Operation,
    ) !void {
        try self.table.binOpReg(self, dst, src, size, op);
    }

    fn movReg(self: *Engine, dst: Register, src: Register) !void {
        try self.table.movReg(self, dst, src);
    }

    fn exit(self: *Engine) !void {
        try self.table.exit(self);
    }

    pub fn compile(self: *Engine, instructions: []align(1) const sbpf.Instruction) !void {
        while (self.pc < instructions.len) : (self.pc += 1) {
            const inst = instructions[self.pc];
            const opcode = inst.opcode;
            const dst = register_map.get(inst.dst).?;
            const src = register_map.get(inst.src).?;
            const size: Register.Size = if (opcode.is64()) .@"64" else .@"32";

            const extended = extend(inst.imm);
            const imm: u64 = if (opcode.is64()) extended else @as(u32, @truncate(extended));

            switch (inst.opcode) {
                .mov32_imm,
                .mov64_imm,
                => try self.loadImmediate(dst, imm, size),

                .mov32_reg,
                .mov64_reg,
                => try self.movReg(dst, src),

                .add32_reg,
                .add64_reg,
                .add64_imm,
                .add32_imm,
                .or64_reg,
                .or64_imm,
                .or32_reg,
                .or32_imm,
                .and64_reg,
                .and64_imm,
                .and32_reg,
                .and32_imm,
                .lsh64_reg,
                .lsh64_imm,
                .lsh32_reg,
                .lsh32_imm,
                .rsh64_reg,
                .rsh64_imm,
                .rsh32_reg,
                .rsh32_imm,
                .xor64_reg,
                .xor64_imm,
                .xor32_reg,
                .xor32_imm,
                .mul64_reg,
                .mul64_imm,
                .mul32_reg,
                .mul32_imm,
                => {
                    const src_register = if (!opcode.isReg()) src: {
                        try self.loadImmediate(arch.scratch_registers[0], imm, size);
                        break :src arch.scratch_registers[0];
                    } else src;

                    const op: Operation = switch (@intFromEnum(opcode) & 0xF0) {
                        Instruction.add => .add,
                        Instruction.mul => .mul,
                        Instruction.@"or" => .@"or",
                        Instruction.xor => .xor,
                        Instruction.@"and" => .@"and",
                        Instruction.lsh => .lsh,
                        Instruction.rsh => .rsh,
                        else => unreachable,
                    };

                    try self.binOpReg(dst, src_register, size, op);
                },

                .ld_dw_imm => {
                    const value: u64 = (@as(u64, instructions[self.pc + 1].imm) << 32) | inst.imm;
                    try self.loadImmediate(dst, value, .@"64");
                    self.pc += 1;
                },

                .exit => try self.table.exit(self),
                else => std.debug.panic("TODO: JIT {s}", .{@tagName(inst.opcode)}),
            }
        }
    }
};

/// Performs a i64 sign-extension. This is commonly needed in SBPv0.
///
/// NOTE: only use this inside of the VM impl!
fn extend(input: anytype) u64 {
    const value: u32 = @truncate(input);
    const signed: i32 = @bitCast(value);
    const extended: i64 = signed;
    return @bitCast(extended);
}
