const std = @import("std");
const jit = @import("../jit.zig");
const sbpf = @import("../sbpf.zig");

const assert = std.debug.assert;
const Engine = jit.Engine;

pub const Register = enum(u8) {
    // zig fmt: off

    // 64-bit general-purpose registers
    x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7,
    x8,  x9,  x10, x11, x12, x13, x14, x15,
    x16, x17, x18, x19, x20, x21, x22, x23,
    x24, x25, x26, x27, x28, fp, lr, xzr,

    // 32-bit general-purpose registers
    w0, w1, w2, w3, w4, w5, w6, w7,
    w8, w9, w10, w11, w12, w13, w14, w15,
    w16, w17, w18, w19, w20, w21, w22, w23,
    w24, w25, w26, w27, w28, w29, w30, wzr,

    // Stack pointer
    sp, wsp,

    // zig fmt: on

    pub const Size = enum {
        @"32",
        @"64",
    };

    /// Returns the bit-width of the register.
    fn size(self: Register) Size {
        return switch (@intFromEnum(self)) {
            @intFromEnum(Register.x0)...@intFromEnum(Register.xzr) => .@"64",
            @intFromEnum(Register.w0)...@intFromEnum(Register.wzr) => .@"32",

            @intFromEnum(Register.sp) => .@"64",
            @intFromEnum(Register.wsp) => .@"32",
            else => unreachable,
        };
    }

    fn enc(self: Register) u5 {
        return switch (@intFromEnum(self)) {
            @intFromEnum(Register.x0)...@intFromEnum(Register.xzr) => @as(u5, @intCast(@intFromEnum(self) - @intFromEnum(Register.x0))),
            @intFromEnum(Register.w0)...@intFromEnum(Register.wzr) => @as(u5, @intCast(@intFromEnum(self) - @intFromEnum(Register.w0))),

            @intFromEnum(Register.sp) => 31,
            @intFromEnum(Register.wsp) => 31,
            else => unreachable,
        };
    }

    fn id(self: Register) u6 {
        return switch (@intFromEnum(self)) {
            @intFromEnum(Register.x0)...@intFromEnum(Register.xzr) => @as(u6, @intCast(@intFromEnum(self) - @intFromEnum(Register.x0))),
            @intFromEnum(Register.w0)...@intFromEnum(Register.wzr) => @as(u6, @intCast(@intFromEnum(self) - @intFromEnum(Register.w0))),

            @intFromEnum(Register.sp) => 32,
            @intFromEnum(Register.wsp) => 32,
            else => unreachable,
        };
    }

    /// Convert from a general-purpose register to its 64 bit alias.
    fn toX(self: Register) Register {
        return switch (@intFromEnum(self)) {
            @intFromEnum(Register.x0)...@intFromEnum(Register.xzr) => @as(
                Register,
                @enumFromInt(@intFromEnum(self) - @intFromEnum(Register.x0) + @intFromEnum(Register.x0)),
            ),
            @intFromEnum(Register.w0)...@intFromEnum(Register.wzr) => @as(
                Register,
                @enumFromInt(@intFromEnum(self) - @intFromEnum(Register.w0) + @intFromEnum(Register.x0)),
            ),
            else => unreachable,
        };
    }

    /// Convert from a general-purpose register to its 32 bit alias.
    fn toW(self: Register) Register {
        return switch (@intFromEnum(self)) {
            @intFromEnum(Register.x0)...@intFromEnum(Register.xzr) => @as(
                Register,
                @enumFromInt(@intFromEnum(self) - @intFromEnum(Register.x0) + @intFromEnum(Register.w0)),
            ),
            @intFromEnum(Register.w0)...@intFromEnum(Register.wzr) => @as(
                Register,
                @enumFromInt(@intFromEnum(self) - @intFromEnum(Register.w0) + @intFromEnum(Register.w0)),
            ),
            else => unreachable,
        };
    }

    fn alias(self: Register, s: Size) Register {
        return switch (s) {
            .@"32" => self.toW(),
            .@"64" => self.toX(),
        };
    }

    fn zero(s: Size) Register {
        return switch (s) {
            .@"32" => .wzr,
            .@"64" => .xzr,
        };
    }
};

pub const Instruction = union(enum) {
    move_wide_immediate: packed struct {
        rd: u5,
        imm16: u16,
        hw: u2,
        fixed: u6 = 0b100101,
        opc: u2,
        sf: u1,
    },
    unconditional_branch_register: packed struct {
        op4: u5,
        rn: u5,
        op3: u6,
        op2: u5,
        opc: u4,
        fixed: u7 = 0b1101_011,
    },
    data_processing_2_source: packed struct {
        rd: u5,
        rn: u5,
        opcode: u6,
        rm: u5,
        fixed_1: u8 = 0b11010110,
        s: u1,
        fixed_2: u1 = 0b0,
        sf: u1,
    },
    bitfield: packed struct {
        rd: u5,
        rn: u5,
        imms: u6,
        immr: u6,
        n: u1,
        fixed: u6 = 0b100110,
        opc: u2,
        sf: u1,
    },
    data_processing_3_source: packed struct {
        rd: u5,
        rn: u5,
        ra: u5,
        o0: u1,
        rm: u5,
        op31: u3,
        fixed: u5 = 0b11011,
        op54: u2,
        sf: u1,
    },
    add_subtract_shifted_register: packed struct {
        rd: u5,
        rn: u5,
        imm6: u6,
        rm: u5,
        fixed_1: u1 = 0b0,
        shift: u2,
        fixed_2: u5 = 0b01011,
        s: u1,
        op: u1,
        sf: u1,
    },
    logical_shifted_register: packed struct(u32) {
        rd: u5,
        rn: u5,
        imm6: u6,
        rm: u5,
        n: u1,
        shift: u2,
        fixed: u5 = 0b01010,
        opc: u2,
        sf: u1,
    },

    const Size = enum(u6) {
        s0 = 0,
        s8 = 8,
        s16 = 16,
        s32 = 32,
        s64 = 64,
    };

    fn mov(dst: Register, src: Register) Instruction {
        return orrShiftedRegister(dst, Register.zero(src.size()), src, .lsl, 0);
    }

    fn movk(rd: Register, imm16: u16, shift: u6) Instruction {
        return moveWideImmediate(0b11, rd, imm16, shift);
    }

    fn @"and"(rd: Register, rn: Register, rm: Register) Instruction {
        return andShiftedRegister(rd, rn, rm, .lsl, 0);
    }

    fn andShiftedRegister(
        rd: Register,
        rn: Register,
        rm: Register,
        shift: LogicalShiftedRegisterShift,
        amount: u6,
    ) Instruction {
        return logicalShiftedRegister(0b00, 0b0, rd, rn, rm, shift, amount);
    }

    fn @"or"(rd: Register, rn: Register, rm: Register) Instruction {
        return logicalShiftedRegister(0b01, 0b0, rd, rn, rm, .lsl, 0);
    }

    fn orrShiftedRegister(
        rd: Register,
        rn: Register,
        rm: Register,
        shift: LogicalShiftedRegisterShift,
        amount: u6,
    ) Instruction {
        return logicalShiftedRegister(0b01, 0b0, rd, rn, rm, shift, amount);
    }

    fn xor(rd: Register, rn: Register, rm: Register) Instruction {
        return eorShiftedRegister(rd, rn, rm, .lsl, 0);
    }

    fn eorShiftedRegister(
        rd: Register,
        rn: Register,
        rm: Register,
        shift: LogicalShiftedRegisterShift,
        amount: u6,
    ) Instruction {
        return logicalShiftedRegister(0b10, 0b0, rd, rn, rm, shift, amount);
    }

    const LogicalShiftedRegisterShift = enum(u2) { lsl, lsr, asr, ror };

    fn logicalShiftedRegister(
        opc: u2,
        n: u1,
        rd: Register,
        rn: Register,
        rm: Register,
        shift: LogicalShiftedRegisterShift,
        amount: u6,
    ) Instruction {
        assert(rd.size() == rn.size());
        assert(rd.size() == rm.size());
        if (rd.size() == .@"32") assert(amount < 32);

        return Instruction{
            .logical_shifted_register = .{
                .rd = rd.enc(),
                .rn = rn.enc(),
                .imm6 = amount,
                .rm = rm.enc(),
                .n = n,
                .shift = @intFromEnum(shift),
                .opc = opc,
                .sf = switch (rd.size()) {
                    .@"32" => 0b0,
                    .@"64" => 0b1,
                },
            },
        };
    }

    fn moveWideImmediate(
        opc: u2,
        rd: Register,
        imm16: u16,
        shift: u6,
    ) Instruction {
        assert(shift % 16 == 0);
        assert(!(rd.size() == .@"32" and shift > 16));
        assert(!(rd.size() == .@"32" and shift > 48));

        return Instruction{
            .move_wide_immediate = .{
                .rd = rd.enc(),
                .imm16 = imm16,
                .hw = @intCast(shift / 16),
                .opc = opc,
                .sf = switch (rd.size()) {
                    .@"32" => 0,
                    .@"64" => 1,
                },
            },
        };
    }

    fn ret(rn: ?Register) Instruction {
        return unconditionalBranchRegister(0b0010, 0b11111, 0b000000, rn orelse .lr, 0b00000);
    }

    fn unconditionalBranchRegister(
        opc: u4,
        op2: u5,
        op3: u6,
        rn: Register,
        op4: u5,
    ) Instruction {
        assert(rn.size() == .@"64");

        return Instruction{
            .unconditional_branch_register = .{
                .op4 = op4,
                .rn = rn.enc(),
                .op3 = op3,
                .op2 = op2,
                .opc = opc,
            },
        };
    }

    pub const AddSubtractShiftedRegisterShift = enum(u2) { lsl, lsr, asr, _ };

    fn add(rd: Register, rn: Register, rm: Register) Instruction {
        return addShiftedRegister(rd, rn, rm, .lsl, 0);
    }

    fn addShiftedRegister(
        rd: Register,
        rn: Register,
        rm: Register,
        shift: AddSubtractShiftedRegisterShift,
        imm6: u6,
    ) Instruction {
        return addSubtractShiftedRegister(0b0, 0b0, shift, rd, rn, rm, imm6);
    }

    fn addSubtractShiftedRegister(
        op: u1,
        s: u1,
        shift: AddSubtractShiftedRegisterShift,
        rd: Register,
        rn: Register,
        rm: Register,
        imm6: u6,
    ) Instruction {
        assert(rd.size() == rn.size());
        assert(rd.size() == rm.size());

        return Instruction{
            .add_subtract_shifted_register = .{
                .rd = rd.enc(),
                .rn = rn.enc(),
                .imm6 = imm6,
                .rm = rm.enc(),
                .shift = @intFromEnum(shift),
                .s = s,
                .op = op,
                .sf = switch (rd.size()) {
                    .@"32" => 0b0,
                    .@"64" => 0b1,
                },
            },
        };
    }

    fn lslv(rd: Register, rn: Register, rm: Register) Instruction {
        return dataProcessing2Source(0b0, 0b001000, rd, rn, rm);
    }

    fn lsrv(rd: Register, rn: Register, rm: Register) Instruction {
        return dataProcessing2Source(0b0, 0b001001, rd, rn, rm);
    }

    fn dataProcessing2Source(
        s: u1,
        opcode: u6,
        rd: Register,
        rn: Register,
        rm: Register,
    ) Instruction {
        assert(rd.size() == rn.size());
        assert(rd.size() == rm.size());

        return Instruction{
            .data_processing_2_source = .{
                .rd = rd.enc(),
                .rn = rn.enc(),
                .opcode = opcode,
                .rm = rm.enc(),
                .s = s,
                .sf = switch (rd.size()) {
                    .@"32" => 0b0,
                    .@"64" => 0b1,
                },
            },
        };
    }

    fn dataProcessing3Source(
        op54: u2,
        op31: u3,
        o0: u1,
        rd: Register,
        rn: Register,
        rm: Register,
        ra: Register,
    ) Instruction {
        return Instruction{
            .data_processing_3_source = .{
                .rd = rd.enc(),
                .rn = rn.enc(),
                .ra = ra.enc(),
                .o0 = o0,
                .rm = rm.enc(),
                .op31 = op31,
                .op54 = op54,
                .sf = switch (rd.size()) {
                    .@"32" => 0b0,
                    .@"64" => 0b1,
                },
            },
        };
    }

    fn madd(rd: Register, rn: Register, rm: Register, ra: Register) Instruction {
        return dataProcessing3Source(0b00, 0b000, 0b0, rd, rn, rm, ra);
    }

    fn mul(rd: Register, rn: Register, rm: Register) Instruction {
        return madd(rd, rn, rm, .xzr);
    }

    fn initBitfield(
        opc: u2,
        n: u1,
        rd: Register,
        rn: Register,
        immr: u6,
        imms: u6,
    ) Instruction {
        assert(rd.size() == rn.size());
        assert(!(rd.size() == .@"64" and n != 1));
        assert(!(rd.size() == .@"32" and (n != 0 or immr >> 5 != 0 or immr >> 5 != 0)));

        return Instruction{
            .bitfield = .{
                .rd = rd.enc(),
                .rn = rn.enc(),
                .imms = imms,
                .immr = immr,
                .n = n,
                .opc = opc,
                .sf = switch (rd.size()) {
                    .@"32" => 0b0,
                    .@"64" => 0b1,
                },
            },
        };
    }

    pub fn sbfm(rd: Register, rn: Register, immr: u6, imms: u6) Instruction {
        const n: u1 = switch (rd.size()) {
            .@"32" => 0b0,
            .@"64" => 0b1,
        };
        return initBitfield(0b00, n, rd, rn, immr, imms);
    }

    pub fn sxtb(rd: Register, rn: Register) Instruction {
        return sbfm(rd, rn, 0, 7);
    }

    pub fn sxth(rd: Register, rn: Register) Instruction {
        return sbfm(rd, rn, 0, 15);
    }

    pub fn sxtw(rd: Register, rn: Register) Instruction {
        assert(rd.size() == .@"64");
        return sbfm(rd, rn, 0, 31);
    }
};

pub const caller_saved_registers = [_]Register{ .x9, .x10, .x11, .x12, .x13, .x14, .x15 };
pub const argument_registers = [_]Register{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };
pub const callee_saved_registers = [_]Register{ .x19, .x20, .x21, .x22, .x23, .x24, .x25, .x26, .x27, .x28 };
pub const scratch_registers = [_]Register{
    caller_saved_registers[1],
    caller_saved_registers[2],
    caller_saved_registers[3],
    caller_saved_registers[4],
};

pub const table: Engine.Table = .{
    .loadImmediate = emitLoadImmediate,
    .binOpReg = emitBinOpReg,
    .movReg = emitMovReg,
    .exit = emitExit,
};

fn ensureUnusedCap(
    buf: *std.ArrayListAlignedUnmanaged(u8, std.mem.page_size),
    allocator: std.mem.Allocator,
    size: usize,
) !usize {
    if (buf.items.len + size > buf.capacity) {
        var increment = buf.capacity / 2;
        if (increment <= std.mem.page_size) {
            increment = std.mem.page_size;
        }
        try buf.ensureTotalCapacityPrecise(allocator, buf.capacity + increment);
    }
    return buf.items.len;
}

fn emitInst(e: *Engine, instruction: Instruction) !void {
    const start = try ensureUnusedCap(&e.code, e.allocator, @sizeOf(u32));
    e.code.items.len += @sizeOf(u32);
    std.mem.writeInt(
        u32,
        e.code.items.ptr[start..][0..@sizeOf(u32)],
        switch (instruction) {
            inline else => |payload| @bitCast(payload),
        },
        .little,
    );
}

fn emitLoadImmediate(e: *Engine, dst: Register, src: u64, size: Register.Size) Engine.Error!void {
    // clear the destination register
    try emitInst(e, Instruction.mov(dst.alias(size), Register.zero(size)));

    // mov the immediate into the destination register, 16 bits at a time
    var imm = src;
    var shift: u6 = 0;
    while (imm != 0) {
        try emitInst(e, Instruction.movk(dst.alias(size), @truncate(imm), shift << 4));
        shift += 1;
        imm >>= 16;
    }
}

fn emitBinOpReg(
    e: *Engine,
    dst: Register,
    src: Register,
    size: Register.Size,
    op: Engine.Operation,
) Engine.Error!void {
    const adst = dst.alias(size);
    const asrc = src.alias(size);

    const inst = switch (op) {
        .add => Instruction.add(adst, adst, asrc),
        .mul => Instruction.mul(adst, adst, asrc),
        .@"or" => Instruction.@"or"(adst, adst, asrc),
        .xor => Instruction.xor(adst, adst, asrc),
        .@"and" => Instruction.@"and"(adst, adst, asrc),
        .lsh => Instruction.lslv(adst, adst, asrc),
        .rsh => Instruction.lsrv(adst, adst, asrc),
    };
    try emitInst(e, inst);

    switch (op) {
        .mul => if (size == .@"32") try emitInst(e, Instruction.sxtw(
            dst.alias(.@"64"),
            dst.alias(.@"64"),
        )),
        else => {},
    }
}

fn emitMovReg(e: *Engine, dst: Register, src: Register) Engine.Error!void {
    try emitInst(e, Instruction.mov(dst, src));
}

fn emitExit(e: *Engine) Engine.Error!void {
    // move the "r0" register into x0 for the return value
    try emitInst(e, Instruction.mov(.x0, caller_saved_registers[0]));
    try emitInst(e, Instruction.ret(null));
}
