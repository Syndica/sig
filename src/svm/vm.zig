const std = @import("std");
const lib = @import("lib.zig");
const sbpf = @import("sbpf.zig");
const memory = @import("memory.zig");
const jit = @import("jit.zig");

const MemoryMap = memory.MemoryMap;
const Instruction = sbpf.Instruction;
const Executable = lib.Executable;
const BuiltinProgram = lib.BuiltinProgram;
const Engine = jit.Engine;

pub const Vm = struct {
    allocator: std.mem.Allocator,
    executable: *const Executable,

    registers: std.EnumArray(sbpf.Instruction.Register, u64),
    memory_map: MemoryMap,
    loader: *const BuiltinProgram,

    vm_addr: u64,
    call_frames: std.ArrayListUnmanaged(CallFrame),
    depth: u64,
    instruction_count: u64,

    const CallFrame = struct {
        caller_saved_regs: [4]u64,
        fp: u64,
        return_pc: u64,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        executable: *const Executable,
        memory_map: MemoryMap,
        loader: *const BuiltinProgram,
        stack_len: u64,
    ) !Vm {
        const offset = if (executable.version.enableDynamicStackFrames())
            stack_len
        else
            executable.config.stack_frame_size;
        const stack_pointer = memory.STACK_START +% offset;
        var self: Vm = .{
            .executable = executable,
            .allocator = allocator,
            .registers = std.EnumArray(sbpf.Instruction.Register, u64).initFill(0),
            .memory_map = memory_map,
            .depth = 0,
            .call_frames = try std.ArrayListUnmanaged(CallFrame).initCapacity(allocator, 64),
            .instruction_count = 0,
            .vm_addr = executable.text_vaddr,
            .loader = loader,
        };

        self.registers.set(.r10, stack_pointer);
        self.registers.set(.r1, memory.INPUT_START);
        self.registers.set(.pc, executable.entry_pc);

        return self;
    }

    pub fn deinit(self: *Vm) void {
        self.call_frames.deinit(self.allocator);
    }

    pub fn run(self: *Vm) !u64 {
        while (try self.step()) {
            self.instruction_count += 1;
        }
        return self.registers.get(.r0);
    }

    pub fn runJit(self: *Vm) !u64 {
        var engine = Engine.init(self.allocator);
        defer engine.deinit();

        try engine.compile(self.executable.instructions);
        const code = engine.code.items;
        const page = code.ptr[0..engine.code.capacity];
        try std.posix.mprotect(page, std.posix.PROT.READ | std.posix.PROT.EXEC);
        defer std.posix.mprotect(page, std.posix.PROT.WRITE) catch @panic("failed to mprotect");

        const main: *const fn () callconv(.C) u64 = @ptrCast(code.ptr);
        const result = main();
        return result;
    }

    fn step(self: *Vm) !bool {
        const version = self.executable.version;
        const registers = &self.registers;
        const pc = registers.get(.pc);
        var next_pc: u64 = pc + 1;

        const instructions = self.executable.instructions;
        const inst = instructions[pc];
        const opcode = inst.opcode;

        switch (opcode) {
            // alu operations
            .add64_reg,
            .add64_imm,
            .add32_reg,
            .add32_imm,
            .mul64_reg,
            .mul64_imm,
            .mul32_reg,
            .mul32_imm,
            .sub64_reg,
            .sub64_imm,
            .sub32_reg,
            .sub32_imm,
            .div64_reg,
            .div64_imm,
            .div32_reg,
            .div32_imm,
            .xor64_reg,
            .xor64_imm,
            .xor32_reg,
            .xor32_imm,
            .or64_reg,
            .or64_imm,
            .or32_reg,
            .or32_imm,
            .and64_reg,
            .and64_imm,
            .and32_reg,
            .and32_imm,
            .mod64_reg,
            .mod64_imm,
            .mod32_reg,
            .mod32_imm,
            .mov64_reg,
            .mov64_imm,
            .mov32_reg,
            .mov32_imm,
            .neg32,
            .neg64,
            .arsh64_reg,
            .arsh64_imm,
            .arsh32_reg,
            .arsh32_imm,
            .hor64_imm,
            .lsh64_reg,
            .lsh64_imm,
            .lsh32_reg,
            .lsh32_imm,
            .rsh64_reg,
            .rsh64_imm,
            .rsh32_reg,
            .rsh32_imm,
            => {
                const lhs_large = registers.get(inst.dst);
                const rhs_large = if (opcode.isReg())
                    registers.get(inst.src)
                else
                    extend(inst.imm);
                const lhs: u64 = if (opcode.is64()) lhs_large else @as(u32, @truncate(lhs_large));
                const rhs: u64 = if (opcode.is64()) rhs_large else @as(u32, @truncate(rhs_large));

                var result: u64 = switch (@intFromEnum(opcode) & 0xF0) {
                    Instruction.sub => switch (opcode) {
                        .sub64_imm, .sub32_imm => if (version.swapSubRegImmOperands())
                            rhs -% lhs
                        else
                            lhs -% rhs,
                        .sub64_reg, .sub32_reg => lhs -% rhs,
                        else => unreachable,
                    },
                    Instruction.lsh => if (opcode.is64())
                        lhs << @truncate(rhs)
                    else
                        @as(u32, @truncate(lhs)) << @truncate(rhs),
                    Instruction.rsh => if (opcode.is64())
                        lhs >> @truncate(rhs)
                    else
                        @as(u32, @truncate(lhs)) >> @truncate(rhs),
                    // zig fmt: off
                    Instruction.add    => lhs +% rhs,
                    Instruction.div    => try std.math.divTrunc(u64, lhs, rhs),
                    Instruction.xor    => lhs ^ rhs,
                    Instruction.@"or"  => lhs | rhs,
                    Instruction.@"and" => lhs & rhs,
                    Instruction.mod    => try std.math.mod(u64, lhs, rhs),
                    Instruction.mov    => rhs,
                    // zig fmt: on
                    Instruction.mul => value: {
                        if (opcode.is64()) break :value lhs *% rhs;
                        const lhs_signed: i32 = @bitCast(@as(u32, @truncate(lhs)));
                        const rhs_signed: i32 = @bitCast(@as(u32, @truncate(rhs)));
                        break :value @bitCast(@as(i64, lhs_signed *% rhs_signed));
                    },
                    Instruction.neg => value: {
                        if (version.disableNegation()) return error.UnknownInstruction;
                        const signed: i64 = @bitCast(lhs);
                        const negated: u64 = @bitCast(-signed);
                        break :value if (opcode.is64()) negated else @as(u32, @truncate(negated));
                    },
                    Instruction.arsh => value: {
                        if (opcode.is64()) {
                            const signed: i64 = @bitCast(lhs);
                            const shifted: u64 = @bitCast(signed >> @truncate(rhs));
                            break :value shifted;
                        } else {
                            const signed: i32 = @bitCast(@as(u32, @truncate(lhs)));
                            const shifted: u32 = @bitCast(signed >> @truncate(rhs));
                            break :value shifted;
                        }
                    },
                    Instruction.hor => if (version.disableLDDW()) value: {
                        break :value lhs_large | @as(u64, inst.imm) << 32;
                    } else return error.UnknownInstruction,
                    else => unreachable,
                };

                switch (@intFromEnum(opcode) & 0xF0) {
                    Instruction.add,
                    => if (!opcode.is64()) {
                        result = @as(u32, @truncate(result));
                    },
                    else => {},
                }

                registers.set(inst.dst, result);
            },

            .lmul32_reg,
            .lmul32_imm,
            .udiv32_reg,
            .udiv32_imm,
            .urem32_reg,
            .urem32_imm,
            .sdiv32_reg,
            .sdiv32_imm,
            .srem32_reg,
            .srem32_imm,
            => {
                if (!version.enablePqr()) return error.UnknownInstruction;
                const lhs_large = registers.get(inst.dst);
                const rhs_large = if (opcode.isReg()) registers.get(inst.src) else inst.imm;

                const opc = @intFromEnum(opcode) & 0b11100000;
                const extended: u64 = switch (opc) {
                    Instruction.lmul,
                    Instruction.sdiv,
                    Instruction.srem,
                    => result: {
                        const lhs: i32 = @truncate(@as(i64, @bitCast(lhs_large)));
                        const rhs: i32 = @truncate(@as(i64, @bitCast(rhs_large)));
                        const result = switch (opc) {
                            Instruction.lmul => lhs *% rhs,
                            Instruction.sdiv => try std.math.divTrunc(i32, lhs, rhs),
                            Instruction.srem => try rem(i32, lhs, rhs),
                            else => unreachable,
                        };
                        break :result @bitCast(@as(i64, result));
                    },
                    Instruction.urem,
                    Instruction.udiv,
                    => result: {
                        const lhs: u32 = @truncate(lhs_large);
                        const rhs: u32 = @truncate(rhs_large);
                        break :result switch (opc) {
                            Instruction.urem => try std.math.rem(u32, lhs, rhs),
                            Instruction.udiv => try std.math.divTrunc(u32, lhs, rhs),
                            else => unreachable,
                        };
                    },
                    else => unreachable,
                };

                registers.set(inst.dst, extended);
            },

            .lmul64_reg,
            .lmul64_imm,
            .uhmul64_reg,
            .uhmul64_imm,
            .shmul64_reg,
            .shmul64_imm,
            .udiv64_reg,
            .udiv64_imm,
            .urem64_reg,
            .urem64_imm,
            .sdiv64_reg,
            .sdiv64_imm,
            .srem64_reg,
            .srem64_imm,
            => {
                if (!version.enablePqr()) return error.UnknownInstruction;
                const lhs = registers.get(inst.dst);
                const rhs = if (opcode.isReg()) registers.get(inst.src) else inst.imm;

                const opc = @intFromEnum(opcode) & 0b11100000;
                const result: u64 = switch (opc) {
                    Instruction.lmul => lhs *% rhs,
                    Instruction.udiv => try std.math.divTrunc(u64, lhs, rhs),
                    Instruction.urem => try std.math.rem(u64, lhs, rhs),
                    Instruction.sdiv => result: {
                        const result = try std.math.divTrunc(i64, @bitCast(lhs), @bitCast(rhs));
                        break :result @bitCast(result);
                    },
                    Instruction.uhmul => result: {
                        const result = @as(u128, lhs) *% @as(u128, rhs);
                        break :result @truncate(result >> 64);
                    },
                    Instruction.shmul,
                    Instruction.srem,
                    => result: {
                        const signed_lhs: i64 = @bitCast(lhs);
                        const signed_rhs: i64 = @bitCast(rhs);
                        const result: i64 = switch (opc) {
                            Instruction.shmul => value: {
                                const result = @as(i128, signed_lhs) *% @as(i128, signed_rhs);
                                break :value @truncate(result >> 64);
                            },
                            Instruction.srem => try rem(i64, signed_lhs, signed_rhs),
                            else => unreachable,
                        };
                        break :result @bitCast(result);
                    },
                    else => unreachable,
                };
                registers.set(inst.dst, result);
            },

            // loads/stores
            inline //
            .ld_b_reg,
            .st_b_reg,
            .st_b_imm,

            .ld_h_reg,
            .st_h_reg,
            .st_h_imm,

            .ld_w_reg,
            .st_w_reg,
            .st_w_imm,

            .ld_dw_reg,
            .st_dw_reg,
            .st_dw_imm,
            => |code| {
                const T = switch (code) {
                    .ld_b_reg,
                    .st_b_reg,
                    .st_b_imm,
                    => u8,
                    .ld_h_reg,
                    .st_h_reg,
                    .st_h_imm,
                    => u16,
                    .ld_w_reg,
                    .st_w_reg,
                    .st_w_imm,
                    => u32,
                    .ld_dw_reg,
                    .st_dw_reg,
                    .st_dw_imm,
                    => u64,
                    else => comptime unreachable,
                };

                const access = code.accessType();
                const addr_reg = if (access == .constant) inst.src else inst.dst;
                const address: i64 = @bitCast(registers.get(addr_reg));
                const vaddr: u64 = @bitCast(address +% inst.off);

                switch (access) {
                    .constant => registers.set(inst.dst, try self.load(T, vaddr)),
                    .mutable => {
                        const operand = switch (@as(u3, @truncate(@intFromEnum(opcode)))) {
                            Instruction.stx => registers.get(inst.src),
                            Instruction.st => inst.imm,
                            else => unreachable,
                        };
                        try self.store(T, vaddr, @truncate(operand));
                    },
                }
            },

            .be,
            .le,
            => {
                if (opcode == .le and !version.enableLe()) return error.UnknownInstruction;
                registers.set(inst.dst, switch (inst.imm) {
                    inline //
                    16,
                    32,
                    64,
                    => |size| std.mem.nativeTo(
                        std.meta.Int(.unsigned, size),
                        @truncate(registers.get(inst.dst)),
                        if (opcode == .le) .little else .big,
                    ),
                    else => return error.UnknownInstruction,
                });
            },

            // branching
            .ja,
            .jeq_imm,
            .jeq_reg,
            .jne_imm,
            .jne_reg,
            .jge_imm,
            .jge_reg,
            .jgt_imm,
            .jgt_reg,
            .jle_imm,
            .jle_reg,
            .jlt_imm,
            .jlt_reg,
            .jset_imm,
            .jset_reg,
            .jsge_imm,
            .jsge_reg,
            .jsgt_imm,
            .jsgt_reg,
            .jsle_imm,
            .jsle_reg,
            .jslt_imm,
            .jslt_reg,
            => {
                const target_pc: u64 = @intCast(@as(i64, @intCast(next_pc)) + inst.off);
                const lhs = registers.get(inst.dst);
                const rhs = if (opcode.isReg()) registers.get(inst.src) else extend(inst.imm);

                // for the signed variants
                const lhs_signed: i64 = @bitCast(lhs);
                const rhs_signed: i64 = if (opcode.isReg())
                    @bitCast(rhs)
                else
                    @as(i32, @bitCast(inst.imm));

                const predicate: bool = switch (opcode) {
                    // zig fmt: off
                .ja => true,
                .jeq_imm,  .jeq_reg  => lhs == rhs,
                .jne_imm,  .jne_reg  => lhs != rhs,
                .jge_imm,  .jge_reg  => lhs >= rhs,
                .jgt_imm,  .jgt_reg  => lhs >  rhs,
                .jle_imm,  .jle_reg  => lhs <= rhs,
                .jlt_imm,  .jlt_reg  => lhs <  rhs,
                .jset_imm, .jset_reg => lhs &  rhs != 0,
                .jsge_imm, .jsge_reg => lhs_signed >= rhs_signed,
                .jsgt_imm, .jsgt_reg => lhs_signed >  rhs_signed,
                .jsle_imm, .jsle_reg => lhs_signed <= rhs_signed,
                .jslt_imm, .jslt_reg => lhs_signed <  rhs_signed,
                // zig fmt: on
                    else => unreachable,
                };
                if (predicate) next_pc = target_pc;
            },

            // calling
            .exit => {
                if (self.depth == 0) {
                    return false;
                }
                self.depth -= 1;
                const frame = self.call_frames.pop();
                self.registers.set(.r10, frame.fp);
                @memcpy(self.registers.values[6..][0..4], &frame.caller_saved_regs);
                if (!version.enableDynamicStackFrames()) {
                    registers.getPtr(.r10).* -= self.executable.config.stack_frame_size;
                }
                next_pc = frame.return_pc;
            },
            .call_imm => {
                var resolved = false;
                const external, const internal = if (version.enableStaticSyscalls())
                    .{ inst.src == .r0, inst.src != .r0 }
                else
                    .{ true, true };
                if (external) {
                    if (self.loader.functions.lookupKey(inst.imm)) |entry| {
                        resolved = true;
                        const builtin_fn = entry.value;
                        try builtin_fn(self);
                    }
                }
                if (internal and !resolved) {
                    if (self.executable.function_registry.lookupKey(inst.imm)) |entry| {
                        resolved = true;
                        try self.pushCallFrame();
                        next_pc = entry.value;
                    }
                }

                if (!resolved) {
                    return error.UnresolvedFunction;
                }
            },
            .call_reg => {
                const src: sbpf.Instruction.Register = if (version.callRegUsesSrcReg())
                    inst.src
                else
                    @enumFromInt(inst.imm);
                const target_pc = registers.get(src);

                try self.pushCallFrame();

                next_pc = (target_pc -% self.vm_addr) / 8;
            },

            // other instructions
            .ld_dw_imm => {
                if (version.disableLDDW()) return error.UnknownInstruction;
                const value: u64 = (@as(u64, instructions[next_pc].imm) << 32) | inst.imm;
                registers.set(inst.dst, value);
                next_pc += 1;
            },
            else => return error.UnknownInstruction,
        }

        if (next_pc >= instructions.len) return error.PcOutOfBounds;
        self.registers.set(.pc, next_pc);
        return true;
    }

    fn load(self: *Vm, T: type, vm_addr: u64) !T {
        const slice = try self.memory_map.vmap(.constant, vm_addr, @sizeOf(T));
        return std.mem.readInt(T, slice[0..@sizeOf(T)], .little);
    }

    fn store(self: *Vm, T: type, vm_addr: u64, value: T) !void {
        const slice = try self.memory_map.vmap(.mutable, vm_addr, @sizeOf(T));
        slice[0..@sizeOf(T)].* = @bitCast(value);
    }

    fn pushCallFrame(self: *Vm) !void {
        const frame = self.call_frames.addOneAssumeCapacity();
        frame.* = .{
            .caller_saved_regs = self.registers.values[6..][0..4].*,
            .fp = self.registers.get(.r10),
            .return_pc = self.registers.get(.pc) + 1,
        };

        self.depth += 1;
        if (self.depth == self.executable.config.max_call_depth) {
            return error.CallDepthExceeded;
        }

        if (!self.executable.version.enableDynamicStackFrames()) {
            self.registers.getPtr(.r10).* += self.executable.config.stack_frame_size;
        }
    }

    /// Performs a i64 sign-extension. This is commonly needed in SBPv0.
    ///
    /// NOTE: only use this inside of the VM impl!
    fn extend(input: anytype) u64 {
        const value: u32 = @truncate(input);
        const signed: i32 = @bitCast(value);
        const extended: i64 = signed;
        return @bitCast(extended);
    }

    pub fn rem(comptime T: type, numerator: T, denominator: T) !T {
        @setRuntimeSafety(false);
        if (denominator == 0) return error.DivisionByZero;
        return @rem(numerator, denominator);
    }
};
