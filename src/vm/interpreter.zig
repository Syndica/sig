const std = @import("std");
const lib = @import("lib.zig");
const sbpf = @import("sbpf.zig");
const memory = @import("memory.zig");
const syscalls = @import("syscalls.zig");
const transaction_context = @import("../runtime/transaction_context.zig");

const MemoryMap = memory.MemoryMap;
const Instruction = sbpf.Instruction;
const Executable = lib.Executable;
const BuiltinProgram = lib.BuiltinProgram;
const TransactionContext = transaction_context.TransactionContext;

pub const RegisterMap = std.EnumArray(sbpf.Instruction.Register, u64);

pub const Vm = struct {
    allocator: std.mem.Allocator,
    executable: *const Executable,

    registers: RegisterMap,
    memory_map: MemoryMap,
    loader: *const BuiltinProgram,

    vm_addr: u64,
    call_frames: std.ArrayListUnmanaged(CallFrame),
    depth: u64,
    instruction_count: u64,
    transaction_context: *TransactionContext,
    result: Result,

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
        ctx: *TransactionContext,
    ) error{OutOfMemory}!Vm {
        const offset = if (executable.version.enableDynamicStackFrames())
            stack_len
        else
            executable.config.stack_frame_size;
        const stack_pointer = memory.STACK_START +% offset;
        var self: Vm = .{
            .executable = executable,
            .allocator = allocator,
            .registers = RegisterMap.initFill(0),
            .memory_map = memory_map,
            .depth = 0,
            .call_frames = try std.ArrayListUnmanaged(CallFrame).initCapacity(allocator, 64),
            .instruction_count = 0,
            .vm_addr = executable.text_vaddr,
            .loader = loader,
            .transaction_context = ctx,
            .result = .{ .ok = 0 },
        };

        self.registers.set(.r10, stack_pointer);
        self.registers.set(.r1, memory.INPUT_START);
        self.registers.set(.pc, executable.entry_pc);

        return self;
    }

    pub fn deinit(self: *Vm) void {
        self.call_frames.deinit(self.allocator);
    }

    pub fn run(self: *Vm) struct { Result, u64 } {
        // std.debug.print("\nVM Run\n", .{});
        const initial_instruction_count = self.transaction_context.getRemaining();
        while (true) {
            const cont = self.step() catch |err| {
                self.result = .{ .err = err };
                break;
            };
            if (!cont) break;
        }
        // https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/vm.rs#L380-L385
        const instruction_count = if (self.executable.config.enable_instruction_meter) blk: {
            self.transaction_context.consumeUnchecked(self.instruction_count);
            break :blk initial_instruction_count -| self.transaction_context.getRemaining();
        } else 0;
        return .{ self.result, instruction_count };
    }

    fn step(self: *Vm) SbpfError!bool {
        // std.debug.print("\n\tVM Step\n", .{});
        const config = self.executable.config;
        if (config.enable_instruction_meter and
            self.instruction_count >= self.transaction_context.getRemaining())
        {
            return error.ExceededMaxInstructions;
        }

        self.instruction_count += 1;
        const version = self.executable.version;
        const registers = &self.registers;
        const pc = registers.get(.pc);
        // std.debug.print("\t\tpc = {}\n", .{pc});
        // std.debug.print("\t\tinstructions.len = {}\n", .{self.executable.instructions.len});
        var next_pc: u64 = pc + 1;

        const instructions = self.executable.instructions;
        const inst = instructions[pc];
        const opcode = inst.opcode;

        if (version.moveMemoryInstructionClasses()) {
            switch (opcode) {
                // reserved opcodes
                .mul32_imm,
                .mod32_imm,
                .div32_imm,
                => return error.UnknownInstruction,

                inline
                // LD_1B_REG
                .mul32_reg,
                // LD_2B_REG
                .div32_reg,
                // LD_4B_REG
                .ld_4b_reg,
                // LD_8B_REG
                .mod32_reg,
                => |tag| {
                    const T = switch (tag) {
                        .mul32_reg => u8,
                        .div32_reg => u16,
                        .ld_4b_reg => u32,
                        .mod32_reg => u64,
                        else => unreachable,
                    };
                    const base_address: i64 = @bitCast(registers.get(inst.src));
                    const vm_addr: u64 = @bitCast(base_address +% @as(i64, inst.off));
                    registers.set(inst.dst, try self.load(T, vm_addr));
                },

                inline
                // ST_1B_IMM
                .mul64_imm,
                // ST_2B_IMM
                .div64_imm,
                // ST_4B_IMM
                .neg64,
                // ST_8B_IMM
                .mod64_imm,
                => |tag| {
                    const T = switch (tag) {
                        .mul64_imm => u8,
                        .div64_imm => u16,
                        .neg64 => u32,
                        .mod64_imm => u64,
                        else => unreachable,
                    };
                    const base_address: i64 = @bitCast(registers.get(inst.dst));
                    const vm_addr: u64 = @bitCast(base_address +% @as(i64, inst.off));
                    try self.store(T, vm_addr, @truncate(@as(u64, inst.imm)));
                },

                inline
                // ST_1B_REG
                .mul64_reg,
                // ST_2B_REG
                .div64_reg,
                // ST_4B_REG
                .st_4b_reg,
                // ST_8B_REG
                .mod64_reg,
                => |tag| {
                    const T = switch (tag) {
                        .mul64_reg => u8,
                        .div64_reg => u16,
                        .st_4b_reg => u32,
                        .mod64_reg => u64,
                        else => unreachable,
                    };
                    const base_address: i64 = @bitCast(registers.get(inst.dst));
                    const vm_addr: u64 = @bitCast(base_address +% @as(i64, inst.off));
                    try self.store(T, vm_addr, @truncate(registers.get(inst.src)));
                },

                else => {},
            }
        }

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
            => cont: {
                if (version.moveMemoryInstructionClasses()) {
                    // instructions handled above
                    switch (@intFromEnum(opcode) & 0xF0) {
                        Instruction.mod,
                        Instruction.neg,
                        Instruction.mul,
                        Instruction.div,
                        => break :cont,
                        else => {},
                    }
                }

                switch (opcode.is64()) {
                    inline //
                    true,
                    false,
                    => |is_64| {
                        const Int = if (is_64) u64 else u32;
                        const SignedInt = if (is_64) i64 else i32;

                        const lhs: Int = @truncate(registers.get(inst.dst));
                        const rhs: Int = @truncate(if (opcode.isReg())
                            registers.get(inst.src)
                        else
                            extend(inst.imm));

                        const result: Int = switch (@intFromEnum(opcode) & 0b11110000) {
                            // zig fmt: off
                            Instruction.add    => lhs +% rhs,
                            Instruction.div    => try std.math.divTrunc(Int, lhs, rhs),
                            Instruction.xor    => lhs ^ rhs,
                            Instruction.@"or"  => lhs | rhs,
                            Instruction.@"and" => lhs & rhs,
                            Instruction.mov    => rhs,
                            Instruction.mod    => try std.math.mod(Int, lhs, rhs),
                            Instruction.lsh    => lhs << @truncate(rhs),
                            Instruction.rsh    => lhs >> @truncate(rhs),
                            // zig fmt: on
                            Instruction.sub => switch (opcode) {
                                .sub64_imm, .sub32_imm => if (version.swapSubRegImmOperands())
                                    rhs -% lhs
                                else
                                    lhs -% rhs,
                                .sub64_reg, .sub32_reg => lhs -% rhs,
                                else => unreachable,
                            },
                            Instruction.mul => value: {
                                if (is_64) break :value lhs *% rhs;
                                const lhs_signed: SignedInt = @bitCast(lhs);
                                const rhs_signed: SignedInt = @bitCast(rhs);
                                break :value @bitCast(lhs_signed *% rhs_signed);
                            },
                            Instruction.neg => value: {
                                if (version.disableNegation()) return error.UnknownInstruction;
                                const signed: SignedInt = @bitCast(lhs);
                                break :value @bitCast(-signed);
                            },
                            Instruction.arsh => value: {
                                const signed: SignedInt = @bitCast(lhs);
                                break :value @bitCast(signed >> @truncate(rhs));
                            },
                            Instruction.hor => if (version.disableLddw()) value: {
                                // The hor instruction only exists as hor64_imm, but Zig can't tell
                                // that the the opcode can't possibly reach here. We'll nicely hint
                                // to it, by specializing the rest of the function
                                // behind the `is_64` boolean.
                                if (!is_64) return error.UnknownInstruction;
                                break :value lhs | @as(u64, inst.imm) << 32;
                            } else return error.UnknownInstruction,
                            else => std.debug.panic("{s}", .{@tagName(opcode)}),
                        };

                        const large_result: u64 = switch (@intFromEnum(opcode) & 0b11110000) {
                            // The mul32 instruction requires a sign extension to u64 from i32.
                            Instruction.mul => if (is_64) result else extend(result),
                            else => result,
                        };
                        registers.set(inst.dst, large_result);
                    },
                }
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
            .exit_or_syscall,
            .@"return",
            => {
                if (opcode == .exit_or_syscall and version.enableStaticSyscalls()) {
                    // SBPFv3 SYSCALL instruction
                    if (self.loader.functions.lookupKey(inst.imm)) |entry| {
                        entry.value(self.transaction_context, &self.memory_map, self.registers) catch |err| {
                            std.debug.print("syscall error: {}\n", .{err});
                            return err;
                        };
                    } else {
                        @panic("TODO: detect invalid syscall in verifier");
                    }
                } else {
                    if (opcode == .@"return" and !version.enableStaticSyscalls()) {
                        return error.UnknownInstruction;
                    }

                    if (self.depth == 0) {
                        if (config.enable_instruction_meter and
                            self.instruction_count > self.transaction_context.getRemaining())
                        {
                            return error.ExceededMaxInstructions;
                        }
                        self.result = .{ .ok = self.registers.get(.r0) };
                        return false;
                    }
                    self.depth -= 1;
                    const frame = self.call_frames.pop();
                    self.registers.set(.r10, frame.fp);
                    @memcpy(self.registers.values[6..][0..4], &frame.caller_saved_regs);
                    if (!version.enableDynamicStackFrames()) {
                        registers.getPtr(.r10).* -= config.stack_frame_size;
                    }
                    next_pc = frame.return_pc;
                }
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
                        try builtin_fn(self.transaction_context, &self.memory_map, self.registers);
                    }
                }

                if (internal and !resolved) {
                    const target_pc = version.computeTargetPc(pc, inst);
                    if (self.executable.function_registry.lookupKey(target_pc)) |entry| {
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
                if (version.disableLddw()) return error.UnknownInstruction;
                const value: u64 = (@as(u64, instructions[next_pc].imm) << 32) | inst.imm;
                registers.set(inst.dst, value);
                next_pc += 1;
            },

            // handled above
            .ld_4b_reg,
            .st_4b_reg,
            => if (!version.moveMemoryInstructionClasses()) return error.UnknownInstruction,

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

pub const SbpfError = error{
    ExceededMaxInstructions,
    UnknownInstruction,
    Overflow,
    InvalidVirtualAddress,
    AccessNotMapped,
    VirtualAccessTooLong,
    AccessViolation,
    CallDepthExceeded,
    UnresolvedFunction,
    DivisionByZero,
    PcOutOfBounds,
} || syscalls.Error;

/// Contains either an error encountered while executing the program, or the
/// result, which is the value of the `r0` register at the time of exit.
///
/// [agave] https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/error.rs#L170-L171
pub const Result = union(enum) {
    err: SbpfError,
    ok: u64,

    /// Helper function for creating the `Result` from an inline value.
    pub fn fromValue(val: anytype) Result {
        if (!@import("builtin").is_test) @compileError("only used in tests");
        return @unionInit(Result, if (@typeInfo(@TypeOf(val)) == .ErrorSet) "err" else "ok", val);
    }
};
