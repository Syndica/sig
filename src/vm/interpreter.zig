const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../sig.zig");

const sbpf = sig.vm.sbpf;
const memory = sig.vm.memory;

const MemoryMap = memory.MemoryMap;
const Instruction = sbpf.Instruction;
const Executable = sig.vm.Executable;
const TransactionContext = sig.runtime.TransactionContext;
const ExecutionError = sig.vm.ExecutionError;
const Syscall = sig.vm.syscalls.SyscallFn;
const SyscallMap = sig.vm.SyscallMap;

pub const RegisterMap = std.EnumArray(sbpf.Instruction.Register, u64);

pub const Vm = struct {
    allocator: std.mem.Allocator,
    executable: *const Executable,

    registers: RegisterMap,
    memory_map: MemoryMap,
    loader: *const SyscallMap,

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
        loader: *const SyscallMap,
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
        self.memory_map.deinit(self.allocator);
    }

    pub fn run(self: *Vm) struct { Result, u64 } {
        const zone = tracy.Zone.init(@src(), .{ .name = "VM.run" });
        defer zone.deinit();

        const initial_instruction_count = self.transaction_context.compute_meter;
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
            break :blk initial_instruction_count -| self.transaction_context.compute_meter;
        } else 0;
        return .{ self.result, instruction_count };
    }

    fn dispatchSyscall(self: *Vm, func: Syscall) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "VM: dispatchSyscall" });
        defer zone.deinit();

        if (self.executable.config.enable_instruction_meter)
            self.transaction_context.consumeUnchecked(self.instruction_count);
        self.instruction_count = 0;
        self.registers.set(.r0, 0);
        try func(
            self.transaction_context,
            &self.memory_map,
            &self.registers,
        );
    }

    fn step(self: *Vm) ExecutionError!bool {
        const config = self.executable.config;
        if (config.enable_instruction_meter and
            self.instruction_count >= self.transaction_context.compute_meter)
        {
            return error.ExceededMaxInstructions;
        }

        self.instruction_count += 1;
        if (self.registers.getPtrConst(.pc).* >= self.executable.instructions.len) {
            return error.ExecutionOverrun;
        }

        const version = self.executable.version;
        const registers = &self.registers;
        const pc = registers.getPtrConst(.pc).*;
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
                => return error.UnsupportedInstruction,

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
                    const base_address: i64 = @bitCast(registers.getPtrConst(inst.src).*);
                    const vm_addr: u64 = @bitCast(base_address +% @as(i64, inst.off));
                    registers.set(inst.dst, try self.memory_map.load(T, vm_addr));
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
                    const base_address: i64 = @bitCast(registers.getPtrConst(inst.dst).*);
                    const vm_addr: u64 = @bitCast(base_address +% @as(i64, inst.off));
                    try self.memory_map.store(T, vm_addr, @truncate(extend(inst.imm)));
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
                    const base_address: i64 = @bitCast(registers.getPtrConst(inst.dst).*);
                    const vm_addr: u64 = @bitCast(base_address +% @as(i64, inst.off));
                    try self.memory_map.store(
                        T,
                        vm_addr,
                        @truncate(registers.getPtrConst(inst.src).*),
                    );
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

                        const lhs: Int = @truncate(registers.getPtrConst(inst.dst).*);
                        const rhs: Int = @truncate(if (opcode.isReg())
                            registers.getPtrConst(inst.src).*
                        else
                            extend(inst.imm));

                        const result: Int = switch (@intFromEnum(opcode) & 0b11110000) {
                            // zig fmt: off
                            Instruction.mov    => rhs,
                            Instruction.add    => lhs +% rhs,
                            Instruction.mul    => lhs *% rhs,
                           
                            Instruction.neg    => -%lhs,
                            Instruction.xor    => lhs ^ rhs,
                            Instruction.@"or"  => lhs | rhs,
                            Instruction.@"and" => lhs & rhs,

                            Instruction.lsh    => lhs << @truncate(rhs),
                            Instruction.rsh    => lhs >> @truncate(rhs),

                            Instruction.div    => try divTrunc(Int, lhs, rhs),
                            Instruction.mod    => try mod(Int, lhs, rhs),
                            // zig fmt: on
                            Instruction.sub => v: {
                                const swapped = !opcode.isReg() and version.swapSubRegImmOperands();
                                break :v if (swapped)
                                    rhs -% lhs
                                else
                                    lhs -% rhs;
                            },
                            Instruction.arsh => value: {
                                const signed: SignedInt = @bitCast(lhs);
                                break :value @bitCast(signed >> @truncate(rhs));
                            },
                            else => std.debug.panic("{s}", .{@tagName(opcode)}),
                        };

                        const large_result: u64 = switch (@intFromEnum(opcode) & 0b11110000) {
                            Instruction.add,
                            Instruction.sub,
                            => if (is_64) result else signExtend(version, @bitCast(result)),
                            // The mul32 instruction requires a sign extension to u64 from i32.
                            Instruction.mul => if (is_64) result else extend(result),
                            Instruction.mov => if (!is_64 and
                                opcode.isReg() and
                                version.explicitSignExtensionOfResults())
                                extend(result)
                            else
                                result,
                            else => result,
                        };
                        registers.set(inst.dst, large_result);
                    },
                }
            },

            .hor64_imm => {
                const lhs = registers.getPtrConst(inst.dst).*;
                const result = lhs | @as(u64, inst.imm) << 32;
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
                if (!version.enablePqr()) return error.UnsupportedInstruction;
                const lhs_large = registers.getPtrConst(inst.dst).*;
                const rhs_large = if (opcode.isReg())
                    registers.getPtrConst(inst.src).*
                else
                    inst.imm;

                const opc = @intFromEnum(opcode) & 0b11100000;
                const extended: u64 = switch (opc) {
                    Instruction.sdiv, Instruction.srem => result: {
                        const lhs: i32 = @truncate(@as(i64, @bitCast(lhs_large)));
                        const rhs: i32 = @truncate(@as(i64, @bitCast(rhs_large)));
                        const result: u32 = @bitCast(switch (opc) {
                            Instruction.sdiv => try divTrunc(i32, lhs, rhs),
                            Instruction.srem => try rem(i32, lhs, rhs),
                            else => unreachable,
                        });
                        break :result result;
                    },
                    Instruction.lmul,
                    Instruction.urem,
                    Instruction.udiv,
                    => result: {
                        const lhs: u32 = @truncate(lhs_large);
                        const rhs: u32 = @truncate(rhs_large);
                        break :result switch (opc) {
                            Instruction.lmul => lhs *% rhs,
                            Instruction.urem => try rem(u32, lhs, rhs),
                            Instruction.udiv => try divTrunc(u32, lhs, rhs),
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
                if (!version.enablePqr()) return error.UnsupportedInstruction;
                const lhs: u64 = registers.getPtrConst(inst.dst).*;
                const rhs: u64 = if (opcode.isReg()) registers.getPtrConst(inst.src).* else inst.imm;
                const signed_rhs: i64 = if (opcode.isReg())
                    @bitCast(registers.getPtrConst(inst.src).*)
                else
                    @bitCast(extend(inst.imm));

                const opc = @intFromEnum(opcode) & 0b11100000;
                const result: u64 = switch (opc) {
                    Instruction.lmul => lhs *% @as(u64, @bitCast(signed_rhs)),
                    Instruction.udiv => try divTrunc(u64, lhs, rhs),
                    Instruction.urem => try rem(u64, lhs, rhs),
                    Instruction.sdiv => result: {
                        const result = try divTrunc(i64, @bitCast(lhs), signed_rhs);
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
                const address: i64 = @bitCast(registers.getPtrConst(addr_reg).*);
                const vaddr: u64 = @bitCast(address +% inst.off);

                switch (access) {
                    .constant => registers.set(inst.dst, try self.memory_map.load(T, vaddr)),
                    .mutable => {
                        const operand = switch (@intFromEnum(opcode) & 0b111) {
                            Instruction.stx => registers.getPtrConst(inst.src).*,
                            Instruction.st => extend(inst.imm),
                            else => unreachable,
                        };
                        try self.memory_map.store(T, vaddr, @truncate(operand));
                    },
                }
            },

            .be,
            .le,
            => {
                registers.set(inst.dst, switch (inst.imm) {
                    inline //
                    16,
                    32,
                    64,
                    => |size| std.mem.nativeTo(
                        std.meta.Int(.unsigned, size),
                        @truncate(registers.getPtrConst(inst.dst).*),
                        if (opcode == .le) .little else .big,
                    ),
                    else => return error.UnsupportedInstruction,
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
                const lhs = registers.getPtrConst(inst.dst).*;
                const rhs = if (opcode.isReg())
                    registers.getPtrConst(inst.src).*
                else
                    extend(inst.imm);

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
                    if (self.loader.get(inst.imm)) |entry| {
                        try self.dispatchSyscall(entry);
                    } else {
                        @panic("TODO: detect invalid syscall in verifier");
                    }
                } else {
                    if (opcode == .@"return" and !version.enableStaticSyscalls()) {
                        return error.UnsupportedInstruction;
                    }

                    if (self.depth == 0) {
                        if (config.enable_instruction_meter and
                            self.instruction_count > self.transaction_context.compute_meter)
                        {
                            return error.ExceededMaxInstructions;
                        }
                        self.result = .{ .ok = self.registers.getPtrConst(.r0).* };
                        return false;
                    }
                    self.depth -= 1;
                    const frame = self.call_frames.pop().?;
                    self.registers.set(.r10, frame.fp);
                    @memcpy(self.registers.values[6..][0..4], &frame.caller_saved_regs);
                    next_pc = frame.return_pc;
                }
            },
            .call_imm => blk: {
                if (!version.enableStaticSyscalls()) {
                    if (self.loader.get(inst.imm)) |entry| {
                        try self.dispatchSyscall(entry);
                        break :blk;
                    }
                }

                const target_pc = version.computeTargetPc(pc, inst);
                const function_registry = &self.executable.function_registry;
                if (function_registry.lookupKey(target_pc)) |entry| {
                    try self.pushCallFrame();
                    next_pc = entry.value;
                    break :blk;
                }

                return error.UnsupportedInstruction;
            },
            .call_reg => {
                const src: sbpf.Instruction.Register = if (version.callRegUsesSrcReg())
                    inst.src
                else
                    @enumFromInt(inst.imm);
                const target_pc = registers.getPtrConst(src).*;

                try self.pushCallFrame();

                next_pc = (target_pc -% self.vm_addr) / 8;
                if (next_pc >= instructions.len) return error.CallOutsideTextSegment;
                if (version.enableStaticSyscalls() and
                    self.executable.function_registry.lookupKey(next_pc) == null)
                {
                    return error.UnsupportedInstruction;
                }
            },

            // other instructions
            .ld_dw_imm => {
                if (version.disableLddw()) return error.UnsupportedInstruction;
                const value: u64 = (@as(u64, instructions[next_pc].imm) << 32) | inst.imm;
                registers.set(inst.dst, value);
                next_pc += 1;
            },

            // handled above
            .ld_4b_reg,
            .st_4b_reg,
            => if (!version.moveMemoryInstructionClasses()) return error.UnsupportedInstruction,

            else => return error.UnsupportedInstruction,
        }

        self.registers.set(.pc, next_pc);
        return true;
    }

    fn pushCallFrame(self: *Vm) !void {
        const frame = self.call_frames.addOneAssumeCapacity();
        frame.* = .{
            .caller_saved_regs = self.registers.values[6..][0..4].*,
            .fp = self.registers.getPtrConst(.r10).*,
            .return_pc = self.registers.getPtrConst(.pc).* + 1,
        };

        self.depth += 1;
        if (self.depth == self.executable.config.max_call_depth) {
            return error.CallDepthExceeded;
        }

        if (!self.executable.version.enableDynamicStackFrames()) {
            const scale: u64 = if (self.executable.config.enable_stack_frame_gaps) 2 else 1;
            const stack_frame_size = self.executable.config.stack_frame_size * scale;
            self.registers.getPtr(.r10).* += stack_frame_size;
        }
    }

    fn signExtend(version: sbpf.Version, input: i32) u64 {
        if (version.explicitSignExtensionOfResults()) {
            return @as(u32, @bitCast(input));
        } else {
            return @bitCast(@as(i64, input));
        }
    }

    /// u32 -> sign extend -> i64 -> bitcast -> u64
    fn extend(input: anytype) u64 {
        const value: u32 = @truncate(input);
        const signed: i32 = @bitCast(value);
        const extended: i64 = signed;
        return @bitCast(extended);
    }

    fn rem(comptime T: type, numerator: T, denominator: T) !T {
        @setRuntimeSafety(false);
        try checkDivByZero(T, denominator);
        if (@typeInfo(T).int.signedness == .signed) try checkDivOverflow(T, numerator, denominator);
        return @rem(numerator, denominator);
    }

    fn divTrunc(comptime T: type, numerator: T, denominator: T) !T {
        @setRuntimeSafety(false);
        try checkDivByZero(T, denominator);
        if (@typeInfo(T).int.signedness == .signed) try checkDivOverflow(T, numerator, denominator);
        if (denominator == 0) return error.DivisionByZero;
        return @divTrunc(numerator, denominator);
    }

    fn mod(comptime T: type, numerator: T, denominator: T) !T {
        @setRuntimeSafety(false);
        try checkDivByZero(T, denominator);
        return @mod(numerator, denominator);
    }

    inline fn checkDivByZero(comptime T: type, denominator: T) !void {
        if (denominator == 0) return error.DivisionByZero;
    }
    inline fn checkDivOverflow(comptime T: type, numerator: T, denominator: T) !void {
        if (numerator == std.math.minInt(T) and denominator == -1) return error.DivideOverflow;
    }
};

/// Contains either an error encountered while executing the program, or the
/// result, which is the value of the `r0` register at the time of exit.
///
/// [agave] https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/error.rs#L170-L171
pub const Result = union(enum) {
    err: ExecutionError,
    ok: u64,

    /// Helper function for creating the `Result` from an inline value.
    pub fn fromValue(val: anytype) Result {
        if (!@import("builtin").is_test) @compileError("only used in tests");
        return @unionInit(Result, if (@typeInfo(@TypeOf(val)) == .error_set) "err" else "ok", val);
    }
};
