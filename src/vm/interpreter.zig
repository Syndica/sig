const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../sig.zig");

const sbpf = sig.vm.sbpf;
const memory = sig.vm.memory;

const MemoryMap = memory.MemoryMap;
const Instruction = sbpf.Instruction;
const OpCode = Instruction.OpCode;
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

    jump_table: *const [256]Handle,

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
        instruction_data_offset: u64,
        ctx: *TransactionContext,
    ) error{OutOfMemory}!Vm {
        const offset = if (executable.version.enableDynamicStackFrames())
            stack_len
        else
            executable.config.stack_frame_size;
        const stack_pointer = memory.STACK_START + offset;
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
            .jump_table = switch (executable.version) {
                // The only difference between v0 and v1 is how function calls work with
                // dynamic frame pointers, which we can just eat the cost of checking the
                // version in `pushCallFrame`, it doesn't seem to matter much.
                .v0, .v1 => &v0.table,
                .v2 => &v2.table,
                .v3 => &v3.table,
                else => @panic("should have been checked when creating the executable"),
            },
        };

        self.registers.set(.r10, stack_pointer);
        self.registers.set(.r1, memory.INPUT_START);
        self.registers.set(.r2, instruction_data_offset);
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

        const initial_meter = self.transaction_context.compute_meter;
        const instructions = self.executable.instructions;

        while (true) {
            const current_meter = self.transaction_context.compute_meter;
            if (self.executable.config.enable_instruction_meter and
                self.instruction_count >= current_meter)
            {
                @branchHint(.unlikely);
                self.result = .{ .err = error.ExceededMaxInstructions };
                break;
            }
            self.instruction_count += 1;

            const pc = self.registers.getPtrConst(.pc).*;
            if (pc >= instructions.len) {
                @branchHint(.unlikely);
                self.result = .{ .err = error.ExecutionOverrun };
                break;
            }

            // Our step function needs to have the same prototype as the instruction handles,
            // in order to force a tail-call to happen. Our instruction handles take in the
            // instruction they're processing as well as the program counter it was found at,
            // and we can match the same behaviour here.
            self.step(instructions[pc], pc) catch |err| switch (err) {
                error.Stop => break,
                else => |e| {
                    self.result = .{ .err = e };
                    break;
                },
            };
        }

        // https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/vm.rs#L380-L385
        const instruction_count = if (self.executable.config.enable_instruction_meter) blk: {
            self.transaction_context.consumeUnchecked(self.instruction_count);
            break :blk initial_meter -| self.transaction_context.compute_meter;
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

    const DispatchError = ExecutionError || error{Stop};

    const Handle = *const fn (*Vm, Instruction, u64) DispatchError!void;

    const v0 = struct {
        const table: [256]Handle = table: {
            var array: [256]Handle = @splat(v0.unsupported);
            for (@typeInfo(OpCode).@"enum".fields) |field| switch (@field(OpCode, field.name)) {
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
                => |t| array[@intFromEnum(t)] = &struct {
                    fn run(vm: *Vm, inst: Instruction, pc: u64) DispatchError!void {
                        return binop(vm, t, inst, pc);
                    }
                }.run,
                .be,
                .le,
                => |t| array[@intFromEnum(t)] = &struct {
                    fn bswap(vm: *Vm, inst: Instruction, pc: u64) DispatchError!void {
                        defer vm.registers.set(.pc, pc + 1);
                        const result = switch (inst.imm) {
                            inline 16, 32, 64 => |size| std.mem.nativeTo(
                                std.meta.Int(.unsigned, size),
                                @truncate(vm.registers.getPtrConst(inst.dst).*),
                                if (t == .le) .little else .big,
                            ),
                            else => return error.UnsupportedInstruction,
                        };
                        vm.registers.set(inst.dst, result);
                    }
                }.bswap,
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
                => |t| array[@intFromEnum(t)] = &struct {
                    fn run(vm: *Vm, inst: Instruction, pc: u64) DispatchError!void {
                        return memop(vm, t, inst, pc);
                    }
                }.run,
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
                => |t| array[@intFromEnum(t)] = &struct {
                    fn run(vm: *Vm, inst: Instruction, pc: u64) DispatchError!void {
                        return branch(vm, t, inst, pc);
                    }
                }.run,
                else => |t| if (@hasDecl(v0, field.name)) {
                    array[@intFromEnum(t)] = @field(v0, field.name);
                },
            };
            break :table array;
        };

        fn unsupported(_: *Vm, _: Instruction, _: u64) DispatchError!void {
            return error.UnsupportedInstruction;
        }

        // NOTE: this is the behaviour specifically for sBPF v0.
        inline fn binop(
            self: *Vm,
            comptime opcode: OpCode,
            inst: Instruction,
            pc: u64,
        ) DispatchError!void {
            const is_64 = comptime opcode.is64();
            const Int = if (is_64) u64 else u32;
            const SignedInt = if (is_64) i64 else i32;

            const registers = &self.registers;
            const lhs: Int = @truncate(registers.getPtrConst(inst.dst).*);
            const rhs: Int = @truncate(if (comptime opcode.isReg())
                registers.getPtrConst(inst.src).*
            else
                extend(inst.imm));

            const result: Int = switch (comptime @intFromEnum(opcode) & 0b11110000) {
                // zig fmt: off
                Instruction.mov    => rhs,
                Instruction.add    => lhs +% rhs,
                Instruction.sub    => lhs -% rhs,
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
                Instruction.arsh => value: {
                    const signed: SignedInt = @bitCast(lhs);
                    break :value @bitCast(signed >> @truncate(rhs));
                },
                else => unreachable,
            };

            const large_result: u64 = switch (@intFromEnum(opcode) & 0b11110000) {
                // The result of add/sub is always extended as if were an i32.
                Instruction.add,
                Instruction.sub,
                => if (is_64) result else @bitCast(@as(i64, @as(i32, @bitCast(result)))),
                // The mul32 instruction requires a sign extension to u64 from i32.
                Instruction.mul => if (is_64) result else extend(result),
                else => result,
            };

            registers.set(inst.dst, large_result);
            self.registers.set(.pc, pc + 1);
        }

        fn hor64_imm(self: *Vm, inst: Instruction, pc: u64) DispatchError!void {
            defer self.registers.set(.pc, pc + 1);
            const lhs = self.registers.getPtrConst(inst.dst).*;
            const result = lhs | @as(u64, inst.imm) << 32;
            self.registers.set(inst.dst, result);
        }

        // memory

        inline fn memop(
            self: *Vm,
            comptime opcode: OpCode,
            inst: Instruction,
            pc: u64,
        ) DispatchError!void {
            const T = switch (opcode) {
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

            const access = comptime opcode.accessType();
            const addr_reg = if (access == .constant) inst.src else inst.dst;
            const address: i64 = @bitCast(self.registers.getPtrConst(addr_reg).*);
            const vaddr: u64 = @bitCast(address +% inst.off);

            switch (access) {
                .constant => self.registers.set(inst.dst, try self.memory_map.load(T, vaddr)),
                .mutable => {
                    const operand = switch (@intFromEnum(opcode) & 0b111) {
                        Instruction.stx => self.registers.getPtrConst(inst.src).*,
                        Instruction.st => extend(inst.imm),
                        else => unreachable,
                    };
                    try self.memory_map.store(T, vaddr, @truncate(operand));
                },
            }

            self.registers.set(.pc, pc + 1);
        }

        // control flow

        inline fn branch(
            self: *Vm,
            comptime opcode: OpCode,
            inst: Instruction,
            pc: u64,
        ) DispatchError!void {
            const target_pc: u64 = @intCast(@as(i64, @intCast(pc + 1)) + inst.off);
            const lhs = self.registers.getPtrConst(inst.dst).*;
            const rhs = if (opcode.isReg())
                self.registers.getPtrConst(inst.src).*
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
            self.registers.set(.pc, if (predicate) target_pc else pc + 1);
        }

        // misc

        fn exit_or_syscall(self: *Vm, _: Instruction, _: u64) DispatchError!void {
            if (self.depth == 0) {
                if (self.executable.config.enable_instruction_meter and
                    self.instruction_count > self.transaction_context.compute_meter)
                {
                    return error.ExceededMaxInstructions;
                }
                self.result = .{ .ok = self.registers.getPtrConst(.r0).* };
                return error.Stop;
            }
            self.depth -= 1;
            const frame = self.call_frames.pop().?;
            self.registers.set(.r10, frame.fp);
            @memcpy(self.registers.values[6..][0..4], &frame.caller_saved_regs);
            self.registers.set(.pc, frame.return_pc);
        }

        fn call_imm(self: *Vm, inst: Instruction, pc: u64) DispatchError!void {
            if (self.loader.get(inst.imm)) |entry| {
                try self.dispatchSyscall(entry);
                self.registers.set(.pc, pc + 1);
                return;
            }
            const function_registry = &self.executable.function_registry;
            if (function_registry.lookupKey(inst.imm)) |entry| {
                try self.pushCallFrame();
                self.registers.set(.pc, entry.value);
                return;
            }
            return error.UnsupportedInstruction;
        }

        fn call_reg(self: *Vm, inst: Instruction, _: u64) DispatchError!void {
            // NOTE: register is checked to be in-bounds in verify()
            const src: sbpf.Instruction.Register = @enumFromInt(inst.imm);
            const target_pc = self.registers.getPtrConst(src).*;

            try self.pushCallFrame();

            const next_pc = (target_pc -% self.vm_addr) / 8;
            const instructions = self.executable.instructions;
            if (next_pc >= instructions.len) return error.CallOutsideTextSegment;
            self.registers.set(.pc, next_pc);
        }

        fn ld_dw_imm(self: *Vm, inst: Instruction, pc: u64) DispatchError!void {
            defer self.registers.set(.pc, pc + 2);
            const instructions = self.executable.instructions;
            const value: u64 = (@as(u64, instructions[pc + 1].imm) << 32) | inst.imm;
            self.registers.set(inst.dst, value);
        }
    };

    /// SIMD-0174, SIMD-0173
    const v2 = struct {
        const table: [256]Handle = table: {
            var array = v0.table;
            for (@typeInfo(OpCode).@"enum".fields) |field| switch (@field(OpCode, field.name)) {
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
                => |t| array[@intFromEnum(t)] = &struct {
                    fn run(vm: *Vm, inst: Instruction, pc: u64) DispatchError!void {
                        return pqr32(vm, t, inst, pc);
                    }
                }.run,
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
                => |t| array[@intFromEnum(t)] = &struct {
                    fn run(vm: *Vm, inst: Instruction, pc: u64) DispatchError!void {
                        return pqr64(vm, t, inst, pc);
                    }
                }.run,
                .add64_reg,
                .add64_imm,
                .add32_reg,
                .add32_imm,
                .sub64_reg,
                .sub64_imm,
                .sub32_reg,
                .sub32_imm,
                => |t| array[@intFromEnum(t)] = &struct {
                    fn run(vm: *Vm, inst: Instruction, pc: u64) DispatchError!void {
                        return binop(vm, t, inst, pc);
                    }
                }.run,
                OpCode.ld_1b_reg,
                OpCode.ld_2b_reg,
                OpCode.ld_4b_reg,
                OpCode.ld_8b_reg,
                OpCode.st_1b_imm,
                OpCode.st_2b_imm,
                OpCode.st_4b_imm,
                OpCode.st_8b_imm,
                OpCode.st_1b_reg,
                OpCode.st_2b_reg,
                OpCode.st_4b_reg,
                OpCode.st_8b_reg,
                => |t| array[@intFromEnum(t)] = &struct {
                    fn run(vm: *Vm, inst: Instruction, pc: u64) DispatchError!void {
                        return memop(vm, t, inst, pc);
                    }
                }.run,
                else => |t| if (@hasDecl(v2, field.name)) {
                    array[@intFromEnum(t)] = @field(v2, field.name);
                },
            };
            break :table array;
        };

        /// SIMD-0174:
        /// "the `MOV32_REG` instruction (opcode `0xBC`) which until now did zero
        /// out the 32 MSBs, must now perform sign extension in the 32 MSBs."
        pub fn mov32_reg(self: *Vm, inst: Instruction, pc: u64) DispatchError!void {
            defer self.registers.set(.pc, pc + 1);
            const rhs: u32 = @truncate(self.registers.getPtrConst(inst.src).*);
            const extended: u64 = extend(rhs);
            self.registers.set(inst.dst, extended);
        }

        /// SIMD-0173:
        /// "A program containing one of the following instructions must throw
        /// `VerifierError::UnknownOpCode` during verification:
        /// - the `LDDW` instruction (opcodes `0x18` and `0x00`)"
        pub const ld_dw_imm = v0.unsupported;

        // TODO: find the simd comment that tells us to turn off / reserve these instructions
        pub const mul32_imm = v0.unsupported;
        pub const mod32_imm = v0.unsupported;
        pub const div32_imm = v0.unsupported;

        inline fn binop(
            self: *Vm,
            comptime opcode: OpCode,
            inst: Instruction,
            pc: u64,
        ) DispatchError!void {
            const is_64 = comptime opcode.is64();
            const is_reg = comptime opcode.isReg();
            const Int = if (is_64) u64 else u32;

            const registers = &self.registers;
            const lhs: Int = @truncate(registers.getPtrConst(inst.dst).*);
            const rhs: Int = @truncate(if (is_reg)
                registers.getPtrConst(inst.src).*
            else
                extend(inst.imm));

            const result: Int = switch (comptime @intFromEnum(opcode) & 0b11110000) {
                Instruction.add => lhs +% rhs,
                // SIMD-0174: sub imm operands are swapped.
                Instruction.sub => if (is_reg) lhs -% rhs else rhs -% lhs,
                else => unreachable,
            };

            registers.set(inst.dst, result);
            self.registers.set(.pc, pc + 1);
        }

        inline fn memop(
            self: *Vm,
            comptime opcode: OpCode,
            inst: Instruction,
            pc: u64,
        ) DispatchError!void {
            switch (opcode) {
                OpCode.ld_1b_reg,
                OpCode.ld_2b_reg,
                OpCode.ld_4b_reg,
                OpCode.ld_8b_reg,
                => |tag| {
                    const T = switch (tag) {
                        OpCode.ld_1b_reg => u8,
                        OpCode.ld_2b_reg => u16,
                        OpCode.ld_4b_reg => u32,
                        OpCode.ld_8b_reg => u64,
                        else => unreachable,
                    };
                    const base_address: i64 = @bitCast(self.registers.getPtrConst(inst.src).*);
                    const vm_addr: u64 = @bitCast(base_address +% @as(i64, inst.off));
                    self.registers.set(inst.dst, try self.memory_map.load(T, vm_addr));
                },

                OpCode.st_1b_imm,
                OpCode.st_2b_imm,
                OpCode.st_4b_imm,
                OpCode.st_8b_imm,
                => |tag| {
                    const T = switch (tag) {
                        OpCode.st_1b_imm => u8,
                        OpCode.st_2b_imm => u16,
                        OpCode.st_4b_imm => u32,
                        OpCode.st_8b_imm => u64,
                        else => unreachable,
                    };
                    const base_address: i64 = @bitCast(self.registers.getPtrConst(inst.dst).*);
                    const vm_addr: u64 = @bitCast(base_address +% @as(i64, inst.off));
                    try self.memory_map.store(T, vm_addr, @truncate(extend(inst.imm)));
                },

                OpCode.st_1b_reg,
                OpCode.st_2b_reg,
                OpCode.st_4b_reg,
                OpCode.st_8b_reg,
                => |tag| {
                    const T = switch (tag) {
                        OpCode.st_1b_reg => u8,
                        OpCode.st_2b_reg => u16,
                        OpCode.st_4b_reg => u32,
                        OpCode.st_8b_reg => u64,
                        else => unreachable,
                    };
                    const base_address: i64 = @bitCast(self.registers.getPtrConst(inst.dst).*);
                    const vm_addr: u64 = @bitCast(base_address +% @as(i64, inst.off));
                    try self.memory_map.store(
                        T,
                        vm_addr,
                        @truncate(self.registers.getPtrConst(inst.src).*),
                    );
                },

                else => comptime unreachable,
            }

            self.registers.set(.pc, pc + 1);
        }

        inline fn pqr32(
            self: *Vm,
            comptime opcode: OpCode,
            inst: Instruction,
            pc: u64,
        ) DispatchError!void {
            const lhs_large = self.registers.getPtrConst(inst.dst).*;
            const rhs_large: u64 = if (comptime opcode.isReg())
                self.registers.getPtrConst(inst.src).*
            else
                inst.imm;

            const opc = comptime @intFromEnum(opcode) & 0b11100000;
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

            self.registers.set(inst.dst, extended);
            self.registers.set(.pc, pc + 1);
        }

        inline fn pqr64(
            self: *Vm,
            comptime opcode: OpCode,
            inst: Instruction,
            pc: u64,
        ) DispatchError!void {
            const lhs: u64 = self.registers.getPtrConst(inst.dst).*;
            const rhs: u64 = if (opcode.isReg())
                self.registers.getPtrConst(inst.src).*
            else
                inst.imm;
            const signed_rhs: i64 = if (opcode.isReg())
                @bitCast(self.registers.getPtrConst(inst.src).*)
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

            self.registers.set(inst.dst, result);
            self.registers.set(.pc, pc + 1);
        }

        pub fn call_reg(self: *Vm, inst: Instruction, _: u64) DispatchError!void {
            const target_pc = self.registers.getPtrConst(inst.src).*;
            try self.pushCallFrame();
            const next_pc = (target_pc -% self.vm_addr) / 8;
            const instructions = self.executable.instructions;
            if (next_pc >= instructions.len) return error.CallOutsideTextSegment;
            self.registers.set(.pc, next_pc);
        }
    };

    /// SIMD-0178, SIMD-0179, SIMD-0189
    const v3 = struct {
        const table = table: {
            var array = v2.table;
            for (@typeInfo(v3).@"struct".decls) |field| {
                array[@intFromEnum(@field(OpCode, field.name))] = @field(v3, field.name);
            }
            break :table array;
        };

        pub fn call_imm(self: *Vm, inst: Instruction, pc: u64) DispatchError!void {
            const target_pc = sbpf.Version.computeTargetPc(.v3, pc, inst);
            try self.pushCallFrame();
            self.registers.set(.pc, target_pc);
        }

        pub fn exit_or_syscall(self: *Vm, inst: Instruction, pc: u64) DispatchError!void {
            if (self.loader.get(inst.imm)) |entry| {
                try self.dispatchSyscall(entry);
                self.registers.set(.pc, pc + 1);
            } else {
                @panic("TODO: detect invalid syscall in verifier");
            }
        }

        pub fn @"return"(self: *Vm, inst: Instruction, pc: u64) DispatchError!void {
            return @call(.always_inline, v0.exit_or_syscall, .{ self, inst, pc });
        }

        pub fn call_reg(self: *Vm, inst: Instruction, _: u64) DispatchError!void {
            const target_pc = self.registers.getPtrConst(inst.src).*;
            try self.pushCallFrame();

            // [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/interpreter.rs#L513
            const next_pc = (target_pc -% self.vm_addr) / 8;
            const instructions = self.executable.instructions;
            if (next_pc >= instructions.len) return error.CallOutsideTextSegment;
            if (!instructions[next_pc].isFunctionStartMarker()) {
                return error.UnsupportedInstruction;
            }
            self.registers.set(.pc, next_pc);
        }
    };

    /// Returns `true` when the instruction executed stops the VM.
    ///
    /// NOTE: no `inline`, since we tail call. But looking at the codegen, it does inline the tail call.
    fn step(self: *Vm, inst: Instruction, pc: u64) DispatchError!void {
        return @call(.always_tail, self.jump_table[@intFromEnum(inst.opcode)], .{ self, inst, pc });
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

    /// u32 -> sign extend -> i64 -> bitcast -> u64
    inline fn extend(input: anytype) u64 {
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
