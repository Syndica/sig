const std = @import("std");
const Executable = @import("Executable.zig");
const ebpf = @import("ebpf.zig");
const Instruction = ebpf.Instruction;
const memory = @import("memory.zig");
const MemoryMap = memory.MemoryMap;
const Vm = @This();

const assert = std.debug.assert;
const log = std.log.scoped(.vm);

allocator: std.mem.Allocator,
executable: *const Executable,

registers: std.EnumArray(ebpf.Instruction.Register, u64),
memory_map: MemoryMap,
loader: *const Executable.BuiltinProgram,

vm_addr: u64,
stack_pointer: u64,
call_frames: std.ArrayListUnmanaged(CallFrame),
depth: u64,
instruction_count: u64,

pub fn init(
    allocator: std.mem.Allocator,
    executable: *const Executable,
    memory_map: MemoryMap,
    loader: *const Executable.BuiltinProgram,
) !Vm {
    var vm: Vm = .{
        .executable = executable,
        .allocator = allocator,
        .registers = std.EnumArray(ebpf.Instruction.Register, u64).initFill(0),
        .memory_map = memory_map,
        .stack_pointer = memory.STACK_START + 4096,
        .depth = 0,
        .call_frames = try std.ArrayListUnmanaged(CallFrame).initCapacity(allocator, 64),
        .instruction_count = 0,
        .vm_addr = executable.text_vaddr,
        .loader = loader,
    };

    vm.registers.set(.r10, memory.STACK_START + 4096);
    vm.registers.set(.r1, memory.INPUT_START);
    vm.registers.set(.pc, executable.entry_pc);

    return vm;
}

pub fn deinit(vm: *Vm) void {
    vm.call_frames.deinit(vm.allocator);
}

pub fn run(vm: *Vm) !u64 {
    while (try vm.step()) {
        vm.instruction_count += 1;
    }
    return vm.registers.get(.r0);
}

fn step(vm: *Vm) !bool {
    const registers = &vm.registers;
    const pc = registers.get(.pc);
    var next_pc: u64 = pc + 1;

    const instructions = vm.executable.instructions;
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
            const rhs_large = if (opcode.isReg()) registers.get(inst.src) else extend(inst.imm);
            const lhs = if (opcode.is64()) lhs_large else @as(u32, @truncate(lhs_large));
            const rhs = if (opcode.is64()) rhs_large else @as(u32, @truncate(rhs_large));

            var result: u64 = switch (@intFromEnum(opcode) & 0xF0) {
                // zig fmt: off
                Instruction.add    => lhs +% rhs,
                Instruction.sub    => lhs -% rhs,
                Instruction.div    => try std.math.divTrunc(u64, lhs, rhs),
                Instruction.xor    => lhs ^ rhs,
                Instruction.@"or"  => lhs | rhs,
                Instruction.@"and" => lhs & rhs,
                Instruction.mod    => try std.math.mod(u64, lhs, rhs),
                Instruction.lsh    => lhs << @truncate(rhs),
                Instruction.rsh    => lhs >> @truncate(rhs),
                Instruction.mov    => rhs,
                // zig fmt: on
                Instruction.mul => value: {
                    if (opcode.is64()) break :value lhs *% rhs;
                    const lhs_signed: i32 = @bitCast(@as(u32, @truncate(lhs)));
                    const rhs_signed: i32 = @bitCast(@as(u32, @truncate(rhs)));
                    break :value @bitCast(@as(i64, lhs_signed *% rhs_signed));
                },
                Instruction.neg => value: {
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
                else => unreachable,
            };

            switch (@intFromEnum(opcode) & 0xF0) {
                Instruction.add,
                => if (!opcode.is64()) {
                    result = extend(result);
                },
                else => {},
            }

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
            const address = if (access == .constant) inst.src else inst.dst;
            const vaddr: u64 = @bitCast(@as(i64, @bitCast(registers.get(address))) +% inst.off);

            switch (access) {
                .constant => registers.set(inst.dst, try vm.load(T, vaddr)),
                .mutable => {
                    const operand = switch (@as(u3, @truncate(@intFromEnum(opcode)))) {
                        Instruction.stx => registers.get(inst.src),
                        Instruction.st => inst.imm,
                        else => unreachable,
                    };
                    try vm.store(T, vaddr, @truncate(operand));
                },
            }
        },

        .be,
        .le,
        => registers.set(inst.dst, switch (inst.imm) {
            inline //
            16,
            32,
            64,
            => |size| std.mem.nativeTo(
                std.meta.Int(.unsigned, size),
                @truncate(registers.get(inst.dst)),
                if (opcode == .le) .little else .big,
            ),
            else => return error.InvalidInstruction,
        }),

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
            if (vm.depth == 0) {
                return false;
            }
            vm.depth -= 1;
            const frame = vm.call_frames.pop();
            vm.registers.set(.r10, frame.fp);
            @memcpy(vm.registers.values[6..][0..4], &frame.caller_saved_regs);
            vm.stack_pointer -= 4096;
            next_pc = frame.return_pc;
        },
        .call_imm => {
            if (vm.executable.function_registry.lookupKey(inst.imm)) |entry| {
                try vm.pushCallFrame();
                next_pc = entry.value;
            } else if (vm.loader.functions.lookupKey(inst.imm)) |entry| {
                const builtin_fn = entry.value;
                try builtin_fn(vm);
            } else {
                return error.UnresolvedFunction;
            }
        },
        .call_reg => {
            try vm.pushCallFrame();

            const target_pc = registers.get(@enumFromInt(inst.imm));
            next_pc = (target_pc -% vm.vm_addr) / 8;
        },

        // other instructions
        .ld_dw_imm => {
            assert(vm.executable.version == .v1);
            const value: u64 = (@as(u64, instructions[next_pc].imm) << 32) | inst.imm;
            registers.set(inst.dst, value);
            next_pc += 1;
        },
    }

    if (next_pc >= instructions.len) return error.PcOutOfBounds;
    vm.registers.set(.pc, next_pc);
    return true;
}

fn load(vm: *Vm, T: type, vm_addr: u64) !T {
    const slice = try vm.memory_map.vmap(.constant, vm_addr, @sizeOf(T));
    return std.mem.readInt(T, slice[0..@sizeOf(T)], .little);
}

fn store(vm: *Vm, T: type, vm_addr: u64, value: T) !void {
    const slice = try vm.memory_map.vmap(.mutable, vm_addr, @sizeOf(T));
    slice[0..@sizeOf(T)].* = @bitCast(value);
}

fn pushCallFrame(vm: *Vm) !void {
    const frame = vm.call_frames.addOneAssumeCapacity();
    @memcpy(&frame.caller_saved_regs, vm.registers.values[6..][0..4]);
    frame.fp = vm.registers.get(.r10);
    frame.return_pc = vm.registers.get(.pc) + 1;

    vm.depth += 1;
    if (vm.depth == 64) {
        return error.CallDepthExceeded;
    }

    vm.stack_pointer += 4096;
    vm.registers.set(.r10, vm.stack_pointer);
}

/// Performs a i64 sign-extension. This is commonly needed in SBPV1.
///
/// NOTE: only use this inside of the VM impl!
fn extend(input: anytype) u64 {
    const value: u32 = @truncate(input);
    const signed: i32 = @bitCast(value);
    const extended: i64 = signed;
    return @bitCast(extended);
}

const CallFrame = struct {
    caller_saved_regs: [4]u64,
    fp: u64,
    return_pc: u64,
};
