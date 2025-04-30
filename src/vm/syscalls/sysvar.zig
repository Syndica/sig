const std = @import("std");
const sig = @import("../../sig.zig");

const memory = sig.vm.memory;
const Error = sig.vm.syscalls.Error;
const Pubkey = sig.core.Pubkey;
const MemoryMap = memory.MemoryMap;
const InstructionError = sig.core.instruction.InstructionError;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const TransactionContext = sig.runtime.TransactionContext;

/// [agave] https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/sysvar.rs#L169
pub fn getSysvar(
    tc: *TransactionContext,
    mmap: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const id_addr = registers.get(.r1);
    const value_addr = registers.get(.r2);
    const offset = registers.get(.r3);
    const length = registers.get(.r4);

    const id_cost = std.math.divFloor(u64, 32, tc.compute_budget.cpi_bytes_per_unit) orelse 0;
    const buf_cost = std.math.divFloor(u64, length, tc.compute_budget.cpi_bytes_per_unit) orelse 0;
    const mem_cost = @max(tc.compute_budget.mem_op_base_cost, buf_cost);

    try tc.consumeCompute(tc.compute_budget.sysvar_base_cost +| id_cost +| mem_cost);

    const check_aligned = tc.getCheckAligned();
    const id = (try mmap.translateType(Pubkey, .constant, id_addr, check_aligned)).*;
    const value = try mmap.translateSlice(u8, .mutable, value_addr, length, check_aligned);

    const offset_len = std.math.add(u64, offset, length) catch
        return InstructionError.ProgramArithmeticOverflow;
    _ = std.math.add(u64, value_addr, length) catch
        return InstructionError.ProgramArithmeticOverflow;

    // https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/sysvar.rs#L164
    const SYSVAR_NOT_FOUND = 2;
    // https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/sysvar.rs#L165
    const OFFSET_LENGTH_EXCEEDS_SYSVAR = 1;

    const buf = tc.sc.sysvar_cache.getSlice(id) orelse return registers.set(.r0, SYSVAR_NOT_FOUND);
    if (buf.len < offset_len) return registers.set(.r0, OFFSET_LENGTH_EXCEEDS_SYSVAR);
    @memcpy(value, buf[offset..][0..length]);
}

test getSysvar {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    const ec, const sc, var tc = try testing.createExecutionContexts(allocator, prng.random(), .{
        .accounts = &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            },
        },
    });
    defer {
        ec.deinit();
        allocator.destroy(ec);
        sc.deinit();
        allocator.destroy(sc);
        tc.deinit();
    }
}
