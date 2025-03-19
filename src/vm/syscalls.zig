const std = @import("std");
const phash = @import("poseidon");
const sig = @import("../sig.zig");
const lib = @import("lib.zig");
const interpreter = @import("interpreter.zig");
const transaction_context = @import("../runtime/transaction_context.zig");

const testElfWithSyscalls = @import("tests.zig").testElfWithSyscalls;
const Pubkey = sig.core.Pubkey;
const MemoryMap = lib.memory.MemoryMap;
const RegisterMap = interpreter.RegisterMap;
const TransactionContext = transaction_context.TransactionContext;
const InstructionError = sig.core.instruction.InstructionError;

pub const Error = error{
    OutOfMemory,
    InvalidVirtualAddress,
    AccessNotMapped,
    SyscallAbort,
    AccessViolation,
    VirtualAccessTooLong,
    Overflow,
    Underflow,
    InvalidLength,
    NonCanonical,
    Unexpected,
    ComputationalBudgetExceeded,
} || std.fs.File.WriteError || InstructionError;

pub const Syscall = *const fn (
    *TransactionContext,
    *MemoryMap,
    RegisterMap,
) Error!void;

pub const Entry = struct {
    name: []const u8,
    builtin_fn: Syscall,
};

// logging
/// https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L3-L33
pub fn log(ctx: *TransactionContext, mmap: *MemoryMap, registers: RegisterMap) Error!void {
    const vm_addr = registers.get(.r1);
    const len = registers.get(.r2);

    // https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L15-L19
    const cost = @max(ctx.getComputeBudget().syscall_base_cost, len);
    try ctx.consumeCompute(cost);

    const host_addr = try mmap.vmap(.constant, vm_addr, len);
    const string = std.mem.sliceTo(host_addr, 0);
    try ctx.log("{s}", .{string});
}

/// https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L35-L56
pub fn log64(ctx: *TransactionContext, _: *MemoryMap, registers: RegisterMap) Error!void {
    // https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L47-L48
    const cost = ctx.getComputeBudget().log_64_units;
    try ctx.consumeCompute(cost);

    const arg1 = registers.get(.r1);
    const arg2 = registers.get(.r2);
    const arg3 = registers.get(.r3);
    const arg4 = registers.get(.r4);
    const arg5 = registers.get(.r5);

    try ctx.log(
        "0x{x} 0x{x} 0x{x} 0x{x} 0x{x}",
        .{ arg1, arg2, arg3, arg4, arg5 },
    );
}

/// https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L82-L105
pub fn logPubkey(ctx: *TransactionContext, mmap: *MemoryMap, registers: RegisterMap) Error!void {
    // https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L94-L95
    const cost = ctx.getComputeBudget().log_pubkey_units;
    try ctx.consumeCompute(cost);

    const pubkey_addr = registers.get(.r1);
    const pubkey_bytes = try mmap.vmap(.constant, pubkey_addr, @sizeOf(Pubkey));
    const pubkey: Pubkey = @bitCast(pubkey_bytes[0..@sizeOf(Pubkey)].*);
    try ctx.log("log: {}", .{pubkey});
}

/// https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L58-L80
pub fn logComputeUnits(ctx: *TransactionContext, _: *MemoryMap, _: RegisterMap) Error!void {
    // https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L70-L71
    const cost = ctx.getComputeBudget().syscall_base_cost;
    try ctx.consumeCompute(cost);

    try ctx.log("TODO: compute budget calculations", .{});
}

// memory operators

/// https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L130-L162
pub fn memset(ctx: *TransactionContext, mmap: *MemoryMap, registers: RegisterMap) Error!void {
    const dst_addr = registers.get(.r1);
    const scalar = registers.get(.r2);
    const len = registers.get(.r3);

    // https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L142
    try consumeMemoryCompute(ctx, len);

    const host_addr = try mmap.vmap(.mutable, dst_addr, len);
    @memset(host_addr, @truncate(scalar));
}

/// https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L31-L52
pub fn memcpy(ctx: *TransactionContext, mmap: *MemoryMap, registers: RegisterMap) Error!void {
    const dst_addr = registers.get(.r1);
    const src_addr = registers.get(.r2);
    const len = registers.get(.r3);

    // https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L43
    try consumeMemoryCompute(ctx, len);

    const dst_host = try mmap.vmap(.mutable, dst_addr, len);
    const src_host = try mmap.vmap(.constant, src_addr, len);
    @memcpy(dst_host, src_host);
}

/// https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L72-L128
pub fn memcmp(ctx: *TransactionContext, mmap: *MemoryMap, registers: RegisterMap) Error!void {
    const a_addr = registers.get(.r1);
    const b_addr = registers.get(.r2);
    const n = registers.get(.r3);
    const cmp_result_addr = registers.get(.r4);

    // https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L84
    try consumeMemoryCompute(ctx, n);

    const a = try mmap.vmap(.constant, a_addr, n);
    const b = try mmap.vmap(.constant, b_addr, n);
    const cmp_result_slice = try mmap.vmap(
        .mutable,
        cmp_result_addr,
        @sizeOf(u32),
    );
    const cmp_result: *align(1) u32 = @ptrCast(cmp_result_slice.ptr);

    const result = std.mem.order(u8, a, b);
    cmp_result.* = @intFromEnum(result);
}

/// https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L8-L15
fn consumeMemoryCompute(ctx: *TransactionContext, length: u64) !void {
    const budget = ctx.getComputeBudget();
    const cost = @max(budget.mem_op_base_cost, length / budget.cpi_bytes_per_unit);
    try ctx.consumeCompute(cost);
}

// hashing
const Parameters = enum(u64) {
    Bn254X5 = 0,
};

const Slice = extern struct {
    addr: [*]const u8,
    len: u64,
};

pub fn poseidon(ctx: *TransactionContext, mmap: *MemoryMap, registers: RegisterMap) Error!void {
    // const parameters: Parameters = @enumFromInt(registers.get(.r1));
    const endianness: std.builtin.Endian = @enumFromInt(registers.get(.r2));
    const addr = registers.get(.r3);
    const len = registers.get(.r4);
    const result_addr = registers.get(.r5);

    if (len > 12) {
        return error.InvalidLength;
    }

    const budget = ctx.getComputeBudget();
    // TODO: Agave logs a specific message when this overflows.
    // https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L1923-L1926
    const cost = try budget.poseidonCost(len);
    try ctx.consumeCompute(cost);

    const hash_result = try mmap.vmap(.mutable, result_addr, 32);
    const input_bytes = try mmap.vmap(
        .constant,
        addr,
        len * @sizeOf(Slice),
    );
    const inputs = std.mem.bytesAsSlice(Slice, input_bytes);

    var hasher = phash.Hasher.init(endianness);
    for (inputs) |input| {
        const slice = try mmap.vmap(
            .constant,
            @intFromPtr(input.addr),
            input.len,
        );
        try hasher.append(slice[0..32]);
    }
    const result = try hasher.finish();
    @memcpy(hash_result, &result);
}

// special
pub fn abort(_: *TransactionContext, _: *MemoryMap, _: RegisterMap) Error!void {
    return error.SyscallAbort;
}

pub fn panic(ctx: *TransactionContext, mmap: *MemoryMap, registers: RegisterMap) Error!void {
    const file = registers.get(.r1);
    const len = registers.get(.r2);
    // const line = registers.get(.r3);
    // const column = registers.get(.r4);

    const message = try mmap.vmap(.constant, file, len);
    try ctx.log("panic: {s}", .{message});
    return error.SyscallAbort;
}

test poseidon {
    try testElfWithSyscalls(
        .{},
        sig.ELF_DATA_DIR ++ "poseidon_test.so",
        &.{
            .{ .name = "sol_poseidon", .builtin_fn = poseidon },
            .{ .name = "log", .builtin_fn = log },
            .{ .name = "sol_panic_", .builtin_fn = panic },
        },
        .{ 0, 48526 },
    );
}
