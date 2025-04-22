const phash = @import("poseidon");
const std = @import("std");
const memops = @import("memops.zig");
const sig = @import("../../sig.zig");

const memory = sig.vm.memory;
const features = sig.runtime.features;
const stable_log = sig.runtime.stable_log;

const SyscallError = sig.vm.SyscallError;
const Pubkey = sig.core.Pubkey;
const MemoryMap = sig.vm.memory.MemoryMap;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const BuiltinProgram = sig.vm.BuiltinProgram;
const FeatureSet = sig.runtime.features.FeatureSet;
const TransactionContext = sig.runtime.TransactionContext;
const TransactionReturnData = sig.runtime.transaction_context.TransactionReturnData;

pub const Error = sig.vm.ExecutionError;

pub const Syscall = *const fn (
    *TransactionContext,
    *MemoryMap,
    RegisterMap,
) Error!void;

pub const Entry = struct {
    name: []const u8,
    builtin_fn: Syscall,
};

// [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/syscalls/mod.rs#L335
pub fn register(
    allocator: std.mem.Allocator,
    feature_set: *const FeatureSet,
    slot: u64,
    is_deploy: bool,
) !BuiltinProgram {
    // Register syscalls
    var syscalls = BuiltinProgram{};
    errdefer syscalls.deinit(allocator);

    // Abort
    _ = try syscalls.functions.registerHashed(
        allocator,
        "abort",
        abort,
    );

    // Panic
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_panic_",
        panic,
    );

    // Alloc Free
    if (!is_deploy) {
        _ = try syscalls.functions.registerHashed(
            allocator,
            "sol_alloc_free",
            allocFree,
        );
    }

    // Logging
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_log_",
        log,
    );

    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_log_64_",
        log64,
    );

    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_log_pubkey",
        logPubkey,
    );

    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_log_compute_units_",
        logComputeUnits,
    );

    // Log Data
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_log_data",
        logData,
    );

    // Program derived addresses
    // _ = try syscalls.functions.registerHashed(allocator, "sol_create_program_address", createProgramAddress,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_try_find_program_address", createProgramAddress,);

    // Sha256, Keccak256, Secp256k1Recover
    // _ = try syscalls.functions.registerHashed(allocator, "sol_sha256", sha256,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_keccak256", keccak256,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_secp256k1_recover", secp256k1Recover,);
    // Blake3
    // if (feature_set.isActive(feature_set.BLAKE3_SYSCALL_ENABLED, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_blake3", blake3,);
    // }

    // Elliptic Curve
    // if (feature_set.isActive(feature_set.CURVE25519_SYSCALL_ENABLED, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_curve_validate_point", curveValidatePoint,);
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_curve_group_op", curveGroupOp,);
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_curve_multiscalar_mul", curveMultiscalarMul,);
    // }

    // Sysvars
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_clock_sysvar", getClockSysvar,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_epoch_schedule_sysvar", getEpochScheduleSysvar,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_fees_sysvar", getFeesSysvar,);
    // if (!feature_set.isActive(feature_set.DISABLE_FEES_SYSVAR, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_get_fees_sysvar", getFeesSysvar,);
    // }
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_rent_sysvar", getRentSysvar,);
    // if (feature_set.isActive(feature_set.LAST_RESTART_SLOT_SYSVAR, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_get_last_restart_slot", getLastRestartSlotSysvar,);
    // }
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_epoch_rewards_sysvar", getEpochRewardsSysvar,);

    // Memory
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_memcpy_",
        memcpy,
    );

    // _ = try syscalls.functions.registerHashed(allocator, "sol_memmove_", memmove,);

    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_memset_",
        memset,
    );

    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_memcmp_",
        memcmp,
    );

    // Processed Sibling
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_processed_sibling_instruction", getProcessedSiblingInstruction,);

    // Stack Height
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_stack_height", getStackHeight,);

    // Return Data
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_set_return_data",
        setReturnData,
    );
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_return_data", getReturnData,);

    // Cross Program Invocation
    // _ = try syscalls.functions.registerHashed(allocator, "sol_invoke_signed_c", invokeSignedC,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_invoke_signed_rust", invokeSignedRust,);

    // Memory Allocator
    if (!feature_set.isActive(features.DISABLE_DEPLOY_OF_ALLOC_FREE_SYSCALL, slot)) {
        _ = try syscalls.functions.registerHashed(
            allocator,
            "sol_alloc_free_",
            allocFree,
        );
    }

    // Alt_bn128
    // if (feature_set.isActive(feature_set.ENABLE_ALT_BN128_SYSCALL, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_alt_bn128_group_op", altBn128GroupOp,);
    // }

    // Big_mod_exp
    // if (feature_set.isActive(feature_set.ENABLE_BIG_MOD_EXP_SYSCALL, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_big_mod_exp", bigModExp,);
    // }

    // Poseidon
    if (feature_set.isActive(features.ENABLE_POSEIDON_SYSCALL, slot)) {
        _ = try syscalls.functions.registerHashed(
            allocator,
            "sol_poseidon",
            poseidon,
        );
    }

    // Remaining Compute Units
    // if (feature_set.isActive(feature_set.ENABLE_REMAINING_COMPUTE_UNITS_SYSCALL, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_remaining_compute_units", remainingComputeUnits,);
    // }

    // Alt_bn_128_compression
    // if (feature_set.isActive(feature_set.ENABLE_ALT_BN_128_COMPRESSION_SYSCALL, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_alt_bn_128_compression", altBn128Compression,);
    // }

    // Sysvar Getter
    // if (feature_set.isActive(feature_set.ENABLE_SYSVAR_SYSCALL, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_get_sysvar", getSysvar,);
    // }

    // Get Epoch Stake
    // if (feature_set.isActive(feature_set.ENABLE_GET_EPOCH_STAKE_SYSCALL, slot)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_get_epoch_stake", getEpochStake,);
    // }

    return syscalls;
}

// logging
/// [agave] https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L3-L33
pub fn log(tc: *TransactionContext, memory_map: *MemoryMap, registers: RegisterMap) Error!void {
    const vm_addr = registers.get(.r1);
    const len = registers.get(.r2);

    try tc.consumeCompute(@max(tc.compute_budget.syscall_base_cost, len));

    const message = try memory_map.translateSlice(
        u8,
        .constant,
        vm_addr,
        len,
        try tc.getCheckAligned(),
    );

    if (!std.unicode.utf8ValidateSlice(message)) {
        return SyscallError.InvalidString;
    }

    try stable_log.programLog(tc, "{s}", .{message});
}

/// [agave] https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L35-L56
pub fn log64(tc: *TransactionContext, _: *MemoryMap, registers: RegisterMap) Error!void {
    try tc.consumeCompute(tc.compute_budget.log_64_units);

    const arg1 = registers.get(.r1);
    const arg2 = registers.get(.r2);
    const arg3 = registers.get(.r3);
    const arg4 = registers.get(.r4);
    const arg5 = registers.get(.r5);

    try stable_log.programLog(
        tc,
        "0x{x}, 0x{x}, 0x{x}, 0x{x}, 0x{x}",
        .{ arg1, arg2, arg3, arg4, arg5 },
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L82-L105
pub fn logPubkey(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: RegisterMap,
) Error!void {
    const vm_addr = registers.get(.r1);

    try tc.consumeCompute(tc.compute_budget.log_pubkey_units);

    const pubkey_bytes = try memory_map.translateSlice(
        u8,
        .constant,
        vm_addr,
        @sizeOf(Pubkey),
        try tc.getCheckAligned(),
    );
    const pubkey: Pubkey = @bitCast(pubkey_bytes[0..@sizeOf(Pubkey)].*);

    try stable_log.programLog(tc, "{}", .{pubkey});
}

/// [agave] https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L58-L80
pub fn logComputeUnits(tc: *TransactionContext, _: *MemoryMap, _: RegisterMap) Error!void {
    try tc.consumeCompute(tc.compute_budget.syscall_base_cost);
    try tc.log("Program consumption: {} units remaining", .{tc.compute_meter});
}

/// [agave] https://github.com/firedancer-io/agave/blob/66ea0a11f2f77086d33253b4028f6ae7083d78e4/programs/bpf_loader/src/syscalls/logging.rs#L107
pub fn logData(tc: *TransactionContext, memory_map: *MemoryMap, registers: RegisterMap) Error!void {
    const vm_addr = registers.get(.r1);
    const len = registers.get(.r2);

    try tc.consumeCompute(tc.compute_budget.syscall_base_cost);

    const vm_messages = try memory_map.translateSlice(
        Slice,
        .constant,
        vm_addr,
        len,
        try tc.getCheckAligned(),
    );

    var cost = tc.compute_budget.syscall_base_cost *| vm_messages.len;
    for (vm_messages) |msg| cost +|= msg.len;
    try tc.consumeCompute(cost);

    var messages = try tc.allocator.alloc([]const u8, vm_messages.len);
    defer tc.allocator.free(messages);
    for (vm_messages, 0..) |msg, i| {
        messages[i] = try memory_map.translateSlice(
            u8,
            .constant,
            @intFromPtr(msg.addr),
            msg.len,
            try tc.getCheckAligned(),
        );
    }

    try stable_log.programData(tc, messages);
}

// memory operators
pub const memcpy = memops.memcpy;
pub const memset = memops.memset;
pub const memcmp = memops.memcmp;

// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/programs/bpf_loader/src/syscalls/mod.rs#L816
pub fn allocFree(_: *TransactionContext, _: *MemoryMap, _: RegisterMap) Error!void {
    @panic("TODO: implement allocFree syscall");
}

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/95764e268fe33a19819e6f9f411ff9e732cbdf0d/cpi/src/lib.rs#L329
pub const MAX_RETURN_DATA: usize = 1024;

/// [agave] https://github.com/anza-xyz/agave/blob/4f68141ba70b7574da0bc185ef5d08fe33d19887/programs/bpf_loader/src/syscalls/mod.rs#L1450
pub fn setReturnData(ctx: *TransactionContext, mm: *MemoryMap, rm: RegisterMap) Error!void {
    const addr = rm.get(.r1);
    const len = rm.get(.r2);

    const cost = if (ctx.compute_budget.cpi_bytes_per_unit > 0)
        (len / ctx.compute_budget.cpi_bytes_per_unit) +| ctx.compute_budget.syscall_base_cost
    else
        std.math.maxInt(u64);

    try ctx.consumeCompute(cost);

    if (len > TransactionReturnData.MAX_RETURN_DATA) {
        return error.ReturnDataTooLarge;
    }

    const empty_return_data: []const u8 = &[_]u8{};
    const return_data = if (len == 0)
        empty_return_data
    else
        try mm.vmap(.constant, addr, len);

    if (ctx.instruction_stack.len == 0) return error.CallDepth;
    const ic = ctx.instruction_stack.buffer[ctx.instruction_stack.len - 1];
    const program_id = ic.ixn_info.program_meta.pubkey;

    ctx.return_data.program_id = program_id;
    ctx.return_data.data.len = 0;
    ctx.return_data.data.appendSliceAssumeCapacity(return_data);
}

// hashing
const Parameters = enum(u64) {
    Bn254X5 = 0,
};

const Slice = extern struct {
    addr: [*]const u8,
    len: u64,
};

pub fn poseidon(
    ctx: *TransactionContext,
    memory_map: *MemoryMap,
    registers: RegisterMap,
) Error!void {
    // const parameters: Parameters = @enumFromInt(registers.get(.r1));
    const endianness: std.builtin.Endian = @enumFromInt(registers.get(.r2));
    const addr = registers.get(.r3);
    const len = registers.get(.r4);
    const result_addr = registers.get(.r5);

    if (len > 12) {
        return error.InvalidLength;
    }

    const budget = ctx.compute_budget;
    // TODO: Agave logs a specific message when this overflows.
    // https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L1923-L1926
    const cost = try budget.poseidonCost(len);
    try ctx.consumeCompute(cost);

    const hash_result = try memory_map.vmap(.mutable, result_addr, 32);
    const input_bytes = try memory_map.vmap(
        .constant,
        addr,
        len * @sizeOf(Slice),
    );
    const inputs = std.mem.bytesAsSlice(Slice, input_bytes);

    var hasher = phash.Hasher.init(endianness);
    for (inputs) |input| {
        const slice = try memory_map.vmap(
            .constant,
            @intFromPtr(input.addr),
            input.len,
        );
        hasher.append(slice[0..32]) catch {
            // TODO: THIS IS INCORRECT, it is set to temporarily match the error set. Agave
            // returns sets a custom poseidon error here.
            return error.OutOfMemory;
        };
    }
    const result = hasher.finish() catch {
        // TODO: THIS IS INCORRECT, it is set to temporarily match the error set. Agave
        // returns sets a custom poseidon error here.
        return error.OutOfMemory;
    };
    @memcpy(hash_result, &result);
}

// special
pub fn abort(_: *TransactionContext, _: *MemoryMap, _: RegisterMap) Error!void {
    return SyscallError.Abort;
}

pub fn panic(ctx: *TransactionContext, memory_map: *MemoryMap, registers: RegisterMap) Error!void {
    const file = registers.get(.r1);
    const len = registers.get(.r2);

    try ctx.consumeCompute(len);

    const message = try memory_map.vmap(.constant, file, len);
    if (!std.unicode.utf8ValidateSlice(message)) {
        return SyscallError.InvalidString;
    }

    return SyscallError.Panic;
}

test poseidon {
    try sig.vm.tests.testElfWithSyscalls(
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
