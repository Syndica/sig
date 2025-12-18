const std = @import("std");
const sig = @import("../../sig.zig");

pub const cpi = @import("cpi.zig");
pub const memops = @import("memops.zig");
pub const hash = @import("hash.zig");
pub const ecc = @import("ecc.zig");
pub const sysvar = @import("sysvar.zig");

const stable_log = sig.runtime.stable_log;
const pubkey_utils = sig.runtime.pubkey_utils;
const serialize = sig.runtime.program.bpf.serialize;

const memory = sig.vm.memory;
const Murmur3 = std.hash.Murmur3_32;
const SyscallError = sig.vm.SyscallError;
const Pubkey = sig.core.Pubkey;
const MemoryMap = memory.MemoryMap;
const InstructionError = sig.core.instruction.InstructionError;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const TransactionContext = sig.runtime.TransactionContext;
const TransactionReturnData = sig.runtime.transaction_context.TransactionReturnData;
const InstructionInfo = sig.runtime.InstructionInfo;
const AccountMeta = cpi.AccountMetaRust;
const Feature = sig.core.features.Feature;

pub const Error = sig.vm.ExecutionError;

pub const SyscallFn = *const fn (
    *TransactionContext,
    *MemoryMap,
    *RegisterMap,
) Error!void;

pub const Syscall = enum {
    abort,
    sol_panic_,
    sol_alloc_free_,

    sol_log_,
    sol_log_64_,
    sol_log_pubkey,
    sol_log_compute_units_,
    sol_log_data,

    sol_create_program_address,
    sol_try_find_program_address,

    sol_sha256,
    sol_keccak256,
    sol_blake3,
    sol_poseidon,

    sol_secp256k1_recover,
    sol_curve_validate_point,
    sol_curve_group_op,
    sol_curve_multiscalar_mul,
    sol_alt_bn128_group_op,
    sol_alt_bn128_compression,

    sol_get_clock_sysvar,
    sol_get_epoch_schedule_sysvar,
    sol_get_fees_sysvar,
    sol_get_rent_sysvar,
    sol_get_last_restart_slot,
    sol_get_epoch_rewards_sysvar,

    sol_memcpy_,
    sol_memmove_,
    sol_memset_,
    sol_memcmp_,

    sol_get_processed_sibling_instruction,
    sol_get_stack_height,
    sol_set_return_data,
    sol_get_return_data,
    sol_get_sysvar,
    sol_get_epoch_stake,
    sol_remaining_compute_units,

    sol_invoke_signed_c,
    sol_invoke_signed_rust,

    /// We basically just store this as an array of syscall enumerations with their murmur hash as the value.
    /// This makes lookups O(N) relative to the number of syscalls, however this shouldn't be a huge problem.
    /// The hashmap approach we had before only slightly reduced the lookup times, all of which was wiped
    /// out by the cost of allocating it. So this is the prefered approach for now.
    ///
    /// TODO: perhaps we can look into a PHF based approach here, although I imagine it'll just end up
    /// being keyed by murmur and truncated to unique bits.
    pub const Registry = struct {
        map: std.EnumArray(Syscall, ?u32),
        is_stubbed: bool,

        /// Relates Syscalls to the Murmur3 hash of their name, used for symbol collision checking.
        pub const ALL_ENABLED: Registry = .{ .map = b: {
            var kvs: std.enums.EnumFieldStruct(Syscall, ?u32, null) = undefined;
            for (@typeInfo(Syscall).@"enum".fields) |field| {
                @field(kvs, field.name) = Murmur3.hashWithSeed(field.name, 0);
            }
            break :b .init(kvs);
        }, .is_stubbed = false };

        pub const ALL_DISABLED: Registry = .{ .map = .initFill(null), .is_stubbed = false };

        /// Returns a `SycallFn` based on the provided hash.
        pub fn get(self: *const Registry, bytes: u32) ?SyscallFn {
            const syscall: Syscall = for (self.map.values, 0..) |entry, i| {
                const value = entry orelse continue; // disabled entries don't collide
                if (value == bytes) break @enumFromInt(i); // assumes that the EnumArray will be in "array" mode, which it should be.
            } else return null; // no such hash
            // TODO: consider just making a build flag for harness builds that removes this check entirely for perf
            return if (self.is_stubbed) &stubbed else map.get(syscall);
        }

        fn stubbed(_: *TransactionContext, _: *MemoryMap, _: *RegisterMap) Error!void {}

        /// Generally spekaing this should only be used for tests and special setup.
        /// Otherwise take the ALL_ENABLED -> disabling approach, since it's faster.
        pub fn enable(self: *Registry, name: Syscall) void {
            self.map.set(name, Murmur3.hashWithSeed(@tagName(name), 0));
        }
    };

    /// Lookup for the syscall's implementation function.
    pub const map = std.EnumArray(Syscall, SyscallFn).init(.{
        .abort = abort,
        .sol_panic_ = panic,
        .sol_alloc_free_ = allocFree,

        .sol_log_ = log,
        .sol_log_64_ = log64,
        .sol_log_pubkey = logPubkey,
        .sol_log_compute_units_ = logComputeUnits,
        .sol_log_data = logData,

        .sol_create_program_address = createProgramAddress,
        .sol_try_find_program_address = findProgramAddress,

        .sol_sha256 = hash.sha256,
        .sol_keccak256 = hash.keccak256,
        .sol_blake3 = hash.blake3,
        .sol_poseidon = hash.poseidon,

        .sol_secp256k1_recover = ecc.secp256k1Recover,
        .sol_curve_validate_point = ecc.curvePointValidation,
        .sol_curve_group_op = ecc.curveGroupOp,
        .sol_curve_multiscalar_mul = ecc.curveMultiscalarMul,
        .sol_alt_bn128_group_op = ecc.altBn128GroupOp,
        .sol_alt_bn128_compression = ecc.altBn128Compression,

        .sol_get_clock_sysvar = sysvar.getClock,
        .sol_get_epoch_schedule_sysvar = sysvar.getEpochSchedule,
        .sol_get_fees_sysvar = sysvar.getFees,
        .sol_get_rent_sysvar = sysvar.getRent,
        .sol_get_last_restart_slot = sysvar.getLastRestartSlot,
        .sol_get_epoch_rewards_sysvar = sysvar.getEpochRewards,
        .sol_get_sysvar = sysvar.getSysvar,

        .sol_memcpy_ = memops.memcpy,
        .sol_memmove_ = memops.memmove,
        .sol_memset_ = memops.memset,
        .sol_memcmp_ = memops.memcmp,

        .sol_get_processed_sibling_instruction = getProcessedSiblingInstruction,
        .sol_get_stack_height = getStackHeight,
        .sol_set_return_data = setReturnData,
        .sol_get_return_data = getReturnData,
        .sol_get_epoch_stake = getEpochStake,
        .sol_remaining_compute_units = remainingComputeUnits,

        .sol_invoke_signed_c = cpi.invokeSignedC,
        .sol_invoke_signed_rust = cpi.invokeSignedRust,
    });

    const Gate = struct {
        feature: Feature,
        /// Whether the feature "disables", instead of "enabling" the syscall.
        invert: bool = false,
    };

    /// Describes syscalls whos activation is locked behind a feature gate.
    pub const gates = std.EnumArray(Syscall, ?Gate).initDefault(@as(?Gate, null), .{
        // NOTE: also needs to check for `reject_deployment_of_broken_elfs`.
        .sol_alloc_free_ = .{ .feature = .disable_deploy_of_alloc_free_syscall, .invert = true },

        .sol_blake3 = .{ .feature = .blake3_syscall_enabled },
        .sol_poseidon = .{ .feature = .enable_poseidon_syscall },

        .sol_curve_validate_point = .{ .feature = .curve25519_syscall_enabled },
        .sol_curve_group_op = .{ .feature = .curve25519_syscall_enabled },
        .sol_curve_multiscalar_mul = .{ .feature = .curve25519_syscall_enabled },
        .sol_alt_bn128_group_op = .{ .feature = .enable_alt_bn128_syscall },
        .sol_alt_bn128_compression = .{ .feature = .enable_alt_bn128_compression_syscall },

        .sol_get_fees_sysvar = .{ .feature = .disable_fees_sysvar, .invert = true },
        .sol_get_last_restart_slot = .{ .feature = .last_restart_slot_sysvar },
        .sol_remaining_compute_units = .{ .feature = .remaining_compute_units_syscall_enabled },
        .sol_get_sysvar = .{ .feature = .get_sysvar_syscall_enabled },
        .sol_get_epoch_stake = .{ .feature = .enable_get_epoch_stake_syscall },
    });
};

// logging
/// [agave] https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L3-L33
pub fn log(tc: *TransactionContext, memory_map: *MemoryMap, registers: *RegisterMap) Error!void {
    const vm_addr = registers.get(.r1);
    const len = registers.get(.r2);

    try tc.consumeCompute(@max(tc.compute_budget.syscall_base_cost, len));

    const message = try memory_map.translateSlice(
        u8,
        .constant,
        vm_addr,
        len,
        tc.getCheckAligned(),
    );

    if (!std.unicode.utf8ValidateSlice(message)) {
        return SyscallError.InvalidString;
    }

    try stable_log.programLog(tc, "{s}", .{message});
}

/// [agave] https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L35-L56
pub fn log64(tc: *TransactionContext, _: *MemoryMap, registers: *RegisterMap) Error!void {
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
    registers: *RegisterMap,
) Error!void {
    const vm_addr = registers.get(.r1);

    try tc.consumeCompute(tc.compute_budget.log_pubkey_units);

    const pubkey_bytes = try memory_map.translateSlice(
        u8,
        .constant,
        vm_addr,
        @sizeOf(Pubkey),
        tc.getCheckAligned(),
    );
    const pubkey: Pubkey = @bitCast(pubkey_bytes[0..@sizeOf(Pubkey)].*);

    try stable_log.programLog(tc, "{}", .{pubkey});
}

/// [agave] https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L58-L80
pub fn logComputeUnits(tc: *TransactionContext, _: *MemoryMap, _: *RegisterMap) Error!void {
    try tc.consumeCompute(tc.compute_budget.syscall_base_cost);
    try tc.log("Program consumption: {} units remaining", .{tc.compute_meter});
}

/// [agave] https://github.com/firedancer-io/agave/blob/66ea0a11f2f77086d33253b4028f6ae7083d78e4/programs/bpf_loader/src/syscalls/logging.rs#L107
pub fn logData(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const vm_addr = registers.get(.r1);
    const len = registers.get(.r2);

    try tc.consumeCompute(tc.compute_budget.syscall_base_cost);

    const vm_messages = try memory_map.translateSlice(
        memory.VmSlice,
        .constant,
        vm_addr,
        len,
        tc.getCheckAligned(),
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
            msg.ptr,
            msg.len,
            tc.getCheckAligned(),
        );
    }

    try stable_log.programData(tc, messages);
}

// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/programs/bpf_loader/src/syscalls/mod.rs#L816
pub fn allocFree(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const size = registers.get(.r1);
    const free_addr = registers.get(.r2);
    const alignment: u64 = if (tc.getCheckAligned()) serialize.BPF_ALIGN_OF_U128 else 1;

    // Ensure aligning up size doesnt overflow isize.
    // https://doc.rust-lang.org/beta/std/alloc/struct.Layout.html#method.from_size_align
    const bump_to_align = (alignment - (size % alignment)) % alignment;
    if ((size +| bump_to_align) > std.math.maxInt(isize)) {
        registers.set(.r0, 0);
        return;
    }

    // Freeing allocated memory is not implemented.
    if (free_addr != 0) {
        registers.set(.r0, 0);
        return;
    }

    // Find the heap region to know how much can be bump allocated.
    var bump_max: u64 = 0;
    if (memory_map.region(.constant, memory.HEAP_START) catch null) |heap_region| {
        bump_max = heap_region.constSlice().len;
    }

    // Bound check
    const bytes_to_align = (alignment - (tc.bpf_alloc_pos % alignment)) % alignment;
    const addr_offset = tc.bpf_alloc_pos +| bytes_to_align;
    if (addr_offset +| size > bump_max) {
        registers.set(.r0, 0);
        return;
    }

    // Return bump allocated offset
    tc.bpf_alloc_pos = addr_offset +| size;
    registers.set(.r0, memory.HEAP_START +| addr_offset);
}

/// [agave] https://github.com/anza-xyz/agave/blob/4d9d57c433b491689ba7793aa9339eae22c218d3/programs/bpf_loader/src/syscalls/mod.rs#L2144
pub fn getEpochStake(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const vote_pubkey_addr = registers.get(.r1);

    // On null voter vm address, return total active cluster stake (as defined by EpochContext).
    if (vote_pubkey_addr == 0) {
        try tc.consumeCompute(tc.compute_budget.syscall_base_cost);
        registers.set(.r0, tc.epoch_stakes.total_stake);
        return;
    }

    try tc.consumeCompute(
        tc.compute_budget.syscall_base_cost +|
            (Pubkey.SIZE / tc.compute_budget.cpi_bytes_per_unit) +|
            tc.compute_budget.mem_op_base_cost,
    );

    const vote_address = try memory_map.translateType(
        Pubkey,
        .constant,
        vote_pubkey_addr,
        tc.getCheckAligned(),
    );

    if (tc.epoch_stakes.stakes.stake_delegations.getPtr(vote_address.*)) |delegation| {
        registers.set(.r0, delegation.stake);
    } else {
        registers.set(.r0, 0);
    }
}

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/ac11e3e568952977e63bce6bb20e37f26a61e151/instruction/src/lib.rs#L296
const ProcessedSiblingInstruction = extern struct {
    data_len: u64,
    accounts_len: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/4d9d57c433b491689ba7793aa9339eae22c218d3/programs/bpf_loader/src/syscalls/mod.rs#L1529
pub fn getProcessedSiblingInstruction(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const index = registers.get(.r1);
    const meta_addr = registers.get(.r2);
    const program_id_addr = registers.get(.r3);
    const data_addr = registers.get(.r4);
    const accounts_addr = registers.get(.r5);

    try tc.consumeCompute(tc.compute_budget.syscall_base_cost);

    var reverse_index: usize = 0;
    const stack_height = tc.instruction_stack.len;
    const maybe_info = for (0..tc.instruction_trace.len) |i| {
        const trace = &tc.instruction_trace.buffer[tc.instruction_trace.len - i - 1]; // reversed
        if (trace.depth < stack_height) break null;
        if (trace.depth == stack_height) {
            if (index +| 1 == reverse_index) break &trace.ixn_info;
            reverse_index +|= 1;
        }
    } else null;

    if (maybe_info) |info| {
        const check_aligned = tc.getCheckAligned();
        const header = try memory_map.translateType(
            ProcessedSiblingInstruction,
            .mutable,
            meta_addr,
            check_aligned,
        );

        if (header.data_len == info.instruction_data.len and
            header.accounts_len == info.account_metas.items.len)
        {
            const program_id = try memory_map.translateType(
                Pubkey,
                .mutable,
                program_id_addr,
                check_aligned,
            );
            const data = try memory_map.translateSlice(
                u8,
                .mutable,
                data_addr,
                header.data_len,
                check_aligned,
            );
            const accounts = try memory_map.translateSlice(
                AccountMeta,
                .mutable,
                accounts_addr,
                header.accounts_len,
                check_aligned,
            );
            if (memops.isOverlapping(
                @intFromPtr(header),
                @sizeOf(ProcessedSiblingInstruction),
                @intFromPtr(program_id),
                @sizeOf(Pubkey),
            ) or memops.isOverlapping(
                @intFromPtr(header),
                @sizeOf(ProcessedSiblingInstruction),
                @intFromPtr(accounts.ptr),
                accounts.len *| @sizeOf(AccountMeta),
            ) or memops.isOverlapping(
                @intFromPtr(header),
                @sizeOf(ProcessedSiblingInstruction),
                @intFromPtr(data.ptr),
                data.len,
            ) or memops.isOverlapping(
                @intFromPtr(program_id),
                @sizeOf(Pubkey),
                @intFromPtr(data.ptr),
                data.len,
            ) or memops.isOverlapping(
                @intFromPtr(program_id),
                @sizeOf(Pubkey),
                @intFromPtr(accounts.ptr),
                accounts.len *| @sizeOf(AccountMeta),
            ) or memops.isOverlapping(
                @intFromPtr(data.ptr),
                data.len,
                @intFromPtr(accounts.ptr),
                accounts.len *| @sizeOf(AccountMeta),
            )) {
                return SyscallError.CopyOverlapping;
            }

            program_id.* = info.program_meta.pubkey;
            @memcpy(data, info.instruction_data);

            for (info.account_metas.items, 0..) |meta, i| {
                const acc = tc.getAccountAtIndex(meta.index_in_transaction) orelse
                    return InstructionError.NotEnoughAccountKeys;

                accounts[i] = .{
                    .pubkey = acc.pubkey,
                    .is_signer = @intFromBool(meta.is_signer),
                    .is_writable = @intFromBool(meta.is_writable),
                };
            }
        }

        header.data_len = info.instruction_data.len;
        header.accounts_len = info.account_metas.items.len;
        registers.set(.r0, 1);
        return;
    }

    registers.set(.r0, 0);
    return;
}

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/95764e268fe33a19819e6f9f411ff9e732cbdf0d/cpi/src/lib.rs#L329
pub const MAX_RETURN_DATA: usize = 1024;

/// [agave] https://github.com/anza-xyz/agave/blob/4f68141ba70b7574da0bc185ef5d08fe33d19887/programs/bpf_loader/src/syscalls/mod.rs#L1450
pub fn setReturnData(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const addr = registers.get(.r1);
    const len = registers.get(.r2);

    const cost = (len / tc.compute_budget.cpi_bytes_per_unit) +|
        tc.compute_budget.syscall_base_cost;

    try tc.consumeCompute(cost);

    if (len > TransactionReturnData.MAX_RETURN_DATA) {
        return error.ReturnDataTooLarge;
    }

    const return_data: []const u8 = if (len == 0)
        &.{}
    else
        try memory_map.translateSlice(
            u8,
            .constant,
            addr,
            len,
            tc.getCheckAligned(),
        );

    if (tc.instruction_stack.len == 0) return error.CallDepth;
    const ic = tc.instruction_stack.buffer[tc.instruction_stack.len - 1];
    const program_id = ic.ixn_info.program_meta.pubkey;

    tc.return_data.program_id = program_id;
    tc.return_data.data.len = 0;
    tc.return_data.data.appendSliceAssumeCapacity(return_data);
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L1495-L1557
pub fn getReturnData(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    try tc.consumeCompute(tc.compute_budget.syscall_base_cost);

    const return_data_addr = registers.get(.r1);
    const input_length = registers.get(.r2);
    const program_id_addr = registers.get(.r3);

    const program_id = tc.return_data.program_id;
    const return_data = tc.return_data.data.constSlice();
    const length = @min(return_data.len, input_length);

    if (length != 0) {
        const cost = (length +| @sizeOf(Pubkey)) / tc.compute_budget.cpi_bytes_per_unit;
        try tc.consumeCompute(cost);

        const return_data_result = try memory_map.translateSlice(
            u8,
            .mutable,
            return_data_addr,
            length,
            tc.getCheckAligned(),
        );

        const program_id_result = try memory_map.translateType(
            Pubkey,
            .mutable,
            program_id_addr,
            tc.getCheckAligned(),
        );

        if (memops.isOverlapping(
            @intFromPtr(return_data_result.ptr),
            length,
            @intFromPtr(program_id_result),
            @sizeOf(Pubkey),
        )) {
            return SyscallError.CopyOverlapping;
        }

        const source = return_data[0..length];
        @memcpy(return_data_result, source);
        program_id_result.* = program_id;
    }

    registers.set(.r0, return_data.len);
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L1697-L1715
pub fn getStackHeight(
    tc: *TransactionContext,
    _: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    try tc.consumeCompute(tc.compute_budget.syscall_base_cost);
    registers.set(.r0, tc.instruction_stack.len);
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L1968-L1986
pub fn remainingComputeUnits(
    tc: *TransactionContext,
    _: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    try tc.consumeCompute(tc.compute_budget.syscall_base_cost);
    registers.set(.r0, tc.compute_meter);
}

// special
pub fn abort(_: *TransactionContext, _: *MemoryMap, _: *RegisterMap) Error!void {
    return SyscallError.Abort;
}

pub fn panic(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const file = registers.get(.r1);
    const len = registers.get(.r2);

    try tc.consumeCompute(len);

    const message = try memory_map.translateSlice(
        u8,
        .constant,
        file,
        len,
        tc.getCheckAligned(),
    );
    if (!std.unicode.utf8ValidateSlice(message)) {
        return SyscallError.InvalidString;
    }

    return SyscallError.Panic;
}

/// [agave] https://github.com/anza-xyz/agave/blob/7dae527c40dd6a7ef466b8555ccf64dfdc85e57b/programs/bpf_loader/src/syscalls/mod.rs#L903
pub fn findProgramAddress(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const seeds_addr = registers.get(.r1);
    const seeds_len = registers.get(.r2);
    const program_id_addr = registers.get(.r3);
    const address_addr = registers.get(.r4);
    const bump_seed_addr = registers.get(.r5);

    const cost = tc.compute_budget.create_program_address_units;
    try tc.consumeCompute(cost);

    const check_aligned = tc.getCheckAligned();
    const program_id, const seeds = try translateAndCheckProgramAddressInputs(
        memory_map,
        seeds_addr,
        seeds_len,
        program_id_addr,
        check_aligned,
    );

    var bump_seed: u8 = std.math.maxInt(u8);
    for (0..255) |_| {
        const new_address = pubkey_utils.createProgramAddress(
            seeds.constSlice(),
            &.{bump_seed},
            program_id,
        ) catch {
            bump_seed -|= 1;
            try tc.consumeCompute(cost);
            continue;
        };

        const bump_seed_ref = try memory_map.translateType(
            u8,
            .mutable,
            bump_seed_addr,
            check_aligned,
        );
        const address = try memory_map.translateSlice(
            u8,
            .mutable,
            address_addr,
            @sizeOf(Pubkey),
            check_aligned,
        );

        if (memops.isOverlapping(
            @intFromPtr(bump_seed_ref),
            @sizeOf(u8),
            @intFromPtr(address.ptr),
            address.len,
        )) return SyscallError.CopyOverlapping;

        bump_seed_ref.* = bump_seed;
        @memcpy(address, std.mem.asBytes(&new_address));
        return; // r0 = 0
    }

    registers.set(.r0, 1);
}

/// [agave] https://github.com/anza-xyz/agave/blob/7dae527c40dd6a7ef466b8555ccf64dfdc85e57b/programs/bpf_loader/src/syscalls/mod.rs#L864
pub fn createProgramAddress(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const seeds_addr = registers.get(.r1);
    const seeds_len = registers.get(.r2);
    const program_id_addr = registers.get(.r3);
    const address_addr = registers.get(.r4);

    const cost = tc.compute_budget.create_program_address_units;
    try tc.consumeCompute(cost);

    const check_aligned = tc.getCheckAligned();
    const program_id, const seeds = try translateAndCheckProgramAddressInputs(
        memory_map,
        seeds_addr,
        seeds_len,
        program_id_addr,
        check_aligned,
    );

    const new_address = pubkey_utils.createProgramAddress(seeds.slice(), &.{}, program_id) catch {
        registers.set(.r0, 1);
        return;
    };
    const address = try memory_map.translateSlice(
        u8,
        .mutable,
        address_addr,
        @sizeOf(Pubkey),
        check_aligned,
    );
    @memcpy(address, std.mem.asBytes(&new_address));
    return; // r0 = 0
}

fn translateAndCheckProgramAddressInputs(
    memory_map: *MemoryMap,
    seeds_addr: u64,
    seeds_len: u64,
    program_id_addr: u64,
    check_aligned: bool,
) Error!struct { Pubkey, std.BoundedArray([]const u8, pubkey_utils.MAX_SEEDS) } {
    const untranslated_seeds = try memory_map.translateSlice(
        memory.VmSlice,
        .constant,
        seeds_addr,
        seeds_len,
        check_aligned,
    );
    if (untranslated_seeds.len > pubkey_utils.MAX_SEEDS) {
        return SyscallError.BadSeeds; // PubkeyError.MaxSeedLengthExceeded
    }

    var seeds: std.BoundedArray([]const u8, pubkey_utils.MAX_SEEDS) = .{};
    for (untranslated_seeds) |untranslated_seed| {
        if (untranslated_seed.len > pubkey_utils.MAX_SEED_LEN) return SyscallError.BadSeeds;
        seeds.appendAssumeCapacity(try memory_map.translateSlice(
            u8,
            .constant,
            untranslated_seed.ptr,
            untranslated_seed.len,
            check_aligned,
        ));
    }

    const program_id = try memory_map.translateType(
        Pubkey,
        .constant,
        program_id_addr,
        check_aligned,
    );

    return .{ program_id.*, seeds };
}

// Syscall Tests

/// Meant only as a helper for tests below.
/// Invokes either createProgramAddress or findProgramAddress syscalls with VM context setup.
///
/// [agave] https://github.com/anza-xyz/agave/blob/7dae527c40dd6a7ef466b8555ccf64dfdc85e57b/programs/bpf_loader/src/syscalls/mod.rs#L4301
fn callProgramAddressSyscall(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    comptime syscall_fn: fn (*TransactionContext, *MemoryMap, *RegisterMap) Error!void,
    seeds: []const []const u8,
    program_id: Pubkey,
    overlap_outputs: bool,
) !struct { Pubkey, u8 } {
    const seeds_addr = 0x100000000;
    const program_id_addr = 0x200000000;
    const address_addr = 0x300000000;
    const bump_seed_addr = 0x400000000;
    const seed_data_addr = 0x500000000;

    var out_bump_seed: u8 = 0;
    var out_address = Pubkey.ZEROES;

    // Setup in/out params.
    var regions = std.ArrayList(memory.Region).init(allocator);
    defer regions.deinit();
    try regions.appendSlice(&.{
        memory.Region.init(.constant, std.mem.asBytes(&program_id), program_id_addr),
        memory.Region.init(.mutable, std.mem.asBytes(&out_address), address_addr),
        memory.Region.init(.mutable, std.mem.asBytes(&out_bump_seed), bump_seed_addr),
    });

    // Setup slice of VmSlices
    var seed_slices = std.ArrayList(memory.VmSlice).init(allocator);
    defer seed_slices.deinit();
    for (seeds, 0..) |seed, i| {
        const vm_addr = seed_data_addr +| (i *% 0x100000000);
        try seed_slices.append(.{ .ptr = vm_addr, .len = seed.len });
        try regions.append(memory.Region.init(.constant, seed, vm_addr));
    }

    // seeds_addr is only finalized now, but should appear before the others.
    try regions.appendSlice(&.{
        memory.Region.init(.constant, std.mem.sliceAsBytes(seed_slices.items), seeds_addr),
    });
    std.mem.sort(memory.Region, regions.items, {}, struct {
        fn less(_: void, r1: memory.Region, r2: memory.Region) bool {
            return r1.vm_addr_start < r2.vm_addr_start;
        }
    }.less);

    var memory_map = try MemoryMap.init(allocator, regions.items, .v3, .{});
    defer memory_map.deinit(allocator);

    var registers = RegisterMap.initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, seeds_addr);
    registers.set(.r2, seeds.len);
    registers.set(.r3, program_id_addr);
    registers.set(.r4, address_addr);
    registers.set(.r5, if (overlap_outputs) address_addr else bump_seed_addr);

    try syscall_fn(tc, &memory_map, &registers);
    return .{ out_address, out_bump_seed };
}

test findProgramAddress {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            },
        },
    });
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const cost = tc.compute_budget.create_program_address_units;
    const address = sig.runtime.program.bpf_loader.v3.ID;
    const max_tries: u64 = 256; // once per seed

    for (0..1000) |_| {
        const new_address = Pubkey.initRandom(prng.random());
        tc.compute_meter = cost * max_tries;
        const found_address, const bump_seed = try callProgramAddressSyscall(
            allocator,
            &tc,
            findProgramAddress,
            &.{ "Lil'", "Bits" },
            new_address,
            false,
        );
        const created_address, _ = try callProgramAddressSyscall(
            allocator,
            &tc,
            createProgramAddress,
            &.{ "Lil'", "Bits", &.{bump_seed} },
            new_address,
            false,
        );
        try std.testing.expect(found_address.equals(&created_address));
    }

    const seeds: []const []const u8 = &.{""};
    tc.compute_meter = cost * max_tries;
    _, const bump_seed = try callProgramAddressSyscall(
        allocator,
        &tc,
        findProgramAddress,
        seeds,
        address,
        false,
    );
    tc.compute_meter = cost * (max_tries - bump_seed);
    _ = try callProgramAddressSyscall(
        allocator,
        &tc,
        findProgramAddress,
        seeds,
        address,
        false,
    );
    tc.compute_meter = cost * (max_tries - bump_seed - 1);
    try std.testing.expectError(
        InstructionError.ComputationalBudgetExceeded,
        callProgramAddressSyscall(
            allocator,
            &tc,
            findProgramAddress,
            seeds,
            address,
            false,
        ),
    );

    const exceeded_seed = [_]u8{127} ** (pubkey_utils.MAX_SEED_LEN + 1);
    tc.compute_meter = cost * (max_tries - 1);
    try std.testing.expectError(
        SyscallError.BadSeeds,
        callProgramAddressSyscall(
            allocator,
            &tc,
            findProgramAddress,
            &.{&exceeded_seed},
            address,
            false,
        ),
    );

    comptime var exceeded_seeds: []const []const u8 = &.{};
    inline for (1..18) |i| exceeded_seeds = exceeded_seeds ++ &[_][]const u8{&[_]u8{@intCast(i)}};
    tc.compute_meter = cost * (max_tries - 1);
    try std.testing.expectError(
        SyscallError.BadSeeds,
        callProgramAddressSyscall(
            allocator,
            &tc,
            findProgramAddress,
            exceeded_seeds,
            address,
            false,
        ),
    );

    try std.testing.expectError(
        SyscallError.CopyOverlapping,
        callProgramAddressSyscall(
            allocator,
            &tc,
            findProgramAddress,
            seeds,
            address,
            true,
        ),
    );
}

test createProgramAddress {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            },
        },
    });
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const cost = tc.compute_budget.create_program_address_units;
    const address = sig.runtime.program.bpf_loader.v3.ID;
    tc.compute_meter = cost * 12; // enough for 12 calls to createProgramAddress

    const exceeded_seed: []const u8 = &([_]u8{127} ** (pubkey_utils.MAX_SEED_LEN + 1));
    try std.testing.expectError(
        SyscallError.BadSeeds,
        callProgramAddressSyscall(
            allocator,
            &tc,
            createProgramAddress,
            &.{exceeded_seed},
            address,
            false,
        ),
    );
    try std.testing.expectError(
        SyscallError.BadSeeds,
        callProgramAddressSyscall(
            allocator,
            &tc,
            createProgramAddress,
            &.{ "short_seed", exceeded_seed },
            address,
            false,
        ),
    );

    const max_seed: []const u8 = &([_]u8{0} ** pubkey_utils.MAX_SEED_LEN);
    _ = try callProgramAddressSyscall(
        allocator,
        &tc,
        createProgramAddress,
        &.{max_seed},
        address,
        false,
    );

    comptime var exceeded_seeds: []const []const u8 = &.{};
    inline for (1..16) |i| {
        exceeded_seeds = exceeded_seeds ++ &[_][]const u8{&[_]u8{@intCast(i + 1)}};
    }
    _ = try callProgramAddressSyscall(
        allocator,
        &tc,
        createProgramAddress,
        exceeded_seeds,
        address,
        false,
    );

    comptime var max_seeds: []const []const u8 = &.{};
    inline for (0..17) |i| {
        max_seeds = max_seeds ++ &[_][]const u8{&[_]u8{@intCast(i + 1)}};
    }
    try std.testing.expectError(
        SyscallError.BadSeeds,
        callProgramAddressSyscall(
            allocator,
            &tc,
            createProgramAddress,
            max_seeds,
            address,
            false,
        ),
    );

    var pk, _ = try callProgramAddressSyscall(
        allocator,
        &tc,
        createProgramAddress,
        &.{ "", &.{1} },
        address,
        false,
    );
    try std.testing.expect(
        Pubkey.parse("BwqrghZA2htAcqq8dzP1WDAhTXYTYWj7CHxF5j7TDBAe")
            .equals(&pk),
    );

    pk, _ = try callProgramAddressSyscall(
        allocator,
        &tc,
        createProgramAddress,
        &.{ "☉", &.{0} },
        address,
        false,
    );
    try std.testing.expect(
        Pubkey.parse("13yWmRpaTR4r5nAktwLqMpRNr28tnVUZw26rTvPSSB19")
            .equals(&pk),
    );

    pk, _ = try callProgramAddressSyscall(
        allocator,
        &tc,
        createProgramAddress,
        &.{ "Talking", "Squirrels" },
        address,
        false,
    );
    try std.testing.expect(
        Pubkey.parse("2fnQrngrQT4SeLcdToJAD96phoEjNL2man2kfRLCASVk")
            .equals(&pk),
    );

    const seed_pk: Pubkey = .parse("SeedPubey1111111111111111111111111111111111");
    pk, _ = try callProgramAddressSyscall(
        allocator,
        &tc,
        createProgramAddress,
        &.{ &seed_pk.data, &.{1} },
        address,
        false,
    );
    try std.testing.expect(
        Pubkey.parse("976ymqVnfE32QFe6NfGDctSvVa36LWnvYxhU6G2232YL")
            .equals(&pk),
    );

    const pk_a, _ = try callProgramAddressSyscall(
        allocator,
        &tc,
        createProgramAddress,
        &.{ "Talking", "Squirrels" },
        address,
        false,
    );
    const pk_b, _ = try callProgramAddressSyscall(
        allocator,
        &tc,
        createProgramAddress,
        &.{"Talking"},
        address,
        false,
    );
    try std.testing.expect(!pk_a.equals(&pk_b));

    tc.compute_meter = 0;
    try std.testing.expectError(
        InstructionError.ComputationalBudgetExceeded,
        callProgramAddressSyscall(
            allocator,
            &tc,
            createProgramAddress,
            &.{ "", &.{1} },
            address,
            false,
        ),
    );
}

test allocFree {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{},
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const heap = try allocator.alloc(u8, 4096);
    defer allocator.free(heap);

    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &.{}, memory.RODATA_START),
            memory.Region.init(.mutable, &.{}, memory.STACK_START),
            memory.Region.init(.mutable, heap, memory.HEAP_START),
        },
        .v3,
        .{},
    );
    defer memory_map.deinit(allocator);

    for ([_]struct { u64, u64, u64 }{
        // first alloc 1021 bytes
        .{ 1021, 0, memory.HEAP_START },
        // then alloc 512 bytes (make sure its aligned)
        .{ 512, 0, std.mem.alignForward(u64, memory.HEAP_START + 1024, 16) },
        // try freeing the first allocation (freeing isnt supported atm)
        .{ 1021, memory.HEAP_START, 0 },
        // try alloc over heap size
        .{ heap.len + 1, 0, 0 },
    }) |case| {
        var registers = RegisterMap.initFill(0);
        registers.set(.r1, case[0]);
        registers.set(.r2, case[1]);
        try allocFree(&tc, &memory_map, &registers);
        try std.testing.expectEqual(case[2], registers.get(.r0));
    }
}

test getProcessedSiblingInstruction {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var account_params: [9]testing.ExecuteContextsParams.AccountParams = undefined;
    for (&account_params) |*a| a.* = .{
        .pubkey = Pubkey.initRandom(prng.random()),
        .owner = sig.runtime.program.bpf_loader.v2.ID,
    };

    var cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &account_params,
    });
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    var allocated_account_metas: std.ArrayListUnmanaged(InstructionInfo.AccountMetas) = .empty;
    defer {
        for (allocated_account_metas.items) |*account_metas| account_metas.deinit(allocator);
        allocated_account_metas.deinit(allocator);
    }

    const trace_indexes: [8]u8 = std.simd.iota(u8, 8);
    for ([_]u8{ 1, 2, 3, 2, 2, 3, 4, 3 }, 0..) |stack_height, index_in_trace| {
        while (stack_height <= tc.instruction_stack.len) {
            _ = tc.instruction_stack.pop();
        }
        if (stack_height > tc.instruction_stack.len) {
            var info = InstructionInfo{
                .program_meta = .{
                    .pubkey = tc.accounts[0].pubkey,
                    .index_in_transaction = 0,
                },
                .account_metas = .empty,
                .dedupe_map = @splat(0xff),
                .instruction_data = @as(*const [1]u8, &trace_indexes[index_in_trace]),
                .owned_instruction_data = false,
            };

            const index_in_tc = index_in_trace +| 1;
            info.dedupe_map[index_in_tc] = 0;
            try info.account_metas.append(allocator, .{
                .pubkey = tc.accounts[index_in_tc].pubkey,
                .index_in_transaction = @intCast(index_in_tc),
                .is_signer = false,
                .is_writable = false,
            });

            try allocated_account_metas.append(allocator, info.account_metas);

            tc.instruction_stack.appendAssumeCapacity(.{
                .tc = &tc,
                .ixn_info = info,
                .depth = @intCast(tc.instruction_stack.len),
            });
            tc.instruction_trace.appendAssumeCapacity(.{
                .ixn_info = info,
                .depth = @intCast(tc.instruction_stack.len),
            });
        }
    }

    const vm_addr = 0x100000000;
    const meta_offset = 0;
    const program_id_offset = meta_offset + @sizeOf(ProcessedSiblingInstruction);
    const data_offset = program_id_offset + @sizeOf(Pubkey);
    const accounts_offset = data_offset + 0x100;
    const end_offset = accounts_offset + (@sizeOf(cpi.AccountInfoRust) * 4);

    var buffer = std.mem.zeroes([end_offset]u8);
    var memory_map = try MemoryMap.init(
        allocator,
        &.{memory.Region.init(.mutable, &buffer, vm_addr)},
        .v3,
        .{},
    );
    defer memory_map.deinit(allocator);

    const ps_instruction = try memory_map.translateType(
        ProcessedSiblingInstruction,
        .mutable,
        vm_addr,
        true,
    );
    ps_instruction.* = .{
        .data_len = 1,
        .accounts_len = 1,
    };

    const program_id = try memory_map.translateType(
        Pubkey,
        .mutable,
        vm_addr +| program_id_offset,
        true,
    );
    const data = try memory_map.translateSlice(
        u8,
        .mutable,
        vm_addr +| data_offset,
        ps_instruction.data_len,
        true,
    );
    const accounts = try memory_map.translateSlice(
        AccountMeta,
        .mutable,
        vm_addr +| accounts_offset,
        ps_instruction.accounts_len,
        true,
    );

    {
        tc.compute_meter = tc.compute_budget.syscall_base_cost;
        var registers = RegisterMap.initFill(0);
        registers.set(.r1, 0);
        registers.set(.r2, vm_addr +| meta_offset);
        registers.set(.r3, vm_addr +| program_id_offset);
        registers.set(.r4, vm_addr +| data_offset);
        registers.set(.r5, vm_addr +| accounts_offset);
        try getProcessedSiblingInstruction(&tc, &memory_map, &registers);

        try std.testing.expectEqual(registers.get(.r0), 1);
        try std.testing.expectEqual(ps_instruction.data_len, 1);
        try std.testing.expectEqual(ps_instruction.accounts_len, 1);
        try std.testing.expect(program_id.equals(&tc.accounts[0].pubkey));
        try std.testing.expectEqualSlices(u8, data, &.{5});
        try std.testing.expectEqualSlices(AccountMeta, accounts, &.{.{
            .pubkey = tc.accounts[6].pubkey,
            .is_signer = 0,
            .is_writable = 0,
        }});
    }

    {
        tc.compute_meter = tc.compute_budget.syscall_base_cost;
        var registers = RegisterMap.initFill(0);
        registers.set(.r1, 1);
        registers.set(.r2, vm_addr +| meta_offset);
        registers.set(.r3, vm_addr +| program_id_offset);
        registers.set(.r4, vm_addr +| data_offset);
        registers.set(.r5, vm_addr +| accounts_offset);
        try getProcessedSiblingInstruction(&tc, &memory_map, &registers);
        try std.testing.expectEqual(registers.get(.r0), 0);
    }

    {
        tc.compute_meter = tc.compute_budget.syscall_base_cost;
        var registers = RegisterMap.initFill(0);
        registers.set(.r1, 0);
        registers.set(.r2, vm_addr +| meta_offset);
        registers.set(.r3, vm_addr +| meta_offset);
        registers.set(.r4, vm_addr +| meta_offset);
        registers.set(.r5, vm_addr +| meta_offset);
        try std.testing.expectError(
            SyscallError.CopyOverlapping,
            getProcessedSiblingInstruction(&tc, &memory_map, &registers),
        );
    }
}

test getEpochStake {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const target_vote_address = Pubkey.initRandom(prng.random());
    const total_epoch_stake = 200_000_000_000_000;

    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            // Sets total_stake to sum of all voter stakes:
            .epoch_stakes = &.{
                .{
                    .pubkey = target_vote_address,
                    .stake = total_epoch_stake / 2,
                },
                .{
                    .pubkey = Pubkey.initRandom(prng.random()),
                    .stake = total_epoch_stake / 2,
                },
            },
        },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    // Test get total stake
    {
        tc.compute_meter = tc.compute_budget.syscall_base_cost;

        var memory_map = try MemoryMap.init(allocator, &.{}, .v3, .{});
        defer memory_map.deinit(allocator);

        var registers = RegisterMap.initFill(0);
        try getEpochStake(&tc, &memory_map, &registers);

        try std.testing.expectEqual(
            registers.get(.r0),
            total_epoch_stake,
        );
    }

    // Test invalid read-only memory region.
    {
        tc.compute_meter = tc.compute_budget.syscall_base_cost +|
            (Pubkey.SIZE / tc.compute_budget.cpi_bytes_per_unit) +|
            tc.compute_budget.mem_op_base_cost;

        const vote_addr = 0x100000000;
        const vote_buffer = std.mem.asBytes(&target_vote_address)[0..31]; // not all bytes readable.

        var memory_map = try MemoryMap.init(allocator, &.{
            memory.Region.init(.constant, vote_buffer, vote_addr),
        }, .v3, .{});
        defer memory_map.deinit(allocator);

        var registers = RegisterMap.initFill(0);
        registers.set(.r1, vote_addr);

        try std.testing.expectError(
            memory.RegionError.AccessViolation,
            getEpochStake(&tc, &memory_map, &registers),
        );
    }

    // Test valid vote address stake read
    {
        tc.compute_meter = tc.compute_budget.syscall_base_cost +|
            (Pubkey.SIZE / tc.compute_budget.cpi_bytes_per_unit) +|
            tc.compute_budget.mem_op_base_cost;

        const vote_addr = 0x100000000;
        const vote_buffer = std.mem.asBytes(&target_vote_address);

        var memory_map = try MemoryMap.init(allocator, &.{
            memory.Region.init(.constant, vote_buffer, vote_addr),
        }, .v3, .{});
        defer memory_map.deinit(allocator);

        var registers = RegisterMap.initFill(0);
        registers.set(.r1, vote_addr);
        try getEpochStake(&tc, &memory_map, &registers);

        try std.testing.expectEqual(
            registers.get(.r0),
            total_epoch_stake / 2,
        );
    }

    // Test readable address (but not a registered voter).
    {
        tc.compute_meter = tc.compute_budget.syscall_base_cost +|
            (Pubkey.SIZE / tc.compute_budget.cpi_bytes_per_unit) +|
            tc.compute_budget.mem_op_base_cost;

        const invalid_vote_address = Pubkey.initRandom(prng.random());
        const vote_addr = 0x100000000;
        const vote_buffer = std.mem.asBytes(&invalid_vote_address);

        var memory_map = try MemoryMap.init(allocator, &.{
            memory.Region.init(.constant, vote_buffer, vote_addr),
        }, .v3, .{});
        defer memory_map.deinit(allocator);

        var registers = RegisterMap.initFill(0);
        registers.set(.r1, vote_addr);
        try getEpochStake(&tc, &memory_map, &registers);

        try std.testing.expectEqual(
            registers.get(.r0),
            0,
        );
    }
}

test "set and get return data" {
    const allocator = std.testing.allocator;

    const src_addr = 0x100000000;
    const dst_addr = 0x200000000;
    const program_id_addr = 0x300000000;

    const data: [24]u8 = .{42} ** 24;
    var data_buffer: [16]u8 = .{0} ** 16;
    var id_buffer: [32]u8 = .{0} ** 32;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{.{
                .pubkey = sig.core.Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            }},
            .compute_meter = 10_000,
        },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const program_id = sig.runtime.program.bpf_loader.v2.ID;
    const instr_info = sig.runtime.InstructionInfo{
        .program_meta = .{
            .index_in_transaction = 0,
            .pubkey = program_id,
        },
        .account_metas = .{},
        .dedupe_map = @splat(0xff),
        .instruction_data = &.{},
        .owned_instruction_data = false,
        .initial_account_lamports = 0,
    };
    try sig.runtime.executor.pushInstruction(&tc, instr_info);

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, &.{
        memory.Region.init(.constant, &data, src_addr),
        memory.Region.init(.mutable, &data_buffer, dst_addr),
        memory.Region.init(.mutable, &id_buffer, program_id_addr),
    }, .v3, .{});
    defer memory_map.deinit(allocator);

    {
        registers.set(.r1, src_addr);
        registers.set(.r2, data.len);

        try setReturnData(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
    }

    {
        registers.set(.r1, dst_addr);
        registers.set(.r2, data_buffer.len);
        registers.set(.r3, program_id_addr);

        try getReturnData(&tc, &memory_map, &registers);

        try std.testing.expectEqual(data.len, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &data_buffer, data[0..data_buffer.len]);
        try std.testing.expectEqual(id_buffer, program_id.data);
    }

    {
        registers.set(.r1, program_id_addr);
        registers.set(.r2, data_buffer.len);
        registers.set(.r3, program_id_addr);

        try std.testing.expectError(
            error.CopyOverlapping,
            getReturnData(&tc, &memory_map, &registers),
        );
    }
}
