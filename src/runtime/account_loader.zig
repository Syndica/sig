const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const AccountSharedData = sig.runtime.AccountSharedData;
const TransactionError = sig.ledger.transaction_status.TransactionError; // TODO: let's put this somewhere else

/// Roughly 0.5us/page, where page is 32K; given roughly 15CU/us, the
/// default heap page cost = 0.5 * 15 ~= 8CU/page
pub const DEFAULT_HEAP_COST: u64 = 8;
pub const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT: u32 = 200_000;
// SIMD-170 defines max CUs to be allocated for any builtin program instructions, that
// have not been migrated to sBPF programs.
pub const MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT: u32 = 3_000;
pub const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
pub const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024;
pub const MIN_HEAP_FRAME_BYTES: u32 = HEAP_LENGTH;

/// Length of the heap memory region used for program heap.
pub const HEAP_LENGTH = 32 * 1024;

/// The total accounts data a transaction can load is limited to 64MiB to not break
/// anyone in Mainnet-beta today. It can be set by set_loaded_accounts_data_size_limit instruction
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/ddde57c40c4d4334c25bb32de17f833d4d79a889/src/ballet/txn/fd_txn.h#L116
const MAX_TX_ACCOUNT_LOCKS = 128;

const Return = struct {
    collected_rent: u64 = 0,
    accounts: [MAX_TX_ACCOUNT_LOCKS]?AccountSharedData = .{null} ** MAX_TX_ACCOUNT_LOCKS,
};

test {
    std.testing.refAllDecls(@This());
}

// [firedancer] https://github.com/firedancer-io/firedancer/blob/49056135a4c7ba024cb75a45925439239904238b/src/flamenco/runtime/fd_executor.c#L377
// firedancer actually already has the accounts data ready at this point, but Agave calls into the
// bank's callbacks into accountsdb.
pub fn loadTransactionAccounts(
    allocator: std.mem.Allocator,
    tx: *const sig.core.Transaction,
    // should be inside tx?
    requested_max_total_data_size: u32,

    // could take in a bank instead?
    slot: Slot,
    schedule: sig.core.EpochSchedule,
    accounts_db: *sig.accounts_db.AccountsDB,
    //
    features: sig.runtime.FeatureSet,
) !Return {
    // required for rent logic
    const epoch, const slot_index = schedule.getEpochAndSlotIndex(slot);
    _ = slot_index;
    _ = epoch;

    const account_in_instr = blk: {
        var buf_instr = [_]bool{false} ** MAX_TX_ACCOUNT_LOCKS;
        for (tx.msg.instructions) |instruction| {
            for (instruction.account_indexes) |account_index| {
                buf_instr[account_index] = true;
            }
        }
        break :blk buf_instr;
    };

    var retval: Return = .{};
    errdefer {
        for (retval.accounts) |maybe_account| {
            if (maybe_account) |account| allocator.free(account.data);
        }
    }

    const disable_account_loader_special_case = true;
    // TODO: properly check this once we support false
    // const disable_account_loader_special_case = features.active.contains(
    //     sig.runtime.feature_set.DISABLE_ACCOUNT_LOADER_SPECIAL_CASE,
    // );

    var accumulated_account_size: u32 = 0;

    for (tx.msg.account_keys, 0..) |account_key, account_idx| {
        const is_instruction_account = account_in_instr[account_idx];
        const is_writeable = tx.msg.isWriteable(account_idx);

        var account_data_size: usize = 0;

        // case 1: account is instructions sysvar.
        //         Do not count it towards the total loaded account size.
        if (account_key.equals(&sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID)) {
            @setCold(true);
            retval.accounts[account_idx] = try constructInstructionsAccount(allocator, tx);
            continue;
        }

        // case 2: account is not writeable, not a program account, and may be in loaded program cache.
        //         https://github.com/anza-xyz/agave/pull/3548 > "This "optimization" actually costs us performance"
        if (!is_instruction_account and
            !is_writeable and
            !disable_account_loader_special_case and
            isMaybeInLoadedProgramCache(account_key))
        {
            @setCold(true);
            @panic("TODO: Assuming the feature is enabled");
        }

        // case 3: default case
        const found_account = try accounts_db.getAccount(&account_key);
        defer found_account.deinit(accounts_db.allocator);

        const found_shared_account: AccountSharedData = .{
            .data = try found_account.data.readAllAllocate(allocator),
            .executable = found_account.executable,
            .lamports = found_account.lamports,
            .owner = found_account.owner,
            .rent_epoch = found_account.rent_epoch,
        };

        retval.accounts[account_idx] = found_shared_account;
        account_data_size += found_shared_account.data.len;
        if (is_writeable) {
            retval.collected_rent += collectRent(account_key);
            // acct->starting_lamports = acct->meta->info.lamports; ? Not sure if we need a field like this
        }

        try accumulateAndCheckLoadedAccountDataSize(
            &accumulated_account_size,
            account_data_size,
            requested_max_total_data_size,
        );
    }

    const remove_accounts_executable_flag_checks = features.active.contains(
        sig.runtime.feature_set.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS,
    );

    for (tx.msg.instructions) |instr| {
        const program_id = tx.msg.account_keys[instr.program_index];

        if (program_id.equals(&sig.runtime.ids.NATIVE_LOADER_ID)) continue;

        const program_account = retval.accounts[instr.program_index] orelse
            return error.ProgramAccountNotFound;

        if (!remove_accounts_executable_flag_checks and !program_account.executable)
            return error.InvalidProgramForExecution;

        if (program_account.owner.equals(&sig.runtime.ids.NATIVE_LOADER_ID)) continue;

        const found_owner = accounts_db.getAccount(&program_account.owner) catch
            return error.ProgramAccountNotFound;

        defer found_owner.deinit(accounts_db.allocator);

        const owner: AccountSharedData = .{
            .data = try found_owner.data.readAllAllocate(allocator),
            .executable = found_owner.executable,
            .lamports = found_owner.lamports,
            .owner = found_owner.owner,
            .rent_epoch = found_owner.rent_epoch,
        };

        if ((!owner.owner.equals(&sig.runtime.ids.NATIVE_LOADER_ID) or
            !remove_accounts_executable_flag_checks) and
            !owner.executable)
        {
            return error.InvalidProgramForExecution;
        }

        // Seems we're not supposed to double-count owners, but firedancer and agave seem to both
        // currently double count. Reported bug to FD team, fix is merged: https://github.com/firedancer-io/firedancer/pull/4714
        // https://github.com/firedancer-io/firedancer/blob/f8262f71bc3d78ba3a6e0d89a9825434b93b156f/src/flamenco/runtime/fd_executor.c#L516-L523

        try accumulateAndCheckLoadedAccountDataSize(
            &accumulated_account_size,
            owner.data.len,
            requested_max_total_data_size,
        );
    }

    return retval;
}

fn accumulateAndCheckLoadedAccountDataSize(
    accumulated_loaded_accounts_data_size: *u32,
    account_data_size: usize,
    /// non-zero
    requested_loaded_accounts_data_size_limit: u32,
) error{MaxLoadedAccountsDataSizeExceeded}!void {
    const account_data_sz = std.math.cast(u32, account_data_size) orelse
        return error.MaxLoadedAccountsDataSizeExceeded;

    accumulated_loaded_accounts_data_size.* +|= account_data_sz;

    if (accumulated_loaded_accounts_data_size.* > requested_loaded_accounts_data_size_limit) {
        return error.MaxLoadedAccountsDataSizeExceeded;
    }
}

const BorrowedAccountMeta = struct {
    pubkey: Pubkey,
    is_signer: bool,
    is_writeable: bool,
};
const BorrowedInstruction = struct {
    program_id: Pubkey,
    accounts: []const BorrowedAccountMeta,
    data: []const u8,
};

// [agave] https://github.com/anza-xyz/agave/blob/cb32984a9b0d5c2c6f7775bed39b66d3a22e3c46/svm/src/account_loader.rs#L639
fn constructInstructionsAccount(
    allocator: std.mem.Allocator,
    tx: *const sig.core.Transaction,
) !AccountSharedData {
    var decompiled_instructions = try std.ArrayList(BorrowedInstruction).initCapacity(
        allocator,
        tx.msg.instructions.len,
    );
    errdefer {
        for (decompiled_instructions.items) |decompiled| allocator.free(decompiled.data);
        decompiled_instructions.deinit();
    }

    for (tx.msg.instructions) |instruction| {
        const accounts_meta = try allocator.alloc(
            BorrowedAccountMeta,
            instruction.account_indexes.len,
        );
        errdefer comptime unreachable;

        for (instruction.account_indexes, accounts_meta) |account_idx, *account_meta| {
            account_meta.* = .{
                .pubkey = tx.msg.account_keys[account_idx],
                .is_signer = tx.msg.isSigner(account_idx),
                .is_writeable = tx.msg.isWriteable(account_idx),
            };
        }

        decompiled_instructions.appendAssumeCapacity(.{
            .accounts = accounts_meta,
            .data = instruction.data,
            .program_id = tx.msg.account_keys[instruction.program_index],
        });
    }

    // [agave] solana-instructions-sysvar-2.2.1/src/lib.rs:68
    var data = try serializeInstructions(allocator, decompiled_instructions.items);
    errdefer data.deinit();
    try data.appendSlice(&.{ 0, 0 }); // room for current instruction index

    return .{
        .data = try data.toOwnedSlice(),
        .owner = sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID,
        .lamports = 0, // a bit weird, but seems correct
        .executable = false,
        .rent_epoch = 0,
    };
}

fn isMaybeInLoadedProgramCache(account: Pubkey) bool {
    // const keys = .{
    //     sig.runtime.ids.BPF_LOADER_DEPRECATED_ID,
    //     sig.runtime.ids.BPF_LOADER_ID,
    //     sig.runtime.ids.BPF_LOADER_UPGRADEABLE_ID,
    //     sig.runtime.ids.BPF_LOADER_V4_ID,
    // };
    // for (keys) |key| if (key.equals(owner_key)) return true;
    // return false;

    _ = account;
    @panic("TODO: get account's owner");
}

// [agave] solana-instructions-sysvar-2.2.1/src/lib.rs:77
const InstructionsSysvarAccountMeta = packed struct(u8) {
    is_signer: bool,
    is_writeable: bool,
    _: u6 = 0, // padding
};

// [agave] solana-instructions-sysvar-2.2.1/src/lib.rs:99
// First encode the number of instructions:
// [0..2 - num_instructions
//
// Then a table of offsets of where to find them in the data
//  3..2 * num_instructions table of instruction offsets
//
// Each instruction is then encoded as:
//   0..2 - num_accounts
//   2 - meta_byte -> (bit 0 signer, bit 1 is_writeable)
//   3..35 - pubkey - 32 bytes
//   35..67 - program_id
//   67..69 - data len - u16
//   69..data_len - data
pub fn serializeInstructions(
    allocator: std.mem.Allocator,
    instructions: []const BorrowedInstruction,
) !std.ArrayList(u8) {
    if (instructions.len > std.math.maxInt(u16)) unreachable;

    const asBytes = std.mem.asBytes;
    const nativeToLittle = std.mem.nativeToLittle;

    // estimated required capacity
    var data = try std.ArrayList(u8).initCapacity(allocator, instructions.len * 64);
    errdefer data.deinit();

    try data.appendSlice(asBytes(&nativeToLittle(u16, @intCast(instructions.len))));
    for (0..instructions.len) |_| try data.appendSlice(&.{ 0, 0 });

    for (instructions, 0..) |instruction, i| {
        const start_instruction_offset: u16 = @intCast(data.items.len);
        const start = 2 + (2 * i);
        @memcpy(
            data.items[start .. start + 2],
            asBytes(&nativeToLittle(u16, start_instruction_offset)),
        );
        try data.appendSlice(asBytes(&nativeToLittle(u16, @intCast(instruction.accounts.len))));

        for (instruction.accounts) |account_meta| {
            const flags: InstructionsSysvarAccountMeta = .{
                .is_signer = account_meta.is_signer,
                .is_writeable = account_meta.is_writeable,
            };
            try data.append(@bitCast(flags));
            try data.appendSlice(&account_meta.pubkey.data);
        }

        try data.appendSlice(&instruction.program_id.data);
        try data.appendSlice(asBytes(&nativeToLittle(u16, @intCast(instruction.data.len))));
        try data.appendSlice(instruction.data);
    }

    return data;
}

fn collectRent(account: Pubkey) u64 {
    _ = account;
    return 0; // TODO: rent collection!
}
