const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");
const runtime = sig.runtime;

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const RENT_EXEMPT_RENT_EPOCH = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH;
const CollectedInfo = sig.core.rent_collector.CollectedInfo;
const AccountMeta = sig.core.instruction.InstructionAccount;

const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const AccountSharedData = runtime.AccountSharedData;
const ComputeBudgetLimits = runtime.program.compute_budget.ComputeBudgetLimits;
const LoadedTransactionAccounts = runtime.account_loader.LoadedTransactionAccounts;
const RuntimeTransaction = runtime.transaction_execution.RuntimeTransaction;
const TransactionResult = runtime.transaction_execution.TransactionResult;

// TODO reconsider where these docs belong
/// Implements much of Agave's AccountLoader functionality. Owns the accounts it loads.
/// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L154
/// pubkey -> AccountSharedData for all pubkeys *except* SYSVAR_INSTRUCTIONS_ID, which is a
/// special case (constructed on a per-transaction basis)
pub const AccountMap = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData);

pub fn deinit(self: AccountMap, allocator: Allocator) void {
    for (self.values()) |account| account.deinit(allocator);
    var mut = self;
    mut.deinit(allocator);
}

/// Initializes a new instance with all the accounts needed for all the
/// provided transactions.
pub fn initFromAccountsDb(
    allocator: Allocator,
    account_reader: SlotAccountReader,
    transactions: []const RuntimeTransaction,
) !std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) {
    var self = try initSufficientCapacity(allocator, transactions);
    for (transactions) |tx| {
        try load(&self, allocator, account_reader, &tx.accounts, tx.instructions);
    }
    return self;
}

/// Allocates a sufficiently large account cache to hold every account that
/// may be needed by these transactions.
pub fn initSufficientCapacity(allocator: Allocator, transactions: anytype) !AccountMap {
    const max_map_entries = total_account_keys: {
        var n: usize = 0;
        for (transactions) |tx| n += tx.accounts.len;
        // for getting program owner accounts and ProgramData accounts
        for (transactions) |tx| n += tx.instructions.len * 2;
        break :total_account_keys n;
    };

    // optimisation: we could also keep per-tx indexes to remove reliance on hashmap get
    var map: AccountMap = .{};
    try map.ensureUnusedCapacity(allocator, max_map_entries);

    return map;
}

/// Loads all the accounts needed to process a single transaction.
///
/// Assumes the best, and will not report errors. Error reporting is
/// deferred until accounts are loaded from AccountMap. No rent
/// collection is performed.
pub fn load(
    map: *AccountMap,
    allocator: Allocator,
    account_reader: SlotAccountReader,
    accounts: *const std.MultiArrayList(sig.core.instruction.InstructionAccount),
    instructions: []const sig.runtime.InstructionInfo,
) !void {
    // we assume the largest is allowed
    const max_data_len = sig.runtime.program.compute_budget.MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES;

    var tx_data_loaded: LoadedTransactionAccounts = .DEFAULT;

    { // load txes account_keys
        for (accounts.items(.pubkey)) |account_key| {
            if (account_key.equals(&sig.runtime.sysvar.instruction.ID)) {
                // this code is special, and requires constructing per-transaction accounts,
                // which we will not perform in advance.
                @branchHint(.unlikely);
                continue;
            }

            var created_new_account: bool = false;
            const account = if (map.get(account_key)) |acc| acc else blk: {
                if (try getAccountSharedData(allocator, account_reader, account_key)) |acc| {
                    map.putAssumeCapacityNoClobber(account_key, acc);
                    break :blk acc;
                } else {
                    // account not found, create a new one at this address
                    const account = AccountSharedData.NEW;
                    map.putAssumeCapacityNoClobber(account_key, account);
                    created_new_account = true;
                    break :blk account;
                }
            };

            tx_data_loaded.increase(
                account.data.len,
                max_data_len,
            ) catch break; // tx will fail - loaded too much

            // Special casing to load BPF V3 program accounts.
            if (account.owner.equals(&runtime.program.bpf_loader.v3.ID)) {
                const program_state = sig.bincode.readFromSlice(
                    allocator,
                    runtime.program.bpf_loader.v3.State,
                    account.data,
                    .{},
                ) catch continue;
                defer sig.bincode.free(allocator, program_state);

                if (program_state != .program) continue;
                const program_data_address = program_state.program.programdata_address;

                const program_data_account = try getAccountSharedData(
                    allocator,
                    account_reader,
                    program_data_address,
                ) orelse continue;

                const entry = map.getOrPutAssumeCapacity(program_data_address);
                if (!entry.found_existing) {
                    entry.value_ptr.* = program_data_account;
                } else {
                    allocator.free(program_data_account.data);
                }
            }
        }
    }

    { // load tx instruction's program account + its owner
        var validated_loaders = std.AutoArrayHashMap(Pubkey, void).init(allocator);
        defer validated_loaders.deinit();

        var tx_loaded_account_data_len: LoadedTransactionAccounts = .DEFAULT;

        for (instructions) |instr| {
            const program_key = instr.program_meta.pubkey;

            if (program_key.equals(&runtime.ids.NATIVE_LOADER_ID) or
                program_key.equals(&runtime.sysvar.instruction.ID)) continue;

            const program_account = map.get(program_key) orelse
                unreachable; // safe: we loaded all accounts in the previous loop

            const program_owner_key = program_account.owner;

            if (validated_loaders.contains(program_owner_key))
                continue; // already loaded + counted program account's owner

            // the native loader doesn't have an account to load
            if (program_owner_key.equals(&runtime.ids.NATIVE_LOADER_ID)) continue;

            const owner_account = if (map.get(program_owner_key)) |owner| owner else blk: {
                const owner_account = try getAccountSharedData(
                    allocator,
                    account_reader,
                    program_owner_key,
                ) orelse {
                    // default account ~= account missing
                    // every account which a load is attempted on should have an entry
                    map.putAssumeCapacityNoClobber(program_owner_key, AccountSharedData.NEW);
                    break; // tx will fail - can't get account
                };

                map.putAssumeCapacityNoClobber(program_owner_key, owner_account);

                break :blk owner_account;
            };

            tx_loaded_account_data_len.increase(
                owner_account.data.len,
                max_data_len,
            ) catch break; // tx will fail - accounts data too large

            try validated_loaders.put(program_owner_key, {});
        }
    }
}

fn getAccountSharedData(
    allocator: Allocator,
    reader: SlotAccountReader,
    pubkey: Pubkey,
) error{ OutOfMemory, GetAccountFailedUnexpectedly }!?AccountSharedData {
    const account: sig.core.Account = reader.get(allocator, pubkey) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileIdNotFound,
        error.InvalidOffset,
        error.SlotNotFound,
        => return error.GetAccountFailedUnexpectedly,
    } orelse return null;
    defer account.deinit(allocator);

    // NOTE: Tmp fix since accounts DB should not return accounts with 0 lamports.
    if (account.lamports == 0) return null;

    const shared_account: AccountSharedData = .{
        .data = try account.data.readAllAllocate(allocator),
        .executable = account.executable,
        .lamports = account.lamports,
        .owner = account.owner,
        .rent_epoch = account.rent_epoch,
    };

    return shared_account;
}
