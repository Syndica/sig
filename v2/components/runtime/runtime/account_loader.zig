//! Implements much of Agave's AccountLoader functionality.
//! [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L154
const std = @import("std");
const std14 = @import("std14");
const sig = @import("../component.zig");
const tracy = @import("tracy");
const runtime = sig.runtime;

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const RENT_EXEMPT_RENT_EPOCH = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH;
const CollectedInfo = sig.core.rent_collector.CollectedInfo;
const AccountMeta = sig.core.instruction.InstructionAccount;

const AccountReader = runtime.execution_interfaces.AccountReader;
const AccountSharedData = runtime.AccountSharedData;
const ComputeBudgetLimits = runtime.program.compute_budget.ComputeBudgetLimits;
const RuntimeTransaction = runtime.transaction_execution.RuntimeTransaction;
const TransactionResult = runtime.transaction_execution.TransactionResult;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/ddde57c40c4d4334c25bb32de17f833d4d79a889/src/ballet/txn/fd_txn.h#L116
pub const MAX_TX_ACCOUNT_LOCKS = 128;

// [agave] https://github.com/anza-xyz/agave/blob/7b0e13bc6fb4bfd84eb3cd0ace4bd86a451f1913/svm/src/account_loader.rs#L43
/// Storage cost of the transaction account metadata.
pub const TRANSACTION_ACCOUNT_BASE_SIZE = 64;
// [agave] https://github.com/anza-xyz/agave/blob/7b0e13bc6fb4bfd84eb3cd0ace4bd86a451f1913/svm/src/account_loader.rs#L47
/// Per SIMD-0186, resolved address lookup tables are assigned a base size of 8248
/// bytes: 8192 bytes for the maximum table size plus 56 bytes for metadata.
pub const ADDRESS_LOOKUP_TABLE_BASE_SIZE = 8248;

pub const RentDebit = struct { rent_collected: u64, rent_balance: u64 };

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L417
/// agave's LoadedTransactionAccounts contains a field "program indices". This has been omitted as
/// it's a Vec<Vec<u8>> whose elements are either [program_id] or [] (when program_id is the native
/// loader), which seems pointless.
pub const LoadedTransactionAccounts = struct {
    /// data owned by AccountMap
    accounts: Accounts,
    /// equal len to .accounts
    rent_debits: std14.BoundedArray(RentDebit, MAX_TX_ACCOUNT_LOCKS),

    rent_collected: u64,
    loaded_accounts_data_size: u32,

    pub const Accounts = std14.BoundedArray(LoadedAccount, MAX_TX_ACCOUNT_LOCKS);

    pub const DEFAULT: LoadedTransactionAccounts = .{
        .accounts = .{},
        .rent_debits = .{},
        .rent_collected = 0,
        .loaded_accounts_data_size = 0,
    };

    pub fn deinit(self: *const LoadedTransactionAccounts, allocator: Allocator) void {
        for (self.accounts.slice()) |account| account.deinit(allocator);
    }

    // [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L618
    pub fn increase(
        self: *LoadedTransactionAccounts,
        account_data_size: usize,
        /// non-zero
        requested_loaded_accounts_data_size_limit: u32,
    ) error{MaxLoadedAccountsDataSizeExceeded}!void {
        // On u32 overflow, saturate the tally so a downstream clamp to the
        // requested limit yields the limit, matching Agave.
        const account_data_sz = std.math.cast(u32, account_data_size) orelse {
            self.loaded_accounts_data_size = std.math.maxInt(u32);
            return error.MaxLoadedAccountsDataSizeExceeded;
        };

        self.loaded_accounts_data_size +|= account_data_sz;

        if (self.loaded_accounts_data_size > requested_loaded_accounts_data_size_limit) {
            return error.MaxLoadedAccountsDataSizeExceeded;
        }
    }
};

// An account that was loaded to execute a transaction. The data slice is owned.
pub const LoadedAccount = struct {
    pubkey: Pubkey,
    account: AccountSharedData,

    pub fn deinit(self: LoadedAccount, allocator: Allocator) void {
        self.account.deinit(allocator);
    }
};

/// An account loaded and prepared for transaction execution, with its
/// contribution to the loaded data size and any rent that was collected.
pub const PreparedAccount = struct {
    account: AccountSharedData,
    loaded_size: usize,
    rent_collected: u64,
};

pub const AccountLoadError = runtime.execution_interfaces.AccountLoadError;

/// Loads all the accounts for a transaction and reports account loading errors.
///
/// On failure, `running_data_size_out` is set to the partial loaded data size
/// at the point of failure (un-clamped); callers should clamp it to the
/// requested limit. Used by `define_ltds_fee_only_semantics` (SIMD-186
/// amendment) to report `loaded_accounts_data_size` for fees-only transactions.
pub fn loadTransactionAccounts(
    account_reader: AccountReader,
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
    rent_collector: *const RentCollector,
    compute_budget_limits: *const ComputeBudgetLimits,
    fee_payer: PreparedAccount,
    running_data_size_out: *u32,
) AccountLoadError!TransactionResult(LoadedTransactionAccounts) {
    var zone = tracy.Zone.init(@src(), .{ .name = "loadTransactionAccounts" });
    defer zone.deinit();

    // [agave] https://github.com/anza-xyz/agave/commit/d5757e29aa - formalize_loaded_transaction_data_size hardcoded
    const result = loadTransactionAccountsInner(
        account_reader,
        allocator,
        transaction,
        rent_collector,
        compute_budget_limits,
        fee_payer,
        running_data_size_out,
    );

    return .{
        .ok = result catch |err| return switch (err) {
            error.ProgramAccountNotFound => .{ .err = .ProgramAccountNotFound },
            error.InvalidProgramForExecution => .{ .err = .InvalidProgramForExecution },
            error.MaxLoadedAccountsDataSizeExceeded => .{
                .err = .MaxLoadedAccountsDataSizeExceeded,
            },
            error.OutOfMemory => return error.OutOfMemory,
            error.AccountsDBError => return error.AccountsDBError,
        },
    };
}

const InternalLoadError = AccountLoadError || error{
    ProgramAccountNotFound,
    InvalidProgramForExecution,
    MaxLoadedAccountsDataSizeExceeded,
};

fn loadTransactionAccountsInner(
    account_reader: AccountReader,
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
    rent_collector: *const RentCollector,
    compute_budget_limits: *const ComputeBudgetLimits,
    fee_payer: PreparedAccount,
    running_data_size_out: *u32,
) InternalLoadError!LoadedTransactionAccounts {
    var fee_payer_consumed = false;
    errdefer if (!fee_payer_consumed) fee_payer.account.deinit(allocator);

    std.debug.assert(compute_budget_limits.loaded_accounts_bytes != 0);

    var loaded = LoadedTransactionAccounts.DEFAULT;
    errdefer {
        for (loaded.accounts.slice()) |account| account.deinit(allocator);
        // Expose the partial tally to the fees-only path on error.
        running_data_size_out.* = loaded.loaded_accounts_data_size;
    }

    try loaded.increase(
        transaction.num_lookup_tables *| ADDRESS_LOOKUP_TABLE_BASE_SIZE,
        compute_budget_limits.loaded_accounts_bytes,
    );

    var additional_loaded_accounts: std.AutoHashMapUnmanaged(Pubkey, void) = .{};
    defer additional_loaded_accounts.deinit(allocator);
    try additional_loaded_accounts.ensureUnusedCapacity(allocator, MAX_TX_ACCOUNT_LOCKS);

    const accounts = transaction.accounts.slice();
    for (accounts.items(.pubkey), 0..) |account_key, i| {
        const prepared = if (i == 0) fee_payer else try loadTransactionAccount(
            account_reader,
            allocator,
            transaction,
            rent_collector,
            &account_key,
        );
        fee_payer_consumed = true;
        errdefer prepared.account.deinit(allocator);

        try loaded.increase(
            prepared.loaded_size,
            compute_budget_limits.loaded_accounts_bytes,
        );
        loaded.rent_collected +|= prepared.rent_collected;
        if (prepared.rent_collected != 0) {
            loaded.rent_debits.appendAssumeCapacity(.{
                .rent_balance = prepared.account.lamports,
                .rent_collected = prepared.rent_collected,
            });
        }

        // [agave] https://github.com/anza-xyz/agave/blob/7b0e13bc6fb4bfd84eb3cd0ace4bd86a451f1913/svm/src/account_loader.rs#L611-L635

        const owner = &prepared.account.owner;
        cont: {
            // If this is a LoaderV3 program...
            if (owner.equals(&runtime.program.bpf_loader.v3.ID)) {
                const account_data = prepared.account.data;
                const program_state = sig.bincode.readFromSlice(
                    allocator,
                    runtime.program.bpf_loader.v3.State,
                    account_data,
                    .{},
                ) catch break :cont;
                const programdata_address: Pubkey = switch (program_state) {
                    .program => |p| p.programdata_address,
                    else => break :cont,
                };
                // ...its programdata was not already counted and will not later be counted...
                for (accounts.items(.pubkey)) |key| {
                    if (programdata_address.equals(&key)) break :cont;
                }
                if (additional_loaded_accounts.contains(programdata_address)) break :cont;
                // ...and the programdata account exists (if it doesn't, it is *not* a load failure)...
                if (try account_reader.get(allocator, programdata_address)) |programdata_account| {
                    defer programdata_account.deinit(allocator);
                    // ...count programdata toward this transaction's total size.
                    try loaded.increase(
                        TRANSACTION_ACCOUNT_BASE_SIZE +| programdata_account.data.len,
                        compute_budget_limits.loaded_accounts_bytes,
                    );
                    additional_loaded_accounts.putAssumeCapacity(programdata_address, {});
                }
            }
        }

        loaded.accounts.appendAssumeCapacity(.{
            .account = prepared.account,
            .pubkey = account_key,
        });
    }

    for (transaction.instructions) |instr| {
        const program_id = &instr.program_meta.pubkey;
        const program_account = try loadAccount(
            account_reader,
            allocator,
            transaction,
            program_id,
        ) orelse return error.ProgramAccountNotFound;
        defer program_account.account.deinit(allocator);

        const owner_id = &program_account.account.owner;
        if (!owner_id.equals(&runtime.ids.NATIVE_LOADER_ID)) {
            for ([_]Pubkey{
                runtime.program.bpf_loader.v1.ID,
                runtime.program.bpf_loader.v2.ID,
                runtime.program.bpf_loader.v3.ID,
                runtime.program.bpf_loader.v4.ID,
            }) |id| {
                if (owner_id.equals(&id)) break; // found it
            } else {
                return error.InvalidProgramForExecution;
            }
        }
    }

    return loaded;
}

fn loadTransactionAccount(
    account_reader: AccountReader,
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
    rent_collector: *const RentCollector,
    key: *const Pubkey,
) InternalLoadError!PreparedAccount {
    if (key.equals(&runtime.sysvar.instruction.ID)) {
        @branchHint(.unlikely);
        return .{
            .account = try constructInstructionsAccount(allocator, transaction),
            .loaded_size = 0,
            .rent_collected = 0,
        };
    }

    var account = try loadAccount(
        account_reader,
        allocator,
        transaction,
        key,
    ) orelse {
        // a previous instruction deallocated this account, we will make a new one in its place.
        var account = AccountSharedData.EMPTY;
        account.rent_epoch = RENT_EXEMPT_RENT_EPOCH;

        return .{
            .account = account,
            .loaded_size = 0,
            .rent_collected = 0,
        };
    };
    errdefer account.account.deinit(allocator);

    const rent_collected = collectRentFromAccount(
        &account.account,
        rent_collector,
    );

    return .{
        .account = account.account,
        .loaded_size = account.loaded_size,
        .rent_collected = rent_collected.rent_amount,
    };
}

/// null return => account is now dead
fn loadAccount(
    account_reader: AccountReader,
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
    key: *const Pubkey,
) InternalLoadError!?struct {
    account: AccountSharedData,
    loaded_size: usize,
    rent_collected: u64,
} {
    const account: AccountSharedData = if (key.equals(&runtime.sysvar.instruction.ID)) account: {
        @branchHint(.unlikely);
        break :account try constructInstructionsAccount(allocator, transaction);
    } else try account_reader.get(allocator, key.*) orelse return null;

    if (account.lamports == 0) {
        account.deinit(allocator);
        return null;
    }

    return .{
        .account = account,
        .loaded_size = TRANSACTION_ACCOUNT_BASE_SIZE +| account.data.len,
        .rent_collected = 0,
    };
}

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L293
pub fn collectRentFromAccount(
    account: *AccountSharedData,
    rent_collector: *const RentCollector,
) CollectedInfo {
    if (account.rent_epoch != RENT_EXEMPT_RENT_EPOCH and
        rent_collector.getRentDue(
            account.lamports,
            account.data.len,
            account.rent_epoch,
        ) == .Exempt)
    {
        account.rent_epoch = RENT_EXEMPT_RENT_EPOCH;
    }

    return CollectedInfo.NoneCollected;
}

// [agave] https://github.com/anza-xyz/agave/blob/996570bcbe7acc4dfd0a6931d024a11a3b4de7a3/svm/src/account_loader.rs#L784
fn constructInstructionsAccount(
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
) error{OutOfMemory}!AccountSharedData {
    const Instruction = sig.core.Instruction;
    const InstructionAccount = sig.core.instruction.InstructionAccount;

    var decompiled_instructions = try std.array_list.Managed(Instruction).initCapacity(
        allocator,
        transaction.instructions.len,
    );
    defer {
        for (decompiled_instructions.items) |decompiled| allocator.free(decompiled.accounts);
        decompiled_instructions.deinit();
    }

    const tx_accounts = transaction.accounts.slice();

    for (transaction.instructions) |instruction| {
        const accounts_meta = try allocator.alloc(
            InstructionAccount,
            instruction.account_metas.items.len,
        );
        errdefer allocator.free(accounts_meta);

        for (instruction.account_metas.items, accounts_meta) |account_meta, *new_account_meta| {
            new_account_meta.* = .{
                .pubkey = tx_accounts.items(.pubkey)[account_meta.index_in_transaction],
                .is_signer = tx_accounts.items(.is_signer)[account_meta.index_in_transaction],
                .is_writable = tx_accounts.items(.is_writable)[account_meta.index_in_transaction],
            };
        }

        decompiled_instructions.appendAssumeCapacity(.{
            .accounts = accounts_meta,
            .data = instruction.instruction_data,
            .owned_data = false,
            .program_id = tx_accounts.items(.pubkey)[instruction.program_meta.index_in_transaction],
        });
    }

    // [agave] https://github.com/anza-xyz/solana-sdk/blob/0fbfb7d1467c1ab0c35e1a3b905b8ba0ac0bf538/instructions-sysvar/src/lib.rs#L68
    var data = try runtime.sysvar.instruction.serializeInstructions(
        allocator,
        decompiled_instructions.items,
    );
    defer data.deinit();
    try data.appendSlice(&.{ 0, 0 }); // room for current instruction index

    return .{
        .data = try data.toOwnedSlice(),
        .owner = runtime.sysvar.OWNER_ID,
        .lamports = 0, // a bit weird, but seems correct
        .executable = false,
        .rent_epoch = 0,
    };
}

const TestingEnv = struct {
    rent_collector: RentCollector,
    compute_budget_limits: ComputeBudgetLimits,
};

fn newTestingEnv() TestingEnv {
    if (!@import("builtin").is_test) @compileError("newTestingEnv for testing only");
    return .{
        .rent_collector = sig.core.rent_collector.defaultCollector(0),
        .compute_budget_limits = ComputeBudgetLimits{
            .heap_size = 0,
            .compute_unit_limit = 0,
            .compute_unit_price = 0,
            .loaded_accounts_bytes = 1_000,
        },
    };
}

fn emptyTxWithKeys(allocator: Allocator, keys: []const Pubkey) !RuntimeTransaction {
    if (!@import("builtin").is_test) @compileError("transactionWithKeys for testing only");

    var accounts = std.MultiArrayList(AccountMeta).empty;
    errdefer accounts.deinit(allocator);
    for (keys) |key| {
        try accounts.append(allocator, .{
            .pubkey = key,
            .is_signer = false,
            .is_writable = false,
        });
    }

    return .{
        .signature_count = 0,
        .fee_payer = Pubkey.ZEROES,
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = Hash.ZEROES,
        .instructions = &.{},
        .accounts = accounts,
        .num_lookup_tables = 0,
        .num_static_account_keys = @intCast(keys.len),
        .is_simple_vote_transaction = false,
    };
}

test "loadTransactionAccounts empty transaction" {
    const allocator = std.testing.allocator;
    const accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    const env = newTestingEnv();

    const empty_tx = RuntimeTransaction{
        .fee_payer = Pubkey.ZEROES,
        .instructions = &.{},
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = Hash.ZEROES,
        .signature_count = 0,
        .num_lookup_tables = 0,
        .num_static_account_keys = 0,
        .is_simple_vote_transaction = false,
    };

    var running_data_size: u32 = 0;
    const tx_accounts = try loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &empty_tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{ .account = AccountSharedData.EMPTY, .loaded_size = 0, .rent_collected = 0 },
        &running_data_size,
    );

    try std.testing.expectEqual(0, tx_accounts.accounts.len);
    // Success path leaves `running_data_size_out` untouched.
    try std.testing.expectEqual(0, running_data_size);
}

test "loadTransactionAccounts sysvar instruction" {
    const allocator = std.testing.allocator;
    var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    const env = newTestingEnv();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const fee_payer_address = Pubkey.initRandom(prng.random());

    var accounts = std.MultiArrayList(AccountMeta).empty;
    defer accounts.deinit(allocator);
    try accounts.append(allocator, sig.core.instruction.InstructionAccount{
        .pubkey = fee_payer_address,
        .is_signer = true,
        .is_writable = true,
    });
    try accounts.append(allocator, sig.core.instruction.InstructionAccount{
        .pubkey = runtime.sysvar.instruction.ID,
        .is_signer = false,
        .is_writable = false,
    });

    const tx = RuntimeTransaction{
        .fee_payer = fee_payer_address,
        .instructions = &.{},
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = Hash.ZEROES,
        .signature_count = 0,
        .accounts = accounts,
        .num_lookup_tables = 0,
        .num_static_account_keys = @intCast(accounts.len),
        .is_simple_vote_transaction = false,
    };

    var running_data_size: u32 = 0;
    const tx_accounts = try loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{ .account = AccountSharedData.EMPTY, .loaded_size = 0, .rent_collected = 0 },
        &running_data_size,
    );
    defer tx_accounts.deinit(allocator);

    try std.testing.expectEqual(2, tx_accounts.accounts.len);
    const sysvar_account = tx_accounts.accounts.slice()[1];

    try std.testing.expect(sysvar_account.account.data.len > 0);
    try std.testing.expectEqual(0, tx_accounts.rent_collected);
    try std.testing.expectEqual(0, tx_accounts.loaded_accounts_data_size);
    try std.testing.expectEqual(0, tx_accounts.rent_debits.len);
    // Success path leaves `running_data_size_out` untouched.
    try std.testing.expectEqual(0, running_data_size);
}

test "accumulated size" {
    var loaded = LoadedTransactionAccounts.DEFAULT;

    const requested_data_size_limit = 123;

    try loaded.increase(
        requested_data_size_limit,
        requested_data_size_limit,
    );

    try std.testing.expectEqual(requested_data_size_limit, loaded.loaded_accounts_data_size);

    // exceed limit
    try std.testing.expectError(
        error.MaxLoadedAccountsDataSizeExceeded,
        loaded.increase(
            1,
            requested_data_size_limit,
        ),
    );
}

test "load accounts rent paid" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    defer accountsdb.deinit(allocator);
    var env = newTestingEnv();
    env.compute_budget_limits.loaded_accounts_bytes = 2_000;

    const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

    const fee_payer_address = Pubkey.initRandom(prng.random());
    const instruction_address = Pubkey.initRandom(prng.random());

    var instruction_data = "dummy instruction".*;

    const fee_payer_balance = 300;

    const data = try allocator.alloc(u8, 1024);
    prng.fill(data);

    var fee_payer_account = AccountSharedData{
        .data = data,
        .lamports = fee_payer_balance,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    };
    _ = collectRentFromAccount(
        &fee_payer_account,
        &env.rent_collector,
    );

    try accountsdb.put(allocator, fee_payer_address, .{
        .data = data,
        .lamports = fee_payer_balance,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    try accountsdb.put(allocator, instruction_address, .{
        .data = &instruction_data,
        .lamports = 1,
        .executable = true,
        .owner = NATIVE_LOADER_ID,
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, NATIVE_LOADER_ID, .{
        .data = &.{},
        .lamports = 1,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, Pubkey.ZEROES, .{
        .data = &.{},
        .lamports = 0,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    var tx = try emptyTxWithKeys(allocator, &.{ fee_payer_address, instruction_address });
    defer tx.accounts.deinit(allocator);

    var metas: sig.runtime.InstructionInfo.AccountMetas = .empty;
    defer metas.deinit(allocator);
    try metas.appendSlice(
        allocator,
        &.{
            .{
                .pubkey = fee_payer_address,
                .index_in_transaction = 0,
                .is_signer = true,
                .is_writable = true,
            },
            .{
                .pubkey = instruction_address,
                .index_in_transaction = 1,
                .is_signer = false,
                .is_writable = false,
            },
        },
    );

    tx.instructions = &.{
        .{
            .program_meta = .{ .pubkey = instruction_address, .index_in_transaction = 1 },
            .account_metas = metas,
            .dedupe_map = blk: {
                var dedupe_map: [sig.runtime.InstructionInfo.MAX_ACCOUNT_METAS]u16 = @splat(0xffff);
                dedupe_map[0] = 0;
                dedupe_map[1] = 1;
                break :blk dedupe_map;
            },
            .instruction_data = "",
            .owned_instruction_data = false,
        },
    };

    var running_data_size: u32 = 0;
    const loaded_accounts = try loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{
            .account = fee_payer_account,
            .loaded_size = fee_payer_account.data.len,
            .rent_collected = 0,
        },
        &running_data_size,
    );
    defer loaded_accounts.deinit(allocator);

    try std.testing.expectEqual(2, loaded_accounts.accounts.len);
    // The fee payer's rent was already collected before being passed to loadTransactionAccounts,
    // so only the instruction account's rent is counted here (which is 0 because it's executable).
    try std.testing.expectEqual(0, loaded_accounts.rent_collected);
    // Success path leaves `running_data_size_out` untouched.
    try std.testing.expectEqual(0, running_data_size);
}

test "load accounts with simd 186 and loaderv3 program" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    defer accountsdb.deinit(allocator);
    var env = newTestingEnv();
    env.compute_budget_limits.loaded_accounts_bytes = 20_000;

    const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

    const fee_payer_address = Pubkey.initRandom(prng.random());
    const instruction_address = Pubkey.initRandom(prng.random());
    const program_address = Pubkey.initRandom(prng.random());
    const programdata_address = Pubkey.initRandom(prng.random());

    var instruction_data = "dummy instruction".*;

    const fee_payer_balance = 300;

    const data = try allocator.alloc(u8, 1024);
    prng.fill(data);

    const fee_payer_account = AccountSharedData{
        .data = data,
        .lamports = fee_payer_balance,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    };

    const program_state: runtime.program.bpf_loader.v3.State = .{
        .program = .{ .programdata_address = programdata_address },
    };
    var program_data_buffer: [1024]u8 = undefined;
    const program_data = try sig.bincode.writeToSlice(
        &program_data_buffer,
        program_state,
        .{},
    );

    try accountsdb.put(allocator, fee_payer_address, .{
        .data = data,
        .lamports = fee_payer_balance,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, program_address, .{
        .data = program_data,
        .lamports = 1,
        .executable = true,
        .owner = runtime.program.bpf_loader.v3.ID,
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, programdata_address, .{
        .data = data,
        .lamports = 1,
        .executable = true,
        .owner = Pubkey.ZEROES, // doesn't matter
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, instruction_address, .{
        .data = &instruction_data,
        .lamports = 1,
        .executable = true,
        .owner = NATIVE_LOADER_ID,
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, NATIVE_LOADER_ID, .{
        .data = &.{},
        .lamports = 1,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, Pubkey.ZEROES, .{
        .data = &.{},
        .lamports = 0,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    var tx = try emptyTxWithKeys(allocator, &.{
        fee_payer_address,
        instruction_address,
        program_address,
    });
    defer tx.accounts.deinit(allocator);

    var meta: sig.runtime.InstructionInfo.AccountMetas = .empty;
    defer meta.deinit(allocator);
    try meta.appendSlice(
        allocator,
        &.{
            .{
                .pubkey = fee_payer_address,
                .index_in_transaction = 0,
                .is_signer = true,
                .is_writable = true,
            },
            .{
                .pubkey = instruction_address,
                .index_in_transaction = 1,
                .is_signer = false,
                .is_writable = false,
            },
            .{
                .pubkey = program_address,
                .index_in_transaction = 2,
                .is_signer = false,
                .is_writable = false,
            },
        },
    );

    tx.instructions = &.{
        .{
            .program_meta = .{ .pubkey = instruction_address, .index_in_transaction = 1 },
            .account_metas = meta,
            .dedupe_map = blk: {
                var dedupe_map: [sig.runtime.InstructionInfo.MAX_ACCOUNT_METAS]u16 = @splat(0xffff);
                dedupe_map[0] = 0;
                dedupe_map[1] = 1;
                dedupe_map[2] = 2;
                break :blk dedupe_map;
            },
            .instruction_data = "",
            .owned_instruction_data = false,
        },
    };

    var running_data_size: u32 = 0;
    const fee_payer_loaded_size = TRANSACTION_ACCOUNT_BASE_SIZE +| fee_payer_account.data.len;
    const loaded_accounts = try loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{
            .account = fee_payer_account,
            .loaded_size = fee_payer_loaded_size,
            .rent_collected = 0,
        },
        &running_data_size,
    );
    defer loaded_accounts.deinit(allocator);

    // fee payer: 64 + 1024 (passed directly), instruction: 64 + 17, program: 64 + bincode(State), programdata: 64 + 1024
    try std.testing.expectEqual(2357, loaded_accounts.loaded_accounts_data_size);
    // Success path leaves `running_data_size_out` untouched.
    try std.testing.expectEqual(0, running_data_size);
}

test "constructInstructionsAccount" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var data: [1024]u8 = undefined;
    prng.fill(&data);

    const fee_payer_address = Pubkey.initRandom(prng.random());
    const instruction_address = Pubkey.initRandom(prng.random());

    var accounts = std.MultiArrayList(AccountMeta).empty;
    defer accounts.deinit(allocator);
    try accounts.append(allocator, sig.core.instruction.InstructionAccount{
        .pubkey = fee_payer_address,
        .is_signer = true,
        .is_writable = true,
    });
    try accounts.append(allocator, sig.core.instruction.InstructionAccount{
        .pubkey = instruction_address,
        .is_signer = false,
        .is_writable = false,
    });

    const empty_tx = RuntimeTransaction{
        .fee_payer = Pubkey.ZEROES,
        .instructions = &.{
            .{
                .program_meta = .{ .pubkey = instruction_address, .index_in_transaction = 1 },
                .account_metas = .{},
                .dedupe_map = @splat(0xffff),
                .instruction_data = "",
                .owned_instruction_data = false,
                .initial_account_lamports = 0,
            },
        },
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = Hash.ZEROES,
        .signature_count = 1,
        .accounts = accounts,
        .num_lookup_tables = 0,
        .num_static_account_keys = @intCast(accounts.len),
        .is_simple_vote_transaction = false,
    };

    const checkFn = struct {
        fn f(alloc: Allocator, txn: *const RuntimeTransaction) !void {
            const account = try constructInstructionsAccount(alloc, txn);
            defer account.deinit(alloc);
        }
    }.f;

    try std.testing.checkAllAllocationFailures(allocator, checkFn, .{&empty_tx});

    const account = try constructInstructionsAccount(allocator, &empty_tx);
    defer account.deinit(allocator);
    try std.testing.expectEqual(0, account.lamports);
    try std.testing.expect(account.data.len > 8);
}

test "loadAccount allocations" {
    const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

    const helper = struct {
        fn check(allocator: Allocator) !void {
            var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
            defer accountsdb.deinit(allocator);

            try accountsdb.put(allocator, NATIVE_LOADER_ID, .{
                .data = &.{},
                .lamports = 1,
                .executable = true,
                .owner = Pubkey.ZEROES,
                .rent_epoch = 0,
            });

            var tx = try emptyTxWithKeys(allocator, &.{NATIVE_LOADER_ID});
            defer tx.accounts.deinit(allocator);

            const account = try loadAccount(
                AccountReader.fromMap(&accountsdb),
                allocator,
                &tx,
                &NATIVE_LOADER_ID,
            ) orelse @panic("account not found");

            try std.testing.expectEqual(1, account.account.lamports);
            try std.testing.expectEqual(true, account.account.executable);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, helper.check, .{});
}

test "load tx too large" {
    const allocator = std.testing.allocator;
    var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    defer accountsdb.deinit(allocator);
    var env = newTestingEnv();
    env.compute_budget_limits.loaded_accounts_bytes = 1000;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const address = Pubkey.initRandom(random);

    // large account
    const account_data = try allocator.alloc(u8, 10 * 1024 * 1024);

    const fee_payer_account = AccountSharedData{
        .data = account_data,
        .lamports = 1_000_000,
        .executable = false,
        .owner = sig.runtime.program.system.ID,
        .rent_epoch = RENT_EXEMPT_RENT_EPOCH,
    };

    var tx = try emptyTxWithKeys(allocator, &.{address});
    defer tx.accounts.deinit(allocator);

    var running_data_size: u32 = 0;
    const fee_payer_loaded_size = TRANSACTION_ACCOUNT_BASE_SIZE +| fee_payer_account.data.len;
    const loaded_accounts_result = loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{
            .account = fee_payer_account,
            .loaded_size = fee_payer_loaded_size,
            .rent_collected = 0,
        },
        &running_data_size,
    );

    try std.testing.expectError(error.MaxLoadedAccountsDataSizeExceeded, loaded_accounts_result);
    // On `MaxLoadedAccountsDataSizeExceeded`, the partial tally exposed via
    // `running_data_size_out` reflects the cumulative loaded size including
    // the offending account (the fee payer here). Consumed by the
    // `define_ltds_fee_only_semantics` branch.
    try std.testing.expectEqual(fee_payer_loaded_size, running_data_size);
}

test "dont double count programdata size" {
    // Two LoaderV3 programs sharing the same programdata address should only count
    // the programdata once. This tests the `additional_loaded_accounts` deduplication
    // in loadTransactionAccountsInner.
    const allocator = std.testing.allocator;
    var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    defer accountsdb.deinit(allocator);
    var env = newTestingEnv();
    env.compute_budget_limits.loaded_accounts_bytes = 20_000;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const fee_payer_address = Pubkey.initRandom(random);
    const pk1 = Pubkey.initRandom(random);
    const pk2 = Pubkey.initRandom(random);
    const shared_programdata = Pubkey.initRandom(random);

    // Both programs point to the same programdata address
    const program_state: runtime.program.bpf_loader.v3.State = .{
        .program = .{ .programdata_address = shared_programdata },
    };
    var program_data_buffer: [1024]u8 = undefined;
    const program_data = try sig.bincode.writeToSlice(
        &program_data_buffer,
        program_state,
        .{},
    );

    var programdata_data = "shared programdata!".*;

    try accountsdb.put(allocator, pk1, .{
        .data = program_data,
        .lamports = 1,
        .executable = true,
        .owner = runtime.program.bpf_loader.v3.ID,
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, pk2, .{
        .data = program_data,
        .lamports = 1,
        .executable = true,
        .owner = runtime.program.bpf_loader.v3.ID,
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, shared_programdata, .{
        .data = &programdata_data,
        .lamports = 1,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    // Transaction with fee payer + both programs as account keys and instruction targets
    var tx: RuntimeTransaction = blk: {
        var tx = try emptyTxWithKeys(allocator, &.{ fee_payer_address, pk1, pk2 });

        tx.instructions = &.{
            .{
                .program_meta = .{ .pubkey = pk2, .index_in_transaction = 2 },
                .account_metas = .empty,
                .dedupe_map = @splat(0xffff),
                .instruction_data = "",
                .owned_instruction_data = false,
            },
            .{
                .program_meta = .{ .pubkey = pk1, .index_in_transaction = 1 },
                .account_metas = .empty,
                .dedupe_map = @splat(0xffff),
                .instruction_data = "",
                .owned_instruction_data = false,
            },
        };
        break :blk tx;
    };
    defer tx.accounts.deinit(allocator);

    var running_data_size: u32 = 0;
    const loaded_accounts = try loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{ .account = AccountSharedData.EMPTY, .loaded_size = 0, .rent_collected = 0 },
        &running_data_size,
    );
    defer loaded_accounts.deinit(allocator);

    // fee payer: 0 (empty), pk1: 64 + bincode(State), pk2: 64 + bincode(State),
    // shared programdata counted ONCE: 64 + 19
    const program_account_size: u32 = @intCast(TRANSACTION_ACCOUNT_BASE_SIZE + program_data.len);
    const programdata_size: u32 = @intCast(TRANSACTION_ACCOUNT_BASE_SIZE + programdata_data.len);
    try std.testing.expectEqual(
        program_account_size + program_account_size + programdata_size,
        loaded_accounts.loaded_accounts_data_size,
    );
}

test "load, create new account" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const new_account_pk = Pubkey.initRandom(random);
    var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    defer accountsdb.deinit(allocator);
    const env = newTestingEnv();

    var tx = try emptyTxWithKeys(allocator, &.{new_account_pk});
    defer tx.accounts.deinit(allocator);

    var running_data_size: u32 = 0;
    const loaded_accounts = try loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{ .account = AccountSharedData.EMPTY, .loaded_size = 0, .rent_collected = 0 },
        &running_data_size,
    );
    defer loaded_accounts.deinit(allocator);

    try std.testing.expectEqual(1, loaded_accounts.accounts.len);
    try std.testing.expectEqual(0, loaded_accounts.rent_collected);
    try std.testing.expectEqual(0, loaded_accounts.accounts.slice()[0].account.lamports);
    // Success path leaves `running_data_size_out` untouched.
    try std.testing.expectEqual(0, running_data_size);
}

test "invalid program owner" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    defer accountsdb.deinit(allocator);
    const env = newTestingEnv();

    const instruction_address = Pubkey.initRandom(random);
    const invalid_owner = Pubkey.initRandom(random);

    try accountsdb.put(allocator, instruction_address, .{
        .data = &.{},
        .lamports = 1,
        .executable = true,
        .owner = invalid_owner,
        .rent_epoch = 0,
    });

    var tx = try emptyTxWithKeys(allocator, &.{instruction_address});
    defer tx.accounts.deinit(allocator);
    tx.instructions = &.{
        .{
            .program_meta = .{ .pubkey = instruction_address, .index_in_transaction = 0 },
            .account_metas = .empty,
            .dedupe_map = @splat(0xffff),
            .instruction_data = "",
            .owned_instruction_data = false,
        },
    };

    var running_data_size: u32 = 0;
    const loaded_accounts_result = loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{ .account = AccountSharedData.EMPTY, .loaded_size = 0, .rent_collected = 0 },
        &running_data_size,
    );

    try std.testing.expectError(error.InvalidProgramForExecution, loaded_accounts_result);
    // Fee payer is EMPTY (loaded_size=0) and the failure happens before any
    // other account contributes to the tally.
    try std.testing.expectEqual(0, running_data_size);
}

test "missing program account" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    const env = newTestingEnv();

    const instruction_address = Pubkey.initRandom(random);

    var tx = try emptyTxWithKeys(allocator, &.{instruction_address});
    defer tx.accounts.deinit(allocator);
    tx.instructions = &.{
        .{
            .program_meta = .{ .pubkey = instruction_address, .index_in_transaction = 0 },
            .account_metas = .empty,
            .dedupe_map = @splat(0xffff),
            .instruction_data = "",
            .owned_instruction_data = false,
        },
    };

    var running_data_size: u32 = 0;
    const loaded_accounts_result = loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{ .account = AccountSharedData.EMPTY, .loaded_size = 0, .rent_collected = 0 },
        &running_data_size,
    );

    try std.testing.expectError(error.ProgramAccountNotFound, loaded_accounts_result);
    // Fee payer is EMPTY (loaded_size=0) and the failure happens before any
    // other account contributes to the tally.
    try std.testing.expectEqual(0, running_data_size);
}

test "deallocate account" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    defer accountsdb.deinit(allocator);
    const env = newTestingEnv();

    const dying_account = Pubkey.initRandom(random);

    var dying_account_data = "this account will soon die, and so will this string".*;

    try accountsdb.put(allocator, dying_account, .{
        .data = &dying_account_data,
        .lamports = 100,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    var tx = try emptyTxWithKeys(allocator, &.{dying_account});
    defer tx.accounts.deinit(allocator);

    // load with the account being alive

    try std.testing.expect(accountsdb.get(dying_account).?.data.len > 0);

    // "previous transaction" makes the account dead
    accountsdb.getPtr(dying_account).?.lamports = 0;

    // load with the account being dead
    var running_data_size: u32 = 0;
    const loaded_accounts = try loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{ .account = AccountSharedData.EMPTY, .loaded_size = 0, .rent_collected = 0 },
        &running_data_size,
    );
    defer loaded_accounts.deinit(allocator);

    // newly created account is returned instead
    try std.testing.expectEqual(1, loaded_accounts.accounts.len);
    try std.testing.expectEqual(0, loaded_accounts.accounts.slice()[0].account.data.len);
    try std.testing.expectEqual(0, loaded_accounts.accounts.slice()[0].account.lamports);
    // Success path leaves `running_data_size_out` untouched.
    try std.testing.expectEqual(0, running_data_size);
}

test "load v3 program" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var accountsdb = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    defer accountsdb.deinit(allocator);
    var env = newTestingEnv();
    env.compute_budget_limits.loaded_accounts_bytes = 20_000;

    const fee_payer_address = Pubkey.initRandom(random);
    const pk_v3_program = Pubkey.initRandom(random);
    const pk_programdata = Pubkey.initRandom(random);

    const program_state: runtime.program.bpf_loader.v3.State = .{
        .program = .{ .programdata_address = pk_programdata },
    };
    var program_data_buffer: [1024]u8 = undefined;
    const program_data = try sig.bincode.writeToSlice(
        &program_data_buffer,
        program_state,
        .{},
    );

    var programdata_data = "program data!".*;

    try accountsdb.put(allocator, pk_v3_program, .{
        .data = program_data,
        .executable = true,
        .owner = runtime.program.bpf_loader.v3.ID,
        .lamports = 1,
        .rent_epoch = 0,
    });
    try accountsdb.put(allocator, pk_programdata, .{
        .data = &programdata_data,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .lamports = 1,
        .rent_epoch = 0,
    });

    var tx = try emptyTxWithKeys(allocator, &.{ fee_payer_address, pk_v3_program });
    defer tx.accounts.deinit(allocator);
    tx.instructions = &.{
        .{
            .program_meta = .{ .pubkey = pk_v3_program, .index_in_transaction = 1 },
            .account_metas = .empty,
            .dedupe_map = @splat(0xffff),
            .instruction_data = "",
            .owned_instruction_data = false,
        },
    };

    var running_data_size: u32 = 0;
    const loaded_accounts = try loadTransactionAccountsInner(
        AccountReader.fromMap(&accountsdb),
        allocator,
        &tx,
        &env.rent_collector,
        &env.compute_budget_limits,
        .{ .account = AccountSharedData.EMPTY, .loaded_size = 0, .rent_collected = 0 },
        &running_data_size,
    );
    defer loaded_accounts.deinit(allocator);

    // fee payer + v3 program returned in account keys
    try std.testing.expectEqual(2, loaded_accounts.accounts.len);
    try std.testing.expectEqual(pk_v3_program, loaded_accounts.accounts.slice()[1].pubkey);

    // data size: fee payer (0) + v3 program (64 + bincode(State)) + programdata (64 + 13)
    const expected_size: u32 = @intCast((TRANSACTION_ACCOUNT_BASE_SIZE + program_data.len) +
        (TRANSACTION_ACCOUNT_BASE_SIZE + programdata_data.len));
    try std.testing.expectEqual(expected_size, loaded_accounts.loaded_accounts_data_size);
}
