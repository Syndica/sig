const std = @import("std");
const sig = @import("../sig.zig");

const executor = sig.runtime.executor;
const features = sig.runtime.features;
const compute_budget_program = sig.runtime.program.compute_budget;

const AccountLoader = sig.runtime.account_loader.BatchAccountCache;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const BlockhashQueue = sig.core.bank.BlockhashQueue;
const AccountSharedData = sig.runtime.AccountSharedData;
const ComputeBudgetLimits = compute_budget_program.ComputeBudgetLimits;
const FeatureSet = sig.runtime.FeatureSet;
const SysvarCache = sig.runtime.SysvarCache;
const EpochContext = sig.runtime.EpochContext;
const SlotContext = sig.runtime.SlotContext;
const TransactionContext = sig.runtime.TransactionContext;
const InstructionInfo = sig.runtime.InstructionInfo;
const TransactionError = sig.accounts_db.snapshots.TransactionError;
const TransactionReturnData = sig.runtime.transaction_context.TransactionReturnData;
const InstructionTrace = TransactionContext.InstructionTrace;
const LogCollector = sig.runtime.LogCollector;
const LoadedTransactionAccount = sig.runtime.account_loader.LoadedTransactionAccount;
const Ancestors = sig.core.bank.Ancestors;
const RentCollector = sig.core.rent_collector.RentCollector;
const RentDebit = sig.runtime.account_loader.RentDebit;
const LoadedTransactionAccounts = sig.runtime.account_loader.LoadedTransactionAccounts;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;

// Transaction execution involves logic and validation which occurs in replay
// and the svm. The location of key processes in Agave are outlined below:
//
// Replay: (Failure results in slot rejection)
//     - Signature verification
//     - Load accounts from address lookup tables
//     - Verify precompiles (if move_verify_precompiles_to_svm is false)
//     - Acquire and check batch account locks
//
// Svm:
//     - Check transactions
//     - Validate fee payer
//     - Load accounts
//
// Once the accounts have been loaded, the transaction is commitable, even if its
// execution fails.

pub const StatusCache = struct {};
pub const EpochStakes = struct {};

pub const RuntimeTransaction = struct {
    signature_count: u64,
    fee_payer: Pubkey,
    msg_hash: Hash,
    recent_blockhash: Hash,
    instruction_infos: []const InstructionInfo,
    accounts: std.MultiArrayList(struct {
        pubkey: Pubkey,
        is_writable: bool,
        is_signer: bool,
    }) = .{},
};

pub const TransactionExecutionEnvironment = struct {
    ancestors: *const Ancestors,
    feature_set: *const FeatureSet,
    status_cache: *const StatusCache,
    sysvar_cache: *const SysvarCache,
    rent_collector: *const RentCollector,
    epoch_stakes: *const EpochStakes,

    max_age: u64,
    last_blockhash: Hash,
    next_durable_nonce: Hash,
    next_lamports_per_signature: u64,
    last_lamports_per_signature: u64,

    lamports_per_signature: u64,
};

pub const TransactionExecutionConfig = struct {
    log: bool,
    log_messages_byte_limit: ?u64,
};

pub fn TransactionResult(comptime T: type) type {
    return union(enum(u8)) {
        ok: T,
        err: TransactionError,
    };
}

pub const TransactionFees = struct {
    transaction_fee: u64,
    prioritization_fee: u64,
};

pub const TransactionRollbacks = union(enum(u8)) {
    fee_payer_only: CopiedAccount,
    same_nonce_and_fee_payer: CopiedAccount,
    separate_nonce_and_fee_payer: struct { CopiedAccount, CopiedAccount },
};

pub const CachedAccount = struct {
    pubkey: Pubkey,
    account: *AccountSharedData,
};

pub const CopiedAccount = struct {
    pubkey: Pubkey,
    account: AccountSharedData,
};

pub const ExecutedTransaction = struct {
    err: ?TransactionError,
    log_collector: ?LogCollector,
    instruction_trace: ?InstructionTrace,
    return_data: ?TransactionReturnData,
    copmute_meter: u64,
    accounts_data_len_delta: i64,

    pub fn deinit(self: ExecutedTransaction, allocator: std.mem.Allocator) void {
        if (self.log_collector) |lc| lc.deinit(allocator);
        if (self.return_data) |data| allocator.free(data);
    }
};

pub const ProcessedTransaction = union(enum(u8)) {
    fees_only: struct {
        err: TransactionError,
        fees: TransactionFees,
        rollbacks: TransactionRollbacks,
    },
    executed: struct {
        loaded_accounts: LoadedTransactionAccounts,
        executed_transaction: ExecutedTransaction,
    },

    pub fn deinit(self: ProcessedTransaction, allocator: std.mem.Allocator) void {
        switch (self) {
            .executed => |executed| {
                executed.loaded_accounts.deinit(allocator);
                executed.executed_transaction.deinit(allocator);
            },
            else => {},
        }
    }
};

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L323-L324
pub fn loadAndExecuteTransactions(
    allocator: std.mem.Allocator,
    transactions: []const RuntimeTransaction,
    batch_account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
) error{OutOfMemory}![]TransactionResult(ProcessedTransaction) {
    const transaction_results = try allocator.alloc(TransactionResult(ProcessedTransaction), transactions.len);
    for (transaction_results, transactions) |result, *transaction| {
        result.* = try loadAndExecuteTransaction(
            allocator,
            transaction,
            batch_account_cache,
            environment,
            config,
        );
    }
    return transaction_results;
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L323-L324
pub fn loadAndExecuteTransaction(
    allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
    batch_account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
) error{OutOfMemory}!TransactionResult(ProcessedTransaction) {
    const check_age_result = checkAge(
        transaction,
        batch_account_cache,
        environment.ancestors,
        environment.status_cache,
        environment.max_age,
        environment.last_blockhash,
        environment.next_durable_nonce,
        environment.next_lamports_per_signature,
    );
    const maybe_nonce_info = switch (check_age_result) {
        .ok => |cached_account| cached_account,
        .err => |err| return .{ .err = err },
    };

    if (checkStatusCache(
        transaction.msg_hash,
        transaction.recent_blockhash,
        environment.ancestors,
        environment.status_cache,
    )) |err| return .{ .err = err };

    // NOTE: in agave nonce validation occurs during check_transactions and validate_nonce_and_fee_payer.
    // Since we do not perform check transactions at the batch level, the secondary checks may not be necessary.
    // We will however need to return the corresponding errors which may occur in agave's validate_transaction_nonce.
    // [agave] hhttps://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L632-L688

    // TODO: Should the compute budget program require the feature set?
    const compute_budget_limits = compute_budget_program.execute(
        transaction.instruction_infos,
    ) catch |err| return .{ .err = err };

    const check_fee_payer_result = checkFeePayer(
        transaction.fee_payer,
        transaction.signature_count,
        batch_account_cache,
        &compute_budget_limits,
        maybe_nonce_info,
        environment.rent_collector,
        environment.feature_set,
        environment.lamports_per_signature,
    );
    const fees, const rollbacks, const loaded_fee_payer = switch (check_fee_payer_result) {
        .ok => |result| result,
        .err => |err| return .{ .err = err },
    };

    // NOTE: should we use this value, to prevent double-loading of the fee payer? Seems it doesn't
    // matter.
    _ = loaded_fee_payer;

    const loaded_accounts_result = loadAccounts(
        allocator,
        transaction,
        batch_account_cache,
        &compute_budget_limits,
        environment.feature_set,
        environment.rent_collector,
    );
    const loaded_accounts = switch (loaded_accounts_result) {
        .ok => |loaded_accounts| loaded_accounts,
        .err => |err| return .{ .ok = .{
            .fees_only = .{
                .err = err,
                .fees = fees,
                .rollbacks = rollbacks,
            },
        } },
    };

    const executed_transaction = try executeTransaction(
        allocator,
        transaction,
        &loaded_accounts,
        compute_budget_limits,
        environment,
        config,
    );

    return .{ .ok = .{
        .executed = .{
            .loaded_accounts = loaded_accounts,
            .executed_transaction = executed_transaction,
        },
    } };
}

/// TODO: Follow up PR will remove EpochContext and SlotContext from the TransactionContext
/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L909
pub fn executeTransaction(
    allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
    loaded_accounts: *const LoadedTransactionAccounts,
    compute_budget_limits: *const ComputeBudgetLimits,
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
) error{OutOfMemory}!ExecutedTransaction {
    const ec = try allocator.create(EpochContext);
    defer allocator.destroy(ec);
    ec.* = .{
        .allocator = allocator,
        .feature_set = environment.feature_set,
    };

    const sc = try allocator.create(SlotContext);
    defer allocator.destroy(sc);
    sc.* = .{
        .allocator = allocator,
        .sysvar_cache = environment.sysvar_cache,
    };

    var tc = try allocator.create(TransactionContext);
    defer {
        tc.deinit();
        allocator.destroy(tc);
    }

    const compute_budget = compute_budget_limits.intoComputeBudget();
    const log_collector = if (config.log)
        LogCollector.init(config.log_messages_byte_limit)
    else
        null;

    tc.* = .{
        .allocator = allocator,
        .ec = ec,
        .sc = sc,
        .accounts = loaded_accounts.accounts,
        .serialized_accounts = .{},
        .instruction_stack = .{},
        .instruction_trace = .{},
        .return_data = .{},
        .accounts_resize_delta = 0,
        .compute_meter = compute_budget.compute_unit_limit,
        .compute_budget = compute_budget,
        .custom_error = null,
        .log_collector = log_collector,
        .rent = environment.rent_collector.rent,
        .prev_blockhash = environment.last_blockhash,
        .prev_lamports_per_signature = environment.last_lamports_per_signature,
    };

    var instruction_error = null;
    for (transaction.instruction_infos) |instruction_info| {
        executor.executeInstruction(
            allocator,
            tc,
            instruction_info,
        ) catch |err| {
            switch (err) {
                .OutOfMemory => return err,
                else => {
                    instruction_error = err;
                    break;
                },
            }
        };
    }

    return .{
        .err = instruction_error,
        .log_messages = tc.takeLogCollector(),
        .instructions = tc.instruction_trace,
        .return_data = tc.takeReturnData(),
        .copmute_meter = tc.compute_meter,
        .accounts_data_len_delta = tc.accounts_resize_delta,
    };
}

/// Requires full transaction to find nonce account in the event that the transactions recent blockhash
/// is not in the blockhash queue within the max age. Also worth noting that Agave returns a CheckTransactionDetails
/// struct which contains a lamports_per_signature field which is unused, hence we return only the nonce account
/// if it exists.
/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/runtime/src/bank/check_transactions.rs#L105
pub fn checkAge(
    transaction: *const RuntimeTransaction,
    batch_account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
    ancestors: *const Ancestors,
    blockhash_queue: *const BlockhashQueue,
    max_age: u64,
    last_blockhash: *const Hash,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
) TransactionResult(CachedAccount) {
    _ = transaction;
    _ = ancestors;
    _ = batch_account_cache;
    _ = blockhash_queue;
    _ = max_age;
    _ = last_blockhash;
    _ = next_durable_nonce;
    _ = next_lamports_per_signature;
    @panic("not implemented");
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/runtime/src/bank/check_transactions.rs#L186
pub fn checkStatusCache(
    msg_hash: *const Hash,
    recent_blockhash: *const Hash,
    ancestors: *const Ancestors,
    status_cache: *const StatusCache,
) ?TransactionError {
    _ = msg_hash;
    _ = recent_blockhash;
    _ = status_cache;
    _ = ancestors;
    @panic("not implemented");
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L557
pub fn checkFeePayer(
    fee_payer: *const Pubkey,
    signature_count: u64,
    batch_account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
    compute_budget_limits: *const ComputeBudgetLimits,
    nonce_account: ?*const CachedAccount,
    rent_collector: *const RentCollector,
    feature_set: *const FeatureSet,
    lamports_per_signature: u64,
) TransactionResult(struct {
    TransactionFees,
    TransactionRollbacks,
    LoadedTransactionAccount,
}) {
    _ = fee_payer;
    _ = signature_count;
    _ = batch_account_cache;
    _ = compute_budget_limits;
    _ = nonce_account;
    _ = lamports_per_signature;
    _ = rent_collector;
    _ = feature_set;
    @panic("not implemented");
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/account_loader.rs#L344
pub fn loadAccounts(
    allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
    batch_account_cache: *const BatchAccountCache,
    compute_budget_limits: *const ComputeBudgetLimits,
    feature_set: *const FeatureSet,
    rent_collector: *const RentCollector,
) TransactionResult(LoadedTransactionAccounts) {
    return batch_account_cache.loadTransactionAccounts(
        allocator,
        transaction,
        rent_collector,
        feature_set,
        compute_budget_limits,
    );
}

// TODO: Test cases to reimplement once validation components are integrated
// test {
//     std.testing.refAllDecls(@This());

//     const allocator = std.testing.allocator;

//     var bank = account_loader.MockedAccountsDb{ .allocator = allocator };
//     defer bank.accounts.deinit(allocator);
//     try bank.accounts.put(allocator, sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID, .{
//         .owner = sig.runtime.ids.NATIVE_LOADER_ID,
//         .executable = true,
//         .data = .{ .empty = .{ .len = 0 } },
//         .lamports = 1,
//         .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
//     });
//     try bank.accounts.put(allocator, sig.runtime.program.vote_program.ID, .{
//         .owner = sig.runtime.ids.NATIVE_LOADER_ID,
//         .executable = true,
//         .data = .{ .empty = .{ .len = 0 } },
//         .lamports = 1,
//         .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
//     });

//     // empty
//     const tx1 = sig.core.Transaction.EMPTY;

//     // zero instructions
//     const tx2: sig.core.Transaction = .{
//         .signatures = &.{},
//         .version = .legacy,
//         .msg = .{
//             .signature_count = 0,
//             .readonly_signed_count = 0,
//             .readonly_unsigned_count = 0,
//             .account_keys = &.{sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID},
//             .recent_blockhash = .{ .data = [_]u8{0x00} ** sig.core.Hash.SIZE },
//             .instructions = &.{},
//             .address_lookups = &.{},
//         },
//     };
//     const Ed25519 = std.crypto.sign.Ed25519;

//     const keypair = try Ed25519.KeyPair.create(null);
//     const ed25519_instruction = try sig.runtime.program.precompile_programs.ed25519.newInstruction(
//         std.testing.allocator,
//         keypair,
//         "hello!",
//     );
//     defer std.testing.allocator.free(ed25519_instruction.data);

//     // a precompile instruction (slightly different codepath) - impl
//     // const tx3: sig.core.Transaction = .{
//     //     .msg = .{
//     //         .account_keys = &.{sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID},
//     //         .instructions = &.{
//     //             .{ .program_index = 0, .account_indexes = &.{0}, .data = ed25519_instruction.data },
//     //         },
//     //         .signature_count = 1,
//     //         .readonly_signed_count = 1,
//     //         .readonly_unsigned_count = 0,
//     //         .recent_blockhash = sig.core.Hash.ZEROES,
//     //     },
//     //     .version = .legacy,
//     //     .signatures = &.{},
//     // };

//     // program not found
//     const tx4 = sig.core.Transaction{
//         .msg = .{
//             .account_keys = &.{Pubkey.ZEROES},
//             .instructions = &.{
//                 .{ .program_index = 0, .account_indexes = &.{0}, .data = "" },
//             },
//             .signature_count = 1,
//             .readonly_signed_count = 1,
//             .readonly_unsigned_count = 0,
//             .recent_blockhash = sig.core.Hash.ZEROES,
//         },
//         .version = .legacy,
//         .signatures = &.{},
//     };

//     // program that should fail
//     const tx5 = sig.core.Transaction{
//         .msg = .{
//             .account_keys = &.{sig.runtime.program.vote_program.ID},
//             .instructions = &.{
//                 .{ .program_index = 0, .account_indexes = &.{0}, .data = "" },
//             },
//             .signature_count = 1,
//             .readonly_signed_count = 1,
//             .readonly_unsigned_count = 0,
//             .recent_blockhash = sig.core.Hash.ZEROES,
//         },
//         .version = .legacy,
//         .signatures = &.{},
//     };

//     const transactions: []const sig.core.Transaction = &.{ tx1, tx2, tx4, tx5 };

//     var loader = try AccountLoader(.Mocked).newWithCacheCapacity(allocator, allocator, bank, 100);
//     defer loader.deinit();

//     const batch_loadedaccounts = try allocator.alloc(LoadedTransactionAccounts, transactions.len);
//     defer allocator.free(batch_loadedaccounts);

//     const batch_budgetlimits = try allocator.alloc(
//         compute_budget.Error!compute_budget.ComputeBudgetLimits,
//         transactions.len,
//     );
//     defer allocator.free(batch_budgetlimits);

//     for (transactions, batch_budgetlimits) |*tx, *tx_budgetlimits| {
//         tx_budgetlimits.* = compute_budget.execute(tx);
//     }

//     for (
//         transactions,
//         batch_loadedaccounts,
//         batch_budgetlimits,
//     ) |*tx, *tx_loaded_account, tx_budgetlimit| {
//         const max_account_bytes = (try tx_budgetlimit).loaded_accounts_bytes;

//         const loaded = try account_loader.loadTransactionAccounts(
//             .Mocked,
//             allocator,
//             tx,
//             max_account_bytes,
//             &loader,
//             &sig.runtime.FeatureSet.EMPTY,
//             &sig.core.rent_collector.defaultCollector(0),
//         );

//         tx_loaded_account.* = loaded;
//     }

//     const env = ProcessingEnv.testingDefault();

//     for (transactions, batch_budgetlimits, 0..) |*tx, tx_budgetlimit, tx_idx| {
//         const loaded = &batch_loadedaccounts[tx_idx];

//         const err: ?anyerror = if (loaded.load_failure) |failure|
//             failure.err
//         else exec_err: {
//             const output = try executeTransaction(allocator, tx, env, try tx_budgetlimit, loaded);
//             defer output.deinit(allocator);

//             break :exec_err output.err;
//         };

//         const expected_err: ?anyerror = switch (tx_idx) {
//             0, 1 => null,
//             2 => error.ProgramAccountNotFound,
//             3 => error.InvalidAccountOwner,
//             else => unreachable,
//         };

//         try std.testing.expectEqual(expected_err, err);
//     }
// }

// // example of usage
// fn loadAndExecuteBatchExample(
//     allocator: std.mem.Allocator,
//     bank: account_loader.MockedAccountsDb,
//     env: ProcessingEnv,
//     transactions: []const sig.core.Transaction,
//     features: *const sig.runtime.FeatureSet,
// ) !void {
//     if (!builtin.is_test) @compileError("example/testing usage only");

//     const per_tx_budget_limit = try allocator.alloc(
//         compute_budget.Error!compute_budget.ComputeBudgetLimits,
//         transactions.len,
//     );
//     defer allocator.free(per_tx_budget_limit);

//     for (transactions, per_tx_budget_limit) |*tx, *tx_budgetlimits| {
//         tx_budgetlimits.* = compute_budget.execute(tx);
//     }

//     var loader = try AccountLoader(.Mocked).newWithCacheCapacity(allocator, allocator, bank, max: {
//         // capacity over-estimate
//         var n_accounts: usize = 0;
//         for (transactions) |tx| n_accounts += tx.msg.account_keys.len;
//         break :max n_accounts;
//     });
//     defer loader.deinit();

//     const per_ex_loaded_accounts = try allocator.alloc(LoadedTransactionAccounts, transactions.len);
//     defer allocator.free(per_ex_loaded_accounts);

//     // load single-threaded (writing to account loader)
//     for (
//         transactions,
//         per_ex_loaded_accounts,
//         per_tx_budget_limit,
//     ) |*tx, *tx_loaded_accounts, tx_budget_limit| {
//         const max_account_bytes = (tx_budget_limit catch continue).loaded_accounts_bytes;

//         const loaded = try account_loader.loadTransactionAccounts(
//             .Mocked,
//             allocator,
//             tx,
//             max_account_bytes,
//             &loader,
//             features,
//             &env.rent_collector,
//         );

//         tx_loaded_accounts.* = loaded;
//     }

//     // easy to parallelize (assuming no lock violations)
//     for (
//         transactions,
//         per_ex_loaded_accounts,
//         per_tx_budget_limit,
//         0..,
//     ) |tx, tx_loaded_accounts, tx_budget_limit, tx_idx| {
//         const budget = tx_budget_limit catch |err| {
//             std.debug.print("tx{}, bad budget program: {}\n", .{ tx_idx, err });
//             continue;
//         };
//         if (tx_loaded_accounts.load_failure) |failure| {
//             std.debug.print("tx{}, failed to load: {}\n", .{ tx_idx, failure });
//             continue;
//         }

//         const output = try executeTransaction(allocator, &tx, env, budget, &tx_loaded_accounts);
//         defer output.deinit(allocator);

//         if (output.err) |err| {
//             std.debug.print("tx{}, failed to execute: {}\n", .{ tx_idx, err });
//             if (output.logs.len > 0) {
//                 std.debug.print("logs: {{\n", .{});
//                 for (output.logs) |log_entry| std.debug.print("{}:\t{s}", .{ tx_idx, log_entry });
//                 std.debug.print("logs: }}\n", .{});
//             }
//         }
//     }
// }

// test "example batch" {
//     const allocator = std.testing.allocator;

//     var bank = account_loader.MockedAccountsDb{ .allocator = allocator };
//     defer bank.accounts.deinit(allocator);

//     const transactions = &.{sig.core.Transaction.EMPTY};
//     const env = ProcessingEnv.testingDefault();

//     try loadAndExecuteBatchExample(
//         allocator,
//         bank,
//         env,
//         transactions,
//         &sig.runtime.FeatureSet.EMPTY,
//     );
// }
