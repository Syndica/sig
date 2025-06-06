const std = @import("std");
const sig = @import("../sig.zig");

const account_loader = sig.runtime.account_loader;
const executor = sig.runtime.executor;
const compute_budget_program = sig.runtime.program.compute_budget;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const BlockhashQueue = sig.core.bank.BlockhashQueue;
const AccountSharedData = sig.runtime.AccountSharedData;
const ComputeBudgetLimits = compute_budget_program.ComputeBudgetLimits;
const FeatureSet = sig.runtime.FeatureSet;
const SysvarCache = sig.runtime.SysvarCache;
const TransactionContext = sig.runtime.TransactionContext;
const InstructionInfo = sig.runtime.InstructionInfo;
const TransactionError = sig.ledger.transaction_status.TransactionError;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionErrorEnum = sig.core.instruction.InstructionErrorEnum;
const TransactionReturnData = sig.runtime.transaction_context.TransactionReturnData;
const InstructionTrace = TransactionContext.InstructionTrace;
const LogCollector = sig.runtime.LogCollector;
const Ancestors = sig.core.bank.Ancestors;
const RentCollector = sig.core.rent_collector.RentCollector;
const LoadedTransactionAccounts = sig.runtime.account_loader.LoadedTransactionAccounts;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const CachedAccount = sig.runtime.account_loader.CachedAccount;
const EpochStakes = sig.core.stake.EpochStakes;
const TransactionContextAccount = sig.runtime.TransactionContextAccount;

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

pub const RuntimeTransaction = struct {
    pub const Accounts = std.MultiArrayList(sig.core.instruction.InstructionAccount);

    signature_count: u64,
    fee_payer: Pubkey,
    msg_hash: Hash,
    recent_blockhash: Hash,
    instruction_infos: []const InstructionInfo,
    accounts: Accounts = .{},
};

pub const TransactionExecutionEnvironment = struct {
    ancestors: *const Ancestors,
    feature_set: *const FeatureSet,
    status_cache: *const StatusCache,
    sysvar_cache: *const SysvarCache,
    rent_collector: *const RentCollector,
    blockhash_queue: *const BlockhashQueue,
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

pub const TransactionFees = struct {
    transaction_fee: u64,
    prioritization_fee: u64,
};

pub const TransactionRollbacks = union(enum(u8)) {
    fee_payer_only: CopiedAccount,
    same_nonce_and_fee_payer: CopiedAccount,
    separate_nonce_and_fee_payer: struct { CopiedAccount, CopiedAccount },
};

pub const CopiedAccount = struct {
    pubkey: Pubkey,
    account: AccountSharedData,
};

pub const ExecutedTransaction = struct {
    err: ?InstructionErrorEnum,
    log_collector: ?LogCollector,
    instruction_trace: ?InstructionTrace,
    return_data: ?TransactionReturnData,
    compute_meter: u64,
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
        fees: TransactionFees,
        rollbacks: TransactionRollbacks,
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

pub fn TransactionResult(comptime T: type) type {
    return union(enum(u8)) {
        ok: T,
        err: TransactionError,
    };
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L323-L324
pub fn loadAndExecuteTransactions(
    allocator: std.mem.Allocator,
    transactions: []const RuntimeTransaction,
    batch_account_cache: *BatchAccountCache,
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
) error{OutOfMemory}![]TransactionResult(ProcessedTransaction) {
    const transaction_results = try allocator.alloc(
        TransactionResult(ProcessedTransaction),
        transactions.len,
    );
    for (transactions, 0..) |*transaction, index| {
        transaction_results[index] = try loadAndExecuteTransaction(
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
    batch_account_cache: *BatchAccountCache,
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
) error{OutOfMemory}!TransactionResult(ProcessedTransaction) {
    const check_age_result = checkAge(
        transaction,
        batch_account_cache,
        environment.ancestors,
        environment.blockhash_queue,
        environment.max_age,
        &environment.last_blockhash,
        &environment.next_durable_nonce,
        environment.next_lamports_per_signature,
    );
    const maybe_nonce_info = switch (check_age_result) {
        .ok => |cached_account| cached_account,
        .err => |err| return .{ .err = err },
    };

    if (checkStatusCache(
        &transaction.msg_hash,
        &transaction.recent_blockhash,
        environment.ancestors,
        environment.status_cache,
    )) |err| return .{ .err = err };

    // NOTE: in agave nonce validation occurs during check_transactions and validate_nonce_and_fee_payer.
    // Since we do not perform check transactions at the batch level, the secondary checks may not be necessary.
    // We will however need to return the corresponding errors which may occur in agave's validate_transaction_nonce.
    // [agave] hhttps://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L632-L688

    // TODO: Should the compute budget program require the feature set?
    const compute_budget_result = compute_budget_program.execute(
        transaction.instruction_infos,
        environment.feature_set,
    );
    const compute_budget_limits = switch (compute_budget_result) {
        .ok => |limits| limits,
        .err => |err| return .{ .err = err },
    };

    const check_fee_payer_result = checkFeePayer(
        &transaction.fee_payer,
        transaction.signature_count,
        batch_account_cache,
        &compute_budget_limits,
        &maybe_nonce_info,
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

    const loaded_accounts_result = try batch_account_cache.loadTransactionAccounts(
        allocator,
        transaction,
        environment.rent_collector,
        environment.feature_set,
        &compute_budget_limits,
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
        &compute_budget_limits,
        environment,
        config,
    );

    return .{ .ok = .{
        .executed = .{
            .fees = fees,
            .rollbacks = rollbacks,
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
    const compute_budget = compute_budget_limits.intoComputeBudget();
    const log_collector = if (config.log)
        try LogCollector.init(allocator, config.log_messages_byte_limit)
    else
        null;

    const accounts = try allocator.alloc(
        TransactionContextAccount,
        loaded_accounts.accounts.len,
    );
    for (loaded_accounts.accounts.slice(), 0..) |account, index| {
        accounts[index] = .{
            .pubkey = account.pubkey,
            .account = account.account.*, // Copy for now until tc is modified to used shared data
            .read_refs = 0,
            .write_ref = false,
        };
    }

    var tc: TransactionContext = .{
        .allocator = allocator,
        .feature_set = environment.feature_set,
        .epoch_stakes = environment.epoch_stakes,
        .sysvar_cache = environment.sysvar_cache,
        .accounts = accounts,
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

    var maybe_instruction_error: ?InstructionError = null;
    for (transaction.instruction_infos) |instruction_info| {
        executor.executeInstruction(
            allocator,
            &tc,
            instruction_info,
        ) catch |err| {
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |e| maybe_instruction_error = e,
            }
            break;
        };
    }

    const instruction_error = if (maybe_instruction_error) |instruction_error|
        InstructionErrorEnum.fromError(instruction_error, tc.custom_error, null) catch |err|
            std.debug.panic("Failed to convert error: instruction_error{}", .{err})
    else
        null;

    return .{
        .err = instruction_error,
        .log_collector = tc.takeLogCollector(),
        .instruction_trace = tc.instruction_trace,
        .return_data = tc.takeReturnData(),
        .compute_meter = tc.compute_meter,
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
    batch_account_cache: *BatchAccountCache,
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
    batch_account_cache: *BatchAccountCache,
    compute_budget_limits: *const ComputeBudgetLimits,
    nonce_account: ?*const CachedAccount,
    rent_collector: *const RentCollector,
    feature_set: *const FeatureSet,
    lamports_per_signature: u64,
) TransactionResult(struct {
    TransactionFees,
    TransactionRollbacks,
    LoadedTransactionAccounts,
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

test "transaction_execution" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    const transactions: []RuntimeTransaction = &.{};
    var batch_account_cache: account_loader.BatchAccountCache = .{};

    const ancestors: Ancestors = .{};
    const feature_set: FeatureSet = FeatureSet.EMPTY;
    const status_cache: StatusCache = .{};
    const sysvar_cache: SysvarCache = .{};
    const rent_collector: RentCollector = sig.core.rent_collector.defaultCollector(10);
    const blockhash_queue: BlockhashQueue = try BlockhashQueue.initRandom(
        prng.random(),
        allocator,
        10,
    );
    defer blockhash_queue.deinit(allocator);
    const epoch_stakes: EpochStakes = try EpochStakes.initEmpty(allocator);
    defer epoch_stakes.deinit(allocator);

    const environment: TransactionExecutionEnvironment = .{
        .ancestors = &ancestors,
        .feature_set = &feature_set,
        .status_cache = &status_cache,
        .sysvar_cache = &sysvar_cache,
        .rent_collector = &rent_collector,
        .blockhash_queue = &blockhash_queue,
        .epoch_stakes = &epoch_stakes,

        .max_age = 0,
        .last_blockhash = Hash.ZEROES,
        .next_durable_nonce = Hash.ZEROES,
        .next_lamports_per_signature = 0,
        .last_lamports_per_signature = 0,

        .lamports_per_signature = 0,
    };

    const config = TransactionExecutionConfig{
        .log = false,
        .log_messages_byte_limit = null,
    };

    const result = try loadAndExecuteTransactions(
        allocator,
        transactions,
        &batch_account_cache,
        &environment,
        &config,
    );

    _ = result;
}
