const std = @import("std");
const sig = @import("../sig.zig");

const features = sig.runtime.features;
const compute_budget_program = sig.runtime.program.compute_budget;

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

pub const Ancestors = struct {};
pub const StatusCache = struct {};
pub const SignatureDetails = struct {};
pub const RentCollector = struct {};
pub const RentDebits = struct {};
pub const EpochStakes = struct {};

pub const AccountMeta = struct {
    pubkey: Pubkey,
    is_signer: bool,
    is_writable: bool,
};

pub const ResolvedTransaction = struct {
    msg_hash: Hash,
    recent_blockhash: Hash,
    resolved_accounts: []const AccountMeta,
    instruction_infos: []const InstructionInfo,
};

pub const ExecutionEnvironment = struct {
    ancestors: *const Ancestors,
    feature_set: *const FeatureSet,
    status_cache: *const StatusCache,
    sysvar_cache: *const SysvarCache,
    rent_collector: *const RentCollector,
    epoch_stakes: *const EpochStakes,

    max_age: u64,
    last_blockhash: *const Hash,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,

    lamports_per_signature: u64,
};

pub const TransactionResult = union(enum(u8)) {
    @"error": TransactionError,
    fees_only: struct {
        @"error": TransactionError,
        transaction_fee: u64,
        prioritization_fee: u64,
        rollback_accounts: FeeDetails.RollbackAccounts,
    },
    executed: struct {
        loaded_accounts: LoadedAccounts,
        executed_transaction: ExecutedTransaction,
    },
};

pub const NonceAccountInfo = struct {
    address: Pubkey,
    account: *AccountSharedData,
};

pub const FeeDetails = struct {
    transaction_fee: u64,
    prioritization_fee: u64,
    // TODO: Establish if we can streamline these structs
    rollback_accounts: RollbackAccounts,
    loaded_fee_payer_account: LoadedFeePayerAccount,
};

pub const LoadedFeePayerAccount = union(enum(u8)) {
    account: AccountSharedData,
    loaded_size: usize,
    rent_collected: u64,
};

// NOTE: We don't need to store the fee payer address since it is
// available in the runtime transaction
pub const RollbackAccounts = union(enum(u8)) {
    fee_payer_only: AccountSharedData,
    same_nonce_and_fee_payer: NonceAccountInfo,
    separate_nonce_and_fee_payer: struct {
        nonce_account: NonceAccountInfo,
        fee_payer_account: AccountSharedData,
    },
};

pub const LoadedAccounts = struct {
    accounts: []const TransactionContextAccount,
    rent: u64,
    rent_debits: RentDebits,
    loaded_accounts_data_size: u32,
};

pub const ExecutedTransaction = struct {};

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L323-L324
pub fn loadAndExecuteTransactions(
    allocator: std.mem.Allocator,
    transactions: []const ResolvedTransaction,
    environment: *const ExecutionEnvironment,
    account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
) error{OutOfMemory}!TransactionResult {
    const transaction_results = try allocator.alloc(TransactionResult, transactions.len);
    for (transaction_results, transactions) |result, *transaction| {
        result.* = try executeTransaction(
            allocator,
            transaction,
            environment,
            account_cache,
        );
    }
    return transaction_results;
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L323-L324
pub fn loadAndExecuteTransaction(
    allocator: std.mem.Allocator,
    transaction: *const ResolvedTransaction,
    environment: *const ExecutionEnvironment,
    account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
) error{OutOfMemory}!TransactionResult {
    const maybe_nonce_info = checkAge(
        transaction,
        account_cache,
        environment.ancestors,
        environment.status_cache,
        environment.max_age,
        environment.last_blockhash,
        environment.next_durable_nonce,
        environment.next_lamports_per_signature,
    ) catch |err| return .{ .@"error" = err };

    checkStatusCache(
        transaction.msg_hash,
        transaction.recent_blockhash,
        environment.ancestors,
        environment.status_cache,
    ) catch |err| return .{ .@"error" = err };

    if (maybe_nonce_info) |nonce_info| {
        checkNonce(
            transaction.resolved_accounts,
            account_cache,
            &nonce_info,
            environment.next_durable_nonce,
        ) catch |err| return .{ .@"error" = err };
    }

    // TODO: Should the compute budget program require the feature set?
    const compute_budget_limits = compute_budget_program.execute(
        transaction.instruction_infos,
    ) catch |err| return .{ .@"error" = err };

    const fee_details = checkFeePayer(
        transaction.fee_payer,
        transaction.signature_details,
        account_cache,
        &compute_budget_limits,
        maybe_nonce_info,
        environment.rent_collector,
        environment.feature_set,
        environment.lamports_per_signature,
    ) catch |err| return .{ .@"error" = err };

    const loaded_accounts = loadAccounts(
        allocator,
        transaction,
        account_cache,
        &fee_details.loaded_fee_payer_account,
        &compute_budget_limits,
        environment.rent_collector,
    ) catch |err| {
        if (environment.feature_set.active.contains(
            features.ENABLE_TRANSACTION_LOADING_FAILURE_FEES,
        ))
            return .{
                .fees_only = .{
                    .@"error" = err,
                    .transaction_fee = fee_details.transaction_fee,
                    .prioritization_fee = fee_details.prioritization_fee,
                    .rollback_accounts = fee_details.rollback_accounts,
                },
            }
        else
            return .{ .@"error" = err };
    };

    const executed_transaction = executeTransaction(
        allocator,
        transaction,
        &loaded_accounts,
        environment,
    );

    return .{
        .executed = .{
            .loaded_accounts = loaded_accounts,
            .executed_transaction = executed_transaction,
        },
    };
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L909
pub fn executeTransaction(
    allocator: std.mem.Allocator,
    transaction: *const ResolvedTransaction,
    loaded_accounts: *const LoadedAccounts,
    environment: *const ExecutionEnvironment,
) ExecutedTransaction {
    _ = allocator;
    _ = transaction;
    _ = loaded_accounts;
    _ = environment;
    @panic("not implemented");
}

/// Requires full transaction to find nonce account in the event that the transactions recent blockhash
/// is not in the blockhash queue within the max age. Also worth noting that Agave returns a CheckTransactionDetails
/// struct which contains a lamports_per_signature field which is unused, hence we return only the nonce account
/// if it exists.
/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/runtime/src/bank/check_transactions.rs#L105
pub fn checkAge(
    transaction: *const ResolvedTransaction,
    account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
    ancestors: *const Ancestors,
    blockhash_queue: *const BlockhashQueue,
    max_age: u64,
    last_blockhash: *const Hash,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
) TransactionError!?NonceAccountInfo {
    _ = transaction;
    _ = ancestors;
    _ = account_cache;
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
) TransactionError!void {
    _ = msg_hash;
    _ = recent_blockhash;
    _ = status_cache;
    _ = ancestors;
    @panic("not implemented");
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L632
pub fn checkNonce(
    accounts: []const AccountMeta,
    account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
    nonce_account: *const NonceAccountInfo,
    next_durable_nonce: *const Hash,
) TransactionError!void {
    _ = accounts;
    _ = nonce_account;
    _ = next_durable_nonce;
    _ = account_cache;
    @panic("not implemented");
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L557
pub fn checkFeePayer(
    fee_payer: *const Pubkey,
    signature_details: *const SignatureDetails,
    account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
    compute_budget_limits: *const ComputeBudgetLimits,
    nonce_account: ?*const NonceAccountInfo,
    rent_collector: *const RentCollector,
    feature_set: *const FeatureSet,
    lamports_per_signature: u64,
) TransactionError!FeeDetails {
    _ = fee_payer;
    _ = signature_details;
    _ = account_cache;
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
    transaction: *const ResolvedTransaction,
    account_cache: *std.AutoArrayHashMap(Pubkey, AccountSharedData),
    loaded_fee_payer_account: *const FeeDetails.LoadedFeePayerAccount,
    compute_budget_limits: *const ComputeBudgetLimits,
    rent_collector: *const RentCollector,
) TransactionError!LoadedAccounts {
    _ = allocator;
    _ = transaction;
    _ = account_cache;
    _ = loaded_fee_payer_account;
    _ = compute_budget_limits;
    _ = rent_collector;
    @panic("not implemented");
}
