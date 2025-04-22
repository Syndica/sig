const std = @import("std");
const sig = @import("../sig.zig");

const account_loader = sig.runtime.account_loader;
const AccountLoader = account_loader.AccountLoader;
const TransactionError = sig.ledger.transaction_status.TransactionError;
const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

const ProcessingEnv = struct {
    blockhash: sig.core.Hash,
    blockhash_lamports_per_signature: u64,
    epoch_total_stake: u64,
    feature_set: *const sig.runtime.FeatureSet,
    rent_collector: *const sig.runtime.rent_collector.RentCollector,
};

// fn loadTransaction()

// reviewers' note: would prefer to use TransactionError!CheckedTransactionDetails, but
// TransactionError is a tagged union; could we get away with an error type (i.e. no fields)?
// const TransactionCheck = union(enum) {
//     Err: TransactionError,
//     Ok: CheckedTransactionDetails,
// };

// const NonceInfo = struct {
//     address: Pubkey,
//     account: AccountSharedData,
// };

// const CheckedTransactionDetails = struct {
//     nonce: ?NonceInfo,
//     compute_budget_and_limits:
// };

// placeholder type
const TransactionResult = union(enum) {
    Err: anyerror,
    Ok: .{},
};

const Output = struct {
    // .len == raw_instructions.len
    processing_results: []const TransactionResult,
};

// simplified ~= agave's load_and_execute_sanitized_transactions
pub fn loadAndExecuteBatch(
    gpa_allocator: std.mem.Allocator,
    env: *const ProcessingEnv,
    bank: sig.accounts_db.Bank,
    raw_transactions: []const sig.core.Transaction, // TODO: assuming sanitized already (!)
) !Output {
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var loader: AccountLoader(.AccountsDb) = .{
        .allocator = allocator,
        .features = env.feature_set,
    };

    // largest-case capacity estimate
    try loader.account_cache.ensureTotalCapacity(allocator, account_keys_sum: {
        var sum: usize = 0;
        for (raw_transactions) |tx| sum += tx.msg.account_keys.len;
        break :account_keys_sum sum;
    });

    // incorrect - transaction details should contain this as a field
    const requested_max_total_data_size = 100 * 1024 * 1024;

    const transaction_result = gpa_allocator.alloc(TransactionResult, raw_transactions.len);
    errdefer gpa_allocator.free(transaction_result);

    // transactions must be executed in order
    for (raw_transactions, 0..) |tx, tx_idx| {
        // now would be a great time to *validate_transaction_nonce_and_fee_payer*
        // not doing it yet. Pretending it's valid for now.

        const loaded_accounts = account_loader.loadTransactionAccounts(
            allocator,
            tx,
            requested_max_total_data_size,
            &account_loader,
            env.feature_set,
        ) catch |err| { // TODO: actual error handling
            transaction_result[tx_idx] = .{ .err = err };
            continue;
        };
        transaction_result[tx_idx] = .Ok;

        executeTransaction(loaded_accounts.accounts_buf[0..tx.msg.account_keys.len]);
    }

    // const transaction_contexts = loadBatch(allocator, &env, bank, raw_transactions);

    return .{
        .processing_results = transaction_result,
    };
}

fn executeTransaction(accounts: []AccountSharedData) !void {
    _ = accounts;
}

// fn loadBatch(
//     allocator: std.mem.Allocator,
//     env: *const ProcessingEnv,
//     bank: sig.accounts_db.Bank,
//     raw_transactions: []const sig.core.Transaction,
// ) []sig.runtime.TransactionContext {
//     // TODO: sanitize
// }

// fn executeBatch(
//     env: *const ProcessingEnv,
//     transactions: []const sig.runtime.TransactionContext,
// ) !void {}

// fn loadTransactions(
//     raw_transactions: []const sig.core.Transaction,
// ) sig.runtime.TransactionContext {}

// fn buildTransactionContext(
//     raw_transactions: []const sig.core.Transaction,
// ) sig.runtime.TransactionContext {}
