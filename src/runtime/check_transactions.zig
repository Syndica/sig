const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;

pub const CheckResult = ?error{ AlreadyProcessed, BlockhashNotFound };

pub fn checkTransactions(
    allocator: std.mem.Allocator,
    transactions: []const sig.core.Transaction,
    max_age: usize,
    status_cache: *const sig.core.StatusCache,
    ancestors: *const sig.core.status_cache.Ancestors,
) ![]CheckResult {
    const check_results = try allocator.alloc(CheckResult, transactions.len);
    @memset(check_results, null);

    // TODO: implement check_age (needs DurableNonce + BlockhashQueue)
    _ = max_age;

    checkStatusCache(transactions, check_results, status_cache, ancestors);

    return check_results;
}

fn checkStatusCache(
    transactions: []const sig.core.Transaction,
    results: []CheckResult,
    status_cache: *const sig.core.StatusCache,
    ancestors: *const sig.core.status_cache.Ancestors,
) void {
    // Assuming for now that lock results are all Ok.
    // Why would we even make a batch with locks that don't work?
    for (results) |*result| {
        if (result != null) continue; // already an error
        if (isTransactionAlreadyProcessed(transactions, ancestors, status_cache))
            result.* = error.AlreadyProcessed;
    }
}

fn isTransactionAlreadyProcessed(
    transaction: *const sig.core.Transaction,
    ancestors: *const sig.core.status_cache.Ancestors,
    status_cache: *sig.core.StatusCache,
) bool {
    const key = transaction.hash();
    return status_cache.getStatus(key, transaction.msg.recent_blockhash, ancestors) != null;
}
