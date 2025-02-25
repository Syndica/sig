const std = @import("std");
const sig = @import("../../sig.zig");

const Transaction = sig.core.Transaction;

const InstructionContextAccountMeta = sig.runtime.InstructionContextAccountMeta;
const TransactionContext = sig.runtime.TransactionContext;

pub fn sumAccountLamports(
    tc: *const TransactionContext,
    account_metas: std.BoundedArray(InstructionContextAccountMeta, Transaction.MAX_ACCOUNTS),
) u128 {
    var lamports: u128 = 0;
    for (account_metas.slice()) |account_meta| {
        const transaction_account = tc.getAccountAtIndex(account_meta.index_in_transaction) orelse
            return 0;

        const account, const account_read_lock = transaction_account.readWithLock() orelse
            return 0;
        defer account_read_lock.release();

        lamports = std.math.add(u128, lamports, account.lamports) catch {
            return 0;
        };
    }
    return lamports;
}
