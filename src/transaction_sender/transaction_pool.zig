const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);

const Slot = sig.core.Slot;
const RwMux = sig.sync.RwMux;
const Signature = sig.core.Signature;
const TransactionInfo = sig.transaction_sender.TransactionInfo;

/// Pool to keep track of pending transactions, transactions are added to the
/// pool after they are received off the incomming channel, and removed when
/// they are confirmed, failed, timed out, or reach the max retries.
/// pending_transactions requires a lock as it is accessed by both the receive
/// thread and the process transactions thread.
/// retry_signatures and drop_signatures do not need a lock as they are
/// only accessed by the process transactions thread.
pub const TransactionPool = struct {
    pending_transactions_rw: RwMux(PendingTransactions),
    retry_signatures: std.ArrayList(Signature),
    drop_signatures: std.ArrayList(Signature),
    max_transactions: usize,

    const PendingTransactions = std.AutoArrayHashMap(Signature, TransactionInfo);

    pub fn init(allocator: Allocator, max_transactions: usize) TransactionPool {
        return .{
            .pending_transactions_rw = RwMux(PendingTransactions).init(PendingTransactions.init(allocator)),
            .retry_signatures = std.ArrayList(Signature).init(allocator),
            .drop_signatures = std.ArrayList(Signature).init(allocator),
            .max_transactions = max_transactions,
        };
    }

    pub fn deinit(self: *TransactionPool) void {
        const pending_transactions: *PendingTransactions, var pending_transactions_lg =
            self.pending_transactions_rw.writeWithLock();
        defer pending_transactions_lg.unlock();
        pending_transactions.deinit();
        self.retry_signatures.deinit();
        self.drop_signatures.deinit();
    }

    pub fn count(self: *TransactionPool) usize {
        const pending_transactions: *const PendingTransactions, var pending_transactions_lg =
            self.pending_transactions_rw.readWithLock();
        defer pending_transactions_lg.unlock();
        return pending_transactions.count();
    }

    pub fn contains(self: *TransactionPool, signature: Signature) bool {
        const pending_transactions: *const PendingTransactions, var pending_transactions_lg =
            self.pending_transactions_rw.readWithLock();
        defer pending_transactions_lg.unlock();
        return pending_transactions.contains(signature);
    }

    pub fn readSignaturesAndTransactionsWithLock(self: *TransactionPool) struct { []const Signature, []const TransactionInfo, RwMux(PendingTransactions).RLockGuard } {
        const pending_transactions: *const PendingTransactions, const pending_transactions_lg = self.pending_transactions_rw.readWithLock();
        return .{ pending_transactions.keys(), pending_transactions.values(), pending_transactions_lg };
    }

    pub fn readRetryTransactionsWithLock(self: *TransactionPool, allocator: Allocator) !struct { []TransactionInfo, RwMux(PendingTransactions).RLockGuard } {
        const pending_transactions: *const PendingTransactions, const pending_transactions_lg = self.pending_transactions_rw.readWithLock();
        var retry_transactions = try allocator.alloc(TransactionInfo, self.retry_signatures.items.len);
        for (self.retry_signatures.items, 0..) |signature, i| {
            retry_transactions[i] = pending_transactions.get(signature) orelse {
                @panic("Retry transaction not found in pool");
            };
        }
        return .{ retry_transactions, pending_transactions_lg };
    }

    pub fn hasRetrySignatures(self: *TransactionPool) bool {
        return self.retry_signatures.items.len > 0;
    }

    pub fn addTransactions(self: *TransactionPool, transactions: []const TransactionInfo) !void {
        const pending_transactions: *PendingTransactions, var pending_transactions_lg =
            self.pending_transactions_rw.writeWithLock();
        defer pending_transactions_lg.unlock();
        for (transactions) |transaction| {
            if (pending_transactions.count() >= self.max_transactions) {
                return error.TransactionPoolFull;
            }
            try pending_transactions.put(transaction.signature, transaction);
        }
    }

    pub fn purge(self: *TransactionPool) void {
        const pending_transactions: *PendingTransactions, var pending_transactions_lg = self.pending_transactions_rw.writeWithLock();
        defer pending_transactions_lg.unlock();
        for (self.drop_signatures.items) |signature| {
            _ = pending_transactions.swapRemove(signature);
        }
        self.drop_signatures.clearRetainingCapacity();
        self.retry_signatures.clearRetainingCapacity();
    }
};
