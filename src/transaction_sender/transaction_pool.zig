const std = @import("std");
const network = @import("zig-network");
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
    pending_transactions: RwMux(PendingTransactions),
    retry_signatures: std.ArrayList(Signature),
    drop_signatures: std.ArrayList(Signature),
    max_transactions: usize,

    const PendingTransactions = std.AutoArrayHashMap(Signature, TransactionInfo);

    pub fn init(allocator: Allocator, max_transactions: usize) TransactionPool {
        return .{
            .pending_transactions = RwMux(PendingTransactions).init(PendingTransactions.init(allocator)),
            .retry_signatures = std.ArrayList(Signature).init(allocator),
            .drop_signatures = std.ArrayList(Signature).init(allocator),
            .max_transactions = max_transactions,
        };
    }

    pub fn deinit(self: *TransactionPool) void {
        const pts: *PendingTransactions, var lock = self.pending_transactions.writeWithLock();
        defer lock.unlock();
        pts.deinit();
        self.retry_signatures.deinit();
        self.drop_signatures.deinit();
    }

    pub fn isEmpty(self: *TransactionPool) bool {
        const pts: *const PendingTransactions, var lock = self.pending_transactions.readWithLock();
        defer lock.unlock();
        return pts.count() == 0;
    }

    pub fn count(self: *TransactionPool) usize {
        const pts: *const PendingTransactions, var lock = self.pending_transactions.readWithLock();
        defer lock.unlock();
        return pts.count();
    }

    pub fn contains(self: *TransactionPool, signature: Signature) bool {
        const pts: *const PendingTransactions, var lock = self.pending_transactions.readWithLock();
        defer lock.unlock();
        return pts.contains(signature);
    }

    pub fn readSignaturesAndTransactionsWithLock(self: *TransactionPool) struct { []const Signature, []const TransactionInfo, RwMux(PendingTransactions).RLockGuard } {
        const pts: *const PendingTransactions, const lock = self.pending_transactions.readWithLock();
        return .{ pts.keys(), pts.values(), lock };
    }

    pub fn readRetryTransactionsWithLock(self: *TransactionPool, allocator: Allocator) !struct { []const TransactionInfo, RwMux(PendingTransactions).RLockGuard } {
        const pts: *const PendingTransactions, const lock = self.pending_transactions.readWithLock();
        var retry_transactions = try allocator.alloc(TransactionInfo, self.retry_signatures.items.len);
        for (self.retry_signatures.items, 0..) |signature, i| {
            retry_transactions[i] = pts.get(signature) orelse {
                @panic("Retry transaction not found in pool");
            };
        }
        return .{ retry_transactions, lock };
    }

    pub fn hasRetrySignatures(self: *TransactionPool) bool {
        return self.retry_signatures.items.len > 0;
    }

    pub fn addDropSignature(self: *TransactionPool, signature: Signature) !void {
        try self.drop_signatures.append(signature);
    }

    pub fn addRetrySignature(self: *TransactionPool, signature: Signature) !void {
        try self.retry_signatures.append(signature);
    }

    pub fn addTransactions(self: *TransactionPool, transactions: []TransactionInfo) !void {
        const pts: *PendingTransactions, var lock = self.pending_transactions.writeWithLock();
        defer lock.unlock();
        for (transactions) |transaction| {
            if (pts.count() >= self.max_transactions) {
                return error.TransactionPoolFull;
            }
            try pts.put(transaction.signature, transaction);
        }
    }

    pub fn purge(self: *TransactionPool) void {
        const pts: *PendingTransactions, var lock = self.pending_transactions.writeWithLock();
        defer lock.unlock();
        for (self.drop_signatures.items) |signature| {
            _ = pts.swapRemove(signature);
        }
        self.drop_signatures.clearRetainingCapacity();
        self.retry_signatures.clearRetainingCapacity();
    }
};