const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");

const socket_utils = sig.net.socket_utils;

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);
const UdpSocket = network.Socket;

const Packet = sig.net.Packet;
const Slot = sig.core.Slot;
const RwMux = sig.sync.RwMux;
const Signature = sig.core.Signature;
const Channel = sig.sync.Channel;
const Instant = sig.time.Instant;
const GossipTable = sig.gossip.GossipTable;
const RpcClient = sig.rpc.Client;
const Logger = sig.trace.log.Logger;
const Config = sig.transaction_sender.Config;
const LeaderInfo = sig.transaction_sender.LeaderInfo;
const TransactionInfo = sig.transaction_sender.TransactionInfo;

/// Pool to keep track of pending transactions, transactions are added to the
/// pool after they are received off the incomming channel, and removed when
/// they are confirmed, failed, timed out, or reach the max retries.
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

    pub fn contains(self: *TransactionPool, signature: Signature) bool {
        const pts: *const PendingTransactions, var lock = self.pending_transactions.readWithLock();
        defer lock.unlock();
        return pts.contains(signature);
    }

    pub fn readSignaturesAndTransactionsWithLock(self: *TransactionPool) struct { []const Signature, []const TransactionInfo, RwMux(PendingTransactions).RLockGuard } {
        const pts: *const PendingTransactions, const lock = self.pending_transactions.readWithLock();
        return .{ pts.keys(), pts.values(), lock };
    }

    pub fn hasRetryTransactions(self: *TransactionPool) bool {
        return self.retry_signatures.items.len > 0;
    }

    pub fn getRetryTransactions(self: *TransactionPool, allocator: Allocator) ![]const TransactionInfo {
        const pts: *const PendingTransactions, var lock = self.pending_transactions.readWithLock();
        defer lock.unlock();
        var retry_transactions = try allocator.alloc(TransactionInfo, self.retry_signatures.items.len);
        for (self.retry_signatures.items, 0..) |signature, i| {
            retry_transactions[i] = pts.get(signature) orelse {
                @panic("Retry transaction not found in pool");
            };
        }
        return retry_transactions;
    }

    pub fn addMany(self: *TransactionPool, transactions: []TransactionInfo) !void {
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
        if (self.retry_signatures.items.len > 0) {
            self.retry_signatures.clearRetainingCapacity();
        }

        if (self.drop_signatures.items.len > 0) {
            const pts: *PendingTransactions, var lock = self.pending_transactions.writeWithLock();
            defer lock.unlock();
            for (self.drop_signatures.items) |signature| {
                _ = pts.swapRemove(signature);
            }
            self.drop_signatures.clearRetainingCapacity();
        }
    }
};
