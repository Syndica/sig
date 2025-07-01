const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const Channel = sig.sync.Channel;
const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const ThreadPool = sig.sync.ThreadPool;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const TransactionError = sig.ledger.transaction_status.TransactionError;

const AccountLocks = replay.account_locks.AccountLocks;
const ConfirmSlotStatus = replay.confirm_slot.ConfirmSlotStatus;
const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;
const ResolvedBatch = replay.resolve_lookup.ResolvedBatch;
const SvmSlot = replay.svm_gateway.SvmSlot;

const AccountSharedData = sig.runtime.AccountSharedData;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;
const TransactionRollbacks = sig.runtime.transaction_execution.TransactionRollbacks;

/// All contained state is required to be thread-safe.
pub const Committer = struct {
    accounts_db: *sig.accounts_db.AccountsDB,
    slot_state: *sig.core.SlotState,
    status_cache: *sig.core.StatusCache,

    pub fn commitTransactions(
        self: Committer,
        allocator: Allocator,
        slot: Slot,
        transactions: []const ResolvedTransaction,
        tx_results: []const struct { Hash, ProcessedTransaction },
        thread_id: i128,
    ) !void {
        // TODO: update stakes cache

        var rng = std.Random.DefaultPrng.init(slot + transactions.len);

        var accounts_to_store = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData).empty;

        var signature_count: usize = 0;
        var rent_collected: u64 = 0;

        std.debug.print("{} - checkpoint a\n", .{thread_id});
        for (transactions, tx_results) |transaction, result| {
            const message_hash, const tx_result = result;
            signature_count += transaction.transaction.signatures.len;

            // collect accounts to store
            switch (tx_result.accounts()) {
                inline else => |accounts| for (accounts) |account| {
                    const gop = try accounts_to_store.getOrPut(allocator, account.pubkey);
                    if (gop.found_existing) return error.AccountLockViolation;
                    gop.value_ptr.* = account.getAccount().*;
                },
            }
            std.debug.print("{} - checkpoint b\n", .{thread_id});

            switch (tx_result) {
                .executed => |exec| rent_collected += exec.loaded_accounts.rent_collected,
                else => {},
            }

            const recent_blockhash = &transaction.transaction.msg.recent_blockhash;
            const signature = transaction.transaction.signatures[0];
            try self.status_cache.insert(allocator, rng.random(), recent_blockhash, &message_hash.data, slot);
            try self.status_cache.insert(allocator, rng.random(), recent_blockhash, &signature.data, slot);
            // TODO: we'll need to store the actual status at some point, probably for rpc.
            std.debug.print("{} - checkpoint c\n", .{thread_id});
        }

        _ = self.slot_state.transaction_count.fetchAdd(tx_results.len, .monotonic);
        _ = self.slot_state.signature_count.fetchAdd(signature_count, .monotonic);
        _ = self.slot_state.collected_rent.fetchAdd(rent_collected, .monotonic);

        std.debug.print("{} - checkpoint d\n", .{thread_id});
        for (accounts_to_store.keys(), accounts_to_store.values()) |pubkey, account| {
            const result = self.accounts_db.putAccount(slot, pubkey, account);
            if (result) |_| {} else |err| {
                std.debug.print("putAccount FAIL: {}", .{err});
                return err;
            }
            std.debug.print("{} - checkpoint e\n", .{thread_id});
        }
        std.debug.print("{} - checkpoint f\n", .{thread_id});
    }
};
