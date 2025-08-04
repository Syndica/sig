const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;

const AccountSharedData = sig.runtime.AccountSharedData;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;

/// All contained state is required to be thread-safe.
pub const Committer = struct {
    account_store: sig.accounts_db.AccountStore,
    slot_state: *sig.core.SlotState,
    status_cache: *sig.core.StatusCache,
    stakes_cache: *sig.core.StakesCache,

    pub fn commitTransactions(
        self: Committer,
        allocator: Allocator,
        slot: Slot,
        transactions: []const ResolvedTransaction,
        tx_results: []const struct { Hash, ProcessedTransaction },
    ) !void {
        var rng = std.Random.DefaultPrng.init(slot + transactions.len);

        var accounts_to_store = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData).empty;
        defer accounts_to_store.deinit(allocator);

        var signature_count: usize = 0;
        var rent_collected: u64 = 0;

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

            switch (tx_result) {
                .executed => |exec| rent_collected += exec.loaded_accounts.rent_collected,
                else => {},
            }

            const recent_blockhash = &transaction.transaction.msg.recent_blockhash;
            const signature = transaction.transaction.signatures[0];
            try self.status_cache
                .insert(allocator, rng.random(), recent_blockhash, &message_hash.data, slot);
            try self.status_cache
                .insert(allocator, rng.random(), recent_blockhash, &signature.data, slot);
            // TODO: we'll need to store the actual status at some point, probably for rpc.
        }

        _ = self.slot_state.transaction_count.fetchAdd(tx_results.len, .monotonic);
        _ = self.slot_state.signature_count.fetchAdd(signature_count, .monotonic);
        _ = self.slot_state.collected_rent.fetchAdd(rent_collected, .monotonic);

        for (accounts_to_store.keys(), accounts_to_store.values()) |pubkey, account| {
            // TODO: look into null value here
            try self.stakes_cache.checkAndStore(allocator, pubkey, account, null);
            try self.account_store.put(slot, pubkey, account);
        }
    }
};
