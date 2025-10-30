const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const Logger = sig.trace.Logger("replay.committer");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Transaction = sig.core.Transaction;

const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;

const AccountSharedData = sig.runtime.AccountSharedData;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;

const vote_listener = sig.consensus.vote_listener;
const ParsedVote = vote_listener.vote_parser.ParsedVote;

const Channel = sig.sync.Channel;

const Committer = @This();

// All contained state is required to be thread-safe.
logger: Logger,
account_store: sig.accounts_db.AccountStore,
slot_state: *sig.core.SlotState,
status_cache: *sig.core.StatusCache,
stakes_cache: *sig.core.StakesCache,
new_rate_activation_epoch: ?sig.core.Epoch,
replay_votes_sender: *Channel(ParsedVote),

pub fn commitTransactions(
    self: Committer,
    allocator: Allocator,
    slot: Slot,
    transactions: []const ResolvedTransaction,
    tx_results: []const struct { Hash, ProcessedTransaction },
) !void {
    var zone = tracy.Zone.init(@src(), .{ .name = "commitTransactions" });
    zone.value(transactions.len);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    var rng = std.Random.DefaultPrng.init(slot + transactions.len);

    var accounts_to_store = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData).empty;
    defer accounts_to_store.deinit(allocator);

    var signature_count: usize = 0;
    var rent_collected: u64 = 0;

    var transaction_fees: u64 = 0;
    var priority_fees: u64 = 0;

    for (transactions, tx_results) |transaction, result| {
        const message_hash, const tx_result = result;
        signature_count += transaction.transaction.signatures.len;

        // collect accounts to store
        switch (tx_result.accounts()) {
            .all_loaded => |accounts| {
                for (accounts, transaction.accounts.items(.is_writable)) |account, is_writable|
                    if (is_writable)
                        try putAccount(allocator, self.logger, &accounts_to_store, account);
            },
            .written => |accounts| {
                for (accounts) |account|
                    try putAccount(allocator, self.logger, &accounts_to_store, account);
            },
        }

        switch (tx_result) {
            .executed => |exec| {
                rent_collected += exec.loaded_accounts.rent_collected;
                transaction_fees += exec.fees.transaction_fee;
                priority_fees += exec.fees.prioritization_fee;
                // Skip non successful or non vote transactions.
                if (exec.executed_transaction.err == null and
                    isSimpleVoteTransaction(transaction.transaction))
                {
                    if (try vote_listener.vote_parser.parseSanitizedVoteTransaction(
                        allocator,
                        transaction,
                    )) |parsed| {
                        if (parsed.vote.lastVotedSlot() != null) {
                            self.replay_votes_sender.send(parsed) catch parsed.deinit(allocator);
                        } else {
                            parsed.deinit(allocator);
                        }
                    }
                }
            },
            .fees_only => |fees| {
                transaction_fees += fees.fees.transaction_fee;
                priority_fees += fees.fees.prioritization_fee;
            },
        }

        const recent_blockhash = &transaction.transaction.msg.recent_blockhash;
        const signature = transaction.transaction.signatures[0];
        try self.status_cache.insert(
            allocator,
            rng.random(),
            recent_blockhash,
            &message_hash.data,
            slot,
        );
        try self.status_cache.insert(
            allocator,
            rng.random(),
            recent_blockhash,
            &signature.toBytes(),
            slot,
        );
        // NOTE: we'll need to store the actual status at some point, probably for rpc.
    }

    _ = self.slot_state.collected_transaction_fees.fetchAdd(transaction_fees, .monotonic);
    _ = self.slot_state.collected_priority_fees.fetchAdd(priority_fees, .monotonic);
    _ = self.slot_state.transaction_count.fetchAdd(tx_results.len, .monotonic);
    _ = self.slot_state.signature_count.fetchAdd(signature_count, .monotonic);
    _ = self.slot_state.collected_rent.fetchAdd(rent_collected, .monotonic);

    for (accounts_to_store.keys(), accounts_to_store.values()) |pubkey, account| {
        try self.stakes_cache.checkAndStore(
            allocator,
            pubkey,
            account,
            self.new_rate_activation_epoch,
        );
        try self.account_store.put(slot, pubkey, account);
    }
}

fn isSimpleVoteTransaction(tx: Transaction) bool {
    const msg = tx.msg;
    if (msg.instructions.len == 0) return false;
    const ix = msg.instructions[0];
    if (ix.program_index >= msg.account_keys.len) return false;
    return sig.runtime.program.vote.ID.equals(&msg.account_keys[ix.program_index]);
}

fn putAccount(
    allocator: Allocator,
    logger: Logger,
    accounts_to_store: *std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
    /// CachedAccount or CopiedAccount
    account: anytype,
) error{ OutOfMemory, MultipleWritesInBatch }!void {
    const gop = try accounts_to_store.getOrPut(allocator, account.pubkey);
    if (gop.found_existing) {
        logger.err().logf("multiple writes in a batch for address: {}\n", .{account.pubkey});
        // this error probably indicates a bug in the SVM or the account locking
        // code, since the account locks should have already been checked before
        // reaching this point.
        return error.MultipleWritesInBatch;
    }
    gop.value_ptr.* = account.getAccount().*;
}
