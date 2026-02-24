const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger("replay.committer");

const Hash = sig.core.Hash;
const Slot = sig.core.Slot;
const Transaction = sig.core.Transaction;

const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;

const LoadedAccount = sig.runtime.account_loader.LoadedAccount;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;

const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const parseSanitizedVoteTransaction =
    sig.consensus.vote_listener.vote_parser.parseSanitizedVoteTransaction;

const account_capture = replay.account_capture;

const Committer = @This();

logger: Logger,
slot_state: *sig.core.SlotState,
status_cache: *sig.core.StatusCache,
stakes_cache: *sig.core.StakesCache,
new_rate_activation_epoch: ?sig.core.Epoch,
replay_votes_sender: ?*Channel(ParsedVote),
account_capture_sender: account_capture.SenderField,

pub fn commitTransactions(
    self: Committer,
    persistent_allocator: Allocator,
    temp_allocator: Allocator,
    slot: Slot,
    transactions: []const ResolvedTransaction,
    tx_results: []const struct { Hash, ProcessedTransaction },
) !void {
    var zone = tracy.Zone.init(@src(), .{ .name = "commitTransactions" });
    zone.value(transactions.len);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    var rng = std.Random.DefaultPrng.init(slot + transactions.len);

    var accounts_to_store = sig.utils.collections.PubkeyMap(LoadedAccount).empty;
    defer accounts_to_store.deinit(temp_allocator);

    var signature_count: usize = 0;
    var rent_collected: u64 = 0;

    var transaction_fees: u64 = 0;
    var priority_fees: u64 = 0;

    for (transactions, tx_results) |transaction, *result| {
        const message_hash = &result.@"0";
        const tx_result = &result.@"1";

        signature_count += transaction.transaction.signatures.len;

        for (tx_result.writes.constSlice()) |*account| {
            try accounts_to_store.put(temp_allocator, account.pubkey, account.*);
        }
        transaction_fees += tx_result.fees.transaction_fee;
        priority_fees += tx_result.fees.prioritization_fee;

        // TODO: fix nesting, this sucks

        if (tx_result.outputs != null) {
            rent_collected += tx_result.rent;

            // Skip non successful or non vote transactions.
            // Only send votes if consensus is enabled (sender exists)
            if (self.replay_votes_sender) |sender| {
                if (tx_result.err == null and isSimpleVoteTransaction(transaction.transaction)) {
                    if (try parseSanitizedVoteTransaction(
                        persistent_allocator,
                        transaction,
                    )) |parsed| {
                        if (parsed.vote.lastVotedSlot() != null) {
                            sender.send(parsed) catch parsed.deinit(persistent_allocator);
                        } else {
                            parsed.deinit(persistent_allocator);
                        }
                    }
                }
            }
        }

        const recent_blockhash = &transaction.transaction.msg.recent_blockhash;
        const signature = transaction.transaction.signatures[0];
        {
            const status_cache_zone = tracy.Zone.init(
                @src(),
                .{ .name = "status_cache.insert: message_hash.data" },
            );
            defer status_cache_zone.deinit();

            try self.status_cache.insert(
                persistent_allocator,
                rng.random(),
                recent_blockhash,
                &message_hash.data,
                slot,
            );
        }
        {
            const status_cache_zone = tracy.Zone.init(
                @src(),
                .{ .name = "status_cache.insert: signature.toBytes()" },
            );
            defer status_cache_zone.deinit();

            try self.status_cache.insert(
                persistent_allocator,
                rng.random(),
                recent_blockhash,
                &signature.toBytes(),
                slot,
            );
        }
        // NOTE: we'll need to store the actual status at some point, probably for rpc.
    }

    _ = self.slot_state.collected_transaction_fees.fetchAdd(transaction_fees, .monotonic);
    _ = self.slot_state.collected_priority_fees.fetchAdd(priority_fees, .monotonic);
    _ = self.slot_state.transaction_count.fetchAdd(tx_results.len, .monotonic);
    _ = self.slot_state.signature_count.fetchAdd(signature_count, .monotonic);
    _ = self.slot_state.collected_rent.fetchAdd(rent_collected, .monotonic);

    for (accounts_to_store.values()) |account| {
        try self.stakes_cache.checkAndStore(
            persistent_allocator,
            account.pubkey,
            account.account,
            self.new_rate_activation_epoch,
        );
    }

    // Capture modified accounts for offline analysis / load testing.
    // When `account_capture.enable` is false, this entire block is comptime-eliminated.
    if (account_capture.enable) {
        if (self.account_capture_sender) |sender| {
            for (accounts_to_store.keys(), accounts_to_store.values()) |pubkey, loaded| {
                const data_copy = persistent_allocator.dupe(u8, loaded.account.data) catch continue;
                const captured: account_capture.CapturedAccount = .{
                    .slot = slot,
                    .pubkey = pubkey,
                    .lamports = loaded.account.lamports,
                    .owner = loaded.account.owner,
                    .executable = loaded.account.executable,
                    .rent_epoch = loaded.account.rent_epoch,
                    .data = data_copy,
                };
                if (!sender.trySend(captured)) {
                    persistent_allocator.free(data_copy);
                }
            }
        }
    }
}

fn isSimpleVoteTransaction(tx: Transaction) bool {
    const msg = tx.msg;
    if (msg.instructions.len == 0) return false;
    const ix = msg.instructions[0];
    if (ix.program_index >= msg.account_keys.len) return false;
    return sig.runtime.program.vote.ID.equals(&msg.account_keys[ix.program_index]);
}
