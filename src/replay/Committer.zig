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

const Committer = @This();

logger: Logger,
slot_state: *sig.core.SlotState,
status_cache: *sig.core.StatusCache,
stakes_cache: *sig.core.StakesCache,
new_rate_activation_epoch: ?sig.core.Epoch,
replay_votes_sender: ?*Channel(ParsedVote),

pub fn commitTransaction(
    self: Committer,
    allocator: Allocator,
    slot: Slot,
    resolved: *const ResolvedTransaction,
    hash: *const Hash,
    result: *const ProcessedTransaction,
) !void {
    var zone = tracy.Zone.init(@src(), .{ .name = "commitTransaction" });
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    var rng = std.Random.DefaultPrng.init(slot);

    var accounts_to_store = sig.utils.collections.PubkeyMap(LoadedAccount).empty;
    defer accounts_to_store.deinit(allocator);

    var signature_count: usize = 0;
    var rent_collected: u64 = 0;

    var transaction_fees: u64 = 0;
    var priority_fees: u64 = 0;

    for (result.writes.slice()) |account| {
        try accounts_to_store.put(allocator, account.pubkey, account);
    }
    signature_count += resolved.transaction.signatures.len;
    transaction_fees += result.fees.transaction_fee;
    priority_fees += result.fees.prioritization_fee;

    if (result.outputs != null) {
        rent_collected += result.rent;

        // Skip non successful or non vote transactions.
        // Only send votes if consensus is enabled (sender exists)
        if (self.replay_votes_sender) |sender| {
            if (result.err == null and isSimpleVoteTransaction(resolved.transaction)) {
                if (try parseSanitizedVoteTransaction(allocator, resolved)) |parsed| {
                    if (parsed.vote.lastVotedSlot() != null) {
                        sender.send(parsed) catch parsed.deinit(allocator);
                    } else {
                        parsed.deinit(allocator);
                    }
                }
            }
        }
    }

    const recent_blockhash = &resolved.transaction.msg.recent_blockhash;
    const signature = resolved.transaction.signatures[0];
    try self.status_cache.insert(
        allocator,
        rng.random(),
        recent_blockhash,
        &hash.data,
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

    _ = self.slot_state.collected_transaction_fees.fetchAdd(transaction_fees, .monotonic);
    _ = self.slot_state.collected_priority_fees.fetchAdd(priority_fees, .monotonic);
    _ = self.slot_state.transaction_count.fetchAdd(1, .monotonic);
    _ = self.slot_state.signature_count.fetchAdd(signature_count, .monotonic);
    _ = self.slot_state.collected_rent.fetchAdd(rent_collected, .monotonic);

    for (accounts_to_store.values()) |account| {
        try self.stakes_cache.checkAndStore(
            allocator,
            account.pubkey,
            account.account,
            self.new_rate_activation_epoch,
        );
    }
}

fn isSimpleVoteTransaction(tx: Transaction) bool {
    const msg = tx.msg;
    if (msg.instructions.len == 0) return false;
    const ix = msg.instructions[0];
    if (ix.program_index >= msg.account_keys.len) return false;
    return sig.runtime.program.vote.ID.equals(&msg.account_keys[ix.program_index]);
}
