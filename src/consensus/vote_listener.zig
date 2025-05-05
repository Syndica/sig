const std = @import("std");
const sig = @import("../sig.zig");
const vote_parser = @import("vote_parser.zig");

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;

const Packet = sig.net.Packet;

/// Subset of root bank's data at a given epoch, wherein each field should be coherent all together.
pub const RootBankEpoch = struct {
    slot: Slot,
    schedule: sig.core.EpochSchedule,
    stakes: sig.core.stake.EpochStakeMap,

    pub const DEFAULT: RootBankEpoch = .{
        .slot = 0,
        .schedule = sig.core.EpochSchedule.DEFAULT,
        .stakes = .{},
    };
};

/// equivalent to agave's solana_gossip::cluster_info::GOSSIP_SLEEP_MILLIS
const GOSSIP_SLEEP_MILLIS = 100 * std.time.ns_per_ms;

fn recvLoop(
    allocator: std.mem.Allocator,
    exit: sig.sync.ExitCondition,
    /// TODO: replace this with something that the current `RootBankEpoch`, or equivalent.
    root_bank_epoch: RootBankEpoch,
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    /// Sends to `processVotesLoop`'s `verified_vote_transactions_receiver` parameter.
    verified_vote_transactions_sender: *sig.sync.Channel(Transaction),
) !void {
    defer exit.afterExit();

    var unverified_votes_buffer: std.ArrayListUnmanaged(Transaction) = .{};
    defer unverified_votes_buffer.deinit(allocator);

    var cursor: u64 = 0;
    while (exit.shouldRun()) {
        const unverified_votes: []const Transaction = blk: {
            const gossip_table, var gossip_table_lg = gossip_table_rw.readWithLock();
            defer gossip_table_lg.unlock();
            cursor = try getVoteTransactionsAfterCursor(
                allocator,
                &unverified_votes_buffer,
                cursor,
                gossip_table,
            );
            break :blk unverified_votes_buffer.items;
        };

        // inc_new_counter_debug!("cluster_info_vote_listener-recv_count", votes.len());
        if (unverified_votes.len == 0) {
            std.time.sleep(GOSSIP_SLEEP_MILLIS);
            continue;
        }

        for (unverified_votes) |vote_tx| {
            switch (try verifyVoteTransaction(allocator, root_bank_epoch, vote_tx)) {
                .verified => try verified_vote_transactions_sender.send(vote_tx),
                .unverified => {},
            }
        }
    }
}

/// Returns the updated value for the insertion index cursor.
fn getVoteTransactionsAfterCursor(
    allocator: std.mem.Allocator,
    /// Cleared and then filled with the most recent vote transactions.
    unverified_votes_buffer: *std.ArrayListUnmanaged(Transaction),
    /// Insertion index in the gossip table to begin reading vote transaction from.
    start_cursor: u64,
    gossip_table: *const sig.gossip.GossipTable,
) std.mem.Allocator.Error!u64 {
    unverified_votes_buffer.clearRetainingCapacity();
    if (start_cursor >= gossip_table.cursor) return start_cursor;

    unverified_votes_buffer.clearRetainingCapacity();
    try unverified_votes_buffer.ensureTotalCapacityPrecise(
        allocator,
        gossip_table.cursor - start_cursor,
    );

    var new_cursor = start_cursor;

    // TODO: this seems like it might be a lot of unnecessary array hash map
    // lookups, would be good if we did have an ordered map that could directly
    // offer a way to iterate over a range of values without needing to check
    // every single value in that range.
    for (start_cursor..gossip_table.cursor) |insertion_index| {
        const store_index = gossip_table.votes.get(insertion_index) orelse continue;
        _, const vote = gossip_table.store.getByIndex(store_index).data.Vote;
        unverified_votes_buffer.appendAssumeCapacity(vote.transaction);
        new_cursor = @max(new_cursor, insertion_index + 1);
    }

    return new_cursor;
}

/// NOTE: in the original agave code, this was an inline part of the `verifyVotes` function which took in a list
/// of transactions to verify, and returned the same list with the unverified votes filtered out.
/// We separate it out
fn verifyVoteTransaction(
    allocator: std.mem.Allocator,
    root_bank_epoch: RootBankEpoch,
    vote_tx: Transaction,
) (std.mem.Allocator.Error || Transaction.VerifyError)!enum { verified, unverified } {
    vote_tx.verify() catch return .unverified;
    const parsed_vote =
        try vote_parser.parseVoteTransaction(allocator, vote_tx) orelse return .unverified;
    defer parsed_vote.deinit(allocator);

    const vote_account_key = parsed_vote.key;
    const vote = parsed_vote.vote;

    const slot = vote.lastVotedSlot() orelse return .unverified;
    const epoch = root_bank_epoch.schedule.getEpoch(slot);
    const authorized_voter: Pubkey = blk: {
        const epoch_stakes = root_bank_epoch.stakes.get(epoch) orelse return .unverified;
        const epoch_authorized_voters = &epoch_stakes.epoch_authorized_voters;
        break :blk epoch_authorized_voters.get(vote_account_key) orelse return .unverified;
    };

    const any_key_is_both_signer_and_authorized_voter = for (
        vote_tx.msg.account_keys,
        0..,
    ) |key, i| {
        const is_signer = vote_tx.msg.isSigner(i);
        const is_authorized_voter = key.equals(&authorized_voter);
        if (is_signer and is_authorized_voter) break true;
    } else false;
    if (!any_key_is_both_signer_and_authorized_voter) return .unverified;

    return .verified;
}

// TODO: port applicable tests from https://github.com/anza-xyz/agave/blob/182823ee353ee64fde230dbad96d8e24b6cd065a/core/src/cluster_info_vote_listener.rs

test verifyVoteTransaction {
    try std.testing.expectEqual(.unverified, verifyVoteTransaction(
        std.testing.allocator,
        RootBankEpoch.DEFAULT,
        Transaction.EMPTY,
    ));
}
