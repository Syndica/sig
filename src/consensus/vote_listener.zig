const std = @import("std");
const sig = @import("../sig.zig");
const vote_parser = @import("vote_parser.zig");

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;

const Packet = sig.net.Packet;

const VoteTransaction = sig.consensus.vote_transaction.VoteTransaction;
const VoteTracker = sig.consensus.VoteTracker;

pub const BankForksStub = struct {
    root_slot: Slot,
    banks: std.AutoArrayHashMapUnmanaged(Slot, BankStub),

    pub fn deinit(self: BankForksStub, allocator: std.mem.Allocator) void {
        var copy = self;
        for (self.banks.values()) |bank| {
            bank.deinit(allocator);
        }
        copy.banks.deinit(allocator);
    }

    pub fn getBank(self: *const BankForksStub, slot: Slot) ?BankStub {
        return self.banks.get(slot);
    }

    pub fn rootBank(self: *const BankForksStub) BankStub {
        return self.banks.get(self.root_slot).?; // root slot's bank must exist
    }

    pub fn bankHash(self: *const BankForksStub, slot: Slot) ?Hash {
        const bank = self.getBank(slot) orelse return null;
        return bank.hash;
    }

    pub fn bankHashOrNullIfFrozen(self: *const BankForksStub, slot: Slot) ?Hash {
        const hash = self.bankHash(slot) orelse return null;
        if (hash.eql(Hash.ZEROES)) return null;
        return hash;
    }

    pub const BankStub = struct {
        slot: Slot,
        /// If this is Hash.ZEROES, it means the bank isn't frozen.
        hash: Hash,
        ancestors: sig.core.bank.Ancestors,
        epoch_schedule: sig.core.EpochSchedule,
        epoch_stakes: sig.core.stake.EpochStakeMap,

        pub const DEFAULT_EMPTY_ZEROES: BankStub = .{
            .slot = 0,
            .hash = Hash.ZEROES,
            .ancestors = .{},
            .epoch_schedule = sig.core.EpochSchedule.DEFAULT,
            .epoch_stakes = .{},
        };

        pub fn deinit(self: BankStub, allocator: std.mem.Allocator) void {
            var copy = self;
            copy.ancestors.deinit(allocator);
            sig.core.stake.epochStakeMapDeinit(copy.epoch_stakes, allocator);
        }
    };
};

pub const ClusterInfoVoteListener = struct {
    recv: std.Thread,
    process_votes: std.Thread,

    pub fn new(
        allocator: std.mem.Allocator,
        exit: sig.sync.ExitCondition,
        logger: sig.trace.Logger,
        vote_tracker: *VoteTracker,
        params: struct {
            bank_forks_rw: *sig.sync.RwMux(BankForksStub),
            gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
            ledger_db: if (TODO_CONFIRMATION_VERIFIER) *sig.ledger.BlockstoreDB else void,
            subscriptions: RpcSubscriptionsStub,

            /// Channels that will be used to `receive` data.
            receivers: struct {
                replay_votes: *ReplayVoteReceiver,
            },

            /// Channels that will be used to `send` data.
            senders: struct {
                verified_vote: *VerifiedVoteSender,
                gossip_verified_vote_hash: *GossipVerifiedVoteHashChannel,
                bank_notification: ?*BankNotificationChannel,
                duplicate_confirmed_slot: *DuplicateConfirmedSlotsSender,
            },
        },
    ) !ClusterInfoVoteListener {
        // const verified_vote_transactions_sender, const verified_vote_transactions_receiver = unbounded();
        const verified_vote_transactions = try VerifiedVoteTransactionsReceiver.create(allocator);
        defer verified_vote_transactions.destroy();

        const recv_thread = try std.Thread.spawn(.{}, recvLoop, .{
            allocator,
            exit,
            params.bank_forks_rw,
            params.gossip_table_rw,
            verified_vote_transactions,
        });
        errdefer recv_thread.join();
        recv_thread.setName("solCiVoteLstnr") catch {};

        const process_votes_thread = try std.Thread.spawn(.{}, processVotesLoop, .{
            allocator,
            logger,
            exit,

            vote_tracker,
            params.ledger_db,
            params.bank_forks_rw,

            verified_vote_transactions,
            params.receivers.replay_votes,

            params.subscriptions,
            params.senders.gossip_verified_vote_hash,
            params.senders.verified_vote,
            params.senders.bank_notification,
            params.senders.duplicate_confirmed_slot,
        });
        errdefer process_votes_thread.join();
        process_votes_thread.setName("solCiProcVotes") catch {};

        return .{
            .recv = recv_thread,
            .process_votes = process_votes_thread,
        };
    }

    pub fn join(self: ClusterInfoVoteListener) void {
        self.recv.join();
        self.process_votes.join();
    }
};

test ClusterInfoVoteListener {
    const allocator = std.testing.allocator;

    var vote_tracker = VoteTracker.EMPTY;
    defer vote_tracker.deinit(allocator);

    var bank_forks_rw = sig.sync.RwMux(BankForksStub).init(.{
        .root_slot = 0,
        .banks = .{},
    });
    defer {
        const bank_forks, _ = bank_forks_rw.writeWithLock();
        bank_forks.deinit(allocator);
    }

    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(
        try sig.gossip.GossipTable.init(allocator, allocator),
    );
    defer {
        const gossip_table, _ = gossip_table_rw.writeWithLock();
        gossip_table.deinit();
    }

    const replay_votes_channel = try ReplayVoteReceiver.create(allocator);
    defer replay_votes_channel.destroy();

    const verified_vote_channel = try VerifiedVoteSender.create(allocator);
    defer verified_vote_channel.destroy();

    const gossip_verified_vote_hash_channel = try GossipVerifiedVoteHashChannel.create(allocator);
    defer gossip_verified_vote_hash_channel.destroy();

    const bank_notification_channel = try BankNotificationChannel.create(allocator);
    defer bank_notification_channel.destroy();

    const duplicate_confirmed_slot_channel = try DuplicateConfirmedSlotsSender.create(allocator);
    defer duplicate_confirmed_slot_channel.destroy();

    var exit = std.atomic.Value(bool).init(false);
    const exit_cond: sig.sync.ExitCondition = .{ .unordered = &exit };
    const civl = try ClusterInfoVoteListener.new(allocator, exit_cond, .noop, &vote_tracker, .{
        .bank_forks_rw = &bank_forks_rw,
        .gossip_table_rw = &gossip_table_rw,
        .ledger_db = {},
        .subscriptions = .{},
        .receivers = .{
            .replay_votes = replay_votes_channel,
        },
        .senders = .{
            .verified_vote = verified_vote_channel,
            .gossip_verified_vote_hash = gossip_verified_vote_hash_channel,
            .bank_notification = bank_notification_channel,
            .duplicate_confirmed_slot = duplicate_confirmed_slot_channel,
        },
    });
    defer civl.join();
    defer exit_cond.setExit();
}

/// equivalent to agave's solana_gossip::cluster_info::GOSSIP_SLEEP_MILLIS
const GOSSIP_SLEEP_MILLIS = 100 * std.time.ns_per_ms;

fn recvLoop(
    allocator: std.mem.Allocator,
    exit: sig.sync.ExitCondition,
    /// TODO: replace this with something that the current `RootBankEpoch`, or equivalent.
    bank_forks_rw: *sig.sync.RwMux(BankForksStub),
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

        const bank_forks, var bank_forks_lg = bank_forks_rw.readWithLock();
        defer bank_forks_lg.unlock();

        const root_bank = bank_forks.rootBank();
        const epoch_schedule = root_bank.epoch_schedule;

        for (unverified_votes) |vote_tx| {
            switch (try verifyVoteTransaction(allocator, vote_tx, .{
                .root_bank = root_bank,
                .epoch_schedule = epoch_schedule,
            })) {
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
    // every single value in that range, like a btree map.
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
    vote_tx: Transaction,
    bank_forks: struct {
        /// Should be `bank_forks.rootBank()`
        root_bank: BankForksStub.BankStub,
        /// Should be `bank_forks.rootBank().epoch_schedule`
        epoch_schedule: sig.core.EpochSchedule,
    },
) std.mem.Allocator.Error!enum { verified, unverified } {
    const root_bank = bank_forks.root_bank;
    const epoch_schedule = bank_forks.epoch_schedule;

    vote_tx.verify() catch return .unverified;
    const parsed_vote =
        try vote_parser.parseVoteTransaction(allocator, vote_tx) orelse return .unverified;
    defer parsed_vote.deinit(allocator);

    const vote_account_key = parsed_vote.key;
    const vote = parsed_vote.vote;

    const slot = vote.lastVotedSlot() orelse return .unverified;
    const epoch = epoch_schedule.getEpoch(slot);
    const authorized_voter: Pubkey = blk: {
        const epoch_stakes = root_bank.epoch_stakes.get(epoch) orelse return .unverified;
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
        Transaction.EMPTY,
        .{
            .root_bank = BankForksStub.BankStub.DEFAULT_EMPTY_ZEROES,
            .epoch_schedule = sig.core.EpochSchedule.DEFAULT,
        },
    ));
}

const ThresholdConfirmedSlot = struct { Slot, Hash };
const GossipVerifiedVoteHashChannel = sig.sync.Channel(struct { Pubkey, Slot, Hash });
const VerifiedVoteSender = sig.sync.Channel(struct { Pubkey, []const Slot });
const DuplicateConfirmedSlotsSender = sig.sync.Channel(ThresholdConfirmedSlot);
const ReplayVoteReceiver = sig.sync.Channel(vote_parser.ParsedVote);
const VerifiedVoteTransactionsReceiver = sig.sync.Channel(Transaction);
const BankNotificationChannel = sig.sync.Channel(BankNotification);

/// The expected duration of a slot (400 milliseconds).
const DEFAULT_MS_PER_SLOT: u64 =
    1_000 *
    sig.core.time.DEFAULT_TICKS_PER_SLOT /
    sig.core.time.DEFAULT_TICKS_PER_SECOND;

const TODO_CONFIRMATION_VERIFIER = false;

fn processVotesLoop(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    exit: sig.sync.ExitCondition,
    vote_tracker: *VoteTracker,
    ledger_db: if (TODO_CONFIRMATION_VERIFIER) *sig.ledger.BlockstoreDB else void,
    bank_forks_rw: *sig.sync.RwMux(BankForksStub),

    // channel
    gossip_vote_txs_receiver: *VerifiedVoteTransactionsReceiver,
    replay_votes_receiver: *ReplayVoteReceiver,

    // listeners
    subscriptions: RpcSubscriptionsStub,
    gossip_verified_vote_hash_sender: *GossipVerifiedVoteHashChannel,
    verified_vote_sender: *VerifiedVoteSender,
    bank_notification_sender: ?*BankNotificationChannel,
    duplicate_confirmed_slot_sender: *DuplicateConfirmedSlotsSender,
) !void {
    defer exit.afterExit();

    var confirmation_verifier = if (TODO_CONFIRMATION_VERIFIER)
        OptimisticConfirmationVerifier.new(blk: {
            const bank_forks, var bank_forks_lg = bank_forks_rw.readWithLock();
            defer bank_forks_lg.unlock();
            // TODO: this is effectively what the agave code does, but could it just be `bank_forks.root_slot`?
            break :blk bank_forks.rootBank().slot;
        });

    var latest_vote_slot_per_validator: std.AutoArrayHashMapUnmanaged(Pubkey, Slot) = .{};
    defer latest_vote_slot_per_validator.deinit(allocator);

    var last_process_root = sig.time.Instant.now();

    var vote_processing_time = VoteProcessingTiming.ZEROES;

    while (true) {
        if (exit.shouldExit()) return;

        const root_bank = blk: {
            const bank_forks, var bank_forks_lg = bank_forks_rw.readWithLock();
            defer bank_forks_lg.unlock();
            break :blk bank_forks.rootBank();
        };

        if (last_process_root.elapsed().asMillis() > DEFAULT_MS_PER_SLOT) {
            if (TODO_CONFIRMATION_VERIFIER) {
                const unrooted_optimistic_slots = confirmation_verifier
                    .verify_for_unrooted_optimistic_slots(&root_bank, ledger_db);
                // SlotVoteTracker's for all `slots` in `unrooted_optimistic_slots`
                // should still be available because we haven't purged in
                // `progress_with_new_root_bank()` yet, which is called below
                OptimisticConfirmationVerifier.log_unrooted_optimistic_slots(
                    &root_bank,
                    &vote_tracker,
                    &unrooted_optimistic_slots,
                );
            }
            vote_tracker.progressWithNewRootBank(allocator, root_bank.slot);
            last_process_root = sig.time.Instant.now();
        }

        var confirmed_slots = listenAndConfirmVotes(
            allocator,
            logger,
            gossip_vote_txs_receiver,
            vote_tracker,
            &root_bank,
            subscriptions,
            gossip_verified_vote_hash_sender,
            verified_vote_sender,
            replay_votes_receiver,
            bank_notification_sender,
            duplicate_confirmed_slot_sender,
            &vote_processing_time,
            &latest_vote_slot_per_validator,
            bank_forks_rw,
        ) catch |err| switch (err) {
            error.RecvTimeoutDisconnected => {
                return;
            },
            error.ReadyTimeout => continue,
            else => |e| {
                logger.err().logf("thread {} error {s}", .{
                    std.Thread.getCurrentId(),
                    @errorName(e),
                });
                continue;
            },
        };
        defer confirmed_slots.deinit(allocator);

        if (TODO_CONFIRMATION_VERIFIER) {
            confirmation_verifier.add_new_optimistic_confirmed_slots(confirmed_slots, ledger_db);
        }

        // NOTE: keep this around for reference while I'm figuring it out

        // match confirmed_slots {
        //     Ok(confirmed_slots) => {
        //         confirmation_verifier
        //             .add_new_optimistic_confirmed_slots(confirmed_slots.clone(), &blockstore);
        //     }
        //     Err(e) => match e {
        //         Error::RecvTimeout(RecvTimeoutError::Disconnected) => {
        //             return Ok(());
        //         }
        //         Error::ReadyTimeout => (),
        //         _ => {
        //             error!("thread {:?} error {:?}", thread::current().name(), e);
        //         }
        //     },
        // }
    }
}

/// TODO: remove this
const TodoErrorSet = error{TODO};
const ListenAndConfirmVotesError = error{
    RecvTimeoutDisconnected,
    ReadyTimeout,
} || std.mem.Allocator.Error;

fn listenAndConfirmVotes(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    gossip_vote_txs_receiver: *VerifiedVoteTransactionsReceiver,
    vote_tracker: *VoteTracker,
    root_bank: *const BankForksStub.BankStub,
    subscriptions: RpcSubscriptionsStub,
    gossip_verified_vote_hash_sender: *GossipVerifiedVoteHashChannel,
    verified_vote_sender: *VerifiedVoteSender,
    replay_votes_receiver: *ReplayVoteReceiver,
    bank_notification_sender: ?*BankNotificationChannel,
    duplicate_confirmed_slot_sender: ?*DuplicateConfirmedSlotsSender,
    vote_processing_time: ?*VoteProcessingTiming,
    latest_vote_slot_per_validator: *std.AutoArrayHashMapUnmanaged(Pubkey, Slot),
    bank_forks: *sig.sync.RwMux(BankForksStub),
) ListenAndConfirmVotesError!std.ArrayListUnmanaged(ThresholdConfirmedSlot) {
    var gossip_vote_txs_buffer: std.ArrayListUnmanaged(Transaction) = .{};
    defer gossip_vote_txs_buffer.deinit(allocator);
    try gossip_vote_txs_buffer.ensureTotalCapacityPrecise(allocator, 4096);

    var replay_votes_buffer: std.ArrayListUnmanaged(vote_parser.ParsedVote) = .{};
    defer replay_votes_buffer.deinit(allocator);
    try replay_votes_buffer.ensureTotalCapacityPrecise(allocator, 4096);

    var remaining_wait_time = sig.time.Duration.fromMillis(200);
    while (remaining_wait_time.gt(sig.time.Duration.zero())) {
        const start = sig.time.Instant.now();
        defer remaining_wait_time = remaining_wait_time.saturatingSub(start.elapsed());

        const gossip_vote_txs: []const Transaction = blk: {
            gossip_vote_txs_buffer.clearRetainingCapacity();
            while (gossip_vote_txs_receiver.tryReceive()) |tx| {
                gossip_vote_txs_buffer.appendAssumeCapacity(tx);
                if (gossip_vote_txs_buffer.unusedCapacitySlice().len == 0) break;
            }
            break :blk gossip_vote_txs_buffer.items;
        };

        const replay_votes: []const vote_parser.ParsedVote = blk: {
            replay_votes_buffer.clearRetainingCapacity();
            while (replay_votes_receiver.tryReceive()) |vote| {
                replay_votes_buffer.appendAssumeCapacity(vote);
                if (gossip_vote_txs_buffer.unusedCapacitySlice().len == 0) break;
            }
            break :blk replay_votes_buffer.items;
        };

        if (gossip_vote_txs.len == 0 and replay_votes.len == 0) {
            continue;
        }

        return try filterAndConfirmWithNewVotes(
            allocator,
            logger,
            vote_tracker,
            gossip_vote_txs,
            replay_votes,
            root_bank,
            subscriptions,
            gossip_verified_vote_hash_sender,
            verified_vote_sender,
            bank_notification_sender,
            duplicate_confirmed_slot_sender,
            vote_processing_time,
            latest_vote_slot_per_validator,
            bank_forks,
        );
    }

    return .{};
}

fn filterAndConfirmWithNewVotes(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    vote_tracker: *VoteTracker,
    gossip_vote_txs: []const Transaction,
    replayed_votes: []const vote_parser.ParsedVote,
    root_bank: *const BankForksStub.BankStub,
    subscriptions: RpcSubscriptionsStub,
    gossip_verified_vote_hash_sender: *GossipVerifiedVoteHashChannel,
    verified_vote_sender: *VerifiedVoteSender,
    bank_notification_sender: ?*BankNotificationChannel,
    duplicate_confirmed_slot_sender: ?*DuplicateConfirmedSlotsSender,
    vote_processing_time: ?*VoteProcessingTiming,
    latest_vote_slot_per_validator: *std.AutoArrayHashMapUnmanaged(Pubkey, Slot),
    bank_forks: *sig.sync.RwMux(BankForksStub),
) std.mem.Allocator.Error!std.ArrayListUnmanaged(ThresholdConfirmedSlot) {
    var diff = SlotsDiff.EMPTY;
    defer diff.deinit(allocator);

    var new_optimistic_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .{};
    defer new_optimistic_confirmed_slots.deinit(allocator);

    // Process votes from gossip and ReplayStage

    // let mut gossip_vote_txn_processing_time = Measure::start("gossip_vote_processing_time");
    inline for (.{
        .{ gossip_vote_txs, true },
        .{ replayed_votes, false },
    }) |chain_item| {
        const txs_or_parsed_votes, const is_gossip = chain_item;
        for (txs_or_parsed_votes) |tx_or_parsed_vote| {
            const parsed_vote = if (is_gossip)
                try vote_parser.parseVoteTransaction(allocator, tx_or_parsed_vote) orelse continue
            else
                tx_or_parsed_vote;
            const vote_pubkey = parsed_vote.key;
            const vote = parsed_vote.vote;
            const signature = parsed_vote.signature;
            try trackNewVotesAndNotifyConfirmations(
                allocator,
                logger,
                vote,
                vote_pubkey,
                signature,
                vote_tracker,
                root_bank,
                subscriptions,
                verified_vote_sender,
                gossip_verified_vote_hash_sender,
                &diff,
                &new_optimistic_confirmed_slots,
                is_gossip,
                bank_notification_sender,
                duplicate_confirmed_slot_sender,
                latest_vote_slot_per_validator,
                bank_forks,
            );
        }
    }

    // gossip_vote_txn_processing_time.stop();
    // let gossip_vote_txn_processing_time_us = gossip_vote_txn_processing_time.as_us();

    // Process all the slots accumulated from replay and gossip.

    // let mut gossip_vote_slot_confirming_time = Measure::start("gossip_vote_slot_confirm_time");

    for (diff.map.keys(), diff.map.values()) |slot, *slot_diff| {
        const slot_tracker = try vote_tracker.getOrInsertSlotTracker(allocator, slot);
        defer slot_tracker.deinit(allocator);

        {
            const r_slot_tracker, var r_slot_tracker_lg = slot_tracker.tracker.readWithLock();
            defer r_slot_tracker_lg.unlock();

            // Only keep the pubkeys we haven't seen voting for this slot
            var start_idx: usize = 0;
            outer: while (start_idx != slot_diff.map.count()) {
                for (
                    slot_diff.map.keys()[start_idx..],
                    slot_diff.map.values()[start_idx..],
                    start_idx..,
                ) |pubkey, seen_in_gossip_above, i| {
                    const seen_in_gossip_previously = r_slot_tracker.voted.get(pubkey);
                    const is_new = seen_in_gossip_previously == null;
                    // `is_new_from_gossip` means we observed a vote for this slot
                    // for the first time in gossip
                    const is_new_from_gossip = !(seen_in_gossip_previously orelse false) and seen_in_gossip_above;
                    if (is_new or is_new_from_gossip) continue;
                    std.debug.assert(slot_diff.map.fetchSwapRemove(pubkey).?.key.equals(&pubkey));
                    start_idx = i;
                    continue :outer;
                }
            }
        }

        const w_slot_tracker, var w_slot_tracker_lg = slot_tracker.tracker.writeWithLock();
        defer w_slot_tracker_lg.unlock();
        if (w_slot_tracker.voted_slot_updates == null) {
            w_slot_tracker.voted_slot_updates = .{};
        }

        var gossip_only_stake: u64 = 0;
        const epoch = root_bank.epoch_schedule.getEpoch(slot);
        const epoch_stakes = root_bank.epoch_stakes.getPtr(epoch);

        const voted = &w_slot_tracker.voted;
        const voted_slot_updates = &w_slot_tracker.voted_slot_updates.?;
        try voted.ensureUnusedCapacity(allocator, slot_diff.map.count());
        try voted_slot_updates.ensureUnusedCapacity(allocator, slot_diff.map.count());
        for (slot_diff.map.keys(), slot_diff.map.values()) |pubkey, seen_in_gossip_above| {
            if (seen_in_gossip_above) {
                // By this point we know if the vote was seen in gossip above,
                // it was not seen in gossip at any point in the past (if it was seen
                // in gossip in the past, `is_new` would be false and it would have
                // been filtered out above), so it's safe to increment the gossip-only
                // stake
                sumStake(&gossip_only_stake, epoch_stakes, pubkey);
            }

            // From the `slot_diff.retain` earlier, we know because there are
            // no other writers to `slot_vote_tracker` that
            // `is_new || is_new_from_gossip`. In both cases we want to record
            // `is_new_from_gossip` for the `pubkey` entry.
            voted.putAssumeCapacity(pubkey, seen_in_gossip_above);
            voted_slot_updates.appendAssumeCapacity(pubkey);
        }

        w_slot_tracker.gossip_only_stake += gossip_only_stake;
    }
    // gossip_vote_slot_confirming_time.stop();
    // let gossip_vote_slot_confirming_time_us = gossip_vote_slot_confirming_time.as_us();

    if (vote_processing_time) |*vpt| {
        _ = vpt;
        // vote_processing_time.update(
        //     gossip_vote_txn_processing_time_us,
        //     gossip_vote_slot_confirming_time_us,
        // );
    }
    return new_optimistic_confirmed_slots;
}

const VoteProcessingTiming = struct {
    gossip_txn_processing_time_us: u64,
    gossip_slot_confirming_time_us: u64,
    last_report: AtomicInterval,

    pub const ZEROES: VoteProcessingTiming = .{
        .gossip_txn_processing_time_us = 0,
        .gossip_slot_confirming_time_us = 0,
        .last_report = AtomicInterval.ZERO,
    };

    fn reset(self: *VoteProcessingTiming) void {
        self.gossip_txn_processing_time_us = 0;
        self.gossip_slot_confirming_time_us = 0;
    }

    fn update(self: *VoteProcessingTiming, vote_txn_processing_time_us: u64, vote_slot_confirming_time_us: u64) void {
        self.gossip_txn_processing_time_us += vote_txn_processing_time_us;
        self.gossip_slot_confirming_time_us += vote_slot_confirming_time_us;

        const VOTE_PROCESSING_REPORT_INTERVAL_MS: u64 = 1_000;
        if (self.last_report.should_update(VOTE_PROCESSING_REPORT_INTERVAL_MS)) {
            // datapoint_info!(
            //     "vote-processing-timing",
            //     (
            //         "vote_txn_processing_us",
            //         self.gossip_txn_processing_time_us as i64,
            //         i64
            //     ),
            //     (
            //         "slot_confirming_time_us",
            //         self.gossip_slot_confirming_time_us as i64,
            //         i64
            //     ),
            // );
            self.reset();
        }
    }
};

const AtomicInterval = struct {
    last_update: std.atomic.Value(u64),

    pub const ZERO: AtomicInterval = .{ .last_update = std.atomic.Value(u64).init(0) };

    /// true if 'interval_time_ms' has elapsed since last time we returned true as long as it has been 'interval_time_ms' since this struct was created
    inline fn should_update(self: AtomicInterval, interval_time_ms: u64) bool {
        return self.should_update_ext(interval_time_ms, true);
    }

    /// a primary use case is periodic metric reporting, potentially from different threads
    /// true if 'interval_time_ms' has elapsed since last time we returned true
    /// except, if skip_first=false, false until 'interval_time_ms' has elapsed since this struct was created
    inline fn should_update_ext(self: AtomicInterval, interval_time_ms: u64, skip_first: bool) bool {
        const now: u64 = @intCast(std.time.timestamp());
        const last: u64 = @intCast(self.last_update.load(.monotonic));
        return now -| last > interval_time_ms and
            self.last_update.cmpxchgStrong(last, now, .monotonic, .monotonic) == last and
            !(skip_first and last == 0);
    }
};

pub const OptimisticConfirmationVerifier = struct {};

/// TODO: move this to its proper place or something
const BankNotification = union(enum) {
    optimistically_confirmed: Slot,
    frozen: if (false) sig.core.BankFields else noreturn,
    new_root_bank: if (false) sig.core.BankFields else noreturn,
    /// The newly rooted slot chain including the parent slot of the oldest bank in the rooted chain.
    new_rooted_chain: if (false) std.ArrayListUnmanaged(Slot) else noreturn,
};

const RpcSubscriptionsStub = struct {
    pub const NotificationEntry = union(enum) {
        slot: SlotInfo,
        slot_update: SlotUpdate,
        vote: struct { Pubkey, VoteTransaction, sig.core.Signature },
        root: Slot,
        bank: CommitmentSlots,
        gossip: Slot,
        signatures_received: struct { Slot, std.ArrayListUnmanaged(sig.core.Signature) },
        subscribed: if (true) noreturn else struct { SubscriptionParams, SubscriptionId },
        unsubscribed: if (true) noreturn else struct { SubscriptionParams, SubscriptionId },

        const SlotInfo = noreturn;
        const SlotUpdate = noreturn;
        const CommitmentSlots = noreturn;
        const SubscriptionParams = noreturn;
        const SubscriptionId = noreturn;
    };

    fn notifyVote(
        self: *const RpcSubscriptionsStub,
        vote_pubkey: Pubkey,
        vote: VoteTransaction,
        signature: sig.core.Signature,
    ) void {
        self.enqueue_notification(.{ .vote = .{ vote_pubkey, vote, signature } });
    }

    fn enqueue_notification(
        self: *const RpcSubscriptionsStub,
        notification_entry: NotificationEntry,
    ) void {
        _ = self;
        _ = notification_entry;
    }
};

const SlotsDiff = struct {
    map: std.AutoArrayHashMapUnmanaged(Slot, PubkeysDiff),

    pub const EMPTY: SlotsDiff = .{ .map = .{} };

    pub fn deinit(self: SlotsDiff, allocator: std.mem.Allocator) void {
        for (self.map.values()) |slot_diff| {
            slot_diff.deinit(allocator);
        }
        var map = self.map;
        map.deinit(allocator);
    }

    const PubkeysDiff = struct {
        map: std.AutoArrayHashMapUnmanaged(Pubkey, bool),

        pub const EMPTY: PubkeysDiff = .{ .map = .{} };

        pub fn deinit(self: PubkeysDiff, allocator: std.mem.Allocator) void {
            var map = self.map;
            map.deinit(allocator);
        }
    };
};

fn trackNewVotesAndNotifyConfirmations(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    vote: VoteTransaction,
    vote_pubkey: Pubkey,
    vote_transaction_signature: sig.core.Signature,
    vote_tracker: *VoteTracker,
    root_bank: *const BankForksStub.BankStub,
    subscriptions: RpcSubscriptionsStub,
    verified_vote_sender: *VerifiedVoteSender,
    gossip_verified_vote_hash_sender: *GossipVerifiedVoteHashChannel,
    diff: *SlotsDiff,
    new_optimistic_confirmed_slots: *std.ArrayListUnmanaged(ThresholdConfirmedSlot),
    is_gossip_vote: bool,
    bank_notification_sender: ?*BankNotificationChannel,
    duplicate_confirmed_slot_sender: ?*DuplicateConfirmedSlotsSender,
    latest_vote_slot_per_validator: *std.AutoArrayHashMapUnmanaged(Pubkey, Slot),
    bank_forks_rw: *sig.sync.RwMux(BankForksStub),
) !void {
    if (vote.isEmpty()) return;

    const last_vote_slot = vote.lastVotedSlot().?;
    const last_vote_hash = vote.getHash();

    const latest_vote_slot: *u64 = blk: {
        const gop = try latest_vote_slot_per_validator.getOrPut(allocator, vote_pubkey);
        latest_vote_slot_per_validator.lockPointers();

        if (!gop.found_existing) gop.value_ptr.* = 0;
        break :blk gop.value_ptr;
    };
    defer latest_vote_slot_per_validator.unlockPointers();

    const root = root_bank.slot;
    var is_new_vote = false;
    const vote_slots: []const Slot = blk: {
        const vote_slots = try allocator.alloc(Slot, vote.slotCount());
        errdefer allocator.free(vote_slots);
        vote.copyAllSlotsTo(vote_slots);
        break :blk vote_slots;
    };
    defer allocator.free(vote_slots);

    const accumulate_intermediate_votes = blk: {
        const bank_forks, var bank_forks_lg = bank_forks_rw.readWithLock();
        defer bank_forks_lg.unlock();

        if (bank_forks.bankHashOrNullIfFrozen(last_vote_slot)) |hash| {
            // Only accumulate intermediates if we have replayed the same version being voted on, as
            // otherwise we cannot verify the ancestry or the hashes.
            // NOTE: this can only be performed on full tower votes, until deprecate_legacy_vote_ixs feature
            // is active we must check the transaction type.
            break :blk hash.eql(last_vote_hash) and vote.isFullTowerVote();
        } else {
            // If we have not frozen the bank do not accumulate intermediate slots as we cannot verify
            // the hashes.
            break :blk false;
        }
    };

    // If slot is before the root, ignore it. Iterate from latest vote slot to earliest.
    for (0 + 1..vote_slots.len + 1) |fwd_index| {
        const rev_index = vote_slots.len - fwd_index;
        const slot = vote_slots[rev_index];
        if (slot <= root) continue;

        // if we don't have stake information, ignore it
        const epoch = root_bank.epoch_schedule.getEpoch(slot);
        const epoch_stakes = root_bank.epoch_stakes.get(epoch) orelse continue;

        // We always track the last vote slot for optimistic confirmation. If we have replayed
        // the same version of last vote slot that is being voted on, then we also track the
        // other votes in the proposed tower.
        if (slot == last_vote_slot or accumulate_intermediate_votes) {
            const vote_accounts = epoch_stakes.stakes.vote_accounts;
            const stake = vote_accounts.getDelegatedStake(vote_pubkey) orelse 0;
            const total_stake = epoch_stakes.total_stake;

            const maybe_hash: ?Hash = get_hash: {
                if (slot == last_vote_slot) break :get_hash last_vote_hash;
                const bank_forks, var bank_forks_lg = bank_forks_rw.readWithLock();
                defer bank_forks_lg.unlock();
                break :get_hash bank_forks.bankHashOrNullIfFrozen(last_vote_slot);
            };
            const hash: Hash = maybe_hash orelse {
                // In this case the supposed ancestor of this vote is missing. This can happen
                // if the ancestor has been pruned, or if this is a malformed vote. In either case
                // we do not track this slot for optimistic confirmation.
                continue;
            };

            // Fast track processing of the last slot in a vote transactions
            // so that notifications for optimistic confirmation can be sent
            // as soon as possible.
            const reached_threshold_results, //
            const is_new: bool //
            = try trackOptimisticConfirmationVote(allocator, vote_tracker, .{
                .slot = slot,
                .hash = hash,
                .pubkey = vote_pubkey,
                .stake = stake,
                .total_epoch_stake = total_stake,
            });

            if (is_gossip_vote and is_new and stake > 0) {
                gossip_verified_vote_hash_sender.send(.{ vote_pubkey, slot, hash }) catch {
                    // WARN: the original agave code does literally just ignore this error, is that fine?
                    // TODO: evaluate this
                };
            }

            if (reached_threshold_results.isSet(0)) {
                if (duplicate_confirmed_slot_sender) |sender| {
                    sender.send(.{ slot, hash }) catch {
                        // WARN: the original agave code does literally just ignore this error, is that fine?
                        // TODO: evaluate this
                    };
                }
            }

            if (reached_threshold_results.isSet(1)) {
                try new_optimistic_confirmed_slots.append(allocator, .{ slot, hash });
                // Notify subscribers about new optimistic confirmation
                if (bank_notification_sender) |sender| {
                    sender.send(.{ .optimistically_confirmed = slot }) catch |err| {
                        logger.warn().logf("bank_notification_sender failed: {s}", .{@errorName(err)});
                    };
                }
            }

            if (!is_new and !is_gossip_vote) {
                // By now:
                // 1) The vote must have come from ReplayStage,
                // 2) We've seen this vote from replay for this hash before
                // (`track_optimistic_confirmation_vote()` will not set `is_new == true`
                // for same slot different hash), so short circuit because this vote
                // has no new information

                // Note gossip votes will always be processed because those should be unique
                // and we need to update the gossip-only stake in the `VoteTracker`.
                return;
            }

            is_new_vote = is_new;
        }

        if (slot < latest_vote_slot.*) {
            // Important that we filter after the `last_vote_slot` check, as even if this vote
            // is old, we still need to track optimistic confirmations.
            // However it is fine to filter the rest of the slots for the propagated check tracking below,
            // as the propagated check is able to roll up votes for descendants unlike optimistic confirmation.
            continue;
        }

        if (diff.map.getPtr(slot)) |pubkey_diff| {
            try pubkey_diff.map.ensureUnusedCapacity(
                allocator,
                @intFromBool(!pubkey_diff.map.contains(vote_pubkey)),
            );
        }

        const slot_diff_gop = try diff.map.getOrPutValue(allocator, slot, SlotsDiff.PubkeysDiff.EMPTY);
        const pubkey_diff_gop = slot_diff_gop.value_ptr.map.getOrPutAssumeCapacity(vote_pubkey);
        const seen_in_gossip_previously: *bool = pubkey_diff_gop.value_ptr;
        if (pubkey_diff_gop.found_existing) {
            seen_in_gossip_previously.* = seen_in_gossip_previously.* or is_gossip_vote;
        } else {
            seen_in_gossip_previously.* = is_gossip_vote;
        }
    }

    latest_vote_slot.* = @max(latest_vote_slot.*, last_vote_slot);

    if (is_new_vote) {
        subscriptions.notifyVote(vote_pubkey, vote, vote_transaction_signature);
        verified_vote_sender.send(.{ vote_pubkey, vote_slots }) catch {
            // WARN: the original agave code does literally just ignore this error, is that fine?
            // TODO: evaluate this
        };
    }
}

const ThresholdReachedResults = std.bit_set.IntegerBitSet(THRESHOLDS_TO_CHECK.len);
const THRESHOLDS_TO_CHECK: [2]f64 = .{
    sig.consensus.unimplemented.DUPLICATE_THRESHOLD,
    sig.consensus.tower.VOTE_THRESHOLD_SIZE,
};

/// Returns if the slot was optimistically confirmed, and whether
/// the slot was new
fn trackOptimisticConfirmationVote(
    allocator: std.mem.Allocator,
    vote_tracker: *VoteTracker,
    params: struct {
        slot: Slot,
        hash: Hash,
        pubkey: Pubkey,
        stake: u64,
        total_epoch_stake: u64,
    },
) std.mem.Allocator.Error!struct { ThresholdReachedResults, bool } {
    const slot = params.slot;
    const hash = params.hash;
    const pubkey = params.pubkey;
    const stake = params.stake;
    const total_epoch_stake = params.total_epoch_stake;

    const rw_slot_tracker = try vote_tracker.getOrInsertSlotTracker(allocator, slot);
    defer rw_slot_tracker.deinit(allocator);

    const slot_tracker, var slot_tracker_lg = rw_slot_tracker.tracker.writeWithLock();
    defer slot_tracker_lg.unlock();

    const vote_stake_tracker = try slot_tracker.getOrInsertOptimisticVotesTracker(allocator, hash);
    try vote_stake_tracker.ensureUnusedCapacity(allocator, 1);

    var reached_thresholds = ThresholdReachedResults.initEmpty();
    const result = vote_stake_tracker.addVotePubkeyAssumeCapacity(&reached_thresholds, .{
        .vote_pubkey = pubkey,
        .stake = stake,
        .total_stake = total_epoch_stake,
        .thresholds_to_check = &THRESHOLDS_TO_CHECK,
    });
    return .{ reached_thresholds, result == .is_new };
}

fn sumStake(sum: *u64, epoch_stakes: ?*const sig.core.stake.EpochStakes, pubkey: Pubkey) void {
    if (epoch_stakes) |stakes| {
        sum.* += stakes.stakes.vote_accounts.getDelegatedStake(pubkey) orelse 0;
    }
}
