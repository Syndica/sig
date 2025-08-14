const std = @import("std");
const sig = @import("../sig.zig");

const vote_program = sig.runtime.program.vote;
const vote_instruction = vote_program.vote_instruction;

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;
const TransactionMessage = sig.core.transaction.Message;
const VoteTransaction = sig.consensus.vote_transaction.VoteTransaction;
const VoteTracker = sig.consensus.VoteTracker;

const SlotTracker = sig.replay.trackers.SlotTracker;
const EpochTracker = sig.replay.trackers.EpochTracker;

pub const BankForksStub = struct {
    slot_tracker: SlotTracker,
    epoch_tracker: EpochTracker,

    pub fn deinit(self: BankForksStub, allocator: std.mem.Allocator) void {
        self.slot_tracker.deinit(allocator);
        self.epoch_tracker.deinit(allocator);
    }

    pub fn init(
        allocator: std.mem.Allocator,
        epoch_schedule: sig.core.EpochSchedule,
        root: struct {
            slot: Slot,
            constants: sig.core.SlotConstants,
            state: sig.core.SlotState,
            epoch_constants: sig.core.EpochConstants,
        },
    ) std.mem.Allocator.Error!BankForksStub {
        var self: BankForksStub = .{
            .slot_tracker = try .init(allocator, root.slot, .{
                .constants = root.constants,
                .state = root.state,
            }),
            .epoch_tracker = .{ .schedule = epoch_schedule },
        };
        errdefer self.deinit(allocator);

        try self.epoch_tracker.epochs.ensureUnusedCapacity(allocator, 1);
        self.epoch_tracker.epochs.putAssumeCapacity(
            epoch_schedule.getEpoch(root.slot),
            try root.epoch_constants.clone(allocator),
        );

        return self;
    }

    pub fn getBank(self: *const BankForksStub, slot: Slot) ?BankStub {
        const st_elem = self.slot_tracker.get(slot) orelse return null;
        const et_elem = self.epoch_tracker.getForSlot(slot);
        return .{
            .slot = slot,
            .st_elem = st_elem,
            .et_elem = et_elem,
        };
    }

    pub fn rootBank(self: *const BankForksStub) BankStub {
        return self.getBank(self.slot_tracker.root).?; // root slot's bank must exist
    }

    pub fn bankHash(self: *const BankForksStub, slot: Slot) ?Hash {
        const bank = self.getBank(slot) orelse return null;
        return bank.st_elem.state.hash.readCopy();
    }

    pub fn bankHashOrNullIfFrozen(self: *const BankForksStub, slot: Slot) ?Hash {
        const hash = self.bankHash(slot) orelse return null;
        if (hash.eql(Hash.ZEROES)) return null;
        return hash;
    }

    pub const BankStub = struct {
        slot: Slot,
        st_elem: SlotTracker.Reference,
        et_elem: ?sig.core.EpochConstants,
    };
};

pub const Senders = struct {
    verified_vote: *sig.sync.Channel(VerifiedVote),
    gossip_verified_vote_hash: *sig.sync.Channel(GossipVerifiedVoteHash),
    bank_notification: ?*sig.sync.Channel(BankNotification),
    duplicate_confirmed_slot: ?*sig.sync.Channel(ThresholdConfirmedSlot),
    subscriptions: RpcSubscriptionsStub,
};

pub const VoteListener = struct {
    allocator: std.mem.Allocator,
    verified_vote_transactions: *sig.sync.Channel(Transaction),
    recv: std.Thread,
    process_votes: std.Thread,

    pub fn init(
        allocator: std.mem.Allocator,
        exit: sig.sync.ExitCondition,
        logger: sig.trace.Logger,
        vote_tracker: *VoteTracker,
        params: struct {
            bank_forks_rw: *sig.sync.RwMux(BankForksStub),
            gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
            ledger_db: if (TODO_CONFIRMATION_VERIFIER) *sig.ledger.LedgerDB else void,

            /// Channels that will be used to `receive` data.
            receivers: struct {
                replay_votes: *sig.sync.Channel(vote_parser.ParsedVote),
            },

            /// Direct outputs
            senders: Senders,
        },
    ) !VoteListener {
        const verified_vote_transactions = try sig.sync.Channel(Transaction).create(allocator);
        errdefer verified_vote_transactions.destroy();

        const recv_thread = try std.Thread.spawn(.{}, recvLoop, .{
            allocator,
            exit,
            params.bank_forks_rw,
            params.gossip_table_rw,
            verified_vote_transactions,
        });
        errdefer recv_thread.join();
        recv_thread.setName("sigSolCiVoteLstnr") catch {};

        const process_votes_thread = try std.Thread.spawn(.{}, processVotesLoop, .{
            allocator,
            logger,

            vote_tracker,
            params.bank_forks_rw,

            params.senders,
            Receivers{
                .verified_vote_transactions = verified_vote_transactions,
                .replay_votes = params.receivers.replay_votes,
            },

            params.ledger_db,
            exit,
        });
        errdefer process_votes_thread.join();
        process_votes_thread.setName("solCiProcVotes") catch {};

        return .{
            .allocator = allocator,
            .verified_vote_transactions = verified_vote_transactions,
            .recv = recv_thread,
            .process_votes = process_votes_thread,
        };
    }

    pub fn joinAndDeinit(self: VoteListener) void {
        self.recv.join();
        self.process_votes.join();

        while (self.verified_vote_transactions.tryReceive()) |verified_vote| {
            verified_vote.deinit(self.allocator);
        }
        self.verified_vote_transactions.destroy();
    }
};

/// equivalent to agave's solana_gossip::cluster_info::GOSSIP_SLEEP_MILLIS
const GOSSIP_SLEEP_MILLIS = 100 * std.time.ns_per_ms;

const UnverifiedVoteReceptor = struct {
    cursor: u64,

    fn recv(
        self: *UnverifiedVoteReceptor,
        allocator: std.mem.Allocator,
        /// Cleared and then filled with the most recent vote transactions.
        /// Re-allocated using `allocator`.
        unverified_votes_buffer: *std.ArrayListUnmanaged(Transaction),
        gossip_table: *const sig.gossip.GossipTable,
    ) std.mem.Allocator.Error!void {
        unverified_votes_buffer.clearRetainingCapacity();
        self.cursor = try getVoteTransactionsAfterCursor(
            allocator,
            unverified_votes_buffer,
            self.cursor,
            gossip_table,
        );
    }

    /// Empties out `unverified_votes_buffer`, calling `deinit` on the transactions which are unverified,
    /// and sending the transactions which are verified to `verified_vote_transactions_sender`.
    fn consumeTransactionsAndSendVerified(
        allocator: std.mem.Allocator,
        epoch_tracker: *const EpochTracker,
        /// Presumably populated by `UnverifiedVoteReceptor.recv`.
        unverified_votes_buffer: *std.ArrayListUnmanaged(Transaction),
        /// Sends to `processVotesLoop`'s `receivers.verified_vote_transactions` parameter.
        verified_vote_transactions_sender: *sig.sync.Channel(Transaction),
    ) (std.mem.Allocator.Error || error{ChannelClosed})!void {
        while (unverified_votes_buffer.pop()) |vote_tx| {
            switch (try verifyVoteTransaction(allocator, vote_tx, epoch_tracker)) {
                .verified => verified_vote_transactions_sender.send(vote_tx) catch |err| {
                    vote_tx.deinit(allocator);
                    return err;
                },
                .unverified => vote_tx.deinit(allocator),
            }
        }
    }

    fn recvAndSendOnce(
        self: *UnverifiedVoteReceptor,
        allocator: std.mem.Allocator,
        bank_forks_rw: *sig.sync.RwMux(BankForksStub),
        gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
        unverified_votes_buffer: *std.ArrayListUnmanaged(Transaction),
        /// Sends to `processVotesLoop`'s `receivers.verified_vote_transactions` parameter.
        verified_vote_transactions_sender: *sig.sync.Channel(Transaction),
    ) !void {
        unverified_votes_buffer.clearRetainingCapacity();
        defer for (unverified_votes_buffer.items) |vote_tx| vote_tx.deinit(allocator);

        {
            const gossip_table, var gossip_table_lg = gossip_table_rw.readWithLock();
            defer gossip_table_lg.unlock();
            try self.recv(allocator, unverified_votes_buffer, gossip_table);
        }

        // inc_new_counter_debug!("cluster_info_vote_listener-recv_count", votes.len());
        if (unverified_votes_buffer.items.len == 0) {
            std.time.sleep(GOSSIP_SLEEP_MILLIS);
            return;
        }

        const bank_forks, var bank_forks_lg = bank_forks_rw.readWithLock();
        defer bank_forks_lg.unlock();

        try consumeTransactionsAndSendVerified(
            allocator,
            &bank_forks.epoch_tracker,
            unverified_votes_buffer,
            verified_vote_transactions_sender,
        );
    }
};

fn recvLoop(
    allocator: std.mem.Allocator,
    exit: sig.sync.ExitCondition,
    bank_forks_rw: *sig.sync.RwMux(BankForksStub),
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    /// Sends to `processVotesLoop`'s `receivers.verified_vote_transactions` parameter.
    verified_vote_transactions_sender: *sig.sync.Channel(Transaction),
) !void {
    defer exit.afterExit();

    var unverified_votes_buffer: std.ArrayListUnmanaged(Transaction) = .empty;
    defer unverified_votes_buffer.deinit(allocator);

    var unverified_vote_receptor: UnverifiedVoteReceptor = .{ .cursor = 0 };
    while (exit.shouldRun()) {
        try unverified_vote_receptor.recvAndSendOnce(
            allocator,
            bank_forks_rw,
            gossip_table_rw,
            &unverified_votes_buffer,
            verified_vote_transactions_sender,
        );
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
        const vote_cloned = try vote.transaction.clone(allocator);
        unverified_votes_buffer.appendAssumeCapacity(vote_cloned);
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
    /// Should be associated with the root bank.
    epoch_tracker: *const EpochTracker,
) std.mem.Allocator.Error!enum { verified, unverified } {
    vote_tx.verify() catch return .unverified;
    const parsed_vote =
        try vote_parser.parseVoteTransaction(allocator, vote_tx) orelse return .unverified;
    defer parsed_vote.deinit(allocator);

    const vote_account_key = parsed_vote.key;
    const vote = parsed_vote.vote;

    const slot = vote.lastVotedSlot() orelse return .unverified;
    const authorized_voter: Pubkey = blk: {
        const epoch_consts = epoch_tracker.getForSlot(slot) orelse return .unverified;
        const epoch_authorized_voters = &epoch_consts.stakes.epoch_authorized_voters;
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

pub const ThresholdConfirmedSlot = struct { Slot, Hash };
pub const GossipVerifiedVoteHash = struct { Pubkey, Slot, Hash };
const VerifiedVote = struct { Pubkey, []const Slot };

/// The expected duration of a slot (400 milliseconds).
const DEFAULT_MS_PER_SLOT: u64 =
    1_000 *
    sig.core.time.DEFAULT_TICKS_PER_SLOT /
    sig.core.time.DEFAULT_TICKS_PER_SECOND;

const TODO_CONFIRMATION_VERIFIER = false;

const Receivers = struct {
    verified_vote_transactions: *sig.sync.Channel(Transaction),
    replay_votes: *sig.sync.Channel(vote_parser.ParsedVote),
};

fn processVotesLoop(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    vote_tracker: *VoteTracker,
    bank_forks_rw: *sig.sync.RwMux(BankForksStub),
    senders: Senders,
    receivers: Receivers,
    ledger_db: if (TODO_CONFIRMATION_VERIFIER) *sig.ledger.LedgerDB else void,
    exit: sig.sync.ExitCondition,
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
    var vote_processing_time: VoteProcessingTiming = .ZEROES;
    while (exit.shouldRun()) {
        switch (try processVotesOnce(
            allocator,
            logger,
            vote_tracker,
            bank_forks_rw,
            senders,
            receivers,
            ledger_db,
            &confirmation_verifier,
            &latest_vote_slot_per_validator,
            &last_process_root,
            &vote_processing_time,
        )) {
            .ok => {},
            .disconnected => return,
            .timeout => continue,
            .logged => continue,
        }
    }
}

fn processVotesOnce(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    vote_tracker: *VoteTracker,
    bank_forks_rw: *sig.sync.RwMux(BankForksStub),
    senders: Senders,
    receivers: Receivers,
    ledger_db: if (TODO_CONFIRMATION_VERIFIER) *sig.ledger.LedgerDB else void,
    confirmation_verifier: *if (TODO_CONFIRMATION_VERIFIER) OptimisticConfirmationVerifier else void,
    latest_vote_slot_per_validator: *std.AutoArrayHashMapUnmanaged(Pubkey, Slot),
    last_process_root: *sig.time.Instant,
    vote_processing_time: *VoteProcessingTiming,
) !enum { ok, disconnected, timeout, logged } {
    const root_bank_slot, const root_bank = blk: {
        const bank_forks, var bank_forks_lg = bank_forks_rw.readWithLock();
        defer bank_forks_lg.unlock();
        break :blk .{ bank_forks.slot_tracker.root, bank_forks.rootBank() };
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
        vote_tracker.progressWithNewRootBank(allocator, root_bank_slot);
        last_process_root.* = sig.time.Instant.now();
    }

    const confirmed_slots = listenAndConfirmVotes(
        allocator,
        logger,
        vote_tracker,
        bank_forks_rw,
        senders,
        receivers,
        &root_bank,
        vote_processing_time,
        latest_vote_slot_per_validator,
    ) catch |err| switch (err) {
        error.RecvTimeoutDisconnected => {
            return .disconnected;
        },
        error.ReadyTimeout => {
            return .timeout;
        },
        else => |e| {
            logger.err().logf("thread {} error {s}", .{
                std.Thread.getCurrentId(),
                @errorName(e),
            });
            return .logged;
        },
    };
    defer allocator.free(confirmed_slots);

    if (TODO_CONFIRMATION_VERIFIER) {
        confirmation_verifier.add_new_optimistic_confirmed_slots(confirmed_slots, ledger_db);
    }

    // NOTE: keep this around for reference while I'm figuring it out

    // match confirmed_slots {
    //     Ok(confirmed_slots) => {
    //         confirmation_verifier
    //             .add_new_optimistic_confirmed_slots(confirmed_slots.clone(), &ledger);
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

    return .ok;
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
    vote_tracker: *VoteTracker,
    bank_forks_rw: *sig.sync.RwMux(BankForksStub),
    senders: Senders,
    receivers: Receivers,
    root_bank: *const BankForksStub.BankStub,
    vote_processing_time: ?*VoteProcessingTiming,
    latest_vote_slot_per_validator: *std.AutoArrayHashMapUnmanaged(Pubkey, Slot),
) ListenAndConfirmVotesError![]const ThresholdConfirmedSlot {
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
            while (receivers.verified_vote_transactions.tryReceive()) |tx| {
                gossip_vote_txs_buffer.appendAssumeCapacity(tx);
                if (gossip_vote_txs_buffer.unusedCapacitySlice().len == 0) break;
            }
            break :blk gossip_vote_txs_buffer.items;
        };
        defer for (gossip_vote_txs) |vote_tx| vote_tx.deinit(allocator);

        const replay_votes: []const vote_parser.ParsedVote = blk: {
            replay_votes_buffer.clearRetainingCapacity();
            while (receivers.replay_votes.tryReceive()) |vote| {
                replay_votes_buffer.appendAssumeCapacity(vote);
                if (replay_votes_buffer.unusedCapacitySlice().len == 0) break;
            }
            break :blk replay_votes_buffer.items;
        };
        // TODO: either pass separate allocator to deinit replay votes, or document
        // that replay and the vote listener must use the same allocator
        defer for (replay_votes) |replay_vote| replay_vote.deinit(allocator);

        if (gossip_vote_txs.len == 0 and replay_votes.len == 0) {
            continue;
        }

        return try filterAndConfirmWithNewVotes(
            allocator,
            logger,
            vote_tracker,
            bank_forks_rw,
            senders,
            root_bank,
            vote_processing_time,
            latest_vote_slot_per_validator,
            gossip_vote_txs,
            replay_votes,
        );
    }

    return &.{};
}

fn filterAndConfirmWithNewVotes(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    vote_tracker: *VoteTracker,
    bank_forks_rw: *sig.sync.RwMux(BankForksStub),
    senders: Senders,
    root_bank: *const BankForksStub.BankStub,
    vote_processing_time: ?*VoteProcessingTiming,
    latest_vote_slot_per_validator: *std.AutoArrayHashMapUnmanaged(Pubkey, Slot),
    gossip_vote_txs: []const Transaction,
    replayed_votes: []const vote_parser.ParsedVote,
) std.mem.Allocator.Error![]const ThresholdConfirmedSlot {
    var diff = SlotsDiff.EMPTY;
    defer diff.deinit(allocator);

    var new_optimistic_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .{};
    errdefer new_optimistic_confirmed_slots.deinit(allocator);

    // Process votes from gossip and ReplayStage

    // let mut gossip_vote_txn_processing_time = Measure::start("gossip_vote_processing_time");
    inline for (.{
        .{ gossip_vote_txs, true },
        .{ replayed_votes, false },
    }) |chain_item| {
        const txs_or_parsed_votes, const is_gossip = chain_item;

        for (txs_or_parsed_votes) |tx_or_parsed_vote| {
            const parsed_vote: vote_parser.ParsedVote = if (is_gossip)
                try vote_parser.parseVoteTransaction(allocator, tx_or_parsed_vote) orelse continue
            else
                tx_or_parsed_vote;
            defer if (is_gossip) parsed_vote.deinit(allocator); // replay votes are already freed

            const vote_pubkey = parsed_vote.key;
            const vote = parsed_vote.vote;
            const signature = parsed_vote.signature;

            try trackNewVotesAndNotifyConfirmations(
                allocator,
                logger,
                vote_tracker,
                bank_forks_rw,
                senders,
                vote,
                vote_pubkey,
                signature,
                root_bank,
                &diff,
                &new_optimistic_confirmed_slots,
                is_gossip,
                latest_vote_slot_per_validator,
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
            // var start_idx: usize = 0;
            var index: usize = 0;
            while (index != slot_diff.map.count()) {
                const pubkey = slot_diff.map.keys()[index];
                const seen_in_gossip_above = slot_diff.map.values()[index];

                const seen_in_gossip_previously = r_slot_tracker.voted.get(pubkey);
                const is_new = seen_in_gossip_previously == null;
                // `is_new_from_gossip` means we observed a vote for this slot
                // for the first time in gossip
                const is_new_from_gossip =
                    !(seen_in_gossip_previously orelse false) and seen_in_gossip_above;
                if (is_new or is_new_from_gossip) {
                    index += 1;
                    continue;
                }
                std.debug.assert(slot_diff.map.fetchSwapRemove(pubkey).?.key.equals(&pubkey));
            }
        }

        const w_slot_tracker, var w_slot_tracker_lg = slot_tracker.tracker.writeWithLock();
        defer w_slot_tracker_lg.unlock();
        if (w_slot_tracker.voted_slot_updates == null) {
            w_slot_tracker.voted_slot_updates = .{};
        }
        const voted = &w_slot_tracker.voted;
        const voted_slot_updates = &w_slot_tracker.voted_slot_updates.?;

        var gossip_only_stake: u64 = 0;
        const epoch_stakes = if (root_bank.et_elem) |*et_elem| &et_elem.stakes else null;

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
    return try new_optimistic_confirmed_slots.toOwnedSlice(allocator);
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

    fn update(
        self: *VoteProcessingTiming,
        vote_txn_processing_time_us: u64,
        vote_slot_confirming_time_us: u64,
    ) void {
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
    inline fn should_update_ext(
        self: AtomicInterval,
        interval_time_ms: u64,
        skip_first: bool,
    ) bool {
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
    vote_tracker: *VoteTracker,
    bank_forks_rw: *sig.sync.RwMux(BankForksStub),
    senders: Senders,
    vote: VoteTransaction,
    vote_pubkey: Pubkey,
    vote_transaction_signature: sig.core.Signature,
    root_bank: *const BankForksStub.BankStub,
    diff: *SlotsDiff,
    new_optimistic_confirmed_slots: *std.ArrayListUnmanaged(ThresholdConfirmedSlot),
    is_gossip_vote: bool,
    latest_vote_slot_per_validator: *std.AutoArrayHashMapUnmanaged(Pubkey, Slot),
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

    var is_new_vote = false;
    // If slot is before the root, ignore it. Iterate from latest vote slot to earliest.
    for (0 + 1..vote_slots.len + 1) |fwd_index| {
        const rev_index = vote_slots.len - fwd_index;
        const slot = vote_slots[rev_index];
        if (slot <= root) continue;

        // if we don't have stake information, ignore it
        const epoch_stakes = blk: {
            const bank_forks, var bank_forks_lg = bank_forks_rw.readWithLock();
            defer bank_forks_lg.unlock();
            const et_elem = bank_forks.epoch_tracker.getForSlot(slot) orelse continue;
            break :blk et_elem.stakes;
        };

        // We always track the last vote slot for optimistic confirmation. If we have replayed
        // the same version of last vote slot that is being voted on, then we also track the
        // other votes in the proposed tower.
        if (slot == last_vote_slot or accumulate_intermediate_votes) {
            const vote_accounts = epoch_stakes.stakes.vote_accounts;
            const stake = vote_accounts.getDelegatedStake(vote_pubkey);
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
                senders.gossip_verified_vote_hash.send(.{ vote_pubkey, slot, hash }) catch {
                    // WARN: the original agave code does literally just ignore this error, is that fine?
                    // TODO: evaluate this
                };
            }

            if (reached_threshold_results.isSet(0)) {
                if (senders.duplicate_confirmed_slot) |sender| {
                    sender.send(.{ slot, hash }) catch {
                        // WARN: the original agave code does literally just ignore this error, is that fine?
                        // TODO: evaluate this
                    };
                }
            }

            if (reached_threshold_results.isSet(1)) {
                try new_optimistic_confirmed_slots.append(allocator, .{ slot, hash });
                // Notify subscribers about new optimistic confirmation
                if (senders.bank_notification) |sender| {
                    sender.send(.{ .optimistically_confirmed = slot }) catch |err| {
                        logger.warn().logf("bank_notification_sender failed: {s}", .{
                            @errorName(err),
                        });
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

        const slot_diff_gop =
            try diff.map.getOrPutValue(allocator, slot, SlotsDiff.PubkeysDiff.EMPTY);
        const pubkey_diff_gop =
            try slot_diff_gop.value_ptr.map.getOrPut(allocator, vote_pubkey);
        const seen_in_gossip_previously: *bool = pubkey_diff_gop.value_ptr;
        if (pubkey_diff_gop.found_existing) {
            seen_in_gossip_previously.* = seen_in_gossip_previously.* or is_gossip_vote;
        } else {
            seen_in_gossip_previously.* = is_gossip_vote;
        }
    }

    latest_vote_slot.* = @max(latest_vote_slot.*, last_vote_slot);

    if (is_new_vote) {
        senders.subscriptions.notifyVote(vote_pubkey, vote, vote_transaction_signature);
        const vote_slots_duped = try allocator.dupe(Slot, vote_slots);
        errdefer allocator.free(vote_slots);
        senders.verified_vote.send(.{ vote_pubkey, vote_slots_duped }) catch {
            // WARN: the original agave code does literally just ignore this error, is that fine?
            // TODO: evaluate this
        };
    }
}

const ThresholdReachedResults = std.bit_set.IntegerBitSet(THRESHOLDS_TO_CHECK.len);
const THRESHOLDS_TO_CHECK: [2]f64 = .{
    sig.replay.service.DUPLICATE_THRESHOLD,
    sig.consensus.replay_tower.VOTE_THRESHOLD_SIZE,
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

fn sumStake(sum: *u64, epoch_stakes: ?*const sig.core.EpochStakes, pubkey: Pubkey) void {
    if (epoch_stakes) |stakes| {
        sum.* += stakes.stakes.vote_accounts.getDelegatedStake(pubkey);
    }
}

const vote_parser = struct {
    //! Based on https://github.com/anza-xyz/agave/blob/182823ee353ee64fde230dbad96d8e24b6cd065a/vote/src/vote_parser.rs
    //! TODO: this is probably/definitely the wrong place for this code to be,
    //! but it's the only place it's needed right now, we can figure out a proper
    //! place for it later.

    pub const ParsedVote = struct {
        key: Pubkey,
        vote: VoteTransaction,
        switch_proof_hash: ?Hash,
        signature: sig.core.Signature,

        pub fn deinit(self: ParsedVote, allocator: std.mem.Allocator) void {
            self.vote.deinit(allocator);
        }
    };

    /// Used for parsing gossip vote transactions
    pub fn parseVoteTransaction(
        allocator: std.mem.Allocator,
        tx: Transaction,
    ) std.mem.Allocator.Error!?ParsedVote {
        // Check first instruction for a vote
        const message = tx.msg;

        if (message.instructions.len == 0) return null;
        const first_instruction = message.instructions[0];
        const program_id_index = first_instruction.program_index;

        if (program_id_index >= message.account_keys.len) return null;
        const program_id = message.account_keys[program_id_index];
        if (!vote_program.ID.equals(&program_id)) {
            return null;
        }

        if (first_instruction.account_indexes.len == 0) return null;
        const first_account = first_instruction.account_indexes[0];

        if (first_account >= message.account_keys.len) return null;
        const key = message.account_keys[first_account];

        const vote, const switch_proof_hash = try parseVoteInstructionData(
            allocator,
            first_instruction.data,
        ) orelse return null;
        errdefer vote.deinit(allocator);

        const signature = if (tx.signatures.len != 0)
            tx.signatures[0]
        else
            sig.core.Signature.ZEROES;
        return .{
            .key = key,
            .vote = vote,
            .switch_proof_hash = switch_proof_hash,
            .signature = signature,
        };
    }

    fn parseVoteInstructionData(
        allocator: std.mem.Allocator,
        vote_instruction_data: []const u8,
    ) std.mem.Allocator.Error!?struct { VoteTransaction, ?Hash } {
        const vote_inst = sig.bincode.readFromSlice(
            allocator,
            vote_program.Instruction,
            vote_instruction_data,
            .{},
        ) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            else => return null,
        };
        errdefer vote_inst.deinit(allocator);

        return switch (vote_inst) {
            .vote => |vote| .{
                .{ .vote = vote.vote },
                null,
            },
            .vote_switch => |vs| .{
                .{ .vote = vs.vote },
                vs.hash,
            },
            .update_vote_state => |vsu| .{
                .{ .vote_state_update = vsu.vote_state_update },
                null,
            },
            .update_vote_state_switch => |uvss| .{
                .{ .vote_state_update = uvss.vote_state_update },
                uvss.hash,
            },
            .compact_update_vote_state => |cuvs| .{
                .{ .vote_state_update = cuvs.vote_state_update },
                null,
            },
            .compact_update_vote_state_switch => |cuvss| .{
                .{ .vote_state_update = cuvss.vote_state_update },
                cuvss.hash,
            },
            .tower_sync => |ts| .{
                .{ .tower_sync = ts.tower_sync },
                null,
            },
            .tower_sync_switch => |tss| .{
                .{ .tower_sync = tss.tower_sync },
                tss.hash,
            },
            .authorize,
            .authorize_checked,
            .authorize_with_seed,
            .authorize_checked_with_seed,
            .initialize_account,
            .update_commission,
            .update_validator_identity,
            .withdraw,
            => null,
        };
    }

    fn testParseVoteTransaction(input_hash: ?Hash, random: std.Random) !void {
        const allocator = std.testing.allocator;

        const node_keypair = try randomKeyPair(random);
        const auth_voter_keypair = try randomKeyPair(random);
        const vote_keypair = try randomKeyPair(random);

        const vote_key = Pubkey.fromPublicKey(&vote_keypair.public_key);

        {
            const bank_hash = Hash.ZEROES;
            const vote_tx = try testNewVoteTransaction(
                allocator,
                &.{42},
                bank_hash,
                Hash.ZEROES,
                node_keypair,
                vote_key,
                auth_voter_keypair,
                input_hash,
            );
            defer vote_tx.deinit(allocator);

            const maybe_parsed_tx = try parseVoteTransaction(allocator, vote_tx);
            defer if (maybe_parsed_tx) |parsed_tx| parsed_tx.deinit(allocator);

            try std.testing.expectEqualDeep(ParsedVote{
                .key = vote_key,
                .vote = .{ .vote = .{
                    .slots = &.{42},
                    .hash = bank_hash,
                    .timestamp = null,
                } },
                .switch_proof_hash = input_hash,
                .signature = vote_tx.signatures[0],
            }, maybe_parsed_tx);
        }

        // Test bad program id fails
        var vote_ix = try vote_instruction.createVote(
            allocator,
            vote_key,
            Pubkey.fromPublicKey(&auth_voter_keypair.public_key),
            .{ .vote = .{
                .slots = &.{ 1, 2 },
                .hash = Hash.ZEROES,
                .timestamp = null,
            } },
        );
        defer vote_ix.deinit(allocator);
        vote_ix.program_id = Pubkey.ZEROES;

        const vote_tx = blk: {
            const vote_tx_msg: TransactionMessage = try .initCompile(
                allocator,
                &.{vote_ix},
                Pubkey.fromPublicKey(&node_keypair.public_key),
                Hash.ZEROES,
                null,
            );
            errdefer vote_tx_msg.deinit(allocator);
            break :blk try Transaction.initOwnedMessageWithSigningKeypairs(
                allocator,
                .legacy,
                vote_tx_msg,
                &.{},
            );
        };
        defer vote_tx.deinit(allocator);
        try std.testing.expectEqual(null, parseVoteTransaction(allocator, vote_tx));
    }

    /// Reimplemented locally from Vote program.
    fn testNewVoteTransaction(
        allocator: std.mem.Allocator,
        slots: []const sig.core.Slot,
        bank_hash: Hash,
        blockhash: Hash,
        node_keypair: sig.identity.KeyPair,
        vote_key: Pubkey,
        authorized_voter_keypair: sig.identity.KeyPair,
        maybe_switch_proof_hash: ?Hash,
    ) !Transaction {
        comptime std.debug.assert(@import("builtin").is_test);
        const vote_ix = try newVoteInstruction(
            allocator,
            slots,
            bank_hash,
            vote_key,
            Pubkey.fromPublicKey(&authorized_voter_keypair.public_key),
            maybe_switch_proof_hash,
        );
        defer vote_ix.deinit(allocator);

        const vote_tx_msg: TransactionMessage = try .initCompile(
            allocator,
            &.{vote_ix},
            Pubkey.fromPublicKey(&node_keypair.public_key),
            blockhash,
            null,
        );
        errdefer vote_tx_msg.deinit(allocator);
        return try Transaction.initOwnedMessageWithSigningKeypairs(
            allocator,
            .legacy,
            vote_tx_msg,
            &.{ node_keypair, authorized_voter_keypair },
        );
    }

    fn newVoteInstruction(
        allocator: std.mem.Allocator,
        slots: []const sig.core.Slot,
        bank_hash: Hash,
        vote_key: Pubkey,
        authorized_voter_key: Pubkey,
        maybe_switch_proof_hash: ?Hash,
    ) !sig.core.Instruction {
        const vote_state: vote_program.state.Vote = .{
            .slots = slots,
            .hash = bank_hash,
            .timestamp = null,
        };

        if (maybe_switch_proof_hash) |switch_proof_hash| {
            return try vote_instruction.createVoteSwitch(
                allocator,
                vote_key,
                authorized_voter_key,
                .{
                    .vote = vote_state,
                    .hash = switch_proof_hash,
                },
            );
        }
        return try vote_instruction.createVote(
            allocator,
            vote_key,
            authorized_voter_key,
            .{
                .vote = vote_state,
            },
        );
    }

    fn randomKeyPair(random: std.Random) !sig.identity.KeyPair {
        var seed: [sig.identity.KeyPair.seed_length]u8 = undefined;
        random.bytes(&seed);
        return try sig.identity.KeyPair.generateDeterministic(seed);
    }
};

fn newTowerSyncTransaction(
    allocator: std.mem.Allocator,
    params: struct {
        tower_sync: vote_program.state.TowerSync,
        recent_blockhash: Hash,
        node_keypair: sig.identity.KeyPair,
        vote_keypair: sig.identity.KeyPair,
        authorized_voter_keypair: sig.identity.KeyPair,
        maybe_switch_proof_hash: ?Hash,
    },
) !Transaction {
    const tower_sync = params.tower_sync;
    const recent_blockhash = params.recent_blockhash;
    const node_keypair = params.node_keypair;
    const vote_keypair = params.vote_keypair;
    const authorized_voter_keypair = params.authorized_voter_keypair;
    const maybe_switch_proof_hash = params.maybe_switch_proof_hash;

    const vote_ix: sig.core.Instruction = blk: {
        const accounts = try allocator.dupe(sig.core.instruction.InstructionAccount, &.{
            .{
                .pubkey = Pubkey.fromPublicKey(&vote_keypair.public_key),
                .is_signer = false,
                .is_writable = true,
            },
            .{
                .pubkey = Pubkey.fromPublicKey(&authorized_voter_keypair.public_key),
                .is_signer = true,
                .is_writable = false,
            },
        });
        errdefer allocator.free(accounts);

        const VoteProgramIx = vote_program.Instruction;
        const vote_ix_data: VoteProgramIx = if (maybe_switch_proof_hash) |switch_proof_hash| .{
            .tower_sync_switch = .{
                .tower_sync = tower_sync,
                .hash = switch_proof_hash,
            },
        } else .{
            .tower_sync = .{
                .tower_sync = tower_sync,
            },
        };

        break :blk try sig.core.Instruction.initUsingBincodeAlloc(
            allocator,
            VoteProgramIx,
            vote_program.ID,
            accounts,
            &vote_ix_data,
        );
    };
    defer vote_ix.deinit(allocator);

    const vote_tx_msg: TransactionMessage = try .initCompile(
        allocator,
        &.{vote_ix},
        Pubkey.fromPublicKey(&node_keypair.public_key),
        recent_blockhash,
        null,
    );
    errdefer vote_tx_msg.deinit(allocator);

    const msg_serialized = try vote_tx_msg.serializeBounded(.legacy);
    const keypairs = [_]sig.identity.KeyPair{ node_keypair, authorized_voter_keypair };

    const signatures = try allocator.alloc(sig.core.Signature, vote_tx_msg.signature_count);
    errdefer allocator.free(signatures);
    @memset(signatures, sig.core.Signature.ZEROES);

    for (0..signatures.len) |i| {
        const keypair = keypairs[i];
        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        const pos = vote_tx_msg.getSigningKeypairPosition(pubkey) orelse
            return error.MissingOrInvalidSigner;
        const signature = try keypairs[i].sign(msg_serialized.constSlice(), null);
        signatures[pos] = .{ .data = signature.toBytes() };
    }

    const tx: Transaction = .{
        .signatures = signatures,
        .version = .legacy,
        .msg = vote_tx_msg,
    };
    try tx.verify();
    return tx;
}

// TODO: port applicable tests from https://github.com/anza-xyz/agave/blob/182823ee353ee64fde230dbad96d8e24b6cd065a/core/src/cluster_info_vote_listener.rs

test "vote_parser.parseVoteTransaction" {
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    try vote_parser.testParseVoteTransaction(null, random);
    try vote_parser.testParseVoteTransaction(Hash.generateSha256(&[_]u8{42}), random);
}

test verifyVoteTransaction {
    const allocator = std.testing.allocator;
    var epoch_tracker: EpochTracker = .{ .schedule = .DEFAULT };
    defer epoch_tracker.deinit(allocator);

    try std.testing.expectEqual(
        .unverified,
        verifyVoteTransaction(allocator, .EMPTY, &epoch_tracker),
    );
}

test "simple usage" {
    const allocator = std.testing.allocator;

    var bank_forks_rw = sig.sync.RwMux(BankForksStub).init(blk: {
        var stakes: sig.core.EpochStakes = try .initEmptyWithGenesisStakeHistoryEntry(allocator);
        defer stakes.deinit(allocator);

        break :blk try .init(allocator, .DEFAULT, .{
            .slot = 0,
            .constants = .{
                .parent_slot = 0,
                .parent_hash = .ZEROES,
                .parent_lt_hash = .IDENTITY,
                .block_height = 1,
                .collector_id = .ZEROES,
                .max_tick_height = 1,
                .fee_rate_governor = .DEFAULT,
                .epoch_reward_status = .inactive,
                .ancestors = .{ .ancestors = .empty },
                .feature_set = .ALL_DISABLED,
                .reserved_accounts = .empty,
            },
            .state = try .genesis(allocator),
            .epoch_constants = .{
                .hashes_per_tick = 1,
                .ticks_per_slot = 1,
                .ns_per_slot = 1,
                .genesis_creation_time = 1,
                .slots_per_year = 1,
                .stakes = stakes,
                .rent_collector = undefined,
            },
        });
    });
    defer {
        const bank_forks, _ = bank_forks_rw.writeWithLock();
        bank_forks.deinit(allocator);
    }

    var gossip_table_rw: sig.sync.RwMux(sig.gossip.GossipTable) = .init(
        try .init(allocator, allocator),
    );
    defer {
        const gossip_table, _ = gossip_table_rw.writeWithLock();
        gossip_table.deinit();
    }

    const replay_votes_channel: *sig.sync.Channel(vote_parser.ParsedVote) = try .create(allocator);
    defer replay_votes_channel.destroy();

    const verified_vote_channel: *sig.sync.Channel(VerifiedVote) = try .create(allocator);
    defer verified_vote_channel.destroy();

    const gossip_verified_vote_hash_channel: *sig.sync.Channel(GossipVerifiedVoteHash) =
        try .create(allocator);
    defer gossip_verified_vote_hash_channel.destroy();

    var vote_tracker: VoteTracker = .EMPTY;
    defer vote_tracker.deinit(allocator);

    var exit: std.atomic.Value(bool) = .init(false);
    const exit_cond: sig.sync.ExitCondition = .{ .unordered = &exit };

    const vote_listener: VoteListener = try .init(allocator, exit_cond, .noop, &vote_tracker, .{
        .bank_forks_rw = &bank_forks_rw,
        .gossip_table_rw = &gossip_table_rw,
        .ledger_db = {},
        .receivers = .{
            .replay_votes = replay_votes_channel,
        },
        .senders = .{
            .verified_vote = verified_vote_channel,
            .gossip_verified_vote_hash = gossip_verified_vote_hash_channel,
            .bank_notification = null,
            .duplicate_confirmed_slot = null,
            .subscriptions = .{},
        },
    });
    defer vote_listener.joinAndDeinit();
    std.time.sleep(sig.time.Duration.asNanos(.fromMillis(DEFAULT_MS_PER_SLOT * 2)));
    exit_cond.setExit();
}

test "check trackers" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(123);
    const random = prng.random();

    const node_keypair: sig.identity.KeyPair = try .generateDeterministic(@splat(1));

    const tracker_templates = [_]struct { Slot, sig.identity.KeyPair, Hash }{
        .{ 2, try .generateDeterministic(@splat(2)), .initRandom(random) },
        .{ 3, try .generateDeterministic(@splat(3)), .initRandom(random) },
        .{ 4, try .generateDeterministic(@splat(4)), .initRandom(random) },
        .{ 5, try .generateDeterministic(@splat(5)), .initRandom(random) },
        .{ 6, try .generateDeterministic(@splat(6)), .initRandom(random) },
    };

    const root_slot: Slot = 0;

    var bank_forks_rw = sig.sync.RwMux(BankForksStub).init(blk: {
        var stakes: sig.core.EpochStakes = try .initEmptyWithGenesisStakeHistoryEntry(allocator);
        defer stakes.deinit(allocator);
        for (tracker_templates) |template| {
            _, const vote_kp, _ = template;
            const vote_key: Pubkey = .fromPublicKey(&vote_kp.public_key);
            try stakes.epoch_authorized_voters.put(allocator, vote_key, vote_key);
        }

        break :blk try .init(allocator, .DEFAULT, .{
            .slot = root_slot,
            .constants = .{
                .parent_slot = 0,
                .parent_hash = .ZEROES,
                .parent_lt_hash = .IDENTITY,
                .block_height = 1,
                .collector_id = .ZEROES,
                .max_tick_height = 1,
                .fee_rate_governor = .DEFAULT,
                .epoch_reward_status = .inactive,
                .ancestors = .{ .ancestors = .empty },
                .feature_set = .ALL_DISABLED,
                .reserved_accounts = .empty,
            },
            .state = try .genesis(allocator),
            .epoch_constants = .{
                .hashes_per_tick = 1,
                .ticks_per_slot = 1,
                .ns_per_slot = 1,
                .genesis_creation_time = 1,
                .slots_per_year = 1,
                .stakes = stakes,
                .rent_collector = undefined,
            },
        });
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

    var vote_tracker: VoteTracker = .EMPTY;
    defer vote_tracker.deinit(allocator);

    const replay_votes_channel = try sig.sync.Channel(vote_parser.ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const verified_vote_channel = try sig.sync.Channel(VerifiedVote).create(allocator);
    defer verified_vote_channel.destroy();
    defer while (verified_vote_channel.tryReceive()) |verified_vote| {
        _, const vote_slots = verified_vote;
        allocator.free(vote_slots);
    };

    const gossip_verified_vote_hash_channel =
        try sig.sync.Channel(GossipVerifiedVoteHash).create(allocator);
    defer gossip_verified_vote_hash_channel.destroy();

    const bank_notification_channel = try sig.sync.Channel(BankNotification).create(allocator);
    defer bank_notification_channel.destroy();

    const duplicate_confirmed_slot_channel =
        try sig.sync.Channel(ThresholdConfirmedSlot).create(allocator);
    defer duplicate_confirmed_slot_channel.destroy();

    var expected_trackers: std.ArrayListUnmanaged(struct { Slot, TestSlotVoteTracker }) = .empty;
    defer expected_trackers.deinit(allocator);
    defer for (expected_trackers.items) |tracker_entry| {
        _, const svt = tracker_entry;
        svt.deinit(allocator);
    };

    // see the logic in `trackNewVotesAndNotifyConfirmations` to see the passthrough of data,
    // specifically everything related to the call to `trackOptimisticConfirmationVote`.
    {
        const gossip_table, var gossip_table_lg = gossip_table_rw.writeWithLock();
        defer gossip_table_lg.unlock();

        for (tracker_templates, 0..) |template, i| {
            const slot, const vote_kp, const hash = template;

            // -- set up expected trackers -- //
            const vote_key: Pubkey = .fromPublicKey(&vote_kp.public_key);
            try expected_trackers.ensureUnusedCapacity(allocator, 1);
            const vst: TestSlotVoteTracker = .{
                .voted = &.{
                    .{ vote_key, true },
                },
                .optimistic_votes_tracker = &.{
                    .{ hash, .{ .stake = 0, .voted = &.{vote_key} } },
                },
                .voted_slot_updates = &.{vote_key},
                .gossip_only_stake = 0,
            };
            expected_trackers.appendAssumeCapacity(.{ slot, try vst.clone(allocator) });

            // -- send the transactions through gossip, matched up with each expected tracker -- //
            const wallclock = 100 + i;
            const from = Pubkey.fromPublicKey(&vote_kp.public_key);

            var tower_sync: vote_program.state.TowerSync = .{
                .lockouts = .{},
                .root = slot - 1,
                .hash = hash,
                .timestamp = @intCast(wallclock),
                .block_id = Hash.ZEROES,
            };
            defer tower_sync.deinit(allocator);

            try tower_sync.lockouts.append(allocator, .{
                .slot = slot,
                .confirmation_count = 1,
            });

            const tower_sync_tx = try newTowerSyncTransaction(gossip_table.gossip_data_allocator, .{
                .tower_sync = tower_sync,
                .recent_blockhash = Hash.ZEROES,
                .node_keypair = node_keypair,
                .vote_keypair = vote_kp,
                .authorized_voter_keypair = vote_kp,
                .maybe_switch_proof_hash = Hash.ZEROES,
            });
            errdefer tower_sync_tx.deinit(allocator);

            const insert_result = try gossip_table.insert(
                sig.gossip.SignedGossipData.initSigned(&node_keypair, .{ .Vote = .{ 0, .{
                    .from = from,
                    .transaction = tower_sync_tx,
                    .wallclock = wallclock,
                    .slot = slot,
                } } }),
                wallclock,
            );
            defer insert_result.deinit(gossip_table.gossip_data_allocator);
        }
    }

    {
        // this code represents the equivalent of `VoteListener.init`, except
        // with each loop only running for exactly one iteration.
        _ = &VoteListener.init;

        var receptor: UnverifiedVoteReceptor = .{ .cursor = 0 };

        const verified_vote_transactions_channel: *sig.sync.Channel(Transaction) =
            try .create(allocator);
        defer verified_vote_transactions_channel.destroy();
        defer while (verified_vote_transactions_channel.tryReceive()) |vote_tx| {
            vote_tx.deinit(allocator);
        };

        var unverified_votes_buffer: std.ArrayListUnmanaged(Transaction) = .empty;
        defer unverified_votes_buffer.deinit(allocator);
        try receptor.recvAndSendOnce(
            allocator,
            &bank_forks_rw,
            &gossip_table_rw,
            &unverified_votes_buffer,
            verified_vote_transactions_channel,
        );

        var latest_vote_slot_per_validator: std.AutoArrayHashMapUnmanaged(Pubkey, Slot) = .empty;
        defer latest_vote_slot_per_validator.deinit(allocator);

        var last_process_root: sig.time.Instant = .now();
        var vote_processing_time: VoteProcessingTiming = .ZEROES;

        var confirmation_verifier = {};
        try std.testing.expectEqual(.ok, try processVotesOnce(
            allocator,
            .noop,
            &vote_tracker,
            &bank_forks_rw,
            .{
                .verified_vote = verified_vote_channel,
                .gossip_verified_vote_hash = gossip_verified_vote_hash_channel,
                .bank_notification = bank_notification_channel,
                .duplicate_confirmed_slot = duplicate_confirmed_slot_channel,
                .subscriptions = .{},
            },
            .{
                .replay_votes = replay_votes_channel,
                .verified_vote_transactions = verified_vote_transactions_channel,
            },
            {},
            &confirmation_verifier,
            &latest_vote_slot_per_validator,
            &last_process_root,
            &vote_processing_time,
        ));
    }

    var actual_trackers: std.ArrayListUnmanaged(struct { Slot, TestSlotVoteTracker }) = .empty;
    defer actual_trackers.deinit(allocator);
    defer for (actual_trackers.items) |slot_tracker| slot_tracker[1].deinit(allocator);

    {
        vote_tracker.map_rwlock.lockShared();
        defer vote_tracker.map_rwlock.unlockShared();
        try actual_trackers.ensureTotalCapacityPrecise(allocator, vote_tracker.map.count());

        for (vote_tracker.map.keys(), vote_tracker.map.values()) |vt_key, vt_val| {
            const svt, var svt_lg = vt_val.tracker.readWithLock();
            defer svt_lg.unlock();
            actual_trackers.appendAssumeCapacity(.{ vt_key, try .from(allocator, svt) });
        }
    }

    const Pair = struct { Slot, TestSlotVoteTracker };
    const pairLessThan = struct {
        fn lessThan(_: void, a: Pair, b: Pair) bool {
            const a_slot, _ = a;
            const b_slot, _ = b;
            return a_slot < b_slot;
        }
    }.lessThan;

    // need to sort the items based on the slot, to ensure nothing is mismatched.
    std.sort.block(Pair, expected_trackers.items, {}, pairLessThan);
    std.sort.block(Pair, actual_trackers.items, {}, pairLessThan);

    try std.testing.expectEqualDeep(
        expected_trackers.items,
        actual_trackers.items,
    );
}

const TestSlotVoteTracker = struct {
    voted: []const struct { Pubkey, bool },
    optimistic_votes_tracker: []const struct { Hash, TestVoteStakeTracker },
    voted_slot_updates: ?[]const Pubkey,
    gossip_only_stake: u64,

    const TestVoteStakeTracker = struct {
        voted: []const Pubkey,
        stake: u64,

        fn deinit(self: TestVoteStakeTracker, allocator: std.mem.Allocator) void {
            allocator.free(self.voted);
        }

        fn clone(
            self: TestVoteStakeTracker,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!TestVoteStakeTracker {
            return .{
                .voted = try allocator.dupe(Pubkey, self.voted),
                .stake = self.stake,
            };
        }

        fn from(
            allocator: std.mem.Allocator,
            vst: *const sig.consensus.vote_tracker.VoteStakeTracker,
        ) std.mem.Allocator.Error!TestVoteStakeTracker {
            return .{
                .stake = vst.stake,
                .voted = try allocator.dupe(Pubkey, vst.voted.keys()),
            };
        }
    };

    fn clone(
        self: TestSlotVoteTracker,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!TestSlotVoteTracker {
        const voted = try allocator.dupe(struct { Pubkey, bool }, self.voted);
        errdefer allocator.free(voted);

        const ovt = try allocator.alloc(
            struct { Hash, TestVoteStakeTracker },
            self.optimistic_votes_tracker.len,
        );
        errdefer allocator.free(ovt);
        for (ovt, self.optimistic_votes_tracker, 0..) |*cloned, original, i| {
            errdefer for (ovt[0..i]) |prev| prev.@"1".deinit(allocator);
            const hash, const vst = original;
            cloned.* = .{ hash, try vst.clone(allocator) };
        }
        errdefer for (ovt) |hash_svt| hash_svt.@"1".deinit(allocator);

        const vsu = if (self.voted_slot_updates) |vsu| try allocator.dupe(Pubkey, vsu) else null;
        errdefer allocator.free(vsu orelse &.{});

        const gossip_only_stake = self.gossip_only_stake;

        return .{
            .voted = voted,
            .optimistic_votes_tracker = ovt,
            .voted_slot_updates = vsu,
            .gossip_only_stake = gossip_only_stake,
        };
    }

    fn deinit(self: TestSlotVoteTracker, allocator: std.mem.Allocator) void {
        allocator.free(self.voted);
        for (self.optimistic_votes_tracker) |slot_ovt| {
            _, const vst = slot_ovt;
            vst.deinit(allocator);
        }
        allocator.free(self.optimistic_votes_tracker);
        if (self.voted_slot_updates) |vsu| allocator.free(vsu);
    }

    fn from(
        allocator: std.mem.Allocator,
        svt: *const sig.consensus.vote_tracker.SlotVoteTracker,
    ) std.mem.Allocator.Error!TestSlotVoteTracker {
        const voted = voted: {
            var actual_voted: std.ArrayListUnmanaged(struct { Pubkey, bool }) = .{};
            defer actual_voted.deinit(allocator);
            try actual_voted.ensureTotalCapacityPrecise(allocator, svt.voted.count());
            for (svt.voted.keys(), svt.voted.values()) |key, val| {
                actual_voted.appendAssumeCapacity(.{ key, val });
            }
            break :voted try actual_voted.toOwnedSlice(allocator);
        };
        errdefer allocator.free(voted);

        var ovt: std.ArrayListUnmanaged(struct { Hash, TestVoteStakeTracker }) = .{};
        defer ovt.deinit(allocator);
        defer for (ovt.items) |slot_vst| slot_vst[1].deinit(allocator);
        try ovt.ensureTotalCapacityPrecise(
            allocator,
            svt.optimistic_votes_tracker.count(),
        );
        for (
            svt.optimistic_votes_tracker.keys(),
            svt.optimistic_votes_tracker.values(),
        ) |key, val| {
            ovt.appendAssumeCapacity(.{ key, try .from(allocator, &val) });
        }

        const voted_slot_updates = if (svt.voted_slot_updates) |vsu|
            try allocator.dupe(Pubkey, vsu.items)
        else
            null;
        errdefer allocator.free(voted_slot_updates orelse &.{});

        const gossip_only_stake = svt.gossip_only_stake;

        return .{
            .voted = voted,
            .optimistic_votes_tracker = try ovt.toOwnedSlice(allocator),
            .voted_slot_updates = voted_slot_updates,
            .gossip_only_stake = gossip_only_stake,
        };
    }
};
