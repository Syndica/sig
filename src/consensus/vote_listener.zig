const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const vote_program = sig.runtime.program.vote;
const vote_instruction = vote_program.vote_instruction;

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;
const TransactionMessage = sig.core.transaction.Message;

const Ledger = sig.ledger.Ledger;

const VoteTransaction = sig.consensus.vote_transaction.VoteTransaction;
const VoteTracker = sig.consensus.VoteTracker;
const OptimisticConfirmationVerifier =
    sig.consensus.optimistic_vote_verifier.OptimisticConfirmationVerifier;

const SlotTracker = sig.replay.trackers.SlotTracker;
const EpochTracker = sig.core.EpochTracker;

const Logger = sig.trace.Logger("vote_listener");

pub const SlotDataProvider = struct {
    slot_tracker: *SlotTracker,
    epoch_tracker: *EpochTracker,

    pub fn rootSlot(self: *const SlotDataProvider) Slot {
        return self.slot_tracker.root.load(.monotonic);
    }

    fn getSlotHash(self: *const SlotDataProvider, slot: Slot) ?Hash {
        const slot_info = self.slot_tracker.get(slot) orelse return null;
        defer slot_info.release();
        return slot_info.state().hash.readCopy();
    }

    fn getSlotEpoch(self: *const SlotDataProvider, slot: Slot) sig.core.Epoch {
        return self.epoch_tracker.epoch_schedule.getEpoch(slot);
    }

    fn getSlotAncestorsPtr(
        self: *const SlotDataProvider,
        slot: Slot,
    ) ?*const sig.core.Ancestors {
        if (self.slot_tracker.get(slot)) |ref| {
            defer ref.release();
            return &ref.constants().ancestors;
        } else return null;
    }

    fn getEpochTotalStake(self: *const SlotDataProvider, epoch: u64) ?u64 {
        var lock = self.epoch_tracker.rooted_epochs.read();
        defer lock.unlock();
        const epoch_info = lock.get().get(epoch) catch return null;
        defer epoch_info.release();
        return epoch_info.stakes.total_stake;
    }

    fn getDelegatedStake(self: *const SlotDataProvider, slot: Slot, pubkey: Pubkey) ?u64 {
        const epoch_info = self.epoch_tracker.getEpochInfo(slot) catch return null;
        defer epoch_info.release();
        return epoch_info.stakes.stakes.vote_accounts.getDelegatedStake(pubkey);
    }

    fn getAuthorizedVoterPubkey(
        self: *const SlotDataProvider,
        slot: Slot,
        vote_account_key: Pubkey,
    ) ?Pubkey {
        const epoch_consts = self.epoch_tracker.getEpochInfo(slot) catch return null;
        defer epoch_consts.release();
        const epoch_authorized_voters = &epoch_consts.stakes.epoch_authorized_voters;
        return epoch_authorized_voters.get(vote_account_key);
    }
};

pub const Senders = struct {
    verified_vote: *sig.sync.Channel(VerifiedVote),
    gossip_verified_vote_hashes: *std.ArrayListUnmanaged(GossipVerifiedVoteHash),
    duplicate_confirmed_slots: *std.ArrayListUnmanaged(ThresholdConfirmedSlot),
    /// TODO: when the RPC hook design is closer to being finished,
    /// see if this could be re-designed to use that, instead of this
    /// slightly awkward channel design.
    bank_notification: ?*sig.sync.Channel(BankNotification),
    /// TODO: same advisory as on `bank_notification` wrt hooking into RPC.
    subscriptions: RpcSubscriptionsStub,

    const test_setup_enabled = @import("builtin").is_test;

    /// Assumes `allocator` can be used to free all of the elements of the channels if any remain.
    pub fn destroyForTest(self: Senders, allocator: std.mem.Allocator) void {
        if (!test_setup_enabled) @compileError("not allowed");

        while (self.verified_vote.tryReceive()) |verified_vote| verified_vote.deinit(allocator);
        self.verified_vote.destroy();

        self.gossip_verified_vote_hashes.deinit(allocator);
        allocator.destroy(self.gossip_verified_vote_hashes);

        self.duplicate_confirmed_slots.deinit(allocator);
        allocator.destroy(self.duplicate_confirmed_slots);

        if (self.bank_notification) |channel| channel.destroy();
    }

    pub const CreateForTestParams = struct {
        bank_notification: bool,
    };
    pub fn createForTest(
        allocator: std.mem.Allocator,
        params: CreateForTestParams,
    ) !Senders {
        if (!test_setup_enabled) @compileError("not allowed");

        const verified_vote: *sig.sync.Channel(VerifiedVote) = try .create(allocator);
        errdefer verified_vote.destroy();

        const gossip_verified_vote_hashes = ptr: {
            const ptr = try allocator.create(std.ArrayListUnmanaged(GossipVerifiedVoteHash));
            ptr.* = .empty;
            break :ptr ptr;
        };
        errdefer allocator.destroy(gossip_verified_vote_hashes);

        const duplicate_confirmed_slots = ptr: {
            const ptr = try allocator.create(std.ArrayListUnmanaged(ThresholdConfirmedSlot));
            ptr.* = .empty;
            break :ptr ptr;
        };
        errdefer allocator.destroy(duplicate_confirmed_slots);

        const bank_notification: ?*sig.sync.Channel(BankNotification) =
            if (params.bank_notification) try .create(allocator) else null;
        errdefer if (bank_notification) |channel| channel.destroy();

        return .{
            .verified_vote = verified_vote,
            .gossip_verified_vote_hashes = gossip_verified_vote_hashes,
            .bank_notification = bank_notification,
            .duplicate_confirmed_slots = duplicate_confirmed_slots,
            .subscriptions = .{},
        };
    }
};

// NOTE: this test exists purely to satisfy codecov
test Senders {
    const impl = struct {
        fn createAndDestroy(
            allocator: std.mem.Allocator,
            params: Senders.CreateForTestParams,
        ) std.mem.Allocator.Error!void {
            const senders: Senders = try .createForTest(allocator, params);
            senders.destroyForTest(allocator);
        }
    };
    for ([_]Senders.CreateForTestParams{
        .{ .bank_notification = false },
        .{ .bank_notification = true },
    }) |params| {
        try std.testing.checkAllAllocationFailures(
            std.testing.allocator,
            impl.createAndDestroy,
            .{params},
        );
    }
}

const GossipVoteReceptor = struct {
    vote_tx_buffer: std.ArrayListUnmanaged(vote_parser.ParsedVote),

    const INIT: GossipVoteReceptor = .{
        .vote_tx_buffer = .empty,
    };

    fn deinit(
        self: *const GossipVoteReceptor,
        allocator: std.mem.Allocator,
    ) void {
        var copy = self.*;

        copy.clearVoteTxBuffer(allocator);
        copy.vote_tx_buffer.deinit(allocator);
    }

    fn clearVoteTxBuffer(
        self: *GossipVoteReceptor,
        allocator: std.mem.Allocator,
    ) void {
        const vote_tx_buffer = &self.vote_tx_buffer;
        for (vote_tx_buffer.items) |vote_tx| vote_tx.deinit(allocator);
        vote_tx_buffer.clearRetainingCapacity();
    }

    /// Returns the list of most recent verified votes from gossip.
    ///
    /// The returned slice remains valid until the subsequent call to this function,
    /// or until `self.deinit(allocator)` is called.
    fn receiveVerifiedVotes(
        self: *GossipVoteReceptor,
        allocator: std.mem.Allocator,
        slot_data_provider: *const SlotDataProvider,
        gossip_votes: *sig.sync.Channel(sig.gossip.data.Vote),
        metrics: VoteListenerMetrics,
    ) ![]const vote_parser.ParsedVote {
        const zone = tracy.Zone.init(@src(), .{ .name = "receiveVerifiedVotes" });
        defer zone.deinit();

        self.clearVoteTxBuffer(allocator);
        const vote_tx_buffer = &self.vote_tx_buffer;
        std.debug.assert(vote_tx_buffer.items.len == 0);

        // this limit ensures the loop will eventually exit. it is set to MAX_VALIDATORS
        // to ensure we can process at least 1 vote per validator per slot
        const max_votes_to_process: usize = sig.MAX_VALIDATORS;
        try vote_tx_buffer.ensureTotalCapacityPrecise(allocator, max_votes_to_process);
        var votes_processed: usize = 0;
        while (gossip_votes.tryReceive()) |gossip_vote| {
            defer gossip_vote.transaction.deinit(gossip_votes.allocator);
            if (parseAndVerifyVoteTransaction(
                allocator,
                gossip_vote.transaction,
                slot_data_provider.epoch_tracker,
            )) |parsed_vote| {
                vote_tx_buffer.appendAssumeCapacity(parsed_vote);
            } else |e| switch (e) {
                error.Unverified => {},
                error.OutOfMemory => return e,
            }
            votes_processed += 1;
            if (votes_processed >= max_votes_to_process) break;
        }

        // Update metrics for gossip votes received
        metrics.gossip_votes_received.add(vote_tx_buffer.items.len);
        if (vote_tx_buffer.items.len == 0) return &.{};

        return vote_tx_buffer.items;
    }
};

/// NOTE: in the original agave code, this was an inline part of the `verifyVotes` function which took in a list
/// of transactions to verify, and returned the same list with the unverified votes filtered out.
/// We separate it out
fn parseAndVerifyVoteTransaction(
    allocator: std.mem.Allocator,
    vote_tx: Transaction,
    /// Should be associated with the root bank.
    epoch_tracker: *EpochTracker,
) error{ OutOfMemory, Unverified }!vote_parser.ParsedVote {
    const zone = tracy.Zone.init(@src(), .{ .name = "verifyVoteTransaction" });
    defer zone.deinit();

    vote_tx.verify() catch return error.Unverified;
    const parsed_vote = try vote_parser.parseVoteTransaction(allocator, vote_tx) orelse
        return error.Unverified;
    errdefer parsed_vote.deinit(allocator);

    const vote_account_key = parsed_vote.key;
    const vote = parsed_vote.vote;

    const slot = vote.lastVotedSlot() orelse return error.Unverified;
    const authorized_voter: Pubkey = blk: {
        const epoch_consts = epoch_tracker.getEpochInfo(slot) catch return error.Unverified;
        defer epoch_consts.release();
        const epoch_authorized_voters = &epoch_consts.stakes.epoch_authorized_voters;
        break :blk epoch_authorized_voters.get(vote_account_key) orelse return error.Unverified;
    };

    const any_key_is_both_signer_and_authorized_voter = for (
        vote_tx.msg.account_keys,
        0..,
    ) |key, i| {
        const is_signer = vote_tx.msg.isSigner(i);
        const is_authorized_voter = key.equals(&authorized_voter);
        if (is_signer and is_authorized_voter) break true;
    } else false;
    if (!any_key_is_both_signer_and_authorized_voter) return error.Unverified;

    return parsed_vote;
}

pub const ThresholdConfirmedSlot = sig.core.hash.SlotAndHash;
pub const GossipVerifiedVoteHash = struct { Pubkey, Slot, Hash };
pub const VerifiedVote = struct {
    key: Pubkey,
    slots: []const Slot,

    pub fn deinit(self: VerifiedVote, allocator: std.mem.Allocator) void {
        allocator.free(self.slots);
    }
};

/// The expected duration of a slot (400 milliseconds).
const DEFAULT_MS_PER_SLOT: u64 =
    1_000 *
    sig.core.time.DEFAULT_TICKS_PER_SLOT /
    sig.core.time.DEFAULT_TICKS_PER_SECOND;

const Receivers = struct {
    replay_votes: ?*sig.sync.Channel(vote_parser.ParsedVote),
};

pub const VoteListenerMetrics = struct {
    gossip_votes_received: *sig.prometheus.Counter,
    replay_votes_received: *sig.prometheus.Counter,
    gossip_votes_processed: *sig.prometheus.Counter,
    replay_votes_processed: *sig.prometheus.Counter,

    pub const prefix = "vote_listener";

    pub fn init(registry: *sig.prometheus.Registry(.{})) !VoteListenerMetrics {
        return try registry.initStruct(VoteListenerMetrics);
    }
};

pub const VoteCollector = struct {
    gossip_vote_receptor: GossipVoteReceptor,
    vote_tracker: sig.consensus.VoteTracker,
    confirmation_verifier: OptimisticConfirmationVerifier,
    latest_vote_slot_per_validator: sig.utils.collections.PubkeyMap(Slot),
    last_process_root: sig.time.Instant,
    vote_processing_time: VoteProcessingTiming,
    metrics: VoteListenerMetrics,

    pub fn deinit(self: *VoteCollector, allocator: std.mem.Allocator) void {
        self.gossip_vote_receptor.deinit(allocator);
        self.vote_tracker.deinit(allocator);
        self.confirmation_verifier.deinit(allocator);
        self.latest_vote_slot_per_validator.deinit(allocator);
    }

    pub fn init(
        /// Should usually be `.now()`.
        now: sig.time.Instant,
        root_slot: Slot,
        registry: *sig.prometheus.Registry(.{}),
    ) !VoteCollector {
        return .{
            .gossip_vote_receptor = .INIT,
            .vote_tracker = .EMPTY,
            .confirmation_verifier = .init(now, root_slot),
            .latest_vote_slot_per_validator = .empty,
            .last_process_root = now,
            .vote_processing_time = .ZEROES,
            .metrics = try .init(registry),
        };
    }

    pub fn collectAndProcessVotes(
        self: *VoteCollector,
        allocator: std.mem.Allocator,
        logger: Logger,
        params: struct {
            slot_data_provider: SlotDataProvider,
            senders: Senders,
            receivers: Receivers,
            ledger: *Ledger,
            gossip_votes: ?*sig.sync.Channel(sig.gossip.data.Vote),
        },
    ) !void {
        const slot_data_provider = params.slot_data_provider;
        const senders = params.senders;
        const receivers = params.receivers;
        const ledger = params.ledger;

        const gossip_vote_txs = if (params.gossip_votes) |gossip_votes|
            try self.gossip_vote_receptor.receiveVerifiedVotes(
                allocator,
                &slot_data_provider,
                gossip_votes,
                self.metrics,
            )
        else
            &.{};

        const root_slot = slot_data_provider.rootSlot();
        const root_hash = slot_data_provider.getSlotHash(root_slot);

        if (self.last_process_root.elapsed().asMillis() > DEFAULT_MS_PER_SLOT) {
            const confirmation_verifier = &self.confirmation_verifier;
            const unrooted_optimistic_slots =
                try confirmation_verifier.verifyForUnrootedOptimisticSlots(allocator, ledger, .{
                    .slot = root_slot,
                    .hash = root_hash,
                    .ancestors = slot_data_provider.getSlotAncestorsPtr(root_slot).?, // must exist for the root slot
                });
            defer allocator.free(unrooted_optimistic_slots);

            self.vote_tracker.progressWithNewRootBank(allocator, root_slot);
            self.last_process_root = .now();
        }

        const confirmed_slots = try listenAndConfirmVotes(
            allocator,
            logger,
            &self.vote_tracker,
            &slot_data_provider,
            senders,
            receivers,
            gossip_vote_txs,
            &self.vote_processing_time,
            &self.latest_vote_slot_per_validator,
            self.metrics,
        );
        defer allocator.free(confirmed_slots);

        try self.confirmation_verifier.addNewOptimisticConfirmedSlots(
            allocator,
            confirmed_slots,
            ledger,
            .from(logger),
        );
    }
};

fn listenAndConfirmVotes(
    allocator: std.mem.Allocator,
    logger: Logger,
    vote_tracker: *VoteTracker,
    slot_data_provider: *const SlotDataProvider,
    senders: Senders,
    receivers: Receivers,
    gossip_vote_txs: []const vote_parser.ParsedVote,
    vote_processing_time: ?*VoteProcessingTiming,
    latest_vote_slot_per_validator: *sig.utils.collections.PubkeyMap(Slot),
    metrics: VoteListenerMetrics,
) std.mem.Allocator.Error![]const ThresholdConfirmedSlot {
    var replay_votes_buffer: std.ArrayListUnmanaged(vote_parser.ParsedVote) = .empty;
    defer replay_votes_buffer.deinit(allocator);
    try replay_votes_buffer.ensureTotalCapacityPrecise(allocator, 4096);

    const replay_votes: []const vote_parser.ParsedVote = blk: {
        replay_votes_buffer.clearRetainingCapacity();
        if (receivers.replay_votes) |channel| {
            while (channel.tryReceive()) |vote| {
                replay_votes_buffer.appendAssumeCapacity(vote);
                if (replay_votes_buffer.unusedCapacitySlice().len == 0) break;
            }
        }
        break :blk replay_votes_buffer.items;
    };
    if (replay_votes.len > 0) metrics.replay_votes_received.add(replay_votes.len);
    // TODO: either pass separate allocator to deinit replay votes, or document
    // that replay and the vote listener must use the same allocator
    defer for (replay_votes) |replay_vote| replay_vote.deinit(allocator);

    if (gossip_vote_txs.len == 0 and replay_votes.len == 0) {
        return &.{};
    }
    return try filterAndConfirmWithNewVotes(
        allocator,
        logger,
        vote_tracker,
        slot_data_provider,
        senders,
        vote_processing_time,
        latest_vote_slot_per_validator,
        gossip_vote_txs,
        replay_votes,
        metrics,
    );
}

fn filterAndConfirmWithNewVotes(
    allocator: std.mem.Allocator,
    logger: Logger,
    vote_tracker: *VoteTracker,
    slot_data_provider: *const SlotDataProvider,
    senders: Senders,
    vote_processing_time: ?*VoteProcessingTiming,
    latest_vote_slot_per_validator: *sig.utils.collections.PubkeyMap(Slot),
    gossip_vote_txs: []const vote_parser.ParsedVote,
    replayed_votes: []const vote_parser.ParsedVote,
    metrics: VoteListenerMetrics,
) std.mem.Allocator.Error![]const ThresholdConfirmedSlot {
    const root_slot = slot_data_provider.rootSlot();

    var diff: SlotsDiff = .EMPTY;
    defer diff.deinit(allocator);

    var new_optimistic_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    errdefer new_optimistic_confirmed_slots.deinit(allocator);

    // Process votes from gossip and ReplayStage
    inline for (.{
        .{ gossip_vote_txs, true },
        .{ replayed_votes, false },
    }) |chain_item| {
        const parsed_votes, const is_gossip = chain_item;

        for (parsed_votes) |parsed_vote| {
            const vote_pubkey = parsed_vote.key;
            const vote = parsed_vote.vote;
            const signature = parsed_vote.signature;

            try trackNewVotesAndNotifyConfirmations(
                allocator,
                logger,
                vote_tracker,
                slot_data_provider,
                senders,
                vote,
                vote_pubkey,
                signature,
                &diff,
                &new_optimistic_confirmed_slots,
                is_gossip,
                latest_vote_slot_per_validator,
            );
            if (is_gossip)
                metrics.gossip_votes_processed.inc()
            else
                metrics.replay_votes_processed.inc();
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
            w_slot_tracker.voted_slot_updates = .empty;
        }
        const voted = &w_slot_tracker.voted;
        const voted_slot_updates = &w_slot_tracker.voted_slot_updates.?;

        var gossip_only_stake: u64 = 0;
        try voted.ensureUnusedCapacity(allocator, slot_diff.map.count());
        try voted_slot_updates.ensureUnusedCapacity(allocator, slot_diff.map.count());
        for (slot_diff.map.keys(), slot_diff.map.values()) |pubkey, seen_in_gossip_above| {
            if (seen_in_gossip_above) {
                // By this point we know if the vote was seen in gossip above, it was
                // not seen in gossip at any point in the past (if it was seen in gossip
                // in the past, `is_new` would be false and it would have been filtered
                // out above), so it's safe to increment the gossip-only stake
                if (slot_data_provider.getDelegatedStake(root_slot, pubkey)) |delegated_stake| {
                    gossip_only_stake += delegated_stake;
                }
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
        map: sig.utils.collections.PubkeyMap(bool),

        pub const EMPTY: PubkeysDiff = .{ .map = .{} };

        pub fn deinit(self: PubkeysDiff, allocator: std.mem.Allocator) void {
            var map = self.map;
            map.deinit(allocator);
        }
    };

    /// Clears the map while retaining capacity, freeing all of the discarded values.
    fn clearRetainingCapacity(self: *SlotsDiff, allocator: std.mem.Allocator) void {
        if (!@import("builtin").is_test) @compileError("only intended for use in tests");
        for (self.map.values()) |slot_diff| {
            slot_diff.deinit(allocator);
        }
        self.map.clearRetainingCapacity();
    }

    fn sortAsc(self: *SlotsDiff) void {
        if (!@import("builtin").is_test) @compileError("only intended for use in tests");
        const SortCtx = struct {
            keys: []const Slot,
            pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                return ctx.keys[a_index] < ctx.keys[b_index];
            }
        };
        const sort_ctx: SortCtx = .{ .keys = self.map.keys() };
        self.map.sort(sort_ctx);
    }
};

fn trackNewVotesAndNotifyConfirmations(
    allocator: std.mem.Allocator,
    logger: Logger,
    vote_tracker: *VoteTracker,
    slot_data_provider: *const SlotDataProvider,
    senders: Senders,
    vote: VoteTransaction,
    vote_pubkey: Pubkey,
    vote_transaction_signature: sig.core.Signature,
    diff: *SlotsDiff,
    new_optimistic_confirmed_slots: *std.ArrayListUnmanaged(ThresholdConfirmedSlot),
    is_gossip_vote: bool,
    latest_vote_slot_per_validator: *sig.utils.collections.PubkeyMap(Slot),
) std.mem.Allocator.Error!void {
    if (vote.isEmpty()) return;
    const root = slot_data_provider.rootSlot();

    const last_vote_slot = vote.lastVotedSlot().?;
    const last_vote_hash = vote.getHash();

    const latest_vote_slot: *u64 = blk: {
        const gop = try latest_vote_slot_per_validator.getOrPut(allocator, vote_pubkey);
        latest_vote_slot_per_validator.lockPointers();

        if (!gop.found_existing) gop.value_ptr.* = 0;
        break :blk gop.value_ptr;
    };
    defer latest_vote_slot_per_validator.unlockPointers();

    const vote_slots: []const Slot = blk: {
        const vote_slots = try allocator.alloc(Slot, vote.slotCount());
        errdefer allocator.free(vote_slots);
        vote.copyAllSlotsTo(vote_slots);
        break :blk vote_slots;
    };
    defer allocator.free(vote_slots);

    const accumulate_intermediate_votes = blk: {
        if (slot_data_provider.getSlotHash(last_vote_slot)) |hash| {
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
        // Pull stakes via slot_data_provider helpers

        // We always track the last vote slot for optimistic confirmation. If we have replayed
        // the same version of last vote slot that is being voted on, then we also track the
        // other votes in the proposed tower.
        if (slot == last_vote_slot or accumulate_intermediate_votes) {
            const stake = slot_data_provider.getDelegatedStake(slot, vote_pubkey) orelse 0;
            const total_stake = blk: {
                const ep = slot_data_provider.getSlotEpoch(slot);
                break :blk slot_data_provider.getEpochTotalStake(ep) orelse 0;
            };

            const maybe_hash: ?Hash = get_hash: {
                if (slot == last_vote_slot) break :get_hash last_vote_hash;
                break :get_hash slot_data_provider.getSlotHash(slot);
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
                try senders.gossip_verified_vote_hashes.append(allocator, .{
                    vote_pubkey, slot, hash,
                });
            }

            if (reached_threshold_results.isSet(0)) {
                try senders.duplicate_confirmed_slots.append(allocator, .{
                    .slot = slot,
                    .hash = hash,
                });
            }

            if (reached_threshold_results.isSet(1)) {
                try new_optimistic_confirmed_slots.append(allocator, .{
                    .slot = slot,
                    .hash = hash,
                });
                slot_data_provider.slot_tracker.latest_confirmed_slot.update(slot);
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
        errdefer allocator.free(vote_slots);
        // TODO: Uncomment when our RepairService implements vote-weighted repair heuristic.
        //
        // In Agave, verified votes are sent to RepairService (via verified_vote_receiver)
        // to prioritize repairing slots that validators are voting on.
        // See: https://github.com/anza-xyz/agave/blob/a2e0bd9515c50f924ece55cd2793817801c43fca/core/src/repair/repair_service.rs#L529
        // const vote_slots_duped = try allocator.dupe(Slot, vote_slots);
        // senders.verified_vote.send(.{
        //     .key = vote_pubkey,
        //     .slots = vote_slots_duped,
        // }) catch |err| {
        //     logger.err().logf(
        //         "{s}: verified vote couldn't send: " ++
        //             ".{{ .vote_pubkey = {f}, .vote_slots_duped = {any} }}",
        //         .{ @errorName(err), vote_pubkey, vote_slots_duped },
        //     );
        // };
    }
}

pub fn slotTrackerElementGenesis(
    allocator: std.mem.Allocator,
    fee_rate_governor: sig.core.genesis_config.FeeRateGovernor,
) std.mem.Allocator.Error!SlotTracker.Element {
    const constants: sig.core.SlotConstants = try .genesis(allocator, fee_rate_governor);
    errdefer constants.deinit(allocator);

    const state: sig.core.SlotState = .GENESIS;
    errdefer state.deinit(allocator);

    return .{
        .constants = constants,
        .state = state,
        .allocator = allocator,
    };
}

test "trackNewVotesAndNotifyConfirmations filter" {
    const allocator = std.testing.allocator;

    var prng_state: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const prng = prng_state.random();

    var slot_tracker: SlotTracker = try .init(
        allocator,
        0,
        try slotTrackerElementGenesis(allocator, .DEFAULT),
    );
    defer slot_tracker.deinit(allocator);

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        prng,
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(allocator);

    const slot_data_provider: SlotDataProvider = .{
        .slot_tracker = &slot_tracker,
        .epoch_tracker = &epoch_tracker,
    };

    const senders: Senders = try .createForTest(allocator, .{
        .bank_notification = true,
    });
    defer senders.destroyForTest(allocator);

    const validator0_node_kp: sig.identity.KeyPair = try randomKeyPair(prng);
    const validator0_vote_kp: sig.identity.KeyPair = try randomKeyPair(prng);

    var vote_tracker: VoteTracker = .EMPTY;
    defer vote_tracker.deinit(allocator);

    var latest_vote_slot_per_validator: sig.utils.collections.PubkeyMap(Slot) = .empty;
    defer latest_vote_slot_per_validator.deinit(allocator);

    var diff: SlotsDiff = .EMPTY;
    defer diff.deinit(allocator);

    var new_optimistic_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    errdefer new_optimistic_confirmed_slots.deinit(allocator);

    {
        const tower_sync_tx_parsed: vote_parser.ParsedVote = blk: {
            const tower_sync: vote_program.state.TowerSync = try .fromLockouts(allocator, &.{
                .{ .slot = 1, .confirmation_count = 3 },
                .{ .slot = 2, .confirmation_count = 2 },
                .{ .slot = 6, .confirmation_count = 1 },
            });
            defer tower_sync.deinit(allocator);

            const tower_sync_tx = try newTowerSyncTransaction(allocator, .{
                .tower_sync = tower_sync,
                .recent_blockhash = .ZEROES,
                .node_keypair = validator0_node_kp,
                .vote_keypair = validator0_vote_kp,
                .authorized_voter_keypair = validator0_vote_kp,
                .maybe_switch_proof_hash = null,
            });
            defer tower_sync_tx.deinit(allocator);

            const maybe_tx_parsed = try vote_parser.parseVoteTransaction(allocator, tower_sync_tx);
            break :blk maybe_tx_parsed.?;
        };
        defer tower_sync_tx_parsed.deinit(allocator);

        const is_gossip_vote = true;
        try trackNewVotesAndNotifyConfirmations(
            allocator,
            .FOR_TESTS,
            &vote_tracker,
            &slot_data_provider,
            senders,
            tower_sync_tx_parsed.vote,
            tower_sync_tx_parsed.key,
            tower_sync_tx_parsed.signature,
            &diff,
            &new_optimistic_confirmed_slots,
            is_gossip_vote,
            &latest_vote_slot_per_validator,
        );
    }
    diff.sortAsc();
    try std.testing.expectEqualSlices(Slot, diff.map.keys(), &.{ 1, 2, 6 });

    // Vote on a new slot, only those later than 6 should show up. 4 is skipped.
    diff.clearRetainingCapacity(allocator);

    {
        const tower_sync_tx_parsed: vote_parser.ParsedVote = blk: {
            const tower_sync: vote_program.state.TowerSync = try .fromLockouts(allocator, &.{
                .{ .slot = 1, .confirmation_count = 6 },
                .{ .slot = 2, .confirmation_count = 5 },
                .{ .slot = 3, .confirmation_count = 4 },
                .{ .slot = 4, .confirmation_count = 3 },
                .{ .slot = 7, .confirmation_count = 2 },
                .{ .slot = 8, .confirmation_count = 1 },
            });
            defer tower_sync.deinit(allocator);

            const tower_sync_tx = try newTowerSyncTransaction(allocator, .{
                .tower_sync = tower_sync,
                .recent_blockhash = .ZEROES,
                .node_keypair = validator0_node_kp,
                .vote_keypair = validator0_vote_kp,
                .authorized_voter_keypair = validator0_vote_kp,
                .maybe_switch_proof_hash = null,
            });
            defer tower_sync_tx.deinit(allocator);

            const maybe_tx_parsed = try vote_parser.parseVoteTransaction(allocator, tower_sync_tx);
            break :blk maybe_tx_parsed.?;
        };
        defer tower_sync_tx_parsed.deinit(allocator);

        const is_gossip_vote = true;
        try trackNewVotesAndNotifyConfirmations(
            allocator,
            .FOR_TESTS,
            &vote_tracker,
            &slot_data_provider,
            senders,
            tower_sync_tx_parsed.vote,
            tower_sync_tx_parsed.key,
            tower_sync_tx_parsed.signature,
            &diff,
            &new_optimistic_confirmed_slots,
            is_gossip_vote,
            &latest_vote_slot_per_validator,
        );
    }
    diff.sortAsc();
    try std.testing.expectEqualSlices(Slot, diff.map.keys(), &.{ 7, 8 });

    // No stake delegated, so optimistic confirmation should not be reached.
    try std.testing.expectEqual(0, slot_data_provider.slot_tracker.getSlotForCommitment(.confirmed));
}

const ThresholdReachedResults = std.bit_set.IntegerBitSet(THRESHOLDS_TO_CHECK.len);
const THRESHOLDS_TO_CHECK: [2]f64 = .{
    sig.consensus.replay_tower.DUPLICATE_THRESHOLD,
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

pub const vote_parser = struct {
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

    /// Used for locally forwarding processed vote transactions to consensus
    /// Analogous to [parse_sanitized_vote_transaction](https://github.com/anza-xyz/agave/blob/961953a6ffab132b9a32e22edcd4cfbdba52c6f8/vote/src/vote_parser.rs#L11)
    pub fn parseSanitizedVoteTransaction(
        allocator: std.mem.Allocator,
        // TODO: Confirm if this is the correct type to use here
        tx: sig.replay.resolve_lookup.ResolvedTransaction,
    ) std.mem.Allocator.Error!?ParsedVote {
        // Check first instruction for a vote
        const instructions = tx.instructions;
        if (instructions.len == 0) return null;
        const first_instruction = instructions[0];

        const program_id = first_instruction.program_meta.pubkey;
        if (!vote_program.ID.equals(&program_id)) {
            return null;
        }

        const account_metas = first_instruction.account_metas.items;
        if (account_metas.len == 0) return null;
        const key = account_metas[0].pubkey;

        const vote, const switch_proof_hash = try parseVoteInstructionData(
            allocator,
            first_instruction.instruction_data,
        ) orelse return null;
        errdefer vote.deinit(allocator);

        const signature: sig.core.Signature = if (tx.transaction.signatures.len != 0)
            tx.transaction.signatures[0]
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

    fn testParseSanitizedVoteTransaction(input_hash: ?Hash, random: std.Random) !void {
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

            // Build a ResolvedTransaction with the first instruction expanded to InstructionInfo
            const message = vote_tx.msg;
            std.debug.assert(message.instructions.len != 0);
            const first_ix = message.instructions[0];

            var dedupe_map: [sig.runtime.InstructionInfo.MAX_ACCOUNT_METAS]u8 = @splat(0xff);

            // Vote instructions have 4 accounts, below MAX_ACCOUNT_METAS (256)
            const n_instr_accounts = 4;
            var account_metas: sig.runtime.InstructionInfo.AccountMetas =
                try .initCapacity(allocator, n_instr_accounts);
            defer account_metas.deinit(allocator);

            std.debug.assert(first_ix.account_indexes.len == n_instr_accounts);
            for (first_ix.account_indexes, 0..) |acct_index_u8, i| {
                const acct_index: usize = acct_index_u8;
                if (dedupe_map[i] == 0xff)
                    dedupe_map[i] = @intCast(i);

                const pubkey = message.account_keys[acct_index];
                account_metas.appendAssumeCapacity(.{
                    .pubkey = pubkey,
                    .index_in_transaction = @intCast(acct_index),
                    .is_signer = message.isSigner(acct_index),
                    .is_writable = false,
                });
            }

            const resolved: sig.replay.resolve_lookup.ResolvedTransaction = .{
                .transaction = vote_tx,
                .accounts = .{},
                .instructions = &.{.{
                    .program_meta = .{
                        .pubkey = message.account_keys[first_ix.program_index],
                        .index_in_transaction = first_ix.program_index,
                    },
                    .account_metas = account_metas,
                    .dedupe_map = dedupe_map,
                    .instruction_data = first_ix.data,
                    .owned_instruction_data = false,
                }},
            };

            const maybe_parsed_tx = try parseSanitizedVoteTransaction(allocator, resolved);
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
        const vote_ix = try vote_instruction.createVote(
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

        const message = vote_tx.msg;
        std.debug.assert(message.instructions.len != 0);
        const first_ix = message.instructions[0];

        var dedupe_map: [sig.runtime.InstructionInfo.MAX_ACCOUNT_METAS]u8 = @splat(0xff);
        var account_metas = sig.runtime.InstructionInfo.AccountMetas{};
        defer account_metas.deinit(allocator);

        // minimal one account to satisfy check
        if (first_ix.account_indexes.len != 0) {
            const acct_index: usize = first_ix.account_indexes[0];
            dedupe_map[0] = 0;
            try account_metas.append(allocator, .{
                .pubkey = message.account_keys[acct_index],
                .index_in_transaction = @intCast(acct_index),
                .is_signer = message.isSigner(acct_index),
                .is_writable = false,
            });
        }

        const resolved_bad: sig.replay.resolve_lookup.ResolvedTransaction = .{
            .transaction = vote_tx,
            .accounts = .{},
            .instructions = &.{.{
                .program_meta = .{
                    .pubkey = Pubkey.ZEROES, // bad program id
                    .index_in_transaction = first_ix.program_index,
                },
                .account_metas = account_metas,
                .dedupe_map = dedupe_map,
                .instruction_data = first_ix.data,
                .owned_instruction_data = false,
            }},
        };

        try std.testing.expectEqual(
            null,
            try parseSanitizedVoteTransaction(allocator, resolved_bad),
        );
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
};

fn randomKeyPair(random: std.Random) !sig.identity.KeyPair {
    var seed: [sig.identity.KeyPair.seed_length]u8 = undefined;
    random.bytes(&seed);
    return try sig.identity.KeyPair.generateDeterministic(seed);
}

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
        signatures[pos] = .fromSignature(signature);
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    try vote_parser.testParseVoteTransaction(null, random);
    try vote_parser.testParseVoteTransaction(Hash.init(&.{42}), random);
}

test "vote_parser.parseSanitizedVoteTransaction" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    try vote_parser.testParseSanitizedVoteTransaction(null, random);
    try vote_parser.testParseSanitizedVoteTransaction(Hash.init(&.{43}), random);
}

test parseAndVerifyVoteTransaction {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        prng.random(),
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(allocator);

    try std.testing.expectError(
        error.Unverified,
        // TODO: consider making two separate APIs, one for the slot tracker, and one for the epoch tracker,
        // since it seems like there's little or no real data inter-dependency internally.
        // Argument against: whether the data is interdependent could change.
        parseAndVerifyVoteTransaction(allocator, .EMPTY, &epoch_tracker),
    );
}

test "simple usage" {
    const allocator = std.testing.allocator;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var slot_tracker: SlotTracker = try .init(allocator, 0, .{
        .constants = .{
            .parent_slot = 0,
            .parent_hash = .ZEROES,
            .parent_lt_hash = .IDENTITY,
            .block_height = 1,
            .collector_id = .ZEROES,
            .max_tick_height = 1,
            .fee_rate_governor = .DEFAULT,
            .ancestors = .{ .ancestors = .empty },
            .feature_set = .ALL_DISABLED,
            .reserved_accounts = .empty,
            .inflation = .DEFAULT,
            .rent_collector = .DEFAULT,
        },
        .state = .GENESIS,
        .allocator = allocator,
    });
    defer slot_tracker.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        prng.random(),
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(allocator);

    const slot_data_provider: SlotDataProvider = .{
        .slot_tracker = &slot_tracker,
        .epoch_tracker = &epoch_tracker,
    };

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer ledger.deinit();

    const senders: Senders = try .createForTest(allocator, .{
        .bank_notification = true,
    });
    defer senders.destroyForTest(allocator);

    const replay_votes_channel: *sig.sync.Channel(vote_parser.ParsedVote) = try .create(allocator);
    defer replay_votes_channel.destroy();

    var vote_collector: VoteCollector = try .init(
        .EPOCH_ZERO,
        slot_data_provider.rootSlot(),
        &registry,
    );
    defer vote_collector.deinit(allocator);

    try vote_collector.collectAndProcessVotes(allocator, .FOR_TESTS, .{
        .slot_data_provider = slot_data_provider,
        .senders = senders,
        .receivers = .{ .replay_votes = replay_votes_channel },
        .ledger = &ledger,
        .gossip_votes = null,
    });

    // Since no votes were sent, slot trackers should remain at their initialized state.
    // NOTE: processed slot is not used here, but required to construct SlotTracker.
    try std.testing.expectEqual(0, slot_tracker.getSlotForCommitment(.processed));
    try std.testing.expectEqual(0, slot_tracker.getSlotForCommitment(.confirmed));
}

test "check trackers" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    const tracker_templates = [_]struct { Slot, sig.identity.KeyPair, Hash }{
        .{ 2, try .generateDeterministic(@splat(2)), .initRandom(random) },
        .{ 3, try .generateDeterministic(@splat(3)), .initRandom(random) },
        .{ 4, try .generateDeterministic(@splat(4)), .initRandom(random) },
        .{ 5, try .generateDeterministic(@splat(5)), .initRandom(random) },
        .{ 6, try .generateDeterministic(@splat(6)), .initRandom(random) },
    };

    const node_keypair: sig.identity.KeyPair = try .generateDeterministic(@splat(1));

    const root_slot: Slot = 0;

    var slot_tracker: SlotTracker = blk: {
        var state: sig.core.SlotState = .GENESIS;
        errdefer state.deinit(allocator);

        break :blk try .init(allocator, root_slot, .{
            .constants = .{
                .parent_slot = root_slot -| 1,
                .parent_hash = .ZEROES,
                .parent_lt_hash = .IDENTITY,
                .block_height = 1,
                .collector_id = .ZEROES,
                .max_tick_height = 1,
                .fee_rate_governor = .DEFAULT,
                .ancestors = .{ .ancestors = .empty },
                .feature_set = .ALL_DISABLED,
                .reserved_accounts = .empty,
                .inflation = .DEFAULT,
                .rent_collector = .DEFAULT,
            },
            .state = state,
            .allocator = allocator,
        });
    };
    defer slot_tracker.deinit(allocator);

    var epoch_tracker = sig.core.EpochTracker.init(
        .default,
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(allocator);

    {
        var stakes = try sig.core.EpochStakes.initRandom(
            allocator,
            random,
            .{ .epoch = 0 },
        );
        errdefer stakes.deinit(allocator);

        for (tracker_templates) |template| {
            _, const vote_kp, _ = template;
            const vote_key: Pubkey = .fromPublicKey(&vote_kp.public_key);
            try stakes.epoch_authorized_voters.put(allocator, vote_key, vote_key);
        }

        try epoch_tracker.insertRootedEpochInfo(allocator, 0, stakes, &.ALL_DISABLED);
    }

    const slot_data_provider: SlotDataProvider = .{
        .slot_tracker = &slot_tracker,
        .epoch_tracker = &epoch_tracker,
    };

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    const gossip_votes_channel: *sig.sync.Channel(sig.gossip.data.Vote) = try .create(allocator);
    defer gossip_votes_channel.destroy();

    const senders: Senders = try .createForTest(allocator, .{
        .bank_notification = true,
    });
    defer senders.destroyForTest(allocator);

    const replay_votes_channel = try sig.sync.Channel(vote_parser.ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    var vote_collector: VoteCollector =
        try .init(.EPOCH_ZERO, slot_data_provider.rootSlot(), &registry);
    defer vote_collector.deinit(allocator);

    var expected_trackers: std.ArrayListUnmanaged(struct { Slot, TestSlotVoteTracker }) = .empty;
    defer expected_trackers.deinit(allocator);
    defer for (expected_trackers.items) |tracker_entry| {
        _, const svt = tracker_entry;
        svt.deinit(allocator);
    };

    // see the logic in `trackNewVotesAndNotifyConfirmations` to see the passthrough of data,
    // specifically everything related to the call to `trackOptimisticConfirmationVote`.
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

        // -- send the transactions through gossip channel, matched up with each expected tracker -- //
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

        const tower_sync_tx = try newTowerSyncTransaction(allocator, .{
            .tower_sync = tower_sync,
            .recent_blockhash = Hash.ZEROES,
            .node_keypair = node_keypair,
            .vote_keypair = vote_kp,
            .authorized_voter_keypair = vote_kp,
            .maybe_switch_proof_hash = Hash.ZEROES,
        });
        errdefer tower_sync_tx.deinit(allocator);

        try gossip_votes_channel.send(.{
            .from = from,
            .transaction = tower_sync_tx,
            .wallclock = wallclock,
            .slot = slot,
        });
    }

    try std.testing.expectEqual({}, vote_collector.collectAndProcessVotes(allocator, .FOR_TESTS, .{
        .slot_data_provider = slot_data_provider,
        .senders = senders,
        .receivers = .{ .replay_votes = replay_votes_channel },
        .ledger = &state,
        .gossip_votes = gossip_votes_channel,
    }));

    var actual_trackers: std.ArrayListUnmanaged(struct { Slot, TestSlotVoteTracker }) = .empty;
    defer actual_trackers.deinit(allocator);
    defer for (actual_trackers.items) |actual_pair| {
        _, const tsvt = actual_pair;
        tsvt.deinit(allocator);
    };

    {
        vote_collector.vote_tracker.map_rwlock.lockShared();
        defer vote_collector.vote_tracker.map_rwlock.unlockShared();
        try actual_trackers.ensureTotalCapacityPrecise(
            allocator,
            vote_collector.vote_tracker.map.count(),
        );

        for (
            vote_collector.vote_tracker.map.keys(),
            vote_collector.vote_tracker.map.values(),
        ) |vt_key, vt_val| {
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

    // Votes were processed but no stake was delegated to validators, so
    // optimisitic confirmation was not reached.
    try std.testing.expectEqual(0, slot_data_provider.slot_tracker.getSlotForCommitment(.processed));
    try std.testing.expectEqual(0, slot_data_provider.slot_tracker.getSlotForCommitment(.confirmed));
}

// tests for OptimisticConfirmationVerifier moved to optimistic_vote_verifier.zig

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
