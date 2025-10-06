const std = @import("std");
const sig = @import("sig");

const TowerConsensus = sig.replay.consensus.TowerConsensus;
const SlotTracker = sig.replay.trackers.SlotTracker;
const EpochTracker = sig.replay.trackers.EpochTracker;
const RwMux = sig.sync.RwMux;
const Channel = sig.sync.Channel;
const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const LandedVote = sig.runtime.program.vote.state.LandedVote;
const VoteStateVersions = sig.runtime.program.vote.state.VoteStateVersions;
const ReplayResult = sig.replay.execution.ReplayResult;
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

// Does it make sense to come up with a lib/harness like tool that allows:
//
// Have a test fixture state that can easily be mutated prior to calling consensus.process
// ie:
// test_fixture.setRoot(...)
// test_fixture.setFroozenRoot(...)
// test_fixture.updateSlotTracker(...)
// test_fixture.updateSProgress(...)
// etc
//
// the idea is to have easy methods to setup the state.
// ...
//
// Then executed the test:
//
// consensus.process(alloc, test_fixture.slot_tracker_rw, test_fixture.epoch_tracker_rw etc)
//
// Then assert:
//
// assert test_fixture

// State setup
// - Set root
//   - Set slot constants
//   - Set slot states
//   - freeze root
//      - set blockhash queue on root state
//
// - Set slot tracker
// - Do above for slot 1
//
// - Set up the epoch tracker
//   - with empty/genesis state
// - Set up the progress map
test "vote on heaviest frozen descendant with no switch" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    // Freeze root.
    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(
        allocator,
        root_slot,
        .{
            .constants = root_consts,
            .state = root_state,
        },
    );
    defer slot_tracker.deinit(allocator);

    // Add frozen descendant slot 1
    const slot1_hash = Hash{ .data = .{1} ** Hash.SIZE };
    {
        const slot: u64 = 1;
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash = .init(slot1_hash);

        try slot_tracker.put(
            allocator,
            slot,
            .{ .constants = slot_constants, .state = slot_state },
        );
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);
    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };
    {
        const epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);
    }
    defer epoch_tracker.deinit(allocator);
    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    // Add root and slot 1 entries into progress map.
    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        const fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        try progress.map.put(allocator, 0, fork_progress0);
        try progress.map.put(allocator, 1, fork_progress1);
    }

    // Include a ReplayResult for slot 1 to drive processResult/fork-choice
    const results = [_]ReplayResult{
        .{
            .slot = 1,
            .output = .{
                .last_entry_hash = Hash{ .data = .{9} ** Hash.SIZE },
            },
        },
    };

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const external = TowerConsensus.Dependencies.External{
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .gossip_table = null,
        .run_vote_listener = false,
    };

    // Build consensus dependencies
    const deps = TowerConsensus.Dependencies{
        .logger = .noop,
        .my_identity = Pubkey.initRandom(std.crypto.random),
        .vote_identity = Pubkey.initRandom(std.crypto.random),
        .root_slot = root_slot,
        .root_hash = Hash.ZEROES,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger_reader = stubs.ledger.reader,
        .ledger_writer = stubs.ledger.result_writer,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    // Component entry point being tested
    try consensus.process(
        allocator,
        &slot_tracker_rw,
        &epoch_tracker_rw,
        &progress,
        &results,
    );

    try std.testing.expectEqual(1, consensus.replay_tower.lastVotedSlot());
    try std.testing.expectEqual(1, consensus.fork_choice.heaviestOverallSlot().slot);

    const stats1 = progress.getForkStats(1).?;
    try std.testing.expect(stats1.computed);
    try std.testing.expectEqual(1, stats1.block_height);
    // Since we are not voting yet
    try std.testing.expect(consensus.replay_tower.last_vote_tx_blockhash == .non_voting);
}

// State setup
// - Set root
//   - Set slot constants
//   - Set slot states
//   - freeze root
//      - set blockhash queue on root state
//
// - Set slot tracker
// - Do above for slot 1
//
// - Set up the epoch tracker
//   - non-empty
// - Set up the progress map
test "vote accounts with landed votes populate bank stats" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    // Freeze root.
    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(
        allocator,
        root_slot,
        .{
            .constants = root_consts,
            .state = root_state,
        },
    );
    defer slot_tracker.deinit(allocator);

    // Add frozen descendant slot 1
    const slot1_hash = Hash{ .data = .{2} ** Hash.SIZE };
    {
        const slot: u64 = 1;
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash = .init(slot1_hash);

        try slot_tracker.put(
            allocator,
            slot,
            .{ .constants = slot_constants, .state = slot_state },
        );
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };

    // Seed epoch 0 constants with vote accounts and landed votes
    {
        var prng = std.Random.DefaultPrng.init(12345);
        const random = prng.random();
        const stake_per_account = 1000;

        const pubkey_count = 5;
        const vote_pubkeys = try allocator.alloc(Pubkey, pubkey_count);
        defer allocator.free(vote_pubkeys);
        for (vote_pubkeys) |*k| k.* = Pubkey.initRandom(random);

        // Build EpochStakes with those vote accounts
        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            stake_per_account,
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        // Inject landed votes for slot 1 into each vote account
        {
            var vote_accounts = &epoch_stakes.stakes.vote_accounts.vote_accounts;

            for (vote_accounts.values()) |*vote_account| {
                try vote_account.account.state.votes.append(LandedVote{
                    .latency = 0,
                    .lockout = .{ .slot = 1, .confirmation_count = 2 },
                });
            }
        }

        var epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        epoch_consts.stakes.deinit(allocator);
        epoch_consts.stakes = epoch_stakes;

        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);
    }
    defer epoch_tracker.deinit(allocator);

    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    {
        const epochs_ptr, var epochs_lg = epoch_tracker_rw.readWithLock();
        defer epochs_lg.unlock();
        const epoch_consts_ptr = epochs_ptr.epochs.getPtr(0).?;

        const slot_tracker_ptr, var st_lg = slot_tracker_rw.writeWithLock();
        defer st_lg.unlock();
        const slot1_ref = slot_tracker_ptr.get(1).?;
        const stakes_ptr, var stakes_guard = slot1_ref.state.stakes_cache.stakes.writeWithLock();
        defer stakes_guard.unlock();
        stakes_ptr.deinit(allocator);
        stakes_ptr.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
    }

    // Progress map for root and slot 1
    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        const fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        try progress.map.put(allocator, 0, fork_progress0);
        try progress.map.put(allocator, 1, fork_progress1);
    }

    // ReplayResult for slot 1
    const results = [_]ReplayResult{
        .{ .slot = 1, .output = .{ .last_entry_hash = Hash{ .data = .{7} ** Hash.SIZE } } },
    };

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const external = TowerConsensus.Dependencies.External{
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .gossip_table = null,
        .run_vote_listener = false,
    };

    const deps = TowerConsensus.Dependencies{
        .logger = .noop,
        .my_identity = Pubkey.initRandom(std.crypto.random),
        .vote_identity = Pubkey.initRandom(std.crypto.random),
        .root_slot = root_slot,
        .root_hash = Hash.ZEROES,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger_reader = stubs.ledger.reader,
        .ledger_writer = stubs.ledger.result_writer,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &results);

    const stats1 = progress.getForkStats(1).?;
    try std.testing.expect(stats1.computed);
    try std.testing.expectEqual(1, stats1.block_height);

    // With seeded landed votes, these should be populated
    try std.testing.expect(stats1.voted_stakes.count() > 0);
    try std.testing.expect(stats1.lockout_intervals.map.count() > 0);

    try std.testing.expectEqual(1, consensus.replay_tower.lastVotedSlot());
    try std.testing.expect(consensus.replay_tower.last_vote_tx_blockhash == .non_voting);
}
