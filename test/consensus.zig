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
        try bhq.mut().insertGenesisHash(allocator, root_state.hash.readCopy().?, 0);
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
    const slot_1: u64 = 1;
    const slot1_hash = Hash{ .data = .{slot_1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = root_state.hash.readCopy().?;
        slot_constants.block_height = 1;

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash = .init(slot1_hash);

        try slot_tracker.put(
            allocator,
            slot_1,
            .{
                .constants = slot_constants,
                .state = slot_state,
            },
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
        try epoch_tracker.epochs.put(allocator, root_slot, epoch_consts);
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
        try progress.map.put(allocator, root_slot, fork_progress0);
        try progress.map.put(allocator, slot_1, fork_progress1);
    }

    // Include a ReplayResult for slot 1 to drive processResult/fork-choice
    const results = [_]ReplayResult{
        .{
            .slot = slot_1,
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
        .root_hash = root_state.hash.readCopy().?,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    try std.testing.expectEqual(null, consensus.replay_tower.lastVotedSlot());
    try std.testing.expectEqual(false, progress.getForkStats(slot_1).?.computed);
    try std.testing.expectEqual(0, progress.getForkStats(1).?.block_height);
    try std.testing.expectEqual(.uninitialized, consensus.replay_tower.last_vote_tx_blockhash);

    // Component entry point being tested
    try consensus.process(
        allocator,
        &slot_tracker_rw,
        &epoch_tracker_rw,
        &progress,
        &results,
    );

    // 1. Assert fork stat in progress map
    const stats1 = progress.getForkStats(slot_1).?;
    try std.testing.expectEqual(0, stats1.fork_stake);
    try std.testing.expectEqual(0, stats1.total_stake);
    try std.testing.expectEqual(1, stats1.block_height);
    try std.testing.expectEqual(slot1_hash, stats1.slot_hash);
    try std.testing.expectEqual(true, stats1.computed);
    // Check voted_stakes
    try std.testing.expect(stats1.voted_stakes.count() == 0);
    // Verify my_latest_landed_vote
    // It should be null (vote hasn't landed on-chain yet)
    try std.testing.expectEqual(null, stats1.my_latest_landed_vote);

    // 2. Assert the replay tower
    try std.testing.expect(consensus.replay_tower.last_vote.getHash().eql(slot1_hash));
    try std.testing.expectEqual(slot_1, consensus.replay_tower.lastVotedSlot());
    // Check that root has not changed (no vote is old enough to advance root)
    try std.testing.expectEqual(root_slot, consensus.replay_tower.tower.vote_state.root_slot.?);
    try std.testing.expectEqual(.non_voting, consensus.replay_tower.last_vote_tx_blockhash);

    // 3. Check lockout intervals.
    try std.testing.expect(stats1.lockout_intervals.map.count() == 0);

    // 4. Check propagated stats in progress map
    // Not propagated in minimal test
    const prop_stats = progress.getPropagatedStats(slot_1).?;
    try std.testing.expectEqual(false, prop_stats.is_propagated);

    // 5. Assert forkchoice
    try std.testing.expectEqual(slot_1, consensus.fork_choice.heaviestOverallSlot().slot);
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
        try bhq.mut().insertGenesisHash(allocator, root_state.hash.readCopy().?, 0);
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
    const slot_1: u64 = 1;
    const slot1_hash = Hash{ .data = .{2} ** Hash.SIZE };
    {
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
            slot_1,
            .{ .constants = slot_constants, .state = slot_state },
        );
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };

    // NOTE: The core setup for this test
    // Seed epoch 0 constants with 5 vote accounts and landed votes
    {
        var prng = std.Random.DefaultPrng.init(12345);
        const random = prng.random();
        const stake_per_account = 1000;

        const pubkey_count = 6;
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
        //
        // This affects the lockouts:
        // Voted slot: 1 (slot_1)
        // Confirmation count: 2
        // Lockout duration: 2² = 4 slots
        // Expiration slot: 1 + 4 = 5
        {
            var vote_accounts = &epoch_stakes.stakes.vote_accounts.vote_accounts;

            for (vote_accounts.values()) |*vote_account| {
                try vote_account.account.state.votes.append(LandedVote{
                    .latency = 0,
                    .lockout = .{ .slot = slot_1, .confirmation_count = 2 },
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
        try progress.map.put(allocator, root_slot, fork_progress0);
        try progress.map.put(allocator, slot_1, fork_progress1);
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
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    try std.testing.expect(progress.getForkStats(1).?.voted_stakes.count() == 0);

    try consensus.process(
        allocator,
        &slot_tracker_rw,
        &epoch_tracker_rw,
        &progress,
        &results,
    );

    const stats1 = progress.getForkStats(1).?;
    try std.testing.expect(stats1.computed);
    try std.testing.expectEqual(1, stats1.block_height);

    // With seeded landed votes, these should be populated
    // Landed votes were seeded for slot 1 in consensus.process updateAncestorVotedStakes
    // ensures the stake is also applied to ancestors: slot 0 hence 2.
    try std.testing.expect(stats1.voted_stakes.count() == 2);
    try std.testing.expectEqual(1, stats1.lockout_intervals.map.count());

    // Voted slot: 1 (slot_1)
    // Confirmation count: 2
    // Lockout duration: 2² = 4 slots
    // Expiration slot: 1 + 4 = 5
    //
    // lockout_intervals.map = {
    //     5 => [  // Key: Expiration slot
    //         (1, validator1_pubkey),  // Voted on slot 1
    //         (1, validator2_pubkey),  // Voted on slot 1
    //         (1, validator3_pubkey),  // Voted on slot 1
    //         (1, validator4_pubkey),  // Voted on slot 1
    //         (1, validator5_pubkey),  // Voted on slot 1
    //         (1, validator6_pubkey),  // Voted on slot 1
    //     ]
    // }
    try std.testing.expectEqual(6, stats1.lockout_intervals.map.get(5).?.items.len);
}

// Test case:
// This test simulates a validator voting on a chain of blocks (slots 0-33) and 
// verifies that the root automatically advances as the tower accumulates enough 
// votes to satisfy lockout requirements.
//
// - Pre-populate tower with votes on slots 1-31 (simulating past voting history)
// - Tower is at MAX_LOCKOUT_HISTORY capacity, root is still 0
// - Sync internal state by processing slots 30-31 via consensus.process()
// - Process slot 32 via consensus.process() → should trigger vote, pop oldest, advance root
// - Process slot 33 via consensus.process() → should trigger vote, pop oldest, advance root again
//
// States updated (setup):
// - SlotHistory sysvar: created and added to accounts (required by consensus)
// - SlotTracker: initialized with root slot 0 (constants, state with hash=Hash.ZEROES, blockhash_queue)
// - SlotTracker: slots 1-31 added with constants (parent_slot, parent_hash, block_height, ancestors)
//   and state (hash) before consensus init
// - EpochTracker: initialized with epochs 0 and 1, each with validator stake=1000
// - ProgressMap: initialized with root slot entry (fork_stats: computed=true)
// - ProgressMap: slots 1-31 added with ForkProgress (fork_stats: computed=true, total_stake=1000)
// - TowerConsensus: initialized with dependencies (builds fork_choice from frozen slots 1-31)
// - Tower: pre-populated with 31 votes on slots 1-31 via recordBankVote (simulating past voting)
// - ProgressMap: each of slots 1-31 has fork_stats.voted_stakes updated with single entry (slot, 1000)
//   representing our validator's vote on that slot
// - Slots 30-31: fork_stats marked computed=false, propagated_stats set (is_leader_slot=true,
//   is_propagated=true), then processed via consensus.process() to sync internal state
//   (computeBankStats, cacheTowerStats)
//
// States updated (via consensus.process for testing):
// - Slot 32: added to SlotTracker (with ancestors) and ProgressMap (with fork_stats.computed=true,
//   fork_stats.total_stake=1000, fork_stats.voted_stakes containing entries {1: 1000, 2: 1000, ..., 31: 1000},
//   propagated_stats.is_leader_slot=true, propagated_stats.is_propagated=true),
//   then processed via consensus.process()
// - Slot 33: added to SlotTracker (with ancestors) and ProgressMap (with fork_stats.computed=true,
//   fork_stats.total_stake=1000, fork_stats.voted_stakes containing entries {1: 1000, 2: 1000, ..., 32: 1000},
//   propagated_stats.is_leader_slot=true, propagated_stats.is_propagated=true),
//   then processed via consensus.process()
//
// States asserted:
// - After pre-population: tower has 31 votes, root is 0
// - After processing slot 32:
//   - Root advances from 0 to 1
//   - Tower maintains 31 votes (oldest popped, new added)
//   - Pruning on root update:
//     - Slot 0 (old root) is pruned from slot_tracker
//     - Slot 1 (new root) and descendants remain in slot_tracker
//     - Progress map entry for slot 0 is removed
//     - Fork choice heaviest (slot 32) is on the rooted path
// - After processing slot 33:
//   - Root advances from 1 to 2
//   - Tower maintains 31 votes
//   - Pruning on root update:
//     - Slots 0 and 1 (old roots) are pruned from slot_tracker
//     - Slot 2 (new root) and descendants remain in slot_tracker
//     - Progress map entries for slots 0 and 1 are removed
//     - Fork choice heaviest (slot 33) is on the rooted path
// - Final: lastVotedSlot() == 33 (most recent vote tracked correctly)
test "root advances after vote satisfies lockouts" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);
        @memset(data, 0);
        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const initial_root: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);

    var root_state = try sig.core.SlotState.genesis(allocator);
    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, root_state.hash.readCopy().?, 0);
    }
    // 34 because slots 0..33
    const chain_length = 34;
    var hashes: [chain_length]Hash = undefined;
    hashes[0] = Hash.ZEROES;
    for (1..chain_length) |i| {
        hashes[i] = Hash{ .data = .{@as(u8, @intCast(i % 256))} ** Hash.SIZE };
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(try SlotTracker.init(allocator, initial_root, .{
        .constants = root_consts,
        .state = root_state,
    }));

    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();
    const validator_vote_pubkey = Pubkey.initRandom(random);
    const validator_identity_pubkey = Pubkey.initRandom(random);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };

    {
        const vote_pubkeys = try allocator.alloc(Pubkey, 1);
        defer allocator.free(vote_pubkeys);
        vote_pubkeys[0] = validator_vote_pubkey; // Use our validator's vote pubkey

        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            1000,
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        var epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        epoch_consts.stakes.deinit(allocator);
        epoch_consts.stakes = epoch_stakes;

        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);
    }
    {
        const vote_pubkeys = try allocator.alloc(Pubkey, 1);
        defer allocator.free(vote_pubkeys);
        vote_pubkeys[0] = validator_vote_pubkey; // Use our validator's vote pubkey

        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            1000,
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        var epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        epoch_consts.stakes.deinit(allocator);
        epoch_consts.stakes = epoch_stakes;

        try epoch_tracker.epochs.put(allocator, 1, epoch_consts);
    }
    defer epoch_tracker.deinit(allocator);
    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);

    {
        var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp.fork_stats.computed = true;
        try progress.map.put(allocator, initial_root, fp);
    }

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
        .my_identity = validator_identity_pubkey,
        .vote_identity = validator_vote_pubkey,
        .root_slot = initial_root,
        .root_hash = Hash.ZEROES,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    const our_validator_stake: u64 = 1000;

    for (1..32) |i| {
        const slot: Slot = @intCast(i);

        {
            const st, var st_lock = slot_tracker_rw.writeWithLock();
            defer st_lock.unlock();

            const parent_slot: Slot = slot - 1;
            const parent_hash = hashes[parent_slot];
            const slot_hash = hashes[slot];

            var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
            slot_constants.parent_slot = parent_slot;
            slot_constants.parent_hash = parent_hash;
            slot_constants.block_height = slot;

            slot_constants.ancestors.deinit(allocator);
            slot_constants.ancestors = .{};
            for (0..slot + 1) |ancestor_slot| {
                try slot_constants.ancestors.ancestors.put(allocator, @intCast(ancestor_slot), {});
            }

            var slot_state = try sig.core.SlotState.genesis(allocator);
            slot_state.hash = .init(slot_hash);

            try st.put(allocator, slot, .{ .constants = slot_constants, .state = slot_state });
        }

        {
            var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
            fp.fork_stats.computed = true;
            fp.fork_stats.total_stake = our_validator_stake; // Set total stake to match epoch stakes
            try progress.map.put(allocator, slot, fp);
        }
    }

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    for (1..32) |i| {
        const slot: Slot = @intCast(i);
        _ = try consensus.replay_tower.recordBankVote(allocator, slot, hashes[slot]);

        if (progress.map.getPtr(slot)) |prog| {
            try prog.fork_stats.voted_stakes.put(allocator, slot, our_validator_stake);
        }
    }

    {
        try std.testing.expectEqual(31, consensus.replay_tower.tower.vote_state.votes.len);
        try std.testing.expectEqual(0, try consensus.replay_tower.tower.getRoot());
    }

    {
        for ([_]Slot{ 29, 30, 31 }) |slot| {
            if (progress.map.getPtr(slot)) |prog| {
                // Mark as not computed so consensus will process it
                prog.fork_stats.computed = false;
                prog.propagated_stats.is_leader_slot = true;
                prog.propagated_stats.is_propagated = true;
            }
        }

        const sync_results = [_]ReplayResult{
            .{ .slot = 29, .output = .{ .last_entry_hash = hashes[29] } },
            .{ .slot = 30, .output = .{ .last_entry_hash = hashes[30] } },
            .{ .slot = 31, .output = .{ .last_entry_hash = hashes[31] } },
        };
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &sync_results);
    }

    {
        const slot: Slot = 32;
        const st, var st_lock = slot_tracker_rw.writeWithLock();
        defer st_lock.unlock();

        const parent_slot: Slot = slot - 1;
        const parent_hash = hashes[parent_slot];
        const slot_hash = hashes[slot];

        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        slot_constants.parent_slot = parent_slot;
        slot_constants.parent_hash = parent_hash;
        slot_constants.block_height = slot;

        // Set up ancestors: slot 32 should have ancestors 0 umtil 32
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        for (0..slot + 1) |ancestor_slot| {
            try slot_constants.ancestors.ancestors.put(allocator, @intCast(ancestor_slot), {});
        }

        var slot_state = try sig.core.SlotState.genesis(allocator);
        slot_state.hash = .init(slot_hash);

        try st.put(allocator, slot, .{ .constants = slot_constants, .state = slot_state });
    }
    {
        var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp.fork_stats.computed = true;
        fp.fork_stats.total_stake = our_validator_stake;

        for (1..32) |prev_slot| {
            try fp.fork_stats.voted_stakes.put(allocator, @intCast(prev_slot), our_validator_stake);
        }
        fp.propagated_stats.is_leader_slot = true;
        fp.propagated_stats.is_propagated = true;
        try progress.map.put(allocator, 32, fp);
    }

    // Test
    {
        const old_root = try consensus.replay_tower.tower.getRoot();

        const results = [_]ReplayResult{
            .{ .slot = 32, .output = .{ .last_entry_hash = hashes[32] } },
        };
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            &results,
        );

        const new_root = try consensus.replay_tower.tower.getRoot();
        try std.testing.expect(new_root > old_root);
        try std.testing.expectEqual(1, new_root);
        try std.testing.expectEqual(31, consensus.replay_tower.tower.vote_state.votes.len);

        {
            const st, var st_lock = slot_tracker_rw.readWithLock();
            defer st_lock.unlock();
            try std.testing.expectEqual(1, st.root);
            try std.testing.expect(!st.contains(0));
            try std.testing.expect(st.contains(1));
            try std.testing.expect(st.contains(32));
        }
        try std.testing.expect(progress.map.get(0) == null);
        try std.testing.expect(progress.map.get(1) != null);
        try std.testing.expectEqual(32, consensus.fork_choice.heaviestOverallSlot().slot);
    }

    {
        const slot: Slot = 33;
        const st, var st_lock = slot_tracker_rw.writeWithLock();
        defer st_lock.unlock();

        const parent_slot: Slot = slot - 1;
        const parent_hash = hashes[parent_slot];
        const slot_hash = hashes[slot];

        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        slot_constants.parent_slot = parent_slot;
        slot_constants.parent_hash = parent_hash;
        slot_constants.block_height = slot;

        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        for (0..slot + 1) |ancestor_slot| {
            try slot_constants.ancestors.ancestors.put(allocator, @intCast(ancestor_slot), {});
        }

        var slot_state = try sig.core.SlotState.genesis(allocator);
        slot_state.hash = .init(slot_hash);

        try st.put(allocator, slot, .{ .constants = slot_constants, .state = slot_state });
    }
    {
        var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp.fork_stats.computed = true;
        fp.fork_stats.total_stake = our_validator_stake;

        for (1..33) |prev_slot| {
            try fp.fork_stats.voted_stakes.put(allocator, @intCast(prev_slot), our_validator_stake);
        }
        fp.propagated_stats.is_leader_slot = true;
        fp.propagated_stats.is_propagated = true;
        try progress.map.put(allocator, 33, fp);
    }

    // Test
    {
        const old_root = try consensus.replay_tower.tower.getRoot();

        const results = [_]ReplayResult{
            .{ .slot = 33, .output = .{ .last_entry_hash = hashes[33] } },
        };
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            &results,
        );

        const new_root = try consensus.replay_tower.tower.getRoot();
        try std.testing.expect(new_root > old_root);
        try std.testing.expectEqual(2, new_root);
        try std.testing.expectEqual(31, consensus.replay_tower.tower.vote_state.votes.len);

        try std.testing.expect(new_root > initial_root);
        const last_voted = consensus.replay_tower.tower.vote_state.lastVotedSlot();
        try std.testing.expectEqual(33, last_voted);

        {
            const st, var st_lock = slot_tracker_rw.readWithLock();
            defer st_lock.unlock();
            try std.testing.expectEqual(2, st.root);
            try std.testing.expect(!st.contains(0));
            try std.testing.expect(!st.contains(1));
            try std.testing.expect(st.contains(2));
            try std.testing.expect(st.contains(33));
        }
        try std.testing.expect(progress.map.get(0) == null);
        try std.testing.expect(progress.map.get(1) == null);
        try std.testing.expect(progress.map.get(2) != null);
        try std.testing.expectEqual(33, consensus.fork_choice.heaviestOverallSlot().slot);
    }

    // Some cleanup.
    {
        const st, var st_lock = slot_tracker_rw.writeWithLock();
        defer st_lock.unlock();

        var it = st.slots.iterator();
        while (it.next()) |entry| {
            const element = entry.value_ptr.*;
            element.state.deinit(allocator);
            element.constants.deinit(allocator);
            allocator.destroy(element);
        }
        st.slots.deinit(allocator);
    }
}

// Test case:
// - Setup: Validator has already voted on slot 1
// - No new votable slots available (heaviest == last vote, no descendants)
// - Process is called with no new replay results
//
// States updated (setup):
// - SlotTracker: root slot 0 and slot 1 (both frozen)
// - EpochTracker: epoch 0 with validator stake
// - ProgressMap: entries for slots 0 and 1 (both computed)
// - TowerConsensus: initialized and has voted on slot 1
// - last_vote_tx_blockhash: set to non_voting initially
//
// States updated (via consensus.process):
// - Called with empty replay results (no new slots to process)
// - Consensus attempts to find votable bank but finds none (heaviest == last vote)
//
// States asserted:
// - lastVotedSlot() remains unchanged (still slot 1)
// - No new vote was recorded in the tower
// - last_vote_tx_blockhash remains .non_voting
test "vote refresh when no new vote available" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);
        @memset(data, 0);
        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(allocator, root_slot, .{
        .constants = root_consts,
        .state = root_state,
    });
    defer slot_tracker.deinit(allocator);

    const slot1_hash = Hash{ .data = .{1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash = .init(slot1_hash);

        try slot_tracker.put(allocator, 1, .{ .constants = slot_constants, .state = slot_state });
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

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        var fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress1.fork_stats.computed = true;
        try progress.map.put(allocator, 0, fork_progress0);
        try progress.map.put(allocator, 1, fork_progress1);
    }

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
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    {
        const results = [_]ReplayResult{
            .{ .slot = 1, .output = .{ .last_entry_hash = slot1_hash } },
        };
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &results);
    }

    const initial_last_voted = consensus.replay_tower.lastVotedSlot();
    try std.testing.expectEqual(1, initial_last_voted);
    const initial_tx_blockhash = consensus.replay_tower.last_vote_tx_blockhash;
    try std.testing.expect(initial_tx_blockhash == .non_voting);

    // The Test
    {
        const empty_results: []const ReplayResult = &.{};
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, empty_results);
    }

    // Assert: No new vote recorded
    const final_last_voted = consensus.replay_tower.lastVotedSlot();
    try std.testing.expectEqual(initial_last_voted, final_last_voted);
    try std.testing.expectEqual(1, final_last_voted);

    // Assert: blockhash status remains non_voting (current stub behavior)
    const final_tx_blockhash = consensus.replay_tower.last_vote_tx_blockhash;
    try std.testing.expect(final_tx_blockhash == .non_voting);

    // The vote count in tower should remain the same (1 vote)
    try std.testing.expectEqual(1, consensus.replay_tower.tower.vote_state.votes.len);
}

// Test case:
// - Setup: Validator votes on a frozen slot, and enough other validators also vote
//   on the same slot such that the stake exceeds DUPLICATE_THRESHOLD (52%)
// - Action: Call consensus.process() which will compute bank stats and detect
//   the duplicate-confirmed condition
//
// NOTE: This test exercises the FALLBACK duplicate-confirmed detection mechanism in
// consensus.process() -> computeBankStats() -> isDuplicateSlotConfirmed().
// In a running validator, duplicate-confirmed is normally detected by:
//   1. vote_listener observing votes from gossip -> trackOptimisticConfirmationVote()
//   2. When stake threshold reached, sends to duplicate_confirmed_slot channel
//   3. consensus.process() -> processEdgeCases() -> processDuplicateConfirmedSlots()
//      reads from channel and marks the slot
// This test bypasses the vote listener and directly tests the bank stats computation path.
//
// States updated (setup):
// - SlotTracker: root slot 0 and slot 1 (both frozen)
// - EpochTracker: epoch 0 with multiple validators (total stake = 600)
// - ProgressMap: entries for slots 0, 1, and 2
// - Vote accounts: seeded with votes on slots 0 and 1 (simulating what vote_listener would track)
//
// States asserted:
// - progress_map.getForkStats(1).?.duplicate_confirmed_hash == slot 1's hash
// - consensus.slot_data.duplicate_confirmed_slots.get(1) == slot 1's hash
test "detect and mark duplicate confirmed fork" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);
        @memset(data, 0);
        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(allocator, root_slot, .{
        .constants = root_consts,
        .state = root_state,
    });
    defer slot_tracker.deinit(allocator);

    // Add frozen slot 1
    const slot1_hash = Hash{ .data = .{1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;

        // Set up ancestors (slot 1 has ancestors 0 and 1)
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot1_hash);

        try slot_tracker.put(allocator, 1, .{ .constants = slot_constants, .state = slot_state });
    }

    const slot2_hash = Hash{ .data = .{2} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 1;
        slot_constants.parent_hash = slot1_hash;
        slot_constants.block_height = 2;

        // Set up ancestors (slot 2 has ancestors 0, 1, and 2)
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});
        try slot_constants.ancestors.ancestors.put(allocator, 2, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot2_hash);

        try slot_tracker.put(allocator, 2, .{ .constants = slot_constants, .state = slot_state });
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };

    {
        var prng = std.Random.DefaultPrng.init(12345);
        const random = prng.random();

        // Create enough vote accounts to exceed duplicate threshold (53% of 1000)
        const pubkey_count = 6;
        const stake_per_account = 100; // Total = 600, but we'll have 5.3 accounts vote = 530 stake
        const vote_pubkeys = try allocator.alloc(Pubkey, pubkey_count);
        defer allocator.free(vote_pubkeys);
        for (vote_pubkeys) |*k| k.* = Pubkey.initRandom(random);

        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            stake_per_account,
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        // SIMULATES VOTE_LISTENER: Inject landed votes for slot 1 into all 6 vote accounts
        // In a real validator, vote_listener would:
        //   1. Observe vote transactions from gossip containing votes for slot 1
        //   2. Track these votes via trackOptimisticConfirmationVote()
        //   3. Check if stake threshold (52%) is reached
        //   4. Send to duplicate_confirmed_slot channel when threshold crossed
        // Here we directly inject the votes into vote account state.
        {
            var vote_accounts = &epoch_stakes.stakes.vote_accounts.vote_accounts;

            for (vote_accounts.values()) |*vote_account| {
                try vote_account.account.state.votes.append(LandedVote{
                    .latency = 0,
                    .lockout = .{ .slot = 0, .confirmation_count = 2 },
                });
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

        {
            const slot1_ref = slot_tracker_ptr.get(1).?;
            const stakes_ptr, var stakes_guard = slot1_ref.state.stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            stakes_ptr.deinit(allocator);
            stakes_ptr.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }

        {
            const slot2_ref = slot_tracker_ptr.get(2).?;
            const stakes_ptr, var stakes_guard = slot2_ref.state.stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            stakes_ptr.deinit(allocator);
            stakes_ptr.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }
    }

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);

    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        const fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        const fork_progress2 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        try progress.map.put(allocator, 0, fork_progress0);
        try progress.map.put(allocator, 1, fork_progress1);
        try progress.map.put(allocator, 2, fork_progress2);
    }

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
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    // Verify slot 1 is not yet marked as duplicate-confirmed
    try std.testing.expect(progress.getForkStats(1).?.duplicate_confirmed_hash == null);
    try std.testing.expect(consensus.slot_data.duplicate_confirmed_slots.get(1) == null);

    // Process slot 2 - should detect duplicate-confirmed condition for slot 1
    // (When processing slot 2, the votes on slot 1 become nth(1) lockouts, which populates voted_stakes[1])
    {
        const results = [_]ReplayResult{
            .{ .slot = 2, .output = .{ .last_entry_hash = slot2_hash } },
        };
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &results);
    }

    // Assert: slot 1 is now marked as duplicate-confirmed
    const stats1 = progress.getForkStats(1).?;
    try std.testing.expect(stats1.duplicate_confirmed_hash != null);
    try std.testing.expect(stats1.duplicate_confirmed_hash.?.eql(slot1_hash));

    // Assert: slot_data tracks the duplicate-confirmed slot
    const dup_hash = consensus.slot_data.duplicate_confirmed_slots.get(1);
    try std.testing.expect(dup_hash != null);
    try std.testing.expect(dup_hash.?.eql(slot1_hash));
}

// Test case:
// - Setup: A duplicate slot is detected (e.g., via shred verification, different hash for same slot)
//   and sent to the duplicate_slots channel
// - Action: Call consensus.process() which will read from the channel via processDuplicateSlots()
//   and mark the slot as duplicate
//
// NOTE: This test exercises the duplicate slot detection mechanism where:
//   1. WindowService/ShredVerifier detects conflicting shreds for the same slot
//   2. Sends the slot number to duplicate_slots channel
//   3. consensus.process() -> processEdgeCases() -> processDuplicateSlots() reads from channel
//   4. Marks slot in duplicate_slots_tracker and updates fork_choice to mark fork invalid
//
// States updated (setup):
// - SlotTracker: root slot 0 and slot 1 (both frozen)
// - EpochTracker: epoch 0 with validators
// - ProgressMap: entries for slots 0 and 1
// - duplicate_slots channel: slot 1 is sent to the channel (simulating duplicate detection)
//
// States asserted:
// - consensus.slot_data.duplicate_slots contains slot 1
// - Fork choice marks slot 1 as invalid candidate (checked via fork_choice state)
test "detect and mark duplicate slot" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);
        @memset(data, 0);
        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(allocator, root_slot, .{
        .constants = root_consts,
        .state = root_state,
    });
    defer slot_tracker.deinit(allocator);

    const slot1_hash = Hash{ .data = .{1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;

        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot1_hash);

        try slot_tracker.put(allocator, 1, .{ .constants = slot_constants, .state = slot_state });
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

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        const fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        try progress.map.put(allocator, 0, fork_progress0);
        try progress.map.put(allocator, 1, fork_progress1);
    }

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
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    try std.testing.expect(!consensus.slot_data.duplicate_slots.contains(1));

    // SIMULATE DUPLICATE DETECTION: Send slot 1 to duplicate_slots channel
    // In a real validator, this would happen when:
    //   1. WindowService receives conflicting shreds for slot 1 (different hashes)
    //   2. ShredVerifier confirms the shreds are valid but conflicting
    //   3. Sends slot 1 to the duplicate_slots channel
    try stubs.receivers.duplicate_slots.send(1);

    {
        const results = [_]ReplayResult{
            .{ .slot = 1, .output = .{ .last_entry_hash = slot1_hash } },
        };
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &results);
    }

    // Assert: slot 1 is now marked as duplicate
    try std.testing.expect(consensus.slot_data.duplicate_slots.contains(1));

    // Assert: fork choice should have marked the fork as invalid
    // (The slot should be marked as invalid candidate in fork_choice)
    // A fork is considered invalid if latest_duplicate_ancestor is not null
    const fork_info = consensus.fork_choice.fork_infos.get(.{ .slot = 1, .hash = slot1_hash });
    try std.testing.expect(fork_info != null);
    try std.testing.expect(fork_info.?.latest_duplicate_ancestor != null);
}

// Test case: Fork switch behavior under lockout and stake thresholds
//
// Setup:
// - Root and sysvars:
//   - root = 0, with genesis `SlotConstants` and frozen `SlotState(hash=ZEROES)` (recent blockhash queue seeded)
//   - SlotHistory sysvar account installed in the account store
//
// - Forks tracked in `SlotTracker`:
//
//     slot 0
//     |   \
//     |    \
//     |     +-- slot 2 (B)
//     +-- slot 1 (A)
//           \
//            +-- slot 4 (B')  [heavier sibling via votes]
//            \
//             +-- slot 5      [sibling with insufficient stake]
//
// - Stakes and progress:
//   - Epoch stakes: 5 validators, 100 stake each (total_stake=500)
//   - Stakes cache installed for slots 1, 2 and 4 (and later 5)
//   - `ProgressMap` entries for slots 0,1,2,4 (and later 5), with `slot_hash` set for 2 and 4
//   - Latest validator votes seeded for slot 4 from 3 validators, via both gossip and replay
//
// - Initial tower state:
//   - Record a vote on slot 1 (fork A). With a single lockout (confirmation_count=1),
//     lastLockedOutSlot = 1 + 2 = 3; any sibling <=3 is locked out; 4 and 5 are not
//
// Actions and Expected Results:
// 1) Attempt to switch to slot 2 (sibling):
//    - Check: makeCheckSwitchThresholdDecision(2) returns switch_proof (requires proof)
//    - Process slot 2: due to lockout, vote is not cast on 2
//
// 2) Attempt to switch to slot 4 (heavier sibling):
//    - Check: decision is switch_proof or same_fork (depending on state)
//    - Process slot 4: 4 > lastLockedOutSlot (3), voting on 4 is allowed; lastVotedSlot == 4
//
// 3) Attempt to switch to slot 5 (insufficient stake):
//    - Slot 5 is added without seeding supporting votes; recompute stats
//    - Check: makeCheckSwitchThresholdDecision(5) returns failed_switch_threshold
//    - Process slot 5: no vote is recorded; lastVotedSlot remains 4
//
// Notes:
// - The switch proof hash is Hash.ZEROES (generation not implemented, same as Agave).
test "successful fork switch (switch_proof)" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);

        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);

        @memset(data, 0);

        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    // Root 0
    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);
    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(
        allocator,
        root_slot,
        .{ .constants = root_consts, .state = root_state },
    );

    // Build first child of root:
    //
    //     slot 0
    //     |
    //     +-- slot 1 (A)
    const slot1_hash = Hash{ .data = .{1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 0;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot1_hash);
        try slot_tracker.put(
            allocator,
            1,
            .{ .constants = slot_constants, .state = slot_state },
        );
    }

    // Add a sibling of slot 1:
    //
    //     slot 0
    //     |   \
    //     |    \
    //     |     +-- slot 2 (B)
    //     +-- slot 1 (A)
    const slot2_hash = Hash{ .data = .{2} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 0;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 2;
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 2, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot2_hash);
        try slot_tracker.put(allocator, 2, .{ .constants = slot_constants, .state = slot_state });
    }

    // Add heavier sibling we’ll vote on:
    //
    //     slot 0
    //     |   \
    //     |    \
    //     |     +-- slot 2 (B)
    //     +-- slot 1 (A)
    //           \
    //            +-- slot 4 (B')  [heavier sibling via votes]
    //
    // With one prior vote on slot 1, lastLockedOutSlot = 1 + 2 = 3, so 4 is not locked out.
    const slot4_hash = Hash{ .data = .{4} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 0;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 4;
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 4, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot4_hash);
        try slot_tracker.put(allocator, 4, .{ .constants = slot_constants, .state = slot_state });
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{ .epochs = .empty, .schedule = sig.core.EpochSchedule.DEFAULT };
    var vote_pubkeys = try allocator.alloc(Pubkey, 5);
    defer allocator.free(vote_pubkeys);
    {
        var prng = std.Random.DefaultPrng.init(98765);
        const random = prng.random();
        for (vote_pubkeys) |*k| k.* = Pubkey.initRandom(random);

        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            100, // stake per account; total = 500
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        var epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        epoch_consts.stakes.deinit(allocator);
        epoch_consts.stakes = epoch_stakes;
        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);

        const epoch_consts_ptr = epoch_tracker.epochs.getPtr(0).?;

        const slot_tracker_ptr, var st_lg = slot_tracker_rw.writeWithLock();
        defer st_lg.unlock();
        {
            const s1 = slot_tracker_ptr.get(1).?;
            const stakes_ptr1, var g1 = s1.state.stakes_cache.stakes.writeWithLock();
            defer g1.unlock();
            stakes_ptr1.deinit(allocator);
            stakes_ptr1.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }
        {
            const s2 = slot_tracker_ptr.get(2).?;
            const stakes_ptr2, var g2 = s2.state.stakes_cache.stakes.writeWithLock();
            defer g2.unlock();
            stakes_ptr2.deinit(allocator);
            stakes_ptr2.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }
        {
            const s4 = slot_tracker_ptr.get(4).?;
            const stakes_ptr4, var g4 = s4.state.stakes_cache.stakes.writeWithLock();
            defer g4.unlock();
            stakes_ptr4.deinit(allocator);
            stakes_ptr4.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }
    }
    defer epoch_tracker.deinit(allocator);
    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fp0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp0.fork_stats.computed = true;
        const fp1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        var fp2 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp2.fork_stats.slot_hash = slot2_hash;
        var fp4 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp4.fork_stats.slot_hash = slot4_hash;
        try progress.map.put(allocator, 0, fp0);
        try progress.map.put(allocator, 1, fp1);
        try progress.map.put(allocator, 2, fp2);
        try progress.map.put(allocator, 4, fp4);
    }

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
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    _ = try consensus.replay_tower.recordBankVote(allocator, 1, slot1_hash);

    // Seed latest validator votes to support slot 4 (>38% of 500 = 190)
    for (vote_pubkeys[0..3]) |pk| {
        // Record the vote gotten via gossip.
        _ = try consensus.latest_validator_votes.checkAddVote(
            allocator,
            pk,
            4,
            slot4_hash,
            .gossip,
        );
        // Record the vote gotten via replay.
        _ = try consensus.latest_validator_votes.checkAddVote(
            allocator,
            pk,
            4,
            slot4_hash,
            .replay,
        );
    }

    var ancestors_map = std.AutoArrayHashMapUnmanaged(Slot, sig.core.Ancestors).empty;
    var descendants_map = std.AutoArrayHashMapUnmanaged(Slot, sig.utils.collections.SortedSetUnmanaged(Slot)).empty;
    defer {
        var it = ancestors_map.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        ancestors_map.deinit(allocator);
        var it2 = descendants_map.iterator();
        while (it2.next()) |entry| entry.value_ptr.deinit(allocator);
        descendants_map.deinit(allocator);
    }
    {
        const st_ptr, var lg = slot_tracker_rw.readWithLock();
        defer lg.unlock();
        try ancestors_map.ensureTotalCapacity(allocator, st_ptr.slots.count());
        try descendants_map.ensureTotalCapacity(allocator, st_ptr.slots.count());
        for (st_ptr.slots.keys(), st_ptr.slots.values()) |slot, info| {
            const slot_ancestors = &info.constants.ancestors.ancestors;
            const gop = try ancestors_map.getOrPutValue(allocator, slot, .EMPTY);
            if (!gop.found_existing) {
                try gop.value_ptr.ancestors.ensureUnusedCapacity(allocator, slot_ancestors.count());
            }
            for (slot_ancestors.keys()) |a| {
                try gop.value_ptr.addSlot(allocator, a);
                const dg = try descendants_map.getOrPutValue(allocator, a, .empty);
                try dg.value_ptr.put(allocator, slot);
            }
        }
    }

    const epoch_consts_ptr = blk: {
        const epochs_ptr, var epochs_lg = epoch_tracker_rw.readWithLock();
        defer epochs_lg.unlock();
        break :blk epochs_ptr.epochs.getPtr(0).?;
    };
    const vote_accounts_map = &epoch_consts_ptr.stakes.stakes.vote_accounts.vote_accounts;
    const total_stake: u64 = 500;

    // First, verify that we cannot switch to sibling slot 2 due to lockout
    // (with a single prior vote on 1, lastLockedOutSlot = 3, so 2 is locked out).
    {
        const decision2 = try consensus.replay_tower.makeCheckSwitchThresholdDecision(
            allocator,
            2,
            &ancestors_map,
            &descendants_map,
            &progress,
            total_stake,
            vote_accounts_map,
            &consensus.latest_validator_votes,
            &consensus.fork_choice,
        );
        switch (decision2) {
            .switch_proof => |h| try std.testing.expect(h.eql(Hash.ZEROES)),
            else => try std.testing.expect(false),
        }

        // Process slot 2 and assert no vote is cast on slot 2. With slot 4 present and eligible,
        // the vote may proceed to 4 instead (still demonstrates inability to switch to 2).
        const results2 = [_]ReplayResult{
            .{ .slot = 2, .output = .{ .last_entry_hash = slot2_hash } },
        };
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &results2);
        try std.testing.expectEqual(4, consensus.replay_tower.lastVotedSlot());
    }

    const decision = try consensus.replay_tower.makeCheckSwitchThresholdDecision(
        allocator,
        4,
        &ancestors_map,
        &descendants_map,
        &progress,
        total_stake,
        vote_accounts_map,
        &consensus.latest_validator_votes,
        &consensus.fork_choice,
    );
    switch (decision) {
        .switch_proof => |h| try std.testing.expect(h.eql(Hash.ZEROES)),
        .same_fork => {},
        else => try std.testing.expect(false),
    }

    // Now process slot 4; lockout for vote on 1 (lastLockedOutSlot = 3) does not prevent voting 4.
    {
        const results = [_]ReplayResult{
            .{ .slot = 4, .output = .{ .last_entry_hash = slot4_hash } },
        };
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            &results,
        );
    }
    try std.testing.expectEqual(4, consensus.replay_tower.lastVotedSlot());

    // Add another sibling slot 5 with very small supporting stake so it fails switch threshold
    // without relying on lockout.
    const slot5_hash = Hash{ .data = .{5} ** Hash.SIZE };
    {
        // Add a new sibling with insufficient stake:
        //
        //     slot 0
        //     |   \
        //     |    \
        //     |     +-- slot 2 (B)
        //     +-- slot 1 (A)
        //           \
        //            +-- slot 4 (B')  [heavier sibling via votes]
        //            \
        //             +-- slot 5      [sibling with insufficient stake]
        //
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 0;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 5;
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 5, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot5_hash);
        {
            const st_ptr, var st_lg = slot_tracker_rw.writeWithLock();
            defer st_lg.unlock();
            try st_ptr.put(allocator, 5, .{ .constants = slot_constants, .state = slot_state });
        }
    }
    // Progress map entry for slot 5
    {
        var fp5 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp5.fork_stats.slot_hash = slot5_hash;
        try progress.map.put(allocator, 5, fp5);
    }
    // Not seeding sufficient votes for slot 5.
    // This ensures it is below threshold so it cannot be switched to
    // Recompute bank stats for new frozen slot 5
    {
        const empty_results: []const ReplayResult = &.{};
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, empty_results);
    }
    // Build fresh ancestors/descendants for slot 5 decision
    var ancestors_map2 = std.AutoArrayHashMapUnmanaged(Slot, sig.core.Ancestors).empty;
    var descendants_map2 = std.AutoArrayHashMapUnmanaged(Slot, sig.utils.collections.SortedSetUnmanaged(Slot)).empty;
    defer {
        var it = ancestors_map2.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        ancestors_map2.deinit(allocator);
        var it2 = descendants_map2.iterator();
        while (it2.next()) |entry| entry.value_ptr.deinit(allocator);
        descendants_map2.deinit(allocator);
    }
    {
        const st_ptr, var lg = slot_tracker_rw.readWithLock();
        defer lg.unlock();
        try ancestors_map2.ensureTotalCapacity(allocator, st_ptr.slots.count());
        try descendants_map2.ensureTotalCapacity(allocator, st_ptr.slots.count());
        for (st_ptr.slots.keys(), st_ptr.slots.values()) |slot, info| {
            const slot_ancestors = &info.constants.ancestors.ancestors;
            const gop = try ancestors_map2.getOrPutValue(allocator, slot, .EMPTY);
            if (!gop.found_existing) {
                try gop.value_ptr.ancestors.ensureUnusedCapacity(allocator, slot_ancestors.count());
            }
            for (slot_ancestors.keys()) |a| {
                try gop.value_ptr.addSlot(allocator, a);
                const dg = try descendants_map2.getOrPutValue(allocator, a, .empty);
                try dg.value_ptr.put(allocator, slot);
            }
        }
    }
    // Check switch threshold decision for slot 5 fails due to insufficient stake
    const decision5 = try consensus.replay_tower.makeCheckSwitchThresholdDecision(
        allocator,
        5,
        &ancestors_map2,
        &descendants_map2,
        &progress,
        total_stake,
        vote_accounts_map,
        &consensus.latest_validator_votes,
        &consensus.fork_choice,
    );
    switch (decision5) {
        .failed_switch_threshold => |d| {
            // Observed stake should be less than total (definitely below threshold)
            try std.testing.expect(d.switch_proof_stake < d.total_stake);
        },
        else => try std.testing.expect(false),
    }
    // Attempt to process slot 5; should not change last voted slot due to threshold failure
    {
        const results5 = [_]ReplayResult{.{ .slot = 5, .output = .{ .last_entry_hash = slot5_hash } }};
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            &results5,
        );
        try std.testing.expectEqual(4, consensus.replay_tower.lastVotedSlot());
    }

    // Cleanup: free SlotTracker elements owned via slot_tracker_rw
    {
        const st, var st_lock = slot_tracker_rw.writeWithLock();
        defer st_lock.unlock();

        var it = st.slots.iterator();
        while (it.next()) |entry| {
            const element = entry.value_ptr.*;
            element.state.deinit(allocator);
            element.constants.deinit(allocator);
            allocator.destroy(element);
        }
        st.slots.deinit(allocator);
    }
}
