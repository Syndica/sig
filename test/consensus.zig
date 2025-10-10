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

// Test case:
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
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
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
        .ledger_reader = stubs.ledger.reader,
        .ledger_writer = stubs.ledger.result_writer,
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
