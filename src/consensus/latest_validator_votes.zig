const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SlotAndHash = sig.core.hash.SlotAndHash;

const LatestVotes = std.AutoArrayHashMapUnmanaged(
    Pubkey,
    struct { slot: Slot, hashes: std.ArrayListUnmanaged(Hash) },
);

/// Analogous to [LatestValidatorVotesForFrozenBanks](https://github.com/anza-xyz/agave/blob/1f147b837a497194977dcd1ed6b5aa25e81de831/core/src/consensus/latest_validator_votes_for_frozen_banks.rs#L10)
pub const LatestValidatorVotes = struct {
    max_gossip_frozen_votes: LatestVotes,
    max_replay_frozen_votes: LatestVotes,
    // Pubkeys that had their `max_frozen_votes` updated since the last
    // fork choice update
    fork_choice_dirty_set: LatestVotes,

    pub const empty: LatestValidatorVotes = .{
        .max_gossip_frozen_votes = .empty,
        .max_replay_frozen_votes = .empty,
        .fork_choice_dirty_set = .empty,
    };

    pub fn deinit(self: *LatestValidatorVotes, allocator: std.mem.Allocator) void {
        for (self.max_gossip_frozen_votes.values()) |*entry| {
            entry.hashes.deinit(allocator);
        }
        self.max_gossip_frozen_votes.deinit(allocator);

        for (self.max_replay_frozen_votes.values()) |*entry| {
            entry.hashes.deinit(allocator);
        }
        self.max_replay_frozen_votes.deinit(allocator);

        for (self.fork_choice_dirty_set.values()) |*entry| {
            entry.hashes.deinit(allocator);
        }
        self.fork_choice_dirty_set.deinit(allocator);
    }

    fn containsHash(slice: []const Hash, needle: Hash) bool {
        for (slice) |item| {
            if (item.eql(needle)) return true;
        }
        return false;
    }

    pub fn checkAddVote(
        self: *LatestValidatorVotes,
        allocator: std.mem.Allocator,
        vote_pubkey: Pubkey,
        vote_slot: Slot,
        maybe_frozen_hash: ?Hash,
        is_replay_vote: bool,
    ) !struct { bool, ?Slot } {
        // `frozen_hash.is_some()` if the bank with slot == `vote_slot` is frozen
        // Returns whether the vote was actually added, and the latest voted frozen slot
        const vote_map = if (is_replay_vote)
            &self.max_replay_frozen_votes
        else
            &self.max_gossip_frozen_votes;

        const maybe_pubkey_max_frozen_votes = vote_map.getEntry(vote_pubkey);
        if (maybe_frozen_hash) |frozen_hash| {
            if (maybe_pubkey_max_frozen_votes) |occupied_entry| {
                const latest_frozen_vote_slot = &occupied_entry.value_ptr.slot;
                const latest_frozen_vote_hashes = &occupied_entry.value_ptr.hashes;
                if (vote_slot > latest_frozen_vote_slot.*) {
                    latest_frozen_vote_hashes.deinit(allocator);

                    var hashes = std.ArrayListUnmanaged(Hash).empty;
                    errdefer hashes.deinit(allocator);

                    try hashes.append(allocator, frozen_hash);
                    if (is_replay_vote) {
                        // Only record votes detected through replaying blocks,
                        // because votes in gossip are not consistently observable
                        // if the validator is replacing them.
                        const hashes_cloned = try hashes.clone(allocator);

                        // Clean up existing entry if it exists
                        if (self.fork_choice_dirty_set.getEntry(vote_pubkey)) |existing_entry| {
                            existing_entry.value_ptr.hashes.deinit(allocator);
                        }

                        try self.fork_choice_dirty_set.put(
                            allocator,
                            vote_pubkey,
                            .{ .slot = vote_slot, .hashes = hashes_cloned },
                        );
                    }
                    latest_frozen_vote_slot.* = vote_slot;
                    latest_frozen_vote_hashes.* = hashes;
                    return .{ true, vote_slot };
                } else if (vote_slot == latest_frozen_vote_slot.* and !containsHash(
                    latest_frozen_vote_hashes.items,
                    frozen_hash,
                )) {
                    if (is_replay_vote) {
                        // Only record votes detected through replaying blocks,
                        // because votes in gossip are not consistently observable
                        // if the validator is replacing them.
                        const dirty_frozen_hashes = try self.fork_choice_dirty_set.getOrPut(
                            allocator,
                            vote_pubkey,
                        );
                        if (!dirty_frozen_hashes.found_existing) {
                            dirty_frozen_hashes.value_ptr.* = .{ .slot = 0, .hashes = .empty };
                        }
                        try dirty_frozen_hashes.value_ptr.hashes.append(allocator, frozen_hash);
                    }
                    try latest_frozen_vote_hashes.*.append(allocator, frozen_hash);
                    return .{ true, vote_slot };
                } else {
                    // We have newer votes for this validator, we don't care about this vote
                    return .{ false, latest_frozen_vote_slot.* };
                }
            } else {
                var hashes = std.ArrayListUnmanaged(Hash).empty;
                errdefer hashes.deinit(allocator);

                try hashes.append(allocator, frozen_hash);
                try vote_map.put(
                    allocator,
                    vote_pubkey,
                    .{ .slot = vote_slot, .hashes = hashes },
                );
                if (is_replay_vote) {
                    var hashes_cloned = try hashes.clone(allocator);
                    errdefer hashes_cloned.deinit(allocator);

                    try self.fork_choice_dirty_set.putNoClobber(
                        allocator,
                        vote_pubkey,
                        .{ .slot = vote_slot, .hashes = hashes_cloned },
                    );
                }
                return .{ true, vote_slot };
            }
        }
        // Non-frozen banks are not inserted because we only track frozen votes in this
        // struct
        if (maybe_pubkey_max_frozen_votes) |pubkey_max_frozen_votes| {
            return .{ false, pubkey_max_frozen_votes.value_ptr.slot };
        } else {
            return .{ false, null };
        }
    }

    pub fn takeVotesDirtySet(
        self: *LatestValidatorVotes,
        allocator: std.mem.Allocator,
        root: Slot,
    ) !std.ArrayListUnmanaged(struct { Pubkey, SlotAndHash }) {
        var result = std.ArrayListUnmanaged(
            struct { Pubkey, SlotAndHash },
        ).empty;
        errdefer result.deinit(allocator);

        for (self.fork_choice_dirty_set.keys(), self.fork_choice_dirty_set.values()) |
            key,
            value,
        | {
            const slot = value.slot;
            if (value.slot >= root) {
                for (value.hashes.items) |hash| {
                    try result.append(
                        allocator,
                        .{ key, .{ .slot = slot, .hash = hash } },
                    );
                }
            }
        }

        for (self.fork_choice_dirty_set.values()) |*entry| {
            entry.hashes.deinit(allocator);
        }
        self.fork_choice_dirty_set.clearAndFree(allocator);
        return result;
    }

    pub fn maxGossipFrozenVotes(self: *const LatestValidatorVotes) *const LatestVotes {
        return &self.max_gossip_frozen_votes;
    }
};

const builtin = @import("builtin");

pub fn latestVote(
    lastest_votes: *const LatestValidatorVotes,
    pubkey: Pubkey,
    is_replay_vote: bool,
) ?struct { slot: Slot, hashes: []const Hash } {
    if (!builtin.is_test) {
        @compileError("latestVote should only be called in test mode");
    }
    const vote_map = if (is_replay_vote)
        &lastest_votes.max_replay_frozen_votes
    else
        &lastest_votes.max_gossip_frozen_votes;

    if (vote_map.get(pubkey)) |entry| {
        return .{ .slot = entry.slot, .hashes = entry.hashes.items };
    }

    return null;
}

fn runFrozenBanksCheckAddVoteIsReplayTest(allocator: std.mem.Allocator, is_replay_vote: bool) !void {
    if (!builtin.is_test) {
        @compileError("runFrozenBanksCheckAddVoteIsReplayTest should only be called in test mode");
    }
    const testing = std.testing;
    var prng = std.Random.DefaultPrng.init(608159);
    const random = prng.random();

    var latest_validator_votes: LatestValidatorVotes = .empty;
    defer latest_validator_votes.deinit(allocator);

    var vote_slot: Slot = 1;
    const vote_pubkey = Pubkey.initRandom(random);
    // Case 1: Non-frozen banks shouldn't be added
    {
        const frozen_hash: ?Hash = null;
        const result1 = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            frozen_hash,
            is_replay_vote,
        );
        try testing.expectEqualDeep(
            .{ false, null },
            result1,
        );
        try testing.expectEqual(
            0,
            latest_validator_votes.max_replay_frozen_votes.count(),
        );
        try testing.expectEqual(
            0,
            latest_validator_votes.max_gossip_frozen_votes.count(),
        );
        try testing.expectEqual(
            0,
            latest_validator_votes.fork_choice_dirty_set.count(),
        );
    }

    const frozen_hash = Hash.initRandom(random);
    // Case 2: Frozen vote should be added, but the same vote added again
    // shouldn't update state
    {
        const num_repeated_iterations = 3;
        for (0..num_repeated_iterations) |i| {
            const expected_result = if (i == 0)
                .{ true, vote_slot }
            else
                .{ false, vote_slot };

            const result = try latest_validator_votes.checkAddVote(
                allocator,
                vote_pubkey,
                vote_slot,
                frozen_hash,
                is_replay_vote,
            );
            try testing.expectEqualDeep(
                expected_result,
                result,
            );

            const latest_vote = latestVote(
                &latest_validator_votes,
                vote_pubkey,
                is_replay_vote,
            );
            try testing.expect(latest_vote != null);
            try testing.expectEqual(latest_vote.?.slot, vote_slot);
            try testing.expectEqual(latest_vote.?.hashes.len, 1);
            try testing.expectEqual(latest_vote.?.hashes[0], frozen_hash);

            if (is_replay_vote) {
                const dirty_entry =
                    latest_validator_votes.fork_choice_dirty_set.get(
                        vote_pubkey,
                    );
                try testing.expect(dirty_entry != null);
                try testing.expectEqual(dirty_entry.?.slot, vote_slot);
                try testing.expectEqual(dirty_entry.?.hashes.items.len, 1);
                try testing.expectEqual(dirty_entry.?.hashes.items[0], frozen_hash);
            } else {
                try testing.expect(
                    !latest_validator_votes.fork_choice_dirty_set.contains(
                        vote_pubkey,
                    ),
                );
            }
        }
    }

    // Case 3: Adding duplicate vote for same slot should update the state
    const duplicate_frozen_hash = Hash.initRandom(random);
    const all_frozen_hashes = [2]Hash{ frozen_hash, duplicate_frozen_hash };
    {
        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            duplicate_frozen_hash,
            is_replay_vote,
        );
        try testing.expectEqualDeep(result, .{ true, vote_slot });

        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            is_replay_vote,
        );
        try testing.expect(latest_vote != null);
        try testing.expectEqual(latest_vote.?.slot, vote_slot);
        try testing.expectEqualSlices(Hash, latest_vote.?.hashes, &all_frozen_hashes);

        if (is_replay_vote) {
            const dirty_entry = latest_validator_votes.fork_choice_dirty_set.get(
                vote_pubkey,
            );
            try testing.expect(dirty_entry != null);
            try testing.expectEqual(dirty_entry.?.slot, vote_slot);
            try testing.expectEqualSlices(Hash, dirty_entry.?.hashes.items, &all_frozen_hashes);
        } else {
            try testing.expect(
                !latest_validator_votes.fork_choice_dirty_set.contains(vote_pubkey),
            );
        }
    }

    // Case 4: Adding duplicate vote that is not frozen should not update the state
    {
        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            null,
            is_replay_vote,
        );
        try testing.expectEqual(result, .{ false, vote_slot });
        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            is_replay_vote,
        );
        try testing.expect(latest_vote != null);
        try testing.expectEqual(latest_vote.?.slot, vote_slot);
        try testing.expectEqualSlices(Hash, latest_vote.?.hashes, &all_frozen_hashes);

        if (is_replay_vote) {
            const dirty_entry = latest_validator_votes.fork_choice_dirty_set.get(
                vote_pubkey,
            );
            try testing.expect(dirty_entry != null);
            try testing.expectEqual(dirty_entry.?.slot, vote_slot);
            try testing.expectEqualSlices(Hash, dirty_entry.?.hashes.items, &all_frozen_hashes);
        } else {
            try testing.expect(
                !latest_validator_votes.fork_choice_dirty_set.contains(vote_pubkey),
            );
        }
    }

    // Case 5: Adding a vote for a new higher slot that is not yet frozen
    {
        const old_vote_slot = vote_slot;
        vote_slot += 1;
        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            null,
            is_replay_vote,
        );
        try testing.expectEqual(result, .{ false, old_vote_slot });
        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            is_replay_vote,
        );
        try testing.expectEqual(latest_vote.?.slot, old_vote_slot);
        try testing.expectEqualSlices(Hash, latest_vote.?.hashes, &all_frozen_hashes);

        if (is_replay_vote) {
            const dirty_entry = latest_validator_votes.fork_choice_dirty_set.get(
                vote_pubkey,
            );
            try testing.expect(dirty_entry != null);
            try testing.expectEqual(dirty_entry.?.slot, old_vote_slot);
            try testing.expectEqualSlices(Hash, dirty_entry.?.hashes.items, &all_frozen_hashes);
        } else {
            try testing.expect(
                !latest_validator_votes.fork_choice_dirty_set.contains(vote_pubkey),
            );
        }
    }

    // Case 6: Adding a vote for a new higher slot that *is* frozen
    {
        const new_frozen_hash = Hash.initRandom(random);

        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            new_frozen_hash,
            is_replay_vote,
        );
        try testing.expectEqual(result, .{ true, vote_slot });
        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            is_replay_vote,
        );
        try testing.expectEqual(latest_vote.?.slot, vote_slot);
        try testing.expectEqual(latest_vote.?.hashes[0], new_frozen_hash);

        if (is_replay_vote) {
            const dirty_entry =
                latest_validator_votes.fork_choice_dirty_set.get(
                    vote_pubkey,
                );
            try testing.expect(dirty_entry != null);
            try testing.expectEqual(dirty_entry.?.slot, vote_slot);
            try testing.expectEqual(dirty_entry.?.hashes.items[0], new_frozen_hash);
        } else {
            try testing.expect(
                !latest_validator_votes.fork_choice_dirty_set.contains(vote_pubkey),
            );
        }
    }

    // Case 7: Adding a vote for a new pubkey should also update the state
    {
        vote_slot += 1;
        const new_vote_pubkey = Pubkey.initRandom(random);
        const new_frozen_hash2 = Hash.initRandom(random);

        const result = try latest_validator_votes.checkAddVote(
            allocator,
            new_vote_pubkey,
            vote_slot,
            new_frozen_hash2,
            is_replay_vote,
        );
        try testing.expectEqual(result, .{ true, vote_slot });
        const latest_vote = latestVote(
            &latest_validator_votes,
            new_vote_pubkey,
            is_replay_vote,
        );
        try testing.expectEqual(latest_vote.?.slot, vote_slot);
        try testing.expectEqual(latest_vote.?.hashes[0], new_frozen_hash2);

        if (is_replay_vote) {
            const dirty_entry = latest_validator_votes.fork_choice_dirty_set.get(
                new_vote_pubkey,
            );
            try testing.expect(dirty_entry != null);
            try testing.expectEqual(dirty_entry.?.slot, vote_slot);
            try testing.expectEqual(dirty_entry.?.hashes.items[0], new_frozen_hash2);
        } else {
            try testing.expect(
                !latest_validator_votes.fork_choice_dirty_set.contains(
                    new_vote_pubkey,
                ),
            );
        }
    }
}

fn setupDirtySet(
    allocator: std.mem.Allocator,
    random: std.Random,
    lvvfb: *LatestValidatorVotes,
    num_validators: u64,
    is_replay: bool,
) !std.ArrayList(struct { Pubkey, SlotAndHash }) {
    if (!builtin.is_test) {
        @compileError("setupDirtySet should only be called in test mode");
    }

    var result = std.ArrayList(struct { Pubkey, SlotAndHash }).init(allocator);
    errdefer result.deinit();

    for (0..num_validators) |i| {
        const vote_slot = @as(u64, i);
        const vote_pubkey = Pubkey.initRandom(random);
        const frozen_hash1 = Hash.initRandom(random);

        const check1 = try lvvfb.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            frozen_hash1,
            is_replay,
        );
        // This vote slot was frozen, and is the highest slot inserted thus far,
        // so the highest vote should be Some(vote_slot)
        try std.testing.expectEqualDeep(.{ true, vote_slot }, check1);

        // Add a duplicate
        const frozen_hash2 = Hash.initRandom(random);
        const check2 = lvvfb.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            frozen_hash2,
            is_replay,
        );
        try std.testing.expectEqual(.{ true, vote_slot }, check2);

        if (is_replay) {
            try result.append(.{ vote_pubkey, .{ .slot = vote_slot, .hash = frozen_hash1 } });
            try result.append(.{ vote_pubkey, .{ .slot = vote_slot, .hash = frozen_hash2 } });
        }
    }

    return result;
}

fn runFrozenBanksTakeVotesDirtySet(allocator: std.mem.Allocator, is_replay: bool) !void {
    if (!@import("builtin").is_test) {
        @compileError("runFrozenBanksTakeVotesDirtySet should only be called in test mode");
    }
    var prng = std.Random.DefaultPrng.init(608159);
    const random = prng.random();

    var latest_validator_votes = LatestValidatorVotes.empty;
    defer latest_validator_votes.deinit(allocator);

    const num_validators = 10;

    // Test case 1: Taking all the dirty votes >= 0 will return everything
    {
        const root = 0;
        var expected_dirty_set = try setupDirtySet(
            allocator,
            random,
            &latest_validator_votes,
            num_validators,
            is_replay,
        );
        defer expected_dirty_set.deinit();

        var votes_dirty_set_output =
            try latest_validator_votes.takeVotesDirtySet(allocator, root);
        defer votes_dirty_set_output.deinit(allocator);

        sortPubkeySlotAndHash(expected_dirty_set.items);
        sortPubkeySlotAndHash(votes_dirty_set_output.items);

        try std.testing.expectEqualSlices(
            struct { Pubkey, SlotAndHash },
            expected_dirty_set.items,
            votes_dirty_set_output.items,
        );
        var result = try latest_validator_votes.takeVotesDirtySet(allocator, 0);
        defer result.deinit(allocator);
        try std.testing.expect(result.items.len == 0);
    }

    // Test case 2: Taking all the dirty votes >= num_validators - 1 will only return the last vote
    {
        const root = num_validators - 1;

        const dirty_set = try setupDirtySet(
            allocator,
            random,
            &latest_validator_votes,
            num_validators,
            is_replay,
        );
        defer dirty_set.deinit();

        var expected_dirty_set = std.ArrayList(
            struct { Pubkey, SlotAndHash },
        ).init(std.testing.allocator);
        defer expected_dirty_set.deinit();
        // Get last 2 elements or whatever is available (saturating_sub)
        const start = if (dirty_set.items.len >= 2) dirty_set.items.len - 2 else 0;
        try expected_dirty_set.appendSlice(dirty_set.items[start..]);

        var votes_dirty_set_output =
            try latest_validator_votes.takeVotesDirtySet(allocator, root);

        defer votes_dirty_set_output.deinit(allocator);

        sortPubkeySlotAndHash(votes_dirty_set_output.items);
        sortPubkeySlotAndHash(expected_dirty_set.items);

        try std.testing.expectEqualSlices(
            struct { Pubkey, SlotAndHash },
            votes_dirty_set_output.items,
            expected_dirty_set.items,
        );

        var result =
            try latest_validator_votes.takeVotesDirtySet(allocator, 0);
        defer result.deinit(allocator);
        try std.testing.expect(result.items.len == 0);
    }
}

fn sortPubkeySlotAndHash(slice: []struct { Pubkey, SlotAndHash }) void {
    if (!@import("builtin").is_test) {
        @compileError("sortPubkeySlotAndHash should only be called in test mode");
    }
    std.mem.sort(
        struct { Pubkey, SlotAndHash },
        slice,
        {},
        struct {
            fn lessThan(
                _: void,
                a: struct { Pubkey, SlotAndHash },
                b: struct { Pubkey, SlotAndHash },
            ) bool {
                // First compare pubkeys
                const pubkey_cmp = a[0].order(b[0]);
                if (pubkey_cmp != .eq) {
                    return pubkey_cmp == .lt;
                }
                // If pubkeys are equal, compare slots and hashes
                return a[1].order(b[1]) == .lt;
            }
        }.lessThan,
    );
}

test "latest_validator_votes_check_add_vote_is_replay" {
    try runFrozenBanksCheckAddVoteIsReplayTest(std.testing.allocator, true);
}

test "latest_validator_votes_check_add_vote_is_not_replay" {
    try runFrozenBanksCheckAddVoteIsReplayTest(std.testing.allocator, false);
}

test "latest_validator_votes_take_votes_dirty_set_is_replay" {
    try runFrozenBanksTakeVotesDirtySet(std.testing.allocator, true);
}

test "latest_validator_votes_take_votes_dirty_set_is_not_replay" {
    try runFrozenBanksTakeVotesDirtySet(std.testing.allocator, false);
}

test "latest_validator_votes_for_frozen_banks_add_replay_and_gossip_vote" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(608159);
    const random = prng.random();

    var latest_validator_votes = LatestValidatorVotes.empty;
    defer latest_validator_votes.deinit(allocator);

    // First simulate vote from gossip
    const vote_pubkey = Pubkey.initRandom(random);
    const vote_slot = 1;
    const frozen_hash = Hash.initRandom(random);
    var is_replay_vote = false;

    {
        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            frozen_hash,
            is_replay_vote,
        );
        try std.testing.expectEqualDeep(
            .{ true, vote_slot },
            result,
        );
    }

    // Should find the vote in the gossip votes.
    {
        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            is_replay_vote,
        );
        try std.testing.expectEqual(latest_vote.?.slot, vote_slot);
        try std.testing.expectEqual(latest_vote.?.hashes.len, 1);
        try std.testing.expectEqual(latest_vote.?.hashes[0], frozen_hash);
    }

    // Shouldn't find the vote in the replayed votes
    {
        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            !is_replay_vote,
        );
        try std.testing.expectEqual(null, latest_vote);

        var votes_dirty_set_output =
            try latest_validator_votes.takeVotesDirtySet(allocator, 0);
        defer votes_dirty_set_output.deinit(allocator);
        try std.testing.expectEqual(0, votes_dirty_set_output.items.len);
    }

    // Next simulate vote from replay
    is_replay_vote = true;
    {
        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            frozen_hash,
            is_replay_vote,
        );
        try std.testing.expectEqualDeep(
            .{ true, vote_slot },
            result,
        );
    }

    // Should find the vote in the gossip and replay votes
    {
        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            is_replay_vote,
        );
        try std.testing.expectEqual(latest_vote.?.slot, vote_slot);
        try std.testing.expectEqual(latest_vote.?.hashes.len, 1);
        try std.testing.expectEqual(latest_vote.?.hashes[0], frozen_hash);
    }
    {
        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            !is_replay_vote,
        );
        try std.testing.expectEqual(latest_vote.?.slot, vote_slot);
        try std.testing.expectEqual(latest_vote.?.hashes.len, 1);
        try std.testing.expectEqual(latest_vote.?.hashes[0], frozen_hash);
    }
    {
        var result = try latest_validator_votes.takeVotesDirtySet(allocator, 0);
        defer result.deinit(allocator);
        try std.testing.expectEqual(result.items[0][0], vote_pubkey);
        try std.testing.expectEqual(result.items[0][1].slot, vote_slot);
        try std.testing.expectEqual(result.items[0][1].hash, frozen_hash);
    }
}
