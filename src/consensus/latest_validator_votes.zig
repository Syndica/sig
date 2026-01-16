const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SlotAndHash = sig.core.hash.SlotAndHash;

/// The key is the validator's Pubkey, and
/// value is a tuple containing the slot number
/// and a list of slot hashes that the validator voted on.
const LatestVotes = std.AutoArrayHashMapUnmanaged(
    Pubkey,
    struct { slot: Slot, hashes: std.ArrayListUnmanaged(Hash) },
);

/// Analogous to [LatestValidatorVotesForFrozenBanks](https://github.com/anza-xyz/agave/blob/1f147b837a497194977dcd1ed6b5aa25e81de831/core/src/consensus/latest_validator_votes_for_frozen_banks.rs#L10)
pub const LatestValidatorVotes = struct {
    max_gossip_frozen_votes: LatestVotes,
    max_replay_frozen_votes: LatestVotes,
    // Pubkeys that had their `max_frozen_votes` updated since the last fork choice update
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

    pub const VoteKind = enum { replay, gossip };

    pub fn latestVotes(self: *LatestValidatorVotes, vote_kind: VoteKind) *LatestVotes {
        return switch (vote_kind) {
            .replay => &self.max_replay_frozen_votes,
            .gossip => &self.max_gossip_frozen_votes,
        };
    }

    /// Returns whether the vote was actually added, and the latest voted frozen slot.
    /// The vote won't be added, and false will be returned for case when there are newer votes
    /// for this validator compared to the vote being inserted.
    ///
    /// Analogous to [check_add_vote](https://github.com/anza-xyz/agave/blob/fecc916333d376cbe2b1013c75f36b99bacae6c4/core/src/consensus/latest_validator_votes_for_frozen_banks.rs#L22)
    pub fn checkAddVote(
        self: *LatestValidatorVotes,
        allocator: std.mem.Allocator,
        vote_pubkey: Pubkey,
        vote_slot: Slot,
        frozen_hash: Hash,
        vote_kind: VoteKind,
    ) !struct { bool, Slot } {
        const vote_map = self.latestVotes(vote_kind);

        const max_frozen_vote = try vote_map.getOrPut(allocator, vote_pubkey);
        errdefer if (!max_frozen_vote.found_existing)
            std.debug.assert(vote_map.swapRemove(vote_pubkey));

        if (!max_frozen_vote.found_existing) {
            max_frozen_vote.value_ptr.* = .{ .slot = vote_slot, .hashes = .empty };
        } else if (vote_slot > max_frozen_vote.value_ptr.slot) {
            // Clean up existing entry if it exists
            max_frozen_vote.value_ptr.slot = vote_slot;
            max_frozen_vote.value_ptr.hashes.clearRetainingCapacity();

            if (self.fork_choice_dirty_set.getPtr(vote_pubkey)) |existing_entry| {
                existing_entry.slot = vote_slot;
                existing_entry.hashes.clearRetainingCapacity();
            }
        } else if (vote_slot != max_frozen_vote.value_ptr.slot or
            containsHash(max_frozen_vote.value_ptr.hashes.items, frozen_hash))
        {
            // We have newer votes for this validator, we don't care about this vote
            return .{ false, max_frozen_vote.value_ptr.slot };
        }

        try max_frozen_vote.value_ptr.hashes.append(allocator, frozen_hash);
        switch (vote_kind) {
            .replay => {
                // Only record votes detected through replaying blocks,
                // because votes in gossip are not consistently observable
                // if the validator is replacing them.
                const dirty_frozen_hash = try self.fork_choice_dirty_set.getOrPutValue(
                    allocator,
                    vote_pubkey,
                    .{ .slot = vote_slot, .hashes = .empty },
                );
                try dirty_frozen_hash.value_ptr.hashes.append(allocator, frozen_hash);
            },
            .gossip => {},
        }
        return .{ true, vote_slot };
    }

    pub fn takeVotesDirtySet(
        self: *LatestValidatorVotes,
        allocator: std.mem.Allocator,
        root: Slot,
    ) ![]const struct { Pubkey, SlotAndHash } {
        var result = std.ArrayListUnmanaged(
            struct { Pubkey, SlotAndHash },
        ).empty;
        errdefer result.deinit(allocator);

        for (
            self.fork_choice_dirty_set.keys(),
            self.fork_choice_dirty_set.values(),
        ) |key, value| {
            const slot = value.slot;
            if (value.slot < root) continue;
            try result.ensureUnusedCapacity(allocator, value.hashes.items.len);
            for (value.hashes.items) |hash| {
                result.appendAssumeCapacity(.{ key, .{ .slot = slot, .hash = hash } });
            }
        }

        for (self.fork_choice_dirty_set.values()) |*entry| {
            entry.hashes.deinit(allocator);
        }
        self.fork_choice_dirty_set.clearRetainingCapacity();
        return result.toOwnedSlice(allocator);
    }

    pub fn maxGossipFrozenVotes(self: *const LatestValidatorVotes) *const LatestVotes {
        return &self.max_gossip_frozen_votes;
    }
};

const builtin = @import("builtin");

pub fn latestVote(
    lastest_votes: *const LatestValidatorVotes,
    pubkey: Pubkey,
    vote_kind: LatestValidatorVotes.VoteKind,
) ?struct { slot: Slot, hashes: []const Hash } {
    if (!builtin.is_test) {
        @compileError("latestVote should only be called in test mode");
    }
    const is_replay_vote = switch (vote_kind) {
        .replay => true,
        .gossip => false,
    };
    const vote_map = if (is_replay_vote)
        &lastest_votes.max_replay_frozen_votes
    else
        &lastest_votes.max_gossip_frozen_votes;

    if (vote_map.get(pubkey)) |entry| {
        return .{ .slot = entry.slot, .hashes = entry.hashes.items };
    }

    return null;
}

fn runFrozenBanksCheckAddVoteIsReplayTest(
    allocator: std.mem.Allocator,
    vote_kind: LatestValidatorVotes.VoteKind,
) !void {
    if (!builtin.is_test) {
        @compileError("runFrozenBanksCheckAddVoteIsReplayTest should only be called in test mode");
    }
    const testing = std.testing;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var latest_validator_votes: LatestValidatorVotes = .empty;
    defer latest_validator_votes.deinit(allocator);

    var vote_slot: Slot = 1;
    const vote_pubkey = Pubkey.initRandom(random);

    const frozen_hash = Hash.initRandom(random);

    // Case 1: Frozen vote should be added, but the same vote added again
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
                vote_kind,
            );
            try testing.expectEqualDeep(
                expected_result,
                result,
            );

            const latest_vote = latestVote(
                &latest_validator_votes,
                vote_pubkey,
                vote_kind,
            );
            try testing.expect(latest_vote != null);
            try testing.expectEqual(latest_vote.?.slot, vote_slot);
            try testing.expectEqual(latest_vote.?.hashes.len, 1);
            try testing.expectEqual(latest_vote.?.hashes[0], frozen_hash);

            switch (vote_kind) {
                .replay => {
                    const dirty_entry =
                        latest_validator_votes.fork_choice_dirty_set.get(vote_pubkey);
                    try testing.expect(dirty_entry != null);
                    try testing.expectEqual(dirty_entry.?.slot, vote_slot);
                    try testing.expectEqual(dirty_entry.?.hashes.items.len, 1);
                    try testing.expectEqual(dirty_entry.?.hashes.items[0], frozen_hash);
                },
                .gossip => {
                    try testing.expect(
                        !latest_validator_votes.fork_choice_dirty_set.contains(
                            vote_pubkey,
                        ),
                    );
                },
            }
        }
    }

    // Case 2: Adding duplicate vote for same slot should update the state
    const duplicate_frozen_hash = Hash.initRandom(random);
    const all_frozen_hashes = [2]Hash{ frozen_hash, duplicate_frozen_hash };
    {
        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            duplicate_frozen_hash,
            vote_kind,
        );
        try testing.expectEqualDeep(result, .{ true, vote_slot });

        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            vote_kind,
        );
        try testing.expect(latest_vote != null);
        try testing.expectEqual(latest_vote.?.slot, vote_slot);
        try testing.expectEqualSlices(Hash, latest_vote.?.hashes, &all_frozen_hashes);

        switch (vote_kind) {
            .replay => {
                const dirty_entry = latest_validator_votes.fork_choice_dirty_set.get(vote_pubkey);
                try testing.expect(dirty_entry != null);
                try testing.expectEqual(dirty_entry.?.slot, vote_slot);
                try testing.expectEqualSlices(
                    Hash,
                    dirty_entry.?.hashes.items,
                    &all_frozen_hashes,
                );
            },
            .gossip => {
                try testing.expect(
                    !latest_validator_votes.fork_choice_dirty_set.contains(vote_pubkey),
                );
            },
        }
    }

    // Case 3: Adding a vote for a new higher slot that *is* frozen
    {
        const new_frozen_hash = Hash.initRandom(random);

        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            new_frozen_hash,
            vote_kind,
        );
        try testing.expectEqual(result, .{ true, vote_slot });
        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            vote_kind,
        );
        try testing.expectEqual(latest_vote.?.slot, vote_slot);
        try testing.expectEqual(
            latest_vote.?.hashes[latest_vote.?.hashes.len - 1],
            new_frozen_hash,
        );

        switch (vote_kind) {
            .replay => {
                const dirty_entry =
                    latest_validator_votes.fork_choice_dirty_set.get(vote_pubkey);
                try testing.expectEqual(dirty_entry.?.slot, vote_slot);
                try testing.expectEqual(
                    dirty_entry.?.hashes.items[dirty_entry.?.hashes.items.len - 1],
                    new_frozen_hash,
                );
            },
            .gossip => {
                try testing.expect(
                    !latest_validator_votes.fork_choice_dirty_set.contains(vote_pubkey),
                );
            },
        }
    }

    // Case 4: Adding a vote for a new pubkey should also update the state
    {
        vote_slot += 1;
        const new_vote_pubkey = Pubkey.initRandom(random);
        const new_frozen_hash2 = Hash.initRandom(random);

        const result = try latest_validator_votes.checkAddVote(
            allocator,
            new_vote_pubkey,
            vote_slot,
            new_frozen_hash2,
            vote_kind,
        );
        try testing.expectEqual(result, .{ true, vote_slot });
        const latest_vote = latestVote(
            &latest_validator_votes,
            new_vote_pubkey,
            vote_kind,
        );
        try testing.expectEqual(latest_vote.?.slot, vote_slot);
        try testing.expectEqual(latest_vote.?.hashes[0], new_frozen_hash2);

        switch (vote_kind) {
            .replay => {
                const dirty_entry =
                    latest_validator_votes.fork_choice_dirty_set.getPtr(new_vote_pubkey) orelse
                    return error.TestExpectedNonNull;
                try testing.expectEqual(dirty_entry.slot, vote_slot);
                try testing.expectEqual(dirty_entry.hashes.items[0], new_frozen_hash2);
            },
            .gossip => try testing.expectEqual(
                null,
                latest_validator_votes.fork_choice_dirty_set.getPtr(new_vote_pubkey),
            ),
        }
    }
}

fn setupDirtySet(
    allocator: std.mem.Allocator,
    random: std.Random,
    lvvfb: *LatestValidatorVotes,
    num_validators: u64,
    vote_kind: LatestValidatorVotes.VoteKind,
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
            vote_kind,
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
            vote_kind,
        );
        try std.testing.expectEqual(.{ true, vote_slot }, check2);

        switch (vote_kind) {
            .replay => {
                try result.append(.{ vote_pubkey, .{ .slot = vote_slot, .hash = frozen_hash1 } });
                try result.append(.{ vote_pubkey, .{ .slot = vote_slot, .hash = frozen_hash2 } });
            },
            .gossip => {},
        }
    }

    return result;
}

fn runFrozenBanksTakeVotesDirtySet(
    allocator: std.mem.Allocator,
    vote_kind: LatestValidatorVotes.VoteKind,
) !void {
    if (!@import("builtin").is_test) {
        @compileError("runFrozenBanksTakeVotesDirtySet should only be called in test mode");
    }
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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
            vote_kind,
        );
        defer expected_dirty_set.deinit();

        const votes_dirty_set_output =
            try latest_validator_votes.takeVotesDirtySet(allocator, root);
        defer allocator.free(votes_dirty_set_output);

        sortPubkeySlotAndHash(expected_dirty_set.items);
        const mutable = try allocator.dupe(struct { Pubkey, SlotAndHash }, votes_dirty_set_output);
        defer allocator.free(mutable);
        sortPubkeySlotAndHash(mutable);

        try std.testing.expectEqualSlices(
            struct { Pubkey, SlotAndHash },
            expected_dirty_set.items,
            mutable,
        );
        const result = try latest_validator_votes.takeVotesDirtySet(allocator, 0);
        defer allocator.free(result);
        try std.testing.expect(result.len == 0);
    }

    // Test case 2: Taking all the dirty votes >= num_validators - 1 will only return the last vote
    {
        const root = num_validators - 1;

        const dirty_set = try setupDirtySet(
            allocator,
            random,
            &latest_validator_votes,
            num_validators,
            vote_kind,
        );
        defer dirty_set.deinit();

        var expected_dirty_set = std.ArrayList(
            struct { Pubkey, SlotAndHash },
        ).init(std.testing.allocator);
        defer expected_dirty_set.deinit();
        // Get last 2 elements or whatever is available (saturating_sub)
        const start = if (dirty_set.items.len >= 2) dirty_set.items.len - 2 else 0;
        try expected_dirty_set.appendSlice(dirty_set.items[start..]);

        const votes_dirty_set_output =
            try latest_validator_votes.takeVotesDirtySet(allocator, root);
        defer allocator.free(votes_dirty_set_output);

        const mutable = try allocator.dupe(struct { Pubkey, SlotAndHash }, votes_dirty_set_output);
        defer allocator.free(mutable);

        sortPubkeySlotAndHash(mutable);
        sortPubkeySlotAndHash(expected_dirty_set.items);

        try std.testing.expectEqualSlices(
            struct { Pubkey, SlotAndHash },
            mutable,
            expected_dirty_set.items,
        );

        const result =
            try latest_validator_votes.takeVotesDirtySet(allocator, 0);
        try std.testing.expect(result.len == 0);
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

test "latest validator votes check add vote is replay" {
    try runFrozenBanksCheckAddVoteIsReplayTest(std.testing.allocator, .replay);
}

test "latest validator votes check add vote is not replay" {
    try runFrozenBanksCheckAddVoteIsReplayTest(std.testing.allocator, .gossip);
}

test "latest validator votes take votes dirty set is replay" {
    try runFrozenBanksTakeVotesDirtySet(std.testing.allocator, .replay);
}

test "latest validator votes take votes dirty set is not replay" {
    try runFrozenBanksTakeVotesDirtySet(std.testing.allocator, .gossip);
}

test "latest validator votes for frozen banks add replay and gossip vote" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var latest_validator_votes = LatestValidatorVotes.empty;
    defer latest_validator_votes.deinit(allocator);

    // First simulate vote from gossip
    const vote_pubkey = Pubkey.initRandom(random);
    const vote_slot = 1;
    const frozen_hash = Hash.initRandom(random);

    // Votes from gossip
    {
        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            frozen_hash,
            .gossip,
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
            .gossip,
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
            .replay,
        );
        try std.testing.expectEqual(null, latest_vote);

        const votes_dirty_set_output =
            try latest_validator_votes.takeVotesDirtySet(allocator, 0);
        try std.testing.expectEqual(0, votes_dirty_set_output.len);
    }

    // Next simulate vote from replay
    {
        const result = try latest_validator_votes.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            frozen_hash,
            .replay,
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
            .replay,
        );
        try std.testing.expectEqual(latest_vote.?.slot, vote_slot);
        try std.testing.expectEqual(latest_vote.?.hashes.len, 1);
        try std.testing.expectEqual(latest_vote.?.hashes[0], frozen_hash);
    }
    {
        const latest_vote = latestVote(
            &latest_validator_votes,
            vote_pubkey,
            .gossip,
        );
        try std.testing.expectEqual(latest_vote.?.slot, vote_slot);
        try std.testing.expectEqual(latest_vote.?.hashes.len, 1);
        try std.testing.expectEqual(latest_vote.?.hashes[0], frozen_hash);
    }
    {
        const result = try latest_validator_votes.takeVotesDirtySet(allocator, 0);
        defer allocator.free(result);
        try std.testing.expectEqual(result[0][0], vote_pubkey);
        try std.testing.expectEqual(result[0][1].slot, vote_slot);
        try std.testing.expectEqual(result[0][1].hash, frozen_hash);
    }
}
