const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;

const Logger = sig.trace.Logger("optimistic_vote_verifier");

pub const OptimisticVotesTracker = struct {
    map: std.AutoArrayHashMapUnmanaged(Hash, sig.consensus.vote_tracker.VoteStakeTracker),

    pub const EMPTY: OptimisticVotesTracker = .{ .map = .{} };

    pub fn deinit(self: OptimisticVotesTracker, allocator: std.mem.Allocator) void {
        for (self.map.values()) |vst| vst.deinit(allocator);
        var map = self.map;
        map.deinit(allocator);
    }

    pub fn clone(
        self: OptimisticVotesTracker,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!OptimisticVotesTracker {
        var cloned_ovt = OptimisticVotesTracker.EMPTY;
        errdefer cloned_ovt.deinit(allocator);

        try cloned_ovt.map.ensureTotalCapacity(allocator, self.map.count());
        for (self.map.keys(), self.map.values()) |k, v| {
            var voted = try v.voted.clone(allocator);
            errdefer voted.deinit(allocator);
            cloned_ovt.map.putAssumeCapacity(k, .{ .voted = voted, .stake = v.stake });
        }

        return cloned_ovt;
    }
};

/// Analogous to [OptimisticConfirmationVerifier](https://github.com/anza-xyz/agave/blob/9d8bf065f7aad8257addfc5639ae5cea4e743204/core/src/optimistic_confirmation_verifier.rs#L11)
pub const OptimisticConfirmationVerifier = struct {
    snapshot_start_slot: Slot,
    unchecked_slots: sig.utils.collections.SortedSet(sig.core.hash.SlotAndHash, .{}),
    last_optimistic_slot_ts: sig.time.Instant,

    pub fn deinit(
        self: *OptimisticConfirmationVerifier,
        allocator: std.mem.Allocator,
    ) void {
        self.unchecked_slots.deinit(allocator);
    }

    pub fn init(
        last_optimistic_slot_ts: sig.time.Instant,
        snapshot_start_slot: Slot,
    ) OptimisticConfirmationVerifier {
        return .{
            .snapshot_start_slot = snapshot_start_slot,
            .unchecked_slots = .empty,
            .last_optimistic_slot_ts = last_optimistic_slot_ts,
        };
    }

    /// Returns any optimistic slots that were not rooted
    pub fn verifyForUnrootedOptimisticSlots(
        self: *OptimisticConfirmationVerifier,
        allocator: std.mem.Allocator,
        ledger: *sig.ledger.Ledger,
        root: struct {
            slot: Slot,
            hash: ?Hash,
            ancestors: *const sig.core.Ancestors,
        },
    ) ![]const sig.core.hash.SlotAndHash {
        var after_root: sig.utils.collections.SortedSet(sig.core.hash.SlotAndHash, .{}) = .empty;
        var after_root_moved: bool = false;
        defer if (!after_root_moved) after_root.deinit(allocator);

        var before_or_equal_root: std.ArrayListUnmanaged(sig.core.hash.SlotAndHash) = .empty;
        defer before_or_equal_root.deinit(allocator);
        try before_or_equal_root.ensureUnusedCapacity(allocator, self.unchecked_slots.count());

        var iter = self.unchecked_slots.iterator();
        while (iter.next()) |entry| {
            const sah = entry.key_ptr.*;
            if (sah.slot > root.slot) {
                try after_root.put(allocator, sah, {});
            } else {
                before_or_equal_root.appendAssumeCapacity(sah);
            }
        }

        var old_set = self.unchecked_slots;
        self.unchecked_slots = after_root;
        old_set.deinit(allocator);
        after_root_moved = true;

        var optimistic_root_not_rooted: std.ArrayListUnmanaged(sig.core.hash.SlotAndHash) = .empty;
        errdefer optimistic_root_not_rooted.deinit(allocator);

        for (before_or_equal_root.items) |slot_and_hash| {
            const is_root_slot = slot_and_hash.slot == root.slot;
            const root_hash_mismatch =
                is_root_slot and root.hash != null and !slot_and_hash.hash.eql(root.hash.?);
            const not_in_ancestors = !root.ancestors.containsSlot(slot_and_hash.slot);
            const not_rooted = !(try ledger.reader().isRoot(allocator, slot_and_hash.slot));
            if (root_hash_mismatch or (!is_root_slot and not_in_ancestors and not_rooted)) {
                try optimistic_root_not_rooted.append(allocator, slot_and_hash);
            }
        }

        return try optimistic_root_not_rooted.toOwnedSlice(allocator);
    }

    pub fn addNewOptimisticConfirmedSlots(
        self: *OptimisticConfirmationVerifier,
        allocator: std.mem.Allocator,
        new_optimistic_slots: []const sig.core.hash.SlotAndHash,
        ledger: *sig.ledger.Ledger,
        logger: Logger,
    ) !void {
        if (new_optimistic_slots.len == 0) return;

        // We don't have any information about ancestors before the snapshot root,
        // so ignore those slots
        var result_writer = ledger.resultWriter();
        for (new_optimistic_slots) |slot_and_hash| {
            if (slot_and_hash.slot > self.snapshot_start_slot) {
                result_writer.insertOptimisticSlot(
                    slot_and_hash.slot,
                    slot_and_hash.hash,
                    @intCast(sig.time.getWallclockMs()),
                ) catch |err| {
                    logger.err().logf("insertOptimisticSlot: {s}", .{@errorName(err)});
                };
                try self.unchecked_slots.put(allocator, slot_and_hash, {});
            }
        }

        self.last_optimistic_slot_ts = sig.time.Instant.now();
    }
};

test "OptimisticConfirmationVerifier.addNewOptimisticConfirmedSlots" {
    const allocator = std.testing.allocator;

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    const snapshot_start_slot = 10;

    var verifier = OptimisticConfirmationVerifier.init(
        sig.time.Instant.now(),
        snapshot_start_slot,
    );
    defer verifier.deinit(allocator);

    const slot_hash = Hash.ZEROES;

    try verifier.addNewOptimisticConfirmedSlots(
        allocator,
        &.{.{ .slot = (snapshot_start_slot - 1), .hash = slot_hash }},
        &state,
        .FOR_TESTS,
    );
    {
        var latest = try state.reader().getLatestOptimisticSlots(allocator, 10);
        defer latest.deinit();
        try std.testing.expectEqual(0, latest.items.len);
    }

    try verifier.addNewOptimisticConfirmedSlots(
        allocator,
        &.{.{ .slot = snapshot_start_slot, .hash = slot_hash }},
        &state,
        .FOR_TESTS,
    );
    {
        var latest = try state.reader().getLatestOptimisticSlots(allocator, 10);
        defer latest.deinit();
        try std.testing.expectEqual(0, latest.items.len);
    }

    try verifier.addNewOptimisticConfirmedSlots(
        allocator,
        &.{.{ .slot = (snapshot_start_slot + 1), .hash = slot_hash }},
        &state,
        .FOR_TESTS,
    );
    var latest = try state.reader().getLatestOptimisticSlots(allocator, 10);
    defer latest.deinit();
    try std.testing.expectEqual(1, latest.items.len);
    try std.testing.expectEqual(1, verifier.unchecked_slots.count());

    try std.testing.expect(verifier.unchecked_slots.contains(
        .{ .slot = (snapshot_start_slot + 1), .hash = slot_hash },
    ));
}

test "OptimisticConfirmationVerifier.verifyForUnrootedOptimisticSlots: same slot different hash" {
    const allocator = std.testing.allocator;

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    const snapshot_start_slot = 0;
    var verifier = OptimisticConfirmationVerifier.init(
        sig.time.Instant.now(),
        snapshot_start_slot,
    );
    defer verifier.deinit(allocator);

    const bad_hash = Hash{ .data = .{42} ** 32 };
    try verifier.addNewOptimisticConfirmedSlots(
        allocator,
        &.{
            .{ .slot = 1, .hash = bad_hash },
            .{ .slot = 3, .hash = Hash.ZEROES },
        },
        &state,
        .FOR_TESTS,
    );
    const latest = try state.reader().getLatestOptimisticSlots(allocator, 10);
    defer latest.deinit();
    try std.testing.expectEqual(2, latest.items.len);

    var root_ancestors: sig.core.Ancestors = .{ .ancestors = .empty };
    defer root_ancestors.deinit(allocator);

    const unrooted = try verifier.verifyForUnrootedOptimisticSlots(
        allocator,
        &state,
        .{
            .slot = 1,
            .hash = Hash.ZEROES,
            .ancestors = &root_ancestors,
        },
    );
    defer allocator.free(unrooted);

    try std.testing.expectEqual(1, unrooted.len);
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 1, .hash = bad_hash },
        unrooted[0],
    );
    try std.testing.expectEqual(1, verifier.unchecked_slots.count());
    try std.testing.expect(verifier.unchecked_slots.contains(.{ .slot = 3, .hash = Hash.ZEROES }));
}

test "OptimisticConfirmationVerifier.verifyForUnrootedOptimisticSlots: unrooted optimistic slots" {
    const allocator = std.testing.allocator;

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    // Hashes for slots 1,3,5
    const h1 = Hash.init("1");
    const h3 = Hash.init("3");
    const h5 = Hash.init("5");

    var verifier = OptimisticConfirmationVerifier.init(
        sig.time.Instant.now(),
        0,
    );
    defer verifier.deinit(allocator);

    const optimistic: []const sig.core.hash.SlotAndHash = &.{
        .{ .slot = 1, .hash = h1 },
        .{ .slot = 3, .hash = h3 },
        .{ .slot = 5, .hash = h5 },
    };
    try verifier.addNewOptimisticConfirmedSlots(allocator, optimistic, &state, .FOR_TESTS);
    {
        var latest = try state.reader().getLatestOptimisticSlots(allocator, 10);
        defer latest.deinit();
        try std.testing.expectEqual(3, latest.items.len);
    }

    // Root on same fork at slot 5: ancestors include 1 and 3
    var anc5: sig.core.Ancestors = .{ .ancestors = .{} };
    defer anc5.deinit(allocator);
    try anc5.addSlot(allocator, 1);
    try anc5.addSlot(allocator, 3);
    {
        const unrooted = try verifier.verifyForUnrootedOptimisticSlots(
            allocator,
            &state,
            .{ .slot = 5, .hash = h5, .ancestors = &anc5 },
        );
        defer allocator.free(unrooted);
        try std.testing.expectEqual(0, unrooted.len);
    }
    try std.testing.expectEqual(0, verifier.unchecked_slots.count());

    // Re-add optimistic slots and check root at 3 (same fork)
    try verifier.addNewOptimisticConfirmedSlots(allocator, optimistic, &state, .FOR_TESTS);
    var anc3: sig.core.Ancestors = .{ .ancestors = .{} };
    defer anc3.deinit(allocator);
    try anc3.addSlot(allocator, 1);
    {
        const unrooted = try verifier.verifyForUnrootedOptimisticSlots(
            allocator,
            &state,
            .{ .slot = 3, .hash = h3, .ancestors = &anc3 },
        );
        defer allocator.free(unrooted);
        try std.testing.expectEqual(0, unrooted.len);
    }
    try std.testing.expectEqual(1, verifier.unchecked_slots.count());
    try std.testing.expect(verifier.unchecked_slots.contains(.{ .slot = 5, .hash = h5 }));

    // Re-add optimistic slots and set a different fork root at slot 4
    try verifier.addNewOptimisticConfirmedSlots(allocator, optimistic, &state, .FOR_TESTS);
    var anc4: sig.core.Ancestors = .{ .ancestors = .{} };
    defer anc4.deinit(allocator);
    // ancestors for 4 include 1 (but not 3)
    try anc4.addSlot(allocator, 1);
    {
        const unrooted = try verifier.verifyForUnrootedOptimisticSlots(
            allocator,
            &state,
            .{ .slot = 4, .hash = Hash.init("4"), .ancestors = &anc4 },
        );
        defer allocator.free(unrooted);
        try std.testing.expectEqual(1, unrooted.len);
        try std.testing.expectEqual(
            sig.core.hash.SlotAndHash{ .slot = 3, .hash = h3 },
            unrooted[0],
        );
    }
    try std.testing.expectEqual(1, verifier.unchecked_slots.count());
    try std.testing.expect(verifier.unchecked_slots.contains(.{ .slot = 5, .hash = h5 }));

    // Simulate missing ancestors by using root at 7 with no ancestors info
    var anc7: sig.core.Ancestors = .{ .ancestors = .empty };
    defer anc7.deinit(allocator);
    // First run should return 1 and 3 (not in ancestors and not rooted). Mark 5 as ancestor.
    try anc7.addSlot(allocator, 5);
    try verifier.addNewOptimisticConfirmedSlots(
        allocator,
        optimistic,
        &state,
        .FOR_TESTS,
    );
    {
        const unrooted = try verifier.verifyForUnrootedOptimisticSlots(
            allocator,
            &state,
            .{ .slot = 7, .hash = Hash.init("7"), .ancestors = &anc7 },
        );
        defer allocator.free(unrooted);
        // Expect two entries (1 and 3), order by slot ascending due to set ordering
        try std.testing.expectEqual(2, unrooted.len);
        try std.testing.expectEqual(
            sig.core.hash.SlotAndHash{ .slot = 1, .hash = h1 },
            unrooted[0],
        );
        try std.testing.expectEqual(
            sig.core.hash.SlotAndHash{ .slot = 3, .hash = h3 },
            unrooted[1],
        );
    }
    try std.testing.expectEqual(0, verifier.unchecked_slots.count());

    // Mark 1 and 3 as roots in the ledger and ensure nothing is returned
    var result_writer = state.resultWriter();
    var roots_setter = try result_writer.setRootsIncremental();
    defer roots_setter.deinit();
    try roots_setter.addRoot(1);
    try roots_setter.addRoot(3);
    try roots_setter.commit();

    try verifier.addNewOptimisticConfirmedSlots(allocator, optimistic, &state, .FOR_TESTS);
    {
        const unrooted = try verifier.verifyForUnrootedOptimisticSlots(
            allocator,
            &state,
            .{ .slot = 7, .hash = Hash.init("7"), .ancestors = &anc7 },
        );
        defer allocator.free(unrooted);
        try std.testing.expectEqual(0, unrooted.len);
    }
    try std.testing.expectEqual(0, verifier.unchecked_slots.count());

    var latest = try state.reader().getLatestOptimisticSlots(allocator, 10);
    defer latest.deinit();
    try std.testing.expectEqual(3, latest.items.len);
}
