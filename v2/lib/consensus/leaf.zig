const std = @import("std");
const replay = @import("../replay.zig");
const solana = @import("../solana.zig");

const BlockPool = replay.BlockPool;
const BlockRef = replay.BlockRef;
const Slot = solana.Slot;

pub const SimpleConsensus = struct {
    pool: *const BlockPool,
    root: BlockRef,
    /// Sorted descending by slot: `leaves[0]` is the tip of the leading fork.
    /// Only `leaves[0..num_leaves]` is valid; the tail is undefined.
    leaves: [max_forks]BlockRef,
    num_leaves: std.math.IntFittingRange(0, max_forks),

    const max_forks = 256;
    const finalization_depth: Slot = 32;

    pub fn init(pool: *const BlockPool, root: BlockRef) SimpleConsensus {
        var leaves: [max_forks]BlockRef = undefined;
        leaves[0] = root;
        return .{
            .pool = pool,
            .root = root,
            .leaves = leaves,
            .num_leaves = 1,
        };
    }

    /// Each of these errors indicates an invalid input. You should likely panic
    /// if any of these occur, unless there is a way to repair the state and recover.
    pub const Error = error{
        /// One of the block's ancestors is missing from the block pool, which
        /// means we can't figure out how this block fits into the block tree
        /// relative to other blocks. This means blocks are being pruned from
        /// the block pool before consensus finalizes them, which is nonsensical
        /// and prevents consensus from functioning properly.
        MissingUnrootedAncestor,
        /// This struct is unable to track the number of forks the block update
        /// would require us to handle.
        TooManyForks,
    };

    // TODO: verify leaves are still consistent with block pool (not needed but
    // more of a safety check)

    // TODO: consider out of order execution. this is assumed not to ever
    // happen, and it won't with the current design. but the struct would be
    // more robust if it handled this correctly.

    pub fn update(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) Error!?BlockRef {
        if (!try self.record(block_ref, passed)) return null;
        return self.finalize();
    }

    /// Returns whether an update was made
    fn record(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) Error!bool {
        if (!passed) return false; // TODO: log

        const executed = block_ref.constPtr(self.pool);

        var ancestor = executed.parent.opt() orelse return error.MissingUnrootedAncestor;

        // Check for common case: new block is a child of a leaf.
        for (self.leaves[0..self.num_leaves], 0..) |*leaf, i| {
            if (leaf.* == ancestor) {
                leaf.* = block_ref;

                // keep it sorted descending. move leaf up if necessary
                var j = i;
                while (j > 0 and
                    self.leaves[j - 1].constPtr(self.pool).slot < executed.slot) : (j -= 1)
                    std.mem.swap(BlockRef, &self.leaves[j - 1], &self.leaves[j]);

                return true;
            }
        }

        // this is a new fork, it doesn't descend from a leaf.
        while (ancestor.constPtr(self.pool).slot > self.root.constPtr(self.pool).slot) {
            ancestor = ancestor.constPtr(self.pool).parent.opt() orelse
                return error.MissingUnrootedAncestor;
        }

        if (ancestor != self.root) {
            // This is a very unusual case. The block doesn't descend from our
            // root, so we could never finalize it. It may indicate a malicious
            // leader, or someone (us or the leader) has an incorrect view of
            // the cluster's state of consensus. This is not necessarily a
            // problem or error, the block is just unusable as a leaf. TODO: log
            return false;
        }

        // This is a new leaf that is a descendant of the current root,
        // so we can add it to our leaves

        if (self.num_leaves == max_forks) return error.TooManyForks;

        // Descending by slot, so insert before the first leaf whose
        // slot is not greater than the new leaf's slot. num_leaves
        // is bounded (<= max_forks), so a linear scan is fine.
        var index: usize = 0;
        while (index < self.num_leaves and
            self.leaves[index].constPtr(self.pool).slot > executed.slot)
            index += 1;

        @memmove(
            self.leaves[index + 1 .. self.num_leaves + 1],
            self.leaves[index..self.num_leaves],
        );
        self.leaves[index] = block_ref;
        self.num_leaves += 1;
        return true;
    }

    fn finalize(self: *SimpleConsensus) ?BlockRef {
        // Confirmation-based finality: the last 32 blocks on the leading fork
        // must all sit at slots strictly greater than the most recent block
        // on any competing branch. The finalize candidate is the 33rd-most-
        // recent block (one hop past the last-32 window).
        const must_exceed_slot = if (self.num_leaves > 1)
            self.leaves[1].constPtr(self.pool).slot
        else
            self.root.constPtr(self.pool).slot;
        std.debug.assert(must_exceed_slot >= self.root.constPtr(self.pool).slot);

        // Walk back `finalization_depth - 1` hops from the tip: the 32nd-
        // most-recent block (oldest of the last 32 confirmations). Chains
        // are slot-ordered, so if its slot exceeds `must_exceed_slot`, so
        // do all 32 last confirmations.
        var node_ref = self.leaves[0];
        for (0..finalization_depth - 1) |_| {
            node_ref = node_ref.constPtr(self.pool).parent.opt() orelse return null;
        }
        if (node_ref.constPtr(self.pool).slot <= must_exceed_slot) return null;

        // One more hop back: the finalize candidate (32 confirmations back).
        const candidate = node_ref.constPtr(self.pool).parent.opt() orelse return null;
        if (candidate == self.root) return null;

        self.root = candidate;
        self.num_leaves = 1;
        return candidate;
    }
};

//
// Tests
//

const testing = std.testing;

fn setupPool(buf: []align(@alignOf(BlockPool)) u8) *BlockPool {
    const pool: *BlockPool = @ptrCast(buf.ptr);
    pool.init();
    return pool;
}

fn addBlock(pool: *BlockPool, slot: Slot, parent: BlockRef.Optional) !BlockRef {
    const ref = try pool.createId();
    ref.ptr(pool).* = .{ .slot = slot, .parent = parent };
    return ref;
}

test "SimpleConsensus init seeds root and single leaf" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    const c: SimpleConsensus = .init(pool, root);

    try testing.expectEqual(root, c.root);
    try testing.expectEqual(@as(usize, 1), @as(usize, c.num_leaves));
    try testing.expectEqual(root, c.leaves[0]);
}

test "SimpleConsensus update returns null and preserves state when passed=false" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    const a = try addBlock(pool, 1, .init(root));
    var c: SimpleConsensus = .init(pool, root);

    try testing.expectEqual(@as(?BlockRef, null), try c.update(a, false));
    try testing.expectEqual(@as(usize, 1), @as(usize, c.num_leaves));
    try testing.expectEqual(root, c.leaves[0]);
}

test "SimpleConsensus update extends leading leaf in place" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    const a = try addBlock(pool, 1, .init(root));
    var c: SimpleConsensus = .init(pool, root);

    try testing.expectEqual(@as(?BlockRef, null), try c.update(a, true));
    try testing.expectEqual(@as(usize, 1), @as(usize, c.num_leaves));
    try testing.expectEqual(a, c.leaves[0]);
}

test "SimpleConsensus update inserts sibling after leader when arriving with smaller slot" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    const a = try addBlock(pool, 2, .init(root));
    const b = try addBlock(pool, 1, .init(root));
    var c: SimpleConsensus = .init(pool, root);

    _ = try c.update(a, true);
    _ = try c.update(b, true);

    try testing.expectEqual(@as(usize, 2), @as(usize, c.num_leaves));
    try testing.expectEqual(a, c.leaves[0]);
    try testing.expectEqual(b, c.leaves[1]);
}

test "SimpleConsensus update inserts sibling before leader when arriving with larger slot" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    const a = try addBlock(pool, 1, .init(root));
    const b = try addBlock(pool, 2, .init(root));
    var c: SimpleConsensus = .init(pool, root);

    _ = try c.update(a, true);
    _ = try c.update(b, true);

    try testing.expectEqual(@as(usize, 2), @as(usize, c.num_leaves));
    try testing.expectEqual(b, c.leaves[0]);
    try testing.expectEqual(a, c.leaves[1]);
}

test "SimpleConsensus update rejects block whose parent chain does not reach root" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 5, .null);
    // Independent chain that terminates at slot 5 but is not the root.
    const x = try addBlock(pool, 5, .null);
    const y = try addBlock(pool, 8, .init(x));
    var c: SimpleConsensus = .init(pool, root);

    try testing.expectEqual(@as(?BlockRef, null), try c.update(y, true));
    try testing.expectEqual(@as(usize, 1), @as(usize, c.num_leaves));
    try testing.expectEqual(root, c.leaves[0]);
}

test "SimpleConsensus update errors when executed block has no parent" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    const orphan = try addBlock(pool, 1, .null);
    var c: SimpleConsensus = .init(pool, root);

    try testing.expectError(error.MissingUnrootedAncestor, c.update(orphan, true));
}

test "SimpleConsensus update errors when parent chain terminates above root" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    // Chain y -> x -> null, all with slots strictly above root's slot.
    const x = try addBlock(pool, 5, .null);
    const y = try addBlock(pool, 6, .init(x));
    var c: SimpleConsensus = .init(pool, root);

    try testing.expectError(error.MissingUnrootedAncestor, c.update(y, true));
}

test "SimpleConsensus update finalizes at 32-deep fork with no competition" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    var c: SimpleConsensus = .init(pool, root);

    var last = root;
    var slot_1_ref: BlockRef = undefined;
    for (1..34) |i| {
        const b = try addBlock(pool, @intCast(i), .init(last));
        if (i == 1) slot_1_ref = b;
        const result = try c.update(b, true);
        if (i < 33) {
            try testing.expectEqual(@as(?BlockRef, null), result);
        } else {
            // Walk-back-31 from leaves[0] lands at slot 2, which exceeds
            // root.slot (0); one more hop gives slot_1_ref as the candidate.
            try testing.expectEqual(slot_1_ref, result.?);
            try testing.expectEqual(slot_1_ref, c.root);
            try testing.expectEqual(@as(usize, 1), @as(usize, c.num_leaves));
            try testing.expectEqual(b, c.leaves[0]);
        }
        last = b;
    }
}

test "SimpleConsensus update does not finalize while competitor sits in the last-32 window" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    var c: SimpleConsensus = .init(pool, root);

    // Winning fork of 33 blocks (slots 1..33) alongside a competitor at
    // slot 2. Walk-back-31 from the tip (slot 33) lands at the winning
    // fork's slot 2 block, which does not exceed the competitor's slot, so
    // no finalization is possible.
    const first_a = try addBlock(pool, 1, .init(root));
    const competitor = try addBlock(pool, 2, .init(root));
    _ = try c.update(first_a, true);
    _ = try c.update(competitor, true);

    var last = first_a;
    for (2..34) |i| {
        const b = try addBlock(pool, @intCast(i), .init(last));
        const result = try c.update(b, true);
        try testing.expectEqual(@as(?BlockRef, null), result);
        last = b;
    }
    try testing.expectEqual(root, c.root);
    try testing.expectEqual(@as(usize, 2), @as(usize, c.num_leaves));
}

test "SimpleConsensus update finalizes when competitor is below the finalization window" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    var c: SimpleConsensus = .init(pool, root);

    // Old competitor at slot 1, then a winning chain of 33 blocks at slots
    // 2..34. Walk-back-31 from the tip (slot 34) lands at slot 3, which
    // exceeds the competitor's slot (1); the finalize candidate is chain[0]
    // at slot 2.
    const competitor = try addBlock(pool, 1, .init(root));
    _ = try c.update(competitor, true);

    var last = root;
    var chain: [33]BlockRef = undefined;
    for (0..33) |i| {
        chain[i] = try addBlock(pool, @intCast(i + 2), .init(last));
        const result = try c.update(chain[i], true);
        if (i < 32) {
            try testing.expectEqual(@as(?BlockRef, null), result);
        } else {
            try testing.expectEqual(chain[0], result.?);
            try testing.expectEqual(chain[0], c.root);
            try testing.expectEqual(@as(usize, 1), @as(usize, c.num_leaves));
            try testing.expectEqual(chain[32], c.leaves[0]);
        }
        last = chain[i];
    }
}

test "SimpleConsensus update keeps leaves sorted after extending non-leading fork" {
    var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool = setupPool(&buf);

    const root = try addBlock(pool, 0, .null);
    // Two forks starting at slot 1, then extend the b-fork to slot 2.
    // After the third update, b2 should be at leaves[0] because it has
    // the largest slot; a1 should be at leaves[1].
    const a1 = try addBlock(pool, 1, .init(root));
    const b1 = try addBlock(pool, 1, .init(root));
    const b2 = try addBlock(pool, 2, .init(b1));
    var c: SimpleConsensus = .init(pool, root);

    _ = try c.update(b1, true);
    _ = try c.update(a1, true);
    _ = try c.update(b2, true);

    try testing.expectEqual(@as(usize, 2), @as(usize, c.num_leaves));
    try testing.expectEqual(b2, c.leaves[0]);
    try testing.expectEqual(a1, c.leaves[1]);
}
