const std = @import("std");
const lib = @import("../lib.zig");

const Slot = lib.solana.Slot;

const BlockPool = lib.replay.BlockPool;
const BlockRef = lib.replay.BlockRef;

const finalization_depth: Slot = 32;

const BlockInfo = struct {
    /// Slot of the block this entry was recorded for. Used to detect stale
    /// entries left behind when a pool index is recycled by a new block.
    slot: Slot,
    passed: bool,
    /// Marks the current local root of the tree. Exactly one entry has this
    /// set: the latest block we have considered finalized. Acts as the sentinel
    /// that no slot earlier than this block is part of our tree.
    finalized: bool,
};

/// Tracks per-block exec results in a `BlockPool`-shaped side table and, on
/// each new result, decides whether any descendant of `last_finalized` can
/// safely be finalized. The block tree itself lives in `pool`; this struct
/// only owns the local state.
pub const SimpleConsensus = struct {
    pool: *const BlockPool,
    state: [BlockPool.capacity]?BlockInfo,
    /// The deepest block we have considered finalized so far. Acts as the
    /// local root of the section of tree we operate on. Supplied at
    /// construction time; never null.
    root: BlockRef,

    pub fn init(pool: *const BlockPool, root: BlockRef) SimpleConsensus {
        var state: [BlockPool.capacity]?BlockInfo = @splat(null);
        state[root.index()] = .{
            .slot = root.constPtr(pool).slot,
            .passed = true,
            .finalized = true,
        };
        return .{
            .pool = pool,
            .state = state,
            .root = root,
        };
    }

    /// Records an exec result and returns the newly finalized block, or null
    /// if nothing finalized this round. Blocks below `last_finalized` are
    /// silently ignored.
    pub fn update(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) ?BlockRef {
        if (!self.record(block_ref, passed)) return null;

        const new_root = self.findFinalizable() orelse return null;

        self.state[self.root.index()].?.finalized = false;
        self.state[new_root.index()].?.finalized = true;
        self.root = new_root;
        return new_root;
    }

    /// Returns true if the local state was updated and finality should be
    /// re-evaluated.
    fn record(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) bool {
        const block = block_ref.constPtr(self.pool);
        const root_slot = self.root.constPtr(self.pool).slot;
        if (block.slot <= root_slot) return false; // TODO log here, this unexpected

        self.state[block_ref.index()] = .{
            .slot = block.slot,
            .passed = passed,
            .finalized = false,
        };
        return true;
    }

    /// Confirmation-based finality: each block on the leading fork is a
    /// "vote", and we finalize the block 32 confirmations back from the tip
    /// once the leading fork's last 32 confirmations are all at slots strictly
    /// after every competing branch's most recent block. Slot distance is
    /// irrelevant on its own -- a fork with only a few blocks spread over
    /// many slots does not qualify.
    ///
    /// Returns null if no progress is possible: too few confirmations on the
    /// leading fork, a competitor with a block inside the last-32 window, or
    /// the candidate would land at `self.root`.
    fn findFinalizable(self: *const SimpleConsensus) ?BlockRef {
        // Descend from root, at each branch picking the child whose subtree
        // has the deepest continuously-passed block. Every child we skip
        // contributes its subtree's `maxPassedSlot` to `other_max_slot`,
        // which becomes the "most recent slot on any competing branch".
        var tip_ref = self.root;
        var other_max_slot: Slot = 0;
        while (true) {
            const node = tip_ref.constPtr(self.pool);
            var best_child: ?BlockRef = null;
            var best_slot: Slot = 0;
            var child_opt = node.child;
            while (child_opt.opt()) |child_ref| {
                const s = self.maxPassedSlot(child_ref);
                if (s > best_slot) {
                    if (best_child != null) other_max_slot = @max(other_max_slot, best_slot);
                    best_child = child_ref;
                    best_slot = s;
                } else if (s > 0) {
                    other_max_slot = @max(other_max_slot, s);
                }
                child_opt = child_ref.constPtr(self.pool).sibling;
            }
            if (best_child) |child| tip_ref = child else break;
        }
        if (tip_ref == self.root) return null;

        // Walk back 31 hops -- that's the 32nd-most-recent block on the
        // leading fork (the oldest of the last 32 confirmations). Chains are
        // slot-ordered, so if its slot exceeds `other_max_slot`, so do all 32
        // last confirmations.
        var node_ref = tip_ref;
        for (0..finalization_depth - 1) |_| {
            node_ref = node_ref.constPtr(self.pool).parent.opt() orelse return null;
        }
        if (node_ref.constPtr(self.pool).slot <= other_max_slot) return null;

        // One more hop back: the finalize candidate (32 confirmations back).
        const candidate = node_ref.constPtr(self.pool).parent.opt() orelse return null;
        if (candidate == self.root) return null;
        return candidate;
    }

    /// Greatest slot of any passed block reachable from `node_ref` via a
    /// continuously-passed path (inclusive). Returns 0 if `node_ref` itself is
    /// not passed - this implicitly enforces that the descent path is all
    /// passed.
    fn maxPassedSlot(self: *const SimpleConsensus, node_ref: BlockRef) Slot {
        if (!self.blockIsPassed(node_ref)) return 0;
        const node = node_ref.constPtr(self.pool);
        var result: Slot = node.slot;
        var child_ref_opt = node.child;
        while (child_ref_opt.opt()) |child_ref| {
            result = @max(result, self.maxPassedSlot(child_ref));
            child_ref_opt = child_ref.constPtr(self.pool).sibling;
        }
        return result;
    }

    /// A block is "passed" if we have recorded a passed exec result for it, or
    /// if it is the current local root (whose passed status is implicit). A
    /// stale entry from a recycled pool index is detected by a slot mismatch.
    fn blockIsPassed(self: *const SimpleConsensus, block_ref: BlockRef) bool {
        const info = self.state[block_ref.index()] orelse return false;
        const slot = block_ref.constPtr(self.pool).slot;
        if (info.slot != slot) return false; // TODO: this should be an error or panic
        return info.passed or info.finalized;
    }
};

fn createTestBlock(block_pool: *BlockPool, slot: Slot, parent_ref: BlockRef.Optional) !BlockRef {
    const block_ref = try block_pool.createId();
    block_ref.ptr(block_pool).* = .{ .slot = slot, .parent = parent_ref };

    if (parent_ref.opt()) |parent_id| {
        const parent = parent_id.ptr(block_pool);
        if (parent.child.opt()) |first_child_id| {
            var sibling_ref = first_child_id;
            while (true) {
                const sibling = sibling_ref.ptr(block_pool);
                if (sibling.sibling.opt()) |next_sibling| {
                    sibling_ref = next_sibling;
                } else {
                    sibling.sibling = .init(block_ref);
                    break;
                }
            }
        } else {
            parent.child = .init(block_ref);
        }
    }

    return block_ref;
}

fn markPassed(consensus: *SimpleConsensus, block_ref: BlockRef) void {
    const slot = block_ref.constPtr(consensus.pool).slot;
    consensus.state[block_ref.index()] = .{ .slot = slot, .passed = true, .finalized = false };
}

test "simple_consensus finalizes 32 confirmations back from the tip" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    // A straight chain of 33 blocks off root, no competing branch.
    const root = try createTestBlock(block_pool, 0, .null);
    var last = root;
    var chain: [33]BlockRef = undefined;
    for (0..33) |i| {
        chain[i] = try createTestBlock(block_pool, @intCast(i + 1), .init(last));
        last = chain[i];
    }

    var consensus: SimpleConsensus = .init(block_pool, root);
    for (chain) |b| markPassed(&consensus, b);

    // 33 confirmations past root and no competitor. Finalize chain[0], which
    // sits 32 hops behind the tip.
    try std.testing.expectEqual(chain[0], consensus.findFinalizable().?);
}

test "simple_consensus exactly 32 slot fork cannot finalize past the root" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    // root -> tip, exactly finalization_depth slots ahead.
    const root = try createTestBlock(block_pool, 0, .null);
    const tip = try createTestBlock(block_pool, finalization_depth, .init(root));

    var consensus: SimpleConsensus = .init(block_pool, root);
    markPassed(&consensus, tip);

    // tip is itself inside the last 32 slots, so there is no new safe block.
    try std.testing.expectEqual(@as(?BlockRef, null), consensus.findFinalizable());
}

test "simple_consensus recent competing fork prevents finality" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    // Winning fork of 33 blocks (slots 1..33), plus a competitor sibling of
    // chain[0] at slot 2. Walk-back-31 from chain[32] lands at chain[1]@2,
    // whose slot does not exceed the competitor's slot, so no finalization.
    const root = try createTestBlock(block_pool, 0, .null);
    var last = root;
    var chain: [33]BlockRef = undefined;
    for (0..33) |i| {
        chain[i] = try createTestBlock(block_pool, @intCast(i + 1), .init(last));
        last = chain[i];
    }
    const competitor = try createTestBlock(block_pool, 2, .init(root));

    var consensus: SimpleConsensus = .init(block_pool, root);
    for (chain) |b| markPassed(&consensus, b);
    markPassed(&consensus, competitor);

    try std.testing.expectEqual(@as(?BlockRef, null), consensus.findFinalizable());
}

test "simple_consensus old competing fork does not prevent finality" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    // Old competitor at slot 1, followed by a winning fork of 33 blocks at
    // slots 2..34. Walk-back-31 from chain[32]@34 lands at chain[1]@3, which
    // exceeds the competitor's slot, so we finalize chain[0]@2.
    const root = try createTestBlock(block_pool, 0, .null);
    const old_competitor = try createTestBlock(block_pool, 1, .init(root));
    var last = root;
    var chain: [33]BlockRef = undefined;
    for (0..33) |i| {
        chain[i] = try createTestBlock(block_pool, @intCast(i + 2), .init(last));
        last = chain[i];
    }

    var consensus: SimpleConsensus = .init(block_pool, root);
    markPassed(&consensus, old_competitor);
    for (chain) |b| markPassed(&consensus, b);

    try std.testing.expectEqual(chain[0], consensus.findFinalizable().?);
}

test "simple_consensus only descends from the local root" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    // The full tree has a long fork through `other_fork`, but the local root
    // is `finalized` (which has no descendants), so no progress is possible.
    const tree_root = try createTestBlock(block_pool, 0, .null);
    const finalized = try createTestBlock(block_pool, 1, .init(tree_root));
    const other_fork = try createTestBlock(block_pool, 2, .init(tree_root));
    const other_tip = try createTestBlock(block_pool, finalization_depth + 2, .init(other_fork));

    var consensus: SimpleConsensus = .init(block_pool, finalized);
    markPassed(&consensus, tree_root);
    markPassed(&consensus, other_fork);
    markPassed(&consensus, other_tip);

    try std.testing.expectEqual(@as(?BlockRef, null), consensus.findFinalizable());
}

test "simple_consensus unpassed block breaks the chain" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    // `a` is never reported as passed, so the chain root -> a -> tip is broken.
    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, 1, .init(root));
    const tip = try createTestBlock(block_pool, finalization_depth + 1, .init(a));

    var consensus: SimpleConsensus = .init(block_pool, root);
    markPassed(&consensus, tip);

    try std.testing.expectEqual(@as(?BlockRef, null), consensus.findFinalizable());
}

test "simple_consensus stale block info from a recycled pool index is ignored" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    const a = try createTestBlock(block_pool, 5, .null);
    var consensus: SimpleConsensus = .init(block_pool, a);
    try std.testing.expect(consensus.blockIsPassed(a));

    // Free `a` and immediately re-allocate at the same pool index for a
    // different block. `consensus.state[a.index()]` still holds the old slot.
    block_pool.destroyId(a);
    const b = try createTestBlock(block_pool, 10, .null);
    try std.testing.expectEqual(a, b);

    try std.testing.expect(!consensus.blockIsPassed(b));
}

test "simple_consensus update ignores blocks below the local root" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    const tree_root = try createTestBlock(block_pool, 10, .null);
    var consensus: SimpleConsensus = .init(block_pool, tree_root);

    // A second, older block with no parent acts as a stale notification.
    const old = try createTestBlock(block_pool, 5, .null);
    try std.testing.expectEqual(@as(?BlockRef, null), consensus.update(old, true));
    try std.testing.expect(!consensus.blockIsPassed(old));
}

test "simple_consensus update returns the finalized block when ready" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    // Straight chain of 33 blocks. The 33rd update should finalize chain[0].
    const root = try createTestBlock(block_pool, 0, .null);
    var chain: [33]BlockRef = undefined;
    var last = root;
    for (0..33) |i| {
        chain[i] = try createTestBlock(block_pool, @intCast(i + 1), .init(last));
        last = chain[i];
    }

    var consensus: SimpleConsensus = .init(block_pool, root);
    for (chain, 0..) |b, i| {
        const result = consensus.update(b, true);
        if (i < 32) {
            try std.testing.expectEqual(@as(?BlockRef, null), result);
        } else {
            try std.testing.expectEqual(chain[0], result.?);
            try std.testing.expectEqual(chain[0], consensus.root);
        }
    }
}
