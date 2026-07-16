const std = @import("std");
const lib = @import("../lib.zig");
const Slot = lib.solana.Slot;

const BlockPool = lib.replay.BlockPool;
const BlockRef = lib.replay.BlockRef;

const finalization_depth: Slot = 32;

/// Extracts the raw slot value from a block ref. Blocks tracked by consensus
/// must always have valid (non-null) slots; panics otherwise.
fn slotOf(pool: *const BlockPool, ref: BlockRef) Slot {
    return ref.constPtr(pool).slot.opt().?;
}

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
            .slot = slotOf(pool, root),
            .passed = true,
            .finalized = true,
        };
        return .{
            .pool = pool,
            .state = state,
            .root = root,
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
    };

    /// Records an exec result and returns the newly finalized block, or null
    /// if nothing finalized this round. Blocks below `last_finalized` are
    /// silently ignored.
    pub fn update(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) Error!?BlockRef {
        if (!try self.record(block_ref, passed)) return null;

        const new_root = self.findFinalizable() orelse return null;

        self.state[self.root.index()].?.finalized = false;
        self.state[new_root.index()].?.finalized = true;
        self.root = new_root;
        return new_root;
    }

    /// Returns true if the local state was updated and finality should be
    /// re-evaluated. Errors if the block's parent chain is broken (contains a
    /// null pointer before reaching a slot at or below the local root).
    fn record(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) Error!bool {
        const block = block_ref.constPtr(self.pool);
        const root_slot = slotOf(self.pool, self.root);
        const block_slot = slotOf(self.pool, block_ref);

        // Every non-root update block must have a linked parent, and its
        // parent chain must reach a slot at or below the local root without
        // terminating at a null pointer. This mirrors leaf.zig's validation.
        var ancestor = block.parent.opt() orelse return error.MissingUnrootedAncestor;
        while (slotOf(self.pool, ancestor) > root_slot) {
            ancestor = ancestor.constPtr(self.pool).parent.opt() orelse
                return error.MissingUnrootedAncestor;
        }

        // Silently drop stale/off-tree well-formed blocks.
        if (block_slot <= root_slot) return false;
        if (ancestor != self.root) return false;

        self.state[block_ref.index()] = .{
            .slot = block_slot,
            .passed = passed,
            .finalized = false,
        };
        return true;
    }

    pub fn findFinalizable(self: *const SimpleConsensus) ?BlockRef {
        const candidate = self.findDeepest(self.root) orelse return null;
        const new_root = self.beats(candidate.block, slotOf(self.pool, self.root)) orelse
            return null;
        return if (new_root == self.root) null else new_root;
    }

    const RootCandidate = struct {
        block: BlockRef,
        slot: Slot,
    };

    fn findDeepest(self: *const SimpleConsensus, node_ref: BlockRef) ?RootCandidate {
        if (!self.blockIsPassed(node_ref)) return null;

        const node = node_ref.constPtr(self.pool);
        var best: ?RootCandidate = null;
        var is_good_enough = true;

        var child: BlockRef.Optional = node.child;
        while (child.opt()) |child_ref| : (child = child_ref.constPtr(self.pool).sibling) {
            const this = self.findDeepest(child_ref) orelse continue;
            if (best) |old_best| {
                if (this.slot > old_best.slot) {
                    best = this;
                    is_good_enough = self.beats(this.block, old_best.slot) != null;
                } else if (is_good_enough) {
                    is_good_enough = self.beats(old_best.block, this.slot) != null;
                }
            } else best = this;
        }
        if (!is_good_enough) return null;
        // If no passed descendant was found (either no children in the pool
        // or every child subtree is unpassed), this node itself is the
        // deepest passed block reachable from here.
        if (best) |b| return b;
        return .{
            .block = node_ref,
            .slot = slotOf(self.pool, node_ref),
        };
    }

    /// Returns the block `finalization_depth` hops back from `a` (the leading
    /// tip) if every one of the intervening `finalization_depth - 1` ancestors
    /// -- together with `a` itself, they form the "last 32 confirmations" --
    /// has slot strictly greater than `slot_to_beat`. Returns null otherwise.
    ///
    /// Note that the returned block itself (the finalize candidate, one hop
    /// past the last-32-block window) is not required to beat `slot_to_beat`.
    fn beats(self: *const SimpleConsensus, a: BlockRef, slot_to_beat: Slot) ?BlockRef {
        var node: BlockRef = a;
        for (0..finalization_depth - 1) |_| {
            const parent = node.constPtr(self.pool).parent.opt() orelse return null;
            if (slotOf(self.pool, parent) <= slot_to_beat) return null;
            node = parent;
        }
        return node.constPtr(self.pool).parent.opt();
    }

    /// A block is "passed" if we have recorded a passed exec result for it, or
    /// if it is the current local root (whose passed status is implicit). A
    /// stale entry from a recycled pool index is detected by a slot mismatch.
    fn blockIsPassed(self: *const SimpleConsensus, block_ref: BlockRef) bool {
        const info = self.state[block_ref.index()] orelse return false;
        const slot = slotOf(self.pool, block_ref);
        if (info.slot != slot) return false; // TODO: this should be an error or panic
        return info.passed or info.finalized;
    }
};

comptime {
    _ = @import("test.zig").consensus_tests(SimpleConsensus);
}

//
// Tests (implementation-specific; behavioural tests live in test.zig)
//

fn createTestBlock(block_pool: *BlockPool, slot: Slot, parent_ref: BlockRef.Optional) !BlockRef {
    const block_ref = try block_pool.createId();
    block_ref.ptr(block_pool).* = .{ .slot = .init(slot), .parent = parent_ref };

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
