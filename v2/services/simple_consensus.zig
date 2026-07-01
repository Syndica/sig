const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");
const Slot = lib.solana.Slot;

comptime {
    _ = start;
}

pub const name = .simple_consensus;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.simple_consensus.ReadOnly;
pub const ReadWrite = services.simple_consensus.ReadWrite;

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

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    // TODO: real root from snapshot / prior state.
    var consensus: SimpleConsensus = .init(ro.block_pool, undefined);
    var exec_results = rw.block_exec_results.get(.reader);
    var finality_writer = rw.block_finality.get(.writer);

    while (true) {
        const result = exec_results.next() orelse {
            try runner.activity.signalIdleSpinning();
            continue;
        };
        defer exec_results.markUsed();
        try runner.activity.signalActive();

        const new_root = consensus.update(result.block_ref, result.passed) orelse continue;

        const finality = finality_writer.next() orelse {
            try runner.activity.signalIdleSpinning();
            continue;
        };
        finality.* = new_root;
        finality_writer.markUsed();
        logger.info().logf("finalized block {}", .{new_root});
    }
}

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
    last_finalized: BlockRef,

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
            .last_finalized = root,
        };
    }

    /// Records an exec result and returns the newly finalized block, or null
    /// if nothing finalized this round. Blocks below `last_finalized` are
    /// silently ignored.
    pub fn update(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) ?BlockRef {
        if (!self.record(block_ref, passed)) return null;

        const new_root = self.findFinalizable() orelse return null;

        self.state[self.last_finalized.index()].?.finalized = false;
        self.state[new_root.index()].?.finalized = true;
        self.last_finalized = new_root;
        return new_root;
    }

    /// Returns true if the local state was updated and finality should be
    /// re-evaluated.
    fn record(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) bool {
        const block = block_ref.constPtr(self.pool);
        const root_slot = self.last_finalized.constPtr(self.pool).slot;
        if (block.slot < root_slot) return false;
        if (block_ref == self.last_finalized) return false;

        self.state[block_ref.index()] = .{
            .slot = block.slot,
            .passed = passed,
            .finalized = false,
        };
        return true;
    }

    /// Descends from `last_finalized` along the unique passed fork and returns
    /// the deepest block that can safely become the new local root, or null
    /// if no progress is possible. The block tree is walked directly via
    /// parent/child links - we never iterate the `state` side table.
    ///
    /// A new root is safe when:
    ///   - There is a fork descended from `last_finalized` whose deepest
    ///     passed slot is at least `finalization_depth` slots ahead of it.
    ///   - At every branch point on the path from `last_finalized` to the new
    ///     root, only one child subtree contains a passed block in the last
    ///     `finalization_depth` slots before that deepest passed slot; all
    ///     other subtrees are quiet within that window.
    fn findFinalizable(self: *const SimpleConsensus) ?BlockRef {
        const root_ref = self.last_finalized;
        const root_slot = root_ref.constPtr(self.pool).slot;
        const tip_slot = self.maxPassedSlot(root_ref);
        if (tip_slot < root_slot + finalization_depth) return null;
        const window_start_slot = tip_slot - finalization_depth;

        var current_ref = root_ref;
        while (true) {
            const current = current_ref.constPtr(self.pool);

            // Of `current`'s children, find the unique subtree that reaches
            // into the last `finalization_depth` slots. If two or more do, the
            // forks through `current` have a competing branch in the window
            // and the entire chain is disqualified.
            var chosen: ?BlockRef = null;
            var child_ref_opt = current.child;
            while (child_ref_opt.opt()) |child_ref| {
                if (self.maxPassedSlot(child_ref) >= window_start_slot) {
                    if (chosen != null) return null;
                    chosen = child_ref;
                }
                child_ref_opt = child_ref.constPtr(self.pool).sibling;
            }

            // With a continuously-passed `maxPassedSlot`, descent always finds
            // a qualifying child as long as `tip_slot` is in `current`'s
            // subtree. Guard against an unexpected dead end anyway.
            const chosen_ref = chosen orelse return null;

            // Stop before descending into the window itself; we never finalize
            // a block within the last `finalization_depth` slots.
            if (chosen_ref.constPtr(self.pool).slot > window_start_slot) break;

            current_ref = chosen_ref;
        }

        if (current_ref == root_ref) return null;
        return current_ref;
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
        if (info.slot != slot) return false;
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

test "simple_consensus finalizes deepest safe block on a long fork" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    // root -> a -> b -> tip, with tip 33 slots ahead of root.
    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, 1, .init(root));
    const b = try createTestBlock(block_pool, 2, .init(a));
    const tip = try createTestBlock(block_pool, finalization_depth + 1, .init(b));

    var consensus: SimpleConsensus = .init(block_pool, root);
    markPassed(&consensus, a);
    markPassed(&consensus, b);
    markPassed(&consensus, tip);

    // tip is at slot 33, window_start = 1, so `a` is the deepest safe block.
    try std.testing.expectEqual(a, consensus.findFinalizable().?);
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

    // Two siblings under `a` both reach into the last 32 slots: one is the
    // long tip, the other a recent competitor.
    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, 1, .init(root));
    const tip = try createTestBlock(block_pool, finalization_depth + 1, .init(a));
    const competitor = try createTestBlock(block_pool, 2, .init(a));

    var consensus: SimpleConsensus = .init(block_pool, root);
    markPassed(&consensus, a);
    markPassed(&consensus, tip);
    markPassed(&consensus, competitor);

    try std.testing.expectEqual(@as(?BlockRef, null), consensus.findFinalizable());
}

test "simple_consensus old competing fork does not prevent finality" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();

    // The competitor is one slot below the window, so it should not disqualify
    // the long fork through `a`.
    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, finalization_depth, .init(root));
    const tip = try createTestBlock(block_pool, finalization_depth * 2, .init(a));
    const old_competitor = try createTestBlock(block_pool, finalization_depth - 1, .init(root));

    var consensus: SimpleConsensus = .init(block_pool, root);
    markPassed(&consensus, a);
    markPassed(&consensus, tip);
    markPassed(&consensus, old_competitor);

    try std.testing.expectEqual(a, consensus.findFinalizable().?);
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

    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, 1, .init(root));
    const b = try createTestBlock(block_pool, 2, .init(a));
    const tip = try createTestBlock(block_pool, finalization_depth + 1, .init(b));

    var consensus: SimpleConsensus = .init(block_pool, root);

    // Intermediate records don't finalize on their own.
    try std.testing.expectEqual(@as(?BlockRef, null), consensus.update(a, true));
    try std.testing.expectEqual(@as(?BlockRef, null), consensus.update(b, true));
    // `tip`'s arrival pushes the deepest safe block (`a`) to be finalized.
    try std.testing.expectEqual(a, consensus.update(tip, true).?);
    try std.testing.expectEqual(a, consensus.last_finalized);
}
