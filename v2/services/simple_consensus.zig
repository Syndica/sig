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

    var consensus: SimpleConsensus = .init(ro.block_pool);
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
    /// local root of the section of tree we operate on. `.null` until the
    /// first exec result bootstraps it from `pool`.
    last_finalized: BlockRef,

    pub fn init(pool: *const BlockPool) SimpleConsensus {
        return .{
            .pool = pool,
            .state = @splat(null),
            .last_finalized = .null,
        };
    }

    /// Records an exec result and returns the newly finalized block, or null
    /// if nothing finalized this round. Blocks below `last_finalized` are
    /// silently ignored, and `last_finalized` is bootstrapped from the tree
    /// on the first call.
    pub fn update(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) ?BlockRef {
        if (!self.record(block_ref, passed)) return null;

        const new_root = self.findFinalizable() orelse return null;

        self.state[self.last_finalized.index().?].?.finalized = false;
        self.state[new_root.index().?].?.finalized = true;
        self.last_finalized = new_root;
        return new_root;
    }

    /// Returns true if the local state was updated and finality should be
    /// re-evaluated. Bootstraps `last_finalized` on the first call.
    fn record(self: *SimpleConsensus, block_ref: BlockRef, passed: bool) bool {
        if (block_ref == .null) return false;
        const block = block_ref.constPtr(self.pool).?;

        if (self.last_finalized == .null) {
            const tree_root = findTreeRoot(self.pool, block_ref);
            self.state[tree_root.index().?] = .{
                .slot = tree_root.constPtr(self.pool).?.slot,
                .passed = true,
                .finalized = true,
            };
            self.last_finalized = tree_root;
        }

        const root_slot = self.last_finalized.constPtr(self.pool).?.slot;
        if (block.slot < root_slot) return false;
        if (block_ref == self.last_finalized) return false;

        self.state[block_ref.index().?] = .{
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
        const root_slot = root_ref.constPtr(self.pool).?.slot;
        const tip_slot = self.maxPassedSlot(root_ref);
        if (tip_slot < root_slot + finalization_depth) return null;
        const window_start_slot = tip_slot - finalization_depth;

        var current_ref = root_ref;
        while (true) {
            const current = current_ref.constPtr(self.pool).?;

            // Of `current`'s children, find the unique subtree that reaches
            // into the last `finalization_depth` slots. If two or more do, the
            // forks through `current` have a competing branch in the window
            // and the entire chain is disqualified.
            var chosen: BlockRef = .null;
            var child_ref = current.child;
            while (child_ref != .null) {
                if (self.maxPassedSlot(child_ref) >= window_start_slot) {
                    if (chosen != .null) return null;
                    chosen = child_ref;
                }
                child_ref = child_ref.constPtr(self.pool).?.sibling;
            }

            // With a continuously-passed `maxPassedSlot`, descent always finds
            // a qualifying child as long as `tip_slot` is in `current`'s
            // subtree. Guard against an unexpected dead end anyway.
            if (chosen == .null) return null;

            // Stop before descending into the window itself; we never finalize
            // a block within the last `finalization_depth` slots.
            if (chosen.constPtr(self.pool).?.slot > window_start_slot) break;

            current_ref = chosen;
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
        const node = node_ref.constPtr(self.pool).?;
        var result: Slot = node.slot;
        var child_ref = node.child;
        while (child_ref != .null) {
            result = @max(result, self.maxPassedSlot(child_ref));
            child_ref = child_ref.constPtr(self.pool).?.sibling;
        }
        return result;
    }

    /// A block is "passed" if we have recorded a passed exec result for it, or
    /// if it is the current local root (whose passed status is implicit). A
    /// stale entry from a recycled pool index is detected by a slot mismatch.
    fn blockIsPassed(self: *const SimpleConsensus, block_ref: BlockRef) bool {
        const index = block_ref.index() orelse return false;
        const info = self.state[index] orelse return false;
        const slot = block_ref.constPtr(self.pool).?.slot;
        if (info.slot != slot) return false;
        return info.passed or info.finalized;
    }
};

/// Walks parent links until we find the tree's root (a block with no parent).
fn findTreeRoot(block_pool: *const BlockPool, start_ref: BlockRef) BlockRef {
    var current_ref = start_ref;
    for (0..BlockPool.capacity) |_| {
        const current = current_ref.constPtr(block_pool).?;
        if (current.parent == .null) return current_ref;
        current_ref = current.parent;
    }
    unreachable; // a cycle in parent links would be a bug in the pool
}

fn createTestBlock(block_pool: *BlockPool, slot: Slot, parent_ref: BlockRef) !BlockRef {
    const block_ref = try block_pool.createId();
    block_ref.constPtr(block_pool).?.* = .{ .slot = slot, .parent = parent_ref };

    if (parent_ref != .null) {
        const parent = parent_ref.constPtr(block_pool).?;
        if (parent.child == .null) {
            parent.child = block_ref;
        } else {
            var sibling_ref = parent.child;
            while (true) {
                const sibling = sibling_ref.constPtr(block_pool).?;
                if (sibling.sibling == .null) {
                    sibling.sibling = block_ref;
                    break;
                }
                sibling_ref = sibling.sibling;
            }
        }
    }

    return block_ref;
}

fn markPassed(consensus: *SimpleConsensus, block_ref: BlockRef) void {
    const slot = block_ref.constPtr(consensus.pool).?.slot;
    consensus.state[block_ref.index().?] = .{ .slot = slot, .passed = true, .finalized = false };
}

fn setRoot(consensus: *SimpleConsensus, block_ref: BlockRef) void {
    const slot = block_ref.constPtr(consensus.pool).?.slot;
    consensus.state[block_ref.index().?] = .{ .slot = slot, .passed = true, .finalized = true };
    consensus.last_finalized = block_ref;
}

test "simple_consensus finalizes deepest safe block on a long fork" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();
    var consensus: SimpleConsensus = .init(block_pool);

    // root -> a -> b -> tip, with tip 33 slots ahead of root.
    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, 1, root);
    const b = try createTestBlock(block_pool, 2, a);
    const tip = try createTestBlock(block_pool, finalization_depth + 1, b);
    setRoot(&consensus, root);
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
    var consensus: SimpleConsensus = .init(block_pool);

    // root -> tip, exactly finalization_depth slots ahead.
    const root = try createTestBlock(block_pool, 0, .null);
    const tip = try createTestBlock(block_pool, finalization_depth, root);
    setRoot(&consensus, root);
    markPassed(&consensus, tip);

    // tip is itself inside the last 32 slots, so there is no new safe block.
    try std.testing.expectEqual(@as(?BlockRef, null), consensus.findFinalizable());
}

test "simple_consensus recent competing fork prevents finality" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();
    var consensus: SimpleConsensus = .init(block_pool);

    // Two siblings under `a` both reach into the last 32 slots: one is the
    // long tip, the other a recent competitor.
    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, 1, root);
    const tip = try createTestBlock(block_pool, finalization_depth + 1, a);
    const competitor = try createTestBlock(block_pool, 2, a);
    setRoot(&consensus, root);
    markPassed(&consensus, a);
    markPassed(&consensus, tip);
    markPassed(&consensus, competitor);

    try std.testing.expectEqual(@as(?BlockRef, null), consensus.findFinalizable());
}

test "simple_consensus old competing fork does not prevent finality" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();
    var consensus: SimpleConsensus = .init(block_pool);

    // The competitor is one slot below the window, so it should not disqualify
    // the long fork through `a`.
    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, finalization_depth, root);
    const tip = try createTestBlock(block_pool, finalization_depth * 2, a);
    const old_competitor = try createTestBlock(block_pool, finalization_depth - 1, root);
    setRoot(&consensus, root);
    markPassed(&consensus, a);
    markPassed(&consensus, tip);
    markPassed(&consensus, old_competitor);

    try std.testing.expectEqual(a, consensus.findFinalizable().?);
}

test "simple_consensus only descends from the local root" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();
    var consensus: SimpleConsensus = .init(block_pool);

    // The full tree has a long fork through `other_fork`, but the local root
    // is `finalized` (which has no descendants), so no progress is possible.
    const tree_root = try createTestBlock(block_pool, 0, .null);
    const finalized = try createTestBlock(block_pool, 1, tree_root);
    const other_fork = try createTestBlock(block_pool, 2, tree_root);
    const other_tip = try createTestBlock(block_pool, finalization_depth + 2, other_fork);
    markPassed(&consensus, tree_root);
    setRoot(&consensus, finalized);
    markPassed(&consensus, other_fork);
    markPassed(&consensus, other_tip);

    try std.testing.expectEqual(@as(?BlockRef, null), consensus.findFinalizable());
}

test "simple_consensus unpassed block breaks the chain" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();
    var consensus: SimpleConsensus = .init(block_pool);

    // `a` is never reported as passed, so the chain root -> a -> tip is broken.
    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, 1, root);
    const tip = try createTestBlock(block_pool, finalization_depth + 1, a);
    setRoot(&consensus, root);
    markPassed(&consensus, tip);

    try std.testing.expectEqual(@as(?BlockRef, null), consensus.findFinalizable());
}

test "simple_consensus stale block info from a recycled pool index is ignored" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();
    var consensus: SimpleConsensus = .init(block_pool);

    const a = try createTestBlock(block_pool, 5, .null);
    markPassed(&consensus, a);
    try std.testing.expect(consensus.blockIsPassed(a));

    // Free `a` and immediately re-allocate at the same pool index for a
    // different block. `consensus.state[a.index()]` still holds the old slot.
    block_pool.destroyId(a);
    const b = try createTestBlock(block_pool, 10, .null);
    try std.testing.expectEqual(a, b);

    try std.testing.expect(!consensus.blockIsPassed(b));
}

test "simple_consensus update bootstraps the tree root" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();
    var consensus: SimpleConsensus = .init(block_pool);

    const tree_root = try createTestBlock(block_pool, 7, .null);
    const child = try createTestBlock(block_pool, 8, tree_root);

    // First exec result for `child` should bootstrap `tree_root` as the local
    // root and record the child as passed.
    try std.testing.expectEqual(@as(?BlockRef, null), consensus.update(child, true));
    try std.testing.expectEqual(tree_root, consensus.last_finalized);
    try std.testing.expect(consensus.state[tree_root.index().?].?.finalized);
    try std.testing.expectEqual(@as(Slot, 7), consensus.state[tree_root.index().?].?.slot);
    try std.testing.expect(consensus.blockIsPassed(child));
}

test "simple_consensus update ignores blocks below the local root" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();
    var consensus: SimpleConsensus = .init(block_pool);

    const tree_root = try createTestBlock(block_pool, 10, .null);
    _ = consensus.update(tree_root, true);

    // A second, older block with no parent acts as a stale notification.
    const old = try createTestBlock(block_pool, 5, .null);
    try std.testing.expectEqual(@as(?BlockRef, null), consensus.update(old, true));
    try std.testing.expect(!consensus.blockIsPassed(old));
}

test "simple_consensus update returns the finalized block when ready" {
    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&pool_buf);
    block_pool.init();
    var consensus: SimpleConsensus = .init(block_pool);

    const root = try createTestBlock(block_pool, 0, .null);
    const a = try createTestBlock(block_pool, 1, root);
    const b = try createTestBlock(block_pool, 2, a);
    const tip = try createTestBlock(block_pool, finalization_depth + 1, b);

    // First updates bootstrap the local root at `root` and record intermediate
    // blocks; neither result triggers finality yet.
    try std.testing.expectEqual(@as(?BlockRef, null), consensus.update(a, true));
    try std.testing.expectEqual(@as(?BlockRef, null), consensus.update(b, true));
    // `tip`'s arrival pushes the deepest safe block (`a`) to be finalized.
    try std.testing.expectEqual(a, consensus.update(tip, true).?);
    try std.testing.expectEqual(a, consensus.last_finalized);
}
