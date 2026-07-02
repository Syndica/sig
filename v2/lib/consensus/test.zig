const std = @import("std");
const lib = @import("../lib.zig");
const testing = std.testing;

const Slot = lib.solana.Slot;

const BlockPool = lib.replay.BlockPool;
const BlockRef = lib.replay.BlockRef;

const finalization_depth: Slot = 32;

/// Shared behavioural test suite for any consensus implementation exposing:
///
///     pub const Error = error{ MissingUnrootedAncestor, ... }
///     pub fn init(pool: *const BlockPool, root: BlockRef) SimpleConsensus
///     pub fn update(self: *SimpleConsensus, block: BlockRef, passed: bool) Error!?BlockRef
///     pub fn findFinalizable(self: *const SimpleConsensus) ?BlockRef
///     root: BlockRef  // publicly readable
///
/// Every implementation must satisfy the confirmation-based finality contract:
/// the finalize candidate is the block 32 confirmations behind the leading
/// fork's tip, and it may only be adopted when the last 32 confirmations on
/// the leading fork all sit at slots strictly greater than the most recent
/// block on any competing branch that shares an ancestor with the leading
/// fork at or above the local root.
///
/// Every implementation must return `error.MissingUnrootedAncestor` when the
/// update block's parent chain terminates (parent pointer is null) without
/// reaching a slot at or below the local root. This is a pool-consistency
/// error, not a "block is stale" signal.
///
/// Each implementation file wires the suite in via:
///
///     comptime {
///         _ = @import("test.zig").consensus_tests(SimpleConsensus);
///     }
pub fn consensus_tests(comptime SimpleConsensus: type) type {
    return struct {
        test "init: root is set and no finalization is possible" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            var c: SimpleConsensus = .init(pool, root);
            try testing.expectEqual(root, c.root);
            try testing.expectEqual(@as(?BlockRef, null), c.findFinalizable());
        }

        test "update: passed=false does not advance the leading fork" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);
            const child = try createBlock(pool, 1, .init(root));

            var c: SimpleConsensus = .init(pool, root);
            try testing.expectEqual(@as(?BlockRef, null), try c.update(child, false));
            try testing.expectEqual(root, c.root);
        }

        test "update: well-formed block at or below the local root is ignored" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            // pool_root(0) has two children: root(10) is the local consensus
            // root; stale(5) is a well-formed competitor whose slot sits
            // below the local root. It has a valid parent chain (to
            // pool_root), so it is not an "unrooted" error -- it is simply a
            // stale/off-tree block and must be silently ignored.
            const pool_root = try createBlock(pool, 0, .null);
            const root = try createBlock(pool, 10, .init(pool_root));
            const stale = try createBlock(pool, 5, .init(pool_root));

            var c: SimpleConsensus = .init(pool, root);
            try testing.expectEqual(@as(?BlockRef, null), try c.update(stale, true));
            try testing.expectEqual(root, c.root);
        }

        test "update: orphan block (null parent) returns MissingUnrootedAncestor" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);
            // orphan.parent == .null and orphan is not the local root. The
            // pool is inconsistent: an unrooted block cannot be placed in
            // the tree relative to the local root.
            const orphan = try createBlock(pool, 5, .null);

            var c: SimpleConsensus = .init(pool, root);
            try testing.expectError(error.MissingUnrootedAncestor, c.update(orphan, true));
        }

        test "update: block whose parent chain terminates above root errors" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);
            // Chain: null <- mid(5) <- tip(10). mid's parent is null and its
            // slot is strictly greater than root's slot, so the parent walk
            // from tip terminates before reaching root.
            const mid = try createBlock(pool, 5, .null);
            const tip = try createBlock(pool, 10, .init(mid));

            var c: SimpleConsensus = .init(pool, root);
            try testing.expectError(error.MissingUnrootedAncestor, c.update(tip, true));
        }

        test "update: single tip at finalization_depth cannot finalize past root" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);
            const tip = try createBlock(pool, finalization_depth, .init(root));

            var c: SimpleConsensus = .init(pool, root);
            try testing.expectEqual(@as(?BlockRef, null), try c.update(tip, true));
            try testing.expectEqual(root, c.root);
        }

        test "update: straight 33-block chain finalizes chain[0] on the 33rd block" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 1), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            for (chain, 0..) |b, i| {
                const result = try c.update(b, true);
                if (i < 32) {
                    try testing.expectEqual(@as(?BlockRef, null), result);
                } else {
                    try testing.expectEqual(chain[0], result.?);
                    try testing.expectEqual(chain[0], c.root);
                }
            }
        }

        test "update: recent competitor inside the last-32 window prevents finality" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Winning chain at slots 1..33; competitor at slot 2 as a sibling
            // of chain[0]. Walk-back-31 from tip@33 lands at chain[1]@2 which
            // does not strictly exceed the competitor's slot -- no finalize.
            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 1), .init(last));
                last = chain[i];
            }
            const competitor = try createBlock(pool, 2, .init(root));

            var c: SimpleConsensus = .init(pool, root);
            _ = try c.update(competitor, true);
            for (chain) |b| _ = try c.update(b, true);
            try testing.expectEqual(root, c.root);
        }

        test "update: old competitor below the last-32 window allows finality" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Competitor at slot 1; winning chain at slots 2..34.
            // Walk-back-31 from tip@34 lands at chain[1]@3 > competitor@1.
            const competitor = try createBlock(pool, 1, .init(root));
            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 2), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            _ = try c.update(competitor, true);
            for (chain, 0..) |b, i| {
                const result = try c.update(b, true);
                if (i < 32) {
                    try testing.expectEqual(@as(?BlockRef, null), result);
                } else {
                    try testing.expectEqual(chain[0], result.?);
                    try testing.expectEqual(chain[0], c.root);
                }
            }
        }

        test "update: unpassed middle block breaks the finalization chain" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 1), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            for (chain, 0..) |b, i| _ = try c.update(b, i != 5);
            try testing.expectEqual(root, c.root);
        }

        test "update: subtree rooted at a sibling of the consensus root is ignored" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);

            // pool_root(0)
            //   |-- consensus_root(1)                   <- local root
            //   |-- sibling_chain[0..32] (slots 10..42) <- 33-block subtree
            //                                              not reachable via
            //                                              consensus_root
            const pool_root = try createBlock(pool, 0, .null);
            const consensus_root = try createBlock(pool, 1, .init(pool_root));

            var sibling_chain: [33]BlockRef = undefined;
            var last = pool_root;
            for (0..33) |i| {
                sibling_chain[i] = try createBlock(pool, @intCast(i + 10), .init(last));
                last = sibling_chain[i];
            }

            var c: SimpleConsensus = .init(pool, consensus_root);
            for (sibling_chain) |b| _ = try c.update(b, true);
            try testing.expectEqual(consensus_root, c.root);
        }

        test "update: leaf competitor added before the winning fork prevents finality" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Competitor is added first so it becomes root's *first* child
            // (its sibling pointer is non-null). Then a 33-block winning
            // chain is added at slots 1..33. Competitor@3 sits inside the
            // winning fork's last-32 window (slots 1..33) -- no finalize.
            //
            // This layout exists specifically to catch implementations that
            // drop leaves whose sibling pointer is non-null.
            const competitor = try createBlock(pool, 3, .init(root));
            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 1), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            _ = try c.update(competitor, true);
            for (chain) |b| _ = try c.update(b, true);
            try testing.expectEqual(root, c.root);
        }

        test "update: competitor exactly at the walk-back-31 slot prevents finality" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Winning chain at slots 2..34; competitor at slot 3 -- exactly
            // where walk-back-31 from tip@34 lands (chain[1]@3). The check
            // must be strict (>), so no finalize.
            const competitor = try createBlock(pool, 3, .init(root));
            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 2), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            _ = try c.update(competitor, true);
            for (chain) |b| _ = try c.update(b, true);
            try testing.expectEqual(root, c.root);
        }

        test "update: repeated finalization advances the root one block at a time" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // 65-block chain. The 33rd update finalizes chain[0]; each
            // update after that advances the root by exactly one block.
            var chain: [65]BlockRef = undefined;
            var last = root;
            for (0..65) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 1), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            for (chain, 0..) |b, i| {
                const result = try c.update(b, true);
                if (i < 32) {
                    try testing.expectEqual(@as(?BlockRef, null), result);
                } else {
                    try testing.expectEqual(chain[i - 32], result.?);
                    try testing.expectEqual(chain[i - 32], c.root);
                }
            }
        }

        test "update: null-parent ancestor at exactly root_slot is silently ignored" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);

            // root has slot 5. `x` is an unrooted block whose slot equals
            // root's slot; its child `y` is above the root slot. Walking
            // from y: parent is x, x.slot == root.slot so the walk exits
            // without erroring, but x != self.root, so `y` is silently
            // dropped. This pins the boundary between "silent drop"
            // (ancestor.slot <= root_slot) and "error"
            // (ancestor.slot > root_slot with null parent).
            const root = try createBlock(pool, 5, .null);
            const x = try createBlock(pool, 5, .null);
            const y = try createBlock(pool, 8, .init(x));

            var c: SimpleConsensus = .init(pool, root);
            try testing.expectEqual(@as(?BlockRef, null), try c.update(y, true));
            try testing.expectEqual(root, c.root);
        }

        test "update: two equal-length 33-chains cannot finalize" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Two independent 33-block chains off root, both at slots 1..33.
            // Updates are interleaved so that at every step each fork's
            // most-recent tip acts as a competitor to the other. Neither
            // fork ever dominates: from either fork's tip, the walk-back-31
            // lands at slot 2, which does not strictly exceed the other
            // fork's tip slot (32 or 33). No finalize is possible.
            var chain_a: [33]BlockRef = undefined;
            var last_a = root;
            for (0..33) |i| {
                chain_a[i] = try createBlock(pool, @intCast(i + 1), .init(last_a));
                last_a = chain_a[i];
            }
            var chain_b: [33]BlockRef = undefined;
            var last_b = root;
            for (0..33) |i| {
                chain_b[i] = try createBlock(pool, @intCast(i + 1), .init(last_b));
                last_b = chain_b[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            for (0..33) |i| {
                _ = try c.update(chain_a[i], true);
                _ = try c.update(chain_b[i], true);
            }
            try testing.expectEqual(root, c.root);
        }

        test "update: multiple old competitors all below the window allow finality" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Three sibling competitors at slots 1, 2, 3. Winning chain at
            // slots 4..36. Walk-back-31 from tip@36 lands at chain[1]@5,
            // which strictly exceeds the greatest competitor slot (3).
            // The finalize candidate is chain[0]@4.
            const c1 = try createBlock(pool, 1, .init(root));
            const c2 = try createBlock(pool, 2, .init(root));
            const c3 = try createBlock(pool, 3, .init(root));
            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 4), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            _ = try c.update(c1, true);
            _ = try c.update(c2, true);
            _ = try c.update(c3, true);
            for (chain, 0..) |b, i| {
                const result = try c.update(b, true);
                if (i < 32) {
                    try testing.expectEqual(@as(?BlockRef, null), result);
                } else {
                    try testing.expectEqual(chain[0], result.?);
                    try testing.expectEqual(chain[0], c.root);
                }
            }
        }

        test "update: competitor's deep grandchild raises the fin threshold" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Competitor sub-tree:  competitor@1 -> deep_child@5
            // Winning chain:        chain@2..34
            // Walk-back-31 from tip@34 lands at chain[1]@3. The competitor's
            // deepest slot is 5, not 1, so the check is 3 <= 5 -- no
            // finalize. Exercises tree walks recursing into competitor
            // subtrees (leaf.zig instead sees deep_child as a leaf directly).
            const competitor = try createBlock(pool, 1, .init(root));
            const deep_child = try createBlock(pool, 5, .init(competitor));
            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 2), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            _ = try c.update(competitor, true);
            _ = try c.update(deep_child, true);
            for (chain) |b| _ = try c.update(b, true);
            try testing.expectEqual(root, c.root);
        }

        test "update: candidate slot exactly equal to competitor slot still finalizes" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Competitor@3 as a sibling of chain[0]. Winning chain at slots
            // 3..35 -- chain[0].slot exactly equals competitor.slot. The
            // "last 32 confirmations" are chain[32..1] (slots 35..4) and all
            // strictly exceed 3; the finalize candidate itself (chain[0]@3)
            // is one hop past the window and its slot is NOT required to
            // exceed the competitor's. Must finalize chain[0].
            //
            // This pins the off-by-one boundary between "the last 32
            // confirmations beat the competitor" (correct: walk-back-31
            // check) and "the last 33 blocks including the candidate beat
            // the competitor" (too strict).
            const competitor = try createBlock(pool, 3, .init(root));
            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 3), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            _ = try c.update(competitor, true);
            for (chain, 0..) |b, i| {
                const result = try c.update(b, true);
                if (i < 32) {
                    try testing.expectEqual(@as(?BlockRef, null), result);
                } else {
                    try testing.expectEqual(chain[0], result.?);
                    try testing.expectEqual(chain[0], c.root);
                }
            }
        }

        test "update: repeated finalization succeeds despite a permanent old competitor" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Competitor@1 as a sibling of chain[0]. 65-block winning chain
            // at slots 2..66. Once the root moves past the competitor's
            // slot, the competitor's subtree is no longer reachable from
            // self.root and cannot affect subsequent finalizations. Every
            // update from i=32 onward advances the root by one.
            const competitor = try createBlock(pool, 1, .init(root));
            var chain: [65]BlockRef = undefined;
            var last = root;
            for (0..65) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 2), .init(last));
                last = chain[i];
            }

            var c: SimpleConsensus = .init(pool, root);
            _ = try c.update(competitor, true);
            for (chain, 0..) |b, i| {
                const result = try c.update(b, true);
                if (i < 32) {
                    try testing.expectEqual(@as(?BlockRef, null), result);
                } else {
                    try testing.expectEqual(chain[i - 32], result.?);
                    try testing.expectEqual(chain[i - 32], c.root);
                }
            }
        }

        test "update: mid-chain fork inside the last-32 window blocks finality" {
            var buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
            const pool = setupPool(&buf);
            const root = try createBlock(pool, 0, .null);

            // Winning chain slots 1..33. A mid-chain sibling `mid_fork`
            // hangs off chain[4]@5 with slot 10. Walk-back-31 from tip@33
            // lands at chain[1]@2; the highest non-leading slot in the
            // subtree is mid_fork@10, so 2 <= 10 -- no finalize. This
            // exercises tree walkers finding competitors below the root's
            // direct children.
            var chain: [33]BlockRef = undefined;
            var last = root;
            for (0..33) |i| {
                chain[i] = try createBlock(pool, @intCast(i + 1), .init(last));
                last = chain[i];
            }
            const mid_fork = try createBlock(pool, 10, .init(chain[4]));

            // Update mid_fork before extending the chain past slot 10 so
            // the competitor is visible during every subsequent
            // finalization attempt.
            var c: SimpleConsensus = .init(pool, root);
            _ = try c.update(mid_fork, true);
            for (chain) |b| _ = try c.update(b, true);
            try testing.expectEqual(root, c.root);
        }
    };
}

fn setupPool(buf: []align(@alignOf(BlockPool)) u8) *BlockPool {
    const pool: *BlockPool = @ptrCast(buf.ptr);
    pool.init();
    return pool;
}

/// Allocates a block in `pool`, sets its `slot`/`parent`, and appends it as
/// the last child of `parent` (wiring `child`/`sibling` pointers). This shape
/// satisfies every implementation: parent-only walkers read `parent`, tree
/// walkers read `child`/`sibling`.
fn createBlock(pool: *BlockPool, slot: Slot, parent: BlockRef.Optional) !BlockRef {
    const ref = try pool.createId();
    ref.ptr(pool).* = .{ .slot = slot, .parent = parent };
    if (parent.opt()) |parent_id| {
        const p = parent_id.ptr(pool);
        if (p.child.opt()) |first_child_id| {
            var s_ref = first_child_id;
            while (true) {
                const s = s_ref.ptr(pool);
                if (s.sibling.opt()) |next| {
                    s_ref = next;
                } else {
                    s.sibling = .init(ref);
                    break;
                }
            }
        } else {
            p.child = .init(ref);
        }
    }
    return ref;
}
