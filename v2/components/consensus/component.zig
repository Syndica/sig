//! NOTE: This component implements simple depth-based finalization, not a full
//!       production fork-choice rule. Replay sends the bootstrap root first,
//!       then only successfully executed blocks. Consensus treats every received
//!       block after the root as confirmed.
//!
//! NOTE: Finalization is computed from the current anchor using BlockPool parent
//!       links and confirmed child/sibling links. Parent links are required for
//!       the block's path back to the anchor; child/sibling links let a late
//!       parent notification notice already-confirmed descendants.
//!
//! NOTE: This component relies on replay's documented BlockPool lifetime behavior.
//!       Replay currently does not implement eviction, so BlockRefs are not recycled
//!       while this consensus state is alive.

const std = @import("std");

pub const api = @import("consensus_api");

const BlockRef = api.BlockRef;
const BlockPool = api.BlockPool;

const FINALIZATION_DEPTH: usize = 3;

pub const ConsensusState = struct {
    const Self = @This();

    current_anchor: BlockRef,
    block_pool: *const BlockPool,
    confirmed: std.StaticBitSet(BlockPool.capacity) = .initEmpty(),

    const ConfirmedDescendant = struct {
        block: BlockRef,
        depth: usize,
    };

    pub fn init(
        root: BlockRef,
        block_pool: *const BlockPool,
    ) Self {
        var self: Self = .{ .current_anchor = root, .block_pool = block_pool };
        self.confirmed.set(root.index());
        return self;
    }

    pub fn blockConfirmed(self: *Self, block: BlockRef) ?BlockRef {
        self.confirmed.set(block.index());

        // walk up to the anchor
        const depth_from_anchor = self.confirmedDepthFromAnchor(block) orelse return null;

        // walk down to the deepest descendant
        // NOTE: currently returns early since it is missing child/sibling links,
        //       it depends on replay maintaining BlockPool child/sibling links.
        const deepest_descendant = self.deepestConfirmedDescendant(block);

        const confirmed_chain_depth = depth_from_anchor + deepest_descendant.depth;
        if (confirmed_chain_depth <= FINALIZATION_DEPTH) return null;

        var candidate = deepest_descendant.block;
        for (0..FINALIZATION_DEPTH) |_| {
            candidate = candidate.constPtr(self.block_pool).parent.opt() orelse unreachable;
        }
        std.debug.assert(candidate != self.current_anchor);

        self.current_anchor = candidate;
        return candidate;
    }

    fn confirmedDepthFromAnchor(self: *const Self, block: BlockRef) ?usize {
        var curr = block;
        var depth: usize = 0;

        while (curr != self.current_anchor) {
            const parent = curr.constPtr(self.block_pool).parent.opt() orelse return null;
            if (parent != self.current_anchor and
                !self.confirmed.isSet(parent.index())) return null;

            curr = parent;
            depth += 1;
        }

        return depth;
    }

    fn deepestConfirmedDescendant(self: *const Self, block: BlockRef) ConfirmedDescendant {
        var deepest: ConfirmedDescendant = .{ .block = block, .depth = 0 };

        var stack: [BlockPool.capacity]ConfirmedDescendant = undefined;
        var stack_len: usize = 0;

        stack[stack_len] = deepest;
        stack_len += 1;

        while (stack_len != 0) {
            stack_len -= 1;
            const candidate = stack[stack_len];
            if (candidate.depth > deepest.depth) {
                deepest = candidate;
            }

            var maybe_child_ref = candidate.block.constPtr(self.block_pool).child.opt();
            while (maybe_child_ref) |child| {
                if (self.confirmed.isSet(child.index())) {
                    stack[stack_len] = .{
                        .block = child,
                        .depth = candidate.depth + 1,
                    };
                    stack_len += 1;
                }

                maybe_child_ref = child.constPtr(self.block_pool).sibling.opt();
            }
        }

        return deepest;
    }
};

fn blockPoolForConsensusTest(
    pool_buf: *align(@alignOf(api.BlockPool)) [api.BlockPool.size()]u8,
) *api.BlockPool {
    const block_pool: *api.BlockPool = @ptrCast(pool_buf);
    block_pool.init();
    return block_pool;
}

fn setParentForConsensusTest(
    block_pool: *api.BlockPool,
    block: BlockRef,
    parent: ?BlockRef,
) void {
    block.ptr(block_pool).* = .{
        .parent = .init(parent),
        .slot = .null,
    };

    const parent_ref = parent orelse return;
    const parent_block = parent_ref.ptr(block_pool);
    if (parent_block.child == .null) {
        parent_block.child = .init(block);
        return;
    }

    var tail_ref = parent_block.child.opt().?;
    while (true) {
        const tail = tail_ref.ptr(block_pool);
        tail_ref = tail.sibling.opt() orelse {
            tail.sibling = .init(block);
            return;
        };
    }
}

test "consensus.component: initializes root as confirmed anchor" {
    var pool_buf: [api.BlockPool.size()]u8 align(@alignOf(api.BlockPool)) = undefined;
    const block_pool = blockPoolForConsensusTest(&pool_buf);

    const root = BlockRef.fromInt(4);
    setParentForConsensusTest(block_pool, root, null);

    var state: ConsensusState = .init(root, block_pool);
    try std.testing.expectEqual(root, state.current_anchor);
    try std.testing.expect(state.confirmed.isSet(root.index()));
}

test "consensus.component: does not finalize at finalization depth" {
    var pool_buf: [api.BlockPool.size()]u8 align(@alignOf(api.BlockPool)) = undefined;
    const block_pool = blockPoolForConsensusTest(&pool_buf);

    const root = BlockRef.fromInt(4);
    const a = BlockRef.fromInt(5);
    const b = BlockRef.fromInt(6);
    const c = BlockRef.fromInt(7);
    setParentForConsensusTest(block_pool, root, null);
    setParentForConsensusTest(block_pool, a, root);
    setParentForConsensusTest(block_pool, b, a);
    setParentForConsensusTest(block_pool, c, b);

    var state: ConsensusState = .init(root, block_pool);
    try std.testing.expectEqual(null, state.blockConfirmed(a));
    try std.testing.expectEqual(null, state.blockConfirmed(b));
    try std.testing.expectEqual(null, state.blockConfirmed(c));
    try std.testing.expectEqual(root, state.current_anchor);
}

test "consensus.component: finalizes first block after finalization depth" {
    var pool_buf: [api.BlockPool.size()]u8 align(@alignOf(api.BlockPool)) = undefined;
    const block_pool = blockPoolForConsensusTest(&pool_buf);

    const root = BlockRef.fromInt(4);
    const a = BlockRef.fromInt(5);
    const b = BlockRef.fromInt(6);
    const c = BlockRef.fromInt(7);
    const d = BlockRef.fromInt(8);
    setParentForConsensusTest(block_pool, root, null);
    setParentForConsensusTest(block_pool, a, root);
    setParentForConsensusTest(block_pool, b, a);
    setParentForConsensusTest(block_pool, c, b);
    setParentForConsensusTest(block_pool, d, c);

    var state: ConsensusState = .init(root, block_pool);
    try std.testing.expectEqual(null, state.blockConfirmed(a));
    try std.testing.expectEqual(null, state.blockConfirmed(b));
    try std.testing.expectEqual(null, state.blockConfirmed(c));
    try std.testing.expectEqual(a, state.blockConfirmed(d).?);
    try std.testing.expectEqual(a, state.current_anchor);
}

test "consensus.component: linear finalization advances repeatedly" {
    var pool_buf: [api.BlockPool.size()]u8 align(@alignOf(api.BlockPool)) = undefined;
    const block_pool = blockPoolForConsensusTest(&pool_buf);

    const root = BlockRef.fromInt(4);
    const a = BlockRef.fromInt(5);
    const b = BlockRef.fromInt(6);
    const c = BlockRef.fromInt(7);
    const d = BlockRef.fromInt(8);
    const e = BlockRef.fromInt(9);
    setParentForConsensusTest(block_pool, root, null);
    setParentForConsensusTest(block_pool, a, root);
    setParentForConsensusTest(block_pool, b, a);
    setParentForConsensusTest(block_pool, c, b);
    setParentForConsensusTest(block_pool, d, c);
    setParentForConsensusTest(block_pool, e, d);

    var state: ConsensusState = .init(root, block_pool);
    try std.testing.expectEqual(null, state.blockConfirmed(a));
    try std.testing.expectEqual(null, state.blockConfirmed(b));
    try std.testing.expectEqual(null, state.blockConfirmed(c));
    try std.testing.expectEqual(a, state.blockConfirmed(d).?);
    try std.testing.expectEqual(b, state.blockConfirmed(e).?);
    try std.testing.expectEqual(b, state.current_anchor);
}

test "consensus.component: confirmed child becomes finalizable when missing parent arrives" {
    var pool_buf: [api.BlockPool.size()]u8 align(@alignOf(api.BlockPool)) = undefined;
    const block_pool = blockPoolForConsensusTest(&pool_buf);

    const root = BlockRef.fromInt(4);
    const a = BlockRef.fromInt(5);
    const b = BlockRef.fromInt(6);
    const c = BlockRef.fromInt(7);
    const d = BlockRef.fromInt(8);
    setParentForConsensusTest(block_pool, root, null);
    setParentForConsensusTest(block_pool, a, root);
    setParentForConsensusTest(block_pool, b, a);
    setParentForConsensusTest(block_pool, c, b);
    setParentForConsensusTest(block_pool, d, c);

    var state: ConsensusState = .init(root, block_pool);
    try std.testing.expectEqual(null, state.blockConfirmed(d));
    try std.testing.expectEqual(null, state.blockConfirmed(c));
    try std.testing.expectEqual(null, state.blockConfirmed(b));
    try std.testing.expectEqual(a, state.blockConfirmed(a).?);
    try std.testing.expectEqual(a, state.current_anchor);
}

test "consensus.component: competing fork must exceed finalization depth" {
    var pool_buf: [api.BlockPool.size()]u8 align(@alignOf(api.BlockPool)) = undefined;
    const block_pool = blockPoolForConsensusTest(&pool_buf);

    const root = BlockRef.fromInt(4);
    const x = BlockRef.fromInt(5);
    const y = BlockRef.fromInt(6);
    const z = BlockRef.fromInt(7);
    const a = BlockRef.fromInt(8);
    const b = BlockRef.fromInt(9);
    const c = BlockRef.fromInt(10);
    const d = BlockRef.fromInt(11);
    setParentForConsensusTest(block_pool, root, null);
    setParentForConsensusTest(block_pool, x, root);
    setParentForConsensusTest(block_pool, y, x);
    setParentForConsensusTest(block_pool, z, y);
    setParentForConsensusTest(block_pool, a, root);
    setParentForConsensusTest(block_pool, b, a);
    setParentForConsensusTest(block_pool, c, b);
    setParentForConsensusTest(block_pool, d, c);

    var state: ConsensusState = .init(root, block_pool);
    try std.testing.expectEqual(null, state.blockConfirmed(x));
    try std.testing.expectEqual(null, state.blockConfirmed(y));
    try std.testing.expectEqual(null, state.blockConfirmed(a));
    try std.testing.expectEqual(null, state.blockConfirmed(z));
    try std.testing.expectEqual(null, state.blockConfirmed(b));
    try std.testing.expectEqual(null, state.blockConfirmed(c));
    try std.testing.expectEqual(a, state.blockConfirmed(d).?);
    try std.testing.expectEqual(a, state.current_anchor);
}
