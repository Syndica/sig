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

var Leaves = [1024]BlockRef;

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

pub const SimpleConsensus = struct {
    pool: *const BlockPool,
    state: [BlockPool.capacity]?BlockInfo,
    last_finalized: BlockRef,

    pub const init: SimpleConsensus = .{
        .state = @splat(null),
        .last_finalized = null,
    };

    pub fn update(self: *SimpleConsensus, execution_result: struct {
        passed: bool,
        block_ref: BlockRef,
    }) ?BlockRef {
        if (execution_result.block_ref == .null) return null;
        const executed = self.state[execution_result.block_ref.index().?];
        if (executed != null) return error.Overflow;
        executed.* = .{
            .slot = lib.replay.getBlockSlot(execution_result.block_ref),
            .passed = execution_result.passed,
            .finalized = false,
        };

        if (self.last_finalized == .null) return;

        self.getBestEnd(self.last_finalized);

        // var checkme = self.last_finalized.constPtr(self.pool).?;
        // _ = checkme; // autofix

        // return execution_result.block_ref;
    }

    pub fn getBestEnd(self: *SimpleConsensus, root: BlockRef) !void {
        var checkme = root.constPtr(self.pool).?;
        self.state[root.index().?];
        while (checkme != null) : (checkme = root.constPtr(self.pool).?) {
            checkme = checkme.sibling.constPtr(self.pool).?;
            self.state[checkme.index().?];
        }
    }
};

pub const SimpleConsensus2 = struct {
    pool: *const BlockPool,
    root: BlockRef,
    leaves: [max_forks]BlockRef,
    num_leaves: std.math.IntFittingRange(0, max_forks),

    const max_forks = 256;
    const finalization_depth: Slot = 32;

    pub fn init(pool: *const BlockPool, root: BlockRef) SimpleConsensus2 {
        var leaves: [max_forks]BlockRef = @splat(.null);
        leaves[0] = root;
        return .{
            .pool = pool,
            .root = root,
            .leaves = leaves,
            .num_leaves = 1,
        };
    }

    // TODO: verify leaves are still consistent with block pool (not needed but
    // more of a safety check)

    // TODO: consider out of order execution. this is assumed not to ever
    // happen, and it won't with the current design. but the struct would be
    // more robust if it handled this correctly.

    pub fn update(self: *SimpleConsensus2, execution_result: struct {
        passed: bool,
        block_ref: BlockRef,
    }) ?BlockRef {
        if (execution_result.block_ref == .null) return null; // TODO: this is an unexpected bad input, should log error
        const executed = execution_result.block_ref.constPtr(self.pool).?;

        std.debug.assert(self.root != .null); // impossible if struct is used properly
        if (!execution_result.passed) return null; // TODO: log

        // add new result to our state
        for (self.leaves[0..self.num_leaves]) |*leaf| {
            if (leaf.* == executed.parent) {
                leaf.* = execution_result.block_ref;
                break;
            }
        } else {
            // this is a new fork, it doesn't descend from a leaf.
            var node = executed;
            while (node.slot > self.root.constPtr(self.pool).?.slot) {
                if (node.parent.constPtr(self.pool)) |parent| {
                    node = parent;
                } else @panic("missing unrooted block in block tree");
            }
            if (self.pool.ptrToIndex(node) == self.root) {
                // This is a new leaf that is a descendant of the current root,
                // so we can add it to our leaves
                if (self.num_leaves == max_forks) @panic("too many forks");
                const index = std.sort.lowerBound(
                    BlockRef,
                    self.leaves[0..self.num_leaves],
                    self.pool,
                    struct {
                        pub fn gt(pool: *const BlockPool, a: BlockRef, b: BlockRef) bool {
                            // this is greater than to sort descending.
                            return a.constPtr(pool).?.slot > b.constPtr(pool).?.slot;
                        }
                    }.gt,
                );
                @memmove(
                    self.leaves[index + 1 .. self.num_leaves + 1],
                    self.leaves[index..self.num_leaves],
                );
                self.leaves[index] = execution_result.block_ref;
                self.num_leaves += 1;
            } else {
                // This is not a descendant of the root so it is not a legal
                // fork. TODO: log an error here - this is very unusual. it
                // indicates either a bug or a misbehaving leader.
                return null;
            }
        }

        // advance root

        // a new root is not allowed unless there are 32 contiguous blocks,
        // starting after this slot, with no other competing forks that had
        // blocks after this slot.
        const must_exceed_slot = if (self.num_leaves > 1)
            self.leaves[1].constPtr(self.pool).?.slot
        else
            self.root.constPtr(self.pool).?.slot;
        std.debug.assert(must_exceed_slot >= self.root.constPtr(self.pool).?.slot);

        // walk back 32 blocks from the first leaf
        var node_ref = self.leaves[0];
        for (0..32) |_| {
            node_ref = node_ref.constPtr(self.pool).?.parent;
            if (node_ref == .null) {
                // TODO log, should only happen on startup
                return null;
            }
        }

        // if the slot of this node is greater than the must_exceed_slot, then
        // we have a new root.
        if (node_ref.constPtr(self.pool).?.slot > must_exceed_slot) {
            // TODO log new root
            self.root = node_ref;
            self.num_leaves = 1;
            return node_ref;
        }

        // TODO should we log here? it means we have forks
        return null;
    }
};

// fn lap(ref: BlockRef) ?u8 {
//     return @truncate(if (ref.index()) |i| i % BlockPool.capacity);
// }
