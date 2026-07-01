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

    // TODO: verify leaves are still consistent with block pool (not needed but
    // more of a safety check)

    // TODO: consider out of order execution. this is assumed not to ever
    // happen, and it won't with the current design. but the struct would be
    // more robust if it handled this correctly.

    pub fn update(self: *SimpleConsensus, execution_result: struct {
        passed: bool,
        block_ref: BlockRef,
    }) ?BlockRef {
        const executed = execution_result.block_ref.constPtr(self.pool);

        if (!execution_result.passed) return null; // TODO: log

        // add new result to our state
        const parent_opt = executed.parent.opt();
        for (self.leaves[0..self.num_leaves]) |*leaf| {
            if (parent_opt) |parent_id| {
                if (leaf.* == parent_id) {
                    leaf.* = execution_result.block_ref;
                    break;
                }
            }
        } else {
            // this is a new fork, it doesn't descend from a leaf.
            var node = executed;
            while (node.slot > self.root.constPtr(self.pool).slot) {
                const parent_id = node.parent.opt() orelse
                    @panic("missing unrooted block in block tree");
                node = parent_id.constPtr(self.pool);
            }
            if (self.pool.ptrToIndex(node) == self.root) {
                // This is a new leaf that is a descendant of the current root,
                // so we can add it to our leaves
                if (self.num_leaves == max_forks) @panic("too many forks");
                // Descending by slot, so insert before the first leaf whose
                // slot is not greater than the new leaf's slot. num_leaves
                // is bounded (<= max_forks), so a linear scan is fine.
                var index: usize = 0;
                while (index < self.num_leaves and
                    self.leaves[index].constPtr(self.pool).slot > executed.slot) : (index += 1)
                {}
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
            self.leaves[1].constPtr(self.pool).slot
        else
            self.root.constPtr(self.pool).slot;
        std.debug.assert(must_exceed_slot >= self.root.constPtr(self.pool).slot);

        // walk back 32 blocks from the first leaf
        var node_ref = self.leaves[0];
        for (0..finalization_depth) |_| {
            node_ref = node_ref.constPtr(self.pool).parent.opt() orelse {
                // TODO log, should only happen on startup
                return null;
            };
        }

        // if the slot of this node is greater than the must_exceed_slot, then
        // we have a new root.
        if (node_ref.constPtr(self.pool).slot > must_exceed_slot) {
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
