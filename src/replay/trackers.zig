const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const Slot = sig.core.Slot;
const SlotConstants = sig.core.SlotConstants;
const SlotState = sig.core.SlotState;
const ReferenceCounter = sig.sync.ReferenceCounter;
const RwMux = sig.sync.RwMux;
const ThreadPool = sig.sync.ThreadPool;
const Commitment = sig.rpc.methods.common.Commitment;

pub const ForkChoiceProcessedSlot = struct {
    slot: std.atomic.Value(Slot) = .init(0),

    /// Set the current processed slot (heaviest fork tip).
    /// Uses store() because this can decrease when the fork choice
    /// switches to a different fork with a lower slot.
    pub fn set(self: *ForkChoiceProcessedSlot, new_slot: Slot) void {
        self.slot.store(new_slot, .monotonic);
    }

    pub fn get(self: *const ForkChoiceProcessedSlot) Slot {
        return self.slot.load(.monotonic);
    }
};

pub const OptimisticallyConfirmedSlot = struct {
    slot: std.atomic.Value(Slot) = .init(0),

    pub fn update(self: *OptimisticallyConfirmedSlot, new_slot: Slot) void {
        _ = self.slot.fetchMax(new_slot, .monotonic);
    }

    pub fn get(self: *const OptimisticallyConfirmedSlot) Slot {
        return self.slot.load(.monotonic);
    }
};

/// Central registry that tracks high-level info about slots and how they fork.
///
/// This is a lean version of `BankForks` from agave, focused on storing the
/// minimal information about slots to serve its core focus, rather than the
/// kitchen-sink style approach of storing everything under the sun.
///
/// [BankForks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank_forks.rs#L75)
///
/// This struct is thread safe for concurrent reads / exclusive writes on slots.
pub const SlotTracker = struct {
    pub const SlotsMap = std.AutoArrayHashMapUnmanaged(Slot, *Element);

    slots: RwMux(SlotsMap),
    latest_processed_slot: ForkChoiceProcessedSlot,
    latest_confirmed_slot: OptimisticallyConfirmedSlot,
    root: std.atomic.Value(Slot),
    wg: *std.Thread.WaitGroup,

    pub const Element = struct {
        constants: SlotConstants,
        state: SlotState,
        destroy_task: ThreadPool.Task = .{ .callback = runDestroy },
        pruned_wg: ?*std.Thread.WaitGroup = null,
        allocator: Allocator,
        rc: ReferenceCounter = .init,

        pub fn toRef(self: *Element) ?Reference {
            if (!self.rc.acquire()) return null;
            return .{ .element = self };
        }

        fn releaseRef(self: *Element) void {
            if (self.rc.release()) self.destroy();
        }

        fn destroy(self: *Element) void {
            const allocator = self.allocator;
            self.constants.deinit(allocator);
            self.state.deinit(allocator);
            allocator.destroy(self);
        }

        fn runDestroy(task: *ThreadPool.Task) void {
            const zone = tracy.Zone.init(@src(), .{ .name = "SlotTracker.Element.destroy" });
            defer zone.deinit();

            const self: *Element = @alignCast(@fieldParentPtr("destroy_task", task));
            const wg = self.pruned_wg.?; // read it out of self, as this will destroy(self)
            defer wg.finish();

            self.releaseRef();
        }
    };

    pub const Reference = struct {
        element: *Element,

        pub fn constants(self: Reference) *const SlotConstants {
            return &self.element.constants;
        }

        pub fn state(self: Reference) *SlotState {
            return &self.element.state;
        }

        pub fn release(self: Reference) void {
            self.element.releaseRef();
        }
    };

    pub fn initEmpty(allocator: Allocator, root_slot: Slot) !SlotTracker {
        const wg = try allocator.create(std.Thread.WaitGroup);
        wg.* = .{};
        return .{
            .root = .init(root_slot),
            .slots = RwMux(SlotsMap).init(.empty),
            .latest_processed_slot = .{},
            .latest_confirmed_slot = .{},
            .wg = wg,
        };
    }

    pub fn init(
        allocator: std.mem.Allocator,
        root_slot: Slot,
        /// ownership is transferred to this function, except in the case of an error return
        slot_init: Element,
    ) std.mem.Allocator.Error!SlotTracker {
        var self: SlotTracker = try .initEmpty(allocator, root_slot);
        errdefer self.deinit(allocator);

        try self.put(allocator, root_slot, slot_init);
        {
            var slots = self.slots.read();
            defer slots.unlock();
            tracy.plot(u32, "slots tracked", @intCast(slots.get().count()));
        }

        return self;
    }

    pub fn deinit(self: *SlotTracker, allocator: Allocator) void {
        self.wg.wait();
        allocator.destroy(self.wg);

        var slots_lg = self.slots.write();
        const slots = slots_lg.mut();
        for (slots.values()) |element| element.destroy();
        slots.deinit(allocator);
        slots_lg.unlock();
    }

    pub fn put(
        self: *SlotTracker,
        allocator: Allocator,
        slot: Slot,
        slot_init: Element,
    ) Allocator.Error!void {
        var slots_lg = self.slots.write();
        defer slots_lg.unlock();
        const slots = slots_lg.mut();

        defer tracy.plot(u32, "slots tracked", @intCast(slots.count()));

        try slots.ensureUnusedCapacity(allocator, 1);
        const elem = try allocator.create(Element);
        elem.* = slot_init;
        const gop = slots.getOrPutAssumeCapacity(slot);
        if (gop.found_existing) gop.value_ptr.*.releaseRef();
        gop.value_ptr.* = elem;
    }

    pub fn get(self: *SlotTracker, slot: Slot) ?Reference {
        var slots_lg = self.slots.read();
        defer slots_lg.unlock();
        const elem = slots_lg.get().get(slot) orelse return null;
        return elem.toRef();
    }

    pub fn getSlotForCommitment(self: *const SlotTracker, commitment: Commitment) Slot {
        return switch (commitment) {
            .processed => self.latest_processed_slot.get(),
            .confirmed => self.latest_confirmed_slot.get(),
            .finalized => self.root.load(.monotonic),
        };
    }

    pub const GetOrPutResult = struct {
        found_existing: bool,
        reference: Reference,
    };

    pub fn getOrPut(
        self: *SlotTracker,
        allocator: Allocator,
        slot: Slot,
        slot_init: Element,
    ) Allocator.Error!GetOrPutResult {
        var slots_lg = self.slots.write();
        defer slots_lg.unlock();
        const slots = slots_lg.mut();

        defer tracy.plot(u32, "slots tracked", @intCast(slots.count()));

        if (slots.get(slot)) |existing| {
            if (existing.toRef()) |ref| return .{
                .found_existing = true,
                .reference = ref,
            };
        }
        try slots.ensureUnusedCapacity(allocator, 1);
        const elem = try allocator.create(Element);
        elem.* = slot_init;
        slots.putAssumeCapacityNoClobber(slot, elem);
        return .{
            .found_existing = false,
            .reference = elem.toRef().?,
        };
    }

    pub fn getRoot(self: *SlotTracker) Reference {
        return self.get(self.root.load(.monotonic)).?; // root slot's bank must exist
    }

    pub fn contains(self: *SlotTracker, slot: Slot) bool {
        var slots_lg = self.slots.read();
        defer slots_lg.unlock();
        return slots_lg.get().contains(slot);
    }

    pub fn activeSlots(
        self: *SlotTracker,
        allocator: Allocator,
    ) Allocator.Error![]const Slot {
        var slots_lg = self.slots.read();
        defer slots_lg.unlock();
        const slots = slots_lg.get();

        var list = try std.ArrayListUnmanaged(Slot).initCapacity(allocator, slots.count());
        errdefer list.deinit(allocator);

        for (slots.keys(), slots.values()) |slot, value| {
            if (!value.state.isFrozen()) {
                list.appendAssumeCapacity(slot);
            }
        }
        return try list.toOwnedSlice(allocator);
    }

    pub fn frozenSlots(
        self: *SlotTracker,
        allocator: Allocator,
    ) Allocator.Error!std.AutoArrayHashMapUnmanaged(Slot, Reference) {
        var slots_lg = self.slots.read();
        defer slots_lg.unlock();
        const slots = slots_lg.get();

        var frozen_slots: std.AutoArrayHashMapUnmanaged(Slot, Reference) = .empty;
        try frozen_slots.ensureTotalCapacity(allocator, slots.count());

        for (slots.keys(), slots.values()) |slot, value| {
            if (!value.state.isFrozen()) continue;

            const ref = value.toRef() orelse continue;
            frozen_slots.putAssumeCapacity(
                slot,
                ref,
            );
        }
        return frozen_slots;
    }

    pub fn parents(
        self: *SlotTracker,
        allocator: Allocator,
        slot: Slot,
    ) Allocator.Error![]const Slot {
        var slots_lg = self.slots.read();
        defer slots_lg.unlock();
        const slots = slots_lg.get();

        var parents_list = std.ArrayListUnmanaged(Slot).empty;
        errdefer parents_list.deinit(allocator);

        // Parent list count cannot be more than the self.slots count.
        try parents_list.ensureTotalCapacity(allocator, slots.count());

        var current_slot = slot;
        while (slots.get(current_slot)) |current| {
            const parent_slot = current.constants.parent_slot;
            parents_list.appendAssumeCapacity(parent_slot);

            // Stop if we've reached the genesis.
            if (parent_slot == current_slot) break;

            current_slot = parent_slot;
        }

        return try parents_list.toOwnedSlice(allocator);
    }

    /// Analogous to [prune_non_rooted](https://github.com/anza-xyz/agave/blob/441258229dfed75e45be8f99c77865f18886d4ba/runtime/src/bank_forks.rs#L591)
    //  TODO Revisit: Currently this removes all slots less than the rooted slot.
    // In Agave, only the slots not in the root path are removed.
    pub fn pruneNonRooted(
        self: *SlotTracker,
        maybe_thread_pool: ?*ThreadPool,
    ) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "SlotTracker.pruneNonRooted" });
        defer zone.deinit();

        var slots_lg = self.slots.write();
        defer slots_lg.unlock();
        const slots = slots_lg.mut();

        defer tracy.plot(u32, "slots tracked", @intCast(slots.count()));

        var destroy_batch = ThreadPool.Batch{};
        defer if (maybe_thread_pool) |thread_pool| {
            self.wg.startMany(destroy_batch.len);
            thread_pool.schedule(destroy_batch);
        };

        var slice = slots.entries.slice();
        var index: usize = 0;
        const root = self.root.load(.monotonic);
        while (index < slice.len) {
            if (slice.items(.key)[index] < root) {
                const element = slice.items(.value)[index];
                slots.swapRemoveAt(index);
                slice = slots.entries.slice();

                // Destroy element inline, or destroy in ThreadPool if provided.
                if (maybe_thread_pool) |_| {
                    element.pruned_wg = self.wg;
                    destroy_batch.push(.from(&element.destroy_task));
                } else {
                    element.releaseRef();
                }
            } else {
                index += 1;
            }
        }
    }
};

/// Tracks forks for the purpose of optimistically rooting slots in the absence
/// of consensus.
pub const SlotTree = struct {
    root: *Node,
    leaves: List(*Node),

    const List = std.ArrayListUnmanaged;
    const min_age = 32;

    /// Returns the highest slot among all fork tips (leaves).
    /// In bypass mode (without ForkChoice), this represents the "processed" slot.
    pub fn tip(self: *const SlotTree) Slot {
        var max_slot: Slot = self.root.slot;
        for (self.leaves.items) |leaf| {
            max_slot = @max(max_slot, leaf.slot);
        }
        return max_slot;
    }

    pub fn deinit(const_self: SlotTree, allocator: Allocator) void {
        var self = const_self;
        self.root.destroyRecursivelyDownstream(allocator);
        self.leaves.deinit(allocator);
    }

    pub fn init(allocator: Allocator, root: Slot) Allocator.Error!SlotTree {
        const root_node = try allocator.create(Node);
        errdefer allocator.destroy(root_node);
        root_node.* = .{
            .slot = root,
            .parent = null,
            .next = .empty,
        };

        var leaves = List(*Node).empty;
        try leaves.append(allocator, root_node);

        return .{
            .root = root_node,
            .leaves = leaves,
        };
    }

    /// record a new slot
    pub fn record(self: *SlotTree, allocator: Allocator, slot: Slot, parent: Slot) !void {
        const node = try allocator.create(Node);
        node.* = .{ .slot = slot, .parent = null, .next = .{} };

        // check leaves first, it's probably there
        for (self.leaves.items) |*leaf_ptr_ptr| {
            const leaf = leaf_ptr_ptr.*;
            if (leaf.slot == parent) {
                node.parent = leaf;
                try leaf.next.append(allocator, node);
                leaf_ptr_ptr.* = node;
                break;
            }
        } else {
            // couldn't find the parent in leaves, so this slot must be creating
            // a new fork (or it's redundnant TODO)
            try self.leaves.append(allocator, node);
            try self.root.append(allocator, node, parent);
        }
    }

    /// Find and set a new root by pruning stale forks and choosing a
    /// sufficiently old common ancestor of the remaining forks.
    ///
    /// Returns the new root.
    ///
    /// 1. look through the fork leaf nodes and identify if there is any gap of
    ///    at least 32 slots between leaves. prune any forks that are older than
    ///    that gap.
    ///
    ///    For example, if you have three forks, with the forks ending at slots
    ///    10, 30, 40, 80, 100, and 120, then there is only one qualifying gap:
    ///    the gap between 40 and 80. The forks ending at 10, 30, and 40 will be
    ///    pruned, the others will be kept.
    ///
    /// 2. set the "root" slot to be the greatest common ancestor of all
    ///    remaining forks that is at least 32 blocks (not slots) older than the
    ///    leaf of the oldest fork that we are keeping after pruning.
    pub fn reRoot(self: *SlotTree, allocator: Allocator) ?Slot {
        const starting_root = self.root.slot;

        std.mem.sort(
            *Node,
            self.leaves.items,
            {},
            struct {
                fn lessThanFn(_: void, lhs: *Node, rhs: *Node) bool {
                    return lhs.slot > rhs.slot; // descending
                }
            }.lessThanFn,
        );

        // prune old forks
        var last_leaf: Slot = 0;
        for (self.leaves.items, 0..) |leaf_to_check, i| {
            if (last_leaf -| leaf_to_check.slot > min_age) {
                for (self.leaves.items[i..]) |leaf_to_prune| {
                    std.debug.assert(leaf_to_prune.pruneUpstreamToFork(allocator));
                }
                self.leaves.shrinkRetainingCapacity(i);
                break;
            }
            last_leaf = leaf_to_check.slot;
        }

        // find greatest common ancestor and oldest fork leaf
        var maybe_common_ancestor: ?*Node = null;
        var oldest_fork_leaf: usize = std.math.maxInt(usize);
        for (self.leaves.items) |leaf| {
            var node = leaf;
            oldest_fork_leaf = @min(oldest_fork_leaf, node.slot);
            while (node.parent) |parent| : (node = parent) {
                if (parent.next.items.len > 1 and
                    (maybe_common_ancestor == null or parent.slot < maybe_common_ancestor.?.slot))
                {
                    maybe_common_ancestor = parent;
                    break;
                }
            }
        }
        var root_candidate = if (maybe_common_ancestor) |ca| ca else blk: {
            // we couldn't find any nodes that branch out, which means there
            // must be only one leaf.
            std.debug.assert(self.leaves.items.len == 1);
            // in that case, we can just use the leaf itself as the root
            // candidate, because in the next step, we'll push it back by 32
            // slots to find a proper root.
            break :blk self.leaves.items[0];
        };

        // look back min_age blocks behind each fork leaf to ensure its block height
        // is at least min_age greater than the common ancestor that will become the
        // root.
        for (self.leaves.items) |leaf| {
            var node = leaf;
            var found_old_root_candidate = false;
            for (0..min_age) |_| {
                if (node.slot == root_candidate.slot) found_old_root_candidate = true;
                node = node.parent orelse break;
            }
            if (node.slot < root_candidate.slot) {
                std.debug.assert(found_old_root_candidate); // must be a common ancestor
                root_candidate = node;
            }
        }

        // we chose the new root. delete all prior slots and set the new root.
        var maybe_parent = root_candidate.parent;
        while (maybe_parent) |node_to_destroy| {
            std.debug.assert(node_to_destroy.next.items.len == 1); // older forks were pruned
            maybe_parent = node_to_destroy.parent;
            node_to_destroy.destroy(allocator);
        }
        self.root = root_candidate;
        self.root.parent = null;

        return if (self.root.slot != starting_root) self.root.slot else null;
    }

    const Node = struct {
        slot: Slot,
        parent: ?*Node,
        next: List(*Node),

        // destroy this node and all downstream nodes
        fn destroyRecursivelyDownstream(self: *Node, allocator: Allocator) void {
            for (self.next.items) |next| next.destroyRecursivelyDownstream(allocator);
            self.next.deinit(allocator);
            allocator.destroy(self);
        }

        // destroy this node only
        fn destroy(self: *Node, allocator: Allocator) void {
            self.next.deinit(allocator);
            allocator.destroy(self);
        }

        fn append(
            self: *Node,
            allocator: Allocator,
            node: *Node,
            parent: Slot,
        ) error{ OutOfMemory, ParentNotFound }!void {
            const parent_node = self.find(parent) orelse return error.ParentNotFound;
            node.parent = parent_node;
            try parent_node.next.append(allocator, node);
        }

        fn find(self: *Node, slot: Slot) ?*Node {
            if (self.slot == slot) return self;
            for (self.next.items) |next| {
                if (next.find(slot)) |tree| {
                    return tree;
                }
            }
            return null;
        }

        /// if this is a leaf node, remove it from the parent, and apply the
        /// same logic recursively.
        ///
        /// do not call this function unless there are other competing forks.
        ///
        /// returns whether this node was a leaf, and thus pruned and deinitted
        fn pruneUpstreamToFork(self: *Node, allocator: Allocator) bool {
            if (self.next.items.len != 0) return false;

            // must not be null since this function is only called when there
            // are competing forks.
            const parent = self.parent.?;

            const siblings = parent.next.items;
            std.debug.assert(siblings.len > 0);

            const index_in_parent = for (siblings, 0..) |sibling, i| {
                if (sibling == self) break i;
            } else unreachable;

            const removed = parent.next.swapRemove(index_in_parent); // remove self from parent
            std.debug.assert(self == removed);
            self.destroy(allocator); // deinit self
            _ = parent.pruneUpstreamToFork(allocator); // prune parent from its parent, and so on

            return true;
        }
    };
};

fn testDummySlotConstants(slot: Slot) SlotConstants {
    return .{
        .parent_slot = slot - 1,
        .parent_hash = .ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = 0,
        .collector_id = .ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = .DEFAULT,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .inflation = .DEFAULT,
        .rent_collector = .DEFAULT,
    };
}

test "SlotTracker.prune removes all slots less than root" {
    const allocator = std.testing.allocator;
    const root_slot: Slot = 4;

    var pool = ThreadPool.init(.{ .max_threads = 1 });
    defer {
        pool.shutdown();
        pool.deinit();
    }

    for ([_]?*ThreadPool{ null, &pool }) |maybe_thread_pool| {
        var tracker: SlotTracker = try .init(allocator, root_slot, .{
            .constants = testDummySlotConstants(root_slot),
            .state = .GENESIS,
            .allocator = allocator,
        });
        defer tracker.deinit(allocator);

        // Add slots 1, 2, 3, 4, 5
        for (1..6) |slot| {
            const gop = try tracker.getOrPut(allocator, slot, .{
                .constants = testDummySlotConstants(slot),
                .state = .GENESIS,
                .allocator = allocator,
            });
            gop.reference.release();
            if (gop.found_existing) std.debug.assert(slot == root_slot);
        }

        // Prune slots less than root (4)
        tracker.pruneNonRooted(maybe_thread_pool);

        // Only slots 4 and 5 should remain
        try std.testing.expect(tracker.contains(4));
        try std.testing.expect(tracker.contains(5));
        try std.testing.expect(!tracker.contains(1));
        try std.testing.expect(!tracker.contains(2));
        try std.testing.expect(!tracker.contains(3));

        try std.testing.expectEqual(0, tracker.getSlotForCommitment(Commitment.processed));
        try std.testing.expectEqual(0, tracker.getSlotForCommitment(Commitment.confirmed));
        try std.testing.expectEqual(4, tracker.getSlotForCommitment(Commitment.finalized));
    }
}

test "SlotTree: if no forks, root follows 32 behind latest" {
    const allocator = std.testing.allocator;
    var tree = try SlotTree.init(allocator, 0);
    defer tree.deinit(allocator);

    try expectSlotTree(&tree, 0, &.{0});
    try std.testing.expectEqual(null, tree.reRoot(allocator));
    try expectSlotTree(&tree, 0, &.{0});

    for (1..33) |slot| {
        try tree.record(allocator, slot, slot -| 1);
        try expectSlotTree(&tree, 0, &.{slot});
        try std.testing.expectEqual(null, tree.reRoot(allocator));
        try expectSlotTree(&tree, 0, &.{slot});
    }

    for (33..10_000) |slot| {
        try tree.record(allocator, slot, slot -| 1);
        try expectSlotTree(&tree, slot -| 33, &.{slot});
        try std.testing.expectEqual(slot -| 32, tree.reRoot(allocator));
        try expectSlotTree(&tree, slot -| 32, &.{slot});
    }
}

test "SlotTree: 4 forks with large gap roots properly" {
    const allocator = std.testing.allocator;
    var tree = try SlotTree.init(allocator, 0);
    defer tree.deinit(allocator);

    // start:
    //
    //        0
    //       /|\
    //      / | \
    //     /  |  \
    //    1  11   21
    //    2  12   22
    //   ..  ..   ..
    //   10  20   30
    //            31
    //            ..
    //            48
    //           /  \
    //         49    61
    //         50    62
    //         ..    ..
    //         60    70

    // we start with four leaves and the root is 0. after reRooting, the forks
    // ending in 10 and 20 should be pruned, and the new root should be slot 26,
    // since that's a block height of 32 blocks away from slot 70.

    // end:
    //
    //     26
    //     27
    //     ..
    //     48
    //    /  \
    //  49    61
    //  50    62
    //  ..    ..
    //  60    70

    for (1..11) |i| try tree.record(allocator, i, i - 1);
    try tree.record(allocator, 11, 0);
    for (12..21) |i| try tree.record(allocator, i, i - 1);
    try tree.record(allocator, 21, 0);
    for (22..61) |i| try tree.record(allocator, i, i - 1);
    try tree.record(allocator, 61, 48);
    for (62..71) |i| try tree.record(allocator, i, i - 1);

    try expectSlotTree(&tree, 0, &.{ 10, 20, 60, 70 });

    try std.testing.expectEqual(26, tree.reRoot(allocator).?);

    try expectSlotTree(&tree, 26, &.{ 60, 70 });
}

fn expectSlotTree(tree: *const SlotTree, root: Slot, leaves: []const Slot) !void {
    try std.testing.expectEqual(root, tree.root.slot);
    try std.testing.expectEqual(leaves.len, tree.leaves.items.len);

    var buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    var leaves_map = std.AutoHashMapUnmanaged(Slot, void).empty;
    defer leaves_map.deinit(fba.allocator());
    for (tree.leaves.items) |leaf| try leaves_map.put(fba.allocator(), leaf.slot, {});

    for (leaves) |slot| try std.testing.expect(leaves_map.contains(slot));
}
