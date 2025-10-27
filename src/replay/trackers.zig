const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const EpochConstants = sig.core.EpochConstants;
const EpochSchedule = sig.core.EpochSchedule;
const Slot = sig.core.Slot;
const SlotConstants = sig.core.SlotConstants;
const SlotState = sig.core.SlotState;

/// Central registry that tracks high-level info about slots and how they fork.
///
/// This is a lean version of `BankForks` from agave, focused on storing the
/// minimal information about slots to serve its core focus, rather than the
/// kitchen-sink style approach of storing everything under the sun.
///
/// [BankForks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank_forks.rs#L75)
///
/// This struct is *not* thread safe, and the lifetimes of the returned pointers
/// will end as soon as the items are removed.
pub const SlotTracker = struct {
    slots: std.AutoArrayHashMapUnmanaged(Slot, *Element),
    root: Slot,

    pub const Element = struct {
        constants: SlotConstants,
        state: SlotState,

        fn toRef(self: *Element) Reference {
            return .{
                .constants = &self.constants,
                .state = &self.state,
            };
        }
    };

    pub const Reference = struct {
        constants: *const SlotConstants,
        state: *SlotState,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        root_slot: Slot,
        /// ownership is transferred to this function
        slot_init: Element,
    ) std.mem.Allocator.Error!SlotTracker {
        var element = slot_init;
        var self: SlotTracker = .{
            .root = root_slot,
            .slots = .empty,
        };
        errdefer {
            self.deinit(allocator);
            element.constants.deinit(allocator);
            element.state.deinit(allocator);
        }
        try self.put(allocator, root_slot, element);
        tracy.plot(u32, "slots tracked", @intCast(self.slots.count()));

        return self;
    }

    pub fn deinit(self: SlotTracker, allocator: Allocator) void {
        var slots = self.slots;
        for (slots.values()) |element| {
            element.constants.deinit(allocator);
            element.state.deinit(allocator);
            allocator.destroy(element);
        }
        slots.deinit(allocator);
    }

    pub fn put(
        self: *SlotTracker,
        allocator: Allocator,
        slot: Slot,
        slot_init: Element,
    ) Allocator.Error!void {
        defer tracy.plot(u32, "slots tracked", @intCast(self.slots.count()));

        try self.slots.ensureUnusedCapacity(allocator, 1);
        const elem = try allocator.create(Element);
        elem.* = slot_init;
        self.slots.putAssumeCapacity(slot, elem);
    }

    pub fn get(self: *const SlotTracker, slot: Slot) ?Reference {
        const elem = self.slots.get(slot) orelse return null;
        return elem.toRef();
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
        defer tracy.plot(u32, "slots tracked", @intCast(self.slots.count()));

        if (self.get(slot)) |existing| return .{
            .found_existing = true,
            .reference = existing,
        };
        try self.slots.ensureUnusedCapacity(allocator, 1);
        const elem = try allocator.create(Element);
        elem.* = slot_init;
        self.slots.putAssumeCapacityNoClobber(slot, elem);
        return .{
            .found_existing = false,
            .reference = elem.toRef(),
        };
    }

    pub fn getRoot(self: *const SlotTracker) Reference {
        return self.get(self.root).?; // root slot's bank must exist
    }

    pub fn contains(self: *const SlotTracker, slot: Slot) bool {
        return self.slots.contains(slot);
    }

    pub fn activeSlots(
        self: *const SlotTracker,
        allocator: Allocator,
    ) Allocator.Error![]const Slot {
        var list = try std.ArrayListUnmanaged(Slot).initCapacity(allocator, self.slots.count());
        for (self.slots.keys(), self.slots.values()) |slot, value| {
            if (!value.state.isFrozen()) {
                list.appendAssumeCapacity(slot);
            }
        }
        return try list.toOwnedSlice(allocator);
    }

    pub fn frozenSlots(
        self: *const SlotTracker,
        allocator: Allocator,
    ) Allocator.Error!std.AutoArrayHashMapUnmanaged(Slot, Reference) {
        var frozen_slots: std.AutoArrayHashMapUnmanaged(Slot, Reference) = .empty;
        try frozen_slots.ensureTotalCapacity(allocator, self.slots.count());

        for (self.slots.keys(), self.slots.values()) |slot, value| {
            if (!value.state.isFrozen()) continue;

            frozen_slots.putAssumeCapacity(
                slot,
                .{ .constants = &value.constants, .state = &value.state },
            );
        }
        return frozen_slots;
    }

    pub fn parents(
        self: *const SlotTracker,
        allocator: Allocator,
        slot: Slot,
    ) Allocator.Error![]const Slot {
        var parents_list = std.ArrayListUnmanaged(Slot).empty;
        errdefer parents_list.deinit(allocator);

        // Parent list count cannot be more than the self.slots count.
        try parents_list.ensureTotalCapacity(allocator, self.slots.count());

        var current_slot = slot;
        while (self.slots.get(current_slot)) |current| {
            const parent_slot = current.constants.parent_slot;
            parents_list.appendAssumeCapacity(parent_slot);

            current_slot = parent_slot;
        }

        return try parents_list.toOwnedSlice(allocator);
    }

    /// Analogous to [prune_non_rooted](https://github.com/anza-xyz/agave/blob/441258229dfed75e45be8f99c77865f18886d4ba/runtime/src/bank_forks.rs#L591)
    //  TODO Revisit: Currently this removes all slots less than the rooted slot.
    // In Agave, only the slots not in the root path are removed.
    pub fn pruneNonRooted(self: *SlotTracker, allocator: Allocator) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "SlotTracker.pruneNonRooted" });
        defer zone.deinit();

        defer tracy.plot(u32, "slots tracked", @intCast(self.slots.count()));

        var slice = self.slots.entries.slice();
        var index: usize = 0;
        while (index < slice.len) {
            if (slice.items(.key)[index] < self.root) {
                const element = slice.items(.value)[index];
                element.state.deinit(allocator);
                element.constants.deinit(allocator);
                allocator.destroy(element);
                self.slots.swapRemoveAt(index);
                slice = self.slots.entries.slice();
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

pub const EpochTracker = struct {
    epochs: std.AutoArrayHashMapUnmanaged(Epoch, EpochConstants) = .empty,
    schedule: EpochSchedule,

    pub fn deinit(self: EpochTracker, allocator: Allocator) void {
        var epochs = self.epochs;
        for (epochs.values()) |ec| ec.deinit(allocator);
        epochs.deinit(allocator);
    }

    pub fn get(self: *const EpochTracker, epoch: Epoch) ?EpochConstants {
        return self.epochs.get(epoch);
    }

    pub fn getForSlot(self: *const EpochTracker, slot: Slot) ?EpochConstants {
        return self.epochs.get(self.schedule.getEpoch(slot));
    }

    /// lifetime ends as soon as the map is modified
    pub fn getPtrForSlot(self: *const EpochTracker, slot: Slot) ?*const EpochConstants {
        return self.epochs.getPtr(self.schedule.getEpoch(slot));
    }

    pub fn put(
        self: *EpochTracker,
        allocator: Allocator,
        epoch: Epoch,
        epoch_constants: EpochConstants,
    ) Allocator.Error!void {
        try self.epochs.ensureUnusedCapacity(allocator, 1);
        self.epochs.putAssumeCapacity(epoch, epoch_constants);
    }
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
        .epoch_reward_status = .inactive,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .EMPTY,
        .inflation = .DEFAULT,
    };
}

test "SlotTracker.prune removes all slots less than root" {
    const allocator = std.testing.allocator;
    const root_slot: Slot = 4;
    var tracker: SlotTracker = try .init(allocator, root_slot, .{
        .constants = testDummySlotConstants(root_slot),
        .state = .GENESIS,
    });
    defer tracker.deinit(allocator);

    // Add slots 1, 2, 3, 4, 5
    for (1..6) |slot| {
        const gop = try tracker.getOrPut(allocator, slot, .{
            .constants = testDummySlotConstants(slot),
            .state = .GENESIS,
        });
        if (gop.found_existing) std.debug.assert(slot == root_slot);
    }

    // Prune slots less than root (4)
    tracker.pruneNonRooted(allocator);

    // Only slots 4 and 5 should remain
    try std.testing.expect(tracker.contains(4));
    try std.testing.expect(tracker.contains(5));
    try std.testing.expect(!tracker.contains(1));
    try std.testing.expect(!tracker.contains(2));
    try std.testing.expect(!tracker.contains(3));
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
