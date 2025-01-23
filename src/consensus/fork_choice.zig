const std = @import("std");
const sig = @import("../sig.zig");

const AutoHashMap = std.AutoHashMap;
const Instant = sig.time.Instant;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SortedMap = sig.utils.collections.SortedMap;
const Slot = sig.core.Slot;

const MAX_ROOT_PRINT_SECONDS: u64 = 60 * 60; // 1 hour

const SlotHashKey = struct {
    slot: Slot,
    hash: Hash,

    pub fn order(a: SlotHashKey, b: SlotHashKey) std.math.Order {
        if (a.slot == b.slot and a.hash.order(&b.hash) == .eq) {
            return .eq;
        } else if (a.slot < b.slot or a.slot == b.slot and (a.hash.order(&b.hash) == .lt)) {
            return .lt;
        } else if (a.slot > b.slot or a.slot == b.slot and (a.hash.order(&b.hash) == .gt)) {
            return .gt;
        } else {
            unreachable;
        }
    }
};

pub const ForkWeight = u64;

/// Analogous to [ForkInfo](https://github.com/anza-xyz/agave/blob/e7301b2a29d14df19c3496579cf8e271b493b3c6/core/src/consensus/heaviest_subtree_fork_choice.rs#L92)
pub const ForkInfo = struct {
    // Amount of stake that has voted for exactly this slot
    stake_voted_at: ForkWeight,
    // Amount of stake that has voted for this slot and the subtree
    // rooted at this slot
    stake_voted_subtree: ForkWeight,
    // Tree height for the subtree rooted at this slot
    height: usize,
    // Best slot in the subtree rooted at this slot, does not
    // have to be a direct child in `children`. This is the slot whose subtree
    // is the heaviest.
    best_slot: SlotHashKey,
    // Deepest slot in the subtree rooted at this slot. This is the slot
    // with the greatest tree height. This metric does not discriminate invalid
    // forks, unlike `best_slot`
    deepest_slot: SlotHashKey,
    parent: ?SlotHashKey,
    children: SortedMap(SlotHashKey, void),
    // The latest ancestor of this node that has been marked invalid. If the slot
    // itself is a duplicate, this is set to the slot itself.
    latest_invalid_ancestor: ?Slot,
    // Set to true if this slot or a child node was duplicate confirmed.
    is_duplicate_confirmed: bool,

    /// Returns if the fork rooted at this node is included in fork choice
    fn isCandidate(self: ForkInfo) bool {
        return self.latest_invalid_ancestor == null;
    }
};

/// Analogous to [HeaviestSubtreeForkChoice](https://github.com/anza-xyz/agave/blob/e7301b2a29d14df19c3496579cf8e271b493b3c6/core/src/consensus/heaviest_subtree_fork_choice.rs#L187)
pub const HeaviestSubtreeForkChoice = struct {
    allocator: std.mem.Allocator,
    fork_infos: AutoHashMap(SlotHashKey, ForkInfo),
    latest_votes: AutoHashMap(Pubkey, SlotHashKey),
    tree_root: SlotHashKey,
    last_root_time: Instant,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, tree_root: SlotHashKey) !Self {
        var heaviest_subtree_fork_choice = HeaviestSubtreeForkChoice{
            .allocator = allocator,
            .fork_infos = AutoHashMap(SlotHashKey, ForkInfo).init(allocator),
            .latest_votes = AutoHashMap(Pubkey, SlotHashKey).init(allocator),
            .tree_root = tree_root,
            .last_root_time = Instant.now(),
        };

        _ = try heaviest_subtree_fork_choice.addNewLeafSlot(tree_root, null);
        return heaviest_subtree_fork_choice;
    }

    pub fn deinit(self: *Self) void {
        self.fork_infos.deinit();
        self.latest_votes.deinit();
    }

    pub fn addNewLeafSlot(
        self: *Self,
        slot_hash_key: SlotHashKey,
        maybe_parent: ?SlotHashKey,
    ) !void {
        if (self.last_root_time.elapsed().asSecs() > MAX_ROOT_PRINT_SECONDS) {
            // TODO implement self.print_state();
        }

        if (self.fork_infos.contains(slot_hash_key)) {
            // Comment from Agave: Can potentially happen if we repair the same version of the duplicate slot, after
            // dumping the original version
            // TODO: What does repair the same version of the duplicate slot, after dumping the original version mean
            return;
        }

        const parent_latest_invalid_ancestor =
            if (maybe_parent) |p| self.latest_invalid_ancestor(p) else null;

        if (self.fork_infos.getPtr(slot_hash_key)) |fork_info| {
            // Modify existing entry
            // TODO:
            // - Why is it okay to modify just the parent and not other fields modified in the else branch
            // - Is this branch necessary given the self.fork_infos.contains(&slot_hash_key) return null check above?
            fork_info.parent = maybe_parent;
        } else {
            // Insert new entry
            const new_fork_info = ForkInfo{
                .stake_voted_at = 0,
                .stake_voted_subtree = 0,
                .height = 1,
                // The `best_slot` and `deepest_slot` of a leaf is itself
                .best_slot = slot_hash_key,
                .deepest_slot = slot_hash_key,
                .children = SortedMap(SlotHashKey, void).init(self.allocator),
                .parent = maybe_parent,
                .latest_invalid_ancestor = parent_latest_invalid_ancestor,
                // If the parent is none, then this is the root, which implies this must
                // have reached the duplicate confirmed threshold
                .is_duplicate_confirmed = (maybe_parent == null),
            };

            _ = try self.fork_infos.put(slot_hash_key, new_fork_info);
        }

        // If no parent is given then we are done.
        const parent = if (maybe_parent) |parent| parent else return;

        if (self.fork_infos.getPtr(parent)) |parent_fork_info| {
            try parent_fork_info.children.put(slot_hash_key, {});
        } else {
            // If parent is given then parent's info must
            // already exist by time child is being added.
            return error.MissingParent;
        }

        self.last_root_time = Instant.now();
    }

    pub fn containsBlock(self: *const Self, key: *const SlotHashKey) bool {
        return self.fork_infos.contains(key.*);
    }

    pub fn latest_invalid_ancestor(self: *const Self, slot_hash_key: SlotHashKey) ?Slot {
        if (self.fork_infos.get(slot_hash_key)) |fork_info| {
            return fork_info.latest_invalid_ancestor;
        }
        return null;
    }

    pub fn bestOverallSlot(self: *const Self) ?SlotHashKey {
        return self.bestSlot(self.tree_root);
    }

    pub fn bestSlot(self: *const Self, slot_hash_key: SlotHashKey) ?SlotHashKey {
        if (self.fork_infos.get(slot_hash_key)) |fork_info| {
            return fork_info.best_slot;
        }
        return null;
    }

    pub fn stakeVotedSubtree(self: *const Self, key: *const SlotHashKey) ?u64 {
        if (self.fork_infos.get(key.*)) |fork_info| {
            return fork_info.stake_voted_subtree;
        }
        return null;
    }

    pub fn getHeight(self: *const Self, key: *const SlotHashKey) ?usize {
        if (self.fork_infos.get(key.*)) |fork_info| {
            return fork_info.height;
        }
        return null;
    }

    pub fn setTreeRoot(self: *Self, new_root: *const SlotHashKey) !void {
        // Remove everything reachable from old root but not new root
        var remove_set = try self.subtreeDiff(&self.tree_root, new_root);
        defer remove_set.deinit();

        for (remove_set.keys()) |node_key| {
            // "Slots reachable from old root must exist in tree"
            // TODO: Revisit. Panic if key is not found?.
            _ = self.fork_infos.remove(node_key);
        }

        const root_fork_info = self.fork_infos.getPtr(new_root.*) orelse return error.NewRootNotFound;

        root_fork_info.parent = null;
        self.tree_root = new_root.*;
        self.last_root_time = Instant.now();
    }

    /// Updates the fork tree's metadata for ancestors when a new slot (slot_hash_key) is added.
    /// Specifically, it propagates updates about the best slot and deepest slot upwards through
    /// the ancestors of the new slot.
    fn propagateNewLeaf(
        self: HeaviestSubtreeForkChoice,
        slot_hash_key: *SlotHashKey,
        parent_slot_hash_key: *SlotHashKey,
    ) void {
        // Returns an error as parent must exist in self.fork_infos after its child leaf was created
        const parent_best_slot_hash_key =
            self.fork_infos.get(&parent_slot_hash_key) orelse return error.MissingParent;
        // If this new leaf is the direct parent's best child, then propagate it up the tree
        if (self.isBestChild(slot_hash_key)) {
            const maybe_ancestor: ?*SlotHashKey = parent_slot_hash_key;
            while (true) {
                if (maybe_ancestor == null) {
                    break;
                }
                // Saftey: maybe_ancestor cannot be null due to the if check above.
                var ancestor = maybe_ancestor.?;
                if (self.fork_infos.getPtr(&ancestor)) |ancestor_fork_info| {
                    // Do the update to the new best slot.
                    if (ancestor_fork_info.best_slot == *parent_best_slot_hash_key) {
                        ancestor_fork_info.*.best_slot = *slot_hash_key;
                        // Walk up the tree.
                        ancestor = ancestor_fork_info.parent;
                    } else {
                        break;
                    }
                } else {
                    // If ancestor is given then ancestor's info must already exist.
                    return error.MissingParent;
                }
            }
        }
        // Propagate the deepest slot up the tree.
        const maybe_ancestor: ?*SlotHashKey = parent_slot_hash_key;
        var current_child = slot_hash_key.*;
        var current_height = 1;
        while (true) {
            if (maybe_ancestor == null) {
                break;
            }
            if (!self.isDeepestChild(&current_child)) {
                break;
            }
            // Saftey: maybe_ancestor cannot be null due to the if check above.
            var ancestor = maybe_ancestor.?;
            if (self.fork_infos.getPtr(&ancestor)) |ancestor_fork_info| {
                ancestor_fork_info.deepest_slot = slot_hash_key.*;
                ancestor_fork_info.height = current_height + 1;
                current_child = ancestor;
                current_height = ancestor_fork_info.height;
                ancestor = ancestor_fork_info.parent;
            } else {
                // If ancestor is given then ancestor's info must already exist.
                return error.MissingParent;
            }
        }
    }

    /// Returns true if the given `maybe_best_child` is the heaviest among the children
    /// of the parent. Breaks ties by slot # (lower is heavier).
    fn isBestChild(self: *const Self, maybe_best_child: *const SlotHashKey) !bool {
        const maybe_best_child_weight =
            self.stakeVotedSubtree(maybe_best_child) orelse return false;
        const maybe_parent = self.getParent(maybe_best_child);

        // If there's no parent, this must be the root
        if (maybe_parent == null) {
            return true;
        }
        // Saftety: maybe_parent cannot be null due to the if check above.
        const parent = maybe_parent.?;
        const children = self.getChildren(parent) orelse return false;

        for (children.items) |child| {
            // child must exist in `self.fork_infos`
            const child_weight = self.stakeVotedSubtree(&child) orelse return error.MissingChild;

            // Don't count children currently marked as invalid
            // child must exist in tree
            if (!(self.isCandidate(child) orelse return error.MissingChild)) {
                continue;
            }

            if (child_weight > maybe_best_child_weight or
                (maybe_best_child_weight == child_weight and child.lessThan(maybe_best_child)))
            {
                return false;
            }
        }

        return true;
    }

    fn isDeepestChild(self: *Self, deepest_child: *const SlotHashKey) bool {
        const maybe_deepest_child_weight =
            self.stakeVotedSubtree(deepest_child) orelse return false;
        const maybe_deepest_child_height = self.height(deepest_child) orelse return false;
        const maybe_parent = self.getParent(deepest_child);

        // If there's no parent, this must be the root
        if (maybe_parent == null) {
            return true;
        }
        // Saftety: maybe_parent cannot be null due to the if check above.
        const parent = maybe_parent.?;
        const children = self.getChildren(&parent) orelse return false;

        for (children.items) |child| {
            const child_height = self.getHeight(&child) orelse return false;
            const child_weight = self.stakeVotedSubtree(&child) orelse return false;

            const height_cmp = std.math.cmp(child_height, maybe_deepest_child_height);
            const weight_cmp = std.math.cmp(child_weight, maybe_deepest_child_weight);
            const slot_cmp = std.math.cmp(child.slot, deepest_child.slot);

            switch (height_cmp) {
                .Greater => return false,
                .Equal => switch (weight_cmp) {
                    .Greater => return false,
                    .Equal => switch (slot_cmp) {
                        .Less => return false,
                        else => {},
                    },
                    else => {},
                },
                else => {},
            }
        }

        return true;
    }

    fn getParent(self: *const Self, slot_hash_key: *const SlotHashKey) ?SlotHashKey {
        if (self.fork_infos.get(slot_hash_key.*)) |fork_info| {
            return fork_info.parent;
        }
        return null;
    }

    // TODO: Change this to return an iterator.
    fn getChildren(self: *Self, slot_hash_key: *const SlotHashKey) ?SortedMap(SlotHashKey, void) {
        const fork_info = self.fork_infos.get(slot_hash_key.*) orelse return null;
        return fork_info.children;
    }

    fn isCandidate(self: *Self, slot_hash_key: *SlotHashKey) ?bool {
        const fork_info = self.fork_infos.get(slot_hash_key) orelse return null;
        return fork_info.isCandidate();
    }

    fn subtreeDiff(
        self: *Self,
        root1: *const SlotHashKey,
        root2: *const SlotHashKey,
    ) !SortedMap(SlotHashKey, void) {
        if (self.containsBlock(root1)) {
            return SortedMap(SlotHashKey, void).init(self.allocator);
        }
        var pending_keys = std.ArrayList(SlotHashKey).init(self.allocator);
        defer pending_keys.deinit();

        try pending_keys.append(root1.*);

        var reachable_set = SortedMap(SlotHashKey, void).init(self.allocator);
        defer reachable_set.deinit();

        while (pending_keys.popOrNull()) |current_key| {
            if (current_key.order(root2.*) == .eq) {
                continue;
            }

            var children = self.getChildren(&current_key) orelse return error.MissingChild;
            for (children.keys()) |child| {
                try pending_keys.append(child);
            }
            try reachable_set.put(current_key, {});
        }

        return reachable_set;
    }
};

/// Testing only ensures everything compiles.
/// TODO: Update to assert.
const test_allocator = std.testing.allocator;

test "HeaviestSubtreeForkChoice.init" {
    var fc = try HeaviestSubtreeForkChoice.init(
        test_allocator,
        SlotHashKey{ .slot = 0, .hash = Hash.ZEROES },
    );
    defer fc.deinit();
}

test "HeaviestSubtreeForkChoice.subtreeDiff" {
    var fc = try HeaviestSubtreeForkChoice.init(
        test_allocator,
        SlotHashKey{ .slot = 0, .hash = Hash.ZEROES },
    );
    defer fc.deinit();

    _ = try fc.subtreeDiff(
        &SlotHashKey{ .slot = 0, .hash = Hash.ZEROES },
        &SlotHashKey{ .slot = 0, .hash = Hash.ZEROES },
    );
}

test "HeaviestSubtreeForkChoice.setTreeRoot" {
    var fc = try HeaviestSubtreeForkChoice.init(
        test_allocator,
        SlotHashKey{ .slot = 0, .hash = Hash.ZEROES },
    );
    defer fc.deinit();

    _ = try fc.setTreeRoot(
        &SlotHashKey{ .slot = 0, .hash = Hash.ZEROES },
    );
}
