const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const AutoHashMap = std.AutoHashMap;
const Instant = sig.time.Instant;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SortedMap = sig.utils.collections.SortedMap;
const SlotAndHash = sig.core.hash.SlotAndHash;
const Slot = sig.core.Slot;

const MAX_ROOT_PRINT_SECONDS: u64 = 60 * 60; // 1 hour

const UpdateLabel = enum {
    Aggregate,
    MarkValid,
    MarkInvalid,
};

const UpdateOperation = union(enum) {
    Add: u64,
    MarkValid: Slot,
    MarkInvalid: Slot,
    Subtract: u64,
    Aggregate,
};

const SlotHashKeyLabel = struct {
    slot_hash_key: SlotAndHash,
    label: UpdateLabel,
    pub fn order(a: SlotHashKeyLabel, b: SlotHashKeyLabel) std.math.Order {
        return a.slot_hash_key.order(b.slot_hash_key);
    }
};

const UpdateOperations = SortedMap(
    SlotHashKeyLabel,
    UpdateOperation,
);

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
    best_slot: SlotAndHash,
    // Deepest slot in the subtree rooted at this slot. This is the slot
    // with the greatest tree height. This metric does not discriminate invalid
    // forks, unlike `best_slot`
    deepest_slot: SlotAndHash,
    parent: ?SlotAndHash,
    children: SortedMap(SlotAndHash, void),
    // The latest ancestor of this node that has been marked invalid. If the slot
    // itself is a duplicate, this is set to the slot itself.
    latest_invalid_ancestor: ?Slot,
    // Set to true if this slot or a child node was duplicate confirmed.
    is_duplicate_confirmed: bool,

    fn deinit(self: *ForkInfo) void {
        self.children.deinit();
    }

    /// Returns if the fork rooted at this node is included in fork choice
    fn isCandidate(self: *const ForkInfo) bool {
        return self.latest_invalid_ancestor == null;
    }

    fn setDuplicateConfirmed(self: *ForkInfo) void {
        self.is_duplicate_confirmed = true;
        self.latest_invalid_ancestor = null;
    }

    /// Updates the fork info with a newly valid ancestor.
    /// If the latest invalid ancestor is less than or equal to the newly valid ancestor,
    /// it clears the latest invalid ancestor.
    fn updateWithNewlyValidAncestor(
        self: *ForkInfo,
        my_key: *const SlotAndHash,
        newly_valid_ancestor: Slot,
    ) void {
        // Check if there is a latest invalid ancestor
        if (self.latest_invalid_ancestor) |invalid_ancestor| {
            // If the latest invalid ancestor is less than or equal to the newly valid ancestor,
            // clear the latest invalid ancestor
            if (invalid_ancestor <= newly_valid_ancestor) {
                // TODO change to logger.
                std.debug.print(
                    \\ Fork choice for {} clearing latest invalid ancestor  
                    \\ {} because {} was duplicate confirmed
                ,
                    .{ my_key, invalid_ancestor, newly_valid_ancestor },
                );
                self.latest_invalid_ancestor = null;
            }
        }
    }

    /// Updates the fork info with a newly invalid ancestor.
    /// Asserts that the fork is not duplicate confirmed.
    /// If the newly invalid ancestor is greater than the current latest invalid ancestor,
    /// updates the latest invalid ancestor.
    fn updateWithNewlyInvalidAncestor(
        self: *ForkInfo,
        my_key: *const SlotAndHash,
        newly_invalid_ancestor: Slot,
    ) void {
        // Should not be marking a duplicate confirmed slot as invalid
        std.debug.assert(!self.is_duplicate_confirmed);

        // Check if the newly invalid ancestor is greater than the current latest invalid ancestor
        const should_update = if (self.latest_invalid_ancestor) |invalid_ancestor|
            newly_invalid_ancestor > invalid_ancestor
        else
            true;

        // If the condition is met, update the latest invalid ancestor
        if (should_update) {
            // TODO: Switch to logger.
            std.debug.print(
                "Fork choice for {} setting latest invalid ancestor from {?} to {}",
                .{ my_key, self.latest_invalid_ancestor, newly_invalid_ancestor },
            );
            self.latest_invalid_ancestor = newly_invalid_ancestor;
        }
    }
};

/// Analogous to [HeaviestSubtreeForkChoice](https://github.com/anza-xyz/agave/blob/e7301b2a29d14df19c3496579cf8e271b493b3c6/core/src/consensus/heaviest_subtree_fork_choice.rs#L187)
pub const HeaviestSubtreeForkChoice = struct {
    allocator: std.mem.Allocator,
    fork_infos: AutoHashMap(SlotAndHash, ForkInfo),
    latest_votes: AutoHashMap(Pubkey, SlotAndHash),
    tree_root: SlotAndHash,
    last_root_time: Instant,

    pub fn init(allocator: std.mem.Allocator, tree_root: SlotAndHash) !HeaviestSubtreeForkChoice {
        var heaviest_subtree_fork_choice = HeaviestSubtreeForkChoice{
            .allocator = allocator,
            .fork_infos = AutoHashMap(SlotAndHash, ForkInfo).init(allocator),
            .latest_votes = AutoHashMap(Pubkey, SlotAndHash).init(allocator),
            .tree_root = tree_root,
            .last_root_time = Instant.now(),
        };

        _ = try heaviest_subtree_fork_choice.addNewLeafSlot(tree_root, null);
        return heaviest_subtree_fork_choice;
    }

    pub fn initForTest(
        allocator: std.mem.Allocator,
        forks: []const TreeNode,
    ) !HeaviestSubtreeForkChoice {
        if (!builtin.is_test) {
            @panic("initForTest should only be called in test mode");
        }

        const root = forks[0][0]; // Assuming the first element contains the root
        var heaviest_subtree_fork_choice = try HeaviestSubtreeForkChoice.init(allocator, root);

        for (forks) |fork_tuple| {
            const slot_hash = fork_tuple[0];
            if (heaviest_subtree_fork_choice.fork_infos.contains(slot_hash)) {
                continue;
            }
            const parent_slot_hash = fork_tuple[1];
            try heaviest_subtree_fork_choice.addNewLeafSlot(slot_hash, parent_slot_hash);
        }

        return heaviest_subtree_fork_choice;
    }

    pub fn deinit(self: *HeaviestSubtreeForkChoice) void {
        var it = self.fork_infos.iterator();
        while (it.next()) |fork_info| {
            fork_info.value_ptr.deinit();
        }
        self.fork_infos.deinit();
        self.latest_votes.deinit();
    }

    pub fn addNewLeafSlot(
        self: *HeaviestSubtreeForkChoice,
        slot_hash_key: SlotAndHash,
        maybe_parent: ?SlotAndHash,
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
                .children = SortedMap(SlotAndHash, void).init(self.allocator),
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

        try self.propagateNewLeaf(&slot_hash_key, &parent);
        // TODO: Revisit, this was set first in the Agave code.
        self.last_root_time = Instant.now();
    }

    pub fn containsBlock(self: *const HeaviestSubtreeForkChoice, key: *const SlotAndHash) bool {
        return self.fork_infos.contains(key.*);
    }

    pub fn latest_invalid_ancestor(
        self: *const HeaviestSubtreeForkChoice,
        slot_hash_key: SlotAndHash,
    ) ?Slot {
        if (self.fork_infos.get(slot_hash_key)) |fork_info| {
            return fork_info.latest_invalid_ancestor;
        }
        return null;
    }

    pub fn bestOverallSlot(self: *const HeaviestSubtreeForkChoice) ?SlotAndHash {
        return self.bestSlot(self.tree_root);
    }

    pub fn bestSlot(
        self: *const HeaviestSubtreeForkChoice,
        slot_hash_key: SlotAndHash,
    ) ?SlotAndHash {
        if (self.fork_infos.get(slot_hash_key)) |fork_info| {
            return fork_info.best_slot;
        }
        return null;
    }

    pub fn stakeVotedSubtree(
        self: *const HeaviestSubtreeForkChoice,
        key: *const SlotAndHash,
    ) ?u64 {
        if (self.fork_infos.get(key.*)) |fork_info| {
            return fork_info.stake_voted_subtree;
        }
        return null;
    }

    pub fn getHeight(self: *const HeaviestSubtreeForkChoice, key: *const SlotAndHash) ?usize {
        if (self.fork_infos.get(key.*)) |fork_info| {
            return fork_info.height;
        }
        return null;
    }

    pub fn setTreeRoot(self: *HeaviestSubtreeForkChoice, new_root: *const SlotAndHash) !void {
        // Remove everything reachable from old root but not new root
        var remove_set = try self.subtreeDiff(&self.tree_root, new_root);
        defer remove_set.deinit();

        for (remove_set.keys()) |node_key| {
            // "Slots reachable from old root must exist in tree"
            // TODO: Revisit. Panic if key is not found?.
            _ = self.fork_infos.remove(node_key);
        }

        const root_fork_info = self
            .fork_infos.getPtr(new_root.*) orelse return error.NewRootNotFound;

        root_fork_info.parent = null;
        self.tree_root = new_root.*;
        self.last_root_time = Instant.now();
    }

    pub fn markForkInvalidCandidate(
        self: *HeaviestSubtreeForkChoice,
        invalid_slot_hash_key: *const SlotAndHash,
    ) !void {
        // Get mutable reference to fork info
        if (self.fork_infos.getPtr(invalid_slot_hash_key.*)) |_| {
            // Should not be marking duplicate confirmed blocks as invalid candidates
            // TODO: Re-enable
            // std.debug.assert(!fork_info.is_duplicate_confirmed);

            var update_operations = UpdateOperations.init(self.allocator);
            defer update_operations.deinit();

            // Notify all children that a parent was marked as invalid
            var children_hash_keys = try self.subtreeDiff(
                invalid_slot_hash_key,
                &.{ .slot = 0, .hash = Hash.ZEROES },
            );

            for (children_hash_keys.keys()) |child_hash_key| {
                _ = try self.doInsertAggregateOperation(
                    &update_operations,
                    UpdateOperation{ .MarkInvalid = invalid_slot_hash_key.slot },
                    child_hash_key,
                );
            }

            // Aggregate across all ancestors to find new best slots excluding this fork
            try self.insertAggregateOperations(&update_operations, invalid_slot_hash_key.*);
            self.processUpdateOperations(update_operations);
        }
    }

    /// Updates the fork tree's metadata for ancestors when a new slot (slot_hash_key) is added.
    /// Specifically, it propagates updates about the best slot and deepest slot upwards through
    /// the ancestors of the new slot.
    fn propagateNewLeaf(
        self: *HeaviestSubtreeForkChoice,
        slot_hash_key: *const SlotAndHash,
        parent_slot_hash_key: *const SlotAndHash,
    ) !void {
        // Returns an error as parent must exist in self.fork_infos after its child leaf was created
        const parent_best_slot_hash_key =
            self.bestSlot(parent_slot_hash_key.*) orelse return error.MissingParent;
        // If this new leaf is the direct parent's best child, then propagate it up the tree
        if (try self.isBestChild(slot_hash_key)) {
            var maybe_ancestor: ?SlotAndHash = parent_slot_hash_key.*;
            while (true) {
                if (maybe_ancestor == null) {
                    break;
                }
                // Saftey: maybe_ancestor cannot be null due to the if check above.
                if (self.fork_infos.getPtr(maybe_ancestor.?)) |ancestor_fork_info| {
                    // Do the update to the new best slot.
                    if (ancestor_fork_info.*.best_slot.order(parent_best_slot_hash_key) == .eq) {
                        ancestor_fork_info.*.best_slot = slot_hash_key.*;
                        // Walk up the tree.
                        maybe_ancestor = ancestor_fork_info.parent;
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
        var maybe_ancestor: ?SlotAndHash = parent_slot_hash_key.*;
        var current_child = slot_hash_key.*;
        var current_height: usize = 1;
        while (true) {
            if (maybe_ancestor == null) {
                break;
            }
            if (!self.isDeepestChild(&current_child)) {
                break;
            }
            if (self.fork_infos.getPtr(maybe_ancestor.?)) |ancestor_fork_info| {
                ancestor_fork_info.deepest_slot = slot_hash_key.*;
                ancestor_fork_info.height = current_height + 1;
                current_child = maybe_ancestor.?;
                current_height = ancestor_fork_info.height;
                maybe_ancestor = ancestor_fork_info.parent;
            } else {
                // If ancestor is given then ancestor's info must already exist.
                return error.MissingParent;
            }
        }
    }

    /// Returns true if the given `maybe_best_child` is the heaviest among the children
    /// of the parent. Breaks ties by slot # (lower is heavier).
    fn isBestChild(
        self: *const HeaviestSubtreeForkChoice,
        maybe_best_child: *const SlotAndHash,
    ) !bool {
        const maybe_best_child_weight =
            self.stakeVotedSubtree(maybe_best_child) orelse return false;
        const maybe_parent = self.getParent(maybe_best_child);

        // If there's no parent, this must be the root
        if (maybe_parent == null) {
            return true;
        }
        // Saftety: maybe_parent cannot be null due to the if check above.
        const parent = maybe_parent.?;
        var children = self.getChildren(&parent) orelse return false;

        for (children.keys()) |child| {
            // child must exist in `self.fork_infos`
            const child_weight = self.stakeVotedSubtree(&child) orelse return error.MissingChild;

            // Don't count children currently marked as invalid
            // child must exist in tree
            if (!(self.isCandidate(&child) orelse return error.MissingChild)) {
                continue;
            }

            if (child_weight > maybe_best_child_weight or
                (maybe_best_child_weight == child_weight and
                child.order(maybe_best_child.*) == .lt))
            {
                return false;
            }
        }

        return true;
    }

    fn isDeepestChild(self: *HeaviestSubtreeForkChoice, deepest_child: *const SlotAndHash) bool {
        const maybe_deepest_child_weight =
            self.stakeVotedSubtree(deepest_child) orelse return false;
        const maybe_deepest_child_height = self.getHeight(deepest_child) orelse return false;
        const maybe_parent = self.getParent(deepest_child);

        // If there's no parent, this must be the root
        if (maybe_parent == null) {
            return true;
        }
        // Saftety: maybe_parent cannot be null due to the if check above.
        const parent = maybe_parent.?;
        var children = self.getChildren(&parent) orelse return false;

        for (children.keys()) |child| {
            const child_height = self.getHeight(&child) orelse return false;
            const child_weight = self.stakeVotedSubtree(&child) orelse return false;

            const height_cmp = std.math.order(child_height, maybe_deepest_child_height);
            const weight_cmp = std.math.order(child_weight, maybe_deepest_child_weight);
            const slot_cmp = std.math.order(child.slot, deepest_child.slot);

            switch (height_cmp) {
                .gt => return false,
                .eq => switch (weight_cmp) {
                    .gt => return false,
                    .eq => switch (slot_cmp) {
                        .lt => return false,
                        else => {},
                    },
                    else => {},
                },
                else => {},
            }
        }

        return true;
    }

    fn getParent(
        self: *const HeaviestSubtreeForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?SlotAndHash {
        if (self.fork_infos.get(slot_hash_key.*)) |fork_info| {
            return fork_info.parent;
        }
        return null;
    }

    // TODO: Change this to return an iterator.
    fn getChildren(
        self: *const HeaviestSubtreeForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?SortedMap(SlotAndHash, void) {
        const fork_info = self.fork_infos.get(slot_hash_key.*) orelse return null;
        return fork_info.children;
    }

    fn isCandidate(
        self: *const HeaviestSubtreeForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?bool {
        const fork_info = self.fork_infos.get(slot_hash_key.*) orelse return null;
        return fork_info.isCandidate();
    }

    /// Find all nodes reachable from `root1`, excluding subtree at `root2`
    ///
    /// For example, given the following tree:
    ///
    ///           A = root1
    ///          / \
    /// root2 = B   C
    ///        / \   \
    ///       D   E   F
    ///          / \
    ///         G   H
    ///
    /// subtreeDiff (root1, root2) = {A, C, F}
    fn subtreeDiff(
        self: *HeaviestSubtreeForkChoice,
        root1: *const SlotAndHash,
        root2: *const SlotAndHash,
    ) !SortedMap(SlotAndHash, void) {
        if (self.containsBlock(root1)) {
            return SortedMap(SlotAndHash, void).init(self.allocator);
        }
        var pending_keys = std.ArrayList(SlotAndHash).init(self.allocator);
        defer pending_keys.deinit();

        try pending_keys.append(root1.*);

        var reachable_set = SortedMap(SlotAndHash, void).init(self.allocator);
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

    fn doInsertAggregateOperation(
        _: *HeaviestSubtreeForkChoice,
        update_operations: *UpdateOperations,
        modify_fork_validity: ?UpdateOperation,
        slot_hash_key: SlotAndHash,
    ) !bool {
        const aggregate_label = SlotHashKeyLabel{
            .slot_hash_key = slot_hash_key,
            .label = .Aggregate,
        };

        if (update_operations.contains(aggregate_label)) {
            return false;
        }

        if (modify_fork_validity) |mark_fork_validity| {
            switch (mark_fork_validity) {
                .MarkValid => |slot| {
                    _ = try update_operations.put(
                        SlotHashKeyLabel{
                            .slot_hash_key = slot_hash_key,
                            .label = .MarkValid,
                        },
                        UpdateOperation{ .MarkValid = slot },
                    );
                },
                .MarkInvalid => |slot| {
                    _ = try update_operations.put(
                        SlotHashKeyLabel{
                            .slot_hash_key = slot_hash_key,
                            .label = .MarkInvalid,
                        },
                        UpdateOperation{ .MarkInvalid = slot },
                    );
                },
                else => {},
            }
        }

        _ = try update_operations.put(aggregate_label, .Aggregate);
        return true;
    }

    fn processUpdateOperations(
        self: *HeaviestSubtreeForkChoice,
        update_operations_: UpdateOperations,
    ) void {
        // Iterate through the update operations from greatest to smallest slot
        // Sort the map to ensure keys are in order

        var update_operations = update_operations_;
        const items_result = update_operations.items();

        // Access the fields of the returned struct
        const keys = items_result.@"0";
        const values = items_result.@"1";

        // Iterate through the update operations from greatest to smallest slot
        var i: usize = keys.len;
        while (i > 0) {
            i -= 1; // Move backward through the array
            const slot_hash_key_label = keys[i];
            const slot_hash_key = slot_hash_key_label.slot_hash_key;
            const operation = values[i];
            switch (operation) {
                .MarkValid => |valid_slot| self.markForkValid(&slot_hash_key, valid_slot),
                .MarkInvalid => |invalid_slot| self.markForkInvalid(slot_hash_key, invalid_slot),
                .Aggregate => self.aggregateSlot(slot_hash_key),
                .Add => |stake| self.addSlotStake(&slot_hash_key, stake),
                .Subtract => |stake| self.subtractSlotStake(&slot_hash_key, stake),
            }
        }
    }

    fn insertAggregateOperations(
        self: *HeaviestSubtreeForkChoice,
        update_operations: *UpdateOperations,
        slot_hash_key: SlotAndHash,
    ) !void {
        try self.doInsertAggregateOperationsAcrossAncestors(
            update_operations,
            null,
            slot_hash_key,
        );
    }

    fn doInsertAggregateOperationsAcrossAncestors(
        self: *HeaviestSubtreeForkChoice,
        update_operations: *UpdateOperations,
        modify_fork_validity: ?UpdateOperation,
        slot_hash_key: SlotAndHash,
    ) !void {
        var parent_iter = self.ancestorIterator(slot_hash_key);
        while (parent_iter.next()) |parent_slot_hash_key| {
            if (!try self.doInsertAggregateOperation(
                update_operations,
                modify_fork_validity,
                parent_slot_hash_key,
            )) {
                // If this parent was already inserted, we assume all the other parents have also
                // already been inserted. This is to prevent iterating over the parents multiple times
                // when we are aggregating leaves that have a lot of shared ancestors
                break;
            }
        }
    }

    /// Mark that `valid_slot` on the fork starting at `fork_to_modify_key` has been marked
    /// valid. Note we don't need the hash for `valid_slot` because slot number uniquely
    /// identifies a node on a single fork.
    fn markForkValid(
        self: *HeaviestSubtreeForkChoice,
        fork_to_modify_key: *const SlotAndHash,
        valid_slot: Slot,
    ) void {
        // Try to get a mutable reference to the fork info
        if (self.fork_infos.getPtr(fork_to_modify_key.*)) |fork_info_to_modify| {
            // Update the fork info with the newly valid ancestor
            fork_info_to_modify.updateWithNewlyValidAncestor(fork_to_modify_key, valid_slot);

            // If the fork's key matches the valid slot, mark it as duplicate confirmed
            if (fork_to_modify_key.slot == valid_slot) {
                fork_info_to_modify.is_duplicate_confirmed = true;
            }
        }
    }

    /// Mark that `invalid_slot` on the fork starting at `fork_to_modify_key` has been marked
    /// invalid. Note we don't need the hash for `invalid_slot` because slot number uniquely
    /// identifies a node on a single fork.
    fn markForkInvalid(
        self: *HeaviestSubtreeForkChoice,
        fork_to_modify_key: SlotAndHash,
        invalid_slot: Slot,
    ) void {
        // Try to get a mutable reference to the fork info
        if (self.fork_infos.getPtr(fork_to_modify_key)) |fork_info_to_modify| {
            // Update the fork info with the newly invalid ancestor
            fork_info_to_modify.updateWithNewlyInvalidAncestor(&fork_to_modify_key, invalid_slot);
        }
    }

    /// Aggregates stake and height information for the subtree rooted at `slot_hash_key`.
    /// Updates the fork info with the aggregated values.
    pub fn aggregateSlot(self: *HeaviestSubtreeForkChoice, slot_hash_key: SlotAndHash) void {
        var stake_voted_subtree: u64 = 0;
        var deepest_child_height: u64 = 0;
        var best_slot_hash_key: SlotAndHash = slot_hash_key;
        var deepest_slot_hash_key: SlotAndHash = slot_hash_key;
        var is_duplicate_confirmed: bool = false;

        // Get the fork info for the given slot_hash_key
        if (self.fork_infos.getPtr(slot_hash_key)) |fork_info| {
            stake_voted_subtree = fork_info.stake_voted_at;

            var best_child_stake_voted_subtree: u64 = 0;
            var best_child_slot_key: SlotAndHash = slot_hash_key;
            var deepest_child_stake_voted_subtree: u64 = 0;
            var deepest_child_slot_key: SlotAndHash = slot_hash_key;

            // Iterate over the children of the current fork
            for (fork_info.children.keys()) |child_key| {
                const child_fork_info = self.fork_infos.get(child_key) orelse {
                    std.debug.panic("Child must exist in fork_info map", .{});
                };

                const child_stake_voted_subtree = child_fork_info.stake_voted_subtree;
                const child_height = child_fork_info.height;
                is_duplicate_confirmed = is_duplicate_confirmed or
                    child_fork_info.is_duplicate_confirmed;

                // Add the child's stake to the subtree stake
                stake_voted_subtree += child_stake_voted_subtree;

                // Update the best child if the child is a candidate and meets the conditions
                if (child_fork_info.isCandidate() and
                    (best_child_slot_key.order(slot_hash_key) == .eq or
                    child_stake_voted_subtree > best_child_stake_voted_subtree or
                    (child_stake_voted_subtree == best_child_stake_voted_subtree and
                    child_key.order(best_child_slot_key) == .lt)))
                {
                    best_child_stake_voted_subtree = child_stake_voted_subtree;
                    best_child_slot_key = child_key;
                    best_slot_hash_key = child_fork_info.best_slot;
                }

                // Update the deepest child based on height, stake, and slot key
                const is_first_child = deepest_child_slot_key.order(slot_hash_key) == .eq;
                const is_deeper_child = child_height > deepest_child_height;
                const is_heavier_child =
                    child_stake_voted_subtree > deepest_child_stake_voted_subtree;
                const is_earlier_child = child_key.order(deepest_child_slot_key) == .lt;

                if (is_first_child or
                    is_deeper_child or
                    (child_height == deepest_child_height and is_heavier_child) or
                    (child_height == deepest_child_height and
                    child_stake_voted_subtree == deepest_child_stake_voted_subtree and
                    is_earlier_child))
                {
                    deepest_child_height = child_height;
                    deepest_child_stake_voted_subtree = child_stake_voted_subtree;
                    deepest_child_slot_key = child_key;
                    deepest_slot_hash_key = child_fork_info.deepest_slot;
                }
            }
        } else {
            // If the fork info does not exist, return early
            return;
        }

        // Update the fork info with the aggregated values
        const fork_info = self.fork_infos.getPtr(slot_hash_key).?;
        if (is_duplicate_confirmed and !fork_info.is_duplicate_confirmed) {
            std.log.info(
                "Fork choice setting {} to duplicate confirmed",
                .{slot_hash_key},
            );
            fork_info.setDuplicateConfirmed();
        }

        fork_info.stake_voted_subtree = stake_voted_subtree;
        fork_info.height = deepest_child_height + 1;
        fork_info.best_slot = best_slot_hash_key;
        fork_info.deepest_slot = deepest_slot_hash_key;
    }

    /// Adds `stake` to the stake voted at and stake voted subtree for the fork identified by `slot_hash_key`.
    pub fn addSlotStake(
        self: *HeaviestSubtreeForkChoice,
        slot_hash_key: *const SlotAndHash,
        stake: u64,
    ) void {
        // Try to get a mutable reference to the fork info
        if (self.fork_infos.getPtr(slot_hash_key.*)) |fork_info| {
            // Add the stake to the fork's voted stake and subtree stake
            fork_info.stake_voted_at += stake;
            fork_info.stake_voted_subtree += stake;
        }
    }

    /// Subtracts `stake` from the stake voted at and stake voted subtree for the fork identified by `slot_hash_key`.
    pub fn subtractSlotStake(
        self: *HeaviestSubtreeForkChoice,
        slot_hash_key: *const SlotAndHash,
        stake: u64,
    ) void {
        // Try to get a mutable reference to the fork info
        if (self.fork_infos.getPtr(slot_hash_key.*)) |fork_info| {
            // Substract the stake to the fork's voted stake and subtree stake
            fork_info.stake_voted_at -= stake;
            fork_info.stake_voted_subtree -= stake;
        }
    }

    fn ancestorIterator(
        self: *HeaviestSubtreeForkChoice,
        start_slot_hash_key: SlotAndHash,
    ) AncestorIterator {
        return AncestorIterator{
            .current_slot_hash_key = start_slot_hash_key,
            .fork_infos = &self.fork_infos,
        };
    }
};

const AncestorIterator = struct {
    current_slot_hash_key: SlotAndHash,
    fork_infos: *const std.AutoHashMap(SlotAndHash, ForkInfo),

    pub fn init(
        start_slot_hash_key: SlotAndHash,
        fork_infos: *const std.AutoHashMap(SlotAndHash, ForkInfo),
    ) AncestorIterator {
        return AncestorIterator{
            .current_slot_hash_key = start_slot_hash_key,
            .fork_infos = fork_infos,
        };
    }

    pub fn next(self: *AncestorIterator) ?SlotAndHash {
        const fork_info = self.fork_infos.get(self.current_slot_hash_key) orelse return null;
        const parent_slot_hash_key = fork_info.parent orelse return null;

        self.current_slot_hash_key = parent_slot_hash_key;
        return self.current_slot_hash_key;
    }
};

/// Testing only ensures everything compiles.
/// TODO: Update to assert.
const test_allocator = std.testing.allocator;

test "HeaviestSubtreeForkChoice.init" {
    var fc = try HeaviestSubtreeForkChoice.init(
        test_allocator,
        SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    );
    defer fc.deinit();
}

test "HeaviestSubtreeForkChoice.subtreeDiff" {
    var fc = try HeaviestSubtreeForkChoice.init(
        test_allocator,
        SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    );
    defer fc.deinit();

    _ = try fc.subtreeDiff(
        &SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
        &SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    );
}

test "HeaviestSubtreeForkChoice.setTreeRoot" {
    var fc = try HeaviestSubtreeForkChoice.init(
        test_allocator,
        SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    );
    defer fc.deinit();

    _ = try fc.setTreeRoot(
        &SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    );
}

test "HeaviestSubtreeForkChoice.markForkInvalidCandidate" {
    var fc = try HeaviestSubtreeForkChoice.init(
        test_allocator,
        SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    );
    defer fc.deinit();

    _ = try fc.markForkInvalidCandidate(
        &SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    );
}

test "HeaviestSubtreeForkChoice.initForTest" {
    var fc = try HeaviestSubtreeForkChoice.initForTest(test_allocator, fork_tuples[0..]);
    defer fc.deinit();
}

test "HeaviestSubtreeForkChoice.testSetRoot" {
    var fc = try HeaviestSubtreeForkChoice.initForTest(test_allocator, fork_tuples[0..]);
    defer fc.deinit();
    // Set root to 1, should only purge 0
    const root1 = SlotAndHash{ .slot = 1, .hash = Hash.ZEROES };
    _ = try fc.setTreeRoot(&root1);
    for (0..6) |i| {
        const slot_hash = SlotAndHash{ .slot = @intCast(i), .hash = Hash.ZEROES };
        const exists = i != 0;
        try std.testing.expectEqual(exists, fc.fork_infos.contains(slot_hash));
    }
}

const TreeNode = std.meta.Tuple(&.{ SlotAndHash, ?SlotAndHash });

const fork_tuples = [_]TreeNode{
    .{
        SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    },
    .{
        SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
    },
    .{
        SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
    },
    .{
        SlotAndHash{ .slot = 3, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
    },
    .{
        SlotAndHash{ .slot = 5, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 3, .hash = Hash.ZEROES },
    },
    .{
        SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 5, .hash = Hash.ZEROES },
    },
};
