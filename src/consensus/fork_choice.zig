const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const ScopedLogger = sig.trace.ScopedLogger;

const AutoHashMap = std.AutoHashMap;
const Instant = sig.time.Instant;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SortedMap = sig.utils.collections.SortedMap;
const SlotAndHash = sig.core.hash.SlotAndHash;
const Slot = sig.core.Slot;
const ReplayTower = sig.consensus.replay_tower.ReplayTower;

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

const SlotAndHashLabel = struct {
    slot_hash_key: SlotAndHash,
    label: UpdateLabel,

    pub fn order(a: SlotAndHashLabel, b: SlotAndHashLabel) std.math.Order {
        return a.slot_hash_key.order(b.slot_hash_key);
    }
};

const UpdateOperations = SortedMap(
    SlotAndHashLabel,
    UpdateOperation,
);

pub const ForkWeight = u64;

/// Analogous to [ForkInfo](https://github.com/anza-xyz/agave/blob/e7301b2a29d14df19c3496579cf8e271b493b3c6/core/src/consensus/heaviest_subtree_fork_choice.rs#L92)
pub const ForkInfo = struct {
    logger: ScopedLogger(@typeName(ForkInfo)),
    /// Amount of stake that has voted for exactly this slot
    stake_for_slot: ForkWeight,
    /// Amount of stake that has voted for this slot and the subtree
    /// rooted at this slot
    stake_for_subtree: ForkWeight,
    /// Tree height for the subtree rooted at this slot
    height: usize,
    /// Heaviest slot in the subtree rooted at this slot, does not
    /// have to be a direct child in `children`. This is the slot whose subtree
    /// is the heaviest.
    /// Analogous to [best_slot](https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L103C5-L103C14)
    heaviest_subtree_slot: SlotAndHash,
    /// Deepest slot in the subtree rooted at this slot. This is the slot
    /// with the greatest tree height. This metric does not discriminate invalid
    /// forks, unlike `heaviest_slot`
    deepest_slot: SlotAndHash,
    parent: ?SlotAndHash,
    children: SortedMap(SlotAndHash, void),
    /// The latest ancestor of this node that has been marked invalid by being a duplicate.
    /// If the slot itself is a duplicate, this is set to the slot itself.
    latest_duplicate_ancestor: ?Slot,
    /// Set to true if this slot or a child node was duplicate confirmed.
    /// Indicates whether this slot have been confirmed as the valid fork in the presence of duplicate slots.
    /// It means that the network has reached consensus that this fork is the valid one,
    /// and all competing forks for the same slot are invalid.
    is_duplicate_confirmed: bool,

    fn deinit(self: *ForkInfo) void {
        self.children.deinit();
    }

    /// Returns true if the fork rooted at this node is included in fork choice
    fn isCandidate(self: *const ForkInfo) bool {
        return self.latest_duplicate_ancestor == null;
    }

    fn setDuplicateConfirmed(self: *ForkInfo) void {
        self.is_duplicate_confirmed = true;
        self.latest_duplicate_ancestor = null;
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L140
    ///
    /// Updates the fork info with a newly valid ancestor.
    /// If the latest invalid ancestor is less than or equal to the newly valid ancestor,
    /// it clears the latest invalid ancestor.
    fn updateWithNewlyValidAncestor(
        self: *ForkInfo,
        my_key: *const SlotAndHash,
        newly_duplicate_ancestor: Slot,
    ) void {
        // Check if there is a latest invalid (duplicate) ancestor
        if (self.latest_duplicate_ancestor) |latest_duplicate_ancestor| {
            // If the latest invalid ancestor is less than or equal to the newly valid ancestor,
            // clear the latest invalid ancestor
            if (latest_duplicate_ancestor <= newly_duplicate_ancestor) {
                self.logger.info().logf(
                    \\ Fork choice for {} clearing latest invalid ancestor
                    \\ {} because {} was duplicate confirmed
                ,
                    .{ my_key, latest_duplicate_ancestor, newly_duplicate_ancestor },
                );
                self.latest_duplicate_ancestor = null;
            }
        }
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L157
    ///
    /// Updates the fork info with a newly invalid ancestor.
    /// Asserts that the fork is not duplicate confirmed.
    /// If the newly invalid ancestor is greater than the current latest invalid ancestor,
    /// updates the latest invalid ancestor.
    fn updateWithNewlyInvalidAncestor(
        self: *ForkInfo,
        my_key: *const SlotAndHash,
        newly_duplicate_ancestor: Slot,
    ) void {
        // Should not be marking a duplicate confirmed slot as invalid
        std.debug.assert(!self.is_duplicate_confirmed);

        // Check if the newly invalid (duplicate) ancestor is greater than the current latest duplicate ancestor
        const should_update = if (self.latest_duplicate_ancestor) |duplicate_ancestor|
            newly_duplicate_ancestor > duplicate_ancestor
        else
            true;

        // If the condition is met, update the latest duplicate ancestor
        if (should_update) {
            self.logger.info().logf(
                "Fork choice for {} setting latest duplicate ancestor from {?} to {}",
                .{ my_key, self.latest_duplicate_ancestor, newly_duplicate_ancestor },
            );
            self.latest_duplicate_ancestor = newly_duplicate_ancestor;
        }
    }
};

/// Analogous to [HeaviestSubtreeForkChoice](https://github.com/anza-xyz/agave/blob/e7301b2a29d14df19c3496579cf8e271b493b3c6/core/src/consensus/heaviest_subtree_fork_choice.rs#L187)
pub const ForkChoice = struct {
    allocator: std.mem.Allocator,
    logger: ScopedLogger(@typeName(ForkChoice)),
    fork_infos: AutoHashMap(SlotAndHash, ForkInfo),
    latest_votes: AutoHashMap(Pubkey, SlotAndHash),
    tree_root: SlotAndHash,
    last_root_time: Instant,

    pub fn init(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        tree_root: SlotAndHash,
    ) !ForkChoice {
        var self = ForkChoice{
            .allocator = allocator,
            .logger = logger.withScope(@typeName(ForkChoice)),
            .fork_infos = AutoHashMap(SlotAndHash, ForkInfo).init(allocator),
            .latest_votes = AutoHashMap(Pubkey, SlotAndHash).init(allocator),
            .tree_root = tree_root,
            .last_root_time = Instant.now(),
        };

        try self.addNewLeafSlot(tree_root, null);
        return self;
    }

    pub fn deinit(self: *ForkChoice) void {
        var it = self.fork_infos.iterator();
        while (it.next()) |fork_info| {
            fork_info.value_ptr.deinit();
        }
        self.fork_infos.deinit();
        self.latest_votes.deinit();
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L452
    ///
    /// This function inserts a new `SlotAndHash` into the tree and ensures that the tree's properties
    /// (such as `heaviest_slot`, `deepest_slot`, and parent-child relationships) are correctly updated.
    ///
    /// If the new leaf already exists in the tree, the function updates the leaf's parent with the provided parent.
    ///
    /// If the new leaf has a parent, the function propagates updates to the tree's `heaviest_slot` and
    /// `deepest_slot` properties up the tree hierarchy.
    ///
    /// ### Before Adding a New Leaf
    ///
    ///
    /// (0)
    /// ├── (1)
    /// │   └── (3)
    /// |
    /// └── (2)
    ///     └── (4)
    ///
    ///
    /// ### After Adding a New Leaf (5) as Child of (2)
    ///
    ///
    /// (0)
    /// ├── (1)
    /// │   └── (3)
    /// |
    /// └── (2)
    ///     └── (4)
    ///     └── (5)
    ///
    ///
    /// ### Or After Adding an Existing Leaf (3) as Child of (2)
    ///
    ///
    /// (0)
    /// ├── (1)
    /// │   └── (3)
    /// |   └── (4)
    /// |
    /// └── (2)
    ///
    pub fn addNewLeafSlot(
        self: *ForkChoice,
        slot_hash_key: SlotAndHash,
        maybe_parent: ?SlotAndHash,
    ) !void {
        errdefer self.deinit();
        // TODO implement self.print_state();

        if (self.fork_infos.contains(slot_hash_key)) {
            // Comment from Agave: Can potentially happen if we repair the same version of the duplicate slot, after
            // dumping the original version
            // TODO: What does repair the same version of the duplicate slot, after dumping the original version mean
            return;
        }

        const parent_latest_duplicate_ancestor =
            if (maybe_parent) |p| self.latestDuplicateAncestor(p) else null;

        if (self.fork_infos.getPtr(slot_hash_key)) |fork_info| {
            // Set the parent of the existing entry with the newly provided parent.
            fork_info.parent = maybe_parent;
        } else {
            // Insert new entry
            const new_fork_info = ForkInfo{
                .logger = self.logger.withScope(@typeName(ForkInfo)),
                .stake_for_slot = 0,
                .stake_for_subtree = 0,
                .height = 1,
                // The `heaviest_slot` and `deepest_slot` of a leaf is itself
                .heaviest_subtree_slot = slot_hash_key,
                .deepest_slot = slot_hash_key,
                .children = SortedMap(SlotAndHash, void).init(self.allocator),
                .parent = maybe_parent,
                .latest_duplicate_ancestor = parent_latest_duplicate_ancestor,
                // If the parent is none, then this is the root, which implies this must
                // have reached the duplicate confirmed threshold
                .is_duplicate_confirmed = (maybe_parent == null),
            };

            try self.fork_infos.put(slot_hash_key, new_fork_info);
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

    pub fn containsBlock(self: *const ForkChoice, key: *const SlotAndHash) bool {
        return self.fork_infos.contains(key.*);
    }

    pub fn latestDuplicateAncestor(
        self: *const ForkChoice,
        slot_hash_key: SlotAndHash,
    ) ?Slot {
        if (self.fork_infos.get(slot_hash_key)) |fork_info| {
            return fork_info.latest_duplicate_ancestor;
        }
        return null;
    }

    /// Analogous to [best_overall_slot](https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L305)
    pub fn heaviestOverallSlot(self: *const ForkChoice) SlotAndHash {
        return self.heaviestSlot(self.tree_root) orelse {
            @panic("Root must exist in tree");
        };
    }

    /// Analogous to [best_slot](https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L293)
    pub fn heaviestSlot(
        self: *const ForkChoice,
        slot_hash_key: SlotAndHash, //TODO change this to reference
    ) ?SlotAndHash {
        if (self.fork_infos.get(slot_hash_key)) |fork_info| {
            return fork_info.heaviest_subtree_slot;
        }
        return null;
    }

    pub fn deepestSlot(
        self: *const ForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?SlotAndHash {
        if (self.fork_infos.get(slot_hash_key.*)) |fork_info| {
            return fork_info.deepest_slot;
        }
        return null;
    }

    pub fn deepestOverallSlot(self: *const ForkChoice) SlotAndHash {
        return self.deepestSlot(&self.tree_root) orelse {
            @panic("Root must exist in tree");
        };
    }

    pub fn stakeForSlot(
        self: *ForkChoice,
        key: *const SlotAndHash,
    ) ?u64 {
        if (self.fork_infos.get(key.*)) |fork_info| {
            return fork_info.stake_for_slot;
        }
        return null;
    }

    pub fn stakeForSubtree(
        self: *const ForkChoice,
        key: *const SlotAndHash,
    ) ?u64 {
        if (self.fork_infos.get(key.*)) |fork_info| {
            return fork_info.stake_for_subtree;
        }
        return null;
    }

    pub fn getHeight(self: *const ForkChoice, key: *const SlotAndHash) ?usize {
        if (self.fork_infos.get(key.*)) |fork_info| {
            return fork_info.height;
        }
        return null;
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L358
    ///
    /// Updates the root of the tree, removing unreachable nodes.
    ///
    /// # Description:
    /// - Computes the difference between the current tree (`tree_root`) and `new_root`.
    /// - Removes nodes that are not reachable from `new_root`.
    /// - Updates `tree_root` to `new_root` and resets `last_root_time`.
    ///
    /// # Example:
    ///
    /// **Before Root Change (`0` is root):**
    ///
    ///
    /// (0) <- Current root
    /// ├── (1)
    /// │   ├── (3)
    /// │   └── (4)
    /// └── (2)
    ///
    ///
    /// **After `setTreeRoot(new_root=1)`:**
    ///
    /// (1) <- New root
    /// ├── (3)
    /// └── (4)
    ///
    ///
    /// - Nodes `{ 0, 2 }` are **removed**.
    pub fn setTreeRoot(self: *ForkChoice, new_root: *const SlotAndHash) !void {
        // Remove everything reachable from old root but not new root
        var remove_set = try self.subtreeDiff(&self.tree_root, new_root);
        defer remove_set.deinit();

        for (remove_set.keys()) |node_key| {
            if (!self.fork_infos.contains(node_key)) {
                return error.MissingForkInfo;
            }
        }

        // Root to be made the new root should already exist in fork choice.
        const root_fork_info = self.fork_infos.getPtr(new_root.*) orelse
            return error.MissingForkInfo;

        // At this point, both the subtree to be removed and new root
        // are confirmed to be in the fork choice.

        for (remove_set.keys()) |node_key| {
            // SAFETY: Previous contains check ensures this won't panic.
            const fork_info = self.fork_infos.getPtr(node_key).?;
            fork_info.children.deinit();
            _ = self.fork_infos.remove(node_key);
        }

        root_fork_info.parent = null;
        self.tree_root = new_root.*;
        self.last_root_time = Instant.now();
    }

    pub fn isDuplicateConfirmed(
        self: *ForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?bool {
        if (self.fork_infos.get(slot_hash_key.*)) |fork_info| {
            return fork_info.is_duplicate_confirmed;
        }
        return null;
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1358
    pub fn markForkValidCandidate(
        self: *ForkChoice,
        valid_slot_hash_key: *const SlotAndHash,
    ) !std.ArrayList(SlotAndHash) {
        var newly_duplicate_confirmed_ancestors = std.ArrayList(SlotAndHash).init(self.allocator);
        if (!(self.isDuplicateConfirmed(valid_slot_hash_key) orelse return error.MissingForkInfo)) {
            try newly_duplicate_confirmed_ancestors.append(valid_slot_hash_key.*);
        }

        var ancestor_iter = self.ancestorIterator(valid_slot_hash_key.*);
        while (ancestor_iter.next()) |ancestor_slot_hash_key| {
            try newly_duplicate_confirmed_ancestors.append(ancestor_slot_hash_key);
        }

        var update_operations = UpdateOperations.init(self.allocator);
        defer update_operations.deinit();

        // Notify all children that a parent was marked as valid.
        var children_hash_keys = try self.subtreeDiff(
            valid_slot_hash_key,
            &.{ .slot = 0, .hash = Hash.ZEROES },
        );
        defer children_hash_keys.deinit();

        for (children_hash_keys.keys()) |child_hash_key| {
            _ = try doInsertAggregateOperation(
                &update_operations,
                UpdateOperation{ .MarkValid = valid_slot_hash_key.slot },
                child_hash_key,
            );
        }

        // Aggregate across all ancestors to find new heaviest slots excluding this fork
        try self.insertAggregateOperations(&update_operations, valid_slot_hash_key.*);
        self.processUpdateOperations(&update_operations);

        return newly_duplicate_confirmed_ancestors;
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1330
    pub fn markForkInvalidCandidate(
        self: *ForkChoice,
        invalid_slot_hash_key: *const SlotAndHash,
    ) !void {
        // Get mutable reference to fork info
        if (self.fork_infos.getPtr(invalid_slot_hash_key.*)) |fork_info| {
            // Should not be marking duplicate confirmed blocks as invalid candidates
            if (fork_info.is_duplicate_confirmed) {
                return error.DuplicateConfirmedCannotBeMarkedInvalid;
            }

            var update_operations = UpdateOperations.init(self.allocator);
            defer update_operations.deinit();

            // Notify all children that a parent was marked as invalid
            var children_hash_keys = try self.subtreeDiff(
                invalid_slot_hash_key,
                &.{ .slot = 0, .hash = Hash.ZEROES },
            );
            defer children_hash_keys.deinit();

            for (children_hash_keys.keys()) |child_hash_key| {
                _ = try doInsertAggregateOperation(
                    &update_operations,
                    UpdateOperation{ .MarkInvalid = invalid_slot_hash_key.slot },
                    child_hash_key,
                );
            }

            // Aggregate across all ancestors to find new heaviest slots excluding this fork
            try self.insertAggregateOperations(&update_operations, invalid_slot_hash_key.*);
            self.processUpdateOperations(&update_operations);
        }
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L736
    ///
    /// Updates the fork tree's metadata for ancestors when a new slot (slot_hash_key) is added.
    /// Specifically, it propagates updates about the heaviest slot and deepest slot upwards through
    /// the ancestors of the new slot.
    ///
    /// ## Before and After Example:
    ///
    ///
    /// (0)
    /// ├── heaviest_slot: (4)
    /// ├── deepest_slot: (6)
    /// └── (1)
    ///     ├── heaviest_slot: (4)
    ///     ├── deepest_slot: (6)
    ///     ├── (2)
    ///     │   ├── heaviest_slot: (4)
    ///     │   ├── deepest_slot: (4)
    ///     │   └── (4)
    ///     │       ├── heaviest_slot: (4)
    ///     │       ├── deepest_slot: (4)
    ///     └── (3)
    ///         ├── heaviest_slot: (6)
    ///         ├── deepest_slot: (6)
    ///         └── (5)
    ///             ├── heaviest_slot: (6)
    ///             ├── deepest_slot: (6)
    ///             └── (6)
    ///                 ├── heaviest_slot: (6)
    ///                 ├── deepest_slot: (6)
    ///
    ///
    /// Adding a new leaf (10) as a child of (4) which update the heaviest slot of (2), (1) and (0) to (10)
    ///
    ///
    /// (0)
    /// ├── heaviest_slot: (10)
    /// ├── deepest_slot: (10)
    /// └── (1)
    ///     ├── heaviest_slot: (10)
    ///     ├── deepest_slot: (10)
    ///     ├── (2)
    ///     │   ├── heaviest_slot: (10)
    ///     │   ├── deepest_slot: (10)
    ///     │   ├── stake_voted_subtree: 0
    ///     │   └── (4)
    ///     │       ├── heaviest_slot: (10)
    ///     │       ├── deepest_slot: (10)
    ///     │       ├── stake_voted_subtree: 0
    ///     │       └── (10) ---------------------------new leaf 10 added as child of 4
    ///     │           ├── heaviest_slot: (10)
    ///     │           ├── deepest_slot: (10)
    ///     └── (3)
    ///         ├── heaviest_slot: (6)
    ///         ├── deepest_slot: (6)
    ///         └── (5)
    ///             ├── heaviest_slot: (6)
    ///             ├── deepest_slot: (6)
    ///             └── (6)
    ///                 ├── heaviest_slot: (6)
    ///                 ├── deepest_slot: (6)
    ///
    ///
    /// For propagating the deepest slot, the function:
    ///
    /// 1. Starts from the newly inserted slot.
    /// 2. Checks if it is the **deepest child**.
    /// 3. If it is, updates the ancestor's `deepest_slot` and increases its `height`.
    /// 4. Continues moving up the tree, repeating the process.
    ///
    /// ## Before and After Example:
    ///
    /// **Before insertion of `3`:**
    ///
    /// (0)
    /// ├── deepest_slot: (2)
    /// ├── depth: 2
    /// ├── (1)
    /// |     # Note: tie are broken by weight and slot number.
    /// └── (2)
    ///     ├── deepest_slot: (2)
    ///     ├── depth: 1
    ///
    ///
    /// **After inserting `3` under `2`:**
    ///
    ///
    /// (0)
    /// ├── deepest_slot: (3)  <- Updated
    /// ├── depth: 2           <- Updated
    /// |
    /// ├── (1)
    /// └── (2)
    ///     ├── deepest_slot: (3)  <- Updated
    ///     ├── depth: 2           <- Updated
    ///     └── (3)
    ///         ├── deepest_slot: (3)  <- New deepest slot
    ///         ├── depth: 1
    ///
    fn propagateNewLeaf(
        self: *ForkChoice,
        slot_hash_key: *const SlotAndHash,
        parent_slot_hash_key: *const SlotAndHash,
    ) !void {
        // Returns an error as parent must exist in self.fork_infos after its child leaf was created
        const parent_heaviest_slot_hash_key =
            self.heaviestSlot(parent_slot_hash_key.*) orelse return error.MissingParent;
        // If this new leaf is the direct parent's heaviest child, then propagate it up the tree
        if (try self.isHeaviestChild(slot_hash_key)) {
            var maybe_ancestor: ?SlotAndHash = parent_slot_hash_key.*;
            while (maybe_ancestor) |ancestor| {
                // Saftey: maybe_ancestor cannot be null due to the if check above.
                if (self.fork_infos.getPtr(ancestor)) |ancestor_fork_info| {
                    // Do the update to the new heaviest slot.
                    if (ancestor_fork_info.*.heaviest_subtree_slot.equals(
                        parent_heaviest_slot_hash_key,
                    )) {
                        ancestor_fork_info.*.heaviest_subtree_slot = slot_hash_key.*;
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
        while (maybe_ancestor) |ancestor| {
            if (!self.isDeepestChild(&current_child)) {
                break;
            }
            if (self.fork_infos.getPtr(ancestor)) |ancestor_fork_info| {
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

    /// Analogous to [is_best_child] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L499
    ///
    /// Returns true if the given `maybe_heaviest_child` is the heaviest among the children
    /// of the parent. Breaks ties by slot # (lower is heavier).
    fn isHeaviestChild(
        self: *const ForkChoice,
        maybe_heaviest_child: *const SlotAndHash,
    ) !bool {
        const maybe_heaviest_child_weight =
            self.stakeForSubtree(maybe_heaviest_child) orelse return false;
        const maybe_parent = self.getParent(maybe_heaviest_child);

        // If there's no parent, this must be the root
        const parent = maybe_parent orelse return true;
        var children = self.getChildren(&parent) orelse return false;

        for (children.keys()) |child| {
            // child must exist in `self.fork_infos`
            const child_weight = self.stakeForSubtree(&child) orelse return error.MissingChild;

            // Don't count children currently marked as invalid
            // child must exist in tree
            if (!(self.isCandidate(&child) orelse return error.MissingChild)) {
                continue;
            }

            if (child_weight > maybe_heaviest_child_weight or
                (maybe_heaviest_child_weight == child_weight and
                    child.order(maybe_heaviest_child.*) == .lt))
            {
                return false;
            }
        }

        return true;
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L528
    ///
    ///  Checks if `deepest_child` is the deepest among its siblings.
    ///
    /// - A node is the deepest if no sibling has:
    ///   1. A greater height.
    ///   2. The same height but higher stake weight.
    ///   3. The same height & stake but a higher slot number.
    ///
    /// - If `deepest_child` has no parent, it is the root and deepest by default.
    fn isDeepestChild(self: *ForkChoice, deepest_child: *const SlotAndHash) bool {
        const maybe_deepest_child_weight =
            self.stakeForSubtree(deepest_child) orelse return false;
        const maybe_deepest_child_height = self.getHeight(deepest_child) orelse return false;
        const maybe_parent = self.getParent(deepest_child);

        // If there's no parent, this must be the root
        const parent = maybe_parent orelse return true;
        // Get the other chidren of the parent. i.e. siblings of the deepest_child.
        var children = self.getChildren(&parent) orelse return false;

        for (children.keys()) |child| {
            const child_height = self.getHeight(&child) orelse return false;
            const child_weight = self.stakeForSubtree(&child) orelse return false;

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
        self: *const ForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?SlotAndHash {
        if (self.fork_infos.get(slot_hash_key.*)) |fork_info| {
            return fork_info.parent;
        }
        return null;
    }

    // TODO: Change this to return an iterator.
    // https://github.com/Syndica/sig/issues/556
    fn getChildren(
        self: *const ForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?SortedMap(SlotAndHash, void) {
        const fork_info = self.fork_infos.get(slot_hash_key.*) orelse return null;
        return fork_info.children;
    }

    fn isCandidate(
        self: *const ForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?bool {
        const fork_info = self.fork_infos.get(slot_hash_key.*) orelse return null;
        return fork_info.isCandidate();
    }

    /// Returns if a node with slot `maybe_ancestor_slot` is an ancestor of the node with
    /// key `node_key`
    pub fn isStrictAncestor(
        self: *const ForkChoice,
        maybe_ancestor_key: *const SlotAndHash,
        node_key: *const SlotAndHash,
    ) bool {
        if (maybe_ancestor_key == node_key) {
            return false;
        }

        if (maybe_ancestor_key.slot > node_key.slot) {
            return false;
        }

        var ancestor_iterator = self.ancestorIterator(node_key.*);
        while (ancestor_iterator.next()) |ancestor| {
            if (ancestor.slot == maybe_ancestor_key.slot and
                ancestor.hash.eql(maybe_ancestor_key.hash))
            {
                return true;
            }
        }
        return false;
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/tree_diff.rs#L12
    ///
    /// Find all nodes reachable from `root1`, excluding subtree at `root2`
    ///
    /// For example, given the following tree:
    ///
    ///```txt
    /// (0) = root1
    /// ├── (1) = root2
    /// │   ├── (3)
    /// │   └── (4)
    /// │       ├── (6)
    /// │       └── (7)
    /// └── (2)
    ///     └── (5)
    ///```
    ///
    /// subtreeDiff(root1, root2) = {0, 2, 5}
    fn subtreeDiff(
        self: *ForkChoice,
        root1: *const SlotAndHash,
        root2: *const SlotAndHash,
    ) !SortedMap(SlotAndHash, void) {
        if (!self.containsBlock(root1)) {
            return SortedMap(SlotAndHash, void).init(self.allocator);
        }
        var pending_keys = std.ArrayList(SlotAndHash).init(self.allocator);
        defer pending_keys.deinit();

        try pending_keys.append(root1.*);

        var reachable_set = SortedMap(SlotAndHash, void).init(self.allocator);

        while (pending_keys.pop()) |current_key| {
            if (current_key.equals(root2.*)) {
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

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1088
    fn processUpdateOperations(
        self: *ForkChoice,
        update_operations: *UpdateOperations,
    ) void {
        // Iterate through the update operations from greatest to smallest slot
        // Sort the map to ensure keys are in order

        const keys, const values = update_operations.items();

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

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L780
    fn insertAggregateOperations(
        self: *ForkChoice,
        update_operations: *UpdateOperations,
        slot_hash_key: SlotAndHash,
    ) !void {
        try self.doInsertAggregateOperationsAcrossAncestors(
            update_operations,
            null,
            slot_hash_key,
        );
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L793
    fn doInsertAggregateOperationsAcrossAncestors(
        self: *ForkChoice,
        update_operations: *UpdateOperations,
        modify_fork_validity: ?UpdateOperation,
        slot_hash_key: SlotAndHash,
    ) !void {
        var parent_iter = self.ancestorIterator(slot_hash_key);
        while (parent_iter.next()) |parent_slot_hash_key| {
            if (!try doInsertAggregateOperation(
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

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L950
    ///
    /// Mark that `valid_slot` on the fork starting at `fork_to_modify_key` has been marked
    /// valid. Note we don't need the hash for `valid_slot` because slot number uniquely
    /// identifies a node on a single fork.
    fn markForkValid(
        self: *ForkChoice,
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

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L962
    ///
    /// Mark that `invalid_slot` on the fork starting at `fork_to_modify_key` has been marked
    /// invalid. Note we don't need the hash for `invalid_slot` because slot number uniquely
    /// identifies a node on a single fork.
    fn markForkInvalid(
        self: *ForkChoice,
        fork_to_modify_key: SlotAndHash,
        invalid_slot: Slot,
    ) void {
        // Try to get a mutable reference to the fork info
        if (self.fork_infos.getPtr(fork_to_modify_key)) |fork_info_to_modify| {
            // Update the fork info with the newly invalid ancestor
            fork_info_to_modify.updateWithNewlyInvalidAncestor(&fork_to_modify_key, invalid_slot);
        }
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L850
    ///
    /// Aggregates stake and height information for the subtree rooted at `slot_hash_key`.
    /// Updates the fork info with the aggregated values.
    fn aggregateSlot(self: *ForkChoice, slot_hash_key: SlotAndHash) void {
        var stake_for_subtree: u64 = 0;
        var deepest_child_height: u64 = 0;
        var heaviest_slot_hash_key: SlotAndHash = slot_hash_key;
        var deepest_slot_hash_key: SlotAndHash = slot_hash_key;
        var is_duplicate_confirmed: bool = false;

        // Get the fork info for the given slot_hash_key
        if (self.fork_infos.getPtr(slot_hash_key)) |fork_info| {
            stake_for_subtree = fork_info.stake_for_slot;

            var heaviest_child_stake_for_subtree: u64 = 0;
            var heaviest_child_slot_key: SlotAndHash = slot_hash_key;
            var deepest_child_stake_for_subtree: u64 = 0;
            var deepest_child_slot_key: SlotAndHash = slot_hash_key;

            // Iterate over the children of the current fork
            for (fork_info.children.keys()) |child_key| {
                const child_fork_info = self.fork_infos.get(child_key) orelse {
                    std.debug.panic("Child must exist in fork_info map", .{});
                };

                const child_stake_for_subtree = child_fork_info.stake_for_subtree;
                const child_height = child_fork_info.height;
                is_duplicate_confirmed = is_duplicate_confirmed or
                    child_fork_info.is_duplicate_confirmed;

                // Child forks that are not candidates still contribute to the weight
                // of the subtree rooted at `slot_hash_key`. For instance:
                //
                // Build fork structure:
                //
                //
                // (0)
                // └── (1)
                //     ├── (2)
                //     │   └── (4)  <- 66%
                //     └── (3)      <- 34%
                //
                //     If slot 4 is a duplicate slot, so no longer qualifies as a candidate until
                //     the slot is confirmed, the weight of votes on slot 4 should still count towards
                //     slot 2, otherwise we might pick slot 3 as the heaviest fork to build blocks on
                //     instead of slot 2.

                // See comment above for why this check is outside of the `is_candidate` check.

                // Add the child's stake to the subtree stake
                stake_for_subtree += child_stake_for_subtree;

                // Update the heaviest child if the child is a candidate and meets the conditions
                if (child_fork_info.isCandidate() and
                    (heaviest_child_slot_key.equals(slot_hash_key) or
                        child_stake_for_subtree > heaviest_child_stake_for_subtree or
                        (child_stake_for_subtree == heaviest_child_stake_for_subtree and
                            child_key.order(heaviest_child_slot_key) == .lt)))
                {
                    heaviest_child_stake_for_subtree = child_stake_for_subtree;
                    heaviest_child_slot_key = child_key;
                    heaviest_slot_hash_key = child_fork_info.heaviest_subtree_slot;
                }

                // Update the deepest child based on height, stake, and slot key
                const is_first_child = deepest_child_slot_key.equals(slot_hash_key);
                const is_deeper_child = child_height > deepest_child_height;
                const is_heavier_child =
                    child_stake_for_subtree > deepest_child_stake_for_subtree;
                const is_earlier_child = child_key.order(deepest_child_slot_key) == .lt;

                if (is_first_child or
                    is_deeper_child or
                    (child_height == deepest_child_height and is_heavier_child) or
                    (child_height == deepest_child_height and
                        child_stake_for_subtree == deepest_child_stake_for_subtree and
                        is_earlier_child))
                {
                    deepest_child_height = child_height;
                    deepest_child_stake_for_subtree = child_stake_for_subtree;
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
            self.logger.info().logf(
                "Fork choice setting {} to duplicate confirmed",
                .{slot_hash_key},
            );
            fork_info.setDuplicateConfirmed();
        }

        fork_info.stake_for_subtree = stake_for_subtree;
        fork_info.height = deepest_child_height + 1;
        fork_info.heaviest_subtree_slot = heaviest_slot_hash_key;
        fork_info.deepest_slot = deepest_slot_hash_key;
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1105
    ///
    /// Adds `stake` to the stake voted at and stake voted subtree for the fork identified by `slot_hash_key`.
    fn addSlotStake(
        self: *ForkChoice,
        slot_hash_key: *const SlotAndHash,
        stake: u64,
    ) void {
        // Try to get a mutable reference to the fork info
        if (self.fork_infos.getPtr(slot_hash_key.*)) |fork_info| {
            // Add the stake to the fork's voted stake and subtree stake
            fork_info.stake_for_slot += stake;
            fork_info.stake_for_subtree += stake;
        }
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1112
    ///
    /// Subtracts `stake` from the stake voted at and stake voted subtree for the fork identified by `slot_hash_key`.
    fn subtractSlotStake(
        self: *ForkChoice,
        slot_hash_key: *const SlotAndHash,
        stake: u64,
    ) void {
        // Try to get a mutable reference to the fork info
        if (self.fork_infos.getPtr(slot_hash_key.*)) |fork_info| {
            // Substract the stake to the fork's voted stake and subtree stake
            fork_info.stake_for_slot -= stake;
            fork_info.stake_for_subtree -= stake;
        }
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/9dbfe93720019942a3d70e0d609b654a57c42555/core/src/consensus/heaviest_subtree_fork_choice.rs#L1133
    pub fn heaviestSlotOnSameVotedFork(
        self: *const ForkChoice,
        replay_tower: *const ReplayTower,
    ) !?SlotAndHash {
        if (replay_tower.lastVotedSlotHash()) |last_voted_slot_hash| {
            if (self.isCandidate(&last_voted_slot_hash)) |is_candidate| {
                if (is_candidate) {
                    return self.heaviestSlot(last_voted_slot_hash);
                } else {
                    // In this case our last voted fork has been marked invalid because
                    // it contains a duplicate block. It is critical that we continue to
                    // build on it as long as there exists at least 1 non duplicate fork.
                    // This is because there is a chance that this fork is actually duplicate
                    // confirmed but not observed because there is no block containing the
                    // required votes.
                    //
                    // Scenario 1:
                    // Slot 0 - Slot 1 (90%)
                    //        |
                    //        - Slot 1'
                    //        |
                    //        - Slot 2 (10%)
                    //
                    // Imagine that 90% of validators voted for Slot 1, but because of the existence
                    // of Slot 1', Slot 1 is marked as invalid in fork choice. It is impossible to reach
                    // the required switch threshold for these validators to switch off of Slot 1 to Slot 2.
                    // In this case it is important for someone to build a Slot 3 off of Slot 1 that contains
                    // the votes for Slot 1. At this point they will see that the fork off of Slot 1 is duplicate
                    // confirmed, and the rest of the network can repair Slot 1, and mark it is a valid candidate
                    // allowing fork choice to converge.
                    //
                    // This will only occur after Slot 2 has been created, in order to resolve the following
                    // scenario:
                    //
                    // Scenario 2:
                    // Slot 0 - Slot 1 (30%)
                    //        |
                    //        - Slot 1' (30%)
                    //
                    // In this scenario only 60% of the network has voted before the duplicate proof for Slot 1 and 1'
                    // was viewed. Neither version of the slot will reach the duplicate confirmed threshold, so it is
                    // critical that a new fork Slot 2 from Slot 0 is created to allow the validators on Slot 1 and
                    // Slot 1' to switch. Since the `best_slot` is an ancestor of the last vote (Slot 0 is ancestor of last
                    // vote Slot 1 or Slot 1'), we will trigger `SwitchForkDecision::FailedSwitchDuplicateRollback`, which
                    // will create an alternate fork off of Slot 0. Once this alternate fork is created, the `best_slot`
                    // will be Slot 2, at which point we will be in Scenario 1 and continue building off of Slot 1 or Slot 1'.
                    //
                    // For more details see the case for
                    // `SwitchForkDecision::FailedSwitchDuplicateRollback` in `ReplayStage::select_vote_and_reset_forks`.
                    return self.deepestSlot(&last_voted_slot_hash);
                }
            } else {
                if (!replay_tower.isStrayLastVote()) {
                    // Unless last vote is stray and stale, self.is_candidate(last_voted_slot_hash) must return
                    // Some(_), justifying to panic! here.
                    // Also, adjust_lockouts_after_replay() correctly makes last_voted_slot None,
                    // if all saved votes are ancestors of replayed_root_slot. So this code shouldn't be
                    // touched in that case as well.
                    // In other words, except being stray, all other slots have been voted on while this
                    // validator has been running, so we must be able to fetch best_slots for all of
                    // them.
                    return error.MissingCandidate;
                } else {
                    // fork_infos doesn't have corresponding data for the stale stray last vote,
                    // meaning some inconsistency between saved tower and ledger.
                    // (newer snapshot, or only a saved tower is moved over to new setup?)
                    return null;
                }
            }
        } else {
            return null;
        }
    }

    fn setStakeVotedAt(
        self: *ForkChoice,
        slot_hash_key: *const SlotAndHash,
        stake_for_slot: u64,
    ) void {
        if (!builtin.is_test) {
            @compileError("setStakeVotedAt should only be called in test mode");
        }

        if (self.fork_infos.getPtr(slot_hash_key.*)) |fork_info| {
            fork_info.stake_for_slot = stake_for_slot;
        }
    }

    fn ancestorIterator(
        self: *const ForkChoice,
        start_slot_hash_key: SlotAndHash,
    ) AncestorIterator {
        return AncestorIterator{
            .current_slot_hash_key = start_slot_hash_key,
            .fork_infos = &self.fork_infos,
        };
    }
};

/// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1390
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

/// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L814
fn doInsertAggregateOperation(
    update_operations: *UpdateOperations,
    modify_fork_validity: ?UpdateOperation,
    slot_hash_key: SlotAndHash,
) !bool {
    const aggregate_label = SlotAndHashLabel{
        .slot_hash_key = slot_hash_key,
        .label = .Aggregate,
    };

    if (update_operations.contains(aggregate_label)) {
        return false;
    }

    if (modify_fork_validity) |mark_fork_validity| {
        switch (mark_fork_validity) {
            .MarkValid => |slot| {
                try update_operations.put(
                    SlotAndHashLabel{
                        .slot_hash_key = slot_hash_key,
                        .label = .MarkValid,
                    },
                    UpdateOperation{ .MarkValid = slot },
                );
            },
            .MarkInvalid => |slot| {
                try update_operations.put(
                    SlotAndHashLabel{
                        .slot_hash_key = slot_hash_key,
                        .label = .MarkInvalid,
                    },
                    UpdateOperation{ .MarkInvalid = slot },
                );
            },
            else => {},
        }
    }

    try update_operations.put(aggregate_label, .Aggregate);
    return true;
}
const test_allocator = std.testing.allocator;
const createTestReplayTower = sig.consensus.replay_tower.createTestReplayTower;
const createTestSlotHistory = sig.consensus.replay_tower.createTestSlotHistory;

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L3281
test "HeaviestSubtreeForkChoice.subtreeDiff" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();

    // Diff of same root is empty, no matter root, intermediate node, or leaf
    {
        var diff = try fork_choice.subtreeDiff(
            &.{ .slot = 0, .hash = Hash.ZEROES },
            &.{ .slot = 0, .hash = Hash.ZEROES },
        );
        defer diff.deinit();
        try std.testing.expectEqual(0, diff.count());
    }

    {
        var diff = try fork_choice.subtreeDiff(
            &.{ .slot = 5, .hash = Hash.ZEROES },
            &.{ .slot = 5, .hash = Hash.ZEROES },
        );
        defer diff.deinit();
        try std.testing.expectEqual(0, diff.count());
    }
    {
        var diff = try fork_choice.subtreeDiff(
            &.{ .slot = 6, .hash = Hash.ZEROES },
            &.{ .slot = 6, .hash = Hash.ZEROES },
        );
        defer diff.deinit();
        try std.testing.expectEqual(0, diff.count());
    }

    // The set reachable from slot 3, excluding subtree 1, is just everything
    // in slot 3 since subtree 1 is an ancestor
    {
        var diff = try fork_choice.subtreeDiff(
            &.{ .slot = 3, .hash = Hash.ZEROES },
            &.{ .slot = 1, .hash = Hash.ZEROES },
        );
        defer diff.deinit();

        const items = diff.items();
        const slot_and_hashes = items[0];

        try std.testing.expectEqual(3, slot_and_hashes.len);

        try std.testing.expectEqual(
            slot_and_hashes[0],
            SlotAndHash{ .slot = 3, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[1],
            SlotAndHash{ .slot = 5, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[2],
            SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
        );
    }

    // The set reachable from slot 1, excluding subtree 3, is just 1 and
    // the subtree at 2
    {
        var diff = try fork_choice.subtreeDiff(
            &.{ .slot = 1, .hash = Hash.ZEROES },
            &.{ .slot = 3, .hash = Hash.ZEROES },
        );
        defer diff.deinit();

        const items = diff.items();
        const slot_and_hashes = items[0]; // Access the keys slice

        try std.testing.expectEqual(3, slot_and_hashes.len);

        try std.testing.expectEqual(
            slot_and_hashes[0],
            SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[1],
            SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[2],
            SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        );
    }

    // The set reachable from slot 1, excluding leaf 6, is just everything
    // except leaf 6
    {
        var diff = try fork_choice.subtreeDiff(
            &.{ .slot = 0, .hash = Hash.ZEROES },
            &.{ .slot = 6, .hash = Hash.ZEROES },
        );
        defer diff.deinit();

        const items = diff.items();
        const slot_and_hashes = items[0]; // Access the keys slice

        try std.testing.expectEqual(6, slot_and_hashes.len);

        try std.testing.expectEqual(
            slot_and_hashes[0],
            SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[1],
            SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[2],
            SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[3],
            SlotAndHash{ .slot = 3, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[4],
            SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[5],
            SlotAndHash{ .slot = 5, .hash = Hash.ZEROES },
        );
    }

    {
        // Set root at 1
        try fork_choice.setTreeRoot(&.{ .slot = 1, .hash = Hash.ZEROES });
        // Zero no longer exists, set reachable from 0 is empty
        try std.testing.expectEqual(
            0,
            (try fork_choice.subtreeDiff(
                &.{ .slot = 0, .hash = Hash.ZEROES },
                &.{ .slot = 6, .hash = Hash.ZEROES },
            )).count(),
        );
    }
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1534
test "HeaviestSubtreeForkChoice.ancestorIterator" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();

    {
        var iterator = fork_choice.ancestorIterator(SlotAndHash{ .slot = 6, .hash = Hash.ZEROES });
        var ancestors: [4]SlotAndHash = undefined;
        var index: usize = 0;

        while (iterator.next()) |ancestor| {
            if (index >= ancestors.len) {
                std.testing.expect(false) catch @panic("Test failed: More than 4 ancestors.");
            }
            ancestors[index] = ancestor;
            index += 1;
        }

        try std.testing.expectEqual(
            ancestors[0],
            SlotAndHash{ .slot = 5, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[1],
            SlotAndHash{ .slot = 3, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[2],
            SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[3],
            SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
        );
    }
    {
        var iterator = fork_choice.ancestorIterator(SlotAndHash{ .slot = 4, .hash = Hash.ZEROES });
        var ancestors: [3]SlotAndHash = undefined;
        var index: usize = 0;

        while (iterator.next()) |ancestor| {
            if (index >= ancestors.len) {
                std.testing.expect(false) catch @panic("Test failed: More than 3 ancestors.");
            }
            ancestors[index] = ancestor;
            index += 1;
        }

        try std.testing.expectEqual(
            ancestors[0],
            SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[1],
            SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[2],
            SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
        );
    }
    {
        var iterator = fork_choice.ancestorIterator(SlotAndHash{ .slot = 1, .hash = Hash.ZEROES });
        var ancestors: [1]SlotAndHash = undefined;
        var index: usize = 0;

        while (iterator.next()) |ancestor| {
            if (index >= ancestors.len) {
                std.testing.expect(false) catch @panic("Test failed: More than 1 ancestors.");
            }
            ancestors[index] = ancestor;
            index += 1;
        }

        try std.testing.expectEqual(
            ancestors[0],
            SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
        );
    }
    {
        var iterator = fork_choice.ancestorIterator(SlotAndHash{ .slot = 0, .hash = Hash.ZEROES });
        try std.testing.expectEqual(null, iterator.next());
    }
    {
        // Set a root, everything but slots 2, 4 should be removed
        try fork_choice.setTreeRoot(&.{ .slot = 2, .hash = Hash.ZEROES });
        var iterator = fork_choice.ancestorIterator(SlotAndHash{ .slot = 4, .hash = Hash.ZEROES });
        var ancestors: [1]SlotAndHash = undefined;
        var index: usize = 0;

        while (iterator.next()) |ancestor| {
            if (index >= ancestors.len) {
                std.testing.expect(false) catch @panic("Test failed: More than 1 ancestors.");
            }
            ancestors[index] = ancestor;
            index += 1;
        }

        try std.testing.expectEqual(
            ancestors[0],
            SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
        );
    }
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1685
test "HeaviestSubtreeForkChoice.setTreeRoot" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();
    // Set root to 1, should only purge 0
    const root1 = SlotAndHash{ .slot = 1, .hash = Hash.ZEROES };
    try fork_choice.setTreeRoot(&root1);
    for (0..6) |i| {
        const slot_hash = SlotAndHash{ .slot = @intCast(i), .hash = Hash.ZEROES };
        const exists = i != 0;
        try std.testing.expectEqual(exists, fork_choice.fork_infos.contains(slot_hash));
    }
}

// [Agave] https://github.com/anza-xyz/agave/blob/4f9ad7a42b14ed681fb6412c104b3df5c310d50f/core/src/consensus/heaviest_subtree_fork_choice.rs#L1918
test "HeaviestSubtreeForkChoice.propagateNewLeaf" {
    // Staring fork choice:
    // (0)
    // ├── heaviest_slot: (4)
    // ├── deepest_slot: (6)
    // ├── stake_voted_subtree: 0
    // └── (1)
    //     ├── heaviest_slot: (4)
    //     ├── deepest_slot: (6)
    //     ├── stake_voted_subtree: 0
    //     ├── (2)
    //     │   ├── heaviest_slot: (4)
    //     │   ├── deepest_slot: (4)
    //     │   ├── stake_voted_subtree: 0
    //     │   └── (4)
    //     │       ├── heaviest_slot: (4)
    //     │       ├── deepest_slot: (4)
    //     │       └── stake_voted_subtree: 0
    //     └── (3)
    //         ├── heaviest_slot: (6)
    //         ├── deepest_slot: (6)
    //         ├── stake_voted_subtree: 0
    //         └── (5)
    //             ├── heaviest_slot: (6)
    //             ├── deepest_slot: (6)
    //             ├── stake_voted_subtree: 0
    //             └── (6)
    //                 ├── heaviest_slot: (6)
    //                 ├── deepest_slot: (6)
    //                 └── stake_voted_subtree: 0
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();

    // Add a leaf 10 as child of leaf 4, it should be the heaviest and deepest choice
    // (0)
    // ├── heaviest_slot: (10)
    // ├── deepest_slot: (10)
    // ├── stake_voted_subtree: 0
    // └── (1)
    //     ├── heaviest_slot: (10)
    //     ├── deepest_slot: (10)
    //     ├── stake_voted_subtree: 0
    //     ├── (2)
    //     │   ├── heaviest_slot: (10)
    //     │   ├── deepest_slot: (10)
    //     │   ├── stake_voted_subtree: 0
    //     │   └── (4)
    //     │       ├── heaviest_slot: (10)
    //     │       ├── deepest_slot: (10)
    //     │       ├── stake_voted_subtree: 0
    //     │       └── (10) ---------------------------new leaf 10 added as child of 4
    //     │           ├── heaviest_slot: (10)
    //     │           ├── deepest_slot: (10)
    //     │           └── stake_voted_subtree: 0
    //     └── (3)
    //         ├── heaviest_slot: (6)
    //         ├── deepest_slot: (6)
    //         ├── stake_voted_subtree: 0
    //         └── (5)
    //             ├── heaviest_slot: (6)
    //             ├── deepest_slot: (6)
    //             ├── stake_voted_subtree: 0
    //             └── (6)
    //                 ├── heaviest_slot: (6)
    //                 ├── deepest_slot: (6)
    //                 └── stake_voted_subtree: 0
    try fork_choice.addNewLeafSlot(
        .{ .slot = 10, .hash = Hash.ZEROES },
        .{ .slot = 4, .hash = Hash.ZEROES },
    );

    // New leaf 10, should be the heaviest and deepest choice for all ancestors
    var ancestors_of_10 = fork_choice.ancestorIterator(
        SlotAndHash{ .slot = 10, .hash = Hash.ZEROES },
    );
    while (ancestors_of_10.next()) |item| {
        try std.testing.expectEqual(10, fork_choice.heaviestSlot(item).?.slot);
        try std.testing.expectEqual(10, fork_choice.deepestSlot(&item).?.slot);
    }
    // Add a smaller leaf 9 as child of leaf 4, it should be the heaviest and deepest choice
    // (0)
    // ├── heaviest_slot: (9)
    // ├── deepest_slot: (9)
    // ├── stake_voted_subtree: 0
    // └── (1)
    //     ├── heaviest_slot: (9)
    //     ├── deepest_slot: (9)
    //     ├── stake_voted_subtree: 0
    //     ├── (2)
    //     │   ├── heaviest_slot: (9)
    //     │   ├── deepest_slot: (9)
    //     │   ├── stake_voted_subtree: 0
    //     │   └── (4)
    //     │       ├── heaviest_slot: (9)
    //     │       ├── deepest_slot: (9)
    //     │       ├── stake_voted_subtree: 0
    //     │       ├── (9) ---------------------------new leaf 9 added as child of 4
    //     │       │   ├── heaviest_slot: (9)
    //     │       │   ├── deepest_slot: (9)
    //     │       │   └── stake_voted_subtree: 0
    //     │       └── (10)
    //     │           ├── heaviest_slot: (10)
    //     │           ├── deepest_slot: (10)
    //     │           └── stake_voted_subtree: 0
    //     └── (3)
    //         ├── heaviest_slot: (6)
    //         ├── deepest_slot: (6)
    //         ├── stake_voted_subtree: 0
    //         └── (5)
    //             ├── heaviest_slot: (6)
    //             ├── deepest_slot: (6)
    //             ├── stake_voted_subtree: 0
    //             └── (6)
    //                 ├── heaviest_slot: (6)
    //                 ├── deepest_slot: (6)
    //                 └── stake_voted_subtree: 0
    try fork_choice.addNewLeafSlot(
        .{ .slot = 9, .hash = Hash.ZEROES },
        .{ .slot = 4, .hash = Hash.ZEROES },
    );
    // New leaf 9, should be the heaviest and deepest choice for all ancestors
    var ancestors_of_9 = fork_choice.ancestorIterator(
        SlotAndHash{ .slot = 10, .hash = Hash.ZEROES },
    );
    while (ancestors_of_9.next()) |item| {
        try std.testing.expectEqual(9, fork_choice.heaviestSlot(item).?.slot);
        try std.testing.expectEqual(9, fork_choice.deepestSlot(&item).?.slot);
    }
    // TODO complete test when vote related functions are implemented
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1863
test "HeaviestSubtreeForkChoice.heaviestOverallSlot" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();
    try std.testing.expectEqual(
        fork_choice.heaviestOverallSlot(),
        SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
    );
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L2078
test "HeaviestSubtreeForkChoice.aggregateSlot" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();

    fork_choice.aggregateSlot(.{ .slot = 1, .hash = Hash.ZEROES });

    // No weights are present, weights should be zero
    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSlot(&.{ .slot = 1, .hash = Hash.ZEROES }),
    );

    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSubtree(&.{ .slot = 1, .hash = Hash.ZEROES }),
    );

    // The heaviest leaf when weights are equal should prioritize the lower leaf
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        fork_choice.heaviestSlot(.{ .slot = 1, .hash = Hash.ZEROES }),
    );
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        fork_choice.heaviestSlot(.{ .slot = 2, .hash = Hash.ZEROES }),
    );
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
        fork_choice.heaviestSlot(.{ .slot = 3, .hash = Hash.ZEROES }),
    );
    // The deepest leaf only tiebreaks by slot # when tree heights are equal
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
        fork_choice.deepestSlot(&.{ .slot = 1, .hash = Hash.ZEROES }),
    );
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        fork_choice.deepestSlot(&.{ .slot = 2, .hash = Hash.ZEROES }),
    );
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
        fork_choice.deepestSlot(&.{ .slot = 3, .hash = Hash.ZEROES }),
    );

    // Update the weights that have voted *exactly* at each slot, the
    // branch containing slots {5, 6} has weight 11, so should be heavier
    // than the branch containing slots {2, 4}

    var total_stake: usize = 0;
    var staked_voted_slots = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer staked_voted_slots.deinit();

    // Add slots to the set
    const slots = [_]u64{ 2, 4, 5, 6 };
    for (slots) |slot| {
        try staked_voted_slots.put(slot, {});
    }

    var it = staked_voted_slots.keyIterator();
    while (it.next()) |slot| {
        fork_choice.setStakeVotedAt(
            &.{ .slot = slot.*, .hash = Hash.ZEROES },
            slot.*,
        );
        total_stake += slot.*;
    }

    var slots_to_aggregate = std.ArrayList(SlotAndHash).init(std.testing.allocator);
    defer slots_to_aggregate.deinit();

    try slots_to_aggregate.append(SlotAndHash{ .slot = 6, .hash = Hash.ZEROES });

    var ancestors_of_6 = fork_choice.ancestorIterator(
        SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
    );
    while (ancestors_of_6.next()) |item| {
        try slots_to_aggregate.append(item);
    }

    try slots_to_aggregate.append(SlotAndHash{ .slot = 4, .hash = Hash.ZEROES });

    var ancestors_of_4 = fork_choice.ancestorIterator(
        SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
    );
    while (ancestors_of_4.next()) |item| {
        try slots_to_aggregate.append(item);
    }

    for (slots_to_aggregate.items) |slot_hash| {
        fork_choice.aggregateSlot(slot_hash);
    }

    // The best path is now 0 -> 1 -> 3 -> 5 -> 6, so leaf 6
    // should be the best choice
    // It is still the deepest choice
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
        fork_choice.heaviestOverallSlot(),
    );

    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
        fork_choice.deepestOverallSlot(),
    );

    for (0..7) |slot| {
        const expected_stake: u64 = if (staked_voted_slots.contains(slot))
            slot
        else
            0;

        try std.testing.expectEqual(
            expected_stake,
            fork_choice.stakeForSlot(&.{ .slot = slot, .hash = Hash.ZEROES }),
        );
    }

    // Verify `stake_for_subtree` for common fork
    for ([_]u64{ 0, 1 }) |slot| {
        // Subtree stake is sum of the `stake_for_slot` across
        // all slots in the subtree
        try std.testing.expectEqual(
            total_stake,
            fork_choice.stakeForSubtree(&.{ .slot = slot, .hash = Hash.ZEROES }),
        );
    }

    {
        // Verify `stake_for_subtree` for fork 1
        var total_expected_stake: u64 = 0;
        for ([_]u64{ 4, 2 }) |slot| {
            total_expected_stake += fork_choice.stakeForSlot(
                &.{ .slot = slot, .hash = Hash.ZEROES },
            ).?;
            try std.testing.expectEqual(
                total_expected_stake,
                fork_choice.stakeForSubtree(&.{ .slot = slot, .hash = Hash.ZEROES }),
            );
        }
    }

    {
        // Verify `stake_for_subtree` for fork 2
        var total_expected_stake: u64 = 0;
        for ([_]u64{ 6, 5, 3 }) |slot| {
            total_expected_stake += fork_choice.stakeForSlot(
                &.{ .slot = slot, .hash = Hash.ZEROES },
            ).?;

            try std.testing.expectEqual(
                total_expected_stake,
                fork_choice.stakeForSubtree(&.{ .slot = slot, .hash = Hash.ZEROES }),
            );
        }
    }
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L3012
test "HeaviestSubtreeForkChoice.isHeaviestChild" {
    const tree = [_]TreeNode{
        //
        // (0)
        // └── (4)
        //     ├── (10)
        //     └── (9)
        //
        .{
            SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
            SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
        },
        .{
            SlotAndHash{ .slot = 10, .hash = Hash.ZEROES },
            SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        },
        .{
            SlotAndHash{ .slot = 9, .hash = Hash.ZEROES },
            SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(test_allocator, tree[0..]);
    defer fork_choice.deinit();

    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 0, .hash = Hash.ZEROES }),
    );
    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 4, .hash = Hash.ZEROES }),
    );
    // 9 is better than 10
    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 9, .hash = Hash.ZEROES }),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 10, .hash = Hash.ZEROES })),
    );
    // Add new leaf 8, which is better than 9, as both have weight 0
    //
    // (0)
    // └── (4)
    //     ├── (10)
    //     ├── (9)
    //     └── (8)
    //
    try fork_choice.addNewLeafSlot(
        .{ .slot = 8, .hash = Hash.ZEROES },
        .{ .slot = 4, .hash = Hash.ZEROES },
    );
    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 8, .hash = Hash.ZEROES }),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 9, .hash = Hash.ZEROES })),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 10, .hash = Hash.ZEROES })),
    );
    // TODO complete test when vote related functions are implemented
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1871
test "HeaviestSubtreeForkChoice.addNewLeafSlot_duplicate" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();
    const duplicate_fork = try setupDuplicateForks();
    defer test_allocator.destroy(duplicate_fork.fork_choice);
    defer test_allocator.free(duplicate_fork.duplicate_leaves_descended_from_4);
    defer test_allocator.free(duplicate_fork.duplicate_leaves_descended_from_5);
    defer test_allocator.free(duplicate_fork.duplicate_leaves_descended_from_6);

    var fork_choice = duplicate_fork.fork_choice;
    defer fork_choice.deinit();
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;
    const duplicate_leaves_descended_from_5 = duplicate_fork.duplicate_leaves_descended_from_5;
    // Add a child to one of the duplicates
    const duplicate_parent = duplicate_leaves_descended_from_4[0];
    const child = SlotAndHash{ .slot = 11, .hash = Hash.initRandom(random) };
    try fork_choice.addNewLeafSlot(child, duplicate_parent);
    {
        var children_ = fork_choice.getChildren(&duplicate_parent).?;
        const children = children_.keys();

        try std.testing.expectEqual(child.slot, children[0].slot);
        try std.testing.expectEqual(child.hash, children[0].hash);
    }

    try std.testing.expectEqual(
        child,
        fork_choice.heaviestOverallSlot(),
    );

    // All the other duplicates should have no children
    for (duplicate_leaves_descended_from_5) |duplicate_leaf| {
        try std.testing.expectEqual(
            0,
            fork_choice.getChildren(&duplicate_leaf).?.count(),
        );
    }
    try std.testing.expectEqual(
        0,
        fork_choice.getChildren(&duplicate_leaves_descended_from_4[1]).?.count(),
    );

    // Re-adding same duplicate slot should not overwrite existing one
    try fork_choice.addNewLeafSlot(duplicate_parent, .{ .slot = 4, .hash = Hash.ZEROES });
    {
        var children_ = fork_choice.getChildren(&duplicate_parent).?;
        const children = children_.keys();

        try std.testing.expectEqual(child.slot, children[0].slot);
        try std.testing.expectEqual(child.hash, children[0].hash);
    }

    try std.testing.expectEqual(child, fork_choice.heaviestOverallSlot());
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L3624
test "HeaviestSubtreeForkChoice.markForkValidCandidate" {
    var fork_choice = try forkChoiceForTest(test_allocator, linear_fork_tuples[0..]);
    defer fork_choice.deinit();
    const duplicate_confirmed_slot: Slot = 1;
    const duplicate_confirmed_key: Hash = Hash.ZEROES;
    const candidates = try fork_choice.markForkValidCandidate(&.{
        .slot = duplicate_confirmed_slot,
        .hash = duplicate_confirmed_key,
    });
    defer candidates.deinit();

    {
        var it = fork_choice.fork_infos.keyIterator();

        while (it.next()) |slot_hash_key| {
            const slot = slot_hash_key.slot;
            if (slot <= duplicate_confirmed_slot) {
                try std.testing.expect(fork_choice.isDuplicateConfirmed(slot_hash_key).?);
            } else {
                try std.testing.expect(!fork_choice.isDuplicateConfirmed(slot_hash_key).?);
            }
            try std.testing.expect(fork_choice.latestDuplicateAncestor(slot_hash_key.*) == null);
        }
    }

    // Mark a later descendant invalid
    const invalid_descendant_slot = 5;
    const invalid_descendant_key: Hash = Hash.ZEROES;
    try fork_choice.markForkInvalidCandidate(&.{
        .slot = invalid_descendant_slot,
        .hash = invalid_descendant_key,
    });

    {
        var it = fork_choice.fork_infos.keyIterator();
        while (it.next()) |slot_hash_key| {
            const slot = slot_hash_key.slot;
            if (slot <= duplicate_confirmed_slot) {
                // All ancestors of the duplicate confirmed slot should:
                // 1) Be duplicate confirmed
                // 2) Have no invalid ancestors
                try std.testing.expect(fork_choice.isDuplicateConfirmed(slot_hash_key).?);
                try std.testing.expectEqual(
                    null,
                    fork_choice.latestDuplicateAncestor(slot_hash_key.*),
                );
            } else if (slot >= invalid_descendant_slot) {
                // Anything descended from the invalid slot should:
                // 1) Not be duplicate confirmed
                // 2) Should have an invalid ancestor == `invalid_descendant_slot`
                try std.testing.expect(!fork_choice.isDuplicateConfirmed(slot_hash_key).?);
                try std.testing.expectEqual(
                    invalid_descendant_slot,
                    fork_choice.latestDuplicateAncestor(slot_hash_key.*).?,
                );
            } else {
                // Anything in between the duplicate confirmed slot and the invalid slot should:
                // 1) Not be duplicate confirmed
                // 2) Should not have an invalid ancestor
                try std.testing.expect(!fork_choice.isDuplicateConfirmed(slot_hash_key).?);
                try std.testing.expectEqual(
                    null,
                    fork_choice.latestDuplicateAncestor(slot_hash_key.*),
                );
            }
        }
    }
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L3752
test "HeaviestSubtreeForkChoice.markForkValidandidate_mark_valid_then_ancestor_invalid" {
    var fork_choice = try forkChoiceForTest(test_allocator, linear_fork_tuples[0..]);
    defer fork_choice.deinit();
    const duplicate_confirmed_slot: Slot = 4;
    const duplicate_confirmed_key: Hash = Hash.ZEROES;
    const candidates = try fork_choice.markForkValidCandidate(&.{
        .slot = duplicate_confirmed_slot,
        .hash = duplicate_confirmed_key,
    });
    defer candidates.deinit();

    // Now mark an ancestor of this fork invalid, should return an error since this ancestor
    // was duplicate confirmed by its descendant 4 already
    try std.testing.expectError(
        error.DuplicateConfirmedCannotBeMarkedInvalid,
        fork_choice.markForkInvalidCandidate(&.{
            .slot = 3,
            .hash = Hash.ZEROES,
        }),
    );
}

test "HeaviestSubtreeForkChoice.isStrictAncestor_maybe_ancestor_same_as_key" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();

    const key = SlotAndHash{ .slot = 10, .hash = Hash.ZEROES };

    try std.testing.expect(!fork_choice.isStrictAncestor(&key, &key));
}

test "HeaviestSubtreeForkChoice.isStrictAncestor_maybe_ancestor_slot_greater_than_key" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();

    const key = SlotAndHash{ .slot = 10, .hash = Hash.ZEROES };
    const maybe_ancestor = SlotAndHash{ .slot = 11, .hash = Hash.ZEROES };

    try std.testing.expect(!fork_choice.isStrictAncestor(&maybe_ancestor, &key));
}

test "HeaviestSubtreeForkChoice.isStrictAncestor_not_maybe_ancestor" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();

    const key = SlotAndHash{ .slot = 5, .hash = Hash.ZEROES };
    const maybe_ancestor = SlotAndHash{ .slot = 4, .hash = Hash.ZEROES };

    try std.testing.expect(!fork_choice.isStrictAncestor(&maybe_ancestor, &key));
}

test "HeaviestSubtreeForkChoice.isStrictAncestor_is_maybe_ancestor" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();

    const key = SlotAndHash{ .slot = 5, .hash = Hash.ZEROES };
    const maybe_ancestor = SlotAndHash{ .slot = 1, .hash = Hash.ZEROES };

    try std.testing.expect(fork_choice.isStrictAncestor(&maybe_ancestor, &key));
}

test "HeaviestSubtreeForkChoice.heaviestSlotOnSameVotedFork_stray_restored_slot" {
    const tree = [_]TreeNode{
        //
        // (0)
        // └── (1)
        //     ├── (2)
        //
        .{
            SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
            SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
        },
        .{
            SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
            SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(test_allocator, tree[0..]);
    defer fork_choice.deinit();

    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(test_allocator);
    _ = try replay_tower.recordBankVote(test_allocator, 1, Hash.ZEROES);

    try std.testing.expect(!replay_tower.isStrayLastVote());
    try std.testing.expectEqualDeep(
        SlotAndHash{ .slot = @as(Slot, 2), .hash = Hash.ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // Make slot 1 (existing in bank_forks) a restored stray slot
    var slot_history = try createTestSlotHistory(test_allocator);
    defer slot_history.deinit(test_allocator);

    slot_history.add(0);
    // Work around TooOldSlotHistory
    slot_history.add(999);

    try replay_tower.adjustLockoutsAfterReplay(test_allocator, 0, &slot_history);

    try std.testing.expect(replay_tower.isStrayLastVote());
    try std.testing.expectEqual(
        SlotAndHash{ .slot = @as(Slot, 2), .hash = Hash.ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // Make slot 3 (NOT existing in bank_forks) a restored stray slot
    _ = try replay_tower.recordBankVote(test_allocator, 3, Hash.ZEROES);
    try replay_tower.adjustLockoutsAfterReplay(test_allocator, 0, &slot_history);

    try std.testing.expect(replay_tower.isStrayLastVote());
    try std.testing.expectEqual(
        null,
        try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower),
    );
}

test "HeaviestSubtreeForkChoice.heaviestSlotOnSameVotedFork_last_voted_not_found" {
    var fork_choice = try forkChoiceForTest(test_allocator, fork_tuples[0..]);
    defer fork_choice.deinit();

    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(test_allocator);

    try std.testing.expectEqualDeep(
        null,
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)),
    );
}

test "HeaviestSubtreeForkChoice.heaviestSlotOnSameVotedFork_use_deepest_slot" {
    const tree = [_]TreeNode{
        //
        // (0)
        // └── (1)
        //     ├── (2)
        //
        .{
            SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
            SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
        },
        .{
            SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
            SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(test_allocator, &tree);
    defer fork_choice.deinit();

    // Create a tower that voted on slot 1.
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(test_allocator);
    _ = try replay_tower.recordBankVote(test_allocator, 1, Hash.ZEROES);

    // Initially, slot 1 is valid so we get the heaviest slot (which would be 2)
    try std.testing.expectEqualDeep(
        SlotAndHash{ .slot = @as(Slot, 2), .hash = Hash.ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // Now mark slot 1 as invalid
    try fork_choice.markForkInvalidCandidate(
        &SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
    );
    try std.testing.expect(
        !fork_choice.isCandidate(&SlotAndHash{ .slot = 1, .hash = Hash.ZEROES }).?,
    );

    // Now heaviestSlotOnSameVotedFork should return the deepest slot (2)
    // even though the fork is invalid
    try std.testing.expectEqualDeep(
        SlotAndHash{ .slot = @as(Slot, 2), .hash = Hash.ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );
}

test "HeaviestSubtreeForkChoice.heaviestSlotOnSameVotedFork_missing_candidate" {
    const tree = [_]TreeNode{
        //
        // (0)
        // └── (1)
        //
        .{
            SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
            SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(test_allocator, &tree);
    defer fork_choice.deinit();

    // Create a tower that voted on slot 2 which doesn't exist in the fork choice.
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(test_allocator);
    _ = try replay_tower.recordBankVote(test_allocator, 2, Hash.ZEROES);

    try std.testing.expect(!replay_tower.isStrayLastVote());

    try std.testing.expectError(
        error.MissingCandidate,
        fork_choice.heaviestSlotOnSameVotedFork(&replay_tower),
    );
}

pub fn forkChoiceForTest(
    allocator: std.mem.Allocator,
    forks: []const TreeNode,
) !ForkChoice {
    if (!builtin.is_test) {
        @compileError("initForTest should only be called in test mode");
    }

    const root = forks[0][1].?;
    var fork_choice = try ForkChoice.init(
        allocator,
        .noop,
        root,
    );
    errdefer fork_choice.deinit();

    for (forks) |fork_tuple| {
        const slot_hash = fork_tuple[0];
        if (fork_choice.fork_infos.contains(slot_hash)) {
            continue;
        }
        const parent_slot_hash = fork_tuple[1];
        try fork_choice.addNewLeafSlot(slot_hash, parent_slot_hash);
    }

    return fork_choice;
}

pub const TreeNode = std.meta.Tuple(&.{ SlotAndHash, ?SlotAndHash });

pub const fork_tuples = [_]TreeNode{
    // (0)
    // └── (1)
    //     ├── (2)
    //     │   └── (4)
    //     └── (3)
    //         └── (5)
    //             └── (6)
    //
    // slot 1 is a child of slot 0
    .{
        SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    },
    // slot 2 is a child of slot 1
    .{
        SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
    },
    // slot 4 is a child of slot 2
    .{
        SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
    },
    // slot 3 is a child of slot 1
    .{
        SlotAndHash{ .slot = 3, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
    },
    // slot 5 is a child of slot 3
    .{
        SlotAndHash{ .slot = 5, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 3, .hash = Hash.ZEROES },
    },
    // slot 6 is a child of slot 5
    .{
        SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 5, .hash = Hash.ZEROES },
    },
};

const linear_fork_tuples = [_]TreeNode{
    // (0)
    // └── (1)
    //     └── (2)
    //         └── (3)
    //             └── (4)
    //                 └── (5)
    //                     └── (6)
    .{
        SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 0, .hash = Hash.ZEROES },
    },
    // slot 2 is a child of slot 1
    .{
        SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 1, .hash = Hash.ZEROES },
    },
    // slot 3 is a child of slot 2
    .{
        SlotAndHash{ .slot = 3, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 2, .hash = Hash.ZEROES },
    },
    // slot 4 is a child of slot 3
    .{
        SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 3, .hash = Hash.ZEROES },
    },
    // slot 5 is a child of slot 4
    .{
        SlotAndHash{ .slot = 5, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 4, .hash = Hash.ZEROES },
    },
    // slot 6 is a child of slot 5
    .{
        SlotAndHash{ .slot = 6, .hash = Hash.ZEROES },
        SlotAndHash{ .slot = 5, .hash = Hash.ZEROES },
    },
};

fn compareSlotHashKey(_: void, a: SlotAndHash, b: SlotAndHash) bool {
    if (a.slot == b.slot) {
        return a.hash.order(&b.hash) == .lt;
    }
    return a.slot < b.slot;
}

pub fn setupDuplicateForks() !struct {
    fork_choice: *ForkChoice,
    duplicate_leaves_descended_from_4: []SlotAndHash,
    duplicate_leaves_descended_from_5: []SlotAndHash,
    duplicate_leaves_descended_from_6: []SlotAndHash,
} {
    // (0)
    // └── (1)
    //     ├── (2)
    //     │   └── (4)
    //     │       ├── (10)
    //     │       └── (10)
    //     └── (3)
    //         └── (5)
    //             ├── (6)
    //             │   ├── (10)
    //             │   └── (10)
    //             ├── (10)
    //             └── (10)
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();
    // Build fork structure
    var fork_choice = try test_allocator.create(ForkChoice);
    errdefer test_allocator.destroy(fork_choice);

    fork_choice.* = try forkChoiceForTest(
        test_allocator,
        fork_tuples[0..],
    );

    const duplicate_slot: u64 = 10;

    // Create duplicate leaves descended from slot 4
    var duplicate_leaves_descended_from_4 = std.ArrayList(SlotAndHash).init(test_allocator);
    defer duplicate_leaves_descended_from_4.deinit();
    for (0..2) |_| {
        try duplicate_leaves_descended_from_4.append(SlotAndHash{
            .slot = duplicate_slot,
            .hash = Hash.initRandom(random),
        });
    }

    // Create duplicate leaves descended from slot 5
    var duplicate_leaves_descended_from_5 = std.ArrayList(SlotAndHash).init(test_allocator);
    defer duplicate_leaves_descended_from_5.deinit();
    for (0..2) |_| {
        try duplicate_leaves_descended_from_5.append(SlotAndHash{
            .slot = duplicate_slot,
            .hash = Hash.initRandom(random),
        });
    }

    // Create duplicate leaves descended from slot 6
    var duplicate_leaves_descended_from_6 = std.ArrayList(SlotAndHash).init(test_allocator);
    defer duplicate_leaves_descended_from_6.deinit();
    for (0..2) |_| {
        try duplicate_leaves_descended_from_6.append(SlotAndHash{
            .slot = duplicate_slot,
            .hash = Hash.initRandom(random),
        });
    }

    std.mem.sort(SlotAndHash, duplicate_leaves_descended_from_4.items, {}, compareSlotHashKey);
    std.mem.sort(SlotAndHash, duplicate_leaves_descended_from_5.items, {}, compareSlotHashKey);
    std.mem.sort(SlotAndHash, duplicate_leaves_descended_from_6.items, {}, compareSlotHashKey);

    // Add duplicate leaves to the fork structure
    for (duplicate_leaves_descended_from_4.items) |duplicate_leaf| {
        try fork_choice.addNewLeafSlot(duplicate_leaf, SlotAndHash{
            .slot = 4,
            .hash = Hash.ZEROES,
        });
    }
    for (duplicate_leaves_descended_from_5.items) |duplicate_leaf| {
        try fork_choice.addNewLeafSlot(duplicate_leaf, SlotAndHash{
            .slot = 5,
            .hash = Hash.ZEROES,
        });
    }
    for (duplicate_leaves_descended_from_6.items) |duplicate_leaf| {
        try fork_choice.addNewLeafSlot(duplicate_leaf, SlotAndHash{
            .slot = 6,
            .hash = Hash.ZEROES,
        });
    }

    // Verify children of slot 4
    var dup_children_4 = fork_choice.getChildren(&.{
        .slot = 4,
        .hash = Hash.ZEROES,
    }).?;
    std.mem.sort(SlotAndHash, dup_children_4.mutableKeys(), {}, compareSlotHashKey);
    // std.debug.assert(std.mem.eql(
    //     SlotAndHash,
    //     dup_children_4.keys(),
    //     duplicate_leaves_descended_from_4.items,
    // ));

    // Verify children of slot 5
    var dup_children_5 = fork_choice.getChildren(&.{
        .slot = 5,
        .hash = Hash.ZEROES,
    }).?;
    std.mem.sort(SlotAndHash, dup_children_5.mutableKeys(), {}, compareSlotHashKey);
    // std.debug.assert(
    //     std.mem.eql(SlotAndHash, dup_children_5.keys(), duplicate_leaves_descended_from_5.items),
    // );

    // Verify children of slot 6
    var dup_children_6 = fork_choice.getChildren(&.{
        .slot = 6,
        .hash = Hash.ZEROES,
    }).?;
    std.mem.sort(SlotAndHash, dup_children_6.mutableKeys(), {}, compareSlotHashKey);
    // std.debug.assert(
    //     std.mem.eql(SlotAndHash, dup_children_6.keys(), duplicate_leaves_descended_from_6.items),
    // );

    return .{
        .fork_choice = fork_choice,
        .duplicate_leaves_descended_from_4 = try duplicate_leaves_descended_from_4.toOwnedSlice(),
        .duplicate_leaves_descended_from_5 = try duplicate_leaves_descended_from_5.toOwnedSlice(),
        .duplicate_leaves_descended_from_6 = try duplicate_leaves_descended_from_6.toOwnedSlice(),
    };
}

pub fn splitOff(
    allocator: std.mem.Allocator,
    fork_choice: *ForkChoice,
    slot_hash_key: SlotAndHash,
) !void {
    if (!builtin.is_test) {
        @compileError("splitOff should only be used in test");
    }
    std.debug.assert(!fork_choice.tree_root.equals(slot_hash_key));

    const node_to_split_at = fork_choice.fork_infos.getPtr(slot_hash_key) orelse
        return error.SlotHashKeyNotFound;
    var split_tree_root = node_to_split_at.*;
    const parent = node_to_split_at.parent orelse return error.SplitNodeIsRoot;

    var update_operations = UpdateOperations.init(allocator);
    defer update_operations.deinit();

    try fork_choice.insertAggregateOperations(&update_operations, slot_hash_key);

    const parent_info = fork_choice.fork_infos.getPtr(parent) orelse return error.ParentNotFound;
    std.debug.assert(parent_info.children.orderedRemove(slot_hash_key));

    fork_choice.processUpdateOperations(&update_operations);

    var split_tree_fork_infos = std.AutoHashMap(SlotAndHash, ForkInfo).init(allocator);
    defer {
        var it = split_tree_fork_infos.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        split_tree_fork_infos.deinit();
    }
    var to_visit = std.ArrayList(SlotAndHash).init(allocator);
    defer to_visit.deinit();

    try to_visit.append(slot_hash_key);

    while (to_visit.pop()) |cuurent_slot_hash_key| {
        var current_fork_info = fork_choice.fork_infos.fetchRemove(cuurent_slot_hash_key) orelse
            return error.NodeNotFound;

        var iter = current_fork_info.value.children.iterator();
        while (iter.next()) |child| {
            try to_visit.append(child.key_ptr.*);
        }

        try split_tree_fork_infos.put(cuurent_slot_hash_key, current_fork_info.value);
    }

    const split_parent = split_tree_root.parent orelse return error.CannotSplitFromRoot;
    const parent_fork_info = fork_choice.fork_infos.getPtr(split_parent) orelse
        return error.ParentNotFound;
    _ = parent_fork_info.children.swapRemoveNoSort(slot_hash_key);

    split_tree_root.parent = null;
    try split_tree_fork_infos.put(slot_hash_key, split_tree_root);

    var split_tree_latest_votes = try fork_choice.latest_votes.clone();
    defer split_tree_latest_votes.deinit();
    var it = split_tree_latest_votes.iterator();
    while (it.next()) |entry| {
        if (!split_tree_fork_infos.contains(entry.value_ptr.*)) {
            _ = split_tree_latest_votes.removeByPtr(entry.key_ptr);
        }
    }

    var it_self = fork_choice.latest_votes.iterator();
    while (it_self.next()) |entry| {
        if (!fork_choice.fork_infos.contains(entry.value_ptr.*)) {
            _ = fork_choice.latest_votes.removeByPtr(entry.key_ptr);
        }
    }
}
