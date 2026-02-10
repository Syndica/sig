const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const Instant = sig.time.Instant;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SortedMap = sig.utils.collections.SortedMapUnmanaged;
const SortedMapCustom = sig.utils.collections.SortedMapUnmanagedCustom;
const SlotAndHash = sig.core.hash.SlotAndHash;
const Slot = sig.core.Slot;
const EpochStakes = sig.core.EpochStakes;
const ReplayTower = sig.consensus.replay_tower.ReplayTower;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;

const Registry = sig.prometheus.Registry;

const Logger = sig.trace.Logger("fork_choice");

const PubkeyVote = struct {
    pubkey: Pubkey,
    slot_hash: SlotAndHash,
};

/// Analogous to [ForkInfo](https://github.com/anza-xyz/agave/blob/e7301b2a29d14df19c3496579cf8e271b493b3c6/core/src/consensus/heaviest_subtree_fork_choice.rs#L92)
const ForkInfo = struct {
    /// Amount of stake that has voted for exactly this slot, i.e. measure of fork weight.
    stake_for_slot: u64,
    /// Amount of stake that has voted for this slot and the subtree rooted at this slot, i.e. measure of fork weight.
    stake_for_subtree: u64,
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
    children: Children,
    /// The latest ancestor of this node that has been marked invalid by being a duplicate.
    /// If the slot itself is a duplicate, this is set to the slot itself.
    latest_duplicate_ancestor: ?Slot,
    /// Set to true if this slot or a child node was duplicate confirmed.
    /// Indicates whether this slot have been confirmed as the valid fork in the presence of duplicate slots.
    /// It means that the network has reached consensus that this fork is the valid one,
    /// and all competing forks for the same slot are invalid.
    is_duplicate_confirmed: bool,

    const Children = SortedMapCustom(SlotAndHash, void, .{
        .orderFn = SlotAndHash.order,
    });

    fn deinit(self: *const ForkInfo, allocator: std.mem.Allocator) void {
        self.children.deinit(allocator);
    }

    /// Returns if this node has been explicitly marked as a duplicate slot
    fn isUnconfirmedDuplicate(self: *const ForkInfo, my_slot: Slot) bool {
        const ancestor = self.latest_duplicate_ancestor orelse return false;
        return ancestor == my_slot;
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
        logger: Logger,
        my_key: *const SlotAndHash,
        newly_duplicate_ancestor: Slot,
    ) void {
        // Check if there is a latest invalid (duplicate) ancestor
        if (self.latest_duplicate_ancestor) |latest_duplicate_ancestor| {
            // If the latest invalid ancestor is less than or equal to the newly valid ancestor,
            // clear the latest invalid ancestor
            if (latest_duplicate_ancestor <= newly_duplicate_ancestor) {
                logger.info().logf(
                    \\ Fork choice for {f} clearing latest invalid ancestor
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
        logger: Logger,
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
            logger.info().logf(
                "Fork choice for {f} setting latest duplicate ancestor from {any} to {}",
                .{ my_key, self.latest_duplicate_ancestor, newly_duplicate_ancestor },
            );
            self.latest_duplicate_ancestor = newly_duplicate_ancestor;
        }
    }
};

/// Analogous to [HeaviestSubtreeForkChoice](https://github.com/anza-xyz/agave/blob/e7301b2a29d14df19c3496579cf8e271b493b3c6/core/src/consensus/heaviest_subtree_fork_choice.rs#L187)
pub const ForkChoice = struct {
    logger: Logger,
    fork_infos: std.AutoArrayHashMapUnmanaged(SlotAndHash, ForkInfo),
    latest_votes: std.AutoArrayHashMapUnmanaged(Pubkey, SlotAndHash),
    tree_root: SlotAndHash,
    last_root_time: Instant,
    metrics: ForkChoiceMetrics,

    pub fn init(
        allocator: std.mem.Allocator,
        logger: Logger,
        tree_root: SlotAndHash,
        registry: *Registry(.{}),
    ) !ForkChoice {
        var self: ForkChoice = .{
            .logger = logger,
            .fork_infos = .empty,
            .latest_votes = .empty,
            .tree_root = tree_root,
            .last_root_time = .now(),
            .metrics = try registry.initStruct(ForkChoiceMetrics),
        };
        try self.addNewLeafSlot(allocator, tree_root, null);
        return self;
    }

    pub fn deinit(self: *const ForkChoice, allocator: std.mem.Allocator) void {
        for (self.fork_infos.values()) |fork_info| {
            fork_info.deinit(allocator);
        }

        var fork_infos = self.fork_infos;
        fork_infos.deinit(allocator);

        var latest_votes = self.latest_votes;
        latest_votes.deinit(allocator);
    }

    /// Updates fork choice metrics based on current state
    fn updateMetrics(self: *const ForkChoice) void {
        const now = Instant.now();
        const update_interval = now.elapsedSince(self.last_root_time);
        self.metrics.update_interval.observe(update_interval.asMicros());
        self.metrics.updates.inc();

        // Calculate basic consensus metrics
        var total_stake: u64 = 0;
        var candidate_count: u64 = 0;
        var maybe_current_heaviest_slot: ?u64 = null;
        var maybe_current_deepest_slot: ?u64 = null;

        for (self.fork_infos.values()) |*fork_info| {
            total_stake += fork_info.stake_for_slot;

            // Count active forks (those that are candidates)
            if (!fork_info.isCandidate()) continue;

            candidate_count += 1;

            if (maybe_current_heaviest_slot) |current_heaviest_slot| {
                if (fork_info.heaviest_subtree_slot.slot > current_heaviest_slot) {
                    maybe_current_heaviest_slot = fork_info.heaviest_subtree_slot.slot;
                }
            }

            if (maybe_current_deepest_slot) |current_deepest_slot| {
                if (fork_info.deepest_slot.slot > current_deepest_slot) {
                    maybe_current_deepest_slot = fork_info.deepest_slot.slot;
                }
            }
        }

        self.metrics.total_stake_in_tree.set(total_stake);
        self.metrics.active_fork_count.set(candidate_count);

        if (maybe_current_heaviest_slot) |slot| {
            self.metrics.current_heaviest_subtree_slot.set(slot);
        }
        if (maybe_current_deepest_slot) |slot| {
            self.metrics.current_deepest_slot.set(slot);
        }

        self.metrics.current_root_slot.set(self.tree_root.slot);
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
        allocator: std.mem.Allocator,
        slot_hash_key: SlotAndHash,
        maybe_parent: ?SlotAndHash,
    ) !void {
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
            try self.fork_infos.put(allocator, slot_hash_key, .{
                .stake_for_slot = 0,
                .stake_for_subtree = 0,
                .height = 1,
                // The `heaviest_slot` and `deepest_slot` of a leaf is itself
                .heaviest_subtree_slot = slot_hash_key,
                .deepest_slot = slot_hash_key,
                .children = .empty,
                .parent = maybe_parent,
                .latest_duplicate_ancestor = parent_latest_duplicate_ancestor,
                // If the parent is none, then this is the root, which implies this must
                // have reached the duplicate confirmed threshold
                .is_duplicate_confirmed = (maybe_parent == null),
            });
        }

        // If no parent is given then we are done.
        const parent = if (maybe_parent) |parent| parent else return;

        if (self.fork_infos.getPtr(parent)) |parent_fork_info| {
            try parent_fork_info.children.put(allocator, slot_hash_key, {});
        } else {
            // If parent is given then parent's info must
            // already exist by time child is being added.
            return error.MissingParent;
        }

        try self.propagateNewLeaf(&slot_hash_key, &parent);
        // TODO: Revisit, this was set first in the Agave code.
        self.last_root_time = .now();

        // Update metrics after adding new leaf
        self.updateMetrics();
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

    /// Add new votes, returns the best slot
    ///
    /// Analogous to [add_votes](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L343)
    pub fn addVotes(
        self: *ForkChoice,
        allocator: std.mem.Allocator,
        pubkey_votes: []const PubkeyVote,
        epoch_tracker: *const sig.core.EpochTracker,
    ) (std.mem.Allocator.Error || error{MultipleVotesForPubKey})!SlotAndHash {
        const noop_ctx: struct {
            pub fn addSlotStake(_: @This(), slot_hash_key: SlotAndHash, stake: u64) !void {
                _ = slot_hash_key;
                _ = stake;
            }

            pub fn subtractSlotStake(_: @This(), slot_hash_key: SlotAndHash, stake: u64) !void {
                _ = slot_hash_key;
                _ = stake;
            }

            pub fn aggregateSlot(_: @This(), slot_hash_key: SlotAndHash) !void {
                _ = slot_hash_key;
            }
        } = .{};
        return try self.addVotesWithCallbacks(
            allocator,
            pubkey_votes,
            epoch_tracker,
            noop_ctx,
        );
    }

    /// Executes operations for the fork choice tree based on new validator votes.
    ///
    /// This function processes a batch of validator votes and executes operations to:
    /// 1) Remove stake from old votes (if they exist)
    /// 2) Add stake to new votes
    /// 3) Generate aggregate operations for affected forks
    /// While notifying `ctx` about each of these operations in order.
    ///
    /// Key invariants:
    /// - Votes older than the current tree root are ignored (they don't affect fork choice)
    /// - Each pubkey can only appear once in the input batch
    /// - Only the latest vote for each validator is considered (by slot, then by smallest hash)
    /// - Stake is only updated if the validator has stake in the vote's epoch
    ///
    /// Analogous to [generate_update_operations](https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L969),
    /// except all operations are executed immediately instead of being encoded as instructions to execute later.
    fn addVotesWithCallbacks(
        self: *ForkChoice,
        allocator: std.mem.Allocator,
        pubkey_votes: []const PubkeyVote,
        epoch_tracker: *const sig.core.EpochTracker,
        /// Expects a value with methods:
        /// * `fn subtractSlotStake(ctx, slot_hash_key: SlotAndHash, stake: u64) !void`
        /// * `fn aggregateSlot(ctx, slot_hash_key: SlotAndHash) !void`
        /// * `fn addSlotStake(slot_hash_key: SlotAndHash, stake: u64) !void`
        ctx: anytype,
    ) !SlotAndHash {
        // Check for duplicate pubkeys in the same batch.
        for (pubkey_votes, 0..) |current, i| {
            for (pubkey_votes[i + 1 ..]) |next| {
                if (current.pubkey.equals(&next.pubkey)) {
                    return error.MultipleVotesForPubKey;
                }
            }
        }
        self.metrics.pubkey_vote_batch_size.set(pubkey_votes.len);

        try self.latest_votes.ensureUnusedCapacity(allocator, pubkey_votes.len);
        for (pubkey_votes) |pubkey_vote| {
            const pubkey = pubkey_vote.pubkey;
            const new_vote_slot_hash = pubkey_vote.slot_hash;
            const new_vote_slot = new_vote_slot_hash.slot;
            const new_vote_hash = new_vote_slot_hash.hash;

            if (new_vote_slot < self.tree_root.slot) {
                // Votes for slots older than the root are irrelevant
                // because the root represents finalized consensus.
                continue;
            }

            // Single lookup that handles both existing and new entries
            const latest_vote_gop = try self.latest_votes.getOrPut(allocator, pubkey);
            if (latest_vote_gop.found_existing) {
                const old_latest_vote = latest_vote_gop.value_ptr.*;
                const old_latest_vote_slot = old_latest_vote.slot;
                const old_latest_vote_hash = old_latest_vote.hash;

                // Filter out any votes or slots < any slot this pubkey has
                // already voted for, we only care about the latest votes.
                //
                // If the new vote is for the same slot, but a different, smaller hash,
                // then allow processing to continue as this is a duplicate version
                // of the same slot.
                if (new_vote_slot < old_latest_vote_slot or
                    (new_vote_slot == old_latest_vote_slot and
                        new_vote_hash.order(&old_latest_vote_hash) != .lt))
                {
                    continue;
                }

                const stake_update = stake_update: {
                    const epoch_info = epoch_tracker.getEpochInfo(old_latest_vote_slot) catch
                        break :stake_update 0;
                    const stake_and_vote_account =
                        epoch_info.stakes.stakes.vote_accounts.vote_accounts.get(pubkey) orelse
                        break :stake_update 0;
                    break :stake_update stake_and_vote_account.stake;
                };

                if (stake_update > 0) {
                    self.subtractSlotStake(&old_latest_vote, stake_update);
                    try ctx.subtractSlotStake(old_latest_vote, stake_update);

                    var parent_iter = self.ancestorIterator(old_latest_vote);
                    while (parent_iter.next()) |parent_slot_hash_key| {
                        self.aggregateSlot(parent_slot_hash_key);
                        try ctx.aggregateSlot(parent_slot_hash_key);
                    }
                }
            }

            // Update to new vote (whether new entry or replacing old)
            latest_vote_gop.value_ptr.* = new_vote_slot_hash;

            // Add this pubkey stake to new fork
            const stake_update: u64 = stake_update: {
                const epoch_info = epoch_tracker.getEpochInfo(new_vote_slot_hash.slot) catch
                    break :stake_update 0;
                const stake_and_vote_account =
                    epoch_info.stakes.stakes.vote_accounts.vote_accounts.get(pubkey) orelse
                    break :stake_update 0;
                break :stake_update stake_and_vote_account.stake;
            };

            if (stake_update > 0) {
                self.addSlotStake(&new_vote_slot_hash, stake_update);
                try ctx.addSlotStake(new_vote_slot_hash, stake_update);

                var parent_iter = self.ancestorIterator(new_vote_slot_hash);
                while (parent_iter.next()) |parent_slot_hash_key| {
                    self.aggregateSlot(parent_slot_hash_key);
                    try ctx.aggregateSlot(parent_slot_hash_key);
                }
            }
        }

        // Update metrics after processing votes
        self.updateMetrics();

        return self.heaviestOverallSlot();
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
    pub fn setTreeRoot(
        self: *ForkChoice,
        allocator: std.mem.Allocator,
        new_root: *const SlotAndHash,
    ) !void {
        // Remove everything reachable from old root but not new root
        var remove_set = try self.subtreeDiff(allocator, &self.tree_root, new_root);
        defer remove_set.deinit(allocator);

        for (remove_set.keys()) |node_key| {
            if (!self.fork_infos.contains(node_key)) {
                return error.MissingForkInfo;
            }
        }

        // Root to be made the new root should already exist in fork choice.
        if (!self.fork_infos.contains(new_root.*)) {
            return error.MissingForkInfo;
        }

        // At this point, both the subtree to be removed and new root
        // are confirmed to be in the fork choice.

        for (remove_set.keys()) |node_key| {
            // SAFETY: Previous contains check ensures this won't panic.
            const kv = self.fork_infos.fetchSwapRemove(node_key).?;
            kv.value.deinit(allocator);
        }

        const root_fork_info = self.fork_infos.getPtr(new_root.*) orelse
            return error.MissingForkInfo;
        root_fork_info.parent = null;
        self.tree_root = new_root.*;
        self.last_root_time = .now();

        // Log the new root update
        self.logger.info().logf("fork_choice: new root set to slot={} hash={f}", .{
            new_root.slot,
            new_root.hash,
        });

        // Update metrics after changing tree root
        self.updateMetrics();
    }

    /// Adds a new root parent to the fork choice tree. This is used when we need to
    /// insert a new slot that becomes the root of the entire tree.
    ///
    /// It expects `root_parent.slot` to be less than `self.tree_root.slot`
    /// and `root_parent` must not already exist in the fork choice.
    ///
    /// Analogous to [add_root_parent](https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L421)
    pub fn addRootParent(
        self: *ForkChoice,
        allocator: std.mem.Allocator,
        root_parent: SlotAndHash,
    ) std.mem.Allocator.Error!void {
        // Assert that the new root parent has a smaller slot than the current root
        std.debug.assert(root_parent.slot < self.tree_root.slot);
        // Assert that the root parent doesn't already exist
        std.debug.assert(!self.fork_infos.contains(root_parent));
        // Assert that the current root exists in fork_infos
        std.debug.assert(self.fork_infos.contains(self.tree_root));

        // Get the current root's fork info (safe due to previous assertion)
        const root_info = self.fork_infos.getPtr(self.tree_root).?;

        // Set the current root's parent to the new root parent
        root_info.parent = root_parent;

        try self.fork_infos.ensureUnusedCapacity(allocator, 1);
        // Create the new root parent's fork info
        var root_parent_children: ForkInfo.Children = .empty;
        try root_parent_children.put(allocator, self.tree_root, {});
        errdefer comptime unreachable;

        self.fork_infos.putAssumeCapacityNoClobber(root_parent, .{
            .stake_for_slot = 0,
            .stake_for_subtree = root_info.stake_for_subtree,
            .height = root_info.height + 1,
            // The `heaviest_subtree_slot` and `deepest_slot` do not change
            .deepest_slot = root_info.deepest_slot,
            .heaviest_subtree_slot = root_info.heaviest_subtree_slot,
            .children = root_parent_children,
            .parent = null,
            .latest_duplicate_ancestor = null,
            .is_duplicate_confirmed = root_info.is_duplicate_confirmed,
        });
        self.tree_root = root_parent;

        // Log the new root parent update
        self.logger.info().logf("fork_choice: new root parent set to slot={} hash={f}", .{
            root_parent.slot,
            root_parent.hash,
        });

        // Update metrics after changing tree root
        self.updateMetrics();
    }

    pub fn isDuplicateConfirmed(
        self: ForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?bool {
        if (self.fork_infos.get(slot_hash_key.*)) |fork_info| {
            return fork_info.is_duplicate_confirmed;
        }
        return null;
    }

    /// Returns if the exact node with the specified key has been explicitly marked as a duplicate
    /// slot (doesn't count ancestors being marked as duplicate).
    pub fn isUnconfirmedDuplicate(self: ForkChoice, slot_hash_key: *const SlotAndHash) ?bool {
        const fork_info = self.fork_infos.get(slot_hash_key.*) orelse return null;
        return fork_info.isUnconfirmedDuplicate(slot_hash_key.slot);
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1358
    pub fn markForkValidCandidate(
        self: *ForkChoice,
        allocator: std.mem.Allocator,
        valid_slot_hash_key: *const SlotAndHash,
        /// Context for telling the caller about all the newly duplicate confirmed ancestors discovered during this call.
        /// Can be set to void to ignore these values.
        ///
        /// Expects methods:
        /// * `fn register(ctx, slot_hash: SlotAndHash) !void`:
        ///   Called when encountering a newly duplicate confirmed ancestor.
        newly_duplicate_confirmed_ancestors_ctx: anytype,
    ) !void {
        const newly_duplicate_confirmed_ancestors: struct {
            inner: @TypeOf(newly_duplicate_confirmed_ancestors_ctx),

            pub fn register(ctx: @This(), slot_hash: SlotAndHash) !void {
                if (@TypeOf(newly_duplicate_confirmed_ancestors_ctx) == void) return;
                try ctx.inner.register(slot_hash);
            }
        } = .{ .inner = newly_duplicate_confirmed_ancestors_ctx };

        if (!(self.isDuplicateConfirmed(valid_slot_hash_key) orelse return error.MissingForkInfo)) {
            try newly_duplicate_confirmed_ancestors.register(valid_slot_hash_key.*);
        }

        var ancestor_iter = self.ancestorIterator(valid_slot_hash_key.*);
        while (ancestor_iter.next()) |ancestor_slot_hash_key| {
            try newly_duplicate_confirmed_ancestors.register(ancestor_slot_hash_key);
        }

        { // Notify all children that a parent was marked as valid, from biggest to smallest slot.
            var children_hash_keys = try self.subtreeDiff(
                allocator,
                valid_slot_hash_key,
                &.{ .slot = 0, .hash = .ZEROES },
            );
            defer children_hash_keys.deinit(allocator);

            const children_hash_keys_keys = children_hash_keys.keys();
            for (1..children_hash_keys_keys.len + 1) |i_plus_one| {
                const rev_i = children_hash_keys.count() - i_plus_one;
                const child_hash_key = children_hash_keys_keys[rev_i];

                self.markForkValid(&child_hash_key, valid_slot_hash_key.slot);
                self.aggregateSlot(child_hash_key);
            }
        }

        // Aggregate across all ancestors to find new heaviest slots excluding this fork
        var parent_iter = self.ancestorIterator(valid_slot_hash_key.*);
        while (parent_iter.next()) |parent_slot_hash_key| {
            self.aggregateSlot(parent_slot_hash_key);
        }
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1330
    pub fn markForkInvalidCandidate(
        self: *ForkChoice,
        allocator: std.mem.Allocator,
        invalid_slot_hash_key: *const SlotAndHash,
    ) !void {
        // Get mutable reference to fork info
        const fork_info = self.fork_infos.getPtr(invalid_slot_hash_key.*) orelse return;

        // Should not be marking duplicate confirmed blocks as invalid candidates
        if (fork_info.is_duplicate_confirmed) {
            return error.DuplicateConfirmedCannotBeMarkedInvalid;
        }

        {
            // Notify all children that a parent was marked as invalid
            var children_hash_keys = try self.subtreeDiff(
                allocator,
                invalid_slot_hash_key,
                &.{ .slot = 0, .hash = .ZEROES },
            );
            defer children_hash_keys.deinit(allocator);

            const children_hash_keys_keys = children_hash_keys.keys();
            for (1..children_hash_keys_keys.len + 1) |i_plus_one| {
                const rev_i = children_hash_keys.count() - i_plus_one;
                const child_hash_key = children_hash_keys_keys[rev_i];

                self.markForkInvalid(child_hash_key, invalid_slot_hash_key.slot);
                self.aggregateSlot(child_hash_key);
            }
        }

        // Aggregate across all ancestors to find new heaviest slots excluding this fork
        var parent_iter = self.ancestorIterator(invalid_slot_hash_key.*);
        while (parent_iter.next()) |parent_slot_hash_key| {
            self.aggregateSlot(parent_slot_hash_key);
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
    ) ?*ForkInfo.Children {
        const fork_info = self.fork_infos.getPtr(slot_hash_key.*) orelse return null;
        return &fork_info.children;
    }

    pub fn latestInvalidAncestor(
        self: *const ForkChoice,
        slot_hash_key: *const SlotAndHash,
    ) ?Slot {
        const fork_info = self.fork_infos.getPtr(slot_hash_key.*) orelse return null;
        return fork_info.latest_duplicate_ancestor;
    }

    pub fn isCandidate(
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
        self: *const ForkChoice,
        allocator: std.mem.Allocator,
        root1: *const SlotAndHash,
        root2: *const SlotAndHash,
    ) (std.mem.Allocator.Error || error{MissingChild})!SortedMap(SlotAndHash, void) {
        if (!self.containsBlock(root1)) return .empty;

        var pending_keys: std.ArrayListUnmanaged(SlotAndHash) = .empty;
        defer pending_keys.deinit(allocator);
        try pending_keys.append(allocator, root1.*);

        var reachable_set: SortedMap(SlotAndHash, void) = .empty;
        errdefer reachable_set.deinit(allocator);

        while (pending_keys.pop()) |current_key| {
            if (current_key.equals(root2.*)) continue;
            const children = self.getChildren(&current_key) orelse return error.MissingChild;
            try pending_keys.appendSlice(allocator, children.keys());
            try reachable_set.put(allocator, current_key, {});
        }

        return reachable_set;
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L950
    ///
    /// Mark that `valid_slot` on the fork starting at `fork_to_modify_key` has been marked
    /// valid. Note we don't need the hash for `valid_slot` because slot number uniquely
    /// identifies a node on a single fork.
    fn markForkValid(
        self: *const ForkChoice,
        fork_to_modify_key: *const SlotAndHash,
        valid_slot: Slot,
    ) void {
        // Try to get a mutable reference to the fork info
        const fork_info_to_modify = self.fork_infos.getPtr(fork_to_modify_key.*) orelse return;
        // Update the fork info with the newly valid ancestor
        fork_info_to_modify.updateWithNewlyValidAncestor(
            self.logger,
            fork_to_modify_key,
            valid_slot,
        );

        // If the fork's key matches the valid slot, mark it as duplicate confirmed
        if (fork_to_modify_key.slot == valid_slot) {
            fork_info_to_modify.is_duplicate_confirmed = true;
        }
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L962
    ///
    /// Mark that `invalid_slot` on the fork starting at `fork_to_modify_key` has been marked
    /// invalid. Note we don't need the hash for `invalid_slot` because slot number uniquely
    /// identifies a node on a single fork.
    fn markForkInvalid(
        self: *const ForkChoice,
        fork_to_modify_key: SlotAndHash,
        invalid_slot: Slot,
    ) void {
        // Try to get a mutable reference to the fork info
        const fork_info_to_modify = self.fork_infos.getPtr(fork_to_modify_key) orelse return;
        // Update the fork info with the newly invalid ancestor
        fork_info_to_modify.updateWithNewlyInvalidAncestor(
            self.logger,
            &fork_to_modify_key,
            invalid_slot,
        );
    }

    /// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L850
    ///
    /// Aggregates stake and height information for the subtree rooted at `slot_hash_key`.
    /// Updates the fork info with the aggregated values.
    fn aggregateSlot(self: *const ForkChoice, slot_hash_key: SlotAndHash) void {
        var stake_for_subtree: u64 = 0;
        var deepest_child_height: u64 = 0;
        var heaviest_slot_hash_key: SlotAndHash = slot_hash_key;
        var deepest_slot_hash_key: SlotAndHash = slot_hash_key;
        var is_duplicate_confirmed: bool = false;

        // Get the fork info for the given slot_hash_key
        // If the fork info does not exist, return early
        const fork_info = self.fork_infos.getPtr(slot_hash_key) orelse return;

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
            const is_heavier_child = child_stake_for_subtree > deepest_child_stake_for_subtree;
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

        // Update the fork info with the aggregated values
        if (is_duplicate_confirmed and !fork_info.is_duplicate_confirmed) {
            self.logger.info().logf(
                "Fork choice setting {f} to duplicate confirmed",
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
        self: *const ForkChoice,
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
        self: *const ForkChoice,
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
        return .{
            .current_slot_hash_key = start_slot_hash_key,
            .fork_infos = &self.fork_infos,
        };
    }

    /// Updates fork choice statistics by processing new validator votes.
    ///
    /// Analogous to [compute_bank_stats](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L1250)
    pub fn processLatestVotes(
        self: *ForkChoice,
        allocator: std.mem.Allocator,
        epoch_tracker: *const sig.core.EpochTracker,
        latest_validator_votes: *LatestValidatorVotes,
    ) !void {
        const root = self.tree_root.slot;

        var new_votes: std.ArrayListUnmanaged(PubkeyVote) = .empty;
        defer new_votes.deinit(allocator);

        const dirty_votest = try latest_validator_votes.takeVotesDirtySet(allocator, root);
        defer allocator.free(dirty_votest);

        try new_votes.ensureUnusedCapacity(allocator, dirty_votest.len);
        for (dirty_votest) |vote_tuple| {
            const pubkey, const slot_hash = vote_tuple;
            new_votes.appendAssumeCapacity(.{
                .pubkey = pubkey,
                .slot_hash = slot_hash,
            });
        }

        _ = try self.addVotes(
            allocator,
            new_votes.items,
            epoch_tracker,
        );
    }

    /// Split off the node at `slot_hash_key` and propagate the stake subtraction up to the root of the
    /// tree.
    ///
    /// Assumes that `slot_hash_key` is not the `tree_root`
    /// Returns the subtree originating from `slot_hash_key`
    ///
    /// Analogous to [split_off](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L581)
    pub fn splitOff(
        self: *ForkChoice,
        allocator: std.mem.Allocator,
        registry: *sig.prometheus.Registry(.{}),
        slot_hash_key: SlotAndHash,
    ) !ForkChoice {
        if (!builtin.is_test) {
            @compileError("splitOff should only be used in test");
        }
        std.debug.assert(!self.tree_root.equals(slot_hash_key));

        var split_tree_root = self.fork_infos.get(slot_hash_key) orelse
            return error.SlotHashKeyNotFound;
        const parent = split_tree_root.parent orelse
            return error.SplitNodeIsRoot;

        // Remove child link so that this slot cannot be chosen as best or deepest
        const parent_info = self.fork_infos.getPtr(parent) orelse return error.ParentNotFound;
        std.debug.assert(parent_info.children.orderedRemove(slot_hash_key));

        { // Insert aggregate operations up to the root
            var parent_iter = self.ancestorIterator(slot_hash_key);
            while (parent_iter.next()) |parent_slot_hash_key| {
                self.aggregateSlot(parent_slot_hash_key);
            }
        }

        // Remove node + all children and add to new tree
        var split_tree_fork_infos: std.AutoArrayHashMapUnmanaged(SlotAndHash, ForkInfo) = .empty;
        errdefer split_tree_fork_infos.deinit(allocator);

        var to_visit: std.ArrayListUnmanaged(SlotAndHash) = .empty;
        defer to_visit.deinit(allocator);

        try to_visit.append(allocator, slot_hash_key);
        while (to_visit.pop()) |current_node| {
            const current_kv = self.fork_infos.fetchSwapRemove(current_node) orelse
                return error.NodeNotFound;
            var current_fork_info = current_kv.value;

            try split_tree_fork_infos.put(allocator, current_node, current_fork_info);
            try to_visit.appendSlice(allocator, current_fork_info.children.keys());
        }

        // Remove link from parent
        const parent_fork_info = self.fork_infos.getPtr(parent) orelse
            return error.ParentNotFound;
        _ = parent_fork_info.children.swapRemoveNoSort(slot_hash_key);

        // Update the root of the new tree with the proper info, now that we have finished
        // aggregating
        split_tree_root.parent = null;
        try split_tree_fork_infos.put(allocator, slot_hash_key, split_tree_root);

        // Split off the relevant votes to the new tree
        var split_tree_latest_votes = try self.latest_votes.clone(allocator);
        errdefer split_tree_latest_votes.deinit(allocator);

        for (self.latest_votes.keys(), self.latest_votes.values()) |key, val| {
            if (!split_tree_fork_infos.contains(val)) {
                _ = split_tree_latest_votes.swapRemove(key);
            }
        }

        var index: usize = 0;
        while (index < self.latest_votes.count()) {
            const value = self.latest_votes.values()[index];
            if (self.fork_infos.contains(value)) {
                index += 1;
                continue;
            }
            const key = self.latest_votes.keys()[index];
            _ = self.latest_votes.swapRemove(key);
        }

        // Create a new tree from the split
        return .{
            .logger = self.logger,
            .fork_infos = split_tree_fork_infos,
            .latest_votes = split_tree_latest_votes,
            .tree_root = slot_hash_key,
            .last_root_time = .now(),
            .metrics = try .init(registry),
        };
    }
};

/// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1390
const AncestorIterator = struct {
    current_slot_hash_key: SlotAndHash,
    fork_infos: *const std.AutoArrayHashMapUnmanaged(SlotAndHash, ForkInfo),

    pub fn next(self: *AncestorIterator) ?SlotAndHash {
        const fork_info = self.fork_infos.get(self.current_slot_hash_key) orelse return null;
        const parent_slot_hash_key = fork_info.parent orelse return null;

        self.current_slot_hash_key = parent_slot_hash_key;
        return self.current_slot_hash_key;
    }
};

const createTestReplayTower = sig.consensus.replay_tower.createTestReplayTower;
const createTestSlotHistory = sig.consensus.replay_tower.createTestSlotHistory;

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L3281
test "HeaviestSubtreeForkChoice.subtreeDiff" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    // Diff of same root is empty, no matter root, intermediate node, or leaf
    {
        var diff = try fork_choice.subtreeDiff(
            allocator,
            &.{ .slot = 0, .hash = .ZEROES },
            &.{ .slot = 0, .hash = .ZEROES },
        );
        defer diff.deinit(allocator);
        try std.testing.expectEqual(0, diff.count());
    }

    {
        var diff = try fork_choice.subtreeDiff(
            allocator,
            &.{ .slot = 5, .hash = .ZEROES },
            &.{ .slot = 5, .hash = .ZEROES },
        );
        defer diff.deinit(allocator);
        try std.testing.expectEqual(0, diff.count());
    }
    {
        var diff = try fork_choice.subtreeDiff(
            allocator,
            &.{ .slot = 6, .hash = .ZEROES },
            &.{ .slot = 6, .hash = .ZEROES },
        );
        defer diff.deinit(allocator);
        try std.testing.expectEqual(0, diff.count());
    }

    // The set reachable from slot 3, excluding subtree 1, is just everything
    // in slot 3 since subtree 1 is an ancestor
    {
        var diff = try fork_choice.subtreeDiff(
            allocator,
            &.{ .slot = 3, .hash = .ZEROES },
            &.{ .slot = 1, .hash = .ZEROES },
        );
        defer diff.deinit(allocator);

        const items = diff.items();
        const slot_and_hashes = items[0];

        try std.testing.expectEqual(3, slot_and_hashes.len);

        try std.testing.expectEqual(
            slot_and_hashes[0],
            SlotAndHash{ .slot = 3, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[1],
            SlotAndHash{ .slot = 5, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[2],
            SlotAndHash{ .slot = 6, .hash = .ZEROES },
        );
    }

    // The set reachable from slot 1, excluding subtree 3, is just 1 and
    // the subtree at 2
    {
        var diff = try fork_choice.subtreeDiff(
            allocator,
            &.{ .slot = 1, .hash = .ZEROES },
            &.{ .slot = 3, .hash = .ZEROES },
        );
        defer diff.deinit(allocator);

        const items = diff.items();
        const slot_and_hashes = items[0]; // Access the keys slice

        try std.testing.expectEqual(3, slot_and_hashes.len);

        try std.testing.expectEqual(
            slot_and_hashes[0],
            SlotAndHash{ .slot = 1, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[1],
            SlotAndHash{ .slot = 2, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[2],
            SlotAndHash{ .slot = 4, .hash = .ZEROES },
        );
    }

    // The set reachable from slot 1, excluding leaf 6, is just everything
    // except leaf 6
    {
        var diff = try fork_choice.subtreeDiff(
            allocator,
            &.{ .slot = 0, .hash = .ZEROES },
            &.{ .slot = 6, .hash = .ZEROES },
        );
        defer diff.deinit(allocator);

        const items = diff.items();
        const slot_and_hashes = items[0]; // Access the keys slice

        try std.testing.expectEqual(6, slot_and_hashes.len);

        try std.testing.expectEqual(
            slot_and_hashes[0],
            SlotAndHash{ .slot = 0, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[1],
            SlotAndHash{ .slot = 1, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[2],
            SlotAndHash{ .slot = 2, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[3],
            SlotAndHash{ .slot = 3, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[4],
            SlotAndHash{ .slot = 4, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            slot_and_hashes[5],
            SlotAndHash{ .slot = 5, .hash = .ZEROES },
        );
    }

    {
        // Set root at 1
        try fork_choice.setTreeRoot(allocator, &.{ .slot = 1, .hash = .ZEROES });
        // Zero no longer exists, set reachable from 0 is empty
        try std.testing.expectEqual(
            0,
            (try fork_choice.subtreeDiff(
                allocator,
                &.{ .slot = 0, .hash = .ZEROES },
                &.{ .slot = 6, .hash = .ZEROES },
            )).count(),
        );
    }
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1534
test "HeaviestSubtreeForkChoice.ancestorIterator" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, &fork_tuples);
    defer fork_choice.deinit(allocator);

    {
        var iterator = fork_choice.ancestorIterator(.{ .slot = 6, .hash = .ZEROES });
        var ancestors: [4]SlotAndHash = undefined;
        var index: usize = 0;

        while (iterator.next()) |ancestor| {
            if (index >= ancestors.len) {
                @panic("Test failed: More than 4 ancestors.");
            }
            ancestors[index] = ancestor;
            index += 1;
        }

        try std.testing.expectEqual(
            ancestors[0],
            SlotAndHash{ .slot = 5, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[1],
            SlotAndHash{ .slot = 3, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[2],
            SlotAndHash{ .slot = 1, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[3],
            SlotAndHash{ .slot = 0, .hash = .ZEROES },
        );
    }
    {
        var iterator = fork_choice.ancestorIterator(.{ .slot = 4, .hash = .ZEROES });
        var ancestors: [3]SlotAndHash = undefined;
        var index: usize = 0;

        while (iterator.next()) |ancestor| {
            if (index >= ancestors.len) {
                @panic("Test failed: More than 3 ancestors.");
            }
            ancestors[index] = ancestor;
            index += 1;
        }

        try std.testing.expectEqual(
            ancestors[0],
            SlotAndHash{ .slot = 2, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[1],
            SlotAndHash{ .slot = 1, .hash = .ZEROES },
        );
        try std.testing.expectEqual(
            ancestors[2],
            SlotAndHash{ .slot = 0, .hash = .ZEROES },
        );
    }
    {
        var iterator = fork_choice.ancestorIterator(.{ .slot = 1, .hash = .ZEROES });
        var ancestors: [1]SlotAndHash = undefined;
        var index: usize = 0;

        while (iterator.next()) |ancestor| {
            if (index >= ancestors.len) {
                @panic("Test failed: More than 1 ancestors.");
            }
            ancestors[index] = ancestor;
            index += 1;
        }

        try std.testing.expectEqual(
            ancestors[0],
            SlotAndHash{ .slot = 0, .hash = .ZEROES },
        );
    }
    {
        var iterator = fork_choice.ancestorIterator(.{ .slot = 0, .hash = .ZEROES });
        try std.testing.expectEqual(null, iterator.next());
    }
    {
        // Set a root, everything but slots 2, 4 should be removed
        try fork_choice.setTreeRoot(allocator, &.{ .slot = 2, .hash = .ZEROES });
        var iterator = fork_choice.ancestorIterator(.{ .slot = 4, .hash = .ZEROES });
        var ancestors: [1]SlotAndHash = undefined;
        var index: usize = 0;

        while (iterator.next()) |ancestor| {
            if (index >= ancestors.len) {
                @panic("Test failed: More than 1 ancestors.");
            }
            ancestors[index] = ancestor;
            index += 1;
        }

        try std.testing.expectEqual(
            ancestors[0],
            SlotAndHash{ .slot = 2, .hash = .ZEROES },
        );
    }
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1685
test "HeaviestSubtreeForkChoice.setTreeRoot" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    // Set root to 1, should only purge 0
    const root1: SlotAndHash = .{ .slot = 1, .hash = .ZEROES };
    try fork_choice.setTreeRoot(allocator, &root1);
    for (0..6) |i| {
        const slot_hash: SlotAndHash = .{ .slot = @intCast(i), .hash = .ZEROES };
        const exists = i != 0;
        try std.testing.expectEqual(exists, fork_choice.fork_infos.contains(slot_hash));
    }

    // Check that root change metrics are tracked
    try std.testing.expectEqual(1, fork_choice.metrics.current_root_slot.get());
}

// [Agave] https://github.com/anza-xyz/agave/blob/4f9ad7a42b14ed681fb6412c104b3df5c310d50f/core/src/consensus/heaviest_subtree_fork_choice.rs#L1918
test "HeaviestSubtreeForkChoice.propagateNewLeaf" {
    const allocator = std.testing.allocator;

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
    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

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
        allocator,
        .{ .slot = 10, .hash = .ZEROES },
        .{ .slot = 4, .hash = .ZEROES },
    );

    // New leaf 10, should be the heaviest and deepest choice for all ancestors
    var ancestors_of_10 = fork_choice.ancestorIterator(
        .{ .slot = 10, .hash = .ZEROES },
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
        allocator,
        .{ .slot = 9, .hash = .ZEROES },
        .{ .slot = 4, .hash = .ZEROES },
    );
    // New leaf 9, should be the heaviest and deepest choice for all ancestors
    var ancestors_of_9 = fork_choice.ancestorIterator(
        .{ .slot = 9, .hash = .ZEROES },
    );
    while (ancestors_of_9.next()) |item| {
        try std.testing.expectEqual(9, fork_choice.heaviestSlot(item).?.slot);
        try std.testing.expectEqual(9, fork_choice.deepestSlot(&item).?.slot);
    }

    // Add a higher leaf 11, should not change the best or deepest choice
    try fork_choice.addNewLeafSlot(
        allocator,
        .{ .slot = 11, .hash = .ZEROES },
        .{ .slot = 4, .hash = .ZEROES },
    );

    // Check that 9 is still the heaviest and deepest choice for all ancestors
    var ancestors_of_9_after_11 = fork_choice.ancestorIterator(
        .{ .slot = 9, .hash = .ZEROES },
    );
    while (ancestors_of_9_after_11.next()) |item| {
        try std.testing.expectEqual(9, fork_choice.heaviestSlot(item).?.slot);
        try std.testing.expectEqual(9, fork_choice.deepestSlot(&item).?.slot);
    }

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const stake: u64 = 100;
    const vote_pubkeys = [_]Pubkey{
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 6, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );

    // Leaf slot 9 stops being the `heaviest_slot` at slot 1 because there
    // are now votes for the branch at slot 3
    // Because slot 1 now sees the child branch at slot 3 has non-zero
    // weight, adding smaller leaf slot 8 in the other child branch at slot 2
    // should not propagate past slot 1
    // Similarly, both forks have the same tree height so we should tie break by
    // stake weight choosing 6 as the deepest slot when possible.
    try fork_choice.addNewLeafSlot(
        allocator,
        .{ .slot = 8, .hash = .ZEROES },
        .{ .slot = 4, .hash = .ZEROES },
    );

    var ancestors_of_8 = fork_choice.ancestorIterator(
        .{ .slot = 8, .hash = .ZEROES },
    );
    while (ancestors_of_8.next()) |item| {
        const expected_best_slot: u8 = if (item.slot > 1) 8 else 6;
        try std.testing.expectEqual(expected_best_slot, fork_choice.heaviestSlot(item).?.slot);
        try std.testing.expectEqual(expected_best_slot, fork_choice.deepestSlot(&item).?.slot);
    }

    // Add vote for slot 8, should now be the best slot (has same weight
    // as fork containing slot 6, but slot 2 is smaller than slot 3).
    const pubkey_votes2 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 8, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes2,
        &epoch_tracker,
    );

    try std.testing.expectEqual(8, fork_choice.heaviestOverallSlot().slot);
    // Deepest overall is now 8 as well
    try std.testing.expectEqual(8, fork_choice.deepestOverallSlot().slot);

    // Because slot 4 now sees the child leaf 8 has non-zero
    // weight, adding smaller leaf slots should not propagate past slot 4
    // Similarly by tiebreak, 8 should be the deepest slot
    try fork_choice.addNewLeafSlot(
        allocator,
        .{ .slot = 7, .hash = .ZEROES },
        .{ .slot = 4, .hash = .ZEROES },
    );

    var ancestors_of_7 = fork_choice.ancestorIterator(
        .{ .slot = 7, .hash = .ZEROES },
    );
    while (ancestors_of_7.next()) |item| {
        try std.testing.expectEqual(8, fork_choice.heaviestSlot(item).?.slot);
        try std.testing.expectEqual(8, fork_choice.deepestSlot(&item).?.slot);
    }

    // All the leaves should think they are their own best and deepest choice
    const leaves = [_]u64{ 8, 9, 10, 11 };
    for (leaves) |leaf| {
        try std.testing.expectEqual(
            leaf,
            fork_choice.heaviestSlot(.{ .slot = leaf, .hash = .ZEROES }).?.slot,
        );
        try std.testing.expectEqual(
            leaf,
            fork_choice.deepestSlot(&.{ .slot = leaf, .hash = .ZEROES }).?.slot,
        );
    }
}

// Analogous to [propagateNewLeaf2](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L2035)
test "HeaviestSubtreeForkChoice.propagateNewLeaf2" {
    const allocator = std.testing.allocator;

    // Build fork structure:
    //      slot 0
    //        |
    //      slot 4
    //        |
    //      slot 6
    const linear_tree = [_]TreeNode{
        .{
            .{ .slot = 4, .hash = .ZEROES },
            .{ .slot = 0, .hash = .ZEROES },
        },
        .{
            .{ .slot = 6, .hash = .ZEROES },
            .{ .slot = 4, .hash = .ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(allocator, linear_tree[0..]);
    defer fork_choice.deinit(allocator);

    // slot 6 should be the best because it's the only leaf
    try std.testing.expectEqual(6, fork_choice.heaviestOverallSlot().slot);

    // Add a leaf slot 5. Even though 5 is less than the best leaf 6,
    // it's not less than it's sibling slot 4, so the best overall
    // leaf should remain unchanged
    try fork_choice.addNewLeafSlot(
        allocator,
        .{ .slot = 5, .hash = .ZEROES },
        .{ .slot = 0, .hash = .ZEROES },
    );
    try std.testing.expectEqual(6, fork_choice.heaviestOverallSlot().slot);

    // Add a leaf slot 2 on a different fork than leaf 6. Slot 2 should
    // be the new best because it's for a lesser slot
    try fork_choice.addNewLeafSlot(
        allocator,
        .{ .slot = 2, .hash = .ZEROES },
        .{ .slot = 0, .hash = .ZEROES },
    );
    try std.testing.expectEqual(2, fork_choice.heaviestOverallSlot().slot);

    // Add a vote for slot 4, so leaf 6 should be the best again
    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const stake: u64 = 100;
    const vote_pubkeys = [_]Pubkey{
        Pubkey.initRandom(random),
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 4, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );
    try std.testing.expectEqual(6, fork_choice.heaviestOverallSlot().slot);

    // Adding a slot 1 that is less than the current best leaf 6 should not change the best
    // slot because the fork slot 5 is on has a higher weight
    try fork_choice.addNewLeafSlot(
        allocator,
        .{ .slot = 1, .hash = .ZEROES },
        .{ .slot = 0, .hash = .ZEROES },
    );
    try std.testing.expectEqual(6, fork_choice.heaviestOverallSlot().slot);
}

// Analogous to [test_set_root_and_add_outdated_votes](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L1772)
test "HeaviestSubtreeForkChoice.setRootAndAddOutdatedVotes" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const stake: u64 = 100;
    const vote_pubkeys = [_]Pubkey{
        Pubkey.initRandom(random),
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    // Vote for slot 0
    const pubkey_votes1 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 0, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes1,
        &epoch_tracker,
    );

    // Set root to 1, should purge 0 from the tree, but
    // there's still an outstanding vote for slot 0 in `pubkey_votes`.
    try fork_choice.setTreeRoot(allocator, &.{ .slot = 1, .hash = .ZEROES });

    // Vote again for slot 3, verify everything is ok
    const pubkey_votes2 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes2,
        &epoch_tracker,
    );

    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSlot(&.{ .slot = 3, .hash = .ZEROES }).?,
    );

    for ([_]u64{ 1, 3 }) |slot| {
        try std.testing.expectEqual(
            stake,
            fork_choice.stakeForSubtree(&.{ .slot = slot, .hash = .ZEROES }).?,
        );
    }

    try std.testing.expectEqual(6, fork_choice.heaviestOverallSlot().slot);

    // Set root again on different fork than the last vote
    try fork_choice.setTreeRoot(allocator, &.{ .slot = 2, .hash = .ZEROES });

    // Smaller vote than last vote 3 should be ignored
    const pubkey_votes3 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 2, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes3,
        &epoch_tracker,
    );

    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSlot(&.{ .slot = 2, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSubtree(&.{ .slot = 2, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(4, fork_choice.heaviestOverallSlot().slot);

    // New larger vote than last vote 3 should be processed
    const pubkey_votes4 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 4, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes4,
        &epoch_tracker,
    );

    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSlot(&.{ .slot = 2, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSlot(&.{ .slot = 4, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSubtree(&.{ .slot = 2, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSubtree(&.{ .slot = 4, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(4, fork_choice.heaviestOverallSlot().slot);
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1863
test "HeaviestSubtreeForkChoice.heaviestOverallSlot" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);
    try std.testing.expectEqual(
        fork_choice.heaviestOverallSlot(),
        SlotAndHash{ .slot = 4, .hash = .ZEROES },
    );
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L2078
test "HeaviestSubtreeForkChoice.aggregateSlot" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    fork_choice.aggregateSlot(.{ .slot = 1, .hash = .ZEROES });

    // No weights are present, weights should be zero
    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSlot(&.{ .slot = 1, .hash = .ZEROES }),
    );

    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSubtree(&.{ .slot = 1, .hash = .ZEROES }),
    );

    // The heaviest leaf when weights are equal should prioritize the lower leaf
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 4, .hash = .ZEROES },
        fork_choice.heaviestSlot(.{ .slot = 1, .hash = .ZEROES }),
    );
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 4, .hash = .ZEROES },
        fork_choice.heaviestSlot(.{ .slot = 2, .hash = .ZEROES }),
    );
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = .ZEROES },
        fork_choice.heaviestSlot(.{ .slot = 3, .hash = .ZEROES }),
    );
    // The deepest leaf only tiebreaks by slot # when tree heights are equal
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = .ZEROES },
        fork_choice.deepestSlot(&.{ .slot = 1, .hash = .ZEROES }),
    );
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 4, .hash = .ZEROES },
        fork_choice.deepestSlot(&.{ .slot = 2, .hash = .ZEROES }),
    );
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = .ZEROES },
        fork_choice.deepestSlot(&.{ .slot = 3, .hash = .ZEROES }),
    );

    // Update the weights that have voted *exactly* at each slot, the
    // branch containing slots {5, 6} has weight 11, so should be heavier
    // than the branch containing slots {2, 4}

    var total_stake: usize = 0;
    var staked_voted_slots: std.AutoArrayHashMapUnmanaged(u64, void) = .empty;
    defer staked_voted_slots.deinit(allocator);

    // Add slots to the set
    for ([_]u64{ 2, 4, 5, 6 }) |slot| try staked_voted_slots.put(allocator, slot, {});

    for (staked_voted_slots.keys()) |slot| {
        fork_choice.setStakeVotedAt(
            &.{ .slot = slot, .hash = .ZEROES },
            slot,
        );
        total_stake += slot;
    }

    var slots_to_aggregate: std.ArrayListUnmanaged(SlotAndHash) = .empty;
    defer slots_to_aggregate.deinit(allocator);

    try slots_to_aggregate.append(allocator, .{ .slot = 6, .hash = .ZEROES });

    var ancestors_of_6 = fork_choice.ancestorIterator(
        .{ .slot = 6, .hash = .ZEROES },
    );
    while (ancestors_of_6.next()) |item| {
        try slots_to_aggregate.append(allocator, item);
    }

    try slots_to_aggregate.append(allocator, .{ .slot = 4, .hash = .ZEROES });

    var ancestors_of_4 = fork_choice.ancestorIterator(
        .{ .slot = 4, .hash = .ZEROES },
    );
    while (ancestors_of_4.next()) |item| {
        try slots_to_aggregate.append(allocator, item);
    }

    for (slots_to_aggregate.items) |slot_hash| {
        fork_choice.aggregateSlot(slot_hash);
    }

    // The best path is now 0 -> 1 -> 3 -> 5 -> 6, so leaf 6
    // should be the best choice
    // It is still the deepest choice
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = .ZEROES },
        fork_choice.heaviestOverallSlot(),
    );

    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = .ZEROES },
        fork_choice.deepestOverallSlot(),
    );

    for (0..7) |slot| {
        const expected_stake: u64 = if (staked_voted_slots.contains(slot))
            slot
        else
            0;

        try std.testing.expectEqual(
            expected_stake,
            fork_choice.stakeForSlot(&.{ .slot = slot, .hash = .ZEROES }),
        );
    }

    // Verify `stake_for_subtree` for common fork
    for ([_]u64{ 0, 1 }) |slot| {
        // Subtree stake is sum of the `stake_for_slot` across
        // all slots in the subtree
        try std.testing.expectEqual(
            total_stake,
            fork_choice.stakeForSubtree(&.{ .slot = slot, .hash = .ZEROES }),
        );
    }

    {
        // Verify `stake_for_subtree` for fork 1
        var total_expected_stake: u64 = 0;
        for ([_]u64{ 4, 2 }) |slot| {
            total_expected_stake += fork_choice.stakeForSlot(
                &.{ .slot = slot, .hash = .ZEROES },
            ).?;
            try std.testing.expectEqual(
                total_expected_stake,
                fork_choice.stakeForSubtree(&.{ .slot = slot, .hash = .ZEROES }),
            );
        }
    }

    {
        // Verify `stake_for_subtree` for fork 2
        var total_expected_stake: u64 = 0;
        for ([_]u64{ 6, 5, 3 }) |slot| {
            total_expected_stake += fork_choice.stakeForSlot(
                &.{ .slot = slot, .hash = .ZEROES },
            ).?;

            try std.testing.expectEqual(
                total_expected_stake,
                fork_choice.stakeForSubtree(&.{ .slot = slot, .hash = .ZEROES }),
            );
        }
    }
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L3012
test "HeaviestSubtreeForkChoice.isHeaviestChild" {
    const allocator = std.testing.allocator;

    const tree = [_]TreeNode{
        //
        // (0)
        // └── (4)
        //     ├── (10)
        //     └── (9)
        //
        .{
            .{ .slot = 4, .hash = .ZEROES },
            .{ .slot = 0, .hash = .ZEROES },
        },
        .{
            .{ .slot = 10, .hash = .ZEROES },
            .{ .slot = 4, .hash = .ZEROES },
        },
        .{
            .{ .slot = 9, .hash = .ZEROES },
            .{ .slot = 4, .hash = .ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(allocator, tree[0..]);
    defer fork_choice.deinit(allocator);

    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 0, .hash = .ZEROES }),
    );
    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 4, .hash = .ZEROES }),
    );
    // 9 is better than 10
    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 9, .hash = .ZEROES }),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 10, .hash = .ZEROES })),
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
        allocator,
        .{ .slot = 8, .hash = .ZEROES },
        .{ .slot = 4, .hash = .ZEROES },
    );
    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 8, .hash = .ZEROES }),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 9, .hash = .ZEROES })),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 10, .hash = .ZEROES })),
    );
    // TODO complete test when vote related functions are implemented
}

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L1871
test "HeaviestSubtreeForkChoice.addNewLeafSlot_duplicate" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const duplicate_fork: TestDuplicateForks = try .setup(allocator);
    defer duplicate_fork.deinit(allocator);

    const fork_choice = duplicate_fork.fork_choice;
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;
    const duplicate_leaves_descended_from_5 = duplicate_fork.duplicate_leaves_descended_from_5;
    // Add a child to one of the duplicates
    const duplicate_parent = duplicate_leaves_descended_from_4[0];
    const child: SlotAndHash = .{ .slot = 11, .hash = .initRandom(random) };
    try fork_choice.addNewLeafSlot(allocator, child, duplicate_parent);
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
    try fork_choice.addNewLeafSlot(allocator, duplicate_parent, .{ .slot = 4, .hash = .ZEROES });
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
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, linear_fork_tuples[0..]);
    defer fork_choice.deinit(allocator);
    const duplicate_confirmed_slot: Slot = 1;
    const duplicate_confirmed_key: Hash = .ZEROES;
    try fork_choice.markForkValidCandidate(allocator, &.{
        .slot = duplicate_confirmed_slot,
        .hash = duplicate_confirmed_key,
    }, {});

    for (fork_choice.fork_infos.keys()) |*slot_hash_key| {
        const slot = slot_hash_key.slot;
        if (slot <= duplicate_confirmed_slot) {
            try std.testing.expect(fork_choice.isDuplicateConfirmed(slot_hash_key).?);
        } else {
            try std.testing.expect(!fork_choice.isDuplicateConfirmed(slot_hash_key).?);
        }
        try std.testing.expect(fork_choice.latestDuplicateAncestor(slot_hash_key.*) == null);
    }

    // Mark a later descendant invalid
    const invalid_descendant_slot = 5;
    const invalid_descendant_key: Hash = .ZEROES;
    try fork_choice.markForkInvalidCandidate(allocator, &.{
        .slot = invalid_descendant_slot,
        .hash = invalid_descendant_key,
    });

    for (fork_choice.fork_infos.keys()) |*slot_hash_key| {
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

// [Agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/core/src/consensus/heaviest_subtree_fork_choice.rs#L3752
test "HeaviestSubtreeForkChoice.markForkValidandidate_mark_valid_then_ancestor_invalid" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, linear_fork_tuples[0..]);
    defer fork_choice.deinit(allocator);
    const duplicate_confirmed_slot: Slot = 4;
    const duplicate_confirmed_key: Hash = .ZEROES;
    try fork_choice.markForkValidCandidate(allocator, &.{
        .slot = duplicate_confirmed_slot,
        .hash = duplicate_confirmed_key,
    }, {});

    // Now mark an ancestor of this fork invalid, should return an error since this ancestor
    // was duplicate confirmed by its descendant 4 already
    try std.testing.expectError(
        error.DuplicateConfirmedCannotBeMarkedInvalid,
        fork_choice.markForkInvalidCandidate(allocator, &.{
            .slot = 3,
            .hash = .ZEROES,
        }),
    );
}

test "HeaviestSubtreeForkChoice.isStrictAncestor_maybe_ancestor_same_as_key" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    const key: SlotAndHash = .{ .slot = 10, .hash = .ZEROES };
    try std.testing.expect(!fork_choice.isStrictAncestor(&key, &key));
}

test "HeaviestSubtreeForkChoice.isStrictAncestor_maybe_ancestor_slot_greater_than_key" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    const key: SlotAndHash = .{ .slot = 10, .hash = .ZEROES };
    const maybe_ancestor: SlotAndHash = .{ .slot = 11, .hash = .ZEROES };

    try std.testing.expect(!fork_choice.isStrictAncestor(&maybe_ancestor, &key));
}

test "HeaviestSubtreeForkChoice.isStrictAncestor_not_maybe_ancestor" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    const key: SlotAndHash = .{ .slot = 5, .hash = .ZEROES };
    const maybe_ancestor: SlotAndHash = .{ .slot = 4, .hash = .ZEROES };

    try std.testing.expect(!fork_choice.isStrictAncestor(&maybe_ancestor, &key));
}

test "HeaviestSubtreeForkChoice.isStrictAncestor_is_maybe_ancestor" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    const key: SlotAndHash = .{ .slot = 5, .hash = .ZEROES };
    const maybe_ancestor: SlotAndHash = .{ .slot = 1, .hash = .ZEROES };

    try std.testing.expect(fork_choice.isStrictAncestor(&maybe_ancestor, &key));
}

test "HeaviestSubtreeForkChoice.heaviestSlotOnSameVotedFork_stray_restored_slot" {
    const allocator = std.testing.allocator;

    const tree = [_]TreeNode{
        //
        // (0)
        // └── (1)
        //     ├── (2)
        //
        .{
            .{ .slot = 1, .hash = .ZEROES },
            .{ .slot = 0, .hash = .ZEROES },
        },
        .{
            .{ .slot = 2, .hash = .ZEROES },
            .{ .slot = 1, .hash = .ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(allocator, tree[0..]);
    defer fork_choice.deinit(allocator);

    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(allocator);
    _ = try replay_tower.recordBankVote(allocator, 1, Hash.ZEROES);

    try std.testing.expect(!replay_tower.isStrayLastVote());
    try std.testing.expectEqualDeep(
        SlotAndHash{ .slot = 2, .hash = .ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // Make slot 1 (existing in bank_forks) a restored stray slot
    var slot_history = try createTestSlotHistory(allocator);
    defer slot_history.deinit(allocator);

    slot_history.add(0);
    // Work around TooOldSlotHistory
    slot_history.add(999);

    try replay_tower.adjustLockoutsAfterReplay(allocator, 0, &slot_history);

    try std.testing.expect(replay_tower.isStrayLastVote());
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 2, .hash = .ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // Make slot 3 (NOT existing in bank_forks) a restored stray slot
    _ = try replay_tower.recordBankVote(allocator, 3, Hash.ZEROES);
    try replay_tower.adjustLockoutsAfterReplay(allocator, 0, &slot_history);

    try std.testing.expect(replay_tower.isStrayLastVote());
    try std.testing.expectEqual(
        null,
        try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower),
    );
}

test "HeaviestSubtreeForkChoice.heaviestSlotOnSameVotedFork_last_voted_not_found" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(allocator);

    try std.testing.expectEqualDeep(
        null,
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)),
    );
}

test "HeaviestSubtreeForkChoice.heaviestSlotOnSameVotedFork_use_deepest_slot" {
    const allocator = std.testing.allocator;

    const tree = [_]TreeNode{
        //
        // (0)
        // └── (1)
        //     ├── (2)
        //
        .{
            .{ .slot = 1, .hash = .ZEROES },
            .{ .slot = 0, .hash = .ZEROES },
        },
        .{
            .{ .slot = 2, .hash = .ZEROES },
            .{ .slot = 1, .hash = .ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(allocator, &tree);
    defer fork_choice.deinit(allocator);

    // Create a tower that voted on slot 1.
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(allocator);
    _ = try replay_tower.recordBankVote(allocator, 1, .ZEROES);

    // Initially, slot 1 is valid so we get the heaviest slot (which would be 2)
    try std.testing.expectEqualDeep(
        SlotAndHash{ .slot = 2, .hash = .ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // Now mark slot 1 as invalid
    try fork_choice.markForkInvalidCandidate(
        allocator,
        &.{ .slot = 1, .hash = .ZEROES },
    );
    try std.testing.expect(
        !fork_choice.isCandidate(&.{ .slot = 1, .hash = .ZEROES }).?,
    );

    // Now heaviestSlotOnSameVotedFork should return the deepest slot (2)
    // even though the fork is invalid
    try std.testing.expectEqualDeep(
        SlotAndHash{ .slot = 2, .hash = .ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );
}

test "HeaviestSubtreeForkChoice.heaviestSlotOnSameVotedFork_missing_candidate" {
    const allocator = std.testing.allocator;

    const tree = [_]TreeNode{
        //
        // (0)
        // └── (1)
        //
        .{
            .{ .slot = 1, .hash = .ZEROES },
            .{ .slot = 0, .hash = .ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(allocator, &tree);
    defer fork_choice.deinit(allocator);

    // Create a tower that voted on slot 2 which doesn't exist in the fork choice.
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(allocator);
    _ = try replay_tower.recordBankVote(allocator, 2, Hash.ZEROES);

    try std.testing.expect(!replay_tower.isStrayLastVote());

    try std.testing.expectError(
        error.MissingCandidate,
        fork_choice.heaviestSlotOnSameVotedFork(&replay_tower),
    );
}

const UpdateOperations = std.MultiArrayList(struct {
    key: SlotAndHash,
    op: UpdateOperation,
});

const UpdateOperation = union(enum) {
    add: u64,
    mark_valid: Slot,
    mark_invalid: Slot,
    subtract: u64,
    aggregate,
};

fn expectAddVotesUpdateOps(
    fork_choice: *ForkChoice,
    epoch_tracker: *const sig.core.EpochTracker,
    pubkey_votes: []const PubkeyVote,
    expected_slots_and_ops: []const struct { Slot, UpdateOperation },
) !void {
    if (!builtin.is_test) @compileError(
        @src().fn_name ++ " is only intended for tests",
    );

    const allocator = std.testing.allocator;

    var expected_update_operations: UpdateOperations = .empty;
    defer expected_update_operations.deinit(allocator);
    for (expected_slots_and_ops) |item| {
        const slot, const update_op = item;
        try expected_update_operations.append(
            allocator,
            .{ .key = .{ .slot = slot, .hash = .ZEROES }, .op = update_op },
        );
    }

    var generated_update_operations: UpdateOperations = .empty;
    defer generated_update_operations.deinit(allocator);

    const add_votes_append_ctx: struct {
        gpa: std.mem.Allocator,
        update_operations: *UpdateOperations,

        pub fn addSlotStake(ctx: @This(), slot_hash_key: SlotAndHash, stake: u64) !void {
            try ctx.update_operations.append(ctx.gpa, .{
                .key = slot_hash_key,
                .op = .{ .add = stake },
            });
        }

        pub fn subtractSlotStake(ctx: @This(), slot_hash_key: SlotAndHash, stake: u64) !void {
            try ctx.update_operations.append(ctx.gpa, .{
                .key = slot_hash_key,
                .op = .{ .subtract = stake },
            });
        }

        pub fn aggregateSlot(ctx: @This(), slot_hash_key: SlotAndHash) !void {
            try ctx.update_operations.append(ctx.gpa, .{
                .key = slot_hash_key,
                .op = .aggregate,
            });
        }
    } = .{
        .gpa = allocator,
        .update_operations = &generated_update_operations,
    };

    _ = try fork_choice.addVotesWithCallbacks(
        allocator,
        pubkey_votes,
        epoch_tracker,
        add_votes_append_ctx,
    );

    const eks: []const SlotAndHash = expected_update_operations.items(.key);
    const eus: []const UpdateOperation = expected_update_operations.items(.op);

    const gks: []const SlotAndHash = generated_update_operations.items(.key);
    const gus: []const UpdateOperation = generated_update_operations.items(.op);
    for (eks, eus) |ek, eu| {
        const found: usize = for (gks, gus, 0..) |gk, gu, i| {
            if (eu != std.meta.activeTag(gu)) continue;
            if (ek.equals(gk)) break i;
        } else return error.NoMatchingSlotHash;
        try std.testing.expectEqual(eu, gus[found]);
    }
}

// Analogous to [test_generate_update_operations](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L2312)
test "HeaviestSubtreeForkChoice.generateUpdateOperations" {
    const allocator = std.testing.allocator;
    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const stake = 100;
    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
    };
    const versioned_stakes_0 = try testEpochStakes(allocator, &vote_pubkeys, stake, random);
    var versioned_stakes_1 = try versioned_stakes_0.clone(allocator);
    versioned_stakes_1.stakes.epoch = 1;

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{ versioned_stakes_0, versioned_stakes_1 },
    );
    defer epoch_tracker.deinit(allocator);

    var fork_choice = try forkChoiceForTest(allocator, &fork_tuples);
    defer fork_choice.deinit(allocator);

    try expectAddVotesUpdateOps(
        &fork_choice,
        &epoch_tracker,
        &.{
            .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
            .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 4, .hash = .ZEROES } },
            .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 1, .hash = .ZEROES } },
        },
        &.{
            // Add/remove from new/old forks
            .{ 1, .{ .add = stake } },
            .{ 3, .{ .add = stake } },
            .{ 4, .{ .add = stake } },

            // Aggregate all ancestors of changed slots
            .{ 0, .aggregate },
            .{ 1, .aggregate },
            .{ 2, .aggregate },
        },
    );

    // Everyone makes older/same votes, should be ignored
    try expectAddVotesUpdateOps(
        &fork_choice,
        &epoch_tracker,
        &.{
            .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
            .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 2, .hash = .ZEROES } },
            .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 1, .hash = .ZEROES } },
        },
        &.{},
    );

    // Some people make newer votes
    try expectAddVotesUpdateOps(
        &fork_choice,
        &epoch_tracker,
        &.{
            // old, ignored
            .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
            // new, switched forks
            .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 5, .hash = .ZEROES } },
            // new, same fork
            .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
        },
        &.{
            // Add/remove from new/old forks
            .{ 3, .{ .add = stake } },
            .{ 5, .{ .add = stake } },
            .{ 1, .{ .subtract = stake } },
            .{ 4, .{ .subtract = stake } },

            // Aggregate all ancestors of changed slots
            .{ 0, .aggregate },
            .{ 1, .aggregate },
            .{ 2, .aggregate },
            .{ 3, .aggregate },
        },
    );

    // People make new votes
    try expectAddVotesUpdateOps(
        &fork_choice,
        &epoch_tracker,
        &.{
            // new, switch forks
            .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 4, .hash = .ZEROES } },
            // new, same fork
            .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 6, .hash = .ZEROES } },
            // new, same fork
            .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 6, .hash = .ZEROES } },
        },
        &.{
            // Add/remove from new/old forks
            .{ 4, .{ .add = stake } },
            .{ 6, .{ .add = stake } },
            .{ 3, .{ .subtract = stake } },
            .{ 5, .{ .subtract = stake } },

            // Aggregate all ancestors of changed slots
            .{ 0, .aggregate },
            .{ 1, .aggregate },
            .{ 2, .aggregate },
            .{ 3, .aggregate },
            .{ 5, .aggregate },
        },
    );
}

// Analogous to [add_root_parent](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L426)
test "HeaviestSubtreeForkChoice.addRootParent" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const vote_pubkeys = [_]Pubkey{.initRandom(random)};
    // Build fork structure:
    // slot 3
    //   |
    // slot 4
    //   |
    // slot 5
    const tree = [_]TreeNode{
        .{
            .{ .slot = 4, .hash = .ZEROES },
            .{ .slot = 3, .hash = .ZEROES },
        },
        .{
            .{ .slot = 5, .hash = .ZEROES },
            .{ .slot = 4, .hash = .ZEROES },
        },
    };
    var fork_choice = try forkChoiceForTest(allocator, tree[0..]);
    defer fork_choice.deinit(allocator);

    const stake: u64 = 100;
    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{
            .slot = 5,
            .hash = .ZEROES,
        } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );

    try fork_choice.addRootParent(allocator, .{ .slot = 2, .hash = .ZEROES });

    try std.testing.expectEqual(
        SlotAndHash{ .slot = 2, .hash = .ZEROES },
        fork_choice.getParent(&.{ .slot = 3, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSubtree(&.{ .slot = 3, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSlot(&.{ .slot = 2, .hash = .ZEROES }).?,
    );

    var children = fork_choice.getChildren(&.{ .slot = 2, .hash = .ZEROES }).?;
    try std.testing.expectEqual(1, children.count());
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 3, .hash = .ZEROES },
        children.keys()[0],
    );

    try std.testing.expectEqual(
        SlotAndHash{ .slot = 5, .hash = .ZEROES },
        fork_choice.heaviestSlot(.{ .slot = 2, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(
        SlotAndHash{ .slot = 5, .hash = .ZEROES },
        fork_choice.deepestSlot(&.{ .slot = 2, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(
        null,
        fork_choice.getParent(&.{ .slot = 2, .hash = .ZEROES }),
    );

    try std.testing.expectEqual(2, fork_choice.metrics.current_root_slot.get());
}

// Analogous to [test_add_votes](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L2493)
test "HeaviestSubtreeForkChoice.addVotes" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const stake: u64 = 100;
    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 2, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 1, .hash = .ZEROES } },
    };

    const deepest_slot = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );

    try std.testing.expectEqual(
        SlotAndHash{ .slot = 4, .hash = .ZEROES },
        deepest_slot,
    );

    try std.testing.expectEqual(
        SlotAndHash{ .slot = 4, .hash = .ZEROES },
        fork_choice.heaviestOverallSlot(),
    );
}

// Analogous to [test_add_votes_duplicate_greater_hash_ignored](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L2616)
test "HeaviestSubtreeForkChoice.addVotesDuplicateGreaterHashIgnored" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
    };

    const stake: u64 = 10;

    const duplicate_fork: TestDuplicateForks = try .setup(allocator);
    defer duplicate_fork.deinit(allocator);

    const fork_choice = duplicate_fork.fork_choice;
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;
    const duplicate_leaves_descended_from_6 = duplicate_fork.duplicate_leaves_descended_from_6;

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = duplicate_leaves_descended_from_4[0] },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = duplicate_leaves_descended_from_4[1] },
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    // duplicate_leaves_descended_from_4 are sorted, and fork choice will pick the smaller
    // one in the event of a tie
    const expected_best_slot_hash = duplicate_leaves_descended_from_4[0];
    try std.testing.expectEqual(expected_best_slot_hash, try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    ));
    // we tie break the duplicate_leaves_descended_from_6 and pick the smaller one
    // for deepest
    const expected_deepest_slot_hash = duplicate_leaves_descended_from_6[1];
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );
    // Adding a duplicate vote for a validator, for another a greater bank hash,
    // should be ignored as we prioritize the smaller bank hash. Thus nothing
    // should change.
    const pubkey_votes2 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = duplicate_leaves_descended_from_4[1] },
    };
    try std.testing.expectEqual(expected_best_slot_hash, try fork_choice.addVotes(
        allocator,
        &pubkey_votes2,
        &epoch_tracker,
    ));
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );

    // Still only has one validator voting on it
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSubtree(&duplicate_leaves_descended_from_4[1]),
    );
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSlot(&duplicate_leaves_descended_from_4[1]),
    );

    // All common ancestors should have subtree voted stake == 2 * stake, but direct
    // voted stake == 0
    const expected_ancestors_stake = 2 * stake;
    var ancestor_iter = fork_choice.ancestorIterator(duplicate_leaves_descended_from_4[1]);
    while (ancestor_iter.next()) |ancestor| {
        try std.testing.expectEqual(
            expected_ancestors_stake,
            fork_choice.stakeForSubtree(&ancestor).?,
        );
        try std.testing.expectEqual(
            0,
            fork_choice.stakeForSlot(&ancestor).?,
        );
    }
}

// Analogous to [test_add_votes_duplicate_smaller_hash_prioritized](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L2704)
test "HeaviestSubtreeForkChoice.addVotesDuplicateSmallerHashPrioritized" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
    };

    const stake: u64 = 10;

    const duplicate_fork: TestDuplicateForks = try .setup(allocator);
    defer duplicate_fork.deinit(allocator);

    const fork_choice = duplicate_fork.fork_choice;
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;
    const duplicate_leaves_descended_from_6 = duplicate_fork.duplicate_leaves_descended_from_6;

    // Both voters voted on duplicate_leaves_descended_from_4[1], so thats the heaviest
    // branch
    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = duplicate_leaves_descended_from_4[1] },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = duplicate_leaves_descended_from_4[1] },
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    const expected_best_slot_hash = duplicate_leaves_descended_from_4[1];
    try std.testing.expectEqual(expected_best_slot_hash, try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    ));
    const expected_deepest_slot_hash = duplicate_leaves_descended_from_6[1];

    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );

    // BEFORE, both validators voting on this leaf
    try std.testing.expectEqual(
        2 * stake,
        fork_choice.stakeForSubtree(&duplicate_leaves_descended_from_4[1]),
    );
    try std.testing.expectEqual(
        2 * stake,
        fork_choice.stakeForSlot(&duplicate_leaves_descended_from_4[1]),
    );

    // Adding a duplicate vote for a validator, for another a smaller bank hash,
    // should be proritized and replace the vote for the greater bank hash.
    // Now because both duplicate nodes are tied, the best leaf is the smaller one.
    const pubkey_votes2 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = duplicate_leaves_descended_from_4[0] },
    };
    const expected_best_slot_hash2 = duplicate_leaves_descended_from_4[0];
    try std.testing.expectEqual(expected_best_slot_hash2, try fork_choice.addVotes(
        allocator,
        &pubkey_votes2,
        &epoch_tracker,
    ));

    // AFTER, only one of the validators is voting on this leaf
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSubtree(&duplicate_leaves_descended_from_4[1]),
    );
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSlot(&duplicate_leaves_descended_from_4[1]),
    );
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );

    // The other leaf now has one of the votes
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSubtree(&duplicate_leaves_descended_from_4[0]),
    );
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSlot(&duplicate_leaves_descended_from_4[0]),
    );

    // All common ancestors should have subtree voted stake == 2 * stake, but direct
    // voted stake == 0
    const expected_ancestors_stake = 2 * stake;
    var ancestor_iter = fork_choice.ancestorIterator(duplicate_leaves_descended_from_4[0]);
    while (ancestor_iter.next()) |ancestor| {
        try std.testing.expectEqual(
            expected_ancestors_stake,
            fork_choice.stakeForSubtree(&ancestor).?,
        );
        try std.testing.expectEqual(
            0,
            fork_choice.stakeForSlot(&ancestor).?,
        );
    }
}

// Analogous to [test_add_votes_duplicate_then_outdated](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L2821)
test "HeaviestSubtreeForkChoice.addVotesDuplicateThenOutdated" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
    };

    const stake: u64 = 10;

    const duplicate_fork: TestDuplicateForks = try .setup(allocator);
    defer duplicate_fork.deinit(allocator);

    const fork_choice = duplicate_fork.fork_choice;
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = duplicate_leaves_descended_from_4[0] },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = duplicate_leaves_descended_from_4[1] },
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    // duplicate_leaves_descended_from_4 are sorted, and fork choice will pick the smaller
    // one in the event of a tie
    const expected_best_slot_hash = duplicate_leaves_descended_from_4[0];
    try std.testing.expectEqual(expected_best_slot_hash, try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    ));

    // Create two children for slots greater than the duplicate slot,
    // 1) descended from the current best slot (which also happens to be a duplicate slot)
    // 2) another descended from a non-duplicate slot.
    try std.testing.expectEqual(
        duplicate_leaves_descended_from_4[0],
        fork_choice.heaviestOverallSlot(),
    );

    // Create new child with heaviest duplicate parent
    const duplicate_parent = duplicate_leaves_descended_from_4[0];
    const duplicate_slot = duplicate_parent.slot;

    // Create new child with non-duplicate parent
    const nonduplicate_parent: SlotAndHash = .{ .slot = 2, .hash = .ZEROES };
    const higher_child_with_duplicate_parent: SlotAndHash = .{
        .slot = duplicate_slot + 1,
        .hash = .initRandom(random),
    };
    const higher_child_with_nonduplicate_parent: SlotAndHash = .{
        .slot = duplicate_slot + 2,
        .hash = .initRandom(random),
    };

    try fork_choice.addNewLeafSlot(
        allocator,
        higher_child_with_duplicate_parent,
        duplicate_parent,
    );
    try fork_choice.addNewLeafSlot(
        allocator,
        higher_child_with_nonduplicate_parent,
        nonduplicate_parent,
    );

    // vote_pubkeys[0] and vote_pubkeys[1] should both have their latest votes
    // erased after a vote for a higher parent
    const pubkey_votes2 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = higher_child_with_duplicate_parent },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = higher_child_with_nonduplicate_parent },
        .{ .pubkey = vote_pubkeys[2], .slot_hash = higher_child_with_nonduplicate_parent },
    };
    const expected_best_slot_hash2 = higher_child_with_nonduplicate_parent;
    try std.testing.expectEqual(expected_best_slot_hash2, try fork_choice.addVotes(
        allocator,
        &pubkey_votes2,
        &epoch_tracker,
    ));

    // All the stake directly voting on the duplicates have been outdated
    for (duplicate_leaves_descended_from_4, 0..) |duplicate_leaf, i| {
        try std.testing.expectEqual(
            0,
            fork_choice.stakeForSlot(&duplicate_leaf),
        );

        if (i == 0) {
            // The subtree stake of the first duplicate however, has one vote still
            // because it's the parent of the `higher_child_with_duplicate_parent`,
            // which has one vote
            try std.testing.expectEqual(
                stake,
                fork_choice.stakeForSubtree(&duplicate_leaf),
            );
        } else {
            try std.testing.expectEqual(
                0,
                fork_choice.stakeForSubtree(&duplicate_leaf),
            );
        }
    }

    // Node 4 has subtree voted stake == stake since it only has one voter on it
    const node4: SlotAndHash = .{ .slot = 4, .hash = .ZEROES };
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSubtree(&node4),
    );
    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSlot(&node4),
    );

    // All ancestors of 4 should have subtree voted stake == num_validators * stake,
    // but direct voted stake == 0
    const expected_ancestors_stake = vote_pubkeys.len * stake;
    var ancestor_iter = fork_choice.ancestorIterator(node4);
    while (ancestor_iter.next()) |ancestor| {
        try std.testing.expectEqual(
            expected_ancestors_stake,
            fork_choice.stakeForSubtree(&ancestor).?,
        );
        try std.testing.expectEqual(
            0,
            fork_choice.stakeForSlot(&ancestor).?,
        );
    }
}

// Analogous to [test_add_votes_duplicate_tie](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L2518)
test "HeaviestSubtreeForkChoice.addVotesDuplicateTie" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
    };

    const stake: u64 = 10;

    const duplicate_fork: TestDuplicateForks = try .setup(allocator);
    defer duplicate_fork.deinit(allocator);

    const fork_choice = duplicate_fork.fork_choice;
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;
    const duplicate_leaves_descended_from_6 = duplicate_fork.duplicate_leaves_descended_from_6;

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = duplicate_leaves_descended_from_4[0] },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = duplicate_leaves_descended_from_4[1] },
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    // duplicate_leaves_descended_from_4 are sorted, and fork choice will pick the smaller
    // one in the event of a tie
    const expected_best_slot_hash = duplicate_leaves_descended_from_4[0];
    try std.testing.expectEqual(expected_best_slot_hash, try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    ));
    try std.testing.expectEqual(
        expected_best_slot_hash,
        fork_choice.heaviestOverallSlot(),
    );

    // we tie break the duplicate_leaves_descended_from_6 and pick the smaller one
    // for deepest
    const expected_deepest_slot_hash = duplicate_leaves_descended_from_6[1];
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestSlot(&.{ .slot = 3, .hash = .ZEROES }).?,
    );
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );

    // Adding the same vote again will not do anything
    const pubkey_votes2 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[1], .slot_hash = duplicate_leaves_descended_from_4[1] },
    };
    try std.testing.expectEqual(expected_best_slot_hash, try fork_choice.addVotes(
        allocator,
        &pubkey_votes2,
        &epoch_tracker,
    ));

    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSubtree(&duplicate_leaves_descended_from_4[1]),
    );
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSlot(&duplicate_leaves_descended_from_4[1]),
    );
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );

    // All common ancestors should have subtree voted stake == 2 * stake, but direct
    // voted stake == 0
    const expected_ancestors_stake = 2 * stake;
    var ancestor_iter = fork_choice.ancestorIterator(duplicate_leaves_descended_from_4[1]);
    while (ancestor_iter.next()) |ancestor| {
        try std.testing.expectEqual(
            expected_ancestors_stake,
            fork_choice.stakeForSubtree(&ancestor).?,
        );
        try std.testing.expectEqual(
            0,
            fork_choice.stakeForSlot(&ancestor).?,
        );
    }
}

// Analogous to [test_add_votes_duplicate_zero_stake](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L2947)
test "HeaviestSubtreeForkChoice.addVotesDuplicateZeroStake" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
    };

    const stake: u64 = 0;

    const duplicate_fork: TestDuplicateForks = try .setup(allocator);
    defer duplicate_fork.deinit(allocator);

    const fork_choice = duplicate_fork.fork_choice;
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    // Make new vote with vote_pubkeys[0] for a higher slot
    // Create new child with heaviest duplicate parent
    const duplicate_parent = duplicate_leaves_descended_from_4[0];
    const duplicate_slot = duplicate_parent.slot;
    const higher_child_with_duplicate_parent: SlotAndHash = .{
        .slot = duplicate_slot + 1,
        .hash = .initRandom(random),
    };
    try fork_choice.addNewLeafSlot(allocator, higher_child_with_duplicate_parent, duplicate_parent);

    // Vote for pubkey 0 on one of the duplicate slots
    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = duplicate_leaves_descended_from_4[1] },
    };

    // Stake is zero, so because duplicate_leaves_descended_from_4[0] and
    // duplicate_leaves_descended_from_4[1] are tied, the child of the smaller
    // node duplicate_leaves_descended_from_4[0] is the one that is picked
    const expected_best_slot_hash = higher_child_with_duplicate_parent;
    try std.testing.expectEqual(expected_best_slot_hash, try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    ));
    try std.testing.expectEqual(
        duplicate_leaves_descended_from_4[1],
        fork_choice.latest_votes.get(vote_pubkeys[0]).?,
    );

    // Now add a vote for a higher slot, and ensure the latest votes
    // for this pubkey were updated
    const pubkey_votes2 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = higher_child_with_duplicate_parent },
    };

    try std.testing.expectEqual(expected_best_slot_hash, try fork_choice.addVotes(
        allocator,
        &pubkey_votes2,
        &epoch_tracker,
    ));
    try std.testing.expectEqual(
        higher_child_with_duplicate_parent,
        fork_choice.latest_votes.get(vote_pubkeys[0]).?,
    );
}

// Analogous to [test_is_best_child](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L3015)
test "HeaviestSubtreeForkChoice.isBestChild" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const vote_pubkeys = [_]Pubkey{
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
    };

    // Build fork structure:
    //      slot 0
    //        |
    //      slot 4
    //     /      \
    // slot 10   slot 9
    const tree = [_]TreeNode{
        .{
            .{ .slot = 4, .hash = .ZEROES },
            .{ .slot = 0, .hash = .ZEROES },
        },
        .{
            .{ .slot = 9, .hash = .ZEROES },
            .{ .slot = 4, .hash = .ZEROES },
        },
        .{
            .{ .slot = 10, .hash = .ZEROES },
            .{ .slot = 4, .hash = .ZEROES },
        },
    };

    var fork_choice = try forkChoiceForTest(
        allocator,
        tree[0..],
    );
    defer fork_choice.deinit(allocator);

    try std.testing.expect(
        try fork_choice.isHeaviestChild(
            &.{ .slot = 0, .hash = .ZEROES },
        ),
    );
    try std.testing.expect(
        try fork_choice.isHeaviestChild(
            &.{ .slot = 4, .hash = .ZEROES },
        ),
    );

    // 9 is better than 10
    try std.testing.expect(
        try fork_choice.isHeaviestChild(
            &.{ .slot = 9, .hash = .ZEROES },
        ),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 10, .hash = .ZEROES })),
    );

    // Add new leaf 8, which is better than 9, as both have weight 0
    try fork_choice.addNewLeafSlot(
        allocator,
        .{ .slot = 8, .hash = .ZEROES },
        .{ .slot = 4, .hash = .ZEROES },
    );
    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 8, .hash = .ZEROES }),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 9, .hash = .ZEROES })),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 10, .hash = .ZEROES })),
    );

    // Add vote for 9, it's the best again
    const stake: u64 = 100;
    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 9, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );

    try std.testing.expect(
        try fork_choice.isHeaviestChild(&.{ .slot = 9, .hash = .ZEROES }),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 8, .hash = .ZEROES })),
    );
    try std.testing.expect(
        !(try fork_choice.isHeaviestChild(&.{ .slot = 10, .hash = .ZEROES })),
    );
}

// Analogous to [test_mark_invalid_then_add_new_heavier_duplicate_slot](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L3589)
test "HeaviestSubtreeForkChoice.markInvalidThenAddNewHeavierDuplicateSlot" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
    };

    const stake: u64 = 100;
    // Setup a fork structure with duplicates and mark one as invalid
    const duplicate_fork: TestDuplicateForks = try .setup(allocator);
    defer duplicate_fork.deinit(allocator);

    const fork_choice = duplicate_fork.fork_choice;
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;

    // Mark one of the duplicate leaves as invalid
    try fork_choice.markForkInvalidCandidate(allocator, &duplicate_leaves_descended_from_4[1]);

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    // If we add a new version of the duplicate slot that is not descended from the invalid
    // candidate and votes for that duplicate slot, the new duplicate slot should be picked
    // once it has more weight
    const new_duplicate_hash: Hash = .ZEROES;

    // The hash has to be smaller in order for the votes to be counted
    try std.testing.expect(
        new_duplicate_hash.order(&duplicate_leaves_descended_from_4[0].hash) == .lt,
    );
    const duplicate_slot = duplicate_leaves_descended_from_4[0].slot;
    const new_duplicate: SlotAndHash = .{ .slot = duplicate_slot, .hash = new_duplicate_hash };
    try fork_choice.addNewLeafSlot(allocator, new_duplicate, .{ .slot = 3, .hash = .ZEROES });

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = new_duplicate },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = new_duplicate },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );

    try std.testing.expectEqual(
        new_duplicate,
        fork_choice.heaviestOverallSlot(),
    );
}

// Analogous to [test_mark_valid_invalid_forks](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L3383)
test "HeaviestSubtreeForkChoice.markValidInvalidForks" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
    };

    // Create fork choice with the standard test fork structure
    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    const stake: u64 = 100;
    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 6, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 6, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 2, .hash = .ZEROES } },
    };
    const expected_best_slot: SlotAndHash = .{ .slot = 6, .hash = .ZEROES };
    try std.testing.expectEqual(expected_best_slot, try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    ));
    try std.testing.expectEqual(
        expected_best_slot,
        fork_choice.deepestOverallSlot(),
    );

    // Simulate a vote on slot 5
    const last_voted_slot_hash: SlotAndHash = .{ .slot = 5, .hash = .ZEROES };
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(allocator);
    _ = try replay_tower.recordBankVote(
        allocator,
        last_voted_slot_hash.slot,
        last_voted_slot_hash.hash,
    );

    // The heaviest_slot_on_same_voted_fork() should be 6, descended from 5.
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = .ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // Mark slot 5 as invalid
    const invalid_candidate = last_voted_slot_hash;
    try fork_choice.markForkInvalidCandidate(allocator, &invalid_candidate);
    try std.testing.expect(!fork_choice.isCandidate(&invalid_candidate).?);

    // The ancestor 3 is still a candidate
    try std.testing.expect(
        fork_choice.isCandidate(&.{ .slot = 3, .hash = .ZEROES }).?,
    );

    // The best fork should be its ancestor 3, not the other fork at 4.
    try std.testing.expectEqual(3, fork_choice.heaviestOverallSlot().slot);

    // After marking the last vote in the tower as invalid, `heaviest_slot_on_same_voted_fork()`
    // should instead use the deepest slot metric, which is still 6
    try std.testing.expectEqual(
        SlotAndHash{ .slot = 6, .hash = .ZEROES },
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // Adding another descendant to the invalid candidate won't
    // update the best slot, even if it contains votes
    const new_leaf7: SlotAndHash = .{ .slot = 7, .hash = .ZEROES };
    try fork_choice.addNewLeafSlot(allocator, new_leaf7, .{ .slot = 6, .hash = .ZEROES });
    const invalid_slot_ancestor: u64 = 3;
    try std.testing.expectEqual(
        invalid_slot_ancestor,
        fork_choice.heaviestOverallSlot().slot,
    );
    const pubkey_votes2 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = new_leaf7 },
    };
    try std.testing.expectEqual(
        SlotAndHash{ .slot = invalid_slot_ancestor, .hash = .ZEROES },
        try fork_choice.addVotes(
            allocator,
            &pubkey_votes2,
            &epoch_tracker,
        ),
    );

    // However this should update the `heaviest_slot_on_same_voted_fork` since we use
    // deepest metric for invalid forks
    try std.testing.expectEqual(
        new_leaf7,
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // Adding a descendant to the ancestor of the invalid candidate *should* update
    // the best slot though, since the ancestor is on the heaviest fork
    const new_leaf8 = SlotAndHash{ .slot = 8, .hash = .ZEROES };
    try fork_choice.addNewLeafSlot(
        allocator,
        new_leaf8,
        .{ .slot = invalid_slot_ancestor, .hash = .ZEROES },
    );
    try std.testing.expectEqual(new_leaf8, fork_choice.heaviestOverallSlot());
    // Should not update the `heaviest_slot_on_same_voted_fork` because the new leaf
    // is not descended from the last vote
    try std.testing.expectEqual(
        new_leaf7,
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );

    // If we mark slot a descendant of `invalid_candidate` as valid, then that
    // should also mark `invalid_candidate` as valid, and the best slot should
    // be the leaf of the heaviest fork, `new_leaf_slot`.
    try fork_choice.markForkValidCandidate(allocator, &invalid_candidate, {});

    try std.testing.expect(fork_choice.isCandidate(&invalid_candidate).?);
    try std.testing.expectEqual(
        // Should pick the smaller slot of the two new equally weighted leaves
        new_leaf7,
        fork_choice.heaviestOverallSlot(),
    );
    // Should update the `heaviest_slot_on_same_voted_fork` as well
    try std.testing.expectEqual(
        new_leaf7,
        (try fork_choice.heaviestSlotOnSameVotedFork(&replay_tower)).?,
    );
}

// Analogous to [test_set_root_and_add_votes](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L1717)
test "HeaviestSubtreeForkChoice.setRootAndAddVotes" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const stake: u64 = 100;
    const vote_pubkeys = [_]Pubkey{
        Pubkey.initRandom(random),
    };

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    // Vote for slot 2
    const pubkey_votes1 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 2, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes1,
        &epoch_tracker,
    );
    try std.testing.expectEqual(4, fork_choice.heaviestOverallSlot().slot);

    // Set a root
    try fork_choice.setTreeRoot(allocator, &.{ .slot = 1, .hash = .ZEROES });

    // Vote again for slot 3 on a different fork than the last vote,
    // verify this fork is now the best fork
    const pubkey_votes2 = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
    };

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes2,
        &epoch_tracker,
    );

    try std.testing.expectEqual(6, fork_choice.heaviestOverallSlot().slot);
    try std.testing.expectEqual(
        0,
        fork_choice.stakeForSlot(&.{ .slot = 1, .hash = .ZEROES }).?,
    );
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSlot(&.{ .slot = 3, .hash = .ZEROES }).?,
    );

    for ([_]u64{ 1, 3 }) |slot| {
        try std.testing.expectEqual(
            stake,
            fork_choice.stakeForSubtree(&.{ .slot = slot, .hash = .ZEROES }).?,
        );
    }

    // Set a root at last vote
    try fork_choice.setTreeRoot(allocator, &.{ .slot = 3, .hash = .ZEROES });

    // Check new leaf 7 is still propagated properly
    try fork_choice.addNewLeafSlot(
        allocator,
        .{ .slot = 7, .hash = .ZEROES },
        .{ .slot = 6, .hash = .ZEROES },
    );
    try std.testing.expectEqual(7, fork_choice.heaviestOverallSlot().slot);
}

// Analogous to [test_split_off_on_best_path](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L4013)
test "HeaviestSubtreeForkChoice.splitOffOnBestPath" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const stake: u64 = 100;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
    };

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 2, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 5, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[3], .slot_hash = .{ .slot = 6, .hash = .ZEROES } },
    };

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );

    try std.testing.expectEqual(6, fork_choice.heaviestOverallSlot().slot);

    // Split off at 6
    var split_tree_6 =
        try fork_choice.splitOff(
            allocator,
            &registry,
            .{ .slot = 6, .hash = .ZEROES },
        );
    defer split_tree_6.deinit(allocator);
    try std.testing.expectEqual(5, fork_choice.heaviestOverallSlot().slot);
    try std.testing.expectEqual(6, split_tree_6.heaviestOverallSlot().slot);

    // Split off at 3
    var split_tree_3 =
        try fork_choice.splitOff(
            allocator,
            &registry,
            .{ .slot = 3, .hash = .ZEROES },
        );
    defer split_tree_3.deinit(allocator);
    try std.testing.expectEqual(4, fork_choice.heaviestOverallSlot().slot);
    try std.testing.expectEqual(5, split_tree_3.heaviestOverallSlot().slot);

    // Split off at 1
    var registry3 = sig.prometheus.Registry(.{}).init(allocator);
    defer registry3.deinit();
    var split_tree_1 =
        try fork_choice.splitOff(
            allocator,
            &registry3,
            .{ .slot = 1, .hash = .ZEROES },
        );
    defer split_tree_1.deinit(allocator);
    try std.testing.expectEqual(0, fork_choice.heaviestOverallSlot().slot);
    try std.testing.expectEqual(4, split_tree_1.heaviestOverallSlot().slot);
}

// Analogous to [test_split_off_simple](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L3906)
test "HeaviestSubtreeForkChoice.splitOffSimple" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const stake: u64 = 100;

    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
    };

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 2, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 6, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[3], .slot_hash = .{ .slot = 4, .hash = .ZEROES } },
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var tree = try fork_choice.splitOff(
        allocator,
        &registry,
        .{ .slot = 5, .hash = .ZEROES },
    );
    defer tree.deinit(allocator);

    try std.testing.expectEqual(
        3 * stake,
        fork_choice.stakeForSubtree(&.{ .slot = 0, .hash = .ZEROES }).?,
    );
    try std.testing.expectEqual(
        2 * stake,
        fork_choice.stakeForSubtree(&.{ .slot = 2, .hash = .ZEROES }).?,
    );
    try std.testing.expectEqual(
        stake,
        fork_choice.stakeForSubtree(&.{ .slot = 3, .hash = .ZEROES }).?,
    );
    try std.testing.expectEqual(
        null,
        fork_choice.stakeForSubtree(&.{ .slot = 5, .hash = .ZEROES }),
    );
    try std.testing.expectEqual(
        null,
        fork_choice.stakeForSubtree(&.{ .slot = 6, .hash = .ZEROES }),
    );
    try std.testing.expectEqual(
        stake,
        tree.stakeForSubtree(&.{ .slot = 5, .hash = .ZEROES }).?,
    );
    try std.testing.expectEqual(
        stake,
        tree.stakeForSubtree(&.{ .slot = 6, .hash = .ZEROES }).?,
    );

    try std.testing.expectEqual(
        null,
        tree.fork_infos.get(tree.tree_root).?.parent,
    );
}

// Analogous to [test_split_off_subtree_with_dups](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L4173)
test "HeaviestSubtreeForkChoice.splitOffSubtreeWithDups" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const vote_pubkeys = [_]Pubkey{
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
    };

    const stake: u64 = 10;

    const duplicate_fork: TestDuplicateForks = try .setup(allocator);
    defer duplicate_fork.deinit(allocator);

    const fork_choice = duplicate_fork.fork_choice;
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;
    const duplicate_leaves_descended_from_5 = duplicate_fork.duplicate_leaves_descended_from_5;
    const duplicate_leaves_descended_from_6 = duplicate_fork.duplicate_leaves_descended_from_6;

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = duplicate_leaves_descended_from_4[0] },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = duplicate_leaves_descended_from_4[1] },
        .{ .pubkey = vote_pubkeys[2], .slot_hash = duplicate_leaves_descended_from_5[0] },
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    // duplicate_leaves_descended_from_4 are sorted, and fork choice will pick the smaller
    // one in the event of a tie
    const expected_best_slot_hash = duplicate_leaves_descended_from_4[0];

    try std.testing.expectEqual(
        expected_best_slot_hash,
        try fork_choice.addVotes(
            allocator,
            &pubkey_votes,
            &epoch_tracker,
        ),
    );

    try std.testing.expectEqual(
        expected_best_slot_hash,
        fork_choice.heaviestOverallSlot(),
    );

    const expected_deepest_slot_hash = duplicate_leaves_descended_from_6[1];
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    var tree = try fork_choice.splitOff(
        allocator,
        &registry,
        .{ .slot = 2, .hash = .ZEROES },
    );
    defer tree.deinit(allocator);

    try std.testing.expectEqual(
        duplicate_leaves_descended_from_5[0],
        fork_choice.heaviestOverallSlot(),
    );
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );

    try std.testing.expectEqual(
        expected_best_slot_hash,
        tree.heaviestOverallSlot(),
    );
    try std.testing.expectEqual(
        expected_best_slot_hash,
        tree.deepestOverallSlot(),
    );
}

// Analogous to [test_split_off_unvoted](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L3969)
test "HeaviestSubtreeForkChoice.splitOffUnvoted" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const stake: u64 = 100;

    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
    };

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 3, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 5, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 6, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[3], .slot_hash = .{ .slot = 1, .hash = .ZEROES } },
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    var tree = try fork_choice.splitOff(
        allocator,
        &registry,
        .{ .slot = 2, .hash = .ZEROES },
    );
    defer tree.deinit(allocator);

    try std.testing.expectEqual(
        4 * stake,
        fork_choice.stakeForSubtree(&.{ .slot = 0, .hash = .ZEROES }).?,
    );
    try std.testing.expectEqual(
        3 * stake,
        fork_choice.stakeForSubtree(&.{ .slot = 3, .hash = .ZEROES }).?,
    );
    try std.testing.expectEqual(
        null,
        fork_choice.stakeForSubtree(&.{ .slot = 2, .hash = .ZEROES }),
    );
    try std.testing.expectEqual(
        null,
        fork_choice.stakeForSubtree(&.{ .slot = 4, .hash = .ZEROES }),
    );
    try std.testing.expectEqual(
        0,
        tree.stakeForSubtree(&.{ .slot = 2, .hash = .ZEROES }).?,
    );
    try std.testing.expectEqual(
        0,
        tree.stakeForSubtree(&.{ .slot = 4, .hash = .ZEROES }).?,
    );
}

// Analogous to [test_split_off_with_dups](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/consensus/heaviest_subtree_fork_choice.rs#L4118)
test "HeaviestSubtreeForkChoice.splitOffWithDups" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    const vote_pubkeys = [_]Pubkey{
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
    };

    const stake: u64 = 10;

    const duplicate_fork: TestDuplicateForks = try .setup(allocator);
    defer duplicate_fork.deinit(allocator);

    const fork_choice = duplicate_fork.fork_choice;
    const duplicate_leaves_descended_from_4 = duplicate_fork.duplicate_leaves_descended_from_4;
    const duplicate_leaves_descended_from_5 = duplicate_fork.duplicate_leaves_descended_from_5;
    const duplicate_leaves_descended_from_6 = duplicate_fork.duplicate_leaves_descended_from_6;

    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = duplicate_leaves_descended_from_4[0] },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = duplicate_leaves_descended_from_4[1] },
        .{ .pubkey = vote_pubkeys[2], .slot_hash = duplicate_leaves_descended_from_5[0] },
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    // duplicate_leaves_descended_from_4 are sorted, and fork choice will pick the smaller
    // one in the event of a tie
    const expected_best_slot_hash = duplicate_leaves_descended_from_4[0];
    try std.testing.expectEqual(
        expected_best_slot_hash,
        try fork_choice.addVotes(
            allocator,
            &pubkey_votes,
            &epoch_tracker,
        ),
    );

    try std.testing.expectEqual(
        expected_best_slot_hash,
        fork_choice.heaviestOverallSlot(),
    );
    const expected_deepest_slot_hash = duplicate_leaves_descended_from_6[1];
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    var tree = try fork_choice.splitOff(
        allocator,
        &registry,
        expected_best_slot_hash,
    );
    defer tree.deinit(allocator);

    try std.testing.expectEqual(
        duplicate_leaves_descended_from_4[1],
        fork_choice.heaviestOverallSlot(),
    );
    try std.testing.expectEqual(
        expected_deepest_slot_hash,
        fork_choice.deepestOverallSlot(),
    );
    try std.testing.expectEqual(
        expected_best_slot_hash,
        tree.heaviestOverallSlot(),
    );
    try std.testing.expectEqual(
        expected_best_slot_hash,
        tree.deepestOverallSlot(),
    );
}

// Analogous to [test_gossip_vote_doesnt_affect_fork_choice](https://github.com/anza-xyz/agave/blob/fac7555c94030ee08820261bfd53f4b3b4d0112e/core/src/replay_stage.rs#L7538)
test "HeaviestSubtreeForkChoice.gossipVoteDoesntAffectForkChoice" {
    const allocator = std.testing.allocator;

    var fork_choice = try forkChoiceForTest(allocator, fork_tuples[0..]);
    defer fork_choice.deinit(allocator);

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    const stake: u64 = 100;

    const vote_pubkeys = [_]Pubkey{
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
        .initRandom(random),
    };

    // Add votes to make slot 4 the best slot
    const pubkey_votes = [_]PubkeyVote{
        .{ .pubkey = vote_pubkeys[0], .slot_hash = .{ .slot = 4, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[1], .slot_hash = .{ .slot = 4, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[2], .slot_hash = .{ .slot = 4, .hash = .ZEROES } },
        .{ .pubkey = vote_pubkeys[3], .slot_hash = .{ .slot = 4, .hash = .ZEROES } },
    };

    const versioned_stakes = try testEpochStakes(
        allocator,
        &vote_pubkeys,
        stake,
        random,
    );

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    _ = try fork_choice.addVotes(
        allocator,
        &pubkey_votes,
        &epoch_tracker,
    );

    // Best slot is 4
    try std.testing.expectEqual(4, fork_choice.heaviestOverallSlot().slot);

    // Create latest validator votes and add a gossip vote for slot 3
    var latest_validator_votes: LatestValidatorVotes = .empty;
    defer latest_validator_votes.deinit(allocator);

    const vote_pubkey = vote_pubkeys[0];
    const vote_slot: u64 = 3;
    const vote_hash: Hash = .ZEROES;

    // Add a gossip vote (is_replay_vote = false) for slot 3
    _ = try latest_validator_votes.checkAddVote(
        allocator,
        vote_pubkey,
        vote_slot,
        vote_hash,
        .replay, // is_replay_vote = false for gossip vote
    );

    // Call computeBankStats - gossip votes shouldn't affect fork choice
    try fork_choice.processLatestVotes(
        allocator,
        &epoch_tracker,
        &latest_validator_votes,
    );

    // Best slot is still 4 (gossip vote didn't affect fork choice)
    try std.testing.expectEqual(4, fork_choice.heaviestOverallSlot().slot);
}

pub fn forkChoiceForTest(
    allocator: std.mem.Allocator,
    forks: []const TreeNode,
) !ForkChoice {
    if (!builtin.is_test) {
        @compileError("initForTest should only be called in test mode");
    }

    const root = forks[0][1].?;
    var fork_choice: ForkChoice = try .init(
        allocator,
        .noop,
        root,
        sig.prometheus.globalRegistry(),
    );
    errdefer fork_choice.deinit(allocator);

    for (forks) |fork_tuple| {
        const slot_hash, const parent_slot_hash = fork_tuple;
        if (fork_choice.fork_infos.contains(slot_hash)) continue;
        try fork_choice.addNewLeafSlot(allocator, slot_hash, parent_slot_hash);
    }

    return fork_choice;
}

pub const TreeNode = struct { SlotAndHash, ?SlotAndHash };

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
        .{ .slot = 1, .hash = .ZEROES },
        .{ .slot = 0, .hash = .ZEROES },
    },
    // slot 2 is a child of slot 1
    .{
        .{ .slot = 2, .hash = .ZEROES },
        .{ .slot = 1, .hash = .ZEROES },
    },
    // slot 4 is a child of slot 2
    .{
        .{ .slot = 4, .hash = .ZEROES },
        .{ .slot = 2, .hash = .ZEROES },
    },
    // slot 3 is a child of slot 1
    .{
        .{ .slot = 3, .hash = .ZEROES },
        .{ .slot = 1, .hash = .ZEROES },
    },
    // slot 5 is a child of slot 3
    .{
        .{ .slot = 5, .hash = .ZEROES },
        .{ .slot = 3, .hash = .ZEROES },
    },
    // slot 6 is a child of slot 5
    .{
        .{ .slot = 6, .hash = .ZEROES },
        .{ .slot = 5, .hash = .ZEROES },
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
        .{ .slot = 1, .hash = .ZEROES },
        .{ .slot = 0, .hash = .ZEROES },
    },
    // slot 2 is a child of slot 1
    .{
        .{ .slot = 2, .hash = .ZEROES },
        .{ .slot = 1, .hash = .ZEROES },
    },
    // slot 3 is a child of slot 2
    .{
        .{ .slot = 3, .hash = .ZEROES },
        .{ .slot = 2, .hash = .ZEROES },
    },
    // slot 4 is a child of slot 3
    .{
        .{ .slot = 4, .hash = .ZEROES },
        .{ .slot = 3, .hash = .ZEROES },
    },
    // slot 5 is a child of slot 4
    .{
        .{ .slot = 5, .hash = .ZEROES },
        .{ .slot = 4, .hash = .ZEROES },
    },
    // slot 6 is a child of slot 5
    .{
        .{ .slot = 6, .hash = .ZEROES },
        .{ .slot = 5, .hash = .ZEROES },
    },
};

fn compareSlotHashKey(_: void, a: SlotAndHash, b: SlotAndHash) bool {
    if (a.slot == b.slot) {
        return a.hash.order(&b.hash) == .lt;
    }
    return a.slot < b.slot;
}

const TestDuplicateForks = struct {
    fork_choice: *ForkChoice,
    duplicate_leaves_descended_from_4: []SlotAndHash,
    duplicate_leaves_descended_from_5: []SlotAndHash,
    duplicate_leaves_descended_from_6: []SlotAndHash,

    fn deinit(self: TestDuplicateForks, gpa: std.mem.Allocator) void {
        self.fork_choice.deinit(gpa);
        gpa.destroy(self.fork_choice);
        gpa.free(self.duplicate_leaves_descended_from_4);
        gpa.free(self.duplicate_leaves_descended_from_5);
        gpa.free(self.duplicate_leaves_descended_from_6);
    }

    fn setup(gpa: std.mem.Allocator) !TestDuplicateForks {
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
        var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
        const random = prng.random();

        // Build fork structure
        const fork_choice = try gpa.create(ForkChoice);
        errdefer gpa.destroy(fork_choice);
        fork_choice.* = try forkChoiceForTest(gpa, &fork_tuples);
        errdefer fork_choice.deinit(gpa);

        const duplicate_slot: u64 = 10;

        // Create duplicate leaves descended from slot 4
        var dupe_leaves_desc_from_4: std.ArrayListUnmanaged(SlotAndHash) = .empty;
        defer dupe_leaves_desc_from_4.deinit(gpa);
        for (0..2) |_| try dupe_leaves_desc_from_4.append(gpa, .{
            .slot = duplicate_slot,
            .hash = .initRandom(random),
        });

        // Create duplicate leaves descended from slot 5
        var dupe_leaves_desc_from_5: std.ArrayListUnmanaged(SlotAndHash) = .empty;
        defer dupe_leaves_desc_from_5.deinit(gpa);
        for (0..2) |_| try dupe_leaves_desc_from_5.append(gpa, .{
            .slot = duplicate_slot,
            .hash = .initRandom(random),
        });

        // Create duplicate leaves descended from slot 6
        var dupe_leaves_desc_from_6: std.ArrayListUnmanaged(SlotAndHash) = .empty;
        defer dupe_leaves_desc_from_6.deinit(gpa);
        for (0..2) |_| try dupe_leaves_desc_from_6.append(gpa, .{
            .slot = duplicate_slot,
            .hash = .initRandom(random),
        });

        std.mem.sort(SlotAndHash, dupe_leaves_desc_from_4.items, {}, compareSlotHashKey);
        std.mem.sort(SlotAndHash, dupe_leaves_desc_from_5.items, {}, compareSlotHashKey);
        std.mem.sort(SlotAndHash, dupe_leaves_desc_from_6.items, {}, compareSlotHashKey);

        // Add duplicate leaves to the fork structure
        for (dupe_leaves_desc_from_4.items) |duplicate_leaf| {
            try fork_choice.addNewLeafSlot(gpa, duplicate_leaf, .{
                .slot = 4,
                .hash = .ZEROES,
            });
        }
        for (dupe_leaves_desc_from_5.items) |duplicate_leaf| {
            try fork_choice.addNewLeafSlot(gpa, duplicate_leaf, .{
                .slot = 5,
                .hash = .ZEROES,
            });
        }
        for (dupe_leaves_desc_from_6.items) |duplicate_leaf| {
            try fork_choice.addNewLeafSlot(gpa, duplicate_leaf, .{
                .slot = 6,
                .hash = .ZEROES,
            });
        }

        // Verify children of slot 4
        var dup_children_4 = fork_choice.getChildren(&.{
            .slot = 4,
            .hash = .ZEROES,
        }).?;

        std.mem.sort(SlotAndHash, dup_children_4.mutableKeys(), {}, compareSlotHashKey);
        std.debug.assert(dup_children_4.keys()[0].equals(dupe_leaves_desc_from_4.items[0]));
        std.debug.assert(dup_children_4.keys()[1].equals(dupe_leaves_desc_from_4.items[1]));

        var dup_children_5: std.ArrayListUnmanaged(SlotAndHash) = .empty;
        defer dup_children_5.deinit(gpa);

        var children_5 = fork_choice.getChildren(&.{
            .slot = 5,
            .hash = .ZEROES,
        }).?;

        for (children_5.keys()) |key| {
            if (key.slot == duplicate_slot) {
                try dup_children_5.append(gpa, key);
            }
        }

        std.mem.sort(SlotAndHash, dup_children_5.items, {}, compareSlotHashKey);
        std.debug.assert(dup_children_5.items[0].equals(dupe_leaves_desc_from_5.items[0]));
        std.debug.assert(dup_children_5.items[1].equals(dupe_leaves_desc_from_5.items[1]));

        // Verify children of slot 6
        var dup_children_6: std.ArrayListUnmanaged(SlotAndHash) = .empty;
        defer dup_children_6.deinit(gpa);

        var children_6 = fork_choice.getChildren(&.{
            .slot = 6,
            .hash = .ZEROES,
        }).?;

        for (children_6.keys()) |key| {
            if (key.slot == duplicate_slot) {
                try dup_children_6.append(gpa, key);
            }
        }

        std.mem.sort(SlotAndHash, dup_children_6.items, {}, compareSlotHashKey);
        std.debug.assert(dup_children_6.items[0].equals(dupe_leaves_desc_from_6.items[0]));
        std.debug.assert(dup_children_6.items[1].equals(dupe_leaves_desc_from_6.items[1]));

        return .{
            .fork_choice = fork_choice,
            .duplicate_leaves_descended_from_4 = try dupe_leaves_desc_from_4.toOwnedSlice(gpa),
            .duplicate_leaves_descended_from_5 = try dupe_leaves_desc_from_5.toOwnedSlice(gpa),
            .duplicate_leaves_descended_from_6 = try dupe_leaves_desc_from_6.toOwnedSlice(gpa),
        };
    }
};

pub fn testEpochStakes(
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    stake: u64,
    random: std.Random,
) !EpochStakes {
    if (!builtin.is_test) {
        @compileError("testEpochStakes should only be called in test mode");
    }

    var vote_accounts = sig.core.stakes.VoteAccounts{};
    errdefer vote_accounts.deinit(allocator);
    try vote_accounts.vote_accounts.ensureUnusedCapacity(allocator, pubkeys.len);

    for (pubkeys) |pubkey| {
        vote_accounts.vote_accounts.putAssumeCapacity(pubkey, .{
            .stake = stake,
            .account = try sig.core.stakes.VoteAccount.initRandom(
                allocator,
                random,
                .initRandom(random),
            ),
        });
    }

    return .{
        .stakes = .{
            .vote_accounts = vote_accounts,
            .stake_accounts = .empty,
            .unused = 0,
            .epoch = 0,
            .stake_history = .INIT,
        },
        .epoch_authorized_voters = .empty,
        .node_id_to_vote_accounts = .empty,
        .total_stake = pubkeys.len * stake,
    };
}

pub const ForkChoiceMetrics = struct {
    /// Current rooted slot.
    current_root_slot: *sig.prometheus.Gauge(u64),

    /// Current heaviest subtree slot (the slot with most stake)
    current_heaviest_subtree_slot: *sig.prometheus.Gauge(u64),
    /// Current deepest slot (the slot with highest tree height)
    current_deepest_slot: *sig.prometheus.Gauge(u64),
    /// Number of active forks (count of fork candidates for consensus)
    active_fork_count: *sig.prometheus.Gauge(u64),
    /// Total stake in the fork choice tree
    total_stake_in_tree: *sig.prometheus.Gauge(u64),

    /// Number of fork choice updates - indicates consensus activity and health
    updates: *sig.prometheus.Counter,
    /// Time between fork choice updates (seconds) - performance and network health indicator
    update_interval: *sig.prometheus.Histogram,

    /// The number of pubkey votes added per batch.
    pubkey_vote_batch_size: *sig.prometheus.Gauge(u64),

    pub const prefix = "fork_choice";

    pub fn init(registry: *sig.prometheus.Registry(.{})) !ForkChoiceMetrics {
        return try registry.initStruct(ForkChoiceMetrics);
    }

    pub fn histogramBucketsForField(comptime field_name: []const u8) []const f64 {
        const HistogramKind = enum {
            update_interval,
        };

        const time_interval_buckets = &.{ 0.001, 0.01, 0.1, 1, 10, 100, 1000 }; // seconds

        return switch (@field(HistogramKind, field_name)) {
            .update_interval => time_interval_buckets,
        };
    }
};
