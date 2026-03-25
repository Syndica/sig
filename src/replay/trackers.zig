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
const Tower = sig.consensus.tower.Tower;

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
    slots: RwMux(std.AutoArrayHashMapUnmanaged(Slot, *Element)),
    root: std.atomic.Value(Slot),
    commitments: CommitmentTracker,
    wg: *std.Thread.WaitGroup,

    pub const Element = struct {
        constants: SlotConstants,
        state: SlotState,
        destroy_task: ThreadPool.Task = .{ .callback = runDestroy },
        pruned_wg: ?*std.Thread.WaitGroup = null,
        allocator: Allocator,
        rc: ReferenceCounter = .init,

        pub fn toRef(self: *Element) Reference {
            std.debug.assert(self.rc.acquire());
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
            .slots = .init(.empty),
            .commitments = .init(root_slot),
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
        defer slots_lg.unlock();
        const slots = slots_lg.mut();
        for (slots.values()) |element| element.destroy();
        slots.deinit(allocator);
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
            return .{
                .found_existing = true,
                .reference = existing.toRef(),
            };
        }
        try slots.ensureUnusedCapacity(allocator, 1);
        const elem = try allocator.create(Element);
        elem.* = slot_init;
        slots.putAssumeCapacityNoClobber(slot, elem);
        return .{
            .found_existing = false,
            .reference = elem.toRef(),
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

            const ref = value.toRef();
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

/// Tracks the slot for each commitment level.
pub const CommitmentTracker = struct {
    processed: std.atomic.Value(Slot),
    confirmed: std.atomic.Value(Slot),
    finalized: std.atomic.Value(Slot),

    /// This function only supports startup from genesis or from a snapshot.
    ///
    /// When starting from genesis, all the levels should be zero.
    ///
    /// When starting from a snapshot, the snapshot's slot is already processed
    /// from the perspective of all the other state we initialize on startup. We
    /// can't safely make any assumptions about any slots being confirmed or
    /// finalized by the cluster as a whole since the snapshot came only from
    /// one other node. We can only assume that the genesis slot (0) is
    /// confirmed and finalized until we start counting votes.
    pub fn init(start_slot: Slot) CommitmentTracker {
        return .{
            .processed = .init(start_slot),
            .confirmed = .init(0),
            .finalized = .init(0),
        };
    }

    pub fn get(self: *const CommitmentTracker, commitment: Commitment) Slot {
        return switch (commitment) {
            .processed => self.processed.load(.monotonic),
            .confirmed => self.confirmed.load(.monotonic),
            .finalized => self.finalized.load(.monotonic),
        };
    }

    pub fn update(self: *CommitmentTracker, commitment: Commitment, slot: Slot) void {
        return switch (commitment) {
            .processed => self.processed.store(slot, .monotonic),
            .confirmed => _ = self.confirmed.fetchMax(slot, .monotonic),
            .finalized => _ = self.finalized.fetchMax(slot, .monotonic),
        };
    }
};

/// Tracks per-slot commitment stake data for computing confirmation counts.
///
/// Each slot's commitment is a `[32]u64` stake-per-depth histogram: index `i`
/// (0..30) stores the total stake from validators whose lockout tower confirms
/// that slot at exactly depth `i+1`, and index 31 stores rooted stake.
/// For example, `[0, 100, 0, 200, 0, …]` means 100 stake at depth 2 and 200
/// stake at depth 4. Depths are recorded independently; callers that need a
/// cumulative view (e.g. `getConfirmationCount`) accumulate at query time by
/// summing from highest to lowest depth.
///
/// Thread-safe for concurrent reads / exclusive writes.
///
/// [agave] https://github.com/anza-xyz/agave/blob/b6eacb135037ab1021683d28b67a3c60e9039010/rpc-client-api/src/response.rs#L452
pub const BlockCommitmentCache = struct {
    state: RwMux(State),

    const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote.state.MAX_LOCKOUT_HISTORY;
    pub const BlockCommitmentArray = [MAX_LOCKOUT_HISTORY + 1]u64;
    const VOTE_THRESHOLD_SIZE: f64 = 2.0 / 3.0;

    const State = struct {
        block_commitment: std.AutoArrayHashMapUnmanaged(Slot, BlockCommitmentArray),
        total_stake: u64,
        highest_super_majority_root: Slot = 0,
    };

    const BlockCommitment = struct {
        commitment: ?BlockCommitmentArray,
        total_stake: u64,
    };

    pub const DEFAULT: BlockCommitmentCache = .{
        .state = .init(.{
            .block_commitment = .empty,
            .total_stake = 0,
            .highest_super_majority_root = 0,
        }),
    };

    pub fn deinit(self: *BlockCommitmentCache, allocator: Allocator) void {
        var state = self.state.tryWrite() orelse
            @panic("attempted to deinit BlockCommitmentCache while still in use");
        defer state.unlock();
        state.mut().block_commitment.deinit(allocator);
    }

    /// Returns the commitment data for a given slot along with the total active stake.
    ///
    /// [agave] https://github.com/anza-xyz/agave/blob/b6eacb135037ab1021683d28b67a3c60e9039010/runtime/src/commitment.rs#L82
    pub fn getBlockCommitment(self: *BlockCommitmentCache, slot: Slot) BlockCommitment {
        var state = self.state.read();
        defer state.unlock();
        return .{
            .commitment = state.get().block_commitment.get(slot),
            .total_stake = state.get().total_stake,
        };
    }

    /// Returns the lowest confirmation depth at which >2/3 of total stake
    /// has confirmed the given slot. Returns null if the slot is not tracked.
    ///
    /// [agave] https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/runtime/src/commitment.rs#L140
    pub fn getConfirmationCount(self: *BlockCommitmentCache, slot: Slot) ?usize {
        return self.getLockoutCount(slot, VOTE_THRESHOLD_SIZE);
    }

    /// Returns the lowest level at which at least `minimum_stake_percentage` of the total epoch
    /// stake is locked out.
    ///
    /// [agave] https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/runtime/src/commitment.rs#L146
    fn getLockoutCount(
        self: *BlockCommitmentCache,
        slot: Slot,
        minimum_stake_percentage: f64,
    ) ?usize {
        const block_commitment = self.getBlockCommitment(slot);
        const commitments = block_commitment.commitment orelse return null;
        const total_stake = block_commitment.total_stake;
        if (total_stake == 0) return 0;
        var sum: u64 = 0;
        for (0..commitments.len) |idx| {
            sum += commitments[commitments.len - 1 - idx];
            const ratio_avg = @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(total_stake));
            if (ratio_avg > minimum_stake_percentage) return commitments.len - idx;
        }
        return 0;
    }

    /// Builder that collects per-slot commitment data from multiple vote
    /// accounts so the cache can be rebuilt in a single atomic swap.
    /// Designed to be fed from `collectClusterVoteState`'s vote-account
    /// loop via `VoteAccountVisitor`, avoiding the need to iterate vote
    /// accounts a second time.
    pub const Accumulator = struct {
        new_commitment: std.AutoArrayHashMapUnmanaged(Slot, BlockCommitmentArray) = .empty,
        rooted_stake: std.ArrayListUnmanaged(RootedStake) = .empty,
        total_stake: u64 = 0,

        const RootedStake = struct { slot: Slot, stake: u64 };

        /// Record one vote account's lockout tower into the accumulator.
        ///
        /// When `ancestors` is provided (a sorted slice of status-cache root
        /// slots), the function matches Agave's
        /// `aggregate_commitment_for_vote_account` semantics:
        /// - Only ancestor slots are credited (slots outside the window are
        ///   ignored, bounding memory and producing `null` for old queries).
        /// - Rooted stake is credited to every ancestor at or below the tower
        ///   root.
        /// - Confirmation stake is credited to every ancestor between
        ///   consecutive votes (not just the vote slot itself).
        ///
        /// When `ancestors` is `null` the old (unfiltered) behaviour is used
        /// so that call-sites without a StatusCache still work.
        ///
        /// Analogous to [AggregateCommitmentService::aggregate_commitment_for_vote_account](https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/core/src/commitment_service.rs#L226)
        pub fn observeVoteAccount(
            self: *Accumulator,
            allocator: Allocator,
            tower: *const Tower,
            stake: u64,
            ancestors: ?[]const Slot,
        ) error{OutOfMemory}!void {
            self.total_stake += stake;

            const sorted_ancestors = ancestors orelse return;
            if (sorted_ancestors.len == 0) return;

            // Agave-compatible walk over sorted ancestor slots.
            var ancestors_index: usize = 0;

            // 1. Root handling: credit rooted stake to every ancestor <= root.
            if (tower.root) |root| {
                for (sorted_ancestors, 0..) |ancestor, i| {
                    if (ancestor > root) {
                        ancestors_index = i;
                        break;
                    }
                    const entry = try self.new_commitment.getOrPutValue(
                        allocator,
                        ancestor,
                        std.mem.zeroes(BlockCommitmentArray),
                    );
                    entry.value_ptr[MAX_LOCKOUT_HISTORY] += stake;
                }
                try self.rooted_stake.append(allocator, .{ .slot = root, .stake = stake });
            }

            // 2. Vote handling: credit confirmation stake to all ancestors
            //    between consecutive votes.
            for (tower.votes.constSlice()) |vote| {
                while (sorted_ancestors[ancestors_index] <= vote.slot) {
                    if (sorted_ancestors[ancestors_index] > vote.slot) break;
                    const entry = try self.new_commitment.getOrPutValue(
                        allocator,
                        sorted_ancestors[ancestors_index],
                        std.mem.zeroes(BlockCommitmentArray),
                    );
                    std.debug.assert(vote.confirmation_count > 0);
                    std.debug.assert(vote.confirmation_count <= MAX_LOCKOUT_HISTORY);
                    entry.value_ptr[vote.confirmation_count - 1] += stake;
                    ancestors_index += 1;

                    if (ancestors_index == sorted_ancestors.len) return;
                }
            }
        }

        /// Compute the highest root slot where cumulative stake exceeds 2/3
        /// of total stake, matching Agave's `get_highest_super_majority_root`.
        ///
        /// [agave] https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/core/src/commitment_service.rs#L27
        pub fn highestSuperMajorityRoot(self: *const Accumulator) Slot {
            if (self.total_stake == 0) return 0;

            // Sort descending by slot.
            const items = self.rooted_stake.items;
            std.mem.sort(RootedStake, items, {}, struct {
                fn cmp(_: void, a: RootedStake, b: RootedStake) bool {
                    return a.slot > b.slot;
                }
            }.cmp);

            var stake_sum: u64 = 0;
            for (items) |entry| {
                stake_sum += entry.stake;
                if (@as(f64, @floatFromInt(stake_sum)) / @as(f64, @floatFromInt(self.total_stake)) > VOTE_THRESHOLD_SIZE) {
                    return entry.slot;
                }
            }
            return 0;
        }

        pub fn deinit(self: *Accumulator, allocator: Allocator) void {
            self.new_commitment.deinit(allocator);
            self.rooted_stake.deinit(allocator);
        }
    };

    /// Atomically swap the cache contents with the data from an Accumulator.
    /// The accumulator's map is consumed (moved); the caller must not use it
    /// afterwards.
    pub fn commitAccumulated(self: *BlockCommitmentCache, acc: *Accumulator) void {
        const hsmr = acc.highestSuperMajorityRoot();
        var state = self.state.write();
        defer state.unlock();
        const old = state.mut().block_commitment;
        state.mut().* = .{
            .block_commitment = acc.new_commitment,
            .total_stake = acc.total_stake,
            .highest_super_majority_root = @max(state.get().highest_super_majority_root, hsmr),
        };
        // Give the old map back to the accumulator for reuse next cycle.
        acc.new_commitment = old;
        acc.new_commitment.clearRetainingCapacity();
        acc.rooted_stake.clearRetainingCapacity();
        acc.total_stake = 0;
    }

    /// Returns the highest slot where >2/3 of total stake has rooted.
    pub fn highestSuperMajorityRoot(self: *BlockCommitmentCache) Slot {
        var state = self.state.read();
        defer state.unlock();
        return state.get().highest_super_majority_root;
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

        try std.testing.expectEqual(4, tracker.commitments.get(.processed));
        try std.testing.expectEqual(0, tracker.commitments.get(.confirmed));
        try std.testing.expectEqual(0, tracker.commitments.get(.finalized));
        try std.testing.expectEqual(4, tracker.root.load(.monotonic));
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

test "BlockCommitmentCache getConfirmationCount returns null for unknown slot" {
    var cache: BlockCommitmentCache = .DEFAULT;
    try std.testing.expectEqual(null, cache.getConfirmationCount(42));
}

test "BlockCommitmentCache getConfirmationCount returns 0 when below threshold" {
    const allocator = std.testing.allocator;
    var cache: BlockCommitmentCache = .DEFAULT;
    defer cache.deinit(allocator);

    // Set up: slot 10 has 100 stake at depth 1, total stake = 1000
    // 100/1000 = 0.1 which is < 2/3, so confirmation count should be 0
    var commitment: BlockCommitmentCache.BlockCommitmentArray = std.mem.zeroes(
        BlockCommitmentCache.BlockCommitmentArray,
    );
    commitment[0] = 100; // depth 1
    {
        var state = cache.state.write();
        defer state.unlock();
        try state.mut().block_commitment.put(allocator, 10, commitment);
        state.mut().total_stake = 1000;
    }

    try std.testing.expectEqual(@as(usize, 0), cache.getConfirmationCount(10).?);
}

test "BlockCommitmentCache getConfirmationCount returns correct depth" {
    const allocator = std.testing.allocator;
    var cache: BlockCommitmentCache = .DEFAULT;
    defer cache.deinit(allocator);

    // Set up: slot 10 has 700 stake at depth 5, total stake = 1000
    // 700/1000 = 0.7 > 2/3, so confirmation count should be 6 (depth index 5 + 1)
    var commitment: BlockCommitmentCache.BlockCommitmentArray = std.mem.zeroes(
        BlockCommitmentCache.BlockCommitmentArray,
    );
    commitment[5] = 700; // depth 6 (index 5)
    {
        var state = cache.state.write();
        defer state.unlock();
        try state.mut().block_commitment.put(allocator, 10, commitment);
        state.mut().total_stake = 1000;
    }

    try std.testing.expectEqual(@as(usize, 6), cache.getConfirmationCount(10).?);
}

test "BlockCommitmentCache getConfirmationCount accumulates from high to low" {
    const allocator = std.testing.allocator;
    var cache: BlockCommitmentCache = .DEFAULT;
    defer cache.deinit(allocator);

    // Stake distributed across multiple depths:
    // depth 10 (index 9): 200 stake
    // depth 8 (index 7): 300 stake
    // depth 5 (index 4): 200 stake
    // total = 1000
    // Walking high to low: sum at 9 = 200 (20%), sum at 7 = 500 (50%), sum at 4 = 700 (70% > 2/3)
    // Should return 5 (index 4 + 1)
    var commitment: BlockCommitmentCache.BlockCommitmentArray = std.mem.zeroes(
        BlockCommitmentCache.BlockCommitmentArray,
    );
    commitment[9] = 200;
    commitment[7] = 300;
    commitment[4] = 200;
    {
        var state = cache.state.write();
        defer state.unlock();
        try state.mut().block_commitment.put(allocator, 10, commitment);
        state.mut().total_stake = 1000;
    }

    try std.testing.expectEqual(@as(usize, 5), cache.getConfirmationCount(10).?);
}

test "BlockCommitmentCache getConfirmationCount rooted stake at index 31" {
    const allocator = std.testing.allocator;
    var cache: BlockCommitmentCache = .DEFAULT;
    defer cache.deinit(allocator);

    // All stake is rooted (index 31 = MAX_LOCKOUT_HISTORY)
    var commitment: BlockCommitmentCache.BlockCommitmentArray = std.mem.zeroes(
        BlockCommitmentCache.BlockCommitmentArray,
    );
    commitment[BlockCommitmentCache.MAX_LOCKOUT_HISTORY] = 700;
    {
        var state = cache.state.write();
        defer state.unlock();
        try state.mut().block_commitment.put(allocator, 10, commitment);
        state.mut().total_stake = 1000;
    }

    // Should return MAX_LOCKOUT_HISTORY + 1 = 32 (highest possible confirmation)
    try std.testing.expectEqual(
        @as(usize, BlockCommitmentCache.MAX_LOCKOUT_HISTORY + 1),
        cache.getConfirmationCount(10).?,
    );
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

test "BlockCommitmentCache getBlockCommitment returns data for known slot" {
    const allocator = std.testing.allocator;
    var cache: BlockCommitmentCache = .DEFAULT;
    defer cache.deinit(allocator);

    var commitment: BlockCommitmentCache.BlockCommitmentArray = std.mem.zeroes(
        BlockCommitmentCache.BlockCommitmentArray,
    );
    commitment[0] = 500;
    commitment[5] = 300;
    {
        var state = cache.state.write();
        defer state.unlock();
        try state.mut().block_commitment.put(allocator, 42, commitment);
        state.mut().total_stake = 2000;
    }

    const result = cache.getBlockCommitment(42);
    try std.testing.expectEqual(@as(u64, 2000), result.total_stake);
    try std.testing.expectEqual(@as(u64, 500), result.commitment.?[0]);
    try std.testing.expectEqual(@as(u64, 300), result.commitment.?[5]);
}

test "BlockCommitmentCache getBlockCommitment returns null for unknown slot" {
    var cache: BlockCommitmentCache = .DEFAULT;
    const result = cache.getBlockCommitment(99);
    try std.testing.expectEqual(
        @as(?BlockCommitmentCache.BlockCommitmentArray, null),
        result.commitment,
    );
    try std.testing.expectEqual(@as(u64, 0), result.total_stake);
}

test "BlockCommitmentCache getConfirmationCount returns 0 when total stake is zero" {
    const allocator = std.testing.allocator;
    var cache: BlockCommitmentCache = .DEFAULT;
    defer cache.deinit(allocator);

    var commitment: BlockCommitmentCache.BlockCommitmentArray = std.mem.zeroes(
        BlockCommitmentCache.BlockCommitmentArray,
    );
    commitment[0] = 100;
    {
        var state = cache.state.write();
        defer state.unlock();
        try state.mut().block_commitment.put(allocator, 10, commitment);
        // total_stake remains 0
    }

    try std.testing.expectEqual(@as(usize, 0), cache.getConfirmationCount(10).?);
}

test "BlockCommitmentCache commitAccumulated swaps data atomically" {
    const allocator = std.testing.allocator;

    var cache: BlockCommitmentCache = .DEFAULT;
    defer cache.deinit(allocator);

    // Pre-populate cache with some old data
    {
        var state = cache.state.write();
        defer state.unlock();
        var old_commitment: BlockCommitmentCache.BlockCommitmentArray = std.mem.zeroes(
            BlockCommitmentCache.BlockCommitmentArray,
        );
        old_commitment[0] = 111;
        try state.mut().block_commitment.put(allocator, 1, old_commitment);
        state.mut().total_stake = 999;
    }

    // Build accumulator with new data
    var tower: Tower = .{ .root = 10 };
    try tower.votes.append(.{ .slot = 42, .confirmation_count = 5 });

    const ancestors = [_]Slot{ 10, 42 };
    var acc: BlockCommitmentCache.Accumulator = .{};
    defer acc.deinit(allocator);
    try acc.observeVoteAccount(allocator, &tower, 700, &ancestors);

    // Commit: should swap cache contents
    cache.commitAccumulated(&acc);

    // Cache should now have the accumulator's data
    const result = cache.getBlockCommitment(42);
    try std.testing.expectEqual(@as(u64, 700), result.total_stake);
    try std.testing.expectEqual(@as(u64, 700), result.commitment.?[4]);

    // Root slot 10 should also be in cache
    const root_result = cache.getBlockCommitment(10);
    try std.testing.expectEqual(
        @as(u64, 700),
        root_result.commitment.?[BlockCommitmentCache.MAX_LOCKOUT_HISTORY],
    );

    // Old slot 1 should no longer be in cache
    try std.testing.expectEqual(
        @as(?BlockCommitmentCache.BlockCommitmentArray, null),
        cache.getBlockCommitment(1).commitment,
    );

    // Accumulator should be reset for reuse
    try std.testing.expectEqual(@as(u64, 0), acc.total_stake);
    try std.testing.expectEqual(@as(usize, 0), acc.new_commitment.count());
}

test "BlockCommitmentCache Accumulator multiple vote accounts accumulate" {
    const allocator = std.testing.allocator;

    var acc: BlockCommitmentCache.Accumulator = .{};
    defer acc.deinit(allocator);

    const ancestors = [_]Slot{100};

    // First vote account votes on slot 100 at depth 2
    var tower1: Tower = .{ .root = null };
    try tower1.votes.append(.{ .slot = 100, .confirmation_count = 2 });
    try acc.observeVoteAccount(allocator, &tower1, 300, &ancestors);

    // Second vote account also votes on slot 100 at depth 2
    var tower2: Tower = .{ .root = null };
    try tower2.votes.append(.{ .slot = 100, .confirmation_count = 2 });
    try acc.observeVoteAccount(allocator, &tower2, 500, &ancestors);

    // Stake should accumulate: 300 + 500 = 800
    try std.testing.expectEqual(@as(u64, 800), acc.total_stake);
    const entry = acc.new_commitment.get(100).?;
    try std.testing.expectEqual(@as(u64, 800), entry[1]); // depth index = min(2-1, 30) = 1
}

test "BlockCommitmentCache Accumulator ancestor-filtered walk credits intermediate ancestors" {
    const allocator = std.testing.allocator;

    // Tower: root=80, votes at 100 (conf 5) and 200 (conf 1).
    // Ancestors (sorted): 70, 80, 90, 95, 100, 150, 200.
    var tower: Tower = .{ .root = 80 };
    try tower.votes.append(.{ .slot = 100, .confirmation_count = 5 });
    try tower.votes.append(.{ .slot = 200, .confirmation_count = 1 });

    const ancestors = [_]Slot{ 70, 80, 90, 95, 100, 150, 200 };

    var acc: BlockCommitmentCache.Accumulator = .{};
    defer acc.deinit(allocator);

    try acc.observeVoteAccount(allocator, &tower, 600, &ancestors);

    try std.testing.expectEqual(@as(u64, 600), acc.total_stake);

    // Ancestors <= root (70, 80): rooted stake at index MAX_LOCKOUT_HISTORY
    const root_idx = BlockCommitmentCache.MAX_LOCKOUT_HISTORY;
    try std.testing.expectEqual(@as(u64, 600), acc.new_commitment.get(70).?[root_idx]);
    try std.testing.expectEqual(@as(u64, 600), acc.new_commitment.get(80).?[root_idx]);

    // Ancestors > root and <= first vote (90, 95, 100): conf 5 → depth index 4
    try std.testing.expectEqual(@as(u64, 600), acc.new_commitment.get(90).?[4]);
    try std.testing.expectEqual(@as(u64, 600), acc.new_commitment.get(95).?[4]);
    try std.testing.expectEqual(@as(u64, 600), acc.new_commitment.get(100).?[4]);

    // Ancestors > first vote and <= second vote (150, 200): conf 1 → depth index 0
    try std.testing.expectEqual(@as(u64, 600), acc.new_commitment.get(150).?[0]);
    try std.testing.expectEqual(@as(u64, 600), acc.new_commitment.get(200).?[0]);

    // Only ancestor slots should be present (7 entries total).
    try std.testing.expectEqual(@as(usize, 7), acc.new_commitment.count());
}

test "BlockCommitmentCache Accumulator ancestor-filtered walk excludes non-ancestor slots" {
    const allocator = std.testing.allocator;

    // Tower with vote at slot 500, but ancestors only cover slots up to 300.
    var tower: Tower = .{ .root = null };
    try tower.votes.append(.{ .slot = 500, .confirmation_count = 3 });

    const ancestors = [_]Slot{ 100, 200, 300 };

    var acc: BlockCommitmentCache.Accumulator = .{};
    defer acc.deinit(allocator);

    try acc.observeVoteAccount(allocator, &tower, 400, &ancestors);

    // All three ancestors are <= vote slot 500, so they get conf stake.
    try std.testing.expectEqual(@as(u64, 400), acc.new_commitment.get(100).?[2]);
    try std.testing.expectEqual(@as(u64, 400), acc.new_commitment.get(200).?[2]);
    try std.testing.expectEqual(@as(u64, 400), acc.new_commitment.get(300).?[2]);

    // Slot 500 itself is NOT an ancestor, so it should NOT be present.
    try std.testing.expectEqual(
        @as(?BlockCommitmentCache.BlockCommitmentArray, null),
        acc.new_commitment.get(500),
    );
}

test "BlockCommitmentCache Accumulator ancestor-filtered root-only tower" {
    const allocator = std.testing.allocator;

    // Tower with root but no votes.
    var tower: Tower = .{ .root = 100 };

    const ancestors = [_]Slot{ 50, 75, 100, 150 };

    var acc: BlockCommitmentCache.Accumulator = .{};
    defer acc.deinit(allocator);

    try acc.observeVoteAccount(allocator, &tower, 200, &ancestors);

    // Ancestors <= root (50, 75, 100) get rooted stake.
    const root_idx = BlockCommitmentCache.MAX_LOCKOUT_HISTORY;
    try std.testing.expectEqual(@as(u64, 200), acc.new_commitment.get(50).?[root_idx]);
    try std.testing.expectEqual(@as(u64, 200), acc.new_commitment.get(75).?[root_idx]);
    try std.testing.expectEqual(@as(u64, 200), acc.new_commitment.get(100).?[root_idx]);

    // Ancestor 150 is > root and there are no votes, so it should not be present.
    try std.testing.expectEqual(
        @as(?BlockCommitmentCache.BlockCommitmentArray, null),
        acc.new_commitment.get(150),
    );
}
