const std = @import("std");
const sig = @import("sig");
const Slot = @import("core").Slot;

const AutoHashMap = std.AutoHashMap;
const Instant = std.time.Instant;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SortedMap = sig.utils.collections.SortedMap;

const MAX_ROOT_PRINT_SECONDS: u64 = 60 * 60; // 1 hour

const SlotHashKey = struct {
    slot: Slot,
    hash: Hash,
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
};

/// Analogous to [HeaviestSubtreeForkChoice](https://github.com/anza-xyz/agave/blob/e7301b2a29d14df19c3496579cf8e271b493b3c6/core/src/consensus/heaviest_subtree_fork_choice.rs#L187)
pub const HeaviestSubtreeForkChoice = struct {
    fork_infos: AutoHashMap(SlotHashKey, ForkInfo),
    latest_votes: AutoHashMap(Pubkey, SlotHashKey),
    tree_root: SlotHashKey,
    last_root_time: Instant,

    const Self = @This();

    pub fn new(allocator: *std.mem.Allocator, tree_root: SlotHashKey) Self {
        const heaviest_subtree_fork_choice = .{
            .fork_infos = AutoHashMap(SlotHashKey, ForkInfo).init(allocator),
            .latest_votes = AutoHashMap(Pubkey, SlotHashKey).init(allocator),
            .tree_root = tree_root,
            .last_root_time = Instant.now(),
        };

        return heaviest_subtree_fork_choice;
    }

    pub fn addNewLeafSlot(self: *Self, slot_hash_key: SlotHashKey, maybe_parent: ?SlotHashKey) void {
        if (self.last_root_time.since(Instant.now()) > MAX_ROOT_PRINT_SECONDS) {
            // TODO implement self.print_state();
            self.last_root_time = Instant.now();
        }

        const parent_latest_invalid_ancestor = if (maybe_parent) |p| self.latest_invalid_ancestor(p) else null;
        if (self.fork_infos.getPtr(slot_hash_key)) |fork_info| {
            // Modify existing entry
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
                .children = SortedMap(SlotHashKey, void).init(std.heap.page_allocator),
                .parent = maybe_parent,
                .latest_invalid_ancestor = parent_latest_invalid_ancestor,
                // If the parent is none, then this is the root, which implies this must
                // have reached the duplicate confirmed threshold
                .is_duplicate_confirmed = (maybe_parent == null),
            };

            self.fork_infos.put(slot_hash_key, new_fork_info) catch unreachable;
        }

        const parent = if (maybe_parent) |parent| parent else return null;

        self.fork_infos.get(&parent).?.*.children.put(slot_hash_key, {}) catch {
            // Handle the error if `parent` does not exist or `put` fails
            return error.InvalidParent;
        };
    }

    pub fn latest_invalid_ancestor(self: *const Self, slot_hash_key: SlotHashKey) ?Slot {
        if (self.fork_infos.get(slot_hash_key)) |fork_info| {
            return fork_info.latest_invalid_ancestor;
        }
        return null;
    }
    

    pub fn bestSlot(self: *const Self, slot_hash_key: SlotHashKey) ?SlotHashKey {
        if (self.fork_infos.get(slot_hash_key)) |fork_info| {
            return fork_info.best_slot;
        }
        return null;
    }
};
