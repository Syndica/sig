const std = @import("std");
const sig = @import("sig");
const Slot = @import("core").Slot;

const AutoHashMap = std.AutoHashMap;
const Instant = std.time.Instant;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SortedMap = sig.utils.collections.SortedMap;

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
};
