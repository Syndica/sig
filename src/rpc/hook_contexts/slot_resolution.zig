const sig = @import("../../sig.zig");

const Slot = sig.core.Slot;
const Commitment = sig.rpc.methods.common.Commitment;
const SlotTracker = sig.replay.trackers.SlotTracker;
const CommitmentTracker = sig.replay.trackers.CommitmentTracker;

/// Validates `minContextSlot` according to Solana RPC semantics.
pub fn validateMinContextSlot(slot: Slot, min_context_slot: ?Slot) !void {
    if (min_context_slot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }
}

/// Resolve a readable slot from commitment with availability fallback.
///
/// [agave] RPC commitment resolution is bank-based and resilient: if the
/// commitment-selected bank is unavailable, Agave falls back to a root-bank
/// path instead of immediately failing.
/// - commitment bank selection: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L345-L376
/// - root-bank fallback path: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L377-L394
///
/// Sig resolves in slot-space (`SlotTracker`) rather than by `Bank`, so for
/// account/consensus reads we preserve Agave's availability intent via:
///   requested commitment slot -> processed slot
/// and re-validate `minContextSlot` after fallback.
pub fn resolveReadableCommitmentSlot(
    slot_tracker: *SlotTracker,
    commitment: ?Commitment,
    min_context_slot: ?Slot,
) !Slot {
    const resolved_commitment = commitment orelse .finalized;
    var slot = slot_tracker.commitments.get(resolved_commitment);
    try validateMinContextSlot(slot, min_context_slot);

    if (resolved_commitment != .processed and !slot_tracker.contains(slot)) {
        slot = slot_tracker.commitments.get(.processed);
        try validateMinContextSlot(slot, min_context_slot);
    }
    return slot;
}

pub fn slotFromCommitment(
    commitments: *const CommitmentTracker,
    commitment: Commitment,
    min_context_slot: ?Slot,
) !Slot {
    const slot = commitments.get(commitment);
    try validateMinContextSlot(slot, min_context_slot);
    return slot;
}
