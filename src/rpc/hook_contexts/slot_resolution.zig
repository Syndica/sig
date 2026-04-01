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

/// Resolve a readable slot from commitment with Agave-style availability fallback.
///
/// [agave] `JsonRpcRequestProcessor::bank()` resolves a commitment-selected
/// bank, and if that bank is missing from `BankForks`, falls back to root bank.
/// [agave] `get_bank_with_config()` then validates `min_context_slot` against
/// the *selected* bank slot (after fallback).
/// - bank selection/fallback: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L345-L394
/// - min context validation: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L270-L285
///
/// Sig resolves in slot-space (`SlotTracker`) instead of bank-space, so we
/// mirror this by selecting:
///   requested commitment slot -> root slot (if unavailable)
/// then validating `minContextSlot` on the chosen slot.
pub fn resolveReadableCommitmentSlot(
    slot_tracker: *SlotTracker,
    commitments: *const CommitmentTracker,
    commitment: ?Commitment,
    min_context_slot: ?Slot,
) !Slot {
    const resolved_commitment = commitment orelse .finalized;
    var slot = commitments.get(resolved_commitment);
    if (!slot_tracker.contains(slot)) slot = slot_tracker.root.load(.monotonic);
    try validateMinContextSlot(slot, min_context_slot);
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
