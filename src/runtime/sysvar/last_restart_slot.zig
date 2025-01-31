const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/last-restart-slot/src/lib.rs#L15
pub const LastRestartSlot = struct {
    /// The last restart `Slot`.
    last_restart_slot: u64,
};
