const builtin = @import("builtin");
const std = @import("std");
const solana = @import("lib").solana;

const Pubkey = solana.Pubkey;
const Slot = solana.Slot;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/last-restart-slot/src/lib.rs#L15
pub const LastRestartSlot = extern struct {
    /// The last restart `Slot`.
    last_restart_slot: Slot,

    pub const ID: Pubkey = .parse("SysvarLastRestartS1ot1111111111111111111111");

    pub const INIT = LastRestartSlot{
        .last_restart_slot = 0,
    };

    pub const STORAGE_SIZE: u64 = 8;

    pub fn initRandom(random: std.Random) LastRestartSlot {
        if (!builtin.is_test) @compileError("only for testing");
        return .{ .last_restart_slot = random.int(Slot) };
    }
};
