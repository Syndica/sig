// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/slot-history/src/lib.rs
// https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/sysvar/fd_sysvar_slot_history.h

const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const SlotHistory = struct {
    bits: sig.bloom.BitVec(u64),
    next_slot: u64,
};
