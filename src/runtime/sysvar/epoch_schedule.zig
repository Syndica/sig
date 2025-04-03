const std = @import("std");
const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;

// inlined to avoid solana_clock dep
const DEFAULT_SLOTS_PER_EPOCH: u64 = 432_000;

/// The minimum number of slots per epoch during the warmup period.
///
/// Based on `MAX_LOCKOUT_HISTORY` from `vote_program`.
pub const MINIMUM_SLOTS_PER_EPOCH: u64 = 32;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/epoch-schedule/src/lib.rs#L56
pub const EpochSchedule = sig.core.EpochSchedule;
