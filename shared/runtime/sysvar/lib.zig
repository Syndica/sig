const std = @import("std");
const sig = @import("../../lib.zig");

const bincode = sig.bincode;
const Pubkey = sig.core.Pubkey;

pub const OWNER_ID: Pubkey = .parse("Sysvar1111111111111111111111111111111111111");

pub const clock = @import("clock.zig");
pub const epoch_rewards = @import("epoch_rewards.zig");
pub const fees = @import("fees.zig");
pub const last_restart_slot = @import("last_restart_slot.zig");
pub const recent_blockhashes = @import("recent_blockhashes.zig");
pub const rent = @import("rent.zig");
pub const slot_hashes = @import("slot_hashes.zig");
pub const slot_history = @import("slot_history.zig");
pub const stake_history = @import("stake_history.zig");

pub const Clock = clock.Clock;
pub const EpochRewards = epoch_rewards.EpochRewards;
pub const EpochSchedule = sig.core.EpochSchedule;
pub const Fees = fees.Fees;
pub const LastRestartSlot = last_restart_slot.LastRestartSlot;
pub const RecentBlockhashes = recent_blockhashes.RecentBlockhashes;
pub const Rent = rent.Rent;
pub const SlotHashes = slot_hashes.SlotHashes;
pub const SlotHistory = slot_history.SlotHistory;
pub const StakeHistory = stake_history.StakeHistory;

pub const instruction = @import("instruction.zig");

/// Serialize a sysvar value into bytes, keeping the correct buffer length.
/// Needed for "sol_get_sysvar" buffer range checks.
/// [agave] https://github.com/anza-xyz/solana-sdk/blob/9148b5cc95b43319f3451391ec66d0086deb5cfa/account/src/lib.rs#L725
pub fn serialize(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const serialized_size = bincode.sizeOf(value, .{});

    const T = @TypeOf(value);
    const STORAGE_SIZE: usize = if (@hasDecl(T, "STORAGE_SIZE")) T.STORAGE_SIZE else @sizeOf(T);
    const size = @max(serialized_size, STORAGE_SIZE);

    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);

    @memset(buffer, 0);
    _ = try bincode.writeToSlice(buffer, value, .{});
    return buffer;
}
