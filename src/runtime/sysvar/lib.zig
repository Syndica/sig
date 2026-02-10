const std = @import("std");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;
const Pubkey = sig.core.Pubkey;

pub const OWNER_ID: Pubkey = .parse("Sysvar1111111111111111111111111111111111111");

pub const Clock = @import("clock.zig").Clock;
pub const EpochRewards = @import("epoch_rewards.zig").EpochRewards;
pub const EpochSchedule = sig.core.EpochSchedule;
pub const Fees = @import("fees.zig").Fees;
pub const LastRestartSlot = @import("last_restart_slot.zig").LastRestartSlot;
pub const RecentBlockhashes = @import("recent_blockhashes.zig").RecentBlockhashes;
pub const Rent = @import("rent.zig").Rent;
pub const SlotHashes = @import("slot_hashes.zig").SlotHashes;
pub const SlotHistory = @import("slot_history.zig").SlotHistory;
pub const StakeHistory = @import("stake_history.zig").StakeHistory;

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
