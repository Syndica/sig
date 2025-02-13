const sig = @import("../../sig.zig");
const Pubkey = sig.core.Pubkey;

pub const OWNER_ID =
    Pubkey.parseBase58String("Sysvar1111111111111111111111111111111111111") catch unreachable;

pub const Clock = @import("clock.zig").Clock;
pub const EpochRewards = @import("epoch_rewards.zig").EpochRewards;
pub const EpochSchedule = @import("epoch_schedule.zig").EpochSchedule;
pub const Fees = @import("fees.zig").Fees;
pub const LastRestartSlot = @import("last_restart_slot.zig").LastRestartSlot;
pub const RecentBlockhashes = @import("recent_blockhashes.zig").RecentBlockhashes;
pub const Rent = @import("rent.zig").Rent;
pub const SlotHashes = @import("slot_hashes.zig").SlotHashes;
pub const StakeHistory = @import("stake_history.zig").StakeHistory;
pub const SlotHistory = @import("slot_history.zig").SlotHistory;
