//! system variables definitions and addresses (clock, slot_history, …)

const std = @import("std");
const ArrayList = std.ArrayList;

const Slot = @import("../core/time.zig").Slot;
const Epoch = @import("../core/time.zig").Epoch;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const Hash = @import("../core/hash.zig").Hash;

const StakeHistoryEntry = @import("./snapshots.zig").StakeHistoryEntry;
const UnixTimestamp = @import("genesis_config.zig").UnixTimestamp;
const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;

const BitVec = @import("../bloom/bit_vec.zig").BitVec;
const DynamicArrayBitSet = @import("../bloom/bit_set.zig").DynamicArrayBitSet;
const BitVecConfig = @import("../bloom/bit_vec.zig").BitVecConfig;
const bincode = @import("../bincode/bincode.zig");

pub const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days
/// Analogous to [Check](https://github.com/anza-xyz/agave/blob/fc2a8794be2526e9fd6cdbc9b304c055b2d9cc57/sdk/program/src/slot_history.rs#L46)
pub const SlotCheckResult = enum { Future, TooOld, Found, NotFound };

/// note: depreciated sysvars not included:
/// - fees
/// - recent_blockhashes
///
/// Analogous to [SysvarCache](https://github.com/anza-xyz/agave/blob/ebd063eb79c6e2f14da660ccfc90f1d4c0b7db1f/program-runtime/src/sysvar_cache.rs#L28)
pub const IDS = struct {
    pub const clock = Pubkey.fromString("SysvarC1ock11111111111111111111111111111111") catch unreachable;
    pub const epoch_schedule = Pubkey.fromString("SysvarEpochSchedu1e111111111111111111111111") catch unreachable;
    pub const epoch_rewards = Pubkey.fromString("SysvarEpochRewards1111111111111111111111111") catch unreachable;
    pub const rent = Pubkey.fromString("SysvarRent111111111111111111111111111111111") catch unreachable;
    pub const slot_hashes = Pubkey.fromString("SysvarS1otHashes111111111111111111111111111") catch unreachable;
    pub const slot_history = Pubkey.fromString("SysvarS1otHistory11111111111111111111111111") catch unreachable;
    pub const stake_history = Pubkey.fromString("SysvarStakeHistory1111111111111111111111111") catch unreachable;
    pub const last_restart_slot = Pubkey.fromString("SysvarLastRestartS1ot1111111111111111111111") catch unreachable;
};

/// Analogous to [Clock](https://github.com/anza-xyz/agave/blob/fc2a8794be2526e9fd6cdbc9b304c055b2d9cc57/sdk/program/src/clock.rs#L180)
pub const Clock = extern struct {
    /// The current `Slot`.
    slot: Slot,
    /// The timestamp of the first `Slot` in this `Epoch`.
    epoch_start_timestamp: UnixTimestamp,
    /// The current `Epoch`.
    epoch: Epoch,
    /// The future `Epoch` for which the leader schedule has
    /// most recently been calculated.
    leader_schedule_epoch: Epoch,
    /// The approximate real world time of the current slot.
    ///
    /// This value was originally computed from genesis creation time and
    /// network time in slots, incurring a lot of drift. Following activation of
    /// the [`timestamp_correction` and `timestamp_bounding`][tsc] features it
    /// is calculated using a [validator timestamp oracle][oracle].
    ///
    /// [tsc]: https://docs.solana.com/implemented-proposals/bank-timestamp-correction
    /// [oracle]: https://docs.solana.com/implemented-proposals/validator-timestamp-oracle
    unix_timestamp: UnixTimestamp,
};

/// Analogous to [EpochSchedule](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/epoch_schedule.rs#L35)
pub const EpochSchedule = struct {
    /// The maximum number of slots in each epoch.
    slots_per_epoch: u64,

    /// A number of slots before beginning of an epoch to calculate
    /// a leader schedule for that epoch.
    leader_schedule_slot_offset: u64,

    /// Whether epochs start short and grow.
    warmup: bool,

    /// The first epoch after the warmup period.
    ///
    /// Basically: `log2(slots_per_epoch) - log2(MINIMUM_SLOTS_PER_EPOCH)`.
    first_normal_epoch: Epoch,

    /// The first slot after the warmup period.
    ///
    /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
    first_normal_slot: Slot,
};

/// Analogous to [UiEpochRewards](https://github.com/anza-xyz/agave/blob/cf1299a871b5299e70c97f5ad0de3bc3aca0f84a/account-decoder/src/parse_sysvar.rs#L244)
pub const EpochRewards = struct {
    /// total rewards for the current epoch, in lamports
    total_rewards: u64,

    /// distributed rewards for the current epoch, in lamports
    distributed_rewards: u64,

    /// distribution of all staking rewards for the current
    /// epoch will be completed at this block height
    distribution_complete_block_height: u64,
};

/// Analogous to [UiRent](https://github.com/anza-xyz/agave/blob/cf1299a871b5299e70c97f5ad0de3bc3aca0f84a/account-decoder/src/parse_sysvar.rs#L163)
pub const Rent = struct {
    /// Rental rate in lamports/byte-year.
    lamports_per_byte_year: u64,

    /// Amount of time (in years) a balance must include rent for the account to
    /// be rent exempt.
    exemption_threshold: f64,

    /// The percentage of collected rent that is burned.
    ///
    /// Valid values are in the range [0, 100]. The remaining percentage is
    /// distributed to validators.
    burn_percent: u8,
};

const SlotAndHash = @import("./snapshots.zig").SlotAndHash;

/// Analogous to [SysvarAccountType::SlotHashes](https://github.com/anza-xyz/agave/blob/cf1299a871b5299e70c97f5ad0de3bc3aca0f84a/account-decoder/src/parse_sysvar.rs#L118C5-L118C15)
pub const SlotHashes = ArrayList(SlotAndHash);

/// Analogous to [SysvarAccountType::StakeHistory](https://github.com/anza-xyz/agave/blob/cf1299a871b5299e70c97f5ad0de3bc3aca0f84a/account-decoder/src/parse_sysvar.rs#L120)
pub const StakeHistory = ArrayList(struct {
    epoch: Epoch,
    stake_history_entry: StakeHistoryEntry,
});

/// Analogous to [SysvarAccountType::LastRestartSlot](https://github.com/anza-xyz/agave/blob/cf1299a871b5299e70c97f5ad0de3bc3aca0f84a/account-decoder/src/parse_sysvar.rs#L121)
pub const LastRestartSlot = struct {
    last_restart_slot: Slot,
};

/// Analogous to [UiSlotHistory](https://github.com/anza-xyz/agave/blob/cf1299a871b5299e70c97f5ad0de3bc3aca0f84a/account-decoder/src/parse_sysvar.rs#L209)
pub const SlotHistory = struct {
    bits: DynamicArrayBitSet(u64),
    next_slot: Slot,

    pub const @"!bincode-config:bits" = BitVecConfig(u64);

    pub fn deinit(self: SlotHistory, allocator: std.mem.Allocator) void {
        bincode.free(allocator, self);
    }

    pub fn check(self: *const SlotHistory, slot: Slot) SlotCheckResult {
        if (slot > self.newest()) {
            return SlotCheckResult.Future;
        } else if (slot < self.oldest()) {
            return SlotCheckResult.TooOld;
        } else if (self.bits.isSet(slot % MAX_ENTRIES)) {
            return SlotCheckResult.Found;
        } else {
            return SlotCheckResult.NotFound;
        }
    }

    pub fn newest(self: *const SlotHistory) Slot {
        return self.next_slot - 1;
    }

    pub fn oldest(self: *const SlotHistory) Slot {
        return self.next_slot -| MAX_ENTRIES;
    }
};
