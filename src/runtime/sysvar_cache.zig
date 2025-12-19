const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;
const sysvars = sig.runtime.sysvar;

const Pubkey = sig.core.Pubkey;
const Clock = sysvars.Clock;
const EpochSchedule = sig.core.EpochSchedule;
const EpochRewards = sysvars.EpochRewards;
const Rent = sysvars.Rent;
const SlotHashes = sysvars.SlotHashes;
const StakeHistory = sysvars.StakeHistory;
const LastRestartSlot = sysvars.LastRestartSlot;
const Fees = sysvars.Fees;
const RecentBlockhashes = sysvars.RecentBlockhashes;

/// `SysvarCache` provides the runtime with access to sysvars during program execution
///
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/sysvar_cache.rs#L28
pub const SysvarCache = struct {
    // full account data as provided by bank, including any trailing zero bytes
    clock: ?[]const u8 = null,
    epoch_schedule: ?[]const u8 = null,
    epoch_rewards: ?[]const u8 = null,
    rent: ?[]const u8 = null,
    last_restart_slot: ?[]const u8 = null,

    // object representations of large sysvars for convenience
    // these are used by the stake and vote builtin programs
    // these should be removed once those programs are ported to bpf
    slot_hashes: ?[]const u8 = null,
    slot_hashes_obj: ?SlotHashes = null,
    stake_history: ?[]const u8 = null,
    stake_history_obj: ?StakeHistory = null,

    // deprecated sysvars, these should be removed once practical
    fees_obj: ?Fees = null,
    recent_blockhashes_obj: ?RecentBlockhashes = null,

    pub fn deinit(self: *const SysvarCache, allocator: std.mem.Allocator) void {
        if (self.clock) |clock| allocator.free(clock);
        if (self.epoch_schedule) |epoch_schedule| allocator.free(epoch_schedule);
        if (self.epoch_rewards) |epoch_rewards| allocator.free(epoch_rewards);
        if (self.rent) |rent| allocator.free(rent);
        if (self.last_restart_slot) |last_restart_slot| allocator.free(last_restart_slot);
        if (self.slot_hashes) |slot_hashes| allocator.free(slot_hashes);
        if (self.stake_history) |stake_history| allocator.free(stake_history);
    }

    /// Returns the sysvar as an object if it is supported
    /// Replaces the sysvar object getters in Agave
    pub fn get(
        self: *const SysvarCache,
        comptime T: type,
    ) error{UnsupportedSysvar}!T {
        // NOTE: No allocations are actually performed here, we require the allocator purely
        // for bincode compatibility so we use a failing allocator. Clock, EpochSchedule, EpochRewards,
        // Rent, LastRestartSlot, and Fees have comptime known sizes. SlotHashes, StakeHistory, and
        // RecentBlockhashes are allocated on insertion to the sysvar cache.
        const allocator = std.testing.failing_allocator;
        return switch (T) {
            Clock => self.deserialize(allocator, Clock),
            EpochSchedule => self.deserialize(allocator, EpochSchedule),
            EpochRewards => self.deserialize(allocator, EpochRewards),
            Rent => self.deserialize(allocator, Rent),
            LastRestartSlot => self.deserialize(allocator, LastRestartSlot),
            SlotHashes => self.slot_hashes_obj orelse error.UnsupportedSysvar,
            StakeHistory => self.stake_history_obj orelse error.UnsupportedSysvar,
            Fees => self.fees_obj orelse error.UnsupportedSysvar,
            RecentBlockhashes => self.recent_blockhashes_obj orelse error.UnsupportedSysvar,
            else => @compileError("Invalid Sysvar"),
        };
    }

    /// Returns the sysvar as a slice of bytes
    /// This should only be used by the getSysvar syscall
    pub fn getSlice(self: *const SysvarCache, id: Pubkey) ?[]const u8 {
        const field = if (id.equals(&sysvars.Clock.ID))
            self.clock
        else if (id.equals(&sysvars.EpochSchedule.ID))
            self.epoch_schedule
        else if (id.equals(&sysvars.EpochRewards.ID))
            self.epoch_rewards
        else if (id.equals(&sysvars.Rent.ID))
            self.rent
        else if (id.equals(&sysvars.SlotHashes.ID))
            self.slot_hashes
        else if (id.equals(&sysvars.StakeHistory.ID))
            self.stake_history
        else if (id.equals(&sysvars.LastRestartSlot.ID))
            self.last_restart_slot
        else
            return null;

        // Should only return null on invalid ID rather than empty/null slice.
        return field orelse &.{};
    }

    /// Deserialises the sysvar from bytes
    /// This should only be used by the getSysvar syscall
    fn deserialize(
        self: *const SysvarCache,
        allocator: std.mem.Allocator,
        comptime T: type,
    ) error{UnsupportedSysvar}!T {
        const maybe_bytes = switch (T) {
            Clock => self.clock,
            EpochSchedule => self.epoch_schedule,
            EpochRewards => self.epoch_rewards,
            Rent => self.rent,
            LastRestartSlot => self.last_restart_slot,
            else => @compileError("Invalid Sysvar"),
        };
        if (maybe_bytes) |bytes| {
            return bincode.readFromSlice(
                allocator,
                T,
                bytes,
                .{},
            ) catch error.UnsupportedSysvar;
        } else {
            return error.UnsupportedSysvar;
        }
    }
};
