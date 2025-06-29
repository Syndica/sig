const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;
const sysvars = sig.runtime.sysvar;
const features = sig.runtime.features;

const AccountsDb = sig.accounts_db.AccountsDB;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Ancestors = sig.core.status_cache.Ancestors;
const Account = sig.core.Account;
const SlotState = sig.core.SlotState;
const Slot = sig.core.Slot;
const HardForks = sig.core.HardForks;
const EpochStakes = sig.core.EpochStakes;
const BlockhashQueue = sig.core.BlockhashQueue;

const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.runtime.FeatureSet;

const Clock = sysvars.Clock;
const EpochSchedule = sysvars.EpochSchedule;
const EpochRewards = sysvars.EpochRewards;
const Fees = sysvars.Fees;
const LastRestartSlot = sysvars.LastRestartSlot;
const RecentBlockhashes = sysvars.RecentBlockhashes;
const Rent = sysvars.Rent;
const SlotHashes = sysvars.SlotHashes;
const StakeHistory = sysvars.StakeHistory;
const SlotHistory = sysvars.SlotHistory;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub fn updateClock(
    allocator: std.mem.Allocator,
    ancestors: *const Ancestors,
    epoch_schedule: *const EpochSchedule,
    rent: *const Rent,
    state: *SlotState,
    accounts_db: *AccountsDb,
    genesis_creation_time: i64,
    slot: Slot,
    epoch: Epoch,
    parent_epoch: ?Epoch,
) !void {
    const clock = nextClock(
        ancestors,
        epoch_schedule,
        genesis_creation_time,
        accounts_db,
        slot,
        epoch,
        parent_epoch,
    );
    try updateSysvarAccount(
        allocator,
        state,
        accounts_db,
        ancestors,
        rent,
        slot,
        Clock,
        clock,
    );
}

pub fn updateLastRestartSlot(
    allocator: std.mem.Allocator,
    ancestors: *const Ancestors,
    feature_set: *const FeatureSet,
    hard_forks: *const HardForks,
    rent: *const Rent,
    state: *SlotState,
    accounts_db: *AccountsDb,
    slot: Slot,
) !void {
    if (!feature_set.active.contains(features.LAST_RESTART_SLOT_SYSVAR)) return;

    const new_last_restart_slot = blk: {
        const iter = std.mem.reverseIterator(hard_forks.forks.items);
        while (iter.next()) |hf| if (hf.slot <= slot) break :blk hf.slot;
        break :blk 0;
    };

    if (getSysvarFromAccount(
        failing_allocator,
        accounts_db,
        ancestors,
        LastRestartSlot,
    )) |current| {
        // Only write a new LastRestartSlot if it has changed.
        if (new_last_restart_slot == current.last_restart_slot) return;
    }

    try updateSysvarAccount(
        allocator,
        state,
        accounts_db,
        ancestors,
        rent,
        slot,
        LastRestartSlot,
        new_last_restart_slot,
    );
}

pub fn updateSlotHistory(
    allocator: std.mem.Allocator,
    ancestors: *const Ancestors,
    rent: *const Rent,
    state: *SlotState,
    accounts_db: *AccountsDb,
    slot: Slot,
) !void {
    const slot_history: SlotHistory = getSysvarFromAccount(
        allocator,
        accounts_db,
        ancestors,
        SlotHistory,
    ) orelse SlotHistory.default(allocator);
    defer slot_history.deinit(allocator);

    slot_history.add(slot);

    try updateSysvarAccount(
        allocator,
        state,
        accounts_db,
        ancestors,
        rent,
        slot,
        SlotHistory,
        slot_history,
    );
}

pub fn updateSlotHashes(
    allocator: std.mem.Allocator,
    ancestors: *const Ancestors,
    rent: *const Rent,
    state: *SlotState,
    accounts_db: *AccountsDb,
    slot: Slot,
) !void {
    const slot_hashes: SlotHashes = getSysvarFromAccount(
        allocator,
        accounts_db,
        ancestors,
        SlotHashes,
    ) orelse SlotHashes.default(allocator);
    defer slot_hashes.deinit(allocator);

    slot_hashes.add(slot);

    try updateSysvarAccount(
        allocator,
        state,
        accounts_db,
        ancestors,
        rent,
        slot,
        SlotHashes,
        slot_hashes,
    );
}

// TODO: Requires StakesCache and EpochStakesMap
// pub const MAX_LEADER_SCHEDULE_STAKES: Epoch = 5;
// pub fn updateEpochStakes(
//     allocator: std.mem.Allocator,
//     ancestors: *const Ancestors,
//     rent: *const Rent,
//     state: *SlotState,
//     accounts_db: *AccountsDb,
//     epoch_stakes: *std.AutoArrayHashMap(Epoch, EpochStakes),
//     stakes_cache: *StakesCache,
//     slot: Slot,
//     leader_schedule_epoch: Epoch,
// ) !void {
//     if (epoch_stakes.contains(leader_schedule_epoch)) return;

//     try removeOldEpochStakes(
//         allocator,
//         epoch_stakes,
//         leader_schedule_epoch,
//     );
// }

// fn removeOldEpochStakes(
//     allocator: std.mem.Allocator,
//     epoch_stakes: *std.AutoArrayHashMap(Epoch, EpochStakes),
//     leader_schedule_epoch: Epoch,
// ) !void {
//     var remove_keys = try std.ArrayListUnmanaged(Epoch).initCapacity(
//         allocator,
//         epoch_stakes.count(),
//     );
//     defer allocator.free(remove_keys);

//     for (epoch_stakes.keys()) |epoch| {
//         if (epoch < leader_schedule_epoch -| MAX_LEADER_SCHEDULE_STAKES) {
//             try remove_keys.append(epoch);
//         }
//     }

//     for (remove_keys.items) |epoch| epoch_stakes.swapRemove(epoch);
// }

pub fn updateRent(
    allocator: std.mem.Allocator,
    ancestors: *const Ancestors,
    rent: *const Rent,
    state: *SlotState,
    accounts_db: *AccountsDb,
    slot: Slot,
) !void {
    try updateSysvarAccount(
        allocator,
        state,
        accounts_db,
        ancestors,
        rent,
        slot,
        Rent,
        rent.*,
    );
}

pub fn updateEpochSchedule(
    allocator: std.mem.Allocator,
    ancestors: *const Ancestors,
    rent: *const Rent,
    state: *SlotState,
    accounts_db: *AccountsDb,
    slot: Slot,
    epoch_schedule: EpochSchedule,
) !void {
    try updateSysvarAccount(
        allocator,
        state,
        accounts_db,
        ancestors,
        rent,
        slot,
        EpochSchedule,
        epoch_schedule,
    );
}

// TODO: Requires StakesCache
// pub fn updateStakeHistory(
//     allocator: std.mem.Allocator,
//     ancestors: *const Ancestors,
//     rent: *const Rent,
//     state: *SlotState,
//     accounts_db: *AccountsDb,
//     slot: Slot,
//     epoch: Epoch,
//     maybe_epoch: ?Epoch,
//     stakes_cache: *const StakesCache,
// ) !void {
//     if (maybe_epoch) |e| if (e == epoch) return;
//     try updateSysvarAccount(
//         allocator,
//         state,
//         accounts_db,
//         ancestors,
//         rent,
//         slot,
//         StakeHistory
//         stakes_cache.stakes().history(),
//     );
// }

// TODO: Update RecentBlockhashes
// pub fn updateRecentBlockhashes(
//     allocator: std.mem.Allocator,
//     ancestors: *const Ancestors,
//     rent: *const Rent,
//     state: *SlotState,
//     accounts_db: *AccountsDb,
//     slot: Slot,
//     blockhash_queue: *const BlockhashQueue,
// ) !void {
//     const recent_blockhashes = blockhash_queue.
// }

/// Update sysvar account is used to update sysvar accounts in the validator runtime
/// outside of the SVM. This is referred to as an 'off-chain' account update. The current sysvar
/// account is loaded from the accounts database using the current ancestors and a new account is
/// created which inherits the lamports and rent epoch from the old account if it exists. The new
/// account lamports are then adjusted to ensure rent exemption. The new account is written back
/// to accounts db, and the slot capitalization is updated to reflect the change in account lamports.
fn updateSysvarAccount(
    allocator: std.mem.Allocator,
    state: *SlotState,
    accounts_db: *AccountsDb,
    ancestors: *const Ancestors,
    rent: *const Rent,
    slot: u64,
    comptime Sysvar: type,
    sysvar: Sysvar,
) !void {
    const old_account = accounts_db.getAccountWithAncestors(
        &Sysvar.ID,
        ancestors,
    ) catch null;

    const new_account = try createSysvarAccount(
        allocator,
        rent,
        Sysvar,
        sysvar,
        &old_account,
    );

    if (new_account.lamports > old_account.lamports)
        state.capitalization.fetchAdd(new_account.lamports - old_account.lamports, .monotonic)
    else if (new_account.lamports < old_account.lamports)
        state.capitalization.fetchSub(old_account.lamports - new_account.lamports, .monotonic);

    try accounts_db.putAccount(slot, Sysvar.ID, new_account);
}

/// Create a new sysvar account with the provided sysvar data. If an old account is provided,
/// the new account will inherit the lamports and rent epoch from the old account, ensuring that
/// the new account is rent-exempt. If no old account is provided, the new account will be created
/// with the minimum lamports required for rent exemption based on the sysvar data size.
fn createSysvarAccount(
    allocator: std.mem.Allocator,
    rent: *const Rent,
    comptime Sysvar: type,
    sysvar: Sysvar,
    old_account: ?*const Account,
) !AccountSharedData {
    const sysvar_data = try allocator.alloc(u8, @max(
        Sysvar.SIZE_OF,
        bincode.sizeOf(sysvar, .{}),
    ));
    errdefer allocator.free(sysvar_data);
    @memset(sysvar_data, 0);

    _ = try bincode.writeToSlice(sysvar_data, sysvar, .{});

    const lamports_for_rent = rent.minimumBalance(sysvar_data.len);
    const lamports, const rent_epoch = if (old_account) |acc|
        .{ @max(acc.lamports, lamports_for_rent), acc.rent_epoch }
    else
        .{ lamports_for_rent, 0 };

    return .{
        .lamports = lamports,
        .data = sysvar_data,
        .owner = sysvars.OWNER_ID,
        .executable = false,
        .rent_epoch = rent_epoch,
    };
}

/// Attempt to read and deserialize a sysvar account from accounts db. Caller owns any memory
/// allocated during deserialization.
fn getSysvarFromAccount(
    allocator: std.mem.Allocator,
    accounts_db: *AccountsDb,
    ancestors: *const Ancestors,
    comptime Sysvar: type,
) ?Sysvar {
    const account = accounts_db.getAccountWithAncestors(
        &Sysvar.ID,
        ancestors,
    ) catch return null;

    return bincode.readFromSlice(
        allocator,
        Sysvar,
        account.data,
        .{},
    ) catch return null;
}

fn nextClock(
    ancestors: *const Ancestors,
    epoch_schedule: *const EpochSchedule,
    genesis_creation_time: i64,
    accounts_db: *AccountsDb,
    slot: Slot,
    epoch: Epoch,
    parent_epoch: ?Epoch,
) Clock {
    if (slot == 0) return .{
        .slot = slot,
        .epoch_start_timestamp = genesis_creation_time,
        .epoch = epoch,
        .leader_schedule_epoch = epoch_schedule.getLeaderScheduleEpoch(slot),
        .unix_timestamp = genesis_creation_time,
    };

    const clock = getSysvarFromAccount(
        failing_allocator,
        accounts_db,
        ancestors,
        Clock.ID,
    ) orelse Clock.DEFAULT;

    var unix_timestamp = clock.unix_timestamp;

    if (getTimestampEstimate(
        MaxAllowableDrift.DEFAULT,
        .{
            epoch_schedule.getFirstSlotInEpoch(parent_epoch orelse epoch),
            clock.epoch_start_timestamp,
        },
    )) |timestamp_estimate| {
        if (timestamp_estimate > unix_timestamp) unix_timestamp = timestamp_estimate;
    }

    const epoch_start_timestamp = if (parent_epoch != null and parent_epoch.? != epoch)
        unix_timestamp
    else
        clock.epoch_start_timestamp;

    return .{
        .slot = slot,
        .epoch_start_timestamp = epoch_start_timestamp,
        .epoch = epoch,
        .leader_schedule_epoch = epoch_schedule.getLeaderScheduleEpoch(slot),
        .unix_timestamp = unix_timestamp,
    };
}

const MaxAllowableDrift = struct {
    fast: u32,
    slot: u32,

    pub const MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST: u32 = 25;
    pub const MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW_V2: u32 = 150;

    pub const DEFAULT: MaxAllowableDrift = .{
        .fast = MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST,
        .slow = MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW_V2,
    };
};

fn getTimestampEstimate(
    // stakes_cache: *const StakesCache,
    max_allowable_drift: MaxAllowableDrift,
    epoch_start: ?struct {
        slot: Slot,
        timestamp: i64,
    },
) ?i64 {
    _ = max_allowable_drift;
    _ = epoch_start;
    // TODO: Implement
    // https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2512
    return null;
}

test createSysvarAccount {
    const allocator = std.testing.allocator;

    inline for (.{
        Clock,
        EpochSchedule,
        EpochRewards,
        Fees,
        LastRestartSlot,
        RecentBlockhashes,
        Rent,
        SlotHashes,
        StakeHistory,
        SlotHistory,
    }) |Sysvar| {
        // Required since default
        const default = if (@hasDecl(Sysvar, "default"))
            try Sysvar.default(allocator)
        else
            Sysvar.DEFAULT;
        defer if (@hasDecl(Sysvar, "deinit")) default.deinit(allocator) else {};

        try testCreateSysvarAccount(allocator, Sysvar, default, null);
        try testCreateSysvarAccount(allocator, Sysvar, default, &.{
            .lamports = 100,
            .data = .initEmpty(0),
            .owner = Pubkey.ZEROES,
            .executable = true,
            .rent_epoch = 50,
        });
    }
}

fn testCreateSysvarAccount(
    allocator: std.mem.Allocator,
    comptime Sysvar: type,
    sysvar: Sysvar,
    old_account: ?*const Account,
) !void {
    const rent = Rent.DEFAULT;

    const sysvar_data = try allocator.alloc(u8, @max(
        Sysvar.SIZE_OF,
        bincode.sizeOf(sysvar, .{}),
    ));
    defer allocator.free(sysvar_data);
    @memset(sysvar_data, 0);

    _ = try bincode.writeToSlice(sysvar_data, sysvar, .{});

    const account = try createSysvarAccount(
        allocator,
        &rent,
        Sysvar,
        sysvar,
        old_account,
    );
    defer allocator.free(account.data);

    const lamports_for_rent = rent.minimumBalance(sysvar_data.len);
    const expected_lamports, const expected_rent_epoch = if (old_account) |acc|
        .{ @max(acc.lamports, lamports_for_rent), acc.rent_epoch }
    else
        .{ lamports_for_rent, 0 };

    try std.testing.expectEqual(expected_lamports, account.lamports);
    try std.testing.expectEqualSlices(u8, sysvar_data, account.data);
    try std.testing.expectEqualSlices(u8, &sysvars.OWNER_ID.data, &account.owner.data);
    try std.testing.expectEqual(false, account.executable);
    try std.testing.expectEqual(expected_rent_epoch, account.rent_epoch);
}
