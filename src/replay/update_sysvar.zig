const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;
const sysvars = sig.runtime.sysvar;
const features = sig.runtime.features;

const AccountsDb = sig.accounts_db.AccountsDB;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const SlotState = sig.core.SlotState;
const Slot = sig.core.Slot;
const HardForks = sig.core.HardForks;
const EpochStakes = sig.core.EpochStakes;
const BlockhashQueue = sig.core.BlockhashQueue;

const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.runtime.FeatureSet;
const SysvarCache = sig.runtime.SysvarCache;

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

pub fn fillMissingEntries(
    allocator: Allocator,
    accounts_db: *AccountsDb,
    ancestors: *const Ancestors,
    sysvar_cache: *SysvarCache,
) !void {
    if (sysvar_cache.clock == null) {
        if (getSysvarAndDataFromAccount(
            allocator,
            accounts_db,
            ancestors,
            Clock,
        )) |sysvar_and_data| {
            sysvar_cache.clock = sysvar_and_data.data;
        }
    }

    if (sysvar_cache.epoch_schedule == null) {
        if (getSysvarAndDataFromAccount(
            allocator,
            accounts_db,
            ancestors,
            EpochSchedule,
        )) |sysvar_and_data| {
            sysvar_cache.epoch_schedule = sysvar_and_data.data;
        }
    }

    if (sysvar_cache.epoch_rewards == null) {
        if (getSysvarAndDataFromAccount(
            allocator,
            accounts_db,
            ancestors,
            EpochRewards,
        )) |sysvar_and_data| {
            sysvar_cache.epoch_rewards = sysvar_and_data.data;
        }
    }

    if (sysvar_cache.rent == null) {
        if (getSysvarAndDataFromAccount(
            allocator,
            accounts_db,
            ancestors,
            Rent,
        )) |sysvar_and_data| {
            sysvar_cache.rent = sysvar_and_data.data;
        }
    }

    if (sysvar_cache.last_restart_slot == null) {
        if (getSysvarAndDataFromAccount(
            allocator,
            accounts_db,
            ancestors,
            LastRestartSlot,
        )) |sysvar_and_data| {
            sysvar_cache.last_restart_slot = sysvar_and_data.data;
        }
    }

    if (sysvar_cache.slot_hashes == null) {
        if (getSysvarAndDataFromAccount(
            allocator,
            accounts_db,
            ancestors,
            SlotHashes,
        )) |sysvar_and_data| {
            sysvar_cache.slot_hashes = sysvar_and_data.data;
            sysvar_cache.slot_hashes_obj = sysvar_and_data.sysvar;
        }
    }

    if (sysvar_cache.stake_history == null) {
        if (getSysvarAndDataFromAccount(
            allocator,
            accounts_db,
            ancestors,
            StakeHistory,
        )) |sysvar_and_data| {
            sysvar_cache.stake_history = sysvar_and_data.data;
            sysvar_cache.stake_history_obj = sysvar_and_data.sysvar;
        }
    }

    if (sysvar_cache.fees_obj == null) {
        if (getSysvarFromAccount(
            allocator,
            accounts_db,
            ancestors,
            Fees,
        )) |fees| {
            sysvar_cache.fees_obj = fees;
        }
    }

    if (sysvar_cache.recent_blockhashes_obj == null) {
        if (getSysvarFromAccount(
            allocator,
            accounts_db,
            ancestors,
            RecentBlockhashes,
        )) |recent_block_hashes| {
            sysvar_cache.recent_blockhashes_obj = recent_block_hashes;
        }
    }
}

/// TODO: getTimestampEstimate is called by `nextClock` and requires the stakes cache
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
) Allocator.Error!void {
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
) Allocator.Error!void {
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
) Allocator.Error!void {
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
) Allocator.Error!void {
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
) Allocator.Error!void {
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
) Allocator.Error!void {
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

pub fn updateRecentBlockhashes(
    allocator: std.mem.Allocator,
    ancestors: *const Ancestors,
    rent: *const Rent,
    state: *SlotState,
    accounts_db: *AccountsDb,
    slot: Slot,
    blockhash_queue: *const BlockhashQueue,
) Allocator.Error!void {
    const recent_blockhashes = try RecentBlockhashes.fromBlockhashQueue(
        allocator,
        blockhash_queue,
    );
    defer recent_blockhashes.deinit(allocator);

    try updateSysvarAccount(
        allocator,
        state,
        accounts_db,
        ancestors,
        rent,
        slot,
        RecentBlockhashes,
        recent_blockhashes,
    );
}

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
) Allocator.Error!void {
    // TODO: handle errors directly
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
) Allocator.Error!AccountSharedData {
    // This should NEVER happen, dynamiclly sized sysvars manage there max size.
    if (bincode.sizeOf(sysvar, .{}) > Sysvar.SIZE_OF)
        std.debug.panic("sysvar data size exceeds maximum allowed size: sysvar={s}, size={}", .{
            @typeName(Sysvar),
            bincode.sizeOf(sysvar, .{}),
        });

    const sysvar_data = try allocator.alloc(u8, Sysvar.SIZE_OF);
    errdefer allocator.free(sysvar_data);
    @memset(sysvar_data, 0);

    // writeToSlice may return a 'NoSpaceLeft' error. The above allocation ensures
    // that there is enough space for serialisation.
    _ = bincode.writeToSlice(sysvar_data, sysvar, .{}) catch unreachable;

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

fn getSysvarAndDataFromAccount(
    allocator: std.mem.Allocator,
    accounts_db: *AccountsDb,
    ancestors: *const Ancestors,
    comptime Sysvar: type,
) ?struct { sysvar: Sysvar, data: []const u8 } {
    const maybe_account = accounts_db.getAccountWithAncestors(
        &Sysvar.ID,
        ancestors,
    ) catch return null;

    const account = maybe_account orelse return null;
    defer account.deinit(allocator);

    // TODO: how/can I read this without allocating?
    const data = account.data.dupeAllocatedOwned(allocator) catch
        return null;

    const sysvar = bincode.readFromSlice(
        allocator,
        Sysvar,
        data.owned_allocation,
        .{},
    ) catch {
        data.deinit(allocator);
        return null;
    };

    return .{ .sysvar = sysvar, .data = data.owned_allocation };
}

fn getSysvarFromAccount(
    allocator: std.mem.Allocator,
    accounts_db: *AccountsDb,
    ancestors: *const Ancestors,
    comptime Sysvar: type,
) ?Sysvar {
    const maybe_account = accounts_db.getAccountWithAncestors(
        &Sysvar.ID,
        ancestors,
    ) catch return null;

    const account = maybe_account orelse return null;
    defer account.deinit(allocator);

    const data = account.data.dupeAllocatedOwned(allocator) catch
        return null;
    defer data.deinit(allocator);

    return bincode.readFromSlice(
        allocator,
        Sysvar,
        data.owned_allocation,
        .{},
    ) catch null;
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

/// TODO: Implementation requires stakes cache
/// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2512
fn getTimestampEstimate(
    max_allowable_drift: MaxAllowableDrift,
    epoch_start: ?struct {
        slot: Slot,
        timestamp: i64,
    },
) ?i64 {
    _ = max_allowable_drift;
    _ = epoch_start;
    return null;
}

test createSysvarAccount {
    const allocator = std.testing.allocator;

    inline for (.{
        Clock,
        EpochSchedule,
        EpochRewards,
        Rent,
        LastRestartSlot,
        SlotHashes,
        StakeHistory,
        Fees,
        RecentBlockhashes,
        SlotHistory,
    }) |Sysvar| {
        // TODO: errdefer log for sysvar type
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

test fillMissingEntries {
    const loadTestAccountsDB = sig.accounts_db.db.loadTestAccountsDB;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    // Create accounts db
    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;
    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDB(allocator, false, 1, .noop, snapshot_dir);
    defer accounts_db.deinit();
    defer full_inc_manifest.deinit(allocator);

    // Set slot and ancestors
    const slot = 10;
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    // Create a sysvar cache with all sysvars randomly initialized.
    const expected = try initRandomSysvarCache(allocator, prng.random());
    defer expected.deinit(allocator);

    // Write all sysvars to accounts db. Do not inherit from old accounts.
    try insertSysvarCacheAccounts(
        allocator,
        &accounts_db,
        &expected,
        slot,
        false,
    );

    // Initialize a new sysvar cache and fill it with missing entries.
    var actual = SysvarCache{};
    defer actual.deinit(allocator);

    // Fill missing entries in the sysvar cache from accounts db.
    try fillMissingEntries(
        allocator,
        &accounts_db,
        &ancestors,
        &actual,
    );

    // Check all sysvar accounts are correct
    try std.testing.expectEqualSlices(u8, expected.clock.?, actual.clock.?);
    // try std.testing.expectEqualSlices(u8, expected.epoch_schedule.?, actual.epoch_schedule.?);
    try std.testing.expectEqualSlices(u8, expected.epoch_rewards.?, actual.epoch_rewards.?);
    try std.testing.expectEqualSlices(u8, expected.rent.?, actual.rent.?);
    try std.testing.expectEqualSlices(u8, expected.last_restart_slot.?, actual.last_restart_slot.?);
    try std.testing.expectEqualSlices(u8, expected.slot_hashes.?, actual.slot_hashes.?);
    try std.testing.expectEqualSlices(
        SlotHashes.Entry,
        expected.slot_hashes_obj.?.entries.items,
        actual.slot_hashes_obj.?.entries.items,
    );
    try std.testing.expectEqualSlices(u8, expected.stake_history.?, actual.stake_history.?);
    try std.testing.expectEqualSlices(
        StakeHistory.Entry,
        expected.stake_history_obj.?.entries.items,
        actual.stake_history_obj.?.entries.items,
    );
    try std.testing.expectEqual(expected.fees_obj, actual.fees_obj);
    try std.testing.expectEqualSlices(
        RecentBlockhashes.Entry,
        expected.recent_blockhashes_obj.?.entries.items,
        actual.recent_blockhashes_obj.?.entries.items,
    );
}

fn initRandomSysvarCache(allocator: Allocator, random: std.Random) !SysvarCache {
    if (!builtin.is_test) @compileError("only for testing");

    const clock = Clock.initRandom(random);
    const epoch_schedule = EpochSchedule.initRandom(random);
    const epoch_rewards = EpochRewards.initRandom(random);
    const rent = Rent.initRandom(random);
    const last_restart_slot = LastRestartSlot.initRandom(random);

    const slot_hashes = try SlotHashes.initRandom(allocator, random);
    const stake_history = try StakeHistory.initRandom(allocator, random);
    const fees = Fees.initRandom(random);
    const recent_blockhashes = try RecentBlockhashes.initRandom(allocator, random);

    return .{
        .clock = try sysvars.serialize(allocator, clock),
        .epoch_schedule = try sysvars.serialize(allocator, epoch_schedule),
        .epoch_rewards = try sysvars.serialize(allocator, epoch_rewards),
        .rent = try sysvars.serialize(allocator, rent),
        .last_restart_slot = try sysvars.serialize(allocator, last_restart_slot),
        .slot_hashes = try sysvars.serialize(allocator, slot_hashes),
        .slot_hashes_obj = slot_hashes,
        .stake_history = try sysvars.serialize(allocator, stake_history),
        .stake_history_obj = stake_history,
        .fees_obj = fees,
        .recent_blockhashes_obj = recent_blockhashes,
    };
}

// TODO: Uncomment other sysvars once we can insert accounts for the same slot
fn insertSysvarCacheAccounts(
    allocator: Allocator,
    accounts_db: *AccountsDb,
    sysvar_cache: *const SysvarCache,
    slot: Slot,
    inherit_from_old_account: bool,
) !void {
    var sysvar_accounts = std.MultiArrayList(struct {
        pubkey: Pubkey,
        account: Account,
    }){};
    defer {
        for (sysvar_accounts.slice().items(.account)) |acc| acc.deinit(allocator);
        sysvar_accounts.deinit(allocator);
    }

    inline for (.{
        Clock,
        EpochSchedule,
        EpochRewards,
        Rent,
        LastRestartSlot,
        SlotHashes,
        StakeHistory,
        Fees,
        RecentBlockhashes,
    }) |Sysvar| {
        const old_account = if (inherit_from_old_account)
            accounts_db.getAccount(&Sysvar.ID) catch null
        else
            null;
        defer if (old_account) |acc| acc.deinit(allocator) else {};

        const account = try createSysvarAccount(
            allocator,
            &Rent.DEFAULT,
            Sysvar,
            try sysvar_cache.get(Sysvar),
            if (old_account) |*acc| acc else null,
        );

        try sysvar_accounts.append(allocator, .{ .pubkey = Sysvar.ID, .account = .{
            .lamports = account.lamports,
            .data = .initAllocatedOwned(account.data),
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        } });
    }

    try accounts_db.putAccountSlice(
        sysvar_accounts.slice().items(.account),
        sysvar_accounts.slice().items(.pubkey),
        slot,
    );
}
