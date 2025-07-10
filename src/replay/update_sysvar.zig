const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const bincode = sig.bincode;
const sysvars = sig.runtime.sysvar;
const features = sig.runtime.features;

const AccountsDb = sig.accounts_db.AccountsDB;

const Epoch = sig.core.Epoch;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const EpochStakesMap = sig.core.EpochStakesMap;
const HardForks = sig.core.HardForks;
const BlockhashQueue = sig.core.BlockhashQueue;
const Slot = sig.core.Slot;
const SlotState = sig.core.SlotState;
const StakesCache = sig.core.StakesCache;

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

pub const UpdateClockDeps = struct {
    feature_set: *const FeatureSet,
    epoch_schedule: *const EpochSchedule,
    epoch_stakes_map: *const EpochStakesMap,
    stakes_cache: *StakesCache,

    epoch: Epoch,
    parent_epoch: ?Epoch,
    genesis_creation_time: i64,
    ns_per_slot: u64,

    update_sysvar_deps: UpdateSysvarAccountDeps,
};

pub fn updateClock(
    allocator: std.mem.Allocator,
    deps: UpdateClockDeps,
) !void {
    const clock = try nextClock(
        allocator,
        deps.feature_set,
        deps.update_sysvar_deps.ancestors,
        deps.epoch_schedule,
        deps.stakes_cache,
        deps.epoch_stakes_map,
        deps.ns_per_slot,
        deps.genesis_creation_time,
        deps.update_sysvar_deps.accounts_db,
        deps.update_sysvar_deps.slot,
        deps.epoch,
        deps.parent_epoch,
    );
    try updateSysvarAccount(
        allocator,
        Clock,
        clock,
        deps.update_sysvar_deps,
    );
}

pub fn updateLastRestartSlot(
    allocator: std.mem.Allocator,
    feature_set: *const FeatureSet,
    hard_forks: *const HardForks,
    deps: UpdateSysvarAccountDeps,
) !void {
    if (!feature_set.active.contains(features.LAST_RESTART_SLOT_SYSVAR)) return;

    const new_last_restart_slot = blk: {
        var iter = std.mem.reverseIterator(hard_forks.entries.items);
        while (iter.next()) |hf| if (hf.slot <= deps.slot) break :blk hf.slot;
        break :blk 0;
    };

    if (getSysvarFromAccount(
        allocator,
        deps.accounts_db,
        deps.ancestors,
        LastRestartSlot,
    )) |current| {
        // Only write a new LastRestartSlot if it has changed.
        if (new_last_restart_slot == current.last_restart_slot) return;
    }

    try updateSysvarAccount(
        allocator,
        LastRestartSlot,
        .{ .last_restart_slot = new_last_restart_slot },
        deps,
    );
}

pub fn updateSlotHistory(
    allocator: std.mem.Allocator,
    deps: UpdateSysvarAccountDeps,
) !void {
    var slot_history: SlotHistory = getSysvarFromAccount(
        allocator,
        deps.accounts_db,
        deps.ancestors,
        SlotHistory,
    ) orelse try SlotHistory.default(allocator);
    defer slot_history.deinit(allocator);

    slot_history.add(deps.slot);

    try updateSysvarAccount(
        allocator,
        SlotHistory,
        slot_history,
        deps,
    );
}

pub fn updateSlotHashes(
    allocator: std.mem.Allocator,
    parent_slot: Slot,
    parent_hash: Hash,
    deps: UpdateSysvarAccountDeps,
) !void {
    var slot_hashes: SlotHashes = getSysvarFromAccount(
        allocator,
        deps.accounts_db,
        deps.ancestors,
        SlotHashes,
    ) orelse try SlotHashes.default(allocator);
    defer slot_hashes.deinit(allocator);

    slot_hashes.add(parent_slot, parent_hash);

    try updateSysvarAccount(
        allocator,
        SlotHashes,
        slot_hashes,
        deps,
    );
}

pub fn updateRent(
    allocator: std.mem.Allocator,
    rent: Rent,
    deps: UpdateSysvarAccountDeps,
) !void {
    try updateSysvarAccount(
        allocator,
        Rent,
        rent,
        deps,
    );
}

pub fn updateEpochSchedule(
    allocator: std.mem.Allocator,
    epoch_schedule: EpochSchedule,
    deps: UpdateSysvarAccountDeps,
) !void {
    try updateSysvarAccount(
        allocator,
        EpochSchedule,
        epoch_schedule,
        deps,
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
    blockhash_queue: *const BlockhashQueue,
    deps: UpdateSysvarAccountDeps,
) !void {
    const recent_blockhashes = try RecentBlockhashes.fromBlockhashQueue(
        allocator,
        blockhash_queue,
    );
    defer recent_blockhashes.deinit(allocator);

    try updateSysvarAccount(
        allocator,
        RecentBlockhashes,
        recent_blockhashes,
        deps,
    );
}

pub const UpdateSysvarAccountDeps = struct {
    accounts_db: *AccountsDb,
    capitalization: *Atomic(u64),
    ancestors: *const Ancestors,
    rent: *const Rent,
    slot: Slot,
};

/// Update sysvar account is used to update sysvar accounts in the validator runtime
/// outside of the SVM. This is referred to as an 'off-chain' account update. The current sysvar
/// account is loaded from the accounts database using the current ancestors and a new account is
/// created which inherits the lamports and rent epoch from the old account if it exists. The new
/// account lamports are then adjusted to ensure rent exemption. The new account is written back
/// to accounts db, and the slot capitalization is updated to reflect the change in account lamports.
fn updateSysvarAccount(
    allocator: std.mem.Allocator,
    comptime Sysvar: type,
    sysvar: Sysvar,
    deps: UpdateSysvarAccountDeps,
) !void {
    // TODO: handle errors directly
    const maybe_old_account = deps.accounts_db.getAccountWithAncestors(
        &Sysvar.ID,
        deps.ancestors,
    ) catch null;
    defer if (maybe_old_account) |old_account| old_account.deinit(allocator);

    const new_account = try createSysvarAccount(
        allocator,
        deps.rent,
        Sysvar,
        sysvar,
        if (maybe_old_account) |acc| &acc else null,
    );
    defer allocator.free(new_account.data);

    if (maybe_old_account) |old_account| {
        if (new_account.lamports > old_account.lamports)
            _ = deps.capitalization.fetchAdd(
                new_account.lamports - old_account.lamports,
                .monotonic,
            )
        else if (new_account.lamports < old_account.lamports)
            _ = deps.capitalization.fetchSub(
                old_account.lamports - new_account.lamports,
                .monotonic,
            );
    } else {
        _ = deps.capitalization.fetchAdd(new_account.lamports, .monotonic);
    }

    try deps.accounts_db.putAccount(deps.slot, Sysvar.ID, new_account);
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
    allocator: Allocator,
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
        allocator,
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
    const loadTestAccountsDbEmpty = sig.accounts_db.db.loadTestAccountsDbEmpty;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    // Create accounts db
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var accounts_db = try loadTestAccountsDbEmpty(allocator, false, .noop, tmp_dir.dir);
    defer accounts_db.deinit();

    // Set slot and ancestors
    const slot = 10;
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    // Create a sysvar cache with all sysvars randomly initialized.
    const expected = try initSysvarCacheWithRandomValues(allocator, prng.random());
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
    try std.testing.expectEqualSlices(u8, expected.epoch_schedule.?, actual.epoch_schedule.?);
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

fn initSysvarCacheWithRandomValues(allocator: Allocator, random: std.Random) !SysvarCache {
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

fn initSysvarCacheWithDefaultValues(allocator: Allocator) !SysvarCache {
    if (!builtin.is_test) @compileError("only for testing");

    const clock = Clock.DEFAULT;
    const epoch_schedule = EpochSchedule.DEFAULT;
    const epoch_rewards = EpochRewards.DEFAULT;
    const rent = Rent.DEFAULT;
    const last_restart_slot = LastRestartSlot.DEFAULT;

    const slot_hashes = try SlotHashes.default(allocator);
    const stake_history = try StakeHistory.default(allocator);
    const fees = Fees.DEFAULT;
    const recent_blockhashes = try RecentBlockhashes.default(allocator);

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

test "updateClock" {
    // TODO
}

test "updateLastRestartSlot" {
    const loadTestAccountsDbEmpty = sig.accounts_db.db.loadTestAccountsDbEmpty;
    const allocator = std.testing.allocator;

    // Create values for update sysvar deps
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var accounts_db = try loadTestAccountsDbEmpty(allocator, false, .noop, tmp_dir.dir);
    defer accounts_db.deinit();
    var capitalization = Atomic(u64).init(0);
    var slot: Slot = 10;
    const rent = Rent.DEFAULT;
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    // Insert default
    const account = try createSysvarAccount(
        allocator,
        &Rent.DEFAULT,
        LastRestartSlot,
        LastRestartSlot.DEFAULT,
        null,
    );
    defer allocator.free(account.data);
    try accounts_db.putAccount(slot, LastRestartSlot.ID, account);

    // NOTE: Putting accounts on the same slot is broken, so increment slot by 1 and add it to ancestors.
    slot = slot + 1;
    const update_sysvar_deps = UpdateSysvarAccountDeps{
        .accounts_db = &accounts_db,
        .capitalization = &capitalization,
        .ancestors = &ancestors,
        .rent = &rent,
        .slot = slot,
    };
    try ancestors.ancestors.put(allocator, slot, {});

    var feature_set = FeatureSet.EMPTY;
    defer feature_set.deinit(allocator);
    try feature_set.active.put(allocator, features.LAST_RESTART_SLOT_SYSVAR, 0);

    const new_restart_slot = slot - 5;

    var hard_forks = HardForks{};
    defer hard_forks.deinit(allocator);
    try hard_forks.register(allocator, new_restart_slot);

    _, const old_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, LastRestartSlot)).?;
    defer allocator.free(old_account.data);

    try updateLastRestartSlot(allocator, &feature_set, &hard_forks, update_sysvar_deps);

    const new_sysvar, const new_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, LastRestartSlot)).?;
    defer allocator.free(new_account.data);

    try std.testing.expectEqual(new_restart_slot, new_sysvar.last_restart_slot);
    try expectSysvarAccountChange(rent, old_account, new_account);
}

test "updateSlotHistory" {
    const loadTestAccountsDbEmpty = sig.accounts_db.db.loadTestAccountsDbEmpty;
    const allocator = std.testing.allocator;

    // Create values for update sysvar deps
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var accounts_db = try loadTestAccountsDbEmpty(allocator, false, .noop, tmp_dir.dir);
    defer accounts_db.deinit();
    var capitalization = Atomic(u64).init(0);
    var slot: Slot = 10;
    const rent = Rent.DEFAULT;
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    // Insert default
    const slot_history = try SlotHistory.default(allocator);
    defer slot_history.deinit(allocator);
    const account = try createSysvarAccount(
        allocator,
        &Rent.DEFAULT,
        SlotHistory,
        slot_history,
        null,
    );
    defer allocator.free(account.data);
    try accounts_db.putAccount(slot, SlotHistory.ID, account);

    // NOTE: Putting accounts on the same slot is broken, so increment slot by 1 and add it to ancestors.
    slot = slot + 1;
    const update_sysvar_deps = UpdateSysvarAccountDeps{
        .accounts_db = &accounts_db,
        .capitalization = &capitalization,
        .ancestors = &ancestors,
        .rent = &rent,
        .slot = slot,
    };
    try ancestors.ancestors.put(allocator, slot, {});

    const old_sysvar, const old_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, SlotHistory)).?;
    defer {
        old_sysvar.deinit(allocator);
        allocator.free(old_account.data);
    }

    try updateSlotHistory(allocator, update_sysvar_deps);

    const new_sysvar, const new_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, SlotHistory)).?;
    defer {
        new_sysvar.deinit(allocator);
        allocator.free(new_account.data);
    }

    try std.testing.expectEqual(slot, new_sysvar.newest());
    try expectSysvarAccountChange(rent, old_account, new_account);
}

test "updateSlotHashes" {
    const loadTestAccountsDbEmpty = sig.accounts_db.db.loadTestAccountsDbEmpty;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // Create values for update sysvar deps
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var accounts_db = try loadTestAccountsDbEmpty(allocator, false, .noop, tmp_dir.dir);
    defer accounts_db.deinit();
    var capitalization = Atomic(u64).init(0);
    var slot: Slot = 10;
    const rent = Rent.DEFAULT;
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    // Insert default
    const slot_hashes = try SlotHashes.default(allocator);
    defer slot_hashes.deinit(allocator);
    const account = try createSysvarAccount(
        allocator,
        &Rent.DEFAULT,
        SlotHashes,
        slot_hashes,
        null,
    );
    defer allocator.free(account.data);
    try accounts_db.putAccount(slot, SlotHashes.ID, account);

    // NOTE: Putting accounts on the same slot is broken, so increment slot by 1 and add it to ancestors.
    slot = slot + 1;
    const update_sysvar_deps = UpdateSysvarAccountDeps{
        .accounts_db = &accounts_db,
        .capitalization = &capitalization,
        .ancestors = &ancestors,
        .rent = &rent,
        .slot = slot,
    };
    try ancestors.ancestors.put(allocator, slot, {});

    const parent_slot = slot - 1;
    const parent_hash = Hash.initRandom(random);

    const old_sysvar, const old_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, SlotHashes)).?;
    defer {
        old_sysvar.deinit(allocator);
        allocator.free(old_account.data);
    }

    try updateSlotHashes(allocator, parent_slot, parent_hash, update_sysvar_deps);

    const new_sysvar, const new_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, SlotHashes)).?;
    defer {
        new_sysvar.deinit(allocator);
        allocator.free(new_account.data);
    }

    try std.testing.expectEqual(parent_hash, new_sysvar.get(parent_slot));
    try expectSysvarAccountChange(rent, old_account, new_account);
}

test "updateRent" {
    const loadTestAccountsDbEmpty = sig.accounts_db.db.loadTestAccountsDbEmpty;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // Create values for update sysvar deps
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var accounts_db = try loadTestAccountsDbEmpty(allocator, false, .noop, tmp_dir.dir);
    defer accounts_db.deinit();
    var capitalization = Atomic(u64).init(0);
    var slot: Slot = 10;
    const rent = Rent.DEFAULT;
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    // Insert default
    const account = try createSysvarAccount(
        allocator,
        &Rent.DEFAULT,
        Rent,
        Rent.DEFAULT,
        null,
    );
    defer allocator.free(account.data);
    try accounts_db.putAccount(slot, Rent.ID, account);

    // NOTE: Putting accounts on the same slot is broken, so increment slot by 1 and add it to ancestors.
    slot = slot + 1;
    const update_sysvar_deps = UpdateSysvarAccountDeps{
        .accounts_db = &accounts_db,
        .capitalization = &capitalization,
        .ancestors = &ancestors,
        .rent = &rent,
        .slot = slot,
    };
    try ancestors.ancestors.put(allocator, slot, {});

    _, const old_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, Rent)).?;
    defer allocator.free(old_account.data);

    const new_rent = Rent.initRandom(random);

    try updateRent(allocator, new_rent, update_sysvar_deps);

    const new_sysvar, const new_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, Rent)).?;
    defer allocator.free(new_account.data);

    try std.testing.expect(std.meta.eql(new_rent, new_sysvar));
    try expectSysvarAccountChange(rent, old_account, new_account);
}

test "updateEpochSchedule" {
    const loadTestAccountsDbEmpty = sig.accounts_db.db.loadTestAccountsDbEmpty;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // Create values for update sysvar deps
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var accounts_db = try loadTestAccountsDbEmpty(allocator, false, .noop, tmp_dir.dir);
    defer accounts_db.deinit();
    var capitalization = Atomic(u64).init(0);
    var slot: Slot = 10;
    const rent = Rent.DEFAULT;
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    // Insert default
    const account = try createSysvarAccount(
        allocator,
        &Rent.DEFAULT,
        EpochSchedule,
        EpochSchedule.DEFAULT,
        null,
    );
    defer allocator.free(account.data);
    try accounts_db.putAccount(slot, EpochSchedule.ID, account);

    // NOTE: Putting accounts on the same slot is broken, so increment slot by 1 and add it to ancestors.
    slot = slot + 1;
    const update_sysvar_deps = UpdateSysvarAccountDeps{
        .accounts_db = &accounts_db,
        .capitalization = &capitalization,
        .ancestors = &ancestors,
        .rent = &rent,
        .slot = slot,
    };
    try ancestors.ancestors.put(allocator, slot, {});

    _, const old_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, EpochSchedule)).?;
    defer allocator.free(old_account.data);

    const new_epoch_schedule = EpochSchedule.initRandom(random);

    try updateEpochSchedule(allocator, new_epoch_schedule, update_sysvar_deps);

    const new_sysvar, const new_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, EpochSchedule)).?;
    defer allocator.free(new_account.data);

    try std.testing.expect(std.meta.eql(new_epoch_schedule, new_sysvar));
    try expectSysvarAccountChange(rent, old_account, new_account);
}

test "updateStakeHistory" {
    // TODO
}

test "updateRecentBlockhashes" {
    const loadTestAccountsDbEmpty = sig.accounts_db.db.loadTestAccountsDbEmpty;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // Create values for update sysvar deps
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var accounts_db = try loadTestAccountsDbEmpty(allocator, false, .noop, tmp_dir.dir);
    defer accounts_db.deinit();
    var capitalization = Atomic(u64).init(0);
    var slot: Slot = 10;
    const rent = Rent.DEFAULT;
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    // Insert default
    const recent_blockhashes = try RecentBlockhashes.default(allocator);
    defer recent_blockhashes.deinit(allocator);
    const account = try createSysvarAccount(
        allocator,
        &Rent.DEFAULT,
        RecentBlockhashes,
        recent_blockhashes,
        null,
    );
    defer allocator.free(account.data);
    try accounts_db.putAccount(slot, RecentBlockhashes.ID, account);

    // NOTE: Putting accounts on the same slot is broken, so increment slot by 1 and add it to ancestors.
    slot = slot + 1;
    const update_sysvar_deps = UpdateSysvarAccountDeps{
        .accounts_db = &accounts_db,
        .capitalization = &capitalization,
        .ancestors = &ancestors,
        .rent = &rent,
        .slot = slot,
    };
    try ancestors.ancestors.put(allocator, slot, {});

    const old_sysvar, const old_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, RecentBlockhashes)).?;
    defer {
        old_sysvar.deinit(allocator);
        allocator.free(old_account.data);
    }

    var blockhash_queue = BlockhashQueue.DEFAULT;
    defer blockhash_queue.deinit(allocator);

    const new_hash = Hash.initRandom(random);
    const new_lamports_per_signature = 1000;
    try blockhash_queue.insertHash(allocator, new_hash, new_lamports_per_signature);

    try updateRecentBlockhashes(allocator, &blockhash_queue, update_sysvar_deps);

    const new_sysvar, const new_account =
        (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, RecentBlockhashes)).?;
    defer {
        new_sysvar.deinit(allocator);
        allocator.free(new_account.data);
    }

    try std.testing.expectEqual(1, new_sysvar.entries.items.len);
    const entry = new_sysvar.entries.items[0];
    try std.testing.expectEqual(new_hash, entry.blockhash);
    try std.testing.expectEqual(new_lamports_per_signature, entry.lamports_per_signature);
    try expectSysvarAccountChange(rent, old_account, new_account);
}

fn expectSysvarAccountChange(rent: Rent, old: AccountSharedData, new: AccountSharedData) !void {
    if (!builtin.is_test) @compileError("only for testing");
    const minimum_for_rent = rent.minimumBalance(new.data.len);
    try std.testing.expectEqual(@max(old.lamports, minimum_for_rent), new.lamports);
    try std.testing.expect(old.owner.equals(&new.owner));
    try std.testing.expectEqual(old.executable, new.executable);
    try std.testing.expectEqual(old.rent_epoch, new.rent_epoch);
}

fn getSysvarAndAccount(
    allocator: std.mem.Allocator,
    accounts_db: *AccountsDb,
    ancestors: *const Ancestors,
    comptime Sysvar: type,
) !?struct { Sysvar, AccountSharedData } {
    if (!builtin.is_test) @compileError("only for testing");
    const maybe_account = accounts_db.getAccountWithAncestors(
        &Sysvar.ID,
        ancestors,
    ) catch return null;

    const account = maybe_account orelse return null;
    defer account.deinit(allocator);

    const data = try account.data.dupeAllocatedOwned(allocator);
    defer data.deinit(allocator);

    const sysvar = bincode.readFromSlice(
        allocator,
        Sysvar,
        data.owned_allocation,
        .{},
    ) catch {
        data.deinit(allocator);
        return null;
    };

    return .{ sysvar, .{
        .lamports = account.lamports,
        .data = try allocator.dupe(u8, data.owned_allocation),
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    } };
}

// TODO: This test should be equivalent to running each of the update tests individually. However,
// it hits an error when trying to load updated sysvar accounts. Commenting out all but one sysvar
// test block results in the test passing, but running a number of them seems to cause an issue. I
// think something is going wrong in accounts db.

// test "update all" {
//     const loadTestAccountsDbEmpty = sig.accounts_db.db.loadTestAccountsDbEmpty;
//     const allocator = std.testing.allocator;
//     var prng = std.Random.DefaultPrng.init(0);
//     const random = prng.random();

//     // Create values for update sysvar deps
//     var tmp_dir = std.testing.tmpDir(.{});
//     defer tmp_dir.cleanup();
//     var accounts_db = try loadTestAccountsDbEmpty(allocator, false, .noop, tmp_dir.dir);
//     defer accounts_db.deinit();
//     var capitalization = Atomic(u64).init(0);
//     var slot: Slot = 10;
//     const rent = Rent.DEFAULT;
//     var ancestors = Ancestors{};
//     defer ancestors.deinit(allocator);
//     try ancestors.ancestors.put(allocator, slot, {});

//     // Create and insert sysvar defaults
//     const initial_sysvars = try initSysvarCacheWithDefaultValues(allocator);
//     defer initial_sysvars.deinit(allocator);
//     try insertSysvarCacheAccounts(
//         allocator,
//         &accounts_db,
//         &initial_sysvars,
//         slot,
//         false,
//     );

//     // Insert slot history default manually since it is not in the sysvar cache
//     const slot_history = try SlotHistory.default(allocator);
//     defer slot_history.deinit(allocator);
//     const account = try createSysvarAccount(
//         allocator,
//         &Rent.DEFAULT,
//         SlotHistory,
//         slot_history,
//         null,
//     );
//     defer allocator.free(account.data);
//     try accounts_db.putAccount(slot, SlotHistory.ID, account);

//     // NOTE: Putting accounts on the same slot is broken, so increment slot by 1 and add it to ancestors.
//     slot = slot + 1;
//     const update_sysvar_deps = UpdateSysvarAccountDeps{
//         .accounts_db = &accounts_db,
//         .capitalization = &capitalization,
//         .ancestors = &ancestors,
//         .rent = &rent,
//         .slot = slot,
//     };
//     try ancestors.ancestors.put(allocator, slot, {});

//     // TODO: updateClock

//     { // updateLastRestartSlot
//         var feature_set = FeatureSet.EMPTY;
//         defer feature_set.deinit(allocator);
//         try feature_set.active.put(allocator, features.LAST_RESTART_SLOT_SYSVAR, 0);

//         const new_restart_slot = slot - 5;

//         var hard_forks = HardForks{};
//         defer hard_forks.deinit(allocator);
//         try hard_forks.register(allocator, new_restart_slot);

//         _, const old_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, LastRestartSlot)).?;
//         defer allocator.free(old_account.data);

//         try updateLastRestartSlot(allocator, &feature_set, &hard_forks, update_sysvar_deps);

//         const new_sysvar, const new_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, LastRestartSlot)).?;
//         defer allocator.free(new_account.data);

//         try std.testing.expectEqual(new_restart_slot, new_sysvar.last_restart_slot);
//         try expectSysvarAccountChange(rent, old_account, new_account);
//     }

//     { // updateSlotHistory
//         const old_sysvar, const old_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, SlotHistory)).?;
//         defer {
//             old_sysvar.deinit(allocator);
//             allocator.free(old_account.data);
//         }

//         try updateSlotHistory(allocator, update_sysvar_deps);

//         const new_sysvar, const new_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, SlotHistory)).?;
//         defer {
//             new_sysvar.deinit(allocator);
//             allocator.free(new_account.data);
//         }

//         try std.testing.expectEqual(slot, new_sysvar.newest());
//         try expectSysvarAccountChange(rent, old_account, new_account);
//     }

// { // updateSlotHashes
//     const parent_slot = slot - 1;
//     const parent_hash = Hash.initRandom(random);

//     const old_sysvar, const old_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, SlotHashes)).?;
//     defer {
//         old_sysvar.deinit(allocator);
//         allocator.free(old_account.data);
//     }

//     try updateSlotHashes(allocator, parent_slot, parent_hash, update_sysvar_deps);

//     const new_sysvar, const new_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, SlotHashes)).?;
//     defer {
//         new_sysvar.deinit(allocator);
//         allocator.free(new_account.data);
//     }

//     try std.testing.expectEqual(parent_hash, new_sysvar.get(parent_slot));
//     try expectSysvarAccountChange(rent, old_account, new_account);
// }

//     { // updateRent
//         _, const old_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, Rent)).?;
//         defer allocator.free(old_account.data);

//         const new_rent = Rent.initRandom(random);

//         try updateRent(allocator, new_rent, update_sysvar_deps);

//         const new_sysvar, const new_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, Rent)).?;
//         defer allocator.free(new_account.data);

//         try std.testing.expect(std.meta.eql(new_rent, new_sysvar));
//         try expectSysvarAccountChange(rent, old_account, new_account);
//     }

//     { // updateEpochSchedule
//         _, const old_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, EpochSchedule)).?;
//         defer allocator.free(old_account.data);

//         const new_epoch_schedule = EpochSchedule.initRandom(random);

//         try updateEpochSchedule(allocator, new_epoch_schedule, update_sysvar_deps);

//         const new_sysvar, const new_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, EpochSchedule)).?;
//         defer allocator.free(new_account.data);

//         try std.testing.expect(std.meta.eql(new_epoch_schedule, new_sysvar));
//         try expectSysvarAccountChange(rent, old_account, new_account);
//     }

//     // TODO: updateStakeHistory

//     { // updateRecentBlockhashes
//         const old_sysvar, const old_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, RecentBlockhashes)).?;
//         defer {
//             old_sysvar.deinit(allocator);
//             allocator.free(old_account.data);
//         }

//         var blockhash_queue = BlockhashQueue.DEFAULT;
//         defer blockhash_queue.deinit(allocator);

//         const new_hash = Hash.initRandom(random);
//         const new_lamports_per_signature = 1000;
//         try blockhash_queue.insertHash(allocator, new_hash, new_lamports_per_signature);

//         try updateRecentBlockhashes(allocator, &blockhash_queue, update_sysvar_deps);

//         const new_sysvar, const new_account = (try getSysvarAndAccount(allocator, &accounts_db, &ancestors, RecentBlockhashes)).?;
//         defer {
//             new_sysvar.deinit(allocator);
//             allocator.free(new_account.data);
//         }

//         try std.testing.expectEqual(1, new_sysvar.entries.items.len);
//         const entry = new_sysvar.entries.items[0];
//         try std.testing.expectEqual(new_hash, entry.blockhash);
//         try std.testing.expectEqual(new_lamports_per_signature, entry.lamports_per_signature);
//         try expectSysvarAccountChange(rent, old_account, new_account);
//     }
// }
