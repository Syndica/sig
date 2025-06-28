const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;
const sysvars = sig.runtime.sysvar;

const AccountsDb = sig.accounts_db.AccountsDB;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Ancestors = sig.core.status_cache.Ancestors;
const Account = sig.core.Account;
const SlotState = sig.core.SlotState;
const Slot = sig.core.Slot;

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

/// Update sysvar account is used to update sysvar accounts in the validator runtime
/// outside of the SVM. This is referred to as an 'off-chain' account update. The current sysvar
/// account is loaded from the accounts database using the current ancestors and a new account is
/// created which inherits the lamports and rent epoch from the old account if it exists. The new
/// account lamports are then adjusted to ensure rent exemption. The new account is written back
/// to accounts db, and the slot capitalization is updated to reflect the change in account lamports.
pub fn updateSysvarAccount(
    allocator: std.mem.Allocator,
    state: *SlotState,
    accounts_db: *AccountsDb,
    ancestors: *const Ancestors,
    rent: *const Rent,
    slot: u64,
    comptime Sysvar: type,
    sysvar: Sysvar,
) !void {
    // TODO: accounts_db.load_with_fixed_root(ancestors, pubkey)
    _ = ancestors;
    const old_account = accounts_db.getAccount(&Sysvar.ID) catch null;
    const new_account = try createSysvarAccount(
        allocator,
        rent,
        Sysvar,
        sysvar,
        &old_account,
    );

    // Update the slot capitalization
    if (new_account.lamports > old_account.lamports)
        state.capitalization.fetchAdd(new_account.lamports - old_account.lamports, .monotonic)
    else if (new_account.lamports < old_account.lamports)
        state.capitalization.fetchSub(old_account.lamports - new_account.lamports, .monotonic);

    // TODO: Store the new account
    _ = slot;
    // accounts_db.storeAccount()
}

pub fn createSysvarAccount(
    allocator: std.mem.Allocator,
    rent: *const Rent,
    comptime Sysvar: type,
    sysvar: Sysvar,
    old_account: ?*const Account,
) !Account {
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
        .data = .initAllocatedOwned(sysvar_data),
        .owner = sysvars.OWNER_ID,
        .executable = false,
        .rent_epoch = rent_epoch,
    };
}

// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2088
// Agave uses argument `parent_epoch: ?Epoch` and otherwise defaults to the current banks epoch.
// Sig uses argument `epoch: Epoch` which the caller can choose to pass either parent or current epoch.
// pub fn updateAndSaveClock()

pub fn updateClock(
    accounts_db: *AccountsDb,
    ancestors: *const Ancestors,
    epoch_schedule: *const EpochSchedule,
    slot: Slot,
    epoch: Epoch,
    parent_epoch: ?Epoch,
) Clock {
    _ = ancestors;
    // TODO: use ancestors
    const clock = accounts_db.getAccount(Clock.ID) orelse Clock.DEFAULT;
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

    var epoch_start_timestamp = if (parent_epoch != null and parent_epoch.? != epoch)
        unix_timestamp
    else
        clock.epoch_start_timestamp;

    if (slot == 0) {
        unix_timestamp = unixTimestampFromGenesis();
        epoch_start_timestamp = unix_timestamp;
    }

    return Clock{
        .slot = slot,
        .epoch_start_timestamp = epoch_start_timestamp,
        .epoch = epoch,
        .leader_schedule_epoch = epoch_schedule.getLeaderScheduleEpoch(slot),
        .unix_timestamp = unix_timestamp,
    };
}

fn unixTimestampFromGenesis(genesis_creation_time: i64, slot: u128, ns_per_slot: u128) i64 {
    return genesis_creation_time +| ((slot *| ns_per_slot) / 1_000_000_000);
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

// TODO: Implement
// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2512
fn getTimestampEstimate(max_allowable_drift: MaxAllowableDrift, epoch_start: ?struct {
    slot: Slot,
    timestamp: i64,
}) ?i64 {
    _ = max_allowable_drift;
    _ = epoch_start;
    return null;
}

// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2147
// pub fn updateLastRestartSlot() {}

// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2206
// pub fn updateSlotHistory() {}

// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2220
// pub fn updateSlotHashes() {}

// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2238
// pub fn updateEpochStakes() {}

// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2277
// pub fn updateRent() {}

// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2286
// pub fn updateEpochSchedule() {}

// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2295
// pub fn updateStakeHistory() {}

// https://github.com/firedancer-io/agave/blob/57059221b5ac5275bca30edceb9f7de7f45f3495/runtime/src/bank.rs#L2507
// pub fn updateRecentBlockhashes() {}

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
    defer account.deinit(allocator);

    const lamports_for_rent = rent.minimumBalance(sysvar_data.len);
    const expected_lamports, const expected_rent_epoch = if (old_account) |acc|
        .{ @max(acc.lamports, lamports_for_rent), acc.rent_epoch }
    else
        .{ lamports_for_rent, 0 };

    try std.testing.expectEqual(expected_lamports, account.lamports);
    try std.testing.expectEqualSlices(u8, sysvar_data, account.data.owned_allocation);
    try std.testing.expectEqualSlices(u8, &sysvars.OWNER_ID.data, &account.owner.data);
    try std.testing.expectEqual(false, account.executable);
    try std.testing.expectEqual(expected_rent_epoch, account.rent_epoch);
}
