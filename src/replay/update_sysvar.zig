const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;
const sysvars = sig.runtime.sysvar;
const store_account = sig.replay.store_account;

const AccountsDb = sig.accounts_db.AccountsDB;

const Pubkey = sig.core.Pubkey;
const Ancestors = sig.core.status_cache.Ancestors;
const Account = sig.core.Account;
const SlotState = sig.core.SlotState;

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

pub fn updateSysvarAccount(
    allocator: std.mem.Allocator,
    state: *SlotState,
    accounts_db: *AccountsDb,
    ancestors: *const Ancestors,
    rent: *const Rent,
    new_warmup_and_cooldown_rate_epoch: ?u64,
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

    store_account.storeAccount(
        state,
        accounts_db,
        new_warmup_and_cooldown_rate_epoch,
        slot,
        Sysvar.ID,
        new_account,
        &old_account,
    );
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
