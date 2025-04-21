const sig = @import("../sig.zig");
const std = @import("std");

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Rent = sig.runtime.sysvar.Rent;
const AccountSharedData = sig.runtime.AccountSharedData;
const EpochSchedule = sig.runtime.sysvar.EpochSchedule;

pub const RENT_EXEMPT_RENT_EPOCH: Epoch = std.math.maxInt(Epoch);

pub const RentResult = union(enum) {
    NoRentCollectionNow,
    Exempt,
    CollectRent: struct {
        new_rent_epoch: Epoch,
        rent_due: u64, // thought: should we have a Lamports = u64 type alias?
    },
};

pub const RentDue = union(enum) {
    Exempt,
    Paying: u64,
};

pub const CollectedInfo = struct {
    rent_amount: u64,
    account_data_len_reclaimed: u64,
    pub const NoneCollected: CollectedInfo = .{ .rent_amount = 0, .account_data_len_reclaimed = 0 };
};

// [agave] https://github.com/anza-xyz/solana-sdk/blob/801ac25f6d35d94736ed576425e44f9ec63de809/rent-collector/src/lib.rs#L21
pub const RentCollector = struct {
    epoch: Epoch,
    epoch_schedule: EpochSchedule,
    slots_per_year: f64,
    rent: Rent,

    pub fn initRandom(random: std.Random) RentCollector {
        return .{
            .epoch = random.int(Epoch),
            .epoch_schedule = EpochSchedule.initRandom(random),
            .slots_per_year = random.float(f64),
            .rent = Rent.initRandom(random),
        };
    }

    // [agave] RentCollector::collect_from_existing_account / SVMRentCollector::collect_rent
    pub fn collectFromExistingAccount(
        self: RentCollector,
        address: *const Pubkey,
        account: *AccountSharedData,
    ) CollectedInfo {
        const rent_result = self.calculateRentResult(address, account.*);

        return switch (rent_result) {
            .Exempt => blk: {
                account.rent_epoch = RENT_EXEMPT_RENT_EPOCH;
                break :blk CollectedInfo.NoneCollected;
            },
            .NoRentCollectionNow => CollectedInfo.NoneCollected,
            .CollectRent => |rent| blk: {
                const lamports_after_rent = account.lamports -| rent.rent_due;

                if (lamports_after_rent == 0) {
                    break :blk .{
                        .rent_amount = account.lamports,
                        .account_data_len_reclaimed = account.data.len,
                    };
                } else {
                    account.lamports = lamports_after_rent;
                    account.rent_epoch = rent.new_rent_epoch;
                    break :blk .{ .rent_amount = rent.rent_due, .account_data_len_reclaimed = 0 };
                }
            },
        };
    }

    fn calculateRentResult(
        self: RentCollector,
        address: *const Pubkey,
        account: AccountSharedData,
    ) RentResult {
        if (account.rent_epoch == RENT_EXEMPT_RENT_EPOCH or account.rent_epoch > self.epoch)
            // potentially rent paying account (or known and already marked exempt)
            // Maybe collect rent later, leave account alone for now.
            return .NoRentCollectionNow;
        if (!shouldCollectRent(address, account.executable))
            // easy to determine this account should not consider having rent collected from it
            return .Exempt;

        return switch (self.getRentDue(
            account.lamports,
            account.data.len,
            account.rent_epoch,
        )) {
            // account will not have rent collected ever
            .Exempt => .Exempt,
            .Paying => |rent_due| blk: {
                break :blk if (rent_due == 0)
                    .NoRentCollectionNow
                else
                    .{ .CollectRent = .{
                        .new_rent_epoch = self.epoch +| 1,
                        .rent_due = rent_due,
                    } };
            },
        };
    }

    pub fn shouldCollectRent(address: *const Pubkey, executable: bool) bool {
        return !(executable or address.equals(&sig.runtime.ids.Incinerator));
    }

    pub fn getRentDue(
        self: RentCollector,
        lamports: u64,
        data_len: usize,
        account_rent_epoch: Epoch,
    ) RentDue {
        if (self.rent.isExempt(lamports, data_len)) return .Exempt;

        var slots_elapsed: u64 = 0;
        for (account_rent_epoch..self.epoch + 1) |epoch| {
            slots_elapsed +|= self.epoch_schedule.getSlotsInEpoch(epoch +| 1);
        }

        // as firedancer says: "Consensus-critical use of doubles :("
        const years_elapsed: f64 = if (self.slots_per_year != 0.0)
            @as(f64, @floatFromInt(slots_elapsed)) / self.slots_per_year
        else
            0;

        const due = self.rent.dueAmount(data_len, years_elapsed);

        return .{ .Paying = due };
    }
};

pub fn defaultCollector(epoch: Epoch) RentCollector {
    if (!@import("builtin").is_test) @compileError("defaultCollector for test usage only");
    return .{
        .epoch = epoch,
        .epoch_schedule = sig.runtime.sysvar.EpochSchedule.default() catch unreachable,
        .slots_per_year = 78892314.983999997, // [agave] GenesisConfig::default().slots_per_year()
        .rent = sig.runtime.sysvar.Rent.DEFAULT,
    };
}

test "calculate rent result" {
    var collector = defaultCollector(0);
    var account = AccountSharedData.EMPTY;

    try std.testing.expectEqual(
        .NoRentCollectionNow,
        collector.calculateRentResult(&Pubkey.ZEROES, account),
    );
    {
        var account_clone = account;
        try std.testing.expectEqual(
            CollectedInfo.NoneCollected,
            collector.collectFromExistingAccount(&Pubkey.ZEROES, &account_clone),
        );
        try std.testing.expectEqualDeep(account, account_clone);
    }

    account.executable = true;
    try std.testing.expectEqual(
        .Exempt,
        collector.calculateRentResult(&Pubkey.ZEROES, account),
    );
    {
        var account_clone = account;
        var account_expected = account;
        account_expected.rent_epoch = RENT_EXEMPT_RENT_EPOCH;

        try std.testing.expectEqual(
            CollectedInfo.NoneCollected,
            collector.collectFromExistingAccount(&Pubkey.ZEROES, &account_clone),
        );
        try std.testing.expectEqualDeep(account_expected, account_clone);
    }

    account.executable = false;
    try std.testing.expectEqual(
        .Exempt,
        collector.calculateRentResult(&sig.runtime.ids.Incinerator, account),
    );
    {
        var account_clone = account;
        var account_expected = account;
        account_expected.rent_epoch = RENT_EXEMPT_RENT_EPOCH;

        try std.testing.expectEqual(
            CollectedInfo.NoneCollected,
            collector.collectFromExistingAccount(&sig.runtime.ids.Incinerator, &account_clone),
        );
        try std.testing.expectEqualDeep(account_expected, account_clone);
    }

    // try a few combinations of rent collector rent epoch and collecting rent
    inline for (&.{ .{ 2, 2 }, .{ 3, 5 } }) |rent| {
        const rent_epoch = rent[0];
        const rent_due_expected = rent[1];
        collector.epoch = rent_epoch;

        account.lamports = 10;
        account.rent_epoch = 1;
        const new_rent_epoch_expected = collector.epoch + 1;

        try std.testing.expectEqual(
            RentResult{
                .CollectRent = .{
                    .rent_due = rent_due_expected,
                    .new_rent_epoch = new_rent_epoch_expected,
                },
            },
            collector.calculateRentResult(&Pubkey.ZEROES, account),
        );

        {
            var account_clone = account;
            try std.testing.expectEqual(
                CollectedInfo{ .rent_amount = rent_due_expected, .account_data_len_reclaimed = 0 },
                collector.collectFromExistingAccount(&Pubkey.ZEROES, &account_clone),
            );
            var account_expected = account;
            account_expected.lamports = account.lamports - rent_due_expected;
            account_expected.rent_epoch = new_rent_epoch_expected;
            try std.testing.expectEqual(account_clone, account_expected);
        }
    }

    // enough lamports to make us exempt
    account.lamports = 1_000_000;
    try std.testing.expectEqual(
        RentResult.Exempt,
        collector.calculateRentResult(&Pubkey.ZEROES, account),
    );
    {
        var account_clone = account;
        var account_expected = account;
        account_expected.rent_epoch = RENT_EXEMPT_RENT_EPOCH;
        try std.testing.expectEqual(
            CollectedInfo.NoneCollected,
            collector.collectFromExistingAccount(&Pubkey.ZEROES, &account_clone),
        );
        try std.testing.expectEqual(account_expected, account_clone);
    }

    // enough lamports to make us exempt
    // but, our rent_epoch is set in the future, so we can't know if we are exempt yet or not.
    // We don't calculate rent amount vs data if the rent_epoch is already in the future.
    account.rent_epoch = 1_000_000;
    try std.testing.expectEqual(
        RentResult.NoRentCollectionNow,
        collector.calculateRentResult(&Pubkey.ZEROES, account),
    );
    {
        var account_clone = account;
        try std.testing.expectEqual(
            CollectedInfo.NoneCollected,
            collector.collectFromExistingAccount(&Pubkey.ZEROES, &account_clone),
        );
        try std.testing.expectEqual(account, account_clone);
    }
}
