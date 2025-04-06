const sig = @import("../sig.zig");
const std = @import("std");

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Rent = sig.runtime.sysvar.Rent;
const AccountSharedData = sig.runtime.AccountSharedData;
const EpochSchedule = sig.runtime.sysvar.EpochSchedule;

const RENT_EXEMPT_RENT_EPOCH: Epoch = std.math.maxInt(Epoch);

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
    const NoneCollected: CollectedInfo = .{ .rent_amount = 0, .account_data_len_reclaimed = 0 };
};

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

    // [agave] solana-rent-collector-2.2.1/src/lib.rs:122
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

    // [agave] solana-rent-collector-2.2.1/src/lib.rs:158
    pub fn calculateRentResult(
        self: RentCollector,
        address: *const Pubkey,
        account: AccountSharedData,
    ) RentResult {
        if (account.rent_epoch == RENT_EXEMPT_RENT_EPOCH or account.rent_epoch > self.epoch) {
            return .NoRentCollectionNow;
        }
        if (!shouldCollectRent(address, account.executable)) return .Exempt;

        const due = self.getRentDue(account.lamports, account.data.len, account.rent_epoch);

        return switch (due) {
            .Exempt => .Exempt,
            .Paying => |rent_due| blk: {
                break :blk if (rent_due == 0)
                    .NoRentCollectionNow
                else
                    .{ .CollectRent = .{ .new_rent_epoch = self.epoch + 1, .rent_due = rent_due } };
            },
        };
    }

    // [agave] solana-rent-collector-2.2.1/src/lib.rs:82
    pub fn shouldCollectRent(address: *const Pubkey, executable: bool) bool {
        return !(executable or address.equals(&sig.runtime.ids.Incinerator));
    }

    // [agave] solana-rent-collector-2.2.1/src/lib.rs:89
    pub fn getRentDue(
        self: RentCollector,
        lamports: u64,
        data_len: usize,
        account_rent_epoch: Epoch,
    ) RentDue {
        if (self.rent.isExempt(lamports, data_len)) return .Exempt;

        var slots_elapsed: u64 = 0;
        for (account_rent_epoch..self.epoch) |epoch| {
            slots_elapsed +|= self.epoch_schedule.getSlotsInEpoch(epoch);
        }

        // as firedancer says: "Consensus-critical use of doubles :(""
        const years_elapsed: f64 = if (self.slots_per_year != 0.0)
            @as(f64, @floatFromInt(slots_elapsed)) / self.slots_per_year
        else
            0;

        const due = self.rent.dueAmount(data_len, years_elapsed);

        return .{ .Paying = due };
    }
};

test {
    std.testing.refAllDecls(@This());
}
