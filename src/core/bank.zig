const std = @import("std");
const AccountsDB = @import("./accounts_db.zig").AccountsDB;
const GenesisConfig = @import("./genesis_config.zig").GenesisConfig;
const BankFields = @import("./snapshot_fields.zig").BankFields;

pub const Bank = struct {
    accounts_db: *AccountsDB,
    bank_fields: *const BankFields,

    pub fn init(accounts_db: *AccountsDB, bank_fields: *const BankFields) Bank {
        return .{
            .accounts_db = accounts_db,
            .bank_fields = bank_fields,
        };
    }

    pub fn validateLoadFromSnapshot(self: *Bank, genesis_config: *const GenesisConfig) !void {
        // self validation
        if (self.bank_fields.max_tick_height != (self.bank_fields.slot + 1) * self.bank_fields.ticks_per_slot) {
            return error.InvalidBankFields;
        }
        if (self.bank_fields.epoch_schedule.getEpoch(self.bank_fields.slot) != self.bank_fields.epoch) {
            return error.InvalidBankFields;
        }

        // cross validation against genesis
        if (genesis_config.creation_time != self.bank_fields.genesis_creation_time) {
            return error.BankAndGenesisMismatch;
        }
        if (genesis_config.ticks_per_slot != self.bank_fields.ticks_per_slot) {
            return error.BankAndGenesisMismatch;
        }
        const genesis_ns_per_slot = genesis_config.poh_config.target_tick_duration.nanos * @as(u128, genesis_config.ticks_per_slot);
        if (self.bank_fields.ns_per_slot != genesis_ns_per_slot) {
            return error.BankAndGenesisMismatch;
        }

        const genesis_slots_per_year = yearsAsSlots(1, genesis_config.poh_config.target_tick_duration.nanos, self.bank_fields.ticks_per_slot);
        if (genesis_slots_per_year != self.bank_fields.slots_per_year) {
            return error.BankAndGenesisMismatch;
        }
        if (!std.meta.eql(self.bank_fields.epoch_schedule, genesis_config.epoch_schedule)) {
            return error.BankAndGenesisMismatch;
        }
    }
};

pub const SECONDS_PER_YEAR: f64 = 365.242_199 * 24.0 * 60.0 * 60.0;
pub fn yearsAsSlots(years: f64, tick_duration_ns: u32, ticks_per_slot: u64) f64 {
    return years * SECONDS_PER_YEAR * (1_000_000_000.0 / @as(f64, @floatFromInt(tick_duration_ns))) / @as(f64, @floatFromInt(ticks_per_slot));
}
