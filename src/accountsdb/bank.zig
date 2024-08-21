//! minimal logic for bank (still being built out)

const std = @import("std");
const AccountsDB = @import("db.zig").AccountsDB;
const GenesisConfig = @import("genesis_config.zig").GenesisConfig;
const BankFields = @import("snapshots.zig").BankFields;
const SnapshotFields = @import("snapshots.zig").SnapshotFields;

// TODO: we can likley come up with a better name for this struct
/// Analogous to [Bank](https://github.com/anza-xyz/agave/blob/ad0a48c7311b08dbb6c81babaf66c136ac092e79/runtime/src/bank.rs#L718)
pub const Bank = struct {
    accounts_db: *AccountsDB,
    bank_fields: *const BankFields,

    pub fn init(accounts_db: *AccountsDB, bank_fields: *const BankFields) Bank {
        return .{
            .accounts_db = accounts_db,
            .bank_fields = bank_fields,
        };
    }

    pub fn validateBankFields(
        bank_fields: *const BankFields,
        genesis_config: *const GenesisConfig,
    ) !void {
        // self validation
        if (bank_fields.max_tick_height != (bank_fields.slot + 1) * bank_fields.ticks_per_slot) {
            return error.InvalidBankFields;
        }
        if (bank_fields.epoch_schedule.getEpoch(bank_fields.slot) != bank_fields.epoch) {
            return error.InvalidBankFields;
        }

        // cross validation against genesis
        if (genesis_config.creation_time != bank_fields.genesis_creation_time) {
            return error.BankAndGenesisMismatch;
        }
        if (genesis_config.ticks_per_slot != bank_fields.ticks_per_slot) {
            return error.BankAndGenesisMismatch;
        }
        const genesis_ns_per_slot = genesis_config.poh_config.target_tick_duration.nanos * @as(u128, genesis_config.ticks_per_slot);
        if (bank_fields.ns_per_slot != genesis_ns_per_slot) {
            return error.BankAndGenesisMismatch;
        }

        const genesis_slots_per_year = yearsAsSlots(1, genesis_config.poh_config.target_tick_duration.nanos, bank_fields.ticks_per_slot);
        if (genesis_slots_per_year != bank_fields.slots_per_year) {
            return error.BankAndGenesisMismatch;
        }
        if (!std.meta.eql(bank_fields.epoch_schedule, genesis_config.epoch_schedule)) {
            return error.BankAndGenesisMismatch;
        }
    }
};

pub const SECONDS_PER_YEAR: f64 = 365.242_199 * 24.0 * 60.0 * 60.0;

pub fn yearsAsSlots(years: f64, tick_duration_ns: u32, ticks_per_slot: u64) f64 {
    return years * SECONDS_PER_YEAR * (1_000_000_000.0 / @as(f64, @floatFromInt(tick_duration_ns))) / @as(f64, @floatFromInt(ticks_per_slot));
}

test "core.bank: load and validate from test snapshot" {
    const allocator = std.testing.allocator;

    const full_metadata_path = "test_data/10";
    var full_snapshot_fields = try SnapshotFields.readFromFilePath(
        allocator,
        full_metadata_path,
    );
    defer full_snapshot_fields.deinit(allocator);

    // use the genesis to verify loading
    const genesis_path = "test_data/genesis.bin";
    const genesis_config = try GenesisConfig.init(allocator, genesis_path);
    defer genesis_config.deinit(allocator);

    try Bank.validateBankFields(
        &full_snapshot_fields.bank_fields,
        &genesis_config,
    );
}
