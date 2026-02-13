/// Types for parsing sysvar accounts for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const account_decoder = @import("lib.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const sysvar = sig.runtime.sysvar;
const bincode = sig.bincode;
const ParseError = account_decoder.ParseError;

// Re-use UiFeeCalculator from parse_nonce
const UiFeeCalculator = @import("parse_nonce.zig").UiFeeCalculator;

/// Parse a sysvar account by its pubkey.
/// Returns null if the pubkey doesn't match any known sysvar.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L24
pub fn parseSysvar(
    allocator: Allocator,
    pubkey: Pubkey,
    reader: anytype,
) ParseError!?SysvarAccountType {
    if (pubkey.equals(&sysvar.Clock.ID)) {
        const clock = bincode.read(allocator, sysvar.Clock, reader, .{}) catch
            return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .clock = UiClock{
                .slot = clock.slot,
                .epoch = clock.epoch,
                .epoch_start_timestamp = clock.epoch_start_timestamp,
                .leader_schedule_epoch = clock.leader_schedule_epoch,
                .unix_timestamp = clock.unix_timestamp,
            },
        };
    } else if (pubkey.equals(&sysvar.EpochSchedule.ID)) {
        const schedule = bincode.read(allocator, sysvar.EpochSchedule, reader, .{}) catch
            return ParseError.InvalidAccountData;
        return SysvarAccountType{ .epoch_schedule = schedule };
    } else if (pubkey.equals(&sysvar.Fees.ID)) {
        const fees = bincode.read(allocator, sysvar.Fees, reader, .{}) catch
            return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .fees = UiFees{
                .fee_calculator = UiFeeCalculator{
                    .lamports_per_signature = fees.lamports_per_signature,
                },
            },
        };
    } else if (pubkey.equals(&sysvar.RecentBlockhashes.ID)) {
        const blockhashes = bincode.read(allocator, sysvar.RecentBlockhashes, reader, .{}) catch
            return ParseError.InvalidAccountData;
        var entries: std.BoundedArray(UiRecentBlockhashesEntry, sysvar.RecentBlockhashes.MAX_ENTRIES) = .{};
        for (blockhashes.entries.constSlice()) |entry| {
            entries.appendAssumeCapacity(UiRecentBlockhashesEntry{
                .blockhash = entry.blockhash.base58String(),
                .lamports_per_signature = entry.lamports_per_signature,
            });
        }
        return SysvarAccountType{
            .recent_blockhashes = UiRecentBlockhashes{ .entries = entries },
        };
    } else if (pubkey.equals(&sysvar.Rent.ID)) {
        const rent = bincode.read(allocator, sysvar.Rent, reader, .{}) catch
            return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .rent = UiRent{
                .lamports_per_byte_year = rent.lamports_per_byte_year,
                .exemption_threshold = rent.exemption_threshold,
                .burn_percent = rent.burn_percent,
            },
        };
    } else if (pubkey.equals(&sig.runtime.ids.SYSVAR_REWARDS_ID)) {
        // Rewards sysvar is deprecated but still parsable.
        // It's just a single f64, read as u64 and bitcast.
        const bits = reader.readInt(u64, .little) catch return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .rewards = UiRewards{
                .validator_point_value = @bitCast(bits),
            },
        };
    } else if (pubkey.equals(&sysvar.SlotHashes.ID)) {
        const slot_hashes = bincode.read(allocator, sysvar.SlotHashes, reader, .{}) catch
            return ParseError.InvalidAccountData;
        var entries: std.BoundedArray(UiSlotHashEntry, sysvar.SlotHashes.MAX_ENTRIES) = .{};
        for (slot_hashes.entries.constSlice()) |entry| {
            entries.appendAssumeCapacity(UiSlotHashEntry{
                .slot = entry.slot,
                .hash = entry.hash.base58String(),
            });
        }
        return SysvarAccountType{
            .slot_hashes = UiSlotHashes{ .entries = entries },
        };
    } else if (pubkey.equals(&sysvar.SlotHistory.ID)) {
        const slot_history = bincode.read(allocator, sysvar.SlotHistory, reader, .{}) catch
            return ParseError.InvalidAccountData;
        // Note: We move ownership of the bits to UiSlotHistory.
        // The caller must ensure the allocator outlives the returned value,
        // or use an arena allocator.
        return SysvarAccountType{
            .slot_history = UiSlotHistory{
                .next_slot = slot_history.next_slot,
                .bits = slot_history.bits,
            },
        };
    } else if (pubkey.equals(&sysvar.StakeHistory.ID)) {
        const stake_history = bincode.read(allocator, sysvar.StakeHistory, reader, .{}) catch
            return ParseError.InvalidAccountData;
        var entries: std.BoundedArray(UiStakeHistoryEntry, sysvar.StakeHistory.MAX_ENTRIES) = .{};
        for (stake_history.entries.constSlice()) |entry| {
            entries.appendAssumeCapacity(UiStakeHistoryEntry{
                .epoch = entry.epoch,
                .effective = entry.stake.effective,
                .activating = entry.stake.activating,
                .deactivating = entry.stake.deactivating,
            });
        }
        return SysvarAccountType{
            .stake_history = UiStakeHistory{ .entries = entries },
        };
    } else if (pubkey.equals(&sysvar.LastRestartSlot.ID)) {
        const last_restart = bincode.read(allocator, sysvar.LastRestartSlot, reader, .{}) catch
            return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .last_restart_slot = UiLastRestartSlot{
                .last_restart_slot = last_restart.last_restart_slot,
            },
        };
    } else if (pubkey.equals(&sysvar.EpochRewards.ID)) {
        const epoch_rewards = bincode.read(allocator, sysvar.EpochRewards, reader, .{}) catch
            return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .epoch_rewards = UiEpochRewards{
                .distribution_starting_block_height = epoch_rewards.distribution_starting_block_height,
                .num_partitions = epoch_rewards.num_partitions,
                .parent_blockhash = epoch_rewards.parent_blockhash.base58String(),
                .total_points = epoch_rewards.total_points,
                .total_rewards = epoch_rewards.total_rewards,
                .distributed_rewards = epoch_rewards.distributed_rewards,
                .active = epoch_rewards.active,
            },
        };
    }
    return null;
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L99
pub const SysvarAccountType = union(enum) {
    clock: UiClock,
    epoch_schedule: sysvar.EpochSchedule,
    fees: UiFees,
    recent_blockhashes: UiRecentBlockhashes,
    rent: UiRent,
    rewards: UiRewards,
    slot_hashes: UiSlotHashes,
    slot_history: UiSlotHistory,
    stake_history: UiStakeHistory,
    last_restart_slot: UiLastRestartSlot,
    epoch_rewards: UiEpochRewards,

    pub fn jsonStringify(self: SysvarAccountType, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            .clock => |v| {
                try jw.write("clock");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .epoch_schedule => |v| {
                try jw.write("epochSchedule");
                try jw.objectField("info");
                try jsonStringifyEpochSchedule(v, jw);
            },
            .fees => |v| {
                try jw.write("fees");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .recent_blockhashes => |v| {
                try jw.write("recentBlockhashes");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .rent => |v| {
                try jw.write("rent");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .rewards => |v| {
                try jw.write("rewards");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .slot_hashes => |v| {
                try jw.write("slotHashes");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .slot_history => |v| {
                try jw.write("slotHistory");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .stake_history => |v| {
                try jw.write("stakeHistory");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .last_restart_slot => |v| {
                try jw.write("lastRestartSlot");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .epoch_rewards => |v| {
                try jw.write("epochRewards");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
        }
        try jw.endObject();
    }
};

/// EpochSchedule is used directly from Sig, needs custom jsonStringify.
fn jsonStringifyEpochSchedule(schedule: sysvar.EpochSchedule, jw: anytype) @TypeOf(jw.*).Error!void {
    try jw.beginObject();
    try jw.objectField("slotsPerEpoch");
    try jw.write(schedule.slots_per_epoch);
    try jw.objectField("leaderScheduleSlotOffset");
    try jw.write(schedule.leader_schedule_slot_offset);
    try jw.objectField("warmup");
    try jw.write(schedule.warmup);
    try jw.objectField("firstNormalEpoch");
    try jw.write(schedule.first_normal_epoch);
    try jw.objectField("firstNormalSlot");
    try jw.write(schedule.first_normal_slot);
    try jw.endObject();
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L113
pub const UiClock = struct {
    slot: Slot,
    epoch: Epoch,
    epoch_start_timestamp: i64,
    leader_schedule_epoch: Epoch,
    unix_timestamp: i64,

    pub fn jsonStringify(self: UiClock, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("slot");
        try jw.write(self.slot);
        try jw.objectField("epoch");
        try jw.write(self.epoch);
        try jw.objectField("epochStartTimestamp");
        try jw.write(self.epoch_start_timestamp);
        try jw.objectField("leaderScheduleEpoch");
        try jw.write(self.leader_schedule_epoch);
        try jw.objectField("unixTimestamp");
        try jw.write(self.unix_timestamp);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L131
pub const UiFees = struct {
    fee_calculator: UiFeeCalculator,

    pub fn jsonStringify(self: UiFees, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("feeCalculator");
        try self.fee_calculator.jsonStringify(jw);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L143
pub const UiRent = struct {
    lamports_per_byte_year: u64,
    exemption_threshold: f64,
    burn_percent: u8,

    pub fn jsonStringify(self: UiRent, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("lamportsPerByteYear");
        try jw.print("\"{d}\"", .{self.lamports_per_byte_year});
        try jw.objectField("exemptionThreshold");
        try jw.write(self.exemption_threshold);
        try jw.objectField("burnPercent");
        try jw.write(self.burn_percent);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L159
pub const UiRewards = struct {
    validator_point_value: f64,

    pub fn jsonStringify(self: UiRewards, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("validatorPointValue");
        try jw.write(self.validator_point_value);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L169
pub const UiRecentBlockhashes = struct {
    entries: std.BoundedArray(UiRecentBlockhashesEntry, sysvar.RecentBlockhashes.MAX_ENTRIES),

    pub fn jsonStringify(self: UiRecentBlockhashes, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginArray();
        for (self.entries.constSlice()) |entry| {
            try jw.beginObject();
            try jw.objectField("blockhash");
            try jw.write(entry.blockhash.slice());
            try jw.objectField("feeCalculator");
            const fee_calc = UiFeeCalculator{ .lamports_per_signature = entry.lamports_per_signature };
            try fee_calc.jsonStringify(jw);
            try jw.endObject();
        }
        try jw.endArray();
    }
};

pub const UiRecentBlockhashesEntry = struct {
    blockhash: Hash.Base58String,
    lamports_per_signature: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L176
pub const UiSlotHashes = struct {
    entries: std.BoundedArray(UiSlotHashEntry, sysvar.SlotHashes.MAX_ENTRIES),

    pub fn jsonStringify(self: UiSlotHashes, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginArray();
        for (self.entries.constSlice()) |entry| {
            try jw.beginObject();
            try jw.objectField("slot");
            try jw.write(entry.slot);
            try jw.objectField("hash");
            try jw.write(entry.hash.slice());
            try jw.endObject();
        }
        try jw.endArray();
    }
};

pub const UiSlotHashEntry = struct {
    slot: Slot,
    hash: Hash.Base58String,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L183
pub const UiSlotHistory = struct {
    next_slot: Slot,
    bits: sig.bloom.bit_set.DynamicArrayBitSet(u64),

    pub fn jsonStringify(self: UiSlotHistory, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("nextSlot");
        try jw.write(self.next_slot);
        try jw.objectField("bits");
        // Agave formats bits as a string of MAX_ENTRIES 0s and 1s using Debug format.
        // We stream-write this to avoid allocating 1MB+ string.
        try jw.beginWriteRaw();
        try jw.stream.writeByte('"');
        // TODO: should be able to optimize/remove this.
        for (0..sig.runtime.sysvar.SlotHistory.MAX_ENTRIES) |i| {
            if (self.bits.isSet(i)) {
                try jw.stream.writeByte('1');
            } else {
                try jw.stream.writeByte('0');
            }
        }
        try jw.stream.writeByte('"');
        jw.endWriteRaw();
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L199
pub const UiStakeHistory = struct {
    entries: std.BoundedArray(UiStakeHistoryEntry, sysvar.StakeHistory.MAX_ENTRIES),

    pub fn jsonStringify(self: UiStakeHistory, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginArray();
        for (self.entries.constSlice()) |entry| {
            try jw.beginObject();
            try jw.objectField("epoch");
            try jw.write(entry.epoch);
            try jw.objectField("stakeHistory");
            try jw.beginObject();
            try jw.objectField("effective");
            try jw.write(entry.effective);
            try jw.objectField("activating");
            try jw.write(entry.activating);
            try jw.objectField("deactivating");
            try jw.write(entry.deactivating);
            try jw.endObject();
            try jw.endObject();
        }
        try jw.endArray();
    }
};

pub const UiStakeHistoryEntry = struct {
    epoch: Epoch,
    effective: u64,
    activating: u64,
    deactivating: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L205
pub const UiLastRestartSlot = struct {
    last_restart_slot: Slot,

    pub fn jsonStringify(self: UiLastRestartSlot, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("lastRestartSlot");
        try jw.write(self.last_restart_slot);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L212
pub const UiEpochRewards = struct {
    distribution_starting_block_height: u64,
    num_partitions: u64,
    parent_blockhash: Hash.Base58String,
    total_points: u128,
    total_rewards: u64,
    distributed_rewards: u64,
    active: bool,

    pub fn jsonStringify(self: UiEpochRewards, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("distributionStartingBlockHeight");
        try jw.write(self.distribution_starting_block_height);
        try jw.objectField("numPartitions");
        try jw.write(self.num_partitions);
        try jw.objectField("parentBlockhash");
        try jw.write(self.parent_blockhash.slice());
        try jw.objectField("totalPoints");
        try jw.print("\"{d}\"", .{self.total_points});
        try jw.objectField("totalRewards");
        try jw.print("\"{d}\"", .{self.total_rewards});
        try jw.objectField("distributedRewards");
        try jw.print("\"{d}\"", .{self.distributed_rewards});
        try jw.objectField("active");
        try jw.write(self.active);
        try jw.endObject();
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L225
test "rpc.account_decoder.parse_sysvar: parse sysvars" {
    const allocator = std.testing.allocator;
    const hash = Hash{ .data = [_]u8{1} ** 32 };

    // Clock sysvar (default)
    {
        const clock = sysvar.Clock.INIT;
        const serialized = try bincode.writeAlloc(allocator, clock, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.Clock.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .clock);
        const ui_clock = result.?.clock;
        try std.testing.expectEqual(@as(Slot, 0), ui_clock.slot);
        try std.testing.expectEqual(@as(Epoch, 0), ui_clock.epoch);
        try std.testing.expectEqual(@as(i64, 0), ui_clock.epoch_start_timestamp);
        try std.testing.expectEqual(@as(Epoch, 0), ui_clock.leader_schedule_epoch);
        try std.testing.expectEqual(@as(i64, 0), ui_clock.unix_timestamp);
    }

    // EpochSchedule sysvar (custom values matching Agave test)
    {
        const epoch_schedule = sysvar.EpochSchedule{
            .slots_per_epoch = 12,
            .leader_schedule_slot_offset = 0,
            .warmup = false,
            .first_normal_epoch = 1,
            .first_normal_slot = 12,
        };
        const serialized = try bincode.writeAlloc(allocator, epoch_schedule, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.EpochSchedule.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .epoch_schedule);
        const ui_epoch_schedule = result.?.epoch_schedule;
        try std.testing.expectEqual(@as(u64, 12), ui_epoch_schedule.slots_per_epoch);
        try std.testing.expectEqual(@as(u64, 0), ui_epoch_schedule.leader_schedule_slot_offset);
        try std.testing.expectEqual(false, ui_epoch_schedule.warmup);
        try std.testing.expectEqual(@as(Epoch, 1), ui_epoch_schedule.first_normal_epoch);
        try std.testing.expectEqual(@as(Slot, 12), ui_epoch_schedule.first_normal_slot);
    }

    // Fees sysvar (deprecated, default)
    {
        const fees = sysvar.Fees.INIT;
        const serialized = try bincode.writeAlloc(allocator, fees, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.Fees.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .fees);
        try std.testing.expectEqual(@as(u64, 0), result.?.fees.fee_calculator.lamports_per_signature);
    }

    // RecentBlockhashes sysvar (deprecated, one entry)
    {
        const recent_blockhashes = sysvar.RecentBlockhashes.initWithEntries(&.{
            .{ .blockhash = hash, .lamports_per_signature = 10 },
        });
        const serialized = try bincode.writeAlloc(allocator, recent_blockhashes, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.RecentBlockhashes.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .recent_blockhashes);
        const entries = result.?.recent_blockhashes.entries.constSlice();
        try std.testing.expectEqual(@as(usize, 1), entries.len);
        try std.testing.expectEqualStrings(hash.base58String().slice(), entries[0].blockhash.slice());
        try std.testing.expectEqual(@as(u64, 10), entries[0].lamports_per_signature);
    }

    // Rent sysvar (custom values)
    {
        const rent = sysvar.Rent{
            .lamports_per_byte_year = 10,
            .exemption_threshold = 2.0,
            .burn_percent = 5,
        };
        const serialized = try bincode.writeAlloc(allocator, rent, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.Rent.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .rent);
        const ui_rent = result.?.rent;
        try std.testing.expectEqual(@as(u64, 10), ui_rent.lamports_per_byte_year);
        try std.testing.expectEqual(@as(f64, 2.0), ui_rent.exemption_threshold);
        try std.testing.expectEqual(@as(u8, 5), ui_rent.burn_percent);
    }

    // Rewards sysvar (deprecated, default = 0.0)
    {
        // Rewards is just a single f64, serialized as u64 bits
        const validator_point_value: f64 = 0.0;
        const bits: u64 = @bitCast(validator_point_value);
        var serialized: [8]u8 = undefined;
        std.mem.writeInt(u64, &serialized, bits, .little);

        var stream = std.io.fixedBufferStream(&serialized);
        const result = try parseSysvar(allocator, sig.runtime.ids.SYSVAR_REWARDS_ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .rewards);
        try std.testing.expectEqual(@as(f64, 0.0), result.?.rewards.validator_point_value);
    }

    // SlotHashes sysvar (one entry)
    {
        var slot_hashes: sysvar.SlotHashes = .INIT;
        slot_hashes.add(1, hash);
        const serialized = try bincode.writeAlloc(allocator, slot_hashes, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.SlotHashes.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .slot_hashes);
        const entries = result.?.slot_hashes.entries.constSlice();
        try std.testing.expectEqual(@as(usize, 1), entries.len);
        try std.testing.expectEqual(@as(Slot, 1), entries[0].slot);
        try std.testing.expectEqualStrings(hash.base58String().slice(), entries[0].hash.slice());
    }

    // SlotHistory sysvar (with slot 42 added)
    {
        var slot_history = try sysvar.SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        slot_history.add(42);

        const serialized = try bincode.writeAlloc(allocator, slot_history, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.SlotHistory.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .slot_history);
        const ui_slot_history = result.?.slot_history;
        defer ui_slot_history.bits.deinit(allocator);
        try std.testing.expectEqual(@as(Slot, 43), ui_slot_history.next_slot);
        // Verify bit 42 is set (and bit 0 from init)
        try std.testing.expect(ui_slot_history.bits.isSet(42));
        try std.testing.expect(ui_slot_history.bits.isSet(0));
    }

    // StakeHistory sysvar (one entry)
    {
        var stake_history: sysvar.StakeHistory = .INIT;
        try stake_history.insertEntry(1, .{
            .effective = 10,
            .activating = 2,
            .deactivating = 3,
        });
        const serialized = try bincode.writeAlloc(allocator, stake_history, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.StakeHistory.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .stake_history);
        const entries = result.?.stake_history.entries.constSlice();
        try std.testing.expectEqual(@as(usize, 1), entries.len);
        try std.testing.expectEqual(@as(Epoch, 1), entries[0].epoch);
        try std.testing.expectEqual(@as(u64, 10), entries[0].effective);
        try std.testing.expectEqual(@as(u64, 2), entries[0].activating);
        try std.testing.expectEqual(@as(u64, 3), entries[0].deactivating);
    }

    // Bad pubkey - unknown sysvar pubkey should return null
    {
        var stake_history: sysvar.StakeHistory = .INIT;
        try stake_history.insertEntry(1, .{ .effective = 10, .activating = 2, .deactivating = 3 });
        const serialized = try bincode.writeAlloc(allocator, stake_history, .{});
        defer allocator.free(serialized);

        const bad_pubkey = Pubkey{ .data = [_]u8{0xAB} ** 32 };
        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, bad_pubkey, stream.reader());

        try std.testing.expect(result == null);
    }

    // Bad data - invalid data for a known sysvar should return error
    {
        const bad_data = [_]u8{ 0, 0, 0, 0 };
        var stream = std.io.fixedBufferStream(&bad_data);
        const result = parseSysvar(allocator, sysvar.StakeHistory.ID, stream.reader());

        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }

    // LastRestartSlot sysvar
    {
        const last_restart_slot = sysvar.LastRestartSlot{
            .last_restart_slot = 1282,
        };
        const serialized = try bincode.writeAlloc(allocator, last_restart_slot, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.LastRestartSlot.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .last_restart_slot);
        try std.testing.expectEqual(@as(Slot, 1282), result.?.last_restart_slot.last_restart_slot);
    }

    // EpochRewards sysvar
    {
        const epoch_rewards = sysvar.EpochRewards{
            .distribution_starting_block_height = 42,
            .num_partitions = 0,
            .parent_blockhash = Hash.ZEROES,
            .total_points = 0,
            .total_rewards = 100,
            .distributed_rewards = 20,
            .active = true,
        };
        const serialized = try bincode.writeAlloc(allocator, epoch_rewards, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(allocator, sysvar.EpochRewards.ID, stream.reader());

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .epoch_rewards);
        const ui_epoch_rewards = result.?.epoch_rewards;
        try std.testing.expectEqual(@as(u64, 42), ui_epoch_rewards.distribution_starting_block_height);
        try std.testing.expectEqual(@as(u64, 0), ui_epoch_rewards.num_partitions);
        try std.testing.expectEqualStrings(Hash.ZEROES.base58String().slice(), ui_epoch_rewards.parent_blockhash.slice());
        try std.testing.expectEqual(@as(u128, 0), ui_epoch_rewards.total_points);
        try std.testing.expectEqual(@as(u64, 100), ui_epoch_rewards.total_rewards);
        try std.testing.expectEqual(@as(u64, 20), ui_epoch_rewards.distributed_rewards);
        try std.testing.expectEqual(true, ui_epoch_rewards.active);
    }
}
