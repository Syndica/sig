/// Types for parsing sysvar accounts for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const parse_nonce = @import("parse_nonce.zig");

const account_codec = sig.rpc.account_codec;
const bincode = sig.bincode;
const sysvar = sig.runtime.sysvar;

const Allocator = std.mem.Allocator;
const Epoch = sig.core.Epoch;
const Hash = sig.core.Hash;
const JsonArray = account_codec.JsonArray;
const ParseError = account_codec.ParseError;
const Pubkey = sig.core.Pubkey;
const RyuF64 = account_codec.RyuF64;
const Slot = sig.core.Slot;
const Stringified = account_codec.Stringified;
const UiFeeCalculator = parse_nonce.UiFeeCalculator;

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
                .epochStartTimestamp = clock.epoch_start_timestamp,
                .leaderScheduleEpoch = clock.leader_schedule_epoch,
                .unixTimestamp = clock.unix_timestamp,
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
                .feeCalculator = UiFeeCalculator{
                    .lamportsPerSignature = Stringified(u64).init(fees.lamports_per_signature),
                },
            },
        };
    } else if (pubkey.equals(&sysvar.RecentBlockhashes.ID)) {
        const blockhashes = bincode.read(
            allocator,
            sysvar.RecentBlockhashes,
            reader,
            .{},
        ) catch
            return ParseError.InvalidAccountData;
        var entries: UiRecentBlockhashes = .{};
        for (blockhashes.entries.constSlice()) |entry| {
            entries.appendAssumeCapacity(UiRecentBlockhashesEntry{
                .blockhash = entry.blockhash,
                .feeCalculator = UiFeeCalculator{
                    .lamportsPerSignature = Stringified(u64).init(entry.lamports_per_signature),
                },
            });
        }
        return SysvarAccountType{
            .recent_blockhashes = entries,
        };
    } else if (pubkey.equals(&sysvar.Rent.ID)) {
        const rent = bincode.read(allocator, sysvar.Rent, reader, .{}) catch
            return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .rent = UiRent{
                .lamportsPerByteYear = Stringified(u64).init(rent.lamports_per_byte_year),
                .exemptionThreshold = RyuF64.init(rent.exemption_threshold),
                .burnPercent = rent.burn_percent,
            },
        };
    } else if (pubkey.equals(&sig.runtime.ids.SYSVAR_REWARDS_ID)) {
        // Rewards sysvar is deprecated but still parsable.
        // It's just a single f64, read as u64 and bitcast.
        const bits = reader.readInt(u64, .little) catch return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .rewards = UiRewards{
                .validatorPointValue = RyuF64.init(@bitCast(bits)),
            },
        };
    } else if (pubkey.equals(&sysvar.SlotHashes.ID)) {
        const slot_hashes = bincode.read(
            allocator,
            sysvar.SlotHashes,
            reader,
            .{},
        ) catch
            return ParseError.InvalidAccountData;
        var entries: UiSlotHashes = .{};
        for (slot_hashes.entries.constSlice()) |entry| {
            entries.appendAssumeCapacity(UiSlotHashEntry{
                .slot = entry.slot,
                .hash = entry.hash,
            });
        }
        return SysvarAccountType{
            .slot_hashes = entries,
        };
    } else if (pubkey.equals(&sysvar.SlotHistory.ID)) {
        const slot_history = bincode.read(
            allocator,
            sysvar.SlotHistory,
            reader,
            .{},
        ) catch
            return ParseError.InvalidAccountData;
        // Note: We move ownership of the bits to UiSlotHistory.
        // The caller must ensure the allocator outlives the returned value,
        // or use an arena allocator.
        return SysvarAccountType{
            .slot_history = UiSlotHistory{
                .nextSlot = slot_history.next_slot,
                .bits = slot_history.bits,
            },
        };
    } else if (pubkey.equals(&sysvar.StakeHistory.ID)) {
        const stake_history = bincode.read(
            allocator,
            sysvar.StakeHistory,
            reader,
            .{},
        ) catch
            return ParseError.InvalidAccountData;
        var entries: UiStakeHistory = .{};
        for (stake_history.entries.constSlice()) |entry| {
            entries.appendAssumeCapacity(UiStakeHistoryEntry{
                .epoch = entry.epoch,
                .stakeHistory = .{
                    .effective = entry.stake.effective,
                    .activating = entry.stake.activating,
                    .deactivating = entry.stake.deactivating,
                },
            });
        }
        return SysvarAccountType{
            .stake_history = entries,
        };
    } else if (pubkey.equals(&sysvar.LastRestartSlot.ID)) {
        const last_restart = bincode.read(
            allocator,
            sysvar.LastRestartSlot,
            reader,
            .{},
        ) catch
            return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .last_restart_slot = UiLastRestartSlot{
                .lastRestartSlot = last_restart.last_restart_slot,
            },
        };
    } else if (pubkey.equals(&sysvar.EpochRewards.ID)) {
        const epoch_rewards = bincode.read(
            allocator,
            sysvar.EpochRewards,
            reader,
            .{},
        ) catch
            return ParseError.InvalidAccountData;
        return SysvarAccountType{
            .epoch_rewards = UiEpochRewards{
                .distributionStartingBlockHeight = epoch_rewards.distribution_starting_block_height,
                .numPartitions = epoch_rewards.num_partitions,
                .parentBlockhash = epoch_rewards.parent_blockhash,
                .totalPoints = Stringified(u128).init(epoch_rewards.total_points),
                .totalRewards = Stringified(u64).init(epoch_rewards.total_rewards),
                .distributedRewards = Stringified(u64).init(epoch_rewards.distributed_rewards),
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
            inline else => |v, tag| {
                try jw.write(comptime typeNameFromTag(tag));
                try jw.objectField("info");
                try jw.write(v);
            },
        }
        try jw.endObject();
    }

    fn typeNameFromTag(tag: std.meta.Tag(SysvarAccountType)) []const u8 {
        return switch (tag) {
            .clock => "clock",
            .epoch_schedule => "epochSchedule",
            .fees => "fees",
            .recent_blockhashes => "recentBlockhashes",
            .rent => "rent",
            .rewards => "rewards",
            .slot_hashes => "slotHashes",
            .slot_history => "slotHistory",
            .stake_history => "stakeHistory",
            .last_restart_slot => "lastRestartSlot",
            .epoch_rewards => "epochRewards",
        };
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L113
pub const UiClock = struct {
    slot: Slot,
    epoch: Epoch,
    epochStartTimestamp: i64,
    leaderScheduleEpoch: Epoch,
    unixTimestamp: i64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L131
pub const UiFees = struct {
    feeCalculator: UiFeeCalculator,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L143
pub const UiRent = struct {
    lamportsPerByteYear: Stringified(u64),
    exemptionThreshold: RyuF64,
    burnPercent: u8,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L159
pub const UiRewards = struct {
    validatorPointValue: RyuF64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L169
pub const UiRecentBlockhashes = JsonArray(
    UiRecentBlockhashesEntry,
    sysvar.RecentBlockhashes.MAX_ENTRIES,
);

pub const UiRecentBlockhashesEntry = struct {
    blockhash: Hash,
    feeCalculator: UiFeeCalculator,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L176
pub const UiSlotHashes = JsonArray(
    UiSlotHashEntry,
    sysvar.SlotHashes.MAX_ENTRIES,
);

pub const UiSlotHashEntry = struct {
    slot: Slot,
    hash: Hash,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L183
pub const UiSlotHistory = struct {
    nextSlot: Slot,
    bits: sig.bloom.bit_set.DynamicArrayBitSet(u64),

    pub fn jsonStringify(self: UiSlotHistory, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("nextSlot");
        try jw.write(self.nextSlot);
        try jw.objectField("bits");
        // Agave formats bits as a string of MAX_ENTRIES 0s and 1s using Debug format.
        // We stream-write this to avoid allocating 1MB+ string.
        try jw.beginWriteRaw();
        try jw.writer.writeByte('"');
        for (0..sig.runtime.sysvar.SlotHistory.MAX_ENTRIES) |i| {
            try jw.writer.writeByte(if (self.bits.isSet(i)) '1' else '0');
        }
        try jw.writer.writeByte('"');
        jw.endWriteRaw();
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L199
pub const UiStakeHistory = JsonArray(UiStakeHistoryEntry, sysvar.StakeHistory.MAX_ENTRIES);

pub const UiStakeHistoryEntry = struct {
    epoch: Epoch,
    stakeHistory: UiStakeHistoryEntryItem,
};

pub const UiStakeHistoryEntryItem = struct {
    effective: u64,
    activating: u64,
    deactivating: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L205
pub const UiLastRestartSlot = struct {
    lastRestartSlot: Slot,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L212
pub const UiEpochRewards = struct {
    distributionStartingBlockHeight: u64,
    numPartitions: u64,
    parentBlockhash: Hash,
    totalPoints: Stringified(u128),
    totalRewards: Stringified(u64),
    distributedRewards: Stringified(u64),
    active: bool,
};

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L225
test "rpc.account_codec.parse_sysvar: parse sysvars" {
    const allocator = std.testing.allocator;
    const hash = Hash{ .data = [_]u8{1} ** 32 };

    // Clock sysvar (default)
    {
        const clock = sysvar.Clock.INIT;
        const serialized = try bincode.writeAlloc(allocator, clock, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(
            allocator,
            sysvar.Clock.ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .clock);
        const ui_clock = result.?.clock;
        try std.testing.expectEqual(@as(Slot, 0), ui_clock.slot);
        try std.testing.expectEqual(@as(Epoch, 0), ui_clock.epoch);
        try std.testing.expectEqual(@as(i64, 0), ui_clock.epochStartTimestamp);
        try std.testing.expectEqual(@as(Epoch, 0), ui_clock.leaderScheduleEpoch);
        try std.testing.expectEqual(@as(i64, 0), ui_clock.unixTimestamp);
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
        const result = try parseSysvar(
            allocator,
            sysvar.EpochSchedule.ID,
            stream.reader(),
        );

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
        const result = try parseSysvar(
            allocator,
            sysvar.Fees.ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .fees);
        const lps = result.?.fees.feeCalculator.lamportsPerSignature.value;
        try std.testing.expectEqual(@as(u64, 0), lps);
    }

    // RecentBlockhashes sysvar (deprecated, one entry)
    {
        const recent_blockhashes = sysvar.RecentBlockhashes.initWithEntries(&.{
            .{ .blockhash = hash, .lamports_per_signature = 10 },
        });
        const serialized = try bincode.writeAlloc(allocator, recent_blockhashes, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(
            allocator,
            sysvar.RecentBlockhashes.ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .recent_blockhashes);
        const entries = result.?.recent_blockhashes.constSlice();
        try std.testing.expectEqual(@as(usize, 1), entries.len);
        try std.testing.expectEqualStrings(
            hash.base58String().constSlice(),
            entries[0].blockhash.base58String().constSlice(),
        );
        const lps = entries[0].feeCalculator.lamportsPerSignature.value;
        try std.testing.expectEqual(@as(u64, 10), lps);
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
        const result = try parseSysvar(
            allocator,
            sysvar.Rent.ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .rent);
        const ui_rent = result.?.rent;
        try std.testing.expectEqual(@as(u64, 10), ui_rent.lamportsPerByteYear.value);
        try std.testing.expectEqual(@as(f64, 2.0), ui_rent.exemptionThreshold.value);
        try std.testing.expectEqual(@as(u8, 5), ui_rent.burnPercent);
    }

    // Rewards sysvar (deprecated, default = 0.0)
    {
        // Rewards is just a single f64, serialized as u64 bits
        const validator_point_value: f64 = 0.0;
        const bits: u64 = @bitCast(validator_point_value);
        var serialized: [8]u8 = undefined;
        std.mem.writeInt(u64, &serialized, bits, .little);

        var stream = std.io.fixedBufferStream(&serialized);
        const result = try parseSysvar(
            allocator,
            sig.runtime.ids.SYSVAR_REWARDS_ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .rewards);
        try std.testing.expectEqual(@as(f64, 0.0), result.?.rewards.validatorPointValue.value);
    }

    // SlotHashes sysvar (one entry)
    {
        var slot_hashes: sysvar.SlotHashes = .INIT;
        slot_hashes.add(1, hash);
        const serialized = try bincode.writeAlloc(allocator, slot_hashes, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(
            allocator,
            sysvar.SlotHashes.ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .slot_hashes);
        const entries = result.?.slot_hashes.constSlice();
        try std.testing.expectEqual(@as(usize, 1), entries.len);
        try std.testing.expectEqual(@as(Slot, 1), entries[0].slot);
        try std.testing.expectEqual(hash, entries[0].hash);
    }

    // SlotHistory sysvar (with slot 42 added)
    {
        var slot_history = try sysvar.SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        slot_history.add(42);

        const serialized = try bincode.writeAlloc(allocator, slot_history, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(
            allocator,
            sysvar.SlotHistory.ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .slot_history);
        const ui_slot_history = result.?.slot_history;
        defer ui_slot_history.bits.deinit(allocator);
        try std.testing.expectEqual(@as(Slot, 43), ui_slot_history.nextSlot);
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
        const result = try parseSysvar(
            allocator,
            sysvar.StakeHistory.ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .stake_history);
        const entries = result.?.stake_history.constSlice();
        try std.testing.expectEqual(@as(usize, 1), entries.len);
        try std.testing.expectEqual(@as(Epoch, 1), entries[0].epoch);
        try std.testing.expectEqual(@as(u64, 10), entries[0].stakeHistory.effective);
        try std.testing.expectEqual(@as(u64, 2), entries[0].stakeHistory.activating);
        try std.testing.expectEqual(@as(u64, 3), entries[0].stakeHistory.deactivating);
    }

    // Bad pubkey - unknown sysvar pubkey should return null
    {
        var stake_history: sysvar.StakeHistory = .INIT;
        try stake_history.insertEntry(
            1,
            .{ .effective = 10, .activating = 2, .deactivating = 3 },
        );
        const serialized = try bincode.writeAlloc(allocator, stake_history, .{});
        defer allocator.free(serialized);

        const bad_pubkey = Pubkey{ .data = [_]u8{0xAB} ** 32 };
        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseSysvar(
            allocator,
            bad_pubkey,
            stream.reader(),
        );

        try std.testing.expect(result == null);
    }

    // Bad data - invalid data for a known sysvar should return error
    {
        const bad_data = [_]u8{ 0, 0, 0, 0 };
        var stream = std.io.fixedBufferStream(&bad_data);
        const result = parseSysvar(
            allocator,
            sysvar.StakeHistory.ID,
            stream.reader(),
        );

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
        const result = try parseSysvar(
            allocator,
            sysvar.LastRestartSlot.ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .last_restart_slot);
        try std.testing.expectEqual(@as(Slot, 1282), result.?.last_restart_slot.lastRestartSlot);
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
        const result = try parseSysvar(
            allocator,
            sysvar.EpochRewards.ID,
            stream.reader(),
        );

        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .epoch_rewards);
        const ui_epoch_rewards = result.?.epoch_rewards;
        try std.testing.expectEqual(@as(u64, 42), ui_epoch_rewards.distributionStartingBlockHeight);
        try std.testing.expectEqual(@as(u64, 0), ui_epoch_rewards.numPartitions);
        try std.testing.expectEqual(Hash.ZEROES, ui_epoch_rewards.parentBlockhash);
        try std.testing.expectEqual(@as(u128, 0), ui_epoch_rewards.totalPoints.value);
        try std.testing.expectEqual(@as(u64, 100), ui_epoch_rewards.totalRewards.value);
        try std.testing.expectEqual(@as(u64, 20), ui_epoch_rewards.distributedRewards.value);
        try std.testing.expectEqual(true, ui_epoch_rewards.active);
    }
}
