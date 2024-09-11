const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const ChaChaRng = sig.rand.ChaChaRng;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const WeightedRandomSampler = sig.rand.WeightedRandomSampler;
const RpcClient = sig.rpc.Client;
const EpochSchedule = sig.core.EpochSchedule;
const BankFields = sig.accounts_db.snapshots.BankFields;
const RwMux = sig.sync.RwMux;

pub const NUM_CONSECUTIVE_LEADER_SLOTS: u64 = 4;
pub const MAX_CACHED_LEADER_SCHEDULES: usize = 10;

pub const SlotLeaderProvider = sig.utils.closure.PointerClosure(Slot, ?Pubkey);

/// LeaderScheduleCache is a cache of leader schedules for each epoch.
/// Leader schedules are expensive to compute, so this cache is used to avoid
/// recomputing leader schedules for the same epoch.
/// LeaderScheduleCache also keeps a copy of the epoch_schedule so that it can
/// compute epoch and slot index from a slot.
pub const LeaderScheduleCache = struct {
    allocator: std.mem.Allocator,
    epoch_schedule: EpochSchedule,
    leader_schedules_rw: RwMux(std.AutoArrayHashMap(Epoch, LeaderSchedule)),

    pub fn init(allocator: std.mem.Allocator, epoch_schedule: EpochSchedule) LeaderScheduleCache {
        return .{
            .allocator = allocator,
            .epoch_schedule = epoch_schedule,
            .leader_schedules_rw = RwMux(std.AutoArrayHashMap(Epoch, LeaderSchedule)).init(
                std.AutoArrayHashMap(Epoch, LeaderSchedule).init(allocator),
            ),
        };
    }

    pub fn deinit(self: LeaderScheduleCache) void {
        const leader_schedules, var leader_schedule_lg = self.leader_schedules_rw.writeWithLock();
        defer leader_schedule_lg.unlock();

        for (leader_schedules.values()) |v| v.deinit();
        leader_schedules.deinit();
    }

    pub fn getUniqueLeaders(self: *LeaderScheduleCache) !std.AutoArrayHashMap(Pubkey, void) {
        const leader_schedules, var leader_schedules_lg = self.leader_schedules_rw.readWithLock();
        defer leader_schedules_lg.unlock();

        var unique_leaders = std.AutoArrayHashMap(Pubkey, void).init(self.allocator);

        for (leader_schedules.values()) |leader_schedule| {
            for (leader_schedule.slot_leaders) |leader| {
                try unique_leaders.put(leader, void{});
            }
        }

        return unique_leaders;
    }

    pub fn getSlotLeaderProvider(self: *LeaderScheduleCache) SlotLeaderProvider {
        return SlotLeaderProvider.init(self, LeaderScheduleCache.getSlotLeaderNoCompute);
    }

    pub fn getSlotLeaderNoCompute(self: *LeaderScheduleCache, slot: Slot) ?Pubkey {
        const epoch, const slot_index = self.epoch_schedule.getEpochAndSlotIndex(slot);
        return self.getSlotLeader(epoch, slot_index);
    }

    pub fn getSlotLeaderMaybeCompute(self: *LeaderScheduleCache, slot: Slot, bank: *const BankFields) !sig.core.Pubkey {
        const epoch, const slot_index = self.epoch_schedule.getEpochAndSlotIndex(slot);
        if (self.getSlotLeader(epoch, slot_index)) |leader| return leader;

        const leader_schedules, var leader_schedule_lg = self.leader_schedules_rw.writeWithLock();
        defer leader_schedule_lg.unlock();

        const entry = try leader_schedules.getOrPut(epoch);
        if (!entry.found_existing) {
            if (leader_schedules.count() == MAX_CACHED_LEADER_SCHEDULES) {
                _ = leader_schedules.swapRemove(std.mem.min(Epoch, leader_schedules.keys()));
            }
            entry.value_ptr.* = try LeaderSchedule.fromBank(
                self.allocator,
                epoch,
                bank,
            );
        }
        return entry.value_ptr.slot_leaders[slot_index];
    }

    pub fn getSlotLeaderMaybeComputeRpc(self: *LeaderScheduleCache, slot: Slot, rpc_client: *RpcClient) !sig.core.Pubkey {
        const epoch, const slot_index = self.epoch_schedule.getEpochAndSlotIndex(slot);
        if (self.getSlotLeader(epoch, slot_index)) |leader| return leader;

        const leader_schedules, var leader_schedule_lg = self.leader_schedules_rw.writeWithLock();
        defer leader_schedule_lg.unlock();

        const entry = try leader_schedules.getOrPut(epoch);
        if (!entry.found_existing) {
            if (leader_schedules.count() == MAX_CACHED_LEADER_SCHEDULES) {
                _ = leader_schedules.swapRemove(std.mem.min(Epoch, leader_schedules.keys()));
            }
            entry.value_ptr.* = try LeaderSchedule.fromRpc(
                self.allocator,
                slot,
                rpc_client,
            );
        }
        return entry.value_ptr.slot_leaders[slot_index];
    }

    fn getSlotLeader(self: *LeaderScheduleCache, epoch: Epoch, slot_index: usize) ?Pubkey {
        const leader_schedules, var leader_schedule_lg = self.leader_schedules_rw.readWithLock();
        defer leader_schedule_lg.unlock();

        if (leader_schedules.getEntry(epoch)) |entry| {
            return entry.value_ptr.slot_leaders[slot_index];
        } else {
            return null;
        }
    }

    /// This method exists purely to allow using leader schedule from cli, manually inserting it into the
    /// cache with its associated epoch.
    pub fn insertLeaderSchedule(self: *LeaderScheduleCache, epoch: Epoch, leader_schedule: LeaderSchedule) !void {
        const leader_schedules, var leader_schedule_lg = self.leader_schedules_rw.writeWithLock();
        defer leader_schedule_lg.unlock();
        try leader_schedules.put(epoch, leader_schedule);
    }
};

/// LeaderSchedule for a single epoch.
/// LeaderSchedule's are constructed by either using information from bank fields
/// to compute the leader schedule from scratch, or using information obtained from a
/// getLeaderSchedule RPC request.
/// To compute a leader schedule for epoch `e`, we must know the state of staked nodes at some
/// fixed point in time before the first slot of epoch `e`. This is usually configured to be
/// 1 full epoch before epoch `e`.
pub const LeaderSchedule = struct {
    allocator: std.mem.Allocator,
    slot_leaders: []const Pubkey,
    first_slot: ?Slot = null, // This is only used in 'mock' scenarios when loading leader schedule from cli

    pub fn deinit(self: LeaderSchedule) void {
        self.allocator.free(self.slot_leaders);
    }

    pub fn fromBank(
        allocator: std.mem.Allocator,
        epoch: Epoch,
        bank: *const BankFields,
    ) !LeaderSchedule {
        const slots_in_epoch = bank.epoch_schedule.getSlotsInEpoch(epoch);
        const staked_nodes = try bank.getStakedNodes(allocator, epoch);
        return .{
            .allocator = allocator,
            .slot_leaders = try LeaderSchedule.computeSlotLeaders(
                allocator,
                epoch,
                slots_in_epoch,
                staked_nodes,
            ),
        };
    }

    pub fn fromRpc(
        allocator: Allocator,
        for_slot: Slot,
        rpc_client: *RpcClient,
    ) !LeaderSchedule {
        const rpc_leader_schedule_response = try rpc_client.getLeaderSchedule(allocator, for_slot, .{});
        defer rpc_leader_schedule_response.deinit();
        const rpc_leader_schedule = try rpc_leader_schedule_response.result();

        var num_leaders: u64 = 0;
        for (rpc_leader_schedule.values()) |leader_slots| {
            num_leaders += leader_slots.len;
        }

        const Record = struct { slot: Slot, key: Pubkey };

        var leaders_index: usize = 0;
        var leaders = try allocator.alloc(Record, num_leaders);
        defer allocator.free(leaders);

        var rpc_leader_iter = rpc_leader_schedule.iterator();
        while (rpc_leader_iter.next()) |entry| {
            const key = try Pubkey.fromString(entry.key_ptr.*);
            for (entry.value_ptr.*) |slot| {
                leaders[leaders_index] = .{ .slot = slot, .key = key };
                leaders_index += 1;
            }
        }

        std.mem.sortUnstable(Record, leaders, {}, struct {
            fn gt(_: void, lhs: Record, rhs: Record) bool {
                return switch (std.math.order(lhs.slot, rhs.slot)) {
                    .gt => false,
                    else => true,
                };
            }
        }.gt);

        var slot_leaders = try allocator.alloc(Pubkey, leaders.len);
        for (leaders, 0..) |record, i| {
            slot_leaders[i] = record.key;
        }

        return .{
            .allocator = allocator,
            .slot_leaders = slot_leaders,
        };
    }

    pub fn computeSlotLeaders(
        allocator: std.mem.Allocator,
        epoch: Epoch,
        slots_in_epoch: Slot,
        staked_nodes: *const std.AutoArrayHashMapUnmanaged(Pubkey, u64),
    ) ![]const Pubkey {
        const Entry = std.AutoArrayHashMap(Pubkey, u64).Entry;

        const nodes = try allocator.alloc(Entry, staked_nodes.count());
        defer allocator.free(nodes);

        for (nodes, staked_nodes.keys(), staked_nodes.values()) |*node, *key_ptr, *value_ptr| {
            node.* = .{
                .key_ptr = key_ptr,
                .value_ptr = value_ptr,
            };
        }

        std.mem.sortUnstable(Entry, nodes, {}, struct {
            fn gt(_: void, lhs: Entry, rhs: Entry) bool {
                return switch (std.math.order(lhs.value_ptr.*, rhs.value_ptr.*)) {
                    .gt => true,
                    .lt => false,
                    .eq => .gt == std.mem.order(u8, &lhs.key_ptr.data, &rhs.key_ptr.data),
                };
            }
        }.gt);

        // init random number generator
        var seed: [32]u8 = .{0} ** 32;
        std.mem.writeInt(Epoch, seed[0..@sizeOf(Epoch)], epoch, .little);
        var rng = ChaChaRng(20).fromSeed(seed);
        const random = rng.random();

        // init sampler from stake weights
        const stakes = try allocator.alloc(u64, nodes.len);
        defer allocator.free(stakes);
        for (nodes, 0..) |entry, i| stakes[i] = entry.value_ptr.*;
        var sampler = try WeightedRandomSampler(u64).init(allocator, random, stakes);
        defer sampler.deinit();

        // calculate leader schedule
        var slot_leaders = try allocator.alloc(Pubkey, slots_in_epoch);
        var current_node: Pubkey = undefined;
        for (0..slots_in_epoch) |i| {
            if (i % NUM_CONSECUTIVE_LEADER_SLOTS == 0) {
                current_node = nodes[sampler.sample()].key_ptr.*;
            }
            slot_leaders[i] = current_node;
        }

        return slot_leaders;
    }

    /// Reads the leader schedule as formatted by the `solana leader-schedule` and
    /// `sig leader-schedule` commands.
    pub fn read(
        allocator: std.mem.Allocator,
        reader: anytype,
    ) !LeaderSchedule {
        const nextNonEmpty = struct {
            pub fn nextNonEmpty(word_iter: anytype) ?[]const u8 {
                while (word_iter.next()) |word| if (word.len > 0) return word;
                return null;
            }
        }.nextNonEmpty;

        var slot_leaders = std.ArrayList(Pubkey).init(allocator);
        var start_slot: Slot = 0;
        var expect: ?Slot = null;
        var row: [256]u8 = undefined;
        while (true) {
            const line = reader.readUntilDelimiter(&row, '\n') catch |e| switch (e) {
                error.EndOfStream => break,
                else => return e,
            };
            var word_iter = std.mem.split(u8, line, " ");
            const slot = try std.fmt.parseInt(Slot, nextNonEmpty(&word_iter) orelse continue, 10);
            if (expect) |*exp_slot| {
                if (slot != exp_slot.*) {
                    return error.Discontinuity;
                }
                exp_slot.* += 1;
            } else {
                expect = slot + 1;
                start_slot = slot;
            }
            const node_str = nextNonEmpty(&word_iter) orelse return error.MissingPubkey;
            try slot_leaders.append(try Pubkey.fromString(node_str));
        }

        return .{
            .allocator = allocator,
            .slot_leaders = try slot_leaders.toOwnedSlice(),
            .first_slot = start_slot,
        };
    }

    /// Writes the leader schedule as formatted by the `solana leader-schedule` and
    /// `sig leader-schedule` commands.
    pub fn write(self: *const LeaderSchedule, writer: anytype, start_slot: Slot) !void {
        for (self.slot_leaders, 0..) |leader, i| {
            try writer.print("  {}       {s}\n", .{ i + start_slot, leader });
        }
    }
};

test "leaderSchedule calculation matches agave" {
    var rng = ChaChaRng(20).fromSeed(.{0} ** 32);
    const random = rng.random();
    var pubkey_bytes: [32]u8 = undefined;
    var staked_nodes = std.AutoArrayHashMap(Pubkey, u64).init(std.testing.allocator);
    defer staked_nodes.deinit();
    for (0..100) |_| {
        random.bytes(&pubkey_bytes);
        const key = Pubkey{ .data = pubkey_bytes };
        const stake = random.int(u64) / 1000;
        try staked_nodes.put(key, stake);
    }
    const slot_leaders = try LeaderSchedule.computeSlotLeaders(std.testing.allocator, 123, 321, &staked_nodes.unmanaged);
    defer std.testing.allocator.free(slot_leaders);
    for (slot_leaders, 0..) |slot_leader, i| {
        try std.testing.expect((try Pubkey.fromString(generated_leader_schedule[i])).equals(&slot_leader));
    }
}

test "parseLeaderSchedule writeLeaderSchedule happy path roundtrip" {
    const allocator = std.testing.allocator;
    const input_file =
        \\  270864000       Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk
        \\  270864001       Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk
        \\  270864002       Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk
        \\  270864003       Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk
        \\  270864004       GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8
        \\  270864005       GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8
        \\  270864006       GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8
        \\  270864007       GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8
        \\  270864008       DWvDTSh3qfn88UoQTEKRV2JnLt5jtJAVoiCo3ivtMwXP
        \\  270864009       DWvDTSh3qfn88UoQTEKRV2JnLt5jtJAVoiCo3ivtMwXP
        \\  270864010       DWvDTSh3qfn88UoQTEKRV2JnLt5jtJAVoiCo3ivtMwXP
        \\
    ;
    const expected_nodes = [_]Pubkey{
        try Pubkey.fromString("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk"),
        try Pubkey.fromString("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk"),
        try Pubkey.fromString("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk"),
        try Pubkey.fromString("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk"),
        try Pubkey.fromString("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8"),
        try Pubkey.fromString("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8"),
        try Pubkey.fromString("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8"),
        try Pubkey.fromString("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8"),
        try Pubkey.fromString("DWvDTSh3qfn88UoQTEKRV2JnLt5jtJAVoiCo3ivtMwXP"),
        try Pubkey.fromString("DWvDTSh3qfn88UoQTEKRV2JnLt5jtJAVoiCo3ivtMwXP"),
        try Pubkey.fromString("DWvDTSh3qfn88UoQTEKRV2JnLt5jtJAVoiCo3ivtMwXP"),
    };
    // const expected_start = 270864000;

    // parse input file
    var stream = std.io.fixedBufferStream(input_file);
    const leader_schedule = try LeaderSchedule.read(allocator, stream.reader());
    defer leader_schedule.deinit();
    // try std.testing.expect(expected_start == leader_schedule.start_slot);
    try std.testing.expect(expected_nodes.len == leader_schedule.slot_leaders.len);
    for (expected_nodes, leader_schedule.slot_leaders) |expected, actual| {
        try std.testing.expect(expected.equals(&actual));
    }

    // write file out
    var out_buf: [2 * input_file.len]u8 = undefined;
    var out_stream = std.io.fixedBufferStream(&out_buf);
    try leader_schedule.write(out_stream.writer(), 270864000);
    const out_file = out_stream.getWritten();
    try std.testing.expect(std.mem.eql(u8, out_file, input_file));
}

const generated_leader_schedule = [_][]const u8{
    "HU1g6zZ3LrXJeFYEmDAekv44kAv9XE8g8FQYz3rSrmNY", "HU1g6zZ3LrXJeFYEmDAekv44kAv9XE8g8FQYz3rSrmNY",
    "HU1g6zZ3LrXJeFYEmDAekv44kAv9XE8g8FQYz3rSrmNY", "HU1g6zZ3LrXJeFYEmDAekv44kAv9XE8g8FQYz3rSrmNY",
    "AvsmCG8R1qGJtRvjqudkX974ihfbYZUVf4t515tzxyHv", "AvsmCG8R1qGJtRvjqudkX974ihfbYZUVf4t515tzxyHv",
    "AvsmCG8R1qGJtRvjqudkX974ihfbYZUVf4t515tzxyHv", "AvsmCG8R1qGJtRvjqudkX974ihfbYZUVf4t515tzxyHv",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "CrFNvAe9JJkW9yzmtUMWpA4GMvRqWz88EJLPyhrxmFzd", "CrFNvAe9JJkW9yzmtUMWpA4GMvRqWz88EJLPyhrxmFzd",
    "CrFNvAe9JJkW9yzmtUMWpA4GMvRqWz88EJLPyhrxmFzd", "CrFNvAe9JJkW9yzmtUMWpA4GMvRqWz88EJLPyhrxmFzd",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "ChZKtGvACLPovxKJLUtnDyNHiPLECoXsneziARENU8kV", "ChZKtGvACLPovxKJLUtnDyNHiPLECoXsneziARENU8kV",
    "ChZKtGvACLPovxKJLUtnDyNHiPLECoXsneziARENU8kV", "ChZKtGvACLPovxKJLUtnDyNHiPLECoXsneziARENU8kV",
    "4SNVzDbWzQmUWRVb5BNXifV4NYGoYA8evhpSFfy5pSaN", "4SNVzDbWzQmUWRVb5BNXifV4NYGoYA8evhpSFfy5pSaN",
    "4SNVzDbWzQmUWRVb5BNXifV4NYGoYA8evhpSFfy5pSaN", "4SNVzDbWzQmUWRVb5BNXifV4NYGoYA8evhpSFfy5pSaN",
    "5nvNxUpHfZ2FSRPbDtDyMeFrvN5YBFBvokoYobe2qgqH", "5nvNxUpHfZ2FSRPbDtDyMeFrvN5YBFBvokoYobe2qgqH",
    "5nvNxUpHfZ2FSRPbDtDyMeFrvN5YBFBvokoYobe2qgqH", "5nvNxUpHfZ2FSRPbDtDyMeFrvN5YBFBvokoYobe2qgqH",
    "8zScg5nWKZEzFJnhPu5s9zBeLRHTTjvfcw2aKWDRJNDt", "8zScg5nWKZEzFJnhPu5s9zBeLRHTTjvfcw2aKWDRJNDt",
    "8zScg5nWKZEzFJnhPu5s9zBeLRHTTjvfcw2aKWDRJNDt", "8zScg5nWKZEzFJnhPu5s9zBeLRHTTjvfcw2aKWDRJNDt",
    "ALiW6m6KxrY98DkUhToCU8eLfgrQ73Zuo3eh9phWmbJV", "ALiW6m6KxrY98DkUhToCU8eLfgrQ73Zuo3eh9phWmbJV",
    "ALiW6m6KxrY98DkUhToCU8eLfgrQ73Zuo3eh9phWmbJV", "ALiW6m6KxrY98DkUhToCU8eLfgrQ73Zuo3eh9phWmbJV",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "8LetEQHxeoVTMFoQiett6odLZTwKw1SLYnC6UiNHaNC9", "8LetEQHxeoVTMFoQiett6odLZTwKw1SLYnC6UiNHaNC9",
    "8LetEQHxeoVTMFoQiett6odLZTwKw1SLYnC6UiNHaNC9", "8LetEQHxeoVTMFoQiett6odLZTwKw1SLYnC6UiNHaNC9",
    "Gh8qe5sKntpd7RMhLSy52CZcwEZZVrPujNxFc6FCsXSC", "Gh8qe5sKntpd7RMhLSy52CZcwEZZVrPujNxFc6FCsXSC",
    "Gh8qe5sKntpd7RMhLSy52CZcwEZZVrPujNxFc6FCsXSC", "Gh8qe5sKntpd7RMhLSy52CZcwEZZVrPujNxFc6FCsXSC",
    "F8RUGg4CfVvsHGH38aAR3s2nsw7Faw2QjhsWomScgEtb", "F8RUGg4CfVvsHGH38aAR3s2nsw7Faw2QjhsWomScgEtb",
    "F8RUGg4CfVvsHGH38aAR3s2nsw7Faw2QjhsWomScgEtb", "F8RUGg4CfVvsHGH38aAR3s2nsw7Faw2QjhsWomScgEtb",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6", "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6",
    "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6", "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6",
    "ALiW6m6KxrY98DkUhToCU8eLfgrQ73Zuo3eh9phWmbJV", "ALiW6m6KxrY98DkUhToCU8eLfgrQ73Zuo3eh9phWmbJV",
    "ALiW6m6KxrY98DkUhToCU8eLfgrQ73Zuo3eh9phWmbJV", "ALiW6m6KxrY98DkUhToCU8eLfgrQ73Zuo3eh9phWmbJV",
    "GmNETdrkoh2trUWJ4bHP6TLsHw2jcbdwTDyKYToYNTqU", "GmNETdrkoh2trUWJ4bHP6TLsHw2jcbdwTDyKYToYNTqU",
    "GmNETdrkoh2trUWJ4bHP6TLsHw2jcbdwTDyKYToYNTqU", "GmNETdrkoh2trUWJ4bHP6TLsHw2jcbdwTDyKYToYNTqU",
    "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY", "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY",
    "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY", "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY",
    "Ar17KaAgMEiGVVRQqo3ta7jfeAksR3JcXaRsiDSBxgz3", "Ar17KaAgMEiGVVRQqo3ta7jfeAksR3JcXaRsiDSBxgz3",
    "Ar17KaAgMEiGVVRQqo3ta7jfeAksR3JcXaRsiDSBxgz3", "Ar17KaAgMEiGVVRQqo3ta7jfeAksR3JcXaRsiDSBxgz3",
    "EgYg66jU5q678BdPGEPj1fyobsPXzwLoxz2uvvSUQ2zG", "EgYg66jU5q678BdPGEPj1fyobsPXzwLoxz2uvvSUQ2zG",
    "EgYg66jU5q678BdPGEPj1fyobsPXzwLoxz2uvvSUQ2zG", "EgYg66jU5q678BdPGEPj1fyobsPXzwLoxz2uvvSUQ2zG",
    "EtnzJyeepGFXSJZ7EWqi1kXYi2zpgFMdUtDx1ovRTi75", "EtnzJyeepGFXSJZ7EWqi1kXYi2zpgFMdUtDx1ovRTi75",
    "EtnzJyeepGFXSJZ7EWqi1kXYi2zpgFMdUtDx1ovRTi75", "EtnzJyeepGFXSJZ7EWqi1kXYi2zpgFMdUtDx1ovRTi75",
    "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB", "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB",
    "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB", "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6", "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6",
    "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6", "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6",
    "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW", "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW",
    "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW", "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW",
    "3dMU1xcDSXzaG9mFB8N6ySKsSE1AknaxPAYBxCs83qsn", "3dMU1xcDSXzaG9mFB8N6ySKsSE1AknaxPAYBxCs83qsn",
    "3dMU1xcDSXzaG9mFB8N6ySKsSE1AknaxPAYBxCs83qsn", "3dMU1xcDSXzaG9mFB8N6ySKsSE1AknaxPAYBxCs83qsn",
    "36hQwDVUzUBqij3vukdrjGogxjH1qzve66vMLLHgkoNG", "36hQwDVUzUBqij3vukdrjGogxjH1qzve66vMLLHgkoNG",
    "36hQwDVUzUBqij3vukdrjGogxjH1qzve66vMLLHgkoNG", "36hQwDVUzUBqij3vukdrjGogxjH1qzve66vMLLHgkoNG",
    "8GfdNsue2yP6dagvMwK9YKWKhxteELz1JGeMdy7b3Xtp", "8GfdNsue2yP6dagvMwK9YKWKhxteELz1JGeMdy7b3Xtp",
    "8GfdNsue2yP6dagvMwK9YKWKhxteELz1JGeMdy7b3Xtp", "8GfdNsue2yP6dagvMwK9YKWKhxteELz1JGeMdy7b3Xtp",
    "A5TCWz8baPdYYgeCa5scXwNEUmnsYwbWbmGLbUSYergs", "A5TCWz8baPdYYgeCa5scXwNEUmnsYwbWbmGLbUSYergs",
    "A5TCWz8baPdYYgeCa5scXwNEUmnsYwbWbmGLbUSYergs", "A5TCWz8baPdYYgeCa5scXwNEUmnsYwbWbmGLbUSYergs",
    "EiLPxcwYe8akU9g6C6A99j5mep3N7A4ySfMNunC3qMjQ", "EiLPxcwYe8akU9g6C6A99j5mep3N7A4ySfMNunC3qMjQ",
    "EiLPxcwYe8akU9g6C6A99j5mep3N7A4ySfMNunC3qMjQ", "EiLPxcwYe8akU9g6C6A99j5mep3N7A4ySfMNunC3qMjQ",
    "4Lu8CGxdYgXAHKUMU3bN4BnDSYdcqniNV4WFJ2GiY5wz", "4Lu8CGxdYgXAHKUMU3bN4BnDSYdcqniNV4WFJ2GiY5wz",
    "4Lu8CGxdYgXAHKUMU3bN4BnDSYdcqniNV4WFJ2GiY5wz", "4Lu8CGxdYgXAHKUMU3bN4BnDSYdcqniNV4WFJ2GiY5wz",
    "9BF6Dt4ELaWvZ88sdKkwx6LPvo51w7A3FG5dqTFBnNC6", "9BF6Dt4ELaWvZ88sdKkwx6LPvo51w7A3FG5dqTFBnNC6",
    "9BF6Dt4ELaWvZ88sdKkwx6LPvo51w7A3FG5dqTFBnNC6", "9BF6Dt4ELaWvZ88sdKkwx6LPvo51w7A3FG5dqTFBnNC6",
    "8GfdNsue2yP6dagvMwK9YKWKhxteELz1JGeMdy7b3Xtp", "8GfdNsue2yP6dagvMwK9YKWKhxteELz1JGeMdy7b3Xtp",
    "8GfdNsue2yP6dagvMwK9YKWKhxteELz1JGeMdy7b3Xtp", "8GfdNsue2yP6dagvMwK9YKWKhxteELz1JGeMdy7b3Xtp",
    "ChZKtGvACLPovxKJLUtnDyNHiPLECoXsneziARENU8kV", "ChZKtGvACLPovxKJLUtnDyNHiPLECoXsneziARENU8kV",
    "ChZKtGvACLPovxKJLUtnDyNHiPLECoXsneziARENU8kV", "ChZKtGvACLPovxKJLUtnDyNHiPLECoXsneziARENU8kV",
    "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB", "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB",
    "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB", "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB",
    "HzAQzrCnH7VAaxAVSahEs6WcBcW38bi3ZLarZaZ1YVR4", "HzAQzrCnH7VAaxAVSahEs6WcBcW38bi3ZLarZaZ1YVR4",
    "HzAQzrCnH7VAaxAVSahEs6WcBcW38bi3ZLarZaZ1YVR4", "HzAQzrCnH7VAaxAVSahEs6WcBcW38bi3ZLarZaZ1YVR4",
    "4XVPmBXM6bfJdUqkLfAxS6t4fsZS9D3rSZd3M835u91H", "4XVPmBXM6bfJdUqkLfAxS6t4fsZS9D3rSZd3M835u91H",
    "4XVPmBXM6bfJdUqkLfAxS6t4fsZS9D3rSZd3M835u91H", "4XVPmBXM6bfJdUqkLfAxS6t4fsZS9D3rSZd3M835u91H",
    "HzAQzrCnH7VAaxAVSahEs6WcBcW38bi3ZLarZaZ1YVR4", "HzAQzrCnH7VAaxAVSahEs6WcBcW38bi3ZLarZaZ1YVR4",
    "HzAQzrCnH7VAaxAVSahEs6WcBcW38bi3ZLarZaZ1YVR4", "HzAQzrCnH7VAaxAVSahEs6WcBcW38bi3ZLarZaZ1YVR4",
    "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ", "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ",
    "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ", "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ",
    "J8pKv47cms17Qav9s97pJjKhQLRvmQbxGMLKVe7QXF7P", "J8pKv47cms17Qav9s97pJjKhQLRvmQbxGMLKVe7QXF7P",
    "J8pKv47cms17Qav9s97pJjKhQLRvmQbxGMLKVe7QXF7P", "J8pKv47cms17Qav9s97pJjKhQLRvmQbxGMLKVe7QXF7P",
    "A5TCWz8baPdYYgeCa5scXwNEUmnsYwbWbmGLbUSYergs", "A5TCWz8baPdYYgeCa5scXwNEUmnsYwbWbmGLbUSYergs",
    "A5TCWz8baPdYYgeCa5scXwNEUmnsYwbWbmGLbUSYergs", "A5TCWz8baPdYYgeCa5scXwNEUmnsYwbWbmGLbUSYergs",
    "ErAWjNHKa2oChJcqdyoCXC5ZZsLqpGwphcbmMxTEwmsZ", "ErAWjNHKa2oChJcqdyoCXC5ZZsLqpGwphcbmMxTEwmsZ",
    "ErAWjNHKa2oChJcqdyoCXC5ZZsLqpGwphcbmMxTEwmsZ", "ErAWjNHKa2oChJcqdyoCXC5ZZsLqpGwphcbmMxTEwmsZ",
    "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ", "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ",
    "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ", "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ",
    "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x", "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x",
    "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x", "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x",
    "DWUt7KxRWF8GdFhTYdM4ZFA3rQ9roKrRXUcm8Xeeywkq", "DWUt7KxRWF8GdFhTYdM4ZFA3rQ9roKrRXUcm8Xeeywkq",
    "DWUt7KxRWF8GdFhTYdM4ZFA3rQ9roKrRXUcm8Xeeywkq", "DWUt7KxRWF8GdFhTYdM4ZFA3rQ9roKrRXUcm8Xeeywkq",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "Esqc3WZPLR1XkvapZxRqFTQa6UxGQM4Lamqt6duLFEtj", "Esqc3WZPLR1XkvapZxRqFTQa6UxGQM4Lamqt6duLFEtj",
    "Esqc3WZPLR1XkvapZxRqFTQa6UxGQM4Lamqt6duLFEtj", "Esqc3WZPLR1XkvapZxRqFTQa6UxGQM4Lamqt6duLFEtj",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ", "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ",
    "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ", "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ",
    "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ", "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ",
    "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ", "8NaFkAtLW8qo4VdgUuU1VAD3nuKZxpDFMGpeg1ajeCSZ",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",  "5W6GpY2dKVsks2QF1EdrDSasdM1f9KqVNVFbZTzBy8V",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN", "Ay73RcvjzYq43dTv32CzTEhddBBQJL6J5JnzbJjTFQZN",
    "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB", "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB",
    "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB", "DCKCfRPPfHUHmJz7ejnLCQodkhsuKj51exdXUBWEivQB",
    "ErAWjNHKa2oChJcqdyoCXC5ZZsLqpGwphcbmMxTEwmsZ", "ErAWjNHKa2oChJcqdyoCXC5ZZsLqpGwphcbmMxTEwmsZ",
    "ErAWjNHKa2oChJcqdyoCXC5ZZsLqpGwphcbmMxTEwmsZ", "ErAWjNHKa2oChJcqdyoCXC5ZZsLqpGwphcbmMxTEwmsZ",
    "9CsaB86comVhyFqtDrALpBHhaBHGmf13iBJL7JDWV9p2", "9CsaB86comVhyFqtDrALpBHhaBHGmf13iBJL7JDWV9p2",
    "9CsaB86comVhyFqtDrALpBHhaBHGmf13iBJL7JDWV9p2", "9CsaB86comVhyFqtDrALpBHhaBHGmf13iBJL7JDWV9p2",
    "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW", "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW",
    "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW", "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW",
    "FLG8C3rziE56N3jib3NPB1TcTrGJXeTmLLwvPCW337PA", "FLG8C3rziE56N3jib3NPB1TcTrGJXeTmLLwvPCW337PA",
    "FLG8C3rziE56N3jib3NPB1TcTrGJXeTmLLwvPCW337PA", "FLG8C3rziE56N3jib3NPB1TcTrGJXeTmLLwvPCW337PA",
    "6b4LnC2vhdfS5MqjBSwWMFdJwA9tgbu2ezEcspeKVYSn", "6b4LnC2vhdfS5MqjBSwWMFdJwA9tgbu2ezEcspeKVYSn",
    "6b4LnC2vhdfS5MqjBSwWMFdJwA9tgbu2ezEcspeKVYSn", "6b4LnC2vhdfS5MqjBSwWMFdJwA9tgbu2ezEcspeKVYSn",
    "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6", "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6",
    "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6", "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6",
    "8gxPGDZK4G8qzW7zsRpw8MW84rRpeUS6vj8CGrPbYdyk", "8gxPGDZK4G8qzW7zsRpw8MW84rRpeUS6vj8CGrPbYdyk",
    "8gxPGDZK4G8qzW7zsRpw8MW84rRpeUS6vj8CGrPbYdyk", "8gxPGDZK4G8qzW7zsRpw8MW84rRpeUS6vj8CGrPbYdyk",
    "Hq6Tke5EnrpDADM4sTcfMZoSLwsNCNz4pmHpCoc4UdY9", "Hq6Tke5EnrpDADM4sTcfMZoSLwsNCNz4pmHpCoc4UdY9",
    "Hq6Tke5EnrpDADM4sTcfMZoSLwsNCNz4pmHpCoc4UdY9", "Hq6Tke5EnrpDADM4sTcfMZoSLwsNCNz4pmHpCoc4UdY9",
    "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY", "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY",
    "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY", "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY",
    "GwckxXocVzxE8Ao1nWrW6QmBCLiy3k5DuLE2uEV2RHAq", "GwckxXocVzxE8Ao1nWrW6QmBCLiy3k5DuLE2uEV2RHAq",
    "GwckxXocVzxE8Ao1nWrW6QmBCLiy3k5DuLE2uEV2RHAq", "GwckxXocVzxE8Ao1nWrW6QmBCLiy3k5DuLE2uEV2RHAq",
    "Gkkp1TrPTWZLRE88HNZvRfUh2Hjpgti9g7AqQv88cf9",  "Gkkp1TrPTWZLRE88HNZvRfUh2Hjpgti9g7AqQv88cf9",
    "Gkkp1TrPTWZLRE88HNZvRfUh2Hjpgti9g7AqQv88cf9",  "Gkkp1TrPTWZLRE88HNZvRfUh2Hjpgti9g7AqQv88cf9",
    "HCbPW8qzM3feTpyYrA1HS5byK7PqBq4m1cvZRuQT6yb1", "HCbPW8qzM3feTpyYrA1HS5byK7PqBq4m1cvZRuQT6yb1",
    "HCbPW8qzM3feTpyYrA1HS5byK7PqBq4m1cvZRuQT6yb1", "HCbPW8qzM3feTpyYrA1HS5byK7PqBq4m1cvZRuQT6yb1",
    "3r3Tzsck7WPJbsbPM9yhC8fsBQtjFFBwrGX2ct394Bef", "3r3Tzsck7WPJbsbPM9yhC8fsBQtjFFBwrGX2ct394Bef",
    "3r3Tzsck7WPJbsbPM9yhC8fsBQtjFFBwrGX2ct394Bef", "3r3Tzsck7WPJbsbPM9yhC8fsBQtjFFBwrGX2ct394Bef",
    "EiLPxcwYe8akU9g6C6A99j5mep3N7A4ySfMNunC3qMjQ", "EiLPxcwYe8akU9g6C6A99j5mep3N7A4ySfMNunC3qMjQ",
    "EiLPxcwYe8akU9g6C6A99j5mep3N7A4ySfMNunC3qMjQ", "EiLPxcwYe8akU9g6C6A99j5mep3N7A4ySfMNunC3qMjQ",
    "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW", "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW",
    "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW", "DxMVzBzTuX2VprSQEvtKraPR5JVMSgx4rqyASG4xEVNW",
    "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x", "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x",
    "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x", "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x",
    "FLG8C3rziE56N3jib3NPB1TcTrGJXeTmLLwvPCW337PA", "FLG8C3rziE56N3jib3NPB1TcTrGJXeTmLLwvPCW337PA",
    "FLG8C3rziE56N3jib3NPB1TcTrGJXeTmLLwvPCW337PA", "FLG8C3rziE56N3jib3NPB1TcTrGJXeTmLLwvPCW337PA",
    "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6", "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6",
    "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6", "6BSbQZxg86LrAtscs3cezszNJmJhRWErG72VWavECEz6",
    "9qBV9MtqqSSt4pt8XvX8URn2fLQqNPWzcYiBx8rcAgiX", "9qBV9MtqqSSt4pt8XvX8URn2fLQqNPWzcYiBx8rcAgiX",
    "9qBV9MtqqSSt4pt8XvX8URn2fLQqNPWzcYiBx8rcAgiX", "9qBV9MtqqSSt4pt8XvX8URn2fLQqNPWzcYiBx8rcAgiX",
    "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x", "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x",
    "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x", "78DHaJZHsmTj5g6xPQJa5pP99Tg6MgG8zQVqcKG5Zq7x",
    "Hq6Tke5EnrpDADM4sTcfMZoSLwsNCNz4pmHpCoc4UdY9", "Hq6Tke5EnrpDADM4sTcfMZoSLwsNCNz4pmHpCoc4UdY9",
    "Hq6Tke5EnrpDADM4sTcfMZoSLwsNCNz4pmHpCoc4UdY9", "Hq6Tke5EnrpDADM4sTcfMZoSLwsNCNz4pmHpCoc4UdY9",
    "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY", "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY",
    "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY", "GGZKvA54JkUQ66NqkLAeo7uqu9dJdneXm9gsPqTbNEMY",
    "EffB1PCz4fwqLGD9ko1bkRTFVHekedCTX83az91Rdbo2", "EffB1PCz4fwqLGD9ko1bkRTFVHekedCTX83az91Rdbo2",
    "EffB1PCz4fwqLGD9ko1bkRTFVHekedCTX83az91Rdbo2", "EffB1PCz4fwqLGD9ko1bkRTFVHekedCTX83az91Rdbo2",
    "AuDjtyKmix6vLHBsfouA82GQrmJ4JRWRPqCEcD54kkkH", "AuDjtyKmix6vLHBsfouA82GQrmJ4JRWRPqCEcD54kkkH",
    "AuDjtyKmix6vLHBsfouA82GQrmJ4JRWRPqCEcD54kkkH", "AuDjtyKmix6vLHBsfouA82GQrmJ4JRWRPqCEcD54kkkH",
    "HU1g6zZ3LrXJeFYEmDAekv44kAv9XE8g8FQYz3rSrmNY", "HU1g6zZ3LrXJeFYEmDAekv44kAv9XE8g8FQYz3rSrmNY",
    "HU1g6zZ3LrXJeFYEmDAekv44kAv9XE8g8FQYz3rSrmNY", "HU1g6zZ3LrXJeFYEmDAekv44kAv9XE8g8FQYz3rSrmNY",
    "DUUJtWATcHjMhNHGh9pPud3HGp4yrrZe1tE7ELHXUAB6",
};
