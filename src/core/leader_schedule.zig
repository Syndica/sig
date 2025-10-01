const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SamplerTree = sig.random.weighted_shuffle.SamplerTree;
const EpochSchedule = sig.core.EpochSchedule;
const RwMux = sig.sync.RwMux;

pub const NUM_CONSECUTIVE_LEADER_SLOTS: u64 = 4;
pub const MAX_CACHED_LEADER_SCHEDULES: usize = 10;

/// interface to express a dependency on slot leaders
pub const SlotLeaders = union(enum) {
    lsc: *LeaderScheduleCache,
    ecm: *sig.adapter.EpochContextManager,
    // only used for testing, otherwise can't exist.
    one_slot: if (builtin.is_test) Pubkey else noreturn,
    one_epoch: if (builtin.is_test) *SingleEpochSlotLeaders else noreturn,

    pub fn get(self: SlotLeaders, slot: Slot) ?Pubkey {
        return switch (self) {
            .lsc => |lsc| lsc.slotLeader(slot),
            .ecm => |ecm| ecm.getLeader(slot),
            .one_slot => |os| os,
            .one_epoch => |oe| oe.get(slot),
        };
    }
};

/// LeaderScheduleCache is a cache of leader schedules for each epoch.
/// Leader schedules are expensive to compute, so this cache is used to avoid
/// recomputing leader schedules for the same epoch.
/// LeaderScheduleCache also keeps a copy of the epoch_schedule so that it can
/// compute epoch and slot index from a slot.
/// NOTE: This struct is not really a 'cache', we should consider renaming it
/// to a SlotLeaders and maybe even moving it outside of the core module.
/// This more accurately describes the purpose of this struct as caching is a means
/// to an end, not the end itself. It may then follow that we could remove the
/// above pointer closure in favor of passing the SlotLeaders directly.
pub const LeaderScheduleCache = struct {
    epoch_schedule: EpochSchedule,
    leader_schedules: RwMux(std.AutoArrayHashMap(Epoch, LeaderSchedule)),

    pub fn init(allocator: Allocator, epoch_schedule: EpochSchedule) LeaderScheduleCache {
        return .{
            .epoch_schedule = epoch_schedule,
            .leader_schedules = RwMux(std.AutoArrayHashMap(Epoch, LeaderSchedule)).init(
                std.AutoArrayHashMap(Epoch, LeaderSchedule).init(allocator),
            ),
        };
    }

    pub fn slotLeaders(self: *LeaderScheduleCache) SlotLeaders {
        return .{ .lsc = self };
    }

    pub fn put(self: *LeaderScheduleCache, epoch: Epoch, leader_schedule: LeaderSchedule) !void {
        const leader_schedules, var leader_schedules_lg = self.leader_schedules.writeWithLock();
        defer leader_schedules_lg.unlock();

        if (leader_schedules.count() >= MAX_CACHED_LEADER_SCHEDULES) {
            _ = leader_schedules.swapRemove(std.mem.min(Epoch, leader_schedules.keys()));
        }

        try leader_schedules.put(epoch, leader_schedule);
    }

    pub fn slotLeader(self: *LeaderScheduleCache, slot: Slot) ?Pubkey {
        const epoch, const slot_index = self.epoch_schedule.getEpochAndSlotIndex(slot);
        const leader_schedules, var leader_schedules_lg = self.leader_schedules.readWithLock();
        defer leader_schedules_lg.unlock();
        return if (leader_schedules.get(epoch)) |schedule| schedule.slot_leaders[slot_index] else null;
    }

    pub fn uniqueLeaders(self: *LeaderScheduleCache, allocator: std.mem.Allocator) ![]const Pubkey {
        const leader_schedules, var leader_schedules_lg = self.leader_schedules.readWithLock();
        defer leader_schedules_lg.unlock();

        var unique_leaders: std.AutoArrayHashMapUnmanaged(Pubkey, void) = .empty;
        defer unique_leaders.deinit(allocator);
        for (leader_schedules.values()) |leader_schedule| {
            for (leader_schedule.slot_leaders) |leader| {
                try unique_leaders.put(allocator, leader, {});
            }
        }

        const unqiue_list = try allocator.alloc(Pubkey, unique_leaders.count());
        @memcpy(unqiue_list, unique_leaders.keys());

        return unqiue_list;
    }
};

/// - The leader schedule (in slots) for a single epoch.
/// - The leader schedule can be constructed via either information from the bank to compute
/// the schedule from scratch, or using information from the `getLeaderSchedule` RPC call.
/// To compute a leader schedule for epoch `e`, we must know the state of staked nodes at some
/// fixed point in time before the first slot of epoch `e`. This is usually configured to be
/// 1 full epoch before epoch `e`.
pub const LeaderSchedule = struct {
    slot_leaders: []const Pubkey,

    pub fn deinit(self: LeaderSchedule, allocator: std.mem.Allocator) void {
        allocator.free(self.slot_leaders);
    }

    /// Converts from a map of Pubkey -> leader slot for the pubkey, into just a flat map of leader slots.
    pub fn fromMap(
        allocator: Allocator,
        leader_to_slots: *const std.AutoArrayHashMapUnmanaged(Pubkey, []const u64),
    ) !LeaderSchedule {
        var num_leaders: u64 = 0;
        for (leader_to_slots.values()) |leader_slots| {
            num_leaders += leader_slots.len;
        }

        const Record = struct { slot: Slot, key: Pubkey };
        var leaders: std.ArrayListUnmanaged(Record) = try .initCapacity(allocator, num_leaders);
        defer leaders.deinit(allocator);

        var rpc_leader_iter = leader_to_slots.iterator();
        while (rpc_leader_iter.next()) |entry| {
            for (entry.value_ptr.*) |slot| {
                try leaders.append(
                    allocator,
                    .{ .slot = slot, .key = entry.key_ptr.* },
                );
            }
        }

        std.mem.sortUnstable(Record, leaders.items, {}, struct {
            fn commpareFn(_: void, lhs: Record, rhs: Record) bool {
                return lhs.slot > rhs.slot;
            }
        }.commpareFn);

        var slot_leaders = try allocator.alloc(Pubkey, leaders.items.len);
        for (leaders.items, 0..) |record, i| {
            slot_leaders[i] = record.key;
        }

        return .{ .slot_leaders = slot_leaders };
    }

    pub fn fromVoteAccounts(
        allocator: std.mem.Allocator,
        epoch: Epoch,
        slots_in_epoch: Slot,
        vote_accounts: *const sig.core.vote_accounts.StakeAndVoteAccountsMap,
    ) ![]const Pubkey {
        // this implementation is naive and performs unnecessay allocations to construct and
        // input compatable with fromStakedNodes and re-key results.
        // It should be addressed as part of issue #945
        var stakes: std.AutoArrayHashMapUnmanaged(Pubkey, u64) = .{};
        defer stakes.deinit(allocator);

        for (vote_accounts.keys(), vote_accounts.values()) |key, value| {
            try stakes.put(allocator, key, value.stake);
        }

        const vote_keyed = try fromStakedNodes(allocator, epoch, slots_in_epoch, &stakes);

        for (vote_keyed) |*pubkey| {
            const vote_account = vote_accounts.get(pubkey.*) orelse unreachable;
            pubkey.* = vote_account.account.state.node_pubkey;
        }

        return vote_keyed;
    }

    pub fn fromStakedNodes(
        allocator: std.mem.Allocator,
        epoch: Epoch,
        slots_in_epoch: Slot,
        staked_nodes: *const std.AutoArrayHashMapUnmanaged(Pubkey, u64),
    ) ![]Pubkey {
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
                    .eq => std.mem.order(u8, &lhs.key_ptr.data, &rhs.key_ptr.data) == .gt,
                };
            }
        }.gt);

        // the epoch is the seed.
        var seed: [32]u8 = @splat(0);
        std.mem.writeInt(Epoch, seed[0..@sizeOf(Epoch)], epoch, .little);
        var sampler = try SamplerTree(.mod).init(allocator, nodes.len, seed);
        defer sampler.deinit(allocator);

        for (nodes) |entry| sampler.addWeight(entry.value_ptr.*);

        // TODO: optimize by only storing every 4th leader schedule, since we're storing 3x the data we need to be.
        var slot_leaders = try allocator.alloc(Pubkey, slots_in_epoch);
        errdefer allocator.free(slot_leaders);

        var current_node: Pubkey = undefined;
        for (0..slots_in_epoch) |i| {
            if (i % NUM_CONSECUTIVE_LEADER_SLOTS == 0) {
                current_node = nodes[try sampler.sample()].key_ptr.*;
            }
            slot_leaders[i] = current_node;
        }

        return slot_leaders;
    }

    fn nextNonEmpty(word_iter: anytype) ?[]const u8 {
        while (word_iter.next()) |word| if (word.len > 0) return word;
        return null;
    }

    /// Reads the leader schedule as formatted by the `solana leader-schedule` and
    /// `sig leader-schedule` commands. Return the start slot and the leader schedule.
    pub fn read(allocator: std.mem.Allocator, reader: anytype) !struct { Slot, LeaderSchedule } {
        var slot_leaders = std.ArrayList(Pubkey).init(allocator);
        var start_slot: Slot = 0;
        var expect: ?Slot = null;
        var row: [256]u8 = undefined;
        while (true) {
            const line = reader.readUntilDelimiter(&row, '\n') catch |e| switch (e) {
                error.EndOfStream => break,
                else => return e,
            };
            var word_iter = std.mem.splitScalar(u8, line, ' ');
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
            try slot_leaders.append(try Pubkey.parseRuntime(node_str));
        }

        return .{
            start_slot,
            .{ .slot_leaders = try slot_leaders.toOwnedSlice() },
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

/// Minimal implementation of SlotLeaders for a single epoch. Useful for tests
/// or any other context that will not exceed a single epoch.
pub const SingleEpochSlotLeaders = struct {
    start_slot: Slot,
    slot_leaders: []const Pubkey,

    pub fn get(self: *SingleEpochSlotLeaders, slot: Slot) ?Pubkey {
        if (slot < self.start_slot or slot - self.start_slot >= self.slot_leaders.len) {
            return null;
        }
        return self.slot_leaders[slot - self.start_slot];
    }

    pub fn slotLeaders(self: *SingleEpochSlotLeaders) SlotLeaders {
        return .{ .one_epoch = self };
    }
};

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
        .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk"),
        .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk"),
        .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk"),
        .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk"),
        .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8"),
        .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8"),
        .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8"),
        .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8"),
        .parse("DWvDTSh3qfn88UoQTEKRV2JnLt5jtJAVoiCo3ivtMwXP"),
        .parse("DWvDTSh3qfn88UoQTEKRV2JnLt5jtJAVoiCo3ivtMwXP"),
        .parse("DWvDTSh3qfn88UoQTEKRV2JnLt5jtJAVoiCo3ivtMwXP"),
    };
    // const expected_start = 270864000;

    // parse input file
    var stream = std.io.fixedBufferStream(input_file);
    _, const leader_schedule = try LeaderSchedule.read(allocator, stream.reader());
    defer leader_schedule.deinit(allocator);

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

test "leaderSchedule calculation matches agave" {
    const allocator = std.testing.allocator;

    var staked_nodes: std.AutoArrayHashMapUnmanaged(Pubkey, u64) = .empty;
    defer staked_nodes.deinit(allocator);

    var rng = sig.crypto.ChaCha(.twenty).init(@splat(0));

    var pubkey_bytes: [32]u8 = undefined;
    for (0..100) |_| {
        pubkey_bytes[0..8].* = @bitCast(rng.int());
        pubkey_bytes[8..16].* = @bitCast(rng.int());
        pubkey_bytes[16..24].* = @bitCast(rng.int());
        pubkey_bytes[24..32].* = @bitCast(rng.int());

        const key: Pubkey = .{ .data = pubkey_bytes };
        const stake = rng.int() / 1000;
        try staked_nodes.put(allocator, key, stake);
    }

    const leader_schedule = try LeaderSchedule.fromStakedNodes(
        allocator,
        123,
        321,
        &staked_nodes,
    );
    defer allocator.free(leader_schedule);
    for (leader_schedule, 0..) |slot_leader, i| {
        try std.testing.expectEqual(
            slot_leader,
            try Pubkey.parseRuntime(generated_leader_schedule[i]),
        );
    }
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
