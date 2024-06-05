const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;

const Bank = sig.accounts_db.Bank;
const ChaChaRng = sig.rand.ChaChaRng;
const Epoch = sig.core.Epoch;
const EpochStakes = sig.accounts_db.EpochStakes;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const WeightedRandomSampler = sig.rand.WeightedRandomSampler;

pub const NUM_CONSECUTIVE_LEADER_SLOTS: u64 = 4;

pub const SlotLeaderProvider = sig.utils.closure.PointerClosure(Slot, ?Pubkey);

/// Only works for a single epoch. This is a basic limited approach that should
/// only be used as a placeholder until a better approach is fleshed out.
pub const SingleEpochLeaderSchedule = struct {
    leader_schedule: []const sig.core.Pubkey,
    start_slot: sig.core.Slot,

    const Self = @This();

    pub fn getLeader(self: *const Self, slot: sig.core.Slot) ?sig.core.Pubkey {
        const index: usize = @intCast(slot - self.start_slot);
        return if (index >= self.leader_schedule.len) null else self.leader_schedule[index];
    }

    pub fn provider(self: *Self) SlotLeaderProvider {
        return SlotLeaderProvider.init(self, Self.getLeader);
    }
};

pub fn leaderScheduleFromBank(allocator: Allocator, bank: *const Bank) ![]Pubkey {
    const epoch = bank.bank_fields.epoch;
    const epoch_stakes = bank.bank_fields.epoch_stakes.getPtr(epoch) orelse return error.NoEpochStakes;
    const slots_in_epoch = bank.bank_fields.epoch_schedule.getSlotsInEpoch(epoch);

    const vote_accounts = epoch_stakes.stakes.vote_accounts.vote_accounts;
    const staked_nodes = try allocator.alloc(StakedNode, vote_accounts.count());
    defer allocator.free(staked_nodes);
    var iter = vote_accounts.iterator();
    var index: usize = 0;
    while (iter.next()) |entry| : (index += 1) {
        staked_nodes[index] = .{
            .id = entry.key_ptr.*,
            .stake = entry.value_ptr.*[0],
        };
    }

    return try leaderSchedule(allocator, staked_nodes, slots_in_epoch, epoch);
}

pub const StakedNode = struct { id: Pubkey, stake: u64 };

pub fn leaderSchedule(
    allocator: Allocator,
    nodes: []StakedNode,
    slots_in_epoch: Slot,
    epoch: Epoch,
) Allocator.Error![]Pubkey {
    std.mem.sortUnstable(StakedNode, nodes, {}, struct {
        fn gt(_: void, lhs: StakedNode, rhs: StakedNode) bool {
            return switch (std.math.order(lhs.stake, rhs.stake)) {
                .gt => true,
                .lt => false,
                .eq => .gt == std.mem.order(u8, &lhs.id.data, &rhs.id.data),
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
    for (nodes, 0..) |entry, i| stakes[i] = entry.stake;
    var sampler = try WeightedRandomSampler(u64).init(allocator, random, stakes);
    defer sampler.deinit();

    // calculate leader schedule
    const slot_leaders = try allocator.alloc(Pubkey, slots_in_epoch);
    var current_node: Pubkey = undefined;
    for (0..slots_in_epoch) |i| {
        if (i % NUM_CONSECUTIVE_LEADER_SLOTS == 0) {
            current_node = nodes[sampler.sample()].id;
        }
        slot_leaders[i] = current_node;
    }

    return slot_leaders;
}

test "leaderSchedule calculation matches agave" {
    var rng = ChaChaRng(20).fromSeed(.{0} ** 32);
    const random = rng.random();
    var pubkey_bytes: [32]u8 = undefined;
    var staked_nodes: [100]StakedNode = undefined;
    for (0..100) |i| {
        random.bytes(&pubkey_bytes);
        const key = Pubkey{ .data = pubkey_bytes };
        const stake = random.int(u64) / 1000;
        staked_nodes[i] = .{ .id = key, .stake = stake };
    }
    const slot_leaders = try leaderSchedule(std.testing.allocator, &staked_nodes, 321, 123);
    defer std.testing.allocator.free(slot_leaders);
    for (slot_leaders, 0..) |slot_leader, i| {
        try std.testing.expect((try Pubkey.fromString(expected[i])).equals(&slot_leader));
    }
}

const expected = [_][]const u8{
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
