const std = @import("std");
const sig = @import("../sig.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;
const Random = std.Random;

const EpochSchedule = core.epoch_schedule.EpochSchedule;
const Pubkey = core.pubkey.Pubkey;

const Epoch = core.time.Epoch;
const Slot = core.time.Slot;

const FeatureSet = sig.core.features.Set;
const VoteAccounts = sig.core.stakes.VoteAccounts;

const ChaChaRng = sig.rand.ChaChaRng;
const WeightedRandomSampler = sig.rand.WeightedRandomSampler;

pub const NUM_CONSECUTIVE_LEADER_SLOTS: u64 = 4;

pub const LeaderSchedules = struct {
    curr: LeaderSchedule,
    next: ?LeaderSchedule,

    pub fn getLeader(self: *const LeaderSchedules, slot: Slot) !Pubkey {
        return self.curr.getLeader(slot) catch
            if (self.next) |next_schedule|
                next_schedule.getLeader(slot)
            else
                error.SlotOutOfRange;
    }

    pub fn getLeaderOrNull(self: *const LeaderSchedules, slot: Slot) ?Pubkey {
        return self.getLeader(slot) catch null;
    }
};

pub const LeaderSchedule = struct {
    leaders: []const Pubkey,
    start: Slot,
    end: Slot,

    pub fn deinit(self: *const LeaderSchedule, allocator: Allocator) void {
        allocator.free(self.leaders);
    }

    pub fn init(
        allocator: Allocator,
        leader_schedule_epoch: Epoch,
        vote_accounts: VoteAccounts,
        epoch_schedule: *const EpochSchedule,
        feature_set: *const FeatureSet,
    ) !LeaderSchedule {
        const slots_in_epoch = epoch_schedule.getSlotsInEpoch(leader_schedule_epoch);
        const slot_leaders = if (useVoteKeyedLeaderSchedule(
            leader_schedule_epoch,
            epoch_schedule,
            feature_set,
        ))
            try computeFromVoteAccounts(
                allocator,
                leader_schedule_epoch,
                slots_in_epoch,
                &vote_accounts.vote_accounts,
            )
        else
            try computeFromStakedNodes(
                allocator,
                leader_schedule_epoch,
                slots_in_epoch,
                &vote_accounts.staked_nodes,
            );
        return .{
            .leaders = slot_leaders,
            .start = epoch_schedule.getFirstSlotInEpoch(leader_schedule_epoch),
            .end = epoch_schedule.getLastSlotInEpoch(leader_schedule_epoch),
        };
    }

    pub fn initRandom(
        allocator: Allocator,
        random: Random,
        options: struct {
            epoch: ?Epoch = null,
            schedule: EpochSchedule = .INIT,
        },
    ) !LeaderSchedule {
        const epoch = options.epoch orelse random.intRangeAtMost(Epoch, 0, 1_000);

        const start = options.schedule.getFirstSlotInEpoch(epoch);
        const end = options.schedule.getLastSlotInEpoch(epoch);

        const leaders = try allocator.alloc(Pubkey, end - start + 1);
        errdefer allocator.free(leaders);
        for (leaders) |*leader| leader.* = Pubkey.initRandom(random);

        return LeaderSchedule{
            .leaders = leaders,
            .start = start,
            .end = end,
        };
    }

    pub fn getLeader(self: *const LeaderSchedule, slot: Slot) !Pubkey {
        if (self.start <= slot and slot <= self.end)
            return self.leaders[slot - self.start];
        return error.SlotOutOfRange;
    }

    /// Reads the leader schedule as formatted by the `solana leader-schedule` and
    /// `sig leader-schedule` commands. Return the start slot and the leader schedule.
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
            .leaders = slot_leaders.toOwnedSlice(),
            .start = start_slot,
            .end = start_slot +| (slot_leaders.len -| 1),
        };
    }

    /// Writes the leader schedule as formatted by the `solana leader-schedule` and
    /// `sig leader-schedule` commands.
    pub fn write(self: *const LeaderSchedule, writer: anytype) !void {
        for (self.leaders, 0..) |leader, i| {
            try writer.print("  {}       {s}\n", .{ self.start + i, leader });
        }
    }
};

pub fn useVoteKeyedLeaderSchedule(
    epoch: Epoch,
    epoch_schedule: *const EpochSchedule,
    feature_set: *const FeatureSet,
) bool {
    const maybe_activation_slot = feature_set.get(.enable_vote_address_leader_schedule);
    if (maybe_activation_slot) |activated_slot| {
        if (activated_slot == 0) {
            // If the feature is activated at slot 0, always use the new leader schedule
            return true;
        } else {
            // Always use the new leader schedule for epochs after the activated epoch
            const activated_epoch = epoch_schedule.getEpoch(activated_slot);
            return epoch >= activated_epoch;
        }
    } else {
        // TODO: do we need to return null here
        return false;
    }
}

pub fn computeFromVoteAccounts(
    allocator: std.mem.Allocator,
    leader_schedule_epoch: Epoch,
    slots_in_epoch: Slot,
    vote_accounts: *const sig.core.stakes.StakeAndVoteAccountsMap,
) ![]const Pubkey {
    // this implementation is naive and performs unnecessay allocations to construct and
    // input compatable with fromStakedNodes and re-key results.
    // It should be addressed as part of issue #945
    var stakes = sig.utils.collections.PubkeyMap(u64){};
    defer stakes.deinit(allocator);

    for (vote_accounts.keys(), vote_accounts.values()) |key, value| {
        try stakes.put(allocator, key, value.stake);
    }

    const vote_keyed = try computeFromStakedNodes(
        allocator,
        leader_schedule_epoch,
        slots_in_epoch,
        &stakes,
    );

    for (vote_keyed) |*pubkey| {
        const vote_account = vote_accounts.get(pubkey.*) orelse unreachable;
        pubkey.* = vote_account.account.state.node_pubkey;
    }

    return vote_keyed;
}

pub fn computeFromStakedNodes(
    allocator: std.mem.Allocator,
    leader_schedule_epoch: Epoch,
    slots_in_epoch: Slot,
    staked_nodes: *const sig.utils.collections.PubkeyMap(u64),
) ![]Pubkey {
    const Entry = sig.utils.collections.PubkeyMap(u64).Entry;

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
    std.mem.writeInt(Epoch, seed[0..@sizeOf(Epoch)], leader_schedule_epoch, .little);
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
