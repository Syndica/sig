const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const ChaChaRng = sig.rand.ChaChaRng;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const WeightedRandomSampler = sig.rand.WeightedRandomSampler;
const EpochSchedule = sig.core.EpochSchedule;
const RwMux = sig.sync.RwMux;

pub const NUM_CONSECUTIVE_LEADER_SLOTS: u64 = 4;
pub const MAX_CACHED_LEADER_SCHEDULES: usize = 10;

/// interface to express a dependency on slot leaders
pub const SlotLeaders = struct {
    state: *anyopaque,
    getFn: *const fn (*anyopaque, Slot) ?Pubkey,

    pub fn init(
        state: anytype,
        getSlotLeader: fn (@TypeOf(state), Slot) ?Pubkey,
    ) SlotLeaders {
        return .{
            .state = state,
            .getFn = struct {
                fn genericFn(generic_state: *anyopaque, slot: Slot) ?Pubkey {
                    return getSlotLeader(@alignCast(@ptrCast(generic_state)), slot);
                }
            }.genericFn,
        };
    }

    pub fn get(self: SlotLeaders, slot: Slot) ?Pubkey {
        return self.getFn(self.state, slot);
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

    const Self = @This();

    pub fn init(allocator: Allocator, epoch_schedule: EpochSchedule) Self {
        return .{
            .epoch_schedule = epoch_schedule,
            .leader_schedules = RwMux(std.AutoArrayHashMap(Epoch, LeaderSchedule)).init(
                std.AutoArrayHashMap(Epoch, LeaderSchedule).init(allocator),
            ),
        };
    }

    pub fn slotLeaders(self: *Self) SlotLeaders {
        return SlotLeaders.init(self, LeaderScheduleCache.slotLeader);
    }

    pub fn put(self: *Self, epoch: Epoch, leader_schedule: LeaderSchedule) !void {
        const leader_schedules, var leader_schedules_lg = self.leader_schedules.writeWithLock();
        defer leader_schedules_lg.unlock();

        if (leader_schedules.count() >= MAX_CACHED_LEADER_SCHEDULES) {
            _ = leader_schedules.swapRemove(std.mem.min(Epoch, leader_schedules.keys()));
        }

        try leader_schedules.put(epoch, leader_schedule);
    }

    pub fn slotLeader(self: *Self, slot: Slot) ?Pubkey {
        const epoch, const slot_index = self.epoch_schedule.getEpochAndSlotIndex(slot);
        const leader_schedules, var leader_schedules_lg = self.leader_schedules.readWithLock();
        defer leader_schedules_lg.unlock();
        return if (leader_schedules.get(epoch)) |schedule| schedule.slot_leaders[slot_index] else null;
    }

    pub fn uniqueLeaders(self: *Self, allocator: std.mem.Allocator) ![]const Pubkey {
        const leader_schedules, var leader_schedules_lg = self.leader_schedules.readWithLock();
        defer leader_schedules_lg.unlock();

        var unique_leaders = sig.utils.collections.PubkeyMapManaged(void).init(allocator);
        defer unique_leaders.deinit();
        for (leader_schedules.values()) |leader_schedule| {
            for (leader_schedule.slot_leaders) |leader| {
                try unique_leaders.put(leader, {});
            }
        }

        const unqiue_list = try allocator.alloc(Pubkey, unique_leaders.count());
        @memcpy(unqiue_list, unique_leaders.keys());

        return unqiue_list;
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

    pub fn deinit(self: LeaderSchedule) void {
        self.allocator.free(self.slot_leaders);
    }

    pub fn fromMap(
        allocator: Allocator,
        leader_to_slots: sig.utils.collections.PubkeyMap([]const u64),
    ) !LeaderSchedule {
        var num_leaders: u64 = 0;
        for (leader_to_slots.values()) |leader_slots| {
            num_leaders += leader_slots.len;
        }

        const Record = struct { slot: Slot, key: Pubkey };

        var leaders_index: usize = 0;
        var leaders = try allocator.alloc(Record, num_leaders);
        defer allocator.free(leaders);

        var rpc_leader_iter = leader_to_slots.iterator();
        while (rpc_leader_iter.next()) |entry| {
            for (entry.value_ptr.*) |slot| {
                leaders[leaders_index] = .{ .slot = slot, .key = entry.key_ptr.* };
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

    pub fn fromVoteAccounts(
        allocator: std.mem.Allocator,
        epoch: Epoch,
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
        staked_nodes: *const sig.utils.collections.PubkeyMap(u64),
    ) ![]Pubkey {
        const Entry = sig.utils.collections.PubkeyMapManaged(u64).Entry;

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
    /// `sig leader-schedule` commands. Return the start slot and the leader schedule.
    pub fn read(
        allocator: std.mem.Allocator,
        reader: anytype,
    ) !struct { Slot, LeaderSchedule } {
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
            start_slot,
            .{
                .allocator = allocator,
                .slot_leaders = try slot_leaders.toOwnedSlice(),
            },
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
