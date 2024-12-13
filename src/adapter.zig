//! Links dependencies with dependents. Connects components from distant regions of the code.

const std = @import("std");
const sig = @import("sig.zig");

const leader_schedule = sig.core.leader_schedule;

const Allocator = std.mem.Allocator;

pub const RpcSlotLeaders = struct {
    allocator: std.mem.Allocator,
    logger: sig.trace.ScopedLogger(@typeName(Self)),
    rpc_client: sig.rpc.Client,
    cache: leader_schedule.LeaderScheduleCache,
    item: ?leader_schedule.LeaderSchedule = null,
    mutex: std.Thread.Mutex = .{},

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: sig.trace.Logger,
        epoch_schedule: sig.core.EpochSchedule,
        rpc_client: sig.rpc.Client,
    ) Self {
        return .{
            .allocator = allocator,
            .logger = logger.withScope(@typeName(Self)),
            .rpc_client = rpc_client,
            .cache = leader_schedule.LeaderScheduleCache.init(allocator, epoch_schedule),
        };
    }

    pub fn slotLeaders(self: *Self) leader_schedule.SlotLeaders {
        return leader_schedule.SlotLeaders.init(self, get);
    }

    fn get(self: *Self, slot: sig.core.Slot) ?sig.core.Pubkey {
        return self.getFallible(slot) catch |e| {
            self.logger.err().logf("error getting leader for slot {} - {}", .{ slot, e });
            return null;
        };
    }

    fn getFallible(self: *Self, slot: sig.core.Slot) !?sig.core.Pubkey {
        self.mutex.lock();
        defer self.mutex.unlock();
        // if (self.cache.slotLeader(slot)) |leader| {
        //     return leader;
        // }

        if (self.item) |item| {
            const epoch, const slot_index = self.cache.epoch_schedule.getEpochAndSlotIndex(slot);
            _ = epoch; // autofix
            // if (true) return sig.core.Pubkey.ZEROES;
            return item.slot_leaders[slot_index];
        }

        const response = try self.rpc_client.getLeaderSchedule(self.allocator, slot, .{});
        defer response.deinit();
        const rpc_schedule = try response.result();
        const schedule = try leader_schedule.LeaderSchedule.fromMap(self.allocator, rpc_schedule);
        const epoch, const slot_index = self.cache.epoch_schedule.getEpochAndSlotIndex(slot);
        _ = epoch; // autofix
        const leader = schedule.slot_leaders[slot_index];

        self.item = schedule;

        if (true) return sig.core.Pubkey.ZEROES;
        return leader;

        // try self.cache.put(epoch, schedule);
    }
};

pub const RpcStakedNodes = struct {
    allocator: std.mem.Allocator,
    rpc_client: sig.rpc.Client,
    cache: Cache,

    const Self = @This();
    const StakedNodes = sig.shred_network.shred_retransmitter.StakedNodes;
    const NodeToStakeMap = StakedNodes.NodeToStakeMap;
    const Cache = sig.utils.lru.SharedPointerLru(
        sig.core.Epoch,
        NodeToStakeMap,
        Allocator,
        NodeToStakeMap.deinit,
    );

    pub fn init(allocator: Allocator, rpc_client: sig.rpc.Client) !Self {
        return .{
            .allocator = allocator,
            .rpc_client = rpc_client,
            .cache = try Cache.init(allocator, 8, allocator),
        };
    }

    pub fn stakedNodes(self: *Self) StakedNodes {
        return StakedNodes.init(self, get, release);
    }

    fn get(self: *Self, epoch: sig.core.Epoch) anyerror!*const NodeToStakeMap {
        _ = epoch; // autofix
        // if (self.cache.get(epoch)) |staked_nodes| {
        //     return staked_nodes;
        // }

        const response = try self.rpc_client.getVoteAccounts(self.allocator, .{});
        defer response.deinit();
        const response_inner = try response.result();
        const all_vote_accounts = .{ response_inner.current, response_inner.delinquent };

        var staked_nodes = std.AutoArrayHashMap(sig.core.Pubkey, u64).init(self.allocator);
        errdefer staked_nodes.deinit();
        inline for (all_vote_accounts) |vote_accounts| for (vote_accounts) |vote_account| {
            const node_entry = try staked_nodes.getOrPut(vote_account.nodePubkey);
            if (!node_entry.found_existing) {
                node_entry.value_ptr.* = 0;
            }
            node_entry.value_ptr.* += vote_account.activatedStake;
        };

        // return try self.cache.putGet(epoch, staked_nodes.unmanaged);
        const item = try self.allocator.create(NodeToStakeMap);
        item.* = staked_nodes.unmanaged;
        return item;
    }

    fn release(self: *Self, ptr: *const NodeToStakeMap) void {
        self.cache.release(ptr);
    }
};

pub const BankFieldsStakedNodes = struct {
    allocator: std.mem.Allocator,
    bank_fields: *const sig.accounts_db.snapshots.BankFields,

    const Self = @This();
    const StakedNodes = sig.shred_network.shred_retransmitter.StakedNodes;

    pub fn stakedNodes(self: *Self) StakedNodes {
        return StakedNodes.init(self, get, release);
    }

    fn get(self: *Self, epoch: sig.core.Epoch) anyerror!*const StakedNodes.NodeToStakeMap {
        return try self.bank_fields.getStakedNodes(self.allocator, epoch);
    }

    fn release(_: *Self, _: *const StakedNodes.NodeToStakeMap) void {}
};
