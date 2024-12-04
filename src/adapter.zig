//! Glue code for hooking up application components from distant areas of the code.

const std = @import("std");
const sig = @import("sig.zig");

const leader_schedule = sig.core.leader_schedule;

const Allocator = std.mem.Allocator;

pub const RpcSlotLeaders = struct {
    allocator: std.mem.Allocator,
    logger: sig.trace.ScopedLogger(@typeName(Self)),
    rpc_client: sig.rpc.Client,
    cache: leader_schedule.LeaderScheduleCache,

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
        return leader_schedule.SlotLeaders.init(self, slotLeader);
    }

    fn slotLeader(self: *Self, slot: sig.core.Slot) ?sig.core.Pubkey {
        return self.slotLeaderFallible(slot) catch |e| {
            self.logger.err().logf("error getting leader for slot {} - {}", .{ slot, e });
            return null;
        };
    }

    fn slotLeaderFallible(self: *Self, slot: sig.core.Slot) !?sig.core.Pubkey {
        if (self.cache.slotLeader(slot)) |leader| {
            return leader;
        }

        const response = try self.rpc_client.getLeaderSchedule(self.allocator, slot, .{});
        defer response.deinit();
        const rpc_schedule = try response.result();
        const schedule = try leader_schedule.LeaderSchedule.fromMap(self.allocator, rpc_schedule);

        const epoch, const slot_index = self.cache.epoch_schedule.getEpochAndSlotIndex(slot);
        const leader = schedule.slot_leaders[slot_index];
        try self.cache.put(epoch, schedule);

        return leader;
    }
};

pub const RpcStakedNodes = struct {
    allocator: std.mem.Allocator,
    rpc_client: sig.rpc.Client,
    cache: Cache,

    const Self = @This();
    const StakedNodes = sig.shred_network.shred_retransmitter.StakedNodes;
    const NodeToStakeMap = StakedNodes.NodeToStakeMap;
    const Cache = sig.utils.lru.LruCacheCustom(
        .locking,
        sig.core.Epoch,
        *NodeToStakeMap,
        Allocator,
        destroyCacheItem,
    );

    pub fn init(allocator: Allocator, rpc_client: sig.rpc.Client) !Self {
        return .{
            .allocator = allocator,
            .rpc_client = rpc_client,
            .cache = try Cache.initWithContext(allocator, 8, allocator),
        };
    }

    pub fn stakedNodes(self: *Self) StakedNodes {
        return StakedNodes.init(self, get);
    }

    fn destroyCacheItem(element: *NodeToStakeMap, allocator: std.mem.Allocator) void {
        element.deinit(allocator);
        allocator.destroy(element);
    }

    fn get(self: *Self, epoch: sig.core.Epoch) anyerror!*const NodeToStakeMap {
        if (self.cache.get(epoch)) |staked_nodes| {
            return staked_nodes;
        }

        const response = try self.rpc_client.getVoteAccounts(self.allocator, .{});
        defer response.deinit();
        const response_inner = try response.result();
        const all_vote_accounts = .{ response_inner.current, response_inner.delinquent };

        var staked_nodes = std.AutoArrayHashMap(sig.core.Pubkey, u64).init(self.allocator);
        errdefer staked_nodes.deinit();
        inline for (all_vote_accounts) |vote_accounts| for (vote_accounts) |vote_account| {
            const node_entry = try staked_nodes
                .getOrPut(vote_account.nodePubkey);
            if (!node_entry.found_existing) {
                node_entry.value_ptr.* = 0;
            }
            node_entry.value_ptr.* += vote_account.activatedStake;
        };

        const staked_nodes_ptr = try self.allocator.create(NodeToStakeMap);
        errdefer self.allocator.destroy(staked_nodes_ptr);
        staked_nodes_ptr.* = staked_nodes.unmanaged;
        if (self.cache.put(epoch, staked_nodes_ptr)) |old| {
            destroyCacheItem(old, self.allocator);
        }

        return staked_nodes_ptr;
    }
};

pub const BankFieldsStakedNodes = struct {
    allocator: std.mem.Allocator,
    bank_fields: *const sig.accounts_db.snapshots.BankFields,

    const Self = @This();
    const StakedNodes = sig.shred_network.shred_retransmitter.StakedNodes;

    pub fn stakedNodes(self: *Self) StakedNodes {
        return StakedNodes.init(self, get);
    }

    fn get(self: *Self, epoch: sig.core.Epoch) anyerror!*const StakedNodes.NodeToStakeMap {
        return try self.bank_fields.getStakedNodes(self.allocator, epoch);
    }
};
