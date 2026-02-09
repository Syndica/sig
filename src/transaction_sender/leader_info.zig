const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);

const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const SocketAddr = sig.net.SocketAddr;
const GossipTable = sig.gossip.GossipTable;
const RpcClient = sig.rpc.Client;
const EpochSchedule = sig.core.epoch_schedule.EpochSchedule;
const Config = sig.transaction_sender.service.Config;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;

pub const NUM_CONSECUTIVE_LEADER_SLOTS: u64 = 4;
pub const MAX_CACHED_LEADER_SCHEDULES: usize = 10;

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

    pub fn slotLeaders(self: *LeaderScheduleCache) sig.core.leader_schedule.SlotLeaders {
        return sig.core.leader_schedule.SlotLeaders.init(self, LeaderScheduleCache.slotLeader);
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
        const epoch, _ = self.epoch_schedule.getEpochAndSlotIndex(slot);
        const leader_schedules, var leader_schedules_lg = self.leader_schedules.readWithLock();
        defer leader_schedules_lg.unlock();
        return if (leader_schedules.get(epoch)) |schedule| schedule.getLeaderOrNull(slot) else null;
    }

    pub fn uniqueLeaders(self: *LeaderScheduleCache, allocator: std.mem.Allocator) ![]const Pubkey {
        const leader_schedules, var leader_schedules_lg = self.leader_schedules.readWithLock();
        defer leader_schedules_lg.unlock();

        var unique_leaders = sig.utils.collections.PubkeyMapManaged(void).init(allocator);
        defer unique_leaders.deinit();
        for (leader_schedules.values()) |leader_schedule| {
            for (leader_schedule.leaders) |leader| {
                try unique_leaders.put(leader, {});
            }
        }

        const unqiue_list = try allocator.alloc(Pubkey, unique_leaders.count());
        @memcpy(unqiue_list, unique_leaders.keys());

        return unqiue_list;
    }
};

/// LeaderInfo contains information about the cluster that is used to send transactions.
/// It uses the RpcClient to get the epoch info and leader schedule.
/// It also uses the GossipTable to get the leader addresses.
/// TODO:
/// - This struct is relatively inefficient because it makes a lot of RPC calls.
/// - It could be moved into its own thread to make improve speed of getting leader addresses.
/// - It's probably not a big deal for now though, because ultimately this implementation will be replaced.
pub const LeaderInfo = struct {
    allocator: Allocator,
    config: Config,
    logger: Logger,
    rpc_client: RpcClient,
    leader_schedule_cache: LeaderScheduleCache,
    leader_addresses_cache: sig.utils.collections.PubkeyMap(SocketAddr),
    gossip_table_rw: *RwMux(GossipTable),

    const Logger = sig.trace.Logger(@typeName(LeaderInfo));

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        config: Config,
        gossip_table_rw: *RwMux(GossipTable),
        epoch_schedule: EpochSchedule,
    ) !LeaderInfo {
        return .{
            .allocator = allocator,
            .config = config,
            .logger = logger.withScope(@typeName(LeaderInfo)),
            .rpc_client = try RpcClient.init(
                allocator,
                config.cluster,
                .{ .max_retries = config.rpc_retries, .logger = .from(logger) },
            ),
            .leader_schedule_cache = LeaderScheduleCache.init(allocator, epoch_schedule),
            .leader_addresses_cache = .{},
            .gossip_table_rw = gossip_table_rw,
        };
    }

    pub fn getLeaderAddresses(self: *LeaderInfo, allocator: Allocator) ![]const SocketAddr {
        const current_slot_response = try self.rpc_client
            .getSlot(.{ .config = .{ .commitment = .processed } });
        defer current_slot_response.deinit();
        const current_slot = try current_slot_response.result();

        var leader_addresses = std.ArrayList(SocketAddr).init(allocator);
        for (0..self.config.max_leaders_to_send_to) |position| {
            const slot = current_slot + position * self.config.number_of_consecutive_leader_slots;
            const leader = try self.getSlotLeader(slot) orelse continue;
            const socket = self.leader_addresses_cache.get(leader) orelse continue;
            try leader_addresses.append(socket);
        }

        self.logger.info().logf("identified {}/{} leaders", .{
            leader_addresses.items.len,
            self.config.max_leaders_to_send_to,
        });

        if (leader_addresses.items.len <= @divFloor(self.config.max_leaders_to_send_to, 2)) {
            const gossip_table: *const GossipTable, var gossip_table_lg =
                self.gossip_table_rw.readWithLock();
            defer gossip_table_lg.unlock();

            const unique_leaders = try self.leader_schedule_cache.uniqueLeaders(self.allocator);
            defer self.allocator.free(unique_leaders);

            for (unique_leaders) |leader| {
                const contact_info = gossip_table.getThreadSafeContactInfo(leader);
                if (contact_info == null or contact_info.?.tpu_quic_addr == null) continue;
                try self.leader_addresses_cache.put(
                    self.allocator,
                    leader,
                    contact_info.?.tpu_quic_addr.?,
                );
            }
        }

        return leader_addresses.toOwnedSlice();
    }

    fn updateLeaderAddressesCache(self: *LeaderInfo) !void {
        const gossip_table: *const GossipTable, var gossip_table_lg =
            self.gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        const unique_leaders = try self.leader_schedule_cache.uniqueLeaders(self.allocator);
        defer self.allocator.free(unique_leaders);

        for (unique_leaders) |leader| {
            const contact_info = gossip_table.getThreadSafeContactInfo(leader);
            if (contact_info == null or
                contact_info.?.tpu_quic_addr == null) continue;
            try self.leader_addresses_cache.put(
                self.allocator,
                leader,
                contact_info.?.tpu_quic_addr.?,
            );
        }
    }

    fn getSlotLeader(self: *LeaderInfo, slot: Slot) !?Pubkey {
        if (self.leader_schedule_cache.slotLeader(slot)) |leader| return leader;

        const epoch, _ =
            self.leader_schedule_cache.epoch_schedule.getEpochAndSlotIndex(slot);

        const leader_schedule = self.getLeaderSchedule(slot) catch |e| {
            self.logger.err().logf(
                "Error getting leader schedule via rpc for slot {}: {}",
                .{ slot, e },
            );
            return e;
        };

        try self.leader_schedule_cache.put(epoch, leader_schedule);

        return leader_schedule.getLeaderOrNull(slot);
    }

    fn getLeaderSchedule(self: *LeaderInfo, slot: Slot) !LeaderSchedule {
        const rpc_leader_schedule_response = try self.rpc_client
            .getLeaderSchedule(.{ .slot = slot });
        defer rpc_leader_schedule_response.deinit();
        const rpc_leader_schedule = try rpc_leader_schedule_response.result();
        return try sig.core.leader_schedule.computeFromMap(
            self.allocator,
            &rpc_leader_schedule.value,
        );
    }
};
