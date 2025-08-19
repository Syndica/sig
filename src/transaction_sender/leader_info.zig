const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const SocketAddr = sig.net.SocketAddr;
const GossipTable = sig.gossip.GossipTable;
const RpcClient = sig.rpc.Client;
const LeaderScheduleCache = sig.core.leader_schedule.LeaderScheduleCache;
const EpochSchedule = sig.core.epoch_schedule.EpochSchedule;
const Config = sig.transaction_sender.service.Config;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;

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
    leader_addresses_cache: std.AutoArrayHashMapUnmanaged(Pubkey, SocketAddr),
    gossip_table_rw: *RwMux(GossipTable),

    const Self = @This();
    const Logger = sig.trace.Logger(@typeName(Self));

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
            .logger = logger.withScope(@typeName(Self)),
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

        const epoch, const slot_index =
            self.leader_schedule_cache.epoch_schedule.getEpochAndSlotIndex(slot);

        const leader_schedule = self.getLeaderSchedule(slot) catch |e| {
            self.logger.err().logf(
                "Error getting leader schedule via rpc for slot {}: {}",
                .{ slot, e },
            );
            return e;
        };

        try self.leader_schedule_cache.put(epoch, leader_schedule);

        return leader_schedule.slot_leaders[slot_index];
    }

    fn getLeaderSchedule(self: *LeaderInfo, slot: Slot) !LeaderSchedule {
        const rpc_leader_schedule_response = try self.rpc_client
            .getLeaderSchedule(.{ .slot = slot });
        defer rpc_leader_schedule_response.deinit();
        const rpc_leader_schedule = try rpc_leader_schedule_response.result();
        return try LeaderSchedule.fromMap(self.allocator, rpc_leader_schedule.value);
    }
};
