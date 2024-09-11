const std = @import("std");
const network = @import("zig-network");
const base58 = @import("base58-zig");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AutoArrayHashMap = std.AutoArrayHashMap;
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
const Logger = sig.trace.log.Logger;
const Config = sig.transaction_sender.service.Config;

/// LeaderInfo contains information about the cluster that is used to send transactions.
/// It uses the RpcClient to get the epoch info and leader schedule.
/// It also uses the GossipTable to get the leader addresses.
/// TODO:
/// - This struct is relatively inefficient because it makes a lot of RPC calls.
/// - It could be moved into its own thread to make improve speed of getting leader addresses.
/// - It's probably not a big deal for now though, because ultimately this implementation will be replaced.
pub const LeaderInfo = struct {
    config: Config,
    rpc_client: RpcClient,
    leader_schedule_cache: LeaderScheduleCache,
    leader_addresses_cache: AutoArrayHashMap(Pubkey, SocketAddr),
    gossip_table_rw: *RwMux(GossipTable),

    pub fn init(
        allocator: Allocator,
        config: Config,
        gossip_table_rw: *RwMux(GossipTable),
        logger: Logger,
    ) !LeaderInfo {
        return .{
            .config = config,
            .rpc_client = RpcClient.init(
                allocator,
                config.cluster,
                .{ .max_retries = config.rpc_retries, .logger = logger },
            ),
            .leader_schedule_cache = LeaderScheduleCache.init(allocator, try EpochSchedule.default()),
            .leader_addresses_cache = std.AutoArrayHashMap(Pubkey, SocketAddr).init(allocator),
            .gossip_table_rw = gossip_table_rw,
        };
    }

    pub fn getLeaderAddresses(self: *LeaderInfo, allocator: Allocator) !std.ArrayList(SocketAddr) {
        const current_slot_response = try self.rpc_client.getSlot(allocator, .{
            .commitment = .processed,
        });
        defer current_slot_response.deinit();
        const current_slot = try current_slot_response.result();

        var leader_addresses = std.ArrayList(SocketAddr).init(allocator);
        for (0..self.config.max_leaders_to_send_to) |i| {
            const slot = current_slot + i * self.config.number_of_consecutive_leader_slots;
            const leader = try self.leader_schedule_cache.getSlotLeaderMaybeComputeRpc(slot, &self.rpc_client);
            const socket = self.leader_addresses_cache.get(leader) orelse continue;
            try leader_addresses.append(socket);
        }

        if (leader_addresses.items.len <= @divFloor(self.config.max_leaders_to_send_to, 2)) {
            const gossip_table: *const GossipTable, var gossip_table_lg = self.gossip_table_rw.readWithLock();
            defer gossip_table_lg.unlock();

            var unique_leaders = try self.leader_schedule_cache.getUniqueLeaders();
            defer unique_leaders.deinit();

            for (unique_leaders.keys()) |leader| {
                const contact_info = gossip_table.getThreadSafeContactInfo(leader);
                if (contact_info == null or contact_info.?.tpu_addr == null) continue;
                try self.leader_addresses_cache.put(leader, contact_info.?.tpu_addr.?);
            }
        }

        return leader_addresses;
    }
};
