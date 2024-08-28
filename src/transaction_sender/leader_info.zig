const std = @import("std");
const network = @import("zig-network");
const base58 = @import("base58-zig");
const sig = @import("../sig.zig");

const socket_utils = sig.net.socket_utils;

const Allocator = std.mem.Allocator;
const AutoArrayHashMap = std.AutoArrayHashMap;
const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);
const Thread = std.Thread;
const UdpSocket = network.Socket;

const Packet = sig.net.Packet;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const RwMux = sig.sync.RwMux;
const Signature = sig.core.Signature;
const Channel = sig.sync.Channel;
const SocketAddr = sig.net.SocketAddr;
const Duration = sig.time.Duration;
const Instant = sig.time.Instant;
const ContactInfo = sig.gossip.ContactInfo;
const GossipTable = sig.gossip.GossipTable;
const RpcClient = sig.rpc.Client;
const RpcEpochInfo = sig.rpc.types.EpochInfo;
const RpcLeaderSchedule = sig.rpc.types.LeaderSchedule;
const RpcLatestBlockhash = sig.rpc.types.LatestBlockhash;
const LeaderSchedule = sig.core.leader_schedule.SingleEpochLeaderSchedule;
const Logger = sig.trace.log.Logger;
const ClusterType = sig.accounts_db.genesis_config.ClusterType;
const Config = sig.transaction_sender.Config;
const TransactionInfo = sig.transaction_sender.TransactionInfo;

/// LeaderInfo contains information about the cluster that is used to send transactions.
/// It uses the RpcClient to get the epoch info and leader schedule.
/// It also uses the GossipTable to get the leader addresses.
/// TODO:
/// - Update leader schedule on Epoch boundary
/// - Move RPC client to be part of the LeaderInfo
pub const LeaderInfo = struct {
    config: Config,
    rpc_client: RpcClient,
    epoch_info: RpcEpochInfo,
    leader_schedule: LeaderSchedule,
    leader_addresses_cache: AutoArrayHashMap(Pubkey, SocketAddr),
    gossip_table_rw: *RwMux(GossipTable),

    pub fn init(
        allocator: Allocator,
        config: Config,
        gossip_table_rw: *RwMux(GossipTable),
        logger: Logger,
    ) !LeaderInfo {
        var rpc_client = RpcClient.init(
            allocator,
            config.cluster,
            .{ .retries = config.rpc_retries, .logger = logger },
        );

        const epoch_info_result = try rpc_client.getEpochInfo(allocator, null, .{ .commitment = .processed });
        defer epoch_info_result.deinit();
        const epoch_info = epoch_info_result.value;

        return .{
            .rpc_client = rpc_client,
            .config = config,
            .epoch_info = epoch_info,
            .leader_schedule = try getLeaderSchedule(allocator, &epoch_info, &rpc_client),
            .leader_addresses_cache = std.AutoArrayHashMap(Pubkey, SocketAddr).init(allocator),
            .gossip_table_rw = gossip_table_rw,
        };
    }

    pub fn getLeaderAddresses(self: *LeaderInfo, allocator: Allocator) !?std.ArrayList(SocketAddr) {
        const current_slot_result = try self.rpc_client.getSlot(allocator, .{
            .commitment = .processed,
        });
        defer current_slot_result.deinit();
        const current_slot = current_slot_result.value;

        // TODO: Improve transition to new epoch
        if (current_slot > self.epoch_info.slotsInEpoch + self.leader_schedule.start_slot) {
            const epoch_info_result = try self.rpc_client.getEpochInfo(allocator, null, .{ .commitment = .processed });
            defer epoch_info_result.deinit();
            self.epoch_info = epoch_info_result.value;
            self.leader_schedule = try getLeaderSchedule(allocator, &self.epoch_info, &self.rpc_client);
            try self.updateLeaderAddressesCache();
        }

        var leader_addresses = std.ArrayList(SocketAddr).init(allocator);
        for (0..self.config.max_leaders_to_send_to) |i| {
            const slot = current_slot + i * self.config.number_of_consecutive_leader_slots;
            const leader = self.leader_schedule.getLeader(slot) orelse continue;
            const socket = self.leader_addresses_cache.get(leader) orelse continue;
            try leader_addresses.append(socket);
        }

        if (leader_addresses.items.len != self.config.max_leaders_to_send_to) {
            try self.updateLeaderAddressesCache();
        }

        return leader_addresses;
    }

    fn updateLeaderAddressesCache(self: *LeaderInfo) !void {
        const gossip_table: *const GossipTable, var gossip_table_lock = self.gossip_table_rw.readWithLock();
        defer gossip_table_lock.unlock();

        for (self.leader_schedule.slot_leaders) |leader| {
            if (self.leader_addresses_cache.contains(leader)) continue;
            const contact_info = gossip_table.getThreadSafeContactInfo(leader);
            if (contact_info == null) continue;
            if (contact_info.?.tpu_addr == null) continue;
            try self.leader_addresses_cache.put(leader, contact_info.?.tpu_addr.?);
        }
    }
};

fn getLeaderSchedule(allocator: Allocator, epoch_info: *const RpcEpochInfo, rpc_client: *RpcClient) !LeaderSchedule {
    const rpc_leader_schedule_result = try rpc_client.getLeaderSchedule(allocator, null, .{});
    defer rpc_leader_schedule_result.deinit();
    const rpc_leader_schedule = rpc_leader_schedule_result.value;

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

    var leader_pubkeys = try allocator.alloc(Pubkey, leaders.len);
    for (leaders, 0..) |record, i| {
        leader_pubkeys[i] = record.key;
    }

    return LeaderSchedule{
        .allocator = allocator,
        .slot_leaders = leader_pubkeys,
        .start_slot = epoch_info.absoluteSlot - epoch_info.slotIndex,
    };
}
