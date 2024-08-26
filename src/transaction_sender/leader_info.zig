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
const RpcEpochInfo = sig.rpc.Client.EpochInfo;
const RpcLeaderSchedule = sig.rpc.Client.LeaderSchedule;
const RpcLatestBlockhash = sig.rpc.Client.LatestBlockhash;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;
const Logger = sig.trace.log.Logger;
const Config = sig.transaction_sender.Config;
const TransactionInfo = sig.transaction_sender.TransactionInfo;
const ClusterType = sig.accounts_db.genesis_config.ClusterType;

/// LeaderInfo contains information about the cluster that is used to send transactions.
/// It uses the RpcClient to get the epoch info and leader schedule.
/// It also uses the GossipTable to get the leader addresses.
/// TODO:
/// - Update leader schedule on Epoch boundary
pub const LeaderInfo = struct {
    epoch_info: RpcEpochInfo,
    leader_schedule: LeaderSchedule,
    leader_addresses_cache: AutoArrayHashMap(Pubkey, SocketAddr),
    gossip_table_rw: *RwMux(GossipTable),

    pub fn init(
        allocator: Allocator,
        cluster: ClusterType,
        gossip_table_rw: *RwMux(GossipTable),
    ) !LeaderInfo {
        var rpc_client = RpcClient.init(allocator, cluster);
        var rpc_arena = std.heap.ArenaAllocator.init(allocator);
        defer rpc_arena.deinit();

        const epoch_info = try rpc_client.getEpochInfo(&rpc_arena, null, .{ .commitment = .processed });
        const leader_schedule = try getLeaderSchedule(allocator, &epoch_info, &rpc_client);

        return .{
            .epoch_info = epoch_info,
            .leader_schedule = leader_schedule,
            .leader_addresses_cache = std.AutoArrayHashMap(Pubkey, SocketAddr).init(allocator),
            .gossip_table_rw = gossip_table_rw,
        };
    }

    pub fn getLeaderAddresses(self: *LeaderInfo, allocator: Allocator, config: Config) !?std.ArrayList(SocketAddr) {
        var rpc_arena = std.heap.ArenaAllocator.init(allocator);
        defer rpc_arena.deinit();

        var rpc_client = RpcClient.init(allocator, config.cluster);
        defer rpc_client.deinit();

        const current_slot = try rpc_client.getSlot(&rpc_arena, .{
            .commitment = .processed,
        });

        // TODO: Improve transition to new epoch
        if (current_slot > self.epoch_info.slotsInEpoch + self.leader_schedule.start_slot) {
            self.epoch_info = try rpc_client.getEpochInfo(&rpc_arena, null, .{ .commitment = .processed });
            self.leader_schedule = try getLeaderSchedule(allocator, &self.epoch_info, &rpc_client);
            try self.updateLeaderAddressesCache();
        }

        var leader_addresses = std.ArrayList(SocketAddr).init(allocator);
        for (0..config.max_leaders_to_send_to) |i| {
            const slot = current_slot + i * config.number_of_consecutive_leader_slots;
            const leader = self.leader_schedule.getLeader(slot) orelse {
                std.debug.print("Leader {d} not found for slot {d}\n", .{ i, slot });
                continue;
            };
            const socket = self.leader_addresses_cache.get(leader) orelse {
                std.debug.print(
                    "Leader {s} not found in cache, current cache size {d}\n",
                    .{ try leader.toString(), self.leader_addresses_cache.count() },
                );
                continue;
            };
            try leader_addresses.append(socket);
        }

        if (leader_addresses.items.len != config.max_leaders_to_send_to) {
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
    var rpc_arena = std.heap.ArenaAllocator.init(allocator);
    defer rpc_arena.deinit();

    const rpc_leader_schedule = try rpc_client.getLeaderSchedule(&rpc_arena, null, .{});
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
