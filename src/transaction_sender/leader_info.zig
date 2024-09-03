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
const RpcEpochInfo = sig.rpc.types.EpochInfo;
const LeaderSchedule = sig.core.leader_schedule.SingleEpochLeaderSchedule;
const Logger = sig.trace.log.Logger;
const Config = sig.transaction_sender.Config;

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
            .{ .max_retries = config.rpc_retries, .logger = logger },
        );

        const epoch_info_response = try rpc_client.getEpochInfo(allocator, .{ .commitment = .processed });
        defer epoch_info_response.deinit(); // Deinit safe because EpochInfo contians only u64's.
        const epoch_info = try epoch_info_response.result();

        return .{
            .rpc_client = rpc_client,
            .config = config,
            .epoch_info = epoch_info,
            .leader_schedule = try getLeaderSchedule(allocator, &epoch_info, &rpc_client),
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

        // TODO: Scrutinize edge cases here.
        if (current_slot > self.epoch_info.slotsInEpoch + self.leader_schedule.start_slot) {
            const epoch_info_response = try self.rpc_client.getEpochInfo(allocator, .{ .commitment = .processed });
            defer epoch_info_response.deinit();
            self.epoch_info = try epoch_info_response.result();
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

        if (leader_addresses.items.len <= @divFloor(self.config.max_leaders_to_send_to, 2)) {
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
    const rpc_leader_schedule_response = try rpc_client.getLeaderSchedule(allocator, null, .{});
    defer rpc_leader_schedule_response.deinit();
    const rpc_leader_schedule = try rpc_leader_schedule_response.result();

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
