const std = @import("std");
const net = @import("zig-network");
const sig = @import("../sig.zig");

const socket_utils = sig.net.socket_utils;

const Random = std.rand.Random;
const UdpSocket = net.Socket;
const EndPoint = net.EndPoint;
const AtomicBool = std.atomic.Value(bool);
const AtomicU64 = std.atomic.Value(u64);

const Packet = sig.net.Packet;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const Duration = sig.time.Duration;
const TurbineTree = sig.turbine.TurbineTree;
const TurbineTreeCache = sig.turbine.TurbineTreeCache;
const Channel = sig.sync.Channel;
const ShredId = sig.ledger.shred.ShredId;
const LeaderScheduleCache = sig.core.leader_schedule.LeaderScheduleCache;
const BankFields = sig.accounts_db.snapshots.BankFields;
const RwMux = sig.sync.RwMux;
const Logger = sig.trace.log.Logger;
const ShredDeduper = sig.turbine.shred_deduper.ShredDeduper;

const globalRegistry = sig.prometheus.globalRegistry;

const DEDUPER_MAX_DUPLICATE_COUNT: usize = 2;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_RESET_CYCLE: Duration = Duration.fromSecs(5 * 60);
const DEDUPER_NUM_BITS: u64 = 637_534_199;

const USE_STAKE_HACK_FOR_TESTING = false;

/// Retransmit Service
/// The retransmit service receives verified shreds from the shred collector and retransmits them to the network.
/// The retransmit service is broken down into two main components:
/// 1. receiveShreds: runs on a single thread and receives shreds from the shred collector, deduplicates them, and then packages them
///    into RetransmitShredInfo's which are sent to a channel for further processing.
/// 2. retransmitShreds: runs on N threads and receives RetransmitShredInfo's from the channel, computes the children to retransmit to
///    and then constructs and sends packets to the network.
pub fn run(
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    bank_fields: *const BankFields,
    leader_schedule_cache: *LeaderScheduleCache,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    receiver: *Channel(Packet),
    num_retransmit_sockets: usize,
    maybe_num_retransmit_threads: ?usize,
    exit: *AtomicBool,
    rand: Random,
    logger: Logger,
) !void {
    errdefer {
        logger.info().log("retransmit service failed");
        exit.store(false, .monotonic);
    }

    var stats = try Stats.init();

    var receive_to_retransmit_channel = try Channel(RetransmitShredInfo).init(allocator);
    defer receive_to_retransmit_channel.deinit();

    var retransmit_to_socket_channel = try Channel(Packet).init(allocator);
    defer retransmit_to_socket_channel.deinit();

    var retransmit_shred_threads = std.ArrayList(std.Thread).init(allocator);
    defer retransmit_shred_threads.deinit();
    const num_retransmit_threads = if (maybe_num_retransmit_threads) |num| num else try std.Thread.getCpuCount();

    var retransmit_sockets: std.ArrayList(UdpSocket) = std.ArrayList(UdpSocket).init(allocator);
    defer {
        for (retransmit_sockets.items) |socket| socket.close();
        retransmit_sockets.deinit();
    }

    for (0..num_retransmit_sockets) |_| {
        var socket = try UdpSocket.create(.ipv4, .udp);
        try socket.bind(try EndPoint.parse("0.0.0.0:0"));
        try retransmit_sockets.append(try UdpSocket.create(.ipv4, .udp));
    }

    var send_socket_threads = std.ArrayList(std.Thread).init(allocator);
    defer send_socket_threads.deinit();

    const receive_shred_thread = try std.Thread.spawn(
        .{},
        receiveShreds,
        .{
            allocator,
            my_contact_info,
            bank_fields,
            leader_schedule_cache,
            receiver,
            &receive_to_retransmit_channel,
            gossip_table_rw,
            rand,
            exit,
            logger,
            &stats,
        },
    );

    for (0..num_retransmit_threads) |_| {
        try retransmit_shred_threads.append(try std.Thread.spawn(
            .{},
            retransmitShreds,
            .{
                allocator,
                &receive_to_retransmit_channel,
                &retransmit_to_socket_channel,
                &stats,
                exit,
            },
        ));
    }

    for (retransmit_sockets.items) |socket| {
        try send_socket_threads.append(try std.Thread.spawn(
            .{},
            socket_utils.sendSocket,
            .{
                socket,
                &retransmit_to_socket_channel,
                logger,
                false,
                exit,
                {},
            },
        ));
    }

    receive_shred_thread.join();
    for (retransmit_shred_threads.items) |thread| thread.join();
    for (send_socket_threads.items) |thread| thread.join();
}

/// Receive shreds from the network, deduplicate them, and then package
/// them into RetransmitShredInfo's to be sent to the retransmit shred threads.
fn receiveShreds(
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    bank_fields: *const BankFields,
    leader_schedule_cache: *LeaderScheduleCache,
    receiver: *Channel(Packet),
    sender: *Channel(RetransmitShredInfo),
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    rand: Random,
    exit: *AtomicBool,
    logger: Logger,
    stats: *Stats,
) !void {
    var turbine_tree_cache = TurbineTreeCache.init(allocator);
    defer turbine_tree_cache.deinit();

    var deduper = try ShredDeduper(2).init(
        allocator,
        rand,
        DEDUPER_NUM_BITS,
    );
    defer deduper.deinit();

    while (!exit.load(.acquire)) {
        var receive_shreds_timer = try sig.time.Timer.start();

        const receiver_len = receiver.len();
        if (receiver_len == 0) continue;

        var shreds = try std.ArrayList(Packet).initCapacity(allocator, receiver_len);
        while (receiver.receive()) |packet| try shreds.append(packet);
        defer shreds.deinit();

        const bytes_filter_saturated, const shred_id_filter_saturated = deduper.maybeReset(
            rand,
            DEDUPER_FALSE_POSITIVE_RATE,
            DEDUPER_RESET_CYCLE,
        );
        if (bytes_filter_saturated) stats.retransmit_shred_byte_filter_saturated_count.reset();
        if (shred_id_filter_saturated) stats.retransmit_shred_id_filter_saturated_count.reset();

        var grouped_shreds = try dedupAndGroupShredsBySlot(
            allocator,
            &shreds,
            &deduper,
            stats,
        );
        defer {
            for (grouped_shreds.values()) |arr| arr.deinit();
            grouped_shreds.deinit();
        }

        try createAndSendRetransmitInfo(
            allocator,
            grouped_shreds,
            my_contact_info,
            bank_fields,
            gossip_table_rw,
            leader_schedule_cache,
            &turbine_tree_cache,
            sender,
            stats,
        );

        stats.retransmit_shreds_received_count.add(shreds.items.len);
        stats.retransmit_receive_shreds_micros.set(@divFloor(receive_shreds_timer.read().asMicros(), shreds.items.len));
        stats.log(logger);
    }
}

/// Group shreds by slot and deduplicate them in the process
/// Returns a map of slot to a list of shred_id and packet pairs
inline fn dedupAndGroupShredsBySlot(
    allocator: std.mem.Allocator,
    shreds: *std.ArrayList(Packet),
    deduper: *ShredDeduper(2),
    stats: *Stats,
) !std.AutoArrayHashMap(Slot, std.ArrayList(ShredIdAndPacket)) {
    var group_shreds_timer = try sig.time.Timer.start();
    var grouped_shreds = std.AutoArrayHashMap(Slot, std.ArrayList(ShredIdAndPacket)).init(allocator);
    for (shreds.items) |shred_packet| {
        const shred_id = try sig.ledger.shred.layout.getShredId(&shred_packet);

        switch (deduper.dedup(&shred_id, &shred_packet.data, DEDUPER_MAX_DUPLICATE_COUNT)) {
            .ByteDuplicate => {
                stats.retransmit_shred_byte_filtered_count.inc();
                continue;
            },
            .ShredIdDuplicate => {
                stats.retransmit_shred_id_filtered_count.inc();
                continue;
            },
            .NotDuplicate => {},
        }

        if (grouped_shreds.getEntry(shred_id.slot)) |entry| {
            try entry.value_ptr.append(.{ shred_id, shred_packet });
        } else {
            var new_slot_shreds = std.ArrayList(ShredIdAndPacket).init(allocator);
            try new_slot_shreds.append(.{ shred_id, shred_packet });
            try grouped_shreds.put(shred_id.slot, new_slot_shreds);
        }
    }
    stats.retransmit_group_shreds_micros.set(group_shreds_timer.read().asMicros());
    return grouped_shreds;
}

/// Create and send retransmit info to the retransmit shred threads
/// Retransmit info contains the slot leader, the shred_id, the shred_packet, and the turbine_tree
inline fn createAndSendRetransmitInfo(
    allocator: std.mem.Allocator,
    shreds: std.AutoArrayHashMap(Slot, std.ArrayList(ShredIdAndPacket)),
    my_contact_info: ThreadSafeContactInfo,
    bank: *const BankFields,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    leader_schedule_cache: *LeaderScheduleCache,
    turbine_tree_cache: *TurbineTreeCache,
    sender: *Channel(RetransmitShredInfo),
    stats: *Stats,
) !void {
    var send_retransmit_info_timer = try sig.time.Timer.start();
    for (shreds.keys(), shreds.values()) |slot, slot_shreds| {
        const epoch, _ = bank.epoch_schedule.getEpochAndSlotIndex(slot);

        const slot_leader = if (leader_schedule_cache.slotLeader(slot)) |leader| leader else blk: {
            try leader_schedule_cache.put(epoch, try bank.leaderSchedule(allocator));
            break :blk leader_schedule_cache.slotLeader(slot) orelse @panic("failed to get slot leader");
        };

        const turbine_tree = if (try turbine_tree_cache.get(epoch)) |tree| tree else blk: {
            const turbine_tree = try allocator.create(TurbineTree);
            turbine_tree.* = try TurbineTree.initForRetransmit(
                allocator,
                my_contact_info,
                gossip_table_rw,
                try bank.getStakedNodes(allocator, epoch),
                USE_STAKE_HACK_FOR_TESTING,
            );
            try turbine_tree_cache.put(epoch, turbine_tree);
            break :blk turbine_tree;
        };
        defer turbine_tree.releaseUnsafe();

        for (slot_shreds.items) |shred_id_and_packet| {
            try sender.send(.{
                .slot_leader = slot_leader,
                // CAUTION: .acquireUnsafe() is used here as the turbine_tree is guaranteed to be valid since:
                // 1. the turbine_tree_provider has one exactly on reference to the turbine_tree after getTurbineTree
                // 2. each call to .aquireUnsafe() increments the reference count by 1
                // 3. there is exactly one call to .release() per send (see RetransmitShredInfo.deinit and retransmitShreds)
                .turbine_tree = turbine_tree.acquireUnsafe(),
                .shred_id = shred_id_and_packet[0],
                .shred_packet = shred_id_and_packet[1],
            });
        }
    }
    stats.retransmit_send_retransmit_info_micros.set(send_retransmit_info_timer.read().asMicros());
}

/// Retransmit shreds to nodes in the network
/// RetransmitShredInfo contains the shred_id, the shred_packet, the slot_leader, and the turbine_tree
/// The shred_id and slot_leader are used to seed an rng for shuffling the nodes in the turbine_tree before
/// computing the children to retransmit to.
fn retransmitShreds(
    allocator: std.mem.Allocator,
    receiver: *Channel(RetransmitShredInfo),
    sender: *Channel(Packet),
    stats: *Stats,
    exit: *AtomicBool,
) !void {
    while (!exit.load(.acquire)) {
        var retransmit_shred_timer = try sig.time.Timer.start();

        const retransmit_info: RetransmitShredInfo = receiver.receive() orelse continue;

        var compute_turbine_children_timer = try sig.time.Timer.start();
        const level, const children = try retransmit_info.turbine_tree.getRetransmitChildren(
            allocator,
            retransmit_info.slot_leader,
            retransmit_info.shred_id,
            TurbineTree.getDataPlaneFanout(),
        );
        defer children.deinit();
        defer retransmit_info.turbine_tree.releaseUnsafe();
        stats.retransmit_compute_turbine_children_micros.set(compute_turbine_children_timer.read().asMicros());

        var children_with_addresses_count: usize = 0;
        for (children.items) |child| {
            if (child.tvuAddress()) |tvu_address| {
                children_with_addresses_count += 1;
                try sender.send(Packet.init(
                    tvu_address.toEndpoint(),
                    retransmit_info.shred_packet.data,
                    retransmit_info.shred_packet.size,
                ));
            }
        }

        stats.retransmit_shreds_sent_count.inc();
        stats.retransmit_turbine_level.set(level);
        stats.retransmit_turbine_children.set(children.items.len);
        stats.retransmit_turbine_children_with_addresses.set(children_with_addresses_count);
        stats.retransmit_retransmit_shreds_micros.set(retransmit_shred_timer.read().asMicros());
    }
}

const ShredIdAndPacket = struct {
    ShredId,
    Packet,
};

const RetransmitShredInfo = struct {
    shred_id: ShredId,
    shred_packet: Packet,
    slot_leader: Pubkey,
    turbine_tree: *TurbineTree,
};

pub const Stats = struct {
    retransmit_shreds_received_count: *Counter,
    retransmit_shreds_sent_count: *Counter,

    retransmit_shred_byte_filtered_count: *Counter,
    retransmit_shred_byte_filter_saturated_count: *Counter,
    retransmit_shred_id_filtered_count: *Counter,
    retransmit_shred_id_filter_saturated_count: *Counter,

    retransmit_turbine_level: *Gauge(u64),
    retransmit_turbine_children: *Gauge(u64),
    retransmit_turbine_children_with_addresses: *Gauge(u64),

    retransmit_send_retransmit_info_micros: *Gauge(u64),
    retransmit_group_shreds_micros: *Gauge(u64),
    retransmit_receive_shreds_micros: *Gauge(u64),

    retransmit_compute_turbine_children_micros: *Gauge(u64),
    retransmit_retransmit_shreds_micros: *Gauge(u64),

    pub fn init() GetMetricError!Stats {
        var self: Stats = undefined;
        const registry = globalRegistry();
        const stats_struct_info = @typeInfo(Stats).Struct;
        inline for (stats_struct_info.fields) |field| {
            if (field.name[0] != '_') {
                @field(self, field.name) = switch (field.type) {
                    *Counter => try registry.getOrCreateCounter(field.name),
                    *Gauge(u64) => try registry.getOrCreateGauge(field.name, u64),
                    else => @compileError("Unhandled field type: " ++ field.name ++ ": " ++ @typeName(field.type)),
                };
            }
        }
        return self;
    }

    pub fn log(self: *const Stats, logger: Logger) void {
        logger.info().logf("retransmit-service: received={} retransmitted={} skipped={}:{}:{}", .{
            self.retransmit_shreds_received_count.get(),
            self.retransmit_shreds_sent_count.get(),
            self.retransmit_shred_byte_filtered_count.get() + self.retransmit_shred_id_filtered_count.get(),
            self.retransmit_shred_byte_filtered_count.get(),
            self.retransmit_shred_id_filtered_count.get(),
        });
    }
};
