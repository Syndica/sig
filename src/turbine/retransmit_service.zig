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

/// Shred deduper configuration from agave
const DEDUPER_MAX_DUPLICATE_COUNT: usize = 2;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_RESET_CYCLE: Duration = Duration.fromSecs(5 * 60);
const DEDUPER_NUM_BITS: u64 = 637_534_199;

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
    overwrite_stake_for_testing: bool,
    exit_after_n_shreds: ?u64,
    exit: *AtomicBool,
    rand: Random,
    logger: Logger,
) !void {
    errdefer {
        logger.info().log("retransmit service failed");
        exit.store(false, .monotonic);
    }
    const num_retransmit_threads = maybe_num_retransmit_threads orelse try std.Thread.getCpuCount();
    logger.info().logf("(turbine_demo.retransmit_service) starting retransmit service: num_retransmit_sockets={} num_retransmit_threads={}", .{
        num_retransmit_sockets,
        num_retransmit_threads,
    });

    var metrics = try RetransmitServiceMetrics.init(logger);

    var receive_to_retransmit_channel = try Channel(RetransmitShredInfo).init(allocator);
    defer receive_to_retransmit_channel.deinit();

    var retransmit_to_socket_channel = try Channel(Packet).init(allocator);
    defer retransmit_to_socket_channel.deinit();

    var retransmit_sockets: std.ArrayList(UdpSocket) = std.ArrayList(UdpSocket).init(allocator);
    defer {
        for (retransmit_sockets.items) |socket| socket.close();
        retransmit_sockets.deinit();
    }

    for (0..num_retransmit_sockets) |_| {
        var socket = try UdpSocket.create(.ipv4, .udp);
        try socket.bind(try EndPoint.parse("0.0.0.0:0"));
        try retransmit_sockets.append(socket);
    }

    var thread_handles = std.ArrayList(std.Thread).init(allocator);
    defer thread_handles.deinit();

    try thread_handles.append(try std.Thread.spawn(
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
            &metrics,
            overwrite_stake_for_testing,
            exit_after_n_shreds,
        },
    ));

    for (0..num_retransmit_threads) |_| {
        try thread_handles.append(try std.Thread.spawn(
            .{},
            retransmitShreds,
            .{
                allocator,
                &receive_to_retransmit_channel,
                &retransmit_to_socket_channel,
                &metrics,
                exit,
            },
        ));
    }

    for (retransmit_sockets.items) |socket| {
        try thread_handles.append(try std.Thread.spawn(
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

    for (thread_handles.items) |thread| thread.join();
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
    metrics: *RetransmitServiceMetrics,
    overwrite_stake_for_testing: bool,
    exit_after_n_shreds: ?u64,
) !void {
    var turbine_tree_cache = TurbineTreeCache.init(allocator);
    defer turbine_tree_cache.deinit();

    var deduper = try ShredDeduper(2).init(
        allocator,
        rand,
        DEDUPER_NUM_BITS,
    );
    defer deduper.deinit();

    var shreds = std.ArrayList(Packet).init(allocator);

    while (!exit.load(.acquire)) {
        var receive_shreds_timer = try sig.time.Timer.start();

        const receiver_len = receiver.len();
        if (receiver_len == 0) continue;

        shreds.clearRetainingCapacity();
        try shreds.ensureTotalCapacity(receiver_len);

        while (receiver.receive()) |packet| try shreds.append(packet);

        if (shreds.items.len == 0) {
            std.time.sleep(1_000_00_0);
            continue;
        }

        const bytes_filter_saturated, const shred_id_filter_saturated = deduper.maybeReset(
            rand,
            DEDUPER_FALSE_POSITIVE_RATE,
            DEDUPER_RESET_CYCLE,
        );
        metrics.shred_byte_filter_saturated.set(@intFromBool(bytes_filter_saturated));
        metrics.shred_id_filter_saturated.set(@intFromBool(shred_id_filter_saturated));

        var grouped_shreds = try dedupAndGroupShredsBySlot(
            allocator,
            &shreds,
            &deduper,
            metrics,
        );
        defer {
            for (grouped_shreds.values()) |arr| arr.deinit();
            grouped_shreds.deinit();
        }

        if (grouped_shreds.count() > 0) {
            try createAndSendRetransmitInfo(
                allocator,
                grouped_shreds,
                my_contact_info,
                bank_fields,
                gossip_table_rw,
                leader_schedule_cache,
                &turbine_tree_cache,
                sender,
                metrics,
                overwrite_stake_for_testing,
            );
        }

        metrics.shreds_received_count.add(shreds.items.len);
        metrics.receive_shreds_nanos.set(receive_shreds_timer.read().asNanos());

        metrics.maybeLog(logger);

        // Set exit after 50_000 shreds received for demo
        if (exit_after_n_shreds) |n| {
            if (metrics.shreds_received_count.get() > n) {
                logger.info().logf("(turbine_demo.retransmit_service) exiting after {} shreds received", .{n});
                exit.store(true, .release);
            }
        }
    }
}

/// Group shreds by slot and deduplicate them in the process
/// Returns a map of slot to a list of shred_id and packet pairs
fn dedupAndGroupShredsBySlot(
    allocator: std.mem.Allocator,
    shreds: *std.ArrayList(Packet),
    deduper: *ShredDeduper(2),
    metrics: *RetransmitServiceMetrics,
) !std.AutoArrayHashMap(Slot, std.ArrayList(ShredIdAndPacket)) {
    var dedup_and_group_shreds_timer = try sig.time.Timer.start();
    var result = std.AutoArrayHashMap(Slot, std.ArrayList(ShredIdAndPacket)).init(allocator);
    for (shreds.items) |shred_packet| {
        const shred_id = try sig.ledger.shred.layout.getShredId(&shred_packet);

        switch (deduper.dedup(&shred_id, &shred_packet.data, DEDUPER_MAX_DUPLICATE_COUNT)) {
            .byte_duplicate => {
                metrics.shred_byte_filtered_count.inc();
                continue;
            },
            .shred_id_duplicate => {
                metrics.shred_id_filtered_count.inc();
                continue;
            },
            .not_duplicate => {},
        }

        if (result.getEntry(shred_id.slot)) |entry| {
            try entry.value_ptr.append(.{ shred_id, shred_packet });
        } else {
            var new_slot_shreds = std.ArrayList(ShredIdAndPacket).init(allocator);
            try new_slot_shreds.append(.{ shred_id, shred_packet });
            try result.put(shred_id.slot, new_slot_shreds);
        }
    }
    metrics.dedup_and_group_shreds_nanos.set(dedup_and_group_shreds_timer.read().asNanos());
    return result;
}

/// Create and send retransmit info to the retransmit shred threads
/// Retransmit info contains the slot leader, the shred_id, the shred_packet, and the turbine_tree
fn createAndSendRetransmitInfo(
    allocator: std.mem.Allocator,
    shreds: std.AutoArrayHashMap(Slot, std.ArrayList(ShredIdAndPacket)),
    my_contact_info: ThreadSafeContactInfo,
    bank: *const BankFields,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    leader_schedule_cache: *LeaderScheduleCache,
    turbine_tree_cache: *TurbineTreeCache,
    retransmit_shred_sender: *Channel(RetransmitShredInfo),
    metrics: *RetransmitServiceMetrics,
    overwrite_stake_for_testing: bool,
) !void {
    var create_and_send_retransmit_info_timer = try sig.time.Timer.start();
    for (shreds.keys(), shreds.values()) |slot, slot_shreds| {
        const epoch, _ = bank.epoch_schedule.getEpochAndSlotIndex(slot);

        var get_slot_leader_timer = try sig.time.Timer.start();
        const slot_leader = if (leader_schedule_cache.slotLeader(slot)) |leader| leader else blk: {
            try leader_schedule_cache.put(epoch, try bank.leaderSchedule(allocator));
            break :blk leader_schedule_cache.slotLeader(slot) orelse @panic("failed to get slot leader");
        };
        metrics.get_slot_leader_nanos.set(get_slot_leader_timer.read().asNanos());

        var get_turbine_tree_timer = try sig.time.Timer.start();
        const turbine_tree = if (try turbine_tree_cache.get(epoch)) |tree| tree else blk: {
            const turbine_tree = try allocator.create(TurbineTree);
            turbine_tree.* = try TurbineTree.initForRetransmit(
                allocator,
                my_contact_info,
                gossip_table_rw,
                try bank.getStakedNodes(allocator, epoch),
                overwrite_stake_for_testing,
            );
            try turbine_tree_cache.put(epoch, turbine_tree);
            break :blk turbine_tree;
        };
        defer turbine_tree.releaseUnsafe();
        metrics.get_turbine_tree_nanos.set(get_turbine_tree_timer.read().asNanos());

        for (slot_shreds.items) |shred_id_and_packet| {
            try retransmit_shred_sender.send(.{
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
    metrics.create_and_send_retransmit_info_nanos.set(create_and_send_retransmit_info_timer.read().asNanos());
}

/// Retransmit shreds to nodes in the network
/// RetransmitShredInfo contains the shred_id, the shred_packet, the slot_leader, and the turbine_tree
/// The shred_id and slot_leader are used to seed an rng for shuffling the nodes in the turbine_tree before
/// computing the children to retransmit to.
fn retransmitShreds(
    allocator: std.mem.Allocator,
    receiver: *Channel(RetransmitShredInfo),
    sender: *Channel(Packet),
    metrics: *RetransmitServiceMetrics,
    exit: *AtomicBool,
) !void {
    var children = try std.ArrayList(TurbineTree.Node).initCapacity(allocator, TurbineTree.getDataPlaneFanout());
    defer children.deinit();
    var shuffled_nodes = std.ArrayList(TurbineTree.Node).init(allocator);
    defer shuffled_nodes.deinit();
    while (!exit.load(.acquire)) {
        var retransmit_shred_timer = try sig.time.Timer.start();

        const retransmit_info: RetransmitShredInfo = receiver.receive() orelse {
            std.time.sleep(1_000_00_0);
            continue;
        };

        children.clearRetainingCapacity();
        shuffled_nodes.clearRetainingCapacity();
        var get_retransmit_children_timer = try sig.time.Timer.start();
        const level = try retransmit_info.turbine_tree.getRetransmitChildren(
            &children,
            &shuffled_nodes,
            retransmit_info.slot_leader,
            retransmit_info.shred_id,
            TurbineTree.getDataPlaneFanout(),
        );
        defer retransmit_info.turbine_tree.releaseUnsafe();
        metrics.turbine_tree_get_children_nanos.set(get_retransmit_children_timer.read().asNanos());

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

        if (children_with_addresses_count > 0) {
            metrics.shreds_sent_count.inc();
        }

        metrics.turbine_tree_level.set(level);
        metrics.turbine_tree_children.set(children.items.len);
        metrics.turbine_tree_children_with_addresses.set(children_with_addresses_count);
        metrics.retransmit_shred_nanos.set(retransmit_shred_timer.read().asNanos());
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

pub const RetransmitServiceMetrics = struct {
    // receiveShreds
    shreds_received_count: *Counter,
    shred_byte_filter_saturated: *Gauge(u64),
    shred_id_filter_saturated: *Gauge(u64),
    receive_shreds_nanos: *Gauge(u64),

    // dedupAndGroupShredsBySlot
    shred_byte_filtered_count: *Counter,
    shred_id_filtered_count: *Counter,
    dedup_and_group_shreds_nanos: *Gauge(u64),

    // createAndSendRetransmitInfo
    get_slot_leader_nanos: *Gauge(u64),
    get_turbine_tree_nanos: *Gauge(u64),
    create_and_send_retransmit_info_nanos: *Gauge(u64),

    // retransmitShreds
    shreds_sent_count: *Counter,
    turbine_tree_level: *Gauge(u64),
    turbine_tree_children: *Gauge(u64),
    turbine_tree_children_with_addresses: *Gauge(u64),
    turbine_tree_get_children_nanos: *Gauge(u64),
    retransmit_shred_nanos: *Gauge(u64),

    // logging info
    logging_fields: struct {
        logger: Logger,
        last_log_instant: sig.time.Instant,
    },

    // metrics prefix
    pub const prefix = "retransmit_service";

    const Gauge64 = Gauge(u64);

    pub fn init(logger: Logger) !RetransmitServiceMetrics {
        var self: RetransmitServiceMetrics = undefined;
        std.debug.assert(try globalRegistry().initFields(&self) == 1);
        self.logging_fields = .{ .logger = logger, .last_log_instant = sig.time.Instant.now() };
        return self;
    }

    pub fn maybeLog(self: *RetransmitServiceMetrics, logger: Logger) void {
        if (self.logging_fields.last_log_instant.elapsed().asMillis() > 250) {
            logger.info().logf("(turbine_demo.retransmit_service) received={} retransmitted={} skipped={}:{}:{}", .{
                self.shreds_received_count.get(),
                self.shreds_sent_count.get(),
                self.shred_byte_filtered_count.get() + self.shred_id_filtered_count.get(),
                self.shred_byte_filtered_count.get(),
                self.shred_id_filtered_count.get(),
            });
            self.logging_fields.last_log_instant = sig.time.Instant.now();
        }
    }
};
