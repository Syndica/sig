const std = @import("std");
const net = @import("zig-network");
const sig = @import("../sig.zig");
const shred_network = @import("lib.zig");

const socket_utils = sig.net.socket_utils;

const AtomicBool = std.atomic.Value(bool);
const AtomicU64 = std.atomic.Value(u64);
const EndPoint = net.EndPoint;
const Random = std.Random;
const UdpSocket = net.Socket;

const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Duration = sig.time.Duration;
const Gauge = sig.prometheus.Gauge;
const Histogram = sig.prometheus.Histogram;
const Logger = sig.trace.log.Logger;
const Packet = sig.net.Packet;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const EpochContextManager = sig.adapter.EpochContextManager;
const ShredId = sig.ledger.shred.ShredId;
const Slot = sig.core.Slot;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;

const ShredDeduper = shred_network.shred_deduper.ShredDeduper;
const TurbineTree = shred_network.turbine_tree.TurbineTree;
const TurbineTreeCache = shred_network.turbine_tree.TurbineTreeCache;

const globalRegistry = sig.prometheus.globalRegistry;

/// Shred deduper configuration from agave
const DEDUPER_MAX_DUPLICATE_COUNT: usize = 2;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_RESET_CYCLE: Duration = Duration.fromSecs(5 * 60);
const DEDUPER_NUM_BITS: u64 = 637_534_199;

pub const ShredRetransmitterParams = struct {
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    epoch_context_mgr: *EpochContextManager,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    receiver: *Channel(Packet),
    maybe_num_retransmit_threads: ?usize,
    overwrite_stake_for_testing: bool,
    exit: *AtomicBool,
    rand: Random,
    logger: Logger,
};

/// Retransmit Service
/// The retransmit service receives verified shreds from the shred network and retransmits them to the network.
/// The retransmit service is broken down into two main components:
/// 1. receiveShreds: runs on a single thread and receives shreds from the shred network, deduplicates them, and then packages them
///    into RetransmitShredInfo's which are sent to a channel for further processing.
/// 2. retransmitShreds: runs on N threads and receives RetransmitShredInfo's from the channel, computes the children to retransmit to
///    and then constructs and sends packets to the network.
pub fn runShredRetransmitter(params: ShredRetransmitterParams) !void {
    errdefer {
        params.logger.info().log("retransmit service failed");
        params.exit.store(false, .monotonic);
    }
    const num_retransmit_threads = params.maybe_num_retransmit_threads orelse
        @max(try std.Thread.getCpuCount(), 8);
    params.logger.info().logf("starting retransmit service: num_retransmit_threads={}", .{
        num_retransmit_threads,
    });

    var metrics = try RetransmitServiceMetrics.init();

    var receive_to_retransmit_channel = try Channel(RetransmitShredInfo).init(params.allocator);
    defer receive_to_retransmit_channel.deinit();

    var retransmit_to_socket_channel = try Channel(Packet).init(params.allocator);
    defer retransmit_to_socket_channel.deinit();

    var retransmit_socket = try UdpSocket.create(.ipv4, .udp);
    defer retransmit_socket.close();
    try retransmit_socket.bind(try EndPoint.parse("0.0.0.0:0"));

    var thread_handles = std.ArrayList(std.Thread).init(params.allocator);
    defer thread_handles.deinit();

    try thread_handles.append(try std.Thread.spawn(
        .{},
        receiveShreds,
        .{
            params.allocator,
            params.my_contact_info,
            params.epoch_context_mgr,
            params.receiver,
            &receive_to_retransmit_channel,
            params.gossip_table_rw,
            params.rand,
            params.exit,
            params.logger,
            &metrics,
            params.overwrite_stake_for_testing,
        },
    ));

    for (0..num_retransmit_threads) |_| {
        try thread_handles.append(try std.Thread.spawn(
            .{},
            retransmitShreds,
            .{
                params.allocator,
                &receive_to_retransmit_channel,
                &retransmit_to_socket_channel,
                &metrics,
                params.exit,
            },
        ));
    }

    const sender_thread = try socket_utils.SocketThread.spawnSender(
        params.allocator,
        params.logger,
        retransmit_socket,
        &retransmit_to_socket_channel,
        .{ .unordered = params.exit },
    );
    defer sender_thread.join();

    for (thread_handles.items) |thread| thread.join();
}

/// Receive shreds from the network, deduplicate them, and then package
/// them into RetransmitShredInfo's to be sent to the retransmit shred threads.
fn receiveShreds(
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    epoch_context_mgr: *EpochContextManager,
    receiver: *Channel(Packet),
    sender: *Channel(RetransmitShredInfo),
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    rand: Random,
    exit: *AtomicBool,
    logger: Logger,
    metrics: *RetransmitServiceMetrics,
    overwrite_stake_for_testing: bool,
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
    var receive_shreds_timer = try sig.time.Timer.start();

    while (true) {
        receiver.waitToReceive(.{ .unordered = exit }) catch break;
        receive_shreds_timer.reset();

        const receiver_len = receiver.len();
        if (receiver_len == 0) continue;

        shreds.clearRetainingCapacity();
        try shreds.ensureTotalCapacity(receiver_len);

        while (receiver.tryReceive()) |packet| try shreds.append(packet);

        if (shreds.items.len == 0) continue;

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
                epoch_context_mgr,
                gossip_table_rw,
                &turbine_tree_cache,
                sender,
                metrics,
                overwrite_stake_for_testing,
            );
        }

        metrics.shreds_received_count.add(shreds.items.len);
        metrics.receive_shreds_nanos.observe(receive_shreds_timer.read().asNanos());

        metrics.maybeLog(logger);
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

        switch (deduper.dedup(&shred_id, &shred_packet.buffer, DEDUPER_MAX_DUPLICATE_COUNT)) {
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
    metrics.dedup_and_group_shreds_nanos.observe(dedup_and_group_shreds_timer.read().asNanos());
    return result;
}

/// Create and send retransmit info to the retransmit shred threads
/// Retransmit info contains the slot leader, the shred_id, the shred_packet, and the turbine_tree
fn createAndSendRetransmitInfo(
    allocator: std.mem.Allocator,
    shreds: std.AutoArrayHashMap(Slot, std.ArrayList(ShredIdAndPacket)),
    my_contact_info: ThreadSafeContactInfo,
    epoch_context_mgr: *EpochContextManager,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    turbine_tree_cache: *TurbineTreeCache,
    retransmit_shred_sender: *Channel(RetransmitShredInfo),
    metrics: *RetransmitServiceMetrics,
    overwrite_stake_for_testing: bool,
) !void {
    var create_and_send_retransmit_info_timer = try sig.time.Timer.start();
    for (shreds.keys(), shreds.values()) |slot, slot_shreds| {
        const epoch, const slot_index = epoch_context_mgr.schedule.getEpochAndSlotIndex(slot);
        const epoch_context = epoch_context_mgr.get(epoch) orelse continue;
        defer epoch_context_mgr.release(epoch_context);

        var get_slot_leader_timer = try sig.time.Timer.start();
        const slot_leader = epoch_context.leader_schedule[slot_index];
        metrics.get_slot_leader_nanos.observe(get_slot_leader_timer.read().asNanos());

        var get_turbine_tree_timer = try sig.time.Timer.start();
        const turbine_tree = if (try turbine_tree_cache.get(epoch)) |tree| tree else blk: {
            const turbine_tree = try allocator.create(TurbineTree);
            turbine_tree.* = try TurbineTree.initForRetransmit(
                allocator,
                my_contact_info,
                gossip_table_rw,
                &epoch_context.staked_nodes,
                overwrite_stake_for_testing,
            );
            try turbine_tree_cache.put(epoch, turbine_tree);
            break :blk turbine_tree;
        };
        defer turbine_tree.releaseUnsafe();
        metrics.get_turbine_tree_nanos.observe(get_turbine_tree_timer.read().asNanos());

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
    metrics.create_and_send_retransmit_info_nanos.observe(
        create_and_send_retransmit_info_timer.read().asNanos(),
    );
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
    var children = try std.ArrayList(TurbineTree.Node).initCapacity(
        allocator,
        TurbineTree.getDataPlaneFanout(),
    );
    defer children.deinit();
    var shuffled_nodes = std.ArrayList(TurbineTree.Node).init(allocator);
    defer shuffled_nodes.deinit();

    while (!exit.load(.acquire)) {
        var retransmit_shred_timer = try sig.time.Timer.start();

        // NOTE: multiple `retransmitShreds` run concurrently so we can't use
        // `receiver.waitToReceive()` here as it only supports one caller thread.
        const retransmit_info: RetransmitShredInfo = receiver.tryReceive() orelse continue;
        defer retransmit_info.turbine_tree.releaseUnsafe();

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

        metrics.turbine_tree_get_children_nanos.observe(
            get_retransmit_children_timer.read().asNanos(),
        );

        var children_with_addresses_count: usize = 0;
        for (children.items) |child| {
            if (child.tvuAddress()) |tvu_address| {
                children_with_addresses_count += 1;
                try sender.send(Packet.init(
                    tvu_address.toEndpoint(),
                    retransmit_info.shred_packet.buffer,
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
        metrics.retransmit_shred_nanos.observe(retransmit_shred_timer.read().asNanos());
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
    receive_shreds_nanos: *Histogram,

    // dedupAndGroupShredsBySlot
    shred_byte_filtered_count: *Counter,
    shred_id_filtered_count: *Counter,
    dedup_and_group_shreds_nanos: *Histogram,

    // createAndSendRetransmitInfo
    get_slot_leader_nanos: *Histogram,
    get_turbine_tree_nanos: *Histogram,
    create_and_send_retransmit_info_nanos: *Histogram,

    // retransmitShreds
    shreds_sent_count: *Counter,
    turbine_tree_level: *Gauge(u64),
    turbine_tree_children: *Gauge(u64),
    turbine_tree_children_with_addresses: *Gauge(u64),
    turbine_tree_get_children_nanos: *Histogram,
    retransmit_shred_nanos: *Histogram,

    // logging info
    logging_fields: struct {
        last_log_instant: std.time.Instant,
    },

    // metrics prefix
    pub const prefix = "retransmit_service";

    // histogram buckets
    pub const histogram_buckets: [10]f64 = .{
        10,   25,
        50,   100,
        250,  500,
        1000, 2500,
        5000, 10000,
    };

    pub fn init() !RetransmitServiceMetrics {
        var self: RetransmitServiceMetrics = undefined;
        std.debug.assert(try globalRegistry().initFields(&self) == 1);
        self.logging_fields = .{ .last_log_instant = sig.time.clock.sample() };
        return self;
    }

    pub fn maybeLog(self: *RetransmitServiceMetrics, logger: Logger) void {
        const now = sig.time.clock.sample();
        if (now.since(self.logging_fields.last_log_instant) > Duration.fromMillis(250).asNanos()) {
            logger.info().logf(
                "turbine-retransmit: received={} retransmitted={} skipped={}:{}:{}",
                .{
                    self.shreds_received_count.get(),
                    self.shreds_sent_count.get(),
                    self.shred_byte_filtered_count.get() + self.shred_id_filtered_count.get(),
                    self.shred_byte_filtered_count.get(),
                    self.shred_id_filtered_count.get(),
                },
            );
            self.logging_fields.last_log_instant = sig.time.clock.sample();
        }
    }
};
