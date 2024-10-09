const std = @import("std");
const net = @import("zig-network");
const sig = @import("../sig.zig");

const socket_utils = sig.net.socket_utils;

const Random = std.rand.Random;
const UdpSocket = net.Socket;
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

const MAX_DUPLICATE_COUNT: usize = 2;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_RESET_CYCLE: Duration = Duration.fromSecs(5 * 60);
const DEDUPER_NUM_BITS: u64 = 637_534_199;
const SEND_SHRED_THREADS: usize = 8;

pub fn run(
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    bank_fields: *const BankFields,
    leader_schedule_cache: *LeaderScheduleCache,
    receiver: *Channel(Packet),
    retransmit_sockets: []const UdpSocket,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    exit: *AtomicBool,
    rand: Random,
    logger: Logger,
) !void {
    errdefer {
        logger.info("retransmit service failed");
        exit.store(false, .monotonic);
    }

    var stats = try Stats.init();

    var receive_to_retransmit_channel = try Channel(RetransmitShredInfo).init(allocator);
    defer receive_to_retransmit_channel.deinit();

    var retransmit_to_socket_channel = try Channel(Packet).init(allocator);
    defer retransmit_to_socket_channel.deinit();

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

    var send_shred_threads: [SEND_SHRED_THREADS]std.Thread = undefined;
    for (0..SEND_SHRED_THREADS) |i| {
        send_shred_threads[i] = try std.Thread.spawn(
            .{},
            retransmitShreds,
            .{
                allocator,
                &receive_to_retransmit_channel,
                &retransmit_to_socket_channel,
                &stats,
                exit,
            },
        );
    }

    var send_socket_threads = std.ArrayList(std.Thread).init(allocator);
    for (retransmit_sockets) |socket| {
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
    for (send_shred_threads) |thread| thread.join();
    for (send_socket_threads.items) |thread| thread.join();
}

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
    var turbine_tree_provider = TurbineTreeCache.init(
        allocator,
        my_contact_info,
        gossip_table_rw,
    );
    defer turbine_tree_provider.deinit();

    var deduper = try ShredDeduper(2).init(
        allocator,
        rand,
        DEDUPER_NUM_BITS,
    );
    defer deduper.deinit();

    while (!exit.load(.acquire)) {
        // Drain receiver
        const receiver_len = receiver.len();
        if (receiver_len == 0) continue;

        var shreds = try std.ArrayList(Packet).initCapacity(allocator, receiver_len);
        while (receiver.receive()) |packet| try shreds.append(packet);
        defer shreds.deinit();

        stats.retransmit_shreds_received_count.add(shreds.items.len);

        // Preprocess shreds
        var preprocess_shreds_timer = try sig.time.Timer.start();

        // Reset deduper
        deduper.maybeReset(
            rand,
            DEDUPER_FALSE_POSITIVE_RATE,
            DEDUPER_RESET_CYCLE,
        );

        // Group shreds by slot
        var grouped_shreds = std.AutoArrayHashMap(Slot, std.ArrayList(ShredIdAndPacket)).init(allocator);
        defer {
            for (grouped_shreds.values()) |arr| arr.deinit();
            grouped_shreds.deinit();
        }
        for (shreds.items) |shred_packet| {
            const shred_id = try sig.ledger.shred.layout.getShredId(&shred_packet);

            if (deduper.dedup(&shred_id, &shred_packet.data, MAX_DUPLICATE_COUNT)) {
                stats.retransmit_shreds_skipped_count.add(1);
                continue;
            }

            if (grouped_shreds.getEntry(shred_id.slot)) |entry| {
                try entry.value_ptr.append(.{ shred_id, shred_packet });
            } else {
                var new_slot_shreds = std.ArrayList(ShredIdAndPacket).init(allocator);
                try new_slot_shreds.append(.{ shred_id, shred_packet });
                try grouped_shreds.put(shred_id.slot, new_slot_shreds);
            }
        }

        // Send shreds and required metadata to retransmit channel
        for (grouped_shreds.keys(), grouped_shreds.values()) |slot, slot_shreds| {
            const epoch, _ = bank_fields.epoch_schedule.getEpochAndSlotIndex(slot);

            const slot_leader = if (leader_schedule_cache.slotLeader(slot)) |leader| leader else blk: {
                try leader_schedule_cache.put(epoch, try bank_fields.leaderSchedule(allocator));
                break :blk leader_schedule_cache.slotLeader(slot) orelse @panic("failed to get slot leader");
            };

            const turbine_tree = try turbine_tree_provider.getTurbineTree(
                epoch,
                bank_fields,
            );

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

        stats.retransmit_preprocess_shreds_micros.set(@divFloor(preprocess_shreds_timer.read().asMicros(), shreds.items.len));
        stats.log(logger);
    }
}

fn retransmitShreds(
    allocator: std.mem.Allocator,
    receiver: *Channel(RetransmitShredInfo),
    sender: *Channel(Packet),
    stats: *Stats,
    exit: *AtomicBool,
) !void {
    while (!exit.load(.acquire)) {
        const retransmit_info: RetransmitShredInfo = receiver.receive() orelse continue;
        defer retransmit_info.deinit();

        var compute_turbine_children_timer = try sig.time.Timer.start();
        const level, const children = try retransmit_info.turbine_tree.getRetransmitChildren(
            allocator,
            retransmit_info.slot_leader,
            retransmit_info.shred_id,
            TurbineTree.getDataPlaneFanout(),
        );
        defer children.deinit();
        stats.retransmit_compute_turbine_children_millis.set(compute_turbine_children_timer.read().asMillis());

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

        stats.retransmit_shreds_sent_count.add(1);
        stats.retransmit_turbine_level.set(level);
        stats.retransmit_turbine_children.set(children.items.len);
        stats.retransmit_turbine_children_with_addresses.set(children_with_addresses_count);
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

    pub fn deinit(self: RetransmitShredInfo) void {
        self.turbine_tree.release();
    }
};

pub const Stats = struct {
    retransmit_shreds_received_count: *Counter,
    retransmit_shreds_skipped_count: *Counter,
    retransmit_shreds_sent_count: *Counter,

    retransmit_turbine_level: *Gauge(u64),
    retransmit_turbine_children: *Gauge(u64),
    retransmit_turbine_children_with_addresses: *Gauge(u64),

    retransmit_preprocess_shreds_micros: *Gauge(u64),
    retransmit_compute_turbine_children_millis: *Gauge(u64),

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
        logger.infof("RetransmitService: received={} skipped={} retransmitted={}", .{
            self.retransmit_shreds_received_count.get(),
            self.retransmit_shreds_skipped_count.get(),
            self.retransmit_shreds_sent_count.get(),
        });
    }
};
