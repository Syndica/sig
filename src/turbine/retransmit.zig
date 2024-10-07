const std = @import("std");
const net = @import("zig-network");
const sig = @import("../sig.zig");

const UdpSocket = net.Socket;
const AtomicBool = std.atomic.Value(bool);
const AtomicU64 = std.atomic.Value(u64);

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

pub fn runRetransmitService(
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    bank_fields: *const BankFields,
    leader_schedule_cache: *LeaderScheduleCache,
    shreds_receiver: *Channel(sig.net.Packet),
    retransmit_sockets: []const UdpSocket,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    rand: std.rand.Random,
    exit: *AtomicBool,
    logger: Logger,
) !void {
    errdefer exit.store(false, .monotonic);

    var stats = try Stats.init();

    var turbine_tree_cache = TurbineTreeCache.init(
        allocator,
        my_contact_info,
        gossip_table_rw,
        logger,
    );
    defer turbine_tree_cache.deinit();

    var shred_deduper = try ShredDeduper(2).init(
        allocator,
        rand,
        DEDUPER_NUM_BITS,
    );
    defer shred_deduper.deinit();

    while (exit.load(.monotonic)) {
        retransmit(
            allocator,
            bank_fields,
            leader_schedule_cache,
            shreds_receiver,
            retransmit_sockets,
            &turbine_tree_cache,
            &shred_deduper,
            &stats,
            rand,
            logger,
        ) catch |err| {
            logger.debugf("error executing retransmit: {}", .{err});
            break;
        };
    }
}

fn retransmit(
    allocator: std.mem.Allocator,
    bank_fields: *const BankFields,
    leader_schedule_cache: *LeaderScheduleCache,
    shreds_receiver: *Channel(sig.net.Packet),
    sockets: []const UdpSocket,
    turbine_tree_cache: *TurbineTreeCache,
    shred_deduper: *ShredDeduper(2),
    stats: *Stats,
    rand: std.rand.Random,
    logger: Logger,
) !void {
    // Drain shreds from the receiver
    // PERF: Implement a channel drain method with pre-allocated buffer?
    var raw_shred_batch = std.ArrayList(sig.net.Packet).init(allocator);
    defer raw_shred_batch.deinit();

    while (shreds_receiver.receive()) |packet| {
        try raw_shred_batch.append(packet);
    }

    if (raw_shred_batch.items.len == 0) {
        return;
    }

    logger.debugf("retransmit received {} shreds", .{raw_shred_batch.items.len});
    stats.shreds_received_count.add(raw_shred_batch.items.len);

    // Reset deduper
    // Resets if false positive rate is exceeded or reset cycle is reached
    shred_deduper.maybeReset(
        rand,
        DEDUPER_FALSE_POSITIVE_RATE,
        DEDUPER_RESET_CYCLE,
    );

    // Group shreds by slot
    // PERF: Use pre-allocations?
    const ShredsArray = std.ArrayList(struct { ShredId, []const u8 });
    var slot_shreds = std.AutoArrayHashMap(Slot, ShredsArray).init(allocator);
    defer {
        for (slot_shreds.values()) |arr| arr.deinit();
        slot_shreds.deinit();
    }

    for (raw_shred_batch.items) |raw_shred| {
        const shred_id = try sig.ledger.shred.layout.getShredId(&raw_shred);

        if (shred_deduper.dedup(&shred_id, &raw_shred.data, MAX_DUPLICATE_COUNT)) {
            stats.shreds_duplicated_count.add(1);
            continue;
        }

        if (slot_shreds.getEntry(shred_id.slot)) |entry| {
            try entry.value_ptr.append(.{ shred_id, &raw_shred.data });
        } else {
            var new_slot_shreds = ShredsArray.init(allocator);
            try new_slot_shreds.append(.{ shred_id, &raw_shred.data });
            try slot_shreds.put(shred_id.slot, new_slot_shreds);
        }
    }
    logger.infof("retransmit received {} shreds from {} slots", .{ raw_shred_batch.items.len, slot_shreds.keys().len });

    // Retransmitting shreds
    // PERF: consider parallelizing
    for (slot_shreds.keys(), slot_shreds.values()) |slot, shreds| {
        const epoch, _ = bank_fields.epoch_schedule.getEpochAndSlotIndex(slot);

        // Get the slot leader, unreachable, panic, or handle error?
        const slot_leader = if (leader_schedule_cache.slotLeader(slot)) |leader| leader else blk: {
            try leader_schedule_cache.put(epoch, try bank_fields.leaderSchedule(allocator));
            break :blk leader_schedule_cache.slotLeader(slot) orelse unreachable;
        };

        // Safe to hold pointer in single-threaded context, careful if parallelizing
        const turbine_tree = try turbine_tree_cache.getTurbineTree(epoch, bank_fields);

        logger.infof("retransmitting {} shreds for slot {}", .{ shreds.items.len, slot });
        for (shreds.items, 0..) |shred, i| {
            const shred_id, const shred_bytes = shred;
            const socket = sockets[i % sockets.len];

            const addresses = try turbine_tree.getRetransmitAddresses(
                allocator,
                slot_leader,
                shred_id,
                TurbineTree.getDataPlaneFanout(),
            );
            defer allocator.free(addresses);

            logger.infof("retransmitting shred to {} addresses", .{addresses.len});
            for (addresses) |address| {
                _ = socket.sendTo(address.toEndpoint(), shred_bytes) catch |err| {
                    logger.debugf("error retransmitting shred to address {}: {}", .{ address, err });
                };
            }
        }
    }
}

pub const Stats = struct {
    shreds_received_count: *Counter,
    shreds_duplicated_count: *Counter,

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
        _ = self;
        logger.infof("retransmit-service", .{});
    }
};
