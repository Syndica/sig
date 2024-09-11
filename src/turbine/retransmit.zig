const std = @import("std");
const net = @import("zig-network");
const sig = @import("../sig.zig");

const UdpSocket = net.Socket;
const AtomicBool = std.atomic.Value(bool);
const AtomicU64 = std.atomic.Value(u64);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Instant = std.time.Instant;

const bincode = sig.bincode;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const Duration = sig.time.Duration;
const TurbineTree = sig.turbine.TurbineTree;
const TurbineTreeCache = sig.turbine.TurbineTreeCache;
const Channel = sig.sync.Channel;
const ShredId = sig.ledger.shred.ShredId;
const BlockstoreReader = sig.ledger.BlockstoreReader;
const BlockstoreWriter = sig.ledger.BlockstoreWriter;
const ShredInserter = sig.ledger.insert_shred.ShredInserter;
const Shred = sig.ledger.shred.Shred;
const LeaderScheduleCache = sig.core.leader_schedule.LeaderScheduleCache;
const BankFields = sig.accounts_db.snapshots.BankFields;
const RwMux = sig.sync.RwMux;

pub fn runRetransmitService(
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    epoch_schedule: EpochSchedule,
    bank_fields: *const BankFields, // Should be replaced with BankForks or some provider of root bank and working bank
    leader_schedule_cache: *LeaderScheduleCache,
    shreds_receiver: *Channel(std.ArrayList(sig.net.Packet)),
    retransmit_sockets: []const UdpSocket,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    exit: *AtomicBool,
    // max_slots: Arc<MaxSlots>,
) !void {
    var turbine_tree_cache = TurbineTreeCache.init(
        allocator,
        my_contact_info,
        epoch_schedule,
        gossip_table_rw,
    );

    var shred_deduper = try ShredDeduper(2).init(allocator);
    defer shred_deduper.deinit();

    while (exit.load(.unordered)) {
        try retransmit(
            allocator,
            bank_fields,
            leader_schedule_cache,
            shreds_receiver,
            retransmit_sockets,
            &turbine_tree_cache,
            &shred_deduper,
            // max_slots,
        );
    }
}

const MAX_DUPLICATE_COUNT: usize = 2;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_RESET_CYCLE: Duration = Duration.fromSecs(5 * 60);

fn retransmit(
    allocator: std.mem.Allocator,
    bank_fields: *const BankFields,
    leader_schedule_cache: *LeaderScheduleCache,
    shreds_receiver: *Channel(std.ArrayList(sig.net.Packet)),
    sockets: []const UdpSocket,
    turbine_tree_cache: *TurbineTreeCache,
    shred_deduper: *ShredDeduper(2),
    // max_slots: &MaxSlots, // When starting validator shared in json rpc service, completed data sets service and tvu retransmit stage
) !void {
    // Drain shred receiver into raw shreds
    const raw_shred_batches = try shreds_receiver.try_drain() orelse return error.NoShreds; // Add timeout?
    defer {
        for (raw_shred_batches) |batch| batch.deinit();
        allocator.free(raw_shred_batches);
    }

    // TODO: Implement / understand shred deduper
    // shred_deduper.maybeReset(
    //     rand,
    //     DEDUPER_FALSE_POSITIVE_RATE,
    //     DEDUPER_RESET_CYCLE,
    // );

    // Group shreds by slot
    const ShredsArray = std.ArrayList(struct { ShredId, []const u8 });

    var slot_shreds = std.AutoArrayHashMap(Slot, ShredsArray).init(allocator);
    defer {
        for (slot_shreds.values()) |arr| arr.deinit();
        slot_shreds.deinit();
    }

    for (raw_shred_batches) |raw_shred_batch| {
        for (raw_shred_batch.items) |raw_shred| {
            const shred_id = ShredId{ .index = 0, .slot = 0, .shred_type = .code };
            // const shred_id = (try bincode.readFromSlice(allocator, Shred, &raw_shred.data, .{})).id(); // Agave just reads shred id using byte offsets into struct
            if (shred_deduper.dedup(&shred_id, &raw_shred.data, MAX_DUPLICATE_COUNT)) continue;
            if (slot_shreds.getEntry(shred_id.slot)) |entry| {
                try entry.value_ptr.append(.{ shred_id, &raw_shred.data });
            } else {
                var new_slot_shreds = ShredsArray.init(allocator);
                try new_slot_shreds.append(.{ shred_id, &raw_shred.data });
                try slot_shreds.put(shred_id.slot, new_slot_shreds);
            }
        }
    }
    // array_list.ArrayListAligned(turbine.retransmit.retransmit__struct_31077,null)
    // array_list.ArrayListAligned(turbine.retransmit.retransmit__struct_31383,null)
    // Retransmit shreds
    for (slot_shreds.keys(), slot_shreds.values()) |slot, shreds| {
        // max_slots.retransmit.fetch_max(slot, Ordering::Relaxed);
        const slot_leader = try leader_schedule_cache.getSlotLeaderMaybeCompute(slot, bank_fields);
        const turbine_tree = try turbine_tree_cache.getTurbineTree(slot, bank_fields);

        // PERF: Move outside for loop and parallelize
        for (shreds.items, 0..) |shred, i| {
            const shred_id, const shred_bytes = shred;
            defer allocator.free(shred_bytes);

            const socket = sockets[i % sockets.len];

            const addresses = try turbine_tree.getRetransmitAddresses(
                allocator,
                slot_leader,
                shred_id,
                TurbineTree.getDataPlaneFanout(),
            );
            defer allocator.free(addresses);

            for (addresses) |address| {
                _ = try socket.sendTo(address.toEndpoint(), shred_bytes);
            }
        }
    }
}

pub fn ShredDeduper(comptime K: usize) type {
    return struct {
        // deduper: Deduper(K, []const u8),
        // shred_id_filter: Deduper(K, struct { ShredId, usize }),

        pub fn init(allocator: std.mem.Allocator) !ShredDeduper(K) {
            _ = allocator;
            return .{
                // .deduper = try Deduper(K, []const u8).init(allocator),
                // .shred_id_filter = try Deduper(K, struct { ShredId, usize }).init(allocator),
            };
        }

        pub fn deinit(self: *ShredDeduper(K)) void {
            _ = self;
            // self.deduper.deinit();
            // self.shred_id_filter.deinit();
        }

        pub fn maybeReset(self: *ShredDeduper(K), rand: std.rand.Random, false_positive_rate: f64, reset_cycle: Duration) void {
            // TODO:
            _ = self;
            _ = rand;
            _ = false_positive_rate;
            _ = reset_cycle;
        }

        pub fn dedup(self: ShredDeduper(K), shred_id: *const ShredId, shred_bytes: []const u8, max_duplicate_count: usize) bool {
            // TODO:
            _ = self;
            _ = shred_id;
            _ = shred_bytes;
            _ = max_duplicate_count;
            return false;
        }
    };
}

pub fn Deduper(comptime K: usize, comptime T: type) type {
    return struct {
        num_bits: u64,
        bits: std.ArrayList(AtomicU64),
        state: [K]RandomState,
        clock: Instant,
        popcount: AtomicU64,

        pub fn init(allocator: std.mem.Allocator) !Deduper(K, T) {
            // TODO
            return .{
                .num_bits = 0,
                .bits = std.ArrayList(AtomicU64).init(allocator),
                .state = [_]RandomState{.{}} ** K,
                .clock = try Instant.now(),
                .popcount = AtomicU64.init(0),
            };
        }

        pub fn deinit(self: *Deduper(K, T)) void {
            self.bits.deinit();
        }

        pub fn dedup(self: *Deduper(K, T), data: *const T) bool {
            // TODO
            _ = self;
            _ = data;
            return false;
        }
    };
}

pub const RandomState = struct {};
