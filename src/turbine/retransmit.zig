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

// MISSING DATA STRUCTURES
// const Bank = struct {};
// const UdpSocket = struct {};
// const Blockstore = struct {};
// const BankForks = struct {};
// const WorkingBankEntry = struct {
//     bank: Bank,
//     entry: PohEntry,
//     last_tick_height: u64,
// };

pub fn runRetransmitService(
    // sockets: Arc<Vec<UdpSocket>>, // Sockets to read from
    // quic_endpoint_sender: AsyncSender<(SocketAddr, Bytes)>,
    // bank_forks: Arc<RwLock<BankForks>>,
    // leader_schedule_cache: Arc<LeaderScheduleCache>,
    // cluster_info: Arc<ClusterInfo>,
    // shreds_receiver: Receiver<Vec</*shred:*/ Vec<u8>>>,
    // max_slots: Arc<MaxSlots>,
    // rpc_subscriptions: Option<Arc<RpcSubscriptions>>,
) !void {
    // Init cluster node cache
    // Init rng
    // Init shred deduper
    // Init thread pool with max threads equal to the number of sockets
    // Loop
    //     call retransmit
}

const MAX_DUPLICATE_COUNT: usize = 2;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_RESET_CYCLE: Duration = Duration.fromSecs(5 * 60);

fn retransmit(
    allocator: std.mem.Allocator,
    rand: std.rand.Random,
    bank_fields: BankFields,
    leader_schedule_cache: *LeaderScheduleCache,
    shreds_receiver: *Channel(std.ArrayList(std.ArrayList(u8))),
    sockets: []const UdpSocket,
    turbine_tree_cache: *TurbineTreeCache,
    shred_deduper: *ShredDeduper(2),
    // max_slots: &MaxSlots, // When starting validator shared in json rpc service, completed data sets service and tvu retransmit stage
) !void {
    // Drain shred receiver into raw shreds
    const raw_shreds = try shreds_receiver.try_drain() orelse return error.NoShreds; // Add timeout?

    shred_deduper.maybeReset(
        rand,
        DEDUPER_FALSE_POSITIVE_RATE,
        DEDUPER_RESET_CYCLE,
    );

    // Group shreds by slot
    var slot_shreds = std.AutoArrayHashMap(Slot, std.ArrayList(struct { ShredId, []const u8 })).init(allocator);
    for (raw_shreds) |raw_shred| {
        const shred_id = (try bincode.readFromSlice(allocator, Shred, raw_shred.items, .{})).id(); // Agave just reads shred id using byte offsets into struct
        if (shred_deduper.dedup(shred_id, raw_shred, MAX_DUPLICATE_COUNT)) continue;
        if (slot_shreds.getEntry(shred_id.slot)) |entry| {
            try entry.value_ptr.append(.{ shred_id, raw_shred });
        } else {
            const new_slot_shreds = std.ArrayList(struct { ShredId, []const u8 }).init(allocator);
            try new_slot_shreds.append(.{ shred_id, raw_shred });
            try slot_shreds.put(shred_id.slot, new_slot_shreds);
        }
    }

    // Retransmit shreds
    for (slot_shreds.keys(), slot_shreds.values()) |slot, shreds| {
        // max_slots.retransmit.fetch_max(slot, Ordering::Relaxed);
        const slot_leader = leader_schedule_cache.getSlotLeader(slot, &bank_fields); // Need bank here, if leader schedule cache does not have leader schedule for slot, we need to compute the leader schedule by getting the staked nodes from the bank for the epoch which contains the provided slot
        const turbine_tree = turbine_tree_cache.getTurbineTree(slot); // Need bank here, if turbine tree cache does not have ...

        // PERF: Move outside for loop and parallelize
        for (shreds, 0..) |shred, i| {
            const shred_id, const shred_bytes = shred;
            const socket = sockets[i % sockets.len];

            const addresses = turbine_tree.getRetransmitAddresses(
                allocator,
                slot_leader,
                shred_id,
                TurbineTree.getDataPlaneFanout(),
            );
            defer allocator.free(addresses);

            for (addresses) |address| {
                try socket.sendTo(address.toEndpoint(), shred_bytes);
            }
        }
    }
}

pub fn ShredDeduper(comptime K: usize) type {
    return struct {
        deduper: Deduper(K, []const u8),
        shred_id_filter: Deduper(K, struct { ShredId, usize }),

        pub fn init() ShredDeduper(K) {
            return .{
                .deduper = Deduper(K, []const u8).init(),
                .shred_id_filter = Deduper(K, struct { ShredId, usize }),
            };
        }

        pub fn maybeReset(self: *ShredDeduper(K), rand: std.rand.Random, false_positive_rate: f64, reset_cycle: Duration) void {
            // TODO:
            _ = self;
            _ = rand;
            _ = false_positive_rate;
            _ = reset_cycle;
        }

        pub fn dedup(self: ShredDeduper(K), shred_id: *ShredId, shred_bytes: []const u8, max_duplicate_count: MAX_DUPLICATE_COUNT) bool {
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

        pub fn init(allocator: std.mem.Allocator) Deduper(K, T) {
            // TODO
            return .{
                .num_bits = 0,
                .bits = std.ArrayList(AtomicU64).init(allocator),
                .state = [_]RandomState{.{}} ** K,
                .clock = Instant.now(),
                .popcount = AtomicU64.init(0),
            };
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
