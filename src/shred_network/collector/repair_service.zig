const std = @import("std");
const sig = @import("../../sig.zig");
const shred_network = @import("../lib.zig");
const tracy = @import("tracy");

const bincode = sig.bincode;

const Allocator = std.mem.Allocator;
const ArrayList = std.array_list.Managed;
const Atomic = std.atomic.Value;
const AutoHashMap = std.AutoHashMap;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.Random;

const ContactInfo = sig.gossip.ContactInfo;
const Counter = sig.prometheus.Counter;
const Duration = sig.time.Duration;
const Gauge = sig.prometheus.Gauge;
const GossipTable = sig.gossip.GossipTable;
const Histogram = sig.prometheus.Histogram;
const ScopedThreadPool = sig.utils.thread.ScopedThreadPool;
const LruCacheCustom = sig.utils.lru.LruCacheCustom;
const Nonce = sig.core.Nonce;
const Packet = sig.net.Packet;
const Pubkey = sig.core.Pubkey;
const Registry = sig.prometheus.Registry;
const RwMux = sig.sync.RwMux;
const SocketAddr = sig.net.SocketAddr;
const SocketThread = sig.net.SocketThread;
const Channel = sig.sync.Channel;
const Slot = sig.core.Slot;

const BasicShredTracker = shred_network.shred_tracker.BasicShredTracker;
const MissingRange = shred_network.shred_tracker.Range;
const MultiSlotReport = shred_network.shred_tracker.MultiSlotReport;
const RepairRequest = shred_network.repair_message.RepairRequest;
const RepairMessage = shred_network.repair_message.RepairMessage;

const Logger = sig.trace.Logger("repair_service");

const serializeRepairRequest = shred_network.repair_message.serializeRepairRequest;

const MAX_DATA_SHREDS_PER_SLOT = sig.ledger.shred.DataShred.constants.max_per_slot;
const EPOCH_SLOTS_DECOMPRESSED_BYTES = sig.gossip.data.MAX_SLOT_PER_ENTRY / 8;
const DEFAULT_CONTINUITY_REPAIR_PEER_FANOUT = 16;
const MAX_CONTINUITY_REPAIR_PEER_FANOUT = 2048;
const DEFAULT_MIN_STRICT_SLOT_SUPPORTED_REPAIR_PEERS = DEFAULT_CONTINUITY_REPAIR_PEER_FANOUT;
const DEFAULT_MAX_AUTOMATIC_ORPHAN_REQUESTS_PER_LOOP = 5;
const TARGET_REPAIR_DEBUG_LOG_LIMIT = 12;
const MAX_STATIC_REPAIR_PEERS = 4096;
const MAX_STATIC_REPAIR_PEERS_FILE_BYTES = 4 * 1024 * 1024;

const TargetedRepairRequestKey = struct {
    kind: enum(u8) {
        orphan,
        highest_shred,
        shred,
    },
    slot: Slot,
    index: u64,
};

/// Identifies which repairs are needed and sends them
/// - delegates to RepairPeerProvider to identify repair peers.
/// - delegates to RepairRequester to send the requests.
///
/// Analogous to [RepairService](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/core/src/repair/repair_service.rs#L245)
pub const RepairService = struct {
    allocator: Allocator,
    requester: RepairRequester,
    peer_provider: RepairPeerProvider,
    shred_tracker: *BasicShredTracker,
    ledger: *sig.ledger.Ledger,
    logger: Logger,
    exit: *Atomic(bool),
    /// memory to re-use across iterations. initialized to empty
    report: MultiSlotReport,
    thread_pool: *RequestBatchThreadPool,
    metrics: Metrics,
    prng: std.Random.DefaultPrng,
    debug_logged_repair_slots: AutoHashMap(Slot, void),
    debug_logged_assignment_slots: AutoHashMap(Slot, void),
    debug_logged_send_slots: AutoHashMap(Slot, void),
    continuity_repair_next_index_by_slot: AutoHashMap(Slot, usize),
    debug_target_slot: ?Slot,
    debug_target_assignment_log_count: usize,
    debug_target_send_log_count: usize,
    continuity_repair_slot_window: Slot,
    continuity_repair_open_ended_prefix_repairs: usize,
    continuity_repair_exact_shreds_per_slot: usize,
    continuity_repair_peer_fanout: usize,
    continuity_repair_only_bottom_slot: bool,
    continuity_repair_bottom_open_ended_prefix_repairs: usize,
    continuity_repair_bottom_exact_shreds_per_slot: usize,
    continuity_repair_bottom_peer_fanout: usize,
    continuity_repair_bottom_rotate_cursor: bool,
    targeted_repair_plan: ArrayList(RepairRequest),
    targeted_repair_plan_path: ?[]u8,
    targeted_repair_plan_file_size: u64,
    targeted_repair_plan_file_mtime: i128,
    targeted_repair_plan_reload_interval_ms: u64,
    targeted_repair_plan_last_check_ms: i64,
    targeted_repair_request_cooldown_ms: u64,
    targeted_repair_last_queued_ms: AutoHashMap(TargetedRepairRequestKey, i64),
    targeted_repair_next_index: usize,
    targeted_repair_max_per_loop: usize,
    targeted_repair_peer_fanout: usize,
    targeted_repair_pin_peer_per_slot: bool,
    targeted_repair_pinned_peers: AutoHashMap(Slot, RepairPeer),
    targeted_repair_plan_only: bool,
    targeted_repair_min_slot: ?Slot,
    targeted_repair_max_slot: ?Slot,
    max_addressed_requests_per_loop: usize,
    max_automatic_orphan_requests_per_loop: usize,
    automatic_orphan_peer_fanout: usize,

    const RequestBatchThreadPool = ScopedThreadPool(RepairRequester.sendRepairRequestBatch);

    const Metrics = struct {
        request_count: *Counter,
        oldest_slot_needing_repair: *Gauge(u64),
        newest_slot_needing_repair: *Gauge(u64),

        batch_size: *Histogram,
        batch_process_time: *Histogram,
        last_batch_size: *Gauge(u64),
        last_batch_process_time: *Gauge(f64),
        targeted_plan_request_count: *Gauge(u64),
        targeted_plan_min_slot: *Gauge(u64),
        targeted_plan_max_slot: *Gauge(u64),
        targeted_plan_reload_count: *Counter,
        targeted_plan_reload_failure_count: *Counter,
        targeted_plan_cooldown_skip_count: *Counter,
        automatic_orphan_request_count: *Counter,
        automatic_orphan_scan_failure_count: *Counter,
        automatic_orphan_requests_latest: *Gauge(u64),

        pub const prefix = "repair_service";

        pub fn histogramBucketsForField(name: []const u8) []const f64 {
            return if (std.mem.eql(u8, name, "batch_size"))
                &.{ 0, 1, 3, 10, 30, 100, 300, 1000, 3_000, 10_000, 30_000, 100_000 }
            else if (std.mem.eql(u8, name, "batch_process_time"))
                &.{ 0, 0.000_1, 0.001, 0.01, 0.1, 1, 10, 100, 1_000 }
            else
                unreachable;
        }
    };

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        exit: *Atomic(bool),
        registry: *Registry(.{}),
        requester: RepairRequester,
        peer_provider: RepairPeerProvider,
        shred_tracker: *BasicShredTracker,
        ledger: *sig.ledger.Ledger,
    ) !Self {
        const zone = tracy.Zone.init(@src(), .{ .name = "RepairService.init" });
        defer zone.deinit();

        const n_threads = maxRequesterThreads();
        const thread_pool = try RequestBatchThreadPool.init(allocator, n_threads);
        errdefer thread_pool.deinit(allocator);

        const continuity_repair_slot_window = try readEnvU64(
            allocator,
            "SIG_CONTINUITY_REPAIR_SLOT_WINDOW",
            CONTINUITY_REPAIR_SLOT_WINDOW,
        );
        const continuity_repair_open_ended_prefix_repairs = try readEnvUsize(
            allocator,
            "SIG_CONTINUITY_REPAIR_OPEN_ENDED_PREFIX_REPAIRS",
            CONTINUITY_REPAIR_OPEN_ENDED_PREFIX_REPAIRS,
        );
        const continuity_repair_exact_shreds_per_slot = try readEnvUsize(
            allocator,
            "SIG_CONTINUITY_REPAIR_EXACT_SHREDS_PER_SLOT",
            CONTINUITY_REPAIR_EXACT_SHREDS_PER_SLOT,
        );
        const continuity_repair_peer_fanout = @min(
            try readEnvUsize(
                allocator,
                "SIG_CONTINUITY_REPAIR_PEER_FANOUT",
                DEFAULT_CONTINUITY_REPAIR_PEER_FANOUT,
            ),
            MAX_CONTINUITY_REPAIR_PEER_FANOUT,
        );
        const continuity_repair_only_bottom_slot = try readEnvBool(
            allocator,
            "SIG_CONTINUITY_REPAIR_ONLY_BOTTOM_SLOT",
            false,
        );
        const continuity_repair_bottom_open_ended_prefix_repairs = try readEnvUsize(
            allocator,
            "SIG_CONTINUITY_REPAIR_BOTTOM_OPEN_ENDED_PREFIX_REPAIRS",
            continuity_repair_open_ended_prefix_repairs,
        );
        const continuity_repair_bottom_exact_shreds_per_slot = try readEnvUsize(
            allocator,
            "SIG_CONTINUITY_REPAIR_BOTTOM_EXACT_SHREDS_PER_SLOT",
            continuity_repair_exact_shreds_per_slot,
        );
        const continuity_repair_bottom_peer_fanout = @min(
            try readEnvUsize(
                allocator,
                "SIG_CONTINUITY_REPAIR_BOTTOM_PEER_FANOUT",
                continuity_repair_peer_fanout,
            ),
            MAX_CONTINUITY_REPAIR_PEER_FANOUT,
        );
        const continuity_repair_bottom_rotate_cursor = try readEnvBool(
            allocator,
            "SIG_CONTINUITY_REPAIR_BOTTOM_ROTATE_CURSOR",
            false,
        );
        const targeted_repair_max_per_loop = try readEnvUsize(
            allocator,
            "SIG_TARGETED_REPAIR_PLAN_MAX_PER_LOOP",
            4096,
        );
        const targeted_repair_peer_fanout = @min(
            try readEnvUsize(
                allocator,
                "SIG_TARGETED_REPAIR_PLAN_PEER_FANOUT",
                continuity_repair_peer_fanout,
            ),
            MAX_CONTINUITY_REPAIR_PEER_FANOUT,
        );
        const targeted_repair_pin_peer_per_slot = try readEnvBool(
            allocator,
            "SIG_TARGETED_REPAIR_PIN_PEER_PER_SLOT",
            false,
        );
        const targeted_repair_plan_only = try readEnvBool(
            allocator,
            "SIG_TARGETED_REPAIR_PLAN_ONLY",
            false,
        );
        const targeted_repair_plan_reload_interval_ms = try readEnvU64(
            allocator,
            "SIG_TARGETED_REPAIR_PLAN_RELOAD_INTERVAL_MS",
            0,
        );
        const targeted_repair_request_cooldown_ms = try readEnvU64(
            allocator,
            "SIG_TARGETED_REPAIR_REQUEST_COOLDOWN_MS",
            0,
        );
        const max_addressed_requests_per_loop = try readEnvUsize(
            allocator,
            "SIG_REPAIR_MAX_ADDRESSED_REQUESTS_PER_LOOP",
            0,
        );
        const max_automatic_orphan_requests_per_loop = try readEnvUsize(
            allocator,
            "SIG_REPAIR_MAX_AUTOMATIC_ORPHAN_REQUESTS_PER_LOOP",
            DEFAULT_MAX_AUTOMATIC_ORPHAN_REQUESTS_PER_LOOP,
        );
        const automatic_orphan_peer_fanout = @min(
            try readEnvUsize(
                allocator,
                "SIG_REPAIR_AUTOMATIC_ORPHAN_PEER_FANOUT",
                4,
            ),
            MAX_CONTINUITY_REPAIR_PEER_FANOUT,
        );

        var targeted_repair_plan = ArrayList(RepairRequest).init(allocator);
        errdefer targeted_repair_plan.deinit();
        var targeted_repair_min_slot: ?Slot = null;
        var targeted_repair_max_slot: ?Slot = null;
        var targeted_repair_plan_file_size: u64 = 0;
        var targeted_repair_plan_file_mtime: i128 = 0;
        const targeted_plan_path = try readOptionalEnvOwned(allocator, "SIG_TARGETED_REPAIR_PLAN_PATH");
        errdefer if (targeted_plan_path) |plan_path| allocator.free(plan_path);
        if (targeted_plan_path) |path| {
            const plan_stats = try loadTargetedRepairPlan(
                allocator,
                path,
                &targeted_repair_plan,
            );
            targeted_repair_min_slot = plan_stats.min_slot;
            targeted_repair_max_slot = plan_stats.max_slot;
            targeted_repair_plan_file_size = plan_stats.file_size;
            targeted_repair_plan_file_mtime = plan_stats.file_mtime;
            logger.info().logf(
                "targeted repair plan loaded path={s} request_count={} min_slot={?} max_slot={?} max_per_loop={} peer_fanout={} pin_peer_per_slot={} plan_only={} reload_interval_ms={} request_cooldown_ms={}",
                .{
                    path,
                    plan_stats.request_count,
                    plan_stats.min_slot,
                    plan_stats.max_slot,
                    targeted_repair_max_per_loop,
                    targeted_repair_peer_fanout,
                    targeted_repair_pin_peer_per_slot,
                    targeted_repair_plan_only,
                    targeted_repair_plan_reload_interval_ms,
                    targeted_repair_request_cooldown_ms,
                },
            );
        }

        const repair_jitter_seed = std.crypto.random.int(u64);

        logger.info().logf(
            "repair continuity config slot_window={} open_ended_prefix_repairs={} exact_shreds_per_slot={} peer_fanout={} only_bottom_slot={} bottom_open_ended_prefix_repairs={} bottom_exact_shreds_per_slot={} bottom_peer_fanout={} bottom_rotate_cursor={} max_addressed_requests_per_loop={} max_automatic_orphan_requests_per_loop={} automatic_orphan_peer_fanout={} max_peer_fanout={} repair_jitter_seed={}",
            .{
                continuity_repair_slot_window,
                continuity_repair_open_ended_prefix_repairs,
                continuity_repair_exact_shreds_per_slot,
                continuity_repair_peer_fanout,
                continuity_repair_only_bottom_slot,
                continuity_repair_bottom_open_ended_prefix_repairs,
                continuity_repair_bottom_exact_shreds_per_slot,
                continuity_repair_bottom_peer_fanout,
                continuity_repair_bottom_rotate_cursor,
                max_addressed_requests_per_loop,
                max_automatic_orphan_requests_per_loop,
                automatic_orphan_peer_fanout,
                MAX_CONTINUITY_REPAIR_PEER_FANOUT,
                repair_jitter_seed,
            },
        );

        const metrics = try registry.initStruct(Metrics);
        metrics.targeted_plan_request_count.set(targeted_repair_plan.items.len);
        metrics.targeted_plan_min_slot.set(targeted_repair_min_slot orelse 0);
        metrics.targeted_plan_max_slot.set(targeted_repair_max_slot orelse 0);

        return RepairService{
            .allocator = allocator,
            .requester = requester,
            .peer_provider = peer_provider,
            .shred_tracker = shred_tracker,
            .ledger = ledger,
            .logger = .from(logger),
            .exit = exit,
            .report = MultiSlotReport.init(allocator),
            .thread_pool = thread_pool,
            .metrics = metrics,
            .prng = std.Random.DefaultPrng.init(repair_jitter_seed),
            .debug_logged_repair_slots = AutoHashMap(Slot, void).init(allocator),
            .debug_logged_assignment_slots = AutoHashMap(Slot, void).init(allocator),
            .debug_logged_send_slots = AutoHashMap(Slot, void).init(allocator),
            .continuity_repair_next_index_by_slot = AutoHashMap(Slot, usize).init(allocator),
            .debug_target_slot = null,
            .debug_target_assignment_log_count = 0,
            .debug_target_send_log_count = 0,
            .continuity_repair_slot_window = continuity_repair_slot_window,
            .continuity_repair_open_ended_prefix_repairs = continuity_repair_open_ended_prefix_repairs,
            .continuity_repair_exact_shreds_per_slot = continuity_repair_exact_shreds_per_slot,
            .continuity_repair_peer_fanout = continuity_repair_peer_fanout,
            .continuity_repair_only_bottom_slot = continuity_repair_only_bottom_slot,
            .continuity_repair_bottom_open_ended_prefix_repairs = continuity_repair_bottom_open_ended_prefix_repairs,
            .continuity_repair_bottom_exact_shreds_per_slot = continuity_repair_bottom_exact_shreds_per_slot,
            .continuity_repair_bottom_peer_fanout = continuity_repair_bottom_peer_fanout,
            .continuity_repair_bottom_rotate_cursor = continuity_repair_bottom_rotate_cursor,
            .targeted_repair_plan = targeted_repair_plan,
            .targeted_repair_plan_path = targeted_plan_path,
            .targeted_repair_plan_file_size = targeted_repair_plan_file_size,
            .targeted_repair_plan_file_mtime = targeted_repair_plan_file_mtime,
            .targeted_repair_plan_reload_interval_ms = targeted_repair_plan_reload_interval_ms,
            .targeted_repair_plan_last_check_ms = std.time.milliTimestamp(),
            .targeted_repair_request_cooldown_ms = targeted_repair_request_cooldown_ms,
            .targeted_repair_last_queued_ms = AutoHashMap(TargetedRepairRequestKey, i64).init(allocator),
            .targeted_repair_next_index = 0,
            .targeted_repair_max_per_loop = targeted_repair_max_per_loop,
            .targeted_repair_peer_fanout = targeted_repair_peer_fanout,
            .targeted_repair_pin_peer_per_slot = targeted_repair_pin_peer_per_slot,
            .targeted_repair_pinned_peers = AutoHashMap(Slot, RepairPeer).init(allocator),
            .targeted_repair_plan_only = targeted_repair_plan_only,
            .targeted_repair_min_slot = targeted_repair_min_slot,
            .targeted_repair_max_slot = targeted_repair_max_slot,
            .max_addressed_requests_per_loop = max_addressed_requests_per_loop,
            .max_automatic_orphan_requests_per_loop = max_automatic_orphan_requests_per_loop,
            .automatic_orphan_peer_fanout = automatic_orphan_peer_fanout,
        };
    }

    pub fn deinit(self: *Self) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "RepairService.deinit" });
        defer zone.deinit();

        self.exit.store(true, .release);
        self.peer_provider.deinit();
        self.requester.deinit();
        self.thread_pool.deinit(self.allocator);
        self.report.deinit();
        self.debug_logged_repair_slots.deinit();
        self.debug_logged_assignment_slots.deinit();
        self.debug_logged_send_slots.deinit();
        self.continuity_repair_next_index_by_slot.deinit();
        self.targeted_repair_plan.deinit();
        self.targeted_repair_last_queued_ms.deinit();
        self.targeted_repair_pinned_peers.deinit();
        if (self.targeted_repair_plan_path) |path| self.allocator.free(path);
    }

    pub fn run(self: *Self) !void {
        var waiting_for_peers = false;
        var timer = sig.time.Timer.start();
        while (!self.exit.load(.acquire)) {
            timer.reset();
            var num_repairs_sent: usize = 0;
            if (self.sendNecessaryRepairs()) |count| {
                num_repairs_sent = count;
                if (waiting_for_peers) {
                    waiting_for_peers = false;
                    self.logger.info().logf("Acquired some repair peers.", .{});
                }
            } else |e| switch (e) {
                error.NoRepairPeers => if (!waiting_for_peers) {
                    self.logger.info().logf("Waiting for repair peers...", .{});
                    waiting_for_peers = true;
                },
                else => return e,
            }
            const last_iteration = timer.lap();

            self.metrics.batch_size.observe(num_repairs_sent);
            self.metrics.batch_process_time.observe(last_iteration.asSecsFloat());
            self.metrics.last_batch_size.set(num_repairs_sent);
            self.metrics.last_batch_process_time.set(last_iteration.asSecsFloat());

            sleepRepair(num_repairs_sent, last_iteration);
        }
    }

    /// Identifies which repairs are needed based on the current state,
    /// and sends those repairs, then returns the number of repairs.
    pub fn sendNecessaryRepairs(self: *Self) !usize {
        const zone = tracy.Zone.init(@src(), .{ .name = "sendNecessaryRepairs" });
        defer zone.deinit();

        const repair_requests = try self.getRepairs();
        defer repair_requests.deinit();
        self.metrics.request_count.add(repair_requests.items.len);
        const addressed_requests = try self.assignRequestsToPeers(repair_requests.items);
        defer addressed_requests.deinit();
        const requests_to_send = self.limitAddressedRequests(addressed_requests.items);

        if (requests_to_send.len < 4) {
            try self.requester.sendRepairRequestBatch(requests_to_send);
        } else {
            const num_threads = numRequesterThreads(requests_to_send.len);
            for (0..num_threads) |i| {
                const start = (requests_to_send.len * i) / num_threads;
                const end = (requests_to_send.len * (i + 1)) / num_threads;
                try self.thread_pool.schedule(self.allocator, .{
                    &self.requester,
                    requests_to_send[start..end],
                });
            }
            try self.thread_pool.join();
        }

        try self.logStartupRepairSendQueuedOnce(self.shred_tracker.current_bottom_slot, requests_to_send);

        return requests_to_send.len;
    }

    fn limitAddressedRequests(self: *const Self, requests: []AddressedRepairRequest) []AddressedRepairRequest {
        const limit = self.max_addressed_requests_per_loop;
        if (limit == 0 or requests.len <= limit) return requests;
        return requests[0..limit];
    }

    /// The maximum number of `.Shred` repairs to request.
    ///
    /// Supports the maximum number of shreds that could possibly be generated
    /// during a repair loop iteration. This ensures it is always possible to
    /// catch up, assuming the current hardware is powerful enough.
    const MAX_SHRED_REPAIRS = (MAX_DATA_SHREDS_PER_SLOT * MAX_REPAIR_LOOP_DURATION_TARGET.asMillis()) / 400;
    // Match the warm handoff gate: repair enough post-root slots to prove a
    // contiguous replay bridge, while MAX_SHRED_REPAIRS still caps each loop.
    const CONTINUITY_REPAIR_SLOT_WINDOW = 128;
    const CONTINUITY_REPAIR_OPEN_ENDED_PREFIX_REPAIRS = 2048;
    const CONTINUITY_REPAIR_EXACT_SHREDS_PER_SLOT = 2048;

    fn getRepairs(self: *Self) !ArrayList(RepairRequest) {
        const zone = tracy.Zone.init(@src(), .{ .name = "getRepairs" });
        defer zone.deinit();

        self.maybeReloadTargetedRepairPlan();

        var oldest_slot_needing_repair: u64 = 0;
        var newest_slot_needing_repair: u64 = 0;
        var repairs = ArrayList(RepairRequest).init(self.allocator);
        if (self.targeted_repair_plan_only) {
            _ = try self.appendTargetedRepairPlanRequests(&repairs);
            return repairs;
        }

        const automatic_orphan_count = appendAutomaticOrphanRepairRequests(
            self.ledger,
            self.shred_tracker.current_bottom_slot,
            self.max_automatic_orphan_requests_per_loop,
            &repairs,
        ) catch |err| automatic_orphan_scan_failed: {
            self.metrics.automatic_orphan_scan_failure_count.inc();
            self.logger.warn().logf(
                "automatic orphan repair scan failed start_slot={} error={s}; continuing ordinary repair",
                .{ self.shred_tracker.current_bottom_slot, @errorName(err) },
            );
            break :automatic_orphan_scan_failed 0;
        };
        self.metrics.automatic_orphan_requests_latest.set(automatic_orphan_count);
        self.metrics.automatic_orphan_request_count.add(automatic_orphan_count);
        if (automatic_orphan_count > 0) {
            const orphan_frontier = self.shred_tracker.current_bottom_slot;
            self.metrics.oldest_slot_needing_repair.set(orphan_frontier);
            self.metrics.newest_slot_needing_repair.set(orphan_frontier);
            _ = try self.appendTargetedRepairPlanRequests(&repairs);
            return repairs;
        }
        if (!try self.shred_tracker.identifyMissing(&self.report, sig.time.Instant.now())) {
            _ = try self.appendTargetedRepairPlanRequests(&repairs);
            return repairs;
        }
        var individual_count: usize = 0;
        var highest_count: usize = 0;
        var slot: Slot = 0;
        const debug_start_slot = self.shred_tracker.start_slot;
        const continuity_repair_start = self.shred_tracker.current_bottom_slot;
        const continuity_repair_slot_window = if (self.continuity_repair_only_bottom_slot)
            1
        else
            self.continuity_repair_slot_window;
        const continuity_repair_end = continuity_repair_start +| continuity_repair_slot_window;

        // request every shred that is reported missing, up to MAX_SHRED_REPAIRS
        for (self.report.items()) |*report| {
            slot = report.slot;
            oldest_slot_needing_repair = @min(slot, oldest_slot_needing_repair);
            newest_slot_needing_repair = @max(slot, newest_slot_needing_repair);
            const is_continuity_repair_slot =
                slot >= continuity_repair_start and slot < continuity_repair_end;
            const is_bottom_continuity_repair_slot = slot == continuity_repair_start;
            const exact_shreds_per_slot = if (is_bottom_continuity_repair_slot)
                self.continuity_repair_bottom_exact_shreds_per_slot
            else
                self.continuity_repair_exact_shreds_per_slot;
            const open_ended_prefix_repairs = if (is_bottom_continuity_repair_slot)
                self.continuity_repair_bottom_open_ended_prefix_repairs
            else
                self.continuity_repair_open_ended_prefix_repairs;
            var planned_shred_requests_for_slot: usize = 0;
            var first_planned_index: ?usize = null;
            var last_planned_index: ?usize = null;
            if (individual_count < MAX_SHRED_REPAIRS and is_continuity_repair_slot) {
                const rotate_bottom_cursor =
                    is_bottom_continuity_repair_slot and self.continuity_repair_bottom_rotate_cursor;
                const repair_cursor = if (is_bottom_continuity_repair_slot and !rotate_bottom_cursor)
                    0
                else
                    self.continuity_repair_next_index_by_slot.get(slot) orelse 0;
                const planned_exact_from_cursor = try appendExactRepairsFromCursor(
                    &repairs,
                    slot,
                    report.missing_shreds.items,
                    repair_cursor,
                    exact_shreds_per_slot,
                    &individual_count,
                    &planned_shred_requests_for_slot,
                    &first_planned_index,
                    &last_planned_index,
                );
                if (planned_exact_from_cursor == 0 and repair_cursor != 0) {
                    _ = try appendExactRepairsFromCursor(
                        &repairs,
                        slot,
                        report.missing_shreds.items,
                        0,
                        exact_shreds_per_slot,
                        &individual_count,
                        &planned_shred_requests_for_slot,
                        &first_planned_index,
                        &last_planned_index,
                    );
                }
                if (last_planned_index) |last| {
                    if (is_bottom_continuity_repair_slot and !rotate_bottom_cursor) {
                        _ = self.continuity_repair_next_index_by_slot.remove(slot);
                    } else {
                        const next_index = if (last + 1 >= MAX_DATA_SHREDS_PER_SLOT) 0 else last + 1;
                        try self.continuity_repair_next_index_by_slot.put(slot, next_index);
                    }
                } else {
                    _ = self.continuity_repair_next_index_by_slot.remove(slot);
                }

                for (report.missing_shreds.items) |shred_window| mid_loop: {
                    if (shred_window.end == null) {
                        const start: usize = shred_window.start;
                        const end: u32 = @intCast(@min(
                            start + open_ended_prefix_repairs,
                            MAX_DATA_SHREDS_PER_SLOT,
                        ));
                        for (shred_window.start..end) |i| {
                            if (individual_count >= MAX_SHRED_REPAIRS) break :mid_loop;
                            individual_count += 1;
                            planned_shred_requests_for_slot += 1;
                            if (first_planned_index == null) first_planned_index = i;
                            last_planned_index = i;
                            try repairs.append(.{ .Shred = .{ slot, i } });
                        }
                    }
                }
            }
            if (debug_start_slot) |start_slot| {
                if (slot >= start_slot and slot <= start_slot +| 128) {
                    try self.logStartupRepairReportOnce(
                        start_slot,
                        report,
                        is_continuity_repair_slot,
                        planned_shred_requests_for_slot,
                        first_planned_index,
                        last_planned_index,
                    );
                }
            }
            highest_count += 1;
            try repairs.append(.{ .HighestShred = .{ slot, 0 } });
        }

        // eagerly request the next unknown slot in case turbine is laggy
        try repairs.append(.{ .HighestShred = .{ slot + 1, 0 } });

        // request ahead to detect if caught behind. use jitter to avoid skipped slots
        const num_slots_ahead = self.prng.random().intRangeAtMost(u32, 10, 50);
        try repairs.append(.{ .HighestShred = .{ slot + num_slots_ahead, 0 } });

        _ = try self.appendTargetedRepairPlanRequests(&repairs);

        self.metrics.oldest_slot_needing_repair.set(oldest_slot_needing_repair);
        self.metrics.newest_slot_needing_repair.set(newest_slot_needing_repair);

        return repairs;
    }

    fn appendTargetedRepairPlanRequests(self: *Self, repairs: *ArrayList(RepairRequest)) !usize {
        if (self.targeted_repair_plan.items.len == 0 or self.targeted_repair_max_per_loop == 0) {
            return 0;
        }

        const limit = @min(self.targeted_repair_max_per_loop, self.targeted_repair_plan.items.len);
        const now_ms = std.time.milliTimestamp();
        var appended: usize = 0;
        for (0..limit) |offset| {
            const index = (self.targeted_repair_next_index + offset) % self.targeted_repair_plan.items.len;
            const request = self.targeted_repair_plan.items[index];
            if (!try targetedRepairCooldownAllows(
                &self.targeted_repair_last_queued_ms,
                request,
                now_ms,
                self.targeted_repair_request_cooldown_ms,
            )) {
                self.metrics.targeted_plan_cooldown_skip_count.inc();
                continue;
            }
            try repairs.append(request);
            appended += 1;
        }
        self.targeted_repair_next_index =
            (self.targeted_repair_next_index + limit) % self.targeted_repair_plan.items.len;
        return appended;
    }

    fn maybeReloadTargetedRepairPlan(self: *Self) void {
        const reload_interval_ms = self.targeted_repair_plan_reload_interval_ms;
        if (reload_interval_ms == 0) return;
        const plan_path = self.targeted_repair_plan_path orelse return;

        const now_ms = std.time.milliTimestamp();
        const elapsed_ms = now_ms - self.targeted_repair_plan_last_check_ms;
        if (elapsed_ms >= 0 and @as(u64, @intCast(elapsed_ms)) < reload_interval_ms) return;
        self.targeted_repair_plan_last_check_ms = now_ms;

        const file_stats = statTargetedRepairPlanFile(plan_path) catch |err| {
            self.metrics.targeted_plan_reload_failure_count.inc();
            self.logger.warn().logf(
                "targeted repair plan reload stat failed path={s} error={s}; retaining current plan",
                .{ plan_path, @errorName(err) },
            );
            return;
        };
        if (!targetedRepairPlanFileChanged(
            self.targeted_repair_plan_file_size,
            self.targeted_repair_plan_file_mtime,
            file_stats.size,
            file_stats.mtime,
        )) return;

        var next_plan = ArrayList(RepairRequest).init(self.allocator);
        const plan_stats = loadTargetedRepairPlan(
            self.allocator,
            plan_path,
            &next_plan,
        ) catch |err| {
            next_plan.deinit();
            self.metrics.targeted_plan_reload_failure_count.inc();
            self.logger.warn().logf(
                "targeted repair plan reload failed path={s} error={s}; retaining current plan",
                .{ plan_path, @errorName(err) },
            );
            return;
        };

        const retained_cooldown_count = retainTargetedRepairCooldownEntries(
            self.allocator,
            &self.targeted_repair_last_queued_ms,
            next_plan.items,
        ) catch |err| {
            next_plan.deinit();
            self.metrics.targeted_plan_reload_failure_count.inc();
            self.logger.warn().logf(
                "targeted repair plan reload cooldown retention failed path={s} error={s}; retaining current plan",
                .{ plan_path, @errorName(err) },
            );
            return;
        };

        self.targeted_repair_plan.deinit();
        self.targeted_repair_plan = next_plan;
        self.targeted_repair_next_index = 0;
        self.targeted_repair_min_slot = plan_stats.min_slot;
        self.targeted_repair_max_slot = plan_stats.max_slot;
        self.targeted_repair_plan_file_size = plan_stats.file_size;
        self.targeted_repair_plan_file_mtime = plan_stats.file_mtime;
        self.metrics.targeted_plan_request_count.set(plan_stats.request_count);
        self.metrics.targeted_plan_min_slot.set(plan_stats.min_slot orelse 0);
        self.metrics.targeted_plan_max_slot.set(plan_stats.max_slot orelse 0);
        self.metrics.targeted_plan_reload_count.inc();
        self.logger.warn().logf(
            "targeted repair plan reloaded path={s} request_count={} min_slot={?} max_slot={?} reload_interval_ms={} retained_cooldown_count={}",
            .{
                plan_path,
                plan_stats.request_count,
                plan_stats.min_slot,
                plan_stats.max_slot,
                reload_interval_ms,
                retained_cooldown_count,
            },
        );
    }

    fn isTargetedRepairPlanSlot(self: *const Self, slot: Slot) bool {
        if (self.targeted_repair_plan.items.len == 0) return false;
        const min_slot = self.targeted_repair_min_slot orelse return false;
        const max_slot = self.targeted_repair_max_slot orelse return false;
        return slot >= min_slot and slot <= max_slot;
    }

    fn logStartupRepairReportOnce(
        self: *Self,
        start_slot: Slot,
        report: *const shred_network.shred_tracker.SlotReport,
        is_continuity_repair_slot: bool,
        planned_shred_requests_for_slot: usize,
        first_planned_index: ?usize,
        last_planned_index: ?usize,
    ) !void {
        const gop = try self.debug_logged_repair_slots.getOrPut(report.slot);
        if (gop.found_existing) return;

        const sample_len = @min(report.missing_shreds.items.len, 8);
        var bounded_missing_count: usize = 0;
        var open_ended_windows: usize = 0;
        for (report.missing_shreds.items) |window| {
            if (window.end) |end| {
                bounded_missing_count += end -| window.start;
            } else {
                open_ended_windows += 1;
            }
        }
        self.logger.info().logf(
            "startup repair report slot={} tracker_start_slot={} continuity_slot={} missing_windows={} bounded_missing_count={} open_ended_windows={} planned_shred_requests={} first_planned_index={?} last_planned_index={?} sample={any}",
            .{
                report.slot,
                start_slot,
                is_continuity_repair_slot,
                report.missing_shreds.items.len,
                bounded_missing_count,
                open_ended_windows,
                planned_shred_requests_for_slot,
                first_planned_index,
                last_planned_index,
                report.missing_shreds.items[0..sample_len],
            },
        );
    }

    fn assignRequestsToPeers(
        self: *Self,
        requests: []const RepairRequest,
    ) !ArrayList(AddressedRepairRequest) {
        const zone = tracy.Zone.init(@src(), .{ .name = "assignRequestsToPeers" });
        defer zone.deinit();

        var addressed = ArrayList(AddressedRepairRequest).init(self.allocator);
        const debug_target_slot = self.shred_tracker.current_bottom_slot;
        self.resetDebugTargetSlotIfChanged(debug_target_slot);
        var debug_target_shred_requests: usize = 0;
        var debug_target_addressed_requests: usize = 0;
        var debug_target_zero_peer_requests: usize = 0;
        var debug_target_highest_requests: usize = 0;
        var debug_target_peer_samples: [8]RepairPeer = undefined;
        var debug_target_peer_sample_count: usize = 0;
        var debug_target_max_selected_peers: usize = 0;
        for (requests) |request| {
            const request_slot = request.slot();
            const is_targeted_repair_plan_slot = self.isTargetedRepairPlanSlot(request_slot);
            const is_automatic_orphan = switch (request) {
                .orphan => !is_targeted_repair_plan_slot,
                else => false,
            };
            const is_continuity_repair =
                request_slot >= self.shred_tracker.current_bottom_slot and
                request_slot < self.shred_tracker.current_bottom_slot +|
                    if (self.continuity_repair_only_bottom_slot)
                        1
                    else
                        self.continuity_repair_slot_window;
            const peer_fanout: usize = if (is_targeted_repair_plan_slot)
                self.targeted_repair_peer_fanout
            else if (is_automatic_orphan)
                self.automatic_orphan_peer_fanout
            else if (is_continuity_repair)
                if (request_slot == self.shred_tracker.current_bottom_slot)
                    self.continuity_repair_bottom_peer_fanout
                else
                    self.continuity_repair_peer_fanout
            else
                1;
            var peers_buf: [MAX_CONTINUITY_REPAIR_PEER_FANOUT]RepairPeer = undefined;
            const selected_peers = if (is_targeted_repair_plan_slot and
                self.targeted_repair_pin_peer_per_slot)
            pinned: {
                if (self.targeted_repair_pinned_peers.get(request_slot)) |peer| {
                    peers_buf[0] = peer;
                    break :pinned peers_buf[0..1];
                }

                const peers = try self.peer_provider.getRandomPeers(request_slot, 1, &peers_buf);
                if (peers.len == 1) {
                    try self.targeted_repair_pinned_peers.put(request_slot, peers[0]);
                    self.logger.info().logf(
                        "targeted repair peer pinned slot={} peer={f} socket={f}",
                        .{ request_slot, peers[0].pubkey, peers[0].serve_repair_socket },
                    );
                }
                break :pinned peers;
            } else try self.peer_provider.getRandomPeers(request_slot, peer_fanout, &peers_buf);
            if (request.slot() == debug_target_slot) {
                switch (request) {
                    .Shred => {
                        debug_target_shred_requests += 1;
                        debug_target_addressed_requests += selected_peers.len;
                        debug_target_max_selected_peers = @max(
                            debug_target_max_selected_peers,
                            selected_peers.len,
                        );
                        if (selected_peers.len == 0) debug_target_zero_peer_requests += 1;
                        for (selected_peers) |peer| {
                            if (debug_target_peer_sample_count >= debug_target_peer_samples.len) break;
                            debug_target_peer_samples[debug_target_peer_sample_count] = peer;
                            debug_target_peer_sample_count += 1;
                        }
                    },
                    .HighestShred => debug_target_highest_requests += 1,
                    else => {},
                }
            }
            for (selected_peers) |peer| {
                try addressed.append(.{
                    .request = request,
                    .recipient = peer.pubkey,
                    .recipient_addr = peer.serve_repair_socket,
                });
            }
            // TODO do something if a peer is not found?
        }
        if ((debug_target_shred_requests > 0 or debug_target_highest_requests > 0) and
            self.debug_target_assignment_log_count < TARGET_REPAIR_DEBUG_LOG_LIMIT)
        {
            self.debug_target_assignment_log_count += 1;
            const peer_stats = self.peer_provider.getPeerStats(debug_target_slot) catch null;
            const peer_stats_available = peer_stats != null;
            const peer_total = if (peer_stats) |stats| stats.total_count else 0;
            const peer_strict = if (peer_stats) |stats| stats.strict_count else 0;
            const peer_preferred = if (peer_stats) |stats| stats.preferred_count else 0;
            const peer_unclear = if (peer_stats) |stats| stats.unclear_count else 0;
            self.logger.info().logf(
                "startup repair assignment slot={} report_index={} shred_requests={} addressed_requests={} zero_peer_requests={} highest_requests={} max_selected_peers={} peer_stats_available={} peer_total={} peer_strict={} peer_preferred={} peer_unclear={} sample_peer_count={} sample_peers={any}",
                .{
                    debug_target_slot,
                    self.debug_target_assignment_log_count,
                    debug_target_shred_requests,
                    debug_target_addressed_requests,
                    debug_target_zero_peer_requests,
                    debug_target_highest_requests,
                    debug_target_max_selected_peers,
                    peer_stats_available,
                    peer_total,
                    peer_strict,
                    peer_preferred,
                    peer_unclear,
                    debug_target_peer_sample_count,
                    debug_target_peer_samples[0..debug_target_peer_sample_count],
                },
            );
        }
        return addressed;
    }

    fn resetDebugTargetSlotIfChanged(self: *Self, slot: Slot) void {
        if (self.debug_target_slot) |current_slot| {
            if (current_slot == slot) return;
        }

        self.debug_target_slot = slot;
        self.debug_target_assignment_log_count = 0;
        self.debug_target_send_log_count = 0;
    }

    fn logStartupRepairSendQueuedOnce(
        self: *Self,
        target_slot: Slot,
        addressed_requests: []const AddressedRepairRequest,
    ) !void {
        var addressed_shred_requests: usize = 0;
        var first_index: ?u64 = null;
        var last_index: ?u64 = null;
        var sample_addrs: [8]SocketAddr = undefined;
        var sample_addr_count: usize = 0;

        for (addressed_requests) |addressed| {
            switch (addressed.request) {
                .Shred => |repair| {
                    if (repair[0] != target_slot) continue;
                    addressed_shred_requests += 1;
                    const index = repair[1];
                    if (first_index == null or index < first_index.?) first_index = index;
                    if (last_index == null or index > last_index.?) last_index = index;
                    if (sample_addr_count < sample_addrs.len) {
                        sample_addrs[sample_addr_count] = addressed.recipient_addr;
                        sample_addr_count += 1;
                    }
                },
                else => {},
            }
        }

        if (addressed_shred_requests == 0) return;

        if (self.debug_target_send_log_count >= TARGET_REPAIR_DEBUG_LOG_LIMIT) return;
        self.debug_target_send_log_count += 1;

        self.logger.info().logf(
            "startup repair send queued slot={} report_index={} addressed_shred_requests={} first_index={?} last_index={?} sample_addr_count={} sample_addrs={any}",
            .{
                target_slot,
                self.debug_target_send_log_count,
                addressed_shred_requests,
                first_index,
                last_index,
                sample_addr_count,
                sample_addrs[0..sample_addr_count],
            },
        );
    }
};

/// Requests the recorded orphan frontier directly from the ledger. A normal
/// highest-shred request cannot discover a missing ancestor chain when later
/// descendants are already present, so the tracker otherwise retries the same
/// empty slots indefinitely. Keep this bounded like Agave's orphan repair
/// pass; once a returned ancestor is inserted, ledger chaining removes the
/// corresponding orphan row and the next loop naturally moves forward.
fn appendAutomaticOrphanRepairRequests(
    ledger: *sig.ledger.Ledger,
    start_slot: Slot,
    max_requests: usize,
    repairs: *ArrayList(RepairRequest),
) !usize {
    if (max_requests == 0) return 0;

    var orphan_iter = try ledger.db.iterator(
        sig.ledger.schema.schema.orphan_slots,
        .forward,
        start_slot,
    );
    defer orphan_iter.deinit();

    var appended: usize = 0;
    while (appended < max_requests) {
        const orphan_slot = (try orphan_iter.nextKey()) orelse break;
        if (orphan_slot < start_slot) continue;
        try repairs.append(.{ .orphan = orphan_slot });
        appended += 1;
    }
    return appended;
}

test "automatic orphan repair requests are ordered and bounded" {
    const allocator = std.testing.allocator;
    var ledger, var ledger_dir = try sig.ledger.Ledger.initForTest(allocator);
    defer ledger_dir.cleanup();
    defer ledger.deinit();

    const orphan_slots = sig.ledger.schema.schema.orphan_slots;
    try ledger.db.put(orphan_slots, 99, true);
    try ledger.db.put(orphan_slots, 102, true);
    try ledger.db.put(orphan_slots, 103, true);
    try ledger.db.put(orphan_slots, 104, true);

    var repairs = ArrayList(RepairRequest).init(allocator);
    defer repairs.deinit();
    try std.testing.expectEqual(
        2,
        try appendAutomaticOrphanRepairRequests(&ledger, 100, 2, &repairs),
    );
    try std.testing.expectEqual(2, repairs.items.len);
    try std.testing.expectEqual(RepairRequest{ .orphan = 102 }, repairs.items[0]);
    try std.testing.expectEqual(RepairRequest{ .orphan = 103 }, repairs.items[1]);
}

/// Returns the number of threads that should be used to send this many repair
/// requests.
///
/// Allows the number of repair requester threads to scale up when a lot of
/// repairs are necessary, and scale down during normal operation.
fn numRequesterThreads(num_requests: usize) usize {
    // serialising a repair request takes approx 50us
    const target_requests_per_thread = 20000;

    const target_threads = num_requests / target_requests_per_thread;
    return @max(1, @min(target_threads, maxRequesterThreads()));
}

/// Sets the maximum number of repair threads to either 16 or half the cpu
/// count, whatever is less.
fn maxRequesterThreads() u32 {
    // Fast enough for sending ~60K requests/second in testing. We can tweak this later, but this
    // will likely require either a) making our packet sender faster, or b) adding backpressure to
    // our channels. Currently too many threads will overwhelm our request sender thread, and cause
    // its channel to grow indefinitely.

    return 4;
}

const TargetedRepairPlanStats = struct {
    request_count: usize = 0,
    min_slot: ?Slot = null,
    max_slot: ?Slot = null,
    file_size: u64 = 0,
    file_mtime: i128 = 0,
};

const TargetedRepairPlanFileStats = struct {
    size: u64,
    mtime: i128,
};

fn readOptionalEnvOwned(allocator: Allocator, key: []const u8) !?[]u8 {
    return std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => err,
    };
}

fn openRepairPlanFile(path: []const u8) !std.fs.File {
    if (std.fs.path.isAbsolute(path)) {
        return try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    }
    return try std.fs.cwd().openFile(path, .{ .mode = .read_only });
}

fn statTargetedRepairPlanFile(path: []const u8) !TargetedRepairPlanFileStats {
    var file = try openRepairPlanFile(path);
    defer file.close();
    const file_stats = try file.stat();
    return .{ .size = file_stats.size, .mtime = file_stats.mtime };
}

fn targetedRepairPlanFileChanged(
    current_size: u64,
    current_mtime: i128,
    next_size: u64,
    next_mtime: i128,
) bool {
    return current_size != next_size or current_mtime != next_mtime;
}

fn targetedRepairRequestKey(request: RepairRequest) TargetedRepairRequestKey {
    return switch (request) {
        .orphan => |slot| .{
            .kind = .orphan,
            .slot = slot,
            .index = 0,
        },
        .HighestShred => |value| .{
            .kind = .highest_shred,
            .slot = value[0],
            .index = value[1],
        },
        .Shred => |value| .{
            .kind = .shred,
            .slot = value[0],
            .index = value[1],
        },
    };
}

fn retainTargetedRepairCooldownEntries(
    allocator: Allocator,
    last_queued_ms: *AutoHashMap(TargetedRepairRequestKey, i64),
    active_requests: []const RepairRequest,
) !usize {
    var retained = AutoHashMap(TargetedRepairRequestKey, i64).init(allocator);
    errdefer retained.deinit();

    for (active_requests) |request| {
        const key = targetedRepairRequestKey(request);
        if (last_queued_ms.get(key)) |queued_ms| {
            try retained.put(key, queued_ms);
        }
    }

    const retained_count = retained.count();
    last_queued_ms.deinit();
    last_queued_ms.* = retained;
    return retained_count;
}

fn targetedRepairCooldownAllows(
    last_queued_ms: *AutoHashMap(TargetedRepairRequestKey, i64),
    request: RepairRequest,
    now_ms: i64,
    cooldown_ms: u64,
) !bool {
    if (cooldown_ms == 0) return true;

    const key = targetedRepairRequestKey(request);
    if (last_queued_ms.get(key)) |last_ms| {
        const elapsed_ms = now_ms - last_ms;
        if (elapsed_ms >= 0 and @as(u64, @intCast(elapsed_ms)) < cooldown_ms) {
            return false;
        }
    }
    try last_queued_ms.put(key, now_ms);
    return true;
}

fn parseTargetedRepairPlanLine(line: []const u8) !?RepairRequest {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] == '#') return null;

    var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
    const record_type = tokens.next() orelse return null;
    const is_data_shred = std.mem.eql(u8, record_type, "repair_data_shred");
    const is_highest_shred = std.mem.eql(u8, record_type, "repair_highest_shred");
    const is_orphan = std.mem.eql(u8, record_type, "repair_orphan");
    if (!is_data_shred and !is_highest_shred and !is_orphan) return null;

    var slot: ?Slot = null;
    var index: ?u64 = null;
    while (tokens.next()) |token| {
        const sep = std.mem.indexOfScalar(u8, token, '=') orelse continue;
        const key = token[0..sep];
        const value = token[sep + 1 ..];
        if (std.mem.eql(u8, key, "slot")) {
            slot = try std.fmt.parseUnsigned(Slot, value, 10);
        } else if (std.mem.eql(u8, key, "index")) {
            index = try std.fmt.parseUnsigned(u64, value, 10);
        }
    }

    const request_slot = slot orelse return error.MissingTargetedRepairSlot;
    if (is_orphan) return .{ .orphan = request_slot };
    const request_index = index orelse return error.MissingTargetedRepairIndex;
    if (is_highest_shred) {
        return .{ .HighestShred = .{ request_slot, request_index } };
    }
    return .{ .Shred = .{ request_slot, request_index } };
}

fn loadTargetedRepairPlan(
    allocator: Allocator,
    path: []const u8,
    requests: *ArrayList(RepairRequest),
) !TargetedRepairPlanStats {
    var file = try openRepairPlanFile(path);
    defer file.close();

    const file_stats = try file.stat();

    const contents = try file.readToEndAlloc(allocator, 64 * 1024 * 1024);
    defer allocator.free(contents);

    var stats: TargetedRepairPlanStats = .{
        .file_size = file_stats.size,
        .file_mtime = file_stats.mtime,
    };
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        const request = (try parseTargetedRepairPlanLine(line)) orelse continue;
        try requests.append(request);
        const slot = request.slot();
        stats.request_count += 1;
        stats.min_slot = if (stats.min_slot) |current| @min(current, slot) else slot;
        stats.max_slot = if (stats.max_slot) |current| @max(current, slot) else slot;
    }
    return stats;
}

fn readEnvU64(allocator: Allocator, key: []const u8, default_value: u64) !u64 {
    const raw = std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return default_value,
        else => return err,
    };
    defer allocator.free(raw);
    return try std.fmt.parseUnsigned(u64, raw, 10);
}

fn readEnvUsize(allocator: Allocator, key: []const u8, default_value: usize) !usize {
    const raw = std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return default_value,
        else => return err,
    };
    defer allocator.free(raw);
    return try std.fmt.parseUnsigned(usize, raw, 10);
}

fn readEnvBool(allocator: Allocator, key: []const u8, default_value: bool) !bool {
    const raw = std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return default_value,
        else => return err,
    };
    defer allocator.free(raw);

    if (std.mem.eql(u8, raw, "1") or
        std.ascii.eqlIgnoreCase(raw, "true") or
        std.ascii.eqlIgnoreCase(raw, "yes"))
    {
        return true;
    }
    if (std.mem.eql(u8, raw, "0") or
        std.ascii.eqlIgnoreCase(raw, "false") or
        std.ascii.eqlIgnoreCase(raw, "no"))
    {
        return false;
    }
    return error.InvalidBooleanEnvironmentVariable;
}

fn boundedRepairWindowEnd(start: usize, end: usize, limit: usize) usize {
    return @min(end, start +| limit);
}

fn appendExactRepairsFromCursor(
    repairs: *ArrayList(RepairRequest),
    slot: Slot,
    windows: []const MissingRange,
    cursor: usize,
    limit: usize,
    individual_count: *usize,
    planned_shred_requests_for_slot: *usize,
    first_planned_index: *?usize,
    last_planned_index: *?usize,
) !usize {
    var planned_exact: usize = 0;
    for (windows) |window| {
        if (planned_exact >= limit or individual_count.* >= RepairService.MAX_SHRED_REPAIRS) break;
        const window_end = window.end orelse continue;
        const repair_start = @max(@as(usize, window.start), cursor);
        if (repair_start >= window_end) continue;
        const repair_end = boundedRepairWindowEnd(
            repair_start,
            window_end,
            @min(limit - planned_exact, RepairService.MAX_SHRED_REPAIRS - individual_count.*),
        );
        for (repair_start..repair_end) |i| {
            individual_count.* += 1;
            planned_exact += 1;
            planned_shred_requests_for_slot.* += 1;
            if (first_planned_index.* == null) first_planned_index.* = i;
            last_planned_index.* = i;
            try repairs.append(.{ .Shred = .{ slot, i } });
        }
    }
    return planned_exact;
}

/// Sleeps an appropriate duration after sending some repair requests.
///
/// This avoids sending massive numbers of redundant requests when we're far
/// behind, while allowing low latency to fill small gaps when we're caught up.
/// It also ensures the repair service does not hog resources 100% of the time,
/// so turbine can get a chance to start keeping up on its own.
///
/// The numbers and logic here are somewhat arbitrary, but this was tuned to
/// work well during testing and should not be modified without thorough
/// testing. If the thread allocation strategy for the repair service changes
/// dramatically, it will likely make sense to revise this sleeping approach.
fn sleepRepair(num_requests: u64, last_iteration: Duration) void {
    // time we'd like the entire loop to take for this number of repairs
    const target = Duration.fromMillis(num_requests / 8);
    const bounded = target.min(MAX_REPAIR_LOOP_DURATION_TARGET).max(MIN_REPAIR_LOOP_DURATION);

    // amount of time to sleep after last_iteration to reach the target
    const remaining_sleep_for_target = bounded.saturatingSub(last_iteration);

    // if overwhelmed by generating many repair requests, this ensures there is
    // a pause between them to dedicate more CPU to process some incoming
    // shreds. This supplements MIN_REPAIR_DELAY to ensure repairs are actively
    // being processed no more than 80% of the time.
    const take_a_break = last_iteration.div(4);

    std.Thread.sleep(remaining_sleep_for_target.max(MIN_REPAIR_DELAY).max(take_a_break).asNanos());
}

/// The maximum time that we want the repair loop to take.
///
/// This could be exceeded if it takes longer to actually send the repair
/// requests. But otherwise this is the maximum loop duration that we'll target
/// with the sleeps.
///
/// This is sort of like a timeout for repair responses. After 1 second, we
/// should have gotten all the repairs, and there's no need to delay sending
/// more requests.
const MAX_REPAIR_LOOP_DURATION_TARGET = Duration.fromSecs(1);

/// Ensures the full repair loop doesn't repeat more often than this.
const MIN_REPAIR_LOOP_DURATION = Duration.fromMillis(200);

/// Ensures the repair loop always sleeps for some time to do other work between
/// repairs.
const MIN_REPAIR_DELAY = Duration.fromMillis(100);

/// Signs and serializes repair requests. Sends them over the network.
pub const RepairRequester = struct {
    allocator: Allocator,
    logger: Logger,
    random: Random,
    keypair: *const KeyPair,
    sender_thread: *SocketThread,
    sender_channel: *Channel(Packet),
    metrics: Metrics,

    const Self = @This();

    const Metrics = struct {
        sent_request_count: *Counter,
        pending_requests: *Gauge(u64),

        pub const prefix = "repair";
    };

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        random: Random,
        registry: *Registry(.{}),
        keypair: *const KeyPair,
        udp_send_socket: sig.net.UdpSocket,
        exit: *Atomic(bool),
    ) !Self {
        const channel = try Channel(Packet).create(allocator);
        channel.name = "repair requester channel(Packet)";
        errdefer channel.destroy();

        const thread = try SocketThread.spawnSender(
            allocator,
            .from(logger),
            udp_send_socket,
            channel,
            .{ .unordered = exit },
            .empty,
        );

        thread.handle.setName("repreq spwnSndr") catch {};

        return .{
            .allocator = allocator,
            .logger = .from(logger),
            .random = random,
            .keypair = keypair,
            .sender_thread = thread,
            .sender_channel = channel,
            .metrics = try registry.initStruct(Metrics),
        };
    }

    pub fn deinit(self: Self) void {
        self.sender_thread.join();
        self.sender_channel.destroy();
    }

    pub fn sendRepairRequestBatch(
        self: *const Self,
        requests: []const AddressedRepairRequest,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "sendRepairRequestBatch" });
        defer zone.deinit();

        self.metrics.pending_requests.add(requests.len);
        defer self.metrics.pending_requests.set(0);
        const timestamp = std.time.milliTimestamp();
        for (requests) |request| {
            var packet: Packet = .{
                .addr = request.recipient_addr,
                .buffer = undefined,
                .size = undefined,
                .flags = .{},
            };
            const data = try serializeRepairRequest(
                &packet.buffer,
                request.request,
                self.keypair,
                request.recipient,
                @intCast(timestamp),
                self.random.int(Nonce),
            );
            packet.size = data.len;
            try self.sender_channel.send(packet);
            self.metrics.pending_requests.dec();
            self.metrics.sent_request_count.inc();
        }
    }
};

/// A repair request plus its destination.
pub const AddressedRepairRequest = struct {
    request: RepairRequest,
    recipient: Pubkey,
    recipient_addr: SocketAddr,
};

/// How many slots to cache in RepairPeerProvider
const REPAIR_PEERS_CACHE_CAPACITY: usize = 8;
/// Maximum age of a cache item to use for repair peers
const REPAIR_PEERS_CACHE_TTL_SECONDS: u64 = 10;

/// A node that can service a repair request.
pub const RepairPeer = struct {
    pubkey: Pubkey,
    serve_repair_socket: SocketAddr,
};

const StaticRepairPeer = struct {
    peer: RepairPeer,
    shred_version: u16,
};

/// Provides peers that repair requests can be sent to.
///
/// TODO benchmark the performance of some alternate approaches, for example:
/// - directly grab a single random peer from gossip instead
///      of the entire list (good if we don't access a slot many times)
/// - single sorted cache for all slots with a binary search to filter by slot
///     - upside is fewer table locks
///     - good if we're mainly looking at older slots, not the last few slots
///     - downside is it may get stale and not represent the latest slots,
///         unless cache TTL is reduced to less than 1 slot duration, in which
///         case it may defeat the purpose of this approach.
/// The key for these benchmarks is to understand the actual repair requests that
/// are being requested on mainnet. There are trade-offs for different kinds
/// of requests. Naive benchmarks will optimize the wrong behaviors.
pub const RepairPeerProvider = struct {
    allocator: Allocator,
    random: Random,
    gossip_table_rw: *RwMux(GossipTable),
    epoch_tracker: *sig.core.EpochTracker,
    cache: LruCacheCustom(.non_locking, Slot, RepairPeers, Allocator, RepairPeers.deinit),
    my_pubkey: Pubkey,
    my_shred_version: *const Atomic(u16),
    min_strict_slot_supported_repair_peers: usize,
    include_unclear_peers_when_slot_supported: bool,
    static_peers: []StaticRepairPeer,
    metrics: Metrics,

    pub const Metrics = struct {
        latest_count_from_gossip: *Gauge(u64),
        latest_slot_supported_count_from_gossip: *Gauge(u64),
        latest_slot_support_unavailable_count_from_gossip: *Gauge(u64),
        configured_static_count: *Gauge(u64),
        latest_count_from_static: *Gauge(u64),
        latest_shred_version_mismatch_count_from_static: *Gauge(u64),
        cache_hit_count: *Counter,
        cache_miss_count: *Counter,
        cache_expired_count: *Counter,

        pub const prefix = "repair_peers";
    };

    const Self = @This();

    const RepairPeers = struct {
        insertion_time_secs: u64,
        peers: []RepairPeer,
        strict_count: usize,
        preferred_count: usize,
        unclear_count: usize,

        fn deinit(self: *@This(), allocator: Allocator) void {
            allocator.free(self.peers);
        }
    };

    const RepairPeersView = struct {
        peers: []RepairPeer,
        strict_count: usize,
        preferred_count: usize,
        unclear_count: usize,
    };

    pub const RepairPeerStats = struct {
        total_count: usize,
        strict_count: usize,
        preferred_count: usize,
        unclear_count: usize,
    };

    pub fn init(
        allocator: Allocator,
        random: Random,
        registry: *Registry(.{}),
        gossip: *RwMux(GossipTable),
        epoch_tracker: *sig.core.EpochTracker,
        my_pubkey: Pubkey,
        my_shred_version: *const Atomic(u16),
    ) !RepairPeerProvider {
        const min_strict_slot_supported_repair_peers = try readEnvUsize(
            allocator,
            "SIG_REPAIR_MIN_STRICT_SLOT_SUPPORTED_PEERS",
            DEFAULT_MIN_STRICT_SLOT_SUPPORTED_REPAIR_PEERS,
        );
        const include_unclear_peers_when_slot_supported = try readEnvBool(
            allocator,
            "SIG_REPAIR_INCLUDE_UNCLEAR_PEERS",
            false,
        );
        const static_peers = try loadStaticRepairPeersFromEnv(allocator);
        errdefer allocator.free(static_peers);
        var provider: RepairPeerProvider = .{
            .allocator = allocator,
            .gossip_table_rw = gossip,
            .epoch_tracker = epoch_tracker,
            .cache = try LruCacheCustom(.non_locking, Slot, RepairPeers, Allocator, RepairPeers.deinit)
                .initWithContext(allocator, REPAIR_PEERS_CACHE_CAPACITY, allocator),
            .my_pubkey = my_pubkey,
            .my_shred_version = my_shred_version,
            .min_strict_slot_supported_repair_peers = min_strict_slot_supported_repair_peers,
            .include_unclear_peers_when_slot_supported = include_unclear_peers_when_slot_supported,
            .static_peers = static_peers,
            .metrics = try registry.initStruct(Metrics),
            .random = random,
        };
        provider.metrics.configured_static_count.set(static_peers.len);
        return provider;
    }

    pub fn deinit(self: *Self) void {
        self.cache.deinit();
        self.allocator.free(self.static_peers);
    }

    pub const Error = error{
        /// There are no known peers at all that could handle any repair
        /// request for any slot (not just the current desired slot).
        NoRepairPeers,
    } || Allocator.Error;

    /// Selects a peer at random from gossip or cache that is expected
    /// to be able to handle a repair request for the specified slot.
    pub fn getRandomPeer(self: *Self, slot: Slot) Error!?RepairPeer {
        const zone = tracy.Zone.init(@src(), .{ .name = "getRandomPeer" });
        defer zone.deinit();

        const view = try self.getPeers(slot);
        const strict_count = @min(view.strict_count, view.peers.len);
        const preferred_count = @min(view.preferred_count, strict_count);
        if (preferred_count > 0) {
            return view.peers[self.random.intRangeLessThan(usize, 0, preferred_count)];
        }
        const peers = if (strict_count > 0) view.peers[0..strict_count] else view.peers;
        if (peers.len == 0) return null;
        const index = self.random.intRangeLessThan(usize, 0, peers.len);
        return peers[index];
    }

    /// Selects up to `limit` distinct peers for the slot. The returned slice
    /// points into `out`.
    pub fn getRandomPeers(
        self: *Self,
        slot: Slot,
        limit: usize,
        out: []RepairPeer,
    ) Error![]RepairPeer {
        const zone = tracy.Zone.init(@src(), .{ .name = "getRandomPeers" });
        defer zone.deinit();

        std.debug.assert(limit <= out.len);
        if (limit == 0) return out[0..0];
        const view = try self.getPeers(slot);
        const peers = view.peers;
        if (peers.len == 0) return out[0..0];

        const strict_count = @min(view.strict_count, peers.len);
        const preferred_count = @min(view.preferred_count, strict_count);
        if (strict_count == 0) {
            return self.sampleDistinctPeers(peers, limit, out);
        }

        const pinned_count = @min(limit, preferred_count);
        if (pinned_count > 0) {
            @memcpy(out[0..pinned_count], peers[0..pinned_count]);
        }

        var selected_count = pinned_count;
        if (selected_count < limit and preferred_count < strict_count) {
            const strict_target = @min(limit - selected_count, strict_count - preferred_count);
            selected_count += self.sampleDistinctPeers(
                peers[preferred_count..strict_count],
                strict_target,
                out[selected_count..],
            ).len;
        }
        if (selected_count < limit and strict_count < peers.len) {
            selected_count += self.sampleDistinctPeers(
                peers[strict_count..],
                limit - selected_count,
                out[selected_count..],
            ).len;
        }
        return out[0..selected_count];
    }

    fn sampleDistinctPeers(
        self: *Self,
        peers: []const RepairPeer,
        limit: usize,
        out: []RepairPeer,
    ) []RepairPeer {
        if (limit == 0 or peers.len == 0) return out[0..0];

        const target = @min(limit, peers.len);
        if (target > peers.len / 4) {
            const start = self.random.intRangeLessThan(usize, 0, peers.len);
            for (0..target) |i| {
                out[i] = peers[(start + i) % peers.len];
            }
            return out[0..target];
        }

        var selected_indexes: [MAX_CONTINUITY_REPAIR_PEER_FANOUT]usize = undefined;
        for (0..target) |i| {
            while (true) {
                const candidate_index = self.random.intRangeLessThan(usize, 0, peers.len);
                for (selected_indexes[0..i]) |selected_index| {
                    if (selected_index == candidate_index) break;
                } else {
                    selected_indexes[i] = candidate_index;
                    out[i] = peers[candidate_index];
                    break;
                }
            }
        }
        return out[0..target];
    }

    /// Tries to get peers that could have the slot. Checks cache, falling back to gossip.
    fn getPeers(self: *Self, slot: Slot) Error!RepairPeersView {
        const zone = tracy.Zone.init(@src(), .{ .name = "getPeers" });
        defer zone.deinit();

        const now: u64 = @intCast(std.time.timestamp());

        if (self.cache.get(slot)) |peers| {
            if (now - peers.insertion_time_secs <= REPAIR_PEERS_CACHE_TTL_SECONDS) {
                self.metrics.cache_hit_count.inc();
                return .{
                    .peers = peers.peers,
                    .strict_count = peers.strict_count,
                    .preferred_count = peers.preferred_count,
                    .unclear_count = peers.unclear_count,
                };
            }
            self.metrics.cache_expired_count.inc();
        } else self.metrics.cache_miss_count.inc();

        const use_static = self.static_peers.len > 0;
        var peers = if (use_static)
            try self.getRepairPeersFromStatic(self.allocator, slot)
        else
            try self.getRepairPeersFromGossip(self.allocator, slot);
        errdefer peers.deinit(self.allocator);

        if (use_static) {
            self.metrics.latest_count_from_gossip.set(0);
            self.metrics.latest_count_from_static.set(peers.peers.len);
        } else {
            self.metrics.latest_count_from_gossip.set(peers.peers.len);
            self.metrics.latest_count_from_static.set(0);
        }
        peers.insertion_time_secs = now;
        try self.cache.insert(slot, peers);
        return .{
            .peers = peers.peers,
            .strict_count = peers.strict_count,
            .preferred_count = peers.preferred_count,
            .unclear_count = peers.unclear_count,
        };
    }

    pub fn getPeerStats(self: *Self, slot: Slot) Error!RepairPeerStats {
        const view = try self.getPeers(slot);
        const strict_count = @min(view.strict_count, view.peers.len);
        const preferred_count = @min(view.preferred_count, strict_count);
        return .{
            .total_count = view.peers.len,
            .strict_count = strict_count,
            .preferred_count = preferred_count,
            .unclear_count = view.unclear_count,
        };
    }

    /// Returns explicitly configured repair peers when gossip discovery is
    /// unavailable. The file includes the RPC-observed shred version, and only
    /// peers matching the live cluster version are eligible. A matching slot
    /// leader is preferred; all other static peers remain possession-unclear.
    fn getRepairPeersFromStatic(
        self: *Self,
        allocator: Allocator,
        slot: Slot,
    ) Error!RepairPeers {
        const current_shred_version = self.my_shred_version.load(.monotonic);
        const slot_leader = self.getSlotLeader(slot);
        var compatible_count: usize = 0;
        var mismatch_count: usize = 0;
        var preferred_count: usize = 0;
        for (self.static_peers) |static_peer| {
            if (static_peer.shred_version != current_shred_version) {
                mismatch_count += 1;
                continue;
            }
            compatible_count += 1;
            if (slot_leader) |leader| {
                if (static_peer.peer.pubkey.equals(&leader)) preferred_count = 1;
            }
        }
        self.metrics.latest_shred_version_mismatch_count_from_static.set(mismatch_count);
        if (compatible_count == 0) return error.NoRepairPeers;

        const peers = try allocator.alloc(RepairPeer, compatible_count);
        var next: usize = 0;
        if (preferred_count == 1) {
            const leader = slot_leader.?;
            for (self.static_peers) |static_peer| {
                if (static_peer.shred_version == current_shred_version and
                    static_peer.peer.pubkey.equals(&leader))
                {
                    peers[next] = static_peer.peer;
                    next += 1;
                    break;
                }
            }
        }
        for (self.static_peers) |static_peer| {
            if (static_peer.shred_version != current_shred_version) continue;
            if (preferred_count == 1 and static_peer.peer.pubkey.equals(&slot_leader.?)) continue;
            peers[next] = static_peer.peer;
            next += 1;
        }
        std.debug.assert(next == compatible_count);
        return .{
            .insertion_time_secs = 0,
            .peers = peers,
            .strict_count = preferred_count,
            .preferred_count = preferred_count,
            .unclear_count = compatible_count - preferred_count,
        };
    }

    /// Gets a list of peers from the gossip table that are likely to have the desired slot.
    /// This will always acquire the gossip table lock.
    /// Instead of using this function, access the cache when possible to avoid contention.
    fn getRepairPeersFromGossip(
        self: *Self,
        allocator: Allocator,
        slot: Slot,
    ) Error!RepairPeers {
        const zone = tracy.Zone.init(@src(), .{ .name = "getRepairPeersFromGossip" });
        defer zone.deinit();

        var gossip_table_lock = self.gossip_table_rw.read();
        defer gossip_table_lock.unlock();
        const gossip_table: *const GossipTable = gossip_table_lock.get();
        const contact_info_count = gossip_table.contact_infos.count();
        const preferred_buf = try allocator.alloc(RepairPeer, contact_info_count);
        defer allocator.free(preferred_buf);
        const strict_buf = try allocator.alloc(RepairPeer, contact_info_count);
        defer allocator.free(strict_buf);
        const unclear_buf = try allocator.alloc(RepairPeer, contact_info_count);
        defer allocator.free(unclear_buf);
        var slot_supported_pubkeys = AutoHashMap(Pubkey, void).init(allocator);
        defer slot_supported_pubkeys.deinit();
        try collectSlotSupportedPubkeys(gossip_table, slot, &slot_supported_pubkeys);
        const slot_leader = self.getSlotLeader(slot);

        var potential_peers: usize = 0; // total count of all repair peers, not just the ones for this slot.
        var preferred_peers: usize = 0; // slot leaders pinned ahead of random slot-supported peers.
        var strict_peers: usize = 0; // peers whose EpochSlots prove they have this slot.
        var unclear_peers: usize = 0; // compatible peers without slot-specific proof.
        var infos = gossip_table.contactInfoIterator(0);
        while (infos.next()) |info| {
            const serve_repair_socket = info.getSocket(.serve_repair);
            if (!info.pubkey.equals(&self.my_pubkey) and // don't request from self
                info.shred_version == self.my_shred_version.load(.monotonic) and // need compatible shreds
                serve_repair_socket != null and // node must be able to receive repair requests
                info.getSocket(.turbine_recv) != null) // node needs access to shreds
            {
                potential_peers += 1;
                // exclude nodes that are known to be missing this slot
                if (gossip_table.getData(.{ .LowestSlot = info.pubkey })) |data| {
                    if (data.LowestSlot[1].lowest > slot) {
                        continue;
                    }
                }
                const peer: RepairPeer = .{
                    .pubkey = info.pubkey,
                    .serve_repair_socket = serve_repair_socket.?,
                };
                // The slot leader generated the shreds, so prefer it for
                // recent-slot repairs before EpochSlots gossip proves support.
                if (slot_leader) |leader| {
                    if (info.pubkey.equals(&leader)) {
                        _ = appendUniqueRepairPeer(
                            preferred_buf,
                            &preferred_peers,
                            preferred_buf[0..preferred_peers],
                            strict_buf[0..strict_peers],
                            unclear_buf[0..unclear_peers],
                            peer,
                        );
                        continue;
                    }
                }
                if (slot_supported_pubkeys.contains(info.pubkey)) {
                    _ = appendUniqueRepairPeer(
                        strict_buf,
                        &strict_peers,
                        preferred_buf[0..preferred_peers],
                        strict_buf[0..strict_peers],
                        unclear_buf[0..unclear_peers],
                        peer,
                    );
                } else {
                    _ = appendUniqueRepairPeer(
                        unclear_buf,
                        &unclear_peers,
                        preferred_buf[0..preferred_peers],
                        strict_buf[0..strict_peers],
                        unclear_buf[0..unclear_peers],
                        peer,
                    );
                }
            }
        }
        if (potential_peers == 0) {
            return error.NoRepairPeers;
        }
        const slot_supported_peers = preferred_peers + strict_peers;
        self.metrics.latest_slot_supported_count_from_gossip.set(slot_supported_peers);
        self.metrics.latest_slot_support_unavailable_count_from_gossip.set(unclear_peers);
        if (slot_supported_peers > 0) {
            const include_unclear =
                (self.include_unclear_peers_when_slot_supported or
                    slot_supported_peers < self.min_strict_slot_supported_repair_peers) and unclear_peers > 0;
            const total_peers = slot_supported_peers + if (include_unclear) unclear_peers else 0;
            const peers = try allocator.alloc(RepairPeer, total_peers);
            @memcpy(peers[0..preferred_peers], preferred_buf[0..preferred_peers]);
            @memcpy(
                peers[preferred_peers..slot_supported_peers],
                strict_buf[0..strict_peers],
            );
            if ((self.include_unclear_peers_when_slot_supported or
                slot_supported_peers < self.min_strict_slot_supported_repair_peers) and unclear_peers > 0)
            {
                @memcpy(
                    peers[slot_supported_peers..total_peers],
                    unclear_buf[0..unclear_peers],
                );
            }
            return .{
                .insertion_time_secs = 0,
                .peers = peers,
                .strict_count = slot_supported_peers,
                .preferred_count = preferred_peers,
                .unclear_count = if (include_unclear) unclear_peers else 0,
            };
        }
        const peers = try allocator.alloc(RepairPeer, unclear_peers);
        @memcpy(peers[0..unclear_peers], unclear_buf[0..unclear_peers]);
        return .{
            .insertion_time_secs = 0,
            .peers = peers,
            .strict_count = 0,
            .preferred_count = 0,
            .unclear_count = unclear_peers,
        };
    }

    fn getSlotLeader(self: *Self, slot: Slot) ?Pubkey {
        const leader_schedules_with_infos = self.epoch_tracker.getLeaderSchedules() catch return null;
        defer leader_schedules_with_infos.release();
        return leader_schedules_with_infos.leader_schedules.getLeaderOrNull(slot);
    }
};

fn loadStaticRepairPeersFromEnv(allocator: Allocator) ![]StaticRepairPeer {
    const path = (try readOptionalEnvOwned(allocator, "SIG_REPAIR_STATIC_PEERS_PATH")) orelse
        return allocator.alloc(StaticRepairPeer, 0);
    defer allocator.free(path);

    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{ .mode = .read_only })
    else
        try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();
    const contents = try file.readToEndAlloc(allocator, MAX_STATIC_REPAIR_PEERS_FILE_BYTES);
    defer allocator.free(contents);
    return parseStaticRepairPeers(allocator, contents);
}

fn parseStaticRepairPeers(allocator: Allocator, contents: []const u8) ![]StaticRepairPeer {
    var peers = ArrayList(StaticRepairPeer).init(allocator);
    errdefer peers.deinit();

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
        const pubkey_text = tokens.next() orelse return error.MissingStaticRepairPeerPubkey;
        const socket_text = tokens.next() orelse return error.MissingStaticRepairPeerSocket;
        const shred_version_text = tokens.next() orelse return error.MissingStaticRepairPeerShredVersion;
        if (tokens.next() != null) return error.UnexpectedStaticRepairPeerField;
        if (peers.items.len >= MAX_STATIC_REPAIR_PEERS) return error.TooManyStaticRepairPeers;

        const peer: StaticRepairPeer = .{
            .peer = .{
                .pubkey = try Pubkey.parseRuntime(pubkey_text),
                .serve_repair_socket = try SocketAddr.parse(socket_text),
            },
            .shred_version = try std.fmt.parseUnsigned(u16, shred_version_text, 10),
        };
        try peer.peer.serve_repair_socket.sanitize();
        for (peers.items) |existing| {
            if (existing.peer.pubkey.equals(&peer.peer.pubkey))
                return error.DuplicateStaticRepairPeerPubkey;
            if (existing.peer.serve_repair_socket.eql(&peer.peer.serve_repair_socket))
                return error.DuplicateStaticRepairPeerSocket;
        }
        try peers.append(peer);
    }
    if (peers.items.len == 0) return error.EmptyStaticRepairPeers;
    return peers.toOwnedSlice();
}

fn appendUniqueRepairPeer(
    out: []RepairPeer,
    count: *usize,
    preferred_peers: []const RepairPeer,
    strict_peers: []const RepairPeer,
    unclear_peers: []const RepairPeer,
    peer: RepairPeer,
) bool {
    if (containsRepairSocket(preferred_peers, &peer.serve_repair_socket) or
        containsRepairSocket(strict_peers, &peer.serve_repair_socket) or
        containsRepairSocket(unclear_peers, &peer.serve_repair_socket))
    {
        return false;
    }

    out[count.*] = peer;
    count.* += 1;
    return true;
}

fn containsRepairSocket(peers: []const RepairPeer, socket: *const SocketAddr) bool {
    for (peers) |peer| {
        if (peer.serve_repair_socket.eql(socket)) return true;
    }
    return false;
}

fn collectSlotSupportedPubkeys(
    gossip_table: *const GossipTable,
    slot: Slot,
    out: *AutoHashMap(Pubkey, void),
) Allocator.Error!void {
    const cursors = gossip_table.epoch_slots.keys();
    for (cursors) |cursor| {
        const entry_index = gossip_table.epoch_slots.get(cursor).?;
        const entry = gossip_table.store.getByIndex(entry_index);
        switch (entry.data) {
            .EpochSlots => |epoch_slots_indexed| {
                const epoch_slots = epoch_slots_indexed[1];
                if (epochSlotsContainSlot(&epoch_slots, slot)) {
                    try out.put(epoch_slots.from, {});
                }
            },
            else => {},
        }
    }
}

fn epochSlotsContainSlot(epoch_slots: *const sig.gossip.data.EpochSlots, slot: Slot) bool {
    for (epoch_slots.slots) |compressed_slots| {
        switch (compressed_slots) {
            .Uncompressed => |uncompressed| {
                if (uncompressedContainsSlot(&uncompressed, slot)) return true;
            },
            .Flate2 => |flate2| {
                if (flate2ContainsSlot(&flate2, slot)) return true;
            },
        }
    }
    return false;
}

fn flate2ContainsSlot(flate2: *const sig.gossip.data.Flate2, slot: Slot) bool {
    if (slot < flate2.first_slot) return false;
    const offset = slot - flate2.first_slot;
    if (offset >= flate2.num) return false;
    if (flate2.num >= sig.gossip.data.MAX_SLOT_PER_ENTRY) return false;

    const byte_index: usize = @intCast(offset / 8);
    if (byte_index >= EPOCH_SLOTS_DECOMPRESSED_BYTES) return false;

    var decompressed: [EPOCH_SLOTS_DECOMPRESSED_BYTES]u8 = undefined;
    var input: std.Io.Reader = .fixed(flate2.compressed);
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&input, .raw, &decompress_buf);
    decompressor.reader.readSliceAll(decompressed[0 .. byte_index + 1]) catch return false;

    const bit_index: u3 = @intCast(offset % 8);
    return (decompressed[byte_index] & (@as(u8, 1) << bit_index)) != 0;
}

fn uncompressedContainsSlot(uncompressed: *const sig.gossip.data.Uncompressed, slot: Slot) bool {
    if (slot < uncompressed.first_slot) return false;
    const offset = slot - uncompressed.first_slot;
    if (offset >= uncompressed.num) return false;
    if (offset >= uncompressed.slots.len) return false;
    const bits = uncompressed.slots.bits orelse return false;
    const byte_index: usize = @intCast(offset / 8);
    if (byte_index >= bits.len) return false;
    const bit_index: u3 = @intCast(offset % 8);
    return (bits[byte_index] & (@as(u8, 1) << bit_index)) != 0;
}

test "epochSlotsContainSlot supports flate2 compressed bitsets" {
    var compressed = [_]u8{
        0b0000_0001, 0x02, 0x00, 0xfd, 0xff, // final stored raw-deflate block, len=2
        0x00, 0x02, // bit 9 is set
    };
    const flate2 = sig.gossip.data.Flate2{
        .first_slot = 1000,
        .num = 16,
        .compressed = compressed[0..],
    };

    try std.testing.expect(flate2ContainsSlot(&flate2, 1009));
    try std.testing.expect(!flate2ContainsSlot(&flate2, 1008));
    try std.testing.expect(!flate2ContainsSlot(&flate2, 1016));

    var compressed_slots = [_]sig.gossip.data.CompressedSlots{.{ .Flate2 = flate2 }};
    const epoch_slots = sig.gossip.data.EpochSlots{
        .from = Pubkey.ZEROES,
        .slots = compressed_slots[0..],
        .wallclock = 0,
    };
    try std.testing.expect(epochSlotsContainSlot(&epoch_slots, 1009));
    try std.testing.expect(!epochSlotsContainSlot(&epoch_slots, 1008));
}

test "flate2 slot support ignores malformed compressed gossip" {
    var compressed = [_]u8{0b0000_0110};
    const flate2 = sig.gossip.data.Flate2{
        .first_slot = 1000,
        .num = 16,
        .compressed = compressed[0..],
    };

    try std.testing.expect(!flate2ContainsSlot(&flate2, 1009));
}

test "bounded repair window caps exact shred requests" {
    try std.testing.expectEqual(512, boundedRepairWindowEnd(0, 671, 512));
    try std.testing.expectEqual(671, boundedRepairWindowEnd(512, 671, 512));
    try std.testing.expectEqual(671, boundedRepairWindowEnd(671, 671, 256));
}

test "targeted repair plan parser accepts fec probe lines" {
    const request = (try parseTargetedRepairPlanLine(
        "repair_data_shred slot=427540109 index=64 fec_set_index=64 data_seen=18 code_seen=0 expected_data=null expected_code=null unique_shards=18",
    )).?;
    try std.testing.expectEqual(RepairRequest{ .Shred = .{ 427540109, 64 } }, request);

    const highest_request = (try parseTargetedRepairPlanLine(
        "repair_highest_shred slot=427540110 index=0",
    )).?;
    try std.testing.expectEqual(
        RepairRequest{ .HighestShred = .{ 427540110, 0 } },
        highest_request,
    );

    const orphan_request = (try parseTargetedRepairPlanLine(
        "repair_orphan slot=427540111",
    )).?;
    try std.testing.expectEqual(RepairRequest{ .orphan = 427540111 }, orphan_request);

    try std.testing.expectEqual(@as(?RepairRequest, null), try parseTargetedRepairPlanLine("# comment"));
    try std.testing.expectEqual(@as(?RepairRequest, null), try parseTargetedRepairPlanLine(""));
}

test "targeted repair plan loader tracks request slot range" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = "repair-plan.txt";
    {
        var file = try tmp.dir.createFile(path, .{});
        defer file.close();
        try file.writeAll(
            \\# repair_data_shred, repair_highest_shred, and repair_orphan lines are targeted repair candidates
            \\repair_data_shred slot=10 index=1 fec_set_index=0 data_seen=1 code_seen=0 expected_data=null expected_code=null unique_shards=1
            \\repair_highest_shred slot=12 index=7
            \\repair_orphan slot=11
            \\
        );
    }

    const abs_path = try tmp.dir.realpathAlloc(allocator, path);
    defer allocator.free(abs_path);

    var requests = ArrayList(RepairRequest).init(allocator);
    defer requests.deinit();
    const stats = try loadTargetedRepairPlan(allocator, abs_path, &requests);

    try std.testing.expectEqual(@as(usize, 3), requests.items.len);
    try std.testing.expectEqual(@as(usize, 3), stats.request_count);
    try std.testing.expectEqual(@as(?Slot, 10), stats.min_slot);
    try std.testing.expectEqual(@as(?Slot, 12), stats.max_slot);
    try std.testing.expect(stats.file_size > 0);
    try std.testing.expectEqual(RepairRequest{ .Shred = .{ 10, 1 } }, requests.items[0]);
    try std.testing.expectEqual(
        RepairRequest{ .HighestShred = .{ 12, 7 } },
        requests.items[1],
    );
}

test "targeted repair plan file fingerprint detects atomic replacement" {
    try std.testing.expect(!targetedRepairPlanFileChanged(100, 200, 100, 200));
    try std.testing.expect(targetedRepairPlanFileChanged(100, 200, 101, 200));
    try std.testing.expect(targetedRepairPlanFileChanged(100, 200, 100, 201));
}

test "targeted repair cooldown suppresses repeat requests until expiry" {
    const allocator = std.testing.allocator;
    var last_queued_ms = AutoHashMap(TargetedRepairRequestKey, i64).init(allocator);
    defer last_queued_ms.deinit();

    const first = RepairRequest{ .Shred = .{ 42, 7 } };
    const second = RepairRequest{ .Shred = .{ 42, 8 } };
    try std.testing.expect(try targetedRepairCooldownAllows(&last_queued_ms, first, 1_000, 5_000));
    try std.testing.expect(!try targetedRepairCooldownAllows(&last_queued_ms, first, 5_999, 5_000));
    try std.testing.expect(try targetedRepairCooldownAllows(&last_queued_ms, second, 5_999, 5_000));
    try std.testing.expect(try targetedRepairCooldownAllows(&last_queued_ms, first, 6_000, 5_000));

    last_queued_ms.clearRetainingCapacity();
    try std.testing.expect(try targetedRepairCooldownAllows(&last_queued_ms, first, 6_001, 5_000));
    try std.testing.expect(try targetedRepairCooldownAllows(&last_queued_ms, first, 6_001, 0));
}

test "targeted repair plan reload retains active cooldowns and prunes completed requests" {
    const allocator = std.testing.allocator;
    var last_queued_ms = AutoHashMap(TargetedRepairRequestKey, i64).init(allocator);
    defer last_queued_ms.deinit();

    const retained_request = RepairRequest{ .Shred = .{ 42, 7 } };
    const completed_request = RepairRequest{ .Shred = .{ 42, 8 } };
    const new_request = RepairRequest{ .Shred = .{ 42, 9 } };
    try std.testing.expect(try targetedRepairCooldownAllows(
        &last_queued_ms,
        retained_request,
        1_000,
        5_000,
    ));
    try std.testing.expect(try targetedRepairCooldownAllows(
        &last_queued_ms,
        completed_request,
        1_000,
        5_000,
    ));

    const next_plan = [_]RepairRequest{ retained_request, new_request };
    try std.testing.expectEqual(
        @as(usize, 1),
        try retainTargetedRepairCooldownEntries(allocator, &last_queued_ms, &next_plan),
    );
    try std.testing.expect(!try targetedRepairCooldownAllows(
        &last_queued_ms,
        retained_request,
        5_999,
        5_000,
    ));
    try std.testing.expect(try targetedRepairCooldownAllows(
        &last_queued_ms,
        completed_request,
        5_999,
        5_000,
    ));
    try std.testing.expect(try targetedRepairCooldownAllows(
        &last_queued_ms,
        new_request,
        5_999,
        5_000,
    ));

    const empty_plan = [_]RepairRequest{};
    try std.testing.expectEqual(
        @as(usize, 0),
        try retainTargetedRepairCooldownEntries(allocator, &last_queued_ms, &empty_plan),
    );
    try std.testing.expectEqual(@as(usize, 0), last_queued_ms.count());
}

test "continuity exact repair cursor resumes after the prior chunk" {
    const allocator = std.testing.allocator;

    var repairs = ArrayList(RepairRequest).init(allocator);
    defer repairs.deinit();

    const windows = [_]MissingRange{.{ .start = 0, .end = 799 }};
    var individual_count: usize = 0;
    var planned_count: usize = 0;
    var first_planned_index: ?usize = null;
    var last_planned_index: ?usize = null;

    const planned = try appendExactRepairsFromCursor(
        &repairs,
        42,
        windows[0..],
        512,
        512,
        &individual_count,
        &planned_count,
        &first_planned_index,
        &last_planned_index,
    );

    try std.testing.expectEqual(287, planned);
    try std.testing.expectEqual(287, repairs.items.len);
    try std.testing.expectEqual(@as(?usize, 512), first_planned_index);
    try std.testing.expectEqual(@as(?usize, 798), last_planned_index);
    try std.testing.expectEqual(RepairRequest{ .Shred = .{ 42, 512 } }, repairs.items[0]);
    try std.testing.expectEqual(RepairRequest{ .Shred = .{ 42, 798 } }, repairs.items[repairs.items.len - 1]);
}

test "RepairService sends repair request to gossip peer" {
    const allocator = std.testing.allocator;
    const logger: sig.trace.Logger("test") = .FOR_TESTS;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    // my details
    const keypair = KeyPair.generate();
    const my_shred_version = Atomic(u16).init(random.int(u16));
    const wallclock = 100;
    var gossip: GossipTable = try .init(allocator, allocator);
    defer gossip.deinit();

    // connectivity
    const repair_port = random.intRangeAtMost(u16, 1000, std.math.maxInt(u16));
    const repair_socket: sig.net.UdpSocket = try .create(.ipv4);
    defer repair_socket.close();
    try repair_socket.bind(.initIp4(.{ 0, 0, 0, 0 }, repair_port));

    // peer
    const peer_port = random.intRangeAtMost(u16, 1000, std.math.maxInt(u16));
    const peer_keypair: KeyPair = .generate();
    var peer_socket: sig.net.UdpSocket = try .create(.ipv4);
    const peer_endpoint: std.net.Address = .initIp4(.{ 127, 0, 0, 1 }, peer_port);
    try peer_socket.bind(peer_endpoint);
    try peer_socket.setReadTimeout(100_000);

    {
        var peer_contact_info: ContactInfo = .init(
            allocator,
            .fromPublicKey(&peer_keypair.public_key),
            wallclock,
            my_shred_version.load(.acquire),
        );
        errdefer peer_contact_info.deinit();
        try peer_contact_info.setSocket(.serve_repair, .initAddress(peer_endpoint));
        try peer_contact_info.setSocket(.turbine_recv, .initAddress(peer_endpoint));
        _ = try gossip.insert(
            .initSigned(&peer_keypair, .{ .ContactInfo = peer_contact_info }),
            wallclock,
        );
    }

    // init service
    var exit: Atomic(bool) = .init(false);
    var gossip_mux: RwMux(GossipTable) = .init(gossip);
    var epoch_tracker = sig.core.EpochTracker.init(.default, 0, sig.core.EpochSchedule.INIT);
    defer epoch_tracker.deinit();
    const peers: RepairPeerProvider = try .init(
        allocator,
        random,
        &registry,
        &gossip_mux,
        &epoch_tracker,
        Pubkey.fromPublicKey(&keypair.public_key),
        &my_shred_version,
    );

    var tracker: BasicShredTracker = undefined;
    try tracker.init(std.testing.allocator, 13579, .noop, &registry, false);
    defer tracker.deinit();

    var ledger, var ledger_dir = try sig.ledger.Ledger.initForTest(allocator);
    defer ledger_dir.cleanup();
    defer ledger.deinit();

    var service: RepairService = blk: {
        const repair_requester: RepairRequester = try .init(
            allocator,
            .from(logger),
            random,
            &registry,
            &keypair,
            repair_socket,
            &exit,
        );
        errdefer repair_requester.deinit();

        break :blk try .init(
            allocator,
            .from(logger),
            &exit,
            &registry,
            repair_requester,
            peers,
            &tracker,
            &ledger,
        );
    };
    defer service.deinit();

    // run test
    _ = try service.sendNecessaryRepairs();

    var buf: [200]u8 = undefined;
    var highest_slots: [3]Slot = undefined;
    var num_window_index: usize = 0;
    var num_recv: usize = 0;
    while (peer_socket.receive(&buf) catch null) |size| {
        try std.testing.expectEqual(160, size);
        const msg = try bincode.readFromSlice(allocator, RepairMessage, buf[0..160], .{});
        switch (msg) {
            .highest_window_index => |highest_window_index| {
                try std.testing.expect(highest_window_index.slot >= 13579);
                try std.testing.expectEqual(0, highest_window_index.shred_index);
                highest_slots[num_recv] = highest_window_index.slot;
                num_recv += 1;
            },
            .window_index => |window_index| {
                try std.testing.expectEqual(13579, window_index.slot);
                try std.testing.expect(window_index.shred_index < RepairService.CONTINUITY_REPAIR_OPEN_ENDED_PREFIX_REPAIRS);
                num_window_index += 1;
            },
            else => return error.TestFailed,
        }
    }

    try std.testing.expectEqual(3, num_recv);
    try std.testing.expectEqual(RepairService.CONTINUITY_REPAIR_OPEN_ENDED_PREFIX_REPAIRS, num_window_index);

    outer: for ([_]Slot{ 13579, 13580 }) |expected_slot| {
        for (highest_slots[0..num_recv]) |slot| if (slot == expected_slot) continue :outer;
        std.debug.print("missing expected repair request for slot: {}\n", .{expected_slot});
        return error.TestFailed;
    }
}

test "RepairPeerProvider selects correct peers" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    // my details
    const keypair = KeyPair.generate();
    const my_shred_version = Atomic(u16).init(random.int(u16));
    var gossip = try GossipTable.init(allocator, allocator);
    defer gossip.deinit();

    // peers
    const peer_generator = TestPeerGenerator{
        .allocator = allocator,
        .gossip = &gossip,
        .random = random,
        .shred_version = my_shred_version.load(.acquire),
        .slot = 13579,
    };
    const good_peers = .{
        try peer_generator.addPeerToGossip(.HasSlot),
        try peer_generator.addPeerToGossip(.SlotPosessionUnclear),
    };
    const bad_peers = .{
        try peer_generator.addPeerToGossip(.MissingServeRepairPort),
        try peer_generator.addPeerToGossip(.MissingTvuPort),
        try peer_generator.addPeerToGossip(.MissingSlot),
        try peer_generator.addPeerToGossip(.WrongShredVersion),
    };

    // init test subject
    var gossip_mux = RwMux(GossipTable).init(gossip);
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    var epoch_tracker = sig.core.EpochTracker.init(.default, 0, sig.core.EpochSchedule.INIT);
    defer epoch_tracker.deinit();
    var peers = try RepairPeerProvider.init(
        allocator,
        random,
        &registry,
        &gossip_mux,
        &epoch_tracker,
        Pubkey.fromPublicKey(&keypair.public_key),
        &my_shred_version,
    );
    defer peers.deinit();

    // run test
    var observed_peers = std.AutoHashMap(RepairPeer, void).init(allocator);
    defer observed_peers.deinit();
    for (0..10) |_| {
        const peer = (try peers.getRandomPeer(13579)).?;
        try observed_peers.put(peer, {});
    }

    // assertions
    var failed = false;
    inline for (good_peers) |good_peer| {
        if (!observed_peers.contains(good_peer[1])) {
            std.debug.print("_\nMISSING: {}\n", .{good_peer[0]});
            failed = true;
        }
    }
    inline for (bad_peers) |bad_peer| {
        if (observed_peers.contains(bad_peer[1])) {
            std.debug.print("_\nUNEXPECTED: {}\n", .{bad_peer[0]});
            failed = true;
        }
    }
    try std.testing.expect(!failed);
}

test "static repair peer parser accepts bounded RPC-derived peers" {
    const allocator = std.testing.allocator;
    const contents =
        \\# pubkey serveRepair shredVersion
        \\EVza6WyZusWifc6U4Vu58zK6fPuTRajTrR7xGeSzHuMs 134.65.192.208:8009 50093
        \\5pPRHniefFjkiaArbGX3Y8NUysJmQ9tMZg3FrFGwHzSm 127.0.0.1:19003 50093
    ;
    const peers = try parseStaticRepairPeers(allocator, contents);
    defer allocator.free(peers);

    try std.testing.expectEqual(@as(usize, 2), peers.len);
    try std.testing.expectEqual(@as(u16, 50093), peers[0].shred_version);
    try std.testing.expectEqual(@as(u16, 8009), peers[0].peer.serve_repair_socket.getPort());
    const expected_pubkey = try Pubkey.parseRuntime("5pPRHniefFjkiaArbGX3Y8NUysJmQ9tMZg3FrFGwHzSm");
    try std.testing.expect(peers[1].peer.pubkey.equals(&expected_pubkey));
}

test "static repair peer parser rejects duplicate sockets" {
    const allocator = std.testing.allocator;
    const contents =
        \\EVza6WyZusWifc6U4Vu58zK6fPuTRajTrR7xGeSzHuMs 134.65.192.208:8009 50093
        \\5pPRHniefFjkiaArbGX3Y8NUysJmQ9tMZg3FrFGwHzSm 134.65.192.208:8009 50093
    ;
    try std.testing.expectError(
        error.DuplicateStaticRepairPeerSocket,
        parseStaticRepairPeers(allocator, contents),
    );
}

const TestPeerGenerator = struct {
    allocator: Allocator,
    gossip: *GossipTable,
    random: Random,
    shred_version: u16,
    slot: Slot,

    const PeerType = enum {
        /// There is a LowestSlot for the peer that indicates they have the slot
        HasSlot,
        /// There is not a LowestSlot
        SlotPosessionUnclear,
        /// There is a LowestSlot for the peer that indicates they do not have the slot
        MissingSlot,
        /// There is no serve repair port specified in the peer's contact info
        MissingServeRepairPort,
        /// There is no turbine port specified in the peer's contact info
        MissingTvuPort,
        /// The peer has a different shred version
        WrongShredVersion,
    };

    fn addPeerToGossip(self: *const @This(), peer_type: PeerType) !struct { PeerType, RepairPeer } {
        const zone = tracy.Zone.init(@src(), .{ .name = "addPeerToGossip" });
        defer zone.deinit();

        const wallclock = 1;
        const keypair: KeyPair = .generate();
        const pubkey: Pubkey = .fromPublicKey(&keypair.public_key);
        const serve_repair_addr: SocketAddr = .initIpv4(
            .{ 127, 0, 0, 1 },
            8003 + @as(u16, @intCast(@intFromEnum(peer_type))),
        );
        const shred_version = switch (peer_type) {
            .WrongShredVersion => self.shred_version + 1,
            else => self.shred_version,
        };

        var contact_info: ContactInfo = .init(self.allocator, pubkey, wallclock, shred_version);
        if (peer_type != .MissingServeRepairPort) {
            try contact_info.setSocket(.serve_repair, serve_repair_addr);
        }
        if (peer_type != .MissingTvuPort) {
            try contact_info.setSocket(.turbine_recv, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8004));
        }
        _ = try self.gossip.insert(
            .initSigned(&keypair, .{ .ContactInfo = contact_info }),
            wallclock,
        );
        switch (peer_type) {
            inline .HasSlot, .MissingSlot => {
                var lowest_slot = sig.gossip.LowestSlot.initRandom(self.random);
                lowest_slot.from = pubkey;
                lowest_slot.lowest = switch (peer_type) {
                    .MissingSlot => self.slot + 1,
                    else => self.slot,
                };
                _ = try self.gossip.insert(
                    .initSigned(&keypair, .{ .LowestSlot = .{ 0, lowest_slot } }),
                    wallclock,
                );
            },
            else => {},
        }
        return .{ peer_type, .{
            .pubkey = pubkey,
            .serve_repair_socket = serve_repair_addr,
        } };
    }
};
