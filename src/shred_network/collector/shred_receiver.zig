const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../../sig.zig");
const shred_network = @import("../lib.zig");

const bincode = sig.bincode;
const layout = sig.ledger.shred.layout;
const shred_verifier = shred_network.shred_verifier;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = sig.identity.KeyPair;

const BasicShredTracker = shred_network.shred_tracker.BasicShredTracker;
const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const Histogram = sig.prometheus.Histogram;
const Packet = sig.net.Packet;
const Ping = sig.gossip.Ping;
const Pong = sig.gossip.Pong;
const RepairMessage = shred_network.repair_message.RepairMessage;
const Shred = sig.ledger.shred.Shred;
const ShredInserter = sig.ledger.ShredInserter;
const Slot = sig.core.Slot;
const SocketThread = sig.net.SocketThread;
const Timer = sig.time.Timer;
const ExitCondition = sig.sync.ExitCondition;
const VariantCounter = sig.prometheus.VariantCounter;

const Logger = sig.trace.Logger("shred_receiver");
const VerifiedMerkleRoots = sig.utils.lru.LruCache(.non_locking, sig.core.Hash, void);

const DuplicateShredHandler = shred_network.duplicate_shred_handler.DuplicateShredHandler;
const DUPLICATE_SHRED_MAX_PAYLOAD_SIZE =
    shred_network.duplicate_shred_handler.DUPLICATE_SHRED_MAX_PAYLOAD_SIZE;
const DUPLICATE_SHRED_HEADER_SIZE =
    shred_network.duplicate_shred_handler.DUPLICATE_SHRED_HEADER_SIZE;

const PacketBatchEntry = struct {
    packet: Packet,
    is_repair: bool,
};

const ParsedShredEntry = struct {
    shred: Shred,
    is_repair: bool,
};

const ParallelParseWorker = struct {
    allocator: Allocator = std.heap.page_allocator,
    packets: []const PacketBatchEntry,
    root_slot: Slot,
    shred_version: *const Atomic(u16),
    metrics: ShredReceiverMetrics,
    drop_code_shreds: bool,
    parsed: std.MultiArrayList(ParsedShredEntry) = .empty,
    moved: bool = false,
    err: ?anyerror = null,

    fn run(self: *ParallelParseWorker) void {
        self.runInner() catch |err| {
            self.err = err;
        };
    }

    fn runInner(self: *ParallelParseWorker) !void {
        try self.parsed.ensureUnusedCapacity(self.allocator, self.packets.len);
        for (self.packets) |entry| {
            const packet = &entry.packet;
            const shred_payload = layout.getShred(packet) orelse {
                self.metrics.discard.observe(error.insufficient_shred_size);
                self.metrics.incValidationDiscard(entry.is_repair, error.insufficient_shred_size);
                continue;
            };
            validateShred(
                packet,
                self.root_slot,
                self.shred_version,
                std.math.maxInt(Slot),
            ) catch |err| {
                self.metrics.discard.observe(err);
                self.metrics.incValidationDiscard(entry.is_repair, err);
                continue;
            };
            self.metrics.satisfactory_shred_count.inc();
            self.metrics.skipped_verifier_count.inc();

            if (self.drop_code_shreds) {
                const variant = layout.getShredVariant(shred_payload) orelse {
                    self.metrics.discard.observe(error.variant_missing);
                    self.metrics.incValidationDiscard(entry.is_repair, error.variant_missing);
                    continue;
                };
                if (variant.shred_type == .code) {
                    self.metrics.dropped_code_shred_count.inc();
                    continue;
                }
            }

            const shred = Shred.fromPayload(self.allocator, shred_payload) catch {
                self.metrics.incDeserializeFail(entry.is_repair);
                continue;
            };
            self.metrics.received_shred.observe(shredSourceKind(entry.is_repair, shred));
            self.parsed.appendAssumeCapacity(.{
                .shred = shred,
                .is_repair = entry.is_repair,
            });
        }
    }

    fn deinit(self: *ParallelParseWorker) void {
        if (!self.moved) {
            for (self.parsed.items(.shred)) |shred| shred.deinit();
        }
        self.parsed.deinit(self.allocator);
    }
};

/// Analogous to [ShredFetchStage](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/shred_fetch_stage.rs#L34)
pub const ShredReceiver = struct {
    params: Params,
    logger: Logger,

    incoming_shreds: Channel(Packet),
    outgoing_pongs: Channel(Packet),

    metrics: ShredReceiverMetrics,
    verifier_metrics: shred_verifier.Metrics,
    seen_shred_packet_keys: std.AutoHashMap(u128, void),

    verified_merkle_roots: VerifiedMerkleRoots,
    packet_batch: std.ArrayListUnmanaged(PacketBatchEntry),
    shred_batch: std.MultiArrayList(struct { shred: Shred, is_repair: bool }),
    max_shreds_per_iter: usize,
    parallel_parse_workers: usize,
    max_pending_packets: usize,
    drop_to_pending_packets: usize,
    skip_shred_verifier: bool,
    dedup_shred_packets: bool,
    trusted_insert: bool,
    drop_code_shreds: bool,
    skip_inserter_recovery: bool,
    skip_inserter_tracker: bool,
    skip_data_recovery_meta: bool,
    debug_logged_batches: usize,
    debug_logged_missing_leader_schedules: usize,
    debug_logged_validation_failures: usize,
    debug_logged_verifier_failures: usize,
    debug_logged_skip_verifier: bool,
    debug_logged_insert_batches: usize,
    debug_logged_backlog_drops: usize,
    debug_target_repair_slot: ?Slot,
    debug_logged_target_repair_candidates: usize,
    debug_logged_target_repair_validation_failures: usize,
    debug_logged_target_repair_verifier_failures: usize,
    debug_logged_target_repair_verified: usize,
    debug_logged_target_repair_deserialize_failures: usize,

    const Params = struct {
        keypair: *const KeyPair,
        exit: *Atomic(bool),

        repair_socket: sig.net.UdpSocket,
        turbine_socket: sig.net.UdpSocket,

        /// me --> retransmit service
        maybe_retransmit_shred_sender: ?*Channel(Packet),

        shred_version: *const Atomic(u16),

        epoch_tracker: *sig.core.EpochTracker,

        /// shared with repair
        tracker: *BasicShredTracker,
        inserter: ShredInserter,

        /// Handler for duplicate slot detection and reporting
        duplicate_handler: DuplicateShredHandler,
    };

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        registry: *sig.prometheus.Registry(.{}),
        params: Params,
    ) !ShredReceiver {
        var incoming_shreds = try Channel(Packet).init(allocator);
        incoming_shreds.name = "ShredReceiver (incoming_shreds)";
        errdefer incoming_shreds.deinit();

        var outgoing_pongs = try Channel(Packet).init(allocator);
        outgoing_pongs.name = "ShredReceiver (outgoing_pongs)";
        errdefer outgoing_pongs.deinit();

        var verified_merkle_roots = try VerifiedMerkleRoots.init(allocator, 1024);
        errdefer verified_merkle_roots.deinit();

        const metrics = try registry.initStruct(ShredReceiverMetrics);
        const verifier_metrics = try registry.initStruct(shred_verifier.Metrics);
        var seen_shred_packet_keys = std.AutoHashMap(u128, void).init(allocator);
        errdefer seen_shred_packet_keys.deinit();
        const max_shreds_per_iter = readEnvUsize(
            allocator,
            "SIG_SHRED_RECEIVER_MAX_SHREDS_PER_ITER",
            DEFAULT_MAX_SHREDS_PER_ITER,
        );
        const parallel_parse_workers = readEnvUsize(
            allocator,
            "SIG_SHRED_RECEIVER_PARALLEL_PARSE_WORKERS",
            1,
        );
        const max_pending_packets = readEnvUsize(
            allocator,
            "SIG_SHRED_RECEIVER_MAX_PENDING_PACKETS",
            0,
        );
        const default_drop_to_pending = if (max_pending_packets > 0)
            @max(max_shreds_per_iter, max_pending_packets / 2)
        else
            0;
        const drop_to_pending_packets = readEnvUsize(
            allocator,
            "SIG_SHRED_RECEIVER_DROP_TO_PENDING_PACKETS",
            default_drop_to_pending,
        );
        const skip_shred_verifier = readEnvBool(
            allocator,
            "SIG_SHRED_RECEIVER_SKIP_VERIFIER",
            false,
        );
        const dedup_shred_packets = readEnvBool(
            allocator,
            "SIG_SHRED_RECEIVER_DEDUP_PACKETS",
            false,
        );
        const trusted_insert = readEnvBool(
            allocator,
            "SIG_SHRED_RECEIVER_TRUSTED_INSERT",
            false,
        );
        const drop_code_shreds = readEnvBool(
            allocator,
            "SIG_SHRED_RECEIVER_DROP_CODE_SHREDS",
            false,
        );
        const skip_inserter_recovery = readEnvBool(
            allocator,
            "SIG_SHRED_INSERTER_SKIP_RECOVERY",
            false,
        );
        const skip_inserter_tracker = readEnvBool(
            allocator,
            "SIG_SHRED_INSERTER_SKIP_TRACKER",
            false,
        );
        const skip_data_recovery_meta = readEnvBool(
            allocator,
            "SIG_SHRED_INSERTER_SKIP_DATA_RECOVERY_META",
            false,
        );

        return ShredReceiver{
            .params = params,
            .logger = logger,
            .incoming_shreds = incoming_shreds,
            .outgoing_pongs = outgoing_pongs,
            .metrics = metrics,
            .verifier_metrics = verifier_metrics,
            .seen_shred_packet_keys = seen_shred_packet_keys,
            .verified_merkle_roots = verified_merkle_roots,
            .packet_batch = .empty,
            .shred_batch = .empty,
            .max_shreds_per_iter = if (max_shreds_per_iter == 0)
                DEFAULT_MAX_SHREDS_PER_ITER
            else
                max_shreds_per_iter,
            .parallel_parse_workers = parallel_parse_workers,
            .max_pending_packets = max_pending_packets,
            .drop_to_pending_packets = if (max_pending_packets > 0)
                @min(drop_to_pending_packets, max_pending_packets)
            else
                0,
            .skip_shred_verifier = skip_shred_verifier,
            .dedup_shred_packets = dedup_shred_packets,
            .trusted_insert = trusted_insert,
            .drop_code_shreds = drop_code_shreds,
            .skip_inserter_recovery = skip_inserter_recovery,
            .skip_inserter_tracker = skip_inserter_tracker,
            .skip_data_recovery_meta = skip_data_recovery_meta,
            .debug_logged_batches = 0,
            .debug_logged_missing_leader_schedules = 0,
            .debug_logged_validation_failures = 0,
            .debug_logged_verifier_failures = 0,
            .debug_logged_skip_verifier = false,
            .debug_logged_insert_batches = 0,
            .debug_logged_backlog_drops = 0,
            .debug_target_repair_slot = null,
            .debug_logged_target_repair_candidates = 0,
            .debug_logged_target_repair_validation_failures = 0,
            .debug_logged_target_repair_verifier_failures = 0,
            .debug_logged_target_repair_verified = 0,
            .debug_logged_target_repair_deserialize_failures = 0,
        };
    }

    pub fn deinit(self: *ShredReceiver, allocator: Allocator) void {
        self.incoming_shreds.deinit();
        self.outgoing_pongs.deinit();
        self.seen_shred_packet_keys.deinit();
        self.verified_merkle_roots.deinit();
        self.packet_batch.deinit(allocator);
        self.shred_batch.deinit(allocator);
    }

    /// Run threads to listen/send over socket and handle all incoming packets.
    /// Returns when exit is set to true.
    pub fn run(self: *ShredReceiver, allocator: Allocator) !void {
        defer self.logger.info().log("exiting shred receiver");
        errdefer self.logger.err().log("error in shred receiver");

        const exit = ExitCondition{ .unordered = self.params.exit };

        // Create pipe from outgoing_pongs -> repair_socket
        const response_sender_thread = try SocketThread.spawnSender(
            allocator,
            .from(self.logger),
            self.params.repair_socket,
            &self.outgoing_pongs,
            exit,
            .empty,
        );
        defer response_sender_thread.join();

        // Create pipe from repair_socket -> incoming_shreds tagged .repair
        const repair_receiver_thread = try SocketThread.spawnReceiver(
            allocator,
            .from(self.logger),
            self.params.repair_socket,
            &self.incoming_shreds,
            exit,
            .from(.repair),
        );
        defer repair_receiver_thread.join();

        // Create pipe from turbine_socket -> incoming_shreds without a tagging.
        const turbine_receiver_thread = try SocketThread.spawnReceiver(
            allocator,
            .from(self.logger),
            self.params.turbine_socket,
            &self.incoming_shreds,
            exit,
            .empty,
        );
        defer turbine_receiver_thread.join();

        // Handle all incoming shreds from the channel.
        while (true) {
            self.incoming_shreds.waitToReceive(exit) catch break;
            try self.handleBatch(allocator);
        }
    }

    const DEFAULT_MAX_SHREDS_PER_ITER = 1024;

    fn handleBatch(self: *ShredReceiver, allocator: Allocator) !void {
        defer {
            for (self.shred_batch.items(.shred)) |shred| shred.deinit();
            self.shred_batch.clearRetainingCapacity();
        }

        if (self.canUseParallelParse()) {
            return self.handleBatchParallelParse(allocator);
        }

        const leader_schedules_with_infos = self.params.epoch_tracker.getLeaderSchedules() catch {
            // Leader schedule not yet populated (RpcLeaderScheduleService hasn't run yet).
            // Drain the channel to prevent backpressure and retry on the next call.
            var drained: usize = 0;
            while (self.incoming_shreds.tryReceive()) |_| drained += 1;
            if (drained > 0 and self.debug_logged_missing_leader_schedules < 8) {
                self.debug_logged_missing_leader_schedules += 1;
                self.logger.warn().logf(
                    "discarded shred batch because leader schedules are unavailable packets={}",
                    .{drained},
                );
            }
            return;
        };
        defer leader_schedules_with_infos.release();
        const leader_schedules = leader_schedules_with_infos.leader_schedules;

        self.trimIncomingBacklog();

        var packet_count: usize = 0;
        while (self.incoming_shreds.tryReceive()) |packet| {
            const is_repair = packet.flags.isSet(.repair);
            self.metrics.incReceived(is_repair);

            packet_count += 1;
            tracy.plot(u32, "shred-batch packets received", @intCast(packet_count));

            if (try self.handlePacket(allocator, &leader_schedules, packet, is_repair)) |shred| {
                self.metrics.received_shred.observe(shredSourceKind(is_repair, shred));
                try self.shred_batch.append(allocator, .{
                    .shred = shred,
                    .is_repair = is_repair,
                });
                if (self.shred_batch.len == self.max_shreds_per_iter) break;
            }
        }
        self.metrics.incoming_pending_packets.set(@intCast(self.incoming_shreds.len()));

        if (packet_count > 0 and self.debug_logged_batches < 8) {
            self.debug_logged_batches += 1;
            self.logger.info().logf(
                "received shred batch packets={} valid_shreds={}",
                .{ packet_count, self.shred_batch.len },
            );
        }

        const result = try self.params.inserter.insertShreds(
            allocator,
            self.shred_batch.items(.shred),
            self.shred_batch.items(.is_repair),
            .{
                .is_trusted = self.trusted_insert,
                .leader_schedules = &leader_schedules,
                .shred_tracker = self.params.tracker,
                .skip_recovery = self.skip_inserter_recovery,
                .skip_shred_tracker = self.skip_inserter_tracker,
                .skip_data_recovery_meta_load = self.skip_data_recovery_meta,
            },
        );
        self.metrics.passed_to_inserter_count.add(self.shred_batch.len);
        if (self.debug_logged_insert_batches < 8) {
            self.debug_logged_insert_batches += 1;
            self.logger.info().logf(
                "inserted shred batch candidate_count={}",
                .{self.shred_batch.len},
            );
        }

        try self.params.duplicate_handler.handleDuplicateSlots(allocator, &result);

        result.deinit();

        self.metrics.batch_size.observe(self.shred_batch.len);
    }

    fn canUseParallelParse(self: *const ShredReceiver) bool {
        return self.parallel_parse_workers > 1 and
            self.skip_shred_verifier and
            self.params.maybe_retransmit_shred_sender == null;
    }

    fn handleBatchParallelParse(self: *ShredReceiver, allocator: Allocator) !void {
        const leader_schedules_with_infos = self.params.epoch_tracker.getLeaderSchedules() catch {
            var drained: usize = 0;
            while (self.incoming_shreds.tryReceive()) |_| drained += 1;
            if (drained > 0 and self.debug_logged_missing_leader_schedules < 8) {
                self.debug_logged_missing_leader_schedules += 1;
                self.logger.warn().logf(
                    "discarded shred batch because leader schedules are unavailable packets={}",
                    .{drained},
                );
            }
            return;
        };
        defer leader_schedules_with_infos.release();
        const leader_schedules = leader_schedules_with_infos.leader_schedules;

        self.packet_batch.clearRetainingCapacity();
        defer self.packet_batch.clearRetainingCapacity();

        self.trimIncomingBacklog();

        var packet_count: usize = 0;
        while (self.incoming_shreds.tryReceive()) |packet| {
            const is_repair = packet.flags.isSet(.repair);
            self.metrics.incReceived(is_repair);
            packet_count += 1;
            tracy.plot(u32, "shred-batch packets received", @intCast(packet_count));

            if (packet.size == REPAIR_RESPONSE_SERIALIZED_PING_BYTES) {
                if (try handlePing(
                    allocator,
                    &packet,
                    self.metrics,
                    self.params.keypair,
                )) |pong_packet| {
                    try self.outgoing_pongs.send(pong_packet);
                    self.metrics.pong_sent_count.inc();
                }
                continue;
            }

            if (self.dedup_shred_packets) {
                if (layout.getShred(&packet)) |shred_payload| {
                    if (shredPacketKey(shred_payload)) |packet_key| {
                        const packet_entry = try self.seen_shred_packet_keys.getOrPut(packet_key);
                        if (packet_entry.found_existing) {
                            self.metrics.duplicate_packet_drop_count.inc();
                            continue;
                        }
                    }
                }
            }

            try self.packet_batch.append(allocator, .{
                .packet = packet,
                .is_repair = is_repair,
            });
            if (self.packet_batch.items.len == self.max_shreds_per_iter) break;
        }
        self.metrics.incoming_pending_packets.set(@intCast(self.incoming_shreds.len()));

        if (packet_count > 0 and self.debug_logged_batches < 8) {
            self.debug_logged_batches += 1;
            self.logger.info().logf(
                "received parallel shred packet batch packets={} candidates={} workers={}",
                .{ packet_count, self.packet_batch.items.len, self.parallel_parse_workers },
            );
        }

        try self.parsePacketsInParallel(allocator, self.packet_batch.items);

        const result = try self.params.inserter.insertShreds(
            allocator,
            self.shred_batch.items(.shred),
            self.shred_batch.items(.is_repair),
            .{
                .is_trusted = self.trusted_insert,
                .leader_schedules = &leader_schedules,
                .shred_tracker = self.params.tracker,
                .skip_recovery = self.skip_inserter_recovery,
                .skip_shred_tracker = self.skip_inserter_tracker,
                .skip_data_recovery_meta_load = self.skip_data_recovery_meta,
            },
        );
        self.metrics.passed_to_inserter_count.add(self.shred_batch.len);
        if (self.debug_logged_insert_batches < 8) {
            self.debug_logged_insert_batches += 1;
            self.logger.info().logf(
                "inserted parallel shred batch candidate_count={}",
                .{self.shred_batch.len},
            );
        }

        try self.params.duplicate_handler.handleDuplicateSlots(allocator, &result);

        result.deinit();

        self.metrics.batch_size.observe(self.shred_batch.len);
    }

    fn parsePacketsInParallel(
        self: *ShredReceiver,
        allocator: Allocator,
        packets: []const PacketBatchEntry,
    ) !void {
        if (packets.len == 0) return;

        const worker_count = @min(self.parallel_parse_workers, packets.len);
        var workers = try allocator.alloc(ParallelParseWorker, worker_count);
        defer allocator.free(workers);
        var threads = try allocator.alloc(std.Thread, worker_count);
        defer allocator.free(threads);

        const root_slot = self.params.epoch_tracker.root_slot.load(.monotonic);

        var timer = Timer.start();
        var initialized: usize = 0;
        defer {
            for (workers[0..initialized]) |*worker| worker.deinit();
        }
        var spawned: usize = 0;
        errdefer {
            for (threads[0..spawned]) |*thread| thread.join();
        }
        for (workers, 0..) |*worker, worker_index| {
            const start = worker_index * packets.len / worker_count;
            const end = (worker_index + 1) * packets.len / worker_count;
            worker.* = .{
                .packets = packets[start..end],
                .root_slot = root_slot,
                .shred_version = self.params.shred_version,
                .metrics = self.metrics,
                .drop_code_shreds = self.drop_code_shreds,
            };
            initialized += 1;
            threads[worker_index] = try std.Thread.spawn(.{}, ParallelParseWorker.run, .{worker});
            spawned += 1;
        }

        for (threads[0..spawned]) |*thread| thread.join();
        self.metrics.parallel_parse_batch_count.inc();
        self.metrics.parallel_parse_elapsed_us.add(timer.read().asMicros());
        self.metrics.parallel_parse_worker_count.set(@intCast(worker_count));

        var total_parsed: usize = 0;
        for (workers) |*worker| {
            if (worker.err) |err| return err;
            total_parsed += worker.parsed.len;
        }

        try self.shred_batch.ensureUnusedCapacity(allocator, total_parsed);
        for (workers) |*worker| {
            for (worker.parsed.items(.shred), worker.parsed.items(.is_repair)) |shred, is_repair| {
                self.shred_batch.appendAssumeCapacity(.{
                    .shred = shred,
                    .is_repair = is_repair,
                });
            }
            worker.moved = true;
        }
    }

    fn trimIncomingBacklog(self: *ShredReceiver) void {
        const max_pending_packets = self.max_pending_packets;
        const pending_packets = self.incoming_shreds.len();
        if (max_pending_packets == 0 or pending_packets <= max_pending_packets) {
            self.metrics.incoming_pending_packets.set(@intCast(pending_packets));
            return;
        }

        const target_pending_packets = if (self.drop_to_pending_packets > 0)
            self.drop_to_pending_packets
        else
            @min(max_pending_packets, self.max_shreds_per_iter);

        var dropped_packets: usize = 0;
        while (pending_packets - dropped_packets > target_pending_packets) {
            if (self.incoming_shreds.tryReceive()) |_| {
                dropped_packets += 1;
            } else {
                break;
            }
        }

        if (dropped_packets > 0) {
            self.metrics.stale_packet_drop_count.add(dropped_packets);
            if (self.debug_logged_backlog_drops < 16) {
                self.debug_logged_backlog_drops += 1;
                self.logger.warn().logf(
                    "dropped stale incoming shred packets pending_before={} dropped={} target_pending={}",
                    .{ pending_packets, dropped_packets, target_pending_packets },
                );
            }
        }
        self.metrics.incoming_pending_packets.set(@intCast(self.incoming_shreds.len()));
    }

    /// Handle a single packet and return a shred if it's a valid shred.
    fn handlePacket(
        self: *ShredReceiver,
        allocator: Allocator,
        leader_schedule: *const sig.core.leader_schedule.LeaderSchedules,
        packet: Packet,
        is_repair: bool,
    ) !?Shred {
        if (packet.size == REPAIR_RESPONSE_SERIALIZED_PING_BYTES) {
            if (try handlePing(
                allocator,
                &packet,
                self.metrics,
                self.params.keypair,
            )) |pong_packet| {
                try self.outgoing_pongs.send(pong_packet);
                self.metrics.pong_sent_count.inc();
            }
            return null;
        } else {
            const current_repair_target_slot = self.params.tracker.current_bottom_slot;
            if (is_repair) self.resetTargetRepairDebugIfSlotChanged(current_repair_target_slot);
            const target_payload = layout.getShred(&packet);
            const is_target_repair = is_repair and if (target_payload) |payload|
                layout.getSlot(payload) == current_repair_target_slot
            else
                false;
            if (is_target_repair and self.debug_logged_target_repair_candidates < 64) {
                self.debug_logged_target_repair_candidates += 1;
                self.logger.info().logf(
                    "target repair response candidate slot={?} index={?} size={} from={any}",
                    .{
                        if (target_payload) |payload| layout.getSlot(payload) else null,
                        if (target_payload) |payload| layout.getIndex(payload) else null,
                        packet.size,
                        packet.addr,
                    },
                );
            }
            const shred_payload = target_payload orelse {
                validateShred(
                    &packet,
                    self.params.epoch_tracker.root_slot.load(.monotonic),
                    self.params.shred_version,
                    std.math.maxInt(Slot),
                ) catch |err| {
                    self.metrics.discard.observe(err);
                    self.metrics.incValidationDiscard(is_repair, err);
                    if (self.debug_logged_validation_failures < 32) {
                        self.debug_logged_validation_failures += 1;
                        self.logger.warn().logf(
                            "discarded shred validation err={s} size={} slot={?} index={?} version={?} variant={?}",
                            .{
                                @errorName(err),
                                packet.size,
                                if (target_payload) |payload| layout.getSlot(payload) else null,
                                if (target_payload) |payload| layout.getIndex(payload) else null,
                                if (target_payload) |payload| layout.getVersion(payload) else null,
                                if (target_payload) |payload| layout.getShredVariant(payload) else null,
                            },
                        );
                    }
                    return null;
                };
                return error.InvalidVerifiedShred;
            };
            if (self.dedup_shred_packets) {
                if (shredPacketKey(shred_payload)) |packet_key| {
                    const packet_entry = try self.seen_shred_packet_keys.getOrPut(packet_key);
                    if (packet_entry.found_existing) {
                        self.metrics.duplicate_packet_drop_count.inc();
                        return null;
                    }
                }
            }
            const max_slot = std.math.maxInt(Slot); // TODO agave uses BankForks for this
            validateShred(
                &packet,
                self.params.epoch_tracker.root_slot.load(.monotonic),
                self.params.shred_version,
                max_slot,
            ) catch |err| {
                self.metrics.discard.observe(err);
                self.metrics.incValidationDiscard(is_repair, err);
                if (self.debug_logged_validation_failures < 32) {
                    self.debug_logged_validation_failures += 1;
                    const validation_payload = layout.getShred(&packet);
                    self.logger.warn().logf(
                        "discarded shred validation err={s} size={} slot={?} index={?} version={?} variant={?}",
                        .{
                            @errorName(err),
                            packet.size,
                            if (validation_payload) |payload| layout.getSlot(payload) else null,
                            if (validation_payload) |payload| layout.getIndex(payload) else null,
                            if (validation_payload) |payload| layout.getVersion(payload) else null,
                            if (validation_payload) |payload| layout.getShredVariant(payload) else null,
                        },
                    );
                }
                if (is_target_repair and self.debug_logged_target_repair_validation_failures < 64) {
                    self.debug_logged_target_repair_validation_failures += 1;
                    const target_validation_payload = layout.getShred(&packet);
                    self.logger.warn().logf(
                        "target repair response discarded validation err={s} size={} slot={?} index={?} version={?} variant={?} from={any}",
                        .{
                            @errorName(err),
                            packet.size,
                            if (target_validation_payload) |payload| layout.getSlot(payload) else null,
                            if (target_validation_payload) |payload| layout.getIndex(payload) else null,
                            if (target_validation_payload) |payload| layout.getVersion(payload) else null,
                            if (target_validation_payload) |payload| layout.getShredVariant(payload) else null,
                            packet.addr,
                        },
                    );
                }
                return null;
            };
            self.metrics.satisfactory_shred_count.inc();

            if (self.skip_shred_verifier) {
                self.metrics.skipped_verifier_count.inc();
                if (!self.debug_logged_skip_verifier) {
                    self.debug_logged_skip_verifier = true;
                    self.logger.warn().log("skipping shred verifier because SIG_SHRED_RECEIVER_SKIP_VERIFIER is enabled");
                }
            } else {
                shred_verifier.verifyShred(
                    &packet,
                    leader_schedule,
                    &self.verified_merkle_roots,
                    self.verifier_metrics,
                ) catch |err| {
                    self.verifier_metrics.fail.observe(err);
                    self.metrics.incVerifierDiscard(is_repair, err);
                    if (self.debug_logged_verifier_failures < 32) {
                        self.debug_logged_verifier_failures += 1;
                        self.logger.warn().logf(
                            "discarded shred verifier err={s} size={} slot={?} index={?} version={?} variant={?}",
                            .{
                                @errorName(err),
                                packet.size,
                                layout.getSlot(shred_payload),
                                layout.getIndex(shred_payload),
                                layout.getVersion(shred_payload),
                                layout.getShredVariant(shred_payload),
                            },
                        );
                    }
                    if (is_target_repair and self.debug_logged_target_repair_verifier_failures < 64) {
                        self.debug_logged_target_repair_verifier_failures += 1;
                        self.logger.warn().logf(
                            "target repair response discarded verifier err={s} size={} slot={?} index={?} version={?} variant={?} from={any}",
                            .{
                                @errorName(err),
                                packet.size,
                                layout.getSlot(shred_payload),
                                layout.getIndex(shred_payload),
                                layout.getVersion(shred_payload),
                                layout.getShredVariant(shred_payload),
                                packet.addr,
                            },
                        );
                    }
                    return null;
                };
                self.verifier_metrics.verified_count.inc();
            }

            if (self.params.maybe_retransmit_shred_sender) |retransmit_shred_sender| {
                try retransmit_shred_sender.send(packet);
            }

            if (is_target_repair and self.debug_logged_target_repair_verified < 64) {
                self.debug_logged_target_repair_verified += 1;
                self.logger.info().logf(
                    "target repair response verified slot={?} index={?} variant={?} from={any}",
                    .{
                        layout.getSlot(shred_payload),
                        layout.getIndex(shred_payload),
                        layout.getShredVariant(shred_payload),
                        packet.addr,
                    },
                );
            }
            if (self.drop_code_shreds) {
                const variant = layout.getShredVariant(shred_payload) orelse return null;
                if (variant.shred_type == .code) {
                    self.metrics.dropped_code_shred_count.inc();
                    return null;
                }
            }
            return Shred.fromPayload(allocator, shred_payload) catch |err| {
                self.metrics.incDeserializeFail(is_repair);
                if (is_target_repair and self.debug_logged_target_repair_deserialize_failures < 64) {
                    self.debug_logged_target_repair_deserialize_failures += 1;
                    self.logger.err().logf(
                        "target repair response deserialize failed slot={?} index={?} err={s} from={any}",
                        .{ layout.getSlot(shred_payload), layout.getIndex(shred_payload), @errorName(err), packet.addr },
                    );
                }
                self.logger.err().logf(
                    "failed to deserialize verified shred {?}.{?}: {}",
                    .{ layout.getSlot(shred_payload), layout.getIndex(shred_payload), err },
                );
                return null;
            };
        }
    }

    fn resetTargetRepairDebugIfSlotChanged(self: *ShredReceiver, slot: Slot) void {
        if (self.debug_target_repair_slot) |current_slot| {
            if (current_slot == slot) return;
        }

        self.debug_target_repair_slot = slot;
        self.debug_logged_target_repair_candidates = 0;
        self.debug_logged_target_repair_validation_failures = 0;
        self.debug_logged_target_repair_verifier_failures = 0;
        self.debug_logged_target_repair_verified = 0;
        self.debug_logged_target_repair_deserialize_failures = 0;
    }

    fn handlePing(
        allocator: std.mem.Allocator,
        packet: *const Packet,
        metrics: ShredReceiverMetrics,
        keypair: *const KeyPair,
    ) !?Packet {
        const repair_ping = bincode.readFromSlice(
            allocator,
            RepairPing,
            packet.data(),
            .{},
        ) catch {
            metrics.ping_deserialize_fail_count.inc();
            return null;
        };
        const ping = switch (repair_ping) {
            .ping => |ping| ping,
        };
        ping.verify() catch {
            metrics.ping_verify_fail_count.inc();
            return null;
        };
        metrics.valid_ping_count.inc();

        const reply: RepairMessage = .{ .pong = try .init(&ping, keypair) };
        return try .initFromBincode(packet.addr, reply);
    }
};

test "handleBatch/handlePacket" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const keypair = try sig.identity.KeyPair.generateDeterministic(.{1} ** 32);
    const root_slot = 0;
    const invalid_socket: sig.net.UdpSocket = .{
        .family = .ipv4,
        .handle = -1,
    };

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        random,
        root_slot,
        .INIT,
    );
    defer epoch_tracker.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var shred_tracker: BasicShredTracker = undefined;
    try shred_tracker.init(allocator, root_slot + 1, .noop, &registry, false);
    defer shred_tracker.deinit();

    var exit: Atomic(bool) = .init(false);
    const shred_version: Atomic(u16) = .init(0);

    var shred_receiver = try ShredReceiver.init(allocator, .noop, &registry, .{
        .keypair = &keypair,
        .exit = &exit,
        .repair_socket = invalid_socket,
        .turbine_socket = invalid_socket,
        .shred_version = &shred_version,
        .maybe_retransmit_shred_sender = null,
        .epoch_tracker = &epoch_tracker,
        .tracker = &shred_tracker,
        .inserter = ledger.shredInserter(),
        .duplicate_handler = .{
            .ledger_reader = ledger.reader(),
            .result_writer = ledger.resultWriter(),
            .epoch_tracker = &epoch_tracker,
            .duplicate_slots_sender = null,
            .push_msg_queue_mux = null,
            .keypair = &keypair,
            .logger = .noop,
        },
    });
    defer shred_receiver.deinit(allocator);

    // test repair packet
    {
        const ping = try Ping.init(.{1} ** 32, &keypair);
        const addr = sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 88);
        var packet = try Packet.initFromBincode(addr, RepairPing{ .ping = ping });
        packet.flags = .from(.repair);
        try shred_receiver.incoming_shreds.send(packet);
    }

    // test shred packet
    {
        const shreds = try sig.ledger.tests.loadShredsFromFile(
            allocator,
            sig.TEST_DATA_DIR ++ "shreds/merkle_root_metas_coding_test_shreds_3_1228.bin",
        );
        defer sig.ledger.tests.deinitShreds(allocator, shreds);
        const shred_data = shreds[0].payload();

        var packet: Packet = undefined;
        @memcpy(packet.buffer[0..shred_data.len], shred_data);
        packet.size = @intCast(shred_data.len);
        packet.addr = .initIpv4(.{ 0, 0, 0, 0 }, 0);
        packet.flags = .{};

        try shred_receiver.incoming_shreds.send(packet);
    }

    try shred_receiver.handleBatch(allocator);
}

test "handlePing" {
    const allocator = std.testing.allocator;
    var metrics_registry = sig.prometheus.Registry(.{}).init(allocator);
    defer metrics_registry.deinit();

    const shred_metrics = try metrics_registry.initStruct(ShredReceiverMetrics);

    const my_keypair = try sig.identity.KeyPair.generateDeterministic(.{1} ** 32);
    const ping = try Ping.init(.{1} ** 32, &my_keypair);
    const pong = try Pong.init(&ping, &my_keypair);

    const addr = sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 88);
    const input_ping_packet = try Packet.initFromBincode(addr, RepairPing{ .ping = ping });

    const expected_pong_packet = try Packet.initFromBincode(addr, RepairMessage{ .pong = pong });
    const actual_pong_packet = try ShredReceiver.handlePing(
        allocator,
        &input_ping_packet,
        shred_metrics,
        &my_keypair,
    );

    try std.testing.expectEqual(expected_pong_packet, actual_pong_packet);

    const evil_keypair = try sig.identity.KeyPair.generateDeterministic(.{64} ** 32);
    var evil_ping = ping;
    evil_ping.from = sig.core.Pubkey.fromPublicKey(&evil_keypair.public_key);
    const evil_ping_packet = try Packet.initFromBincode(addr, RepairPing{ .ping = evil_ping });
    try std.testing.expectEqual(null, try ShredReceiver.handlePing(
        allocator,
        &evil_ping_packet,
        shred_metrics,
        &evil_keypair,
    ));
}

fn validateShred(
    packet: *const Packet,
    root: Slot,
    shred_version: *const Atomic(u16),
    max_slot: Slot,
) ShredValidationError!void {
    const shred = layout.getShred(packet) orelse return error.insufficient_shred_size;
    const version = layout.getVersion(shred) orelse return error.missing_version;
    const slot = layout.getSlot(shred) orelse return error.slot_missing;
    const index = layout.getIndex(shred) orelse return error.index_missing;
    const variant = layout.getShredVariant(shred) orelse return error.variant_missing;

    if (version != shred_version.load(.acquire)) return error.wrong_version;
    if (slot > max_slot) return error.slot_too_new;
    switch (variant.shred_type) {
        .code => {
            if (index >= sig.ledger.shred.CodeShred.constants.max_per_slot) {
                return error.code_index_too_high;
            }
            if (slot <= root) return error.rooted_slot;
        },
        .data => {
            if (index >= sig.ledger.shred.DataShred.constants.max_per_slot) {
                return error.data_index_too_high;
            }
            const parent_slot_offset = layout.getParentSlotOffset(shred) orelse {
                return error.parent_slot_offset_missing;
            };
            const parent = slot -| @as(Slot, @intCast(parent_slot_offset));
            if (!verifyShredSlots(slot, parent, root)) return error.slot_verification_failed;
        },
    }

    // TODO: check for feature activation of enable_chained_merkle_shreds
    // 7uZBkJXJ1HkuP6R3MJfZs7mLwymBcDbKdqbF51ZWLier
    // https://github.com/solana-labs/solana/pull/34916
    // https://github.com/solana-labs/solana/pull/35076

    _ = layout.getLeaderSignature(shred) orelse return error.signature_missing;
    _ = layout.merkleRoot(shred) orelse return error.signed_data_missing;
}

/// TODO: this may need to move to ledger
fn verifyShredSlots(slot: Slot, parent: Slot, root: Slot) bool {
    if (slot == 0 and parent == 0 and root == 0) {
        return true; // valid write to slot zero.
    }
    // Ignore shreds that chain to slots before the root,
    // or have invalid parent >= slot.
    return root <= parent and parent < slot;
}

const REPAIR_RESPONSE_SERIALIZED_PING_BYTES = 132;

const RepairPing = union(enum) { ping: Ping };

const ReceivedShredKind = enum {
    turbine_data,
    turbine_code,
    repair_data,
    repair_code,
};

fn shredSourceKind(is_repair: bool, shred: Shred) ReceivedShredKind {
    return switch (shred) {
        .data => if (is_repair) .repair_data else .turbine_data,
        .code => if (is_repair) .repair_code else .turbine_code,
    };
}

pub const ShredReceiverMetrics = struct {
    received_count: *Counter,
    turbine_received_count: *Counter,
    repair_received_count: *Counter,
    incoming_pending_packets: *Gauge(u64),
    stale_packet_drop_count: *Counter,
    duplicate_packet_drop_count: *Counter,
    dropped_code_shred_count: *Counter,
    skipped_verifier_count: *Counter,
    satisfactory_shred_count: *Counter,
    passed_to_inserter_count: *Counter,
    valid_ping_count: *Counter,
    ping_deserialize_fail_count: *Counter,
    ping_verify_fail_count: *Counter,
    pong_sent_count: *Counter,
    turbine_deserialize_fail_count: *Counter,
    repair_deserialize_fail_count: *Counter,
    parallel_parse_batch_count: *Counter,
    parallel_parse_elapsed_us: *Counter,
    parallel_parse_worker_count: *Gauge(u64),
    batch_size: *Histogram,
    discard: *VariantCounter(ShredValidationError),
    turbine_validation_discard: *VariantCounter(ShredValidationError),
    repair_validation_discard: *VariantCounter(ShredValidationError),
    turbine_verifier_discard: *VariantCounter(shred_verifier.ShredVerificationFailure),
    repair_verifier_discard: *VariantCounter(shred_verifier.ShredVerificationFailure),
    received_shred: *VariantCounter(ReceivedShredKind),

    pub const prefix = "shred_receiver";
    pub const histogram_buckets = sig.prometheus.histogram.exponentialBuckets(2, -1, 8);

    pub fn incReceived(self: *const ShredReceiverMetrics, is_repair: bool) void {
        self.received_count.inc();
        if (is_repair) {
            self.repair_received_count.inc();
        } else {
            self.turbine_received_count.inc();
        }
    }

    pub fn incValidationDiscard(
        self: *const ShredReceiverMetrics,
        is_repair: bool,
        err: ShredValidationError,
    ) void {
        if (is_repair) {
            self.repair_validation_discard.observe(err);
        } else {
            self.turbine_validation_discard.observe(err);
        }
    }

    pub fn incVerifierDiscard(
        self: *const ShredReceiverMetrics,
        is_repair: bool,
        err: shred_verifier.ShredVerificationFailure,
    ) void {
        if (is_repair) {
            self.repair_verifier_discard.observe(err);
        } else {
            self.turbine_verifier_discard.observe(err);
        }
    }

    pub fn incDeserializeFail(self: *const ShredReceiverMetrics, is_repair: bool) void {
        if (is_repair) {
            self.repair_deserialize_fail_count.inc();
        } else {
            self.turbine_deserialize_fail_count.inc();
        }
    }
};

fn readEnvUsize(allocator: Allocator, key: []const u8, default: usize) usize {
    const raw = std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return default,
        else => return default,
    };
    defer allocator.free(raw);
    if (raw.len == 0) return default;
    return std.fmt.parseInt(usize, raw, 10) catch default;
}

fn readEnvBool(allocator: Allocator, key: []const u8, default: bool) bool {
    const raw = std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return default,
        else => return default,
    };
    defer allocator.free(raw);
    if (raw.len == 0) return default;
    if (std.mem.eql(u8, raw, "1")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "true")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "on")) return true;
    if (std.mem.eql(u8, raw, "0")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "false")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "no")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "off")) return false;
    return default;
}

fn shredPacketKey(shred_payload: []const u8) ?u128 {
    const slot = layout.getSlot(shred_payload) orelse return null;
    const index = layout.getIndex(shred_payload) orelse return null;
    const variant = layout.getShredVariant(shred_payload) orelse return null;
    const type_bit: u128 = switch (variant.shred_type) {
        .data => 0,
        .code => 1,
    };
    return (@as(u128, slot) << 33) |
        (@as(u128, index) << 1) |
        type_bit;
}

/// Something about the shred was unexpected, so we will discard it.
pub const ShredValidationError = error{
    insufficient_shred_size,
    missing_version,
    slot_missing,
    index_missing,
    variant_missing,
    wrong_version,
    slot_too_new,
    code_index_too_high,
    rooted_slot,
    data_index_too_high,
    parent_slot_offset_missing,
    slot_verification_failed,
    signature_missing,
    signed_data_missing,
};
