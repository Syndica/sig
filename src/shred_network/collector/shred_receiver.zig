const std = @import("std");
const network = @import("zig-network");
const tracy = @import("tracy");
const sig = @import("../../sig.zig");
const shred_network = @import("../lib.zig");

const bincode = sig.bincode;
const layout = sig.ledger.shred.layout;
const shred_verifier = shred_network.shred_verifier;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = sig.identity.KeyPair;
const Socket = network.Socket;

const BasicShredTracker = shred_network.shred_tracker.BasicShredTracker;
const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Histogram = sig.prometheus.Histogram;
const Packet = sig.net.Packet;
const Ping = sig.gossip.Ping;
const Pong = sig.gossip.Pong;
const RepairMessage = shred_network.repair_message.RepairMessage;
const Shred = sig.ledger.shred.Shred;
const ShredInserter = sig.ledger.ShredInserter;
const Slot = sig.core.Slot;
const SocketThread = sig.net.SocketThread;
const ExitCondition = sig.sync.ExitCondition;
const VariantCounter = sig.prometheus.VariantCounter;

const Logger = sig.trace.Logger("shred_receiver");
const VerifiedMerkleRoots = sig.utils.lru.LruCache(.non_locking, sig.core.Hash, void);

/// Analogous to [ShredFetchStage](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/shred_fetch_stage.rs#L34)
pub const ShredReceiver = struct {
    params: Params,
    logger: Logger,

    incoming_shreds: Channel(Packet),
    outgoing_pongs: Channel(Packet),

    metrics: ShredReceiverMetrics,
    verifier_metrics: shred_verifier.Metrics,

    verified_merkle_roots: VerifiedMerkleRoots,
    shred_batch: std.MultiArrayList(struct { shred: Shred, is_repair: bool }),

    const Params = struct {
        keypair: *const KeyPair,
        exit: *Atomic(bool),

        repair_socket: Socket,
        turbine_socket: Socket,

        /// me --> retransmit service
        maybe_retransmit_shred_sender: ?*Channel(Packet),

        shred_version: *const Atomic(u16),

        magic_tracker: *const sig.core.magic_info.MagicTracker,

        /// shared with repair
        tracker: *BasicShredTracker,
        inserter: ShredInserter,
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

        return ShredReceiver{
            .params = params,
            .logger = logger,
            .incoming_shreds = incoming_shreds,
            .outgoing_pongs = outgoing_pongs,
            .metrics = metrics,
            .verifier_metrics = verifier_metrics,
            .verified_merkle_roots = verified_merkle_roots,
            .shred_batch = .empty,
        };
    }

    pub fn deinit(self: *ShredReceiver, allocator: Allocator) void {
        self.incoming_shreds.deinit();
        self.outgoing_pongs.deinit();
        self.verified_merkle_roots.deinit();
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

    fn handleBatch(self: *ShredReceiver, allocator: Allocator) !void {
        defer {
            for (self.shred_batch.items(.shred)) |shred| shred.deinit();
            self.shred_batch.clearRetainingCapacity();
        }

        const leader_schedules = try self.params.magic_tracker.getLeaderSchedules();

        var packet_count: usize = 0;
        while (self.incoming_shreds.tryReceive()) |packet| {
            const is_repair = packet.flags.isSet(.repair);
            self.metrics.incReceived(is_repair);

            packet_count += 1;
            tracy.plot(u32, "shred-batch packets received", @intCast(packet_count));

            if (try self.handlePacket(allocator, &leader_schedules, packet)) |shred| {
                try self.shred_batch.append(allocator, .{
                    .shred = shred,
                    .is_repair = is_repair,
                });
                if (self.shred_batch.len == MAX_SHREDS_PER_ITER) break;
            }
        }

        const result = try self.params.inserter.insertShreds(
            allocator,
            self.shred_batch.items(.shred),
            self.shred_batch.items(.is_repair),
            .{
                .leader_schedules = &leader_schedules,
                .shred_tracker = self.params.tracker,
            },
        );
        self.metrics.passed_to_inserter_count.add(self.shred_batch.len);
        result.deinit();

        self.metrics.batch_size.observe(self.shred_batch.len);
    }

    const MAX_SHREDS_PER_ITER = 1024;

    /// Handle a single packet and return a shred if it's a valid shred.
    fn handlePacket(
        self: *ShredReceiver,
        allocator: Allocator,
        leader_schedule: *const sig.core.magic_leader_schedule.LeaderSchedules,
        packet: Packet,
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
            const max_slot = std.math.maxInt(Slot); // TODO agave uses BankForks for this
            validateShred(
                &packet,
                self.params.magic_tracker.root_slot.load(.monotonic),
                self.params.shred_version,
                max_slot,
            ) catch |err| {
                self.metrics.discard.observe(err);
                return null;
            };
            self.metrics.satisfactory_shred_count.inc();

            shred_verifier.verifyShred(
                &packet,
                leader_schedule,
                &self.verified_merkle_roots,
                self.verifier_metrics,
            ) catch |err| {
                self.verifier_metrics.fail.observe(err);
                return null;
            };
            self.verifier_metrics.verified_count.inc();

            if (self.params.maybe_retransmit_shred_sender) |retransmit_shred_sender| {
                try retransmit_shred_sender.send(packet);
            }

            const shred_payload = layout.getShred(&packet) orelse return error.InvalidVerifiedShred;
            return Shred.fromPayload(allocator, shred_payload) catch |err| {
                self.logger.err().logf(
                    "failed to deserialize verified shred {?}.{?}: {}",
                    .{ layout.getSlot(shred_payload), layout.getIndex(shred_payload), err },
                );
                return null;
            };
        }
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

        const reply: RepairMessage = .{ .pong = try Pong.init(&ping, keypair) };

        return try Packet.initFromBincode(
            sig.net.SocketAddr.fromEndpoint(&packet.addr),
            reply,
        );
    }
};

test "handleBatch/handlePacket" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const keypair = try sig.identity.KeyPair.generateDeterministic(.{1} ** 32);
    const root_slot = 0;
    const invalid_socket = Socket{
        .family = .ipv4,
        .internal = -1,
        .endpoint = null,
    };

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var magic_tracker = try sig.core.magic_info.MagicTracker.initForTest(
        allocator,
        random,
        root_slot,
        .INIT,
    );
    defer magic_tracker.deinit(allocator);

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var shred_tracker = try sig.shred_network.shred_tracker.BasicShredTracker.init(
        allocator,
        root_slot + 1,
        .noop,
        &registry,
    );
    defer shred_tracker.deinit();

    var exit = Atomic(bool).init(false);
    const shred_version = Atomic(u16).init(0);

    var shred_receiver = try ShredReceiver.init(allocator, .noop, &registry, .{
        .keypair = &keypair,
        .exit = &exit,
        .repair_socket = invalid_socket,
        .turbine_socket = invalid_socket,
        .shred_version = &shred_version,
        .maybe_retransmit_shred_sender = null,
        .magic_tracker = &magic_tracker,
        .tracker = &shred_tracker,
        .inserter = ledger.shredInserter(),
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
        packet.addr = .{ .address = .{ .ipv4 = .init(0, 0, 0, 0) }, .port = 0 };
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

pub const ShredReceiverMetrics = struct {
    received_count: *Counter,
    turbine_received_count: *Counter,
    repair_received_count: *Counter,
    satisfactory_shred_count: *Counter,
    passed_to_inserter_count: *Counter,
    valid_ping_count: *Counter,
    ping_deserialize_fail_count: *Counter,
    ping_verify_fail_count: *Counter,
    pong_sent_count: *Counter,
    batch_size: *Histogram,
    discard: *VariantCounter(ShredValidationError),

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
};

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
