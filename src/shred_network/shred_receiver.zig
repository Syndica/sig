const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const shred_network = @import("lib.zig");

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
const SlotLeaders = sig.core.leader_schedule.SlotLeaders;
const SocketThread = sig.net.SocketThread;
const ExitCondition = sig.sync.ExitCondition;
const VariantCounter = sig.prometheus.VariantCounter;

const Logger = sig.trace.Logger("shred_receiver");
const VerifiedMerkleRoots = sig.utils.lru.LruCache(.non_locking, sig.core.Hash, void);

/// Analogous to [ShredFetchStage](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/shred_fetch_stage.rs#L34)
pub const ShredReceiver = struct {
    allocator: Allocator,
    keypair: *const KeyPair,
    exit: *Atomic(bool),
    logger: Logger,

    repair_socket: Socket,
    turbine_socket: Socket,

    /// me --> retransmit service
    maybe_retransmit_shred_sender: ?*Channel(Packet),

    shred_version: *const Atomic(u16),
    registry: *sig.prometheus.Registry(.{}),
    root_slot: Slot,
    leader_schedule: SlotLeaders,

    /// shared with repair
    tracker: *BasicShredTracker,
    inserter: ShredInserter,

    /// Run threads to listen/send over socket and handle all incoming packets.
    /// Returns when exit is set to true.
    pub fn run(self: *ShredReceiver) !void {
        defer self.logger.info().log("exiting shred receiver");
        errdefer self.logger.err().log("error in shred receiver");

        const exit = ExitCondition{ .unordered = self.exit };

        // Cretae pipe from response_sender -> repair_socket
        const response_sender = try Channel(Packet).create(self.allocator);
        defer response_sender.destroy();

        const response_sender_thread = try SocketThread.spawnSender(
            self.allocator,
            .from(self.logger),
            self.repair_socket,
            response_sender,
            exit,
        );
        defer response_sender_thread.join();

        // Incoming shreds channel (from socket thread)
        const incoming_shreds = try Channel(Packet).create(self.allocator);
        defer incoming_shreds.destroy();

        // Receive repair thread
        const repair_receiver = try SocketThread.spawnReceiverFlagged(
            self.allocator,
            .from(self.logger),
            self.repair_socket,
            incoming_shreds,
            exit,
            .from(.repair),
        );
        defer repair_receiver.join();

        // Receive turbine thread
        const turbine_receiver = try SocketThread.spawnReceiver(
            self.allocator,
            .from(self.logger),
            self.turbine_socket,
            incoming_shreds,
            exit,
        );
        defer turbine_receiver.join();

        var verified_merkle_roots = try VerifiedMerkleRoots.init(self.allocator, 1024);
        defer verified_merkle_roots.deinit();

        const metrics = try self.registry.initStruct(ShredReceiverMetrics);
        const verifier_metrics = try self.registry.initStruct(shred_verifier.Metrics);

        var shred_batch = std.MultiArrayList(struct { shred: Shred, is_repair: bool }).empty;
        defer shred_batch.deinit(self.allocator);

        // Handle all incoming shreds from the channel.
        while (!exit.shouldExit()) {
            defer for (shred_batch.items(.shred)) |shred| shred.deinit();

            incoming_shreds.waitToReceive(exit) catch break;
            while (incoming_shreds.tryReceive()) |packet| {
                const is_repair = packet.flags.isSet(.repair);
                metrics.incReceived(is_repair);

                if (try self.handlePacket(
                    packet,
                    response_sender,
                    &verified_merkle_roots,
                    verifier_metrics,
                    metrics,
                )) |shred| shred_batch.appendAssumeCapacity(.{
                    .shred = shred,
                    .is_repair = packet.flags.isSet(.repair),
                });
                if (shred_batch.len == MAX_SHREDS_PER_ITER) break;
            }

            const result = try self.inserter.insertShreds(
                shred_batch.items(.shred),
                shred_batch.items(.is_repair),
                .{
                    .slot_leaders = self.leader_schedule,
                    .shred_tracker = self.tracker,
                },
            );
            metrics.passed_to_inserter_count.add(shred_batch.len);
            result.deinit();

            metrics.batch_size.observe(shred_batch.len);
        }
    }

    const MAX_SHREDS_PER_ITER = 1024;

    /// Handle a single packet and return a shred if it's a valid shred.
    fn handlePacket(
        self: ShredReceiver,
        packet: Packet,
        response_sender: *Channel(Packet),
        verified_merkle_roots: *VerifiedMerkleRoots,
        verifier_metrics: shred_verifier.Metrics,
        metrics: ShredReceiverMetrics,
    ) !?Shred {
        if (packet.size == REPAIR_RESPONSE_SERIALIZED_PING_BYTES) {
            if (try self.handlePing(&packet, metrics)) |pong_packet| {
                try response_sender.send(pong_packet);
                metrics.pong_sent_count.inc();
            }
            return null;
        } else {
            const max_slot = std.math.maxInt(Slot); // TODO agave uses BankForks for this
            validateShred(&packet, self.root_slot, self.shred_version, max_slot) catch |err| {
                metrics.discard.observe(err);
                return null;
            };
            metrics.satisfactory_shred_count.inc();

            if (shred_verifier.verifyShred(
                &packet,
                self.leader_schedule,
                verified_merkle_roots,
                verifier_metrics,
            )) |_| {
                verifier_metrics.verified_count.inc();
                if (self.maybe_retransmit_shred_sender) |retransmit_shred_sender| {
                    try retransmit_shred_sender.send(packet);
                }
                const shred_payload = layout.getShred(&packet) orelse
                    return error.InvalidVerifiedShred;
                return Shred.fromPayload(self.allocator, shred_payload) catch |e| {
                    self.logger.err().logf(
                        "failed to deserialize verified shred {?}.{?}: {}",
                        .{ layout.getSlot(shred_payload), layout.getIndex(shred_payload), e },
                    );
                    return null;
                };
            } else |err| {
                verifier_metrics.fail.observe(err);
                return null;
            }
        }
    }

    /// Handle a ping message and returns the repair message.
    fn handlePing(
        self: *const ShredReceiver,
        packet: *const Packet,
        metrics: ShredReceiverMetrics,
    ) !?Packet {
        return handlePingInner(self.allocator, packet, metrics, self.keypair);
    }

    fn handlePingInner(
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
            .Ping => |ping| ping,
        };
        ping.verify() catch {
            metrics.ping_verify_fail_count.inc();
            return null;
        };
        metrics.valid_ping_count.inc();

        const reply: RepairMessage = .{ .Pong = try Pong.init(&ping, keypair) };

        return try Packet.initFromBincode(
            sig.net.SocketAddr.fromEndpoint(&packet.addr),
            reply,
        );
    }
};

test "handlePing" {
    const allocator = std.testing.allocator;
    var metrics_registry = sig.prometheus.Registry(.{}).init(allocator);
    defer metrics_registry.deinit();

    const shred_metrics = try metrics_registry.initStruct(ShredReceiverMetrics);

    const my_keypair = try sig.identity.KeyPair.generateDeterministic(.{1} ** 32);
    const ping = try Ping.init(.{1} ** 32, &my_keypair);
    const pong = try Pong.init(&ping, &my_keypair);

    const addr = sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 88);
    const input_ping_packet = try Packet.initFromBincode(addr, RepairPing{ .Ping = ping });

    const expected_pong_packet = try Packet.initFromBincode(addr, RepairMessage{ .Pong = pong });
    const actual_pong_packet = try ShredReceiver.handlePingInner(
        allocator,
        &input_ping_packet,
        shred_metrics,
        &my_keypair,
    );

    try std.testing.expectEqual(expected_pong_packet, actual_pong_packet);

    const evil_keypair = try sig.identity.KeyPair.generateDeterministic(.{64} ** 32);
    var evil_ping = ping;
    evil_ping.from = sig.core.Pubkey.fromPublicKey(&evil_keypair.public_key);
    const evil_ping_packet = try Packet.initFromBincode(addr, RepairPing{ .Ping = evil_ping });
    try std.testing.expectEqual(null, try ShredReceiver.handlePingInner(
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

const RepairPing = union(enum) { Ping: Ping };

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
