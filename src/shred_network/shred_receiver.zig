const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const shred_network = @import("lib.zig");

const bincode = sig.bincode;
const layout = sig.ledger.shred.layout;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = sig.identity.KeyPair;
const Socket = network.Socket;

const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Histogram = sig.prometheus.Histogram;
const ScopedLogger = sig.trace.ScopedLogger;
const Packet = sig.net.Packet;
const Ping = sig.gossip.Ping;
const Pong = sig.gossip.Pong;
const RepairMessage = shred_network.repair_message.RepairMessage;
const Slot = sig.core.Slot;
const SocketThread = sig.net.SocketThread;
const ExitCondition = sig.sync.ExitCondition;
const VariantCounter = sig.prometheus.VariantCounter;

/// Analogous to [ShredFetchStage](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/shred_fetch_stage.rs#L34)
pub const ShredReceiver = struct {
    allocator: Allocator,
    keypair: *const KeyPair,
    exit: *Atomic(bool),
    logger: ScopedLogger(@typeName(Self)),
    repair_socket: Socket,
    turbine_socket: Socket,
    /// me --> shred verifier
    unverified_shred_sender: *Channel(Packet),
    shred_version: *const Atomic(u16),
    metrics: ShredReceiverMetrics,
    root_slot: Slot, // TODO: eventually, this should be handled by BankForks

    const Self = @This();

    /// Run threads to listen/send over socket and handle all incoming packets.
    /// Returns when exit is set to true.
    pub fn run(self: *Self) !void {
        defer self.logger.err().log("exiting shred receiver");
        errdefer self.logger.err().log("error in shred receiver");

        const exit = ExitCondition{ .unordered = self.exit };

        // Cretae pipe from response_sender -> repair_socket
        const response_sender = try Channel(Packet).create(self.allocator);
        defer response_sender.destroy();

        const response_sender_thread = try SocketThread.spawnSender(
            self.allocator,
            self.logger.unscoped(),
            self.repair_socket,
            response_sender,
            exit,
        );
        defer response_sender_thread.join();

        // Run a packetHandler thread which pipes from repair_socket -> handlePacket.
        const response_thread = try std.Thread.spawn(.{}, runPacketHandler, .{
            self,
            response_sender,
            self.repair_socket,
            exit,
            true, // is_repair
        });
        defer response_thread.join();

        // Run a packetHandler thread which pipes from turbine_socket -> handlePacket.
        const turbine_thread = try std.Thread.spawn(.{}, runPacketHandler, .{
            self,
            response_sender,
            self.turbine_socket,
            exit,
            false, // is_repair
        });
        defer turbine_thread.join();
    }

    fn runPacketHandler(
        self: *Self,
        response_sender: *Channel(Packet),
        receiver_socket: Socket,
        exit: ExitCondition,
        comptime is_repair: bool,
    ) !void {
        // Setup a channel.
        const receiver = try Channel(Packet).create(self.allocator);
        defer receiver.destroy();

        // Receive from the socket into the channel.
        const receiver_thread = try SocketThread.spawnReceiver(
            self.allocator,
            self.logger.unscoped(),
            receiver_socket,
            receiver,
            exit,
        );
        defer receiver_thread.join();

        // Handle packets from the channel.
        while (true) {
            receiver.waitToReceive(exit) catch break;
            var packet_count: usize = 0;
            while (receiver.tryReceive()) |packet| {
                self.metrics.incReceived(is_repair);
                packet_count += 1;
                try self.handlePacket(packet, response_sender, is_repair);
            }
            self.metrics.observeBatchSize(is_repair, packet_count);
        }
    }

    /// Handle a single packet and return.
    fn handlePacket(
        self: Self,
        packet: Packet,
        response_sender: *Channel(Packet),
        comptime is_repair: bool,
    ) !void {
        if (packet.size == REPAIR_RESPONSE_SERIALIZED_PING_BYTES) {
            if (try self.handlePing(&packet)) |pong_packet| {
                try response_sender.send(pong_packet);
                self.metrics.pong_sent_count.inc();
            }
        } else {
            const max_slot = std.math.maxInt(Slot); // TODO agave uses BankForks for this
            validateShred(&packet, self.root_slot, self.shred_version, max_slot) catch |err| {
                self.metrics.discard.observe(err);
                return;
            };
            var our_packet = packet;
            if (is_repair) our_packet.flags.set(.repair);
            self.metrics.satisfactory_shred_count.inc();
            try self.unverified_shred_sender.send(our_packet);
        }
    }

    /// Handle a ping message and returns the repair message.
    fn handlePing(self: *const Self, packet: *const Packet) !?Packet {
        return handlePingInner(self.allocator, packet, self.metrics, self.keypair);
    }

    fn handlePingInner(
        allocator: std.mem.Allocator,
        packet: *const Packet,
        metrics: ShredReceiverMetrics,
        keypair: *const KeyPair,
    ) !?Packet {
        const repair_ping = bincode.deserializeSlice(
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

/// TODO: this may need to move to blockstore
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
    valid_ping_count: *Counter,
    ping_deserialize_fail_count: *Counter,
    ping_verify_fail_count: *Counter,
    pong_sent_count: *Counter,
    repair_batch_size: *Histogram,
    turbine_batch_size: *Histogram,
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

    pub fn observeBatchSize(
        self: *const ShredReceiverMetrics,
        is_repair: bool,
        packet_count: usize,
    ) void {
        if (is_repair) {
            self.repair_batch_size.observe(packet_count);
        } else {
            self.turbine_batch_size.observe(packet_count);
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
