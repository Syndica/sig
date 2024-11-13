const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const shred_collector = @import("lib.zig");

const bincode = sig.bincode;
const layout = sig.ledger.shred.layout;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Socket = network.Socket;

const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Histogram = sig.prometheus.Histogram;
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Ping = sig.gossip.Ping;
const Pong = sig.gossip.Pong;
const RepairMessage = shred_collector.repair_message.RepairMessage;
const Slot = sig.core.Slot;
const SocketThread = sig.net.SocketThread;
const VariantCounter = sig.prometheus.VariantCounter;

const NUM_TVU_RECEIVERS = 2;

/// Analogous to [ShredFetchStage](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/shred_fetch_stage.rs#L34)
pub const ShredReceiver = struct {
    allocator: Allocator,
    keypair: *const KeyPair,
    exit: *Atomic(bool),
    logger: Logger,
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

        var response_sender = try SocketThread
            .initSender(self.allocator, self.logger, self.repair_socket, self.exit);
        defer response_sender.deinit(self.allocator);
        var repair_receiver = try SocketThread
            .initReceiver(self.allocator, self.logger, self.repair_socket, self.exit);
        defer repair_receiver.deinit(self.allocator);

        var turbine_receivers: [NUM_TVU_RECEIVERS]SocketThread = undefined;
        for (0..NUM_TVU_RECEIVERS) |i| {
            turbine_receivers[i] = try SocketThread.initReceiver(
                self.allocator,
                self.logger,
                self.turbine_socket,
                self.exit,
            );
        }
        defer for (turbine_receivers) |r| r.deinit(self.allocator);

        var turbine_channels: [NUM_TVU_RECEIVERS]*Channel(Packet) = undefined;
        for (&turbine_receivers, &turbine_channels) |*receiver, *channel| {
            channel.* = receiver.channel;
        }

        const turbine_thread = try std.Thread.spawn(
            .{},
            Self.runPacketHandler,
            .{ self, &turbine_channels, response_sender.channel, false },
        );
        const receiver_thread = try std.Thread.spawn(
            .{},
            Self.runPacketHandler,
            .{ self, &.{repair_receiver.channel}, response_sender.channel, true },
        );
        turbine_thread.join();
        receiver_thread.join();
    }

    /// Keep looping over packet channel and process the incoming packets.
    /// Returns when exit is set to true.
    fn runPacketHandler(
        self: *Self,
        receivers: []const *Channel(Packet),
        response_sender: *Channel(Packet),
        comptime is_repair: bool,
    ) !void {
        while (!self.exit.load(.acquire)) {
            std.time.sleep(1_000_00_0);
            for (receivers) |receiver| {
                var packet_count: usize = 0;
                while (receiver.receive()) |packet| {
                    self.metrics.received_count.inc();
                    packet_count += 1;
                    try self.handlePacket(packet, response_sender, is_repair);
                }
                if (is_repair) {
                    self.metrics.repair_batch_size.observe(packet_count);
                } else {
                    self.metrics.turbine_batch_size.observe(packet_count);
                }
            }
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
        const repair_ping = bincode.readFromSlice(self.allocator, RepairPing, &packet.data, .{}) catch {
            self.metrics.ping_deserialize_fail_count.inc();
            return null;
        };
        const ping = repair_ping.Ping;
        ping.verify() catch {
            self.metrics.ping_verify_fail_count.inc();
            return null;
        };
        self.metrics.valid_ping_count.inc();
        const reply: RepairMessage = .{ .Pong = try Pong.init(&ping, self.keypair) };

        var reply_packet = Packet.default();
        const reply_bytes = try bincode.writeToSlice(&reply_packet.data, reply, .{});
        reply_packet.size = reply_bytes.len;
        reply_packet.addr = packet.addr;
        return reply_packet;
    }
};

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
            if (index >= sig.ledger.shred.code_shred_constants.max_per_slot) {
                return error.code_index_too_high;
            }
            if (slot <= root) return error.rooted_slot;
        },
        .data => {
            if (index >= sig.ledger.shred.data_shred_constants.max_per_slot) {
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
