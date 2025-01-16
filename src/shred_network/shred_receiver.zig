const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const shred_network = @import("lib.zig");

const bincode = sig.bincode;
const layout = sig.ledger.shred.layout;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
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
const SocketPipe = sig.net.SocketPipe;
const ExitCondition = sig.sync.ExitCondition;
const VariantCounter = sig.prometheus.VariantCounter;

const NUM_TVU_RECEIVERS = 2;

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

    /// A shared instance of an event to support waiting on multiple Channels.
    const ReceiverSignal = struct {
        event: std.Thread.ResetEvent = .{},
        hook: Channel(Packet).SendHook = .{ .after_send = afterSend },

        fn afterSend(hook: *Channel(Packet).SendHook, _: *Channel(Packet)) void {
            const self: *ReceiverSignal = @alignCast(@fieldParentPtr("hook", hook));
            self.event.set();
        }

        fn waitUntilSent(self: *ReceiverSignal, exit: ExitCondition) error{Exit}!void {
            while (true) {
                self.event.timedWait(1 * std.time.ns_per_s) catch {};
                if (exit.shouldExit()) return error.Exit;
                if (self.event.isSet()) return self.event.reset();
            }
        }
    };

    /// Run threads to listen/send over socket and handle all incoming packets.
    /// Returns when exit is set to true.
    pub fn run(self: *Self) !void {
        defer self.logger.err().log("exiting shred receiver");
        errdefer self.logger.err().log("error in shred receiver");

        var receive_signal = ReceiverSignal{};
        const exit = ExitCondition{ .unordered = self.exit };

        // Cretae pipe from response_sender -> repair_socket
        const response_sender = try Channel(Packet).create(self.allocator);
        defer response_sender.destroy();

        const response_sender_pipe = try SocketPipe.initSender(
            self.allocator,
            self.logger.unscoped(),
            self.repair_socket,
            response_sender,
            exit,
        );
        defer response_sender_pipe.deinit(self.allocator);

        // Create pipe from repair_socket -> response_receiver.
        const response_receiver = try Channel(Packet).create(self.allocator);
        response_receiver.send_hook = &receive_signal.hook;
        defer response_receiver.destroy();

        const response_receiver_pipe = try SocketPipe.initReceiver(
            self.allocator,
            self.logger.unscoped(),
            self.repair_socket,
            response_receiver,
            exit,
        );
        defer response_receiver_pipe.deinit(self.allocator);

        // Create pipe from turbine_socket -> turbine_receiver.
        const turbine_receiver = try Channel(Packet).create(self.allocator);
        turbine_receiver.send_hook = &receive_signal.hook;
        defer turbine_receiver.destroy();

        const turbine_receiver_pipe = try SocketPipe.initReceiver(
            self.allocator,
            self.logger.unscoped(),
            self.turbine_socket,
            turbine_receiver,
            .{ .unordered = self.exit },
        );
        defer turbine_receiver_pipe.deinit(self.allocator);

        // Run thread to handle incoming packets. Stops when exit is set.
        while (true) {
            receive_signal.waitUntilSent(exit) catch break;
            try self.runPacketHandler(response_sender, response_receiver, true);
            try self.runPacketHandler(response_sender, turbine_receiver, false);
        }
    }

    fn runPacketHandler(
        self: *Self,
        response_sender: *Channel(Packet),
        receiver: *Channel(Packet),
        comptime is_repair: bool,
    ) !void {
        var packet_count: usize = 0;
        while (receiver.tryReceive()) |packet| {
            self.metrics.incReceived(is_repair);
            packet_count += 1;
            try self.handlePacket(packet, response_sender, is_repair);
        }
        self.metrics.observeBatchSize(is_repair, packet_count);
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
        const repair_ping = bincode.readFromSlice(
            self.allocator,
            RepairPing,
            &packet.data,
            .{},
        ) catch {
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
