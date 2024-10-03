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
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Ping = sig.gossip.Ping;
const Pong = sig.gossip.Pong;
const RepairMessage = shred_collector.repair_message.RepairMessage;
const Slot = sig.core.Slot;
const SocketThread = sig.net.SocketThread;

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
            for (receivers) |receiver| {
                while (receiver.receive()) |packet| {
                    try self.handlePacket(packet, response_sender, is_repair);
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
            if (try self.handlePing(&packet)) |p| try response_sender.send(p);
        } else {
            const max_slot = std.math.maxInt(Slot); // TODO agave uses BankForks for this
            if (shouldDiscardShred(&packet, self.root_slot, self.shred_version, max_slot)) {
                return;
            }
            var our_packet = packet;
            if (is_repair) our_packet.flags.set(.repair);
            try self.unverified_shred_sender.send(our_packet);
        }
    }

    /// Handle a ping message and returns the repair message.
    fn handlePing(self: *const Self, packet: *const Packet) !?Packet {
        const repair_ping = bincode.readFromSlice(self.allocator, RepairPing, &packet.data, .{}) catch {
            self.metrics.invalid_repair_pings.inc();
            return null;
        };
        const ping = repair_ping.Ping;
        ping.verify() catch {
            self.metrics.invalid_repair_pings.inc();
            return null;
        };
        const reply: RepairMessage = .{ .Pong = try Pong.init(&ping, self.keypair) };

        var reply_packet = Packet.default();
        const reply_bytes = try bincode.writeToSlice(&reply_packet.data, reply, .{});
        reply_packet.size = reply_bytes.len;
        reply_packet.addr = packet.addr;
        return reply_packet;
    }
};

fn shouldDiscardShred(
    packet: *const Packet,
    root: Slot,
    shred_version: *const Atomic(u16),
    max_slot: Slot,
) bool {
    const shred = layout.getShred(packet) orelse return true;
    const version = layout.getVersion(shred) orelse return true;
    const slot = layout.getSlot(shred) orelse return true;
    const index = layout.getIndex(shred) orelse return true;
    const variant = layout.getShredVariant(shred) orelse return true;

    if (version != shred_version.load(.acquire)) return true;
    if (slot > max_slot) return true;
    switch (variant.shred_type) {
        .code => {
            if (index >= sig.ledger.shred.code_shred_constants.max_per_slot) return true;
            if (slot <= root) return true;
        },
        .data => {
            if (index >= sig.ledger.shred.data_shred_constants.max_per_slot) return true;
            const parent_offset = layout.getParentOffset(shred) orelse return true;
            const parent = slot -| @as(Slot, @intCast(parent_offset));
            if (!verifyShredSlots(slot, parent, root)) return true;
        },
    }

    // TODO: check for feature activation of enable_chained_merkle_shreds
    // 7uZBkJXJ1HkuP6R3MJfZs7mLwymBcDbKdqbF51ZWLier
    // https://github.com/solana-labs/solana/pull/34916
    // https://github.com/solana-labs/solana/pull/35076

    _ = layout.getSignature(shred) orelse return true;
    _ = layout.getSignedData(shred) orelse return true;

    return false;
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
    invalid_repair_pings: *sig.prometheus.Counter,

    pub fn init() !ShredReceiverMetrics {
        const registry = sig.prometheus.globalRegistry();
        return .{ .invalid_repair_pings = try registry.getOrCreateCounter("invalid_repair_pings") };
    }
};
