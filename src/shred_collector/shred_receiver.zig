const std = @import("std");
const network = @import("zig-network");
const sig = @import("../lib.zig");

const bincode = sig.bincode;
const layout = sig.shred_collector.shred_layout;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Socket = network.Socket;

const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Ping = sig.gossip.Ping;
const Pong = sig.gossip.Pong;
const RepairMessage = sig.shred_collector.RepairMessage;
const Slot = sig.core.Slot;
const SocketThread = sig.net.SocketThread;

const endpointToString = sig.net.endpointToString;

/// Analogous to [ShredFetchStage](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/shred_fetch_stage.rs#L34)
pub const ShredReceiver = struct {
    allocator: Allocator,
    keypair: *const KeyPair,
    exit: *Atomic(bool),
    logger: Logger,
    repair_socket: Socket,
    tvu_socket: Socket,
    outgoing_shred_channel: *Channel(ArrayList(Packet)),
    shred_version: *const Atomic(u16),

    const Self = @This();

    /// Run threads to listen/send over socket and handle all incoming packets.
    /// Returns when exit is set to true.
    pub fn run(self: *Self) !void {
        defer self.logger.err("exiting shred receiver");
        errdefer self.logger.err("error in shred receiver");

        var sender = try SocketThread
            .initSender(self.allocator, self.logger, self.repair_socket, self.exit);
        defer sender.deinit();
        var repair_receiver = try SocketThread
            .initReceiver(self.allocator, self.logger, self.repair_socket, self.exit);
        defer repair_receiver.deinit();

        const num_tvu_receivers = 2;
        var tvu_receivers: [num_tvu_receivers]*Channel(ArrayList(Packet)) = undefined;
        for (0..num_tvu_receivers) |i| {
            tvu_receivers[i] = (try SocketThread.initReceiver(
                self.allocator,
                self.logger,
                self.tvu_socket,
                self.exit,
            )).channel;
        }
        defer for (tvu_receivers) |r| r.deinit();
        const x = try std.Thread.spawn(
            .{},
            Self.runPacketHandler,
            .{ self, tvu_receivers, sender.channel },
        );
        const y = try std.Thread.spawn(
            .{},
            Self.runPacketHandler,
            .{ self, .{repair_receiver.channel}, sender.channel },
        );
        x.join();
        y.join();
    }

    /// Keep looping over packet channel and process the incoming packets.
    /// Returns when exit is set to true.
    fn runPacketHandler(
        self: *Self,
        receivers: anytype,
        sender: *Channel(ArrayList(Packet)),
    ) !void {
        var buf = ArrayList(ArrayList(Packet)).init(self.allocator);
        while (!self.exit.load(.unordered)) {
            inline for (receivers) |receiver| {
                var responses = ArrayList(Packet).init(self.allocator);
                try receiver.tryDrainRecycle(&buf);
                if (buf.items.len > 0) {
                    const shred_version = self.shred_version.load(.monotonic);
                    for (buf.items) |batch| {
                        for (batch.items) |*packet| {
                            try self.handlePacket(packet, &responses, shred_version);
                        }
                        try self.outgoing_shred_channel.send(batch);
                    }
                    if (responses.items.len > 0) {
                        try sender.send(responses);
                    }
                } else {
                    std.time.sleep(10 * std.time.ns_per_ms);
                }
            }
        }
    }

    /// Handle a single packet and return
    fn handlePacket(
        self: *Self,
        packet: *Packet,
        responses: *ArrayList(Packet),
        shred_version: u16,
    ) !void {
        if (packet.size == REPAIR_RESPONSE_SERIALIZED_PING_BYTES) {
            try self.handlePing(packet, responses);
            packet.set(.discard);
        } else {
            const endpoint_str = try endpointToString(self.allocator, &packet.addr);
            defer endpoint_str.deinit();

            // TODO set correct values once using snapshot + blockstore
            const root = 0;
            const max_slot = std.math.maxInt(Slot);
            if (shouldDiscardShred(packet, root, shred_version, max_slot)) {
                packet.set(.discard);
            }
        }
    }

    /// Handle a ping message and return
    fn handlePing(self: *Self, packet: *const Packet, responses: *ArrayList(Packet)) !void {
        const repair_ping = bincode.readFromSlice(self.allocator, RepairPing, &packet.data, .{}) catch |e| {
            self.logger.errf("could not deserialize ping: {} - {any}", .{ e, packet.data[0..packet.size] });
            return;
        };
        const ping = repair_ping.Ping;
        ping.verify() catch |e| {
            self.logger.errf("ping failed verification: {} - {any}", .{ e, packet.data[0..packet.size] });
            return;
        };

        const reply = RepairMessage{ .Pong = try Pong.init(&ping, self.keypair) };
        const reply_packet = try responses.addOne();
        reply_packet.addr = packet.addr;
        const reply_bytes = try bincode.writeToSlice(&reply_packet.data, reply, .{});
        reply_packet.size = reply_bytes.len;

        const endpoint_str = try endpointToString(self.allocator, &packet.addr);
        defer endpoint_str.deinit();
    }
};

fn shouldDiscardShred(
    packet: *const Packet,
    root: Slot,
    shred_version: u16,
    max_slot: Slot,
) bool {
    const shred = layout.getShred(packet) orelse return true;
    const version = layout.getVersion(shred) orelse return true;
    const slot = layout.getSlot(shred) orelse return true;
    const index = layout.getIndex(shred) orelse return true;
    const variant = layout.getShredVariant(shred) orelse return true;

    if (version != shred_version) return true;
    if (slot > max_slot) return true;
    switch (variant.shred_type) {
        .Code => {
            if (index >= sig.shred_collector.coding_shred.max_per_slot) return true;
            if (slot <= root) return true;
        },
        .Data => {
            if (index >= sig.shred_collector.data_shred.max_per_slot) return true;
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
