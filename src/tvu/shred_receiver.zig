const std = @import("std");
const network = @import("zig-network");
const sig = @import("../lib.zig");

const bincode = sig.bincode;
const layout = sig.tvu.shred_layout;

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
const RepairMessage = sig.tvu.RepairMessage;
const Slot = sig.core.Slot;
const SocketThread = sig.net.SocketThread;

/// Use this in a single thread where you want to keep accessing
/// a value that's stored in an atomic, but you don't want to do
/// an expensive `load` operation every time you read it, and
/// you're fine with reading a slightly stale value each time.
///
/// Periodically call `update` to refresh the value.
///
/// The `cache` field and `update` methods are NOT thread safe.
/// Do not read the `cache` while executing `update`
pub fn CachedAtomic(comptime T: type) type {
    return struct {
        atomic: *Atomic(T),
        cache: T,

        const Self = @This();

        pub fn init(atomic: *Atomic(T)) Self {
            return .{
                .atomic = atomic,
                .cache = atomic.load(.Monotonic),
            };
        }

        pub fn update(self: *Self) void {
            self.cache = self.atomic.load(.Monotonic);
        }
    };
}

/// Analogous to `ShredFetchStage`  TODO permalinks
pub const ShredReceiver = struct {
    allocator: Allocator,
    keypair: *const KeyPair,
    exit: *Atomic(bool),
    logger: Logger,
    repair_socket: *Socket,
    tvu_socket: *Socket,
    outgoing_shred_channel: *Channel(ArrayList(Packet)),
    shred_version: CachedAtomic(u16),

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
        while (!self.exit.load(.Unordered)) {
            inline for (receivers) |receiver| {
                var responses = ArrayList(Packet).init(self.allocator);
                try receiver.tryDrainRecycle(&buf);
                if (buf.items.len > 0) {
                    for (buf.items) |batch| {
                        for (batch.items) |*packet| {
                            try self.handlePacket(packet, &responses);
                        }
                        try self.outgoing_shred_channel.send(batch);
                    }
                    if (responses.items.len > 0) {
                        try sender.send(responses);
                    }
                } else {
                    std.time.sleep(10 * std.time.ns_per_ms);
                }
                self.shred_version.update();
            }
        }
    }

    /// Handle a single packet and return
    fn handlePacket(self: *Self, packet: *Packet, responses: *ArrayList(Packet)) !void {
        if (packet.size == REPAIR_RESPONSE_SERIALIZED_PING_BYTES) {
            try self.handlePing(packet, responses);
            packet.set(.discard);
        } else {
            const endpoint_str = try endpointToString(self.allocator, &packet.addr);
            defer endpoint_str.deinit();
            // self.logger.field("from_endpoint", endpoint_str.items)
            //     .debugf("tvu: recv shred message: {} bytes", .{packet.size});

            // TODO figure out these values
            const root = 0;
            const max_slot = std.math.maxInt(Slot);
            if (shouldDiscardShred(packet, root, self.shred_version.cache, max_slot)) {
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
        // self.logger.field("from_endpoint", endpoint_str.items)
        //     .field("from_pubkey", &ping.from.string())
        //     .info("tvu: recv repair ping");
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
            if (index >= sig.tvu.MAX_CODE_SHREDS_PER_SLOT) return true;
            if (slot <= root) return true;
        },
        .Data => {
            if (index >= sig.tvu.MAX_DATA_SHREDS_PER_SLOT) return true;
            const parent_offset = layout.getParentOffset(shred) orelse return true;
            const parent = slot -| @as(Slot, @intCast(parent_offset));
            if (!verifyShredSlots(slot, parent, root)) return true;
        },
    }

    // TODO: should we check for enable_chained_merkle_shreds?

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
