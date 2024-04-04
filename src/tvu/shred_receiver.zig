const std = @import("std");
const sig = @import("../lib.zig");
const network = @import("zig-network");

const bincode = sig.bincode;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Atomic;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Socket = network.Socket;

const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Ping = sig.gossip.Ping;
const Pong = sig.gossip.Pong;
const RepairMessage = sig.tvu.RepairMessage;
const SocketThread = sig.net.SocketThread;

/// Analogous to `ShredFetchStage`
pub const ShredReceiver = struct {
    allocator: Allocator,
    keypair: *const KeyPair,
    exit: *Atomic(bool),
    logger: Logger,
    socket: *Socket,

    const Self = @This();

    /// Run threads to listen/send over socket and handle all incoming packets.
    /// Returns when exit is set to true.
    pub fn run(self: *Self) !void {
        defer self.logger.err("exiting shred receiver");
        errdefer self.logger.err("error in shred receiver");

        var sender = try SocketThread.initSender(self.allocator, self.logger, self.socket, self.exit);
        defer sender.deinit();
        var receiver = try SocketThread.initReceiver(self.allocator, self.logger, self.socket, self.exit);
        defer receiver.deinit();

        try self.runPacketHandler(receiver.channel, sender.channel);
    }

    /// Keep looping over packet channel and process the incoming packets.
    /// Returns when exit is set to true.
    fn runPacketHandler(
        self: *Self,
        receiver: *Channel(ArrayList(Packet)),
        sender: *Channel(ArrayList(Packet)),
    ) !void {
        while (!self.exit.load(.Unordered)) {
            var responses = ArrayList(Packet).init(self.allocator);
            if (try receiver.try_drain()) |batches| {
                for (batches) |batch| for (batch.items) |*packet| {
                    try self.handlePacket(packet, &responses);
                };
                if (responses.items.len > 0) {
                    try sender.send(responses);
                }
            } else {
                std.time.sleep(10_000_000);
            }
        }
    }

    /// Handle a single packet and return
    fn handlePacket(self: *Self, packet: *const Packet, responses: *ArrayList(Packet)) !void {
        if (packet.size == REPAIR_RESPONSE_SERIALIZED_PING_BYTES) {
            try self.handlePing(packet, responses);
        } else {
            const endpoint_str = try sig.net.endpointToString(self.allocator, &packet.addr);
            defer endpoint_str.deinit();
            self.logger.field("from_endpoint", endpoint_str.items)
                .infof("tvu: recv unknown shred message: {} bytes", .{packet.size});
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

        const endpoint_str = try sig.net.endpointToString(self.allocator, &packet.addr);
        defer endpoint_str.deinit();
        self.logger.field("from_endpoint", endpoint_str.items)
            .field("from_pubkey", &ping.from.string())
            .info("tvu: recv repair ping");
    }
};

const REPAIR_RESPONSE_SERIALIZED_PING_BYTES = 132;

const RepairPing = union(enum) { Ping: Ping };
