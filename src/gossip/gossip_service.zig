const std = @import("std");
const ClusterInfo = @import("cluster_info.zig").ClusterInfo;
const network = @import("zig-network");
const EndPoint = network.EndPoint;
const Packet = @import("packet.zig").Packet;
const PACKET_DATA_SIZE = @import("packet.zig").PACKET_DATA_SIZE;
const Channel = @import("../sync/channel.zig").Channel;
const Thread = std.Thread;
const AtomicBool = std.atomic.Atomic(bool);
const UdpSocket = network.Socket;
const Tuple = std.meta.Tuple;
const SocketAddr = @import("net.zig").SocketAddr;
const Protocol = @import("protocol.zig").Protocol;
const Ping = @import("protocol.zig").Ping;
const bincode = @import("../bincode/bincode.zig");
const crds = @import("../gossip/crds.zig");
const CrdsValue = crds.CrdsValue;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const get_wallclock = @import("../gossip/crds.zig").get_wallclock;

const _crds_table = @import("../gossip/crds_table.zig");
const CrdsTable = _crds_table.CrdsTable;
const CrdsError = _crds_table.CrdsError;
const Logger = @import("../trace/log.zig").Logger;
const GossipRoute = _crds_table.GossipRoute;

const pull_request = @import("../gossip/pull_request.zig");
const pull_response = @import("../gossip/pull_response.zig");

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
var gpa = gpa_allocator.allocator();

const PacketChannel = Channel(Packet);
const ProtocolMessage = struct { from_addr: EndPoint, message: Protocol };
const ProtocolChannel = Channel(ProtocolMessage);

const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;
const CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS: u64 = 30000;
const FAILED_INSERTS_RETENTION_MS: u64 = 20_000;
const MAX_VALUES_PER_PUSH: u64 = PACKET_DATA_SIZE * 64;

pub const GossipService = struct {
    cluster_info: *ClusterInfo,
    gossip_socket: UdpSocket,
    exit_sig: AtomicBool,
    packet_channel: PacketChannel,
    responder_channel: PacketChannel,
    crds_table: CrdsTable,
    allocator: std.mem.Allocator,
    verified_channel: ProtocolChannel,

    push_msg_queue: std.ArrayList(CrdsValue),
    push_msg_queue_lock: std.Thread.Mutex = .{},
    push_cursor: u64 = 0,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        cluster_info: *ClusterInfo,
        gossip_socket: UdpSocket,
        exit: AtomicBool,
    ) !Self {
        var packet_channel = PacketChannel.init(allocator, 10000);
        var verified_channel = ProtocolChannel.init(allocator, 10000);
        var responder_channel = PacketChannel.init(allocator, 10000);

        var crds_table = try CrdsTable.init(allocator);

        return Self{
            .cluster_info = cluster_info,
            .gossip_socket = gossip_socket,
            .exit_sig = exit,
            .packet_channel = packet_channel,
            .responder_channel = responder_channel,
            .verified_channel = verified_channel,
            .crds_table = crds_table,
            .allocator = allocator,
            .push_msg_queue = std.ArrayList(CrdsValue).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.packet_channel.deinit();
        self.responder_channel.deinit();
        self.verified_channel.deinit();

        self.crds_table.deinit();
        self.push_msg_queue.deinit();
    }

    pub fn run(self: *Self, logger: *Logger) !void {
        const id = self.cluster_info.our_contact_info.pubkey;
        logger.infof("running gossip service at {any} with pubkey {s}", .{ self.gossip_socket.getLocalEndPoint(), id.cached_str.? });
        defer self.deinit();

        // process input threads
        var receiver_handle = try Thread.spawn(.{}, Self.read_gossip_socket, .{
            &self.gossip_socket,
            &self.packet_channel,
            logger,
        });
        var packet_verifier_handle = try Thread.spawn(.{}, Self.verify_packets, .{
            self.allocator,
            &self.packet_channel,
            &self.verified_channel,
        });
        var packet_handle = try Thread.spawn(.{}, Self.process_packets, .{
            self.allocator,
            &self.crds_table,
            &self.verified_channel,
            logger,
        });

        // periodically send output thread
        var gossip_loop_handle = try Thread.spawn(.{}, Self.gossip_loop, .{
            self,
            logger,
        });

        // outputer thread
        var responder_handle = try Thread.spawn(.{}, Self.responder, .{
            self,
        });

        packet_verifier_handle.join();
        responder_handle.join();
        receiver_handle.join();
        packet_handle.join();
        gossip_loop_handle.join();
    }

    fn responder(self: *Self) !void {
        while (self.responder_channel.receive()) |p| {
            _ = try self.gossip_socket.sendTo(p.from, p.data[0..p.size]);
        }
    }

    fn verify_packets(
        allocator: std.mem.Allocator,
        packet_channel: *PacketChannel,
        verified_channel: *ProtocolChannel,
    ) !void {
        var failed_protocol_msgs: usize = 0;

        while (packet_channel.receive()) |packet| {
            var protocol_message = bincode.readFromSlice(
                allocator,
                Protocol,
                packet.data[0..packet.size],
                bincode.Params.standard,
            ) catch {
                failed_protocol_msgs += 1;
                std.debug.print("failed to deserialize protocol message", .{});
                continue;
            };
            defer bincode.free(allocator, protocol_message);

            // TODO: verify protocol message signatures
            protocol_message.sanitize() catch {
                std.debug.print("failed to sanitize protocol message", .{});
                continue;
            };

            // TODO: send the pointers over the channel vs item copy
            const msg = ProtocolMessage{ .from_addr = packet.from, .message = protocol_message };
            verified_channel.send(msg);
        }
    }

    fn gossip_loop(self: *Self, logger: *Logger) !void {
        // solana-gossip spy -- local node for testing
        const peer = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 8000).toEndpoint();

        while (true) {
            // new pings
            try self.send_ping(&peer, logger);
            try self.push_contact_info();

            // new pull msgs
            var filters = new_pull_requests(
                self.allocator,
                &self.crds_table,
                pull_request.MAX_BLOOM_SIZE,
            );
            defer pull_request.deinit_crds_filters(&filters);

            // new push msgs
            try drain_push_queue_to_crds_table(
                &self.crds_table,
                &self.push_msg_queue,
                &self.push_msg_queue_lock,
            );

            var push_msgs = try new_push_messages(
                self.allocator,
                &self.crds_table,
                &self.push_cursor,
            );
            defer push_msgs.deinit();

            try trim_crds_table(&self.crds_table);

            std.time.sleep(std.time.ns_per_s * 1);
        }
    }

    fn new_pull_requests(
        allocator: std.mem.Allocator,
        crds_table: *CrdsTable,
        bloom_size: usize,
    ) std.ArrayList(pull_request.CrdsFilter) {
        var filters = pull_request.build_crds_filters(allocator, crds_table, bloom_size) catch {
            // TODO: handle this -- crds store not enough data?
            std.debug.print("failed to build crds filters", .{});
            return std.ArrayList(pull_request.CrdsFilter).init(allocator);
        };
        return filters;
    }

    fn trim_crds_table(crds_table: *CrdsTable) !void {
        const now = get_wallclock();

        const purged_cutoff_timestamp = now -| (5 * CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS);
        try crds_table.trim_purged_values(purged_cutoff_timestamp);

        const failed_insert_cutoff_timestamp = now -| FAILED_INSERTS_RETENTION_MS;
        try crds_table.trim_failed_inserts_values(failed_insert_cutoff_timestamp);
    }

    fn send_ping(self: *Self, peer: *const EndPoint, logger: *Logger) !void {
        var protocol = Protocol{ .PingMessage = Ping.random(self.cluster_info.our_keypair) };
        var out = [_]u8{0} ** PACKET_DATA_SIZE;
        var bytes = try bincode.writeToSlice(out[0..], protocol, bincode.Params.standard);

        logger.debugf("sending a ping message to: {any}", .{peer});
        self.responder_channel.send(
            Packet.init(peer.*, out, bytes.len),
        );
    }

    fn push_contact_info(self: *Self) !void {
        const id = self.cluster_info.our_contact_info.pubkey;
        const gossip_endpoint = try self.gossip_socket.getLocalEndPoint();
        const gossip_addr = SocketAddr.init_ipv4(gossip_endpoint.address.ipv4.value, gossip_endpoint.port);

        var legacy_contact_info = crds.LegacyContactInfo.default();
        legacy_contact_info.gossip = gossip_addr;
        legacy_contact_info.id = id;

        var crds_data = crds.CrdsData{
            .LegacyContactInfo = legacy_contact_info,
        };
        var crds_value = try crds.CrdsValue.initSigned(crds_data, self.cluster_info.our_keypair);

        self.push_msg_queue_lock.lock();
        defer self.push_msg_queue_lock.unlock();

        try self.push_msg_queue.append(crds_value);
    }

    fn drain_push_queue_to_crds_table(
        crds_table: *CrdsTable,
        push_msg_queue: *std.ArrayList(CrdsValue),
        push_msg_queue_lock: *std.Thread.Mutex,
    ) !void {
        const wallclock = get_wallclock();

        push_msg_queue_lock.lock();
        defer push_msg_queue_lock.unlock();

        crds_table.write();
        defer crds_table.release_write();

        while (push_msg_queue.popOrNull()) |crds_value| {
            crds_table.insert(crds_value, wallclock, GossipRoute.LocalMessage) catch {};
        }
    }

    fn new_push_messages(
        allocator: std.mem.Allocator,
        crds_table: *CrdsTable,
        push_cursor: *u64,
    ) !std.AutoHashMap(Pubkey, CrdsValue) {
        crds_table.read();
        defer crds_table.release_read();

        var buf: [64]crds.CrdsVersionedValue = undefined;
        var entries = try crds_table.get_entries_with_cursor(&buf, push_cursor);

        const timeout = CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS;
        const wallclock = get_wallclock();

        var total_byte_size: usize = 0;
        const max_bytes = MAX_VALUES_PER_PUSH;

        var push_messages = std.AutoHashMap(Pubkey, CrdsValue).init(allocator);

        // TODO: replace with active set
        var rng = std.rand.DefaultPrng.init(wallclock);
        const peer_pubkey = Pubkey.random(rng.random(), .{ .skip_encoding = true });

        for (entries) |entry| {
            const value = entry.value;

            const entry_time = value.wallclock();
            const too_old = entry_time < wallclock -| timeout;
            const too_new = entry_time > wallclock +| timeout;
            if (too_old or too_new) {
                continue;
            }

            const byte_size = try bincode.get_serialized_size(allocator, value, bincode.Params{});
            total_byte_size +|= byte_size;

            if (total_byte_size > max_bytes) {
                break;
            }

            // TODO: add value to active set's nodes
            try push_messages.put(peer_pubkey, value);
        }

        return push_messages;
    }

    fn read_gossip_socket(
        gossip_socket: *UdpSocket,
        packet_channel: *PacketChannel,
        logger: *Logger,
    ) !void {
        // we close the chan if no more packet's can ever be produced
        defer packet_channel.close();

        // handle packet reads
        var read_buf: [PACKET_DATA_SIZE]u8 = undefined;
        @memset(&read_buf, 0);

        var bytes_read: usize = undefined;
        while (bytes_read != 0) {
            var recv_meta = try gossip_socket.receiveFrom(&read_buf);
            bytes_read = recv_meta.numberOfBytes;

            // send packet through channel
            packet_channel.send(Packet.init(recv_meta.sender, read_buf, bytes_read));

            // reset buffer
            @memset(&read_buf, 0);
        }

        logger.debugf("reading gossip exiting...", .{});
    }

    pub fn process_packets(
        allocator: std.mem.Allocator,
        crds_table: *CrdsTable,
        verified_channel: *ProtocolChannel,
        logger: *Logger,
    ) !void {
        while (verified_channel.receive()) |protocol_message| {
            // note: to recieve PONG messages (from a local spy node) from a PING
            // you need to modify: streamer/src/socket.rs
            // pub fn check(&self, addr: &SocketAddr) -> bool {
            //     return true;
            // }

            var message = protocol_message.message;
            var from_addr = protocol_message.from_addr;
            _ = from_addr;

            switch (message) {
                .PongMessage => |*pong| {
                    if (pong.signature.verify(pong.from, &pong.hash.data)) {
                        logger.debugf("got a pong message", .{});
                    } else {
                        logger.debugf("pong message verification failed...", .{});
                    }
                },
                .PingMessage => |*ping| {
                    if (ping.signature.verify(ping.from, &ping.token)) {
                        logger.debugf("got a ping message", .{});
                    } else {
                        logger.debugf("ping message verification failed...", .{});
                    }
                },
                .PushMessage => |*push| {
                    logger.debugf("got a push message: {any}", .{protocol_message});
                    const values = push[1];
                    // TODO: handle prune messages
                    insert_crds_values(crds_table, values, logger, GossipRoute.PushMessage, CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS);
                },
                .PullResponse => |*pull| {
                    logger.debugf("got a pull message: {any}", .{protocol_message});
                    const values = pull[1];
                    insert_crds_values(crds_table, values, logger, GossipRoute.PullResponse, CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS);
                },
                .PullRequest => |*pull| {
                    var filter = pull[0];
                    var value = pull[1]; // contact info
                    const now = get_wallclock();

                    const crds_values = try pull_response.filter_crds_values(
                        allocator,
                        crds_table,
                        &value,
                        &filter,
                        100,
                        now,
                    );
                    // TODO: send them out as a pull response
                    _ = crds_values;
                },
                else => {
                    logger.debugf("got a protocol message: {any}", .{protocol_message});
                },
            }
        }
    }

    pub fn insert_crds_values(crds_table: *CrdsTable, values: []crds.CrdsValue, logger: *Logger, route: GossipRoute, timeout: u64) void {
        var now = get_wallclock();

        crds_table.write();
        defer crds_table.release_write();

        for (values) |value| {
            const value_time = value.wallclock();
            const is_too_new = value_time > now +| timeout;
            const is_too_old = value_time < now -| timeout;
            if (is_too_new or is_too_old) {
                continue;
            }

            crds_table.insert(value, now, route) catch |err| switch (err) {
                CrdsError.OldValue => {
                    logger.debugf("failed to insert into crds: {any}", .{value});
                },
                else => {
                    logger.debugf("failed to insert into crds with unkown error: {any}", .{err});
                },
            };
        }
    }
};

test "gossip.gossip_service: new pull messages" {
    const allocator = std.testing.allocator;

    var crds_table = try CrdsTable.init(allocator);
    defer crds_table.deinit();

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var rng = std.rand.DefaultPrng.init(get_wallclock());

    for (0..20) |_| {
        var value = try CrdsValue.random(rng.random(), keypair);
        try crds_table.insert(value, get_wallclock(), null);
    }

    var filters = GossipService.new_pull_requests(allocator, &crds_table, 2);
    defer pull_request.deinit_crds_filters(&filters);

    try std.testing.expect(filters.items.len > 0);
}

test "gossip.gossip_service: new push messages" {
    const allocator = std.testing.allocator;

    var crds_table = try CrdsTable.init(allocator);
    defer crds_table.deinit();

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var rng = std.rand.DefaultPrng.init(get_wallclock());
    var value = try CrdsValue.random(rng.random(), keypair);

    var push_queue = std.ArrayList(CrdsValue).init(allocator);
    defer push_queue.deinit();
    var mutex = std.Thread.Mutex{};

    try push_queue.append(value);
    try GossipService.drain_push_queue_to_crds_table(
        &crds_table,
        &push_queue,
        &mutex,
    );
    try std.testing.expect(crds_table.len() == 1);

    var cursor: usize = 0;
    var msgs = try GossipService.new_push_messages(
        allocator,
        &crds_table,
        &cursor,
    );

    try std.testing.expect(cursor == 1);
    try std.testing.expect(msgs.count() == 1);
    msgs.deinit();

    msgs = try GossipService.new_push_messages(
        allocator,
        &crds_table,
        &cursor,
    );

    try std.testing.expect(cursor == 1);
    try std.testing.expect(msgs.count() == 0);
    msgs.deinit();
}

test "gossip.gossip_service: test packet verification" {
    const allocator = std.testing.allocator;

    var packet_channel = PacketChannel.init(allocator, 100);
    defer packet_channel.deinit();

    var verified_channel = ProtocolChannel.init(allocator, 100);
    defer verified_channel.deinit();

    var packet_verifier_handle = try Thread.spawn(.{}, GossipService.verify_packets, .{
        allocator,
        &packet_channel,
        &verified_channel,
    });

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var id = Pubkey.fromPublicKey(&keypair.public_key, true);

    var rng = std.rand.DefaultPrng.init(get_wallclock());
    var value = try CrdsValue.initSigned(crds.CrdsData.random_from_index(rng.random(), 0), keypair);
    var values = [_]crds.CrdsValue{value};
    const protocol_msg = Protocol{
        .PushMessage = .{ id, &values },
    };

    var peer = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 0);
    var from = peer.toEndpoint();

    var buf = [_]u8{0} ** PACKET_DATA_SIZE;
    var out = try bincode.writeToSlice(buf[0..], protocol_msg, bincode.Params{});
    var packet = Packet.init(from, buf, out.len);

    for (0..10) |_| {
        packet_channel.send(packet);
    }

    // send one which fails sanitization
    var value_v2 = try CrdsValue.initSigned(crds.CrdsData.random_from_index(rng.random(), 1), keypair);
    value_v2.data.EpochSlots[0] = crds.MAX_EPOCH_SLOTS;
    var values_v2 = [_]crds.CrdsValue{value_v2};
    const protocol_msg_v2 = Protocol{
        .PushMessage = .{ id, &values_v2 },
    };
    var buf_v2 = [_]u8{0} ** PACKET_DATA_SIZE;
    var out_v2 = try bincode.writeToSlice(buf_v2[0..], protocol_msg_v2, bincode.Params{});
    var packet_v2 = Packet.init(from, buf_v2, out_v2.len);
    packet_channel.send(packet_v2);

    // send one with a incorrect signature

    for (0..10) |_| {
        var msg = verified_channel.receive().?;
        try std.testing.expect(msg.message.PushMessage[0].equals(&id));
    }
    try std.testing.expect(verified_channel.buffer.items.len == 0);

    packet_channel.close();
    verified_channel.close();
    packet_verifier_handle.join();
}

test "gossip.gossip_service: process contact_info push packet" {
    const allocator = std.testing.allocator;
    var crds_table = try CrdsTable.init(allocator);
    defer crds_table.deinit();

    var verified_channel = ProtocolChannel.init(allocator, 100);
    defer verified_channel.deinit();

    var logger = Logger.init(allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var packet_handle = try Thread.spawn(
        .{},
        GossipService.process_packets,
        .{ allocator, &crds_table, &verified_channel, logger },
    );

    // send a push message
    var kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk, true);

    // new contact info
    var legacy_contact_info = crds.LegacyContactInfo.default();
    var crds_data = crds.CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    };
    var crds_value = try crds.CrdsValue.initSigned(crds_data, kp);
    var values = [_]crds.CrdsValue{crds_value};
    const msg = Protocol{
        .PushMessage = .{ id, &values },
    };

    // packet
    const peer = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 8000).toEndpoint();
    const protocol_msg = ProtocolMessage{
        .from_addr = peer,
        .message = msg,
    };
    verified_channel.send(protocol_msg);

    // correct insertion into table
    var buf2: [100]crds.CrdsVersionedValue = undefined;
    std.time.sleep(std.time.ns_per_s);
    var res = try crds_table.get_contact_infos(&buf2);
    try std.testing.expect(res.len == 1);

    verified_channel.close();
    packet_handle.join();
}
