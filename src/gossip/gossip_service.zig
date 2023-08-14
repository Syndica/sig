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
const Ping = @import("ping_pong.zig").Ping;
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
const CrdsFilter = pull_request.CrdsFilter;
const MAX_NUM_PULL_REQUESTS = pull_request.MAX_NUM_PULL_REQUESTS;

const pull_response = @import("../gossip/pull_response.zig");
const ActiveSet = @import("../gossip/active_set.zig").ActiveSet;

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
var gpa = gpa_allocator.allocator();

const PacketChannel = Channel(Packet);
const ProtocolMessage = struct { from_addr: EndPoint, message: Protocol };
const ProtocolChannel = Channel(ProtocolMessage);

const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;
const CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS: u64 = 30000;
const FAILED_INSERTS_RETENTION_MS: u64 = 20_000;

const MAX_PACKETS_PER_PUSH: usize = 64;
const MAX_BYTES_PER_PUSH: u64 = PACKET_DATA_SIZE * @as(u64, MAX_PACKETS_PER_PUSH);

const PUSH_MESSAGE_MAX_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;

const GOSSIP_SLEEP_MILLIS: u64 = 100;

const NUM_ACTIVE_SET_ENTRIES: usize = 25;

pub const GossipService = struct {
    cluster_info: *ClusterInfo,
    gossip_socket: UdpSocket,
    exit_sig: AtomicBool,
    packet_channel: PacketChannel,
    responder_channel: PacketChannel,
    crds_table: CrdsTable,
    allocator: std.mem.Allocator,
    verified_channel: ProtocolChannel,

    active_set: ActiveSet,
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
            .active_set = ActiveSet.init(),
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
            _ = try self.gossip_socket.sendTo(p.addr, p.data[0..p.size]);
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
                std.debug.print("failed to deserialize protocol message\n", .{});
                continue;
            };
            defer bincode.free(allocator, protocol_message);

            protocol_message.sanitize() catch {
                std.debug.print("failed to sanitize protocol message\n", .{});
                continue;
            };

            protocol_message.verify_signature() catch {
                std.debug.print("failed to verify protocol message signature\n", .{});
                continue;
            };

            // TODO: send the pointers over the channel (similar to PinnedVec) vs item copy
            const msg = ProtocolMessage{ .from_addr = packet.addr, .message = protocol_message };
            verified_channel.send(msg);
        }
    }

    fn gossip_loop(self: *Self, logger: *Logger) !void {
        // solana-gossip spy -- local node for testing
        const peer = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 8000).toEndpoint();
        var last_push_ts: u64 = 0;
        var should_send_pull_requests = true;

        const my_contact_info = try self.get_contact_info();
        const my_keypair = self.cluster_info.our_keypair;
        const my_pubkey = my_contact_info.id();
        const my_shred_version = my_contact_info.data.LegacyContactInfo.shred_version;

        while (true) {
            const top_of_loop_ts = get_wallclock();

            // new pings
            try self.send_ping(&peer, logger);

            // new pull msgs
            if (should_send_pull_requests) {
                // update wallclock and sign
                my_contact_info.wallclock = get_wallclock();
                const my_contact_info_value = try crds.CrdsValue.initSigned(crds.CrdsData{
                    .LegacyContactInfo = my_contact_info,
                }, my_keypair);

                var pull_packets = new_pull_requests(
                    self.allocator,
                    &self.crds_table,
                    pull_request.MAX_BLOOM_SIZE,
                    my_contact_info_value,
                    logger,
                ) catch |e| blk: {
                    std.debug.print("failed to generate pull requests: {any}\n", .{e});
                    break :blk std.ArrayList(Packet).init(self.allocator);
                };
                defer pull_packets.deinit();

                // send packets
                for (pull_packets.items) |packet| {
                    self.responder_channel.send(packet);
                }
            }
            // every other loop
            should_send_pull_requests = !should_send_pull_requests;

            // new push msgs
            try drain_push_queue_to_crds_table(
                &self.crds_table,
                &self.push_msg_queue,
                &self.push_msg_queue_lock,
            );
            var push_packets = try new_push_messages(
                self.allocator,
                &self.crds_table,
                &self.active_set,
                my_pubkey,
                &self.push_cursor,
            );
            defer push_packets.deinit();

            for (push_packets.items) |packet| {
                self.responder_channel.send(packet);
            }

            // trim data
            try trim_crds_table(&self.crds_table);

            // periodic things
            if (top_of_loop_ts - last_push_ts > CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 2) {
                // update wallclock and sign
                my_contact_info.wallclock = get_wallclock();
                var my_contact_info_value = try crds.CrdsValue.initSigned(crds.CrdsData{
                    .LegacyContactInfo = my_contact_info,
                }, my_keypair);

                // push contact info
                self.push_msg_queue_lock.lock();
                try self.push_msg_queue.append(my_contact_info_value);
                self.push_msg_queue_lock.unlock();

                // reset push active set
                try self.active_set.reset(&self.crds_table, my_pubkey, my_shred_version);
                last_push_ts = get_wallclock();
            }

            // sleep
            const elapsed_ts = get_wallclock() - top_of_loop_ts;
            if (elapsed_ts < GOSSIP_SLEEP_MILLIS) {
                const time_left_ms = GOSSIP_SLEEP_MILLIS - elapsed_ts;
                std.time.sleep(time_left_ms * std.time.ns_per_ms);
            }
        }
    }

    pub fn get_gossip_nodes(
        crds_table: *CrdsTable, // reads to get contact infos
        my_pubkey: *const Pubkey, // used to filter out ourself
        my_shred_version: u16, // used to filter matching shredversions
        nodes: []crds.LegacyContactInfo, // output
        comptime MAX_SIZE: usize, // max_size == nodes.len but comptime for init of stack array
        now: u64, // filters old values
    ) ![]crds.LegacyContactInfo {
        std.debug.assert(MAX_SIZE == nodes.len);

        crds_table.read();
        var buf: [MAX_SIZE]crds.CrdsVersionedValue = undefined;
        const contact_infos = try crds_table.get_contact_infos(&buf);
        crds_table.release_read();

        if (contact_infos.len == 0) {
            return nodes[0..0];
        }

        // filter only valid gossip addresses
        const GOSSIP_ACTIVE_TIMEOUT = 60 * std.time.ms_per_s;
        const too_old_ts = now -| GOSSIP_ACTIVE_TIMEOUT;

        var node_index: usize = 0;
        for (contact_infos) |contact_info| {
            const peer_info = contact_info.value.data.LegacyContactInfo;
            const peer_gossip_addr = peer_info.gossip;

            // filter inactive nodes
            if (contact_info.timestamp_on_insertion < too_old_ts) {
                continue;
            }
            // filter self
            if (contact_info.value.id().equals(my_pubkey)) {
                continue;
            }
            // filter matching shred version or my_shred_version == 0
            if (my_shred_version != 0 and my_shred_version != peer_info.shred_version) {
                continue;
            }
            // filter on valid gossip address
            crds.sanitize_socket(&peer_gossip_addr) catch continue;

            nodes[node_index] = peer_info;
            node_index += 1;

            if (node_index == nodes.len) {
                break;
            }
        }

        return nodes[0..node_index];
    }

    fn new_pull_requests(
        allocator: std.mem.Allocator,
        crds_table: *CrdsTable,
        bloom_size: usize,
        my_contact_info: CrdsValue,
        logger: *Logger,
    ) !std.ArrayList(Packet) {
        // NOTE: these filters need to be de-init at some point
        // should serialize them into packets and de-init asap imo
        // ie, PacketBatch them
        var filters = pull_request.build_crds_filters(
            allocator,
            crds_table,
            bloom_size,
            MAX_NUM_PULL_REQUESTS,
        ) catch |err| {
            logger.debugf("failed to build crds filters: {any}\n", .{err});
            return error.FailedToBuildFilters;
        };
        // we serialize at the end of this function so this is ok
        defer pull_request.deinit_crds_filters(&filters);

        // get nodes from crds table
        const now = crds.get_wallclock();
        const my_pubkey = my_contact_info.id();
        const my_shred_version = my_contact_info.data.LegacyContactInfo.shred_version;

        var buf: [MAX_NUM_PULL_REQUESTS]crds.LegacyContactInfo = undefined;
        var peers = try get_gossip_nodes(
            crds_table,
            &my_pubkey,
            my_shred_version,
            &buf,
            MAX_NUM_PULL_REQUESTS,
            now,
        );
        const num_peers = peers.len;
        if (num_peers == 0) {
            return error.NoPeers;
        }

        // build packet responses
        var output = try std.ArrayList(Packet).initCapacity(allocator, filters.items.len);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;

        var rng = std.rand.DefaultPrng.init(now);
        for (filters.items) |filter_i| {
            // TODO: incorperate stake weight in random sampling
            const peer_index = rng.random().intRangeAtMost(usize, 0, num_peers - 1);
            const peer_contact_info = peers[peer_index];
            const peer_addr = peer_contact_info.gossip.toEndpoint();

            const protocol_msg = Protocol{ .PullRequest = .{ filter_i, my_contact_info } };

            var msg_slice = try bincode.writeToSlice(&packet_buf, protocol_msg, bincode.Params{});
            var packet = Packet.init(peer_addr, packet_buf, msg_slice.len);
            output.appendAssumeCapacity(packet);
        }

        return output;
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

    fn get_contact_info(self: *Self) !crds.LegacyContactInfo {
        const id = self.cluster_info.our_contact_info.pubkey;
        const gossip_socket = self.gossip_socket;

        const gossip_endpoint = try gossip_socket.getLocalEndPoint();
        const gossip_addr = SocketAddr.init_ipv4(gossip_endpoint.address.ipv4.value, gossip_endpoint.port);

        var legacy_contact_info = crds.LegacyContactInfo.default(id);
        legacy_contact_info.gossip = gossip_addr;
        // TODO: use correct shred version
        legacy_contact_info.shred_version = 0;

        return legacy_contact_info;
    }

    fn push_contact_info(self: *Self) !void {
        const contact_info = try self.get_contact_info();

        self.push_msg_queue_lock.lock();
        defer self.push_msg_queue_lock.unlock();

        try self.push_msg_queue.append(contact_info);
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
        active_set: *const ActiveSet,
        my_pubkey: Pubkey,
        push_cursor: *u64,
    ) !std.ArrayList(Packet) {
        // TODO: find a better static value?
        var buf: [512]crds.CrdsVersionedValue = undefined;
        crds_table.read();
        var crds_entries = try crds_table.get_entries_with_cursor(&buf, push_cursor);
        crds_table.release_read();

        const now = get_wallclock();
        var total_byte_size: usize = 0;

        // find new values in crds table
        var push_messages = std.ArrayList(CrdsValue).init(allocator);
        defer push_messages.deinit();

        var num_values_considered: usize = 0;
        for (crds_entries) |entry| {
            const value = entry.value;

            const entry_time = value.wallclock();
            const too_old = entry_time < now -| CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS;
            const too_new = entry_time > now +| CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS;
            if (too_old or too_new) {
                num_values_considered += 1;
                continue;
            }

            const byte_size = try bincode.get_serialized_size(allocator, value, bincode.Params{});
            total_byte_size +|= byte_size;

            if (total_byte_size > MAX_BYTES_PER_PUSH) {
                break;
            }
            try push_messages.append(value);
            num_values_considered += 1;
        }

        // adjust cursor for values not sent this round
        // NOTE: labs client doesnt do this? - bug?
        const num_values_not_considered = crds_entries.len - num_values_considered;
        push_cursor.* -= num_values_not_considered;

        // derive the active set
        const active_set_peers = active_set.get_fanout_peers();
        // retrieve the gossip endpoints
        var active_set_addrs = try std.ArrayList(EndPoint).initCapacity(allocator, active_set_peers.len);
        defer active_set_addrs.deinit();
        for (active_set_peers) |peer_pubkey| {
            const peer_info = crds_table.get(crds.CrdsValueLabel{
                .LegacyContactInfo = peer_pubkey,
            }).?;
            const peer_gossip_addr = peer_info.value.data.LegacyContactInfo.gossip.toEndpoint();
            active_set_addrs.appendAssumeCapacity(peer_gossip_addr);
        }

        // build Push msg packets
        var push_packets = try std.ArrayList(Packet).initCapacity(allocator, MAX_PACKETS_PER_PUSH * @as(u64, active_set.len));
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;

        const max_chunk_size = PUSH_MESSAGE_MAX_PAYLOAD_SIZE;
        var buf_byte_size: u64 = 0;

        var protocol_msg_values = std.ArrayList(CrdsValue).init(allocator);
        defer protocol_msg_values.deinit();

        for (push_messages.items) |crds_value| {
            const data_byte_size = try bincode.get_serialized_size(allocator, crds_value, bincode.Params{});
            const new_chunk_size = buf_byte_size + data_byte_size;

            if (new_chunk_size <= max_chunk_size) {
                buf_byte_size = new_chunk_size;
                try protocol_msg_values.append(crds_value);
            } else if (data_byte_size <= max_chunk_size) {
                // write to Push to packet
                const protocol_msg = Protocol{ .PushMessage = .{ my_pubkey, protocol_msg_values.items } };
                var msg_slice = try bincode.writeToSlice(&packet_buf, protocol_msg, bincode.Params{});

                // write to all push peers
                for (active_set_addrs.items) |peer_gossip_addr| {
                    var packet = Packet.init(peer_gossip_addr, packet_buf, msg_slice.len);
                    try push_packets.append(packet);
                }

                // reset array
                buf_byte_size = data_byte_size;
                protocol_msg_values.clearRetainingCapacity();
                try protocol_msg_values.append(crds_value);
            } else {
                // should never have a chunk larger than the max
                unreachable;
            }
        }

        // write whats left
        if (buf_byte_size > 0) {
            const protocol_msg = Protocol{ .PushMessage = .{ my_pubkey, protocol_msg_values.items } };
            var msg_slice = try bincode.writeToSlice(&packet_buf, protocol_msg, bincode.Params{});
            for (active_set_addrs.items) |peer_gossip_addr| {
                var packet = Packet.init(peer_gossip_addr, packet_buf, msg_slice.len);
                try push_packets.append(packet);
            }
        }

        return push_packets;
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
                .PushMessage => |*push| {
                    const values = push[1];
                    insert_crds_values(
                        crds_table,
                        values,
                        logger,
                        GossipRoute.PushMessage,
                        CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS,
                    );

                    // TODO: handle prune messages

                },
                .PullResponse => |*pull| {
                    const values = pull[1];
                    insert_crds_values(
                        crds_table,
                        values,
                        logger,
                        GossipRoute.PullResponse,
                        CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS,
                    );
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
                    // const respose = Protocol {
                    //     .PullResponse = .{
                    //     }
                    // }

                    // TODO: send them out as a pull response
                    _ = crds_values;
                },
                .PongMessage => |*pong| {
                    _ = pong;
                },
                .PingMessage => |*ping| {
                    _ = ping;
                },
                .PruneMessage => |*prune| {
                    _ = prune;
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

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var crds_table = try CrdsTable.init(allocator);
    defer crds_table.deinit();

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var rng = std.rand.DefaultPrng.init(get_wallclock());

    for (0..20) |_| {
        var value = try CrdsValue.random(rng.random(), keypair);
        try crds_table.insert(value, get_wallclock(), null);
    }

    var id = Pubkey.fromPublicKey(&keypair.public_key, true);
    var contact_info = crds.LegacyContactInfo.default(id);
    var value = try CrdsValue.initSigned(crds.CrdsData{
        .LegacyContactInfo = contact_info,
    }, keypair);

    var packets = try GossipService.new_pull_requests(allocator, &crds_table, 2, value, logger);
    defer packets.deinit();

    try std.testing.expect(packets.items.len > 1);
    try std.testing.expect(!std.mem.eql(u8, &packets.items[0].data, &packets.items[1].data));
}

test "gossip.gossip_service: new push messages" {
    const allocator = std.testing.allocator;

    var crds_table = try CrdsTable.init(allocator);
    defer crds_table.deinit();

    // add some peers
    var rng = std.rand.DefaultPrng.init(get_wallclock());

    for (0..10) |_| {
        var keypair = try KeyPair.create(null);
        var value = try CrdsValue.random_with_index(rng.random(), keypair, 0); // contact info
        try crds_table.insert(value, get_wallclock(), null);
    }

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var id = Pubkey.fromPublicKey(&keypair.public_key, false);
    var value = try CrdsValue.random(rng.random(), keypair);

    // set the active set
    var active_set = ActiveSet.init();
    try active_set.reset(&crds_table, id, 0);
    std.debug.print("active set len: {d}\n", .{active_set.len});

    var push_queue = std.ArrayList(CrdsValue).init(allocator);
    defer push_queue.deinit();
    var mutex = std.Thread.Mutex{};

    try push_queue.append(value);
    try GossipService.drain_push_queue_to_crds_table(
        &crds_table,
        &push_queue,
        &mutex,
    );
    try std.testing.expect(crds_table.len() == 11);

    var cursor: usize = 0;
    var msgs = try GossipService.new_push_messages(
        allocator,
        &crds_table,
        &active_set,
        id,
        &cursor,
    );

    try std.testing.expectEqual(cursor, 11);
    try std.testing.expect(msgs.items.len > 0);
    msgs.deinit();

    msgs = try GossipService.new_push_messages(
        allocator,
        &crds_table,
        &active_set,
        id,
        &cursor,
    );

    try std.testing.expect(cursor == 11);
    try std.testing.expect(msgs.items.len == 0);
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
    var data = crds.CrdsData.random_from_index(rng.random(), 0);
    data.LegacyContactInfo.id = id;
    data.LegacyContactInfo.wallclock = 0;
    var value = try CrdsValue.initSigned(data, keypair);

    try std.testing.expect(try value.verify(id));

    var values = [_]crds.CrdsValue{value};
    const protocol_msg = Protocol{
        .PushMessage = .{ id, &values },
    };

    var peer = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 0);
    var from = peer.toEndpoint();

    var buf = [_]u8{0} ** PACKET_DATA_SIZE;
    var out = try bincode.writeToSlice(buf[0..], protocol_msg, bincode.Params{});
    var packet = Packet.init(from, buf, out.len);

    for (0..3) |_| {
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
    var rand_keypair = try KeyPair.create([_]u8{3} ** 32);
    var value2 = try CrdsValue.initSigned(crds.CrdsData.random_from_index(rng.random(), 0), rand_keypair);
    var values2 = [_]crds.CrdsValue{value2};
    const protocol_msg2 = Protocol{
        .PushMessage = .{ id, &values2 },
    };
    var buf2 = [_]u8{0} ** PACKET_DATA_SIZE;
    var out2 = try bincode.writeToSlice(buf2[0..], protocol_msg2, bincode.Params{});
    var packet2 = Packet.init(from, buf2, out2.len);
    packet_channel.send(packet2);

    for (0..3) |_| {
        var msg = verified_channel.receive().?;
        try std.testing.expect(msg.message.PushMessage[0].equals(&id));
    }

    var attempt_count: u16 = 0;
    while (packet_channel.buffer.items.len != 0) {
        std.time.sleep(std.time.ns_per_ms * 10);
        attempt_count += 1;
        if (attempt_count > 10) {
            try std.testing.expect(false);
        }
    }

    try std.testing.expect(packet_channel.buffer.items.len == 0);
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
    var legacy_contact_info = crds.LegacyContactInfo.default(id);
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
