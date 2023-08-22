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
const _protocol = @import("protocol.zig");
const Protocol = _protocol.Protocol;
const PruneData = _protocol.PruneData;

const Mux = @import("../sync/mux.zig").Mux;
const RwMux = @import("../sync/mux.zig").RwMux;

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
const HashTimeQueue = _crds_table.HashTimeQueue;
const CRDS_UNIQUE_PUBKEY_CAPACITY = _crds_table.CRDS_UNIQUE_PUBKEY_CAPACITY;

const Logger = @import("../trace/log.zig").Logger;

const pull_request = @import("../gossip/pull_request.zig");
const CrdsFilter = pull_request.CrdsFilter;
const MAX_NUM_PULL_REQUESTS = pull_request.MAX_NUM_PULL_REQUESTS;

const pull_response = @import("../gossip/pull_response.zig");
const ActiveSet = @import("../gossip/active_set.zig").ActiveSet;
const CRDS_GOSSIP_PUSH_FANOUT = @import("../gossip/active_set.zig").CRDS_GOSSIP_PUSH_FANOUT;

const Hash = @import("../core/hash.zig").Hash;

const PacketChannel = Channel(Packet);
const ProtocolMessage = struct { from_endpoint: EndPoint, message: Protocol };
const ProtocolChannel = Channel(ProtocolMessage);

const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;
const CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS: u64 = 30000;
const CRDS_GOSSIP_PRUNE_MSG_TIMEOUT_MS: u64 = 500;

const FAILED_INSERTS_RETENTION_MS: u64 = 20_000;

const MAX_PACKETS_PER_PUSH: usize = 64;
const MAX_BYTES_PER_PUSH: u64 = PACKET_DATA_SIZE * @as(u64, MAX_PACKETS_PER_PUSH);

const PUSH_MESSAGE_MAX_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;

const GOSSIP_SLEEP_MILLIS: u64 = 100;

/// Maximum number of origin nodes that a PruneData may contain, such that the
/// serialized size of the PruneMessage stays below PACKET_DATA_SIZE.
const MAX_PRUNE_DATA_NODES: usize = 32;
const NUM_ACTIVE_SET_ENTRIES: usize = 25;

pub const GossipService = struct {
    cluster_info: *ClusterInfo,
    gossip_socket: UdpSocket,
    exit_sig: AtomicBool,
    packet_channel: *PacketChannel,
    responder_channel: *PacketChannel,
    crds_table_rw: RwMux(CrdsTable),
    allocator: std.mem.Allocator,
    verified_channel: *ProtocolChannel,

    // push message things
    active_set_rw: RwMux(ActiveSet),
    push_msg_queue_mux: Mux(std.ArrayList(CrdsValue)),
    push_cursor: u64 = 0,

    // pull message things
    failed_pull_hashes_mux: Mux(HashTimeQueue),

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
        var crds_table_rw = RwMux(CrdsTable).init(crds_table);

        var my_pubkey = cluster_info.our_contact_info.pubkey;
        var my_shred_version = cluster_info.our_contact_info.shred_version;
        var active_set = try ActiveSet.rotate(allocator, &crds_table_rw, my_pubkey, my_shred_version);

        var failed_pull_hashes = HashTimeQueue.init();
        var push_msg_q = std.ArrayList(CrdsValue).init(allocator);

        return Self{
            .cluster_info = cluster_info,
            .gossip_socket = gossip_socket,
            .exit_sig = exit,
            .packet_channel = packet_channel,
            .responder_channel = responder_channel,
            .verified_channel = verified_channel,
            .crds_table_rw = crds_table_rw,
            .allocator = allocator,
            .push_msg_queue_mux = Mux(std.ArrayList(CrdsValue)).init(push_msg_q),
            .active_set_rw = RwMux(ActiveSet).init(active_set),
            .failed_pull_hashes_mux = Mux(HashTimeQueue).init(failed_pull_hashes),
        };
    }

    pub fn deinit(self: *Self) void {
        // TODO: join and exit threads

        self.packet_channel.deinit();
        self.responder_channel.deinit();
        self.verified_channel.deinit();

        {
            var lg = self.crds_table_rw.write();
            lg.mut().deinit();
            lg.unlock();
        }

        {
            var lg = self.push_msg_queue_mux.lock();
            lg.mut().deinit();
            lg.unlock();
        }
    }

    pub fn run(self: *Self, logger: *Logger) !void {
        const id = self.cluster_info.our_contact_info.pubkey;
        logger.infof("running gossip service at {any} with pubkey {s}", .{ self.gossip_socket.getLocalEndPoint(), id.cached_str.? });
        defer self.deinit();

        // process input threads
        var receiver_handle = try Thread.spawn(.{}, Self.read_gossip_socket, .{
            &self.gossip_socket,
            self.packet_channel,
            logger,
        });
        var packet_verifier_handle = try Thread.spawn(.{}, Self.verify_packets, .{
            self.allocator,
            self.packet_channel,
            self.verified_channel,
        });
        var packet_handle = try Thread.spawn(.{}, Self.process_messages, .{
            self.allocator,
            &self.crds_table_rw,
            self.verified_channel,
            self.responder_channel,
            &self.failed_pull_hashes_mux,
            &self.active_set_rw,
            &self.cluster_info.our_keypair,
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
            const msg = ProtocolMessage{ .from_endpoint = packet.addr, .message = protocol_message };
            try verified_channel.send(msg);
        }
    }

    fn gossip_loop(self: *Self, logger: *Logger) !void {
        // solana-gossip spy -- local node for testing
        const peer = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 8000).toEndpoint();
        var last_push_ts: u64 = 0;
        var should_send_pull_requests = true;

        const my_keypair = self.cluster_info.our_keypair;
        var my_contact_info = try self.get_contact_info();
        const my_pubkey = my_contact_info.id;
        const my_shred_version = my_contact_info.shred_version;

        var failed_pull_hashes_mux = self.failed_pull_hashes_mux;

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

                var failed_pull_hashes_lg = failed_pull_hashes_mux.lock();
                const failed_pull_hashes_array = try failed_pull_hashes_lg.get().get_values(self.allocator);
                defer failed_pull_hashes_array.deinit();
                failed_pull_hashes_lg.unlock();

                var pull_packets = new_pull_requests(
                    self.allocator,
                    &self.crds_table_rw,
                    &failed_pull_hashes_array,
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
                    try self.responder_channel.send(packet);
                }
            }
            // every other loop
            should_send_pull_requests = !should_send_pull_requests;

            // new push msgs
            try drain_push_queue_to_crds_table(
                &self.crds_table_rw,
                &self.push_msg_queue_mux,
            );
            var push_packets = new_push_messages(
                self.allocator,
                &self.crds_table_rw,
                &self.active_set_rw,
                my_pubkey,
                &self.push_cursor,
            ) catch |e| blk: {
                std.debug.print("failed to generate push messages: {any}\n", .{e});
                break :blk std.ArrayList(Packet).init(self.allocator);
            };
            defer push_packets.deinit();

            for (push_packets.items) |packet| {
                try self.responder_channel.send(packet);
            }

            // trim data
            const now = get_wallclock();

            const purged_cutoff_timestamp = now -| (5 * CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS);
            {
                var crds_table_lg = self.crds_table_rw.write();
                defer crds_table_lg.unlock();
                var crds_table = crds_table_lg.mut();

                try crds_table.attempt_trim(CRDS_UNIQUE_PUBKEY_CAPACITY);
                crds_table.purged.trim(purged_cutoff_timestamp);
                try crds_table.remove_old_labels(now, CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS);
            }

            const failed_insert_cutoff_timestamp = now -| FAILED_INSERTS_RETENTION_MS;
            var failed_pull_hashes_lg = failed_pull_hashes_mux.lock();
            failed_pull_hashes_lg.mut().trim(failed_insert_cutoff_timestamp);
            failed_pull_hashes_lg.unlock();

            // periodic things
            if (top_of_loop_ts - last_push_ts > CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 2) {
                // update wallclock and sign
                my_contact_info.wallclock = get_wallclock();
                var my_contact_info_value = try crds.CrdsValue.initSigned(crds.CrdsData{
                    .LegacyContactInfo = my_contact_info,
                }, my_keypair);

                // push contact info
                var push_msg_queue_lg = self.push_msg_queue_mux.lock();
                try push_msg_queue_lg.mut().append(my_contact_info_value);
                push_msg_queue_lg.unlock();

                // reset push active set
                var active_set_lg = self.active_set_rw.write();
                active_set_lg.mut().deinit();
                var new_active_set = ActiveSet.rotate(
                    self.allocator,
                    &self.crds_table_rw,
                    my_pubkey,
                    my_shred_version,
                ) catch unreachable;
                active_set_lg.replace(new_active_set);
                active_set_lg.unlock();

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
        crds_table_rw: *RwMux(CrdsTable), // reads to get contact infos
        my_pubkey: *const Pubkey, // used to filter out ourself
        my_shred_version: u16, // used to filter matching shredversions
        nodes: []crds.LegacyContactInfo, // output
        comptime MAX_SIZE: usize, // max_size == nodes.len but comptime for init of stack array
        now: u64, // filters old values
    ) ![]crds.LegacyContactInfo {
        std.debug.assert(MAX_SIZE == nodes.len);

        var buf: [MAX_SIZE]crds.CrdsVersionedValue = undefined;
        const contact_infos = blk: {
            var crds_table_lg = crds_table_rw.read();
            defer crds_table_lg.unlock();

            break :blk try crds_table_lg.get().get_contact_infos(&buf);
        };

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
        crds_table: *RwMux(CrdsTable),
        failed_pull_hashes: *const std.ArrayList(Hash),
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
            failed_pull_hashes,
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

    fn send_ping(self: *Self, peer: *const EndPoint, logger: *Logger) !void {
        var protocol = Protocol{ .PingMessage = try Ping.random(self.cluster_info.our_keypair) };
        var out = [_]u8{0} ** PACKET_DATA_SIZE;
        var bytes = try bincode.writeToSlice(out[0..], protocol, bincode.Params.standard);

        logger.debugf("sending a ping message to: {any}", .{peer});
        try self.responder_channel.send(
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

    fn drain_push_queue_to_crds_table(
        crds_table_rw: *RwMux(CrdsTable),
        push_msg_queue_mux: *Mux(std.ArrayList(CrdsValue)),
    ) !void {
        const now = get_wallclock();

        var push_msg_queue_lg = push_msg_queue_mux.lock();
        var push_msg_queue = push_msg_queue_lg.mut();
        defer push_msg_queue_lg.unlock();

        var crds_table_lg = crds_table_rw.write();
        var crds_table = crds_table_lg.mut();
        defer crds_table_lg.unlock();

        while (push_msg_queue.popOrNull()) |crds_value| {
            crds_table.insert(crds_value, now) catch {};
        }
    }

    fn new_push_messages(
        allocator: std.mem.Allocator,
        crds_table_rw: *RwMux(CrdsTable),
        active_set_rw: *RwMux(ActiveSet),
        my_pubkey: Pubkey,
        push_cursor: *u64,
    ) !std.ArrayList(Packet) {
        // TODO: find a better static value?
        var buf: [512]crds.CrdsVersionedValue = undefined;

        var crds_entries = blk: {
            var crds_table_lg = crds_table_rw.read();
            defer crds_table_lg.unlock();

            break :blk crds_table_lg.get().get_entries_with_cursor(&buf, push_cursor);
        };

        const now = get_wallclock();
        var total_byte_size: usize = 0;

        // find new values in crds table
        // TODO: benchmark different approach of HashMapping(origin, value) first
        // then deriving the active set per origin in a batch
        var push_messages = std.AutoHashMap(EndPoint, std.ArrayList(CrdsValue)).init(allocator);
        defer push_messages.deinit();

        var active_set_lg = active_set_rw.read();
        var active_set = active_set_lg.get();
        errdefer active_set_lg.unlock();

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

            // get the active set for these values *PER ORIGIN* due to prunes
            const origin = value.id();
            var crds_table_lg = crds_table_rw.read();
            const active_set_peers = try active_set.get_fanout_peers(allocator, origin, crds_table_lg.get());
            defer active_set_peers.deinit();
            crds_table_lg.unlock();

            for (active_set_peers.items) |peer| {
                var maybe_peer_entry = push_messages.getEntry(peer);
                if (maybe_peer_entry) |peer_entry| {
                    try peer_entry.value_ptr.append(value);
                } else {
                    var peer_entry = try std.ArrayList(CrdsValue).initCapacity(allocator, 1);
                    peer_entry.appendAssumeCapacity(value);
                    try push_messages.put(peer, peer_entry);
                }
            }
            num_values_considered += 1;
        }
        active_set_lg.unlock();

        // adjust cursor for values not sent this round
        // NOTE: labs client doesnt do this - bug?
        const num_values_not_considered = crds_entries.len - num_values_considered;
        push_cursor.* -= num_values_not_considered;

        // build Push msg packets
        var push_packets = try std.ArrayList(Packet).initCapacity(allocator, MAX_PACKETS_PER_PUSH * CRDS_GOSSIP_PUSH_FANOUT);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;

        const max_chunk_size = PUSH_MESSAGE_MAX_PAYLOAD_SIZE;
        var buf_byte_size: u64 = 0;

        var protocol_msg_values = std.ArrayList(CrdsValue).init(allocator);
        defer protocol_msg_values.deinit();

        var push_iter = push_messages.iterator();
        while (push_iter.next()) |push_entry| {
            const values = push_entry.value_ptr;
            defer values.deinit();
            const to_endpoint = push_entry.key_ptr.*;

            for (values.items, 0..) |crds_value, i| {
                const data_byte_size = try bincode.get_serialized_size(allocator, crds_value, bincode.Params{});

                // should never have a chunk larger than the max
                if (data_byte_size > max_chunk_size) {
                    // std.debug.print("skipping data larger than max chunk size\n", .{});
                    unreachable;
                }

                const new_chunk_size = buf_byte_size + data_byte_size;
                const is_last_iter = i == values.items.len - 1;

                if (new_chunk_size > max_chunk_size or is_last_iter) {
                    // write to Push to packet
                    const protocol_msg = Protocol{ .PushMessage = .{ my_pubkey, protocol_msg_values.items } };
                    var msg_slice = try bincode.writeToSlice(&packet_buf, protocol_msg, bincode.Params{});

                    var packet = Packet.init(to_endpoint, packet_buf, msg_slice.len);
                    try push_packets.append(packet);

                    // reset array
                    buf_byte_size = data_byte_size;
                    protocol_msg_values.clearRetainingCapacity();
                    try protocol_msg_values.append(crds_value);
                } else {
                    // new_chunk_size <= max_chunk_size
                    buf_byte_size = new_chunk_size;
                    try protocol_msg_values.append(crds_value);
                }
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
            try packet_channel.send(Packet.init(recv_meta.sender, read_buf, bytes_read));

            // reset buffer
            @memset(&read_buf, 0);
        }

        logger.debugf("reading gossip exiting...", .{});
    }

    pub fn build_prune_messages(
        allocator: std.mem.Allocator,
        crds_table_rw: *RwMux(CrdsTable),
        failed_origins: *const std.AutoArrayHashMap(Pubkey, void),
        push_from: Pubkey,
        my_keypair: *KeyPair,
    ) error{ CantFindContactInfo, InvalidGossipAddress, OutOfMemory, SignatureError }!std.ArrayList(Packet) {
        const from_contact_info = blk: {
            var crds_table_lg = crds_table_rw.read();
            defer crds_table_lg.unlock();

            break :blk crds_table_lg.get().get(crds.CrdsValueLabel{ .LegacyContactInfo = push_from }) orelse {
                return error.CantFindContactInfo;
            };
        };
        const from_gossip_addr = from_contact_info.value.data.LegacyContactInfo.gossip;
        crds.sanitize_socket(&from_gossip_addr) catch return error.InvalidGossipAddress;
        const from_gossip_endpoint = from_gossip_addr.toEndpoint();

        const failed_origin_len = failed_origins.keys().len;
        var n_packets = failed_origins.keys().len / MAX_PRUNE_DATA_NODES;
        var prune_packets = try std.ArrayList(Packet).initCapacity(allocator, n_packets);
        errdefer prune_packets.deinit();

        var origin_buf: [MAX_PRUNE_DATA_NODES]Pubkey = undefined;
        var origin_count: usize = 0;

        const now = get_wallclock();
        var buf: [PACKET_DATA_SIZE]u8 = undefined;
        const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

        for (failed_origins.keys(), 0..) |origin, i| {
            origin_buf[origin_count] = origin;
            origin_count += 1;

            const is_last_iter = i == failed_origin_len - 1;
            if (origin_count == MAX_PRUNE_DATA_NODES or is_last_iter) {
                // create protocol message
                var prune_data = PruneData.init(my_pubkey, origin_buf[0..origin_count], push_from, now);
                prune_data.sign(my_keypair) catch return error.SignatureError;

                // put it into a packet
                var msg = Protocol{ .PruneMessage = .{ my_pubkey, prune_data } };
                // msg should never be bigger than the PacketSize and serialization shouldnt fail (unrecoverable)
                var msg_slice = bincode.writeToSlice(&buf, msg, bincode.Params{}) catch unreachable;
                var packet = Packet.init(from_gossip_endpoint, buf, msg_slice.len);
                try prune_packets.append(packet);

                // reset array
                origin_count = 0;
            }
        }

        return prune_packets;
    }

    pub fn handle_push_message(
        allocator: std.mem.Allocator,
        push_values: []CrdsValue,
        crds_table_rw: *RwMux(CrdsTable),
    ) error{OutOfMemory}!std.AutoArrayHashMap(Pubkey, void) {
        const failed_insert_indexs = blk: {
            var crds_table_lg = crds_table_rw.write();
            defer crds_table_lg.unlock();

            var result = try crds_table_lg.mut().insert_values(allocator, push_values, CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS, false, false);
            break :blk result.failed.?;
        };
        defer failed_insert_indexs.deinit();

        // origins are used to generate prune messages
        // hashmap to account for duplicates
        var failed_origins = std.AutoArrayHashMap(Pubkey, void).init(allocator);
        errdefer failed_origins.deinit();

        if (failed_insert_indexs.items.len == 0) {
            return failed_origins;
        }

        for (failed_insert_indexs.items) |index| {
            const origin = push_values[index].id();
            try failed_origins.put(origin, {});
        }
        return failed_origins;
    }

    pub fn process_messages(
        allocator: std.mem.Allocator,
        crds_table_rw: *RwMux(CrdsTable),
        verified_channel: *ProtocolChannel,
        responder_channel: *PacketChannel,
        failed_pull_hashes_mux: *Mux(HashTimeQueue),
        active_set_rw: *RwMux(ActiveSet),
        my_keypair: *KeyPair,
        logger: *Logger,
    ) !void {
        const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, false);

        while (verified_channel.receive()) |protocol_message| {
            // note: to recieve PONG messages (from a local spy node) from a PING
            // you need to modify: streamer/src/socket.rs
            // pub fn check(&self, addr: &SocketAddr) -> bool {
            //     return true;
            // }

            var message = protocol_message.message;
            var from_endpoint = protocol_message.from_endpoint;

            switch (message) {
                .PushMessage => |*push| {
                    const push_from = push[0];
                    const push_values = push[1];

                    var failed_insert_origins = handle_push_message(
                        allocator,
                        push_values,
                        crds_table_rw,
                    ) catch |err| {
                        logger.warnf("error handling push message: {s}", .{@errorName(err)});
                        continue;
                    };
                    defer failed_insert_origins.deinit();

                    var prune_packets = build_prune_messages(allocator, crds_table_rw, &failed_insert_origins, push_from, my_keypair) catch |err| {
                        logger.warnf("error building prune messages: {s}", .{@errorName(err)});
                        continue;
                    };
                    defer prune_packets.deinit();

                    for (prune_packets.items) |packet| {
                        try responder_channel.send(packet);
                    }
                },
                .PullResponse => |*pull| {
                    const values = pull[1];

                    // TODO: benchmark and compare with labs' preprocessing
                    const now = get_wallclock();
                    var crds_table_lg = crds_table_rw.write();
                    var crds_table: *CrdsTable = crds_table_lg.mut();

                    const insert_results = try crds_table.insert_values(
                        allocator,
                        values,
                        CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS,
                        true,
                        true,
                    );

                    // silently insert the timeout values
                    // (without updating all associated origin values)
                    const timeout_indexs = insert_results.timeouts.?;
                    defer timeout_indexs.deinit();
                    for (timeout_indexs.items) |index| {
                        crds_table.insert(
                            values[index],
                            now,
                        ) catch {};
                    }

                    // update the contactInfo timestamps of the successful inserts
                    // (and all other origin values)
                    const successful_insert_indexs = insert_results.inserted.?;
                    defer successful_insert_indexs.deinit();
                    for (successful_insert_indexs.items) |index| {
                        const origin = values[index].id();
                        crds_table.update_record_timestamp(origin, now);
                    }
                    crds_table_lg.unlock();

                    // track failed inserts - to use when constructing pull requests
                    var failed_insert_indexs = insert_results.failed.?;
                    defer failed_insert_indexs.deinit();
                    {
                        var failed_pull_hashes_lg = failed_pull_hashes_mux.lock();
                        var failed_pull_hashes = failed_pull_hashes_lg.mut();
                        defer failed_pull_hashes_lg.unlock();

                        const failed_insert_cutoff_timestamp = now -| FAILED_INSERTS_RETENTION_MS;
                        failed_pull_hashes.trim(failed_insert_cutoff_timestamp);

                        var buf: [PACKET_DATA_SIZE]u8 = undefined;
                        for (failed_insert_indexs.items) |insert_index| {
                            const value = values[insert_index];
                            var bytes = try bincode.writeToSlice(&buf, value, bincode.Params.standard);
                            const value_hash = Hash.generateSha256Hash(bytes);

                            failed_pull_hashes.insert(value_hash, now);
                        }
                    }
                },
                .PullRequest => |*pull| {
                    var filter = pull[0];
                    var value = pull[1]; // contact info
                    const now = get_wallclock();

                    {
                        var crds_table_lg = crds_table_rw.write();
                        defer crds_table_lg.unlock();
                        var crds_table = crds_table_lg.mut();

                        try crds_table.insert(value, now);
                        crds_table.update_record_timestamp(value.id(), now);
                    }

                    // TODO: filter out requests which hasnt responded to a ping request

                    var crds_table_lg = crds_table_rw.read();
                    const crds_values = pull_response.filter_crds_values(
                        allocator,
                        crds_table_lg.get(),
                        &filter,
                        100,
                        value.wallclock(),
                    ) catch |err| {
                        logger.warnf("error filtering crds values: {s}", .{@errorName(err)});
                        continue;
                    };
                    defer crds_values.deinit();
                    crds_table_lg.unlock();

                    // send the values as a pull response
                    var packets = try std.ArrayList(Packet).initCapacity(allocator, MAX_PACKETS_PER_PUSH);
                    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;

                    const max_chunk_size = PUSH_MESSAGE_MAX_PAYLOAD_SIZE;
                    var buf_byte_size: u64 = 0;

                    var protocol_msg_values = std.ArrayList(CrdsValue).init(allocator);
                    defer protocol_msg_values.deinit();
                    const crds_value_len = crds_values.items.len;

                    for (crds_values.items, 0..) |crds_value, i| {
                        const data_byte_size = try bincode.get_serialized_size(allocator, crds_value, bincode.Params{});
                        // should never have a chunk larger than the max
                        if (data_byte_size > max_chunk_size) {
                            // std.debug.print("skipping data larger than max chunk size\n", .{});
                            unreachable;
                        }
                        const new_chunk_size = buf_byte_size + data_byte_size;
                        const is_last_iter = i == crds_value_len - 1;

                        if (new_chunk_size > max_chunk_size or is_last_iter) {
                            // write to Push to packet
                            const protocol_msg = Protocol{ .PullResponse = .{ my_pubkey, protocol_msg_values.items } };
                            var msg_slice = try bincode.writeToSlice(&packet_buf, protocol_msg, bincode.Params{});

                            var packet = Packet.init(from_endpoint, packet_buf, msg_slice.len);
                            try packets.append(packet);

                            // reset array
                            buf_byte_size = data_byte_size;
                            protocol_msg_values.clearRetainingCapacity();
                            try protocol_msg_values.append(crds_value);
                        } else {
                            // new_chunk_size <= max_chunk_size
                            buf_byte_size = new_chunk_size;
                            try protocol_msg_values.append(crds_value);
                        }
                    }

                    for (packets.items) |packet| {
                        try responder_channel.send(packet);
                    }
                },
                .PruneMessage => |*prune| {
                    const prune_msg: PruneData = prune[1];

                    const now = get_wallclock();
                    const prune_wallclock = prune_msg.wallclock;
                    const too_old = prune_wallclock < now -| CRDS_GOSSIP_PRUNE_MSG_TIMEOUT_MS;
                    if (too_old) {
                        continue;
                    }

                    const bad_destination = !prune_msg.destination.equals(&my_pubkey);
                    if (bad_destination) {
                        continue;
                    }

                    // update active set
                    const from_pubkey = prune_msg.pubkey;

                    var active_set_lg = active_set_rw.write();
                    var active_set = active_set_lg.mut();
                    for (prune_msg.prunes) |origin| {
                        if (origin.equals(&my_pubkey)) {
                            continue;
                        }
                        active_set.prune(from_pubkey, origin);
                    }
                    active_set_lg.unlock();
                },
                .PongMessage => |*pong| {
                    _ = pong;
                },
                .PingMessage => |*ping| {
                    _ = ping;
                },
            }

            var crds_table_lg = crds_table_rw.write();
            crds_table_lg.mut().attempt_trim(CRDS_UNIQUE_PUBKEY_CAPACITY) catch |err| {
                logger.warnf("error trimming crds table: {s}", .{@errorName(err)});
            };
            crds_table_lg.unlock();
        }
    }
};

test "gossip.gossip_service: generate prune messages" {
    const allocator = std.testing.allocator;

    var kp = try KeyPair.create(null);
    var rng = std.rand.DefaultPrng.init(91);
    var push_from = Pubkey.random(rng.random(), .{});

    var values = std.ArrayList(CrdsValue).init(allocator);
    defer values.deinit();
    for (0..10) |_| {
        var value = try CrdsValue.random_with_index(rng.random(), kp, 0);
        value.data.LegacyContactInfo.id = Pubkey.random(rng.random(), .{});
        try values.append(value);
    }

    var crds_table = try CrdsTable.init(allocator);
    var crds_table_rw = RwMux(CrdsTable).init(crds_table);
    defer {
        var crds_lg = crds_table_rw.write();
        crds_lg.mut().deinit();
    }

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    // insert contact info to send prunes to
    var contact_info = crds.LegacyContactInfo.random(rng.random());
    contact_info.id = push_from;
    // valid socket addr
    var gossip_socket = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 20);
    contact_info.gossip = gossip_socket;

    var ci_value = try CrdsValue.initSigned(crds.CrdsData{
        .LegacyContactInfo = contact_info,
    }, kp);
    var lg = crds_table_rw.write();
    try lg.mut().insert(ci_value, get_wallclock());
    lg.unlock();

    var forigins = try GossipService.handle_push_message(
        allocator,
        values.items,
        &crds_table_rw,
    );
    defer forigins.deinit();
    try std.testing.expect(forigins.keys().len == 0);

    var failed_origins = try GossipService.handle_push_message(
        allocator,
        values.items,
        &crds_table_rw,
    );
    defer failed_origins.deinit();
    try std.testing.expect(failed_origins.keys().len > 0);

    var prune_packets = try GossipService.build_prune_messages(
        allocator,
        &crds_table_rw,
        &failed_origins,
        push_from,
        &kp,
    );
    defer prune_packets.deinit();

    var packet = prune_packets.items[0];
    var protocol_message = try bincode.readFromSlice(
        allocator,
        Protocol,
        packet.data[0..packet.size],
        bincode.Params.standard,
    );
    defer bincode.free(allocator, protocol_message);

    var msg = protocol_message.PruneMessage;
    var prune_data = msg[1];
    try std.testing.expect(prune_data.destination.equals(&push_from));
    try std.testing.expectEqual(prune_data.prunes.len, 10);
}

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
        try crds_table.insert(value, get_wallclock());
    }

    var id = Pubkey.fromPublicKey(&keypair.public_key, true);
    var contact_info = crds.LegacyContactInfo.default(id);
    var value = try CrdsValue.initSigned(crds.CrdsData{
        .LegacyContactInfo = contact_info,
    }, keypair);

    var crds_table_rw = RwMux(CrdsTable).init(crds_table);

    const failed_pull_hashes = std.ArrayList(Hash).init(std.testing.allocator);
    var packets = try GossipService.new_pull_requests(
        allocator,
        &crds_table_rw,
        &failed_pull_hashes,
        2,
        value,
        logger,
    );
    defer packets.deinit();

    try std.testing.expect(packets.items.len > 1);
    try std.testing.expect(!std.mem.eql(u8, &packets.items[0].data, &packets.items[1].data));
}

test "gossip.gossip_service: new push messages" {
    const allocator = std.testing.allocator;

    var crds_table = try CrdsTable.init(allocator);
    var crds_table_rw = RwMux(CrdsTable).init(crds_table);
    defer {
        var lg = crds_table_rw.write();
        lg.mut().deinit();
    }

    // add some peers
    var rng = std.rand.DefaultPrng.init(get_wallclock());

    var lg = crds_table_rw.write();
    for (0..10) |_| {
        var keypair = try KeyPair.create(null);
        var value = try CrdsValue.random_with_index(rng.random(), keypair, 0); // contact info
        try lg.mut().insert(value, get_wallclock());
    }
    lg.unlock();

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var id = Pubkey.fromPublicKey(&keypair.public_key, false);
    var value = try CrdsValue.random(rng.random(), keypair);

    // set the active set
    var active_set = try ActiveSet.rotate(allocator, &crds_table_rw, id, 0);
    defer active_set.deinit();

    var active_set_rw = RwMux(ActiveSet).init(active_set);
    std.debug.print("active set len: {d}\n", .{active_set.len});

    var push_queue = std.ArrayList(CrdsValue).init(allocator);
    defer push_queue.deinit();
    try push_queue.append(value);
    var push_queue_m = Mux(std.ArrayList(CrdsValue)).init(push_queue);

    try GossipService.drain_push_queue_to_crds_table(
        &crds_table_rw,
        &push_queue_m,
    );

    var clg = crds_table_rw.read();
    try std.testing.expect(clg.get().len() == 11);
    clg.unlock();

    var cursor: usize = 0;
    var msgs = try GossipService.new_push_messages(
        allocator,
        &crds_table_rw,
        &active_set_rw,
        id,
        &cursor,
    );

    try std.testing.expectEqual(cursor, 11);
    try std.testing.expect(msgs.items.len > 0);
    msgs.deinit();

    msgs = try GossipService.new_push_messages(
        allocator,
        &crds_table_rw,
        &active_set_rw,
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
        packet_channel,
        verified_channel,
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
        try packet_channel.send(packet);
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
    try packet_channel.send(packet_v2);

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
    try packet_channel.send(packet2);

    for (0..3) |_| {
        var msg = verified_channel.receive().?;
        try std.testing.expect(msg.message.PushMessage[0].equals(&id));
    }

    var attempt_count: u16 = 0;

    while (packet_channel.buffer.private.v.items.len != 0) {
        std.time.sleep(std.time.ns_per_ms * 10);
        attempt_count += 1;
        if (attempt_count > 10) {
            try std.testing.expect(false);
        }
    }

    try std.testing.expect(packet_channel.buffer.private.v.items.len == 0);
    try std.testing.expect(verified_channel.buffer.private.v.items.len == 0);

    packet_channel.close();
    verified_channel.close();
    packet_verifier_handle.join();
}

test "gossip.gossip_service: process contact_info push packet" {
    const allocator = std.testing.allocator;
    var crds_table = try CrdsTable.init(allocator);
    var crds_table_rw = RwMux(CrdsTable).init(crds_table);
    defer {
        var lg = crds_table_rw.write();
        lg.mut().deinit();
    }

    var verified_channel = ProtocolChannel.init(allocator, 100);
    defer verified_channel.deinit();

    var responder_channel = PacketChannel.init(allocator, 100);
    defer responder_channel.deinit();

    var logger = Logger.init(allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var failed_pull = HashTimeQueue.init();
    var kp = try KeyPair.create(null);
    var pk = Pubkey.fromPublicKey(&kp.public_key, false);

    var active_set = try ActiveSet.rotate(
        allocator,
        &crds_table_rw,
        pk,
        0,
    );
    defer active_set.deinit();

    var active_set_rw = RwMux(ActiveSet).init(active_set);

    var mfph = Mux(HashTimeQueue).init(failed_pull);

    var packet_handle = try Thread.spawn(
        .{},
        GossipService.process_messages,
        .{
            allocator,
            &crds_table_rw,
            verified_channel,
            responder_channel,
            &mfph,
            &active_set_rw,
            &kp,
            logger,
        },
    );

    // send a push message
    var id = pk;

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
        .from_endpoint = peer,
        .message = msg,
    };
    try verified_channel.send(protocol_msg);

    // correct insertion into table
    var buf2: [100]crds.CrdsVersionedValue = undefined;
    std.time.sleep(std.time.ns_per_s);

    var lg = crds_table_rw.read();
    var res = try lg.get().get_contact_infos(&buf2);
    try std.testing.expect(res.len == 1);
    lg.unlock();

    verified_channel.close();
    packet_handle.join();
}
