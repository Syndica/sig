const std = @import("std");
const builtin = @import("builtin");
const network = @import("zig-network");
const EndPoint = network.EndPoint;
const Packet = @import("packet.zig").Packet;
const PACKET_DATA_SIZE = @import("packet.zig").PACKET_DATA_SIZE;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

const Thread = std.Thread;
const AtomicBool = std.atomic.Atomic(bool);
const UdpSocket = network.Socket;
const Tuple = std.meta.Tuple;
const SocketAddr = @import("../net/net.zig").SocketAddr;
const endpointToString = @import("../net/net.zig").endpointToString;
const _protocol = @import("protocol.zig");
const Protocol = _protocol.Protocol;
const PruneData = _protocol.PruneData;

const Mux = @import("../sync/mux.zig").Mux;
const RwMux = @import("../sync/mux.zig").RwMux;

const Ping = @import("ping_pong.zig").Ping;
const Pong = @import("ping_pong.zig").Pong;
const bincode = @import("../bincode/bincode.zig");
const crds = @import("../gossip/crds.zig");
const CrdsValue = crds.CrdsValue;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const getWallclockMs = @import("../gossip/crds.zig").getWallclockMs;

const _crds_table = @import("../gossip/crds_table.zig");
const CrdsTable = _crds_table.CrdsTable;
const CrdsError = _crds_table.CrdsError;
const HashTimeQueue = _crds_table.HashTimeQueue;
const CRDS_UNIQUE_PUBKEY_CAPACITY = _crds_table.CRDS_UNIQUE_PUBKEY_CAPACITY;

const Logger = @import("../trace/log.zig").Logger;
const DoNothingSink = @import("../trace/log.zig").DoNothingSink;
const Entry = @import("../trace/entry.zig").Entry;

const pull_request = @import("../gossip/pull_request.zig");
const CrdsFilter = pull_request.CrdsFilter;
const MAX_NUM_PULL_REQUESTS = pull_request.MAX_NUM_PULL_REQUESTS;

const pull_response = @import("../gossip/pull_response.zig");
const ActiveSet = @import("../gossip/active_set.zig").ActiveSet;

const Hash = @import("../core/hash.zig").Hash;

const socket_utils = @import("socket_utils.zig");

const Channel = @import("../sync/channel.zig").Channel;
const PacketChannel = Channel(Packet);
const ProtocolMessage = struct { from_endpoint: EndPoint, message: Protocol };
const ProtocolChannel = Channel(ProtocolMessage);
const PingCache = @import("./ping_pong.zig").PingCache;
const PingAndSocketAddr = @import("./ping_pong.zig").PingAndSocketAddr;
const echo = @import("../net/echo.zig");

pub const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;
pub const CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS: u64 = 30000;
pub const CRDS_GOSSIP_PRUNE_MSG_TIMEOUT_MS: u64 = 500;

pub const FAILED_INSERTS_RETENTION_MS: u64 = 20_000;

pub const MAX_PACKETS_PER_PUSH: usize = 64;
pub const MAX_BYTES_PER_PUSH: u64 = PACKET_DATA_SIZE * @as(u64, MAX_PACKETS_PER_PUSH);

// 4 (enum) + 32 (pubkey) + 8 (len) = 44
pub const MAX_PUSH_MESSAGE_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;

pub const GOSSIP_SLEEP_MILLIS: u64 = 100;
pub const GOSSIP_PING_CACHE_CAPACITY: usize = 65536;
pub const GOSSIP_PING_CACHE_TTL_NS: u64 = std.time.ns_per_s * 1280;
pub const GOSSIP_PING_CACHE_RATE_LIMIT_DELAY_NS: u64 = std.time.ns_per_s * (1280 / 64);

pub const MAX_NUM_CRDS_VALUES_PULL_RESPONSE = 20; // TODO: this is approx the rust one -- should tune

/// Maximum number of origin nodes that a PruneData may contain, such that the
/// serialized size of the PruneMessage stays below PACKET_DATA_SIZE.
pub const MAX_PRUNE_DATA_NODES: usize = 32;
pub const NUM_ACTIVE_SET_ENTRIES: usize = 25;

const Config = struct { mode: enum { normal, tests, bench } = .normal };

pub const GossipService = struct {
    allocator: std.mem.Allocator,

    // note: this contact info should not change
    gossip_socket: UdpSocket,
    my_contact_info: crds.LegacyContactInfo,
    my_keypair: KeyPair,
    my_pubkey: Pubkey,
    my_shred_version: u64,
    exit: *AtomicBool,

    // communication between threads
    packet_incoming_channel: *PacketChannel,
    packet_outgoing_channel: *PacketChannel,
    verified_incoming_channel: *ProtocolChannel,

    crds_table_rw: RwMux(CrdsTable),
    // push message things
    active_set_rw: RwMux(ActiveSet),
    push_msg_queue_mux: Mux(std.ArrayList(CrdsValue)),
    // pull message things
    failed_pull_hashes_mux: Mux(HashTimeQueue),

    entrypoints: std.ArrayList(SocketAddr),
    ping_cache_rw: RwMux(PingCache),
    logger: Logger,
    thread_pool: *ThreadPool,
    echo_server: ?echo.Server,

    // used for benchmarking
    messages_processed: std.atomic.Atomic(usize) = std.atomic.Atomic(usize).init(0),

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        my_contact_info: crds.LegacyContactInfo,
        my_keypair: KeyPair,
        entrypoints: ?std.ArrayList(SocketAddr),
        exit: *AtomicBool,
        logger: Logger,
    ) error{ OutOfMemory, SocketCreateFailed, SocketBindFailed, SocketSetTimeoutFailed }!Self {
        var packet_incoming_channel = PacketChannel.init(allocator, 10000);
        var packet_outgoing_channel = PacketChannel.init(allocator, 10000);
        var verified_incoming_channel = ProtocolChannel.init(allocator, 10000);

        errdefer {
            packet_incoming_channel.deinit();
            packet_outgoing_channel.deinit();
            verified_incoming_channel.deinit();
        }

        var thread_pool = try allocator.create(ThreadPool);
        var n_threads = @max(@as(u32, @truncate(std.Thread.getCpuCount() catch 0)), 8);
        thread_pool.* = ThreadPool.init(.{
            .max_threads = n_threads,
            .stack_size = 2 * 1024 * 1024,
        });
        logger.debugf("using n_threads in gossip: {}\n", .{n_threads});

        var crds_table = try CrdsTable.init(allocator, thread_pool);
        errdefer crds_table.deinit();
        var crds_table_rw = RwMux(CrdsTable).init(crds_table);
        var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, false);
        var my_shred_version = my_contact_info.shred_version;
        var active_set = ActiveSet.init(allocator);

        // bind the socket
        const gossip_address = my_contact_info.gossip;
        var gossip_socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
        gossip_socket.bindToPort(gossip_address.port()) catch return error.SocketBindFailed;
        gossip_socket.setReadTimeout(socket_utils.SOCKET_TIMEOUT) catch return error.SocketSetTimeoutFailed; // 1 second

        var failed_pull_hashes = HashTimeQueue.init(allocator);
        var push_msg_q = std.ArrayList(CrdsValue).init(allocator);

        // var echo_server = echo.Server.init(allocator, my_contact_info.gossip.port(), logger, exit);

        return Self{
            .my_contact_info = my_contact_info,
            .my_keypair = my_keypair,
            .my_pubkey = my_pubkey,
            .my_shred_version = my_shred_version,
            .gossip_socket = gossip_socket,
            .exit = exit,
            .packet_incoming_channel = packet_incoming_channel,
            .packet_outgoing_channel = packet_outgoing_channel,
            .verified_incoming_channel = verified_incoming_channel,
            .crds_table_rw = crds_table_rw,
            .allocator = allocator,
            .push_msg_queue_mux = Mux(std.ArrayList(CrdsValue)).init(push_msg_q),
            .active_set_rw = RwMux(ActiveSet).init(active_set),
            .failed_pull_hashes_mux = Mux(HashTimeQueue).init(failed_pull_hashes),
            .entrypoints = entrypoints orelse std.ArrayList(SocketAddr).init(allocator),
            .ping_cache_rw = RwMux(PingCache).init(
                try PingCache.init(
                    allocator,
                    GOSSIP_PING_CACHE_TTL_NS,
                    GOSSIP_PING_CACHE_RATE_LIMIT_DELAY_NS,
                    GOSSIP_PING_CACHE_CAPACITY,
                ),
            ),
            .echo_server = null,
            .logger = logger,
            .thread_pool = thread_pool,
        };
    }

    fn deinitRwMux(v: anytype) void {
        var lg = v.write();
        lg.mut().deinit();
        lg.unlock();
    }

    fn deinitMux(v: anytype) void {
        var lg = v.lock();
        lg.mut().deinit();
        lg.unlock();
    }

    pub fn deinit(self: *Self) void {
        // self.echo_server.deinit();

        self.gossip_socket.close();

        self.packet_incoming_channel.deinit();
        self.packet_outgoing_channel.deinit();
        self.verified_incoming_channel.deinit();

        self.entrypoints.deinit();

        self.allocator.destroy(self.thread_pool);

        deinitRwMux(&self.crds_table_rw);
        deinitRwMux(&self.active_set_rw);
        deinitRwMux(&self.ping_cache_rw);
        deinitMux(&self.push_msg_queue_mux);
        deinitMux(&self.failed_pull_hashes_mux);
    }

    /// these threads should run forever - so if they join - somethings wrong
    /// and we should shutdown
    fn joinAndExit(self: *Self, handle: *std.Thread) void {
        handle.join();
        self.exit.store(true, std.atomic.Ordering.Unordered);
    }

    /// spawns required threads for the gossip serivce.
    /// including:
    ///     1) socket reciever
    ///     2) packet verifier
    ///     3) packet processor
    ///     4) build message loop (to send outgoing message)
    ///     and 5) a socket responder (to send outgoing packets)
    pub fn run(self: *Self) !void {
        var ip_echo_server_listener_handle = try Thread.spawn(.{}, echo.Server.listenAndServe, .{&self.echo_server});
        defer self.joinAndExit(&ip_echo_server_listener_handle);

        var receiver_handle = try Thread.spawn(.{}, socket_utils.readSocket, .{
            &self.gossip_socket,
            self.packet_incoming_channel,
            self.exit,
            self.logger,
        });
        defer self.joinAndExit(&receiver_handle);

        var packet_verifier_handle = try Thread.spawn(.{}, Self.verifyPackets, .{self});
        defer self.joinAndExit(&packet_verifier_handle);

        var packet_handle = try Thread.spawn(.{}, Self.processMessages, .{self});
        defer self.joinAndExit(&packet_handle);

        var build_messages_handle = try Thread.spawn(.{}, Self.buildMessages, .{self});
        defer self.joinAndExit(&build_messages_handle);

        // outputer thread
        var responder_handle = try Thread.spawn(.{}, socket_utils.sendSocket, .{
            &self.gossip_socket,
            self.packet_outgoing_channel,
            self.exit,
            self.logger,
        });
        defer self.joinAndExit(&responder_handle);
    }

    pub fn runSpy(self: *Self) !void {
        // var ip_echo_server_listener_handle = try Thread.spawn(.{}, echo.Server.listenAndServe, .{&self.echo_server});
        // defer self.joinAndExit(&ip_echo_server_listener_handle);

        var receiver_handle = try Thread.spawn(.{}, socket_utils.readSocket, .{
            &self.gossip_socket,
            self.packet_incoming_channel,
            self.exit,
            self.logger,
        });
        defer self.joinAndExit(&receiver_handle);

        var packet_verifier_handle = try Thread.spawn(.{}, Self.verifyPackets, .{self});
        defer self.joinAndExit(&packet_verifier_handle);

        var packet_handle = try Thread.spawn(.{}, Self.processMessages, .{self});
        defer self.joinAndExit(&packet_handle);

        // outputer thread
        var responder_handle = try Thread.spawn(.{}, socket_utils.sendSocket, .{
            &self.gossip_socket,
            self.packet_outgoing_channel,
            self.exit,
            self.logger,
        });
        defer self.joinAndExit(&responder_handle);
    }

    /// main logic for deserializing Packets into Protocol messages
    /// and verifing they have valid values, and have valid signatures.
    /// Verified Protocol messages are then sent to the verified_channel.
    fn verifyPackets(self: *Self) !void {
        var failed_protocol_msgs: usize = 0;

        while (!self.exit.load(std.atomic.Ordering.Unordered)) {
            const maybe_packets = try self.packet_incoming_channel.try_drain();
            if (maybe_packets == null) {
                // // sleep for 1ms
                // std.time.sleep(std.time.ns_per_ms * 1);
                continue;
            }

            const packets = maybe_packets.?;
            defer self.packet_incoming_channel.allocator.free(packets);

            for (packets) |*packet| {
                var protocol_message = bincode.readFromSlice(
                    self.allocator,
                    Protocol,
                    packet.data[0..packet.size],
                    bincode.Params.standard,
                ) catch {
                    failed_protocol_msgs += 1;
                    self.logger.debugf("failed to deserialize protocol message: {d}\n", .{std.mem.readIntLittle(u32, packet.data[0..4])});
                    continue;
                };

                protocol_message.sanitize() catch |err| {
                    self.logger.debugf("failed to sanitize protocol message: {s}\n", .{@errorName(err)});
                    bincode.free(self.allocator, protocol_message);
                    continue;
                };

                protocol_message.verifySignature() catch |err| {
                    self.logger.debugf("failed to verify protocol message signature {s}\n", .{@errorName(err)});
                    bincode.free(self.allocator, protocol_message);
                    continue;
                };

                // TODO: send the pointers over the channel (similar to PinnedVec) vs item copy
                const msg = ProtocolMessage{ .from_endpoint = packet.addr, .message = protocol_message };
                try self.verified_incoming_channel.send(msg);
            }
        }

        self.logger.debugf("verify_packets loop closed\n", .{});
    }

    pub const PullRequestMessage = struct {
        filter: CrdsFilter,
        value: CrdsValue,
        from_endpoint: EndPoint,
    };

    /// main logic for recieving and processing `Protocol` messages.
    pub fn processMessages(self: *Self) !void {
        var timer = std.time.Timer.start() catch unreachable;
        var msg_count: usize = 0;

        var pull_requests = try std.ArrayList(PullRequestMessage).initCapacity(self.allocator, 100);
        defer pull_requests.deinit();

        while (!self.exit.load(std.atomic.Ordering.Unordered)) {
            const maybe_protocol_messages = try self.verified_incoming_channel.try_drain();
            if (maybe_protocol_messages == null) {
                // // sleep for 1ms
                // std.time.sleep(std.time.ns_per_ms * 1);
                continue;
            }
            if (msg_count == 0) {
                timer.reset();
            }

            const protocol_messages = maybe_protocol_messages.?;
            defer self.verified_incoming_channel.allocator.free(protocol_messages);
            msg_count += protocol_messages.len;

            // TODO: filter messages based on_shred_version

            for (protocol_messages) |*protocol_message| {
                var from_endpoint: EndPoint = protocol_message.from_endpoint;

                switch (protocol_message.message) {
                    .PushMessage => |*push| {
                        var x_timer = std.time.Timer.start() catch unreachable;
                        defer {
                            const elapsed = x_timer.read();
                            self.logger.debugf("handle batch push took {} with {} items\n", .{ elapsed, 1 });
                        }

                        const push_from: Pubkey = push[0];
                        const push_values: []CrdsValue = push[1];

                        var push_log_entry = self.logger
                            .field("num_crds_values", push_values.len)
                            .field("from_address", &push_from.string());

                        var failed_insert_origins = self.handlePushMessage(
                            push_values,
                        ) catch |err| {
                            push_log_entry.field("error", @errorName(err))
                                .err("error handling push message");
                            continue;
                        };
                        defer failed_insert_origins.deinit();
                        _ = push_log_entry.field("num_failed_insert_origins", failed_insert_origins.count());

                        if (failed_insert_origins.count() != 0) {
                            var prune_packets = self.buildPruneMessage(&failed_insert_origins, push_from) catch |err| {
                                push_log_entry.field("error", @errorName(err))
                                    .err("error building prune messages");
                                continue;
                            };
                            defer prune_packets.deinit();

                            _ = push_log_entry.field("num_prune_msgs", prune_packets.items.len);
                            for (prune_packets.items) |packet| {
                                try self.packet_outgoing_channel.send(packet);
                            }
                        }

                        push_log_entry.info("received push message");
                    },
                    .PullResponse => |*pull| {
                        var x_timer = std.time.Timer.start() catch unreachable;
                        defer {
                            const elapsed = x_timer.read();
                            self.logger.debugf("handle batch pull_resp took {} with {} items\n", .{ elapsed, 1 });
                        }

                        const from: Pubkey = pull[0];
                        const crds_values: []CrdsValue = pull[1];

                        var pull_log_entry = self.logger
                            .field("num_crds_values", crds_values.len)
                            .field("from_address", &from.string());

                        self.handlePullResponse(
                            crds_values,
                            pull_log_entry,
                        ) catch |err| {
                            pull_log_entry.field("error", @errorName(err))
                                .err("error handling pull response");
                            continue;
                        };

                        // pull_log_entry.info("received pull response");
                    },
                    .PullRequest => |*pull| {
                        var pull_value: CrdsValue = pull[1]; // contact info
                        switch (pull_value.data) {
                            .LegacyContactInfo => |*info| {
                                if (info.id.equals(&self.my_pubkey)) {
                                    // talking to myself == ignore
                                    continue;
                                }
                            },
                            // only contact info supported
                            else => continue,
                        }

                        try pull_requests.append(.{
                            .filter = pull[0],
                            .value = pull[1],
                            .from_endpoint = from_endpoint,
                        });
                    },
                    .PruneMessage => |*prune| {
                        var x_timer = std.time.Timer.start() catch unreachable;
                        defer {
                            const elapsed = x_timer.read();
                            self.logger.debugf("handle batch prune took {} with {} items\n", .{ elapsed, 1 });
                        }
                        const prune_msg: PruneData = prune[1];

                        var endpoint_buf = try endpointToString(self.allocator, &from_endpoint);
                        defer endpoint_buf.deinit();

                        var prune_log_entry = self.logger
                            .field("from_endpoint", endpoint_buf.items)
                            .field("from_pubkey", &prune_msg.pubkey.string())
                            .field("num_prunes", prune_msg.prunes.len);

                        self.handlePruneMessage(&prune_msg) catch |err| {
                            prune_log_entry.field("error", @errorName(err))
                                .err("error handling prune message");
                            continue;
                        };

                        prune_log_entry.info("received prune message");
                    },
                    .PingMessage => |*ping| {
                        var x_timer = std.time.Timer.start() catch unreachable;
                        defer {
                            const elapsed = x_timer.read();
                            self.logger.debugf("handle batch ping took {} with {} items\n", .{ elapsed, 1 });
                        }

                        var endpoint_buf = try endpointToString(self.allocator, &from_endpoint);
                        defer endpoint_buf.deinit();

                        var ping_log_entry = self.logger
                            .field("from_endpoint", endpoint_buf.items)
                            .field("from_pubkey", &ping.from.string());

                        const packet = self.handlePingMessage(ping, from_endpoint) catch |err| {
                            ping_log_entry
                                .field("error", @errorName(err))
                                .err("error handling ping message");
                            continue;
                        };

                        try self.packet_outgoing_channel.send(packet);

                        ping_log_entry
                            .field("pongs sent", 1)
                            .info("received ping message");
                    },
                    .PongMessage => |*pong| {
                        var x_timer = std.time.Timer.start() catch unreachable;
                        defer {
                            const elapsed = x_timer.read();
                            self.logger.debugf("handle batch pong took {} with {} items\n", .{ elapsed, 1 });
                        }

                        var endpoint_buf = try endpointToString(self.allocator, &from_endpoint);
                        defer endpoint_buf.deinit();

                        {
                            const now = std.time.Instant.now() catch @panic("time is not supported on the OS!");

                            var ping_cache_lock = self.ping_cache_rw.write();
                            defer ping_cache_lock.unlock();
                            var ping_cache: *PingCache = ping_cache_lock.mut();

                            _ = ping_cache.receviedPong(
                                pong,
                                SocketAddr.fromEndpoint(&from_endpoint),
                                now,
                            );
                        }

                        self.logger
                            .field("from_endpoint", endpoint_buf.items)
                            .field("from_pubkey", &pong.from.string())
                            .info("received pong message");
                    },
                }
            }

            // handle batch messages
            if (pull_requests.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                const length = pull_requests.items.len;
                self.handleBatchPullRequest(pull_requests);
                const elapsed = x_timer.read();
                self.logger.debugf("handle batch pull_req took {} with {} items\n", .{ elapsed, length });

                for (pull_requests.items) |*pr| {
                    pr.filter.deinit();
                }
            }
            pull_requests.clearRetainingCapacity();

            {
                var x_timer = std.time.Timer.start() catch unreachable;
                defer {
                    const elapsed = x_timer.read();
                    self.logger.debugf("handle batch crds_trim took {} with {} items\n", .{ elapsed, 1 });
                }

                var crds_table_lock = self.crds_table_rw.write();
                defer crds_table_lock.unlock();

                var crds_table: *CrdsTable = crds_table_lock.mut();
                crds_table.attemptTrim(CRDS_UNIQUE_PUBKEY_CAPACITY) catch |err| {
                    self.logger.warnf("error trimming crds table: {s}", .{@errorName(err)});
                };
            }

            const elapsed = timer.read();
            self.logger.debugf("{} messages processed in {}ns\n", .{ msg_count, elapsed });
            self.messages_processed.store(msg_count, std.atomic.Ordering.Release);
        }

        self.logger.debugf("process_messages loop closed\n", .{});
    }

    /// main gossip loop for periodically sending new protocol messages.
    /// this includes sending push messages, pull requests, and triming old
    /// gossip data (in the crds_table, active_set, and failed_pull_hashes).
    fn buildMessages(
        self: *Self,
    ) !void {
        var last_push_ts: u64 = 0;
        var push_cursor: u64 = 0;
        var should_send_pull_requests = true;

        while (!self.exit.load(std.atomic.Ordering.Unordered)) {
            const top_of_loop_ts = getWallclockMs();

            // TODO: send ping messages based on PingCache

            // new pull msgs
            if (should_send_pull_requests) pull_blk: {
                var pull_packets = self.buildPullRequests(
                    pull_request.MAX_BLOOM_SIZE,
                ) catch |e| {
                    self.logger.debugf("failed to generate pull requests: {any}", .{e});
                    break :pull_blk;
                };
                defer pull_packets.deinit();

                // send packets
                for (pull_packets.items) |packet| {
                    try self.packet_outgoing_channel.send(packet);
                }
            }
            // every other loop
            should_send_pull_requests = !should_send_pull_requests;

            // new push msgs
            self.drainPushQueueToCrdsTable(getWallclockMs());
            var maybe_push_packets = self.buildPushMessages(&push_cursor) catch |e| blk: {
                self.logger.debugf("failed to generate push messages: {any}\n", .{e});
                break :blk null;
            };
            if (maybe_push_packets) |push_packets| {
                defer push_packets.deinit();
                for (push_packets.items) |packet| {
                    try self.packet_outgoing_channel.send(packet);
                }
            }

            // trim data
            self.trimMemory(getWallclockMs()) catch @panic("out of memory");

            // periodic things
            if (top_of_loop_ts - last_push_ts > CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 2) {
                // update wallclock and sign
                self.my_contact_info.wallclock = getWallclockMs();
                var my_contact_info_value = try crds.CrdsValue.initSigned(crds.CrdsData{
                    .LegacyContactInfo = self.my_contact_info,
                }, &self.my_keypair);

                // push contact info
                {
                    var push_msg_queue_lock = self.push_msg_queue_mux.lock();
                    defer push_msg_queue_lock.unlock();
                    var push_msg_queue: *std.ArrayList(CrdsValue) = push_msg_queue_lock.mut();

                    try push_msg_queue.append(my_contact_info_value);
                }

                self.rotateActiveSet() catch @panic("out of memory");

                last_push_ts = getWallclockMs();
            }

            // sleep
            const elapsed_ts = getWallclockMs() - top_of_loop_ts;
            if (elapsed_ts < GOSSIP_SLEEP_MILLIS) {
                const time_left_ms = GOSSIP_SLEEP_MILLIS - elapsed_ts;
                std.time.sleep(time_left_ms * std.time.ns_per_ms);
            }
        }
        self.logger.infof("build_messages loop closed\n", .{});
    }

    pub fn rotateActiveSet(
        self: *Self,
    ) error{ OutOfMemory, SerializationError, ChannelClosed }!void {
        const now = getWallclockMs();
        var buf: [NUM_ACTIVE_SET_ENTRIES]crds.LegacyContactInfo = undefined;
        var gossip_peers = self.getGossipNodes(&buf, NUM_ACTIVE_SET_ENTRIES, now);

        // filter out peers who have responded to pings
        var ping_cache_result = blk: {
            var ping_cache_lock = self.ping_cache_rw.write();
            defer ping_cache_lock.unlock();
            var ping_cache: *PingCache = ping_cache_lock.mut();

            var result = try ping_cache.filterValidPeers(self.allocator, self.my_keypair, gossip_peers);
            break :blk result;
        };
        var valid_gossip_peers = ping_cache_result.valid_peers;
        defer valid_gossip_peers.deinit();

        // send pings to peers
        var pings_to_send_out = ping_cache_result.pings;
        defer pings_to_send_out.deinit();
        try self.sendPings(pings_to_send_out);

        // reset push active set
        var active_set_lock = self.active_set_rw.write();
        defer active_set_lock.unlock();
        var active_set: *ActiveSet = active_set_lock.mut();
        try active_set.rotate(valid_gossip_peers.items);
    }

    /// logic for building new push messages which are sent to peers from the
    /// active set and serialized into packets.
    fn buildPushMessages(self: *Self, push_cursor: *u64) !?std.ArrayList(Packet) {
        // TODO: find a better static value?
        var buf: [512]crds.CrdsVersionedValue = undefined;

        var crds_entries = blk: {
            var crds_table_lock = self.crds_table_rw.read();
            defer crds_table_lock.unlock();

            const crds_table: *const CrdsTable = crds_table_lock.get();
            break :blk crds_table.getEntriesWithCursor(&buf, push_cursor);
        };

        if (crds_entries.len == 0) {
            return null;
        }

        const now = getWallclockMs();
        var total_byte_size: usize = 0;

        // find new values in crds table
        // TODO: benchmark different approach of HashMapping(origin, value) first
        // then deriving the active set per origin in a batch
        var push_messages = std.AutoHashMap(EndPoint, std.ArrayList(CrdsValue)).init(self.allocator);
        defer {
            var push_iter = push_messages.iterator();
            while (push_iter.next()) |push_entry| {
                push_entry.value_ptr.deinit();
            }
            push_messages.deinit();
        }

        var num_values_considered: usize = 0;
        var active_set_lock = self.active_set_rw.read();
        var active_set: *const ActiveSet = active_set_lock.get();
        {
            defer active_set_lock.unlock();
            for (crds_entries) |entry| {
                const value = entry.value;

                const entry_time = value.wallclock();
                const too_old = entry_time < now -| CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS;
                const too_new = entry_time > now +| CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS;
                if (too_old or too_new) {
                    num_values_considered += 1;
                    continue;
                }

                const byte_size = try bincode.getSerializedSize(self.allocator, value, bincode.Params{});
                total_byte_size +|= byte_size;

                if (total_byte_size > MAX_BYTES_PER_PUSH) {
                    break;
                }

                // get the active set for these values *PER ORIGIN* due to prunes
                const origin = value.id();
                var active_set_peers = blk: {
                    var crds_table_lock = self.crds_table_rw.read();
                    defer crds_table_lock.unlock();
                    const crds_table: *const CrdsTable = crds_table_lock.get();

                    break :blk try active_set.getFanoutPeers(self.allocator, origin, crds_table);
                };
                defer active_set_peers.deinit();

                for (active_set_peers.items) |peer| {
                    var maybe_peer_entry = push_messages.getEntry(peer);
                    if (maybe_peer_entry) |peer_entry| {
                        try peer_entry.value_ptr.append(value);
                    } else {
                        var peer_entry = try std.ArrayList(CrdsValue).initCapacity(self.allocator, 1);
                        peer_entry.appendAssumeCapacity(value);
                        try push_messages.put(peer, peer_entry);
                    }
                }
                num_values_considered += 1;
            }
        }

        // adjust cursor for values not sent this round
        // NOTE: labs client doesnt do this - bug?
        const num_values_not_considered = crds_entries.len - num_values_considered;
        push_cursor.* -= num_values_not_considered;

        var packets = std.ArrayList(Packet).init(self.allocator);
        errdefer packets.deinit();

        var push_iter = push_messages.iterator();
        while (push_iter.next()) |push_entry| {
            const crds_values: *const std.ArrayList(CrdsValue) = push_entry.value_ptr;
            const to_endpoint: *const EndPoint = push_entry.key_ptr;

            // send the values as a pull response
            var maybe_endpoint_packets = try crdsValuesToPackets(
                self.allocator,
                &self.my_pubkey,
                crds_values.items,
                to_endpoint,
                ChunkType.PushMessage,
            );
            if (maybe_endpoint_packets) |endpoint_packets| {
                defer endpoint_packets.deinit();
                try packets.appendSlice(endpoint_packets.items);
            }
        }

        return packets;
    }

    /// builds new pull request messages and serializes it into a list of Packets
    /// to be sent to a random set of gossip nodes.
    fn buildPullRequests(
        self: *Self,
        /// the bloomsize of the pull request's filters
        bloom_size: usize,
    ) !std.ArrayList(Packet) {
        // get nodes from crds table
        var buf: [MAX_NUM_PULL_REQUESTS]crds.LegacyContactInfo = undefined;
        const now = getWallclockMs();
        var peers = self.getGossipNodes(
            &buf,
            MAX_NUM_PULL_REQUESTS,
            now,
        );

        // randomly include an entrypoint in the pull if we dont have their contact info
        var rng = std.rand.DefaultPrng.init(now);
        var entrypoint_index: i16 = -1;
        if (self.entrypoints.items.len != 0) blk: {
            var crds_table_lg = self.crds_table_rw.read();
            defer crds_table_lg.unlock();

            var maybe_entrypoint_index = rng.random().intRangeAtMost(usize, 0, self.entrypoints.items.len - 1);
            const entrypoint = self.entrypoints.items[maybe_entrypoint_index];

            const crds_table: *const CrdsTable = crds_table_lg.get();
            const contact_infos = try crds_table.getAllContactInfos();
            defer contact_infos.deinit();

            for (contact_infos.items) |contact_info| {
                if (contact_info.gossip.eql(&entrypoint)) {
                    // early exit - we already have the peers in our contact info
                    break :blk;
                }
            }
            // we dont have them so well add them to the peer list (as default contact info)
            entrypoint_index = @intCast(maybe_entrypoint_index);
        }

        // filter out peers who have responded to pings
        var ping_cache_result = blk: {
            var ping_cache_lock = self.ping_cache_rw.write();
            defer ping_cache_lock.unlock();
            var ping_cache: *PingCache = ping_cache_lock.mut();

            var result = try ping_cache.filterValidPeers(self.allocator, self.my_keypair, peers);
            break :blk result;
        };
        var valid_gossip_peers = ping_cache_result.valid_peers;
        defer valid_gossip_peers.deinit();

        // send pings to peers
        var pings_to_send_out = ping_cache_result.pings;
        defer pings_to_send_out.deinit();
        try self.sendPings(pings_to_send_out);

        const should_send_to_entrypoint = entrypoint_index != -1;
        const num_peers = valid_gossip_peers.items.len;

        if (num_peers == 0 and !should_send_to_entrypoint) {
            return error.NoPeers;
        }

        // compute failed pull crds hash values
        const failed_pull_hashes_array = blk: {
            var failed_pull_hashes_lock = self.failed_pull_hashes_mux.lock();
            defer failed_pull_hashes_lock.unlock();

            const failed_pull_hashes: *const HashTimeQueue = failed_pull_hashes_lock.get();
            break :blk try failed_pull_hashes.getValues();
        };
        defer failed_pull_hashes_array.deinit();

        // build crds filters
        var filters = try pull_request.buildCrdsFilters(
            self.allocator,
            &self.crds_table_rw,
            &failed_pull_hashes_array,
            bloom_size,
            MAX_NUM_PULL_REQUESTS,
        );
        defer pull_request.deinitCrdsFilters(&filters);

        // build packet responses
        var output = try std.ArrayList(Packet).initCapacity(self.allocator, filters.items.len);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;

        // update wallclock and sign
        self.my_contact_info.wallclock = now;
        const my_contact_info_value = try crds.CrdsValue.initSigned(crds.CrdsData{
            .LegacyContactInfo = self.my_contact_info,
        }, &self.my_keypair);

        if (num_peers != 0) {
            for (filters.items) |filter_i| {
                // TODO: incorperate stake weight in random sampling
                const peer_index = rng.random().intRangeAtMost(usize, 0, num_peers - 1);
                const peer_contact_info = valid_gossip_peers.items[peer_index];
                const peer_addr = peer_contact_info.gossip.toEndpoint();

                const protocol_msg = Protocol{ .PullRequest = .{ filter_i, my_contact_info_value } };

                var msg_slice = try bincode.writeToSlice(&packet_buf, protocol_msg, bincode.Params{});
                var packet = Packet.init(peer_addr, packet_buf, msg_slice.len);
                output.appendAssumeCapacity(packet);
            }
        }

        // append entrypoint msgs
        if (should_send_to_entrypoint) {
            const entrypoint_addr = self.entrypoints.items[@as(usize, @intCast(entrypoint_index))];
            for (filters.items) |filter| {
                const protocol_msg = Protocol{ .PullRequest = .{ filter, my_contact_info_value } };
                var msg_slice = try bincode.writeToSlice(&packet_buf, protocol_msg, bincode.Params{});
                var packet = Packet.init(entrypoint_addr.toEndpoint(), packet_buf, msg_slice.len);
                try output.append(packet);
            }
        }

        return output;
    }

    fn handleBatchPullRequest(
        self: *Self,
        pull_requests: std.ArrayList(PullRequestMessage),
    ) void {
        // self.handleBatchPullRequestSequential(pull_requests) catch {};
        self.handleBatchPullRequestParallel(pull_requests) catch |err| {
            std.debug.print("handleBatchPullRequestParallel failed: {}\n", .{err});
        };
    }

    const PullRequestTask = struct {
        allocator: std.mem.Allocator,
        filter: CrdsFilter,
        crds_table: *const CrdsTable,
        output: std.ArrayList(CrdsValue),

        task: Task,
        done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),

        pub fn deinit(this: *PullRequestTask) void {
            this.output.deinit();
        }

        pub fn callback(task: *Task) void {
            var this = @fieldParentPtr(@This(), "task", task);
            defer this.done.store(true, std.atomic.Ordering.Release);

            const response_crds_values = pull_response.filterCrdsValues(
                this.allocator,
                this.crds_table,
                &this.filter,
                crds.getWallclockMs(),
                MAX_NUM_CRDS_VALUES_PULL_RESPONSE,
            ) catch {
                // std.debug.print("filterCrdsValues failed\n", .{});
                return;
            };
            defer response_crds_values.deinit();

            this.output.appendSlice(response_crds_values.items) catch {
                // std.debug.print("append slice failed\n", .{});
                return;
            };
            // std.debug.print("success: len = {}\n", .{ response_crds_values.items.len });
        }
    };

    fn handleBatchPullRequestParallel(
        self: *Self,
        pull_requests: std.ArrayList(PullRequestMessage),
    ) !void {
        // update the callers
        const now = getWallclockMs();
        {
            var crds_table_lock = self.crds_table_rw.write();
            defer crds_table_lock.unlock();
            var crds_table: *CrdsTable = crds_table_lock.mut();

            for (pull_requests.items) |*req| {
                const caller = req.value.id();
                crds_table.insert(req.value, now) catch {};
                crds_table.updateRecordTimestamp(caller, now);
            }
        }

        const n_requests = pull_requests.items.len;
        var valid_indexs = try std.ArrayList(usize).initCapacity(self.allocator, n_requests);
        defer valid_indexs.deinit();

        {
            var ping_cache_lock = self.ping_cache_rw.write();
            defer ping_cache_lock.unlock();
            var ping_cache: *PingCache = ping_cache_lock.mut();

            var ping_buff = [_]u8{0} ** PACKET_DATA_SIZE;

            for (pull_requests.items, 0..) |req, i| {
                // filter out valid peers and send ping messages to peers
                var now_instant = std.time.Instant.now() catch @panic("time is not supported on this OS!");
                var puller_socket_addr = SocketAddr.fromEndpoint(&req.from_endpoint);

                const caller = req.value.id();
                var result = ping_cache.check(
                    now_instant,
                    .{ caller, puller_socket_addr },
                    &self.my_keypair,
                );

                // send a ping
                if (result.maybe_ping) |ping| {
                    var protocol_msg = Protocol{ .PingMessage = ping };
                    var serialized_ping = bincode.writeToSlice(&ping_buff, protocol_msg, .{}) catch return error.SerializationError;
                    var packet = Packet.init(req.from_endpoint, ping_buff, serialized_ping.len);
                    try self.packet_outgoing_channel.send(packet);
                }

                if (result.passes_ping_check) {
                    valid_indexs.appendAssumeCapacity(i);
                }
            }
        }

        if (valid_indexs.items.len == 0) {
            return;
        }

        // create the pull requests
        const n_valid_requests = valid_indexs.items.len;
        var tasks = try std.ArrayList(*PullRequestTask).initCapacity(self.allocator, n_valid_requests);
        defer {
            for (tasks.items) |task| {
                task.deinit();
                self.allocator.destroy(task);
            }
            tasks.deinit();
        }

        {
            var crds_table_lock = self.crds_table_rw.read();
            const crds_table: *const CrdsTable = crds_table_lock.get();
            defer crds_table_lock.unlock();

            for (valid_indexs.items) |i| {
                // create the thread task
                var output = std.ArrayList(CrdsValue).init(self.allocator);
                var task = PullRequestTask{
                    .task = .{ .callback = PullRequestTask.callback },
                    .filter = pull_requests.items[i].filter,
                    .crds_table = crds_table,
                    .output = output,
                    .allocator = self.allocator,
                };

                // alloc on heap
                var task_heap = try self.allocator.create(PullRequestTask);
                task_heap.* = task;
                tasks.appendAssumeCapacity(task_heap);

                // run it
                const batch = Batch.from(&task_heap.task);
                ThreadPool.schedule(self.thread_pool, batch);
            }

            // wait for them to be done to release the lock
            for (tasks.items) |task| {
                while (!task.done.load(std.atomic.Ordering.Acquire)) {
                    // wait
                }
            }
        }

        for (tasks.items, valid_indexs.items) |task, message_i| {
            const from_endpoint = pull_requests.items[message_i].from_endpoint;
            const maybe_packets = try crdsValuesToPackets(
                self.allocator,
                &self.my_pubkey,
                task.output.items,
                &from_endpoint,
                ChunkType.PullResponse,
            );
            if (maybe_packets) |packets| {
                defer packets.deinit();
                for (packets.items) |packet| {
                    try self.packet_outgoing_channel.send(packet);
                }
            }
        }
    }

    fn handleBatchPullRequestSequential(
        self: *Self,
        pull_requests: std.ArrayList(PullRequestMessage),
    ) !void {
        for (pull_requests.items) |*pr| {
            const maybe_resp_packets = try self.handlePullRequest(
                pr.value,
                pr.filter,
                pr.from_endpoint,
                null,
            );
            if (maybe_resp_packets) |*resp_packets| {
                for (resp_packets.items) |packet| {
                    try self.packet_outgoing_channel.send(packet);
                }
            }
        }
    }

    /// logic for handling a pull request message
    /// values which are missing in the pull request filter are returned as a pull response
    /// which are serialized into packets.
    fn handlePullRequest(
        self: *Self,
        /// the crds value associated with the pull request
        pull_value: CrdsValue,
        /// the crds filter of the pull request
        pull_filter: CrdsFilter,
        /// the endpoint of the peer sending the pull request (/who to send the pull response to)
        pull_from_endpoint: EndPoint,
        // logging
        maybe_log_entry: ?Entry,
    ) error{ SerializationError, OutOfMemory, ChannelClosed }!?std.ArrayList(Packet) {
        const now = getWallclockMs();

        {
            var x_timer = std.time.Timer.start() catch unreachable;
            defer {
                const elapsed = x_timer.read();
                std.debug.print("pull_request crds_table_insert took {}ns\n", .{elapsed});
            }

            var crds_table_lock = self.crds_table_rw.write();
            defer crds_table_lock.unlock();
            var crds_table: *CrdsTable = crds_table_lock.mut();

            crds_table.insert(pull_value, now) catch {};
            crds_table.updateRecordTimestamp(pull_value.id(), now);
        }

        // filter out valid peers and send ping messages to peers
        var now_instant = std.time.Instant.now() catch @panic("time is not supported on this OS!");
        var puller_socket_addr = SocketAddr.fromEndpoint(&pull_from_endpoint);

        var ping_cache_lock = self.ping_cache_rw.write();
        var ping_cache: *PingCache = ping_cache_lock.mut();
        var result = ping_cache.check(
            now_instant,
            .{ pull_value.id(), puller_socket_addr },
            &self.my_keypair,
        );
        ping_cache_lock.unlock();

        // send a ping
        if (result.maybe_ping) |ping| {
            if (maybe_log_entry) |log_entry| {
                _ = log_entry.field("pings_sent", 1);
            }
            var ping_buff = [_]u8{0} ** PACKET_DATA_SIZE;
            var protocol_msg = Protocol{ .PingMessage = ping };
            var serialized_ping = bincode.writeToSlice(&ping_buff, protocol_msg, .{}) catch return error.SerializationError;
            var packet = Packet.init(pull_from_endpoint, ping_buff, serialized_ping.len);
            try self.packet_outgoing_channel.send(packet);
        }

        // peer hasnt responded to a ping = dont send a pull response
        if (!result.passes_ping_check) {
            return null;
        }

        const crds_values = blk: {
            var crds_table_lock = self.crds_table_rw.read();
            defer crds_table_lock.unlock();

            var x_timer = std.time.Timer.start() catch unreachable;
            defer {
                const elapsed = x_timer.read();
                std.debug.print("pull_request filterCrdsValues took {}ns\n", .{elapsed});
            }

            break :blk try pull_response.filterCrdsValues(
                self.allocator,
                crds_table_lock.get(),
                &pull_filter,
                pull_value.wallclock(),
                MAX_NUM_CRDS_VALUES_PULL_RESPONSE,
            );
        };
        defer crds_values.deinit();

        if (maybe_log_entry) |log_entry| {
            _ = log_entry.field("num_crds_values_resp", crds_values.items.len);
        }

        if (crds_values.items.len == 0) {
            return null;
        }

        // send the values as a pull response
        const packets = try crdsValuesToPackets(
            self.allocator,
            &self.my_pubkey,
            crds_values.items,
            &pull_from_endpoint,
            ChunkType.PullResponse,
        );
        return packets;
    }

    /// logic for handling a pull response message.
    /// successful inserted values, have their origin value timestamps updated.
    /// failed inserts (ie, too old or duplicate values) are added to the failed pull hashes so that they can be
    /// included in the next pull request (so we dont receive them again).
    fn handlePullResponse(
        self: *Self,
        /// the array of values to insert into the crds table
        crds_values: []CrdsValue,
        // logging info
        maybe_pull_log_entry: ?Entry,
    ) error{OutOfMemory}!void {
        // TODO: benchmark and compare with labs' preprocessing
        const now = getWallclockMs();
        var crds_table_lock = self.crds_table_rw.write();
        var crds_table: *CrdsTable = crds_table_lock.mut();

        const insert_results = try crds_table.insertValues(
            crds_values,
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
                crds_values[index],
                now,
            ) catch {};
        }

        // update the contactInfo timestamps of the successful inserts
        // (and all other origin values)
        const successful_insert_indexs = insert_results.inserted.?;
        defer successful_insert_indexs.deinit();
        for (successful_insert_indexs.items) |index| {
            const origin = crds_values[index].id();
            crds_table.updateRecordTimestamp(origin, now);
        }
        crds_table_lock.unlock();

        // track failed inserts - to use when constructing pull requests
        var failed_insert_indexs = insert_results.failed.?;
        defer failed_insert_indexs.deinit();
        {
            var failed_pull_hashes_lock = self.failed_pull_hashes_mux.lock();
            var failed_pull_hashes: *HashTimeQueue = failed_pull_hashes_lock.mut();
            defer failed_pull_hashes_lock.unlock();

            const failed_insert_cutoff_timestamp = now -| FAILED_INSERTS_RETENTION_MS;
            try failed_pull_hashes.trim(failed_insert_cutoff_timestamp);

            var buf: [PACKET_DATA_SIZE]u8 = undefined;
            for (failed_insert_indexs.items) |insert_index| {
                const value = crds_values[insert_index];
                var bytes = bincode.writeToSlice(&buf, value, bincode.Params.standard) catch {
                    std.debug.print("handle_pull_response: failed to serialize crds value: {any}\n", .{value});
                    continue;
                };
                const value_hash = Hash.generateSha256Hash(bytes);

                try failed_pull_hashes.insert(value_hash, now);
            }
        }

        // update logs
        if (maybe_pull_log_entry) |pull_log_entry| {
            _ = pull_log_entry
                .field("num_timeout_values", timeout_indexs.items.len)
                .field("num_success_insert_values", successful_insert_indexs.items.len)
                .field("num_failed_insert_values", failed_insert_indexs.items.len);
        }
    }

    /// logic for handling a prune message. verifies the prune message
    /// is not too old, and that the destination pubkey is the local node,
    /// then updates the active set to prune the list of origin Pubkeys.
    fn handlePruneMessage(
        self: *Self,
        /// the prune message to process
        prune_data: *const PruneData,
    ) error{ PruneMessageTooOld, BadDestination }!void {
        const now = getWallclockMs();
        const prune_wallclock = prune_data.wallclock;
        const too_old = prune_wallclock < now -| CRDS_GOSSIP_PRUNE_MSG_TIMEOUT_MS;
        if (too_old) {
            return error.PruneMessageTooOld;
        }

        const bad_destination = !prune_data.destination.equals(&self.my_pubkey);
        if (bad_destination) {
            return error.BadDestination;
        }

        // update active set
        const from_pubkey = prune_data.pubkey;

        var active_set_lock = self.active_set_rw.write();
        defer active_set_lock.unlock();

        var active_set: *ActiveSet = active_set_lock.mut();
        for (prune_data.prunes) |origin| {
            if (origin.equals(&self.my_pubkey)) {
                continue;
            }
            active_set.prune(from_pubkey, origin);
        }
    }

    /// builds a prune message for a list of origin Pubkeys and serializes the values
    /// into packets to send to the prune_destination.
    fn buildPruneMessage(
        self: *Self,
        /// origin Pubkeys which will be pruned
        failed_origins: *const std.AutoArrayHashMap(Pubkey, void),
        /// the pubkey of the node which we will send the prune message to
        prune_destination: Pubkey,
    ) error{ CantFindContactInfo, InvalidGossipAddress, OutOfMemory, SignatureError }!std.ArrayList(Packet) {
        const from_contact_info = blk: {
            var crds_table_lock = self.crds_table_rw.read();
            defer crds_table_lock.unlock();

            const crds_table: *const CrdsTable = crds_table_lock.get();
            break :blk crds_table.get(crds.CrdsValueLabel{ .LegacyContactInfo = prune_destination }) orelse {
                return error.CantFindContactInfo;
            };
        };
        const from_gossip_addr = from_contact_info.value.data.LegacyContactInfo.gossip;
        crds.sanitizeSocket(&from_gossip_addr) catch return error.InvalidGossipAddress;
        const from_gossip_endpoint = from_gossip_addr.toEndpoint();

        const failed_origin_len = failed_origins.keys().len;
        var n_packets = failed_origins.keys().len / MAX_PRUNE_DATA_NODES;
        var prune_packets = try std.ArrayList(Packet).initCapacity(self.allocator, n_packets);
        errdefer prune_packets.deinit();

        const now = getWallclockMs();
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;

        var index: usize = 0;
        while (true) {
            const prune_size = @min(failed_origin_len - index, MAX_PRUNE_DATA_NODES);
            if (prune_size == 0) break;

            var prune_data = PruneData.init(
                self.my_pubkey,
                failed_origins.keys()[index..(prune_size + index)],
                prune_destination,
                now,
            );
            prune_data.sign(&self.my_keypair) catch return error.SignatureError;

            // put it into a packet
            var msg = Protocol{ .PruneMessage = .{ self.my_pubkey, prune_data } };
            // msg should never be bigger than the PacketSize and serialization shouldnt fail (unrecoverable)
            var msg_slice = bincode.writeToSlice(&packet_buf, msg, bincode.Params{}) catch unreachable;
            var packet = Packet.init(from_gossip_endpoint, packet_buf, msg_slice.len);
            try prune_packets.append(packet);

            index += prune_size;
        }

        return prune_packets;
    }

    /// logic for handling push messages. crds values from the push message
    /// are inserted into the crds table. the origin pubkeys of values which
    /// fail the insertion are returned to generate prune messages.
    fn handlePushMessage(
        self: *Self,
        push_values: []CrdsValue,
    ) error{OutOfMemory}!std.AutoArrayHashMap(Pubkey, void) {
        const failed_insert_indexs = blk: {
            var crds_table_lock = self.crds_table_rw.write();
            defer crds_table_lock.unlock();

            var crds_table: *CrdsTable = crds_table_lock.mut();
            var result = try crds_table.insertValues(
                push_values,
                CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS,
                false,
                false,
            );
            break :blk result.failed.?;
        };
        defer failed_insert_indexs.deinit();

        // origins are used to generate prune messages
        // hashmap to account for duplicates
        var failed_origins = std.AutoArrayHashMap(Pubkey, void).init(self.allocator);
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

    /// builds a corresponding Pong message for a given Ping message and serializes the
    /// protocol message into a Packet.
    fn handlePingMessage(
        self: *Self,
        /// the ping message to build a Pong message for
        ping: *const Ping,
        /// the endpoint to send the Pong message
        from_endpoint: EndPoint,
    ) error{ SignatureError, SerializationError }!Packet {
        const pong = try Pong.init(ping, &self.my_keypair);
        const pong_message = Protocol{
            .PongMessage = pong,
        };

        // write to packet
        var buf: [PACKET_DATA_SIZE]u8 = undefined;
        const msg = bincode.writeToSlice(&buf, pong_message, bincode.Params.standard) catch return error.SerializationError;
        const packet = Packet.init(from_endpoint, buf, msg.len);

        return packet;
    }

    /// removes old values from the crds table and failed pull hashes struct
    /// based on the current time. This includes triming the purged values from the
    /// crds table, triming the max number of pubkeys in the crds table, and removing
    /// old labels from the crds table.
    fn trimMemory(
        self: *Self,
        /// the current time
        now: u64,
    ) error{OutOfMemory}!void {
        const purged_cutoff_timestamp = now -| (5 * CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS);
        {
            var crds_table_lock = self.crds_table_rw.write();
            defer crds_table_lock.unlock();
            var crds_table: *CrdsTable = crds_table_lock.mut();

            try crds_table.purged.trim(purged_cutoff_timestamp);
            try crds_table.attemptTrim(CRDS_UNIQUE_PUBKEY_CAPACITY);
            try crds_table.removeOldLabels(now, CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS);
        }

        const failed_insert_cutoff_timestamp = now -| FAILED_INSERTS_RETENTION_MS;
        {
            var failed_pull_hashes_lock = self.failed_pull_hashes_mux.lock();
            defer failed_pull_hashes_lock.unlock();
            var failed_pull_hashes: *HashTimeQueue = failed_pull_hashes_lock.mut();

            try failed_pull_hashes.trim(failed_insert_cutoff_timestamp);
        }
    }

    /// drains values from the push queue and inserts them into the crds table.
    /// when inserting values in the crds table, any errors are ignored.
    fn drainPushQueueToCrdsTable(
        self: *Self,
        /// the current time to insert the values with
        now: u64,
    ) void {
        var push_msg_queue_lock = self.push_msg_queue_mux.lock();
        defer push_msg_queue_lock.unlock();
        var push_msg_queue: *std.ArrayList(CrdsValue) = push_msg_queue_lock.mut();

        var crds_table_lock = self.crds_table_rw.write();
        defer crds_table_lock.unlock();
        var crds_table: *CrdsTable = crds_table_lock.mut();

        while (push_msg_queue.popOrNull()) |crds_value| {
            crds_table.insert(crds_value, now) catch {};
        }
    }

    /// serializes a list of ping messages into Packets and sends them out
    pub fn sendPings(
        self: *Self,
        pings: std.ArrayList(PingAndSocketAddr),
    ) error{ OutOfMemory, ChannelClosed, SerializationError }!void {
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;

        for (pings.items) |ping_and_addr| {
            const protocol_msg = Protocol{ .PingMessage = ping_and_addr.ping };
            var serialized_ping = bincode.writeToSlice(&packet_buf, protocol_msg, .{}) catch return error.SerializationError;

            var to_endpoint = ping_and_addr.socket.toEndpoint();
            var packet = Packet.init(to_endpoint, packet_buf, serialized_ping.len);
            try self.packet_outgoing_channel.send(packet);
        }
    }

    /// returns a list of valid gossip nodes. this works by reading
    /// the contact infos from the crds table and filtering out
    /// nodes that are 1) too old, 2) have a different shred version, or 3) have
    /// an invalid gossip address.
    pub fn getGossipNodes(
        self: *Self,
        /// the output slice which will be filled with gossip nodes
        nodes: []crds.LegacyContactInfo,
        /// the maximum number of nodes to return ( max_size == nodes.len but comptime for init of stack array)
        comptime MAX_SIZE: usize,
        /// current time (used to filter out nodes that are too old)
        now: u64,
    ) []crds.LegacyContactInfo {
        std.debug.assert(MAX_SIZE == nodes.len);

        // * 2 bc we might filter out some
        var buf: [MAX_SIZE * 2]crds.CrdsVersionedValue = undefined;
        const contact_infos = blk: {
            var crds_table_lock = self.crds_table_rw.read();
            defer crds_table_lock.unlock();

            var crds_table: *const CrdsTable = crds_table_lock.get();
            break :blk crds_table.getContactInfos(&buf);
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
            if (contact_info.value.id().equals(&self.my_pubkey)) {
                continue;
            }
            // filter matching shred version or my_shred_version == 0
            if (self.my_shred_version != 0 and self.my_shred_version != peer_info.shred_version) {
                continue;
            }
            // filter on valid gossip address
            crds.sanitizeSocket(&peer_gossip_addr) catch continue;

            nodes[node_index] = peer_info;
            node_index += 1;

            if (node_index == nodes.len) {
                break;
            }
        }

        return nodes[0..node_index];
    }
};

pub const ChunkType = enum(u8) {
    PushMessage,
    PullResponse,
};

pub fn crdsValuesToPackets(
    allocator: std.mem.Allocator,
    my_pubkey: *const Pubkey,
    crds_values: []CrdsValue,
    to_endpoint: *const EndPoint,
    chunk_type: ChunkType,
) error{ OutOfMemory, SerializationError }!?std.ArrayList(Packet) {
    if (crds_values.len == 0) return null;

    const indexs = try chunkValuesIntoPacketIndexs(
        allocator,
        crds_values,
        MAX_PUSH_MESSAGE_PAYLOAD_SIZE,
    );
    defer indexs.deinit();
    var chunk_iter = std.mem.window(usize, indexs.items, 2, 1);

    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var packets = try std.ArrayList(Packet).initCapacity(allocator, indexs.items.len -| 1);
    errdefer packets.deinit();

    while (chunk_iter.next()) |window| {
        const start_index = window[0];
        const end_index = window[1];
        const values = crds_values[start_index..end_index];

        const protocol_msg = switch (chunk_type) {
            .PushMessage => Protocol{ .PushMessage = .{ my_pubkey.*, values } },
            .PullResponse => Protocol{ .PullResponse = .{ my_pubkey.*, values } },
        };
        var msg_slice = bincode.writeToSlice(&packet_buf, protocol_msg, bincode.Params{}) catch {
            return error.SerializationError;
        };
        var packet = Packet.init(to_endpoint.*, packet_buf, msg_slice.len);
        packets.appendAssumeCapacity(packet);
    }

    return packets;
}

pub fn chunkValuesIntoPacketIndexs(
    allocator: std.mem.Allocator,
    crds_values: []CrdsValue,
    max_chunk_bytes: usize,
) error{ OutOfMemory, SerializationError }!std.ArrayList(usize) {
    var packet_indexs = try std.ArrayList(usize).initCapacity(allocator, 1);
    errdefer packet_indexs.deinit();
    packet_indexs.appendAssumeCapacity(0);

    if (crds_values.len == 0) {
        return packet_indexs;
    }

    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var buf_byte_size: u64 = 0;

    for (crds_values, 0..) |crds_value, i| {
        const data_byte_size = bincode.getSerializedSizeWithSlice(&packet_buf, crds_value, bincode.Params{}) catch {
            return error.SerializationError;
        };
        const new_chunk_size = buf_byte_size + data_byte_size;
        const is_last_iter = i == crds_values.len - 1;

        if (new_chunk_size > max_chunk_bytes or is_last_iter) {
            try packet_indexs.append(i);
            buf_byte_size = data_byte_size;
        } else {
            buf_byte_size = new_chunk_size;
        }
    }

    return packet_indexs;
}

test "gossip.gossip_service: tests handle_prune_messages" {
    var rng = std.rand.DefaultPrng.init(91);

    const allocator = std.testing.allocator;
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = crds.LegacyContactInfo.default(my_pubkey);
    contact_info.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        my_keypair,
        null,
        &exit,
        logger,
    );
    defer gossip_service.deinit();

    // add some peers
    var lg = gossip_service.crds_table_rw.write();
    var peers = std.ArrayList(crds.LegacyContactInfo).init(allocator);
    defer peers.deinit();
    for (0..10) |_| {
        var rand_keypair = try KeyPair.create(null);
        var value = try CrdsValue.randomWithIndex(rng.random(), &rand_keypair, 0); // contact info
        try lg.mut().insert(value, getWallclockMs());
        try peers.append(value.data.LegacyContactInfo);
    }
    lg.unlock();

    {
        var as_lock = gossip_service.active_set_rw.write();
        var as: *ActiveSet = as_lock.mut();
        try as.rotate(peers.items);
        as_lock.unlock();
    }

    var as_lock = gossip_service.active_set_rw.read();
    var as: *const ActiveSet = as_lock.get();
    try std.testing.expect(as.len > 0); // FIX
    var peer0 = as.peers[0];
    as_lock.unlock();

    var prunes = [_]Pubkey{Pubkey.random(rng.random(), .{})};
    var prune_data = PruneData{
        .pubkey = peer0,
        .destination = gossip_service.my_pubkey,
        .prunes = &prunes,
        .signature = undefined,
        .wallclock = getWallclockMs(),
    };
    try prune_data.sign(&my_keypair);

    try gossip_service.handlePruneMessage(&prune_data);

    var as_lock2 = gossip_service.active_set_rw.read();
    var as2: *const ActiveSet = as_lock2.get();
    try std.testing.expect(as2.pruned_peers.get(peer0).?.contains(&prunes[0].data));
    as_lock2.unlock();
}

test "gossip.gossip_service: tests handle_pull_response" {
    const allocator = std.testing.allocator;

    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = crds.LegacyContactInfo.default(my_pubkey);
    contact_info.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        my_keypair,
        null,
        &exit,
        logger,
    );
    defer gossip_service.deinit();

    // get random values
    var crds_values: [5]CrdsValue = undefined;
    var kp = try KeyPair.create(null);
    for (0..5) |i| {
        var value = try CrdsValue.randomWithIndex(rng.random(), &kp, 0);
        value.data.LegacyContactInfo.id = Pubkey.random(rng.random(), .{});
        crds_values[i] = value;
    }

    try gossip_service.handlePullResponse(&crds_values, null);

    // make sure values are inserted
    var crds_table_lock = gossip_service.crds_table_rw.read();
    var crds_table: *const CrdsTable = crds_table_lock.get();
    for (crds_values) |value| {
        _ = crds_table.get(value.label()).?;
    }
    crds_table_lock.unlock();

    // try inserting again with same values (should all fail)
    try gossip_service.handlePullResponse(&crds_values, null);

    var lg = gossip_service.failed_pull_hashes_mux.lock();
    var failed_pull_hashes: *HashTimeQueue = lg.mut();
    try std.testing.expect(failed_pull_hashes.len() == 5);
    lg.unlock();
}

test "gossip.gossip_service: tests handle_pull_request" {
    const allocator = std.testing.allocator;

    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = crds.LegacyContactInfo.default(my_pubkey);
    contact_info.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        my_keypair,
        null,
        &exit,
        logger,
    );
    defer gossip_service.deinit();

    // insert random values
    var crds_table_lock = gossip_service.crds_table_rw.write();
    var crds_table: *CrdsTable = crds_table_lock.mut();
    const N_FILTER_BITS = 1;

    var done = false;
    var count: usize = 0;
    while (!done) {
        count += 1;
        for (0..5) |_| {
            var value = try CrdsValue.randomWithIndex(rng.random(), &my_keypair, 0);
            value.data.LegacyContactInfo.id = Pubkey.random(rng.random(), .{});
            try crds_table.insert(value, getWallclockMs());

            // make sure well get a response from the request
            const vers_value = crds_table.get(value.label()).?;
            const hash_bits = pull_request.hashToU64(&vers_value.value_hash) >> (64 - N_FILTER_BITS);
            if (hash_bits == 0) {
                done = true;
            }
        }

        if (count > 5) {
            @panic("something went wrong");
        }
    }
    crds_table_lock.unlock();

    const Bloom = @import("../bloom/bloom.zig").Bloom;
    // only consider the first bit so we know well get matches
    var bloom = try Bloom.random(allocator, 100, 0.1, N_FILTER_BITS);
    defer bloom.deinit();

    var ci_data = crds.CrdsData.randomFromIndex(rng.random(), 0);
    ci_data.LegacyContactInfo.id = my_pubkey;
    var crds_value = try CrdsValue.initSigned(ci_data, &my_keypair);

    const addr = SocketAddr.random(rng.random());
    var ping_lock = gossip_service.ping_cache_rw.write();
    var ping_cache: *PingCache = ping_lock.mut();
    ping_cache._setPong(my_pubkey, addr);
    ping_lock.unlock();

    var filter = CrdsFilter{
        .filter = bloom,
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };

    var packets = try gossip_service.handlePullRequest(
        crds_value,
        filter,
        addr.toEndpoint(),
        null,
    );
    defer packets.?.deinit();
    try std.testing.expect(packets.?.items.len > 0);

    var batch_requests = std.ArrayList(GossipService.PullRequestMessage).init(allocator);
    defer batch_requests.deinit();

    var from_endpoint = addr.toEndpoint();
    try batch_requests.append(GossipService.PullRequestMessage{
        .value = crds_value,
        .filter = filter,
        .from_endpoint = from_endpoint,
    });

    gossip_service.handleBatchPullRequest(batch_requests);
}

test "gossip.gossip_service: test build prune messages and handle_push_msgs" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = crds.LegacyContactInfo.default(my_pubkey);
    contact_info.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        my_keypair,
        null,
        &exit,
        logger,
    );
    defer gossip_service.deinit();

    var push_from = Pubkey.random(rng.random(), .{});
    var values = std.ArrayList(CrdsValue).init(allocator);
    defer values.deinit();
    for (0..10) |_| {
        var value = try CrdsValue.randomWithIndex(rng.random(), &my_keypair, 0);
        value.data.LegacyContactInfo.id = Pubkey.random(rng.random(), .{});
        try values.append(value);
    }

    // insert contact info to send prunes to
    var send_contact_info = crds.LegacyContactInfo.random(rng.random());
    send_contact_info.id = push_from;
    // valid socket addr
    var gossip_socket = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 20);
    send_contact_info.gossip = gossip_socket;

    var ci_value = try CrdsValue.initSigned(crds.CrdsData{
        .LegacyContactInfo = send_contact_info,
    }, &my_keypair);
    var lg = gossip_service.crds_table_rw.write();
    try lg.mut().insert(ci_value, getWallclockMs());
    lg.unlock();

    var forigins = try gossip_service.handlePushMessage(values.items);
    defer forigins.deinit();
    try std.testing.expect(forigins.keys().len == 0);

    var failed_origins = try gossip_service.handlePushMessage(values.items);
    defer failed_origins.deinit();
    try std.testing.expect(failed_origins.keys().len > 0);

    var prune_packets = try gossip_service.buildPruneMessage(&failed_origins, push_from);
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

test "gossip.gossip_service: test build_pull_requests" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = crds.LegacyContactInfo.default(my_pubkey);
    contact_info.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        my_keypair,
        null,
        &exit,
        logger,
    );
    defer gossip_service.deinit();

    // insert peers to send msgs to
    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var ping_lock = gossip_service.ping_cache_rw.write();
    var lg = gossip_service.crds_table_rw.write();
    for (0..20) |_| {
        var value = try CrdsValue.randomWithIndex(rng.random(), &keypair, 0);
        try lg.mut().insert(value, getWallclockMs());
        var pc: *PingCache = ping_lock.mut();
        pc._setPong(value.data.LegacyContactInfo.id, value.data.LegacyContactInfo.gossip);
    }
    lg.unlock();
    ping_lock.unlock();

    var packets = try gossip_service.buildPullRequests(2);
    defer packets.deinit();

    try std.testing.expect(packets.items.len > 1);
    try std.testing.expect(!std.mem.eql(u8, &packets.items[0].data, &packets.items[1].data));
}

test "gossip.gossip_service: test build_push_messages" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = crds.LegacyContactInfo.default(my_pubkey);
    contact_info.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        my_keypair,
        null,
        &exit,
        logger,
    );
    defer gossip_service.deinit();

    // add some peers
    var peers = std.ArrayList(crds.LegacyContactInfo).init(allocator);
    defer peers.deinit();
    var lg = gossip_service.crds_table_rw.write();
    for (0..10) |_| {
        var keypair = try KeyPair.create(null);
        var value = try CrdsValue.randomWithIndex(rng.random(), &keypair, 0); // contact info
        try lg.mut().insert(value, getWallclockMs());
        try peers.append(value.data.LegacyContactInfo);
    }
    lg.unlock();

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    // var id = Pubkey.fromPublicKey(&keypair.public_key, false);
    var value = try CrdsValue.random(rng.random(), &keypair);

    // set the active set
    {
        var as_lock = gossip_service.active_set_rw.write();
        var as: *ActiveSet = as_lock.mut();
        try as.rotate(peers.items);
        as_lock.unlock();
        try std.testing.expect(as.len > 0);
    }

    {
        var pqlg = gossip_service.push_msg_queue_mux.lock();
        var push_queue = pqlg.mut();
        try push_queue.append(value);
        pqlg.unlock();
    }
    gossip_service.drainPushQueueToCrdsTable(getWallclockMs());

    var clg = gossip_service.crds_table_rw.read();
    try std.testing.expect(clg.get().len() == 11);
    clg.unlock();

    var cursor: u64 = 0;
    var msgs = (try gossip_service.buildPushMessages(&cursor)).?;
    try std.testing.expectEqual(cursor, 11);
    try std.testing.expect(msgs.items.len > 0);
    msgs.deinit();

    var msgs2 = try gossip_service.buildPushMessages(&cursor);
    try std.testing.expectEqual(cursor, 11);
    try std.testing.expect(msgs2 == null);
}

test "gossip.gossip_service: test packet verification" {
    const allocator = std.testing.allocator;
    var exit = AtomicBool.init(false);
    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var id = Pubkey.fromPublicKey(&keypair.public_key, true);

    var contact_info = crds.LegacyContactInfo.default(id);
    contact_info.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        keypair,
        null,
        &exit,
        logger,
    );

    defer gossip_service.deinit();

    var packet_channel = gossip_service.packet_incoming_channel;
    var verified_channel = gossip_service.verified_incoming_channel;

    var packet_verifier_handle = try Thread.spawn(.{}, GossipService.verifyPackets, .{&gossip_service});

    var rng = std.rand.DefaultPrng.init(getWallclockMs());
    var data = crds.CrdsData.randomFromIndex(rng.random(), 0);
    data.LegacyContactInfo.id = id;
    data.LegacyContactInfo.wallclock = 0;
    var value = try CrdsValue.initSigned(data, &keypair);

    try std.testing.expect(try value.verify(id));

    var values = [_]crds.CrdsValue{value};
    const protocol_msg = Protocol{
        .PushMessage = .{ id, &values },
    };

    var peer = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);
    var from = peer.toEndpoint();

    var buf = [_]u8{0} ** PACKET_DATA_SIZE;
    var out = try bincode.writeToSlice(buf[0..], protocol_msg, bincode.Params{});
    var packet = Packet.init(from, buf, out.len);

    for (0..3) |_| {
        try packet_channel.send(packet);
    }

    // send one which fails sanitization
    var value_v2 = try CrdsValue.initSigned(crds.CrdsData.randomFromIndex(rng.random(), 2), &keypair);
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
    var value2 = try CrdsValue.initSigned(crds.CrdsData.randomFromIndex(rng.random(), 0), &rand_keypair);
    var values2 = [_]crds.CrdsValue{value2};
    const protocol_msg2 = Protocol{
        .PushMessage = .{ id, &values2 },
    };
    var buf2 = [_]u8{0} ** PACKET_DATA_SIZE;
    var out2 = try bincode.writeToSlice(buf2[0..], protocol_msg2, bincode.Params{});
    var packet2 = Packet.init(from, buf2, out2.len);
    try packet_channel.send(packet2);

    // send it with a CrdsValue which hash a slice
    {
        var rand_pubkey = Pubkey.fromPublicKey(&rand_keypair.public_key, true);
        var dshred = crds.DuplicateShred.random(rng.random());
        var chunk: [32]u8 = .{1} ** 32;
        dshred.chunk = &chunk;
        dshred.from = rand_pubkey;
        var dshred_data = crds.CrdsData{
            .DuplicateShred = .{ 1, dshred },
        };
        var dshred_value = try CrdsValue.initSigned(dshred_data, &rand_keypair);
        var values3 = [_]crds.CrdsValue{dshred_value};
        const protocol_msg3 = Protocol{
            .PushMessage = .{ id, &values3 },
        };
        var buf3 = [_]u8{0} ** PACKET_DATA_SIZE;
        var out3 = try bincode.writeToSlice(buf3[0..], protocol_msg3, bincode.Params{});
        var packet3 = Packet.init(from, buf3, out3.len);
        try packet_channel.send(packet3);
    }

    var msg_count: usize = 0;
    while (msg_count < 4) {
        if (try verified_channel.try_drain()) |msgs| {
            defer verified_channel.allocator.free(msgs);
            for (msgs) |msg| {
                defer bincode.free(gossip_service.allocator, msg);
                try std.testing.expect(msg.message.PushMessage[0].equals(&id));
                msg_count += 1;
            }
        }
        std.time.sleep(10);
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

    exit.store(true, std.atomic.Ordering.Unordered);
    packet_verifier_handle.join();
}

test "gossip.gossip_service: process contact_info push packet" {
    const allocator = std.testing.allocator;
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = crds.LegacyContactInfo.default(my_pubkey);
    contact_info.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);

    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        my_keypair,
        null,
        &exit,
        logger,
    );
    defer gossip_service.deinit();

    var verified_channel = gossip_service.verified_incoming_channel;
    var responder_channel = gossip_service.packet_outgoing_channel;

    var kp = try KeyPair.create(null);
    var pk = Pubkey.fromPublicKey(&kp.public_key, false);

    var packet_handle = try Thread.spawn(
        .{},
        GossipService.processMessages,
        .{
            &gossip_service,
        },
    );

    // send a push message
    var id = pk;

    // new contact info
    var legacy_contact_info = crds.LegacyContactInfo.default(id);
    var crds_data = crds.CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    };
    var crds_value = try crds.CrdsValue.initSigned(crds_data, &kp);
    var values = [_]crds.CrdsValue{crds_value};
    const msg = Protocol{
        .PushMessage = .{ id, &values },
    };

    // packet
    const peer = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8000).toEndpoint();
    const protocol_msg = ProtocolMessage{
        .from_endpoint = peer,
        .message = msg,
    };
    try verified_channel.send(protocol_msg);

    // ping
    const ping_msg = ProtocolMessage{
        .message = Protocol{
            .PingMessage = try Ping.init(.{0} ** 32, &kp),
        },
        .from_endpoint = peer,
    };
    try verified_channel.send(ping_msg);

    // correct insertion into table
    var buf2: [100]crds.CrdsVersionedValue = undefined;
    std.time.sleep(std.time.ns_per_s);

    {
        var lg = gossip_service.crds_table_rw.read();
        var res = lg.get().getContactInfos(&buf2);
        try std.testing.expect(res.len == 1);
        lg.unlock();
    }

    const resp = (try responder_channel.try_drain()).?;
    defer responder_channel.allocator.free(resp);
    try std.testing.expect(resp.len == 1);

    exit.store(true, std.atomic.Ordering.Unordered);
    packet_handle.join();
}

test "gossip.gossip_service: init, exit, and deinit" {
    var gossip_address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);
    var my_keypair = try KeyPair.create(null);
    var rng = std.rand.DefaultPrng.init(getWallclockMs());
    var contact_info = crds.LegacyContactInfo.random(rng.random());
    contact_info.gossip = gossip_address;
    var exit = AtomicBool.init(false);
    var logger = Logger.init(std.testing.allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        std.testing.allocator,
        contact_info,
        my_keypair,
        null,
        &exit,
        logger,
    );

    var handle = try std.Thread.spawn(
        .{},
        GossipService.run,
        .{&gossip_service},
    );

    gossip_service.echo_server.kill();
    exit.store(true, std.atomic.Ordering.Unordered);
    handle.join();
    gossip_service.deinit();
}

const fuzz = @import("./fuzz.zig");

pub const BenchmarkGossipServiceGeneral = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 3;

    pub const args = [_]usize{
        1_000,
        5_000,
        10_000,
    };

    pub const arg_names = [_][]const u8{
        "1k_msgs",
        "5k_msgs",
        "10k_msg_iters",
    };

    pub fn benchmarkGossipServiceProcessMessages(num_message_iterations: usize) !void {
        const allocator = std.heap.page_allocator;
        var keypair = try KeyPair.create(null);
        var address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8888);
        var endpoint = address.toEndpoint();

        var pubkey = Pubkey.fromPublicKey(&keypair.public_key, false);
        var contact_info = crds.LegacyContactInfo.default(pubkey);
        contact_info.shred_version = 19;
        contact_info.gossip = address;

        // var logger = Logger.init(allocator, .debug);
        // defer logger.deinit();
        // logger.spawn();
        var logger: Logger = .noop;

        // process incoming packets/messsages
        var exit = AtomicBool.init(false);
        var gossip_service = try GossipService.init(
            allocator,
            contact_info,
            keypair,
            null,
            &exit,
            logger,
        );
        defer gossip_service.deinit();

        var packet_handle = try Thread.spawn(.{}, GossipService.runSpy, .{
            &gossip_service,
        });

        // send incomign packets/messages
        var outgoing_channel = Channel(Packet).init(allocator, 10_000);
        defer outgoing_channel.deinit();

        var socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
        socket.bindToPort(8889) catch return error.SocketBindFailed;
        socket.setReadTimeout(1000000) catch return error.SocketSetTimeoutFailed; // 1 second
        defer {
            socket.close();
        }

        var outgoing_handle = try Thread.spawn(.{}, socket_utils.sendSocket, .{
            &socket,
            outgoing_channel,
            &exit,
            logger,
        });

        // generate messages
        var rand = std.rand.DefaultPrng.init(19);
        var rng = rand.random();
        var sender_keypair = try KeyPair.create(null);

        var msg_sent: usize = 0;
        while (msg_sent < num_message_iterations) {
            // send a ping message
            {
                var msg = try fuzz.randomPingPacket(rng, &keypair, endpoint);
                try outgoing_channel.send(msg);
                msg_sent += 1;
            }
            // send a pong message
            {
                var msg = try fuzz.randomPongPacket(rng, &keypair, endpoint);
                try outgoing_channel.send(msg);
                msg_sent += 1;
            }
            // send a push message
            {
                var packets = try fuzz.randomPushMessage(rng, &keypair, address.toEndpoint());
                defer packets.deinit();

                for (packets.items) |packet| {
                    try outgoing_channel.send(packet);
                    msg_sent += 1;
                }
            }
            // send a pull response
            {
                var packets = try fuzz.randomPullResponse(rng, &keypair, address.toEndpoint());
                defer packets.deinit();

                for (packets.items) |packet| {
                    try outgoing_channel.send(packet);
                    msg_sent += 1;
                }
            }
            // send a pull request
            {
                var packet = try fuzz.randomPullRequest(allocator, rng, &sender_keypair, address.toEndpoint());
                try outgoing_channel.send(packet);
                msg_sent += 1;
            }
        }

        // wait for all messages to be processed
        while (true) {
            const v = gossip_service.messages_processed.load(std.atomic.Ordering.Acquire);
            if (v >= msg_sent) {
                break;
            }
        }

        exit.store(true, std.atomic.Ordering.Unordered);
        packet_handle.join();
        outgoing_handle.join();
    }
};

pub const BenchmarkGossipServicePullRequest = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 1;

    pub const args = [_]usize{
        1_000,
    };

    pub const arg_names = [_][]const u8{
        "1_000",
    };

    pub fn benchmarkPullRequests(num_message_iterations: usize) !void {
        const allocator = std.heap.page_allocator;
        var address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);

        var keypair = try KeyPair.create(null);
        var pubkey = Pubkey.fromPublicKey(&keypair.public_key, false);
        var contact_info = crds.LegacyContactInfo.default(pubkey);
        contact_info.shred_version = 19;
        contact_info.gossip = address;

        // var logger = Logger.init(allocator, .debug);
        // defer logger.deinit();
        // logger.spawn();
        var logger: Logger = .noop;

        var exit = AtomicBool.init(false);
        var gossip_service = try GossipService.init(
            allocator,
            contact_info,
            keypair,
            null,
            &exit,
            logger,
        );
        defer gossip_service.deinit();

        // var packet_handle = try Thread.spawn(.{}, GossipService.processMessages, .{
        //     &gossip_service,
        // });

        var packet_handle = try Thread.spawn(.{}, GossipService.runSpy, .{
            &gossip_service,
        });

        var rand = std.rand.DefaultPrng.init(19);
        var rng = rand.random();

        var sender_keypair = try KeyPair.create(null);

        var msg_sent: usize = 0;
        for (0..num_message_iterations) |i| {
            // send a push message
            if (i % 2 == 0) {
                var packets = try fuzz.randomPushMessage(rng, &sender_keypair, address.toEndpoint());
                defer packets.deinit();

                for (packets.items) |packet| {
                    try gossip_service.packet_incoming_channel.send(packet);
                    msg_sent += 1;
                }
            } else {
                // send a pull request
                var packet = try fuzz.randomPullRequest(allocator, rng, &sender_keypair, address.toEndpoint());
                try gossip_service.packet_incoming_channel.send(packet);
                msg_sent += 1;
            }
        }

        while (true) {
            const v = gossip_service.messages_processed.load(std.atomic.Ordering.Unordered);
            if (v == msg_sent) {
                break;
            }
            std.time.sleep(std.time.ns_per_s);
        }

        exit.store(true, std.atomic.Ordering.Unordered);
        packet_handle.join();
    }
};
