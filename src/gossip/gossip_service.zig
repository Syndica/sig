const std = @import("std");
const builtin = @import("builtin");
const network = @import("zig-network");
const EndPoint = network.EndPoint;
const Packet = @import("packet.zig").Packet;
const PACKET_DATA_SIZE = @import("packet.zig").PACKET_DATA_SIZE;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;
const ArrayList = std.ArrayList;

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
const LegacyContactInfo = crds.LegacyContactInfo;
const CrdsValue = crds.CrdsValue;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const getWallclockMs = @import("../gossip/crds.zig").getWallclockMs;

const _crds_table = @import("../gossip/crds_table.zig");
const CrdsTable = _crds_table.CrdsTable;
const CrdsError = _crds_table.CrdsError;
const HashTimeQueue = _crds_table.HashTimeQueue;
const CRDS_UNIQUE_PUBKEY_CAPACITY = _crds_table.CRDS_UNIQUE_PUBKEY_CAPACITY;
const AutoArrayHashSet = _crds_table.AutoArrayHashSet;

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

const PacketBatch = ArrayList(Packet);
const PacketChannel = Channel(Packet);
const PacketBatchChannel = Channel(PacketBatch);

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

// TODO: replace with get_epoch_duration when BankForks is supported
const DEFAULT_EPOCH_DURATION: u64 = 172800000;

const Config = struct { mode: enum { normal, tests, bench } = .normal };

pub const GossipService = struct {
    allocator: std.mem.Allocator,

    // note: this contact info should not change
    gossip_socket: UdpSocket,
    /// This contact info is mutated by the buildMessages thread, so it must
    /// only be read by that thread, or it needs a synchronization mechanism.
    my_contact_info: LegacyContactInfo,
    my_keypair: KeyPair,
    my_pubkey: Pubkey,
    my_shred_version: std.atomic.Atomic(u16),
    exit: *AtomicBool,

    // communication between threads
    packet_incoming_channel: *PacketBatchChannel,
    packet_outgoing_channel: *PacketBatchChannel,
    verified_incoming_channel: *ProtocolChannel,

    crds_table_rw: RwMux(CrdsTable),
    // push message things
    active_set_rw: RwMux(ActiveSet),
    push_msg_queue_mux: Mux(ArrayList(CrdsValue)),
    // pull message things
    failed_pull_hashes_mux: Mux(HashTimeQueue),

    /// This contact info is mutated by the buildMessages thread, so it must
    /// only be read by that thread, or it needs a synchronization mechanism.
    entrypoints: ArrayList(Entrypoint),
    ping_cache_rw: RwMux(PingCache),
    logger: Logger,
    thread_pool: *ThreadPool,
    echo_server: echo.Server,

    // used for benchmarking
    messages_processed: std.atomic.Atomic(usize) = std.atomic.Atomic(usize).init(0),

    const Entrypoint = struct { addr: SocketAddr, info: ?LegacyContactInfo = null };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        my_contact_info: LegacyContactInfo,
        my_keypair: KeyPair,
        entrypoints: ?ArrayList(SocketAddr),
        exit: *AtomicBool,
        logger: Logger,
    ) error{ OutOfMemory, SocketCreateFailed, SocketBindFailed, SocketSetTimeoutFailed }!Self {
        var packet_incoming_channel = PacketBatchChannel.init(allocator, 10000);
        var packet_outgoing_channel = PacketBatchChannel.init(allocator, 10000);
        var verified_incoming_channel = ProtocolChannel.init(allocator, 10000);

        errdefer {
            packet_incoming_channel.deinit();
            packet_outgoing_channel.deinit();
            verified_incoming_channel.deinit();
        }

        var thread_pool = try allocator.create(ThreadPool);
        var n_threads = @min(@as(u32, @truncate(std.Thread.getCpuCount() catch 1)), 8);
        thread_pool.* = ThreadPool.init(.{
            .max_threads = n_threads,
            .stack_size = 2 * 1024 * 1024,
        });
        logger.debugf("using n_threads in gossip: {}", .{n_threads});

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
        var push_msg_q = ArrayList(CrdsValue).init(allocator);

        var echo_server = echo.Server.init(allocator, my_contact_info.gossip.port(), logger, exit);

        var entrypointList = ArrayList(Entrypoint).init(allocator);
        if (entrypoints) |eps| {
            for (eps.items) |ep| try entrypointList.append(.{ .addr = ep });
        }

        return Self{
            .my_contact_info = my_contact_info,
            .my_keypair = my_keypair,
            .my_pubkey = my_pubkey,
            .my_shred_version = std.atomic.Atomic(u16).init(my_shred_version),
            .gossip_socket = gossip_socket,
            .exit = exit,
            .packet_incoming_channel = packet_incoming_channel,
            .packet_outgoing_channel = packet_outgoing_channel,
            .verified_incoming_channel = verified_incoming_channel,
            .crds_table_rw = crds_table_rw,
            .allocator = allocator,
            .push_msg_queue_mux = Mux(ArrayList(CrdsValue)).init(push_msg_q),
            .active_set_rw = RwMux(ActiveSet).init(active_set),
            .failed_pull_hashes_mux = Mux(HashTimeQueue).init(failed_pull_hashes),
            .entrypoints = entrypointList,
            .ping_cache_rw = RwMux(PingCache).init(
                try PingCache.init(
                    allocator,
                    GOSSIP_PING_CACHE_TTL_NS,
                    GOSSIP_PING_CACHE_RATE_LIMIT_DELAY_NS,
                    GOSSIP_PING_CACHE_CAPACITY,
                ),
            ),
            .echo_server = echo_server,
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
        self.echo_server.deinit();
        self.gossip_socket.close();

        {
            var buff_lock = self.packet_incoming_channel.buffer.lock();
            var buff: *std.ArrayList(PacketBatch) = buff_lock.mut();
            for (buff.items) |*item| item.deinit();
            buff_lock.unlock();
            self.packet_incoming_channel.deinit();
        }
        self.verified_incoming_channel.deinit();
        {
            var buff_lock = self.packet_outgoing_channel.buffer.lock();
            var buff: *std.ArrayList(PacketBatch) = buff_lock.mut();
            for (buff.items) |*item| item.deinit();
            buff_lock.unlock();
            self.packet_outgoing_channel.deinit();
        }

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
    ///     4) build message loop (to send outgoing message) (only active if not a spy node)
    ///     5) a socket responder (to send outgoing packets)
    ///     6) echo server
    pub fn run(self: *Self, spy_node: bool) !void {
        var ip_echo_server_listener_handle = try Thread.spawn(.{}, echo.Server.listenAndServe, .{&self.echo_server});
        defer self.joinAndExit(&ip_echo_server_listener_handle);

        var receiver_handle = try Thread.spawn(.{}, socket_utils.readSocket, .{
            self.allocator,
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

        var maybe_build_messages_handle = if (!spy_node) try Thread.spawn(.{}, Self.buildMessages, .{self}) else null;
        defer {
            if (maybe_build_messages_handle) |*handle| {
                self.joinAndExit(handle);
            }
        }

        var responder_handle = try Thread.spawn(.{}, socket_utils.sendSocket, .{
            &self.gossip_socket,
            self.packet_outgoing_channel,
            self.exit,
            self.logger,
        });
        defer self.joinAndExit(&responder_handle);

        { // periodically print crds content summary to stdout
            const base58 = @import("base58-zig");
            const base58Encoder = base58.Encoder.init(.{});
            const start_time = std.time.timestamp();
            while (true) {
                var file = try std.fs.cwd().createFile("crds-dump.csv", .{});
                defer file.close();
                const writer = file.writer();
                var crds_table_lock = self.crds_table_rw.read();
                defer crds_table_lock.unlock();
                const crds_table: *const CrdsTable = crds_table_lock.get();
                var encoder_buf: [44]u8 = undefined;
                for (crds_table.store.values()) |crds_versioned_value| {
                    const val: CrdsValue = crds_versioned_value.value;
                    var size = base58Encoder.encode(
                        &crds_versioned_value.value_hash.data,
                        &encoder_buf,
                    ) catch unreachable;
                    try writer.print("{s},{s},{s},{}\n", .{
                        crds_variant_name(&val),
                        val.id().string(),
                        encoder_buf[0..size],
                        val.wallclock(),
                    });
                }
                const time = std.time.timestamp() - start_time;
                self.logger.errf("{} - CRDS LEN: {}", .{ time, crds_table.store.count() });
                std.time.sleep(10_000_000_000);
            }
        }
    }

    fn createFileWith(path: []const u8, data: []const u8) void {
        var file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        _ = try file.write(data);
    }

    fn sortSlices(slices: anytype) void {
        const InnerSlice = @typeInfo(@TypeOf(slices)).Pointer.child;
        const InnerType = @typeInfo(InnerSlice).Pointer.child;
        std.mem.sort(InnerSlice, slices, {}, struct {
            fn cmp(_: void, lhs: InnerSlice, rhs: InnerSlice) bool {
                return std.mem.lessThan(InnerType, lhs, rhs);
            }
        }.cmp);
    }

    const VerifyMessageTask = struct {
        packet: *const Packet,
        allocator: std.mem.Allocator,
        verified_incoming_channel: *Channel(ProtocolMessage),
        logger: Logger,

        task: Task,
        done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),

        pub fn callback(task: *Task) void {
            var self = @fieldParentPtr(@This(), "task", task);
            std.debug.assert(!self.done.load(std.atomic.Ordering.Acquire));
            defer self.done.store(true, std.atomic.Ordering.Release);

            var protocol_message = bincode.readFromSlice(
                self.allocator,
                Protocol,
                self.packet.data[0..self.packet.size],
                bincode.Params.standard,
            ) catch {
                self.logger.errf("gossip: packet_verify: failed to deserialize", .{});
                return;
            };

            protocol_message.sanitize() catch {
                self.logger.errf("gossip: packet_verify: failed to sanitize", .{});
                bincode.free(self.allocator, protocol_message);
                return;
            };

            protocol_message.verifySignature() catch |e| {
                self.logger.errf(
                    "gossip: packet_verify: failed to verify signature: {} from {}",
                    .{ e, self.packet.addr },
                );
                bincode.free(self.allocator, protocol_message);
                return;
            };

            const msg = ProtocolMessage{
                .from_endpoint = self.packet.addr,
                .message = protocol_message,
            };
            self.verified_incoming_channel.send(msg) catch unreachable;
        }

        /// waits for the task to be done, then resets the done state to false
        fn awaitAndReset(self: *VerifyMessageTask) void {
            while (!self.done.load(std.atomic.Ordering.Acquire)) {
                // wait
            }
            self.done.store(false, std.atomic.Ordering.Release);
        }
    };

    /// main logic for deserializing Packets into Protocol messages
    /// and verifing they have valid values, and have valid signatures.
    /// Verified Protocol messages are then sent to the verified_channel.
    fn verifyPackets(self: *Self) !void {
        var tasks = try self.allocator.alloc(VerifyMessageTask, socket_utils.PACKETS_PER_BATCH);
        defer self.allocator.free(tasks);

        // pre-allocate all the tasks
        for (tasks) |*task| {
            task.* = VerifyMessageTask{
                .task = .{ .callback = VerifyMessageTask.callback },
                .allocator = self.allocator,
                .verified_incoming_channel = self.verified_incoming_channel,
                .packet = &Packet.default(),
                .logger = self.logger,
            };
        }

        while (!self.exit.load(std.atomic.Ordering.Unordered)) {
            const maybe_packets = try self.packet_incoming_channel.try_drain();
            if (maybe_packets == null) {
                continue;
            }

            const packet_batches = maybe_packets.?;
            defer {
                for (packet_batches) |*packet_batch| {
                    packet_batch.deinit();
                }
                self.packet_incoming_channel.allocator.free(packet_batches);
            }

            // verify in parallel using the threadpool
            var count: usize = 0;
            for (packet_batches) |*packet_batch| {
                for (packet_batch.items) |*packet| {
                    var task = &tasks[count % socket_utils.PACKETS_PER_BATCH];
                    if (count >= socket_utils.PACKETS_PER_BATCH) {
                        task.awaitAndReset();
                    }
                    task.packet = packet;

                    const batch = Batch.from(&task.task);
                    self.thread_pool.schedule(batch);

                    count += 1;
                }
            }

            for (tasks[0..@min(count, socket_utils.PACKETS_PER_BATCH)]) |*task| {
                task.awaitAndReset();
            }
        }

        self.logger.debugf("verify_packets loop closed", .{});
    }

    // structs used in process_messages loop
    pub const PullRequestMessage = struct {
        filter: CrdsFilter,
        value: CrdsValue,
        from_endpoint: EndPoint,
    };

    pub const PongMessage = struct {
        pong: *Pong,
        from_endpoint: *EndPoint,
    };

    pub const PingMessage = struct {
        ping: *Ping,
        from_endpoint: *EndPoint,
    };

    pub const PushMessage = struct {
        crds_values: []CrdsValue,
        from_pubkey: *const Pubkey,
        from_endpoint: *const EndPoint,
    };

    pub const PullResponseMessage = struct {
        crds_values: []CrdsValue,
        from_pubkey: *Pubkey,
    };

    /// main logic for recieving and processing `Protocol` messages.
    pub fn processMessages(self: *Self) !void {
        var timer = std.time.Timer.start() catch unreachable;
        var msg_count: usize = 0;

        // we batch messages bc:
        // 1) less lock contention
        // 2) can use packetbatchs (ie, pre-allocated packets)
        // 3) processing read-heavy messages in parallel (specifically pull-requests)

        const init_capacity = socket_utils.PACKETS_PER_BATCH;
        var push_messages = try ArrayList(PushMessage).initCapacity(self.allocator, init_capacity);
        var pull_requests = try ArrayList(PullRequestMessage).initCapacity(self.allocator, init_capacity);
        var pull_responses = try ArrayList(PullResponseMessage).initCapacity(self.allocator, init_capacity);
        var ping_messages = try ArrayList(PingMessage).initCapacity(self.allocator, init_capacity);
        var pong_messages = try ArrayList(PongMessage).initCapacity(self.allocator, init_capacity);
        var prune_messages = try ArrayList(*PruneData).initCapacity(self.allocator, init_capacity);

        defer {
            pull_responses.deinit();
            ping_messages.deinit();
            pong_messages.deinit();
            prune_messages.deinit();
            pull_requests.deinit();
            push_messages.deinit();
        }

        while (!self.exit.load(std.atomic.Ordering.Unordered)) {
            const maybe_protocol_messages = try self.verified_incoming_channel.try_drain();

            if (maybe_protocol_messages == null) {
                continue;
            }

            if (msg_count == 0) {
                timer.reset();
            }

            const protocol_messages = maybe_protocol_messages.?;
            defer {
                for (protocol_messages) |*msg| {
                    bincode.free(self.allocator, msg.message);
                }
                self.verified_incoming_channel.allocator.free(protocol_messages);
            }

            msg_count += protocol_messages.len;

            for (protocol_messages) |*protocol_message| {
                var from_endpoint: EndPoint = protocol_message.from_endpoint;

                switch (protocol_message.message) {
                    .PushMessage => |*push| {
                        try push_messages.append(PushMessage{
                            .crds_values = push[1],
                            .from_pubkey = &push[0],
                            .from_endpoint = &from_endpoint,
                        });
                    },
                    .PullResponse => |*pull| {
                        try pull_responses.append(PullResponseMessage{
                            .from_pubkey = &pull[0],
                            .crds_values = pull[1],
                        });
                    },
                    .PullRequest => |*pull| {
                        const value: CrdsValue = pull[1];
                        switch (value.data) {
                            .LegacyContactInfo => |*data| {
                                if (data.id.equals(&self.my_pubkey)) {
                                    // talking to myself == ignore
                                    continue;
                                }
                                // Allow spy nodes with shred-verion == 0 to pull from other nodes.
                                if (data.shred_version != 0 and data.shred_version != self.my_shred_version.load(.Monotonic)) {
                                    // non-matching shred version
                                    continue;
                                }
                            },
                            // only contact info supported
                            else => continue,
                        }

                        const from_addr = SocketAddr.fromEndpoint(&from_endpoint);
                        if (from_addr.isUnspecified() or from_addr.port() == 0) {
                            // unable to respond to these messages
                            continue;
                        }

                        try pull_requests.append(.{
                            .filter = pull[0],
                            .value = value,
                            .from_endpoint = from_endpoint,
                        });
                    },
                    .PruneMessage => |*prune| {
                        var prune_data = &prune[1];
                        const now = getWallclockMs();
                        const prune_wallclock = prune_data.wallclock;

                        const too_old = prune_wallclock < now -| CRDS_GOSSIP_PRUNE_MSG_TIMEOUT_MS;
                        const incorrect_destination = !prune_data.destination.equals(&self.my_pubkey);
                        if (too_old or incorrect_destination) {
                            continue;
                        }
                        try prune_messages.append(prune_data);
                    },
                    .PingMessage => |*ping| {
                        const from_addr = SocketAddr.fromEndpoint(&from_endpoint);
                        if (from_addr.isUnspecified() or from_addr.port() == 0) {
                            // unable to respond to these messages
                            continue;
                        }

                        try ping_messages.append(PingMessage{
                            .ping = ping,
                            .from_endpoint = &from_endpoint,
                        });
                    },
                    .PongMessage => |*pong| {
                        try pong_messages.append(PongMessage{
                            .pong = pong,
                            .from_endpoint = &from_endpoint,
                        });
                    },
                }
            }

            // handle batch messages
            if (push_messages.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                const length = push_messages.items.len;
                self.handleBatchPushMessages(&push_messages) catch |err| {
                    self.logger.errf("handleBatchPushMessages failed: {}", .{err});
                };
                const elapsed = x_timer.read();
                self.logger.debugf("handle batch push took {} with {} items @{}", .{ elapsed, length, msg_count });
                push_messages.clearRetainingCapacity();
            }

            if (prune_messages.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                const length = prune_messages.items.len;
                self.handleBatchPruneMessages(&prune_messages);
                const elapsed = x_timer.read();
                self.logger.debugf("handle batch prune took {} with {} items @{}", .{ elapsed, length, msg_count });
                prune_messages.clearRetainingCapacity();
            }

            if (pull_requests.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                const length = pull_requests.items.len;
                self.handleBatchPullRequest(pull_requests) catch |err| {
                    self.logger.errf("handleBatchPullRequest failed: {}", .{err});
                };
                const elapsed = x_timer.read();
                self.logger.debugf("handle batch pull_req took {} with {} items @{}", .{ elapsed, length, msg_count });
                pull_requests.clearRetainingCapacity();
            }

            if (pull_responses.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                const length = pull_responses.items.len;
                self.handleBatchPullResponses(&pull_responses) catch |err| {
                    self.logger.errf("handleBatchPullResponses failed: {}", .{err});
                };
                const elapsed = x_timer.read();
                self.logger.debugf("handle batch pull_resp took {} with {} items @{}", .{ elapsed, length, msg_count });
                pull_responses.clearRetainingCapacity();
            }

            if (ping_messages.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                const n_ping_messages = ping_messages.items.len;
                self.handleBatchPingMessages(&ping_messages) catch |err| {
                    self.logger.errf("handleBatchPingMessages failed: {}", .{err});
                };
                self.logger.debugf("handle batch ping took {} with {} items @{}", .{ x_timer.read(), n_ping_messages, msg_count });
                ping_messages.clearRetainingCapacity();
            }

            if (pong_messages.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                const n_pong_messages = pong_messages.items.len;
                self.handleBatchPongMessages(&pong_messages);
                self.logger.debugf("handle batch pong took {} with {} items @{}", .{ x_timer.read(), n_pong_messages, msg_count });
                pong_messages.clearRetainingCapacity();
            }

            // TRIM crds-table
            {
                var crds_table_lock = self.crds_table_rw.write();
                defer crds_table_lock.unlock();
                var crds_table: *CrdsTable = crds_table_lock.mut();

                var x_timer = std.time.Timer.start() catch unreachable;
                crds_table.attemptTrim(CRDS_UNIQUE_PUBKEY_CAPACITY) catch |err| {
                    self.logger.warnf("error trimming crds table: {s}", .{@errorName(err)});
                };
                const elapsed = x_timer.read();
                self.logger.debugf("handle batch crds_trim took {} with {} items @{}", .{ elapsed, 1, msg_count });
            }

            const elapsed = timer.read();
            self.logger.debugf("{} messages processed in {}ns", .{ msg_count, elapsed });
            // std.debug.print("{} messages processed in {}ns\n", .{ msg_count, elapsed });
            self.messages_processed.store(msg_count, std.atomic.Ordering.Release);
        }

        self.logger.debugf("process_messages loop closed", .{});
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
        var entrypoints_identified = false;
        var shred_version_assigned = false;

        while (!self.exit.load(std.atomic.Ordering.Unordered)) {
            const top_of_loop_ts = getWallclockMs();

            if (should_send_pull_requests) pull_blk: {
                // this also includes sending ping messages to other peers
                var packets = self.buildPullRequests(
                    pull_request.MAX_BLOOM_SIZE,
                ) catch |e| {
                    self.logger.errf("failed to generate pull requests: {any}", .{e});
                    break :pull_blk;
                };
                try self.packet_outgoing_channel.send(packets);
            }
            // every other loop
            should_send_pull_requests = !should_send_pull_requests;

            // new push msgs
            self.drainPushQueueToCrdsTable(getWallclockMs());
            var maybe_push_packets = self.buildPushMessages(&push_cursor) catch |e| blk: {
                self.logger.errf("failed to generate push messages: {any}", .{e});
                break :blk null;
            };
            if (maybe_push_packets) |push_packets| {
                try self.packet_outgoing_channel.sendBatch(push_packets);
                push_packets.deinit();
            }

            // trim data
            self.logger.errf("trimming...", .{});
            self.trimMemory(getWallclockMs()) catch @panic("out of memory");
            self.logger.errf("...trimmed", .{});

            // initialize cluster data from crds values
            entrypoints_identified = entrypoints_identified or self.identifyEntrypoints();
            shred_version_assigned = shred_version_assigned or self.assignDefaultShredVersionFromEntrypoint();

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
                    var push_msg_queue: *ArrayList(CrdsValue) = push_msg_queue_lock.mut();

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
        var buf: [NUM_ACTIVE_SET_ENTRIES]LegacyContactInfo = undefined;
        var gossip_peers = self.getGossipNodes(&buf, NUM_ACTIVE_SET_ENTRIES, now);

        // filter out peers who have responded to pings
        var ping_cache_result = blk: {
            var ping_cache_lock = self.ping_cache_rw.write();
            defer ping_cache_lock.unlock();
            var ping_cache: *PingCache = ping_cache_lock.mut();

            var result = try ping_cache.filterValidPeers(self.allocator, self.my_keypair, gossip_peers);
            break :blk result;
        };
        var valid_gossip_indexs = ping_cache_result.valid_peers;
        defer valid_gossip_indexs.deinit();

        var valid_gossip_peers: [NUM_ACTIVE_SET_ENTRIES]LegacyContactInfo = undefined;
        for (0.., valid_gossip_indexs.items) |i, valid_gossip_index| {
            valid_gossip_peers[i] = gossip_peers[valid_gossip_index];
        }

        // send pings to peers
        var pings_to_send_out = ping_cache_result.pings;
        defer pings_to_send_out.deinit();
        try self.sendPings(pings_to_send_out);

        // reset push active set
        var active_set_lock = self.active_set_rw.write();
        defer active_set_lock.unlock();
        var active_set: *ActiveSet = active_set_lock.mut();
        try active_set.rotate(valid_gossip_peers[0..valid_gossip_indexs.items.len]);
    }

    /// logic for building new push messages which are sent to peers from the
    /// active set and serialized into packets.
    fn buildPushMessages(self: *Self, push_cursor: *u64) !ArrayList(ArrayList(Packet)) {
        // TODO: find a better static value?
        var buf: [512]crds.CrdsVersionedValue = undefined;

        var crds_entries = blk: {
            var crds_table_lock = self.crds_table_rw.read();
            defer crds_table_lock.unlock();

            const crds_table: *const CrdsTable = crds_table_lock.get();
            break :blk crds_table.getEntriesWithCursor(&buf, push_cursor);
        };

        var packet_batch = ArrayList(ArrayList(Packet)).init(self.allocator);
        errdefer packet_batch.deinit();

        if (crds_entries.len == 0) {
            return packet_batch;
        }

        const now = getWallclockMs();
        var total_byte_size: usize = 0;

        // find new values in crds table
        // TODO: benchmark different approach of HashMapping(origin, value) first
        // then deriving the active set per origin in a batch
        var push_messages = std.AutoHashMap(EndPoint, ArrayList(CrdsValue)).init(self.allocator);
        defer {
            var push_iter = push_messages.iterator();
            while (push_iter.next()) |push_entry| {
                push_entry.value_ptr.deinit();
            }
            push_messages.deinit();
        }

        var num_values_considered: usize = 0;
        {
            var active_set_lock = self.active_set_rw.read();
            var active_set: *const ActiveSet = active_set_lock.get();
            defer active_set_lock.unlock();

            if (active_set.len() == 0) return packet_batch;

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
                        var peer_entry = try ArrayList(CrdsValue).initCapacity(self.allocator, 1);
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

        var push_iter = push_messages.iterator();
        while (push_iter.next()) |push_entry| {
            const crds_values: *const ArrayList(CrdsValue) = push_entry.value_ptr;
            const to_endpoint: *const EndPoint = push_entry.key_ptr;

            // send the values as a pull response
            var packets = try crdsValuesToPackets(
                self.allocator,
                &self.my_pubkey,
                crds_values.items,
                to_endpoint,
                ChunkType.PushMessage,
            );
            if (packets.items.len > 0) {
                try packet_batch.append(packets);
            }
        }
        return packet_batch;
    }

    /// builds new pull request messages and serializes it into a list of Packets
    /// to be sent to a random set of gossip nodes.
    fn buildPullRequests(
        self: *Self,
        /// the bloomsize of the pull request's filters
        bloom_size: usize,
    ) !ArrayList(Packet) {
        // get nodes from crds table
        var buf: [MAX_NUM_PULL_REQUESTS]LegacyContactInfo = undefined;
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
            var maybe_entrypoint_index = rng.random().intRangeAtMost(usize, 0, self.entrypoints.items.len - 1);
            if (self.entrypoints.items[maybe_entrypoint_index].info) |_| {
                // early exit - we already have the peer in our contact info
                break :blk;
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
        var valid_gossip_peer_indexs = ping_cache_result.valid_peers;
        defer valid_gossip_peer_indexs.deinit();

        // send pings to peers
        var pings_to_send_out = ping_cache_result.pings;
        defer pings_to_send_out.deinit();
        try self.sendPings(pings_to_send_out);

        const should_send_to_entrypoint = entrypoint_index != -1;
        const num_peers = valid_gossip_peer_indexs.items.len;

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
        var n_packets: usize = 0;
        if (num_peers != 0) n_packets += filters.items.len;
        if (should_send_to_entrypoint) n_packets += filters.items.len;

        var packet_batch = try ArrayList(Packet).initCapacity(self.allocator, n_packets);
        packet_batch.appendNTimesAssumeCapacity(Packet.default(), n_packets);
        var packet_index: usize = 0;

        // update wallclock and sign
        self.my_contact_info.wallclock = now;
        const my_contact_info_value = try crds.CrdsValue.initSigned(crds.CrdsData{
            .LegacyContactInfo = self.my_contact_info,
        }, &self.my_keypair);

        if (num_peers != 0) {
            for (filters.items) |filter_i| {
                // TODO: incorperate stake weight in random sampling
                const peer_index = rng.random().intRangeAtMost(usize, 0, num_peers - 1);
                const peer_contact_info_index = valid_gossip_peer_indexs.items[peer_index];
                const peer_contact_info = peers[peer_contact_info_index];
                const peer_addr = peer_contact_info.gossip.toEndpoint();

                const protocol_msg = Protocol{ .PullRequest = .{ filter_i, my_contact_info_value } };

                var packet = &packet_batch.items[packet_index];
                var bytes = try bincode.writeToSlice(&packet.data, protocol_msg, bincode.Params{});
                packet.size = bytes.len;
                packet.addr = peer_addr;
                packet_index += 1;
            }
        }

        // append entrypoint msgs
        if (should_send_to_entrypoint) {
            const entrypoint = self.entrypoints.items[@as(usize, @intCast(entrypoint_index))];
            for (filters.items) |filter| {
                const protocol_msg = Protocol{ .PullRequest = .{ filter, my_contact_info_value } };

                var packet = &packet_batch.items[packet_index];
                var bytes = try bincode.writeToSlice(&packet.data, protocol_msg, bincode.Params{});
                packet.size = bytes.len;
                packet.addr = entrypoint.addr.toEndpoint();
                packet_index += 1;
            }
        }

        return packet_batch;
    }

    const PullRequestTask = struct {
        allocator: std.mem.Allocator,
        my_pubkey: *const Pubkey,
        from_endpoint: *const EndPoint,
        filter: *CrdsFilter,
        value: *CrdsValue,
        crds_table: *const CrdsTable,
        output: ArrayList(Packet),
        output_limit: *std.atomic.Atomic(i64),

        task: Task,
        done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),

        pub fn deinit(this: *PullRequestTask) void {
            this.output.deinit();
        }

        pub fn callback(task: *Task) void {
            var self = @fieldParentPtr(@This(), "task", task);
            defer self.done.store(true, std.atomic.Ordering.Release);

            const output_limit = self.output_limit.load(std.atomic.Ordering.Unordered);
            if (output_limit <= 0) {
                return;
            }

            const response_crds_values = pull_response.filterCrdsValues(
                self.allocator,
                self.crds_table,
                self.filter,
                crds.getWallclockMs(),
                @as(usize, @max(output_limit, 0)),
            ) catch {
                // std.debug.print("filterCrdsValues failed\n", .{});
                return;
            };
            defer response_crds_values.deinit();

            _ = self.output_limit.fetchSub(
                @as(i64, @intCast(response_crds_values.items.len)),
                std.atomic.Ordering.Release,
            );

            const packets = crdsValuesToPackets(
                self.allocator,
                self.my_pubkey,
                response_crds_values.items,
                self.from_endpoint,
                ChunkType.PullResponse,
            ) catch return;

            if (packets.items.len > 0) {
                defer packets.deinit();
                self.output.appendSlice(packets.items) catch {
                    std.debug.panic("thread task: failed to append packets", .{});
                };
            }
        }
    };

    fn handleBatchPullRequest(
        self: *Self,
        pull_requests: ArrayList(PullRequestMessage),
    ) !void {
        // update the callers
        // TODO: parallelize this?
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

        var valid_indexs = blk: {
            var ping_cache_lock = self.ping_cache_rw.write();
            defer ping_cache_lock.unlock();
            var ping_cache: *PingCache = ping_cache_lock.mut();

            var peers = try ArrayList(LegacyContactInfo).initCapacity(self.allocator, pull_requests.items.len);
            defer peers.deinit();
            for (pull_requests.items) |req| {
                peers.appendAssumeCapacity(req.value.data.LegacyContactInfo);
            }

            const result = try ping_cache.filterValidPeers(self.allocator, self.my_keypair, peers.items);
            defer result.pings.deinit();
            try self.sendPings(result.pings);

            break :blk result.valid_peers;
        };
        defer valid_indexs.deinit();

        if (valid_indexs.items.len == 0) {
            return;
        }

        // create the pull requests
        const n_valid_requests = valid_indexs.items.len;

        var tasks = try self.allocator.alloc(PullRequestTask, n_valid_requests);
        defer {
            for (tasks) |*task| task.deinit();
            self.allocator.free(tasks);
        }

        {
            var crds_table_lock = self.crds_table_rw.read();
            const crds_table: *const CrdsTable = crds_table_lock.get();
            defer crds_table_lock.unlock();

            var output_limit = std.atomic.Atomic(i64).init(MAX_NUM_CRDS_VALUES_PULL_RESPONSE);

            for (valid_indexs.items, 0..) |i, task_index| {
                // create the thread task
                tasks[task_index] = PullRequestTask{
                    .task = .{ .callback = PullRequestTask.callback },
                    .my_pubkey = &self.my_pubkey,
                    .from_endpoint = &pull_requests.items[i].from_endpoint,
                    .filter = &pull_requests.items[i].filter,
                    .value = &pull_requests.items[i].value,
                    .crds_table = crds_table,
                    .output = ArrayList(Packet).init(self.allocator),
                    .allocator = self.allocator,
                    .output_limit = &output_limit,
                };

                // run it
                const batch = Batch.from(&tasks[task_index].task);
                self.thread_pool.schedule(batch);
            }

            // wait for them to be done to release the lock
            for (tasks) |*task| {
                while (!task.done.load(std.atomic.Ordering.Acquire)) {
                    // wait
                }
            }
        }

        for (tasks) |*task| {
            if (task.output.items.len > 0) {
                // TODO: should only need one mux lock in this loop
                try self.packet_outgoing_channel.send(task.output);
            }
        }
    }

    pub fn handleBatchPongMessages(
        self: *Self,
        pong_messages: *const ArrayList(PongMessage),
    ) void {
        const now = std.time.Instant.now() catch @panic("time is not supported on the OS!");

        var ping_cache_lock = self.ping_cache_rw.write();
        defer ping_cache_lock.unlock();
        var ping_cache: *PingCache = ping_cache_lock.mut();

        for (pong_messages.items) |*pong_message| {
            _ = ping_cache.receviedPong(
                pong_message.pong,
                SocketAddr.fromEndpoint(pong_message.from_endpoint),
                now,
            );
        }
    }

    pub fn handleBatchPingMessages(
        self: *Self,
        ping_messages: *const ArrayList(PingMessage),
    ) !void {
        const n_ping_messages = ping_messages.items.len;

        // init a new batch of pong responses
        var ping_packet_batch = try ArrayList(Packet).initCapacity(self.allocator, n_ping_messages);
        ping_packet_batch.appendNTimesAssumeCapacity(Packet.default(), n_ping_messages);
        errdefer ping_packet_batch.deinit();

        for (ping_messages.items, 0..) |*ping_message, i| {
            const pong = try Pong.init(ping_message.ping, &self.my_keypair);
            const pong_message = Protocol{ .PongMessage = pong };

            var packet = &ping_packet_batch.items[i];
            const bytes_written = try bincode.writeToSlice(
                &packet.data,
                pong_message,
                bincode.Params.standard,
            );

            packet.size = bytes_written.len;
            packet.addr = ping_message.from_endpoint.*;

            const endpoint_str = try endpointToString(self.allocator, ping_message.from_endpoint);
            defer endpoint_str.deinit();
            self.logger
                .field("from_endpoint", endpoint_str.items)
                .field("from_pubkey", &ping_message.ping.from.string())
                .info("gossip: recv ping");
        }
        try self.packet_outgoing_channel.send(ping_packet_batch);
    }

    /// logic for handling a pull response message.
    /// successful inserted values, have their origin value timestamps updated.
    /// failed inserts (ie, too old or duplicate values) are added to the failed pull hashes so that they can be
    /// included in the next pull request (so we dont receive them again).
    pub fn handleBatchPullResponses(
        self: *Self,
        pull_response_messages: *const ArrayList(PullResponseMessage),
    ) !void {
        if (pull_response_messages.items.len == 0) {
            return;
        }

        const now = getWallclockMs();
        var failed_insert_ptrs = ArrayList(*CrdsValue).init(self.allocator);
        defer failed_insert_ptrs.deinit();

        {
            var crds_table_lock = self.crds_table_rw.write();
            var crds_table: *CrdsTable = crds_table_lock.mut();
            defer crds_table_lock.unlock();

            for (pull_response_messages.items) |*pull_message| {
                const valid_len = self.filterCrdsValuesBasedOnShredVersion(
                    crds_table,
                    pull_message.crds_values,
                    pull_message.from_pubkey.*,
                );

                const insert_results = try crds_table.insertValues(
                    pull_message.crds_values[0..valid_len],
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
                        pull_message.crds_values[index],
                        now,
                    ) catch {};
                }

                // update the contactInfo timestamps of the successful inserts
                // (and all other origin values)
                const successful_insert_indexs = insert_results.inserted.?;
                defer successful_insert_indexs.deinit();
                for (successful_insert_indexs.items) |index| {
                    const origin = pull_message.crds_values[index].id();
                    crds_table.updateRecordTimestamp(origin, now);
                }
                crds_table.updateRecordTimestamp(pull_message.from_pubkey.*, now);

                var failed_insert_indexs = insert_results.failed.?;
                defer failed_insert_indexs.deinit();
                for (failed_insert_indexs.items) |index| {
                    try failed_insert_ptrs.append(&pull_message.crds_values[index]);
                }
            }
        }

        {
            var failed_pull_hashes_lock = self.failed_pull_hashes_mux.lock();
            var failed_pull_hashes: *HashTimeQueue = failed_pull_hashes_lock.mut();
            defer failed_pull_hashes_lock.unlock();

            var buf: [PACKET_DATA_SIZE]u8 = undefined;
            for (failed_insert_ptrs.items) |crds_value_ptr| {
                var bytes = bincode.writeToSlice(&buf, crds_value_ptr.*, bincode.Params.standard) catch {
                    continue;
                };
                const value_hash = Hash.generateSha256Hash(bytes);
                try failed_pull_hashes.insert(value_hash, now);
            }
        }
    }

    /// logic for handling a prune message. verifies the prune message
    /// is not too old, and that the destination pubkey is the local node,
    /// then updates the active set to prune the list of origin Pubkeys.
    pub fn handleBatchPruneMessages(
        self: *Self,
        prune_messages: *const ArrayList(*PruneData),
    ) void {
        var active_set_lock = self.active_set_rw.write();
        defer active_set_lock.unlock();
        var active_set: *ActiveSet = active_set_lock.mut();

        for (prune_messages.items) |prune_data| {
            // update active set
            const from_pubkey = prune_data.pubkey;
            for (prune_data.prunes) |origin| {
                if (origin.equals(&self.my_pubkey)) {
                    continue;
                }
                active_set.prune(from_pubkey, origin);
            }
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
    ) error{ CantFindContactInfo, InvalidGossipAddress, OutOfMemory, SignatureError }!ArrayList(Packet) {
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
        var prune_packets = try ArrayList(Packet).initCapacity(self.allocator, n_packets);
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

    pub fn handleBatchPushMessages(
        self: *Self,
        batch_push_messages: *const ArrayList(PushMessage),
    ) !void {
        if (batch_push_messages.items.len == 0) {
            return;
        }

        var pubkey_to_failed_origins = std.AutoArrayHashMap(
            Pubkey,
            AutoArrayHashSet(Pubkey),
        ).init(self.allocator);

        var pubkey_to_endpoint = std.AutoArrayHashMap(
            Pubkey,
            EndPoint,
        ).init(self.allocator);

        defer {
            // TODO: figure out a way to re-use these allocs
            pubkey_to_failed_origins.deinit();
            pubkey_to_endpoint.deinit();
        }

        // insert values and track the failed origins per pubkey
        {
            var crds_table_lock = self.crds_table_rw.write();
            defer crds_table_lock.unlock();

            for (batch_push_messages.items) |*push_message| {
                var crds_table: *CrdsTable = crds_table_lock.mut();
                const valid_len = self.filterCrdsValuesBasedOnShredVersion(
                    crds_table,
                    push_message.crds_values,
                    push_message.from_pubkey.*,
                );

                var result = try crds_table.insertValues(
                    push_message.crds_values[0..valid_len],
                    CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS,
                    false,
                    false,
                );
                const failed_insert_indexs = result.failed.?;
                defer failed_insert_indexs.deinit();

                self.logger
                    .field("n_values", valid_len)
                    .field("from_addr", &push_message.from_pubkey.string())
                    .field("n_failed_inserts", failed_insert_indexs.items.len)
                    .info("gossip: recv push_message");

                if (failed_insert_indexs.items.len == 0) {
                    // dont need to build prune messages
                    continue;
                }

                // lookup contact info
                const from_contact_info = crds_table.get(crds.CrdsValueLabel{ .LegacyContactInfo = push_message.from_pubkey.* }) orelse {
                    // unable to find contact info
                    continue;
                };
                const from_gossip_addr = from_contact_info.value.data.LegacyContactInfo.gossip;
                crds.sanitizeSocket(&from_gossip_addr) catch {
                    // invalid gossip socket
                    continue;
                };

                // track the endpoint
                const from_gossip_endpoint = from_gossip_addr.toEndpoint();
                try pubkey_to_endpoint.put(push_message.from_pubkey.*, from_gossip_endpoint);

                // track failed origins
                var failed_origins = blk: {
                    var lookup_result = try pubkey_to_failed_origins.getOrPut(push_message.from_pubkey.*);
                    if (!lookup_result.found_existing) {
                        lookup_result.value_ptr.* = AutoArrayHashSet(Pubkey).init(self.allocator);
                    }
                    break :blk lookup_result.value_ptr;
                };
                for (failed_insert_indexs.items) |failed_index| {
                    const origin = push_message.crds_values[failed_index].id();
                    try failed_origins.put(origin, {});
                }
            }
        }

        // build prune packets
        const now = getWallclockMs();
        var pubkey_to_failed_origins_iter = pubkey_to_failed_origins.iterator();

        var n_packets = pubkey_to_failed_origins_iter.len;
        if (n_packets == 0) return;

        var prune_packet_batch = try ArrayList(Packet).initCapacity(self.allocator, n_packets);
        prune_packet_batch.appendNTimesAssumeCapacity(Packet.default(), n_packets);
        var count: usize = 0;

        while (pubkey_to_failed_origins_iter.next()) |failed_origin_entry| {
            const from_pubkey = failed_origin_entry.key_ptr.*;
            const failed_origins_hashset = failed_origin_entry.value_ptr;
            defer failed_origins_hashset.deinit();
            const from_endpoint = pubkey_to_endpoint.get(from_pubkey).?;

            const failed_origins: []Pubkey = failed_origins_hashset.keys();
            const prune_size = @min(failed_origins.len, MAX_PRUNE_DATA_NODES);

            var prune_data = PruneData.init(
                self.my_pubkey,
                failed_origins[0..prune_size],
                from_pubkey,
                now,
            );
            prune_data.sign(&self.my_keypair) catch return error.SignatureError;
            var protocol = Protocol{ .PruneMessage = .{ self.my_pubkey, prune_data } };

            self.logger
                .field("n_pruned_origins", prune_size)
                .field("to_addr", &from_pubkey.string())
                .info("gossip: send prune_message");

            var packet = &prune_packet_batch.items[count];
            var written_slice = bincode.writeToSlice(&packet.data, protocol, bincode.Params{}) catch unreachable;
            packet.size = written_slice.len;
            packet.addr = from_endpoint;
            count += 1;
        }

        try self.packet_outgoing_channel.send(prune_packet_batch);
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

            // TODO: condition timeout on stake weight:
            // - values from nodes with non-zero stake: epoch duration
            // - values from nodes with zero stake:
            //   - if all nodes have zero stake: epoch duration
            //   - if any other nodes have non-zero stake: CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS (15s)
            try crds_table.removeOldLabels(now, DEFAULT_EPOCH_DURATION);
        }

        const failed_insert_cutoff_timestamp = now -| FAILED_INSERTS_RETENTION_MS;
        {
            var failed_pull_hashes_lock = self.failed_pull_hashes_mux.lock();
            defer failed_pull_hashes_lock.unlock();
            var failed_pull_hashes: *HashTimeQueue = failed_pull_hashes_lock.mut();

            try failed_pull_hashes.trim(failed_insert_cutoff_timestamp);
        }
    }

    /// Attempts to associate each entrypoint address with a contact info.
    /// Returns true if all entrypoints have been identified
    fn identifyEntrypoints(self: *Self) bool {
        var identified_all = true;
        for (self.entrypoints.items) |*entrypoint| {
            if (entrypoint.info == null) {
                var reader = self.crds_table_rw.read();
                defer reader.unlock();
                entrypoint.info = reader.get().getContactInfoByGossipAddr(entrypoint.addr);
            }
            identified_all = identified_all and entrypoint.info == null;
        }
        return identified_all;
    }

    /// if we have no shred version, attempt to get one from an entrypoint.
    /// Returns true if the shred version is set to non-zero
    fn assignDefaultShredVersionFromEntrypoint(self: *Self) bool {
        if (self.my_shred_version.load(.Monotonic) != 0) return true;
        for (self.entrypoints.items) |entrypoint| {
            if (entrypoint.info) |info| {
                if (info.shred_version != 0) {
                    self.my_shred_version.store(info.shred_version, .Monotonic);
                    self.my_contact_info.shred_version = info.shred_version;
                    return true;
                }
            }
        }
        return false;
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
        var push_msg_queue: *ArrayList(CrdsValue) = push_msg_queue_lock.mut();

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
        pings: ArrayList(PingAndSocketAddr),
    ) error{ OutOfMemory, ChannelClosed, SerializationError }!void {
        const n_pings = pings.items.len;
        if (n_pings == 0) return;

        var packet_batch = try ArrayList(Packet).initCapacity(self.allocator, n_pings);
        errdefer packet_batch.deinit();
        packet_batch.appendNTimesAssumeCapacity(Packet.default(), n_pings);

        for (pings.items, 0..) |ping_and_addr, i| {
            const protocol_msg = Protocol{ .PingMessage = ping_and_addr.ping };

            var packet = &packet_batch.items[i];
            var serialized_ping = bincode.writeToSlice(&packet.data, protocol_msg, .{}) catch return error.SerializationError;
            packet.size = serialized_ping.len;
            packet.addr = ping_and_addr.socket.toEndpoint();
        }
        try self.packet_outgoing_channel.send(packet_batch);
    }

    /// returns a list of valid gossip nodes. this works by reading
    /// the contact infos from the crds table and filtering out
    /// nodes that are 1) too old, 2) have a different shred version, or 3) have
    /// an invalid gossip address.
    pub fn getGossipNodes(
        self: *Self,
        /// the output slice which will be filled with gossip nodes
        nodes: []LegacyContactInfo,
        /// the maximum number of nodes to return ( max_size == nodes.len but comptime for init of stack array)
        comptime MAX_SIZE: usize,
        /// current time (used to filter out nodes that are too old)
        now: u64,
    ) []LegacyContactInfo {
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
            const my_shred_version = self.my_shred_version.load(.Monotonic);
            if (my_shred_version != 0 and my_shred_version != peer_info.shred_version) {
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

    pub fn filterCrdsValuesBasedOnShredVersion(
        self: *Self,
        crds_table: *const CrdsTable,
        crds_values: []CrdsValue,
        from_pubkey: Pubkey,
    ) usize {
        // we use swap remove which just reorders the array
        // (order dm), so we just track the new len -- ie, no allocations/frees
        var crds_values_array = ArrayList(CrdsValue).fromOwnedSlice(self.allocator, crds_values);
        const my_shred_version = self.my_shred_version.load(.Monotonic);
        if (my_shred_version == 0) {
            return crds_values_array.items.len;
        }
        if (crds_table.check_matching_shred_version(from_pubkey, my_shred_version)) {
            for (crds_values, 0..) |*crds_value, i| {
                switch (crds_value.data) {
                    // always allow contact info + node instance to update shred versions
                    .ContactInfo => {},
                    .LegacyContactInfo => {},
                    .NodeInstance => {},
                    else => {
                        // only allow other values with matching shred versions
                        if (!crds_table.check_matching_shred_version(
                            crds_value.id(),
                            my_shred_version,
                        )) {
                            _ = crds_values_array.swapRemove(i);
                        }
                    },
                }
            }
        } else {
            for (crds_values, 0..) |*crds_value, i| {
                switch (crds_value.data) {
                    // always allow contact info + node instance to update shred versions
                    .ContactInfo => {},
                    .LegacyContactInfo => {},
                    .NodeInstance => {},
                    else => {
                        // dont update any other values
                        _ = crds_values_array.swapRemove(i);
                    },
                }
            }
        }
        return crds_values_array.items.len;
    }
};

fn crds_variant_name(val: *const CrdsValue) []const u8 {
    return switch (val.data) {
        .LegacyContactInfo => "LegacyContactInfo",
        .Vote => "Vote",
        .LowestSlot => "LowestSlot",
        .LegacySnapshotHashes => "LegacySnapshotHashes",
        .AccountsHashes => "AccountsHashes",
        .EpochSlots => "EpochSlots",
        .LegacyVersion => "LegacyVersion",
        .Version => "Version",
        .NodeInstance => "NodeInstance",
        .DuplicateShred => "DuplicateShred",
        .SnapshotHashes => "SnapshotHashes",
        .ContactInfo => "ContactInfo",
    };
}

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
) error{ OutOfMemory, SerializationError }!ArrayList(Packet) {
    if (crds_values.len == 0)
        return ArrayList(Packet).init(allocator);

    const indexs = try chunkValuesIntoPacketIndexs(
        allocator,
        crds_values,
        MAX_PUSH_MESSAGE_PAYLOAD_SIZE,
    );
    defer indexs.deinit();
    var chunk_iter = std.mem.window(usize, indexs.items, 2, 1);

    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var packets = try ArrayList(Packet).initCapacity(allocator, indexs.items.len -| 1);
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
) error{ OutOfMemory, SerializationError }!ArrayList(usize) {
    var packet_indexs = try ArrayList(usize).initCapacity(allocator, 1);
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

test "gossip.gossip_service: build messages startup and shutdown" {
    const allocator = std.testing.allocator;
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = LegacyContactInfo.default(my_pubkey);
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

    var build_messages_handle = try Thread.spawn(.{}, GossipService.buildMessages, .{&gossip_service});

    // add some crds values to push
    var rng = std.rand.DefaultPrng.init(91);
    var lg = gossip_service.crds_table_rw.write();
    var ping_lock = gossip_service.ping_cache_rw.write();
    var ping_cache: *PingCache = ping_lock.mut();

    var peers = ArrayList(LegacyContactInfo).init(allocator);
    defer peers.deinit();

    for (0..10) |_| {
        var rand_keypair = try KeyPair.create(null);
        var value = try CrdsValue.randomWithIndex(rng.random(), &rand_keypair, 0); // contact info
        // make gossip valid
        value.data.LegacyContactInfo.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8000);
        try lg.mut().insert(value, getWallclockMs());
        try peers.append(value.data.LegacyContactInfo);
        // set the pong status as OK so they included in active set
        ping_cache._setPong(value.data.LegacyContactInfo.id, value.data.LegacyContactInfo.gossip);
    }
    lg.unlock();
    ping_lock.unlock();

    std.time.sleep(std.time.ns_per_s * 3);

    exit.store(true, std.atomic.Ordering.Unordered);
    build_messages_handle.join();
}

test "gossip.gossip_service: tests handle_prune_messages" {
    var rng = std.rand.DefaultPrng.init(91);

    const allocator = std.testing.allocator;
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = LegacyContactInfo.default(my_pubkey);
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
    var peers = ArrayList(LegacyContactInfo).init(allocator);
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
    try std.testing.expect(as.len() > 0); // FIX
    var iter = as.pruned_peers.keyIterator();
    const peer0 = iter.next().?.*;
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

    var data = std.ArrayList(*PruneData).init(allocator);
    defer data.deinit();

    try data.append(&prune_data);
    gossip_service.handleBatchPruneMessages(&data);

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

    var contact_info = LegacyContactInfo.default(my_pubkey);
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

    var data = ArrayList(GossipService.PullResponseMessage).init(allocator);
    defer data.deinit();

    try data.append(GossipService.PullResponseMessage{
        .crds_values = &crds_values,
        .from_pubkey = &my_pubkey,
    });

    try gossip_service.handleBatchPullResponses(&data);

    // make sure values are inserted
    var crds_table_lock = gossip_service.crds_table_rw.read();
    var crds_table: *const CrdsTable = crds_table_lock.get();
    for (crds_values) |value| {
        _ = crds_table.get(value.label()).?;
    }
    crds_table_lock.unlock();

    // try inserting again with same values (should all fail)
    try gossip_service.handleBatchPullResponses(&data);

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

    var contact_info = LegacyContactInfo.default(my_pubkey);
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

    var rando_keypair = try KeyPair.create([_]u8{22} ** 32);
    var rando_pubkey = Pubkey.fromPublicKey(&rando_keypair.public_key, true);

    var ci_data = crds.CrdsData.randomFromIndex(rng.random(), 0);
    ci_data.LegacyContactInfo.id = rando_pubkey;
    var crds_value = try CrdsValue.initSigned(ci_data, &rando_keypair);

    const addr = SocketAddr.random(rng.random());
    var ping_lock = gossip_service.ping_cache_rw.write();
    var ping_cache: *PingCache = ping_lock.mut();
    ping_cache._setPong(rando_pubkey, addr);
    ping_lock.unlock();

    var filter = CrdsFilter{
        .filter = bloom,
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };

    var pull_requests = ArrayList(GossipService.PullRequestMessage).init(allocator);
    defer pull_requests.deinit();
    try pull_requests.append(GossipService.PullRequestMessage{
        .filter = filter,
        .from_endpoint = contact_info.gossip.toEndpoint(),
        .value = crds_value,
    });

    try gossip_service.handleBatchPullRequest(pull_requests);
    {
        var packet_lg = gossip_service.packet_outgoing_channel.buffer.lock();
        defer packet_lg.unlock();
        var outgoing_packets: *const ArrayList(PacketBatch) = packet_lg.get();
        try std.testing.expect(outgoing_packets.items.len > 0);
    }
}

test "gossip.gossip_service: test build prune messages and handle_push_msgs" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = LegacyContactInfo.default(my_pubkey);
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
    var values = ArrayList(CrdsValue).init(allocator);
    defer values.deinit();
    for (0..10) |_| {
        var value = try CrdsValue.randomWithIndex(rng.random(), &my_keypair, 0);
        value.data.LegacyContactInfo.id = Pubkey.random(rng.random(), .{});
        try values.append(value);
    }

    // insert contact info to send prunes to
    var send_contact_info = LegacyContactInfo.random(rng.random());
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

    var msgs = ArrayList(GossipService.PushMessage).init(allocator);
    defer msgs.deinit();

    var endpoint = gossip_socket.toEndpoint();
    try msgs.append(GossipService.PushMessage{
        .crds_values = values.items,
        .from_endpoint = &endpoint,
        .from_pubkey = &push_from,
    });

    try gossip_service.handleBatchPushMessages(&msgs);
    {
        var packet_lg = gossip_service.packet_outgoing_channel.buffer.lock();
        defer packet_lg.unlock();
        var outgoing_packets: *const ArrayList(PacketBatch) = packet_lg.get();
        // zero prune messages
        try std.testing.expect(outgoing_packets.items.len == 0);
    }

    try gossip_service.handleBatchPushMessages(&msgs);
    var packet = blk: {
        var packet_lg = gossip_service.packet_outgoing_channel.buffer.lock();
        defer packet_lg.unlock();
        var outgoing_packets: *const ArrayList(PacketBatch) = packet_lg.get();
        // > 0 prune messages to account for duplicate push messages
        try std.testing.expect(outgoing_packets.items.len > 0);

        break :blk outgoing_packets.items[0].items[0];
    };
    var protocol_message = try bincode.readFromSlice(
        allocator,
        Protocol,
        packet.data[0..packet.size],
        bincode.Params.standard,
    );
    defer bincode.free(allocator, protocol_message);

    var prune_data = protocol_message.PruneMessage[1];
    try std.testing.expect(prune_data.destination.equals(&push_from));
    try std.testing.expectEqual(prune_data.prunes.len, 10);
}

test "gossip.gossip_service: test build_pull_requests" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, true);

    var contact_info = LegacyContactInfo.default(my_pubkey);
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

    var contact_info = LegacyContactInfo.default(my_pubkey);
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
    var peers = ArrayList(LegacyContactInfo).init(allocator);
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
        try std.testing.expect(as.len() > 0);
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
    var msgs = try gossip_service.buildPushMessages(&cursor);
    try std.testing.expectEqual(cursor, 11);
    try std.testing.expect(msgs.items.len > 0);
    for (msgs.items) |*msg| msg.deinit();
    msgs.deinit();

    var msgs2 = try gossip_service.buildPushMessages(&cursor);
    try std.testing.expectEqual(cursor, 11);
    try std.testing.expect(msgs2.items.len == 0);
}

test "gossip.gossip_service: test packet verification" {
    const allocator = std.testing.allocator;
    var exit = AtomicBool.init(false);
    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var id = Pubkey.fromPublicKey(&keypair.public_key, true);

    var contact_info = LegacyContactInfo.default(id);
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
    var packet_batch = ArrayList(Packet).init(allocator);
    for (0..3) |_| {
        try packet_batch.append(packet);
    }
    try packet_channel.send(packet_batch);

    var packet_batch_2 = ArrayList(Packet).init(allocator);

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
    try packet_batch_2.append(packet_v2);

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
    try packet_batch_2.append(packet2);

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
        try packet_batch_2.append(packet3);
    }
    try packet_channel.send(packet_batch_2);

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

    var contact_info = LegacyContactInfo.default(my_pubkey);
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
        .{&gossip_service},
    );

    // send a push message
    var id = pk;

    // new contact info
    var legacy_contact_info = LegacyContactInfo.default(id);
    var crds_data = crds.CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    };
    var crds_value = try crds.CrdsValue.initSigned(crds_data, &kp);
    var heap_values = try allocator.alloc(crds.CrdsValue, 1);
    heap_values[0] = crds_value;
    const msg = Protocol{
        .PushMessage = .{ id, heap_values },
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
    defer {
        for (resp) |*packet_batch| {
            packet_batch.deinit();
        }
        responder_channel.allocator.free(resp);
    }
    try std.testing.expect(resp.len == 1);

    exit.store(true, std.atomic.Ordering.Unordered);
    packet_handle.join();
}

test "gossip.gossip_service: init, exit, and deinit" {
    var gossip_address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);
    var my_keypair = try KeyPair.create(null);
    var rng = std.rand.DefaultPrng.init(getWallclockMs());
    var contact_info = LegacyContactInfo.random(rng.random());
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
        .{ &gossip_service, true },
    );

    gossip_service.echo_server.kill();
    exit.store(true, std.atomic.Ordering.Unordered);
    handle.join();
    gossip_service.deinit();
}

const fuzz = @import("./fuzz.zig");

pub const BenchmarkGossipServiceGeneral = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 1;

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
        var contact_info = LegacyContactInfo.default(pubkey);
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
        gossip_service.echo_server.kill(); // we dont need this rn
        defer gossip_service.deinit();

        var packet_handle = try Thread.spawn(.{}, GossipService.run, .{ &gossip_service, true });

        // send incomign packets/messages
        var outgoing_channel = Channel(ArrayList(Packet)).init(allocator, 10_000);
        defer outgoing_channel.deinit();

        var socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
        socket.bindToPort(8889) catch return error.SocketBindFailed;
        socket.setReadTimeout(1000000) catch return error.SocketSetTimeoutFailed; // 1 second
        defer {
            socket.close();
        }

        var sender_exit = AtomicBool.init(false);
        var outgoing_handle = try Thread.spawn(.{}, socket_utils.sendSocket, .{
            &socket,
            outgoing_channel,
            &sender_exit,
            logger,
        });

        // generate messages
        var rand = std.rand.DefaultPrng.init(19);
        var rng = rand.random();
        var sender_keypair = try KeyPair.create(null);

        var msg_sent: usize = 0;

        while (msg_sent < num_message_iterations) {
            var packet_batch = try ArrayList(Packet).initCapacity(allocator, 10);

            // send a ping message
            {
                var packet = try fuzz.randomPingPacket(rng, &keypair, endpoint);
                try packet_batch.append(packet);
                msg_sent += 1;
            }
            // send a pong message
            {
                var packet = try fuzz.randomPongPacket(rng, &keypair, endpoint);
                try packet_batch.append(packet);
                msg_sent += 1;
            }
            // send a push message
            {
                var packets = try fuzz.randomPushMessage(rng, &keypair, address.toEndpoint());
                try outgoing_channel.send(packets);
                msg_sent += packets.items.len;
            }
            // send a pull response
            {
                var packets = try fuzz.randomPullResponse(rng, &keypair, address.toEndpoint());
                try outgoing_channel.send(packets);
                msg_sent += packets.items.len;
            }
            // send a pull request
            {
                var packet = try fuzz.randomPullRequest(allocator, rng, &sender_keypair, address.toEndpoint());
                try packet_batch.append(packet);
                msg_sent += 1;
            }

            try outgoing_channel.send(packet_batch);
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

        sender_exit.store(true, std.atomic.Ordering.Unordered);
        outgoing_handle.join();
    }
};
