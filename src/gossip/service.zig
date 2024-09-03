const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const Bloom = @import("../bloom/bloom.zig").Bloom;

const bincode = sig.bincode;
const socket_utils = sig.net.socket_utils;
const pull_request = sig.gossip.pull_request;
const pull_response = sig.gossip.pull_response;

const ArrayList = std.ArrayList;
const Thread = std.Thread;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const EndPoint = network.EndPoint;
const UdpSocket = network.Socket;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Logger = sig.trace.log.Logger;
const Packet = sig.net.Packet;
const EchoServer = sig.net.echo.Server;
const SocketAddr = sig.net.SocketAddr;
const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const Histogram = sig.prometheus.Histogram;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const ThreadPoolTask = sig.utils.thread.ThreadPoolTask;
const ThreadPool = sig.sync.ThreadPool;
const Task = sig.sync.ThreadPool.Task;
const Batch = sig.sync.ThreadPool.Batch;
const Mux = sig.sync.Mux;
const RwMux = sig.sync.RwMux;
const Channel = sig.sync.Channel;
const ActiveSet = sig.gossip.active_set.ActiveSet;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const ContactInfo = sig.gossip.data.ContactInfo;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const GossipVersionedData = sig.gossip.data.GossipVersionedData;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipData = sig.gossip.data.GossipData;
const GossipDumpService = sig.gossip.dump_service.GossipDumpService;
const GossipMessage = sig.gossip.message.GossipMessage;
const PruneData = sig.gossip.message.PruneData;
const GossipTable = sig.gossip.table.GossipTable;
const HashTimeQueue = sig.gossip.table.HashTimeQueue;
const AutoArrayHashSet = sig.gossip.table.AutoArrayHashSet;
const GossipPullFilter = sig.gossip.pull_request.GossipPullFilter;
const Ping = sig.gossip.ping_pong.Ping;
const Pong = sig.gossip.ping_pong.Pong;
const PingCache = sig.gossip.ping_pong.PingCache;
const PingAndSocketAddr = sig.gossip.ping_pong.PingAndSocketAddr;
const ServiceManager = sig.utils.service_manager.ServiceManager;
const Duration = sig.time.Duration;

const endpointToString = sig.net.endpointToString;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.time.getWallclockMs;

const PACKET_DATA_SIZE = sig.net.packet.PACKET_DATA_SIZE;
const UNIQUE_PUBKEY_CAPACITY = sig.gossip.table.UNIQUE_PUBKEY_CAPACITY;
const MAX_NUM_PULL_REQUESTS = sig.gossip.pull_request.MAX_NUM_PULL_REQUESTS;

const GossipMessageWithEndpoint = struct { from_endpoint: EndPoint, message: GossipMessage };

pub const PULL_REQUEST_RATE = Duration.fromSecs(5);
pub const PULL_RESPONSE_TIMEOUT = Duration.fromSecs(5);
pub const ACTIVE_SET_REFRESH_RATE = Duration.fromSecs(15);
pub const DATA_TIMEOUT = Duration.fromSecs(15);
pub const TABLE_TRIM_RATE = Duration.fromSecs(10);
pub const BUILD_MESSAGE_LOOP_MIN = Duration.fromSecs(1);
pub const PUBLISH_STATS_INTERVAL = Duration.fromSecs(2);

pub const PUSH_MSG_TIMEOUT = Duration.fromSecs(30);
pub const PRUNE_MSG_TIMEOUT = Duration.fromMillis(500);
pub const FAILED_INSERTS_RETENTION = Duration.fromSecs(20);
pub const PURGED_RETENTION = Duration.fromSecs(PULL_REQUEST_RATE.asSecs() * 5);

pub const MAX_PACKETS_PER_PUSH: usize = 64;
pub const MAX_BYTES_PER_PUSH: u64 = PACKET_DATA_SIZE * @as(u64, MAX_PACKETS_PER_PUSH);
// 4 (enum) + 32 (pubkey) + 8 (len) = 44
pub const MAX_PUSH_MESSAGE_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;

pub const MAX_NUM_VALUES_PER_PULL_RESPONSE = 20; // TODO: this is approx the rust one -- should tune
pub const NUM_ACTIVE_SET_ENTRIES: usize = 25;
/// Maximum number of origin nodes that a PruneData may contain, such that the
/// serialized size of the PruneMessage stays below PACKET_DATA_SIZE.
pub const MAX_PRUNE_DATA_NODES: usize = 32;

pub const PING_CACHE_CAPACITY: usize = 65_536;
pub const PING_CACHE_TTL = Duration.fromSecs(1280);
pub const PING_CACHE_RATE_LIMIT_DELAY = Duration.fromSecs(1280 / 64);

// TODO: replace with get_epoch_duration when BankForks is supported
const DEFAULT_EPOCH_DURATION = Duration.fromMillis(172_800_000);

pub const VERIFY_PACKET_PARALLEL_TASKS = 4;

const MAX_PROCESS_BATCH_SIZE = 64;

/// The flow of data goes as follows:
///
/// `readSocket` ->
///         - reads from the gossip socket
///         - puts the new packet onto `packet_incoming_channel`
///         - repeat until exit
///
/// `verifyPackets` ->
///         - receives from `packet_incoming_channel`
///         - starts queuing new parallel tasks with the new packets
///         - as a task verifies the incoming packet, it sends it into `verified_incoming_channel`
///         - repeat until exit *and* `packet_incoming_channel` is empty
///
/// `processMessages` ->
///         - receives from `verified_incoming_channel`
///         - processes the verified message it has received
///         - depending on the type of message received, it may put something onto `packet_outgoing_channel`
///
///  `sendSocket` ->
///         - receives from `packet_outgoing_channel`
///         - sends the outgoing packet onto the gossip socket
///         - repeats while `exit` is false and `packet_outgoing_channel`
///         - when `sendSocket` sees that `exit` has become `true`, it will begin waiting on
///           the previous thing in the chain to close, that usually being `processMessages`.
///           this ensures that `processMessages` doesn't add new items to `packet_outgoing_channel`
///           after the `sendSocket` thread exits.
///
pub const GossipService = struct {
    allocator: std.mem.Allocator,
    gossip_value_allocator: std.mem.Allocator,

    // note: this contact info should not change
    gossip_socket: UdpSocket,
    /// This contact info is mutated by the buildMessages thread, so it must
    /// only be read by that thread, or it needs a synchronization mechanism.
    my_contact_info: ContactInfo,
    my_keypair: KeyPair,
    my_pubkey: Pubkey,
    my_shred_version: Atomic(u16),

    /// Indicates if the gossip service is closed.
    closed: bool,
    /// An atomic counter for ensuring proper exit order of tasks.
    counter: *Atomic(usize),
    service_exit: Atomic(bool),

    // communication between threads
    packet_incoming_channel: *Channel(Packet),
    packet_outgoing_channel: *Channel(Packet),
    verified_incoming_channel: *Channel(GossipMessageWithEndpoint),

    // TODO(x19): most of these things need to be on the heap to be shared between threads
    // but rn we do this by having GossipService be on the heap, which is not ideal
    // ... we should figure out a better way to do this
    gossip_table_rw: RwMux(GossipTable),
    // push message things
    active_set_rw: RwMux(ActiveSet),
    push_msg_queue_mux: Mux(ArrayList(SignedGossipData)),
    // pull message things
    failed_pull_hashes_mux: Mux(HashTimeQueue),

    /// This contact info is mutated by the buildMessages thread, so it must
    /// only be read by that thread, or it needs a synchronization mechanism.
    entrypoints: ArrayList(Entrypoint),
    ping_cache_rw: RwMux(*PingCache),
    logger: Logger,
    thread_pool: *ThreadPool,
    echo_server: EchoServer,

    stats: GossipStats,

    const Self = @This();

    const Entrypoint = struct { addr: SocketAddr, info: ?ContactInfo = null };

    pub fn init(
        /// Must be thread-safe.
        allocator: std.mem.Allocator,
        /// Can be supplied as a different allocator in order to reduce contention.
        /// Must be thread safe.
        gossip_value_allocator: std.mem.Allocator,
        my_contact_info: ContactInfo,
        my_keypair: KeyPair,
        entrypoints: ?[]const SocketAddr,
        counter: *Atomic(usize),
        logger: Logger,
    ) !Self {
        var packet_incoming_channel = try Channel(Packet).create(allocator);
        errdefer packet_incoming_channel.deinit();

        var packet_outgoing_channel = try Channel(Packet).create(allocator);
        errdefer packet_outgoing_channel.deinit();

        var verified_incoming_channel = try Channel(GossipMessageWithEndpoint).create(allocator);
        errdefer verified_incoming_channel.deinit();

        const thread_pool = try allocator.create(ThreadPool);
        const n_threads: usize = @min(std.Thread.getCpuCount() catch 1, 8);
        thread_pool.* = ThreadPool.init(.{
            .max_threads = @intCast(n_threads),
            .stack_size = 2 * 1024 * 1024,
        });
        logger.debugf("using n_threads in gossip: {}", .{n_threads});

        var gossip_table = try GossipTable.init(gossip_value_allocator, thread_pool);
        errdefer gossip_table.deinit();

        const gossip_table_rw = RwMux(GossipTable).init(gossip_table);
        const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
        const my_shred_version = my_contact_info.shred_version;
        const active_set = ActiveSet.init(allocator);

        // bind the socket
        const gossip_address = my_contact_info.getSocket(.gossip) orelse return error.GossipAddrUnspecified;
        var gossip_socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
        gossip_socket.bindToPort(gossip_address.port()) catch return error.SocketBindFailed;
        gossip_socket.setReadTimeout(socket_utils.SOCKET_TIMEOUT_US) catch return error.SocketSetTimeoutFailed; // 1 second

        const failed_pull_hashes = HashTimeQueue.init(allocator);
        const push_msg_q = ArrayList(SignedGossipData).init(allocator);
        const echo_server = EchoServer.init(allocator, gossip_address.port());

        var entrypoint_list = ArrayList(Entrypoint).init(allocator);
        if (entrypoints) |eps| {
            try entrypoint_list.ensureTotalCapacityPrecise(eps.len);
            for (eps) |ep| entrypoint_list.appendAssumeCapacity(.{ .addr = ep });
        }

        const stats = try GossipStats.init(logger);

        const ping_cache_ptr = try allocator.create(PingCache);
        ping_cache_ptr.* = try PingCache.init(
            allocator,
            PING_CACHE_TTL,
            PING_CACHE_RATE_LIMIT_DELAY,
            PING_CACHE_CAPACITY,
        );

        return .{
            .allocator = allocator,
            .gossip_value_allocator = gossip_value_allocator,

            .counter = counter,
            .service_exit = Atomic(bool).init(false),
            .closed = false,

            .my_contact_info = my_contact_info,
            .my_keypair = my_keypair,
            .my_pubkey = my_pubkey,
            .my_shred_version = Atomic(u16).init(my_shred_version),
            .gossip_socket = gossip_socket,
            .packet_incoming_channel = packet_incoming_channel,
            .packet_outgoing_channel = packet_outgoing_channel,
            .verified_incoming_channel = verified_incoming_channel,
            .gossip_table_rw = gossip_table_rw,
            .push_msg_queue_mux = Mux(ArrayList(SignedGossipData)).init(push_msg_q),
            .active_set_rw = RwMux(ActiveSet).init(active_set),
            .failed_pull_hashes_mux = Mux(HashTimeQueue).init(failed_pull_hashes),
            .entrypoints = entrypoint_list,
            .ping_cache_rw = RwMux(*PingCache).init(ping_cache_ptr),
            .echo_server = echo_server,
            .logger = logger,
            .thread_pool = thread_pool,
            .stats = stats,
        };
    }

    /// Starts the shutdown chain for all services. Does *not* block until
    /// the service manager is joined.
    pub fn shutdown(self: *Self) void {
        std.debug.assert(!self.closed);
        defer self.closed = true;

        self.counter.store(1, .release); // kick off the shutdown chain
        self.service_exit.store(true, .release);
    }

    pub fn deinit(self: *Self) void {
        std.debug.assert(self.closed); // call `self.shutdown()` first

        self.thread_pool.shutdown();
        self.thread_pool.deinit();

        // assert the channels are empty in order to make sure no data was lost.
        // everything should be cleaned up when the thread-pool joins.
        std.debug.assert(self.packet_incoming_channel.len() == 0);
        self.packet_incoming_channel.deinit();
        self.allocator.destroy(self.packet_incoming_channel);

        std.debug.assert(self.packet_outgoing_channel.len() == 0);
        self.packet_outgoing_channel.deinit();
        self.allocator.destroy(self.packet_outgoing_channel);

        std.debug.assert(self.verified_incoming_channel.len() == 0);
        self.verified_incoming_channel.deinit();
        self.allocator.destroy(self.verified_incoming_channel);

        self.my_contact_info.deinit();
        self.echo_server.deinit();
        self.gossip_socket.close();

        self.entrypoints.deinit();
        self.allocator.destroy(self.thread_pool);

        {
            var t, var lg = self.gossip_table_rw.writeWithLock();
            defer lg.unlock();
            t.deinit();
        }

        {
            var t, var lg = self.active_set_rw.writeWithLock();
            defer lg.unlock();
            t.deinit();
        }

        var ping_cache, var ping_cache_lg = self.ping_cache_rw.writeWithLock();
        defer ping_cache_lg.unlock();

        ping_cache.deinit();
        self.allocator.destroy(ping_cache);

        {
            var t, var lg = self.push_msg_queue_mux.writeWithLock();
            defer lg.unlock();
            t.deinit();
        }

        {
            var t, var lg = self.failed_pull_hashes_mux.writeWithLock();
            defer lg.unlock();
            t.deinit();
        }
    }

    pub const RunThreadsParams = struct {
        spy_node: bool = false,
        dump: bool = false,
    };

    /// starts gossip and blocks until it exits
    pub fn run(self: *Self, params: RunThreadsParams) !void {
        var manager = ServiceManager.init(
            self.allocator,
            self.logger,
            &self.service_exit,
            "gossip",
            .{},
            .{},
        );
        try self.start(params, &manager);
        manager.join();
        manager.deinit();
    }

    /// spawns required threads for the gossip service and returns immediately
    /// including:
    ///     1) socket reciever
    ///     2) packet verifier
    ///     3) packet processor
    ///     4) build message loop (to send outgoing message) (only active if not a spy node)
    ///     5) a socket responder (to send outgoing packets)
    ///     6) echo server
    pub fn start(
        self: *Self,
        params: RunThreadsParams,
        manager: *ServiceManager,
    ) (std.mem.Allocator.Error || std.Thread.SpawnError)!void {
        // TODO(Ahmad): need new server impl, for now we don't join server thread
        // because http.zig's server doesn't stop when you call server.stop() - it's broken
        // const echo_server_thread = try self.echo_server.listenAndServe();
        // _ = echo_server_thread;
        errdefer manager.deinit();

        try manager.spawn("gossip readSocket", socket_utils.readSocket, .{
            self.gossip_socket,
            self.packet_incoming_channel,
            self.logger,
            true,
            self.counter,
        }, true);

        try manager.spawn("gossip verifyPackets", verifyPackets, .{self}, true);
        try manager.spawn("gossip processMessages", processMessages, .{ self, 19 }, true);

        if (!params.spy_node) {
            try manager.spawn("gossip buildMessages", buildMessages, .{ self, 19 }, true);
        }

        try manager.spawn("gossip sendSocket", socket_utils.sendSocket, .{
            self.gossip_socket,
            self.packet_outgoing_channel,
            self.logger,
            true,
            self.counter,
        }, true);

        if (params.dump) {
            try manager.spawn("GossipDumpService", GossipDumpService.run, .{.{
                .allocator = self.allocator,
                .logger = self.logger,
                .gossip_table_rw = &self.gossip_table_rw,
                .counter = self.counter,
            }}, true);
        }
    }

    const VerifyMessageTask = ThreadPoolTask(VerifyMessageEntry);
    const VerifyMessageEntry = struct {
        gossip_value_allocator: std.mem.Allocator,
        packet: Packet,
        verified_incoming_channel: *Channel(GossipMessageWithEndpoint),
        logger: Logger,

        pub fn callback(self: *VerifyMessageEntry) !void {
            const packet = self.packet;
            var message = bincode.readFromSlice(
                self.gossip_value_allocator,
                GossipMessage,
                packet.data[0..packet.size],
                bincode.Params.standard,
            ) catch |e| {
                self.logger.errf("gossip: packet_verify: failed to deserialize: {s}", .{@errorName(e)});
                return;
            };

            message.sanitize() catch |e| {
                self.logger.errf("gossip: packet_verify: failed to sanitize: {s}", .{@errorName(e)});
                bincode.free(self.gossip_value_allocator, message);
                return;
            };

            message.verifySignature() catch |e| {
                self.logger.errf(
                    "gossip: packet_verify: failed to verify signature from {}: {s}",
                    .{ packet.addr, @errorName(e) },
                );
                bincode.free(self.gossip_value_allocator, message);
                return;
            };

            const msg: GossipMessageWithEndpoint = .{
                .from_endpoint = packet.addr,
                .message = message,
            };
            try self.verified_incoming_channel.send(msg);
        }
    };

    /// main logic for deserializing Packets into GossipMessage messages
    /// and verifing they have valid values, and have valid signatures.
    /// Verified GossipMessagemessages are then sent to the verified_channel.
    fn verifyPackets(self: *Self, idx: usize) !void {
        defer {
            // trigger the next service in the chain to close
            self.counter.store(idx + 1, .release);
            self.logger.debugf("verifyPackets loop closed", .{});
        }

        const tasks = try VerifyMessageTask.init(self.allocator, VERIFY_PACKET_PARALLEL_TASKS);
        defer self.allocator.free(tasks);

        // pre-allocate all the tasks
        for (tasks) |*task| {
            task.entry = .{
                .gossip_value_allocator = self.gossip_value_allocator,
                .verified_incoming_channel = self.verified_incoming_channel,
                .packet = undefined,
                .logger = self.logger,
            };
        }

        // loop until the previous service closes and triggers us to close
        // and the packet_incoming_channel isn't empty, in order to not lose messages.
        while (self.counter.load(.acquire) != idx or
            self.packet_incoming_channel.len() != 0)
        {
            // verify in parallel using the threadpool
            // PERF: investigate CPU pinning
            var task_search_start_idx: usize = 0;
            while (self.packet_incoming_channel.receive()) |packet| {
                defer self.stats.gossip_packets_received.inc();

                const acquired_task_idx = VerifyMessageTask.awaitAndAcquireFirstAvailableTask(tasks, task_search_start_idx);
                task_search_start_idx = (acquired_task_idx + 1) % tasks.len;

                const task_ptr = &tasks[acquired_task_idx];
                task_ptr.entry.packet = packet;
                task_ptr.result catch |err| self.logger.errf("VerifyMessageTask encountered error: {s}", .{@errorName(err)});

                const batch = Batch.from(&task_ptr.task);
                self.thread_pool.schedule(batch);
            }
        }

        for (tasks) |*task| {
            task.blockUntilCompletion();
            task.result catch |err| self.logger.errf("VerifyMessageTask encountered error: {s}", .{@errorName(err)});
        }
    }

    // structs used in process_messages loop
    pub const PingMessage = struct {
        ping: *const Ping,
        from_endpoint: *const EndPoint,
    };

    pub const PongMessage = struct {
        pong: *const Pong,
        from_endpoint: *const EndPoint,
    };

    pub const PushMessage = struct {
        gossip_values: []SignedGossipData,
        from_pubkey: *const Pubkey,
        from_endpoint: *const EndPoint,
    };

    pub const PullRequestMessage = struct {
        filter: GossipPullFilter,
        value: SignedGossipData,
        from_endpoint: EndPoint,
    };

    pub const PullResponseMessage = struct {
        gossip_values: []SignedGossipData,
        from_pubkey: *const Pubkey,
    };

    /// main logic for recieving and processing gossip messages.
    pub fn processMessages(self: *Self, seed: u64, idx: usize) !void {
        defer {
            // even if we fail, trigger the next thing
            self.counter.store(idx + 1, .release);
            self.logger.debugf("processMessages loop closed", .{});
        }

        // we batch messages bc:
        // 1) less lock contention
        // 2) can use packetbatchs (ie, pre-allocated packets)
        // 3) processing read-heavy messages in parallel (specifically pull-requests)

        const init_capacity = socket_utils.PACKETS_PER_BATCH;

        var ping_messages = try ArrayList(PingMessage).initCapacity(self.allocator, init_capacity);
        defer ping_messages.deinit();

        var pong_messages = try ArrayList(PongMessage).initCapacity(self.allocator, init_capacity);
        defer pong_messages.deinit();

        var push_messages = try ArrayList(PushMessage).initCapacity(self.allocator, init_capacity);
        defer push_messages.deinit();

        var pull_requests = try ArrayList(PullRequestMessage).initCapacity(self.allocator, init_capacity);
        defer pull_requests.deinit();

        var pull_responses = try ArrayList(PullResponseMessage).initCapacity(self.allocator, init_capacity);
        defer pull_responses.deinit();

        var prune_messages = try ArrayList(PruneData).initCapacity(self.allocator, init_capacity);
        defer prune_messages.deinit();

        var trim_table_timer = try sig.time.Timer.start();

        // keep waiting for new data until,
        // - `exit` isn't set,
        // - there isn't any data to process in the input channel, in order to block the join until we've finished
        while (self.counter.load(.acquire) != idx or
            self.verified_incoming_channel.len() != 0)
        {
            var msg_count: usize = 0;
            while (self.verified_incoming_channel.receive()) |message| {
                msg_count += 1;
                switch (message.message) {
                    .PushMessage => |*push| {
                        try push_messages.append(.{
                            .gossip_values = push[1],
                            .from_pubkey = &push[0],
                            .from_endpoint = &message.from_endpoint,
                        });
                    },
                    .PullResponse => |*pull| {
                        try pull_responses.append(.{
                            .from_pubkey = &pull[0],
                            .gossip_values = pull[1],
                        });
                    },
                    .PullRequest => |*pull| {
                        const value: SignedGossipData = pull[1];
                        var should_process_value = true;
                        switch (value.data) {
                            .ContactInfo => |*data| {
                                if (data.pubkey.equals(&self.my_pubkey)) {
                                    // talking to myself == ignore
                                    should_process_value = false;
                                }
                                // Allow spy nodes with shred-verion == 0 to pull from other nodes.
                                if (data.shred_version != 0 and data.shred_version != self.my_shred_version.load(.monotonic)) {
                                    // non-matching shred version
                                    self.stats.pull_requests_dropped.add(1);
                                    should_process_value = false;
                                }
                            },
                            .LegacyContactInfo => |*data| {
                                if (data.id.equals(&self.my_pubkey)) {
                                    // talking to myself == ignore
                                    should_process_value = false;
                                }
                                // Allow spy nodes with shred-verion == 0 to pull from other nodes.
                                if (data.shred_version != 0 and data.shred_version != self.my_shred_version.load(.monotonic)) {
                                    // non-matching shred version
                                    self.stats.pull_requests_dropped.add(1);
                                    should_process_value = false;
                                }
                            },
                            // only contact info supported
                            else => {
                                self.stats.pull_requests_dropped.add(1);
                                should_process_value = false;
                            },
                        }

                        const from_addr = SocketAddr.fromEndpoint(&message.from_endpoint);
                        if (from_addr.isUnspecified() or from_addr.port() == 0) {
                            // unable to respond to these messages
                            self.stats.pull_requests_dropped.add(1);
                            should_process_value = false;
                        }

                        if (!should_process_value) {
                            bincode.free(self.gossip_value_allocator, value.data);
                            continue;
                        }

                        try pull_requests.append(.{
                            .filter = pull[0],
                            .value = value,
                            .from_endpoint = message.from_endpoint,
                        });
                    },
                    .PruneMessage => |*prune| {
                        const prune_data = prune[1];
                        const now = getWallclockMs();
                        const prune_wallclock = prune_data.wallclock;

                        const too_old = prune_wallclock < now -| PRUNE_MSG_TIMEOUT.asMillis();
                        const incorrect_destination = !prune_data.destination.equals(&self.my_pubkey);
                        if (too_old or incorrect_destination) {
                            self.stats.prune_messages_dropped.add(1);
                            continue;
                        }
                        try prune_messages.append(prune_data);
                    },
                    .PingMessage => |*ping| {
                        const from_addr = SocketAddr.fromEndpoint(&message.from_endpoint);
                        if (from_addr.isUnspecified() or from_addr.port() == 0) {
                            // unable to respond to these messages
                            self.stats.ping_messages_dropped.add(1);
                            continue;
                        }

                        try ping_messages.append(PingMessage{
                            .ping = ping,
                            .from_endpoint = &message.from_endpoint,
                        });
                    },
                    .PongMessage => |*pong| {
                        try pong_messages.append(PongMessage{
                            .pong = pong,
                            .from_endpoint = &message.from_endpoint,
                        });
                    },
                }
                if (msg_count > MAX_PROCESS_BATCH_SIZE) break;
            }
            if (msg_count == 0) continue;

            // track metrics
            self.stats.gossip_packets_verified.add(msg_count);
            self.stats.ping_messages_recv.add(ping_messages.items.len);
            self.stats.pong_messages_recv.add(pong_messages.items.len);
            self.stats.push_messages_recv.add(push_messages.items.len);
            self.stats.pull_requests_recv.add(pull_requests.items.len);
            self.stats.pull_responses_recv.add(pull_responses.items.len);
            self.stats.prune_messages_recv.add(prune_messages.items.len);

            var gossip_packets_processed: usize = 0;
            gossip_packets_processed += ping_messages.items.len;
            gossip_packets_processed += pong_messages.items.len;
            gossip_packets_processed += push_messages.items.len;
            gossip_packets_processed += pull_requests.items.len;
            gossip_packets_processed += pull_responses.items.len;
            gossip_packets_processed += prune_messages.items.len;

            // only add the count once we've finished processing
            defer self.stats.gossip_packets_processed.add(gossip_packets_processed);

            self.stats.maybeLog();

            // handle batch messages
            if (push_messages.items.len > 0) {
                var x_timer = try sig.time.Timer.start();
                self.handleBatchPushMessages(&push_messages) catch |err| {
                    self.logger.errf("handleBatchPushMessages failed: {}", .{err});
                };
                const elapsed = x_timer.read().asMillis();
                self.stats.handle_batch_push_time.observe(@floatFromInt(elapsed));

                push_messages.clearRetainingCapacity();
            }

            if (prune_messages.items.len > 0) {
                var x_timer = try sig.time.Timer.start();
                self.handleBatchPruneMessages(&prune_messages);
                const elapsed = x_timer.read().asMillis();
                self.stats.handle_batch_prune_time.observe(@floatFromInt(elapsed));

                prune_messages.clearRetainingCapacity();
            }

            if (pull_requests.items.len > 0) {
                var x_timer = try sig.time.Timer.start();
                self.handleBatchPullRequest(pull_requests, seed + msg_count) catch |err| {
                    self.logger.errf("handleBatchPullRequest failed: {}", .{err});
                };
                const elapsed = x_timer.read().asMillis();
                self.stats.handle_batch_pull_req_time.observe(@floatFromInt(elapsed));

                pull_requests.clearRetainingCapacity();
            }

            if (pull_responses.items.len > 0) {
                var x_timer = try sig.time.Timer.start();
                self.handleBatchPullResponses(pull_responses.items) catch |err| {
                    self.logger.errf("handleBatchPullResponses failed: {}", .{err});
                };
                const elapsed = x_timer.read().asMillis();
                self.stats.handle_batch_pull_resp_time.observe(@floatFromInt(elapsed));

                pull_responses.clearRetainingCapacity();
            }

            if (ping_messages.items.len > 0) {
                var x_timer = try sig.time.Timer.start();
                self.handleBatchPingMessages(&ping_messages) catch |err| {
                    self.logger.errf("handleBatchPingMessages failed: {}", .{err});
                };
                const elapsed = x_timer.read().asMillis();
                self.stats.handle_batch_ping_time.observe(@floatFromInt(elapsed));

                ping_messages.clearRetainingCapacity();
            }

            if (pong_messages.items.len > 0) {
                var x_timer = try sig.time.Timer.start();
                self.handleBatchPongMessages(&pong_messages);
                const elapsed = x_timer.read().asMillis();
                self.stats.handle_batch_pong_time.observe(@floatFromInt(elapsed));

                pong_messages.clearRetainingCapacity();
            }

            // TRIM gossip-table
            if (trim_table_timer.read().asNanos() > TABLE_TRIM_RATE.asNanos()) {
                defer trim_table_timer.reset();
                try self.attemptGossipTableTrim();
            }
        }
    }

    /// uses a read lock to first check if the gossip table should be trimmed,
    /// then acquires a write lock to perform the trim.
    /// NOTE: in practice, trim is rare because the number of global validators is much <10k (the global constant
    /// used is UNIQUE_PUBKEY_CAPACITY)
    pub fn attemptGossipTableTrim(self: *Self) !void {
        // first check with a read lock
        const should_trim = blk: {
            const gossip_table, var gossip_table_lock = self.gossip_table_rw.readWithLock();
            defer gossip_table_lock.unlock();

            const should_trim = gossip_table.shouldTrim(UNIQUE_PUBKEY_CAPACITY);
            break :blk should_trim;
        };

        // then trim with write lock
        const n_pubkeys_dropped: u64 = if (should_trim) blk: {
            var gossip_table, var gossip_table_lock = self.gossip_table_rw.writeWithLock();
            defer gossip_table_lock.unlock();

            var x_timer = sig.time.Timer.start() catch unreachable;
            const now = getWallclockMs();
            const n_pubkeys_dropped = gossip_table.attemptTrim(now, UNIQUE_PUBKEY_CAPACITY) catch |err| err_blk: {
                self.logger.warnf("gossip_table.attemptTrim failed: {s}", .{@errorName(err)});
                break :err_blk 0;
            };
            const elapsed = x_timer.read().asMillis();
            self.stats.handle_trim_table_time.observe(@floatFromInt(elapsed));

            break :blk n_pubkeys_dropped;
        } else 0;

        self.stats.table_pubkeys_dropped.add(n_pubkeys_dropped);
    }

    /// main gossip loop for periodically sending new GossipMessagemessages.
    /// this includes sending push messages, pull requests, and triming old
    /// gossip data (in the gossip_table, active_set, and failed_pull_hashes).
    fn buildMessages(self: *Self, seed: u64, idx: usize) !void {
        defer {
            self.counter.store(idx + 1, .release);
            self.logger.infof("buildMessages loop closed", .{});
        }

        var loop_timer = try sig.time.Timer.start();
        var active_set_timer = try sig.time.Timer.start();
        var pull_req_timer = try sig.time.Timer.start();
        var stats_publish_timer = try sig.time.Timer.start();
        var trim_memory_timer = try sig.time.Timer.start();

        var prng = std.rand.DefaultPrng.init(seed);
        const rng = prng.random();

        var push_cursor: u64 = 0;
        var entrypoints_identified = false;
        var shred_version_assigned = false;

        while (self.counter.load(.acquire) != idx) {
            defer loop_timer.reset();

            if (pull_req_timer.read().asNanos() > PULL_REQUEST_RATE.asNanos()) pull_blk: {
                defer pull_req_timer.reset();
                // this also includes sending ping messages to other peers
                const now = getWallclockMs();
                const packets = self.buildPullRequests(
                    rng,
                    pull_request.MAX_BLOOM_SIZE,
                    now,
                ) catch |e| {
                    self.logger.errf("failed to generate pull requests: {any}", .{e});
                    break :pull_blk;
                };
                for (packets.items) |packet| {
                    try self.packet_outgoing_channel.send(packet);
                }
                self.stats.pull_requests_sent.add(packets.items.len);
            }

            // new push msgs
            self.drainPushQueueToGossipTable(getWallclockMs());
            const maybe_push_packets = self.buildPushMessages(&push_cursor) catch |e| blk: {
                self.logger.errf("failed to generate push messages: {any}", .{e});
                break :blk null;
            };
            if (maybe_push_packets) |push_packets| {
                self.stats.push_messages_sent.add(push_packets.items.len);
                for (push_packets.items) |push_packet| {
                    try self.packet_outgoing_channel.send(push_packet);
                }
                push_packets.deinit();
            }

            // trim data
            if (trim_memory_timer.read().asNanos() > TABLE_TRIM_RATE.asNanos()) {
                defer trim_memory_timer.reset();
                try self.trimMemory(getWallclockMs());
            }

            // initialize cluster data from gossip values
            entrypoints_identified = entrypoints_identified or try self.populateEntrypointsFromGossipTable();
            shred_version_assigned = shred_version_assigned or self.assignDefaultShredVersionFromEntrypoint();

            // periodic things
            if (active_set_timer.read().asNanos() > ACTIVE_SET_REFRESH_RATE.asNanos()) {
                defer active_set_timer.reset();

                // update wallclock and sign
                self.my_contact_info.wallclock = getWallclockMs();
                const my_contact_info_value = try SignedGossipData.initSigned(GossipData{
                    .ContactInfo = try self.my_contact_info.clone(),
                }, &self.my_keypair);
                const my_legacy_contact_info_value = try SignedGossipData.initSigned(GossipData{
                    .LegacyContactInfo = LegacyContactInfo.fromContactInfo(&self.my_contact_info),
                }, &self.my_keypair);

                // push contact info
                {
                    var push_msg_queue, var push_msg_queue_lock = self.push_msg_queue_mux.writeWithLock();
                    defer push_msg_queue_lock.unlock();

                    try push_msg_queue.append(my_contact_info_value);
                    try push_msg_queue.append(my_legacy_contact_info_value);
                }

                try self.rotateActiveSet(rng);
            }

            // publish metrics
            if (stats_publish_timer.read().asNanos() > PUBLISH_STATS_INTERVAL.asNanos()) {
                defer stats_publish_timer.reset();
                try self.collectGossipTableMetrics();
            }

            // sleep
            if (loop_timer.read().asNanos() < BUILD_MESSAGE_LOOP_MIN.asNanos()) {
                const time_left_ms = BUILD_MESSAGE_LOOP_MIN.asMillis() -| loop_timer.read().asMillis();
                std.time.sleep(time_left_ms * std.time.ns_per_ms);
            }
        }
    }

    // collect gossip table metrics and pushes them to stats
    pub fn collectGossipTableMetrics(self: *Self) !void {
        var gossip_table_lock = self.gossip_table_rw.read();
        defer gossip_table_lock.unlock();

        const gossip_table = gossip_table_lock.get();
        const n_entries = gossip_table.store.count();
        const n_pubkeys = gossip_table.pubkey_to_values.count();

        self.stats.table_n_values.set(n_entries);
        self.stats.table_n_pubkeys.set(n_pubkeys);

        const incoming_channel_length = self.packet_incoming_channel.len();
        self.stats.incoming_channel_length.set(incoming_channel_length);

        const outgoing_channel_length = self.packet_outgoing_channel.len();
        self.stats.outgoing_channel_length.set(outgoing_channel_length);

        self.stats.verified_channel_length.set(self.verified_incoming_channel.len());
    }

    pub fn rotateActiveSet(self: *Self, rand: std.Random) !void {
        const now = getWallclockMs();
        var buf: [NUM_ACTIVE_SET_ENTRIES]ThreadSafeContactInfo = undefined;
        const gossip_peers = try self.getThreadSafeGossipNodes(&buf, NUM_ACTIVE_SET_ENTRIES, now);

        // filter out peers who have responded to pings
        const ping_cache_result = blk: {
            var ping_cache_lock = self.ping_cache_rw.write();
            defer ping_cache_lock.unlock();
            var ping_cache: *PingCache = ping_cache_lock.mut();

            const result = try ping_cache.filterValidPeers(self.allocator, self.my_keypair, gossip_peers);
            break :blk result;
        };
        var valid_gossip_indexs = ping_cache_result.valid_peers;
        defer valid_gossip_indexs.deinit();

        var valid_gossip_peers: [NUM_ACTIVE_SET_ENTRIES]ThreadSafeContactInfo = undefined;
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
        try active_set.rotate(rand, valid_gossip_peers[0..valid_gossip_indexs.items.len]);
    }

    /// logic for building new push messages which are sent to peers from the
    /// active set and serialized into packets.
    fn buildPushMessages(self: *Self, push_cursor: *u64) !ArrayList(Packet) {
        // TODO: find a better static value?
        var buf: [512]GossipVersionedData = undefined;

        const gossip_entries = blk: {
            var gossip_table_lock = self.gossip_table_rw.read();
            defer gossip_table_lock.unlock();

            const gossip_table: *const GossipTable = gossip_table_lock.get();
            break :blk try gossip_table.getClonedEntriesWithCursor(self.gossip_value_allocator, &buf, push_cursor);
        };
        defer for (gossip_entries) |*ge| ge.deinit(self.gossip_value_allocator);

        var packet_batch = ArrayList(Packet).init(self.allocator);
        errdefer packet_batch.deinit();

        if (gossip_entries.len == 0) {
            return packet_batch;
        }

        const now = getWallclockMs();
        var total_byte_size: usize = 0;

        // find new values in gossip table
        // TODO: benchmark different approach of HashMapping(origin, value) first
        // then deriving the active set per origin in a batch
        var push_messages = std.AutoHashMap(EndPoint, ArrayList(SignedGossipData)).init(self.allocator);
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

            for (gossip_entries) |entry| {
                const value = entry.value;

                const entry_time = value.wallclock();
                const too_old = entry_time < now -| PUSH_MSG_TIMEOUT.asMillis();
                const too_new = entry_time > now +| PUSH_MSG_TIMEOUT.asMillis();
                if (too_old or too_new) {
                    num_values_considered += 1;
                    continue;
                }

                const byte_size = bincode.sizeOf(value, .{});
                total_byte_size +|= byte_size;

                if (total_byte_size > MAX_BYTES_PER_PUSH) {
                    break;
                }

                // get the active set for these values *PER ORIGIN* due to prunes
                const origin = value.id();
                var active_set_peers = blk: {
                    var gossip_table_lock = self.gossip_table_rw.read();
                    defer gossip_table_lock.unlock();
                    const gossip_table: *const GossipTable = gossip_table_lock.get();

                    break :blk try active_set.getFanoutPeers(self.allocator, origin, gossip_table);
                };
                defer active_set_peers.deinit();

                for (active_set_peers.items) |peer| {
                    const maybe_peer_entry = push_messages.getEntry(peer);
                    if (maybe_peer_entry) |peer_entry| {
                        try peer_entry.value_ptr.append(value);
                    } else {
                        var peer_entry = try ArrayList(SignedGossipData).initCapacity(self.allocator, 1);
                        peer_entry.appendAssumeCapacity(value);
                        try push_messages.put(peer, peer_entry);
                    }
                }
                num_values_considered += 1;
            }
        }

        // adjust cursor for values not sent this round
        // NOTE: labs client doesnt do this - bug?
        const num_values_not_considered = gossip_entries.len - num_values_considered;
        push_cursor.* -= num_values_not_considered;

        var push_iter = push_messages.iterator();
        while (push_iter.next()) |push_entry| {
            const gossip_values: *const ArrayList(SignedGossipData) = push_entry.value_ptr;
            const to_endpoint: *const EndPoint = push_entry.key_ptr;

            // send the values as a pull response
            const packets = try gossipDataToPackets(
                self.allocator,
                &self.my_pubkey,
                gossip_values.items,
                to_endpoint,
                ChunkType.PushMessage,
            );
            defer packets.deinit();

            try packet_batch.appendSlice(packets.items);
        }

        return packet_batch;
    }

    /// builds new pull request messages and serializes it into a list of Packets
    /// to be sent to a random set of gossip nodes.
    fn buildPullRequests(
        self: *Self,
        rand: std.Random,
        /// the bloomsize of the pull request's filters
        bloom_size: usize,
        now: u64,
    ) !ArrayList(Packet) {
        // get nodes from gossip table
        var buf: [MAX_NUM_PULL_REQUESTS]ThreadSafeContactInfo = undefined;
        const peers = try self.getThreadSafeGossipNodes(
            &buf,
            MAX_NUM_PULL_REQUESTS,
            now,
        );

        // randomly include an entrypoint in the pull if we dont have their contact info
        var entrypoint_index: i16 = -1;
        if (self.entrypoints.items.len != 0) blk: {
            const maybe_entrypoint_index = rand.intRangeAtMost(usize, 0, self.entrypoints.items.len - 1);
            if (self.entrypoints.items[maybe_entrypoint_index].info) |_| {
                // early exit - we already have the peer in our contact info
                break :blk;
            }
            // we dont have them so well add them to the peer list (as default contact info)
            entrypoint_index = @intCast(maybe_entrypoint_index);
        }

        // filter out peers who have responded to pings
        const ping_cache_result = blk: {
            var ping_cache, var ping_cache_lg = self.ping_cache_rw.writeWithLock();
            defer ping_cache_lg.unlock();

            const result = try ping_cache.filterValidPeers(self.allocator, self.my_keypair, peers);
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

        // compute failed pull gossip hash values
        const failed_pull_hashes_array = blk: {
            var failed_pull_hashes, var failed_pull_hashes_lock = self.failed_pull_hashes_mux.writeWithLock();
            defer failed_pull_hashes_lock.unlock();

            break :blk try failed_pull_hashes.getValues();
        };
        defer failed_pull_hashes_array.deinit();

        // build gossip filters
        var filters = try pull_request.buildGossipPullFilters(
            self.allocator,
            rand,
            &self.gossip_table_rw,
            &failed_pull_hashes_array,
            bloom_size,
            MAX_NUM_PULL_REQUESTS,
        );
        defer pull_request.deinitGossipPullFilters(&filters);

        // build packet responses
        var n_packets: usize = 0;
        if (num_peers != 0) n_packets += filters.items.len;
        if (should_send_to_entrypoint) n_packets += filters.items.len;

        var packet_batch = try ArrayList(Packet).initCapacity(self.allocator, n_packets);
        packet_batch.appendNTimesAssumeCapacity(Packet.default(), n_packets);
        var packet_index: usize = 0;

        // update wallclock and sign
        self.my_contact_info.wallclock = now;
        const my_contact_info_value = try SignedGossipData.initSigned(GossipData{
            .LegacyContactInfo = LegacyContactInfo.fromContactInfo(&self.my_contact_info),
        }, &self.my_keypair);

        const my_shred_version = self.my_contact_info.shred_version;
        if (num_peers != 0) {
            for (filters.items) |filter_i| {
                // TODO: incorperate stake weight in random sampling
                const peer_index = rand.intRangeAtMost(usize, 0, num_peers - 1);
                const peer_contact_info_index = valid_gossip_peer_indexs.items[peer_index];
                const peer_contact_info = peers[peer_contact_info_index];
                if (peer_contact_info.shred_version != my_shred_version) {
                    continue;
                }
                if (peer_contact_info.gossip_addr) |gossip_addr| {
                    const message = GossipMessage{ .PullRequest = .{ filter_i, my_contact_info_value } };
                    var packet = &packet_batch.items[packet_index];

                    const bytes = try bincode.writeToSlice(&packet.data, message, bincode.Params{});
                    packet.size = bytes.len;
                    packet.addr = gossip_addr.toEndpoint();
                    packet_index += 1;
                }
            }
        }

        // append entrypoint msgs
        if (should_send_to_entrypoint) {
            const entrypoint = self.entrypoints.items[@as(usize, @intCast(entrypoint_index))];
            for (filters.items) |filter| {
                const message = GossipMessage{ .PullRequest = .{ filter, my_contact_info_value } };
                var packet = &packet_batch.items[packet_index];
                const bytes = try bincode.writeToSlice(&packet.data, message, bincode.Params{});
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
        filter: *GossipPullFilter,
        gossip_table: *const GossipTable,
        output: ArrayList(Packet),
        output_limit: *Atomic(i64),
        output_consumed: Atomic(bool) = Atomic(bool).init(false),
        seed: u64,

        task: Task,
        done: Atomic(bool) = Atomic(bool).init(false),

        pub fn deinit(this: *PullRequestTask) void {
            if (!this.output_consumed.load(.acquire)) {
                this.output.deinit();
            }
        }

        pub fn callback(task: *Task) void {
            var self: *@This() = @fieldParentPtr("task", task);
            defer self.done.store(true, .release);

            const output_limit = self.output_limit.load(.acquire);
            if (output_limit <= 0) {
                return;
            }

            var rng = std.Random.Xoshiro256.init(self.seed);
            const response_gossip_values = pull_response.filterSignedGossipDatas(
                rng.random(),
                self.allocator,
                self.gossip_table,
                self.filter,
                getWallclockMs(),
                @as(usize, @max(output_limit, 0)),
            ) catch return;
            defer response_gossip_values.deinit();

            _ = self.output_limit.fetchSub(
                @as(i64, @intCast(response_gossip_values.items.len)),
                .release,
            );

            const packets = gossipDataToPackets(
                self.allocator,
                self.my_pubkey,
                response_gossip_values.items,
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

    /// For all pull requests:
    ///     - PullRequestMessage.value is inserted into the gossip table
    ///     - PullRequestMessage.filter is freed in process messages
    fn handleBatchPullRequest(
        self: *Self,
        pull_requests: ArrayList(PullRequestMessage),
        seed: u64,
    ) !void {
        // update the callers
        // TODO: parallelize this?
        const now = getWallclockMs();
        {
            var gossip_table_lock = self.gossip_table_rw.write();
            defer gossip_table_lock.unlock();
            var gossip_table: *GossipTable = gossip_table_lock.mut();

            for (pull_requests.items) |*req| {
                _ = gossip_table.insert(req.value, now) catch {};
                gossip_table.updateRecordTimestamp(req.value.id(), now);
            }
        }

        var valid_indexs = blk: {
            var ping_cache_lock = self.ping_cache_rw.write();
            defer ping_cache_lock.unlock();
            var ping_cache: *PingCache = ping_cache_lock.mut();

            var peers = try ArrayList(ThreadSafeContactInfo).initCapacity(self.allocator, pull_requests.items.len);
            defer peers.deinit();
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();

            for (pull_requests.items) |*req| {
                const threads_safe_contact_info = switch (req.value.data) {
                    .ContactInfo => |ci| ThreadSafeContactInfo.fromContactInfo(ci),
                    .LegacyContactInfo => |legacy| ThreadSafeContactInfo.fromLegacyContactInfo(legacy),
                    else => return error.PullRequestWithoutContactInfo,
                };
                peers.appendAssumeCapacity(threads_safe_contact_info);
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
        const tasks = try self.allocator.alloc(PullRequestTask, n_valid_requests);
        defer {
            for (tasks) |*task| task.deinit();
            self.allocator.free(tasks);
        }

        {
            var gossip_table_lock = self.gossip_table_rw.read();
            const gossip_table: *const GossipTable = gossip_table_lock.get();
            defer gossip_table_lock.unlock();

            var output_limit = Atomic(i64).init(MAX_NUM_VALUES_PER_PULL_RESPONSE);

            for (valid_indexs.items, 0..) |i, task_index| {
                // create the thread task
                tasks[task_index] = PullRequestTask{
                    .task = .{ .callback = PullRequestTask.callback },
                    .my_pubkey = &self.my_pubkey,
                    .from_endpoint = &pull_requests.items[i].from_endpoint,
                    .filter = &pull_requests.items[i].filter,
                    .gossip_table = gossip_table,
                    .output = ArrayList(Packet).init(self.allocator),
                    .allocator = self.allocator,
                    .output_limit = &output_limit,
                    .seed = seed + i,
                };

                // run it
                const batch = Batch.from(&tasks[task_index].task);
                self.thread_pool.schedule(batch);
            }

            // wait for them to be done to release the lock
            for (tasks) |*task| {
                while (!task.done.load(.acquire)) {
                    // wait
                }
            }
        }

        for (tasks) |*task| {
            if (task.output.items.len > 0) {
                for (task.output.items) |output| {
                    try self.packet_outgoing_channel.send(output);
                    self.stats.pull_responses_sent.add(1);
                }
                task.output_consumed.store(true, .release);
            }
            task.output.deinit();
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
        for (ping_messages.items) |*ping_message| {
            const pong = try Pong.init(ping_message.ping, &self.my_keypair);
            const pong_message = GossipMessage{ .PongMessage = pong };

            var packet = Packet.default();
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
                .field("from_pubkey", ping_message.ping.from.string().slice())
                .debug("gossip: recv ping");

            try self.packet_outgoing_channel.send(packet);
            self.stats.pong_messages_sent.add(1);
        }
    }

    /// logic for handling a pull response message.
    /// successful inserted values, have their origin value timestamps updated.
    /// failed inserts (ie, too old or duplicate values) are added to the failed pull hashes so that they can be
    /// included in the next pull request (so we dont receive them again).
    /// For all pull responses:
    ///     - PullResponseMessage.gossip_values are inserted into the gossip table or added to failed pull hashes and freed
    pub fn handleBatchPullResponses(
        self: *Self,
        pull_response_messages: []const PullResponseMessage,
    ) !void {
        if (pull_response_messages.len == 0) {
            return;
        }

        const now = getWallclockMs();
        var failed_insert_ptrs = ArrayList(*const SignedGossipData).init(self.allocator);
        defer failed_insert_ptrs.deinit();

        {
            var gossip_table, var gossip_table_lg = self.gossip_table_rw.writeWithLock();
            defer gossip_table_lg.unlock();

            for (pull_response_messages) |*pull_message| {
                const full_len = pull_message.gossip_values.len;
                const valid_len = self.filterBasedOnShredVersion(
                    gossip_table,
                    pull_message.gossip_values,
                    pull_message.from_pubkey.*,
                );
                const invalid_shred_count = full_len - valid_len;

                const insert_results = try gossip_table.insertValues(
                    now,
                    pull_message.gossip_values[0..valid_len],
                    PULL_RESPONSE_TIMEOUT.asMillis(),
                );
                defer insert_results.deinit();

                for (insert_results.items) |result| {
                    switch (result) {
                        .InsertedNewEntry => self.stats.pull_response_n_new_inserts.inc(),
                        .OverwroteExistingEntry => self.stats.pull_response_n_overwrite_existing.inc(),
                        .IgnoredOldValue => self.stats.pull_response_n_old_value.inc(),
                        .IgnoredDuplicateValue => self.stats.pull_response_n_duplicate_value.inc(),
                        .IgnoredTimeout => self.stats.pull_response_n_timeouts.inc(),
                        .GossipTableFull => {},
                    }
                }
                self.stats.pull_response_n_invalid_shred_version.add(invalid_shred_count);

                for (insert_results.items, 0..) |result, index| {
                    if (result.wasInserted()) {
                        // update the contactInfo (and all other origin values) timestamps of
                        // successful inserts
                        const origin = pull_message.gossip_values[index].id();
                        gossip_table.updateRecordTimestamp(origin, now);

                        switch (result) {
                            .OverwroteExistingEntry => |old_data| {
                                // if the value was overwritten, we need to free the old value
                                bincode.free(self.gossip_value_allocator, old_data);
                            },
                            else => {},
                        }
                    } else if (result == .IgnoredTimeout) {
                        // silently insert the timeout values
                        // (without updating all associated origin values)
                        _ = try gossip_table.insert(
                            pull_message.gossip_values[index],
                            now,
                        );
                    } else {
                        try failed_insert_ptrs.append(&pull_message.gossip_values[index]);
                    }
                }
                gossip_table.updateRecordTimestamp(pull_message.from_pubkey.*, now);
            }
        }

        {
            var failed_pull_hashes, var failed_pull_hashes_lock = self.failed_pull_hashes_mux.writeWithLock();
            defer failed_pull_hashes_lock.unlock();

            var buf: [PACKET_DATA_SIZE]u8 = undefined;
            for (failed_insert_ptrs.items) |gossip_value_ptr| {
                const bytes = bincode.writeToSlice(&buf, gossip_value_ptr.*, bincode.Params.standard) catch {
                    continue;
                };
                const value_hash = Hash.generateSha256Hash(bytes);
                try failed_pull_hashes.insert(value_hash, now);
                bincode.free(self.gossip_value_allocator, gossip_value_ptr.*);
            }
        }
    }

    /// logic for handling a prune message. verifies the prune message
    /// is not too old, and that the destination pubkey is not the local node,
    /// then updates the active set to prune the list of origin Pubkeys.
    pub fn handleBatchPruneMessages(
        self: *Self,
        prune_messages: *const ArrayList(PruneData),
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

    /// For each push messages:
    ///     - PushMessage.gossip_values are filtered and then inserted into the gossip table, filtered values and failed inserts are freed
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

        // pre-allocate memory to track insertion failures
        var max_inserts_per_push: usize = 0;
        for (batch_push_messages.items) |push_message| {
            max_inserts_per_push = @max(max_inserts_per_push, push_message.gossip_values.len);
        }
        var insert_results = try std.ArrayList(GossipTable.InsertResult).initCapacity(self.allocator, max_inserts_per_push);
        defer insert_results.deinit();

        // insert values and track the failed origins per pubkey
        {
            var timer = try sig.time.Timer.start();
            defer {
                const elapsed = timer.read().asMillis();
                self.stats.push_messages_time_to_insert.observe(@floatFromInt(elapsed));
            }

            var gossip_table, var gossip_table_lg = self.gossip_table_rw.writeWithLock();
            defer gossip_table_lg.unlock();

            const now = getWallclockMs();
            for (batch_push_messages.items) |*push_message| {
                // Filtered values are freed
                const full_len = push_message.gossip_values.len;
                const valid_len = self.filterBasedOnShredVersion(
                    gossip_table,
                    push_message.gossip_values,
                    push_message.from_pubkey.*,
                );
                const invalid_shred_count = full_len - valid_len;

                try gossip_table.insertValuesWithResults(
                    now,
                    push_message.gossip_values[0..valid_len],
                    PUSH_MSG_TIMEOUT.asMillis(),
                    &insert_results,
                );

                var insert_fail_count: u64 = 0;
                for (insert_results.items) |result| {
                    switch (result) {
                        .InsertedNewEntry => self.stats.push_message_n_new_inserts.inc(),
                        .OverwroteExistingEntry => |old_data| {
                            self.stats.push_message_n_overwrite_existing.inc();
                            // if the value was overwritten, we need to free the old value
                            bincode.free(self.gossip_value_allocator, old_data);
                        },
                        .IgnoredOldValue => self.stats.push_message_n_old_value.inc(),
                        .IgnoredDuplicateValue => self.stats.push_message_n_duplicate_value.inc(),
                        .IgnoredTimeout => self.stats.push_message_n_timeouts.inc(),
                        .GossipTableFull => {},
                    }
                    if (!result.wasInserted()) {
                        insert_fail_count += 1;
                    }
                }
                self.stats.push_message_n_invalid_shred_version.add(invalid_shred_count);

                // logging this message takes too long and causes a bottleneck
                // self.logger
                //     .field("n_values", valid_len)
                //     .field("from_addr", &push_message.from_pubkey.string())
                //     .field("n_failed_inserts", failed_insert_indexs.items.len)
                //     .debug("gossip: recv push_message");

                if (insert_fail_count == 0) {
                    // dont need to build prune messages
                    continue;
                }

                // free failed inserts
                defer {
                    for (insert_results.items, 0..) |result, index| {
                        if (!result.wasInserted()) {
                            bincode.free(self.gossip_value_allocator, push_message.gossip_values[index]);
                        }
                    }
                }

                // lookup contact info to send a prune message to
                const from_contact_info = gossip_table.getThreadSafeContactInfo(push_message.from_pubkey.*) orelse {
                    // unable to find contact info
                    continue;
                };
                const from_gossip_addr = from_contact_info.gossip_addr orelse continue;
                from_gossip_addr.sanitize() catch {
                    // invalid gossip socket
                    continue;
                };

                // track the endpoint
                const from_gossip_endpoint = from_gossip_addr.toEndpoint();
                try pubkey_to_endpoint.put(push_message.from_pubkey.*, from_gossip_endpoint);

                // track failed origins
                var failed_origins = blk: {
                    const lookup_result = try pubkey_to_failed_origins.getOrPut(push_message.from_pubkey.*);
                    if (!lookup_result.found_existing) {
                        lookup_result.value_ptr.* = AutoArrayHashSet(Pubkey).init(self.allocator);
                    }
                    break :blk lookup_result.value_ptr;
                };

                for (insert_results.items, 0..) |result, index| {
                    if (!result.wasInserted()) {
                        const origin = push_message.gossip_values[index].id();
                        try failed_origins.put(origin, {});
                    }
                }
            }
        }

        // build prune packets
        const now = getWallclockMs();
        var timer = try sig.time.Timer.start();
        defer {
            const elapsed = timer.read().asMillis();
            self.stats.push_messages_time_build_prune.observe(@floatFromInt(elapsed));
        }
        var pubkey_to_failed_origins_iter = pubkey_to_failed_origins.iterator();

        const n_packets = pubkey_to_failed_origins_iter.len;
        if (n_packets == 0) return;

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
            const msg = GossipMessage{ .PruneMessage = .{ self.my_pubkey, prune_data } };

            self.logger
                .field("n_pruned_origins", prune_size)
                .field("to_addr", from_pubkey.string().slice())
                .debug("gossip: send prune_message");

            var packet = Packet.default();
            const written_slice = bincode.writeToSlice(&packet.data, msg, bincode.Params{}) catch unreachable;
            packet.size = written_slice.len;
            packet.addr = from_endpoint;

            try self.packet_outgoing_channel.send(packet);
            self.stats.prune_messages_sent.add(1);
        }
    }

    /// removes old values from the gossip table and failed pull hashes struct
    /// based on the current time. This includes triming the purged values from the
    /// gossip table, triming the max number of pubkeys in the gossip table, and removing
    /// old labels from the gossip table.
    fn trimMemory(
        self: *Self,
        /// the current time
        now: u64,
    ) error{OutOfMemory}!void {
        const purged_cutoff_timestamp = now -| PURGED_RETENTION.asMillis();
        {
            try self.attemptGossipTableTrim();

            var gossip_table, var gossip_table_lg = self.gossip_table_rw.writeWithLock();
            defer gossip_table_lg.unlock();

            try gossip_table.purged.trim(purged_cutoff_timestamp);

            // TODO: condition timeout on stake weight:
            // - values from nodes with non-zero stake: epoch duration
            // - values from nodes with zero stake:
            //   - if all nodes have zero stake: epoch duration (TODO: this might be unreasonably large)
            //   - if any other nodes have non-zero stake: DATA_TIMEOUT (15s)
            const n_values_removed = try gossip_table.removeOldLabels(now, DEFAULT_EPOCH_DURATION.asMillis());
            self.stats.table_old_values_removed.add(n_values_removed);
        }

        const failed_insert_cutoff_timestamp = now -| FAILED_INSERTS_RETENTION.asMillis();
        {
            var failed_pull_hashes, var failed_pull_hashes_lg = self.failed_pull_hashes_mux.writeWithLock();
            defer failed_pull_hashes_lg.unlock();

            try failed_pull_hashes.trim(failed_insert_cutoff_timestamp);
        }
    }

    /// Attempts to associate each entrypoint address with a contact info.
    /// Returns true if all entrypoints have been identified
    ///
    /// Acquires the gossip table lock regardless of whether the gossip table is used.
    fn populateEntrypointsFromGossipTable(self: *Self) !bool {
        var identified_all = true;

        var gossip_table_lock = self.gossip_table_rw.read();
        defer gossip_table_lock.unlock();
        var gossip_table: *const GossipTable = gossip_table_lock.get();

        for (self.entrypoints.items) |*entrypoint| {
            if (entrypoint.info == null) {
                entrypoint.info = try gossip_table.getOwnedContactInfoByGossipAddr(entrypoint.addr);
            }
            identified_all = identified_all and entrypoint.info != null;
        }
        return identified_all;
    }

    /// if we have no shred version, attempt to get one from an entrypoint.
    /// Returns true if the shred version is set to non-zero
    fn assignDefaultShredVersionFromEntrypoint(self: *Self) bool {
        if (self.my_shred_version.load(.monotonic) != 0) return true;
        for (self.entrypoints.items) |entrypoint| {
            if (entrypoint.info) |info| {
                if (info.shred_version != 0) {
                    var addr_str = entrypoint.addr.toString();
                    self.logger.infof(
                        "shred version: {} - from entrypoint contact info: {s}",
                        .{ info.shred_version, addr_str[0][0..addr_str[1]] },
                    );
                    self.my_shred_version.store(info.shred_version, .monotonic);
                    self.my_contact_info.shred_version = info.shred_version;
                    return true;
                }
            }
        }
        return false;
    }

    /// drains values from the push queue and inserts them into the gossip table.
    /// when inserting values in the gossip table, any errors are ignored.
    fn drainPushQueueToGossipTable(
        self: *Self,
        /// the current time to insert the values with
        now: u64,
    ) void {
        var push_msg_queue, var push_msg_queue_lock = self.push_msg_queue_mux.writeWithLock();
        defer push_msg_queue_lock.unlock();

        var gossip_table, var gossip_table_lock = self.gossip_table_rw.writeWithLock();
        defer gossip_table_lock.unlock();

        while (push_msg_queue.popOrNull()) |gossip_value| {
            _ = gossip_table.insert(gossip_value, now) catch {};
        }
    }

    /// serializes a list of ping messages into Packets and sends them out
    pub fn sendPings(
        self: *Self,
        pings: ArrayList(PingAndSocketAddr),
    ) error{ OutOfMemory, ChannelClosed, SerializationError }!void {
        const n_pings = pings.items.len;
        if (n_pings == 0) return;

        for (pings.items) |ping_and_addr| {
            const message = GossipMessage{ .PingMessage = ping_and_addr.ping };

            var packet = Packet.default();
            const serialized_ping = bincode.writeToSlice(&packet.data, message, .{}) catch return error.SerializationError;
            packet.size = serialized_ping.len;
            packet.addr = ping_and_addr.socket.toEndpoint();

            try self.packet_outgoing_channel.send(packet);
            self.stats.ping_messages_sent.add(1);
        }
    }

    /// returns a list of valid gossip nodes. this works by reading
    /// the contact infos from the gossip table and filtering out
    /// nodes that are 1) too old, 2) have a different shred version, or 3) have
    /// an invalid gossip address.
    pub fn getThreadSafeGossipNodes(
        self: *Self,
        /// the output slice which will be filled with gossip nodes
        nodes: []ThreadSafeContactInfo,
        /// the maximum number of nodes to return ( max_size == nodes.len but comptime for init of stack array)
        comptime MAX_SIZE: usize,
        /// current time (used to filter out nodes that are too old)
        now: u64,
    ) ![]ThreadSafeContactInfo {
        std.debug.assert(MAX_SIZE == nodes.len);

        // filter only valid gossip addresses
        const CONTACT_INFO_TIMEOUT_MS = 60 * std.time.ms_per_s;
        const too_old_ts = now -| CONTACT_INFO_TIMEOUT_MS;

        // * 2 bc we might filter out some
        var buf: [MAX_SIZE * 2]ThreadSafeContactInfo = undefined;
        const contact_infos = blk: {
            var gossip_table, var gossip_table_lock = self.gossip_table_rw.readWithLock();
            defer gossip_table_lock.unlock();

            break :blk gossip_table.getThreadSafeContactInfos(&buf, too_old_ts);
        };

        if (contact_infos.len == 0) {
            return nodes[0..0];
        }

        var node_index: usize = 0;
        for (contact_infos) |contact_info| {
            // filter self
            if (contact_info.pubkey.equals(&self.my_pubkey)) {
                continue;
            }
            // filter matching shred version or my_shred_version == 0
            const my_shred_version = self.my_shred_version.load(.acquire);
            if (my_shred_version != 0 and my_shred_version != contact_info.shred_version) {
                continue;
            }
            // filter on valid gossip address
            if (contact_info.gossip_addr) |addr| {
                addr.sanitize() catch continue;
            } else continue;

            nodes[node_index] = contact_info;
            node_index += 1;

            if (node_index == nodes.len) {
                break;
            }
        }

        return nodes[0..node_index];
    }

    /// Sorts the incoming `gossip_values` slice to place the valid gossip data
    /// at the start, and returns the number of valid gossip values in that slice.
    pub fn filterBasedOnShredVersion(
        self: *Self,
        gossip_table: *const GossipTable,
        gossip_values: []SignedGossipData,
        sender_pubkey: Pubkey,
    ) usize {
        // we use swap remove which just reorders the array
        // (order dm), so we just track the new len -- ie, no allocations/frees
        const my_shred_version = self.my_shred_version.load(.monotonic);
        if (my_shred_version == 0) {
            return gossip_values.len;
        }

        var gossip_values_array = ArrayList(SignedGossipData).fromOwnedSlice(self.allocator, gossip_values);
        const sender_matches = gossip_table.checkMatchingShredVersion(sender_pubkey, my_shred_version);
        var i: usize = 0;
        while (i < gossip_values_array.items.len) {
            const gossip_value = &gossip_values[i];
            switch (gossip_value.data) {
                // always allow contact info + node instance to update shred versions.
                // this also allows us to know who *not* to send pull requests to, if the shred version
                // doesnt match ours
                .ContactInfo => {},
                .LegacyContactInfo => {},
                .NodeInstance => {},
                else => {
                    // only allow values where both the sender and origin match our shred version
                    if (!sender_matches or
                        !gossip_table.checkMatchingShredVersion(gossip_value.id(), my_shred_version))
                    {
                        const removed_value = gossip_values_array.swapRemove(i);
                        bincode.free(self.gossip_value_allocator, removed_value);
                        continue; // do not incrememnt `i`. it has a new value we need to inspect.
                    }
                },
            }
            i += 1;
        }
        return gossip_values_array.items.len;
    }
};

/// stats that we publish to prometheus
pub const GossipStats = struct {
    gossip_packets_received: *Counter,
    gossip_packets_verified: *Counter,
    gossip_packets_processed: *Counter,

    ping_messages_recv: *Counter,
    pong_messages_recv: *Counter,
    push_messages_recv: *Counter,
    pull_requests_recv: *Counter,
    pull_responses_recv: *Counter,
    prune_messages_recv: *Counter,

    ping_messages_dropped: *Counter,
    pull_requests_dropped: *Counter,
    prune_messages_dropped: *Counter,

    ping_messages_sent: *Counter,
    pong_messages_sent: *Counter,
    push_messages_sent: *Counter,
    pull_requests_sent: *Counter,
    pull_responses_sent: *Counter,
    prune_messages_sent: *Counter,

    // inserting push messages stats
    push_message_n_invalid_shred_version: *Counter,
    push_message_n_new_inserts: *Counter,
    push_message_n_overwrite_existing: *Counter,
    push_message_n_old_value: *Counter,
    push_message_n_duplicate_value: *Counter,
    push_message_n_timeouts: *Counter,

    // inserting pull response stats
    pull_response_n_invalid_shred_version: *Counter,
    pull_response_n_new_inserts: *Counter,
    pull_response_n_overwrite_existing: *Counter,
    pull_response_n_old_value: *Counter,
    pull_response_n_duplicate_value: *Counter,
    pull_response_n_timeouts: *Counter,

    handle_batch_ping_time: *Histogram,
    handle_batch_pong_time: *Histogram,
    handle_batch_push_time: *Histogram,
    handle_batch_pull_req_time: *Histogram,
    handle_batch_pull_resp_time: *Histogram,
    handle_batch_prune_time: *Histogram,
    handle_trim_table_time: *Histogram,
    push_messages_time_to_insert: *Histogram,
    push_messages_time_build_prune: *Histogram,

    incoming_channel_length: *GaugeU64,
    verified_channel_length: *GaugeU64,
    outgoing_channel_length: *GaugeU64,

    // TODO(x19): consider moving these into a separate GossipTableStats
    table_n_values: *GaugeU64,
    table_n_pubkeys: *GaugeU64,
    table_pubkeys_dropped: *Counter,
    table_old_values_removed: *Counter,

    // logging details
    _logging_fields: struct {
        logger: Logger,
        log_interval_micros: i64 = 10 * std.time.us_per_s,
        last_log: i64 = 0,
        last_logged_snapshot: StatsToLog = .{},
        updates_since_last: u64 = 0,
    },

    const GaugeU64 = Gauge(u64);

    const StatsToLog = struct {
        gossip_packets_received: u64 = 0,

        ping_messages_recv: u64 = 0,
        pong_messages_recv: u64 = 0,
        push_messages_recv: u64 = 0,
        pull_requests_recv: u64 = 0,
        pull_responses_recv: u64 = 0,
        prune_messages_recv: u64 = 0,

        ping_messages_sent: u64 = 0,
        pong_messages_sent: u64 = 0,
        push_messages_sent: u64 = 0,
        pull_requests_sent: u64 = 0,
        pull_responses_sent: u64 = 0,
        prune_messages_sent: u64 = 0,
    };

    const Self = @This();

    const HANDLE_TIME_BUCKETS_MS: [10]f64 = .{
        10,   25,
        50,   100,
        250,  500,
        1000, 2500,
        5000, 10000,
    };
    pub fn init(logger: Logger) GetMetricError!Self {
        var self: Self = undefined;
        const registry = globalRegistry();
        const stats_struct_info = @typeInfo(GossipStats).Struct;
        inline for (stats_struct_info.fields) |field| {
            if (field.name[0] != '_') {
                @field(self, field.name) = switch (field.type) {
                    *Counter => try registry.getOrCreateCounter(field.name),
                    *GaugeU64 => try registry.getOrCreateGauge(field.name, u64),
                    *Histogram => try registry.getOrCreateHistogram(field.name, &HANDLE_TIME_BUCKETS_MS),
                    else => @compileError("Unhandled field type: " ++ field.name ++ ": " ++ @typeName(field.type)),
                };
            }
        }

        self._logging_fields = .{ .logger = logger };
        return self;
    }

    pub fn reset(self: *Self) void {
        inline for (@typeInfo(GossipStats).Struct.fields) |field| {
            if (field.name[0] != '_') {
                @field(self, field.name).reset();
            }
        }
    }

    /// If log_interval_millis has passed since the last log,
    /// then log the number of events since then.
    fn maybeLog(
        self: *Self,
    ) void {
        const now = std.time.microTimestamp();
        const logging_fields = self._logging_fields;
        const interval = @as(u64, @intCast(now -| logging_fields.last_log));
        if (interval < logging_fields.log_interval_micros) return;

        const current_stats = StatsToLog{
            .gossip_packets_received = self.gossip_packets_received.get(),
            .ping_messages_recv = self.ping_messages_recv.get(),
            .pong_messages_recv = self.pong_messages_recv.get(),
            .push_messages_recv = self.push_messages_recv.get(),
            .pull_requests_recv = self.pull_requests_recv.get(),
            .pull_responses_recv = self.pull_responses_recv.get(),
            .prune_messages_recv = self.prune_messages_recv.get(),

            .ping_messages_sent = self.ping_messages_sent.get(),
            .pong_messages_sent = self.pong_messages_sent.get(),
            .push_messages_sent = self.push_messages_sent.get(),
            .pull_requests_sent = self.pull_requests_sent.get(),
            .pull_responses_sent = self.pull_responses_sent.get(),
            .prune_messages_sent = self.prune_messages_sent.get(),
        };

        logging_fields.logger.infof(
            "gossip: recv {}: {} ping, {} pong, {} push, {} pull request, {} pull response, {} prune",
            .{
                current_stats.gossip_packets_received - logging_fields.last_logged_snapshot.gossip_packets_received,
                current_stats.ping_messages_recv - logging_fields.last_logged_snapshot.ping_messages_recv,
                current_stats.pong_messages_recv - logging_fields.last_logged_snapshot.pong_messages_recv,
                current_stats.push_messages_recv - logging_fields.last_logged_snapshot.push_messages_recv,
                current_stats.pull_requests_recv - logging_fields.last_logged_snapshot.pull_requests_recv,
                current_stats.pull_responses_recv - logging_fields.last_logged_snapshot.pull_responses_recv,
                current_stats.prune_messages_recv - logging_fields.last_logged_snapshot.prune_messages_recv,
            },
        );
        logging_fields.logger.infof(
            "gossip: sent: {} ping, {} pong, {} push, {} pull request, {} pull response, {} prune",
            .{
                current_stats.ping_messages_sent - logging_fields.last_logged_snapshot.ping_messages_sent,
                current_stats.pong_messages_sent - logging_fields.last_logged_snapshot.pong_messages_sent,
                current_stats.push_messages_sent - logging_fields.last_logged_snapshot.push_messages_sent,
                current_stats.pull_requests_sent - logging_fields.last_logged_snapshot.pull_requests_sent,
                current_stats.pull_responses_sent - logging_fields.last_logged_snapshot.pull_responses_sent,
                current_stats.prune_messages_sent - logging_fields.last_logged_snapshot.prune_messages_sent,
            },
        );
        self._logging_fields.last_logged_snapshot = current_stats;
        self._logging_fields.last_log = now;
        self._logging_fields.updates_since_last = 0;
    }
};

pub const ChunkType = enum(u8) {
    PushMessage,
    PullResponse,
};

pub fn gossipDataToPackets(
    allocator: std.mem.Allocator,
    my_pubkey: *const Pubkey,
    gossip_values: []SignedGossipData,
    to_endpoint: *const EndPoint,
    chunk_type: ChunkType,
) error{ OutOfMemory, SerializationError }!ArrayList(Packet) {
    if (gossip_values.len == 0)
        return ArrayList(Packet).init(allocator);

    const indexs = try chunkValuesIntoPacketIndexes(
        allocator,
        gossip_values,
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
        const values = gossip_values[start_index..end_index];

        const message = switch (chunk_type) {
            .PushMessage => GossipMessage{ .PushMessage = .{ my_pubkey.*, values } },
            .PullResponse => GossipMessage{ .PullResponse = .{ my_pubkey.*, values } },
        };
        const msg_slice = bincode.writeToSlice(&packet_buf, message, bincode.Params{}) catch {
            return error.SerializationError;
        };
        const packet = Packet.init(to_endpoint.*, packet_buf, msg_slice.len);
        packets.appendAssumeCapacity(packet);
    }

    return packets;
}

pub fn chunkValuesIntoPacketIndexes(
    allocator: std.mem.Allocator,
    gossip_values: []const SignedGossipData,
    max_chunk_bytes: usize,
) error{ OutOfMemory, SerializationError }!ArrayList(usize) {
    var packet_indexs = try ArrayList(usize).initCapacity(allocator, 1);
    errdefer packet_indexs.deinit();
    packet_indexs.appendAssumeCapacity(0);

    if (gossip_values.len == 0) {
        return packet_indexs;
    }

    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var buf_byte_size: u64 = 0;

    for (gossip_values, 0..) |gossip_value, i| {
        const data_byte_size = bincode.getSerializedSizeWithSlice(&packet_buf, gossip_value, bincode.Params{}) catch {
            return error.SerializationError;
        };
        const new_chunk_size = buf_byte_size + data_byte_size;
        const is_last_iter = i == gossip_values.len - 1;

        if (new_chunk_size > max_chunk_bytes or is_last_iter) {
            try packet_indexs.append(i);
            buf_byte_size = data_byte_size;
        } else {
            buf_byte_size = new_chunk_size;
        }
    }

    return packet_indexs;
}

test "handle pong messages" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    const contact_info = try localhostTestContactInfo(pubkey);

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        keypair,
        null,
        &counter,
        .noop,
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
    }

    const endpoint = try allocator.create(EndPoint);
    defer allocator.destroy(endpoint);
    endpoint.* = try EndPoint.parse("127.0.0.1:8000");

    // send out a ping to the endpoint
    const other_keypair = try KeyPair.create(null);
    const other_pubkey = Pubkey.fromPublicKey(&other_keypair.public_key);
    const pubkey_and_addr = sig.gossip.ping_pong.PubkeyAndSocketAddr{
        .pubkey = other_pubkey,
        .socket_addr = SocketAddr.fromEndpoint(endpoint),
    };

    const ping = blk: {
        const ping_cache_ptr_ptr, var ping_cache_lg = gossip_service.ping_cache_rw.writeWithLock();
        defer ping_cache_lg.unlock();

        const now = try std.time.Instant.now();
        const ping = ping_cache_ptr_ptr.*.maybePing(now, pubkey_and_addr, &keypair);
        break :blk ping.?;
    };

    // recv and matching pong
    var pong_messages = ArrayList(GossipService.PongMessage).init(allocator);
    defer pong_messages.deinit();

    const pong = try allocator.create(Pong);
    defer allocator.destroy(pong);
    pong.* = try Pong.init(&ping, &other_keypair);

    try pong_messages.append(.{
        .from_endpoint = endpoint,
        .pong = pong,
    });

    // main method to test
    gossip_service.handleBatchPongMessages(&pong_messages);

    // make sure it passes the ping check
    {
        const ping_cache_ptr_ptr, var ping_cache_lg = gossip_service.ping_cache_rw.writeWithLock();
        defer ping_cache_lg.unlock();

        const now = try std.time.Instant.now();
        const r = ping_cache_ptr_ptr.*.check(now, pubkey_and_addr, &keypair);
        std.debug.assert(r.passes_ping_check);
    }
}

test "build messages startup and shutdown" {
    const allocator = std.testing.allocator;
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer gossip_service.deinit();

    var prng = std.Random.Xoshiro256.init(0);
    const rng = prng.random();

    var build_messages_handle = try Thread.spawn(
        .{},
        GossipService.buildMessages,
        .{ &gossip_service, 19, 1 },
    );
    defer {
        gossip_service.shutdown();
        build_messages_handle.join();
    }

    // add some gossip values to push
    var lg = gossip_service.gossip_table_rw.write();
    var ping_lock = gossip_service.ping_cache_rw.write();
    var ping_cache: *PingCache = ping_lock.mut();

    var peers = ArrayList(LegacyContactInfo).init(allocator);
    defer peers.deinit();

    for (0..10) |_| {
        var rand_keypair = try KeyPair.create(null);
        var value = try SignedGossipData.randomWithIndex(rng, &rand_keypair, 0); // contact info
        // make gossip valid
        value.data.LegacyContactInfo.gossip = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8000);
        _ = try lg.mut().insert(value, getWallclockMs());
        try peers.append(value.data.LegacyContactInfo);
        // set the pong status as OK so they included in active set
        ping_cache._setPong(value.data.LegacyContactInfo.id, value.data.LegacyContactInfo.gossip);
    }
    lg.unlock();
    ping_lock.unlock();
}

test "handling prune messages" {
    var rng = std.rand.DefaultPrng.init(91);

    const allocator = std.testing.allocator;
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
    }

    // add some peers
    var lg = gossip_service.gossip_table_rw.write();
    var peers = ArrayList(ThreadSafeContactInfo).init(allocator);
    defer peers.deinit();
    for (0..10) |_| {
        var rand_keypair = try KeyPair.create(null);
        const value = try SignedGossipData.randomWithIndex(rng.random(), &rand_keypair, 0); // contact info
        _ = try lg.mut().insert(value, getWallclockMs());
        try peers.append(ThreadSafeContactInfo.fromLegacyContactInfo(value.data.LegacyContactInfo));
    }
    lg.unlock();

    {
        var as_lock = gossip_service.active_set_rw.write();
        var as: *ActiveSet = as_lock.mut();
        const prng_seed: u64 = @intCast(std.time.milliTimestamp());
        var prng = std.Random.Xoshiro256.init(prng_seed);
        try as.rotate(prng.random(), peers.items);
        as_lock.unlock();
    }

    var as_lock = gossip_service.active_set_rw.read();
    var as: *const ActiveSet = as_lock.get();
    try std.testing.expect(as.len() > 0); // FIX
    var iter = as.peers.keyIterator();
    const peer0 = iter.next().?.*;
    as_lock.unlock();

    var prunes = [_]Pubkey{Pubkey.random(rng.random())};
    var prune_data = PruneData{
        .pubkey = peer0,
        .destination = gossip_service.my_pubkey,
        .prunes = &prunes,
        .signature = undefined,
        .wallclock = getWallclockMs(),
    };
    try prune_data.sign(&my_keypair);

    var data = std.ArrayList(PruneData).init(allocator);
    defer data.deinit();
    try data.append(prune_data);

    gossip_service.handleBatchPruneMessages(&data);

    var as_lock2 = gossip_service.active_set_rw.read();
    var as2: *const ActiveSet = as_lock2.get();
    try std.testing.expect(as2.peers.get(peer0).?.contains(&prunes[0].data));
    as_lock2.unlock();
}

test "handling pull responses" {
    const allocator = std.testing.allocator;

    var rng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
    }

    // get random values
    var gossip_values: [5]SignedGossipData = undefined;
    var kp = try KeyPair.create(null);
    for (0..5) |i| {
        var value = try SignedGossipData.randomWithIndex(rng.random(), &kp, 0);
        value.data.LegacyContactInfo.id = Pubkey.random(rng.random());
        gossip_values[i] = value;
    }

    var data = ArrayList(GossipService.PullResponseMessage).init(allocator);
    defer data.deinit();

    try data.append(GossipService.PullResponseMessage{
        .gossip_values = &gossip_values,
        .from_pubkey = &my_pubkey,
    });

    try gossip_service.handleBatchPullResponses(data.items);

    // make sure values are inserted
    var gossip_table_lock = gossip_service.gossip_table_rw.read();
    var gossip_table: *const GossipTable = gossip_table_lock.get();
    for (gossip_values) |value| {
        _ = gossip_table.get(value.label()).?;
    }
    gossip_table_lock.unlock();

    // try inserting again with same values (should all fail)
    try gossip_service.handleBatchPullResponses(data.items);

    var lg = gossip_service.failed_pull_hashes_mux.lock();
    var failed_pull_hashes: *HashTimeQueue = lg.mut();
    try std.testing.expect(failed_pull_hashes.len() == 5);
    lg.unlock();
}

test "handle old prune & pull request message" {
    const allocator = std.testing.allocator;

    var random = std.rand.DefaultPrng.init(91);
    const rng = random.random();

    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = try localhostTestContactInfo(my_pubkey);
    contact_info.shred_version = 99;

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        .noop,
    );
    defer gossip_service.deinit();

    const prune_pubkey = Pubkey.random(rng);
    const prune_data = PruneData.init(prune_pubkey, &.{}, my_pubkey, 0);
    const message = .{
        .PruneMessage = .{ prune_pubkey, prune_data },
    };

    const handle = try std.Thread.spawn(.{}, GossipService.run, .{ &gossip_service, .{} });

    try gossip_service.verified_incoming_channel.send(.{
        .from_endpoint = try EndPoint.parse("127.0.0.1:8000"),
        .message = message,
    });

    // send a pull request message
    const N_FILTER_BITS = 1;
    var bloom = try Bloom.random(allocator, rng, 100, 0.1, N_FILTER_BITS);
    defer bloom.deinit();

    const filter = GossipPullFilter{
        .filter = bloom,
        // this is why we wanted atleast one hash_bit == 1
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };
    var rando_keypair = try KeyPair.create([_]u8{22} ** 32);

    var ci = try SignedGossipData.randomWithIndex(rng, &rando_keypair, 0);
    const addr = SocketAddr.random(rng);
    ci.data.LegacyContactInfo.gossip = addr;
    ci.data.LegacyContactInfo.shred_version = 100; // DIFFERENT SHRED VERSION
    try ci.sign(&rando_keypair);

    try gossip_service.verified_incoming_channel.send(.{
        .from_endpoint = try EndPoint.parse("127.0.0.1:8000"),
        .message = .{ .PullRequest = .{ filter, ci } },
    });

    // DIFFERENT GOSSIP DATA (NOT A LEGACY CONTACT INFO)
    // NOTE: need fresh bloom filter because it gets deinit
    var bloom2 = try Bloom.random(allocator, rng, 100, 0.1, N_FILTER_BITS);
    defer bloom2.deinit();

    const filter2 = GossipPullFilter{
        .filter = bloom2,
        // this is why we wanted atleast one hash_bit == 1
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };
    const data = try SignedGossipData.randomWithIndex(rng, &rando_keypair, 2);
    try gossip_service.verified_incoming_channel.send(.{
        .from_endpoint = try EndPoint.parse("127.0.0.1:8000"),
        .message = .{ .PullRequest = .{ filter2, data } },
    });

    gossip_service.shutdown();
    handle.join();

    try std.testing.expect(gossip_service.stats.pull_requests_dropped.get() == 2);
}

test "handle pull request" {
    const allocator = std.testing.allocator;

    var rng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = try localhostTestContactInfo(my_pubkey);
    contact_info.shred_version = 99;

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer gossip_service.deinit();

    // insert random values
    const N_FILTER_BITS = 1;
    {
        const gossip_table, var gossip_table_lock = gossip_service.gossip_table_rw.writeWithLock();
        defer gossip_table_lock.unlock();

        var done = false;
        var count: usize = 0;
        while (!done) {
            count += 1;
            for (0..10) |_| {
                var value = try SignedGossipData.randomWithIndex(rng.random(), &(try KeyPair.create(null)), 0);
                _ = try gossip_table.insert(value, getWallclockMs());

                // make sure well get a response from the request
                const vers_value = gossip_table.get(value.label()).?;
                const hash_bits = pull_request.hashToU64(&vers_value.value_hash) >> (64 - N_FILTER_BITS);
                if (hash_bits == 1) {
                    done = true;
                }
            }
            if (count > 5) {
                @panic("something went wrong");
            }
        }
    }

    // make sure we get a response by setting a valid pong response
    var rando_keypair = try KeyPair.create([_]u8{22} ** 32);
    const rando_pubkey = Pubkey.fromPublicKey(&rando_keypair.public_key);

    const addr = SocketAddr.random(rng.random());
    var ci = try SignedGossipData.randomWithIndex(rng.random(), &rando_keypair, 0);
    ci.data.LegacyContactInfo.gossip = addr;
    ci.data.LegacyContactInfo.shred_version = 99;
    try ci.sign(&rando_keypair);

    {
        var ping_lock = gossip_service.ping_cache_rw.write();
        var ping_cache: *PingCache = ping_lock.mut();
        ping_cache._setPong(rando_pubkey, addr);
        ping_lock.unlock();
    }

    // only consider the first bit so we know well get matches
    var bloom = try Bloom.random(allocator, rng.random(), 100, 0.1, N_FILTER_BITS);
    defer bloom.deinit();

    const filter = GossipPullFilter{
        .filter = bloom,
        // this is why we wanted atleast one hash_bit == 1
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };

    var pull_requests = ArrayList(GossipService.PullRequestMessage).init(allocator);
    defer pull_requests.deinit();

    try pull_requests.append(.{
        .filter = filter,
        .from_endpoint = addr.toEndpoint(),
        .value = ci,
    });

    try gossip_service.handleBatchPullRequest(pull_requests, 19);

    {
        const outgoing_packets = gossip_service.packet_outgoing_channel;

        while (outgoing_packets.receive()) |response_packet| {
            const message = try bincode.readFromSlice(
                allocator,
                GossipMessage,
                response_packet.data[0..response_packet.size],
                bincode.Params.standard,
            );
            defer bincode.free(allocator, message);

            const values = message.PullResponse[1];
            try std.testing.expect(values.len > 0);
        }
    }

    gossip_service.shutdown();
}

test "test build prune messages and handle push messages" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer gossip_service.deinit();

    var push_from = Pubkey.random(rng.random());
    var values = ArrayList(SignedGossipData).init(allocator);
    defer values.deinit();
    for (0..10) |_| {
        var value = try SignedGossipData.randomWithIndex(rng.random(), &my_keypair, 0);
        value.data.LegacyContactInfo.id = Pubkey.random(rng.random());
        try values.append(value);
    }

    // insert contact info to send prunes to
    var send_contact_info = LegacyContactInfo.random(rng.random());
    send_contact_info.id = push_from;
    // valid socket addr
    var gossip_socket = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 20);
    send_contact_info.gossip = gossip_socket;

    const ci_value = try SignedGossipData.initSigned(GossipData{
        .LegacyContactInfo = send_contact_info,
    }, &my_keypair);
    var lg = gossip_service.gossip_table_rw.write();
    _ = try lg.mut().insert(ci_value, getWallclockMs());
    lg.unlock();

    var msgs = ArrayList(GossipService.PushMessage).init(allocator);
    defer msgs.deinit();

    var endpoint = gossip_socket.toEndpoint();
    try msgs.append(GossipService.PushMessage{
        .gossip_values = values.items,
        .from_endpoint = &endpoint,
        .from_pubkey = &push_from,
    });

    try gossip_service.handleBatchPushMessages(&msgs);
    {
        // zero prune messages
        try std.testing.expect(gossip_service.packet_outgoing_channel.len() == 0);
    }

    try gossip_service.handleBatchPushMessages(&msgs);
    var packet = gossip_service.packet_outgoing_channel.receive() orelse return error.ChannelEmpty;
    const message = try bincode.readFromSlice(
        allocator,
        GossipMessage,
        packet.data[0..packet.size],
        bincode.Params.standard,
    );
    defer bincode.free(allocator, message);

    var prune_data = message.PruneMessage[1];
    try std.testing.expect(prune_data.destination.equals(&push_from));
    try std.testing.expectEqual(prune_data.prunes.len, 10);

    gossip_service.shutdown();
}

test "build pull requests" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
    }

    // insert peers to send msgs to
    const now = getWallclockMs();
    {
        var ping_lock = gossip_service.ping_cache_rw.write();
        var lg = gossip_service.gossip_table_rw.write();
        defer {
            lg.unlock();
            ping_lock.unlock();
        }

        var pc: *PingCache = ping_lock.mut();
        for (0..20) |i| {
            var rando_keypair = try KeyPair.create(null);
            var value = try SignedGossipData.randomWithIndex(prng.random(), &rando_keypair, 0);
            value.wallclockPtr().* = now + 10 * i;
            value.data.LegacyContactInfo.shred_version = contact_info.shred_version;

            _ = try lg.mut().insert(value, now + 10 * i);
            pc._setPong(value.data.LegacyContactInfo.id, value.data.LegacyContactInfo.gossip);
        }
    }

    var packets = gossip_service.buildPullRequests(prng.random(), 2, now) catch |err| {
        std.log.err("\nThe failing now time is: '{d}'\n", .{now});
        return err;
    };
    defer packets.deinit();

    try std.testing.expect(packets.items.len > 1);
    try std.testing.expect(!std.mem.eql(u8, &packets.items[0].data, &packets.items[1].data));
}

test "test build push messages" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
    }

    // add some peers
    var peers = ArrayList(ThreadSafeContactInfo).init(allocator);
    defer peers.deinit();
    var lg = gossip_service.gossip_table_rw.write();
    for (0..10) |_| {
        var keypair = try KeyPair.create(null);
        const value = try SignedGossipData.randomWithIndex(rng.random(), &keypair, 0); // contact info
        _ = try lg.mut().insert(value, getWallclockMs());
        try peers.append(ThreadSafeContactInfo.fromLegacyContactInfo(value.data.LegacyContactInfo));
    }
    lg.unlock();

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    // var id = Pubkey.fromPublicKey(&keypair.public_key);
    const value = try SignedGossipData.random(rng.random(), &keypair);

    // set the active set
    {
        var as_lock = gossip_service.active_set_rw.write();
        var as: *ActiveSet = as_lock.mut();
        const prng_seed: u64 = @intCast(std.time.milliTimestamp());
        var prng = std.Random.Xoshiro256.init(prng_seed);
        try as.rotate(prng.random(), peers.items);
        as_lock.unlock();
        try std.testing.expect(as.len() > 0);
    }

    {
        var pqlg = gossip_service.push_msg_queue_mux.lock();
        var push_queue = pqlg.mut();
        try push_queue.append(value);
        pqlg.unlock();
    }
    gossip_service.drainPushQueueToGossipTable(getWallclockMs());

    var clg = gossip_service.gossip_table_rw.read();
    try std.testing.expect(clg.get().len() == 11);
    clg.unlock();

    var cursor: u64 = 0;
    var msgs = try gossip_service.buildPushMessages(&cursor);
    defer msgs.deinit();

    try std.testing.expectEqual(cursor, 11);
    try std.testing.expect(msgs.items.len > 0);

    const msgs2 = try gossip_service.buildPushMessages(&cursor);
    defer msgs2.deinit();

    try std.testing.expectEqual(cursor, 11);
    try std.testing.expect(msgs2.items.len == 0);
}

test "test large push messages" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
    }

    // add some peers
    var peers = ArrayList(ThreadSafeContactInfo).init(allocator);
    defer {
        peers.deinit();
    }
    {
        var lock_guard = gossip_service.gossip_table_rw.write();
        defer lock_guard.unlock();
        for (0..2_000) |_| {
            var keypair = try KeyPair.create(null);
            const value = try SignedGossipData.randomWithIndex(rng.random(), &keypair, 0); // contact info
            _ = try lock_guard.mut().insert(value, getWallclockMs());
            try peers.append(ThreadSafeContactInfo.fromLegacyContactInfo(value.data.LegacyContactInfo));
        }
    }

    // set the active set
    {
        var as_lock = gossip_service.active_set_rw.write();
        var as: *ActiveSet = as_lock.mut();
        const prng_seed: u64 = @intCast(std.time.milliTimestamp());
        var prng = std.Random.Xoshiro256.init(prng_seed);
        try as.rotate(prng.random(), peers.items);
        as_lock.unlock();
        try std.testing.expect(as.len() > 0);
    }

    var cursor: u64 = 0;
    const msgs = try gossip_service.buildPushMessages(&cursor);
    defer msgs.deinit();

    try std.testing.expect(msgs.items.len < 2_000);
}

test "test packet verification" {
    const allocator = std.testing.allocator;
    var keypair = try KeyPair.create([_]u8{1} ** 32);
    const id = Pubkey.fromPublicKey(&keypair.public_key);
    const contact_info = try localhostTestContactInfo(id);

    // noop for this case because this tests error failed verification
    const logger: Logger = .noop;

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        keypair,
        null,
        &counter,
        logger,
    );
    defer gossip_service.deinit();

    var packet_channel = gossip_service.packet_incoming_channel;
    var verified_channel = gossip_service.verified_incoming_channel;

    const packet_verifier_handle = try Thread.spawn(
        .{},
        GossipService.verifyPackets,
        .{ &gossip_service, 1 },
    );
    defer {
        gossip_service.shutdown();
        packet_verifier_handle.join();
    }

    var rng = std.rand.DefaultPrng.init(getWallclockMs());
    var data = GossipData.randomFromIndex(rng.random(), 0);
    data.LegacyContactInfo.id = id;
    data.LegacyContactInfo.wallclock = 0;
    var value = try SignedGossipData.initSigned(data, &keypair);

    try std.testing.expect(try value.verify(id));

    var values = [_]SignedGossipData{value};
    const message = GossipMessage{
        .PushMessage = .{ id, &values },
    };

    var peer = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);
    const from = peer.toEndpoint();

    var buf = [_]u8{0} ** PACKET_DATA_SIZE;
    const out = try bincode.writeToSlice(buf[0..], message, bincode.Params{});
    const packet = Packet.init(from, buf, out.len);
    for (0..3) |_| {
        try packet_channel.send(packet);
    }

    // send one which fails sanitization
    var value_v2 = try SignedGossipData.initSigned(GossipData.randomFromIndex(rng.random(), 2), &keypair);
    value_v2.data.EpochSlots[0] = sig.gossip.data.MAX_EPOCH_SLOTS;
    var values_v2 = [_]SignedGossipData{value_v2};
    const message_v2 = GossipMessage{
        .PushMessage = .{ id, &values_v2 },
    };
    var buf_v2 = [_]u8{0} ** PACKET_DATA_SIZE;
    const out_v2 = try bincode.writeToSlice(buf_v2[0..], message_v2, bincode.Params{});
    const packet_v2 = Packet.init(from, buf_v2, out_v2.len);
    try packet_channel.send(packet_v2);

    // send one with a incorrect signature
    var rand_keypair = try KeyPair.create([_]u8{3} ** 32);
    const value2 = try SignedGossipData.initSigned(GossipData.randomFromIndex(rng.random(), 0), &rand_keypair);
    var values2 = [_]SignedGossipData{value2};
    const message2 = GossipMessage{
        .PushMessage = .{ id, &values2 },
    };
    var buf2 = [_]u8{0} ** PACKET_DATA_SIZE;
    const out2 = try bincode.writeToSlice(buf2[0..], message2, bincode.Params{});
    const packet2 = Packet.init(from, buf2, out2.len);
    try packet_channel.send(packet2);

    // send it with a SignedGossipData which hash a slice
    {
        const rand_pubkey = Pubkey.fromPublicKey(&rand_keypair.public_key);
        var dshred = sig.gossip.data.DuplicateShred.random(rng.random());
        var chunk: [32]u8 = .{1} ** 32;
        dshred.chunk = &chunk;
        dshred.wallclock = 1714155765121;
        dshred.slot = 16592333628234015598;
        dshred.shred_index = 3853562894;
        dshred.shred_type = sig.gossip.data.ShredType.Data;
        dshred.num_chunks = 99;
        dshred.chunk_index = 69;
        dshred.from = rand_pubkey;
        const dshred_data = GossipData{
            .DuplicateShred = .{ 1, dshred },
        };
        const dshred_value = try SignedGossipData.initSigned(dshred_data, &rand_keypair);
        var values3 = [_]SignedGossipData{dshred_value};
        const message3 = GossipMessage{
            .PushMessage = .{ id, &values3 },
        };
        var buf3 = [_]u8{0} ** PACKET_DATA_SIZE;
        const out3 = try bincode.writeToSlice(buf3[0..], message3, bincode.Params{});
        const packet3 = Packet.init(from, buf3, out3.len);
        try packet_channel.send(packet3);
    }

    var msg_count: usize = 0;
    while (msg_count < 4) {
        if (verified_channel.receive()) |msg| {
            defer bincode.free(gossip_service.allocator, msg);
            try std.testing.expect(msg.message.PushMessage[0].equals(&id));
            msg_count += 1;
        }
    }
}

test "process contact info push packet" {
    const allocator = std.testing.allocator;

    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var counter = Atomic(usize).init(0);
    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer gossip_service.deinit();

    const verified_channel = gossip_service.verified_incoming_channel;
    const responder_channel = gossip_service.packet_outgoing_channel;

    const kp = try KeyPair.create(null);
    const id = Pubkey.fromPublicKey(&kp.public_key);

    var packet_handle = try Thread.spawn(
        .{},
        GossipService.processMessages,
        .{ &gossip_service, 19, 1 },
    );

    // new contact info
    const legacy_contact_info = LegacyContactInfo.default(id);
    const gossip_data: GossipData = .{ .LegacyContactInfo = legacy_contact_info };
    const gossip_value = try SignedGossipData.initSigned(gossip_data, &kp);
    const heap_values = try allocator.dupe(SignedGossipData, &.{gossip_value});
    defer allocator.free(heap_values);

    // packet
    const msg: GossipMessage = .{ .PushMessage = .{ id, heap_values } };
    const peer = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8000).toEndpoint();
    const message: GossipMessageWithEndpoint = .{
        .message = msg,
        .from_endpoint = peer,
    };
    try verified_channel.send(message);

    // ping
    const ping_msg: GossipMessageWithEndpoint = .{
        .message = .{ .PingMessage = try Ping.init(.{0} ** 32, &kp) },
        .from_endpoint = peer,
    };
    try verified_channel.send(ping_msg);

    // send pull request with own pubkey
    const erroneous_pull_request_msg: GossipMessageWithEndpoint = .{
        .message = .{
            .PullRequest = .{
                GossipPullFilter.init(allocator),
                try SignedGossipData.initSigned(.{
                    .ContactInfo = try localhostTestContactInfo(my_pubkey), // whoops
                }, &my_keypair),
            },
        },
        .from_endpoint = peer,
    };
    try verified_channel.send(erroneous_pull_request_msg);

    // close everything up before looking at the output channel in order to
    // not race with work services are doing
    gossip_service.shutdown();
    packet_handle.join();

    // the ping message we sent, processed into a pong
    try std.testing.expectEqual(1, responder_channel.len());
    _ = responder_channel.receive().?;

    // correct insertion into table
    var buf2: [100]ContactInfo = undefined;
    {
        var lg = gossip_service.gossip_table_rw.read();
        defer lg.unlock();

        const res = lg.get().getContactInfos(&buf2, 0);
        try std.testing.expect(res.len == 1);
    }
}

test "init, exit, and deinit" {
    const gossip_address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);
    const my_keypair = try KeyPair.create(null);
    var rng = std.rand.DefaultPrng.init(getWallclockMs());

    var contact_info = try LegacyContactInfo.random(rng.random()).toContactInfo(std.testing.allocator);
    try contact_info.setSocket(.gossip, gossip_address);

    var counter = Atomic(usize).init(0);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var gossip_service = try GossipService.init(
        std.testing.allocator,
        std.testing.allocator,
        contact_info,
        my_keypair,
        null,
        &counter,
        logger,
    );
    defer gossip_service.deinit();

    const handle = try std.Thread.spawn(.{}, GossipService.run, .{
        &gossip_service, .{
            .spy_node = true,
            .dump = false,
        },
    });
    defer {
        gossip_service.shutdown();
        handle.join();
    }
}

const fuzz_service = @import("./fuzz_service.zig");

pub const BenchmarkGossipServiceGeneral = struct {
    pub const min_iterations = 3;
    pub const max_iterations = 10;

    pub const MessageCounts = struct {
        n_ping: usize,
        n_push_message: usize,
        n_pull_response: usize,
    };

    pub const BenchmarkArgs = struct {
        name: []const u8 = "",
        message_counts: MessageCounts,
    };

    pub const args = [_]BenchmarkArgs{
        .{
            .name = "5k_ping_msgs",
            .message_counts = .{
                .n_ping = 5_000,
                .n_push_message = 0,
                .n_pull_response = 0,
            },
        },
        .{
            .name = "5k_push_msgs",
            .message_counts = .{
                .n_ping = 0,
                .n_push_message = 5_000,
                .n_pull_response = 0,
            },
        },
        .{
            .name = "1k_pull_resp_msgs",
            .message_counts = .{
                .n_ping = 0,
                .n_push_message = 0,
                .n_pull_response = 1_000,
            },
        },
    };

    pub fn benchmarkGossipService(bench_args: BenchmarkArgs) !usize {
        const allocator = std.heap.c_allocator;
        var keypair = try KeyPair.create(null);
        var address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8888);
        const endpoint = address.toEndpoint();

        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        var contact_info = ContactInfo.init(allocator, pubkey, 0, 19);
        try contact_info.setSocket(.gossip, address);

        // var logger = Logger.init(allocator, .debug);
        // defer logger.deinit();
        // logger.spawn();

        const logger: Logger = .noop;

        // process incoming packets/messsages
        var counter = Atomic(usize).init(0);
        var gossip_service = try GossipService.init(
            allocator,
            allocator,
            contact_info,
            keypair,
            null,
            &counter,
            logger,
        );
        gossip_service.echo_server.kill(); // we dont need this rn
        defer {
            gossip_service.stats.reset();
            gossip_service.deinit();
        }

        const outgoing_channel = gossip_service.packet_incoming_channel;

        // generate messages
        var rand = std.rand.DefaultPrng.init(19);
        const rng = rand.random();

        var msg_sent: usize = 0;
        msg_sent += bench_args.message_counts.n_ping;

        for (0..bench_args.message_counts.n_ping) |_| {
            // send a ping message
            const packet = try fuzz_service.randomPingPacket(rng, &keypair, endpoint);
            try outgoing_channel.send(packet);
        }

        for (0..bench_args.message_counts.n_push_message) |_| {
            // send a push message
            var packets = try fuzz_service.randomPushMessage(
                allocator,
                rng,
                &keypair,
                address.toEndpoint(),
            );
            defer packets.deinit();

            msg_sent += packets.items.len;
            for (packets.items) |packet| try outgoing_channel.send(packet);
        }

        for (0..bench_args.message_counts.n_pull_response) |_| {
            // send a pull response
            var packets = try fuzz_service.randomPullResponse(
                rng,
                &keypair,
                address.toEndpoint(),
            );
            defer packets.deinit();

            msg_sent += packets.items.len;
            for (packets.items) |packet| try outgoing_channel.send(packet);
        }

        const packet_handle = try Thread.spawn(.{}, GossipService.run, .{
            &gossip_service, .{
                .spy_node = true, // dont build any outgoing messages
                .dump = false,
            },
        });

        // wait for all messages to be processed
        var timer = try std.time.Timer.start();

        gossip_service.shutdown();
        packet_handle.join();

        return timer.read();
    }
};

/// pull requests require some additional setup to work
pub const BenchmarkGossipServicePullRequests = struct {
    pub const min_iterations = 3;
    pub const max_iterations = 10;

    pub const BenchmarkArgs = struct {
        name: []const u8 = "",
        n_data_populated: usize,
        n_pull_requests: usize,
    };

    pub const args = [_]BenchmarkArgs{
        .{
            .name = "1k_data_1k_pull_reqs",
            .n_data_populated = 1_000,
            .n_pull_requests = 1_000,
        },
        .{
            .name = "10k_data_1k_pull_reqs",
            .n_data_populated = 10_000,
            .n_pull_requests = 1_000,
        },
    };

    pub fn benchmarkPullRequests(bench_args: BenchmarkArgs) !usize {
        const allocator = std.heap.c_allocator;
        var keypair = try KeyPair.create(null);
        var address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8888);

        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        var contact_info = ContactInfo.init(allocator, pubkey, 0, 19);
        try contact_info.setSocket(.gossip, address);

        // var logger = Logger.init(allocator, .debug);
        // defer logger.deinit();
        // logger.spawn();

        const logger: Logger = .noop;

        // process incoming packets/messsages
        var counter = Atomic(usize).init(0);
        var gossip_service = try GossipService.init(
            allocator,
            allocator,
            contact_info,
            keypair,
            null,
            &counter,
            logger,
        );
        gossip_service.echo_server.kill(); // we dont need this rn
        defer {
            gossip_service.stats.reset();
            gossip_service.deinit();
        }

        // setup recv peer
        const recv_address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8889);
        var recv_keypair = try KeyPair.create(null);
        const recv_pubkey = Pubkey.fromPublicKey(&recv_keypair.public_key);

        var contact_info_recv = ContactInfo.init(allocator, recv_pubkey, 0, 19);
        try contact_info_recv.setSocket(.gossip, recv_address);
        const signed_contact_info_recv = try SignedGossipData.initSigned(.{
            .ContactInfo = contact_info_recv,
        }, &recv_keypair);

        const now = getWallclockMs();
        var random = std.rand.DefaultPrng.init(19);
        const rng = random.random();

        {
            var ping_cache_rw = gossip_service.ping_cache_rw;
            var ping_cache_lock = ping_cache_rw.write();
            var ping_cache: *PingCache = ping_cache_lock.mut();
            ping_cache._setPong(recv_pubkey, recv_address);
            ping_cache_lock.unlock();
        }

        {
            var table_lock = gossip_service.gossip_table_rw.write();
            var table: *GossipTable = table_lock.mut();
            // insert contact info of pull request
            _ = try table.insert(signed_contact_info_recv, now);
            // insert all other values
            for (0..bench_args.n_data_populated) |_| {
                const value = try SignedGossipData.random(rng, &recv_keypair);
                _ = try table.insert(value, now);
            }
            table_lock.unlock();
        }

        const outgoing_channel = gossip_service.packet_incoming_channel;

        // generate messages
        for (0..bench_args.n_pull_requests) |_| {
            const packet = try fuzz_service.randomPullRequestWithContactInfo(
                allocator,
                rng,
                address.toEndpoint(),
                signed_contact_info_recv,
            );

            try outgoing_channel.send(packet);
        }

        const packet_handle = try Thread.spawn(.{}, GossipService.run, .{
            &gossip_service, .{
                .spy_node = true, // dont build any outgoing messages
                .dump = false,
            },
        });

        var timer = try std.time.Timer.start();

        // wait for all messages to be processed
        gossip_service.shutdown();
        packet_handle.join();

        return timer.read();
    }
};

fn localhostTestContactInfo(id: Pubkey) !ContactInfo {
    comptime std.debug.assert(@import("builtin").is_test); // should only be used for testin
    var contact_info = try LegacyContactInfo.default(id).toContactInfo(std.testing.allocator);
    try contact_info.setSocket(.gossip, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0));
    return contact_info;
}
