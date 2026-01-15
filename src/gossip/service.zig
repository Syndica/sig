const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

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

const Bloom = sig.bloom.Bloom;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Packet = sig.net.Packet;
const EchoServer = sig.net.echo.Server;
const SocketAddr = sig.net.SocketAddr;
const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const Histogram = sig.prometheus.Histogram;
const GetMetricError = sig.prometheus.registry.GetMetricError;
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
const PruneData = sig.gossip.PruneData;
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
const ExitCondition = sig.sync.ExitCondition;
const SocketThread = sig.net.SocketThread;

const endpointToString = sig.net.endpointToString;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.time.getWallclockMs;
const deinitMux = sig.sync.mux.deinitMux;

const PACKET_DATA_SIZE = Packet.DATA_SIZE;
const UNIQUE_PUBKEY_CAPACITY = sig.gossip.table.UNIQUE_PUBKEY_CAPACITY;
const MAX_NUM_PULL_REQUESTS = sig.gossip.pull_request.MAX_NUM_PULL_REQUESTS;

const Logger = sig.trace.log.Logger("gossip.service");
const GossipMessageWithEndpoint = struct { from_endpoint: EndPoint, message: GossipMessage };

pub const PULL_REQUEST_RATE: Duration = .fromSecs(1);
pub const PULL_RESPONSE_TIMEOUT: Duration = .fromSecs(5);
pub const ACTIVE_SET_REFRESH_RATE: Duration = .fromSecs(15);
pub const DATA_TIMEOUT: Duration = .fromSecs(15);
pub const TABLE_TRIM_RATE: Duration = .fromSecs(10);
pub const BUILD_MESSAGE_LOOP_MIN: Duration = .fromSecs(1);
pub const PUBLISH_STATS_INTERVAL: Duration = .fromSecs(2);

pub const PUSH_MSG_TIMEOUT: Duration = .fromSecs(30);
pub const PRUNE_MSG_TIMEOUT: Duration = .fromMillis(500);
pub const FAILED_INSERTS_RETENTION: Duration = .fromSecs(20);
pub const PURGED_RETENTION: Duration = .mul(PULL_REQUEST_RATE, 5);

// 4 (enum) + 32 (pubkey) + 8 (len) = 44
pub const MAX_PUSH_MESSAGE_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;

pub const MAX_NUM_VALUES_PER_PULL_RESPONSE = 20; // TODO: this is approx the rust one -- should tune
pub const NUM_ACTIVE_SET_ENTRIES: usize = 25;
/// Maximum number of origin nodes that a PruneData may contain, such that the
/// serialized size of the PruneMessage stays below PACKET_DATA_SIZE.
pub const MAX_PRUNE_DATA_NODES: usize = 32;

pub const PING_CACHE_CAPACITY: usize = 65_536;
pub const PING_CACHE_TTL: Duration = .fromSecs(1280);
pub const PING_CACHE_RATE_LIMIT_DELAY: Duration = .fromSecs(1280 / 64);

// TODO: replace with get_epoch_duration when BankForks is supported
const DEFAULT_EPOCH_DURATION: Duration = .fromMillis(172_800_000);

pub const VERIFY_PACKET_PARALLEL_TASKS = 4;
const THREAD_POOL_SIZE = 4;
const MAX_PROCESS_BATCH_SIZE = 64;
const GOSSIP_PRNG_SEED = 19;

/// The flow of data goes as follows:
///
/// `SocketThread.initReceiver` ->
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
///  `SocketThread.initSender` ->
///         - receives from `packet_outgoing_channel`
///         - sends the outgoing packet onto the gossip socket
///         - repeats while `exit` is false and `packet_outgoing_channel`
///         - when `SocketThread` sees that `exit` has become `true`, it will begin waiting on
///           the previous thing in the chain to close, that usually being `processMessages`.
///           this ensures that `processMessages` doesn't add new items to `packet_outgoing_channel`
///           after the `SocketThread` exits.
///
pub const GossipService = struct {
    /// used for general allocation purposes
    allocator: std.mem.Allocator,
    /// used specifically to allocate the gossip values
    gossip_data_allocator: std.mem.Allocator,

    gossip_socket: UdpSocket,
    /// This contact info is mutated by the buildMessages thread (specifically, .shred_version and .wallclock),
    /// so it must only be read by that thread, or it needs a synchronization mechanism.
    my_contact_info: ContactInfo,
    my_keypair: KeyPair,
    my_pubkey: Pubkey,
    my_shred_version: Atomic(u16),

    /// An atomic counter for ensuring proper exit order of tasks.
    exit_counter: *Atomic(u64),
    /// Indicates if the gossip service is closed.
    closed: bool,

    /// Piping data between the gossip_socket and the channels.
    /// Set to null until start() is called as they represent threads.
    incoming_socket_thread: ?*SocketThread = null,
    outgoing_socket_thread: ?*SocketThread = null,

    /// communication between threads
    packet_incoming_channel: *Channel(Packet),
    packet_outgoing_channel: *Channel(Packet),
    verified_incoming_channel: *Channel(GossipMessageWithEndpoint),

    /// table to store gossip values
    gossip_table_rw: RwMux(GossipTable),
    /// manages push message peers
    active_set_rw: RwMux(ActiveSet),
    /// all gossip data pushed into this will have its wallclock overwritten during `drainPushQueueToGossipTable`.
    /// NOTE: for all messages appended to this queue, the memory ownership is transfered to this struct.
    push_msg_queue_mux: PushMessageQueue,
    /// hashes of failed gossip values from pull responses
    failed_pull_hashes_mux: Mux(HashTimeQueue),

    /// entrypoint peers to start the process of discovering the network
    entrypoints: []Entrypoint,
    /// manages ping/pong heartbeats for the network
    ping_cache_rw: RwMux(PingCache),
    /// Only used to generate tokens for the `PingCache`; should only be accessed
    /// on the same thread as `ping_cache_rw` is locked.
    ping_token_prng: std.Random.Xoshiro256,

    thread_pool: ThreadPool,
    // TODO: fix when http server is working
    // echo_server: EchoServer,
    logger: Logger,
    metrics: GossipMetrics,
    service_manager: ServiceManager,

    /// Communication with other validator components
    broker: LocalMessageBroker,

    pub const PushMessageQueue = Mux(struct {
        queue: ArrayList(GossipData),
        data_allocator: std.mem.Allocator,
    });
    const Entrypoint = struct { addr: SocketAddr, info: ?ContactInfo = null };

    pub fn create(
        /// Must be thread-safe.
        allocator: std.mem.Allocator,
        /// Can be supplied as a different allocator in order to reduce contention.
        /// Must be thread safe.
        gossip_data_allocator: std.mem.Allocator,
        my_contact_info: ContactInfo,
        my_keypair: KeyPair,
        maybe_entrypoints: ?[]const SocketAddr,
        logger: Logger,
        broker: LocalMessageBroker,
    ) !*GossipService {
        const self = try allocator.create(GossipService);
        self.* = try GossipService.init(
            allocator,
            gossip_data_allocator,
            my_contact_info,
            my_keypair,
            maybe_entrypoints,
            .from(logger),
            broker,
        );
        return self;
    }

    pub fn init(
        /// Must be thread-safe.
        allocator: std.mem.Allocator,
        /// Can be supplied as a different allocator in order to reduce contention.
        /// Must be thread safe.
        gossip_data_allocator: std.mem.Allocator,
        /// Shallow copied / ownership transferred
        my_contact_info: ContactInfo,
        my_keypair: KeyPair,
        maybe_entrypoints: ?[]const SocketAddr,
        logger: Logger,
        broker: LocalMessageBroker,
    ) !GossipService {
        // setup channels for communication between threads
        const packet_incoming_channel: *Channel(Packet) = try .create(allocator);
        errdefer packet_incoming_channel.destroy();
        packet_incoming_channel.name = "gossip packet incoming channel";

        const packet_outgoing_channel: *Channel(Packet) = try .create(allocator);
        errdefer packet_outgoing_channel.destroy();
        packet_outgoing_channel.name = "gossip packet outgoing channel";

        const verified_incoming_channel: *Channel(GossipMessageWithEndpoint) = try .create(allocator);
        errdefer verified_incoming_channel.destroy();
        verified_incoming_channel.name = "gossip verified incoming channel";

        // setup the socket (bind with read-timeout)
        const gossip_address = my_contact_info.getSocket(.gossip) orelse return error.GossipAddrUnspecified;
        var gossip_socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
        gossip_socket.bindToPort(gossip_address.port()) catch return error.SocketBindFailed;
        gossip_socket.setReadTimeout(socket_utils.SOCKET_TIMEOUT_US) catch return error.SocketSetTimeoutFailed; // 1 second

        // setup the threadpool for processing messages
        const n_threads: usize = @min(std.Thread.getCpuCount() catch 1, THREAD_POOL_SIZE);
        logger.info().logf("starting threadpool with {} threads", .{n_threads});

        // setup the table
        var gossip_table = try GossipTable.init(allocator, gossip_data_allocator);
        errdefer gossip_table.deinit();

        // setup entrypoints
        const entrypoints: []Entrypoint = entrypoints: {
            const entrypoint_addrs = maybe_entrypoints orelse break :entrypoints &.{};

            const entrypoints = try allocator.alloc(Entrypoint, entrypoint_addrs.len);
            errdefer allocator.free(entrypoints);

            for (entrypoint_addrs, entrypoints) |addr, *entrypoint| {
                entrypoint.* = .{ .addr = addr };
            }

            break :entrypoints entrypoints;
        };
        errdefer allocator.free(entrypoints);

        // setup ping/pong cache
        var ping_cache = try PingCache.init(
            allocator,
            PING_CACHE_TTL,
            PING_CACHE_RATE_LIMIT_DELAY,
            PING_CACHE_CAPACITY,
        );
        errdefer ping_cache.deinit();

        const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

        var failed_pull_hashes = HashTimeQueue.init(allocator);
        errdefer failed_pull_hashes.deinit();

        const metrics = try GossipMetrics.init();

        const exit_counter = try allocator.create(Atomic(u64));
        errdefer allocator.destroy(exit_counter);
        exit_counter.* = Atomic(u64).init(0);

        const exit = try allocator.create(Atomic(bool));
        errdefer allocator.destroy(exit);
        exit.* = Atomic(bool).init(false);

        var service_manager = ServiceManager.init(allocator, .from(logger), exit, "gossip", .{});
        errdefer service_manager.deinit();

        return .{
            .allocator = allocator,
            .gossip_data_allocator = gossip_data_allocator,
            .my_contact_info = my_contact_info,
            .my_keypair = my_keypair,
            .my_pubkey = my_pubkey,
            .my_shred_version = .init(my_contact_info.shred_version),
            .gossip_socket = gossip_socket,
            .packet_incoming_channel = packet_incoming_channel,
            .packet_outgoing_channel = packet_outgoing_channel,
            .verified_incoming_channel = verified_incoming_channel,
            .gossip_table_rw = .init(gossip_table),
            .push_msg_queue_mux = .init(.{
                .queue = .init(allocator),
                .data_allocator = gossip_data_allocator,
            }),
            .active_set_rw = .init(.init(allocator)),
            .failed_pull_hashes_mux = .init(failed_pull_hashes),
            .entrypoints = entrypoints,
            .ping_cache_rw = .init(ping_cache),
            .ping_token_prng = .init(GOSSIP_PRNG_SEED),
            .logger = .from(logger),
            .thread_pool = .init(.{
                .max_threads = @intCast(n_threads),
                .stack_size = 2 * 1024 * 1024,
            }),
            .metrics = metrics,
            .exit_counter = exit_counter,
            .service_manager = service_manager,
            .closed = false,
            .broker = broker,
        };
    }

    /// Starts the shutdown chain for all services. Does *not* block until
    /// the service manager is joined.
    pub fn shutdown(self: *GossipService) void {
        std.debug.assert(!self.closed);
        defer self.closed = true;

        // kick off the shutdown chain
        self.exit_counter.store(1, .release);
        // exit the service manager loops when methods return
        self.service_manager.exit.store(true, .release);
    }

    pub fn deinit(self: *GossipService) void {
        std.debug.assert(self.closed); // call `self.shutdown()` first

        // wait for all threads to shutdown correctly
        self.service_manager.deinit();

        // Wait for pipes to shutdown if any
        if (self.incoming_socket_thread) |thread| thread.join();
        if (self.outgoing_socket_thread) |thread| thread.join();

        // assert the channels are empty in order to make sure no data was lost.
        // everything should be cleaned up when the thread-pool joins.
        std.debug.assert(self.packet_incoming_channel.isEmpty());
        self.packet_incoming_channel.destroy();

        std.debug.assert(self.packet_outgoing_channel.isEmpty());
        self.packet_outgoing_channel.destroy();

        std.debug.assert(self.verified_incoming_channel.isEmpty());
        self.verified_incoming_channel.destroy();

        self.gossip_socket.close();

        self.thread_pool.shutdown();
        self.thread_pool.deinit();

        self.allocator.destroy(self.exit_counter);
        self.allocator.destroy(self.service_manager.exit);

        self.allocator.free(self.entrypoints);
        self.my_contact_info.deinit();
        deinitMux(&self.gossip_table_rw);
        deinitMux(&self.active_set_rw);
        deinitMux(&self.ping_cache_rw);
        deinitMux(&self.failed_pull_hashes_mux);

        {
            // clear and deinit the push quee
            const push_msg_queue, var lock = self.push_msg_queue_mux.writeWithLock();
            defer lock.unlock();
            for (push_msg_queue.queue.items) |*v| v.deinit(push_msg_queue.data_allocator);
            push_msg_queue.queue.deinit();
        }
    }

    pub const RunThreadsParams = struct {
        spy_node: bool = false,
        dump: bool = false,
    };

    /// starts gossip and blocks until it exits (which can be signaled by calling `shutdown`)
    pub fn run(self: *GossipService, params: RunThreadsParams) !void {
        try self.start(params);
        self.service_manager.join();
    }

    /// spawns required threads for the gossip service and returns immediately
    /// including:
    ///     1) socket reciever
    ///     2) packet verifier
    ///     3) packet processor
    ///     4) build message loop (to send outgoing message) (if a spy node, not active)
    ///     5) a socket responder (to send outgoing packets)
    pub fn start(
        self: *GossipService,
        params: RunThreadsParams,
    ) !void {
        // NOTE: this is stack copied on each spawn() call below so we can modify it without
        // affecting other threads
        var exit_condition = sig.sync.ExitCondition{
            .ordered = .{
                .exit_counter = self.exit_counter,
                .exit_index = 1,
            },
        };

        self.incoming_socket_thread = try SocketThread.spawnReceiver(
            self.allocator,
            .from(self.logger),
            self.gossip_socket,
            self.packet_incoming_channel,
            exit_condition,
            .empty,
        );
        exit_condition.ordered.exit_index += 1;

        try self.service_manager.spawn("[gossip] verifyPackets", verifyPackets, .{
            self,
            exit_condition,
        });
        exit_condition.ordered.exit_index += 1;

        try self.service_manager.spawn("[gossip] processMessages", processMessages, .{
            self,
            GOSSIP_PRNG_SEED,
            exit_condition,
        });
        exit_condition.ordered.exit_index += 1;

        if (!params.spy_node) {
            try self.service_manager.spawn("[gossip] buildMessages", buildMessages, .{
                self,
                GOSSIP_PRNG_SEED,
                exit_condition,
            });
            exit_condition.ordered.exit_index += 1;
        }

        self.outgoing_socket_thread = try SocketThread.spawnSender(
            self.allocator,
            .from(self.logger),
            self.gossip_socket,
            self.packet_outgoing_channel,
            exit_condition,
            .empty,
        );
        exit_condition.ordered.exit_index += 1;

        if (params.dump) {
            try self.service_manager.spawn("[gossip] dumpService", GossipDumpService.run, .{
                GossipDumpService{
                    .allocator = self.allocator,
                    .logger = self.logger.withScope(@typeName(GossipDumpService)),
                    .gossip_table_rw = &self.gossip_table_rw,
                    .exit_condition = exit_condition,
                },
            });
            exit_condition.ordered.exit_index += 1;
        }
    }

    fn verifyMessage(
        allocator: std.mem.Allocator,
        logger: Logger,
        packet: *const Packet,
    ) error{ DeserializeFail, SanitizeFail, VerifyFail }!GossipMessage {
        const message = bincode.readFromSlice(
            allocator,
            GossipMessage,
            packet.data(),
            .standard,
        ) catch |e| {
            logger.err().logf("packet_verify: failed to deserialize: {s}", .{@errorName(e)});
            return error.DeserializeFail;
        };
        errdefer bincode.free(allocator, message);

        message.sanitize() catch |e| {
            logger.err().logf("packet_verify: failed to sanitize: {s}", .{@errorName(e)});
            return error.SanitizeFail;
        };

        message.verifySignature() catch |e| {
            logger.err().logf(
                "packet_verify: failed to verify signature from {}: {s}",
                .{ packet.addr, @errorName(e) },
            );
            return error.VerifyFail;
        };

        return message;
    }

    /// main logic for deserializing Packets into GossipMessage messages
    /// and verifing they have valid values, and have valid signatures.
    /// Verified GossipMessagemessages are then sent to the verified_channel.
    fn verifyPackets(self: *GossipService, exit_condition: ExitCondition) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "gossip verifyPackets" });
        defer zone.deinit();

        defer {
            // empty the channel
            while (self.packet_incoming_channel.tryReceive()) |_| {}
            // trigger the next service in the chain to close
            exit_condition.afterExit();
            self.logger.debug().log("verifyPackets loop closed");
        }

        // loop until the previous service closes and triggers us to close
        while (true) {
            self.packet_incoming_channel.waitToReceive(exit_condition) catch break;

            const zone_inner = tracy.Zone.init(@src(), .{ .name = "gossip verifyPackets: receiving" });
            defer zone_inner.deinit();

            // TODO: investigate doing verifyPacket in parallel using self.thread_pool.
            while (self.packet_incoming_channel.tryReceive()) |packet| {
                defer self.metrics.gossip_packets_received_total.inc();

                const message = verifyMessage(
                    self.gossip_data_allocator,
                    self.logger,
                    &packet,
                ) catch |err| switch (err) {
                    error.DeserializeFail, error.SanitizeFail, error.VerifyFail => continue,
                };
                errdefer bincode.free(self.gossip_data_allocator, message);
                try self.verified_incoming_channel.send(.{
                    .from_endpoint = packet.addr,
                    .message = message,
                });
            }
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
    pub fn processMessages(self: *GossipService, seed: u64, exit_condition: ExitCondition) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "gossip processMessages" });
        defer zone.deinit();

        defer {
            // empty the channel and release the memory
            while (self.verified_incoming_channel.tryReceive()) |message| {
                bincode.free(self.gossip_data_allocator, message.message);
            }
            // even if we fail, trigger the next thread to close
            exit_condition.afterExit();
            self.logger.debug().log("processMessages loop closed");
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

        var received_messages = std.SegmentedList(GossipMessageWithEndpoint, 0){};
        defer received_messages.deinit(self.allocator);

        var trim_table_timer = sig.time.Timer.start();

        // keep waiting for new data until,
        // - `exit` isn't set,
        // - there isn't any data to process in the input channel, in order to block the join until we've finished
        while (true) {
            self.verified_incoming_channel.waitToReceive(exit_condition) catch break;

            var msg_count: usize = 0;
            while (self.verified_incoming_channel.tryReceive()) |msg| {
                msg_count += 1;

                // references to the message are stored in ArrayLists that escape this while loop
                // so store the message in a local list with stable pointers across append()s.
                const message = try received_messages.addOne(self.allocator);
                message.* = msg;

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
                        var should_drop = false;
                        switch (value.data) {
                            .ContactInfo => |*data| {
                                if (data.pubkey.equals(&self.my_pubkey)) {
                                    // talking to myself == ignore
                                    should_drop = true;
                                }
                                // Allow spy nodes with shred-verion == 0 to pull from other nodes.
                                if (data.shred_version != 0 and data.shred_version != self.my_shred_version.load(.monotonic)) {
                                    // non-matching shred version
                                    self.metrics.pull_requests_dropped.add(1);
                                    should_drop = true;
                                }
                            },
                            .LegacyContactInfo => |*data| {
                                if (data.id.equals(&self.my_pubkey)) {
                                    // talking to myself == ignore
                                    should_drop = true;
                                }
                                // Allow spy nodes with shred-verion == 0 to pull from other nodes.
                                if (data.shred_version != 0 and data.shred_version != self.my_shred_version.load(.monotonic)) {
                                    // non-matching shred version
                                    self.metrics.pull_requests_dropped.add(1);
                                    should_drop = true;
                                }
                            },
                            // only contact info supported
                            else => {
                                self.metrics.pull_requests_dropped.add(1);
                                should_drop = true;
                            },
                        }

                        const from_addr = SocketAddr.fromEndpoint(&message.from_endpoint);
                        if (from_addr.isUnspecified() or from_addr.port() == 0) {
                            // unable to respond to these messages
                            self.metrics.pull_requests_dropped.add(1);
                            should_drop = true;
                        }

                        if (should_drop) {
                            pull[0].deinit();
                            value.deinit(self.gossip_data_allocator);
                        } else {
                            try pull_requests.append(.{
                                .filter = pull[0],
                                .value = value,
                                .from_endpoint = message.from_endpoint,
                            });
                        }
                    },
                    .PruneMessage => |*prune| {
                        const prune_data = prune[1];
                        const now = getWallclockMs();
                        const prune_wallclock = prune_data.wallclock;

                        const too_old = prune_wallclock < now -| PRUNE_MSG_TIMEOUT.asMillis();
                        const incorrect_destination = !prune_data.destination.equals(&self.my_pubkey);
                        if (too_old or incorrect_destination) {
                            self.metrics.prune_messages_dropped.add(1);
                            prune_data.deinit(self.gossip_data_allocator);
                            continue;
                        }
                        try prune_messages.append(prune_data);
                    },
                    .PingMessage => |*ping| {
                        const from_addr = SocketAddr.fromEndpoint(&message.from_endpoint);
                        if (from_addr.isUnspecified() or from_addr.port() == 0) {
                            // unable to respond to these messages
                            self.metrics.ping_messages_dropped.add(1);
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
            self.metrics.gossip_packets_verified_total.add(msg_count);
            self.metrics.ping_messages_recv.add(ping_messages.items.len);
            self.metrics.pong_messages_recv.add(pong_messages.items.len);
            self.metrics.push_messages_recv.add(push_messages.items.len);
            self.metrics.pull_requests_recv.add(pull_requests.items.len);
            self.metrics.pull_responses_recv.add(pull_responses.items.len);
            self.metrics.prune_messages_recv.add(prune_messages.items.len);

            var gossip_packets_processed_total: usize = 0;
            gossip_packets_processed_total += ping_messages.items.len;
            gossip_packets_processed_total += pong_messages.items.len;
            gossip_packets_processed_total += push_messages.items.len;
            gossip_packets_processed_total += pull_requests.items.len;
            gossip_packets_processed_total += pull_responses.items.len;
            gossip_packets_processed_total += prune_messages.items.len;

            // only add the count once we've finished processing
            defer self.metrics.gossip_packets_processed_total.add(gossip_packets_processed_total);

            // handle batch messages
            const batch_handle_zone = tracy.Zone.init(
                @src(),
                .{ .name = "gossip processMessages - handle batch messages" },
            );
            defer batch_handle_zone.deinit();
            batch_handle_zone.value(msg_count);

            if (push_messages.items.len > 0) {
                var x_timer = sig.time.Timer.start();
                self.handleBatchPushMessages(&push_messages) catch |err| {
                    self.logger.err().logf("handleBatchPushMessages failed: {}", .{err});
                };
                const elapsed = x_timer.read().asMillis();
                self.metrics.handle_batch_push_time.observe(elapsed);

                for (push_messages.items) |push| {
                    // NOTE: this just frees the slice of values, not the values themselves
                    // (which were either inserted into the store, or freed)
                    self.gossip_data_allocator.free(push.gossip_values);
                }
                push_messages.clearRetainingCapacity();
            }

            if (prune_messages.items.len > 0) {
                var x_timer = sig.time.Timer.start();
                self.handleBatchPruneMessages(&prune_messages);
                const elapsed = x_timer.read().asMillis();
                self.metrics.handle_batch_prune_time.observe(elapsed);

                for (prune_messages.items) |prune| {
                    prune.deinit(self.gossip_data_allocator);
                }
                prune_messages.clearRetainingCapacity();
            }

            if (pull_requests.items.len > 0) {
                var x_timer = sig.time.Timer.start();
                self.handleBatchPullRequest(seed + msg_count, pull_requests.items) catch |err| {
                    self.logger.err().logf("handleBatchPullRequest failed: {}", .{err});
                };
                const elapsed = x_timer.read().asMillis();
                self.metrics.handle_batch_pull_req_time.observe(elapsed);

                for (pull_requests.items) |*req| {
                    // NOTE: the contact info (req.value) is inserted into the gossip table
                    // so we only free the filter
                    req.filter.deinit();
                }
                pull_requests.clearRetainingCapacity();
            }

            if (pull_responses.items.len > 0) {
                var x_timer = sig.time.Timer.start();
                self.handleBatchPullResponses(pull_responses.items) catch |err| {
                    self.logger.err().logf("handleBatchPullResponses failed: {}", .{err});
                };
                const elapsed = x_timer.read().asMillis();
                self.metrics.handle_batch_pull_resp_time.observe(elapsed);

                for (pull_responses.items) |*pull| {
                    // NOTE: this just frees the slice of values, not the values themselves
                    // (which were either inserted into the store, or freed)
                    self.gossip_data_allocator.free(pull.gossip_values);
                }
                pull_responses.clearRetainingCapacity();
            }

            if (ping_messages.items.len > 0) {
                var x_timer = sig.time.Timer.start();
                self.handleBatchPingMessages(&ping_messages) catch |err| {
                    self.logger.err().logf("handleBatchPingMessages failed: {}", .{err});
                };
                const elapsed = x_timer.read().asMillis();
                self.metrics.handle_batch_ping_time.observe(elapsed);

                ping_messages.clearRetainingCapacity();
            }

            if (pong_messages.items.len > 0) {
                var x_timer = sig.time.Timer.start();
                self.handleBatchPongMessages(&pong_messages);
                const elapsed = x_timer.read().asMillis();
                self.metrics.handle_batch_pong_time.observe(elapsed);

                pong_messages.clearRetainingCapacity();
            }

            if (received_messages.count() > 0) {
                received_messages.clearRetainingCapacity();
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
    pub fn attemptGossipTableTrim(self: *GossipService) !void {
        // first check with a read lock
        const should_trim = blk: {
            const gossip_table, var gossip_table_lock = self.gossip_table_rw.readWithLock();
            defer gossip_table_lock.unlock();

            const should_trim = gossip_table.shouldTrim(UNIQUE_PUBKEY_CAPACITY);
            break :blk should_trim;
        };

        // then trim with write lock
        const n_pubkeys_dropped: u64 = if (should_trim) blk: {
            const gossip_table, var gossip_table_lock = self.gossip_table_rw.writeWithLock();
            defer gossip_table_lock.unlock();

            var x_timer = sig.time.Timer.start();
            const now = getWallclockMs();
            const n_pubkeys_dropped = gossip_table.attemptTrim(now, UNIQUE_PUBKEY_CAPACITY) catch |err| err_blk: {
                self.logger.err().logf("gossip_table.attemptTrim failed: {s}", .{@errorName(err)});
                break :err_blk 0;
            };
            const elapsed = x_timer.read().asMillis();
            self.metrics.handle_trim_table_time.observe(elapsed);

            break :blk n_pubkeys_dropped;
        } else 0;

        self.metrics.table_pubkeys_dropped.add(n_pubkeys_dropped);
    }

    /// main gossip loop for periodically sending new GossipMessagemessages.
    /// this includes sending push messages, pull requests, and triming old
    /// gossip data (in the gossip_table, active_set, and failed_pull_hashes).
    fn buildMessages(self: *GossipService, seed: u64, exit_condition: ExitCondition) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "gossip buildMessages" });
        defer zone.deinit();

        defer {
            exit_condition.afterExit();
            self.logger.info().log("buildMessages loop closed");
        }

        var loop_timer = sig.time.Timer.start();
        var active_set_timer = sig.time.Timer.start();
        var pull_req_timer = sig.time.Timer.start();
        var stats_publish_timer = sig.time.Timer.start();
        var trim_memory_timer = sig.time.Timer.start();

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        var push_cursor: u64 = 0;
        var entrypoints_identified = false;
        var shred_version_assigned = false;

        while (exit_condition.shouldRun()) {
            defer loop_timer.reset();

            if (pull_req_timer.read().asNanos() > PULL_REQUEST_RATE.asNanos()) pull_blk: {
                defer pull_req_timer.reset();
                // this also includes sending ping messages to other peers
                const now = getWallclockMs();
                const pull_req_packets = self.buildPullRequests(
                    random,
                    pull_request.MAX_BLOOM_SIZE,
                    now,
                ) catch |e| {
                    self.logger.err().logf("failed to generate pull requests: {any}", .{e});
                    break :pull_blk;
                };
                defer pull_req_packets.deinit();
                for (pull_req_packets.items) |packet| {
                    try self.packet_outgoing_channel.send(packet);
                }
                self.metrics.pull_requests_sent.add(pull_req_packets.items.len);
            }

            // new push msgs
            try self.drainPushQueueToGossipTable(getWallclockMs());
            const maybe_push_packets = self.buildPushMessages(&push_cursor) catch |e| blk: {
                self.logger.err().logf(
                    "failed to generate push messages: {any}\n{any}",
                    .{ e, @errorReturnTrace() },
                );
                break :blk null;
            };
            if (maybe_push_packets) |push_packets| {
                defer push_packets.deinit();
                self.metrics.push_messages_sent.add(push_packets.items.len);
                for (push_packets.items) |push_packet| {
                    try self.packet_outgoing_channel.send(push_packet);
                }
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

                // push contact info
                {
                    var push_msg_queue, var push_msg_queue_lock = self.push_msg_queue_mux.writeWithLock();
                    defer push_msg_queue_lock.unlock();

                    // NOTE: wallclock is updated when draining the push_msg_queue
                    // in drainPushQueueToGossipTable
                    const contact_info: ContactInfo = try self.my_contact_info.clone();
                    errdefer contact_info.deinit();

                    const legacy_contact_info = LegacyContactInfo.fromContactInfo(
                        &contact_info,
                    );

                    try push_msg_queue.queue.appendSlice(&.{
                        .{ .ContactInfo = contact_info },
                        .{ .LegacyContactInfo = legacy_contact_info },
                    });
                }

                try self.rotateActiveSet(random);
            }

            // publish metrics
            if (stats_publish_timer.read().asNanos() > PUBLISH_STATS_INTERVAL.asNanos()) {
                defer stats_publish_timer.reset();
                try self.collectGossipTableMetrics();
            }

            // sleep
            if (loop_timer.read().asNanos() < BUILD_MESSAGE_LOOP_MIN.asNanos()) {
                const time_left_ms = BUILD_MESSAGE_LOOP_MIN.asMillis() -| loop_timer.read().asMillis();
                std.Thread.sleep(time_left_ms * std.time.ns_per_ms);
            }
        }
    }

    // collect gossip table metrics and pushes them to stats
    pub fn collectGossipTableMetrics(self: *GossipService) !void {
        const gossip_table, var gossip_table_lg = self.gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        const n_entries = gossip_table.store.count();
        const n_pubkeys = gossip_table.pubkey_to_values.count();

        self.metrics.table_n_values.set(n_entries);
        self.metrics.table_n_pubkeys.set(n_pubkeys);

        const incoming_channel_length = self.packet_incoming_channel.len();
        self.metrics.incoming_channel_length.set(incoming_channel_length);

        const outgoing_channel_length = self.packet_outgoing_channel.len();
        self.metrics.outgoing_channel_length.set(outgoing_channel_length);

        self.metrics.verified_channel_length.set(self.verified_incoming_channel.len());
    }

    pub fn rotateActiveSet(self: *GossipService, random: std.Random) !void {
        const now = getWallclockMs();
        var buf: [NUM_ACTIVE_SET_ENTRIES]ThreadSafeContactInfo = undefined;
        const gossip_peers = try self.getThreadSafeGossipNodes(buf.len, &buf, now);

        // filter out peers who have responded to pings
        var valid_gossip_indexs, var pings_to_send_out = blk: {
            var ping_cache_lock = self.ping_cache_rw.write();
            defer ping_cache_lock.unlock();
            const ping_cache: *PingCache = ping_cache_lock.mut();

            const result = try ping_cache.filterValidPeers(self.allocator, random, self.my_keypair, gossip_peers);
            break :blk .{ result.valid_peers, result.pings };
        };
        defer valid_gossip_indexs.deinit(self.allocator);
        defer pings_to_send_out.deinit(self.allocator);

        var valid_gossip_peers: [NUM_ACTIVE_SET_ENTRIES]ThreadSafeContactInfo = undefined;
        for (
            valid_gossip_peers[0..valid_gossip_indexs.items.len],
            valid_gossip_indexs.items,
        ) |*valid_gossip_peer, valid_gossip_index| {
            valid_gossip_peer.* = gossip_peers[valid_gossip_index];
        }

        // send pings to peers
        try self.sendPings(pings_to_send_out.items);

        // reset push active set
        const active_set, var active_set_lg = self.active_set_rw.writeWithLock();
        defer active_set_lg.unlock();
        try active_set.initRotate(random, valid_gossip_peers[0..valid_gossip_indexs.items.len]);
    }

    /// logic for building new push messages which are sent to peers from the
    /// active set and serialized into packets.
    fn buildPushMessages(self: *GossipService, push_cursor: *u64) !ArrayList(Packet) {
        const zone = tracy.Zone.init(@src(), .{ .name = "gossip buildPushMessages" });
        defer zone.deinit();

        // TODO: find a better static value for the length?
        // NOTE: this size seems to work reasonably well given the rate of
        // cursor growth from new insertions and how fast we generate
        // push messages. if its too small, then our new contact infos may
        // not be pushed out which would cause things to break.
        var buf: [5000]GossipVersionedData = undefined;

        const start_cursor = push_cursor.*;
        // NOTE: the cursor is modified in getClonedEntriesWithCursor and will
        // be reset if the active_set.len == 0.
        defer self.metrics.gen_push_message_cursor_value.set(push_cursor.*);

        // find new values to push in gossip table
        const gossip_entries = blk: {
            var gossip_table_lock = self.gossip_table_rw.read();
            defer gossip_table_lock.unlock();

            const gossip_table: *const GossipTable = gossip_table_lock.get();
            self.metrics.table_cursor.set(gossip_table.cursor);

            break :blk try gossip_table.getClonedEntriesWithCursor(
                self.gossip_data_allocator,
                &buf,
                push_cursor,
            );
        };
        defer for (gossip_entries) |*ge| ge.deinit(self.gossip_data_allocator);

        var packet_batch = ArrayList(Packet).init(self.allocator);
        errdefer packet_batch.deinit();

        if (gossip_entries.len == 0) {
            return packet_batch;
        }

        // TODO: benchmark different approach of HashMapping(origin, value) first
        var push_messages = std.AutoHashMap(EndPoint, ArrayList(SignedGossipData)).init(self.allocator);
        defer {
            var push_iter = push_messages.iterator();
            while (push_iter.next()) |push_entry| {
                push_entry.value_ptr.deinit();
            }
            push_messages.deinit();
        }

        // derive the push msgs with a map : active_set_peer -> []new_gossip_data_messages
        // , accounting for prune messages per origin/endpoint
        {
            var active_set_lock = self.active_set_rw.read();
            var active_set: *const ActiveSet = active_set_lock.get();
            defer active_set_lock.unlock();

            const active_set_len = active_set.len();
            self.metrics.gen_push_message_active_set_len.set(active_set_len);

            if (active_set_len == 0) {
                // we have done nothing with the data, so reset the cursor
                // back to what it was originally
                push_cursor.* = start_cursor;
                return packet_batch;
            }

            const now = getWallclockMs();

            var n_values_sent: u64 = 0;
            var n_values_timeout: u64 = 0;
            var n_zero_active_set_count: u64 = 0;
            defer {
                self.metrics.gen_push_message_send_count.add(n_values_sent);
                self.metrics.gen_push_message_send_timeout_count.add(n_values_timeout);
                self.metrics.gen_push_message_zero_active_set_count.add(n_zero_active_set_count);
            }

            // NOTE: we have no limit on push message size so that
            // the push queue doesnt fall behind which would result in
            // our updated contact_info's not being propogated to the cluster.
            for (gossip_entries) |entry| {
                const value = entry.signedData();

                const entry_time = value.wallclock();
                const too_old = entry_time < now -| PUSH_MSG_TIMEOUT.asMillis();
                const too_new = entry_time > now +| PUSH_MSG_TIMEOUT.asMillis();
                if (too_old or too_new) {
                    n_values_timeout += 1;
                    continue;
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

                if (active_set_peers.items.len == 0) {
                    n_zero_active_set_count += 1;
                    continue;
                } else {
                    n_values_sent += 1;
                }

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
            }
        }

        var push_iter = push_messages.iterator();
        while (push_iter.next()) |push_entry| {
            const gossip_values: *const ArrayList(SignedGossipData) = push_entry.value_ptr;
            const to_endpoint: *const EndPoint = push_entry.key_ptr;

            // send the values as a push message packet
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
        self: *GossipService,
        random: std.Random,
        /// the bloomsize of the pull request's filters
        bloom_size: usize,
        now: u64,
    ) !ArrayList(Packet) {
        const zone = tracy.Zone.init(@src(), .{ .name = "gossip buildPullRequests" });
        defer zone.deinit();

        // get nodes from gossip table
        var buf: [MAX_NUM_PULL_REQUESTS]ThreadSafeContactInfo = undefined;
        const peers = try self.getThreadSafeGossipNodes(buf.len, &buf, now);

        // randomly include an entrypoint in the pull if we dont have their contact info
        const entrypoint_index: ?u15 = blk: {
            if (self.entrypoints.len == 0) break :blk null;
            const maybe_entrypoint_index = random.uintLessThan(u15, @intCast(self.entrypoints.len));
            if (self.entrypoints[maybe_entrypoint_index].info != null) {
                // early exit - we already have the peer in our contact info
                break :blk null;
            }

            // we dont have them so well add them to the peer list (as default contact info)
            break :blk maybe_entrypoint_index;
        };

        // filter out peers who have responded to pings
        var valid_gossip_peer_indexs, var pings_to_send_out = blk: {
            const ping_cache, var ping_cache_lg = self.ping_cache_rw.writeWithLock();
            defer ping_cache_lg.unlock();
            const result = try ping_cache.filterValidPeers(self.allocator, random, self.my_keypair, peers);
            break :blk .{ result.valid_peers, result.pings };
        };
        defer valid_gossip_peer_indexs.deinit(self.allocator);
        defer pings_to_send_out.deinit(self.allocator);

        try self.sendPings(pings_to_send_out.items);

        const num_peers = valid_gossip_peer_indexs.items.len;
        if (num_peers == 0 and entrypoint_index == null) {
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
            random,
            &self.gossip_table_rw,
            &failed_pull_hashes_array,
            bloom_size,
            MAX_NUM_PULL_REQUESTS,
        );
        defer pull_request.deinitGossipPullFilters(&filters);

        // build packet responses
        var n_packets: usize = 0;
        if (num_peers != 0) n_packets += filters.items.len;
        if (entrypoint_index != null) n_packets += filters.items.len;

        var packet_batch = try ArrayList(Packet).initCapacity(self.allocator, n_packets);
        packet_batch.appendNTimesAssumeCapacity(Packet.ANY_EMPTY, n_packets);
        var packet_index: usize = 0;

        // update wallclock and sign
        self.my_contact_info.wallclock = now;
        const my_contact_info_value = SignedGossipData.initSigned(
            &self.my_keypair,
            // safe to copy contact info since it is immediately serialized
            .{ .ContactInfo = self.my_contact_info },
        );

        if (num_peers != 0) {
            const my_shred_version = self.my_contact_info.shred_version;
            for (filters.items) |filter_i| {
                // TODO: incorperate stake weight in random sampling
                const peer_index = random.intRangeAtMost(usize, 0, num_peers - 1);
                const peer_contact_info_index = valid_gossip_peer_indexs.items[peer_index];
                const peer_contact_info = peers[peer_contact_info_index];
                if (peer_contact_info.shred_version != my_shred_version) {
                    continue;
                }
                if (peer_contact_info.gossip_addr) |gossip_addr| {
                    const message: GossipMessage = .{ .PullRequest = .{ filter_i, my_contact_info_value } };
                    var packet = &packet_batch.items[packet_index];

                    const bytes = try bincode.writeToSlice(&packet.buffer, message, bincode.Params{});
                    packet.size = bytes.len;
                    packet.addr = gossip_addr.toEndpoint();
                    packet_index += 1;
                }
            }
        }

        // append entrypoint msgs
        if (entrypoint_index) |entrypoint_idx| {
            const entrypoint = self.entrypoints[entrypoint_idx];
            for (filters.items) |filter| {
                const packet = &packet_batch.items[packet_index];
                const message: GossipMessage = .{ .PullRequest = .{ filter, my_contact_info_value } };
                try packet.populateFromBincode(entrypoint.addr, message);
                packet_index += 1;
            }
        }

        return packet_batch;
    }

    const PullRequestTask = struct {
        allocator: std.mem.Allocator,
        my_pubkey: *const Pubkey,
        from_endpoint: *const EndPoint,
        filter: *const GossipPullFilter,
        gossip_table: *const GossipTable,
        output: ArrayList(Packet),
        output_limit: *Atomic(i64),
        output_consumed: Atomic(bool) = Atomic(bool).init(false),
        seed: u64,

        task: Task,
        wg_done: *std.Thread.WaitGroup,

        pub fn deinit(this: *PullRequestTask) void {
            this.output.deinit();
        }

        pub fn callback(task: *Task) void {
            var self: *@This() = @fieldParentPtr("task", task);
            defer self.wg_done.finish();

            const output_limit = self.output_limit.load(.acquire);
            if (output_limit <= 0) {
                return;
            }

            var prng = std.Random.Xoshiro256.init(self.seed);
            const response_gossip_values = pull_response.filterSignedGossipDatas(
                prng.random(),
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
            defer packets.deinit();

            if (packets.items.len > 0) {
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
        self: *GossipService,
        seed: u64,
        pull_requests: []const PullRequestMessage,
    ) !void {
        // update the callers and free the values which are not inserted
        defer {
            var gossip_table, var lock = self.gossip_table_rw.writeWithLock();
            defer lock.unlock();

            const now = getWallclockMs();
            for (pull_requests) |*req| {
                gossip_table.updateRecordTimestamp(req.value.id(), now);
                const result = gossip_table.insert(req.value, now) catch {
                    @panic("gossip table insertion failed");
                };
                if (result == .fail) req.value.deinit(self.gossip_data_allocator);
            }
        }

        var valid_indices = blk: {
            const ping_cache, var lock = self.ping_cache_rw.writeWithLock();
            defer lock.unlock();

            var peers = try ArrayList(ThreadSafeContactInfo).initCapacity(self.allocator, pull_requests.len);
            defer peers.deinit();

            for (pull_requests) |*req| {
                const threads_safe_contact_info = switch (req.value.data) {
                    .ContactInfo => |ci| ThreadSafeContactInfo.fromContactInfo(ci),
                    .LegacyContactInfo => |legacy| ThreadSafeContactInfo.fromLegacyContactInfo(legacy),
                    else => return error.PullRequestWithoutContactInfo,
                };
                peers.appendAssumeCapacity(threads_safe_contact_info);
            }

            var result = try ping_cache.filterValidPeers(
                self.allocator,
                self.ping_token_prng.random(),
                self.my_keypair,
                peers.items,
            );
            defer result.pings.deinit(self.allocator);
            errdefer result.valid_peers.deinit(self.allocator);
            try self.sendPings(result.pings.items);

            break :blk result.valid_peers;
        };
        defer valid_indices.deinit(self.allocator);

        if (valid_indices.items.len == 0) {
            return;
        }

        // create the pull requests
        const n_valid_requests = valid_indices.items.len;
        const tasks = try self.allocator.alloc(PullRequestTask, n_valid_requests);
        defer {
            for (tasks) |*task| {
                // assert: tasks are always consumed in the last for-loop of this method
                std.debug.assert(task.output_consumed.load(.monotonic));
                task.deinit();
            }
            self.allocator.free(tasks);
        }

        {
            const gossip_table, var lock = self.gossip_table_rw.readWithLock();
            defer lock.unlock();

            var batch = Batch{};
            var wg = std.Thread.WaitGroup{};
            var output_limit = Atomic(i64).init(MAX_NUM_VALUES_PER_PULL_RESPONSE);

            for (valid_indices.items, 0..) |valid_index, task_index| {
                // create the thread task
                tasks[task_index] = PullRequestTask{
                    .task = .{ .callback = PullRequestTask.callback },
                    .wg_done = &wg,
                    .allocator = self.allocator,
                    .my_pubkey = &self.my_pubkey,
                    .gossip_table = gossip_table,
                    .output_limit = &output_limit,
                    .seed = seed + valid_index,
                    .output = ArrayList(Packet).init(self.allocator),
                    .from_endpoint = &pull_requests[valid_index].from_endpoint,
                    .filter = &pull_requests[valid_index].filter,
                };

                // prepare to run it.
                wg.start();
                batch.push(Batch.from(&tasks[task_index].task));
            }

            // Run all tasks and wait for them to complete
            self.thread_pool.schedule(batch);
            wg.wait();
        }

        for (tasks) |*task| {
            packet_loop: for (task.output.items) |output| {
                self.packet_outgoing_channel.send(output) catch {
                    self.logger.err().log("handleBatchPullRequest: failed to send outgoing packet");
                    break :packet_loop;
                };
                self.metrics.pull_responses_sent.add(1);
            }
            task.output_consumed.store(true, .release);
        }
    }

    pub fn handleBatchPongMessages(
        self: *GossipService,
        pong_messages: *const ArrayList(PongMessage),
    ) void {
        const now = std.time.Instant.now() catch @panic("time is not supported on the OS!");

        const ping_cache, var ping_cache_lg = self.ping_cache_rw.writeWithLock();
        defer ping_cache_lg.unlock();

        for (pong_messages.items) |*pong_message| {
            _ = ping_cache.receviedPong(
                pong_message.pong,
                SocketAddr.fromEndpoint(pong_message.from_endpoint),
                now,
            );
        }
    }

    pub fn handleBatchPingMessages(
        self: *GossipService,
        ping_messages: *const ArrayList(PingMessage),
    ) !void {
        for (ping_messages.items) |*ping_message| {
            const pong = try Pong.init(ping_message.ping, &self.my_keypair);
            const pong_message = GossipMessage{ .PongMessage = pong };

            var packet = Packet.ANY_EMPTY;
            const bytes_written = try bincode.writeToSlice(
                &packet.buffer,
                pong_message,
                bincode.Params.standard,
            );

            packet.size = bytes_written.len;
            packet.addr = ping_message.from_endpoint.*;

            const endpoint_str = try endpointToString(self.allocator, ping_message.from_endpoint);
            defer endpoint_str.deinit();

            try self.packet_outgoing_channel.send(packet);
            self.metrics.pong_messages_sent.add(1);
        }
    }

    /// logic for handling a pull response message.
    /// successful inserted values, have their origin value timestamps updated.
    /// failed inserts (ie, too old or duplicate values) are added to the failed pull hashes so that they can be
    /// included in the next pull request (so we dont receive them again).
    /// For all pull responses:
    ///     - PullResponseMessage.gossip_values are inserted into the gossip table or added to failed pull hashes and freed
    fn handleBatchPullResponses(
        self: *GossipService,
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
                const values_to_insert = self.filterBasedOnShredVersion(
                    gossip_table,
                    pull_message.gossip_values,
                    pull_message.from_pubkey.*,
                );
                const invalid_shred_count = full_len - values_to_insert.len;
                self.metrics.pull_response_n_invalid_shred_version.add(invalid_shred_count);

                for (values_to_insert) |*value| {
                    const result = try gossip_table.insert(value.*, now);
                    self.metrics.observeInsertResult(result);
                    switch (result) {
                        .success => {
                            const wallclock = value.wallclock();
                            const timeout = PULL_RESPONSE_TIMEOUT.asMillis();
                            // we can't trust this wallclock at all unless it's current
                            if (wallclock >= now -| timeout and wallclock <= now +| timeout) {
                                gossip_table.updateRecordTimestamp(value.id(), now);
                            }
                            try self.broker.publish(&value.data);
                        },
                        .fail => try failed_insert_ptrs.append(value),
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
                const value_hash = Hash.init(bytes);
                try failed_pull_hashes.insert(value_hash, now);
                gossip_value_ptr.deinit(self.gossip_data_allocator);
            }
        }
    }

    /// logic for handling a prune message. verifies the prune message
    /// is not too old, and that the destination pubkey is not the local node,
    /// then updates the active set to prune the list of origin Pubkeys.
    pub fn handleBatchPruneMessages(
        self: *GossipService,
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
        self: *GossipService,
        batch_push_messages: *const ArrayList(PushMessage),
    ) !void {
        if (batch_push_messages.items.len == 0) {
            return;
        }
        const allocator = self.allocator;

        var pubkey_to_failed_origins: std.AutoArrayHashMapUnmanaged(
            Pubkey,
            std.AutoArrayHashMapUnmanaged(Pubkey, void),
        ) = .empty;

        var pubkey_to_endpoint: std.AutoArrayHashMapUnmanaged(Pubkey, EndPoint) = .empty;

        defer {
            // TODO: figure out a way to re-use these allocs
            pubkey_to_failed_origins.deinit(allocator);
            pubkey_to_endpoint.deinit(allocator);
        }

        // pre-allocate memory to track insertion failures
        var max_inserts_per_push: usize = 0;
        for (batch_push_messages.items) |push_message| {
            max_inserts_per_push = @max(max_inserts_per_push, push_message.gossip_values.len);
        }

        // insert values and track the failed origins per pubkey
        {
            var timer = sig.time.Timer.start();
            defer {
                const elapsed = timer.read().asMillis();
                self.metrics.push_messages_time_to_insert.observe(elapsed);
            }

            var gossip_table, var gossip_table_lg = self.gossip_table_rw.writeWithLock();
            defer gossip_table_lg.unlock();

            const now = getWallclockMs();
            for (batch_push_messages.items) |*push_message| {
                // Filtered values are freed
                const full_len = push_message.gossip_values.len;
                const values_to_insert = self.filterBasedOnShredVersion(
                    gossip_table,
                    push_message.gossip_values,
                    push_message.from_pubkey.*,
                );
                const invalid_shred_count = full_len - values_to_insert.len;

                var insert_fail_count: u64 = 0;
                var failed_origins: ?*std.AutoArrayHashMapUnmanaged(Pubkey, void) = null;

                for (values_to_insert) |value| {
                    const wallclock = value.wallclock();
                    const timeout = PUSH_MSG_TIMEOUT.asMillis();
                    if (wallclock < now -| timeout or wallclock > now +| timeout) continue;
                    const result = try gossip_table.insert(value, now);
                    self.metrics.observeInsertResult(result);
                    switch (result) {
                        .success => try self.broker.publish(&value.data),
                        .fail => {
                            insert_fail_count += 1;
                            if (failed_origins == null) {
                                const lookup_result = try pubkey_to_failed_origins
                                    .getOrPut(allocator, push_message.from_pubkey.*);
                                if (!lookup_result.found_existing) {
                                    lookup_result.value_ptr.* = .empty;
                                }
                                failed_origins = lookup_result.value_ptr;
                            }
                            try failed_origins.?.put(allocator, value.id(), {});
                            value.deinit(self.gossip_data_allocator);
                        },
                    }
                }
                self.metrics.push_message_n_invalid_shred_version.add(invalid_shred_count);

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

                // lookup contact info to send a prune message to
                const from_contact_info = gossip_table.getThreadSafeContactInfo(
                    push_message.from_pubkey.*,
                ) orelse {
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
                try pubkey_to_endpoint.put(
                    allocator,
                    push_message.from_pubkey.*,
                    from_gossip_endpoint,
                );
            }
        }

        // build prune packets
        const now = getWallclockMs();
        var timer = sig.time.Timer.start();
        defer {
            const elapsed = timer.read().asMillis();
            self.metrics.push_messages_time_build_prune.observe(elapsed);
        }
        var pubkey_to_failed_origins_iter = pubkey_to_failed_origins.iterator();

        const n_packets = pubkey_to_failed_origins_iter.len;
        if (n_packets == 0) return;

        while (pubkey_to_failed_origins_iter.next()) |failed_origin_entry| {
            const from_pubkey = failed_origin_entry.key_ptr.*;
            const failed_origins_hashset = failed_origin_entry.value_ptr;
            defer failed_origins_hashset.deinit(allocator);
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

            var packet = Packet.ANY_EMPTY;
            const written_slice = bincode.writeToSlice(&packet.buffer, msg, .{}) catch unreachable;
            packet.size = written_slice.len;
            packet.addr = from_endpoint;

            try self.packet_outgoing_channel.send(packet);
            self.metrics.prune_messages_sent.add(1);
        }
    }

    /// removes old values from the gossip table and failed pull hashes struct
    /// based on the current time. This includes triming the purged values from the
    /// gossip table, triming the max number of pubkeys in the gossip table, and removing
    /// old labels from the gossip table.
    fn trimMemory(
        self: *GossipService,
        /// the current time
        now: u64,
    ) error{OutOfMemory}!void {
        {
            try self.attemptGossipTableTrim();

            var gossip_table, var gossip_table_lg = self.gossip_table_rw.writeWithLock();
            defer gossip_table_lg.unlock();

            try gossip_table.purged.trim(now -| PURGED_RETENTION.asMillis());

            // TODO: condition timeout on stake weight:
            // - values from nodes with non-zero stake: epoch duration
            // - values from nodes with zero stake:
            //   - if all nodes have zero stake: epoch duration (TODO: this might be unreasonably large)
            //   - if any other nodes have non-zero stake: DATA_TIMEOUT (15s)
            const n_values_removed = try gossip_table.removeOldLabels(now, DEFAULT_EPOCH_DURATION.asMillis());
            self.metrics.table_old_values_removed.add(n_values_removed);
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
    fn populateEntrypointsFromGossipTable(self: *GossipService) !bool {
        var identified_all = true;

        const gossip_table, var gossip_table_lg = self.gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        for (self.entrypoints) |*entrypoint| {
            if (entrypoint.info == null) {
                entrypoint.info = try gossip_table.getOwnedContactInfoByGossipAddr(entrypoint.addr);
            }
            identified_all = identified_all and entrypoint.info != null;
        }
        return identified_all;
    }

    /// if we have no shred version, attempt to get one from an entrypoint.
    /// Returns true if the shred version is set to non-zero
    fn assignDefaultShredVersionFromEntrypoint(self: *GossipService) bool {
        if (self.my_shred_version.load(.monotonic) != 0) return true;
        for (self.entrypoints) |entrypoint| {
            if (entrypoint.info) |info| {
                if (info.shred_version != 0) {
                    self.logger.info()
                        .field("shred_version", info.shred_version)
                        .field("entrypoint", entrypoint.addr.toString().constSlice())
                        .log("shred_version_from_entrypoint");

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
        self: *GossipService,
        /// the current time to insert the values with
        now: u64,
    ) !void {
        const push_msg_queue, var push_msg_queue_lock = self.push_msg_queue_mux.writeWithLock();
        defer push_msg_queue_lock.unlock();

        const deinit_allocator = push_msg_queue.data_allocator;

        const gossip_table, var gossip_table_lock = self.gossip_table_rw.writeWithLock();
        defer gossip_table_lock.unlock();

        // number of items consumed, starting from the beginning of the queue
        const consumed_item_count, const maybe_err = for (push_msg_queue.queue.items, 0..) |*data, i| {
            errdefer comptime unreachable;

            var gossip_data_unsigned = data.*;
            gossip_data_unsigned.wallclockPtr().* = now;
            const signed = SignedGossipData.initSigned(&self.my_keypair, gossip_data_unsigned);

            const result = gossip_table.insert(signed, now) catch |err| break .{ i, err };

            if (result == .fail) switch (result.fail) {
                .too_old => {
                    data.deinit(deinit_allocator);
                    self.logger.warn().logf("DrainPushMessages: Ignored old value ({})", .{signed});
                },
                .duplicate => {
                    data.deinit(deinit_allocator);
                    self.logger.warn().logf(
                        "DrainPushMessages: Ignored duplicate value ({})",
                        .{signed},
                    );
                },
                // retry this value
                .table_full => break .{ i, {} },
            };
        } else .{ push_msg_queue.queue.items.len, {} };

        // remove the gossip values which were inserted
        for (0..consumed_item_count) |_| {
            _ = push_msg_queue.queue.swapRemove(0);
        }

        return maybe_err;
    }

    /// serializes a list of ping messages into Packets and sends them out
    pub fn sendPings(
        self: *GossipService,
        pings: []const PingAndSocketAddr,
    ) error{ OutOfMemory, ChannelClosed, SerializationError }!void {
        for (pings) |ping_and_addr| {
            const message: GossipMessage = .{ .PingMessage = ping_and_addr.ping };
            const packet = Packet.initFromBincode(ping_and_addr.socket, message) catch
                return error.SerializationError;
            try self.packet_outgoing_channel.send(packet);
            self.metrics.ping_messages_sent.add(1);
        }
    }

    /// returns a list of valid gossip nodes. this works by reading
    /// the contact infos from the gossip table and filtering out
    /// nodes that are 1) too old, 2) have a different shred version, or 3) have
    /// an invalid gossip address.
    pub fn getThreadSafeGossipNodes(
        self: *GossipService,
        /// the maximum number of nodes to return ( max_size == nodes.len but comptime for init of stack array)
        comptime MAX_SIZE: usize,
        /// the output slice which will be filled with gossip nodes
        nodes: *[MAX_SIZE]ThreadSafeContactInfo,
        /// current time (used to filter out nodes that are too old)
        now: u64,
    ) ![]ThreadSafeContactInfo {
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
    fn filterBasedOnShredVersion(
        self: *GossipService,
        gossip_table: *const GossipTable,
        gossip_values: []SignedGossipData,
        sender_pubkey: Pubkey,
    ) []const SignedGossipData {
        // we use swap remove which just reorders the array
        // (order dm), so we just track the new len -- ie, no allocations/frees
        const my_shred_version = self.my_shred_version.load(.monotonic);
        if (my_shred_version == 0) {
            return gossip_values;
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
                        removed_value.deinit(self.gossip_data_allocator);
                        continue; // do not incrememnt `i`. it has a new value we need to inspect.
                    }
                },
            }
            i += 1;
        }
        return gossip_values_array.items;
    }
};

/// Manages messaging of gossip data with other validator components.
///
/// Other validator components need to receive gossip data as soon as it arrives
/// from the network. Those components can register channels with this broker by
/// populating the respective fields.
///
/// The word "local" here means "within the validator," to contrast with gossip
/// messaging that happens between multiple validators over the network.
pub const LocalMessageBroker = struct {
    /// Pushes votes to VoteCollector in consensus.
    vote_collector: ?*Channel(sig.gossip.data.Vote) = null,

    /// Publishes new gossip data that was just received over the network to the
    /// appropriate channels.
    ///
    /// Any allocated data is cloned using the channel's allocator before sending.
    fn publish(self: *const LocalMessageBroker, data: *const GossipData) !void {
        switch (data.*) {
            .Vote => |vote| if (self.vote_collector) |channel| {
                const cloned_vote = try vote[1].clone(channel.allocator);
                errdefer cloned_vote.deinit(channel.allocator);
                try channel.send(cloned_vote);
            },
            else => {},
        }
    }
};

/// stats that we publish to prometheus
pub const GossipMetrics = struct {
    gossip_packets_received_total: *Counter,
    gossip_packets_verified_total: *Counter,
    gossip_packets_processed_total: *Counter,

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
    // this is the value of the `cursor` field on the gossip table at the
    // time of generating push messages. it should be close to `gen_push_message_cursor_value`
    // so gossip values are being sent out to peers.
    table_cursor: *GaugeU64,

    // this value tracks the cursor value used to generate push messages.
    // this value should incrementally increase and ideally follow the table_cursor
    // closely to ensure we are pushing all the data in the table.
    gen_push_message_cursor_value: *GaugeU64,
    // this is how many gossip values we have sent in push messages
    gen_push_message_send_count: *Counter,
    // this is how many of the values which we attempted to push but
    // their wallclock was too old or new (ie, the value timed out)
    gen_push_message_send_timeout_count: *Counter,
    // this is how many values who had zero peers in the active set to
    // send to (because of prune messages)
    gen_push_message_zero_active_set_count: *Counter,
    // this is the length of the active set while generating push
    // messages
    gen_push_message_active_set_len: *GaugeU64,

    const GaugeU64 = Gauge(u64);

    pub const histogram_buckets: [10]f64 = .{
        10,   25,
        50,   100,
        250,  500,
        1000, 2500,
        5000, 10000,
    };

    pub fn init() GetMetricError!GossipMetrics {
        var self: GossipMetrics = undefined;
        const registry = globalRegistry();
        std.debug.assert(try registry.initFields(&self) == 0);
        return self;
    }

    pub fn reset(self: *GossipMetrics) void {
        inline for (@typeInfo(GossipMetrics).@"struct".fields) |field| {
            @field(self, field.name).reset();
        }
    }

    fn observeInsertResult(
        metrics: GossipMetrics,
        result: GossipTable.InsertResult,
    ) void {
        switch (result) {
            .success => |success| switch (success) {
                .new => metrics.pull_response_n_new_inserts.inc(),
                .replaced => metrics.pull_response_n_overwrite_existing.inc(),
            },
            .fail => |reason| switch (reason) {
                .too_old => metrics.pull_response_n_old_value.inc(),
                .duplicate => metrics.pull_response_n_duplicate_value.inc(),
                .table_full => {},
            },
        }
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
        const data_byte_size = bincode.getSerializedSizeWithSlice(
            &packet_buf,
            gossip_value,
            bincode.Params{},
        ) catch {
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

pub fn getClusterEntrypoints(cluster: sig.core.Cluster) []const []const u8 {
    return switch (cluster) {
        .mainnet => &.{
            "entrypoint.mainnet-beta.solana.com:8001",
            "entrypoint2.mainnet-beta.solana.com:8001",
            "entrypoint3.mainnet-beta.solana.com:8001",
            "entrypoint4.mainnet-beta.solana.com:8001",
            "entrypoint5.mainnet-beta.solana.com:8001",
        },
        .testnet => &.{
            "entrypoint.testnet.solana.com:8001",
            "entrypoint2.testnet.solana.com:8001",
            "entrypoint3.testnet.solana.com:8001",
        },
        .devnet => &.{
            "entrypoint.devnet.solana.com:8001",
            "entrypoint2.devnet.solana.com:8001",
            "entrypoint3.devnet.solana.com:8001",
            "entrypoint4.devnet.solana.com:8001",
            "entrypoint5.devnet.solana.com:8001",
        },
        .localnet => &.{
            "127.0.0.1:1024", // agave test-validator default
            "127.0.0.1:8001", // sig validator default
        },
    };
}

test "general coverage" {
    const allocator = std.testing.allocator;

    var prng_state: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const prng = prng_state.random();

    const keypair: KeyPair = try .generateDeterministic(seed: {
        var seed: [KeyPair.seed_length]u8 = undefined;
        prng.bytes(&seed);
        break :seed seed;
    });
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    const contact_info = try localhostTestContactInfo(pubkey);

    const gossip_service: *GossipService = try .create(
        allocator,
        allocator,
        contact_info,
        keypair,
        null,
        .noop,
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    {
        const ping_cache, var ping_cache_lg = gossip_service.ping_cache_rw.writeWithLock();
        defer ping_cache_lg.unlock();

        const peer_pk_socket: sig.gossip.ping_pong.PubkeyAndSocketAddr = .{
            .pubkey = .initRandom(prng),
            .socket_addr = .initRandom(prng),
        };

        const result0 = ping_cache.checkAndUpdate(prng, try .now(), peer_pk_socket, &keypair);
        try std.testing.expectEqual(false, result0.passes_ping_check);
        try std.testing.expect(result0.maybe_ping != null);

        ping_cache._setPong(peer_pk_socket.pubkey, peer_pk_socket.socket_addr);

        const result1 = ping_cache.checkAndUpdate(prng, try .now(), peer_pk_socket, &keypair);
        try std.testing.expectEqual(true, result1.passes_ping_check);
    }

    {
        const gossip_table, var gossip_table_lg = gossip_service.gossip_table_rw.writeWithLock();
        defer gossip_table_lg.unlock();

        for (0..sig.gossip.service.UNIQUE_PUBKEY_CAPACITY * 2) |_| {
            const value: sig.gossip.SignedGossipData = .initRandom(prng, &keypair);
            _ = try gossip_table.insert(value, 1);
        }
    }

    try gossip_service.rotateActiveSet(prng);
    try gossip_service.collectGossipTableMetrics();
    try gossip_service.attemptGossipTableTrim();
    try gossip_service.handleBatchPullRequest(prng.int(u64), &.{});
}

test "handle pong messages" {
    const allocator = std.testing.allocator;

    var prng_state: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng_state.random();

    var keypair = try KeyPair.generateDeterministic(@splat(1));
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    const contact_info = try localhostTestContactInfo(pubkey);

    const gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        keypair,
        null,
        .noop,
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    const endpoint = try allocator.create(EndPoint);
    defer allocator.destroy(endpoint);
    endpoint.* = try EndPoint.parse("127.0.0.1:8000");

    // send out a ping to the endpoint
    const other_keypair = KeyPair.generate();
    const other_pubkey = Pubkey.fromPublicKey(&other_keypair.public_key);
    const pubkey_and_addr = sig.gossip.ping_pong.PubkeyAndSocketAddr{
        .pubkey = other_pubkey,
        .socket_addr = SocketAddr.fromEndpoint(endpoint),
    };

    const ping = blk: {
        const ping_cache_ptr_ptr, var ping_cache_lg = gossip_service.ping_cache_rw.writeWithLock();
        defer ping_cache_lg.unlock();

        const now = try std.time.Instant.now();
        const ping = ping_cache_ptr_ptr.maybePing(random, now, pubkey_and_addr, &keypair);
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
        const r = ping_cache_ptr_ptr.checkAndUpdate(random, now, pubkey_and_addr, &keypair);
        std.debug.assert(r.passes_ping_check);
    }
}

test "build messages startup and shutdown" {
    const allocator = std.testing.allocator;
    var my_keypair = try KeyPair.generateDeterministic(@splat(1));
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        .FOR_TESTS,
        .{},
    );
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    var prng = std.Random.Xoshiro256.init(0);
    const random = prng.random();

    var build_messages_handle = try Thread.spawn(.{}, GossipService.buildMessages, .{
        gossip_service,
        19,
        sig.sync.ExitCondition{ .unordered = gossip_service.service_manager.exit },
    });
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
        var rand_keypair = KeyPair.generate();
        var value = try SignedGossipData.randomWithIndex(random, &rand_keypair, 0); // contact info
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const allocator = std.testing.allocator;
    var my_keypair = try KeyPair.generateDeterministic(@splat(1));
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        .FOR_TESTS,
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    // add some peers
    var lg = gossip_service.gossip_table_rw.write();
    var peers = ArrayList(ThreadSafeContactInfo).init(allocator);
    defer peers.deinit();
    for (0..10) |_| {
        var rand_keypair = KeyPair.generate();
        const value = try SignedGossipData.randomWithIndex(prng.random(), &rand_keypair, 0); // contact info
        _ = try lg.mut().insert(value, getWallclockMs());
        try peers.append(ThreadSafeContactInfo.fromLegacyContactInfo(value.data.LegacyContactInfo));
    }
    lg.unlock();

    {
        var as_lock = gossip_service.active_set_rw.write();
        var as: *ActiveSet = as_lock.mut();
        try as.initRotate(prng.random(), peers.items);
        as_lock.unlock();
    }

    var as_lock = gossip_service.active_set_rw.read();
    var as: *const ActiveSet = as_lock.get();
    try std.testing.expect(as.len() > 0); // FIX
    var iter = as.peers.keyIterator();
    const peer0 = iter.next().?.*;
    as_lock.unlock();

    var prunes = [_]Pubkey{Pubkey.initRandom(prng.random())};
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var my_keypair = try KeyPair.generateDeterministic(@splat(1));
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        .FOR_TESTS,
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    // get random values
    var gossip_values: [5]SignedGossipData = undefined;
    var kp = KeyPair.generate();
    for (0..5) |i| {
        var value = try SignedGossipData.randomWithIndex(prng.random(), &kp, 0);
        value.data.LegacyContactInfo.id = Pubkey.initRandom(prng.random());
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var my_keypair = try KeyPair.generateDeterministic(@splat(1));
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = try localhostTestContactInfo(my_pubkey);
    contact_info.shred_version = 99;

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        .noop,
        .{},
    );
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    const handle = try std.Thread.spawn(.{}, GossipService.run, .{
        gossip_service,
        GossipService.RunThreadsParams{},
    });

    const prune_pubkey = Pubkey.initRandom(random);
    const prune_data = PruneData.init(prune_pubkey, &.{}, my_pubkey, 0);
    const message: GossipMessage = .{
        .PruneMessage = .{ prune_pubkey, prune_data },
    };
    try gossip_service.verified_incoming_channel.send(.{
        .from_endpoint = try EndPoint.parse("127.0.0.1:8000"),
        .message = message,
    });

    // send a pull request message
    const N_FILTER_BITS = 1;
    const bloom = try Bloom.initRandom(allocator, random, 100, 0.1, N_FILTER_BITS);
    const filter: GossipPullFilter = .{
        .filter = bloom,
        // this is why we wanted atleast one hash_bit == 1
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };
    const rando_keypair = try KeyPair.generateDeterministic(@splat(22));

    const ci = SignedGossipData.initSigned(&rando_keypair, ci: {
        var ci = LegacyContactInfo.initRandom(random);
        ci.shred_version = 100;
        break :ci .{ .LegacyContactInfo = ci };
    });
    try gossip_service.verified_incoming_channel.send(.{
        .from_endpoint = try EndPoint.parse("127.0.0.1:8000"),
        .message = .{ .PullRequest = .{ filter, ci } },
    });

    // DIFFERENT GOSSIP DATA (NOT A LEGACY CONTACT INFO)
    // NOTE: need fresh bloom filter because it gets deinit
    const bloom2 = try Bloom.initRandom(allocator, random, 100, 0.1, N_FILTER_BITS);
    const filter2 = GossipPullFilter{
        .filter = bloom2,
        // this is why we wanted atleast one hash_bit == 1
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };
    const data = try SignedGossipData.randomWithIndex(random, &rando_keypair, 2);
    try gossip_service.verified_incoming_channel.send(.{
        .from_endpoint = try EndPoint.parse("127.0.0.1:8000"),
        .message = .{ .PullRequest = .{ filter2, data } },
    });

    // wait for all processing to be done
    const MAX_N_SLEEPS = 100;
    var i: u64 = 0;
    while (gossip_service.metrics.pull_requests_dropped.get() != 2) {
        std.Thread.sleep(std.time.ns_per_ms * 100);
        if (i > MAX_N_SLEEPS) return error.LoopRangeExceeded;
        i += 1;
    }
    while (gossip_service.metrics.prune_messages_dropped.get() != 1) {
        std.Thread.sleep(std.time.ns_per_ms * 100);
        if (i > MAX_N_SLEEPS) return error.LoopRangeExceeded;
        i += 1;
    }

    gossip_service.shutdown();
    handle.join();

    try std.testing.expect(gossip_service.metrics.pull_requests_dropped.get() == 2);
    try std.testing.expect(gossip_service.metrics.prune_messages_dropped.get() == 1);
}

test "handle pull request" {
    if (true) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var my_keypair = try KeyPair.generateDeterministic(@splat(1));
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = try localhostTestContactInfo(my_pubkey);
    contact_info.shred_version = 99;

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        .FOR_TESTS,
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

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
                var value = try SignedGossipData.randomWithIndex(prng.random(), &(KeyPair.generate()), 0);
                _ = try gossip_table.insert(value, getWallclockMs());

                // make sure well get a response from the request
                const metadata = gossip_table.getMetadata(value.label()).?;
                const hash_bits = pull_request.hashToU64(&metadata.value_hash) >> (64 - N_FILTER_BITS);
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
    var random_keypair = try KeyPair.generateDeterministic(@splat(22));
    const random_pubkey = Pubkey.fromPublicKey(&random_keypair.public_key);

    const addr = SocketAddr.initRandom(prng.random());

    const ci = blk: {
        var lci = LegacyContactInfo.initRandom(prng.random());
        lci.id = random_pubkey;
        lci.gossip = addr;
        lci.shred_version = 99;

        const unsigned_ci: GossipData = .{ .LegacyContactInfo = lci };
        break :blk SignedGossipData.initSigned(&random_keypair, unsigned_ci);
    };

    {
        var ping_lock = gossip_service.ping_cache_rw.write();
        defer ping_lock.unlock();

        const ping_cache: *PingCache = ping_lock.mut();
        ping_cache._setPong(random_pubkey, addr);
    }

    // only consider the first bit so we know well get matches
    var bloom = try Bloom.initRandom(allocator, prng.random(), 100, 0.1, N_FILTER_BITS);
    defer bloom.deinit();

    const filter: GossipPullFilter = .{
        .filter = bloom,
        // this is why we wanted atleast one hash_bit == 1
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };

    try gossip_service.handleBatchPullRequest(19, &.{.{
        .filter = filter,
        .from_endpoint = addr.toEndpoint(),
        .value = ci,
    }});

    {
        const outgoing_packets = gossip_service.packet_outgoing_channel;

        while (outgoing_packets.tryReceive()) |response_packet| {
            const message = try bincode.readFromSlice(
                allocator,
                GossipMessage,
                response_packet.data(),
                bincode.Params.standard,
            );
            defer bincode.free(allocator, message);

            const values = message.PullResponse[1];
            try std.testing.expect(values.len > 0);
        }
    }
}

test "test build prune messages and handle push messages" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var my_keypair = try KeyPair.generateDeterministic(@splat(1));
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        .FOR_TESTS,
        .{},
    );
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    var push_from = Pubkey.initRandom(prng.random());
    var values = ArrayList(SignedGossipData).init(allocator);
    defer values.deinit();
    for (0..10) |_| {
        var value = try SignedGossipData.randomWithIndex(prng.random(), &my_keypair, 0);
        value.data.LegacyContactInfo.id = Pubkey.initRandom(prng.random());
        try values.append(value);
    }

    // insert contact info to send prunes to
    var send_contact_info = LegacyContactInfo.initRandom(prng.random());
    send_contact_info.id = push_from;
    // valid socket addr
    var gossip_socket = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 20);
    send_contact_info.gossip = gossip_socket;

    const ci_value = SignedGossipData.initSigned(&my_keypair, .{
        .LegacyContactInfo = send_contact_info,
    });
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
    var packet = gossip_service.packet_outgoing_channel.tryReceive() orelse return error.ChannelEmpty;
    const message = try bincode.readFromSlice(
        allocator,
        GossipMessage,
        packet.data(),
        bincode.Params.standard,
    );
    defer bincode.free(allocator, message);

    var prune_data = message.PruneMessage[1];
    try std.testing.expect(prune_data.destination.equals(&push_from));
    try std.testing.expectEqual(prune_data.prunes.len, 10);

    gossip_service.shutdown();
}

test testBuildPullRequests {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const my_keypair = try KeyPair.generateDeterministic(.{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

    const contact_info = try localhostTestContactInfo(my_pubkey);
    defer contact_info.deinit();

    try testBuildPullRequests(prng.random(), my_keypair, contact_info, null);
    try testBuildPullRequests(
        prng.random(),
        my_keypair,
        contact_info,
        &.{contact_info.getSocket(.gossip).?},
    );
}

fn testBuildPullRequests(
    random: std.Random,
    my_keypair: KeyPair,
    contact_info: ContactInfo,
    maybe_entrypoints: ?[]const SocketAddr,
) !void {
    const allocator = std.testing.allocator;

    const gossip_service = blk: {
        const contact_info_clone = try contact_info.clone();
        errdefer contact_info_clone.deinit();
        break :blk try GossipService.create(
            allocator,
            allocator,
            contact_info_clone,
            my_keypair,
            maybe_entrypoints,
            .FOR_TESTS,
            .{},
        );
    };
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
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
            const rando_keypair = KeyPair.generate();

            var lci = LegacyContactInfo.initRandom(random);
            lci.id = Pubkey.fromPublicKey(&rando_keypair.public_key);
            lci.wallclock = now + 10 * i;
            lci.shred_version = contact_info.shred_version;
            const value = SignedGossipData.initSigned(&rando_keypair, .{ .LegacyContactInfo = lci });

            _ = try lg.mut().insert(value, now + 10 * i);
            pc._setPong(lci.id, lci.gossip);
        }
    }

    var packets = gossip_service.buildPullRequests(random, 2, now) catch |err| {
        std.log.err("\nThe failing now time is: '{d}'\n", .{now});
        return err;
    };
    defer packets.deinit();

    try std.testing.expect(packets.items.len > 1);
    try std.testing.expect(!std.mem.eql(u8, packets.items[0].data(), packets.items[1].data()));
}

test "test build push messages" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var my_keypair = try KeyPair.generateDeterministic(@splat(1));
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        .FOR_TESTS,
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    // add some peers
    var peers = ArrayList(ThreadSafeContactInfo).init(allocator);
    defer peers.deinit();
    var lg = gossip_service.gossip_table_rw.write();
    for (0..10) |_| {
        var keypair = KeyPair.generate();
        const value = try SignedGossipData.randomWithIndex(prng.random(), &keypair, 0); // contact info
        _ = try lg.mut().insert(value, getWallclockMs());
        try peers.append(ThreadSafeContactInfo.fromLegacyContactInfo(value.data.LegacyContactInfo));
    }
    lg.unlock();

    const value = GossipData.initRandom(prng.random());

    // set the active set
    {
        var as_lock = gossip_service.active_set_rw.write();
        var as: *ActiveSet = as_lock.mut();
        try as.initRotate(prng.random(), peers.items);
        as_lock.unlock();
        try std.testing.expect(as.len() > 0);
    }

    {
        var pqlg = gossip_service.push_msg_queue_mux.lock();
        var push_queue = pqlg.mut();
        try push_queue.queue.append(value);
        pqlg.unlock();
    }
    try gossip_service.drainPushQueueToGossipTable(getWallclockMs());

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

test "large push messages" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(91);

    const my_keypair = KeyPair.generate();
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

    const contact_info = try localhostTestContactInfo(my_pubkey);

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        .noop,
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    // add some peers
    var peers: std.ArrayListUnmanaged(ThreadSafeContactInfo) = .empty;
    defer peers.deinit(allocator);
    {
        var lock_guard = gossip_service.gossip_table_rw.write();
        defer lock_guard.unlock();

        const count = if (sig.build_options.long_tests) 2_000 else 20;
        for (0..count) |_| {
            var keypair = KeyPair.generate();
            const value = try SignedGossipData.randomWithIndex(prng.random(), &keypair, 0); // contact info
            _ = try lock_guard.mut().insert(value, getWallclockMs());
            try peers.append(allocator, .fromLegacyContactInfo(value.data.LegacyContactInfo));
        }
    }

    // set the active set
    {
        var as_lock = gossip_service.active_set_rw.write();
        var as: *ActiveSet = as_lock.mut();
        try as.initRotate(prng.random(), peers.items);
        as_lock.unlock();
        try std.testing.expect(as.len() > 0);
    }

    var cursor: u64 = 0;
    const msgs = try gossip_service.buildPushMessages(&cursor);
    defer msgs.deinit();

    const expected = if (sig.build_options.long_tests) 3_780 else 42;
    try std.testing.expectEqual(expected, msgs.items.len);
}

test "test packet verification" {
    const allocator = std.testing.allocator;
    var keypair = try KeyPair.generateDeterministic(@splat(1));
    const id = Pubkey.fromPublicKey(&keypair.public_key);
    const contact_info = try localhostTestContactInfo(id);

    // noop for this case because this tests error failed verification
    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        keypair,
        null,
        .noop,
        .{},
    );
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    var packet_channel = gossip_service.packet_incoming_channel;
    var verified_channel = gossip_service.verified_incoming_channel;

    const packet_verifier_handle = try Thread.spawn(.{}, GossipService.verifyPackets, .{
        gossip_service,
        sig.sync.ExitCondition{ .unordered = gossip_service.service_manager.exit },
    });
    defer {
        gossip_service.shutdown();
        packet_verifier_handle.join();
    }

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var data = GossipData.randomFromIndex(prng.random(), 0);
    data.LegacyContactInfo.id = id;
    data.LegacyContactInfo.wallclock = 0;
    var value = SignedGossipData.initSigned(&keypair, data);

    try value.verify(id);

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
    var value_v2 = SignedGossipData.initSigned(&keypair, GossipData.randomFromIndex(prng.random(), 2));
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
    var rand_keypair = try KeyPair.generateDeterministic(@splat(3));
    const value2 = SignedGossipData.initSigned(&rand_keypair, GossipData.randomFromIndex(prng.random(), 0));
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
        var dshred = sig.gossip.data.DuplicateShred.initRandom(prng.random());
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
        const dshred_value = SignedGossipData.initSigned(&rand_keypair, dshred_data);
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
        if (verified_channel.tryReceive()) |msg| {
            defer bincode.free(gossip_service.allocator, msg);
            try std.testing.expect(msg.message.PushMessage[0].equals(&id));
            msg_count += 1;
        }
    }
}

test "process contact info push packet" {
    const allocator = std.testing.allocator;

    var my_keypair = try KeyPair.generateDeterministic(@splat(1));
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        .FOR_TESTS,
        .{},
    );
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    const verified_channel = gossip_service.verified_incoming_channel;
    const responder_channel = gossip_service.packet_outgoing_channel;

    const kp = KeyPair.generate();
    const id = Pubkey.fromPublicKey(&kp.public_key);

    var packet_handle = try Thread.spawn(.{}, GossipService.processMessages, .{
        gossip_service,
        19,
        sig.sync.ExitCondition{ .unordered = gossip_service.service_manager.exit },
    });

    // new contact info
    const legacy_contact_info = LegacyContactInfo.default(id);
    const gossip_data: GossipData = .{ .LegacyContactInfo = legacy_contact_info };
    const gossip_value = SignedGossipData.initSigned(&kp, gossip_data);
    const heap_values = try allocator.dupe(SignedGossipData, &.{gossip_value});

    var valid_messages_sent: u64 = 0;

    // push message
    const msg: GossipMessage = .{ .PushMessage = .{ id, heap_values } };
    const peer = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8000).toEndpoint();
    const message: GossipMessageWithEndpoint = .{
        .message = msg,
        .from_endpoint = peer,
    };
    try verified_channel.send(message);
    valid_messages_sent += 1;

    // ping
    const ping_msg: GossipMessageWithEndpoint = .{
        .message = .{ .PingMessage = try Ping.init(.{0} ** 32, &kp) },
        .from_endpoint = peer,
    };
    try verified_channel.send(ping_msg);
    valid_messages_sent += 1;

    // send pull request with own pubkey
    const erroneous_pull_request_msg: GossipMessageWithEndpoint = .{
        .message = .{
            .PullRequest = .{
                try GossipPullFilter.init(allocator),
                SignedGossipData.initSigned(&my_keypair, .{
                    .ContactInfo = try localhostTestContactInfo(my_pubkey), // whoops
                }),
            },
        },
        .from_endpoint = peer,
    };
    try verified_channel.send(erroneous_pull_request_msg);

    // wait for all processing to be done
    const MAX_N_SLEEPS = 100;
    var i: u64 = 0;
    while (gossip_service.metrics.gossip_packets_processed_total.get() != valid_messages_sent) {
        std.Thread.sleep(std.time.ns_per_ms * 100);
        if (i > MAX_N_SLEEPS) return error.LoopRangeExceeded;
        i += 1;
    }

    // the ping message we sent, processed into a pong
    try std.testing.expectEqual(1, responder_channel.len());
    const out_packet = responder_channel.tryReceive().?;
    const out_msg = try bincode.readFromSlice(std.testing.allocator, GossipMessage, out_packet.data(), .{});
    defer bincode.free(std.testing.allocator, out_msg);
    try std.testing.expect(out_msg == .PongMessage);

    // close everything up before looking at the output channel in order to
    // not race with work services are doing
    gossip_service.shutdown();
    packet_handle.join();

    // correct insertion into table (from push message)
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
    const my_keypair = KeyPair.generate();
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var contact_info = try LegacyContactInfo.initRandom(prng.random()).toContactInfo(std.testing.allocator);
    try contact_info.setSocket(.gossip, gossip_address);

    const gossip_service = try GossipService.create(
        std.testing.allocator,
        std.testing.allocator,
        contact_info,
        my_keypair,
        null,
        .FOR_TESTS,
        .{},
    );
    defer {
        gossip_service.deinit();
        std.testing.allocator.destroy(gossip_service);
    }

    const handle = try std.Thread.spawn(.{}, GossipService.run, .{
        gossip_service, GossipService.RunThreadsParams{ .spy_node = true, .dump = false },
    });
    defer {
        gossip_service.shutdown();
        handle.join();
    }
}

test "leak checked gossip init" {
    const testfn = struct {
        fn f(allocator: std.mem.Allocator) !void {
            var my_keypair = try KeyPair.generateDeterministic(@splat(1));
            const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
            const contact_info = try localhostTestContactInfo(my_pubkey);
            errdefer contact_info.deinit();

            var gossip_service = try GossipService.init(
                allocator,
                allocator,
                contact_info,
                my_keypair,
                null,
                .FOR_TESTS,
                .{},
            );
            gossip_service.shutdown();
            gossip_service.deinit();
        }
    }.f;

    try std.testing.checkAllAllocationFailures(std.testing.allocator, testfn, .{});
}

const fuzz_service = sig.gossip.fuzz_service;

pub const BenchmarkGossipServiceGeneral = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 5;
    pub const name = "GossipServiceGeneral";

    pub const MessageCounts = struct {
        n_ping: usize,
        n_push_message: usize,
        n_pull_response: usize,
    };

    pub const BenchmarkInputs = struct {
        name: []const u8 = "",
        message_counts: MessageCounts,
    };

    pub const inputs = [_]BenchmarkInputs{
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

    pub fn benchmarkGossipService(bench_args: BenchmarkInputs) !sig.time.Duration {
        const allocator = if (@import("builtin").is_test) std.testing.allocator else std.heap.c_allocator;
        var keypair = KeyPair.generate();
        var address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8888);
        const endpoint = address.toEndpoint();

        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        var contact_info = ContactInfo.init(allocator, pubkey, 0, 19);
        try contact_info.setSocket(.gossip, address);

        // process incoming packets/messsages
        var gossip_service = try GossipService.create(
            allocator,
            allocator,
            contact_info,
            keypair,
            null,
            .noop,
            .{},
        );
        defer {
            gossip_service.metrics.reset();
            gossip_service.deinit();
            allocator.destroy(gossip_service);
        }

        const outgoing_channel = gossip_service.packet_incoming_channel;

        // generate messages
        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
        const random = prng.random();

        var msg_sent: usize = 0;
        msg_sent += bench_args.message_counts.n_ping;

        for (0..bench_args.message_counts.n_ping) |_| {
            // send a ping message
            const packet = try fuzz_service.randomPingPacket(random, &keypair, endpoint);
            try outgoing_channel.send(packet);
        }

        for (0..bench_args.message_counts.n_push_message) |_| {
            // send a push message
            var packets = try fuzz_service.randomPushMessage(
                allocator,
                random,
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
                allocator,
                random,
                &keypair,
                address.toEndpoint(),
            );
            defer packets.deinit();

            msg_sent += packets.items.len;
            for (packets.items) |packet| try outgoing_channel.send(packet);
        }

        const packet_handle = try Thread.spawn(.{}, GossipService.run, .{
            gossip_service, GossipService.RunThreadsParams{
                .spy_node = true, // dont build any outgoing messages
                .dump = false,
            },
        });

        // wait for all messages to be processed
        var timer = sig.time.Timer.start();

        gossip_service.shutdown();
        packet_handle.join();

        return timer.read();
    }
};

/// pull requests require some additional setup to work
pub const BenchmarkGossipServicePullRequests = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 5;
    pub const name = "GossipServicePullRequests";

    pub const BenchmarkInputs = struct {
        name: []const u8 = "",
        n_data_populated: usize,
        n_pull_requests: usize,
    };

    pub const inputs = [_]BenchmarkInputs{
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

    pub fn benchmarkPullRequests(bench_args: BenchmarkInputs) !sig.time.Duration {
        const allocator = if (@import("builtin").is_test) std.testing.allocator else std.heap.c_allocator;
        var keypair = KeyPair.generate();
        var address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8888);

        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        var contact_info = ContactInfo.init(allocator, pubkey, 0, 19);
        try contact_info.setSocket(.gossip, address);

        const logger: Logger = .noop;

        // process incoming packets/messsages
        var gossip_service = try GossipService.create(
            allocator,
            allocator,
            contact_info,
            keypair,
            null,
            .from(logger),
            .{},
        );
        defer {
            gossip_service.metrics.reset();
            gossip_service.deinit();
            allocator.destroy(gossip_service);
        }

        // setup recv peer
        const recv_address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8889);
        var recv_keypair = KeyPair.generate();
        const recv_pubkey = Pubkey.fromPublicKey(&recv_keypair.public_key);

        var contact_info_recv = ContactInfo.init(allocator, recv_pubkey, 0, 19);
        try contact_info_recv.setSocket(.gossip, recv_address);
        const signed_contact_info_recv = SignedGossipData.initSigned(&recv_keypair, .{
            .ContactInfo = contact_info_recv,
        });

        const now = getWallclockMs();
        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
        const random = prng.random();

        {
            var ping_cache: *PingCache, var lock = gossip_service.ping_cache_rw.writeWithLock();
            defer lock.unlock();
            ping_cache._setPong(recv_pubkey, recv_address);
        }

        {
            var table, var lock = gossip_service.gossip_table_rw.writeWithLock();
            defer lock.unlock();
            // insert contact info of pull request
            _ = try table.insert(signed_contact_info_recv, now);
            // insert all other values
            for (0..bench_args.n_data_populated) |_| {
                const value = SignedGossipData.initRandom(random, &recv_keypair);
                _ = try table.insert(value, now);
            }
        }

        const outgoing_channel = gossip_service.packet_incoming_channel;

        // generate messages
        for (0..bench_args.n_pull_requests) |_| {
            const packet = try fuzz_service.randomPullRequestWithContactInfo(
                allocator,
                random,
                address.toEndpoint(),
                signed_contact_info_recv,
            );

            try outgoing_channel.send(packet);
        }

        const packet_handle = try Thread.spawn(.{}, GossipService.run, .{
            gossip_service, GossipService.RunThreadsParams{
                .spy_node = true, // dont build any outgoing messages
                .dump = false,
            },
        });

        var timer = sig.time.Timer.start();

        // wait for all messages to be processed
        gossip_service.shutdown();
        packet_handle.join();

        return timer.read();
    }
};

fn localhostTestContactInfo(id: Pubkey) !ContactInfo {
    if (!@import("builtin").is_test) @compileError("only for testing");
    var contact_info = try LegacyContactInfo.default(id).toContactInfo(std.testing.allocator);
    errdefer contact_info.deinit();
    try contact_info.setSocket(.gossip, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0));
    return contact_info;
}

test "benchmarkPullRequests" {
    _ = try BenchmarkGossipServicePullRequests.benchmarkPullRequests(.{
        .name = "1k_data_1k_pull_reqs",
        .n_data_populated = 10,
        .n_pull_requests = 2,
    });
}

test "benchmarkGossipService" {
    _ = try BenchmarkGossipServiceGeneral.benchmarkGossipService(.{
        .message_counts = .{
            .n_ping = 10,
            .n_push_message = 10,
            .n_pull_response = 10,
        },
    });
}

test LocalMessageBroker {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(0);
    var vote_collector: Channel(sig.gossip.data.Vote) = try .init(allocator);
    defer vote_collector.deinit();
    const broker: LocalMessageBroker = .{ .vote_collector = &vote_collector };
    var signer: Pubkey = undefined;
    {
        var txn = try sig.core.Transaction.initRandom(allocator, rng.random(), null);
        defer txn.deinit(allocator);
        signer = txn.msg.account_keys[0];
        try broker.publish(&.{ .Vote = .{ 0, .{
            .from = .ZEROES,
            .transaction = txn,
            .wallclock = 0,
            .slot = 0,
        } } });
    }
    const vote = vote_collector.tryReceive().?;
    defer vote.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &signer.data, &vote.transaction.msg.account_keys[0].data);
}
