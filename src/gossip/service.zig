const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const gossip = @import("lib.zig");

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
const Entrypoint = gossip.send_service.Entrypoint;

const endpointToString = sig.net.endpointToString;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.time.getWallclockMs;
const deinitMux = sig.sync.mux.deinitMux;

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
    // /// used for general allocation purposes
    // allocator: std.mem.Allocator,
    // /// used specifically to allocate the gossip values
    // gossip_data_allocator: std.mem.Allocator,

    my_shred_version: Atomic(u16),

    logger: ScopedLogger,
    service_manager: ServiceManager,
    /// An atomic counter for ensuring proper exit order of tasks.
    exit_counter: *Atomic(u64),
    /// Indicates if the gossip service is closed.
    closed: bool,

    /////////////////////////////////////////////////////////////
    // Shared state to manage

    /// Piping data between the gossip_socket and the channels.
    /// Set to null until start() is called as they represent threads.
    incoming_socket_thread: ?*SocketThread = null,
    outgoing_socket_thread: ?*SocketThread = null,
    gossip_socket: UdpSocket,

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
    /// manages ping/pong heartbeats for the network
    ping_cache_rw: RwMux(PingCache),
    thread_pool: ThreadPool,

    /////////////////////////////////////////////////////////////
    // Sub-services

    verify_service: gossip.verify_service.GossipVerifyService,
    recv_service: gossip.recv_service.GossipRecvService,
    send_service: gossip.send_service.GossipSendService,

    pub const LOG_SCOPE = "gossip_service";
    pub const ScopedLogger = sig.trace.log.ScopedLogger(LOG_SCOPE);

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
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = try Self.init(
            allocator,
            gossip_data_allocator,
            my_contact_info,
            my_keypair,
            maybe_entrypoints,
            logger,
        );
        return self;
    }

    pub fn init(
        /// Must be thread-safe.
        allocator: std.mem.Allocator,
        /// Can be supplied as a different allocator in order to reduce contention.
        /// Must be thread safe.
        gossip_data_allocator: std.mem.Allocator,
        my_contact_info: ContactInfo,
        my_keypair: KeyPair,
        maybe_entrypoints: ?[]const SocketAddr,
        logger: Logger,
    ) !Self {
        const gossip_logger = logger.withScope(LOG_SCOPE);

        // setup channels for communication between threads
        var packet_incoming_channel = try Channel(Packet).create(allocator);
        errdefer packet_incoming_channel.destroy();

        var packet_outgoing_channel = try Channel(Packet).create(allocator);
        errdefer packet_outgoing_channel.destroy();

        var verified_incoming_channel = try Channel(GossipMessageWithEndpoint).create(allocator);
        errdefer verified_incoming_channel.destroy();

        // setup the socket (bind with read-timeout)
        const gossip_address = my_contact_info.getSocket(.gossip) orelse return error.GossipAddrUnspecified;
        var gossip_socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
        gossip_socket.bindToPort(gossip_address.port()) catch return error.SocketBindFailed;
        gossip_socket.setReadTimeout(socket_utils.SOCKET_TIMEOUT_US) catch return error.SocketSetTimeoutFailed; // 1 second

        // setup the threadpool for processing messages
        const n_threads: usize = @min(std.Thread.getCpuCount() catch 1, THREAD_POOL_SIZE);
        const thread_pool = ThreadPool.init(.{
            .max_threads = @intCast(n_threads),
            .stack_size = 2 * 1024 * 1024,
        });
        gossip_logger.info().logf("starting threadpool with {} threads", .{n_threads});

        // setup the table
        var gossip_table = try GossipTable.init(allocator, gossip_data_allocator);
        errdefer gossip_table.deinit();

        // setup the active set for push messages
        const active_set = ActiveSet.init(allocator);

        // setup entrypoints
        var entrypoints = ArrayList(Entrypoint).init(allocator);
        if (maybe_entrypoints) |entrypoint_addrs| {
            try entrypoints.ensureTotalCapacityPrecise(entrypoint_addrs.len);
            for (entrypoint_addrs) |entrypoint_addr| {
                entrypoints.appendAssumeCapacity(.{ .addr = entrypoint_addr });
            }
        }

        // setup ping/pong cache
        const ping_cache = try PingCache.init(
            allocator,
            PING_CACHE_TTL,
            PING_CACHE_RATE_LIMIT_DELAY,
            PING_CACHE_CAPACITY,
        );

        const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
        const my_shred_version = my_contact_info.shred_version;
        const failed_pull_hashes = HashTimeQueue.init(allocator);
        const metrics = try GossipMetrics.init();

        const exit_counter = try allocator.create(Atomic(u64));
        exit_counter.* = Atomic(u64).init(0);

        const exit = try allocator.create(Atomic(bool));
        exit.* = Atomic(bool).init(false);

        const service_manager = ServiceManager.init(
            allocator,
            logger,
            exit,
            "gossip",
            .{},
            .{},
        );

        return GossipService{
            .verify_service = .{
                .gossip_data_allocator = gossip_data_allocator,
                .packet_incoming_channel = packet_incoming_channel,
                .verified_incoming_channel = verified_incoming_channel,
                .logger = gossip_logger,
                .thread_pool = thread_pool,
            },
            .recv_service = .{
                .allocator = allocator,
                .gossip_data_allocator = gossip_data_allocator,
                .my_keypair = my_keypair,
                .my_pubkey = my_pubkey,
                .my_shred_version = Atomic(u16).init(my_shred_version),
                .packet_outgoing_channel = packet_outgoing_channel,
                .verified_incoming_channel = verified_incoming_channel,
                .gossip_table_rw = RwMux(GossipTable).init(gossip_table),
                .active_set_rw = RwMux(ActiveSet).init(active_set),
                .failed_pull_hashes_mux = Mux(HashTimeQueue).init(failed_pull_hashes),
                .ping_cache_rw = RwMux(PingCache).init(ping_cache),
                .thread_pool = thread_pool,
                .metrics = metrics,
            },
            .send_service = .{
                .allocator = allocator,
                .gossip_data_allocator = gossip_data_allocator,
                .my_contact_info = my_contact_info,
                .my_keypair = my_keypair,
                .my_pubkey = my_pubkey,
                .my_shred_version = Atomic(u16).init(my_shred_version),
                .packet_incoming_channel = packet_incoming_channel,
                .packet_outgoing_channel = packet_outgoing_channel,
                .verified_incoming_channel = verified_incoming_channel,
                .gossip_table_rw = RwMux(GossipTable).init(gossip_table),
                .push_msg_queue_mux = gossip.send_service.GossipSendService.PushMessageQueue.init(.{
                    .queue = ArrayList(GossipData).init(allocator),
                    .data_allocator = gossip_data_allocator,
                }),
                .active_set_rw = RwMux(ActiveSet).init(active_set),
                .failed_pull_hashes_mux = Mux(HashTimeQueue).init(failed_pull_hashes),
                .entrypoints = entrypoints,
                .ping_cache_rw = RwMux(PingCache).init(ping_cache),
                .logger = gossip_logger,
                .metrics = metrics,
            },
        };

        return .{
            .allocator = allocator,
            .gossip_data_allocator = gossip_data_allocator,
            .my_contact_info = my_contact_info,
            .my_keypair = my_keypair,
            .my_pubkey = my_pubkey,
            .my_shred_version = Atomic(u16).init(my_shred_version),
            .gossip_socket = gossip_socket,
            .packet_incoming_channel = packet_incoming_channel,
            .packet_outgoing_channel = packet_outgoing_channel,
            .verified_incoming_channel = verified_incoming_channel,
            .gossip_table_rw = RwMux(GossipTable).init(gossip_table),
            .push_msg_queue_mux = PushMessageQueue.init(.{
                .queue = ArrayList(GossipData).init(allocator),
                .data_allocator = gossip_data_allocator,
            }),
            .active_set_rw = RwMux(ActiveSet).init(active_set),
            .failed_pull_hashes_mux = Mux(HashTimeQueue).init(failed_pull_hashes),
            .entrypoints = entrypoints,
            .ping_cache_rw = RwMux(PingCache).init(ping_cache),
            .logger = gossip_logger,
            .thread_pool = thread_pool,
            .metrics = metrics,
            .exit_counter = exit_counter,
            .service_manager = service_manager,
            .closed = false,
        };
    }

    /// Starts the shutdown chain for all services. Does *not* block until
    /// the service manager is joined.
    pub fn shutdown(self: *Self) void {
        std.debug.assert(!self.closed);
        defer self.closed = true;

        // kick off the shutdown chain
        self.exit_counter.store(1, .release);
        // exit the service manager loops when methods return
        self.service_manager.exit.store(true, .release);
    }

    pub fn deinit(self: *Self) void {
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

        self.entrypoints.deinit();
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
    pub fn run(self: *Self, params: RunThreadsParams) !void {
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
        self: *Self,
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
            self.logger.unscoped(),
            self.gossip_socket,
            self.packet_incoming_channel,
            exit_condition,
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
            self.logger.unscoped(),
            self.gossip_socket,
            self.packet_outgoing_channel,
            exit_condition,
        );
        exit_condition.ordered.exit_index += 1;

        if (params.dump) {
            try self.service_manager.spawn("[gossip] dumpService", GossipDumpService.run, .{.{
                .allocator = self.allocator,
                .logger = self.logger.withScope(@typeName(GossipDumpService)),
                .gossip_table_rw = &self.gossip_table_rw,
                .exit_condition = exit_condition,
            }});
            exit_condition.ordered.exit_index += 1;
        }
    }
};

pub const GossipShared = struct {
    /// table to store gossip values
    gossip_table_rw: RwMux(GossipTable),
    /// manages push message peers
    active_set_rw: RwMux(ActiveSet),
    /// hashes of failed gossip values from pull responses
    failed_pull_hashes_mux: Mux(HashTimeQueue),
    /// manages ping/pong heartbeats for the network
    ping_cache_rw: RwMux(PingCache),
    my_shred_version: Atomic(u16),
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
        inline for (@typeInfo(GossipMetrics).Struct.fields) |field| {
            @field(self, field.name).reset();
        }
    }
};

const TestingLogger = @import("../trace/log.zig").DirectPrintLogger;

test "handle pong messages" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    const contact_info = try localhostTestContactInfo(pubkey);

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        keypair,
        null,
        .noop,
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

    var test_logger = TestingLogger.init(
        std.testing.allocator,
        Logger.TEST_DEFAULT_LEVEL,
    );

    const logger = test_logger.logger();

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        logger,
    );
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    var prng = std.Random.Xoshiro256.init(0);
    const random = prng.random();

    var build_messages_handle = try Thread.spawn(
        .{},
        GossipService.buildMessages,
        .{ gossip_service, 19, .{ .unordered = gossip_service.service_manager.exit } },
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
    var prng = std.rand.DefaultPrng.init(91);

    const allocator = std.testing.allocator;
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var test_logger = TestingLogger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        logger,
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
        var rand_keypair = try KeyPair.create(null);
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

    var prng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var test_logger = TestingLogger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        logger,
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    // get random values
    var gossip_values: [5]SignedGossipData = undefined;
    var kp = try KeyPair.create(null);
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

    var prng = std.rand.DefaultPrng.init(91);
    const random = prng.random();

    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
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
    );
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    const handle = try std.Thread.spawn(.{}, GossipService.run, .{ gossip_service, .{} });

    const prune_pubkey = Pubkey.initRandom(random);
    const prune_data = PruneData.init(prune_pubkey, &.{}, my_pubkey, 0);
    const message = .{
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
    const rando_keypair = try KeyPair.create([_]u8{22} ** 32);

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
        std.time.sleep(std.time.ns_per_ms * 100);
        if (i > MAX_N_SLEEPS) return error.LoopRangeExceeded;
        i += 1;
    }
    while (gossip_service.metrics.prune_messages_dropped.get() != 1) {
        std.time.sleep(std.time.ns_per_ms * 100);
        if (i > MAX_N_SLEEPS) return error.LoopRangeExceeded;
        i += 1;
    }

    gossip_service.shutdown();
    handle.join();

    try std.testing.expect(gossip_service.metrics.pull_requests_dropped.get() == 2);
    try std.testing.expect(gossip_service.metrics.prune_messages_dropped.get() == 1);
}

test "handle pull request" {
    const allocator = std.testing.allocator;

    var prng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = try localhostTestContactInfo(my_pubkey);
    contact_info.shred_version = 99;

    var test_logger = TestingLogger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();
    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        logger,
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
                var value = try SignedGossipData.randomWithIndex(prng.random(), &(try KeyPair.create(null)), 0);
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
    var random_keypair = try KeyPair.create([_]u8{22} ** 32);
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
                response_packet.data[0..response_packet.size],
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
    var prng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var test_logger = TestingLogger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        logger,
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

    var test_logger = TestingLogger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        logger,
    );
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
            const rando_keypair = try KeyPair.create(null);

            var lci = LegacyContactInfo.initRandom(prng.random());
            lci.id = Pubkey.fromPublicKey(&rando_keypair.public_key);
            lci.wallclock = now + 10 * i;
            lci.shred_version = contact_info.shred_version;
            const value = SignedGossipData.initSigned(&rando_keypair, .{ .LegacyContactInfo = lci });

            _ = try lg.mut().insert(value, now + 10 * i);
            pc._setPong(lci.id, lci.gossip);
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
    var prng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var test_logger = TestingLogger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        logger,
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
        var keypair = try KeyPair.create(null);
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

test "test large push messages" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(91);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var test_logger = TestingLogger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        logger,
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
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
            const value = try SignedGossipData.randomWithIndex(prng.random(), &keypair, 0); // contact info
            _ = try lock_guard.mut().insert(value, getWallclockMs());
            try peers.append(ThreadSafeContactInfo.fromLegacyContactInfo(value.data.LegacyContactInfo));
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

    try std.testing.expect(msgs.items.len < 2_000);
}

test "process contact info push packet" {
    const allocator = std.testing.allocator;

    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var test_logger = TestingLogger.init(allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    var gossip_service = try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        null,
        logger,
    );
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    const verified_channel = gossip_service.verified_incoming_channel;
    const responder_channel = gossip_service.packet_outgoing_channel;

    const kp = try KeyPair.create(null);
    const id = Pubkey.fromPublicKey(&kp.public_key);

    var packet_handle = try Thread.spawn(
        .{},
        GossipService.processMessages,
        .{ gossip_service, 19, .{ .unordered = gossip_service.service_manager.exit } },
    );

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
                GossipPullFilter.init(allocator),
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
        std.time.sleep(std.time.ns_per_ms * 100);
        if (i > MAX_N_SLEEPS) return error.LoopRangeExceeded;
        i += 1;
    }

    // the ping message we sent, processed into a pong
    try std.testing.expectEqual(1, responder_channel.len());
    const out_packet = responder_channel.tryReceive().?;
    const out_msg = try bincode.readFromSlice(std.testing.allocator, GossipMessage, &out_packet.data, .{});
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
    const my_keypair = try KeyPair.create(null);
    var prng = std.rand.DefaultPrng.init(91);

    var contact_info = try LegacyContactInfo.initRandom(prng.random()).toContactInfo(std.testing.allocator);
    try contact_info.setSocket(.gossip, gossip_address);

    var test_logger = TestingLogger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    const gossip_service = try GossipService.create(
        std.testing.allocator,
        std.testing.allocator,
        contact_info,
        my_keypair,
        null,
        logger,
    );
    defer {
        gossip_service.deinit();
        std.testing.allocator.destroy(gossip_service);
    }

    const handle = try std.Thread.spawn(.{}, GossipService.run, .{
        gossip_service, .{ .spy_node = true, .dump = false },
    });
    defer {
        gossip_service.shutdown();
        handle.join();
    }
}

const fuzz_service = sig.gossip.fuzz_service;

pub const BenchmarkGossipServiceGeneral = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 5;

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

    pub fn benchmarkGossipService(bench_args: BenchmarkArgs) !sig.time.Duration {
        const allocator = if (@import("builtin").is_test) std.testing.allocator else std.heap.c_allocator;
        var keypair = try KeyPair.create(null);
        var address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8888);
        const endpoint = address.toEndpoint();

        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        var contact_info = ContactInfo.init(allocator, pubkey, 0, 19);
        try contact_info.setSocket(.gossip, address);

        // const logger = Logger.init(allocator, .debug);
        // defer logger.deinit();
        // logger.spawn();

        const logger = .noop;

        // process incoming packets/messsages
        var gossip_service = try GossipService.create(
            allocator,
            allocator,
            contact_info,
            keypair,
            null,
            logger,
        );
        defer {
            gossip_service.metrics.reset();
            gossip_service.deinit();
            allocator.destroy(gossip_service);
        }

        const outgoing_channel = gossip_service.packet_incoming_channel;

        // generate messages
        var prng = std.rand.DefaultPrng.init(19);
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
            gossip_service, .{
                .spy_node = true, // dont build any outgoing messages
                .dump = false,
            },
        });

        // wait for all messages to be processed
        var timer = try sig.time.Timer.start();

        gossip_service.shutdown();
        packet_handle.join();

        return timer.read();
    }
};

/// pull requests require some additional setup to work
pub const BenchmarkGossipServicePullRequests = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 5;

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

    pub fn benchmarkPullRequests(bench_args: BenchmarkArgs) !sig.time.Duration {
        const allocator = if (@import("builtin").is_test) std.testing.allocator else std.heap.c_allocator;
        var keypair = try KeyPair.create(null);
        var address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8888);

        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        var contact_info = ContactInfo.init(allocator, pubkey, 0, 19);
        try contact_info.setSocket(.gossip, address);

        const logger = .noop;

        // process incoming packets/messsages
        var gossip_service = try GossipService.create(
            allocator,
            allocator,
            contact_info,
            keypair,
            null,
            logger,
        );
        defer {
            gossip_service.metrics.reset();
            gossip_service.deinit();
            allocator.destroy(gossip_service);
        }

        // setup recv peer
        const recv_address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8889);
        var recv_keypair = try KeyPair.create(null);
        const recv_pubkey = Pubkey.fromPublicKey(&recv_keypair.public_key);

        var contact_info_recv = ContactInfo.init(allocator, recv_pubkey, 0, 19);
        try contact_info_recv.setSocket(.gossip, recv_address);
        const signed_contact_info_recv = SignedGossipData.initSigned(&recv_keypair, .{
            .ContactInfo = contact_info_recv,
        });

        const now = getWallclockMs();
        var prng = std.rand.DefaultPrng.init(19);
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
            gossip_service, .{
                .spy_node = true, // dont build any outgoing messages
                .dump = false,
            },
        });

        var timer = try sig.time.Timer.start();

        // wait for all messages to be processed
        gossip_service.shutdown();
        packet_handle.join();

        return timer.read();
    }
};

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
