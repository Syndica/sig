const std = @import("std");
const network = @import("zig-network");
const EndPoint = network.EndPoint;
const Packet = @import("../net/packet.zig").Packet;
const PACKET_DATA_SIZE = @import("../net/packet.zig").PACKET_DATA_SIZE;
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
const _gossipMessages = @import("message.zig");
const GossipMessage = _gossipMessages.GossipMessage;
const PruneData = _gossipMessages.PruneData;
const Mux = @import("../sync/mux.zig").Mux;
const RwMux = @import("../sync/mux.zig").RwMux;
const Ping = @import("ping_pong.zig").Ping;
const Pong = @import("ping_pong.zig").Pong;
const bincode = @import("../bincode/bincode.zig");
const gossip = @import("../gossip/data.zig");
const LegacyContactInfo = gossip.LegacyContactInfo;
const ContactInfo = @import("data.zig").ContactInfo;
const socket_tag = @import("data.zig").socket_tag;
const SignedGossipData = gossip.SignedGossipData;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const getWallclockMs = @import("../gossip/data.zig").getWallclockMs;
const _gossip_table = @import("../gossip/table.zig");
const GossipTable = _gossip_table.GossipTable;
const HashTimeQueue = _gossip_table.HashTimeQueue;
const UNIQUE_PUBKEY_CAPACITY = _gossip_table.UNIQUE_PUBKEY_CAPACITY;
const AutoArrayHashSet = _gossip_table.AutoArrayHashSet;
const Logger = @import("../trace/log.zig").Logger;
const Entry = @import("../trace/entry.zig").Entry;
const pull_request = @import("../gossip/pull_request.zig");
const GossipPullFilter = pull_request.GossipPullFilter;
const MAX_NUM_PULL_REQUESTS = pull_request.MAX_NUM_PULL_REQUESTS;
const pull_response = @import("../gossip/pull_response.zig");
const ActiveSet = @import("../gossip/active_set.zig").ActiveSet;
const Hash = @import("../core/hash.zig").Hash;
const socket_utils = @import("../net/socket_utils.zig");
const Channel = @import("../sync/channel.zig").Channel;
const PingCache = @import("./ping_pong.zig").PingCache;
const PingAndSocketAddr = @import("./ping_pong.zig").PingAndSocketAddr;
const echo = @import("../net/echo.zig");
const GossipDumpService = @import("../gossip/dump_service.zig").GossipDumpService;

const Registry = @import("../prometheus/registry.zig").Registry;
const globalRegistry = @import("../prometheus/registry.zig").globalRegistry;
const GetMetricError = @import("../prometheus/registry.zig").GetMetricError;
const Counter = @import("../prometheus/counter.zig").Counter;

const PacketBatch = ArrayList(Packet);
const GossipMessageWithEndpoint = struct { from_endpoint: EndPoint, message: GossipMessage };

pub const GOSSIP_PULL_TIMEOUT_MS: u64 = 15000;
pub const GOSSIP_PUSH_MSG_TIMEOUT_MS: u64 = 30000;
pub const GOSSIP_PRUNE_MSG_TIMEOUT_MS: u64 = 500;

pub const FAILED_INSERTS_RETENTION_MS: u64 = 20_000;

pub const MAX_PACKETS_PER_PUSH: usize = 64;
pub const MAX_BYTES_PER_PUSH: u64 = PACKET_DATA_SIZE * @as(u64, MAX_PACKETS_PER_PUSH);

// 4 (enum) + 32 (pubkey) + 8 (len) = 44
pub const MAX_PUSH_MESSAGE_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;

pub const GOSSIP_SLEEP_MILLIS: u64 = 100;
pub const GOSSIP_PING_CACHE_CAPACITY: usize = 65536;
pub const GOSSIP_PING_CACHE_TTL_NS: u64 = std.time.ns_per_s * 1280;
pub const GOSSIP_PING_CACHE_RATE_LIMIT_DELAY_NS: u64 = std.time.ns_per_s * (1280 / 64);

pub const MAX_NUM_VALUES_PULL_RESPONSE = 20; // TODO: this is approx the rust one -- should tune

/// Maximum number of origin nodes that a PruneData may contain, such that the
/// serialized size of the PruneMessage stays below PACKET_DATA_SIZE.
pub const MAX_PRUNE_DATA_NODES: usize = 32;
pub const NUM_ACTIVE_SET_ENTRIES: usize = 25;

// TODO: replace with get_epoch_duration when BankForks is supported
const DEFAULT_EPOCH_DURATION: u64 = 172800000;

pub const PUB_GOSSIP_STATS_INTERVAL_MS = 2 * std.time.ms_per_s;
pub const GOSSIP_TRIM_INTERVAL_MS = 10 * std.time.ms_per_s;

pub const GossipService = struct {
    allocator: std.mem.Allocator,

    // note: this contact info should not change
    gossip_socket: UdpSocket,
    /// This contact info is mutated by the buildMessages thread, so it must
    /// only be read by that thread, or it needs a synchronization mechanism.
    my_contact_info: ContactInfo,
    my_keypair: KeyPair,
    my_pubkey: Pubkey,
    my_shred_version: std.atomic.Atomic(u16),
    exit: *AtomicBool,

    // communication between threads
    packet_incoming_channel: *Channel(PacketBatch),
    packet_outgoing_channel: *Channel(PacketBatch),
    verified_incoming_channel: *Channel(GossipMessageWithEndpoint),

    gossip_table_rw: RwMux(GossipTable),
    // push message things
    active_set_rw: RwMux(ActiveSet),
    push_msg_queue_mux: Mux(ArrayList(SignedGossipData)),
    // pull message things
    failed_pull_hashes_mux: Mux(HashTimeQueue),

    /// This contact info is mutated by the buildMessages thread, so it must
    /// only be read by that thread, or it needs a synchronization mechanism.
    entrypoints: ArrayList(Entrypoint),
    ping_cache_rw: RwMux(PingCache),
    logger: Logger,
    thread_pool: *ThreadPool,
    echo_server: echo.Server,

    stats: GossipStats,

    // used for benchmarking
    messages_processed: std.atomic.Atomic(usize) = std.atomic.Atomic(usize).init(0),

    const Entrypoint = struct { addr: SocketAddr, info: ?ContactInfo = null };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        my_contact_info: ContactInfo,
        my_keypair: KeyPair,
        entrypoints: ?ArrayList(SocketAddr),
        exit: *AtomicBool,
        logger: Logger,
    ) !Self {
        var packet_incoming_channel = Channel(PacketBatch).init(allocator, 10000);
        var packet_outgoing_channel = Channel(PacketBatch).init(allocator, 10000);
        var verified_incoming_channel = Channel(GossipMessageWithEndpoint).init(allocator, 10000);

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

        var gossip_table = try GossipTable.init(allocator, thread_pool);
        errdefer gossip_table.deinit();
        var gossip_table_rw = RwMux(GossipTable).init(gossip_table);
        var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
        var my_shred_version = my_contact_info.shred_version;
        var active_set = ActiveSet.init(allocator);

        // bind the socket
        const gossip_address = my_contact_info.getSocket(socket_tag.GOSSIP) orelse return error.GossipAddrUnspecified;
        var gossip_socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
        gossip_socket.bindToPort(gossip_address.port()) catch return error.SocketBindFailed;
        gossip_socket.setReadTimeout(socket_utils.SOCKET_TIMEOUT) catch return error.SocketSetTimeoutFailed; // 1 second

        var failed_pull_hashes = HashTimeQueue.init(allocator);
        var push_msg_q = ArrayList(SignedGossipData).init(allocator);

        var echo_server = echo.Server.init(allocator, gossip_address.port(), logger, exit);

        var entrypoint_list = ArrayList(Entrypoint).init(allocator);
        if (entrypoints) |eps| {
            try entrypoint_list.ensureTotalCapacityPrecise(eps.items.len);
            for (eps.items) |ep| entrypoint_list.appendAssumeCapacity(.{ .addr = ep });
        }

        var stats = try GossipStats.init(logger);

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
            .gossip_table_rw = gossip_table_rw,
            .allocator = allocator,
            .push_msg_queue_mux = Mux(ArrayList(SignedGossipData)).init(push_msg_q),
            .active_set_rw = RwMux(ActiveSet).init(active_set),
            .failed_pull_hashes_mux = Mux(HashTimeQueue).init(failed_pull_hashes),
            .entrypoints = entrypoint_list,
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
            .stats = stats,
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
        self.my_contact_info.deinit();
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

        deinitRwMux(&self.gossip_table_rw);
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
    pub fn run(self: *Self, spy_node: bool, dump: bool) !void {
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

        var packet_verifier_handle = try Thread.spawn(.{}, verifyPackets, .{self});
        defer self.joinAndExit(&packet_verifier_handle);

        var packet_handle = try Thread.spawn(.{}, processMessages, .{self});
        defer self.joinAndExit(&packet_handle);

        var maybe_build_messages_handle = if (!spy_node) try Thread.spawn(.{}, buildMessages, .{self}) else null;
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

        var dump_handle = if (dump) try Thread.spawn(.{}, GossipDumpService.run, .{.{
            .allocator = self.allocator,
            .logger = self.logger,
            .gossip_table_rw = &self.gossip_table_rw,
            .exit = self.exit,
        }}) else null;
        defer if (dump_handle) |*h| self.joinAndExit(h);
    }

    const VerifyMessageTask = struct {
        allocator: std.mem.Allocator,
        packet_batch: ArrayList(Packet),
        verified_incoming_channel: *Channel(GossipMessageWithEndpoint),
        logger: Logger,

        task: Task,
        done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(true),

        pub fn callback(task: *Task) void {
            var self = @fieldParentPtr(@This(), "task", task);
            std.debug.assert(!self.done.load(std.atomic.Ordering.Acquire));
            defer self.done.store(true, std.atomic.Ordering.Release);
            defer self.packet_batch.deinit();

            for (self.packet_batch.items) |*packet| {
                var message = bincode.readFromSlice(
                    self.allocator,
                    GossipMessage,
                    packet.data[0..packet.size],
                    bincode.Params.standard,
                ) catch {
                    self.logger.errf("gossip: packet_verify: failed to deserialize", .{});
                    continue;
                };

                message.sanitize() catch {
                    self.logger.errf("gossip: packet_verify: failed to sanitize", .{});
                    bincode.free(self.allocator, message);
                    continue;
                };

                message.verifySignature() catch |e| {
                    self.logger.errf(
                        "gossip: packet_verify: failed to verify signature: {} from {}",
                        .{ e, packet.addr },
                    );
                    bincode.free(self.allocator, message);
                    continue;
                };

                const msg = GossipMessageWithEndpoint{
                    .from_endpoint = packet.addr,
                    .message = message,
                };

                self.verified_incoming_channel.send(msg) catch unreachable;
            }
        }

        /// waits for the task to be done, then resets the done state to false
        fn awaitAndReset(self: *VerifyMessageTask) void {
            while (!self.done.load(std.atomic.Ordering.Acquire)) {
                // wait
            }
            self.done.store(false, std.atomic.Ordering.Release);
        }
    };

    /// main logic for deserializing Packets into GossipMessage messages
    /// and verifing they have valid values, and have valid signatures.
    /// Verified GossipMessagemessages are then sent to the verified_channel.
    fn verifyPackets(self: *Self) !void {
        var tasks = try self.allocator.alloc(VerifyMessageTask, 4);
        defer self.allocator.free(tasks);

        // pre-allocate all the tasks
        for (tasks) |*task| {
            task.* = VerifyMessageTask{
                // .allocator = std.heap.page_allocator, // TODO: swap out with arg
                .allocator = self.allocator, // TODO: swap out with arg
                .task = .{ .callback = VerifyMessageTask.callback },
                .verified_incoming_channel = self.verified_incoming_channel,
                .packet_batch = undefined,
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
                self.packet_incoming_channel.allocator.free(packet_batches);
            }

            // count number of packets
            var n_packets_drained: usize = 0;
            for (packet_batches) |*packet_batch| {
                n_packets_drained += packet_batch.items.len;
            }
            self.stats.gossip_packets_received.add(n_packets_drained);

            // verify in parallel using the threadpool
            // PERF: investigate CPU pinning
            var task_i: usize = 0;
            var n_tasks = tasks.len;
            for (packet_batches) |packet_batch| {
                // find a free task
                var task_ptr = &tasks[task_i];
                while (!task_ptr.done.load(std.atomic.Ordering.Acquire)) {
                    task_i = (task_i + 1) % n_tasks;
                    task_ptr = &tasks[task_i];
                }
                // schedule it
                task_ptr.done.store(false, std.atomic.Ordering.Release);
                task_ptr.packet_batch = packet_batch;

                const batch = Batch.from(&task_ptr.task);
                self.thread_pool.schedule(batch);
            }
        }

        self.logger.debugf("verify_packets loop closed", .{});
    }

    // structs used in process_messages loop
    pub const PingMessage = struct {
        ping: *Ping,
        from_endpoint: *EndPoint,
    };

    pub const PongMessage = struct {
        pong: *Pong,
        from_endpoint: *EndPoint,
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
        from_pubkey: *Pubkey,
    };

    /// main logic for recieving and processing gossip messages.
    pub fn processMessages(self: *Self) !void {
        var timer = std.time.Timer.start() catch unreachable;
        var last_table_trim_ts: u64 = 0;
        var msg_count: usize = 0;

        // we batch messages bc:
        // 1) less lock contention
        // 2) can use packetbatchs (ie, pre-allocated packets)
        // 3) processing read-heavy messages in parallel (specifically pull-requests)

        const init_capacity = socket_utils.PACKETS_PER_BATCH;
        var ping_messages = try ArrayList(PingMessage).initCapacity(self.allocator, init_capacity);
        var pong_messages = try ArrayList(PongMessage).initCapacity(self.allocator, init_capacity);
        var push_messages = try ArrayList(PushMessage).initCapacity(self.allocator, init_capacity);
        var pull_requests = try ArrayList(PullRequestMessage).initCapacity(self.allocator, init_capacity);
        var pull_responses = try ArrayList(PullResponseMessage).initCapacity(self.allocator, init_capacity);
        var prune_messages = try ArrayList(*PruneData).initCapacity(self.allocator, init_capacity);

        defer {
            ping_messages.deinit();
            pong_messages.deinit();
            push_messages.deinit();
            pull_requests.deinit();
            pull_responses.deinit();
            prune_messages.deinit();
        }

        while (!self.exit.load(std.atomic.Ordering.Unordered)) {
            const maybe_messages = try self.verified_incoming_channel.try_drain();

            if (maybe_messages == null) {
                continue;
            }

            if (msg_count == 0) {
                timer.reset();
            }

            const messages = maybe_messages.?;
            defer {
                for (messages) |*msg| {
                    // Important: this uses shallowFree instead of bincode.free
                    //
                    // The message contains some messaging metadata plus a
                    // payload of a SignedGossipData. The metadata won't be needed
                    // after this iteration is complete. The payload will be
                    // needed since it is stored in the GossipTable.
                    //
                    // bincode.free would free the entire message including the
                    // payload. This would lead to a segfault if the data is
                    // accessed from the GossipTable later.
                    //
                    // Not freeing at all would lead to a memory leak of any
                    // allocations in the metadata.
                    //
                    // The compromise is a "shallow" free that only frees the
                    // messaging metadata. SignedGossipData ownership will be
                    // transferred to GossipTable. The GossipTable implementation
                    // becomes responsible for freeing any SignedGossipDatas when
                    // needed.
                    //
                    // TODO: this approach is not ideal because it is difficult
                    // to maintain. Another approach such as reference counting
                    // would be safer. For more info, see:
                    // - GossipTable.remove
                    // - https://github.com/Syndica/sig/pull/69
                    msg.message.shallowFree(self.allocator);
                }
                self.verified_incoming_channel.allocator.free(messages);
            }

            msg_count += messages.len;

            for (messages) |*message| {
                var from_endpoint: EndPoint = message.from_endpoint;

                switch (message.message) {
                    .PushMessage => |*push| {
                        try push_messages.append(PushMessage{
                            .gossip_values = push[1],
                            .from_pubkey = &push[0],
                            .from_endpoint = &from_endpoint,
                        });
                    },
                    .PullResponse => |*pull| {
                        try pull_responses.append(PullResponseMessage{
                            .from_pubkey = &pull[0],
                            .gossip_values = pull[1],
                        });
                    },
                    .PullRequest => |*pull| {
                        const value: SignedGossipData = pull[1];
                        switch (value.data) {
                            .ContactInfo => |*data| {
                                if (data.pubkey.equals(&self.my_pubkey)) {
                                    // talking to myself == ignore
                                    continue;
                                }
                                // Allow spy nodes with shred-verion == 0 to pull from other nodes.
                                if (data.shred_version != 0 and data.shred_version != self.my_shred_version.load(.Monotonic)) {
                                    // non-matching shred version
                                    self.stats.pull_requests_dropped.add(1);
                                    continue;
                                }
                            },
                            .LegacyContactInfo => |*data| {
                                if (data.id.equals(&self.my_pubkey)) {
                                    // talking to myself == ignore
                                    continue;
                                }
                                // Allow spy nodes with shred-verion == 0 to pull from other nodes.
                                if (data.shred_version != 0 and data.shred_version != self.my_shred_version.load(.Monotonic)) {
                                    // non-matching shred version
                                    self.stats.pull_requests_dropped.add(1);
                                    continue;
                                }
                            },
                            // only contact info supported
                            else => {
                                self.stats.pull_requests_dropped.add(1);
                                continue;
                            },
                        }

                        const from_addr = SocketAddr.fromEndpoint(&from_endpoint);
                        if (from_addr.isUnspecified() or from_addr.port() == 0) {
                            // unable to respond to these messages
                            self.stats.pull_requests_dropped.add(1);
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

                        const too_old = prune_wallclock < now -| GOSSIP_PRUNE_MSG_TIMEOUT_MS;
                        const incorrect_destination = !prune_data.destination.equals(&self.my_pubkey);
                        if (too_old or incorrect_destination) {
                            self.stats.prune_messages_dropped.add(1);
                            continue;
                        }
                        try prune_messages.append(prune_data);
                    },
                    .PingMessage => |*ping| {
                        const from_addr = SocketAddr.fromEndpoint(&from_endpoint);
                        if (from_addr.isUnspecified() or from_addr.port() == 0) {
                            // unable to respond to these messages
                            self.stats.ping_messages_dropped.add(1);
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

            // track metrics
            self.stats.gossip_packets_verified.add(messages.len);
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
            self.stats.gossip_packets_processed.add(gossip_packets_processed);

            self.stats.maybeLog();

            // handle batch messages
            if (push_messages.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                self.handleBatchPushMessages(&push_messages) catch |err| {
                    self.logger.errf("handleBatchPushMessages failed: {}", .{err});
                };
                const elapsed = x_timer.read();
                self.stats.handle_batch_push_time.add(elapsed);

                push_messages.clearRetainingCapacity();
            }

            if (prune_messages.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                self.handleBatchPruneMessages(&prune_messages);
                const elapsed = x_timer.read();
                self.stats.handle_batch_prune_time.add(elapsed);

                prune_messages.clearRetainingCapacity();
            }

            if (pull_requests.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                self.handleBatchPullRequest(pull_requests) catch |err| {
                    self.logger.errf("handleBatchPullRequest failed: {}", .{err});
                };
                const elapsed = x_timer.read();
                self.stats.handle_batch_pull_req_time.add(elapsed);

                pull_requests.clearRetainingCapacity();
            }

            if (pull_responses.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                self.handleBatchPullResponses(&pull_responses) catch |err| {
                    self.logger.errf("handleBatchPullResponses failed: {}", .{err});
                };
                const elapsed = x_timer.read();
                self.stats.handle_batch_pull_resp_time.add(elapsed);

                pull_responses.clearRetainingCapacity();
            }

            if (ping_messages.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                self.handleBatchPingMessages(&ping_messages) catch |err| {
                    self.logger.errf("handleBatchPingMessages failed: {}", .{err});
                };
                const elapsed = x_timer.read();
                self.stats.handle_batch_ping_time.add(elapsed);

                ping_messages.clearRetainingCapacity();
            }

            if (pong_messages.items.len > 0) {
                var x_timer = std.time.Timer.start() catch unreachable;
                self.handleBatchPongMessages(&pong_messages);
                const elapsed = x_timer.read();
                self.stats.handle_batch_pong_time.add(elapsed);

                pong_messages.clearRetainingCapacity();
            }

            // TRIM gossip-table
            const trim_elapsed_ts = getWallclockMs() - last_table_trim_ts;
            if (trim_elapsed_ts > GOSSIP_TRIM_INTERVAL_MS) {
                // first check with a read lock
                const should_trim = blk: {
                    var gossip_table_lock = self.gossip_table_rw.read();
                    defer gossip_table_lock.unlock();
                    var gossip_table: *const GossipTable = gossip_table_lock.get();

                    const should_trim = gossip_table.shouldTrim(UNIQUE_PUBKEY_CAPACITY);
                    break :blk should_trim;
                };

                // then trim with write lock
                if (should_trim) {
                    var gossip_table_lock = self.gossip_table_rw.write();
                    defer gossip_table_lock.unlock();
                    var gossip_table: *GossipTable = gossip_table_lock.mut();

                    var x_timer = std.time.Timer.start() catch unreachable;
                    gossip_table.attemptTrim(UNIQUE_PUBKEY_CAPACITY) catch |err| {
                        self.logger.warnf("gossip_table.attemptTrim failed: {s}", .{@errorName(err)});
                    };
                    const elapsed = x_timer.read();
                    self.stats.handle_trim_table_time.add(elapsed);
                }
                last_table_trim_ts = getWallclockMs();
            }
        }

        self.logger.debugf("process_messages loop closed", .{});
    }

    /// main gossip loop for periodically sending new GossipMessagemessages.
    /// this includes sending push messages, pull requests, and triming old
    /// gossip data (in the gossip_table, active_set, and failed_pull_hashes).
    fn buildMessages(
        self: *Self,
    ) !void {
        var last_push_ts: u64 = 0;
        var last_stats_publish_ts: u64 = 0;
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
                self.stats.pull_requests_sent.add(packets.items.len);
                try self.packet_outgoing_channel.send(packets);
            }
            // every other loop
            should_send_pull_requests = !should_send_pull_requests;

            // new push msgs
            self.drainPushQueueToGossipTable(getWallclockMs());
            var maybe_push_packets = self.buildPushMessages(&push_cursor) catch |e| blk: {
                self.logger.errf("failed to generate push messages: {any}", .{e});
                break :blk null;
            };
            if (maybe_push_packets) |push_packets| {
                self.stats.push_messages_sent.add(push_packets.items.len);
                try self.packet_outgoing_channel.sendBatch(push_packets);
                push_packets.deinit();
            }

            // trim data
            try self.trimMemory(getWallclockMs());

            // initialize cluster data from gossip values
            entrypoints_identified = entrypoints_identified or try self.populateEntrypointsFromGossipTable();
            shred_version_assigned = shred_version_assigned or self.assignDefaultShredVersionFromEntrypoint();

            // periodic things
            if (top_of_loop_ts - last_push_ts > GOSSIP_PULL_TIMEOUT_MS / 2) {
                // update wallclock and sign
                self.my_contact_info.wallclock = getWallclockMs();
                var my_contact_info_value = try gossip.SignedGossipData.initSigned(gossip.GossipData{
                    .ContactInfo = try self.my_contact_info.clone(),
                }, &self.my_keypair);
                var my_legacy_contact_info_value = try gossip.SignedGossipData.initSigned(gossip.GossipData{
                    .LegacyContactInfo = LegacyContactInfo.fromContactInfo(&self.my_contact_info),
                }, &self.my_keypair);

                // push contact info
                {
                    var push_msg_queue_lock = self.push_msg_queue_mux.lock();
                    defer push_msg_queue_lock.unlock();
                    var push_msg_queue: *ArrayList(SignedGossipData) = push_msg_queue_lock.mut();

                    try push_msg_queue.append(my_contact_info_value);
                    try push_msg_queue.append(my_legacy_contact_info_value);
                }

                try self.rotateActiveSet();
                last_push_ts = getWallclockMs();
            }

            // publish metrics
            const stats_publish_elapsed_ts = getWallclockMs() - last_stats_publish_ts;
            if (stats_publish_elapsed_ts > PUB_GOSSIP_STATS_INTERVAL_MS) {
                try self.collectGossipTableMetrics();
                last_stats_publish_ts = getWallclockMs();
            }

            // sleep
            const elapsed_ts = getWallclockMs() - top_of_loop_ts;
            if (elapsed_ts < GOSSIP_SLEEP_MILLIS) {
                const time_left_ms = GOSSIP_SLEEP_MILLIS - elapsed_ts;
                std.time.sleep(time_left_ms * std.time.ns_per_ms);
            }
        }
        self.logger.infof("build_messages loop closed", .{});
    }

    // collect gossip table metrics and pushes them to stats
    pub fn collectGossipTableMetrics(self: *Self) !void {
        var gossip_table_lock = self.gossip_table_rw.read();
        defer gossip_table_lock.unlock();

        var gossip_table: *const GossipTable = gossip_table_lock.get();
        const n_entries = gossip_table.store.count();
        const n_pubkeys = gossip_table.pubkey_to_values.count();

        self.stats.table_n_values.add(n_entries);
        self.stats.table_n_pubkeys.add(n_pubkeys);
    }

    pub fn rotateActiveSet(
        self: *Self,
    ) !void {
        const now = getWallclockMs();
        var buf: [NUM_ACTIVE_SET_ENTRIES]ContactInfo = undefined;
        var gossip_peers = try self.getGossipNodes(&buf, NUM_ACTIVE_SET_ENTRIES, now);

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

        var valid_gossip_peers: [NUM_ACTIVE_SET_ENTRIES]ContactInfo = undefined;
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
        var buf: [512]gossip.GossipVersionedData = undefined;

        var gossip_entries = blk: {
            var gossip_table_lock = self.gossip_table_rw.read();
            defer gossip_table_lock.unlock();

            const gossip_table: *const GossipTable = gossip_table_lock.get();
            break :blk gossip_table.getEntriesWithCursor(&buf, push_cursor);
        };

        var packet_batch = ArrayList(ArrayList(Packet)).init(self.allocator);
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
                const too_old = entry_time < now -| GOSSIP_PUSH_MSG_TIMEOUT_MS;
                const too_new = entry_time > now +| GOSSIP_PUSH_MSG_TIMEOUT_MS;
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
                    var gossip_table_lock = self.gossip_table_rw.read();
                    defer gossip_table_lock.unlock();
                    const gossip_table: *const GossipTable = gossip_table_lock.get();

                    break :blk try active_set.getFanoutPeers(self.allocator, origin, gossip_table);
                };
                defer active_set_peers.deinit();

                for (active_set_peers.items) |peer| {
                    var maybe_peer_entry = push_messages.getEntry(peer);
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
            var packets = try gossipDataToPackets(
                self.allocator,
                &self.my_pubkey,
                gossip_values.items,
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
        // get nodes from gossip table
        var buf: [MAX_NUM_PULL_REQUESTS]ContactInfo = undefined;
        const now = getWallclockMs();
        var peers = try self.getGossipNodes(
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

        // compute failed pull gossip hash values
        const failed_pull_hashes_array = blk: {
            var failed_pull_hashes_lock = self.failed_pull_hashes_mux.lock();
            defer failed_pull_hashes_lock.unlock();

            const failed_pull_hashes: *const HashTimeQueue = failed_pull_hashes_lock.get();
            break :blk try failed_pull_hashes.getValues();
        };
        defer failed_pull_hashes_array.deinit();

        // build gossip filters
        var filters = try pull_request.buildGossipPullFilters(
            self.allocator,
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
        const my_contact_info_value = try gossip.SignedGossipData.initSigned(gossip.GossipData{
            .LegacyContactInfo = LegacyContactInfo.fromContactInfo(&self.my_contact_info),
        }, &self.my_keypair);

        if (num_peers != 0) {
            for (filters.items) |filter_i| {
                // TODO: incorperate stake weight in random sampling
                const peer_index = rng.random().intRangeAtMost(usize, 0, num_peers - 1);
                const peer_contact_info_index = valid_gossip_peer_indexs.items[peer_index];
                const peer_contact_info = peers[peer_contact_info_index];
                if (peer_contact_info.getSocket(socket_tag.GOSSIP)) |gossip_addr| {
                    const message = GossipMessage{ .PullRequest = .{ filter_i, my_contact_info_value } };

                    var packet = &packet_batch.items[packet_index];
                    var bytes = try bincode.writeToSlice(&packet.data, message, bincode.Params{});
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
                var bytes = try bincode.writeToSlice(&packet.data, message, bincode.Params{});
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
        value: *SignedGossipData,
        gossip_table: *const GossipTable,
        output: ArrayList(Packet),
        output_limit: *std.atomic.Atomic(i64),
        output_consumed: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),

        task: Task,
        done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),

        pub fn deinit(this: *PullRequestTask) void {
            if (!this.output_consumed.load(.Acquire)) {
                this.output.deinit();
            }
        }

        pub fn callback(task: *Task) void {
            var self = @fieldParentPtr(@This(), "task", task);
            defer self.done.store(true, std.atomic.Ordering.Release);

            const output_limit = self.output_limit.load(std.atomic.Ordering.Unordered);
            if (output_limit <= 0) {
                return;
            }

            const response_gossip_values = pull_response.filterSignedGossipDatas(
                self.allocator,
                self.gossip_table,
                self.filter,
                gossip.getWallclockMs(),
                @as(usize, @max(output_limit, 0)),
            ) catch {
                return;
            };
            defer response_gossip_values.deinit();

            _ = self.output_limit.fetchSub(
                @as(i64, @intCast(response_gossip_values.items.len)),
                std.atomic.Ordering.Release,
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

    fn handleBatchPullRequest(
        self: *Self,
        pull_requests: ArrayList(PullRequestMessage),
    ) !void {
        // update the callers
        // TODO: parallelize this?
        const now = getWallclockMs();
        {
            var gossip_table_lock = self.gossip_table_rw.write();
            defer gossip_table_lock.unlock();
            var gossip_table: *GossipTable = gossip_table_lock.mut();

            for (pull_requests.items) |*req| {
                const caller = req.value.id();
                gossip_table.insert(req.value, now) catch {};
                gossip_table.updateRecordTimestamp(caller, now);
            }
        }

        var valid_indexs = blk: {
            var ping_cache_lock = self.ping_cache_rw.write();
            defer ping_cache_lock.unlock();
            var ping_cache: *PingCache = ping_cache_lock.mut();

            var peers = try ArrayList(ContactInfo).initCapacity(self.allocator, pull_requests.items.len);
            defer peers.deinit();
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            {
                var gossip_table_lock = self.gossip_table_rw.read();
                defer gossip_table_lock.unlock();
                var gossip_table: *const GossipTable = gossip_table_lock.get();
                for (pull_requests.items) |req| {
                    const contact_info = switch (req.value.data) {
                        .ContactInfo => |ci| ci,
                        .LegacyContactInfo => |legacy| gossip_table.getContactInfo(legacy.id) orelse
                            try legacy.toContactInfo(arena.allocator()),
                        else => return error.PullRequestWithoutContactInfo,
                    };
                    peers.appendAssumeCapacity(contact_info);
                }
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
            var gossip_table_lock = self.gossip_table_rw.read();
            const gossip_table: *const GossipTable = gossip_table_lock.get();
            defer gossip_table_lock.unlock();

            var output_limit = std.atomic.Atomic(i64).init(MAX_NUM_VALUES_PULL_RESPONSE);

            for (valid_indexs.items, 0..) |i, task_index| {
                // create the thread task
                tasks[task_index] = PullRequestTask{
                    .task = .{ .callback = PullRequestTask.callback },
                    .my_pubkey = &self.my_pubkey,
                    .from_endpoint = &pull_requests.items[i].from_endpoint,
                    .filter = &pull_requests.items[i].filter,
                    .value = &pull_requests.items[i].value,
                    .gossip_table = gossip_table,
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
                self.stats.pull_responses_sent.add(1);
                // TODO: should only need one mux lock in this loop
                try self.packet_outgoing_channel.send(task.output);
                task.output_consumed.store(true, .Release);
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
            const pong_message = GossipMessage{ .PongMessage = pong };

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
                .debug("gossip: recv ping");
        }
        self.stats.pong_messages_sent.add(n_ping_messages);
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
        var failed_insert_ptrs = ArrayList(*SignedGossipData).init(self.allocator);
        defer failed_insert_ptrs.deinit();

        {
            var gossip_table_lock = self.gossip_table_rw.write();
            var gossip_table: *GossipTable = gossip_table_lock.mut();
            defer gossip_table_lock.unlock();

            for (pull_response_messages.items) |*pull_message| {
                const valid_len = self.filterBasedOnShredVersion(
                    gossip_table,
                    pull_message.gossip_values,
                    pull_message.from_pubkey.*,
                );

                const insert_results = try gossip_table.insertValues(
                    pull_message.gossip_values[0..valid_len],
                    GOSSIP_PULL_TIMEOUT_MS,
                    true,
                    true,
                );

                // silently insert the timeout values
                // (without updating all associated origin values)
                const timeout_indexs = insert_results.timeouts.?;
                defer timeout_indexs.deinit();
                for (timeout_indexs.items) |index| {
                    gossip_table.insert(
                        pull_message.gossip_values[index],
                        now,
                    ) catch {};
                }

                // update the contactInfo timestamps of the successful inserts
                // (and all other origin values)
                const successful_insert_indexs = insert_results.inserted.?;
                defer successful_insert_indexs.deinit();
                for (successful_insert_indexs.items) |index| {
                    const origin = pull_message.gossip_values[index].id();
                    gossip_table.updateRecordTimestamp(origin, now);
                }
                gossip_table.updateRecordTimestamp(pull_message.from_pubkey.*, now);

                var failed_insert_indexs = insert_results.failed.?;
                defer failed_insert_indexs.deinit();
                for (failed_insert_indexs.items) |index| {
                    try failed_insert_ptrs.append(&pull_message.gossip_values[index]);
                }
            }
        }

        {
            var failed_pull_hashes_lock = self.failed_pull_hashes_mux.lock();
            var failed_pull_hashes: *HashTimeQueue = failed_pull_hashes_lock.mut();
            defer failed_pull_hashes_lock.unlock();

            var buf: [PACKET_DATA_SIZE]u8 = undefined;
            for (failed_insert_ptrs.items) |gossip_value_ptr| {
                var bytes = bincode.writeToSlice(&buf, gossip_value_ptr.*, bincode.Params.standard) catch {
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
            var gossip_table_lock = self.gossip_table_rw.read();
            defer gossip_table_lock.unlock();

            const gossip_table: *const GossipTable = gossip_table_lock.get();
            break :blk gossip_table.getContactInfo(prune_destination) orelse {
                return error.CantFindContactInfo;
            };
        };
        const from_gossip_addr = from_contact_info.getSocket(socket_tag.GOSSIP) orelse return error.InvalidGossipAddress;
        gossip.sanitizeSocket(&from_gossip_addr) catch return error.InvalidGossipAddress;
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
            var msg = GossipMessage{ .PruneMessage = .{ self.my_pubkey, prune_data } };
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

        // pre-allocate memory to track insertion failures
        var max_inserts_per_push: usize = 0;
        for (batch_push_messages.items) |*push_message| {
            max_inserts_per_push = @max(max_inserts_per_push, push_message.gossip_values.len);
        }
        var failed_insert_indexs = try std.ArrayList(usize)
            .initCapacity(self.allocator, max_inserts_per_push);
        defer failed_insert_indexs.deinit();

        // insert values and track the failed origins per pubkey
        {
            var timer = try std.time.Timer.start();

            var gossip_table_lock = self.gossip_table_rw.write();
            var gossip_table: *GossipTable = gossip_table_lock.mut();

            defer {
                gossip_table_lock.unlock();
                self.stats.push_messages_time_to_insert.add(timer.read());
            }

            var n_gossip_data: usize = 0;
            var n_failed_inserts: usize = 0;
            var n_invalid_data: usize = 0;

            for (batch_push_messages.items) |*push_message| {
                n_gossip_data += push_message.gossip_values.len;

                const valid_len = self.filterBasedOnShredVersion(
                    gossip_table,
                    push_message.gossip_values,
                    push_message.from_pubkey.*,
                );
                n_invalid_data += push_message.gossip_values.len - valid_len;

                try gossip_table.insertValuesMinAllocs(
                    push_message.gossip_values[0..valid_len],
                    GOSSIP_PUSH_MSG_TIMEOUT_MS,
                    &failed_insert_indexs,
                );
                n_failed_inserts += failed_insert_indexs.items.len;

                // logging this message takes too long and causes a bottleneck
                // self.logger
                //     .field("n_values", valid_len)
                //     .field("from_addr", &push_message.from_pubkey.string())
                //     .field("n_failed_inserts", failed_insert_indexs.items.len)
                //     .debug("gossip: recv push_message");

                if (failed_insert_indexs.items.len == 0) {
                    // dont need to build prune messages
                    continue;
                }

                // lookup contact info
                const from_contact_info = gossip_table.getContactInfo(push_message.from_pubkey.*) orelse {
                    // unable to find contact info
                    continue;
                };
                const from_gossip_addr = from_contact_info.getSocket(socket_tag.GOSSIP) orelse continue;
                from_gossip_addr.sanitize() catch {
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
                    const origin = push_message.gossip_values[failed_index].id();
                    try failed_origins.put(origin, {});
                }
            }

            self.stats.push_message_n_values.add(n_gossip_data);
            self.stats.push_message_n_invalid_values.add(n_failed_inserts);
            self.stats.push_message_n_invalid_values.add(n_invalid_data);
        }

        // build prune packets
        const now = getWallclockMs();
        var timer = try std.time.Timer.start();
        defer {
            self.stats.push_messages_time_build_prune.add(timer.read());
        }
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
            var msg = GossipMessage{ .PruneMessage = .{ self.my_pubkey, prune_data } };

            self.logger
                .field("n_pruned_origins", prune_size)
                .field("to_addr", &from_pubkey.string())
                .debug("gossip: send prune_message");

            var packet = &prune_packet_batch.items[count];
            var written_slice = bincode.writeToSlice(&packet.data, msg, bincode.Params{}) catch unreachable;
            packet.size = written_slice.len;
            packet.addr = from_endpoint;
            count += 1;
        }

        self.stats.prune_messages_sent.add(n_packets);
        try self.packet_outgoing_channel.send(prune_packet_batch);
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
        const purged_cutoff_timestamp = now -| (5 * GOSSIP_PULL_TIMEOUT_MS);
        {
            var gossip_table_lock = self.gossip_table_rw.write();
            defer gossip_table_lock.unlock();
            var gossip_table: *GossipTable = gossip_table_lock.mut();

            try gossip_table.purged.trim(purged_cutoff_timestamp);
            try gossip_table.attemptTrim(UNIQUE_PUBKEY_CAPACITY);

            // TODO: condition timeout on stake weight:
            // - values from nodes with non-zero stake: epoch duration
            // - values from nodes with zero stake:
            //   - if all nodes have zero stake: epoch duration
            //   - if any other nodes have non-zero stake: GOSSIP_PULL_TIMEOUT_MS (15s)
            try gossip_table.removeOldLabels(now, DEFAULT_EPOCH_DURATION);
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
        if (self.my_shred_version.load(.Monotonic) != 0) return true;
        for (self.entrypoints.items) |entrypoint| {
            if (entrypoint.info) |info| {
                if (info.shred_version != 0) {
                    var addr_str = entrypoint.addr.toString();
                    self.logger.infof(
                        "shred version: {} - from entrypoint contact info: {s}",
                        .{ info.shred_version, addr_str[0][0..addr_str[1]] },
                    );
                    self.my_shred_version.store(info.shred_version, .Monotonic);
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
        var push_msg_queue_lock = self.push_msg_queue_mux.lock();
        defer push_msg_queue_lock.unlock();
        var push_msg_queue: *ArrayList(SignedGossipData) = push_msg_queue_lock.mut();

        var gossip_table_lock = self.gossip_table_rw.write();
        defer gossip_table_lock.unlock();
        var gossip_table: *GossipTable = gossip_table_lock.mut();

        while (push_msg_queue.popOrNull()) |gossip_value| {
            gossip_table.insert(gossip_value, now) catch {};
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
            const message = GossipMessage{ .PingMessage = ping_and_addr.ping };

            var packet = &packet_batch.items[i];
            var serialized_ping = bincode.writeToSlice(&packet.data, message, .{}) catch return error.SerializationError;
            packet.size = serialized_ping.len;
            packet.addr = ping_and_addr.socket.toEndpoint();
        }

        self.stats.ping_messages_sent.add(n_pings);
        try self.packet_outgoing_channel.send(packet_batch);
    }

    /// returns a list of valid gossip nodes. this works by reading
    /// the contact infos from the gossip table and filtering out
    /// nodes that are 1) too old, 2) have a different shred version, or 3) have
    /// an invalid gossip address.
    pub fn getGossipNodes(
        self: *Self,
        /// the output slice which will be filled with gossip nodes
        nodes: []ContactInfo,
        /// the maximum number of nodes to return ( max_size == nodes.len but comptime for init of stack array)
        comptime MAX_SIZE: usize,
        /// current time (used to filter out nodes that are too old)
        now: u64,
    ) ![]ContactInfo {
        std.debug.assert(MAX_SIZE == nodes.len);

        // filter only valid gossip addresses
        const GOSSIP_ACTIVE_TIMEOUT = 60 * std.time.ms_per_s;
        const too_old_ts = now -| GOSSIP_ACTIVE_TIMEOUT;

        // * 2 bc we might filter out some
        var buf: [MAX_SIZE * 2]ContactInfo = undefined;
        const contact_infos = blk: {
            var gossip_table_lock = self.gossip_table_rw.read();
            defer gossip_table_lock.unlock();

            var gossip_table: *const GossipTable = gossip_table_lock.get();
            break :blk gossip_table.getContactInfos(&buf, too_old_ts);
        };

        if (contact_infos.len == 0) {
            return nodes[0..0];
        }

        var node_index: usize = 0;
        for (contact_infos) |contact_info| {
            const peer_gossip_addr = contact_info.getSocket(socket_tag.GOSSIP);

            // filter self
            if (contact_info.pubkey.equals(&self.my_pubkey)) {
                continue;
            }
            // filter matching shred version or my_shred_version == 0
            const my_shred_version = self.my_shred_version.load(.Monotonic);
            if (my_shred_version != 0 and my_shred_version != contact_info.shred_version) {
                continue;
            }
            // filter on valid gossip address
            if (peer_gossip_addr) |addr| {
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

    pub fn filterBasedOnShredVersion(
        self: *Self,
        gossip_table: *const GossipTable,
        gossip_values: []SignedGossipData,
        from_pubkey: Pubkey,
    ) usize {
        // we use swap remove which just reorders the array
        // (order dm), so we just track the new len -- ie, no allocations/frees
        const my_shred_version = self.my_shred_version.load(.Monotonic);
        if (my_shred_version == 0) {
            return gossip_values.len;
        }

        var gossip_values_array = ArrayList(SignedGossipData).fromOwnedSlice(self.allocator, gossip_values);
        const sender_matches = gossip_table.checkMatchingShredVersion(from_pubkey, my_shred_version);
        var i: usize = 0;
        while (i < gossip_values_array.items.len) {
            const gossip_value = &gossip_values[i];
            switch (gossip_value.data) {
                // always allow contact info + node instance to update shred versions
                .ContactInfo => {},
                .LegacyContactInfo => {},
                .NodeInstance => {},
                else => {
                    // only allow values where both the sender and origin match our shred version
                    if (!sender_matches or
                        !gossip_table.checkMatchingShredVersion(gossip_value.id(), my_shred_version))
                    {
                        _ = gossip_values_array.swapRemove(i);
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

    handle_batch_ping_time: *Counter,
    handle_batch_pong_time: *Counter,
    handle_batch_push_time: *Counter,
    handle_batch_pull_req_time: *Counter,
    handle_batch_pull_resp_time: *Counter,
    handle_batch_prune_time: *Counter,
    handle_trim_table_time: *Counter,

    push_message_n_values: *Counter,
    push_message_n_failed_inserts: *Counter,
    push_message_n_invalid_values: *Counter,
    push_messages_time_to_insert: *Counter,
    push_messages_time_build_prune: *Counter,

    table_n_values: *Counter,
    table_n_pubkeys: *Counter,

    // logging details
    _logging_fields: struct {
        logger: Logger,
        log_interval_micros: i64 = 10_000_000,
        last_log: i64 = 0,
        last_logged_snapshot: StatsToLog = .{},
        updates_since_last: u64 = 0,
    },

    const StatsToLog = struct {
        gossip_packets_received: u64 = 0,
        ping_messages_recv: u64 = 0,
        pong_messages_recv: u64 = 0,
        push_messages_recv: u64 = 0,
        pull_requests_recv: u64 = 0,
        pull_responses_recv: u64 = 0,
        prune_messages_recv: u64 = 0,
    };

    const Self = @This();

    pub fn init(logger: Logger) GetMetricError!Self {
        var self: Self = undefined;
        const registry = globalRegistry();
        const stats_struct_info = @typeInfo(GossipStats).Struct;
        inline for (stats_struct_info.fields) |field| {
            if (field.name[0] != '_') {
                var field_counter: *Counter = try registry.getOrCreateCounter(field.name);
                @field(self, field.name) = field_counter;
            }
        }

        self._logging_fields = .{ .logger = logger };
        return self;
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
        var msg_slice = bincode.writeToSlice(&packet_buf, message, bincode.Params{}) catch {
            return error.SerializationError;
        };
        var packet = Packet.init(to_endpoint.*, packet_buf, msg_slice.len);
        packets.appendAssumeCapacity(packet);
    }

    return packets;
}

pub fn chunkValuesIntoPacketIndexes(
    allocator: std.mem.Allocator,
    gossip_values: []SignedGossipData,
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

test "gossip.gossip_service: build messages startup and shutdown" {
    const allocator = std.testing.allocator;
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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

    // add some gossip values to push
    var rng = std.rand.DefaultPrng.init(91);
    var lg = gossip_service.gossip_table_rw.write();
    var ping_lock = gossip_service.ping_cache_rw.write();
    var ping_cache: *PingCache = ping_lock.mut();

    var peers = ArrayList(LegacyContactInfo).init(allocator);
    defer peers.deinit();

    for (0..10) |_| {
        var rand_keypair = try KeyPair.create(null);
        var value = try SignedGossipData.randomWithIndex(rng.random(), &rand_keypair, 0); // contact info
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

test "gossip.gossip_service: tests handling prune messages" {
    var rng = std.rand.DefaultPrng.init(91);

    const allocator = std.testing.allocator;
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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
    var lg = gossip_service.gossip_table_rw.write();
    var peers = ArrayList(ContactInfo).init(allocator);
    defer {
        for (peers.items) |p| p.deinit();
        peers.deinit();
    }
    for (0..10) |_| {
        var rand_keypair = try KeyPair.create(null);
        var value = try SignedGossipData.randomWithIndex(rng.random(), &rand_keypair, 0); // contact info
        try lg.mut().insert(value, getWallclockMs());
        try peers.append(try value.data.LegacyContactInfo.toContactInfo(allocator));
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

    var prunes = [_]Pubkey{Pubkey.random(rng.random())};
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

test "gossip.gossip_service: tests handling pull responses" {
    const allocator = std.testing.allocator;

    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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

    try gossip_service.handleBatchPullResponses(&data);

    // make sure values are inserted
    var gossip_table_lock = gossip_service.gossip_table_rw.read();
    var gossip_table: *const GossipTable = gossip_table_lock.get();
    for (gossip_values) |value| {
        _ = gossip_table.get(value.label()).?;
    }
    gossip_table_lock.unlock();

    // try inserting again with same values (should all fail)
    try gossip_service.handleBatchPullResponses(&data);

    var lg = gossip_service.failed_pull_hashes_mux.lock();
    var failed_pull_hashes: *HashTimeQueue = lg.mut();
    try std.testing.expect(failed_pull_hashes.len() == 5);
    lg.unlock();
}

test "gossip.gossip_service: tests handle pull request" {
    const allocator = std.testing.allocator;

    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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
    var gossip_table_lock = gossip_service.gossip_table_rw.write();
    var gossip_table: *GossipTable = gossip_table_lock.mut();
    const N_FILTER_BITS = 1;

    var done = false;
    var count: usize = 0;
    while (!done) {
        count += 1;
        for (0..5) |_| {
            var value = try SignedGossipData.randomWithIndex(rng.random(), &my_keypair, 0);
            value.data.LegacyContactInfo.id = Pubkey.random(rng.random());
            try gossip_table.insert(value, getWallclockMs());

            // make sure well get a response from the request
            const vers_value = gossip_table.get(value.label()).?;
            const hash_bits = pull_request.hashToU64(&vers_value.value_hash) >> (64 - N_FILTER_BITS);
            if (hash_bits == 0) {
                done = true;
            }
        }

        if (count > 5) {
            @panic("something went wrong");
        }
    }
    gossip_table_lock.unlock();

    const Bloom = @import("../bloom/bloom.zig").Bloom;
    // only consider the first bit so we know well get matches
    var bloom = try Bloom.random(allocator, 100, 0.1, N_FILTER_BITS);
    defer bloom.deinit();

    var rando_keypair = try KeyPair.create([_]u8{22} ** 32);
    var rando_pubkey = Pubkey.fromPublicKey(&rando_keypair.public_key);

    var ci_data = gossip.GossipData.randomFromIndex(rng.random(), 0);
    ci_data.LegacyContactInfo.id = rando_pubkey;
    var gossip_value = try SignedGossipData.initSigned(ci_data, &rando_keypair);

    const addr = SocketAddr.random(rng.random());
    var ping_lock = gossip_service.ping_cache_rw.write();
    var ping_cache: *PingCache = ping_lock.mut();
    ping_cache._setPong(rando_pubkey, addr);
    ping_lock.unlock();

    var filter = GossipPullFilter{
        .filter = bloom,
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };

    var pull_requests = ArrayList(GossipService.PullRequestMessage).init(allocator);
    defer pull_requests.deinit();
    try pull_requests.append(GossipService.PullRequestMessage{
        .filter = filter,
        .from_endpoint = (contact_info.getSocket(socket_tag.GOSSIP) orelse unreachable).toEndpoint(),
        .value = gossip_value,
    });

    try gossip_service.handleBatchPullRequest(pull_requests);
    {
        var packet_lg = gossip_service.packet_outgoing_channel.buffer.lock();
        defer packet_lg.unlock();
        var outgoing_packets: *const ArrayList(PacketBatch) = packet_lg.get();
        try std.testing.expect(outgoing_packets.items.len > 0);
    }
}

test "gossip.gossip_service: test build prune messages and handle push messages" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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

    var ci_value = try SignedGossipData.initSigned(gossip.GossipData{
        .LegacyContactInfo = send_contact_info,
    }, &my_keypair);
    var lg = gossip_service.gossip_table_rw.write();
    try lg.mut().insert(ci_value, getWallclockMs());
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
    var message = try bincode.readFromSlice(
        allocator,
        GossipMessage,
        packet.data[0..packet.size],
        bincode.Params.standard,
    );
    defer bincode.free(allocator, message);

    var prune_data = message.PruneMessage[1];
    try std.testing.expect(prune_data.destination.equals(&push_from));
    try std.testing.expectEqual(prune_data.prunes.len, 10);
}

test "gossip.gossip_service: test build pull requests" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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
    var lg = gossip_service.gossip_table_rw.write();
    for (0..20) |_| {
        var value = try SignedGossipData.randomWithIndex(rng.random(), &keypair, 0);
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

test "gossip.gossip_service: test build push messages" {
    const allocator = std.testing.allocator;
    var rng = std.rand.DefaultPrng.init(91);
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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
    var peers = ArrayList(ContactInfo).init(allocator);
    defer {
        for (peers.items) |p| p.deinit();
        peers.deinit();
    }
    var lg = gossip_service.gossip_table_rw.write();
    for (0..10) |_| {
        var keypair = try KeyPair.create(null);
        var value = try SignedGossipData.randomWithIndex(rng.random(), &keypair, 0); // contact info
        try lg.mut().insert(value, getWallclockMs());
        try peers.append(try value.data.LegacyContactInfo.toContactInfo(allocator));
    }
    lg.unlock();

    var keypair = try KeyPair.create([_]u8{1} ** 32);
    // var id = Pubkey.fromPublicKey(&keypair.public_key);
    var value = try SignedGossipData.random(rng.random(), &keypair);

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
    gossip_service.drainPushQueueToGossipTable(getWallclockMs());

    var clg = gossip_service.gossip_table_rw.read();
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
    var id = Pubkey.fromPublicKey(&keypair.public_key);
    const contact_info = try localhostTestContactInfo(id);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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
    var data = gossip.GossipData.randomFromIndex(rng.random(), 0);
    data.LegacyContactInfo.id = id;
    data.LegacyContactInfo.wallclock = 0;
    var value = try SignedGossipData.initSigned(data, &keypair);

    try std.testing.expect(try value.verify(id));

    var values = [_]gossip.SignedGossipData{value};
    const message = GossipMessage{
        .PushMessage = .{ id, &values },
    };

    var peer = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);
    var from = peer.toEndpoint();

    var buf = [_]u8{0} ** PACKET_DATA_SIZE;
    var out = try bincode.writeToSlice(buf[0..], message, bincode.Params{});
    var packet = Packet.init(from, buf, out.len);
    var packet_batch = ArrayList(Packet).init(allocator);
    for (0..3) |_| {
        try packet_batch.append(packet);
    }
    try packet_channel.send(packet_batch);

    var packet_batch_2 = ArrayList(Packet).init(allocator);

    // send one which fails sanitization
    var value_v2 = try SignedGossipData.initSigned(gossip.GossipData.randomFromIndex(rng.random(), 2), &keypair);
    value_v2.data.EpochSlots[0] = gossip.MAX_EPOCH_SLOTS;
    var values_v2 = [_]gossip.SignedGossipData{value_v2};
    const message_v2 = GossipMessage{
        .PushMessage = .{ id, &values_v2 },
    };
    var buf_v2 = [_]u8{0} ** PACKET_DATA_SIZE;
    var out_v2 = try bincode.writeToSlice(buf_v2[0..], message_v2, bincode.Params{});
    var packet_v2 = Packet.init(from, buf_v2, out_v2.len);
    try packet_batch_2.append(packet_v2);

    // send one with a incorrect signature
    var rand_keypair = try KeyPair.create([_]u8{3} ** 32);
    var value2 = try SignedGossipData.initSigned(gossip.GossipData.randomFromIndex(rng.random(), 0), &rand_keypair);
    var values2 = [_]gossip.SignedGossipData{value2};
    const message2 = GossipMessage{
        .PushMessage = .{ id, &values2 },
    };
    var buf2 = [_]u8{0} ** PACKET_DATA_SIZE;
    var out2 = try bincode.writeToSlice(buf2[0..], message2, bincode.Params{});
    var packet2 = Packet.init(from, buf2, out2.len);
    try packet_batch_2.append(packet2);

    // send it with a SignedGossipData which hash a slice
    {
        var rand_pubkey = Pubkey.fromPublicKey(&rand_keypair.public_key);
        var dshred = gossip.DuplicateShred.random(rng.random());
        var chunk: [32]u8 = .{1} ** 32;
        dshred.chunk = &chunk;
        dshred.from = rand_pubkey;
        var dshred_data = gossip.GossipData{
            .DuplicateShred = .{ 1, dshred },
        };
        var dshred_value = try SignedGossipData.initSigned(dshred_data, &rand_keypair);
        var values3 = [_]gossip.SignedGossipData{dshred_value};
        const message3 = GossipMessage{
            .PushMessage = .{ id, &values3 },
        };
        var buf3 = [_]u8{0} ** PACKET_DATA_SIZE;
        var out3 = try bincode.writeToSlice(buf3[0..], message3, bincode.Params{});
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

test "gossip.gossip_service: process contact info push packet" {
    const allocator = std.testing.allocator;
    var exit = AtomicBool.init(false);
    var my_keypair = try KeyPair.create([_]u8{1} ** 32);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const contact_info = try localhostTestContactInfo(my_pubkey);

    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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
    var pk = Pubkey.fromPublicKey(&kp.public_key);

    var packet_handle = try Thread.spawn(
        .{},
        GossipService.processMessages,
        .{&gossip_service},
    );

    // send a push message
    var id = pk;

    // new contact info
    var legacy_contact_info = LegacyContactInfo.default(id);
    var gossip_data = gossip.GossipData{
        .LegacyContactInfo = legacy_contact_info,
    };
    var gossip_value = try gossip.SignedGossipData.initSigned(gossip_data, &kp);
    var heap_values = try allocator.alloc(gossip.SignedGossipData, 1);
    heap_values[0] = gossip_value;
    const msg = GossipMessage{
        .PushMessage = .{ id, heap_values },
    };

    // packet
    const peer = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8000).toEndpoint();
    const message = GossipMessageWithEndpoint{
        .from_endpoint = peer,
        .message = msg,
    };
    try verified_channel.send(message);

    // ping
    const ping_msg = GossipMessageWithEndpoint{
        .message = GossipMessage{
            .PingMessage = try Ping.init(.{0} ** 32, &kp),
        },
        .from_endpoint = peer,
    };
    try verified_channel.send(ping_msg);

    // correct insertion into table
    var buf2: [100]ContactInfo = undefined;
    std.time.sleep(std.time.ns_per_s);

    {
        var lg = gossip_service.gossip_table_rw.read();
        var res = lg.get().getContactInfos(&buf2, 0);
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
    var contact_info = try LegacyContactInfo.random(rng.random()).toContactInfo(std.testing.allocator);
    try contact_info.setSocket(socket_tag.GOSSIP, gossip_address);
    var exit = AtomicBool.init(false);
    var logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
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
        .{ &gossip_service, true, false },
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

    pub const BenchmarkArgs = struct {
        num_message_iterations: usize,
        name: []const u8 = "",
    };

    pub const args = [_]BenchmarkArgs{ .{
        .num_message_iterations = 1_000,
        .name = "1k_msgs",
    }, .{
        .num_message_iterations = 5_000,
        .name = "5k_msgs",
    }, .{
        .num_message_iterations = 10_000,
        .name = "10k_msgs",
    } };

    pub fn benchmarkGossipServiceProcessMessages(bench_args: BenchmarkArgs) !usize {
        const num_message_iterations = bench_args.num_message_iterations;
        const allocator = std.heap.page_allocator;
        var keypair = try KeyPair.create(null);
        var address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8888);
        var endpoint = address.toEndpoint();

        var pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        var contact_info = ContactInfo.init(allocator, pubkey, 0, 19);
        try contact_info.setSocket(socket_tag.GOSSIP, address);

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

        var packet_handle = try Thread.spawn(.{}, GossipService.run, .{ &gossip_service, true, false });

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
        var timer = try std.time.Timer.start();
        while (true) {
            const v = gossip_service.messages_processed.load(std.atomic.Ordering.Acquire);
            if (v >= msg_sent) {
                break;
            }
        }
        const elapsed = timer.read();

        exit.store(true, std.atomic.Ordering.Unordered);
        packet_handle.join();

        sender_exit.store(true, std.atomic.Ordering.Unordered);
        outgoing_handle.join();

        return elapsed;
    }
};

fn localhostTestContactInfo(id: Pubkey) !ContactInfo {
    var contact_info = try LegacyContactInfo.default(id).toContactInfo(std.testing.allocator);
    try contact_info.setSocket(socket_tag.GOSSIP, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0));
    return contact_info;
}
