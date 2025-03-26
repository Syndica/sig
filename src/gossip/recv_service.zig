const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const gossip = @import("lib.zig");

const bincode = sig.bincode;
const socket_utils = sig.net.socket_utils;
const pull_request = sig.gossip.pull_request;
const pull_response = sig.gossip.pull_response;

const Allocator = std.mem.Allocator;
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

const endpointToString = sig.net.endpointToString;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.time.getWallclockMs;
const deinitMux = sig.sync.mux.deinitMux;

const PACKET_DATA_SIZE = sig.net.packet.PACKET_DATA_SIZE;
const UNIQUE_PUBKEY_CAPACITY = sig.gossip.table.UNIQUE_PUBKEY_CAPACITY;
const MAX_NUM_PULL_REQUESTS = sig.gossip.pull_request.MAX_NUM_PULL_REQUESTS;

const GossipMessageWithEndpoint = gossip.svc.GossipMessageWithEndpoint;

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

pub const ScopedLogger = sig.trace.log.ScopedLogger("gossip-recv");

pub const GossipRecvService = struct {
    allocator: Allocator,
    gossip_data_allocator: Allocator,
    logger: ScopedLogger,
    verified_incoming_channel: *Channel(Packet),
    packet_outgoing_channel: *Channel(Packet),
    metrics: GossipRecvMetrics,
    my_keypair: KeyPair,
    my_pubkey: Pubkey,

    my_shred_version: Atomic(u16),
    /// table to store gossip values
    gossip_table_rw: RwMux(GossipTable),
    /// manages push message peers
    active_set_rw: RwMux(ActiveSet),
    /// manages ping/pong heartbeats for the network
    ping_cache_rw: RwMux(PingCache),
    failed_pull_hashes_mux: Mux(HashTimeQueue),

    thread_pool: ThreadPool,

    /// main logic for recieving and processing gossip messages.
    pub fn processMessages(self: *GossipRecvService, seed: u64, exit_condition: ExitCondition) !void {
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

        var trim_table_timer = try sig.time.Timer.start();

        // keep waiting for new data until,
        // - `exit` isn't set,
        // - there isn't any data to process in the input channel, in order to block the join until we've finished
        while (true) {
            self.verified_incoming_channel.waitToReceive(exit_condition) catch break;

            var msg_count: usize = 0;
            while (self.verified_incoming_channel.tryReceive()) |message| {
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
            if (push_messages.items.len > 0) {
                var x_timer = try sig.time.Timer.start();
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
                var x_timer = try sig.time.Timer.start();
                self.handleBatchPruneMessages(&prune_messages);
                const elapsed = x_timer.read().asMillis();
                self.metrics.handle_batch_prune_time.observe(elapsed);

                for (prune_messages.items) |prune| {
                    prune.deinit(self.gossip_data_allocator);
                }
                prune_messages.clearRetainingCapacity();
            }

            if (pull_requests.items.len > 0) {
                var x_timer = try sig.time.Timer.start();
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
                var x_timer = try sig.time.Timer.start();
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
                var x_timer = try sig.time.Timer.start();
                self.handleBatchPingMessages(&ping_messages) catch |err| {
                    self.logger.err().logf("handleBatchPingMessages failed: {}", .{err});
                };
                const elapsed = x_timer.read().asMillis();
                self.metrics.handle_batch_ping_time.observe(elapsed);

                ping_messages.clearRetainingCapacity();
            }

            if (pong_messages.items.len > 0) {
                var x_timer = try sig.time.Timer.start();
                self.handleBatchPongMessages(&pong_messages);
                const elapsed = x_timer.read().asMillis();
                self.metrics.handle_batch_pong_time.observe(elapsed);

                pong_messages.clearRetainingCapacity();
            }

            // TRIM gossip-table
            if (trim_table_timer.read().asNanos() > TABLE_TRIM_RATE.asNanos()) {
                defer trim_table_timer.reset();
                try self.attemptGossipTableTrim();
            }
        }
    }

    /// For all pull requests:
    ///     - PullRequestMessage.value is inserted into the gossip table
    ///     - PullRequestMessage.filter is freed in process messages
    fn handleBatchPullRequest(
        self: *GossipRecvService,
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
                switch (result) {
                    .InsertedNewEntry => {},
                    .OverwroteExistingEntry => |x| x.deinit(self.gossip_data_allocator),
                    else => {
                        req.value.deinit(self.gossip_data_allocator);
                    },
                }
            }
        }

        var valid_indexs = blk: {
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

            const result = try ping_cache.filterValidPeers(self.allocator, self.my_keypair, peers.items);
            defer result.pings.deinit();

            try self.sendPings(result.pings.items);

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

            for (valid_indexs.items, 0..) |i, task_index| {
                // create the thread task
                tasks[task_index] = PullRequestTask{
                    .task = .{ .callback = PullRequestTask.callback },
                    .wg_done = &wg,
                    .allocator = self.allocator,
                    .my_pubkey = &self.my_pubkey,
                    .gossip_table = gossip_table,
                    .output_limit = &output_limit,
                    .seed = seed + i,
                    .output = ArrayList(Packet).init(self.allocator),
                    .from_endpoint = &pull_requests[i].from_endpoint,
                    .filter = &pull_requests[i].filter,
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
        self: *GossipRecvService,
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
        self: *GossipRecvService,
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
    pub fn handleBatchPullResponses(
        self: *GossipRecvService,
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
                        .InsertedNewEntry => self.metrics.pull_response_n_new_inserts.inc(),
                        .OverwroteExistingEntry => self.metrics.pull_response_n_overwrite_existing.inc(),
                        .IgnoredOldValue => self.metrics.pull_response_n_old_value.inc(),
                        .IgnoredDuplicateValue => self.metrics.pull_response_n_duplicate_value.inc(),
                        .IgnoredTimeout => self.metrics.pull_response_n_timeouts.inc(),
                        .GossipTableFull => {},
                    }
                }
                self.metrics.pull_response_n_invalid_shred_version.add(invalid_shred_count);

                for (insert_results.items, 0..) |result, index| {
                    if (result.wasInserted()) {
                        // update the contactInfo (and all other origin values) timestamps of
                        // successful inserts
                        const origin = pull_message.gossip_values[index].id();
                        gossip_table.updateRecordTimestamp(origin, now);

                        switch (result) {
                            .OverwroteExistingEntry => |old_data| {
                                // if the value was overwritten, we need to free the old value
                                old_data.deinit(self.gossip_data_allocator);
                            },
                            else => {},
                        }
                    } else if (result == .IgnoredTimeout) {
                        // silently insert the timeout values
                        // (without updating all associated origin values)
                        _ = try gossip_table.insert(pull_message.gossip_values[index], now);
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
                gossip_value_ptr.deinit(self.gossip_data_allocator);
            }
        }
    }

    /// logic for handling a prune message. verifies the prune message
    /// is not too old, and that the destination pubkey is not the local node,
    /// then updates the active set to prune the list of origin Pubkeys.
    pub fn handleBatchPruneMessages(
        self: *GossipRecvService,
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
        self: *GossipRecvService,
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
        var insert_results = try std.ArrayList(GossipTable.InsertResult).initCapacity(
            self.allocator,
            max_inserts_per_push,
        );
        defer insert_results.deinit();

        // insert values and track the failed origins per pubkey
        {
            var timer = try sig.time.Timer.start();
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
                        .InsertedNewEntry => self.metrics.push_message_n_new_inserts.inc(),
                        .OverwroteExistingEntry => |old_data| {
                            self.metrics.push_message_n_overwrite_existing.inc();
                            // if the value was overwritten, we need to free the old value
                            old_data.deinit(self.gossip_data_allocator);
                        },
                        .IgnoredOldValue => self.metrics.push_message_n_old_value.inc(),
                        .IgnoredDuplicateValue => self.metrics.push_message_n_duplicate_value.inc(),
                        .IgnoredTimeout => self.metrics.push_message_n_timeouts.inc(),
                        .GossipTableFull => {},
                    }
                    if (!result.wasInserted()) {
                        insert_fail_count += 1;
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
                // free failed inserts
                defer {
                    for (insert_results.items, 0..) |result, index| {
                        if (!result.wasInserted()) {
                            push_message.gossip_values[index].deinit(self.gossip_data_allocator);
                        }
                    }
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
            self.metrics.push_messages_time_build_prune.observe(elapsed);
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

            var packet = Packet.default();
            const written_slice = bincode.writeToSlice(&packet.data, msg, .{}) catch unreachable;
            packet.size = written_slice.len;
            packet.addr = from_endpoint;

            try self.packet_outgoing_channel.send(packet);
            self.metrics.prune_messages_sent.add(1);
        }
    }

    /// Sorts the incoming `gossip_values` slice to place the valid gossip data
    /// at the start, and returns the number of valid gossip values in that slice.
    fn filterBasedOnShredVersion(
        self: *GossipRecvService,
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
                        removed_value.deinit(self.gossip_data_allocator);
                        continue; // do not incrememnt `i`. it has a new value we need to inspect.
                    }
                },
            }
            i += 1;
        }
        return gossip_values_array.items.len;
    }
};

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

        const packets = gossip.svc.gossipDataToPackets(
            self.allocator,
            self.my_pubkey,
            response_gossip_values.items,
            self.from_endpoint,
            .PullResponse,
        ) catch return;
        defer packets.deinit();

        if (packets.items.len > 0) {
            self.output.appendSlice(packets.items) catch {
                std.debug.panic("thread task: failed to append packets", .{});
            };
        }
    }
};

pub const GossipRecvMetrics = struct {
    gossip_packets_verified_total: *Counter,
    gossip_packets_processed_total: *Counter,

    ping_messages_recv: *Counter,
    pong_messages_recv: *Counter,
    push_messages_recv: *Counter,
    pull_requests_recv: *Counter,
    pull_responses_recv: *Counter,
    prune_messages_recv: *Counter,
};

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
