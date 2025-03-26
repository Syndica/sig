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

pub const ScopedLogger = sig.trace.log.ScopedLogger("gossip-send");

pub const Entrypoint = struct { addr: SocketAddr, info: ?ContactInfo = null };

pub const GossipSendService = struct {
    allocator: Allocator,
    gossip_data_allocator: Allocator,
    logger: ScopedLogger,

    packet_incoming_channel: *Channel(Packet),
    verified_incoming_channel: *Channel(GossipMessageWithEndpoint),
    packet_outgoing_channel: *Channel(Packet),

    metrics: gossip.service.GossipMetrics,

    my_contact_info: ContactInfo,
    my_keypair: KeyPair,
    my_pubkey: Pubkey,

    shared: *gossip.service.GossipShared,

    /// all gossip data pushed into this will have its wallclock overwritten during `drainPushQueueToGossipTable`.
    /// NOTE: for all messages appended to this queue, the memory ownership is transfered to this struct.
    push_msg_queue_mux: PushMessageQueue,

    /// entrypoint peers to start the process of discovering the network
    entrypoints: ArrayList(Entrypoint),

    pub const PushMessageQueue = Mux(struct {
        queue: ArrayList(GossipData),
        data_allocator: std.mem.Allocator,
    });

    /// main gossip loop for periodically sending new GossipMessagemessages.
    /// this includes sending push messages, pull requests, and triming old
    /// gossip data (in the gossip_table, active_set, and failed_pull_hashes).
    pub fn buildMessages(self: *GossipSendService, seed: u64, exit_condition: ExitCondition) !void {
        defer {
            exit_condition.afterExit();
            self.logger.info().log("buildMessages loop closed");
        }

        var loop_timer = try sig.time.Timer.start();
        var active_set_timer = try sig.time.Timer.start();
        var pull_req_timer = try sig.time.Timer.start();
        var stats_publish_timer = try sig.time.Timer.start();
        var trim_memory_timer = try sig.time.Timer.start();

        var prng = std.rand.DefaultPrng.init(seed);
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

                    const contact_info: ContactInfo = try self.my_contact_info.clone();
                    errdefer contact_info.deinit();

                    const legacy_contact_info = LegacyContactInfo.fromContactInfo(
                        &self.my_contact_info,
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
                std.time.sleep(time_left_ms * std.time.ns_per_ms);
            }
        }
    }

    /// logic for building new push messages which are sent to peers from the
    /// active set and serialized into packets.
    fn buildPushMessages(self: *GossipSendService, push_cursor: *u64) !ArrayList(Packet) {
        // TODO: find a better static value?
        var buf: [512]GossipVersionedData = undefined;

        const gossip_entries = blk: {
            var gossip_table_lock = self.gossip_table_rw.read();
            defer gossip_table_lock.unlock();

            const gossip_table: *const GossipTable = gossip_table_lock.get();
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
                const value = entry.signedData();

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
            const packets = try gossip.svc.gossipDataToPackets(
                self.allocator,
                &self.my_pubkey,
                gossip_values.items,
                to_endpoint,
                .PushMessage,
            );
            defer packets.deinit();

            try packet_batch.appendSlice(packets.items);
        }

        return packet_batch;
    }

    /// builds new pull request messages and serializes it into a list of Packets
    /// to be sent to a random set of gossip nodes.
    fn buildPullRequests(
        self: *GossipSendService,
        random: std.Random,
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
            const maybe_entrypoint_index = random.intRangeAtMost(usize, 0, self.entrypoints.items.len - 1);
            if (self.entrypoints.items[maybe_entrypoint_index].info) |_| {
                // early exit - we already have the peer in our contact info
                break :blk;
            }
            // we dont have them so well add them to the peer list (as default contact info)
            entrypoint_index = @intCast(maybe_entrypoint_index);
        }

        // filter out peers who have responded to pings
        const ping_cache_result = blk: {
            const ping_cache, var ping_cache_lg = self.ping_cache_rw.writeWithLock();
            defer ping_cache_lg.unlock();
            break :blk try ping_cache.filterValidPeers(self.allocator, self.my_keypair, peers);
        };
        var valid_gossip_peer_indexs = ping_cache_result.valid_peers;
        defer valid_gossip_peer_indexs.deinit();

        // send pings to peers
        var pings_to_send_out = ping_cache_result.pings;
        defer pings_to_send_out.deinit();
        try self.sendPings(pings_to_send_out.items);

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
        if (should_send_to_entrypoint) n_packets += filters.items.len;

        var packet_batch = try ArrayList(Packet).initCapacity(self.allocator, n_packets);
        packet_batch.appendNTimesAssumeCapacity(Packet.default(), n_packets);
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

    /// drains values from the push queue and inserts them into the gossip table.
    /// when inserting values in the gossip table, any errors are ignored.
    fn drainPushQueueToGossipTable(
        self: *GossipSendService,
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
            const signed_gossip_data = SignedGossipData.initSigned(&self.my_keypair, gossip_data_unsigned);

            const result = gossip_table.insert(signed_gossip_data, now) catch |err| break .{ i, err };

            switch (result) {
                // good and expected
                .InsertedNewEntry => {},
                .OverwroteExistingEntry => |*v| v.deinit(deinit_allocator),

                // concerning
                .IgnoredOldValue => {
                    data.deinit(deinit_allocator);
                    self.logger.warn().logf("DrainPushMessages: Ignored old value ({})", .{signed_gossip_data});
                },
                .IgnoredDuplicateValue => {
                    data.deinit(deinit_allocator);
                    self.logger.warn().logf("DrainPushMessages: Ignored duplicate value ({})", .{signed_gossip_data});
                },

                // not possible to reach from `insert`.
                .IgnoredTimeout => unreachable,

                // retry this value
                .GossipTableFull => break .{ i, {} },
            }
        } else .{ push_msg_queue.queue.items.len, {} };

        // remove the gossip values which were inserted
        for (0..consumed_item_count) |_| {
            _ = push_msg_queue.queue.swapRemove(0);
        }

        return maybe_err;
    }

    /// removes old values from the gossip table and failed pull hashes struct
    /// based on the current time. This includes triming the purged values from the
    /// gossip table, triming the max number of pubkeys in the gossip table, and removing
    /// old labels from the gossip table.
    fn trimMemory(
        self: *GossipSendService,
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
    fn populateEntrypointsFromGossipTable(self: *GossipSendService) !bool {
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
    fn assignDefaultShredVersionFromEntrypoint(self: *GossipSendService) bool {
        if (self.my_shred_version.load(.monotonic) != 0) return true;
        for (self.entrypoints.items) |entrypoint| {
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

    // collect gossip table metrics and pushes them to stats
    fn collectGossipTableMetrics(self: *GossipSendService) !void {
        var gossip_table_lock = self.gossip_table_rw.read();
        defer gossip_table_lock.unlock();

        const gossip_table = gossip_table_lock.get();
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

    fn rotateActiveSet(self: *GossipSendService, random: std.Random) !void {
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
        try self.sendPings(pings_to_send_out.items);

        // reset push active set
        var active_set_lock = self.active_set_rw.write();
        defer active_set_lock.unlock();
        var active_set: *ActiveSet = active_set_lock.mut();
        try active_set.initRotate(random, valid_gossip_peers[0..valid_gossip_indexs.items.len]);
    }

    /// returns a list of valid gossip nodes. this works by reading
    /// the contact infos from the gossip table and filtering out
    /// nodes that are 1) too old, 2) have a different shred version, or 3) have
    /// an invalid gossip address.
    fn getThreadSafeGossipNodes(
        self: *GossipSendService,
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
};
