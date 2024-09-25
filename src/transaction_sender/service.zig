const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");

const socket_utils = sig.net.socket_utils;

const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);
const UdpSocket = network.Socket;

const ClusterType = sig.accounts_db.genesis_config.ClusterType;
const Slot = sig.core.Slot;
const Signature = sig.core.Signature;
const GossipTable = sig.gossip.GossipTable;
const SocketAddr = sig.net.SocketAddr;
const Packet = sig.net.Packet;
const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const RpcClient = sig.rpc.Client;
const RwMux = sig.sync.RwMux;
const Channel = sig.sync.Channel;
const Duration = sig.time.Duration;
const Instant = sig.time.Instant;
const Timer = sig.time.Timer;
const Logger = sig.trace_ng.log.Logger;
const LeaderInfo = sig.transaction_sender.LeaderInfo;
const TransactionInfo = sig.transaction_sender.TransactionInfo;
const TransactionPool = sig.transaction_sender.TransactionPool;

const globalRegistry = sig.prometheus.globalRegistry;

/// Basic send transaction service that listens for transactions on a channel.
/// Transactions are added to the pool and retried until they are confirmed, failed,
/// timed out, or reach the max retries.
/// The leader schedule and current slot are loaded via RPC calls to the cluster.
/// The leader TPU addresses are loaded from the gossip table.
/// TODO:
/// - Add nonce handling
/// - Remove RPC calls
pub const Service = struct {
    allocator: std.mem.Allocator,
    config: Config,
    stats: Stats,
    transaction_pool: TransactionPool,
    leader_info_rw: RwMux(LeaderInfo),
    send_socket: UdpSocket,
    send_channel: *Channel(std.ArrayList(Packet)),
    receive_channel: *Channel(TransactionInfo),
    exit: *AtomicBool,
    logger: *Logger,

    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
        receive_channel: *Channel(TransactionInfo),
        gossip_table_rw: *RwMux(GossipTable),
        exit: *AtomicBool,
        logger: *Logger,
    ) !Service {
        return .{
            .allocator = allocator,
            .config = config,
            .stats = try Stats.init(),
            .transaction_pool = TransactionPool.init(
                allocator,
                config.pool_max_size,
            ),
            .leader_info_rw = RwMux(LeaderInfo).init(try LeaderInfo.init(
                allocator,
                config,
                gossip_table_rw,
                logger,
            )),
            .send_socket = try UdpSocket.create(
                .ipv4,
                .udp,
            ),
            .send_channel = Channel(std.ArrayList(Packet)).init(
                allocator,
                config.pool_max_size,
            ),
            .receive_channel = receive_channel,
            .logger = logger,
            .exit = exit,
        };
    }

    pub fn run(self: *Service) !void {
        const send_socket_handle = try std.Thread.spawn(
            .{},
            socket_utils.sendSocket,
            .{
                self.send_socket,
                self.send_channel,
                self.exit,
                self.logger,
            },
        );

        const receive_transactions_handle = try std.Thread.spawn(
            .{},
            Service.receiveTransactionsThread,
            .{self},
        );

        const process_transactions_handle = try std.Thread.spawn(
            .{},
            Service.processTransactionsThread,
            .{self},
        );

        send_socket_handle.join();
        receive_transactions_handle.join();
        process_transactions_handle.join();
    }

    /// Receives transactions, performing an initial send and then adding to the pool
    fn receiveTransactionsThread(self: *Service) !void {
        errdefer self.exit.store(true, .unordered);

        var last_batch_sent = Instant.now();
        var transaction_batch = std.AutoArrayHashMap(Signature, TransactionInfo).init(self.allocator);
        defer transaction_batch.deinit();

        while (!self.exit.load(.unordered)) {
            const transaction = self.receive_channel.receive() orelse break;
            self.stats.transactions_received_count.add(1);

            if (!transaction_batch.contains(transaction.signature) and
                !self.transaction_pool.contains(transaction.signature))
            {
                try transaction_batch.put(transaction.signature, transaction);
            } else if (transaction_batch.count() == 0) {
                continue;
            }

            if (transaction_batch.count() >= self.config.batch_size or
                last_batch_sent.elapsed().asNanos() >= self.config.batch_send_rate.asNanos())
            {
                const leader_addresses = try self.getLeaderAddresses();
                defer leader_addresses.deinit();

                try self.sendTransactions(transaction_batch.values(), leader_addresses);
                last_batch_sent = Instant.now();

                self.transaction_pool.addTransactions(transaction_batch.values()) catch {
                    self.logger.warn("Transaction pool is full, dropping transactions");
                };

                transaction_batch.clearRetainingCapacity();
            }
        }
    }

    /// Retries transactions if they are still valid, otherwise remove from the pool
    fn processTransactionsThread(self: *Service) !void {
        errdefer self.exit.store(true, .unordered);

        var rpc_client = RpcClient.init(
            self.allocator,
            self.config.cluster,
            .{ .max_retries = self.config.rpc_retries, .logger = self.logger },
        );
        defer rpc_client.deinit();

        while (!self.exit.load(.unordered)) {
            std.time.sleep(self.config.pool_process_rate.asNanos());
            if (self.transaction_pool.count() == 0) continue;
            var timer = try Timer.start();

            try self.processTransactions(&rpc_client);
            self.stats.process_transactions_latency_millis.set(timer.lap().asMillis());

            try self.retryTransactions();
            self.stats.retry_transactions_latency_millis.set(timer.lap().asMillis());

            self.transaction_pool.purge();
            self.stats.transactions_pending.set(self.transaction_pool.count());

            self.stats.log(self.logger);
        }
    }

    /// Checks for transactions to retry or drop from the pool
    fn processTransactions(self: *Service, rpc_client: *RpcClient) !void {
        var block_height_timer = try Timer.start();
        const block_height_response = try rpc_client.getBlockHeight(
            self.allocator,
            .{ .commitment = .processed },
        );
        defer block_height_response.deinit();
        const block_height = try block_height_response.result();
        self.stats.rpc_block_height_latency_millis.set(block_height_timer.read().asMillis());

        // We need to hold a read lock until we are finished using the signatures and transactions, otherwise
        // the receiver thread could add new transactions and corrupt the underlying array
        const signatures, const transactions, var transactions_lg = self.transaction_pool.readSignaturesAndTransactionsWithLock();
        defer transactions_lg.unlock();

        var signature_statuses_timer = try Timer.start();
        const signature_statuses_response = try rpc_client.getSignatureStatuses(
            self.allocator,
            signatures,
            .{ .searchTransactionHistory = false },
        );
        defer signature_statuses_response.deinit();
        const signature_statuses = try signature_statuses_response.result();
        self.stats.rpc_signature_statuses_latency_millis.set(signature_statuses_timer.read().asMillis());

        for (signature_statuses.value, signatures, transactions) |maybe_signature_status, signature, transaction_info| {
            if (maybe_signature_status) |signature_status| {
                if (signature_status.confirmations == null) {
                    try self.transaction_pool.drop_signatures.append(signature);
                    self.stats.transactions_rooted_count.add(1);
                    continue;
                }

                if (signature_status.err) |_| {
                    try self.transaction_pool.drop_signatures.append(signature);
                    self.stats.transactions_failed_count.add(1);
                    continue;
                }

                if (transaction_info.isExpired(block_height)) {
                    try self.transaction_pool.drop_signatures.append(signature);
                    self.stats.transactions_expired_count.add(1);
                    continue;
                }
            } else {
                if (transaction_info.exceededMaxRetries(self.config.default_max_retries)) {
                    try self.transaction_pool.drop_signatures.append(signature);
                    self.stats.transactions_exceeded_max_retries_count.add(1);
                    continue;
                }

                if (transaction_info.shouldRetry(self.config.retry_rate)) {
                    try self.transaction_pool.retry_signatures.append(signature);
                    self.stats.transactions_retry_count.add(1);
                }
            }
        }
    }

    /// Sends retry transactions in batches to the leader TPU addresses
    fn retryTransactions(self: *Service) !void {
        if (self.transaction_pool.hasRetrySignatures()) {
            // We need to hold a read lock until we are finished using the retry transactions, otherwise
            // the receiver thread could add new transactions and corrupt the underlying array
            const retry_transactions, var transactions_lg = try self.transaction_pool.readRetryTransactionsWithLock(self.allocator);
            defer {
                self.allocator.free(retry_transactions);
                transactions_lg.unlock();
            }

            const leader_addresses = try self.getLeaderAddresses();
            defer leader_addresses.deinit();

            var start_index: usize = 0;
            while (start_index < retry_transactions.len) {
                const end_index = @min(start_index + self.config.batch_size, retry_transactions.len);
                const batch = retry_transactions[start_index..end_index];
                try self.sendTransactions(batch, leader_addresses);
                start_index = end_index;
            }
        }
    }

    /// Gets the leader TPU addresses from leader info
    fn getLeaderAddresses(self: *Service) !std.ArrayList(SocketAddr) {
        var get_leader_addresses_timer = try Timer.start();
        const leader_addresses = blk: {
            const leader_info: *LeaderInfo, var leader_info_lg = self.leader_info_rw.writeWithLock();
            defer leader_info_lg.unlock();
            break :blk try leader_info.getLeaderAddresses(self.allocator);
        };
        self.stats.get_leader_addresses_latency_millis.set(get_leader_addresses_timer.read().asMillis());
        self.stats.number_of_leaders_identified.set(leader_addresses.items.len);
        return leader_addresses;
    }

    /// Sends transactions to the next N leaders TPU addresses
    fn sendTransactions(self: *Service, transactions: []const TransactionInfo, leader_addresses: std.ArrayList(SocketAddr)) !void {
        if (leader_addresses.items.len == 0) {
            self.logger.warn("No leader addresses found");
            return;
        }

        for (leader_addresses.items) |leader_address| {
            var packets = try std.ArrayList(Packet).initCapacity(self.allocator, transactions.len);
            for (transactions) |tx| {
                try packets.append(Packet.init(
                    leader_address.toEndpoint(),
                    tx.wire_transaction,
                    tx.wire_transaction_size,
                ));
            }
            try self.send_channel.send(packets);
        }

        const last_sent_time = Instant.now();
        for (transactions) |_tx| {
            var tx = _tx;
            tx.last_sent_time = last_sent_time;
        }

        self.stats.transactions_sent_count.add(transactions.len);
    }
};

pub const Config = struct {
    // Cluster type
    cluster: ClusterType,
    // Socket to send transactions from
    socket: SocketAddr,
    // Maximum number of transactions to send in a batch
    batch_size: usize = 1,
    // Time waited between sending transaction batches
    batch_send_rate: Duration = Duration.fromSecs(1),
    // Maximum number of transactions allowed in the transaction pool
    pool_max_size: usize = 1000,
    // Time waited between processing the transaction pool
    pool_process_rate: Duration = Duration.fromSecs(1),
    // Maximum number of leaders to forward to ahead of the current leader
    max_leaders_to_send_to: usize = 5,
    // Number of consecutive leader slots (TODO: this should come from other config somewhere)
    number_of_consecutive_leader_slots: u64 = 4,
    // Maximum number of retries for a transaction whoes max_retries is null
    default_max_retries: ?usize = null,
    // Time waited between retrying transactions
    retry_rate: Duration = Duration.fromSecs(1),
    // Maximum number of rpc http request retries before a request raises an error
    rpc_retries: usize = 3,
};

pub const Stats = struct {
    transactions_pending: *Gauge(u64),
    transactions_received_count: *Counter,
    transactions_retry_count: *Counter,
    transactions_sent_count: *Counter,
    transactions_rooted_count: *Counter,
    transactions_failed_count: *Counter,
    transactions_expired_count: *Counter,
    transactions_exceeded_max_retries_count: *Counter,
    number_of_leaders_identified: *Gauge(u64),

    process_transactions_latency_millis: *Gauge(u64),
    retry_transactions_latency_millis: *Gauge(u64),
    get_leader_addresses_latency_millis: *Gauge(u64),

    rpc_block_height_latency_millis: *Gauge(u64),
    rpc_signature_statuses_latency_millis: *Gauge(u64),

    pub fn init() GetMetricError!Stats {
        var self: Stats = undefined;
        const registry = globalRegistry();
        const stats_struct_info = @typeInfo(Stats).Struct;
        inline for (stats_struct_info.fields) |field| {
            if (field.name[0] != '_') {
                @field(self, field.name) = switch (field.type) {
                    *Counter => try registry.getOrCreateCounter(field.name),
                    *Gauge(u64) => try registry.getOrCreateGauge(field.name, u64),
                    else => @compileError("Unhandled field type: " ++ field.name ++ ": " ++ @typeName(field.type)),
                };
            }
        }
        return self;
    }

    pub fn log(self: *const Stats, logger: *Logger) void {
        logger.infof("transaction-sender: {} received, {} pending, {} rooted, {} failed, {} expired, {} exceeded_retries", .{
            self.transactions_received_count.get(),
            self.transactions_pending.get(),
            self.transactions_rooted_count.get(),
            self.transactions_failed_count.get(),
            self.transactions_expired_count.get(),
            self.transactions_exceeded_max_retries_count.get(),
        });
    }
};
