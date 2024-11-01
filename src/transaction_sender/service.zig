const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");

const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);

const Slot = sig.core.Slot;
const Signature = sig.core.Signature;
const GossipTable = sig.gossip.GossipTable;
const SocketAddr = sig.net.SocketAddr;
const Packet = sig.net.Packet;
const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const RpcClient = sig.rpc.Client;
const ClusterType = sig.accounts_db.ClusterType;
const RwMux = sig.sync.RwMux;
const Channel = sig.sync.Channel;
const Duration = sig.time.Duration;
const Instant = sig.time.Instant;
const Timer = sig.time.Timer;
const Logger = sig.trace.log.Logger;
const ScopedLogger = sig.trace.log.ScopedLogger;
const LeaderInfo = sig.transaction_sender.LeaderInfo;
const TransactionInfo = sig.transaction_sender.TransactionInfo;
const TransactionPool = sig.transaction_sender.TransactionPool;
const EpochSchedule = sig.core.epoch_schedule.EpochSchedule;

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
    metrics: Metrics,
    transaction_pool: TransactionPool,
    leader_info_rw: RwMux(LeaderInfo),
    /// Channel used inside to move processed transactions to the socket sender.
    send_channel: *Channel(Packet),
    /// Put transactions onto this channel to send them.
    input_channel: *Channel(TransactionInfo),
    exit: *AtomicBool,
    logger: ScopedLogger(@typeName(Self)),

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        logger: Logger,
        config: Config,
        input_channel: *Channel(TransactionInfo),
        gossip_table_rw: *RwMux(GossipTable),
        epoch_schedule: EpochSchedule,
        exit: *AtomicBool,
    ) !Service {
        return .{
            .allocator = allocator,
            .config = config,
            .metrics = try Metrics.init(),
            .transaction_pool = TransactionPool.init(
                allocator,
                config.pool_max_size,
            ),
            .leader_info_rw = RwMux(LeaderInfo).init(try LeaderInfo.init(
                allocator,
                logger,
                config,
                gossip_table_rw,
                epoch_schedule,
            )),
            .send_channel = try Channel(Packet).create(allocator),
            .input_channel = input_channel,
            .logger = logger.withScope(@typeName(Self)),
            .exit = exit,
        };
    }

    pub fn run(self: *Service) !void {
        const send_socket_handle = try std.Thread.spawn(
            .{},
            sig.net.quic.runClient,
            .{
                self.allocator,
                self.send_channel,
                self.logger.unscoped(),
                false,
                self.exit,
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
        errdefer self.exit.store(true, .monotonic);

        var last_batch_sent = Instant.now();
        var transaction_batch = std.AutoArrayHashMap(Signature, TransactionInfo).init(self.allocator);
        defer transaction_batch.deinit();

        while (!self.exit.load(.monotonic) or
            self.input_channel.len() != 0)
        {
            while (self.input_channel.receive()) |transaction| {
                self.metrics.transactions_received_count.inc();

                // If the transaction signature isn't in the batch or the pool, add the transaction.
                if (!transaction_batch.contains(transaction.signature) and
                    !self.transaction_pool.contains(transaction.signature))
                {
                    try transaction_batch.put(transaction.signature, transaction);
                }
                // Otherwise, continue on, we're already going to process this transaction
                else if (transaction_batch.count() == 0) {
                    continue;
                }

                if (transaction_batch.count() >= self.config.batch_size or
                    last_batch_sent.elapsed().asNanos() >= self.config.batch_send_rate.asNanos())
                {
                    const leader_addresses = try self.getLeaderAddresses();
                    defer self.allocator.free(leader_addresses);

                    try self.sendTransactions(transaction_batch.values(), leader_addresses);
                    last_batch_sent = Instant.now();

                    self.transaction_pool.addTransactions(transaction_batch.values()) catch {
                        self.logger.warn().log("Transaction pool is full, dropping transactions");
                    };

                    transaction_batch.clearRetainingCapacity();
                }
            }
        }
    }

    /// Retries transactions if they are still valid, otherwise remove from the pool
    fn processTransactionsThread(self: *Service) !void {
        errdefer self.exit.store(true, .monotonic);

        var rpc_client = RpcClient.init(
            self.allocator,
            self.config.cluster,
            .{ .max_retries = self.config.rpc_retries, .logger = self.logger.unscoped() },
        );
        defer rpc_client.deinit();

        while (!self.exit.load(.monotonic)) {
            std.time.sleep(self.config.pool_process_rate.asNanos());
            if (self.transaction_pool.count() == 0) continue;
            var timer = try Timer.start();

            try self.processTransactions(&rpc_client);
            self.metrics.process_transactions_latency_millis.set(timer.lap().asMillis());

            try self.retryTransactions();
            self.metrics.retry_transactions_latency_millis.set(timer.lap().asMillis());

            self.transaction_pool.purge();
            self.metrics.transactions_pending.set(self.transaction_pool.count());

            self.metrics.log(self.logger.unscoped());
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
        self.metrics.rpc_block_height_latency_millis.set(block_height_timer.read().asMillis());

        // We need to hold a read lock until we are finished using the signatures and transactions, otherwise
        // the receiver thread could add new transactions and corrupt the underlying array
        const signatures, const transactions, var transactions_lg =
            self.transaction_pool.readSignaturesAndTransactionsWithLock();
        defer transactions_lg.unlock();

        var signature_statuses_timer = try Timer.start();
        const signature_statuses_response = try rpc_client.getSignatureStatuses(
            self.allocator,
            signatures,
            .{ .searchTransactionHistory = false },
        );
        defer signature_statuses_response.deinit();
        const signature_statuses = try signature_statuses_response.result();
        self.metrics.rpc_signature_statuses_latency_millis.set(signature_statuses_timer.read().asMillis());

        for (
            signature_statuses.value,
            signatures,
            transactions,
        ) |maybe_signature_status, signature, transaction_info| {
            if (maybe_signature_status) |signature_status| {
                if (signature_status.confirmations == null) {
                    try self.transaction_pool.drop_signatures.append(signature);
                    self.metrics.transactions_rooted_count.inc();
                    continue;
                }

                if (signature_status.err) |err| {
                    try self.transaction_pool.drop_signatures.append(signature);
                    self.metrics.transactions_failed_count.inc();
                    std.debug.print("transaction {} failed with error: {}\n", .{ signature, err });
                    continue;
                }
            }

            if (transaction_info.isExpired(block_height)) {
                try self.transaction_pool.drop_signatures.append(signature);
                self.metrics.transactions_expired_count.inc();
                continue;
            }

            if (transaction_info.exceededMaxRetries(self.config.default_max_retries)) {
                try self.transaction_pool.drop_signatures.append(signature);
                self.metrics.transactions_exceeded_max_retries_count.inc();
                continue;
            }

            if (transaction_info.shouldRetry(self.config.retry_rate)) {
                try self.transaction_pool.retry_signatures.append(signature);
                self.metrics.transactions_retry_count.inc();
                continue;
            }
        }
    }

    /// Sends retry transactions in batches to the leader TPU addresses
    fn retryTransactions(self: *Service) !void {
        if (self.transaction_pool.hasRetrySignatures()) {
            // We need to hold a read lock until we are finished using the retry transactions, otherwise
            // the receiver thread could add new transactions and corrupt the underlying array
            const retry_transactions, var transactions_lg =
                try self.transaction_pool.readRetryTransactionsWithLock(self.allocator);
            defer {
                self.allocator.free(retry_transactions);
                transactions_lg.unlock();
            }

            const leader_addresses = try self.getLeaderAddresses();
            defer self.allocator.free(leader_addresses);

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
    fn getLeaderAddresses(self: *Service) ![]const SocketAddr {
        var get_leader_addresses_timer = try Timer.start();
        const leader_addresses = blk: {
            const leader_info: *LeaderInfo, var leader_info_lg = self.leader_info_rw.writeWithLock();
            defer leader_info_lg.unlock();
            break :blk try leader_info.getLeaderAddresses(self.allocator);
        };
        self.metrics.get_leader_addresses_latency_millis.set(get_leader_addresses_timer.read().asMillis());
        self.metrics.number_of_leaders_identified.set(leader_addresses.len);
        return leader_addresses;
    }

    /// Sends transactions to the next N leaders TPU addresses
    fn sendTransactions(
        self: *Service,
        transactions: []const TransactionInfo,
        leader_addresses: []const SocketAddr,
    ) !void {
        if (leader_addresses.len == 0) {
            self.logger.warn().log("No leader addresses found");
            return;
        }

        for (leader_addresses) |leader_address| {
            for (transactions) |tx| {
                self.logger.info().logf("(transaction_sender.Service) sending transaction {} to leader at {}", .{ tx.signature, leader_address });
                try self.send_channel.send(Packet.init(
                    leader_address.toEndpoint(),
                    tx.wire_transaction,
                    tx.wire_transaction_size,
                ));
            }
        }

        // TODO: update last_seen_time in order to not retry all transactions

        self.metrics.transactions_sent_count.add(transactions.len);
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

pub const Metrics = struct {
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

    pub fn init() GetMetricError!Metrics {
        return globalRegistry().initStruct(Metrics);
    }

    pub fn log(self: *const Metrics, logger: Logger) void {
        logger.info().logf("transaction-sender: {} received, {} pending, {} rooted, {} failed, {} expired, {} exceeded_retries", .{
            self.transactions_received_count.get(),
            self.transactions_pending.get(),
            self.transactions_rooted_count.get(),
            self.transactions_failed_count.get(),
            self.transactions_expired_count.get(),
            self.transactions_exceeded_max_retries_count.get(),
        });
    }
};
