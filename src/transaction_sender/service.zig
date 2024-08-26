const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");

const socket_utils = sig.net.socket_utils;

const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);
const UdpSocket = network.Socket;

const Packet = sig.net.Packet;
const Slot = sig.core.Slot;
const RwMux = sig.sync.RwMux;
const Signature = sig.core.Signature;
const Channel = sig.sync.Channel;
const Instant = sig.time.Instant;
const GossipTable = sig.gossip.GossipTable;
const RpcClient = sig.rpc.Client;
const Logger = sig.trace.log.Logger;
const Config = sig.transaction_sender.Config;
const LeaderInfo = sig.transaction_sender.LeaderInfo;
const TransactionInfo = sig.transaction_sender.TransactionInfo;

/// Pool to keep track of pending transactions, transactions are added to the
/// pool after they are received off the incomming channel, and removed when
/// they are confirmed, failed, timed out, or reach the max retries.
const TransactionPool = std.AutoArrayHashMap(Signature, TransactionInfo);

/// Basic send transaction service that listens for transactions on a channel.
/// Transactions are added to the pool and retried until they are confirmed, failed,
/// timed out, or reach the max retries.
/// The leader schedule and current slot are loaded via RPC calls to the cluster.
/// The leader TPU addresses are loaded from the gossip table.
/// TODO:
/// - Add logging
/// - Add stats tracking
/// - Add nonce handling
/// - Remove RPC calls
pub fn run(
    allocator: std.mem.Allocator,
    config: Config,
    transaction_channel: *Channel(TransactionInfo),
    gossip_table_rw: *RwMux(GossipTable),
    exit: *AtomicBool,
    logger: Logger,
) !void {
    var socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
    socket.bindToPort(config.socket.port()) catch return error.SocketBindFailed;
    socket.setReadTimeout(socket_utils.SOCKET_TIMEOUT_US) catch return error.SocketSetTimeoutFailed;

    const packet_channel = Channel(std.ArrayList(Packet)).init(allocator, 100);

    const cluster_info = try LeaderInfo.init(allocator, config.cluster, gossip_table_rw);
    var cluster_info_rw = RwMux(LeaderInfo).init(cluster_info);

    const transaction_pool = TransactionPool.init(allocator);
    var transaction_pool_rw = RwMux(TransactionPool).init(transaction_pool);

    const send_socket_handle = try std.Thread.spawn(
        .{},
        socket_utils.sendSocket,
        .{
            socket,
            packet_channel,
            exit,
            logger,
        },
    );

    const receive_transactions_handle = try std.Thread.spawn(
        .{},
        receiveTransactionsThread,
        .{
            allocator,
            transaction_channel,
            packet_channel,
            config,
            &cluster_info_rw,
            &transaction_pool_rw,
            exit,
            logger,
        },
    );

    const process_transactions_handle = try std.Thread.spawn(
        .{},
        processTransactionsThread,
        .{
            allocator,
            packet_channel,
            config,
            &cluster_info_rw,
            &transaction_pool_rw,
            exit,
            logger,
        },
    );

    send_socket_handle.join();
    receive_transactions_handle.join();
    process_transactions_handle.join();
}

fn receiveTransactionsThread(
    allocator: std.mem.Allocator,
    receiver: *Channel(TransactionInfo),
    sender: *Channel(std.ArrayList(Packet)),
    config: Config,
    cluster_info_rw: *RwMux(LeaderInfo),
    transaction_pool_rw: *RwMux(TransactionPool),
    exit: *AtomicBool,
    logger: Logger,
) !void {
    errdefer exit.store(true, .unordered);

    var last_batch_sent = try Instant.now();

    // As transactions are received, they are added to a transaction batch until
    // the batch size is reached or the batch send rate is reached. The transactions are then
    // sent to the leader TPU addresses and subsequently added to the transaction pool.
    var transaction_batch = std.AutoArrayHashMap(Signature, TransactionInfo).init(allocator);
    defer transaction_batch.deinit();

    while (!exit.load(.unordered)) {
        const transaction = receiver.receive() orelse break;

        if (!transaction_batch.contains(transaction.signature)) {
            const transaction_pool: *const TransactionPool, var transaction_pool_lock = transaction_pool_rw.readWithLock();
            defer transaction_pool_lock.unlock();

            if (!transaction_pool.contains(transaction.signature)) {
                try transaction_batch.put(transaction.signature, transaction);
            }
        }

        if (transaction_batch.count() >= config.batch_size or
            (transaction_batch.count() > 0 and
            (try last_batch_sent.elapsed()).asNanos() >= config.batch_send_rate.asNanos()))
        {
            try sendTransactions(
                allocator,
                sender,
                config,
                cluster_info_rw,
                transaction_batch.values(),
            );
            last_batch_sent = try Instant.now();

            var transaction_pool: *TransactionPool, var transaction_pool_lock = transaction_pool_rw.writeWithLock();
            defer transaction_pool_lock.unlock();

            logger.infof("Adding {d} new transactions to pool.", .{transaction_batch.count()});
            for (transaction_batch.values()) |_tx| {
                if (transaction_pool.count() >= config.pool_max_size) {
                    logger.warnf("Transaction pool is full, dropping transaction: signature={s}", .{_tx.signature});
                    continue;
                }
                var tx = _tx; // Is there a nicer way to do this?
                tx.last_sent_time = last_batch_sent;
                try transaction_pool.put(tx.signature, tx);
            }
            transaction_batch.clearRetainingCapacity();
        }
    }
}

fn processTransactionsThread(
    allocator: std.mem.Allocator,
    sender: *Channel(std.ArrayList(Packet)),
    config: Config,
    cluster_info_rw: *RwMux(LeaderInfo),
    transaction_pool_rw: *RwMux(TransactionPool),
    exit: *AtomicBool,
    logger: Logger,
) !void {
    errdefer exit.store(true, .unordered);

    while (!exit.load(.unordered)) {
        std.time.sleep(config.pool_process_rate.asNanos());

        var transaction_pool: *TransactionPool, var transaction_pool_lock = transaction_pool_rw.writeWithLock();
        defer transaction_pool_lock.unlock();

        if (transaction_pool.count() == 0) continue;

        try processTransactions(
            allocator,
            sender,
            config,
            cluster_info_rw,
            transaction_pool,
            logger,
        );
    }
}

fn processTransactions(
    allocator: std.mem.Allocator,
    sender: *Channel(std.ArrayList(Packet)),
    config: Config,
    cluster_info_rw: *RwMux(LeaderInfo),
    transaction_pool: *TransactionPool,
    logger: Logger,
) !void {
    var successful_signatures = std.ArrayList(Signature).init(allocator);
    defer successful_signatures.deinit();

    var retry_signatures = std.ArrayList(Signature).init(allocator);
    defer retry_signatures.deinit();

    var drop_signatures = std.ArrayList(Signature).init(allocator);
    defer drop_signatures.deinit();

    var rpc_arena = std.heap.ArenaAllocator.init(allocator);
    defer rpc_arena.deinit();

    var rpc_client = RpcClient.init(allocator, .Testnet);
    defer rpc_client.deinit();

    const block_height = try rpc_client.getBlockHeight(
        &rpc_arena,
        .{ .commitment = .processed },
    );

    const signature_statuses = try rpc_client.getSignatureStatuses(
        &rpc_arena,
        transaction_pool.keys(),
        .{ .searchTransactionHistory = false },
    );

    // Populate retry_signatures and drop_signatures
    var pending_transactions_iter = transaction_pool.iterator();
    for (signature_statuses.value) |maybe_signature_status| {
        const entry = pending_transactions_iter.next().?;
        const signature = entry.key_ptr.*;
        const transaction_info = entry.value_ptr;

        if (maybe_signature_status) |signature_status| {
            // Drop transaction if it is rooted
            if (signature_status.confirmations == null) {
                try drop_signatures.append(signature);
                try successful_signatures.append(signature);
                continue;
            }

            // Drop transaction if it failed
            if (signature_status.err) |_| {
                try drop_signatures.append(signature);
                continue;
            }

            // Drop transaction if it is expired
            if (transaction_info.last_valid_block_height < block_height) {
                try drop_signatures.append(signature);
                continue;
            }
        } else {
            // Drop transaction if it has reached max retries
            const maybe_max_retries = transaction_info.max_retries orelse config.default_max_retries;
            if (maybe_max_retries) |max_retries| {
                if (transaction_info.retries >= max_retries) {
                    try drop_signatures.append(signature);
                    continue;
                }
            }

            // Skip transactions which are not ready to be retried
            if (transaction_info.last_sent_time) |lst| {
                const elapsed = try lst.elapsed();
                if (elapsed.asNanos() < config.retry_rate.asNanos()) continue;
            }

            // Update transaction retries and last sent time
            if (transaction_info.last_sent_time) |_| {
                transaction_info.retries += 1;
            }
            transaction_info.last_sent_time = try Instant.now();

            // Retry transaction
            try retry_signatures.append(signature);
        }
    }

    logger.infof(
        "Processed {d} transactions: {d} successful, {d} retry, {d} drop",
        .{
            successful_signatures.len + retry_signatures.len + drop_signatures.len,
            successful_signatures.len,
            retry_signatures.len,
            drop_signatures.len,
        },
    );

    // Retry transactions
    if (retry_signatures.items.len > 0) {
        var retry_transactions = try allocator.alloc(TransactionInfo, retry_signatures.items.len);
        defer allocator.free(retry_transactions);

        for (retry_signatures.items, 0..) |signature, i| {
            retry_transactions[i] = transaction_pool.get(signature).?;
        }

        var start_index: usize = 0;
        while (start_index < retry_transactions.len) {
            const end_index = @min(start_index + config.batch_size, retry_transactions.len);
            const batch = retry_transactions[start_index..end_index];
            try sendTransactions(
                allocator,
                sender,
                config,
                cluster_info_rw,
                batch,
                logger,
            );
            start_index = end_index;
        }
    }

    // Remove transactions
    for (drop_signatures.items) |signature| {
        _ = transaction_pool.swapRemove(signature);
    }
}

fn sendTransactions(
    allocator: std.mem.Allocator,
    sender: *Channel(std.ArrayList(Packet)),
    config: Config,
    cluster_info_rw: *RwMux(LeaderInfo),
    transactions: []TransactionInfo,
    logger: Logger,
) !void {
    const leader_addresses = blk: {
        const cluster_info: *LeaderInfo, var cluster_info_lock = cluster_info_rw.writeWithLock();
        defer cluster_info_lock.unlock();
        break :blk try cluster_info.getLeaderAddresses(allocator, config) orelse return;
    };
    defer leader_addresses.deinit();

    logger.infof("Sending {d} transactions to {d} leaders", .{ transactions.len, leader_addresses.items.len });
    for (leader_addresses.items) |leader_address| {
        var packets = try std.ArrayList(Packet).initCapacity(allocator, transactions.len);
        for (transactions) |tx| {
            try packets.append(Packet.init(
                leader_address.toEndpoint(),
                tx.wire_transaction,
                tx.wire_transaction_size,
            ));
        }
        try sender.send(packets);
    }
}
