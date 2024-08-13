const std = @import("std");
const network = @import("zig-network");
const base58 = @import("base58-zig");
const sig = @import("../sig.zig");

const socket_utils = sig.net.socket_utils;

const Allocator = std.mem.Allocator;
const AutoArrayHashMap = std.AutoArrayHashMap;
const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);
const Thread = std.Thread;
const UdpSocket = network.Socket;

const Packet = sig.net.Packet;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const RwMux = sig.sync.RwMux;
const Signature = sig.core.Signature;
const Channel = sig.sync.Channel;
const SocketAddr = sig.net.SocketAddr;
const Duration = sig.time.Duration;
const Instant = sig.time.Instant;
const ContactInfo = sig.gossip.ContactInfo;
const GossipTable = sig.gossip.GossipTable;
const RpcClient = sig.rpc.Client;
const RpcEpochInfo = sig.rpc.Client.EpochInfo;
const RpcLeaderSchedule = sig.rpc.Client.LeaderSchedule;
const RpcLatestBlockhash = sig.rpc.Client.LatestBlockhash;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;
const Logger = sig.trace.log.Logger;
const RpcCluster = sig.rpc.Client.Cluster;

/// Pool to keep track of pending transactions, transactions are added to the
/// pool after they are received off the incomming channel, and removed when
/// they are confirmed, failed, timed out, or reach the max retries.
const TransactionPool = AutoArrayHashMap(Signature, TransactionInfo);

pub const Config = struct {
    cluster: RpcCluster,
    socket: SocketAddr,
    batch_size: usize = 1,
    batch_send_rate: Duration = Duration.fromSecs(1),
    pool_max_size: usize = 1000,
    pool_process_rate: Duration = Duration.fromSecs(1),
    max_leaders_to_send_to: usize = 5,
    number_of_consecutive_leader_slots: u64 = 4,
    max_retries: ?usize = null,
    retry_rate: Duration = Duration.fromSecs(1),
};

const Info = struct {
    rpc_client: RpcClient,
    epoch_info: RpcEpochInfo,
    leader_schedule: LeaderSchedule,
    leader_addresses_cache: AutoArrayHashMap(Pubkey, SocketAddr),
    gossip_table_rw: *RwMux(GossipTable),

    pub fn init(
        allocator: Allocator,
        cluster: RpcCluster,
        gossip_table_rw: *RwMux(GossipTable),
    ) !Info {
        var rpc_client = RpcClient.init(allocator, cluster);
        var rpc_arena = std.heap.ArenaAllocator.init(allocator);
        defer rpc_arena.deinit();

        const epoch_info = try rpc_client.getEpochInfo(&rpc_arena, null, .{ .commitment = .processed });
        const leader_schedule = try getLeaderSchedule(allocator, &epoch_info, &rpc_client);
        const leader_addresses_cache = try getLeaderAddressesCache(allocator, leader_schedule.slot_leaders, gossip_table_rw);

        return .{
            .rpc_client = rpc_client,
            .epoch_info = epoch_info,
            .leader_schedule = leader_schedule,
            .leader_addresses_cache = leader_addresses_cache,
            .gossip_table_rw = gossip_table_rw,
        };
    }

    fn getLeaderAddresses(self: *Info, allocator: Allocator, config: Config) !?std.ArrayList(SocketAddr) {
        var rpc_arena = std.heap.ArenaAllocator.init(allocator);
        defer rpc_arena.deinit();

        const current_slot = try self.rpc_client.getSlot(&rpc_arena, .{
            .commitment = .processed,
        });

        var leader_addresses = std.ArrayList(SocketAddr).init(allocator);
        for (0..config.max_leaders_to_send_to) |i| {
            const slot = current_slot + i * config.number_of_consecutive_leader_slots;
            const leader = self.leader_schedule.getLeader(slot) orelse continue;
            const socket = self.leader_addresses_cache.get(leader) orelse continue;
            try leader_addresses.append(socket);
        }

        return leader_addresses;
    }

    fn getLeaderSchedule(allocator: Allocator, epoch_info: *const RpcEpochInfo, rpc_client: *RpcClient) !LeaderSchedule {
        var rpc_arena = std.heap.ArenaAllocator.init(allocator);
        defer rpc_arena.deinit();

        const rpc_leader_schedule = try rpc_client.getLeaderSchedule(&rpc_arena, null, .{});
        var num_leaders: u64 = 0;
        for (rpc_leader_schedule.values()) |leader_slots| {
            num_leaders += leader_slots.len;
        }

        const Record = struct { slot: Slot, key: Pubkey };

        var leaders_index: usize = 0;
        var leaders = try allocator.alloc(Record, num_leaders);
        defer allocator.free(leaders);

        var rpc_leader_iter = rpc_leader_schedule.iterator();
        while (rpc_leader_iter.next()) |entry| {
            const key = try Pubkey.fromBase58String(entry.key_ptr.*);
            for (entry.value_ptr.*) |slot| {
                leaders[leaders_index] = .{ .slot = slot, .key = key };
                leaders_index += 1;
            }
        }

        std.mem.sortUnstable(Record, leaders, {}, struct {
            fn gt(_: void, lhs: Record, rhs: Record) bool {
                return switch (std.math.order(lhs.slot, rhs.slot)) {
                    .gt => false,
                    else => true,
                };
            }
        }.gt);

        var leader_pubkeys = try allocator.alloc(Pubkey, leaders.len);
        for (leaders, 0..) |record, i| {
            leader_pubkeys[i] = record.key;
        }

        return LeaderSchedule{
            .allocator = allocator,
            .slot_leaders = leader_pubkeys,
            .start_slot = epoch_info.absoluteSlot - epoch_info.slotIndex,
        };
    }

    fn getLeaderAddressesCache(allocator: Allocator, leaders: []const Pubkey, gossip_table_rw: *RwMux(GossipTable)) !AutoArrayHashMap(Pubkey, SocketAddr) {
        const gossip_table: *const GossipTable, var gossip_table_lock = gossip_table_rw.readWithLock();
        defer gossip_table_lock.unlock();

        var leader_addresses = AutoArrayHashMap(Pubkey, SocketAddr).init(allocator);
        for (leaders) |leader| {
            if (leader_addresses.contains(leader)) continue;
            const contact_info = gossip_table.getThreadSafeContactInfo(leader);
            if (contact_info == null) continue;
            if (contact_info.?.tpu_addr == null) continue;
            try leader_addresses.put(leader, contact_info.?.tpu_addr.?);
        }

        return leader_addresses;
    }
};

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

    const info = try Info.init(allocator, config.cluster, gossip_table_rw);
    var info_rw = RwMux(Info).init(info);

    const transaction_pool = TransactionPool.init(allocator);
    var transaction_pool_rw = RwMux(TransactionPool).init(transaction_pool);

    const send_socket_handle = try Thread.spawn(
        .{},
        socket_utils.sendSocket,
        .{
            socket,
            packet_channel,
            exit,
            logger,
        },
    );

    const receive_transactions_handle = try Thread.spawn(
        .{},
        receiveTransactionsThread,
        .{
            allocator,
            transaction_channel,
            packet_channel,
            config,
            &info_rw,
            &transaction_pool_rw,
            exit,
        },
    );

    const process_transactions_handle = try Thread.spawn(
        .{},
        processTransactionsThread,
        .{
            allocator,
            packet_channel,
            config,
            &info_rw,
            &transaction_pool_rw,
            exit,
        },
    );

    const mock_transaction_generator_handle = try Thread.spawn(
        .{},
        mockTransactionGenerator,
        .{
            allocator,
            transaction_channel,
            &info_rw,
            exit,
        },
    );

    send_socket_handle.join();
    receive_transactions_handle.join();
    process_transactions_handle.join();
    mock_transaction_generator_handle.join();
}

fn receiveTransactionsThread(
    allocator: Allocator,
    receiver: *Channel(TransactionInfo),
    sender: *Channel(std.ArrayList(Packet)),
    config: Config,
    info_rw: *RwMux(Info),
    transaction_pool_rw: *RwMux(TransactionPool),
    exit: *AtomicBool,
) !void {
    errdefer exit.store(true, .unordered);

    var last_batch_sent = try Instant.now();

    var transaction_batch = TransactionPool.init(allocator);
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
                info_rw,
                transaction_batch.values(),
            );
            last_batch_sent = try Instant.now();

            var transaction_pool: *TransactionPool, var transaction_pool_lock = transaction_pool_rw.writeWithLock();
            defer transaction_pool_lock.unlock();

            for (transaction_batch.values()) |_tx| {
                var tx = _tx; // Is there a nicer way to do this?
                if (transaction_pool.contains(tx.signature)) continue;
                if (transaction_pool.count() >= config.pool_max_size) break;
                tx.last_sent_time = last_batch_sent;
                try transaction_pool.put(tx.signature, tx);
            }
            transaction_batch.clearRetainingCapacity();
        }
    }
}

fn processTransactionsThread(
    allocator: Allocator,
    sender: *Channel(std.ArrayList(Packet)),
    config: Config,
    info_rw: *RwMux(Info),
    transaction_pool_rw: *RwMux(TransactionPool),
    exit: *AtomicBool,
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
            info_rw,
            transaction_pool,
        );
    }
}

fn processTransactions(
    allocator: Allocator,
    sender: *Channel(std.ArrayList(Packet)),
    config: Config,
    info_rw: *RwMux(Info),
    transaction_pool: *TransactionPool,
) !void {
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
            const maybe_max_retries = transaction_info.max_retries orelse config.max_retries;
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
                info_rw,
                batch,
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
    allocator: Allocator,
    sender: *Channel(std.ArrayList(Packet)),
    config: Config,
    info_rw: *RwMux(Info),
    transactions: []TransactionInfo,
) !void {
    const leader_addresses = blk: {
        const service_info: *Info, var service_info_lock = info_rw.writeWithLock();
        defer service_info_lock.unlock();
        break :blk try service_info.getLeaderAddresses(allocator, config) orelse return;
    };
    defer leader_addresses.deinit();

    for (leader_addresses.items) |leader_address| {
        var packets = try std.ArrayList(Packet).initCapacity(allocator, transactions.len);
        defer packets.deinit();
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

pub const TransactionInfo = struct {
    signature: Signature,
    wire_transaction: [sig.net.packet.PACKET_DATA_SIZE]u8,
    wire_transaction_size: usize,
    last_valid_block_height: u64,
    durable_nonce_info: ?struct { Pubkey, Hash },
    max_retries: ?usize,
    retries: usize,
    last_sent_time: ?Instant,

    pub fn new(
        transaction: Transaction,
        last_valid_block_height: u64,
        durable_nonce_info: ?struct { Pubkey, Hash },
        max_retries: ?usize,
    ) !TransactionInfo {
        const signature = transaction.signatures[0];
        var transaction_info = TransactionInfo{
            .signature = signature,
            .wire_transaction = undefined,
            .wire_transaction_size = 0,
            .last_valid_block_height = last_valid_block_height,
            .durable_nonce_info = durable_nonce_info,
            .max_retries = max_retries,
            .retries = 0,
            .last_sent_time = null,
        };
        const written = try sig.bincode.writeToSlice(&transaction_info.wire_transaction, transaction, .{});
        transaction_info.wire_transaction_size = written.len;
        return transaction_info;
    }
};

const Transaction = sig.core.transaction.Transaction;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

pub fn mockTransactionGenerator(
    allocator: Allocator,
    sender: *Channel(TransactionInfo),
    service_info_rw: *RwMux(Info),
    exit: *AtomicBool,
) !void {
    errdefer exit.store(true, .unordered);

    const from_pubkey = try Pubkey.fromBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const from_keypair = KeyPair{
        .public_key = .{ .bytes = from_pubkey.data },
        .secret_key = .{ .bytes = [_]u8{ 76, 196, 192, 17, 40, 245, 120, 49, 64, 133, 213, 227, 12, 42, 183, 70, 235, 64, 235, 96, 246, 205, 78, 13, 173, 111, 254, 96, 210, 208, 121, 240, 159, 193, 185, 89, 227, 77, 234, 91, 232, 234, 253, 119, 162, 105, 200, 227, 123, 90, 111, 105, 72, 53, 60, 147, 76, 154, 44, 72, 29, 165, 2, 246 } },
    };
    const to_pubkey = try Pubkey.fromBase58String("GDFVa3uYXDcNhcNk8A4v28VeF4wcMn8mauZNwVWbpcN");
    const lamports: u64 = 100;

    while (!exit.load(.unordered)) {
        std.time.sleep(Duration.fromSecs(10).asNanos());

        const latest_blockhash, const last_valid_blockheight = blk: {
            const info: *Info, var info_lock = service_info_rw.writeWithLock();
            defer info_lock.unlock();
            var rpc_arena = std.heap.ArenaAllocator.init(allocator);
            defer rpc_arena.deinit();
            const blockhash = try info.rpc_client.getLatestBlockhash(&rpc_arena, .{});
            break :blk .{
                try Hash.fromBase58String(blockhash.value.blockhash),
                blockhash.value.lastValidBlockHeight,
            };
        };

        const transaction = try sig.core.transaction.buildTransferTansaction(
            allocator,
            from_keypair,
            from_pubkey,
            to_pubkey,
            lamports,
            latest_blockhash,
        );

        const transaction_info = try TransactionInfo.new(
            transaction,
            last_valid_blockheight,
            null,
            null,
        );

        try sender.send(transaction_info);
    }
}

test "mockTransaction" {
    const allocator = std.heap.page_allocator;

    var rpc_arena = std.heap.ArenaAllocator.init(allocator);
    defer rpc_arena.deinit();
    var rpc_client = RpcClient.init(allocator, .Testnet);
    defer rpc_client.deinit();
    const latest_blockhash = try rpc_client.getLatestBlockhash(&rpc_arena, .{});

    const from_pubkey = try Pubkey.fromBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const from_keypair = KeyPair{
        .public_key = .{ .bytes = from_pubkey.data },
        .secret_key = .{ .bytes = [_]u8{ 76, 196, 192, 17, 40, 245, 120, 49, 64, 133, 213, 227, 12, 42, 183, 70, 235, 64, 235, 96, 246, 205, 78, 13, 173, 111, 254, 96, 210, 208, 121, 240, 159, 193, 185, 89, 227, 77, 234, 91, 232, 234, 253, 119, 162, 105, 200, 227, 123, 90, 111, 105, 72, 53, 60, 147, 76, 154, 44, 72, 29, 165, 2, 246 } },
    };
    const to_pubkey = try Pubkey.fromBase58String("GDFVa3uYXDcNhcNk8A4v28VeF4wcMn8mauZNwVWbpcN");
    const lamports: u64 = 100;

    const transaction = try sig.core.transaction.buildTransferTansaction(
        allocator,
        from_keypair,
        from_pubkey,
        to_pubkey,
        lamports,
        try Hash.fromBase58String(latest_blockhash.value.blockhash),
    );

    // _ = transaction;
    std.debug.print("TRANSACTION\n", .{});
    for (transaction.signatures) |s| {
        std.debug.print("Signature: {s}\n", .{s.toBase58String().slice()});
    }

    std.debug.print("MessageHeader: {}\n", .{transaction.message.header});
    for (transaction.message.account_keys) |k| {
        std.debug.print("AccountKey: {s}\n", .{k.toBase58String().slice()});
    }
    std.debug.print("RecentBlockhash: {any}\n", .{transaction.message.recent_blockhash});
    for (transaction.message.instructions) |i| {
        std.debug.print("Instruction: {any}\n", .{i});
    }

    var buf: [sig.net.packet.PACKET_DATA_SIZE]u8 = undefined;
    const transaction_bytes = try sig.bincode.writeToSlice(&buf, transaction, .{});
    std.debug.print("TransactionBytes: {any}\n", .{transaction_bytes});
}
