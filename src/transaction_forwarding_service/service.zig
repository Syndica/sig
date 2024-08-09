const std = @import("std");
const network = @import("zig-network");
const sig = @import("../lib.zig");

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
const LeaderSchedule = sig.core.leader_schedule.SingleEpochLeaderSchedule;
const Logger = sig.trace.log.Logger;

const NUM_CONSECUTIVE_LEADER_SLOTS = sig.core.leader_schedule.NUM_CONSECUTIVE_LEADER_SLOTS;

/// Maximum size of the transaction retry poolx
const MAX_PENDING_POOL_SIZE: usize = 10_000; // This seems like a lot but maybe it needs to be bigger one day

/// Default retry interval
const DEFAULT_PROCESS_TRANSACTIONS_RATE: Duration = Duration.fromSecs(2);

/// Default number of leaders to forward transactions to
const DEFAULT_LEADER_FORWARD_COUNT: u64 = 2;

/// Default max number of time the service will retry broadcast
const DEFAULT_MAX_RETRIES: ?usize = null;
const DEFAULT_SERVICE_MAX_RETRIES: usize = std.math.maxInt(usize);

/// Default batch size for sending transaction in batch
/// When this size is reached, send out the transactions.
const DEFAULT_BATCH_SIZE: usize = 1;

// The maximum transaction batch size
const MAX_TRANSACTION_BATCH_SIZE: usize = 10_000;

/// Maximum transaction sends per second
const MAX_TRANSACTION_SENDS_PER_SECOND: u64 = 1_000;

/// Default maximum batch waiting time in ms. If this time is reached,
/// whatever transactions are cached will be sent.
const DEFAULT_BATCH_SEND_RATE = Duration.fromMillis(1);

// The maximum transaction batch send rate in MS
const MAX_BATCH_SEND_RATE_MS: usize = 100_000;

/// The maximum duration the retry thread may be configured to sleep before
/// processing the transactions that need to be retried.
const MAX_RETRY_SLEEP = Duration.fromSecs(1);

/// The leader info refresh rate.
const LEADER_INFO_REFRESH_RATE = Duration.fromSecs(1);

/// Report the send transaction memtrics for every 5 seconds.
const SEND_TRANSACTION_METRICS_REPORT_RATE = Duration.fromSecs(5);

/// Type to for pending transactions
const PendingTransactions = AutoArrayHashMap(Signature, TransactionInfo);

pub fn run(
    socket_address: SocketAddr,
    incoming_channel: *Channel(TransactionInfo),
    gossip_table_rw: *RwMux(GossipTable),
    exit: *AtomicBool,
    logger: Logger,
) !void {
    const allocator = std.heap.page_allocator;

    var socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
    socket.bindToPort(socket_address.port()) catch return error.SocketBindFailed;
    socket.setReadTimeout(socket_utils.SOCKET_TIMEOUT_US) catch return error.SocketSetTimeoutFailed;

    const outgoing_channel = Channel(std.ArrayList(Packet)).init(allocator, 100);

    const pending_transactions = PendingTransactions.init(allocator);
    var pending_transactions_rw = RwMux(PendingTransactions).init(pending_transactions);

    const service_info = try ServiceInfo.init(allocator, gossip_table_rw);
    var service_info_rw = RwMux(ServiceInfo).init(service_info);

    const send_socket_handle = try Thread.spawn(
        .{},
        socket_utils.sendSocket,
        .{
            socket,
            outgoing_channel,
            exit,
            logger,
        },
    );

    const refresh_service_info_handle = try Thread.spawn(
        .{},
        refreshServiceInfoThread,
        .{
            &service_info_rw,
            exit,
        },
    );

    const receive_transactions_handle = try Thread.spawn(
        .{},
        receiveTransactionsThread,
        .{
            allocator,
            incoming_channel,
            outgoing_channel,
            &service_info_rw,
            &pending_transactions_rw,
            exit,
        },
    );

    const process_transactions_handle = try Thread.spawn(
        .{},
        processTransactionsThread,
        .{
            allocator,
            outgoing_channel,
            &service_info_rw,
            &pending_transactions_rw,
            exit,
        },
    );

    const mock_transaction_generator_handle = try Thread.spawn(
        .{},
        mockTransactionGenerator,
        .{
            allocator,
            incoming_channel,
            &service_info_rw,
            exit,
        },
    );

    send_socket_handle.join();
    refresh_service_info_handle.join();
    receive_transactions_handle.join();
    process_transactions_handle.join();
    mock_transaction_generator_handle.join();
}

fn refreshServiceInfoThread(
    service_info_rw: *RwMux(ServiceInfo),
    exit: *AtomicBool,
) !void {
    errdefer exit.store(true, .unordered);

    while (!exit.load(.unordered)) {
        std.time.sleep(ServiceInfo.REFERENCE_SLOT_REFRESH_RATE.asNanos());

        var service_info_lock = service_info_rw.write();
        defer service_info_lock.unlock();
        var service_info: *ServiceInfo = service_info_lock.mut();

        try service_info.refresh();
    }
}

fn receiveTransactionsThread(
    allocator: Allocator,
    receive_channel: *Channel(TransactionInfo),
    send_channel: *Channel(std.ArrayList(Packet)),
    service_info_rw: *RwMux(ServiceInfo),
    pending_transactions_rw: *RwMux(PendingTransactions),
    exit: *AtomicBool,
) !void {
    errdefer exit.store(true, .unordered);

    var last_batch_sent = try Instant.now();
    var transaction_batch = PendingTransactions.init(allocator);
    defer transaction_batch.deinit();

    while (!exit.load(.unordered)) {
        const maybe_transaction = receive_channel.receive();
        const transaction = if (maybe_transaction == null) {
            break;
        } else blk: {
            std.debug.print("Failed to find leader addresses\n", .{});
            break :blk maybe_transaction.?;
        };

        if (!transaction_batch.contains(transaction.signature)) {
            var pending_transactions_lock = pending_transactions_rw.read();
            defer pending_transactions_lock.unlock();
            const pending_transactions: *const PendingTransactions = pending_transactions_lock.get();

            if (!pending_transactions.contains(transaction.signature)) {
                try transaction_batch.put(transaction.signature, transaction);
            }
        }

        if (transaction_batch.count() >= DEFAULT_BATCH_SIZE or
            (transaction_batch.count() > 0 and
            (try last_batch_sent.elapsed()).asNanos() >= DEFAULT_BATCH_SEND_RATE.asNanos()))
        {
            try sendTransactions(
                allocator,
                send_channel,
                service_info_rw,
                transaction_batch.values(),
            );
            last_batch_sent = try Instant.now();

            var pending_transactions_lock = pending_transactions_rw.write();
            defer pending_transactions_lock.unlock();
            var pending_transactions: *PendingTransactions = pending_transactions_lock.mut();

            for (transaction_batch.values()) |_tx| {
                var tx = _tx;
                if (pending_transactions.contains(tx.signature)) continue;
                if (pending_transactions.count() >= MAX_PENDING_POOL_SIZE) break;
                tx.last_sent_time = last_batch_sent;
                try pending_transactions.put(tx.signature, tx);
            }
            transaction_batch.clearRetainingCapacity();
        }
    }
}

fn processTransactionsThread(
    allocator: Allocator,
    send_channel: *Channel(std.ArrayList(Packet)),
    service_info_rw: *RwMux(ServiceInfo),
    pending_transactions_rw: *RwMux(PendingTransactions),
    exit: *AtomicBool,
) !void {
    errdefer exit.store(true, .unordered);

    while (!exit.load(.unordered)) {
        std.time.sleep(DEFAULT_PROCESS_TRANSACTIONS_RATE.asNanos());

        var pending_transactions_lock = pending_transactions_rw.write();
        defer pending_transactions_lock.unlock();
        var pending_transactions: *PendingTransactions = pending_transactions_lock.mut();

        if (pending_transactions.count() == 0) continue;

        try processTransactions(
            allocator,
            send_channel,
            service_info_rw,
            pending_transactions,
        );
    }
}

fn sendTransactions(
    allocator: Allocator,
    channel: *Channel(std.ArrayList(Packet)),
    service_info_rw: *RwMux(ServiceInfo),
    transactions: []TransactionInfo,
) !void {
    const leader_addresses = blk: {
        var service_info_lock = service_info_rw.read();
        defer service_info_lock.unlock();
        const service_info: *const ServiceInfo = service_info_lock.get();
        if (try service_info.getLeaderAddresses(allocator)) |leader_addresses| {
            break :blk leader_addresses;
        } else {
            return;
        }
    };
    defer allocator.free(leader_addresses);

    // const wire_transactions = try allocator.alloc([sig.net.packet.PACKET_DATA_SIZE]u8, transactions.len);
    // defer allocator.free(wire_transactions);

    // for (transactions, 0..) |tx, i| {
    //     wire_transactions[i] = tx.wire_transaction;
    // }

    std.debug.print("Sending {} transactions to {} leaders\n", .{ transactions.len, leader_addresses.len });
    for (transactions) |tx| {
        std.debug.print("Transaction: {any}\n", .{tx});
    }

    for (leader_addresses) |leader_address| {
        std.debug.print("Sending transactions to {}\n", .{leader_address});
        var packets = try std.ArrayList(Packet).initCapacity(allocator, transactions.len);
        for (transactions) |tx| {
            try packets.append(Packet.init(leader_address.toEndpoint(), tx.wire_transaction, tx.wire_transaction_size));
        }
        try channel.send(
            packets,
        );
    }
}

fn processTransactions(
    allocator: Allocator,
    send_channel: *Channel(std.ArrayList(Packet)),
    service_info_rw: *RwMux(ServiceInfo),
    pending_transactions: *PendingTransactions,
) !void {
    var retry_signatures = std.ArrayList(Signature).init(allocator);
    defer retry_signatures.deinit();

    var drop_signatures = std.ArrayList(Signature).init(allocator);
    defer drop_signatures.deinit();

    var rpc_client = RpcClient.init(allocator, "https://api.testnet.solana.com");
    defer rpc_client.deinit();

    const block_height = try rpc_client.getBlockHeight(allocator);
    const signatures = pending_transactions.keys();
    const signature_statuses = try rpc_client.getSignatureStatuses(allocator, .{
        .signatures = signatures,
        .searchTransactionHistory = false,
    });

    std.debug.print("Processing {} transactions\n", .{signature_statuses.value.len});
    std.debug.print("Statuses: {any}\n", .{signature_statuses.value});

    // Populate retry_signatures and drop_signatures
    var pending_transactions_iter = pending_transactions.iterator();
    for (signature_statuses.value) |maybe_signature_status| {
        const entry = pending_transactions_iter.next().?;
        const signature = entry.key_ptr.*;
        var transaction_info = entry.value_ptr;

        if (maybe_signature_status) |signature_status| {
            // If transaction is rooted, drop it
            if (signature_status.confirmations == null) {
                try drop_signatures.append(signature);
                continue;
            }

            // If transaction failed, drop it
            if (signature_status.err) {
                try drop_signatures.append(signature);
                continue;
            }

            // If transaction last valid block height is less than current block height, drop it
            if (transaction_info.last_valid_block_height < block_height) {
                try drop_signatures.append(signature);
                continue;
            }
        } else {
            // If transaction max retries exceeded, drop it
            const maybe_max_retries = transaction_info.max_retries orelse DEFAULT_MAX_RETRIES;
            if (maybe_max_retries) |max_retries| {
                if (transaction_info.retries >= max_retries) {
                    try drop_signatures.append(signature);
                    continue;
                }
            }

            // If transaction last sent time is greater than the retry sleep time, retry it
            const now = try Instant.now();
            const resend_transaction = if (transaction_info.last_sent_time) |lst| blk: {
                break :blk now.elapsed_since(lst).asNanos() >= DEFAULT_PROCESS_TRANSACTIONS_RATE.asNanos();
            } else true;
            if (resend_transaction) {
                if (transaction_info.last_sent_time) |_| {
                    transaction_info.retries += 1;
                }
                transaction_info.last_sent_time = now;
                try retry_signatures.append(signature);
            }
        }
    }

    // Retry transactions
    if (retry_signatures.items.len > 0) {
        var retry_transactions = try allocator.alloc(TransactionInfo, retry_signatures.items.len);
        defer allocator.free(retry_transactions);

        for (retry_signatures.items, 0..) |signature, i| {
            retry_transactions[i] = pending_transactions.get(signature).?;
        }

        var start_index: usize = 0;
        while (start_index < retry_transactions.len) {
            const end_index = @min(start_index + DEFAULT_BATCH_SIZE, retry_transactions.len);
            const batch = retry_transactions[start_index..end_index];
            try sendTransactions(
                allocator,
                send_channel,
                service_info_rw,
                batch,
            );
            start_index = end_index;
        }
    }

    // Remove transactions
    for (drop_signatures.items) |signature| {
        _ = pending_transactions.swapRemove(signature);
    }
}

const ServiceInfo = struct {
    allocator: Allocator,
    epoch_info: RpcEpochInfo,
    epoch_info_instant: Instant,
    latest_blockhash: RpcLatestBlockhash,
    leader_schedule: LeaderSchedule,
    leader_addresses: AutoArrayHashMap(Pubkey, SocketAddr),
    gossip_table_rw: *RwMux(GossipTable),

    const REFERENCE_SLOT_REFRESH_RATE = Duration.fromSecs(10);
    const NUMBER_OF_LEADERS_TO_FORWARD_TO = 1;

    pub fn init(
        allocator: Allocator,
        gossip_table_rw: *RwMux(GossipTable),
    ) !ServiceInfo {
        var rpc_client = RpcClient.init(allocator, "https://api.testnet.solana.com");
        defer rpc_client.deinit();

        const epoch_info_instant = try Instant.now();
        const epoch_info = try rpc_client.getEpochInfo(allocator, .{});
        const latest_blockhash = try rpc_client.getLatestBlockhash(allocator, .{});
        const leader_schedule = try fetchLeaderSchedule(allocator, &rpc_client);
        const leader_addresses = try fetchLeaderAddresses(allocator, leader_schedule.slot_leaders, gossip_table_rw);

        const file = try std.fs.cwd().createFile("leader-schedule.log", .{});
        defer file.close();

        for (leader_schedule.slot_leaders, 0..) |leader, i| {
            const slot = epoch_info.absoluteSlot - epoch_info.slotIndex + i;
            const string = try std.fmt.allocPrint(allocator, "{} {s}", .{ slot, try leader.toString() });
            try file.writeAll(string);
            try file.writeAll("\n");
        }

        return .{
            .allocator = allocator,
            .epoch_info = epoch_info,
            .epoch_info_instant = epoch_info_instant,
            .latest_blockhash = latest_blockhash,
            .leader_schedule = leader_schedule,
            .leader_addresses = leader_addresses,
            .gossip_table_rw = gossip_table_rw,
        };
    }

    pub fn deinit(self: *ServiceInfo) void {
        self.rpc_client.deinit();
        self.leader_schedule.deinit();
        self.leader_addresses.deinit();
    }

    pub fn refresh(self: *ServiceInfo) !void {
        // Deinit allocated resources
        self.leader_schedule.deinit();
        self.leader_addresses.deinit();

        // Fetch new data
        var rpc_client = RpcClient.init(self.allocator, "https://api.testnet.solana.com");
        defer rpc_client.deinit();

        self.epoch_info_instant = try Instant.now();
        self.epoch_info = try rpc_client.getEpochInfo(self.allocator, .{});
        self.latest_blockhash = try rpc_client.getLatestBlockhash(self.allocator, .{});
        self.leader_schedule = try fetchLeaderSchedule(self.allocator, &rpc_client);
        self.leader_addresses = try fetchLeaderAddresses(self.allocator, self.leader_schedule.slot_leaders, self.gossip_table_rw);
    }

    pub fn getLeaderAddresses(
        self: *const ServiceInfo,
        allocator: Allocator,
    ) !?[]SocketAddr {
        const leaders = try allocator.alloc(Pubkey, NUMBER_OF_LEADERS_TO_FORWARD_TO);
        defer allocator.free(leaders);

        for (0..NUMBER_OF_LEADERS_TO_FORWARD_TO) |i| {
            leaders[i] = try self.getLeaderAfterNSlots(NUM_CONSECUTIVE_LEADER_SLOTS * (i + 1));
        }

        const leader_addresses = try allocator.alloc(SocketAddr, NUMBER_OF_LEADERS_TO_FORWARD_TO);
        for (leaders, 0..) |pk, i| {
            leader_addresses[i] = self.leader_addresses.get(pk) orelse {
                return null;
            };
            std.debug.print("Leader pubkey={s} has address={any}\n", .{ try leaders[i].toString(), leader_addresses[i] });
        }

        return leader_addresses;
    }

    fn getLeaderAfterNSlots(self: *const ServiceInfo, n: u64) !Pubkey {
        var rpc_client = RpcClient.init(self.allocator, "https://api.testnet.solana.com");
        defer rpc_client.deinit();
        const slot = try rpc_client.getSlot(self.allocator);

        const slots_elapsed = (try self.epoch_info_instant.elapsed()).asMillis() / 400;

        const slot_index = self.epoch_info.slotIndex + slots_elapsed + n;

        std.debug.assert(slot_index < self.leader_schedule.slot_leaders.len);
        std.debug.print("N:                         {}\n", .{n});
        std.debug.print("Rpc Slot:                  {}\n", .{slot});
        std.debug.print("Slot After N:              {}\n", .{self.epoch_info.absoluteSlot + slots_elapsed + n});
        // std.debug.print("Approximate Slot Index:    {}\n", .{self.epoch_info.slotIndex + slots_elapsed});
        // std.debug.print("Approximate Absolute Slot: {}\n", .{self.epoch_info.absoluteSlot + slots_elapsed});
        // std.debug.print("Epoch Info Slot Index:     {}\n", .{self.epoch_info.slotIndex});
        // std.debug.print("Epoch Info Absolute Slot:  {}\n", .{self.epoch_info.absoluteSlot});
        // std.debug.print("Approximate Slots Elapsed: {}\n", .{slots_elapsed});
        std.debug.print("EpochInfo: {any}\n", .{self.epoch_info});
        std.debug.print("Leader Schedule Start: {any}\n", .{self.leader_schedule.start_slot});

        return self.leader_schedule.slot_leaders[slot_index];
    }

    fn fetchLeaderSchedule(allocator: Allocator, rpc_client: *RpcClient) !LeaderSchedule {
        const rpc_leader_schedule = try rpc_client.getLeaderSchedule(allocator, .{});

        var num_leaders: u64 = 0;
        for (rpc_leader_schedule.values()) |leader_slots| {
            num_leaders += leader_slots.len;
        }

        const Record = struct {
            slot: Slot,
            key: Pubkey,
        };

        var leaders_index: usize = 0;
        var leaders = try allocator.alloc(Record, num_leaders);
        defer allocator.free(leaders);

        var rpc_leader_iter = rpc_leader_schedule.iterator();
        while (rpc_leader_iter.next()) |entry| {
            const key = try Pubkey.fromString(entry.key_ptr.*);
            for (entry.value_ptr.*) |slot| {
                leaders[leaders_index] = .{
                    .slot = slot,
                    .key = key,
                };
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
            .start_slot = leaders[0].slot,
        };
    }

    fn fetchLeaderAddresses(allocator: Allocator, leaders: []const Pubkey, gossip_table_rw: *RwMux(GossipTable)) !AutoArrayHashMap(Pubkey, SocketAddr) {
        var gossip_table_lock = gossip_table_rw.read();
        defer gossip_table_lock.unlock();
        const gossip_table: *const GossipTable = gossip_table_lock.get();

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
    service_info_rw: *RwMux(ServiceInfo),
    exit: *AtomicBool,
) !void {
    errdefer exit.store(true, .unordered);

    const from_pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const from_keypair = KeyPair{
        .public_key = .{ .bytes = from_pubkey.data },
        .secret_key = .{ .bytes = [_]u8{ 76, 196, 192, 17, 40, 245, 120, 49, 64, 133, 213, 227, 12, 42, 183, 70, 235, 64, 235, 96, 246, 205, 78, 13, 173, 111, 254, 96, 210, 208, 121, 240, 159, 193, 185, 89, 227, 77, 234, 91, 232, 234, 253, 119, 162, 105, 200, 227, 123, 90, 111, 105, 72, 53, 60, 147, 76, 154, 44, 72, 29, 165, 2, 246 } },
    };
    const to_pubkey = try Pubkey.fromString("GDFVa3uYXDcNhcNk8A4v28VeF4wcMn8mauZNwVWbpcN");
    const lamports: u64 = 100;

    while (!exit.load(.unordered)) {
        std.time.sleep(Duration.fromSecs(60 * 2).asNanos());

        const latest_blockhash = blk: {
            var service_info_lock = service_info_rw.read();
            defer service_info_lock.unlock();
            const service_info: *const ServiceInfo = service_info_lock.get();

            break :blk service_info.latest_blockhash.value;
        };

        const transaction = try sig.core.transaction.buildTransferTansaction(
            allocator,
            from_keypair,
            from_pubkey,
            to_pubkey,
            lamports,
            latest_blockhash.blockhash,
        );

        const transaction_info = try TransactionInfo.new(
            transaction,
            latest_blockhash.lastValidBlockHeight,
            null,
            null,
        );

        try sender.send(transaction_info);
    }
}

test "mockTransaction" {
    const allocator = std.heap.page_allocator;

    var client = RpcClient{
        .http_client = std.http.Client{
            .allocator = std.heap.page_allocator,
        },
        .http_endpoint = "https://api.testnet.solana.com",
    };
    defer client.http_client.deinit();
    const params = sig.rpc.Client.LatestBlockhashParams{};
    const latest_blockhash = try client.getLatestBlockhash(allocator, params);

    const from_pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const from_keypair = KeyPair{
        .public_key = .{ .bytes = from_pubkey.data },
        .secret_key = .{ .bytes = [_]u8{ 76, 196, 192, 17, 40, 245, 120, 49, 64, 133, 213, 227, 12, 42, 183, 70, 235, 64, 235, 96, 246, 205, 78, 13, 173, 111, 254, 96, 210, 208, 121, 240, 159, 193, 185, 89, 227, 77, 234, 91, 232, 234, 253, 119, 162, 105, 200, 227, 123, 90, 111, 105, 72, 53, 60, 147, 76, 154, 44, 72, 29, 165, 2, 246 } },
    };
    const to_pubkey = try Pubkey.fromString("GDFVa3uYXDcNhcNk8A4v28VeF4wcMn8mauZNwVWbpcN");
    const lamports: u64 = 100;

    const transaction = try sig.core.transaction.buildTransferTansaction(
        allocator,
        from_keypair,
        from_pubkey,
        to_pubkey,
        lamports,
        latest_blockhash.value.blockhash,
    );

    // _ = transaction;
    std.debug.print("TRANSACTION\n", .{});
    for (transaction.signatures) |s| {
        std.debug.print("Signature: {s}\n", .{try s.toString()});
    }

    std.debug.print("MessageHeader: {}\n", .{transaction.message.header});
    for (transaction.message.account_keys) |k| {
        std.debug.print("AccountKey: {s}\n", .{try k.toString()});
    }
    std.debug.print("RecentBlockhash: {any}\n", .{transaction.message.recent_blockhash});
    for (transaction.message.instructions) |i| {
        std.debug.print("Instruction: {any}\n", .{i});
    }

    var buf: [sig.net.packet.PACKET_DATA_SIZE]u8 = undefined;
    const transaction_bytes = try sig.bincode.writeToSlice(&buf, transaction, .{});
    std.debug.print("TransactionBytes: {any}\n", .{transaction_bytes});
}
