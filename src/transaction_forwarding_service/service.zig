const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const AutoArrayHashMap = std.AutoArrayHashMap;
const AtomicBool = std.atomic.Value(bool);
const AtomicSlot = std.atomic.Value(Slot);
const Thread = std.Thread;

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
const LeaderSchedule = sig.core.leader_schedule.SingleEpochLeaderSchedule;

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
    my_contact_info: *RwMux(ContactInfo),
    gossip_table_rw: *RwMux(GossipTable),
    receiver: *Channel(TransactionInfo),
    exit: *AtomicBool,
) !void {
    const allocator = std.heap.page_allocator;

    const pending_transactions = PendingTransactions.init(allocator);
    var pending_transactions_rw = RwMux(PendingTransactions).init(pending_transactions);

    const service_info = try ServiceInfo.init(allocator, my_contact_info, gossip_table_rw);
    var service_info_rw = RwMux(ServiceInfo).init(service_info);

    const refresh_service_info_handle = try Thread.spawn(
        .{},
        refreshServiceInfoThread,
        .{
            allocator,
            &service_info_rw,
            exit,
        },
    );

    const receive_transactions_handle = try Thread.spawn(
        .{},
        receiveTransactionsThread,
        .{
            allocator,
            receiver,
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
            &service_info_rw,
            &pending_transactions_rw,
            exit,
        },
    );

    refresh_service_info_handle.join();
    receive_transactions_handle.join();
    process_transactions_handle.join();
}

fn refreshServiceInfoThread(
    allocator: Allocator,
    service_info_rw: *RwMux(ServiceInfo),
    exit: *AtomicBool,
) !void {
    errdefer exit.store(true, .unordered);

    while (!exit.load(.unordered)) {
        std.time.sleep(ServiceInfo.REFERENCE_SLOT_REFRESH_RATE.asNanos());

        var service_info_lock = service_info_rw.write();
        defer service_info_lock.unlock();
        var service_info: *ServiceInfo = service_info_lock.mut();

        try service_info.refresh(allocator);
    }
}

fn receiveTransactionsThread(
    allocator: Allocator,
    receiver: *Channel(TransactionInfo),
    service_info_rw: *RwMux(ServiceInfo),
    pending_transactions_rw: *RwMux(PendingTransactions),
    exit: *AtomicBool,
) !void {
    errdefer exit.store(true, .unordered);

    var last_batch_sent = try Instant.now();
    var transaction_batch = PendingTransactions.init(allocator);
    defer transaction_batch.deinit();

    while (!exit.load(.unordered)) {
        const maybe_transaction = receiver.receive();
        const transaction = if (maybe_transaction == null) {
            break;
        } else blk: {
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
                service_info_rw,
                &transaction_batch,
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
            service_info_rw,
            pending_transactions,
        );
    }
}

fn sendTransactions(
    allocator: Allocator,
    service_info_rw: *RwMux(ServiceInfo),
    transactions: *PendingTransactions,
) !void {
    const leader_addresses = blk: {
        var service_info_lock = service_info_rw.read();
        defer service_info_lock.unlock();
        const service_info: *const ServiceInfo = service_info_lock.get();
        break :blk try service_info.getLeaderAddresses(allocator);
    };
    defer allocator.free(leader_addresses);

    const wire_transactions = try allocator.alloc([]u8, transactions.count());
    defer allocator.free(wire_transactions);

    for (transactions.values(), 0..) |tx, i| {
        wire_transactions[i] = tx.wire_transaction;
    }

    for (leader_addresses) |leader_address| {
        try sendWireTransactions(
            leader_address,
            &wire_transactions,
        );
    }
}

fn sendWireTransactions(
    address: SocketAddr,
    transactions: *const [][]u8,
) !void {
    // TODO: Implement
    // var conn = connection_cache.get_connection(tpu_address);
    // conn.send_data_async(transactions);
    _ = address;
    _ = transactions;
}

fn processTransactions(
    allocator: Allocator,
    service_info_rw: *RwMux(ServiceInfo),
    pending_transactions: *PendingTransactions,
) !void {
    var drop_signatures = std.ArrayList(Signature).init(allocator);
    defer drop_signatures.deinit();

    var service_info_lock = service_info_rw.write();
    defer service_info_lock.unlock();
    const service_info: *ServiceInfo = service_info_lock.mut();

    const block_height = try service_info.rpc_client.getBlockHeight(allocator);

    const signatures = pending_transactions.keys();
    const signature_statuses = try service_info.rpc_client.getSignatureStatuses(allocator, .{
        .signatures = signatures,
        .searchTransactionHistory = false,
    });

    for (signatures, signature_statuses.value, pending_transactions.values()) |
        signature,
        signature_status,
        transaction_info,
    | {
        // If transaction is rooted, drop it
        if (signature_status == null) {
            try drop_signatures.append(signature);
            continue;
        }

        // If transaction last valid block height is less than current block height, drop it
        if (transaction_info.last_valid_block_height < block_height) {
            try drop_signatures.append(signature);
            continue;
        }

        // If transaction has used max retries, drop it
        const unbounded_max_retries = transaction_info.max_retries orelse DEFAULT_MAX_RETRIES;
        if (unbounded_max_retries) |max_retries| {
            if (transaction_info.retries >= @min(max_retries, DEFAULT_SERVICE_MAX_RETRIES)) {
                try drop_signatures.append(signature);
                continue;
            }
        }

        //
    }
}

const ServiceInfo = struct {
    rpc_client: RpcClient,
    epoch_info: RpcEpochInfo,
    epoch_info_instant: Instant,
    leader_schedule: LeaderSchedule,
    leader_addresses: AutoArrayHashMap(Pubkey, SocketAddr),
    my_contact_info_rw: *RwMux(ContactInfo),
    gossip_table_rw: *RwMux(GossipTable),

    const REFERENCE_SLOT_REFRESH_RATE = Duration.fromSecs(60);
    const NUMBER_OF_LEADERS_TO_FORWARD_TO = 2;

    pub fn init(
        allocator: Allocator,
        my_contact_info_rw: *RwMux(ContactInfo),
        gossip_table_rw: *RwMux(GossipTable),
    ) !ServiceInfo {
        var rpc_client = RpcClient.init(allocator, "https://api.mainnet-beta.solana.com");

        const epoch_info_instant = try Instant.now();
        const epoch_info = try rpc_client.getEpochInfo(allocator, .{});
        const leader_schedule = try fetchLeaderSchedule(allocator, &rpc_client);
        const leader_addresses = try fetchLeaderAddresses(allocator, leader_schedule.slot_leaders, gossip_table_rw);

        return .{
            .rpc_client = rpc_client,
            .epoch_info = epoch_info,
            .epoch_info_instant = epoch_info_instant,
            .leader_schedule = leader_schedule,
            .leader_addresses = leader_addresses,
            .my_contact_info_rw = my_contact_info_rw,
            .gossip_table_rw = gossip_table_rw,
        };
    }

    pub fn deinit(self: *ServiceInfo) void {
        self.rpc_client.deinit();
        self.leader_schedule.deinit();
        self.leader_addresses.deinit();
    }

    pub fn refresh(self: *ServiceInfo, allocator: Allocator) !void {
        self.epoch_info_instant = try Instant.now();
        self.epoch_info = try self.rpc_client.getEpochInfo(allocator, .{});
        self.leader_schedule = try fetchLeaderSchedule(allocator, &self.rpc_client);
        self.leader_addresses = try fetchLeaderAddresses(allocator, self.leader_schedule.slot_leaders, self.gossip_table_rw);
    }

    pub fn getLeaderAddresses(
        self: *const ServiceInfo,
        allocator: Allocator,
    ) ![]SocketAddr {
        const leaders = try allocator.alloc(Pubkey, NUMBER_OF_LEADERS_TO_FORWARD_TO);
        defer allocator.free(leaders);

        for (0..NUMBER_OF_LEADERS_TO_FORWARD_TO) |i| {
            leaders[i] = try self.getLeaderAfterNSlots(NUM_CONSECUTIVE_LEADER_SLOTS * i);
        }

        const leader_addresses = try allocator.alloc(SocketAddr, NUMBER_OF_LEADERS_TO_FORWARD_TO);
        for (leaders, 0..) |pk, i| {
            leader_addresses[i] = self.leader_addresses.get(pk).?;
        }

        return leader_addresses;
    }

    fn getLeaderAfterNSlots(self: *const ServiceInfo, n: u64) !Pubkey {
        const slots_elapsed = (try self.epoch_info_instant.elapsed()).asMillis() / 400;
        const slot_index = self.epoch_info.slotIndex + slots_elapsed + n;
        std.debug.assert(slot_index < self.leader_schedule.slot_leaders.len);
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
                    .gt => true,
                    else => false,
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

const TransactionInfo = struct {
    signature: Signature,
    wire_transaction: []u8,
    last_valid_block_height: u64,
    durable_nonce_info: ?struct { Pubkey, Hash },
    max_retries: ?usize,
    retries: usize,
    last_sent_time: ?Instant,

    pub fn new(
        signature: Signature,
        wire_transaction: []u8,
        last_valid_block_height: u64,
        durable_nonce_info: ?struct { Pubkey, Hash },
        max_retries: ?usize,
    ) TransactionInfo {
        return TransactionInfo{
            .signature = signature,
            .wire_transaction = wire_transaction,
            .last_valid_block_height = last_valid_block_height,
            .durable_nonce_info = durable_nonce_info,
            .max_retries = max_retries,
            .retries = 0,
            .last_sent_time = null,
        };
    }
};
