const std = @import("std");
const sig = @import("../sig.zig");

const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

const Instant = sig.time.Instant;
const Duration = sig.time.Duration;

const AccountStore = sig.accounts_db.AccountStore;

const Packet = sig.net.Packet;

const Channel = sig.sync.Channel;
const ExitCondition = sig.sync.ExitCondition;

pub const Logger = sig.trace.Logger("transaction_sender");

/// Spawn quic client
/// Receive Transactions
///     - If transaction is not in pool, add to batch
///     - If batch is full or batch duration has elapsed, process transactions
/// Process Transactions
///     - Get current block height
///     - Get signature statuses
///     - Iterate statuses, signatures, transactions
///         - If transaction succeeded, add to drop pool
///         - If transaction failed, add to drop pool
///         - If transaction is expired, add to drop pool
///         = if transaction exceeded max retries, add to drop pool
///         - If transaction is eligible for retry, add to retry batch
/// Retry Transactions
///     - Send transactions in retry batch to quic client
pub fn run(
    gpa: std.mem.Allocator,
    config: Config,
    account_store: AccountStore,
    epoch_tracker: *sig.core.EpochTracker,
    slot_tracker: *sig.replay.trackers.SlotTracker,
    status_cache: *sig.core.StatusCache,
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    receiver: *Channel(TransactionInfo),
    logger: Logger,
    exit: ExitCondition,
) !void {
    const quic_channel = try Channel(Packet).create(gpa);
    quic_channel.name = "Transaction Sender: Quic Channel";
    errdefer quic_channel.destroy();

    const quic_client_handle = try std.Thread.spawn(
        .{},
        sig.net.quic_client.runClient,
        .{
            gpa,
            quic_channel,
            sig.net.quic_client.Logger.from(logger),
            exit,
        },
    );
    defer quic_client_handle.join();

    try handleTransactions(
        gpa,
        config,
        account_store,
        epoch_tracker,
        slot_tracker,
        status_cache,
        gossip_table_rw,
        receiver,
        quic_channel,
        logger,
        exit,
    );
}

pub fn handleTransactions(
    gpa: std.mem.Allocator,
    config: Config,
    account_store: AccountStore,
    epoch_tracker: *sig.core.EpochTracker,
    slot_tracker: *sig.replay.trackers.SlotTracker,
    status_cache: *sig.core.StatusCache,
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    receiver: *Channel(TransactionInfo),
    sender: *Channel(Packet),
    logger: Logger,
    exit: ExitCondition,
) !void {
    errdefer |err| {
        std.debug.print("(TSS) Process transactions failed: {any}\n", .{err});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    var leader_info = try LeaderInfo.init(
        gpa,
        epoch_tracker,
        gossip_table_rw,
        config.max_leaders_to_send_to,
    );
    defer leader_info.deinit(gpa);

    // const metrics = try Metrics.init();

    var txn_pool = std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo).empty;
    defer txn_pool.deinit(gpa);
    try txn_pool.ensureTotalCapacity(gpa, config.max_pool_size);

    var drop_signatures = std.ArrayList(Signature).empty;
    defer drop_signatures.deinit(gpa);
    try drop_signatures.ensureTotalCapacity(gpa, config.max_pool_size);

    while (!exit.shouldExit()) {
        receiveTransactions(
            receiver,
            &txn_pool,
            config.process_interval,
            logger,
            exit,
        );

        processTransactions();
    }
    // processTransactions();

    //
    // Process transactions
    //

    //     // Get last processed slot reference
    //     // NOTE: Agave uses the working bank here, which is not the last processed slot.
    //     const working_slot = slot_tracker.commitments.processed.load(.monotonic);
    //     const working_slot_ref = slot_tracker.get(working_slot) orelse {
    //         std.debug.print("(TSS) Working slot {d} not available yet\n", .{working_slot});
    //         std.Thread.sleep(100_000_000);
    //         continue;
    //     };
    //     defer working_slot_ref.release();
    //     const working_ancestors = &working_slot_ref.constants().ancestors;

    //     const root_slot = slot_tracker.root.load(.monotonic);
    //     const root_slot_ref = slot_tracker.get(root_slot) orelse {
    //         std.debug.print("(TSS) Root slot {d} not available yet\n", .{root_slot});
    //         std.Thread.sleep(100_000_000);
    //         continue;
    //     };
    //     defer root_slot_ref.release();
    //     const root_ancestors = &root_slot_ref.constants().ancestors;
    //     const root_block_height = root_slot_ref.constants().block_height;

    //     const slot_account_store = account_store.forSlot(working_slot, working_ancestors);
    //     const slot_account_reader = slot_account_store.reader();

    //     const leader_addresses = try leader_info.getLeaderAddresses(gpa, working_slot);

    //     std.debug.print("(TSS) Processing transactions: working_slot={d} root_slot={d} pool_size={d} leaders={any}\n", .{
    //         working_slot,
    //         root_slot,
    //         txn_pool.count(),
    //         leader_addresses,
    //     });
    //     for (txn_pool.keys(), txn_pool.values()) |signature, *txn_info| {
    //         std.debug.print("(TSS) Processing transaction: signature={f}\n", .{txn_info.signature});

    //         if (status_cache.getStatusSummary(
    //             &txn_info.message_hash.data,
    //             &txn_info.recent_blockhash,
    //             root_ancestors,
    //         ) != .unprocessed) {
    //             std.debug.print("(TSS) Transaction rooted: signature={f}\n", .{txn_info.signature});
    //             drop_signatures.appendAssumeCapacity(signature);
    //             continue;
    //         }

    //         const txn_status = status_cache.getStatusSummary(
    //             &txn_info.message_hash.data,
    //             &txn_info.recent_blockhash,
    //             working_ancestors,
    //         );

    //         if (txn_status == .failed) {
    //             std.debug.print("(TSS) Dropping failed transaction: signature={f}\n", .{txn_info.signature});
    //             drop_signatures.appendAssumeCapacity(signature);
    //             continue;
    //         }

    //         if (txn_info.last_valid_block_height < root_block_height) {
    //             std.debug.print("(TSS) Dropping expired transaction: signature={f}\n", .{txn_info.signature});
    //             drop_signatures.appendAssumeCapacity(signature);
    //             continue;
    //         }

    //         if (txn_info.retries >= @min(txn_info.max_retries, config.max_retries)) {
    //             std.debug.print("(TSS) Dropping transaction due to max retries: signature={f}\n", .{txn_info.signature});
    //             drop_signatures.appendAssumeCapacity(signature);
    //             continue;
    //         }

    //         if (txn_info.durable_nonce_info) |durable_nonce_info| {
    //             const nonce_pubkey = durable_nonce_info[0];
    //             const nonce_hash = durable_nonce_info[1];

    //             const nonce_account = try slot_account_reader.get(gpa, nonce_pubkey) orelse sig.core.Account{
    //                 .lamports = 0,
    //                 .data = .initEmpty(0),
    //                 .owner = .ZEROES,
    //                 .executable = false,
    //                 .rent_epoch = 0,
    //             };
    //             defer nonce_account.deinit(gpa);

    //             const verify_nonce_result = sig.runtime.check_transactions.verifyNonceAccount(
    //                 nonce_account,
    //                 &nonce_hash,
    //             );

    //             const expired = if (txn_info.last_sent_time) |last_sent_time|
    //                 Instant.now().elapsedSince(last_sent_time).ns >= config.retry_rate.ns
    //             else
    //                 false;

    //             // TODO: Why require transaction status unprocessed and expired to drop?
    //             if (txn_status == .unprocessed and verify_nonce_result == null and expired) {
    //                 std.debug.print("(TSS) Dropping transaction with expired durable nonce: signature={f}\n", .{txn_info.signature});
    //                 drop_signatures.appendAssumeCapacity(signature);
    //                 continue;
    //             }
    //         }

    //         const should_send = if (txn_info.last_sent_time) |last_sent_time|
    //             Instant.now().elapsedSince(last_sent_time).ns >= config.retry_rate.ns
    //         else
    //             true;

    //         if (should_send) {
    //             std.debug.print("(TSS) Sending transaction: signature={f}\n", .{txn_info.signature});
    //             if (txn_info.last_sent_time == null) logCliSubmitCommand(txn_info);
    //             var packet = Packet.init(
    //                 undefined,
    //                 txn_info.wire_transaction,
    //                 txn_info.wire_transaction_size,
    //             );

    //             for (leader_addresses) |maybe_leader_address| {
    //                 const leader_address = maybe_leader_address orelse continue;
    //                 std.debug.print("(TSS) Sending transaction to leader at {f}: signature={f}\n", .{ leader_address, txn_info.signature });
    //                 packet.addr = leader_address;
    //                 try sender.send(packet);
    //             }

    //             if (txn_info.last_sent_time) |_| txn_info.retries += 1;
    //             txn_info.last_sent_time = Instant.now();

    //             std.debug.print("(TSS) Transaction sent: signature={f}, retries={}\n", .{ txn_info.signature, txn_info.retries });
    //         }
    //     }

    //     for (drop_signatures.items) |signature| _ = txn_pool.swapRemove(signature);
    //     drop_signatures.clearRetainingCapacity();

    //     last_process_time = Instant.now();
    // }
}

fn receiveTransactions(
    receiver: *Channel(TransactionInfo),
    txn_pool: *std.AutoArrayHashMap(Signature, TransactionInfo),
    timeout: Duration,
    exit: ExitCondition,
) void {
    var timer = Instant.now();
    while (exit.shouldRun() and
        timer.elapsed().lt(timeout) and
        txn_pool.count() < txn_pool.capacity())
    {
        defer if (txn_pool.count() == 0) {
            timer = Instant.now();
        };
        receiver.event.timedWait(10 * std.time.ns_per_ms) catch continue;
        if (receiver.tryReceive()) |txn_info| {
            if (!txn_pool.contains(txn_info.signature)) txn_pool.putAssumeCapacity(
                txn_info.signature,
                txn_info,
            );
        }
    }
}

const StatusCache = sig.core.Statu
fn processTransactions(
    txn_pool: *std.AutoArrayHashMap(Signature, TransactionInfo),
    status_cache: *StatusCache,
    root_ancestors: *RootAncestors,
    drop_signatures: *std.ArrayList(Signature),
) !void {
    for (txn_pool.keys(), txn_pool.values()) |signature, *txn_info| {
        std.debug.print("(TSS) Processing transaction: signature={f}\n", .{txn_info.signature});

        if (status_cache.getStatusSummary(
            &txn_info.message_hash.data,
            &txn_info.recent_blockhash,
            root_ancestors,
        ) != .unprocessed) {
            std.debug.print("(TSS) Transaction rooted: signature={f}\n", .{txn_info.signature});
            drop_signatures.appendAssumeCapacity(signature);
            continue;
        }

        const txn_status = status_cache.getStatusSummary(
            &txn_info.message_hash.data,
            &txn_info.recent_blockhash,
            working_ancestors,
        );

        if (txn_status == .failed) {
            std.debug.print("(TSS) Dropping failed transaction: signature={f}\n", .{txn_info.signature});
            drop_signatures.appendAssumeCapacity(signature);
            continue;
        }

        if (txn_info.last_valid_block_height < root_block_height) {
            std.debug.print("(TSS) Dropping expired transaction: signature={f}\n", .{txn_info.signature});
            drop_signatures.appendAssumeCapacity(signature);
            continue;
        }

        if (txn_info.retries >= @min(txn_info.max_retries, config.max_retries)) {
            std.debug.print("(TSS) Dropping transaction due to max retries: signature={f}\n", .{txn_info.signature});
            drop_signatures.appendAssumeCapacity(signature);
            continue;
        }

        if (txn_info.durable_nonce_info) |durable_nonce_info| {
            const nonce_pubkey = durable_nonce_info[0];
            const nonce_hash = durable_nonce_info[1];

            const nonce_account = try slot_account_reader.get(gpa, nonce_pubkey) orelse sig.core.Account{
                .lamports = 0,
                .data = .initEmpty(0),
                .owner = .ZEROES,
                .executable = false,
                .rent_epoch = 0,
            };
            defer nonce_account.deinit(gpa);

            const verify_nonce_result = sig.runtime.check_transactions.verifyNonceAccount(
                nonce_account,
                &nonce_hash,
            );

            const expired = if (txn_info.last_sent_time) |last_sent_time|
                Instant.now().elapsedSince(last_sent_time).ns >= config.retry_rate.ns
            else
                false;

            // TODO: Why require transaction status unprocessed and expired to drop?
            if (txn_status == .unprocessed and verify_nonce_result == null and expired) {
                std.debug.print("(TSS) Dropping transaction with expired durable nonce: signature={f}\n", .{txn_info.signature});
                drop_signatures.appendAssumeCapacity(signature);
                continue;
            }
        }

        const should_send = if (txn_info.last_sent_time) |last_sent_time|
            Instant.now().elapsedSince(last_sent_time).ns >= config.retry_rate.ns
        else
            true;

        if (should_send) {
            std.debug.print("(TSS) Sending transaction: signature={f}\n", .{txn_info.signature});
            if (txn_info.last_sent_time == null) logCliSubmitCommand(txn_info);
            var packet = Packet.init(
                undefined,
                txn_info.wire_transaction,
                txn_info.wire_transaction_size,
            );

            for (leader_addresses) |maybe_leader_address| {
                const leader_address = maybe_leader_address orelse continue;
                std.debug.print("(TSS) Sending transaction to leader at {f}: signature={f}\n", .{ leader_address, txn_info.signature });
                packet.addr = leader_address;
                try sender.send(packet);
            }

            if (txn_info.last_sent_time) |_| txn_info.retries += 1;
            txn_info.last_sent_time = Instant.now();

            std.debug.print("(TSS) Transaction sent: signature={f}, retries={}\n", .{ txn_info.signature, txn_info.retries });
        }
    }

    for (drop_signatures.items) |signature| _ = txn_pool.swapRemove(signature);
    drop_signatures.clearRetainingCapacity();

    last_process_time = Instant.now();
}

pub const Config = struct {
    process_interval: sig.time.Duration,
    retry_rate: sig.time.Duration,
    max_pool_size: usize,
    receive_batch_size: usize,
    max_retries: usize,
    max_leaders_to_send_to: usize,
};

pub const TransactionInfo = struct {
    signature: Signature,
    message_hash: Hash,
    recent_blockhash: Hash,
    wire_transaction: [sig.net.Packet.DATA_SIZE]u8,
    wire_transaction_size: usize,
    last_valid_block_height: u64,
    durable_nonce_info: ?struct { Pubkey, Hash },
    retries: usize,
    max_retries: usize,
    last_sent_time: ?Instant,

    pub fn init(
        transaction: sig.core.Transaction,
        message_hash: Hash,
        last_valid_block_height: u64,
        durable_nonce_info: ?struct { Pubkey, Hash },
        max_retries: ?usize,
    ) !TransactionInfo {
        var wire_transaction: [sig.net.Packet.DATA_SIZE]u8 = @splat(0);
        const wire_transaction_size = (try sig.bincode.writeToSlice(
            &wire_transaction,
            transaction,
            .{},
        )).len;
        return .{
            .signature = transaction.signatures[0],
            .message_hash = message_hash,
            .recent_blockhash = transaction.msg.recent_blockhash,
            .wire_transaction = wire_transaction,
            .wire_transaction_size = wire_transaction_size,
            .last_valid_block_height = last_valid_block_height,
            .durable_nonce_info = durable_nonce_info,
            .retries = 0,
            .max_retries = max_retries orelse std.math.maxInt(usize),
            .last_sent_time = null,
        };
    }
};

fn logCliSubmitCommand(txn_info: *const TransactionInfo) void {
    const wire_txn = txn_info.wire_transaction[0..txn_info.wire_transaction_size];

    var encoded_buf: [std.base64.standard.Encoder.calcSize(sig.net.Packet.DATA_SIZE)]u8 = undefined;
    const encoded_len = std.base64.standard.Encoder.calcSize(wire_txn.len);
    const encoded_wire_txn = std.base64.standard.Encoder.encode(encoded_buf[0..encoded_len], wire_txn);

    std.debug.print("(TSS) Transaction wire payload (base64): {s}\n", .{encoded_wire_txn});
    std.debug.print(
        "(TSS) JSON-RPC submit: curl https://api.testnet.solana.com -H 'Content-Type: application/json' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendTransaction\",\"params\":[\"{s}\",{{\"encoding\":\"base64\"}}]}}'\n",
        .{encoded_wire_txn},
    );
}

/// Provide access to the leader schedule and leader addresses.
const LeaderInfo = struct {
    next_leader_addresses: []?sig.net.SocketAddr,
    leader_addresses: sig.utils.collections.PubkeyMap(?struct { sig.net.SocketAddr, Instant }),
    leader_schedules: sig.core.epoch_tracker.LeaderSchedulesWithEpochInfos,
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    epoch_tracker: *sig.core.EpochTracker,

    const REFRESH_LEADER_ADDRESS_INTERVAL = sig.time.Duration.fromSecs(60);

    pub fn deinit(self: *LeaderInfo, gpa: std.mem.Allocator) void {
        gpa.free(self.next_leader_addresses);
        self.leader_addresses.deinit(gpa);
        self.leader_schedules.release();
    }

    pub fn init(
        gpa: std.mem.Allocator,
        epoch_tracker: *sig.core.EpochTracker,
        gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
        max_leaders_to_send_to: usize,
    ) !LeaderInfo {
        const leader_schedules = try epoch_tracker.getLeaderSchedules();
        errdefer leader_schedules.release();

        const next_leader_addresses = try gpa.alloc(?sig.net.SocketAddr, max_leaders_to_send_to);
        errdefer gpa.free(next_leader_addresses);
        for (next_leader_addresses) |*leader_address| leader_address.* = null;

        return .{
            .next_leader_addresses = next_leader_addresses,
            .leader_addresses = .empty,
            .leader_schedules = leader_schedules,
            .gossip_table_rw = gossip_table_rw,
            .epoch_tracker = epoch_tracker,
        };
    }

    pub fn getLeaderAddresses(self: *LeaderInfo, gpa: std.mem.Allocator, slot: Slot) ![]const ?sig.net.SocketAddr {
        for (self.next_leader_addresses, 0..) |*leader_address, i| {
            leader_address.* = try self.getLeaderAddress(
                gpa,
                slot + i * sig.core.leader_schedule.NUM_CONSECUTIVE_LEADER_SLOTS,
            );
        }
        return self.next_leader_addresses;
    }

    fn getLeaderAddress(self: *LeaderInfo, gpa: std.mem.Allocator, slot: u64) !?sig.net.SocketAddr {
        var leader_schedules = &self.leader_schedules.leader_schedules;
        const leader_pubkey = leader_schedules.getLeader(slot) catch blk: {
            self.leader_schedules.release();
            self.leader_schedules = try self.epoch_tracker.getLeaderSchedules();
            leader_schedules = &self.leader_schedules.leader_schedules;
            break :blk leader_schedules.getLeader(slot) catch return error.NoLeaderForSlot;
        };
        std.debug.print("(TSS) Leader for slot {d} is {f}\n", .{ slot, leader_pubkey });

        const maybe_cached_address = self.leader_addresses.get(leader_pubkey) orelse blk: {
            std.debug.print("(TSS) Leader address for {f} not in cache, refreshing leader schedules\n", .{leader_pubkey});
            self.leader_addresses.clearRetainingCapacity();

            for (leader_schedules.curr.leaders) |leader| {
                try self.leader_addresses.put(gpa, leader, null);
            }

            if (leader_schedules.next) |next| {
                for (next.leaders) |leader| {
                    try self.leader_addresses.put(gpa, leader, null);
                }
            }

            break :blk self.leader_addresses.get(leader_pubkey) orelse return error.NoLeaderForSlot;
        };

        if (maybe_cached_address) |cached_address| {
            std.debug.print("(TSS) Found cached leader address for {f}: {f}\n", .{ leader_pubkey, cached_address[0] });
            if (Instant.now().elapsedSince(cached_address[1]).ns < REFRESH_LEADER_ADDRESS_INTERVAL.ns) {
                return cached_address[0];
            }
        }

        std.debug.print("(TSS) Leader address for {f} is not fresh, refreshing from gossip table\n", .{leader_pubkey});
        const gossip_table: *const sig.gossip.GossipTable, var gossip_table_lg =
            self.gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        if (gossip_table.getThreadSafeContactInfo(leader_pubkey)) |contact_info| {
            std.debug.print("(TSS) Found contact info for leader: pubkey={f} tpu_quic_addr={any}\n", .{ leader_pubkey, contact_info.tpu_quic_addr });
            if (contact_info.tpu_quic_addr) |leader_address| {
                try self.leader_addresses.put(gpa, leader_pubkey, .{
                    leader_address,
                    Instant.now(),
                });
            } else try self.leader_addresses.put(gpa, leader_pubkey, null);
            return contact_info.tpu_quic_addr;
        } else {
            std.debug.print("(TSS) No contact info found for leader {f} in gossip table\n", .{leader_pubkey});
            try self.leader_addresses.put(gpa, leader_pubkey, null);
            return null;
        }
    }
};

// const Counter = sig.prometheus.Counter;
// const Gauge = sig.prometheus.Gauge;

// const Metrics = struct {
//     pub const prefix = "transaction_sender";

//     pub fn init() sig.prometheus.GetMetricError!Metrics {
//         return sig.prometheus.globalRegistry().initStruct(Metrics);
//     }

//     pub fn log(self: *const Metrics, logger: Logger) void {
// std.debug.print("\n", .{});
//     }
// };

pub const TRANSFER_AMOUNT: u64 = 1e6;
pub const TRANSFER_FEE: u64 = 5000;
pub const TRANSFER_COST: u64 = TRANSFER_AMOUNT + TRANSFER_FEE;

pub const MockAccount = struct {
    keypair: KeyPair,
    pubkey: Pubkey,
    balance: u64,

    pub fn init(keypair: KeyPair) MockAccount {
        return .{
            .keypair = keypair,
            .pubkey = Pubkey.fromPublicKey(&keypair.public_key),
            .balance = 0,
        };
    }
};

pub const MockAccounts = struct {
    alice: MockAccount,
    bob: MockAccount,

    pub const DEFAULT: MockAccounts = .{
        // H67JSziFxAZR1KSQshWfa8Rdpr7LSv1VkT2cFQHL79rd
        .bob = MockAccount.init(.{
            .public_key = .{ .bytes = .{ 239, 10, 4, 236, 219, 237, 69, 197, 199, 60, 117, 184, 223, 215, 132, 73, 93, 248, 200, 254, 212, 239, 251, 120, 223, 25, 201, 196, 20, 58, 163, 62 } },
            .secret_key = .{ .bytes = .{ 208, 26, 255, 64, 164, 52, 99, 120, 92, 227, 25, 240, 222, 245, 70, 77, 171, 89, 129, 64, 110, 73, 159, 230, 38, 212, 150, 202, 57, 157, 151, 175, 239, 10, 4, 236, 219, 237, 69, 197, 199, 60, 117, 184, 223, 215, 132, 73, 93, 248, 200, 254, 212, 239, 251, 120, 223, 25, 201, 196, 20, 58, 163, 62 } },
        }),
        // ErnDW7vq2XmzstretUJ7NhT95PV6zeXeyXwLssowF6i
        .alice = MockAccount.init(.{
            .public_key = .{ .bytes = .{ 3, 140, 214, 34, 176, 145, 149, 13, 169, 145, 117, 3, 98, 140, 206, 183, 20, 52, 35, 97, 89, 82, 55, 162, 13, 26, 172, 9, 77, 242, 217, 211 } },
            .secret_key = .{ .bytes = .{ 28, 57, 92, 177, 192, 198, 0, 137, 66, 122, 128, 0, 112, 193, 184, 209, 72, 187, 109, 65, 115, 173, 181, 139, 194, 185, 253, 182, 173, 110, 184, 124, 3, 140, 214, 34, 176, 145, 149, 13, 169, 145, 117, 3, 98, 140, 206, 183, 20, 52, 35, 97, 89, 82, 55, 162, 13, 26, 172, 9, 77, 242, 217, 211 } },
        }),
    };
};

pub const MockTransferLogger = sig.trace.Logger("mock_transfer");

pub fn runMockTransfers(
    gpa: std.mem.Allocator,
    sender: *Channel(TransactionInfo),
    account_store: AccountStore,
    status_cache: *sig.core.StatusCache,
    slot_tracker: *sig.replay.trackers.SlotTracker,
    exit_condition: sig.sync.ExitCondition,
    logger: MockTransferLogger,
) !void {
    errdefer |err| {
        std.debug.print("(MTS) Mock transfer failed: {any}\n", .{err});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    var accounts = MockAccounts.DEFAULT;

    if (try account_store.reader().getLatest(gpa, accounts.alice.pubkey)) |account| {
        accounts.alice.balance = account.lamports;
        account.deinit(gpa);
    }
    if (try account_store.reader().getLatest(gpa, accounts.bob.pubkey)) |account| {
        accounts.bob.balance = account.lamports;
        account.deinit(gpa);
    }
    std.debug.print("(MTS) Initial balances - Alice: {}, Bob: {}\n", .{
        accounts.alice.balance,
        accounts.bob.balance,
    });

    var from_account, var to_account = if (accounts.alice.balance > accounts.bob.balance)
        .{ &accounts.alice, &accounts.bob }
    else
        .{ &accounts.bob, &accounts.alice };

    while (!exit_condition.shouldExit()) {
        if (from_account.balance < TRANSFER_COST and to_account.balance < TRANSFER_COST) {
            return error.InsufficientBalance;
        } else if (from_account.balance < TRANSFER_COST) {
            const tmp = from_account;
            from_account = to_account;
            to_account = tmp;
        }
        std.debug.print("(MTS) Initiating transfer of {} lamports from {f} to {f}\n", .{
            TRANSFER_AMOUNT,
            from_account.pubkey,
            to_account.pubkey,
        });

        // const sig_blockhash = sigBlockhash(
        //     slot_tracker,
        // ) catch |err| {
        //     std.debug.print("(MTS) Failed to load meta for transfer: {any}\n", .{err});
        //     std.Thread.sleep(100_000_000);
        //     continue;
        // };
        const rpc_blockhash = rpcBlockhash(gpa) catch |err| {
            std.debug.print("(MTS) Failed to fetch blockhash from RPC for transfer: {any}\n", .{err});
            std.Thread.sleep(100_000_000);
            continue;
        };

        const txn_info = try sendTransfer(
            gpa,
            rpc_blockhash,
            from_account,
            to_account,
            sender,
        );
        std.debug.print("(MTS) \tSent transfer: signature={f} transaction={any}\n", .{
            txn_info.signature,
            txn_info.wire_transaction[0..txn_info.wire_transaction_size],
        });

        const result = waitForTransfer(
            gpa,
            txn_info,
            slot_tracker,
            status_cache,
            exit_condition,
            logger,
        );
        std.debug.print("(MTS) \tTransfer result: {any}\n", .{result});

        switch (result) {
            .succeeded => {
                const last_processed_slot = slot_tracker.commitments.confirmed.load(.monotonic);
                const slot_ref = slot_tracker.get(last_processed_slot) orelse return error.LastConfirmedSlotNotAvailable;
                defer slot_ref.release();

                const slot_account_store = account_store.forSlot(
                    last_processed_slot,
                    &slot_ref.constants().ancestors,
                );

                if (try slot_account_store.reader().get(gpa, from_account.pubkey)) |account| {
                    defer account.deinit(gpa);
                    std.debug.print("(MTS) From account balance change: before={} after={} delta={}\n", .{
                        from_account.balance,
                        account.lamports,
                        account.lamports - from_account.balance,
                    });
                    from_account.balance = account.lamports;
                } else {
                    std.debug.print("(MTS) Failed to get from account balance after transfer\n", .{});
                    return error.FromAccountNotAvailable;
                }

                if (try slot_account_store.reader().get(gpa, to_account.pubkey)) |account| {
                    defer account.deinit(gpa);
                    std.debug.print("(MTS) To account balance change: before={} after={} delta={}\n", .{
                        to_account.balance,
                        account.lamports,
                        account.lamports - to_account.balance,
                    });
                    to_account.balance = account.lamports;
                } else {
                    std.debug.print("(MTS) Failed to get to account balance after transfer\n", .{});
                    return error.ToAccountNotAvailable;
                }
            },
            .failed => return error.TransferFailed,
            .unprocessed => continue,
        }
    }
}

fn sigBlockhash(slot_tracker: *sig.replay.trackers.SlotTracker) !Hash {
    const slot = slot_tracker.commitments.confirmed.load(.monotonic);

    const slot_ref = slot_tracker.get(slot) orelse return error.LastConfirmedSlotNotAvailable;
    defer slot_ref.release();

    const bh_queue, var bh_queue_lg = slot_ref.state().blockhash_queue.readWithLock();
    defer bh_queue_lg.unlock();
    return bh_queue.last_hash orelse return error.BlockhashQueueEmpty;
}

fn sigSignarureState(
    slot_tracker: *sig.replay.trackers.SlotTracker,
    status_cache: *sig.core.StatusCache,
    txn_info: *const TransactionInfo,
) ?sig.core.status_cache.StatusCache.StatusSummary {
    const slot = slot_tracker.commitments.confirmed.load(.monotonic);
    const slot_ref = slot_tracker.get(slot) orelse return null;
    defer slot_ref.release();

    return status_cache.getStatusSummary(
        &txn_info.message_hash.data,
        &txn_info.recent_blockhash,
        &slot_ref.constants().ancestors,
    );
}

fn rpcBlockhash(allocator: std.mem.Allocator) !Hash {
    var arena = std.heap.ArenaAllocator.init(allocator);
    var rpc_client = try sig.rpc.Client.init(
        arena.allocator(),
        "https://api.testnet.solana.com",
        .{ .max_retries = 2, .logger = .noop },
    );
    defer rpc_client.deinit();

    var response = try rpc_client.getLatestBlockhash(
        .{ .config = .{ .commitment = .processed } },
    );
    defer response.deinit();
    const result = try response.result();
    return try Hash.parseRuntime(result.value.blockhash);
}

fn rpcSignatureState(allocator: std.mem.Allocator, signature: Signature) !sig.core.status_cache.StatusCache.StatusSummary {
    var arena = std.heap.ArenaAllocator.init(allocator);
    var rpc_client = try sig.rpc.Client.init(
        arena.allocator(),
        "https://api.testnet.solana.com",
        .{ .max_retries = 2, .logger = .noop },
    );
    defer rpc_client.deinit();

    var response = try rpc_client.getSignatureStatuses(.{
        .signatures = &.{signature},
        .config = .{ .searchTransactionHistory = true },
    });
    defer response.deinit();
    const result = try response.result();
    if (result.value.len == 0) return .unprocessed;

    const maybe_status = result.value[0] orelse return .unprocessed;
    if (maybe_status.err != null) return .failed;
    return .succeeded;
}

fn sendTransfer(
    gpa: std.mem.Allocator,
    recent_blockhash: Hash,
    from_account: *MockAccount,
    to_account: *MockAccount,
    sender: *Channel(TransactionInfo),
) !TransactionInfo {
    errdefer |err| {
        std.debug.print("(MTS) Transfer failed: {any}\n", .{err});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    const transaction = try buildTransferTansaction(
        gpa,
        from_account.keypair,
        to_account.pubkey,
        TRANSFER_AMOUNT,
        recent_blockhash,
    );

    const msg_bytes = try transaction.msg.serializeBounded(transaction.version);
    const message_hash = sig.core.Hash.init(msg_bytes.constSlice());

    const transaction_info = try TransactionInfo.init(
        transaction,
        message_hash,
        std.math.maxInt(u64),
        null,
        null,
    );

    try sender.send(transaction_info);

    return transaction_info;
}

fn waitForTransfer(
    allocator: std.mem.Allocator,
    txn_info: TransactionInfo,
    slot_tracker: *sig.replay.trackers.SlotTracker,
    status_cache: *sig.core.StatusCache,
    exit_condition: sig.sync.ExitCondition,
    logger: MockTransferLogger,
) sig.core.status_cache.StatusCache.StatusSummary {
    _ = logger;

    errdefer |err| {
        std.debug.print("(MTS) Wait for transfer failed: {any}\n", .{err});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    const start_time = Instant.now();
    while (!exit_condition.shouldExit() and start_time.elapsed().lt(.fromSecs(30))) {
        const status = sigSignarureState(
            slot_tracker,
            status_cache,
            &txn_info,
        ) orelse rpcSignatureState(
            allocator,
            txn_info.signature,
        ) catch |err| blk: {
            std.debug.print("(MTS) Failed to get signature status from RPC for transfer: {any}\n", .{err});
            break :blk .unprocessed;
        };

        switch (status) {
            .failed => {
                std.debug.print("(MTS) Transaction failed: signature={f}\n", .{txn_info.signature});
                return .failed;
            },
            .succeeded => {
                std.debug.print("(MTS) Transaction processed: signature={f}\n", .{txn_info.signature});
                return .succeeded;
            },
            .unprocessed => std.Thread.sleep(100_000_000),
        }
    }

    return .unprocessed;
}

fn buildTransferTansaction(
    gpa: std.mem.Allocator,
    from_keypair: KeyPair,
    to_pubkey: Pubkey,
    lamports: u64,
    recent_blockhash: Hash,
) !sig.core.Transaction {
    const from_pubkey = Pubkey.fromPublicKey(&from_keypair.public_key);

    const account_keys = try gpa.dupe(Pubkey, &.{
        from_pubkey,
        to_pubkey,
        sig.runtime.program.system.ID,
    });
    errdefer gpa.free(account_keys);

    const account_indexes = try gpa.dupe(u8, &.{ 0, 1 });
    errdefer gpa.free(account_indexes);

    var transfer_data = [_]u8{0} ** 12;
    var fbs = std.io.fixedBufferStream(&transfer_data);
    const writer = fbs.writer();
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, lamports, .little);

    const instruction_data = try gpa.dupe(u8, &transfer_data);
    errdefer gpa.free(instruction_data);

    const instructions = try gpa.alloc(sig.core.transaction.Instruction, 1);
    errdefer gpa.free(instructions);
    instructions[0] = .{
        .program_index = 2,
        .account_indexes = account_indexes,
        .data = instruction_data,
    };

    const msg: sig.core.transaction.Message = .{
        .signature_count = 1,
        .readonly_signed_count = 0,
        .readonly_unsigned_count = 1,
        .account_keys = account_keys,
        .recent_blockhash = recent_blockhash,
        .instructions = instructions,
    };

    return try sig.core.Transaction.initOwnedMessageWithSigningKeypairs(
        gpa,
        .legacy,
        msg,
        &.{from_keypair},
    );
}
