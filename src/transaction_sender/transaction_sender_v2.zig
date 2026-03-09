const std = @import("std");
const sig = @import("../sig.zig");

const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

const Instant = sig.time.Instant;

const AccountStore = sig.accounts_db.AccountStore;

const Packet = sig.net.Packet;

const Channel = sig.sync.Channel;

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
    exit: *Atomic(bool),
    logger: Logger,
) !void {
    const exit_condition = sig.sync.ExitCondition{
        .unordered = exit,
    };

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
            exit_condition,
        },
    );
    defer quic_client_handle.join();

    try processTransactions(
        gpa,
        config,
        account_store,
        epoch_tracker,
        slot_tracker,
        status_cache,
        gossip_table_rw,
        receiver,
        quic_channel,
        exit_condition,
        logger,
    );
}

pub fn processTransactions(
    gpa: std.mem.Allocator,
    config: Config,
    account_store: AccountStore,
    epoch_tracker: *sig.core.EpochTracker,
    slot_tracker: *sig.replay.trackers.SlotTracker,
    status_cache: *sig.core.StatusCache,
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    receiver: *Channel(TransactionInfo),
    sender: *Channel(Packet),
    exit_condition: sig.sync.ExitCondition,
    logger: Logger,
) !void {
    errdefer |err| {
        logger.err().logf("Process transactions failed: {any}", .{err});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
        exit_condition.setExit();
    }

    var leader_info = try LeaderInfo.init(
        gpa,
        epoch_tracker,
        gossip_table_rw,
        config.max_leaders_to_send_to,
    );
    defer leader_info.deinit(gpa);

    // const metrics = try Metrics.init();

    var pool = std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo).empty;
    defer pool.deinit(gpa);
    try pool.ensureTotalCapacity(gpa, config.max_pool_size);

    var drop_signatures = std.ArrayList(Signature).empty;
    defer drop_signatures.deinit(gpa);
    try drop_signatures.ensureTotalCapacity(gpa, config.max_pool_size);

    var last_process_time = sig.time.Instant.now();

    while (!exit_condition.shouldExit()) {
        //
        // Receive transactions
        //

        // Receive transactions until batch is full or process interval has elapsed
        var txns_received: usize = 0;
        while (receiver.tryReceive()) |txn_info| {
            if (pool.contains(txn_info.signature)) continue;
            if (pool.count() < config.max_pool_size) {
                logger.info().logf("Received transaction: signature={f}", .{txn_info.signature});
                pool.putAssumeCapacity(txn_info.signature, txn_info);
            } else {
                logger.warn().logf("Transaction pool is full, dropping transaction with signature {f}", .{txn_info.signature});
            }
            txns_received += 1;
            if (txns_received >= config.max_batch_size) break;
        }

        // If no transactions were received, sleep until next process interval
        if (txns_received == 0 and last_process_time.elapsed().ns < config.process_interval.ns) {
            logger.info().log("No transactions received, sleeping until next process interval");
            std.Thread.sleep(config.process_interval.ns - last_process_time.elapsed().ns);
            continue;
        }

        //
        // Process transactions
        //

        // Get last processed slot reference
        // NOTE: Agave uses the working bank here, which is not the last processed slot.
        const working_slot = slot_tracker.latest_processed_slot.get();
        const working_slot_ref = slot_tracker.get(working_slot) orelse return error.LastProcessedSlotNotAvailable;
        defer working_slot_ref.release();
        const working_ancestors = &working_slot_ref.constants().ancestors;

        const root_slot_ref = slot_tracker.get(
            epoch_tracker.root_slot.load(.monotonic),
        ) orelse return error.RootSlotNotAvailable;
        defer root_slot_ref.release();
        const root_ancestors = &root_slot_ref.constants().ancestors;
        const root_block_height = root_slot_ref.constants().block_height;

        const slot_account_store = account_store.forSlot(working_slot, working_ancestors);
        const slot_account_reader = slot_account_store.reader();

        const leader_addresses = try leader_info.getLeaderAddresses(gpa, working_slot);

        for (pool.keys(), pool.values()) |signature, *txn_info| {
            logger.info().logf("Processing transaction: signature={f}", .{txn_info.signature});

            if (status_cache.getStatusSummary(
                &txn_info.message_hash.data,
                &txn_info.recent_blockhash,
                root_ancestors,
            ) != .unprocessed) {
                logger.info().logf("Transaction rooted: signature={f}", .{txn_info.signature});
                drop_signatures.appendAssumeCapacity(signature);
                continue;
            }

            const txn_status = status_cache.getStatusSummary(
                &txn_info.message_hash.data,
                &txn_info.recent_blockhash,
                working_ancestors,
            );

            if (txn_status == .failed) {
                logger.info().logf("Dropping failed transaction: signature={f}", .{txn_info.signature});
                drop_signatures.appendAssumeCapacity(signature);
                continue;
            }

            if (txn_info.last_valid_block_height < root_block_height) {
                logger.info().logf("Dropping expired transaction: signature={f}", .{txn_info.signature});
                drop_signatures.appendAssumeCapacity(signature);
                continue;
            }

            if (txn_info.retries >= @min(txn_info.max_retries, config.max_retries)) {
                logger.info().logf("Dropping transaction due to max retries: signature={f}", .{txn_info.signature});
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
                    logger.info().logf("Dropping transaction with expired durable nonce: signature={f}", .{txn_info.signature});
                    drop_signatures.appendAssumeCapacity(signature);
                    continue;
                }
            }

            const should_send = if (txn_info.last_sent_time) |last_sent_time|
                Instant.now().elapsedSince(last_sent_time).ns >= config.retry_rate.ns
            else
                true;

            if (should_send) {
                logger.info().logf("Sending transaction: signature={f}", .{txn_info.signature});
                var packet = Packet.init(
                    undefined,
                    txn_info.wire_transaction,
                    txn_info.wire_transaction_size,
                );

                for (leader_addresses) |maybe_leader_address| {
                    const leader_address = maybe_leader_address orelse continue;
                    logger.info().logf("Sending transaction to leader at {f}: signature={f}", .{ leader_address, txn_info.signature });
                    packet.addr = leader_address;
                    try sender.send(packet);
                }

                if (txn_info.last_sent_time) |_| txn_info.retries += 1;
                txn_info.last_sent_time = Instant.now();

                logger.info().logf("Transaction sent: signature={f}, retries={}", .{ txn_info.signature, txn_info.retries });
            }
        }

        for (drop_signatures.items) |signature| _ = pool.swapRemove(signature);
        drop_signatures.clearRetainingCapacity();

        last_process_time = Instant.now();
    }
}

pub const Config = struct {
    process_interval: sig.time.Duration,
    retry_rate: sig.time.Duration,
    max_pool_size: usize,
    max_batch_size: usize,
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

        const maybe_cached_address = self.leader_addresses.get(leader_pubkey) orelse blk: {
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
            if (Instant.now().elapsedSince(cached_address[1]).ns < REFRESH_LEADER_ADDRESS_INTERVAL.ns) {
                return cached_address[0];
            }
        }

        const gossip_table: *const sig.gossip.GossipTable, var gossip_table_lg =
            self.gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        if (gossip_table.getThreadSafeContactInfo(leader_pubkey)) |contact_info| {
            if (contact_info.tpu_quic_addr) |leader_address| {
                try self.leader_addresses.put(gpa, leader_pubkey, .{
                    leader_address,
                    Instant.now(),
                });
            } else try self.leader_addresses.put(gpa, leader_pubkey, null);
            return contact_info.tpu_quic_addr;
        } else {
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
//         logger.info().logf("", .{});
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
        std.debug.print("Mock transfer failed: {any}\n", .{err});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
        exit_condition.setExit();
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
    logger.info().logf("Initial balances - Alice: {}, Bob: {}", .{
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

        logger.info().logf("Initiating transfer of {} lamports from {f} to {f}", .{
            TRANSFER_AMOUNT,
            from_account.pubkey,
            to_account.pubkey,
        });

        const slot = slot_tracker.latest_confirmed_slot.get();
        const slot_ref = slot_tracker.get(slot) orelse return error.LastConfirmedSlotNotAvailable;
        defer slot_ref.release();

        const latest_blockhash, const last_valid_block_height = blk: {
            const bh_queue, var bh_queue_lg = slot_ref.state().blockhash_queue.readWithLock();
            defer bh_queue_lg.unlock();
            const blockhash = bh_queue.last_hash orelse return error.BlockhashQueueEmpty;
            const age = bh_queue.getHashAge(blockhash) orelse return error.BlockhashNotFound;
            break :blk .{ blockhash, slot_ref.constants().block_height + 150 - age };
        };

        logger.info().logf("\tSlot: {}, Latest Blockhash: {f}, Last Valid Block Height: {}", .{
            slot,
            latest_blockhash,
            last_valid_block_height,
        });

        const txn_info = try sendTransfer(
            gpa,
            latest_blockhash,
            last_valid_block_height,
            from_account,
            to_account,
            sender,
        );

        logger.info().logf("\tWaiting for transfer: signature={f} transaction={any}", .{
            txn_info.signature,
            txn_info.wire_transaction[0..txn_info.wire_transaction_size],
        });

        try waitForTransfer(
            txn_info,
            slot_tracker,
            status_cache,
            exit_condition,
            logger,
        );
    }
}

fn sendTransfer(
    gpa: std.mem.Allocator,
    last_blockhash: Hash,
    last_valid_block_height: u64,
    from_account: *MockAccount,
    to_account: *MockAccount,
    sender: *Channel(TransactionInfo),
) !TransactionInfo {
    errdefer |err| {
        std.debug.print("Transfer failed: {any}\n", .{err});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    var prng = std.Random.DefaultPrng.init(sig.time.Instant.now().uptime_ns);

    const transaction = try buildTransferTansaction(
        gpa,
        prng.random(),
        from_account.keypair,
        to_account.pubkey,
        TRANSFER_AMOUNT,
        last_blockhash,
    );

    const msg_bytes = try transaction.msg.serializeBounded(transaction.version);
    const message_hash = sig.core.Hash.init(msg_bytes.constSlice());

    const transaction_info = try TransactionInfo.init(
        transaction,
        message_hash,
        last_valid_block_height,
        null,
        null,
    );

    try sender.send(transaction_info);

    return transaction_info;
}

fn waitForTransfer(
    txn_info: TransactionInfo,
    slot_tracker: *sig.replay.trackers.SlotTracker,
    status_cache: *sig.core.StatusCache,
    exit_condition: sig.sync.ExitCondition,
    logger: MockTransferLogger,
) !void {
    errdefer |err| {
        std.debug.print("Wait for transfer failed: {any}\n", .{err});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    const start_time = Instant.now();
    while (!exit_condition.shouldExit() and start_time.elapsed().lt(.fromSecs(30))) {
        const slot = slot_tracker.latest_confirmed_slot.get();
        const slot_ref = slot_tracker.get(slot) orelse return error.LastConfirmedSlotNotAvailable;
        defer slot_ref.release();

        const status = status_cache.getStatusSummary(
            &txn_info.message_hash.data,
            &txn_info.recent_blockhash,
            &slot_ref.constants().ancestors,
        );

        logger.info().logf("Received status for slot: slot={} status={any} signature={f}", .{
            slot,
            status,
            txn_info.signature,
        });

        switch (status) {
            .failed => {
                logger.info().logf("Transaction failed: signature={f}", .{txn_info.signature});
                return;
            },
            .succeeded => {
                logger.info().logf("Transaction processed: signature={f}", .{txn_info.signature});
                return;
            },
            .unprocessed => std.Thread.sleep(100_000_000),
        }
    }
}

fn buildTransferTansaction(
    allocator: std.mem.Allocator,
    random: std.Random,
    from_keypair: KeyPair,
    to_pubkey: Pubkey,
    lamports: u64,
    recent_blockhash: Hash,
) !sig.core.Transaction {
    const from_pubkey = Pubkey.fromPublicKey(&from_keypair.public_key);

    const addresses = try allocator.dupe(Pubkey, &.{
        from_pubkey,
        to_pubkey,
        sig.runtime.program.system.ID,
    });
    errdefer allocator.free(addresses);

    const account_indexes = try allocator.dupe(u8, &.{ 0, 1 });
    errdefer allocator.free(account_indexes);

    var data = [_]u8{0} ** 12;
    var fbs = std.io.fixedBufferStream(&data);
    const writer = fbs.writer();
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, lamports, .little);

    const instructions = try allocator.alloc(sig.core.transaction.Instruction, 1);
    errdefer allocator.free(instructions);
    instructions[0] = .{
        .program_index = 2,
        .account_indexes = account_indexes,
        .data = try allocator.dupe(u8, &data),
    };

    const signature: Signature = blk: {
        const buffer = [_]u8{0} ** sig.core.Transaction.MAX_BYTES;
        const signable = &buffer;

        var noise: [KeyPair.seed_length]u8 = undefined;
        random.bytes(&noise);

        const signature = try from_keypair.sign(signable, noise);
        break :blk .fromSignature(signature);
    };

    const signatures = try allocator.dupe(Signature, &.{signature});
    errdefer allocator.free(signatures);

    return .{
        .signatures = signatures,
        .version = .legacy,
        .msg = .{
            .signature_count = @intCast(signatures.len),
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 1,
            .account_keys = addresses,
            .recent_blockhash = recent_blockhash,
            .instructions = instructions,
        },
    };
}
