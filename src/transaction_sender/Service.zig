const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const QuicClient = sig.net.QuicClient;

const AccountStore = sig.accounts_db.AccountStore;

const EpochTracker = sig.core.EpochTracker;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const StatusCache = sig.core.StatusCache;
const Transaction = sig.core.Transaction;
const LeaderSchedulesWithEpochInfos = sig.core.epoch_tracker.LeaderSchedulesWithEpochInfos;

const GossipTable = sig.gossip.GossipTable;

const Packet = sig.net.Packet;
const SocketAddr = sig.net.SocketAddr;

const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const GetMetricError = sig.prometheus.GetMetricError;

const SlotTracker = sig.replay.trackers.SlotTracker;

const Channel = sig.sync.Channel;
const ExitCondition = sig.sync.ExitCondition;
const RwMux = sig.sync.RwMux;

const Instant = sig.time.Instant;
const Duration = sig.time.Duration;

const PubkeyMap = sig.utils.collections.PubkeyMap;

const NUM_CONSECUTIVE_LEADER_SLOTS = sig.core.leader_schedule.NUM_CONSECUTIVE_LEADER_SLOTS;

pub const Logger = sig.trace.Logger("TransactionSenderService");
pub const Service = @This();

exit: ExitCondition,
logger: Logger,
metrics: Metrics,

cfg: Config,
ctx: Context,

receiver: *Channel(TransactionInfo),

pub const Config = struct {
    process_interval: Duration = .fromSecs(1),
    retry_interval: Duration = .fromSecs(5),
    max_pooled: usize = 1_000,
    max_retries: usize = 3,
    max_leaders: usize = 3,
    tpu_cache_size: usize = LeaderInfo.TPU_CACHE_SIZE,
    log_metrics_interval: ?u64 = null,
};

pub const Context = struct {
    account_store: AccountStore,
    epoch_tracker: *EpochTracker,
    slot_tracker: *SlotTracker,
    status_cache: *StatusCache,
    gossip_table_rw: *RwMux(GossipTable),
};

pub fn deinit(self: *Service) void {
    self.receiver.destroy();
}

pub fn init(
    allocator: Allocator,
    exit: ExitCondition,
    logger: Logger,
    cfg: Config,
    ctx: Context,
) !Service {
    const receiver = try Channel(TransactionInfo).create(allocator);
    receiver.name = "TransactionSenderService: TransactionInfo Receiver";
    errdefer receiver.destroy();

    return .{
        .exit = exit,
        .logger = logger,
        .metrics = try Metrics.init(),
        .cfg = cfg,
        .ctx = ctx,
        .receiver = receiver,
    };
}

pub fn run(self: *Service, allocator: Allocator) !void {
    errdefer |err| {
        self.logger.err().logf("TransactionSenderService Error: {s}", .{@errorName(err)});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
        self.exit.setExit();
    }

    const quic_client = try QuicClient.create(allocator, .from(self.logger), self.exit, .{});
    defer quic_client.destroy();

    const quic_handle = try std.Thread.spawn(.{}, QuicClient.run, .{quic_client});
    defer quic_handle.join();

    try self.handleTransactions(allocator, quic_client.receiver);
}

fn handleTransactions(self: *Service, allocator: Allocator, quic_sender: *Channel(Packet)) !void {
    var txn_pool = std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo).empty;
    defer txn_pool.deinit(allocator);
    try txn_pool.ensureTotalCapacity(allocator, self.cfg.max_pooled);

    var drop_list = std.ArrayList(Signature).empty;
    defer drop_list.deinit(allocator);
    try drop_list.ensureTotalCapacity(allocator, self.cfg.max_pooled);

    var leader_info = try LeaderInfo.init(
        allocator,
        self.logger,
        self.ctx.epoch_tracker,
        self.ctx.gossip_table_rw,
        self.cfg.tpu_cache_size,
    );
    defer leader_info.deinit(allocator);

    const leader_addresses = try allocator.alloc(?SocketAddr, self.cfg.max_leaders);
    defer allocator.free(leader_addresses);

    var metrics_last_logged = Instant.EPOCH_ZERO;
    while (!self.exit.shouldExit()) {
        defer if (self.cfg.log_metrics_interval) |interval| {
            if (metrics_last_logged.elapsed().gt(.fromSecs(interval))) {
                metrics_last_logged = Instant.now();
                self.metrics.log(self.logger);
            }
        };

        self.receiveTransactions(&txn_pool, self.cfg.process_interval);

        if (self.exit.shouldExit()) break;

        self.processTransactions(
            allocator,
            quic_sender,
            &txn_pool,
            &drop_list,
            &leader_info,
            leader_addresses,
        ) catch |err| switch (err) {
            error.RootSlotNotAvailable, error.WorkingSlotNotAvailable => {
                self.logger.warn().logf(
                    "Root or working slot not available, retrying: err={any}",
                    .{err},
                );
                std.Thread.sleep(std.time.ns_per_s);
            },
            else => return err,
        };
    }
}

/// Receive transactions from the receiver channel into the transaction pool for `timeout` duration.
/// If the transaction pool is empty, it will wait until a transaction is received before starting the `timeout` countdown.
/// If the transaction pool is or becomes full, it will wait the remaining `timeout` duration before returning.
fn receiveTransactions(
    self: *Service,
    txn_pool: *std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo),
    timeout: Duration,
) void {
    var timer = Instant.now();
    defer {
        self.metrics.receive_transactions_millis.set(timer.elapsed().asMillis());
        self.metrics.pool_size.set(txn_pool.count());
    }

    while (self.exit.shouldRun() and timer.elapsed().lt(timeout)) {
        // Don't break to process transactions until the pool is populated.
        defer if (txn_pool.count() == 0) {
            timer = Instant.now();
        };

        // Don't break to process transactions until the timeout has elapsed.
        if (txn_pool.count() == txn_pool.capacity()) {
            std.Thread.sleep(timeout.saturatingSub(timer.elapsed()).asNanos());
            break;
        }

        // Wait up to 10ms for a new transaction before checking the exit condition.
        self.receiver.event.timedWait(10 * std.time.ns_per_ms) catch continue;
        if (self.receiver.tryReceive()) |txn_info| {
            if (!txn_pool.contains(txn_info.signature)) {
                self.metrics.received_count.inc();
                txn_pool.putAssumeCapacity(
                    txn_info.signature,
                    txn_info,
                );
            }
        }
    }
}

/// Check the status of transactions in the pool.
/// Resend transactions which are eligible for retry.
/// Drop transactions which are failed, expired, or rooted.
fn processTransactions(
    self: *Service,
    allocator: Allocator,
    sender: *Channel(Packet),
    txn_pool: *std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo),
    drop_list: *std.ArrayList(Signature),
    leader_info: *LeaderInfo,
    leader_addresses: []?SocketAddr,
) !void {
    const timer = Instant.now();
    defer {
        self.metrics.process_transactions_millis.set(timer.elapsed().asMillis());
        self.metrics.pool_size.set(txn_pool.count());
    }

    const root_slot = self.ctx.slot_tracker.root.load(.monotonic);
    const root_ref = self.ctx.slot_tracker.get(root_slot) orelse
        return error.RootSlotNotAvailable;
    defer root_ref.release();

    const working_slot = self.ctx.slot_tracker.commitments.processed.load(.monotonic);
    const working_ref = self.ctx.slot_tracker.get(working_slot) orelse
        return error.WorkingSlotNotAvailable;
    defer working_ref.release();

    const account_reader = self.ctx.account_store.forSlot(
        working_slot,
        &working_ref.constants().ancestors,
    ).reader();

    try leader_info.fillLeaderAddresses(working_slot, leader_addresses);

    for (txn_pool.keys(), txn_pool.values()) |signature, *txn_info| {
        switch (self.ctx.status_cache.getStatus(
            &txn_info.message_hash.data,
            &txn_info.recent_blockhash,
            &root_ref.constants().ancestors,
        )) {
            // Check for drop or retry
            .pending => {},
            // Drop after rooted
            .failed, .succeeded => {
                self.metrics.rooted_count.inc();
                drop_list.appendAssumeCapacity(signature);
                continue;
            },
        }

        switch (self.ctx.status_cache.getStatus(
            &txn_info.message_hash.data,
            &txn_info.recent_blockhash,
            &working_ref.constants().ancestors,
        )) {
            // Check for drop or retry
            .pending => {},
            // Drop immediately
            .failed => {
                self.metrics.failed_count.inc();
                drop_list.appendAssumeCapacity(signature);
                continue;
            },
            // Drop after rooted
            .succeeded => continue,
        }

        // Drop the transaction if:
        // - It has reached max retry attempts
        // - It is expired based on block height
        // - It is a durable nonce transaction which is not inflight and has an invalid nonce
        const drop_txn =
            txn_info.retries >= @min(txn_info.max_retries, self.cfg.max_retries) or
            txn_info.last_valid_block_height < root_ref.constants().block_height or
            if (txn_info.durable_nonce_info) |nonce| drop_nonce: {
                const inflight = if (txn_info.last_sent_time) |last_sent_time|
                    last_sent_time.elapsed().lte(self.cfg.retry_interval)
                else
                    false;

                break :drop_nonce !inflight and invalid_nonce: {
                    const account = try account_reader.get(allocator, nonce[0]) orelse
                        break :invalid_nonce true;
                    defer account.deinit(allocator);

                    break :invalid_nonce sig.runtime.check_transactions.verifyNonceAccount(
                        account,
                        &nonce[1],
                    ) == null;
                };
            } else false;

        if (drop_txn) {
            self.metrics.expired_count.inc();
            drop_list.appendAssumeCapacity(signature);
            continue;
        }

        if (txn_info.last_sent_time) |last_sent_time| {
            if (last_sent_time.elapsed().lt(self.cfg.retry_interval)) continue;
        }

        var packet = Packet.init(
            undefined,
            txn_info.wire_transaction,
            txn_info.wire_transaction_size,
        );

        for (leader_addresses) |maybe_leader_address| {
            const leader_address = maybe_leader_address orelse continue;
            packet.addr = leader_address;
            try sender.send(packet);
        }

        if (txn_info.last_sent_time) |_| txn_info.retries += 1;
        txn_info.last_sent_time = Instant.now();
    }

    for (drop_list.items) |signature| _ = txn_pool.swapRemove(signature);
    drop_list.clearRetainingCapacity();
}

pub const TransactionInfo = struct {
    signature: Signature,
    message_hash: Hash,
    recent_blockhash: Hash,
    wire_transaction: [Packet.DATA_SIZE]u8,
    wire_transaction_size: usize,
    last_valid_block_height: u64,
    durable_nonce_info: ?struct { Pubkey, Hash },
    retries: usize,
    max_retries: usize,
    last_sent_time: ?Instant,

    pub fn init(
        transaction: Transaction,
        message_hash: Hash,
        last_valid_block_height: u64,
        durable_nonce_info: ?struct { Pubkey, Hash },
        max_retries: ?usize,
    ) !TransactionInfo {
        var wire_transaction: [Packet.DATA_SIZE]u8 = @splat(0);
        const wire_transaction_size = (try sig.bincode.writeToSlice(
            &wire_transaction,
            transaction,
            .{},
        )).len;
        return initWithWire(
            transaction,
            wire_transaction,
            wire_transaction_size,
            message_hash,
            last_valid_block_height,
            durable_nonce_info,
            max_retries,
        );
    }

    pub fn initWithWire(
        transaction: Transaction,
        wire_transaction: [Packet.DATA_SIZE]u8,
        wire_transaction_size: usize,
        message_hash: Hash,
        last_valid_block_height: u64,
        durable_nonce_info: ?struct { Pubkey, Hash },
        max_retries: ?usize,
    ) TransactionInfo {
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

const LeaderInfo = struct {
    tpu_cache: PubkeyMap(CachedAddress),
    leader_schedules: LeaderSchedulesWithEpochInfos,
    gossip_table_rw: *RwMux(GossipTable),
    epoch_tracker: *EpochTracker,
    logger: Logger,

    const TPU_CACHE_SIZE = 2048;
    const TPU_REFRESH_INTERVAL = Duration.fromSecs(60);

    const CachedAddress = struct {
        time: Instant,
        addr: ?SocketAddr,
    };

    pub fn deinit(self: *LeaderInfo, allocator: Allocator) void {
        self.tpu_cache.deinit(allocator);
        self.leader_schedules.release();
    }

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        epoch_tracker: *EpochTracker,
        gossip_table_rw: *RwMux(GossipTable),
        tpu_cache_size: u64,
    ) !LeaderInfo {
        const leader_schedules = try epoch_tracker.getLeaderSchedules();
        errdefer leader_schedules.release();

        var tpu_cache = PubkeyMap(CachedAddress).empty;
        errdefer tpu_cache.deinit(allocator);
        try tpu_cache.ensureTotalCapacity(allocator, tpu_cache_size);

        return .{
            .tpu_cache = tpu_cache,
            .leader_schedules = leader_schedules,
            .gossip_table_rw = gossip_table_rw,
            .epoch_tracker = epoch_tracker,
            .logger = logger,
        };
    }

    pub fn fillLeaderAddresses(self: *LeaderInfo, slot: Slot, buf: []?SocketAddr) !void {
        for (buf, 0..) |*leader_address, i| {
            const leader_slot = slot + i * NUM_CONSECUTIVE_LEADER_SLOTS;
            leader_address.* = try self.getLeaderAddress(leader_slot);
        }
    }

    fn getLeaderAddress(self: *LeaderInfo, slot: u64) !?SocketAddr {
        const leader_pubkey = self.leader_schedules.leader_schedules.getLeader(slot) catch blk: {
            const old_leader_schedules = self.leader_schedules;
            defer old_leader_schedules.release();
            self.leader_schedules = try self.epoch_tracker.getLeaderSchedules();
            break :blk self.leader_schedules.leader_schedules.getLeader(slot) catch
                return error.NoLeaderForSlot;
        };
        errdefer comptime unreachable;

        if (self.tpu_cache.count() >= self.tpu_cache.capacity() -| 1) {
            self.logger.info().log("tpu cache is full, pruning old entries.");
            var threshold = TPU_REFRESH_INTERVAL;
            var pruned_count: usize = 0;
            while (pruned_count == 0) : (threshold = .fromSecs(threshold.asSecs() / 2)) {
                const current_count = self.tpu_cache.count();
                var i: usize = 0;
                while (i < self.tpu_cache.count()) {
                    const item = self.tpu_cache.values()[i];
                    if (item.time.elapsed().lt(threshold))
                        i += 1
                    else
                        self.tpu_cache.swapRemoveAt(i);
                }
                pruned_count += current_count - self.tpu_cache.count();
            }
            self.logger.info().logf("pruned {d} entries from tpu cache.", .{
                pruned_count,
            });
        }

        const entry = self.tpu_cache.getOrPutAssumeCapacity(leader_pubkey);
        if (entry.found_existing and entry.value_ptr.*.time.elapsed().lt(TPU_REFRESH_INTERVAL)) {
            return entry.value_ptr.*.addr;
        }

        if (!entry.found_existing) entry.key_ptr.* = leader_pubkey;

        const gossip_table: *const GossipTable, var gossip_table_lg =
            self.gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        const maybe_contact_info = gossip_table.getThreadSafeContactInfo(leader_pubkey);
        const tpu_quic_addr = if (maybe_contact_info) |contact_info|
            contact_info.tpu_quic_addr
        else
            null;

        entry.value_ptr.* = .{
            .time = Instant.now(),
            .addr = tpu_quic_addr,
        };

        return tpu_quic_addr;
    }
};

pub const Metrics = struct {
    pool_size: *Gauge(u64),

    received_count: *Counter,
    rooted_count: *Counter,
    failed_count: *Counter,
    expired_count: *Counter,

    receive_transactions_millis: *Gauge(u64),
    process_transactions_millis: *Gauge(u64),

    pub const prefix = "TransactionSenderService";

    pub fn init() GetMetricError!Metrics {
        return sig.prometheus.globalRegistry().initStruct(Metrics);
    }

    pub fn log(self: *const Metrics, logger: Logger) void {
        // zig fmt: off
        logger.info().logf("pool_size={}, received={}, rooted={}, failed={}, expired={}, receive_ms={}, process_ms={}", .{
            self.pool_size.get(),
            self.received_count.get(),
            self.rooted_count.get(),
            self.failed_count.get(),
            self.expired_count.get(),
            self.receive_transactions_millis.get(),
            self.process_transactions_millis.get(),
        });
        // zig fmt: on
    }
};

const TestContext = struct {
    exit_flag: std.atomic.Value(bool),
    db_ctx: sig.accounts_db.Db.TestContext,
    epoch_tracker: EpochTracker,
    slot_tracker: SlotTracker,
    status_cache: StatusCache,
    gossip_table_rw: RwMux(GossipTable),
    quic_sender: *Channel(Packet),

    fn deinit(self: *TestContext, allocator: Allocator) void {
        self.db_ctx.deinit();
        self.epoch_tracker.deinit();
        self.slot_tracker.deinit(allocator);
        self.status_cache.deinit(allocator);
        const table, var table_lg = self.gossip_table_rw.writeWithLock();
        table.deinit();
        table_lg.unlock();
        self.quic_sender.destroy();
    }

    fn init(allocator: Allocator, random: std.Random, root_slot: Slot) !TestContext {
        const exit_flag = std.atomic.Value(bool).init(false);

        var db_ctx = try sig.accounts_db.Db.initTest(allocator);
        errdefer db_ctx.deinit();

        var epoch_tracker = try EpochTracker.initForTest(allocator, random, root_slot, .INIT);
        errdefer epoch_tracker.deinit();

        var slot_tracker = try SlotTracker.initEmpty(allocator, root_slot);
        errdefer slot_tracker.deinit(allocator);

        var status_cache = StatusCache.DEFAULT;
        errdefer status_cache.deinit(allocator);

        var gossip_table_rw = RwMux(GossipTable).init(try GossipTable.init(allocator, allocator));
        errdefer {
            const table, var table_lg = gossip_table_rw.writeWithLock();
            table.deinit();
            table_lg.unlock();
        }

        const quic_sender = try Channel(Packet).create(allocator);
        errdefer quic_sender.destroy();

        return .{
            .exit_flag = exit_flag,
            .db_ctx = db_ctx,
            .epoch_tracker = epoch_tracker,
            .slot_tracker = slot_tracker,
            .status_cache = status_cache,
            .gossip_table_rw = gossip_table_rw,
            .quic_sender = quic_sender,
        };
    }
};

test "TransactionInfo.initWithWire:sets fields correctly" {
    const tx = sig.core.transaction.transaction_legacy_example.as_struct;
    var wire: [Packet.DATA_SIZE]u8 = @splat(0);
    @memcpy(
        wire[0..sig.core.transaction.transaction_legacy_example.as_bytes.len],
        &sig.core.transaction.transaction_legacy_example.as_bytes,
    );
    const msg_hash = Hash.ZEROES;

    const info = TransactionInfo.initWithWire(
        tx,
        wire,
        sig.core.transaction.transaction_legacy_example.as_bytes.len,
        msg_hash,
        1000,
        null,
        null,
    );

    try std.testing.expectEqualSlices(u8, &tx.signatures[0].toBytes(), &info.signature.toBytes());
    try std.testing.expectEqual(msg_hash, info.message_hash);
    try std.testing.expectEqual(tx.msg.recent_blockhash, info.recent_blockhash);
    try std.testing.expectEqual(@as(u64, 1000), info.last_valid_block_height);
    try std.testing.expectEqual(@as(?struct { Pubkey, Hash }, null), info.durable_nonce_info);
    try std.testing.expectEqual(@as(usize, 0), info.retries);
    try std.testing.expectEqual(std.math.maxInt(usize), info.max_retries);
    try std.testing.expectEqual(@as(?sig.time.Instant, null), info.last_sent_time);
}

test "TransactionInfo.initWithWire:with max_retries" {
    const tx = sig.core.transaction.transaction_legacy_example.as_struct;
    const wire: [Packet.DATA_SIZE]u8 = @splat(0);

    const info = TransactionInfo.initWithWire(tx, wire, 0, Hash.ZEROES, 500, null, 10);

    try std.testing.expectEqual(@as(usize, 10), info.max_retries);
}

test "TransactionInfo.initWithWire:with durable nonce info" {
    const tx = sig.core.transaction.transaction_legacy_example.as_struct;
    const wire: [Packet.DATA_SIZE]u8 = @splat(0);
    const nonce_pubkey = Pubkey.ZEROES;
    const nonce_hash = Hash.ZEROES;

    const info = TransactionInfo.initWithWire(
        tx,
        wire,
        0,
        Hash.ZEROES,
        500,
        .{ nonce_pubkey, nonce_hash },
        null,
    );

    try std.testing.expect(info.durable_nonce_info != null);
    const nonce_info = info.durable_nonce_info.?;
    try std.testing.expectEqual(nonce_pubkey, nonce_info[0]);
    try std.testing.expectEqual(nonce_hash, nonce_info[1]);
}
test "handleTransactions" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const root_slot: u64 = 5e6;
    const working_slot: u64 = root_slot + 10;

    var test_ctx = try TestContext.init(allocator, random, root_slot);
    defer test_ctx.deinit(allocator);

    {
        var root_ancestors = sig.core.Ancestors.EMPTY;
        errdefer root_ancestors.deinit(allocator);
        for (root_slot - 10..root_slot + 1) |slot| try root_ancestors.addSlot(allocator, slot);

        var root_constants = try sig.core.bank.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer root_constants.deinit(allocator);
        root_constants.ancestors.deinit(allocator);
        root_constants.ancestors = root_ancestors;

        try test_ctx.slot_tracker.put(allocator, root_slot, .{
            .allocator = allocator,
            .constants = root_constants,
            .state = .GENESIS,
        });
    }
    test_ctx.slot_tracker.root.store(root_slot, .monotonic);

    {
        var working_ancestors = sig.core.Ancestors.EMPTY;
        errdefer working_ancestors.deinit(allocator);
        for (root_slot..working_slot + 1) |slot| try working_ancestors.addSlot(allocator, slot);

        var working_constants = try sig.core.bank.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer working_constants.deinit(allocator);
        working_constants.ancestors.deinit(allocator);
        working_constants.ancestors = working_ancestors;

        try test_ctx.slot_tracker.put(allocator, working_slot, .{
            .allocator = allocator,
            .constants = working_constants,
            .state = .GENESIS,
        });
    }
    test_ctx.slot_tracker.commitments.processed.store(working_slot, .monotonic);

    var service = try Service.init(
        allocator,
        .{ .unordered = &test_ctx.exit_flag },
        .noop,
        .{
            .process_interval = .fromMillis(10),
            .retry_interval = .fromNanos(0),
            .max_pooled = 2,
            .max_retries = 2,
            .max_leaders = 5,
        },
        .{
            .account_store = .{ .accounts_db = &test_ctx.db_ctx.db },
            .epoch_tracker = &test_ctx.epoch_tracker,
            .slot_tracker = &test_ctx.slot_tracker,
            .status_cache = &test_ctx.status_cache,
            .gossip_table_rw = &test_ctx.gossip_table_rw,
        },
    );
    defer service.deinit();

    const handle_transactions_handle = try std.Thread.spawn(
        .{},
        Service.handleTransactions,
        .{ &service, allocator, test_ctx.quic_sender },
    );
    defer handle_transactions_handle.join();
    defer test_ctx.exit_flag.store(true, .monotonic);

    var count: usize = 0;
    for (0..10) |i| {
        count += 1;
        const txn = try Transaction.initRandom(allocator, random, null);
        defer txn.deinit(allocator);
        const txn_info = try TransactionInfo.init(
            txn,
            Hash.initRandom(random),
            root_slot - 1 + i,
            null,
            null,
        );

        // Add a transaction which hits the root status cache check
        if (i == 7) {
            try test_ctx.status_cache.insert(
                allocator,
                random,
                &txn_info.recent_blockhash,
                &txn_info.message_hash.data,
                root_slot - 1,
                null,
            );
        }

        // Add a transaction which hits the working status cache check
        // This will remain in the pool until its is rooted, or dropped after a a fork switch
        if (i == 8) {
            try test_ctx.status_cache.insert(
                allocator,
                random,
                &txn_info.recent_blockhash,
                &txn_info.message_hash.data,
                working_slot - 1,
                null,
            );
        }

        // Add a transaction which hits the working status cache check but is failed
        // This will remain in the pool until its is rooted, or dropped after a a fork switch
        if (i == 9) {
            try test_ctx.status_cache.insert(
                allocator,
                random,
                &txn_info.recent_blockhash,
                &txn_info.message_hash.data,
                working_slot - 1,
                .AccountInUse,
            );
        }

        try service.receiver.send(txn_info);
    }

    const start = Instant.now();
    while (start.elapsed().lt(.fromSecs(10))) {
        if (service.metrics.pool_size.get() == 1 and
            service.metrics.received_count.get() == 10 and
            service.metrics.rooted_count.get() == 1 and
            service.metrics.failed_count.get() == 1 and
            service.metrics.expired_count.get() == 7) break;
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }

    try std.testing.expectEqual(1, service.metrics.pool_size.get());
    try std.testing.expectEqual(10, service.metrics.received_count.get());
    try std.testing.expectEqual(1, service.metrics.rooted_count.get());
    try std.testing.expectEqual(1, service.metrics.failed_count.get());
    try std.testing.expectEqual(7, service.metrics.expired_count.get());
}

test "fillLeaderAddresses" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const root_slot: u64 = 5e6;
    var test_ctx = try TestContext.init(allocator, random, root_slot);
    defer test_ctx.deinit(allocator);

    const leader_addresses_null = [_]?SocketAddr{null} ** 5;
    var leader_addresses = [_]?SocketAddr{null} ** 5;
    var leader_info = try LeaderInfo.init(
        allocator,
        .noop,
        &test_ctx.epoch_tracker,
        &test_ctx.gossip_table_rw,
        5,
    );
    defer leader_info.deinit(allocator);

    try std.testing.expectError(
        error.NoLeaderForSlot,
        leader_info.fillLeaderAddresses(0, &leader_addresses),
    );
    try std.testing.expectError(
        error.NoLeaderForSlot,
        leader_info.fillLeaderAddresses(
            root_slot + 2 * test_ctx.epoch_tracker.epoch_schedule.slots_per_epoch,
            &leader_addresses,
        ),
    );

    // Fill leader addresses repeatedly to force pruning of the cache.
    for (0..10) |i| {
        try leader_info.fillLeaderAddresses(
            root_slot + i * leader_addresses.len,
            &leader_addresses,
        );
    }
    try std.testing.expectEqualSlices(
        ?SocketAddr,
        &leader_addresses_null,
        &leader_addresses,
    );

    // Insert contact info for the first 5 leaders into the gossip table.
    // Check that the correct addresses are filled into the leader_addresses array.
    var tpu_addresses = [_]?SocketAddr{null} ** 5;
    for (0..leader_addresses.len) |i| {
        const leader_slot = root_slot + i * NUM_CONSECUTIVE_LEADER_SLOTS;
        const leader_schedules = &leader_info.leader_schedules.leader_schedules;
        const leader_pubkey = try leader_schedules.getLeader(leader_slot);

        var contact_info = sig.gossip.ContactInfo.init(allocator, leader_pubkey, 0, 0);
        try contact_info.setSocket(.tpu_quic, SocketAddr.initRandom(random));
        tpu_addresses[i] = contact_info.getSocket(.tpu_quic);

        const gossip_table: *GossipTable, var gossip_table_lg =
            leader_info.gossip_table_rw.writeWithLock();
        defer gossip_table_lg.unlock();
        _ = try gossip_table.insert(.{
            .signature = .ZEROES,
            .data = .{ .ContactInfo = contact_info },
        }, 0);
    }

    try leader_info.fillLeaderAddresses(
        root_slot,
        &leader_addresses,
    );
    try std.testing.expectEqualSlices(
        ?SocketAddr,
        &tpu_addresses,
        &leader_addresses,
    );

    // Fill leader addresses repeatedly to force pruning of the cache.
    for (0..10) |i| {
        try leader_info.fillLeaderAddresses(
            root_slot + i * leader_addresses.len,
            &leader_addresses,
        );
    }
    try std.testing.expectEqualSlices(
        ?SocketAddr,
        &leader_addresses_null,
        &leader_addresses,
    );
}
