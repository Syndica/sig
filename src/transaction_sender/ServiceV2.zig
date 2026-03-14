const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const AccountStore = sig.accounts_db.AccountStore;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const Ancestors = sig.core.Ancestors;
const EpochTracker = sig.core.EpochTracker;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const StatusCache = sig.core.StatusCache;
const Status = sig.core.status_cache.Status;

const Packet = sig.net.Packet;

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

cfg: Config,
ctx: Context,

receiver: *Channel(TransactionInfo),

pub const Context = struct {
    account_store: AccountStore,
    epoch_tracker: *EpochTracker,
    slot_tracker: *SlotTracker,
    status_cache: *StatusCache,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
};

pub fn deinit(self: *Service) void {
    self.receiver.destroy();
}

pub fn init(
    gpa: Allocator,
    exit: ExitCondition,
    logger: Logger,
    cfg: Config,
    ctx: Context,
) !Service {
    const receiver = try Channel(TransactionInfo).create(gpa);
    receiver.name = "TransactionSenderService: TransactionInfo Receiver";
    errdefer receiver.destroy();

    return .{
        .exit = exit,
        .logger = logger,
        .cfg = cfg,
        .ctx = ctx,
        .receiver = receiver,
    };
}

pub fn run(self: *Service, gpa: Allocator) !void {
    const quic_sender = try Channel(Packet).create(gpa);
    quic_sender.name = "TransactionSenderService: Packet Sender";
    errdefer quic_sender.destroy();

    const quic_handle = try std.Thread.spawn(
        .{},
        sig.net.quic_client.runClient,
        .{
            gpa,
            quic_sender,
            sig.net.quic_client.Logger.from(self.logger),
            self.exit,
        },
    );
    defer quic_handle.join();

    try self.handleTransactions(gpa, quic_sender);
}

fn handleTransactions(self: *Service, gpa: Allocator, quic_sender: *Channel(Packet)) !void {
    errdefer {
        self.logger.err().log("handle transactions error");
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    var metrics = try Metrics.init();

    var txn_pool = std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo).empty;
    defer txn_pool.deinit(gpa);
    try txn_pool.ensureTotalCapacity(gpa, self.cfg.max_pooled);

    var drop_list = std.ArrayList(Signature).empty;
    defer drop_list.deinit(gpa);
    try drop_list.ensureTotalCapacity(gpa, self.cfg.max_pooled);

    var leader_info = try LeaderInfo.init(
        gpa,
        self.ctx.epoch_tracker,
        self.ctx.gossip_table_rw,
        self.cfg.max_leaders,
        self.logger,
    );
    defer leader_info.deinit(gpa);

    const leader_addresses = try gpa.alloc(?sig.net.SocketAddr, self.cfg.max_leaders);
    defer gpa.free(leader_addresses);

    while (!self.exit.shouldExit()) {
        const start_receive = Instant.now();
        self.receiveTransactions(&txn_pool, &metrics);
        metrics.retry_transactions_millis.set(start_receive.elapsed().asMillis());

        const start_process = Instant.now();
        self.processTransactions(
            gpa,
            quic_sender,
            &txn_pool,
            &drop_list,
            &leader_info,
            leader_addresses,
            &metrics,
        ) catch |err| switch (err) {
            error.RootSlotNotAvailable, error.WorkingSlotNotAvailable => {
                self.logger.warn().logf("Root or working slot not available, retrying: err={any}", .{err});
                std.Thread.sleep(5 * std.time.ns_per_s);
            },
            else => return err,
        };
        metrics.process_transactions_millis.set(start_process.elapsed().asMillis());
    }
}

fn receiveTransactions(
    self: *Service,
    txn_pool: *std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo),
    metrics: *Metrics,
) void {
    var timer = Instant.now();
    while (self.exit.shouldRun() and
        timer.elapsed().lt(self.cfg.process_interval) and
        txn_pool.count() < txn_pool.capacity())
    {
        defer if (txn_pool.count() == 0) {
            timer = Instant.now();
        };
        self.receiver.event.timedWait(10 * std.time.ns_per_ms) catch continue;
        if (self.receiver.tryReceive()) |txn_info| {
            if (!txn_pool.contains(txn_info.signature)) {
                metrics.received_count.inc();
                txn_pool.putAssumeCapacity(
                    txn_info.signature,
                    txn_info,
                );
            }
        }
    }
}

const ProcessContext = struct {
    root_slot: u64,
    root_ref: SlotTracker.Reference,
    root_ancestors: *const Ancestors,
    root_block_height: u64,
    working_slot: u64,
    working_ref: SlotTracker.Reference,
    working_ancestors: *const Ancestors,
    account_reader: SlotAccountReader,

    pub fn release(self: *const ProcessContext) void {
        self.root_ref.release();
        self.working_ref.release();
    }
};

fn processTransactions(
    self: *Service,
    gpa: Allocator,
    sender: *Channel(Packet),
    txn_pool: *std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo),
    drop_list: *std.ArrayList(Signature),
    leader_info: *LeaderInfo,
    leader_addresses: []?sig.net.SocketAddr,
    metrics: *Metrics,
) !void {
    const root_slot = self.ctx.slot_tracker.root.load(.monotonic);
    const root_ref = self.ctx.slot_tracker.get(root_slot) orelse
        return error.RootSlotNotAvailable;
    errdefer root_ref.release();

    const working_slot = self.ctx.slot_tracker.commitments.processed.load(.monotonic);
    const working_ref = self.ctx.slot_tracker.get(working_slot) orelse
        return error.WorkingSlotNotAvailable;
    errdefer working_ref.release();

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
                metrics.rooted_count.inc();
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
                metrics.failed_count.inc();
                drop_list.appendAssumeCapacity(signature);
                continue;
            },
            // Drop after rooted
            .succeeded => continue,
        }

        if (txn_info.retries >= @min(txn_info.max_retries, self.cfg.max_retries)) {
            metrics.expired_count.inc();
            drop_list.appendAssumeCapacity(signature);
            continue;
        }

        if (txn_info.last_valid_block_height < root_ref.constants().block_height) {
            metrics.expired_count.inc();
            drop_list.appendAssumeCapacity(signature);
            continue;
        }

        if (txn_info.durable_nonce_info) |nonce| {
            const inflight = if (txn_info.last_sent_time) |last_sent_time|
                last_sent_time.elapsed().lte(self.cfg.retry_interval)
            else
                false;

            const valid = blk: {
                const account = try account_reader.get(
                    gpa,
                    nonce[0],
                ) orelse break :blk false;
                defer account.deinit(gpa);

                break :blk sig.runtime.check_transactions.verifyNonceAccount(
                    account,
                    &nonce[1],
                ) != null;
            };

            if (!inflight and !valid) {
                metrics.expired_count.inc();
                drop_list.appendAssumeCapacity(signature);
                continue;
            }
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

pub const Config = struct {
    process_interval: sig.time.Duration,
    retry_interval: sig.time.Duration,
    max_pooled: usize,
    max_retries: usize,
    max_leaders: usize,
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

const LeaderInfo = struct {
    leader_addresses: sig.utils.collections.PubkeyMap(CachedAddress),
    leader_schedules: sig.core.epoch_tracker.LeaderSchedulesWithEpochInfos,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    epoch_tracker: *EpochTracker,
    logger: Logger,

    const MAX_LEADER_ADDRESSES = 2048;
    const START_PRUNE_THRESHOLD = sig.time.Duration.fromSecs(1_100_000);
    const GOSSIP_REFRESH_INTERVAL = sig.time.Duration.fromSecs(60);

    const CachedAddress = struct {
        time: Instant,
        addr: ?sig.net.SocketAddr,
    };

    pub fn deinit(self: *LeaderInfo, gpa: Allocator) void {
        self.leader_addresses.deinit(gpa);
        self.leader_schedules.release();
    }

    pub fn init(
        gpa: Allocator,
        epoch_tracker: *EpochTracker,
        gossip_table_rw: *RwMux(sig.gossip.GossipTable),
        max_leader_addresses: ?usize,
        logger: Logger,
    ) !LeaderInfo {
        const leader_schedules = try epoch_tracker.getLeaderSchedules();
        errdefer leader_schedules.release();

        var leader_addresses = PubkeyMap(CachedAddress).empty;
        errdefer leader_addresses.deinit(gpa);
        try leader_addresses.ensureTotalCapacity(
            gpa,
            max_leader_addresses orelse MAX_LEADER_ADDRESSES,
        );

        return .{
            .leader_addresses = leader_addresses,
            .leader_schedules = leader_schedules,
            .gossip_table_rw = gossip_table_rw,
            .epoch_tracker = epoch_tracker,
            .logger = logger,
        };
    }

    pub fn fillLeaderAddresses(self: *LeaderInfo, slot: Slot, buf: []?sig.net.SocketAddr) !void {
        for (buf, 0..) |*leader_address, i| {
            const leader_slot = slot + i * NUM_CONSECUTIVE_LEADER_SLOTS;
            leader_address.* = try self.getLeaderAddress(leader_slot);
        }
    }

    fn getLeaderAddress(self: *LeaderInfo, slot: u64) !?sig.net.SocketAddr {
        var leader_schedules = &self.leader_schedules.leader_schedules;
        const leader_pubkey = leader_schedules.getLeader(slot) catch blk: {
            self.leader_schedules.release();
            self.leader_schedules = try self.epoch_tracker.getLeaderSchedules();
            leader_schedules = &self.leader_schedules.leader_schedules;
            break :blk leader_schedules.getLeader(slot) catch return error.NoLeaderForSlot;
        };

        if (self.leader_addresses.count() >= self.leader_addresses.capacity() - 1) {
            self.logger.info().logf(
                "Leader address cache is full ({}/{}), pruning old entries.",
                .{
                    self.leader_addresses.count(),
                    self.leader_addresses.capacity(),
                },
            );
            var threshold = START_PRUNE_THRESHOLD;
            var pruned_count: usize = 0;
            while (pruned_count == 0) : (threshold = .fromSecs(threshold.asSecs() / 2)) {
                const current_count = self.leader_addresses.count();
                var i: usize = 0;
                while (i < self.leader_addresses.count()) {
                    const item = self.leader_addresses.values()[i];
                    if (item.time.elapsed().lt(threshold))
                        i += 1
                    else
                        self.leader_addresses.swapRemoveAt(i);
                }
                pruned_count += current_count - self.leader_addresses.count();
            }
            self.logger.info().logf("Pruned {d} entries from leader address cache.", .{
                pruned_count,
            });
        }

        const entry = self.leader_addresses.getOrPutAssumeCapacity(leader_pubkey);
        if (entry.found_existing and entry.value_ptr.*.time.elapsed().lt(GOSSIP_REFRESH_INTERVAL)) {
            return entry.value_ptr.*.addr;
        }

        if (!entry.found_existing) entry.key_ptr.* = leader_pubkey;

        const gossip_table: *const sig.gossip.GossipTable, var gossip_table_lg =
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
    failed_count: *Counter,
    rooted_count: *Counter,
    expired_count: *Counter,

    process_transactions_millis: *Gauge(u64),
    retry_transactions_millis: *Gauge(u64),
    get_leader_addresses_millis: *Gauge(u64),

    rpc_block_height_millis: *Gauge(u64),
    rpc_signature_statuses_millis: *Gauge(u64),

    pub const prefix = "TransactionSenderService";

    pub fn init() GetMetricError!Metrics {
        return sig.prometheus.globalRegistry().initStruct(Metrics);
    }
};
