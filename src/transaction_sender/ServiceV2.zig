const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const AccountStore = sig.accounts_db.AccountStore;
const SlotAccountStore = sig.accounts_db.SlotAccountStore;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const Ancestors = sig.core.Ancestors;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const StatusCache = sig.core.StatusCache;
const Status = sig.core.status_cache.Status;

const Packet = sig.net.Packet;

const EpochTracker = sig.core.EpochTracker;
const SlotTracker = sig.replay.trackers.SlotTracker;

const Channel = sig.sync.Channel;
const ExitCondition = sig.sync.ExitCondition;
const RwMux = sig.sync.RwMux;

const Instant = sig.time.Instant;
const Duration = sig.time.Duration;

const PubkeyMap = sig.utils.collections.PubkeyMap;

const NUM_CONSECUTIVE_LEADER_SLOTS = sig.core.leader_schedule.NUM_CONSECUTIVE_LEADER_SLOTS;

pub const Logger = sig.trace.Logger("TransactionSender");
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

fn handleTransactions(
    self: *Service,
    gpa: Allocator,
    quic_sender: *Channel(Packet),
) !void {
    errdefer |err| {
        self.logger.info().logf("handleTransactions: error={any}\n", .{err});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    // const metrics = try Metrics.init();

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
        self.receiveTransactions(&txn_pool);

        const process_ctx = loadProcessContext(
            self.ctx.account_store,
            self.ctx.slot_tracker,
        ) catch |err| {
            self.logger.warn().logf("Failed to load context: err={any}", .{err});
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };
        defer process_ctx.release();

        try leader_info.fillLeaderAddresses(process_ctx.working_slot, leader_addresses);

        try processTransactions(
            gpa,
            quic_sender,
            &txn_pool,
            &drop_list,
            self.cfg.retry_interval,
            self.cfg.max_retries,
            self.ctx.status_cache,
            process_ctx.root_ancestors,
            process_ctx.root_block_height,
            process_ctx.working_ancestors,
            process_ctx.account_reader,
            leader_addresses,
        );
    }
}

fn receiveTransactions(
    self: *Service,
    txn_pool: *std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo),
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
            if (!txn_pool.contains(txn_info.signature)) txn_pool.putAssumeCapacity(
                txn_info.signature,
                txn_info,
            );
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

fn loadProcessContext(
    account_store: AccountStore,
    slot_tracker: *SlotTracker,
) !ProcessContext {
    const root_slot = slot_tracker.root.load(.monotonic);
    const root_ref = slot_tracker.get(root_slot) orelse return error.RootSlotNotAvailable;
    errdefer root_ref.release();

    const working_slot = slot_tracker.commitments.processed.load(.monotonic);
    const working_ref = slot_tracker.get(working_slot) orelse return error.WorkingSlotNotAvailable;
    errdefer working_ref.release();

    return .{
        .root_slot = root_slot,
        .root_ref = root_ref,
        .root_ancestors = &root_ref.constants().ancestors,
        .root_block_height = root_ref.constants().block_height,
        .working_slot = working_slot,
        .working_ref = working_ref,
        .working_ancestors = &working_ref.constants().ancestors,
        .account_reader = account_store.forSlot(
            working_slot,
            &working_ref.constants().ancestors,
        ).reader(),
    };
}

fn processTransactions(
    gpa: Allocator,
    sender: *Channel(Packet),
    txn_pool: *std.AutoArrayHashMapUnmanaged(Signature, TransactionInfo),
    drop_list: *std.ArrayList(Signature),
    retry_interval: Duration,
    max_retries: usize,
    status_cache: *StatusCache,
    root_ancestors: *const Ancestors,
    root_block_height: u64,
    working_ancestors: *const Ancestors,
    working_account_reader: sig.accounts_db.SlotAccountReader,
    leader_addresses: []const ?sig.net.SocketAddr,
) !void {
    for (txn_pool.keys(), txn_pool.values()) |signature, *txn_info| {
        switch (status_cache.getStatus(
            &txn_info.message_hash.data,
            &txn_info.recent_blockhash,
            root_ancestors,
        )) {
            // Check for drop or retry
            .pending => {},
            // Drop after rooted
            .failed, .succeeded => {
                drop_list.appendAssumeCapacity(signature);
                continue;
            },
        }

        switch (status_cache.getStatus(
            &txn_info.message_hash.data,
            &txn_info.recent_blockhash,
            working_ancestors,
        )) {
            // Check for drop or retry
            .pending => {},
            // Drop immediately
            .failed => {
                drop_list.appendAssumeCapacity(signature);
                continue;
            },
            // Drop after rooted
            .succeeded => continue,
        }

        if (txn_info.retries >= @min(txn_info.max_retries, max_retries)) {
            drop_list.appendAssumeCapacity(signature);
            continue;
        }

        if (txn_info.last_valid_block_height < root_block_height) {
            drop_list.appendAssumeCapacity(signature);
            continue;
        }

        if (txn_info.durable_nonce_info) |nonce| {
            const inflight = if (txn_info.last_sent_time) |last_sent_time|
                last_sent_time.elapsed().lte(retry_interval)
            else
                false;

            const valid = blk: {
                const account = try working_account_reader.get(
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
                drop_list.appendAssumeCapacity(signature);
                continue;
            }
        }

        if (txn_info.last_sent_time) |last_sent_time| {
            if (last_sent_time.elapsed().lt(retry_interval)) continue;
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
            self.logger.info().logf("Leader address cache is full, pruning old entries. Count: {}, Capacity: {}", .{
                self.leader_addresses.count(),
                self.leader_addresses.capacity(),
            });
            var threshold = START_PRUNE_THRESHOLD;
            while (self.leader_addresses.count() >=
                self.leader_addresses.capacity() - 1) : (threshold = .fromSecs(threshold.asSecs() / 2))
            {
                const current_count = self.leader_addresses.count();
                var i: usize = 0;
                while (i < self.leader_addresses.count()) {
                    const item = self.leader_addresses.values()[i];
                    if (item.time.elapsed().lt(threshold))
                        i += 1
                    else
                        self.leader_addresses.swapRemoveAt(i);
                }
                const pruned_count = current_count - self.leader_addresses.count();
                self.logger.info().logf("Pruned {d} entries from leader address cache with threshold {d} seconds.", .{
                    pruned_count,
                    threshold.asSecs(),
                });
            }
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

// fn logCliSubmitCommand(txn_info: *const TransactionInfo) void {
//     const wire_txn = txn_info.wire_transaction[0..txn_info.wire_transaction_size];

//     var encoded_buf: [std.base64.standard.Encoder.calcSize(sig.net.Packet.DATA_SIZE)]u8 = undefined;
//     const encoded_len = std.base64.standard.Encoder.calcSize(wire_txn.len);
//     const encoded_wire_txn = std.base64.standard.Encoder.encode(encoded_buf[0..encoded_len], wire_txn);

//     std.debug.print("(TSS) Transaction wire payload (base64): {s}\n", .{encoded_wire_txn});
//     std.debug.print(
//         "(TSS) JSON-RPC submit: curl https://api.testnet.solana.com -H 'Content-Type: application/json' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendTransaction\",\"params\":[\"{s}\",{{\"encoding\":\"base64\"}}]}}'\n",
//         .{encoded_wire_txn},
//     );
// }

// pub const mock = struct {
//     const Commitment = sig.rpc.methods.common.Commitment;

//     const MockLogger = sig.trace.Logger("mock_transfer");

//     pub const TRANSFER_AMOUNT: u64 = 1e6;
//     pub const TRANSFER_FEE: u64 = 5000;
//     pub const TRANSFER_COST: u64 = TRANSFER_AMOUNT + TRANSFER_FEE;

//     pub const Mode = union(enum) {
//         rpc: RpcMode,
//         sig: SigMode,

//         pub fn getAccountBalance(
//             self: *Mode,
//             gpa: Allocator,
//             pubkey: Pubkey,
//             commitment: Commitment,
//         ) !u64 {
//             return switch (self.*) {
//                 .rpc => try self.rpc.getAccountBalance(pubkey, commitment),
//                 .sig => try self.sig.getAccountBalance(gpa, pubkey, commitment),
//             };
//         }

//         pub fn getLatestBlockhash(self: *Mode, commitment: Commitment) !Hash {
//             return switch (self.*) {
//                 .rpc => try self.rpc.getLatestBlockhash(commitment),
//                 .sig => try self.sig.getLatestBlockhash(commitment),
//             };
//         }

//         pub fn getTransactionStatus(self: *Mode, txn_info: *const TransactionInfo) !Status {
//             return switch (self.*) {
//                 .rpc => try self.rpc.getSignatureStatus(txn_info.signature),
//                 .sig => try self.sig.getTransactionStatus(txn_info),
//             };
//         }
//     };

//     pub const RpcMode = struct {
//         client: sig.rpc.Client,

//         pub fn getAccountBalance(self: *RpcMode, pubkey: Pubkey, commitment: Commitment) !u64 {
//             var response = try self.client.getBalance(
//                 .{ .pubkey = pubkey, .config = .{ .commitment = commitment } },
//             );
//             defer response.deinit();
//             const result = try response.result();
//             return result.value;
//         }

//         pub fn getLatestBlockhash(self: *RpcMode, commitment: Commitment) !Hash {
//             var response = try self.client.getLatestBlockhash(
//                 .{ .config = .{ .commitment = commitment } },
//             );
//             defer response.deinit();
//             const result = try response.result();
//             return try Hash.parseRuntime(result.value.blockhash);
//         }

//         pub fn getSignatureStatus(self: *RpcMode, signature: Signature) !Status {
//             var response = try self.client.getSignatureStatuses(.{
//                 .signatures = &.{signature},
//                 .config = .{ .searchTransactionHistory = true },
//             });
//             defer response.deinit();
//             const result = try response.result();
//             if (result.value.len == 0) return .pending;

//             const maybe_status = result.value[0] orelse return .pending;
//             if (maybe_status.err != null) return .failed;
//             return .succeeded;
//         }
//     };

//     pub const SigMode = struct {
//         account_store: AccountStore,
//         slot_tracker: *sig.replay.trackers.SlotTracker,
//         status_cache: *sig.core.StatusCache,

//         pub fn getAccountBalance(self: *SigMode, gpa: Allocator, pubkey: Pubkey, commitment: Commitment) !u64 {
//             const slot = switch (commitment) {
//                 .processed => self.slot_tracker.commitments.processed.load(.monotonic),
//                 .confirmed => self.slot_tracker.commitments.confirmed.load(.monotonic),
//                 .finalized => self.slot_tracker.commitments.finalized.load(.monotonic),
//             };

//             const slot_ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
//             defer slot_ref.release();

//             const account = try self.account_store.forSlot(
//                 slot,
//                 &slot_ref.constants().ancestors,
//             ).reader().get(gpa, pubkey) orelse return 0;
//             defer account.deinit(gpa);

//             return account.lamports;
//         }

//         pub fn getLatestBlockhash(self: *SigMode, commitment: Commitment) !Hash {
//             const slot = switch (commitment) {
//                 .processed => self.slot_tracker.commitments.processed.load(.monotonic),
//                 .confirmed => self.slot_tracker.commitments.confirmed.load(.monotonic),
//                 .finalized => self.slot_tracker.commitments.finalized.load(.monotonic),
//             };

//             const slot_ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
//             defer slot_ref.release();

//             const bh_queue, var bh_queue_lg = slot_ref.state().blockhash_queue.readWithLock();
//             defer bh_queue_lg.unlock();

//             return bh_queue.last_hash orelse return error.BlockhashQueueEmpty;
//         }

//         pub fn getTransactionStatus(self: *SigMode, txn_info: *const TransactionInfo) !Status {
//             const slot = self.slot_tracker.commitments.confirmed.load(.monotonic);

//             const slot_ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
//             defer slot_ref.release();

//             return self.status_cache.getStatus(
//                 &txn_info.message_hash.data,
//                 &txn_info.recent_blockhash,
//                 &slot_ref.constants().ancestors,
//             );
//         }
//     };

//     pub const MockAccount = struct {
//         name: []const u8,
//         keypair: KeyPair,
//         pubkey: Pubkey,
//         lamports: u64,

//         // Pubkey: H67JSziFxAZR1KSQshWfa8Rdpr7LSv1VkT2cFQHL79rd
//         pub const ALICE: MockAccount = .init("alice", .{
//             .public_key = .{ .bytes = .{ 3, 140, 214, 34, 176, 145, 149, 13, 169, 145, 117, 3, 98, 140, 206, 183, 20, 52, 35, 97, 89, 82, 55, 162, 13, 26, 172, 9, 77, 242, 217, 211 } },
//             .secret_key = .{ .bytes = .{ 28, 57, 92, 177, 192, 198, 0, 137, 66, 122, 128, 0, 112, 193, 184, 209, 72, 187, 109, 65, 115, 173, 181, 139, 194, 185, 253, 182, 173, 110, 184, 124, 3, 140, 214, 34, 176, 145, 149, 13, 169, 145, 117, 3, 98, 140, 206, 183, 20, 52, 35, 97, 89, 82, 55, 162, 13, 26, 172, 9, 77, 242, 217, 211 } },
//         });

//         // Pubkey: ErnDW7vq2XmzstretUJ7NhT95PV6zeXeyXwLssowF6i
//         pub const BOB: MockAccount = .init("bob", .{
//             .public_key = .{ .bytes = .{ 239, 10, 4, 236, 219, 237, 69, 197, 199, 60, 117, 184, 223, 215, 132, 73, 93, 248, 200, 254, 212, 239, 251, 120, 223, 25, 201, 196, 20, 58, 163, 62 } },
//             .secret_key = .{ .bytes = .{ 208, 26, 255, 64, 164, 52, 99, 120, 92, 227, 25, 240, 222, 245, 70, 77, 171, 89, 129, 64, 110, 73, 159, 230, 38, 212, 150, 202, 57, 157, 151, 175, 239, 10, 4, 236, 219, 237, 69, 197, 199, 60, 117, 184, 223, 215, 132, 73, 93, 248, 200, 254, 212, 239, 251, 120, 223, 25, 201, 196, 20, 58, 163, 62 } },
//         });

//         fn init(name: []const u8, keypair: KeyPair) MockAccount {
//             return .{
//                 .name = name,
//                 .keypair = keypair,
//                 .pubkey = Pubkey.fromPublicKey(&keypair.public_key),
//                 .lamports = 0,
//             };
//         }

//         pub fn format(self: MockAccount, writer: *std.Io.Writer) std.Io.Writer.Error!void {
//             try writer.print("(name={s}, lamports={d}, pubkey={f})", .{ self.name, self.lamports, self.pubkey });
//         }
//     };

//     pub fn run(
//         gpa: Allocator,
//         num_transfers: usize,
//         mode: Mode,
//         sender: *Channel(TransactionInfo),
//         logger: MockLogger,
//         exit: ExitCondition,
//     ) !void {
//         var alice = MockAccount.ALICE;
//         var bob = MockAccount.BOB;

//         logger.info().log("Initializing accounts for mock transfer");
//         var from_account, var to_account = try initAccounts(
//             gpa,
//             &mode,
//             &alice,
//             &bob,
//             logger,
//             exit,
//         );

//         logger.info().logf("Starting mock transfers: {f} -> {f}", .{ from_account, to_account });
//         var num_successful: usize = 0;
//         while (!exit.shouldExit() and num_successful < num_transfers) {
//             if (from_account.lamports < TRANSFER_COST and to_account.lamports < TRANSFER_COST) {
//                 logger.info().logf("Insufficient lamports: {f} -> {f}", .{ from_account, to_account });
//                 return error.InsufficientBalance;
//             } else if (from_account.lamports < TRANSFER_COST) {
//                 logger.info().logf("Switching mock transfers: {f} -> {f}", .{ from_account, to_account });
//                 const tmp = from_account;
//                 from_account = to_account;
//                 to_account = tmp;
//             }

//             logger.info().logf("Attempting transfer {}/{}", .{ num_successful + 1, num_transfers });
//             const txn_info = try buildTransfer(gpa, &mode, from_account, to_account);

//             logger.info().logf("Sending transfer {}/{}: signature={f}", .{txn_info.signature});
//             try sender.send(txn_info);

//             switch (waitForTransfer(
//                 gpa,
//                 &mode,
//                 txn_info,
//                 .fromSecs(60),
//                 logger,
//                 exit,
//             )) {
//                 .succeeded => {
//                     from_account.lamports = try mode.getAccountBalance(
//                         gpa,
//                         from_account.pubkey,
//                         .finalized,
//                     );
//                     to_account.lamports = try mode.getAccountBalance(
//                         gpa,
//                         to_account.pubkey,
//                         .finalized,
//                     );
//                     logger.info().logf("Transfer success {}/{}: signature={f}", .{
//                         num_successful + 1,
//                         num_transfers,
//                         txn_info.signature,
//                     });
//                     num_successful += 1;
//                     continue;
//                 },
//                 .failed => {
//                     logger.info().logf("Transfer failure {}/{}: signature={f}", .{
//                         num_successful + 1,
//                         num_transfers,
//                         txn_info.signature,
//                     });
//                     return error.TransferFailed;
//                 },
//                 .unprocessed => {
//                     logger.info().logf("Transfer timeout {}/{}: signature={f}", .{
//                         num_successful + 1,
//                         num_transfers,
//                         txn_info.signature,
//                     });
//                     continue;
//                 },
//             }
//         }
//     }

//     pub fn initAccounts(
//         gpa: Allocator,
//         mode: *Mode,
//         account_0: *MockAccount,
//         account_1: *MockAccount,
//         logger: MockLogger,
//         exit: ExitCondition,
//     ) !struct { *MockAccount, *MockAccount } {
//         while (exit.shouldRun()) {
//             inline for (&.{ account_0, account_1 }) |account| {
//                 account.lamports = mode.getAccountBalance(
//                     gpa,
//                     account.pubkey,
//                     .finalized,
//                 ) catch |err| switch (err) {
//                     error.SlotNotAvailable => break,
//                     else => return err,
//                 };
//             } else break;
//             logger.info().log("Finalized slot not available, waiting to catch up...");
//             std.Thread.sleep(10 * std.time.ns_per_s);
//         }
//         return if (account_0.lamports > account_1.lamports)
//             .{ account_0, account_1 }
//         else
//             .{ account_1, account_0 };
//     }

//     pub fn buildTransfer(
//         gpa: std.mem.Allocator,
//         mode: *Mode,
//         from_account: *MockAccount,
//         to_account: *MockAccount,
//     ) !TransactionInfo {
//         const blockhash = try mode.getLatestBlockhash(.confirmed);

//         const transaction = try buildTransferTansaction(
//             gpa,
//             from_account.keypair,
//             to_account.pubkey,
//             TRANSFER_AMOUNT,
//             blockhash,
//         );

//         const msg_bytes = try transaction.msg.serializeBounded(transaction.version);
//         const message_hash = sig.core.Hash.init(msg_bytes.constSlice());

//         return try TransactionInfo.init(
//             transaction,
//             message_hash,
//             std.math.maxInt(u64),
//             null,
//             null,
//         );
//     }

//     fn waitForTransfer(
//         mode: *Mode,
//         txn_info: *const TransactionInfo,
//         timeout: Duration,
//         logger: MockLogger,
//         exit: ExitCondition,
//     ) Status {
//         const start_time = Instant.now();

//         while (exit.shouldRun() and start_time.elapsed().lt(timeout)) {
//             const status = mode.getTransactionStatus(txn_info) catch |err| {
//                 logger.info().logf("Failed to get transaction status: {any}", .{err});
//                 std.Thread.sleep(1 * std.time.ns_per_s);
//                 continue;
//             };

//             switch (status) {
//                 .failed, .succeeded => return status,
//                 .unprocessed => std.Thread.sleep(1 * std.time.ns_per_s),
//             }
//         }

//         return .unprocessed;
//     }

//     pub fn buildTransferTansaction(
//         gpa: std.mem.Allocator,
//         from_keypair: KeyPair,
//         to_pubkey: Pubkey,
//         lamports: u64,
//         recent_blockhash: Hash,
//     ) !sig.core.Transaction {
//         const from_pubkey = Pubkey.fromPublicKey(&from_keypair.public_key);

//         const account_keys = try gpa.dupe(Pubkey, &.{
//             from_pubkey,
//             to_pubkey,
//             sig.runtime.program.system.ID,
//         });
//         errdefer gpa.free(account_keys);

//         const account_indexes = try gpa.dupe(u8, &.{ 0, 1 });
//         errdefer gpa.free(account_indexes);

//         var transfer_data = [_]u8{0} ** 12;
//         var fbs = std.io.fixedBufferStream(&transfer_data);
//         const writer = fbs.writer();
//         try writer.writeInt(u32, 2, .little);
//         try writer.writeInt(u64, lamports, .little);

//         const instruction_data = try gpa.dupe(u8, &transfer_data);
//         errdefer gpa.free(instruction_data);

//         const instructions = try gpa.alloc(sig.core.transaction.Instruction, 1);
//         errdefer gpa.free(instructions);
//         instructions[0] = .{
//             .program_index = 2,
//             .account_indexes = account_indexes,
//             .data = instruction_data,
//         };

//         const msg: sig.core.transaction.Message = .{
//             .signature_count = 1,
//             .readonly_signed_count = 0,
//             .readonly_unsigned_count = 1,
//             .account_keys = account_keys,
//             .recent_blockhash = recent_blockhash,
//             .instructions = instructions,
//         };

//         return try sig.core.Transaction.initOwnedMessageWithSigningKeypairs(
//             gpa,
//             .legacy,
//             msg,
//             &.{from_keypair},
//         );
//     }
// };
