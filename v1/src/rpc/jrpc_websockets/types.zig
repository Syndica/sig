const std = @import("std");
const sig = @import("../../sig.zig");
const xev = @import("xev");
const tracy = @import("tracy");
const NotifPayload = sig.sync.RcSlice(u8);
const methods = @import("methods.zig");
const ws_request = @import("ws_request.zig");

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;
const Account = sig.core.Account;
const TransactionError = sig.ledger.transaction_status.TransactionError;
const InnerInstructions = sig.ledger.transaction_status.InnerInstructions;
const TransactionTokenBalance = sig.ledger.transaction_status.TransactionTokenBalance;
const LoadedAddresses = sig.ledger.transaction_status.LoadedAddresses;
const TransactionReturnData = sig.ledger.transaction_status.TransactionReturnData;
const DistributedRewards = sig.replay.freeze.DistributedRewards;
const Hash = sig.core.Hash;

pub const AccountWithPubkey = struct {
    pubkey: Pubkey,
    account: Account,
};

pub const SlotReadContext = struct {
    slot_tracker: *sig.replay.trackers.SlotTracker,
    commitments: *sig.replay.trackers.CommitmentTracker,
    account_reader: sig.accounts_db.AccountReader,
    status_cache: *sig.core.StatusCache,
};

/// Subscription families used for subscription identity and fanout.
pub const SubscriptionKind = enum {
    account,
    block,
    logs,
    program,
    root,
    signature,
    slot,
    slots_updates,
    vote,
};

/// Canonicalized subscription request key: subscription kind + kind-specific parameters.
/// Determines which NotifQueue a subscription maps to. Two clients subscribing
/// with the same SubReqKey share one queue and SubId.
///
/// All params that affect message content or shape are identity-determining:
/// filters, encoding, commitment, and dataSlice all contribute to key equality.
pub const SubReqKey = struct {
    method: SubscriptionKind,
    params: Params,

    pub const Params = union(SubscriptionKind) {
        account: AccountParams,
        block: BlockParams,
        logs: LogsParams,
        program: ProgramParams,
        root: void,
        signature: SignatureParams,
        slot: void,
        slots_updates: void,
        vote: void,
    };

    pub const AccountParams = struct {
        pubkey: Pubkey,
        commitment: methods.Commitment = .finalized,
        encoding: methods.AccountEncoding = .binary,
        data_slice: ?methods.DataSlice = null,
    };

    pub const BlockParams = struct {
        filter: methods.BlockFilter = .all,
        commitment: methods.Commitment = .finalized,
        encoding: methods.TransactionEncoding = .json,
        transaction_details: methods.TransactionDetails = .full,
        max_supported_transaction_version: ?u64 = null,
        show_rewards: bool = true,
    };

    pub const LogsParams = struct {
        filter: methods.LogsFilter,
        commitment: methods.Commitment = .finalized,
    };

    pub const ProgramParams = struct {
        program_id: Pubkey,
        commitment: methods.Commitment = .finalized,
        encoding: methods.AccountEncoding = .binary,
        data_slice: ?methods.DataSlice = null,
        /// When heap-allocated, each filter (and memcmp bytes) is owned by the map's allocator.
        filters: ?[]const methods.ProgramSubscribe.Filter = null,
    };

    pub const SignatureParams = struct {
        sig_value: Signature,
        commitment: methods.Commitment = .finalized,
        enableReceivedNotification: bool = false,
    };

    pub fn eql(a: *const SubReqKey, b: *const SubReqKey) bool {
        if (a.method != b.method) {
            return false;
        }
        switch (a.params) {
            .account => |pa| {
                const pb = b.params.account;
                return std.mem.eql(u8, &pa.pubkey.data, &pb.pubkey.data) and
                    pa.commitment == pb.commitment and
                    pa.encoding == pb.encoding and
                    dataSliceEql(pa.data_slice, pb.data_slice);
            },
            .block => |pa| {
                const pb = b.params.block;
                return blockFilterEql(pa.filter, pb.filter) and
                    pa.commitment == pb.commitment and
                    pa.encoding == pb.encoding and
                    pa.transaction_details == pb.transaction_details and
                    pa.max_supported_transaction_version == pb.max_supported_transaction_version and
                    pa.show_rewards == pb.show_rewards;
            },
            .logs => |pa| {
                const pb = b.params.logs;
                return logsFilterEql(pa.filter, pb.filter) and
                    pa.commitment == pb.commitment;
            },
            .program => |pa| {
                const pb = b.params.program;
                return std.mem.eql(u8, &pa.program_id.data, &pb.program_id.data) and
                    pa.commitment == pb.commitment and
                    pa.encoding == pb.encoding and
                    dataSliceEql(pa.data_slice, pb.data_slice) and
                    programFiltersEql(pa.filters, pb.filters);
            },
            .root, .slot, .slots_updates, .vote => return true,
            .signature => |pa| {
                const pb = b.params.signature;
                return std.mem.eql(u8, &pa.sig_value.r, &pb.sig_value.r) and
                    std.mem.eql(u8, &pa.sig_value.s, &pb.sig_value.s) and
                    pa.commitment == pb.commitment and
                    pa.enableReceivedNotification == pb.enableReceivedNotification;
            },
        }
    }

    fn logsFilterEql(a: methods.LogsFilter, b: methods.LogsFilter) bool {
        const tag_a: std.meta.Tag(methods.LogsFilter) = a;
        const tag_b: std.meta.Tag(methods.LogsFilter) = b;
        if (tag_a != tag_b) {
            return false;
        }
        switch (a) {
            .all, .allWithVotes => return true,
            .mentions => |va| {
                const vb = b.mentions;
                return std.mem.eql(u8, &va.mentions[0].data, &vb.mentions[0].data);
            },
        }
    }

    fn blockFilterEql(a: methods.BlockFilter, b: methods.BlockFilter) bool {
        const tag_a: std.meta.Tag(methods.BlockFilter) = a;
        const tag_b: std.meta.Tag(methods.BlockFilter) = b;
        if (tag_a != tag_b) {
            return false;
        }
        switch (a) {
            .all => return true,
            .mentionsAccountOrProgram => |va| {
                const vb = b.mentionsAccountOrProgram;
                return std.mem.eql(
                    u8,
                    &va.mentionsAccountOrProgram.data,
                    &vb.mentionsAccountOrProgram.data,
                );
            },
        }
    }

    fn dataSliceEql(a: ?methods.DataSlice, b: ?methods.DataSlice) bool {
        const sa = a orelse return b == null;
        const sb = b orelse return false;
        return sa.offset == sb.offset and sa.length == sb.length;
    }

    const Filter = methods.ProgramSubscribe.Filter;

    fn programFiltersEql(
        a: ?[]const Filter,
        b: ?[]const Filter,
    ) bool {
        const fa = a orelse return b == null;
        const fb = b orelse return false;
        if (fa.len != fb.len) {
            return false;
        }
        for (fa, fb) |ea, eb| {
            if (!programFilterEql(ea, eb)) {
                return false;
            }
        }
        return true;
    }

    fn programFilterEql(a: Filter, b: Filter) bool {
        const tag_a: std.meta.Tag(Filter) = a;
        const tag_b: std.meta.Tag(Filter) = b;
        if (tag_a != tag_b) {
            return false;
        }
        switch (a) {
            .dataSize => |va| return va == b.dataSize,
            .memcmp => |va| {
                const vb = b.memcmp;
                return va.offset == vb.offset and std.mem.eql(u8, va.bytes, vb.bytes);
            },
            .tokenAccountState => return true,
        }
    }

    /// Construct a SubReqKey from a parsed WsMethodAndParams, populating
    /// Solana-spec defaults for any omitted optional config fields.
    /// Returns null for methods that don't map to a subscription key.
    pub fn fromMethod(method: *const ws_request.WsMethodAndParams) ?SubReqKey {
        return switch (method.*) {
            .accountSubscribe => |p| blk: {
                const cfg: methods.AccountSubscribe.Config = p.config orelse .{};
                break :blk .{
                    .method = .account,
                    .params = .{ .account = .{
                        .pubkey = p.pubkey,
                        .commitment = cfg.commitment orelse .finalized,
                        .encoding = cfg.encoding orelse .binary,
                        .data_slice = cfg.dataSlice,
                    } },
                };
            },
            .blockSubscribe => |p| blk: {
                const cfg: methods.BlockSubscribe.Config = p.config orelse .{};
                break :blk .{
                    .method = .block,
                    .params = .{
                        .block = .{
                            .filter = p.filter,
                            .commitment = cfg.commitment orelse .finalized,
                            // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc_pubsub.rs#L558
                            .encoding = cfg.encoding orelse .base64,
                            .transaction_details = cfg.transactionDetails orelse .full,
                            .max_supported_transaction_version = cfg.maxSupportedTransactionVersion,
                            // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc_pubsub.rs#L569
                            .show_rewards = cfg.showRewards orelse false,
                        },
                    },
                };
            },
            .logsSubscribe => |p| blk: {
                const cfg: methods.LogsSubscribe.Config = p.config orelse .{};
                break :blk .{
                    .method = .logs,
                    .params = .{ .logs = .{
                        .filter = p.filter,
                        .commitment = cfg.commitment orelse .finalized,
                    } },
                };
            },
            .programSubscribe => |p| blk: {
                const cfg: methods.ProgramSubscribe.Config = p.config orelse .{};
                break :blk .{
                    .method = .program,
                    .params = .{ .program = .{
                        .program_id = p.program_id,
                        .commitment = cfg.commitment orelse .finalized,
                        .encoding = cfg.encoding orelse .binary,
                        .data_slice = cfg.dataSlice,
                        .filters = cfg.filters,
                    } },
                };
            },
            .rootSubscribe => .{
                .method = .root,
                .params = .{ .root = {} },
            },
            .signatureSubscribe => |p| blk: {
                const cfg: methods.SignatureSubscribe.Config = p.config orelse .{};
                break :blk .{
                    .method = .signature,
                    .params = .{ .signature = .{
                        .sig_value = p.signature,
                        .commitment = cfg.commitment orelse .finalized,
                        .enableReceivedNotification = cfg.enableReceivedNotification orelse false,
                    } },
                };
            },
            .slotSubscribe => .{
                .method = .slot,
                .params = .{ .slot = {} },
            },
            .slotsUpdatesSubscribe => .{
                .method = .slots_updates,
                .params = .{ .slots_updates = {} },
            },
            .voteSubscribe => .{
                .method = .vote,
                .params = .{ .vote = {} },
            },
            else => null,
        };
    }

    /// Convenience constructors for tests/benchmarks.
    pub fn slotKey() SubReqKey {
        return .{ .method = .slot, .params = .{ .slot = {} } };
    }

    pub fn voteKey() SubReqKey {
        return .{ .method = .vote, .params = .{ .vote = {} } };
    }

    pub fn accountKey(pubkey: Pubkey) SubReqKey {
        return .{ .method = .account, .params = .{ .account = .{ .pubkey = pubkey } } };
    }

    pub fn logsKeyAll() SubReqKey {
        return .{ .method = .logs, .params = .{ .logs = .{ .filter = .all } } };
    }

    /// Clone key data into allocator-owned memory when heap-backed fields exist.
    pub fn clone(self: *const SubReqKey, allocator: std.mem.Allocator) !SubReqKey {
        var result = self.*;
        switch (self.params) {
            .program => |pp| {
                if (pp.filters) |filters| {
                    const duped = try allocator.alloc(methods.ProgramSubscribe.Filter, filters.len);
                    var copied: usize = 0;
                    errdefer {
                        for (duped[0..copied]) |f| {
                            switch (f) {
                                .memcmp => |mc| allocator.free(mc.bytes),
                                else => {},
                            }
                        }
                        allocator.free(duped);
                    }
                    for (filters, 0..) |f, i| {
                        duped[i] = switch (f) {
                            .memcmp => |mc| .{ .memcmp = .{
                                .offset = mc.offset,
                                .bytes = try allocator.dupe(u8, mc.bytes),
                            } },
                            else => f,
                        };
                        copied = i + 1;
                    }
                    result.params = .{ .program = .{
                        .program_id = pp.program_id,
                        .commitment = pp.commitment,
                        .encoding = pp.encoding,
                        .data_slice = pp.data_slice,
                        .filters = duped,
                    } };
                }
            },
            else => {},
        }
        return result;
    }

    /// Free heap-allocated data in the key. Only `program.filters`
    /// (including memcmp bytes) have heap data.
    pub fn deinit(self: *SubReqKey, allocator: std.mem.Allocator) void {
        switch (self.params) {
            .program => |pp| {
                if (pp.filters) |filters| {
                    for (filters) |f| {
                        switch (f) {
                            .memcmp => |mc| allocator.free(mc.bytes),
                            else => {},
                        }
                    }
                    allocator.free(filters);
                }
            },
            else => {},
        }
    }
};

/// Globally unique, monotonically increasing subscription ID.
pub const SubId = u64;

pub const SlotModifiedAccounts = struct {
    /// All accounts modified in a frozen slot, owned by `arena`.
    accounts: []AccountWithPubkey = &.{},
    arena_state: std.heap.ArenaAllocator.State,

    pub fn empty() SlotModifiedAccounts {
        return .{
            .accounts = &.{},
            .arena_state = .{},
        };
    }

    pub fn deinit(self: *SlotModifiedAccounts, allocator: std.mem.Allocator) void {
        self.arena_state.promote(allocator).deinit();
        self.* = empty();
    }
};

pub const SlotFrozenEvent = struct {
    slot: u64,
    parent: u64,
    root: u64,
    stats: SlotTransactionStats = .{},
    accounts: SlotModifiedAccounts = SlotModifiedAccounts.empty(),
    /// Block-level metadata populated at freeze time.
    blockhash: sig.core.Hash = .ZEROES,
    previous_blockhash: sig.core.Hash = .ZEROES,
    block_height: ?u64 = null,
    block_time: ?i64 = null,
    /// Rewards and partitions for this slot. Owns an arena
    /// that backs the rewards slice; freed in deinit.
    distributed_rewards: DistributedRewards = DistributedRewards.empty(),

    pub fn deinit(self: *SlotFrozenEvent, allocator: std.mem.Allocator) void {
        self.accounts.deinit(allocator);
        self.distributed_rewards.deinit(allocator);
    }
};

/// Internal runtime input event from producer threads to the websocket loop thread.
pub const ReceivedSignaturesEvent = struct {
    slot: u64,
    signatures: []const Signature,

    pub fn deinit(self: ReceivedSignaturesEvent, allocator: std.mem.Allocator) void {
        if (self.signatures.len > 0) {
            allocator.free(self.signatures);
        }
    }
};

/// Internal runtime input event from producer threads
/// to the websocket loop thread.
pub const InboundEvent = union(enum) {
    transaction_batch: SlotTransactionBatch,
    received_signatures: ReceivedSignaturesEvent,
    slot_frozen: SlotFrozenEvent,
    slot_confirmed: u64,
    /// Local replay/tower rooted.
    slot_local_rooted: u64,
    /// Finalized (super majority) rooted.
    slot_finalized_rooted: u64,
    tip_changed: u64,
    slot_dead: SlotDeadEvent,
    first_shred_received: u64,
    slot_completed: u64,
    bank_created: BankCreatedEvent,
    vote: VoteEventData,

    pub fn deinit(self: InboundEvent, allocator: std.mem.Allocator) void {
        switch (self) {
            .transaction_batch => |batch| {
                var b = batch;
                b.deinit(allocator);
            },
            .received_signatures => |data| data.deinit(allocator),
            .vote => |vote_data| vote_data.deinit(allocator),
            .slot_frozen => |slot_data| {
                var data = slot_data;
                data.deinit(allocator);
            },
            .slot_dead => |dead| {
                allocator.free(dead.err);
            },
            .slot_confirmed,
            .slot_local_rooted,
            .slot_finalized_rooted,
            .tip_changed,
            .first_shred_received,
            .slot_completed,
            .bank_created,
            => {},
        }
    }
};

pub const SlotDeadEvent = struct {
    slot: u64,
    err: []const u8,
};

pub const BankCreatedEvent = struct {
    slot: u64,
    parent: u64,
    root: u64,
};

/// Sink to push events for jrpc ws runtime broadcasting.
pub const EventSink = struct {
    channel: Channel(InboundEvent),
    /// Used to wake the IO loop.
    loop_async: xev.Async,
    /// Used to avoid spamming IO loop wakes.
    notify_pending: std.atomic.Value(bool) = .init(false),

    const Channel = sig.sync.Channel;

    pub fn create(sink_allocator: std.mem.Allocator) !*EventSink {
        const self = try sink_allocator.create(EventSink);
        errdefer sink_allocator.destroy(self);
        var channel = try Channel(InboundEvent).init(sink_allocator);
        errdefer channel.deinit();
        self.* = .{
            .channel = channel,
            .loop_async = try xev.Async.init(),
        };
        return self;
    }

    pub fn allocator(self: *const EventSink) std.mem.Allocator {
        return self.channel.allocator;
    }

    pub fn destroy(self: *EventSink) void {
        while (self.channel.tryReceive()) |msg| {
            msg.deinit(self.allocator());
        }
        self.channel.deinit();
        self.loop_async.deinit();
        self.allocator().destroy(self);
    }

    pub fn send(self: *EventSink, msg: InboundEvent) !void {
        try self.channel.send(msg);
        const already = self.notify_pending.swap(true, .release);
        if (!already) {
            self.loop_async.notify() catch |err| {
                _ = self.notify_pending.swap(false, .release);
                return err;
            };
        }
    }

    pub fn materializeSlotModifiedAccounts(
        self: *EventSink,
        logger: anytype,
        account_reader: sig.accounts_db.AccountReader,
        slot: u64,
    ) !SlotModifiedAccounts {
        const zone = tracy.Zone.init(@src(), .{ .name = "materialize slot modified accounts" });
        defer zone.deinit();
        var arena = std.heap.ArenaAllocator.init(self.channel.allocator);
        errdefer arena.deinit();
        const arena_allocator = arena.allocator();

        var iterator = account_reader.slotModifiedIterator(slot) orelse {
            // Logging for observability, there should always be modified accounts for a slot in
            // Solana and likely indicates a bug
            logger.err().logf(
                "frozen slot {} had no modified accounts to materialize",
                .{slot},
            );
            return .{
                .accounts = &.{},
                .arena_state = arena.state,
            };
        };
        defer iterator.unlock();

        const accounts = try arena_allocator.alloc(AccountWithPubkey, iterator.len());
        var index: usize = 0;
        while (try iterator.next(arena_allocator)) |account_with_pubkey| {
            accounts[index] = .{
                .pubkey = account_with_pubkey[0],
                .account = account_with_pubkey[1],
            };
            index += 1;
        }
        return .{
            .accounts = accounts,
            .arena_state = arena.state,
        };
    }
};

pub const SlotEventData = struct {
    slot: u64,
    parent: u64,
    root: u64,
    stats: SlotTransactionStats = .{},
};

pub const AccountEventData = struct {
    account: AccountWithPubkey,
    slot: u64,

    pub fn deinit(self: AccountEventData, allocator: std.mem.Allocator) void {
        self.account.account.deinit(allocator);
    }
};

pub const TransactionLogsEntry = struct {
    signature: Signature,
    err: ?TransactionError,
    is_vote: bool,
    logs: []const []const u8,
    mentioned_pubkeys: []const Pubkey,

    /// Returns a deep-cloned LogsNotificationData, allocated using the provided allocator,
    /// caller must call deinit.
    pub fn toOwnedNotificationData(
        self: *const TransactionLogsEntry,
        allocator: std.mem.Allocator,
        slot: u64,
    ) !LogsNotificationData {
        const cloned_logs = try cloneLogLines(allocator, self.logs);
        errdefer freeLogLines(allocator, cloned_logs);

        const cloned_mentions = try allocator.dupe(Pubkey, self.mentioned_pubkeys);
        errdefer allocator.free(cloned_mentions);

        const cloned_err = if (self.err) |tx_err| try tx_err.clone(allocator) else null;
        errdefer if (cloned_err) |tx_err| tx_err.deinit(allocator);

        return .{
            .slot = slot,
            .signature = self.signature,
            .err = cloned_err,
            .is_vote = self.is_vote,
            .logs = cloned_logs,
            .mentioned_pubkeys = cloned_mentions,
        };
    }
};

/// A batch of full transaction metadata for a single slot, streamed from the Committer at commit time. Carries
/// everything needed to build block, log, and future transaction notifications from cache (no ledger read).
/// Owns all referenced data through an arena allocator.
pub const SlotTransactionBatch = struct {
    /// Slot this batch belongs to.
    slot: u64 = 0,
    /// Transaction entries, arena-owned.
    entries: []const TransactionEntry = &.{},
    arena_state: std.heap.ArenaAllocator.State,

    pub fn empty() SlotTransactionBatch {
        return .{
            .slot = 0,
            .entries = &.{},
            .arena_state = .{},
        };
    }

    pub fn deinit(self: *SlotTransactionBatch, allocator: std.mem.Allocator) void {
        self.arena_state.promote(allocator).deinit();
        self.* = empty();
    }
};

/// Full per-transaction metadata, arena-owned inside a `SlotTransactionBatch`. Contains everything previously
/// spread across `TransactionStatusMeta`, the transaction itself, vote flag, and log-subscribe filter keys.
///
/// Fields mirror `TransactionStatusMeta` + identity data so both `blockSubscribe` and `logSubscribe` (and future
/// `transactionSubscribe`) can be served from this single cached structure.
pub const TransactionEntry = struct {
    // Identity
    signature: Signature,
    /// Full transaction (signatures + versioned message). Arena-owned; the `Transaction` itself does NOT own
    /// the inner slices, the batch arena does.
    transaction: Transaction,
    is_vote: bool,

    /// Global position of this transaction within the slot (across all entries). Used to restore canonical ordering
    /// in `buildConfirmedBlock` when transactions are committed out-of-order by the async replay path.
    /// [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/ledger/src/blockstore_processor.rs#L1497
    transaction_index: usize,

    // Execution result
    err: ?TransactionError,
    fee: u64,
    compute_units_consumed: ?u64,
    cost_units: u64,

    // Balance snapshots
    pre_balances: []const u64,
    post_balances: []const u64,
    pre_token_balances: ?[]const TransactionTokenBalance,
    post_token_balances: ?[]const TransactionTokenBalance,

    // Execution trace
    inner_instructions: ?[]const InnerInstructions,
    log_messages: ?[]const []const u8,
    return_data: ?TransactionReturnData,

    // Address lookup table resolution
    loaded_addresses: LoadedAddresses,

    // For logSubscribe filter matching
    mentioned_pubkeys: []const Pubkey,
};

pub const LogsNotificationData = struct {
    slot: u64,
    signature: Signature,
    err: ?TransactionError,
    is_vote: bool,
    logs: []const []const u8,
    mentioned_pubkeys: []const Pubkey,

    pub fn deinit(self: LogsNotificationData, allocator: std.mem.Allocator) void {
        freeLogLines(allocator, self.logs);
        if (self.mentioned_pubkeys.len > 0) {
            allocator.free(self.mentioned_pubkeys);
        }
        if (self.err) |tx_err| {
            tx_err.deinit(allocator);
        }
    }
};

pub fn cloneLogLines(
    allocator: std.mem.Allocator,
    log_lines: []const []const u8,
) ![]const []const u8 {
    const cloned = try allocator.alloc([]const u8, log_lines.len);
    var copied: usize = 0;
    errdefer {
        for (cloned[0..copied]) |line| {
            allocator.free(line);
        }
        allocator.free(cloned);
    }

    for (log_lines, 0..) |line, i| {
        cloned[i] = try allocator.dupe(u8, line);
        copied = i + 1;
    }
    return cloned;
}

fn freeLogLines(allocator: std.mem.Allocator, log_lines: []const []const u8) void {
    for (log_lines) |line| {
        allocator.free(line);
    }
    if (log_lines.len > 0) {
        allocator.free(log_lines);
    }
}

pub const RootEventData = struct {
    root: u64,
};

pub const SignatureNotificationData = struct {
    slot: u64,
    value: Value,

    pub const Value = union(enum) {
        received,
        final: struct {
            err: ?TransactionError,
        },

        pub fn deinit(self: Value, allocator: std.mem.Allocator) void {
            switch (self) {
                .received => {},
                .final => |result| {
                    if (result.err) |tx_err| {
                        tx_err.deinit(allocator);
                    }
                },
            }
        }
    };

    pub fn deinit(self: SignatureNotificationData, allocator: std.mem.Allocator) void {
        self.value.deinit(allocator);
    }
};

/// Transaction stats included in slotsUpdatesSubscribe "frozen" notifications.
pub const SlotTransactionStats = struct {
    numTransactionEntries: u64 = 0,
    numSuccessfulTransactions: u64 = 0,
    numFailedTransactions: u64 = 0,
    maxTransactionsPerEntry: u64 = 0,
};

/// Data for a single slotsUpdatesSubscribe notification.
/// Each variant maps to one of the 7 Agave SlotUpdate event types.
/// Uses custom JSON serialization to produce Agave-compatible
/// internally-tagged format: `{"type": "<eventType>", ...}`.
pub const SlotUpdateData = union(enum) {
    first_shred_received: BasicSlotUpdate,
    completed: BasicSlotUpdate,
    created_bank: CreatedBankUpdate,
    frozen: FrozenUpdate,
    dead: DeadUpdate,
    optimistic_confirmation: BasicSlotUpdate,
    root: BasicSlotUpdate,

    pub const BasicSlotUpdate = struct {
        slot: u64,
        timestamp: u64,
    };

    pub const CreatedBankUpdate = struct {
        slot: u64,
        parent: u64,
        timestamp: u64,
    };

    pub const FrozenUpdate = struct {
        slot: u64,
        timestamp: u64,
        stats: SlotTransactionStats,
    };

    pub const DeadUpdate = struct {
        slot: u64,
        timestamp: u64,
        err: []const u8,
    };

    pub fn clone(self: SlotUpdateData, allocator: std.mem.Allocator) !SlotUpdateData {
        return switch (self) {
            .first_shred_received,
            .completed,
            .created_bank,
            .frozen,
            .optimistic_confirmation,
            .root,
            => self,
            .dead => |dead| .{ .dead = .{
                .slot = dead.slot,
                .timestamp = dead.timestamp,
                .err = try allocator.dupe(u8, dead.err),
            } },
        };
    }

    pub fn deinit(self: SlotUpdateData, allocator: std.mem.Allocator) void {
        switch (self) {
            .first_shred_received,
            .completed,
            .created_bank,
            .frozen,
            .optimistic_confirmation,
            .root,
            => {},
            .dead => |dead| allocator.free(dead.err),
        }
    }

    pub fn typeName(self: SlotUpdateData) []const u8 {
        return switch (self) {
            .first_shred_received => "firstShredReceived",
            .completed => "completed",
            .created_bank => "createdBank",
            .frozen => "frozen",
            .dead => "dead",
            .optimistic_confirmation => "optimisticConfirmation",
            .root => "root",
        };
    }

    fn slotValue(self: SlotUpdateData) u64 {
        return switch (self) {
            inline else => |d| d.slot,
        };
    }

    fn timestampValue(self: SlotUpdateData) u64 {
        return switch (self) {
            inline else => |d| d.timestamp,
        };
    }

    /// Agave-compatible internally-tagged JSON:
    /// `{"slot": N, "type": "eventName", "timestamp": N, ...}`
    pub fn jsonStringify(
        self: SlotUpdateData,
        jw: anytype,
    ) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("slot");
        try jw.write(self.slotValue());
        try jw.objectField("type");
        try jw.write(self.typeName());
        try jw.objectField("timestamp");
        try jw.write(self.timestampValue());
        switch (self) {
            .created_bank => |d| {
                try jw.objectField("parent");
                try jw.write(d.parent);
            },
            .frozen => |d| {
                try jw.objectField("stats");
                try jw.write(d.stats);
            },
            .dead => |d| {
                try jw.objectField("err");
                try jw.write(d.err);
            },
            else => {},
        }
        try jw.endObject();
    }
};

/// Data carried by a block serialization job.
/// The block is pre-built from cached transaction data
/// on the IO loop thread; the arena owns all block data
/// and is freed in `JobType.deinit`.
pub const BlockJobData = struct {
    slot: u64,
    filter: methods.BlockFilter,
    encoding: methods.TransactionEncoding,
    transaction_details: methods.TransactionDetails,
    max_supported_transaction_version: ?u64,
    show_rewards: bool,
    block: sig.ledger.Reader.VersionedConfirmedBlock,
    arena: std.heap.ArenaAllocator,
};

pub const VoteEventData = struct {
    vote_pubkey: Pubkey,
    slots: []const u64,
    hash: Hash,
    timestamp: ?i64,
    signature: Signature,

    pub fn empty() VoteEventData {
        return .{
            .vote_pubkey = Pubkey.ZEROES,
            .slots = &.{},
            .hash = Hash.ZEROES,
            .timestamp = null,
            .signature = Signature.ZEROES,
        };
    }

    pub fn initOwned(
        allocator: std.mem.Allocator,
        vote_pubkey: Pubkey,
        /// The slots array is duped into the provided allocator. Caller can free slots safely.
        slots: []const u64,
        hash: Hash,
        timestamp: ?i64,
        signature: Signature,
    ) std.mem.Allocator.Error!VoteEventData {
        return .{
            .vote_pubkey = vote_pubkey,
            .slots = try allocator.dupe(u64, slots),
            .hash = hash,
            .timestamp = timestamp,
            .signature = signature,
        };
    }

    pub fn deinit(self: VoteEventData, allocator: std.mem.Allocator) void {
        if (self.slots.len > 0) {
            allocator.free(self.slots);
        }
    }
};

/// Serialization job: loop thread -> worker thread.
/// Serialization workers round-trip sub_id to match result back to associated subscription.
pub const SerializeJob = struct {
    sub_id: SubId,
    index: ?u64,
    job_type: JobType,
    is_final: bool = false,
    submitted_at: std.time.Instant,

    pub const JobType = union(enum) {
        account: struct {
            data: AccountEventData,
            encoding: methods.AccountEncoding,
            data_slice: ?methods.DataSlice = null,
            read_ctx: SlotReadContext,
        },
        block: BlockJobData,
        logs: LogsNotificationData,
        program: struct {
            data: AccountEventData,
            encoding: methods.AccountEncoding,
            data_slice: ?methods.DataSlice = null,
            read_ctx: SlotReadContext,
        },
        root: RootEventData,
        signature: SignatureNotificationData,
        slot: SlotEventData,
        slots_updates: SlotUpdateData,
        vote: VoteEventData,

        pub fn deinit(self: JobType, allocator: std.mem.Allocator) void {
            switch (self) {
                .account => |job| job.data.deinit(allocator),
                .block => |job| {
                    var arena = job.arena;
                    arena.deinit();
                },
                .logs => |job| job.deinit(allocator),
                .program => |job| job.data.deinit(allocator),
                .signature => |job| job.deinit(allocator),
                .slots_updates => |job| job.deinit(allocator),
                .vote => |job| job.deinit(allocator),
                else => {},
            }
        }
    };

    pub fn deinit(self: SerializeJob, allocator: std.mem.Allocator) void {
        self.job_type.deinit(allocator);
    }
};

/// Commit result from worker -> loop thread.
pub const CommitResult = union(enum) {
    payload: NotifPayload,
    serialize_error: anyerror,

    pub fn deinit(self: CommitResult, allocator: std.mem.Allocator) void {
        switch (self) {
            .payload => |p| p.deinit(allocator),
            .serialize_error => {},
        }
    }
};

/// Commit message: worker thread -> loop thread.
pub const CommitMsg = struct {
    sub_id: SubId,
    index: ?u64,
    result: CommitResult,
    is_final: bool = false,
    serialize_ns: u64 = 0,
    pipeline_latency_ns: u64 = 0,
    payload_bytes: u64 = 0,
};

test "SubReqKey fromMethod defaults accountSubscribe encoding to binary" {
    const pubkey = Pubkey.parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    const method: ws_request.WsMethodAndParams = .{ .accountSubscribe = .{
        .pubkey = pubkey,
    } };

    const key = SubReqKey.fromMethod(&method).?;
    try std.testing.expectEqual(methods.AccountEncoding.binary, key.params.account.encoding);
}

test "SubReqKey fromMethod defaults programSubscribe encoding to binary" {
    const program_id = Pubkey.parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    const method: ws_request.WsMethodAndParams = .{ .programSubscribe = .{
        .program_id = program_id,
    } };

    const key = SubReqKey.fromMethod(&method).?;
    try std.testing.expectEqual(methods.AccountEncoding.binary, key.params.program.encoding);
}

test "SubReqKey equality - slot" {
    const a = SubReqKey.slotKey();
    const b = SubReqKey.slotKey();
    try std.testing.expect(a.eql(&b));
}

test "SubReqKey equality - account same pubkey" {
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAA);
    const a = SubReqKey.accountKey(pk);
    const b = SubReqKey.accountKey(pk);
    try std.testing.expect(a.eql(&b));
}

test "SubReqKey equality - account different pubkey" {
    var pk1: Pubkey = undefined;
    @memset(&pk1.data, 0xAA);
    var pk2: Pubkey = undefined;
    @memset(&pk2.data, 0xBB);
    const a = SubReqKey.accountKey(pk1);
    const b = SubReqKey.accountKey(pk2);
    try std.testing.expect(!a.eql(&b));
}

test "SubReqKey equality - cross-method never equal" {
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAA);
    const a = SubReqKey.slotKey();
    const b = SubReqKey.accountKey(pk);
    try std.testing.expect(!a.eql(&b));
}

test "SubReqKey equality - logs all vs all" {
    const a = SubReqKey.logsKeyAll();
    const b = SubReqKey.logsKeyAll();
    try std.testing.expect(a.eql(&b));
}

test "SubReqKey equality - account with different commitment" {
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAA);
    const a: SubReqKey = .{
        .method = .account,
        .params = .{ .account = .{
            .pubkey = pk,
            .commitment = .finalized,
        } },
    };
    const b: SubReqKey = .{
        .method = .account,
        .params = .{ .account = .{
            .pubkey = pk,
            .commitment = .confirmed,
        } },
    };
    try std.testing.expect(!a.eql(&b));
}

test "SubReqKey equality - account data slice matters" {
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAA);
    const a: SubReqKey = .{
        .method = .account,
        .params = .{ .account = .{
            .pubkey = pk,
            .data_slice = .{ .offset = 0, .length = 4 },
        } },
    };
    const b: SubReqKey = .{
        .method = .account,
        .params = .{ .account = .{
            .pubkey = pk,
            .data_slice = .{ .offset = 1, .length = 4 },
        } },
    };
    try std.testing.expect(!a.eql(&b));
}

test "SubReqKey equality - program memcmp bytes dedupe across encodings" {
    const allocator = std.testing.allocator;
    const program_id = Pubkey.parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");

    const base58_method: ws_request.WsMethodAndParams = .{ .programSubscribe = .{
        .program_id = program_id,
        .config = .{
            .filters = &.{.{ .memcmp = .{ .offset = 0, .bytes = "abc" } }},
        },
    } };

    const parsed = try std.json.parseFromSlice(
        ws_request.WsRequest,
        allocator,
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["vinesvinesvinesvinesvinesvinesvinesvinesvin",{"filters":[{"memcmp":{"offset":0,"bytes":"YWJj","encoding":"base64"}}]}]}
    ,
        .{},
    );
    defer parsed.deinit();

    const a = SubReqKey.fromMethod(&base58_method).?;
    const b = SubReqKey.fromMethod(&parsed.value.method).?;
    try std.testing.expect(a.eql(&b));
}

test "SubReqKey equality - void methods" {
    const root_a: SubReqKey = .{ .method = .root, .params = .{ .root = {} } };
    const root_b: SubReqKey = .{ .method = .root, .params = .{ .root = {} } };
    try std.testing.expect(root_a.eql(&root_b));

    const slot_a: SubReqKey = .{ .method = .slot, .params = .{ .slot = {} } };
    try std.testing.expect(!root_a.eql(&slot_a));
}

test "SubReqKey clone - slot has same value" {
    const allocator = std.testing.allocator;

    const key = SubReqKey.slotKey();
    var cloned = try key.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expect(key.eql(&cloned));
}

test "SubReqKey clone - logs mentions copies by value" {
    const allocator = std.testing.allocator;

    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAB);

    var key: SubReqKey = .{
        .method = .logs,
        .params = .{ .logs = .{
            .filter = .{ .mentions = .{ .mentions = .{pk} } },
        } },
    };

    var cloned = try key.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expect(key.eql(&cloned));
    try std.testing.expect(cloned.params.logs.filter == .mentions);

    @memset(&key.params.logs.filter.mentions.mentions[0].data, 0xCD);
    try std.testing.expect(!key.eql(&cloned));
}

test "SubReqKey clone - program filters deep copy memcmp bytes" {
    const allocator = std.testing.allocator;

    var program_id: Pubkey = undefined;
    @memset(&program_id.data, 0x11);

    var memcmp_bytes: [3]u8 = .{ 1, 2, 3 };
    const filters = [_]methods.ProgramSubscribe.Filter{
        .{ .dataSize = 8 },
        .{ .memcmp = .{ .offset = 4, .bytes = memcmp_bytes[0..] } },
    };
    const key: SubReqKey = .{
        .method = .program,
        .params = .{ .program = .{
            .program_id = program_id,
            .filters = filters[0..],
        } },
    };

    var cloned = try key.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expect(key.eql(&cloned));

    const cloned_filters = cloned.params.program.filters.?;
    try std.testing.expect(cloned_filters.ptr != filters[0..].ptr);
    try std.testing.expect(cloned_filters[1] == .memcmp);
    try std.testing.expect(cloned_filters[1].memcmp.bytes.ptr != memcmp_bytes[0..].ptr);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, cloned_filters[1].memcmp.bytes);

    memcmp_bytes[0] = 9;
    try std.testing.expect(!key.eql(&cloned));
}

test "LogsNotificationData deinit accepts empty static slices" {
    const allocator = std.testing.allocator;

    const data = LogsNotificationData{
        .slot = 1,
        .signature = Signature.ZEROES,
        .err = null,
        .is_vote = false,
        .logs = &.{},
        .mentioned_pubkeys = &.{},
    };

    data.deinit(allocator);
}

test "TransactionLogsEntry toOwnedNotificationData deep copies into logs notification data" {
    const allocator = std.testing.allocator;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const logs = try arena_allocator.alloc([]const u8, 1);
    logs[0] = "slot log line";

    var mention: Pubkey = undefined;
    @memset(&mention.data, 0xEF);

    const entry = TransactionLogsEntry{
        .signature = Signature.ZEROES,
        .err = .{ .InstructionError = .{
            4,
            .{ .BorshIoError = try arena_allocator.dupe(u8, "arena err") },
        } },
        .is_vote = true,
        .logs = logs,
        .mentioned_pubkeys = try arena_allocator.dupe(Pubkey, &.{mention}),
    };

    var cloned = try entry.toOwnedNotificationData(allocator, 99);
    defer cloned.deinit(allocator);

    try std.testing.expectEqual(99, cloned.slot);
    try std.testing.expect(cloned.logs.ptr != entry.logs.ptr);
    try std.testing.expect(cloned.logs[0].ptr != entry.logs[0].ptr);
    try std.testing.expect(cloned.mentioned_pubkeys.ptr != entry.mentioned_pubkeys.ptr);
    try std.testing.expectEqualStrings("slot log line", cloned.logs[0]);
    try std.testing.expectEqual(0xEF, cloned.mentioned_pubkeys[0].data[0]);
    try std.testing.expectEqualStrings(
        "arena err",
        cloned.err.?.InstructionError.@"1".BorshIoError,
    );
}

test "blockFilterEql - both all" {
    const a: methods.BlockFilter = .all;
    const b: methods.BlockFilter = .all;
    try std.testing.expect(SubReqKey.blockFilterEql(a, b));
}

test "blockFilterEql - same mentionsAccountOrProgram" {
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAA);
    const a: methods.BlockFilter = .{
        .mentionsAccountOrProgram = .{ .mentionsAccountOrProgram = pk },
    };
    const b: methods.BlockFilter = .{
        .mentionsAccountOrProgram = .{ .mentionsAccountOrProgram = pk },
    };
    try std.testing.expect(SubReqKey.blockFilterEql(a, b));
}

test "blockFilterEql - different mentionsAccountOrProgram pubkeys" {
    var pk1: Pubkey = undefined;
    @memset(&pk1.data, 0xAA);
    var pk2: Pubkey = undefined;
    @memset(&pk2.data, 0xBB);
    const a: methods.BlockFilter = .{
        .mentionsAccountOrProgram = .{ .mentionsAccountOrProgram = pk1 },
    };
    const b: methods.BlockFilter = .{
        .mentionsAccountOrProgram = .{ .mentionsAccountOrProgram = pk2 },
    };
    try std.testing.expect(!SubReqKey.blockFilterEql(a, b));
}

test "blockFilterEql - different tags" {
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAA);
    const a: methods.BlockFilter = .all;
    const b: methods.BlockFilter = .{
        .mentionsAccountOrProgram = .{ .mentionsAccountOrProgram = pk },
    };
    try std.testing.expect(!SubReqKey.blockFilterEql(a, b));
}

test "SubReqKey equality - block same params" {
    const a: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{} },
    };
    const b: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{} },
    };
    try std.testing.expect(a.eql(&b));
}

test "SubReqKey equality - block different commitment" {
    const a: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .commitment = .finalized } },
    };
    const b: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .commitment = .confirmed } },
    };
    try std.testing.expect(!a.eql(&b));
}

test "SubReqKey equality - block different encoding" {
    const a: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .encoding = .json } },
    };
    const b: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .encoding = .base64 } },
    };
    try std.testing.expect(!a.eql(&b));
}

test "SubReqKey equality - block different transaction_details" {
    const a: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .transaction_details = .full } },
    };
    const b: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .transaction_details = .none } },
    };
    try std.testing.expect(!a.eql(&b));
}

test "SubReqKey equality - block different max_supported_transaction_version" {
    const a: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{
            .max_supported_transaction_version = 0,
        } },
    };
    const b: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{
            .max_supported_transaction_version = null,
        } },
    };
    try std.testing.expect(!a.eql(&b));
}

test "SubReqKey equality - block different show_rewards" {
    const a: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .show_rewards = true } },
    };
    const b: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .show_rewards = false } },
    };
    try std.testing.expect(!a.eql(&b));
}

test "SubReqKey equality - block different filter" {
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAA);
    const a: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .filter = .all } },
    };
    const b: SubReqKey = .{
        .method = .block,
        .params = .{ .block = .{ .filter = .{
            .mentionsAccountOrProgram = .{
                .mentionsAccountOrProgram = pk,
            },
        } } },
    };
    try std.testing.expect(!a.eql(&b));
}

// --- SlotUpdateData.jsonStringify tests ---

fn stringifySlotUpdate(data: SlotUpdateData) ![]const u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(std.testing.allocator);
    var aw: std.Io.Writer.Allocating = .init(
        std.testing.allocator,
    );
    errdefer aw.deinit();
    try std.json.Stringify.value(data, .{}, &aw.writer);
    buf = aw.toArrayList();
    return buf.toOwnedSlice(std.testing.allocator);
}

test "SlotUpdateData json - first_shred_received" {
    const json = try stringifySlotUpdate(.{
        .first_shred_received = .{
            .slot = 42,
            .timestamp = 1000,
        },
    });
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        \\{"slot":42,"type":"firstShredReceived","timestamp":1000}
    , json);
}

test "SlotUpdateData json - completed" {
    const json = try stringifySlotUpdate(.{
        .completed = .{ .slot = 99, .timestamp = 2000 },
    });
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        \\{"slot":99,"type":"completed","timestamp":2000}
    , json);
}

test "SlotUpdateData json - optimistic_confirmation" {
    const json = try stringifySlotUpdate(.{
        .optimistic_confirmation = .{
            .slot = 55,
            .timestamp = 3000,
        },
    });
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        \\{"slot":55,"type":"optimisticConfirmation","timestamp":3000}
    , json);
}

test "SlotUpdateData json - root" {
    const json = try stringifySlotUpdate(.{
        .root = .{ .slot = 10, .timestamp = 4000 },
    });
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        \\{"slot":10,"type":"root","timestamp":4000}
    , json);
}

test "SlotUpdateData json - created_bank" {
    const json = try stringifySlotUpdate(.{
        .created_bank = .{
            .slot = 77,
            .parent = 76,
            .timestamp = 5000,
        },
    });
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        \\{"slot":77,"type":"createdBank","timestamp":5000,"parent":76}
    , json);
}

test "SlotUpdateData json - frozen" {
    const json = try stringifySlotUpdate(.{
        .frozen = .{
            .slot = 33,
            .timestamp = 6000,
            .stats = .{
                .numTransactionEntries = 100,
                .numSuccessfulTransactions = 90,
                .numFailedTransactions = 10,
                .maxTransactionsPerEntry = 50,
            },
        },
    });
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        \\{"slot":33,"type":"frozen","timestamp":6000,"stats":{"numTransactionEntries":100,"numSuccessfulTransactions":90,"numFailedTransactions":10,"maxTransactionsPerEntry":50}}
    , json);
}

test "SlotUpdateData json - dead" {
    const json = try stringifySlotUpdate(.{
        .dead = .{
            .slot = 44,
            .timestamp = 7000,
            .err = "slot marked dead",
        },
    });
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        \\{"slot":44,"type":"dead","timestamp":7000,"err":"slot marked dead"}
    , json);
}

test "SlotUpdateData typeName" {
    const cases = .{
        .{ SlotUpdateData{ .first_shred_received = .{
            .slot = 0,
            .timestamp = 0,
        } }, "firstShredReceived" },
        .{ SlotUpdateData{ .completed = .{
            .slot = 0,
            .timestamp = 0,
        } }, "completed" },
        .{ SlotUpdateData{ .created_bank = .{
            .slot = 0,
            .parent = 0,
            .timestamp = 0,
        } }, "createdBank" },
        .{ SlotUpdateData{ .frozen = .{
            .slot = 0,
            .timestamp = 0,
            .stats = .{},
        } }, "frozen" },
        .{ SlotUpdateData{ .dead = .{
            .slot = 0,
            .timestamp = 0,
            .err = "",
        } }, "dead" },
        .{ SlotUpdateData{ .optimistic_confirmation = .{
            .slot = 0,
            .timestamp = 0,
        } }, "optimisticConfirmation" },
        .{ SlotUpdateData{ .root = .{
            .slot = 0,
            .timestamp = 0,
        } }, "root" },
    };
    inline for (cases) |c| {
        try std.testing.expectEqualStrings(c[1], c[0].typeName());
    }
}
