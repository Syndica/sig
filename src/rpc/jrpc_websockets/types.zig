const std = @import("std");
const sig = @import("../../sig.zig");
const xev = @import("xev");
const tracy = @import("tracy");
const NotifPayload = sig.sync.RcSlice(u8);
const methods = @import("methods.zig");
const ws_request = @import("ws_request.zig");

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Account = sig.core.Account;
const TransactionError = sig.ledger.transaction_status.TransactionError;

pub const AccountWithPubkey = struct {
    pubkey: Pubkey,
    account: Account,
};

pub const SlotReadContext = struct {
    slot_tracker: *sig.replay.trackers.SlotTracker,
    commitments: *sig.replay.trackers.CommitmentTracker,
    account_reader: sig.accounts_db.AccountReader,
};

/// Subscription families used for subscription identity and fanout.
pub const SubscriptionKind = enum {
    account,
    logs,
    program,
    root,
    signature,
    slot,
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
        logs: LogsParams,
        program: ProgramParams,
        root: void,
        signature: SignatureParams,
        slot: void,
    };

    pub const AccountParams = struct {
        pubkey: Pubkey,
        commitment: methods.Commitment = .finalized,
        encoding: methods.AccountEncoding = .binary,
        data_slice: ?methods.DataSlice = null,
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
            .root, .slot => return true,
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
            else => null,
        };
    }

    /// Convenience constructors for tests/benchmarks.
    pub fn slotKey() SubReqKey {
        return .{ .method = .slot, .params = .{ .slot = {} } };
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
    arena: std.heap.ArenaAllocator,

    pub fn empty() SlotModifiedAccounts {
        return .{
            .accounts = &.{},
            .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator),
        };
    }

    pub fn deinit(self: *SlotModifiedAccounts) void {
        self.arena.deinit();
        self.* = empty();
    }
};

pub const SlotFrozenEvent = struct {
    slot: u64,
    parent: u64,
    root: u64,
    accounts: SlotModifiedAccounts = SlotModifiedAccounts.empty(),
};

/// Internal runtime input event from producer threads to the websocket loop thread.
pub const InboundEvent = union(enum) {
    logs: SlotTransactionLogs,
    slot_frozen: SlotFrozenEvent,
    slot_confirmed: u64,
    slot_rooted: u64,
    tip_changed: u64,

    pub fn deinit(self: InboundEvent) void {
        switch (self) {
            .logs => |slot_logs| {
                var logs = slot_logs;
                logs.deinit();
            },
            .slot_frozen => |slot_data| {
                var accounts = slot_data.accounts;
                accounts.deinit();
            },
            .slot_confirmed => {},
            .slot_rooted => {},
            .tip_changed => {},
        }
    }
};

/// Sink to push events for jrpc ws runtime broadcasting.
pub const EventSink = struct {
    channel: Channel(InboundEvent),
    /// Used to wake the IO loop.
    loop_async: xev.Async,
    /// Used to avoid spamming IO loop wakes.
    notify_pending: std.atomic.Value(bool) = .init(false),

    const Channel = sig.sync.Channel;

    pub fn create(allocator: std.mem.Allocator) !*EventSink {
        const self = try allocator.create(EventSink);
        errdefer allocator.destroy(self);
        var channel = try Channel(InboundEvent).init(allocator);
        errdefer channel.deinit();
        self.* = .{
            .channel = channel,
            .loop_async = try xev.Async.init(),
        };
        return self;
    }

    pub fn destroy(self: *EventSink) void {
        while (self.channel.tryReceive()) |msg| {
            msg.deinit();
        }
        self.channel.deinit();
        self.loop_async.deinit();
        self.channel.allocator.destroy(self);
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
                .arena = arena,
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
            .arena = arena,
        };
    }
};

pub const SlotEventData = struct {
    slot: u64,
    parent: u64,
    root: u64,
};

pub const AccountEventData = struct {
    account: AccountWithPubkey,
    slot: u64,

    pub fn deinit(self: AccountEventData, allocator: std.mem.Allocator) void {
        self.account.account.deinit(allocator);
    }
};

pub const SlotTransactionLogs = struct {
    /// Slot whose transaction logs this batch belongs to.
    slot: u64 = 0,
    /// Batch of transaction log entries owned by `arena`.
    entries: []const TransactionLogsEntry = &.{},
    arena: std.heap.ArenaAllocator,

    pub fn empty() SlotTransactionLogs {
        return .{
            .slot = 0,
            .entries = &.{},
            .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator),
        };
    }

    pub fn deinit(self: *SlotTransactionLogs) void {
        self.arena.deinit();
        self.* = empty();
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

fn cloneLogLines(
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

/// Serialization job: loop thread -> worker thread.
/// Serialization workers round-trip sub_id to match result back to associated subscription.
pub const SerializeJob = struct {
    sub_id: SubId,
    index: ?u64,
    job_type: JobType,
    submitted_at: std.time.Instant,

    pub const JobType = union(enum) {
        account: struct {
            data: AccountEventData,
            encoding: methods.AccountEncoding,
            data_slice: ?methods.DataSlice = null,
            read_ctx: SlotReadContext,
        },
        logs: LogsNotificationData,
        program: struct {
            data: AccountEventData,
            encoding: methods.AccountEncoding,
            data_slice: ?methods.DataSlice = null,
            read_ctx: SlotReadContext,
        },
        root: RootEventData,
        slot: SlotEventData,

        pub fn deinit(self: JobType, allocator: std.mem.Allocator) void {
            switch (self) {
                .account => |job| job.data.deinit(allocator),
                .logs => |job| job.deinit(allocator),
                .program => |job| job.data.deinit(allocator),
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

test "SlotTransactionLogs deinit accepts empty static slices" {
    var data = SlotTransactionLogs.empty();
    data.deinit();
}
