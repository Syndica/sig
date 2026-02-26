const std = @import("std");
const sig = @import("sig");
const NotifPayload = sig.sync.RcSlice(u8);
const methods = @import("methods.zig");
const ws_request = @import("ws_request.zig");

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Account = sig.core.Account;

pub const AccountWithPubkey = struct {
    pubkey: Pubkey,
    account: Account,
};

pub const RcAccountWithPubkey = struct {
    inner: sig.sync.Rc(AccountWithPubkey),

    pub fn init(
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
        account: Account,
    ) !RcAccountWithPubkey {
        const rc = try sig.sync.Rc(AccountWithPubkey).create(allocator);
        rc.payload().* = .{ .pubkey = pubkey, .account = account };
        return .{ .inner = rc };
    }

    pub fn acquire(self: RcAccountWithPubkey) RcAccountWithPubkey {
        return .{ .inner = self.inner.acquire() };
    }

    pub fn release(self: RcAccountWithPubkey, allocator: std.mem.Allocator) void {
        if (self.inner.release()) |bytes| {
            self.inner.payload().account.deinit(allocator);
            allocator.free(bytes);
        }
    }

    pub fn get(self: RcAccountWithPubkey) *const AccountWithPubkey {
        return self.inner.payload();
    }
};

/// Subscription method families.
pub const SubMethod = enum {
    account,
    logs,
    program,
    root,
    signature,
    slot,
};

/// Canonicalized subscription request key: method + method-specific parameters.
/// Determines which NotifQueue a subscription maps to. Two clients subscribing
/// with the same SubReqKey share one queue and SubId.
///
/// All params that affect message content or shape are identity-determining:
/// filters, encoding, and commitment all contribute to key equality.
pub const SubReqKey = struct {
    method: SubMethod,
    params: Params,

    pub const Params = union(SubMethod) {
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
        encoding: methods.Encoding = .base64,
    };

    pub const LogsParams = struct {
        /// When heap-allocated (mentions variant), owned by the map's allocator.
        filter: methods.LogsFilter,
        commitment: methods.Commitment = .finalized,
    };

    pub const ProgramParams = struct {
        program_id: Pubkey,
        commitment: methods.Commitment = .finalized,
        encoding: methods.Encoding = .base64,
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
                    pa.encoding == pb.encoding;
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
                if (va.mentions.len != vb.mentions.len) {
                    return false;
                }
                for (va.mentions, vb.mentions) |pa, pb| {
                    if (!std.mem.eql(u8, &pa.data, &pb.data)) {
                        return false;
                    }
                }
                return true;
            },
        }
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
                        .encoding = cfg.encoding orelse .base64,
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
                        .encoding = cfg.encoding orelse .base64,
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
            .logs => |lp| switch (lp.filter) {
                .mentions => |m| {
                    result.params = .{ .logs = .{
                        .filter = .{ .mentions = .{
                            .mentions = try allocator.dupe(Pubkey, m.mentions),
                        } },
                        .commitment = lp.commitment,
                    } };
                },
                else => {},
            },
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
                        .filters = duped,
                    } };
                }
            },
            else => {},
        }
        return result;
    }

    /// Free heap-allocated data in the key. Only `logs.mentions` and
    /// `program.filters` (including memcmp bytes) have heap data.
    pub fn deinit(self: *SubReqKey, allocator: std.mem.Allocator) void {
        switch (self.params) {
            .logs => |lp| switch (lp.filter) {
                .mentions => |m| allocator.free(m.mentions),
                else => {},
            },
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

/// Event from a producer thread to the loop thread.
pub const EventMsg = struct {
    method: SubMethod,
    event_data: EventData,
};

/// Tagged union of event payloads.
/// Not all SubMethods have their own event type — e.g. program subscriptions
/// receive account events (matched by owner in the runtime).
/// TODO: real event data types
pub const EventData = union(enum) {
    account: AccountEventData,
    logs: LogsEventData,
    root: RootEventData,
    slot: SlotEventData,

    pub fn deinit(self: EventData, allocator: std.mem.Allocator) void {
        switch (self) {
            .account => |ad| ad.rc.release(allocator),
            else => {},
        }
    }
};

pub const SlotEventData = struct {
    slot: u64,
    parent: u64,
    root: u64,
};

pub const AccountEventData = struct {
    rc: RcAccountWithPubkey,
    slot: u64,
};

pub const LogsEventData = struct {
    signature: sig.core.Signature,
    num_logs: u32,
    slot: u64,
};

pub const RootEventData = struct {
    root: u64,
};

/// Serialization job: loop thread -> worker thread.
/// Workers carry sub_id (not key ref/queue pointer) for safe cross-thread identification.
pub const SerializeJob = struct {
    sub_id: SubId,
    index: ?u64,
    event_data: EventData,
    encoding: methods.Encoding,
    sub_method: SubMethod,
    submitted_ns: i128,
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

test "SubReqKey clone - logs mentions deep copies mentions slice" {
    const allocator = std.testing.allocator;

    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAB);

    var mentions: [1]Pubkey = .{pk};
    const key: SubReqKey = .{
        .method = .logs,
        .params = .{ .logs = .{
            .filter = .{ .mentions = .{ .mentions = mentions[0..] } },
        } },
    };

    var cloned = try key.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expect(key.eql(&cloned));
    try std.testing.expect(cloned.params.logs.filter == .mentions);
    try std.testing.expect(cloned.params.logs.filter.mentions.mentions.ptr != mentions[0..].ptr);

    @memset(&mentions[0].data, 0xCD);
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
