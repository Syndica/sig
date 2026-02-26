const std = @import("std");
const sig = @import("sig");
const types = @import("types.zig");
const metrics_mod = @import("metrics.zig");
const NotifQueue = @import("NotifQueue.zig");

const SubReqKey = types.SubReqKey;
const SubId = types.SubId;

/// Per-key subscription map entry.
pub const MapEntry = struct {
    key: SubReqKey,
    sub_id: SubId,
    queue: *NotifQueue,
};

/// Subscription map managing active subscriptions and their notification queues.
///
/// Uses ArrayList with linear scans.
///
/// Lookup patterns:
/// - getOrCreate(key): subscribe path, dedup by SubReqKey equality
/// - getById(sub_id): commit resolution path (mapping after serialization via SubId)
/// - iterating entries filtered by SubReqKey method and params: event dispatch fanout
///
/// All operations are loop-thread only (no locks required).
pub const RPCSubMap = struct {
    entries: std.ArrayList(MapEntry),
    allocator: std.mem.Allocator,
    next_sub_id: SubId = 1,
    queue_capacity: u64,
    metrics: ?*metrics_mod.Metrics,

    pub fn init(allocator: std.mem.Allocator, queue_capacity: u64) RPCSubMap {
        return .{
            .entries = .{},
            .allocator = allocator,
            .queue_capacity = queue_capacity,
            .metrics = null,
        };
    }

    pub fn setMetrics(self: *RPCSubMap, metrics: *metrics_mod.Metrics) void {
        self.metrics = metrics;
        self.updateSizeMetrics();
    }

    pub fn deinit(self: *RPCSubMap) void {
        for (self.entries.items) |*e| {
            e.key.deinit(self.allocator);
            e.queue.deinit();
            self.allocator.destroy(e.queue);
        }
        self.entries.deinit(self.allocator);
    }

    /// Get existing or create new entry for the given key.
    /// Heap data in `key` (logs mentions, program filters) must point to
    /// memory owned by the caller (e.g., the JSON parse tree). On match,
    /// the caller's data is not retained. On new entry, heap fields are
    /// deep-copied into the map's allocator.
    ///
    /// Queue commit path policy:
    /// - `.slot` and `.root` use `.reserved`
    /// - all other methods use `.direct`
    pub fn getOrCreate(
        self: *RPCSubMap,
        key: *const SubReqKey,
    ) !struct { sub_id: SubId, queue: *NotifQueue } {
        for (self.entries.items) |*entry| {
            if (key.eql(&entry.key)) {
                return .{ .sub_id = entry.sub_id, .queue = entry.queue };
            }
        }

        const queue = try self.allocator.create(NotifQueue);
        const commit_path: NotifQueue.CommitPath = switch (key.method) {
            .slot, .root => .reserved,
            else => .direct,
        };
        queue.* = try NotifQueue.init(self.allocator, self.queue_capacity, commit_path);
        errdefer {
            queue.deinit();
            self.allocator.destroy(queue);
        }

        const sub_id = self.next_sub_id;
        self.next_sub_id += 1;

        var owned_key = try key.clone(self.allocator);
        errdefer owned_key.deinit(self.allocator);

        try self.entries.append(self.allocator, .{
            .key = owned_key,
            .sub_id = sub_id,
            .queue = queue,
        });

        self.updateSizeMetrics();
        return .{ .sub_id = sub_id, .queue = queue };
    }

    /// Look up entry by SubId (for commit resolution).
    pub fn getById(self: *RPCSubMap, sub_id: SubId) ?MapEntry {
        for (self.entries.items) |e| {
            if (e.sub_id == sub_id) {
                return e;
            }
        }
        return null;
    }

    /// Remove entry by SubId and destroy its queue and key data.
    pub fn removeById(self: *RPCSubMap, sub_id: SubId) void {
        for (self.entries.items, 0..) |*e, i| {
            if (e.sub_id == sub_id) {
                e.key.deinit(self.allocator);
                e.queue.deinit();
                self.allocator.destroy(e.queue);
                _ = self.entries.swapRemove(i);
                self.updateSizeMetrics();
                return;
            }
        }
    }

    fn updateSizeMetrics(self: *RPCSubMap) void {
        if (self.metrics) |metrics| {
            const current: u64 = @intCast(self.entries.items.len);
            metrics.sub_map_keys_current = current;
            if (current > metrics.sub_map_keys_max) {
                metrics.sub_map_keys_max = current;
            }
        }
    }
};

test "RPCSubMap getOrCreate returns same entry for same key" {
    const allocator = std.testing.allocator;

    var sm = RPCSubMap.init(allocator, 8);
    defer sm.deinit();

    const key = SubReqKey.slotKey();
    const e1 = try sm.getOrCreate(&key);
    try std.testing.expectEqual(@as(SubId, 1), e1.sub_id);
    try std.testing.expectEqual(NotifQueue.CommitPath.reserved, e1.queue.commit_path);

    // Same key returns same entry.
    const e2 = try sm.getOrCreate(&key);
    try std.testing.expectEqual(e1.sub_id, e2.sub_id);
    try std.testing.expectEqual(e1.queue, e2.queue);
}

test "RPCSubMap different params get different entries" {
    const allocator = std.testing.allocator;
    const Pubkey = sig.core.Pubkey;

    var sm = RPCSubMap.init(allocator, 8);
    defer sm.deinit();

    var pk1: Pubkey = undefined;
    @memset(&pk1.data, 0xAA);
    var pk2: Pubkey = undefined;
    @memset(&pk2.data, 0xBB);

    const key1 = SubReqKey.accountKey(pk1);
    const key2 = SubReqKey.accountKey(pk2);
    const e1 = try sm.getOrCreate(&key1);
    const e2 = try sm.getOrCreate(&key2);
    try std.testing.expect(e1.sub_id != e2.sub_id);
    try std.testing.expectEqual(NotifQueue.CommitPath.direct, e1.queue.commit_path);
    try std.testing.expectEqual(NotifQueue.CommitPath.direct, e2.queue.commit_path);

    // Same pubkey returns same entry.
    const e3 = try sm.getOrCreate(&key1);
    try std.testing.expectEqual(e1.sub_id, e3.sub_id);
}

test "RPCSubMap logs all and mentions filters get different entries" {
    const allocator = std.testing.allocator;
    const Pubkey = sig.core.Pubkey;

    var sm = RPCSubMap.init(allocator, 8);
    defer sm.deinit();

    const all_key = SubReqKey.logsKeyAll();
    const all = try sm.getOrCreate(&all_key);

    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xCC);
    const mentions_key: SubReqKey = .{
        .method = .logs,
        .params = .{ .logs = .{
            .filter = .{ .mentions = .{ .mentions = &.{pk} } },
        } },
    };

    const mentions = try sm.getOrCreate(&mentions_key);
    try std.testing.expect(all.sub_id != mentions.sub_id);
    try std.testing.expect(all.queue != mentions.queue);

    const mentions_again = try sm.getOrCreate(&mentions_key);
    try std.testing.expectEqual(mentions.sub_id, mentions_again.sub_id);
}

test "RPCSubMap removeById and recreate gets new sub_id" {
    const allocator = std.testing.allocator;

    var sm = RPCSubMap.init(allocator, 8);
    defer sm.deinit();

    const key = SubReqKey.slotKey();
    const e1 = try sm.getOrCreate(&key);
    try std.testing.expectEqual(@as(SubId, 1), e1.sub_id);

    sm.removeById(e1.sub_id);
    try std.testing.expect(sm.getById(e1.sub_id) == null);

    const e2 = try sm.getOrCreate(&key);
    try std.testing.expectEqual(@as(SubId, 2), e2.sub_id);
}

test "RPCSubMap getById" {
    const allocator = std.testing.allocator;

    var sm = RPCSubMap.init(allocator, 8);
    defer sm.deinit();

    const slot_key = SubReqKey.slotKey();
    _ = try sm.getOrCreate(&slot_key);
    const logs_key = SubReqKey.logsKeyAll();
    const e2 = try sm.getOrCreate(&logs_key);

    const found = sm.getById(e2.sub_id);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(e2.sub_id, found.?.sub_id);
    try std.testing.expect(sm.getById(999) == null);
}

test "RPCSubMap method fanout iteration" {
    const allocator = std.testing.allocator;
    const Pubkey = sig.core.Pubkey;

    var sm = RPCSubMap.init(allocator, 8);
    defer sm.deinit();

    var pk1: Pubkey = undefined;
    @memset(&pk1.data, 0xAA);
    var pk2: Pubkey = undefined;
    @memset(&pk2.data, 0xBB);

    const account_key1 = SubReqKey.accountKey(pk1);
    const account_key2 = SubReqKey.accountKey(pk2);
    const logs_key = SubReqKey.logsKeyAll();
    _ = try sm.getOrCreate(&account_key1);
    _ = try sm.getOrCreate(&account_key2);
    _ = try sm.getOrCreate(&logs_key);

    var account_count: usize = 0;
    for (sm.entries.items) |e| {
        if (e.key.method == .account) {
            account_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), account_count);
}
