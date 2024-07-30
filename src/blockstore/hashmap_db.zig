const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const DefaultRwLock = std.Thread.RwLock.DefaultRwLock;

const BytesRef = sig.blockstore.database.BytesRef;
const ColumnFamily = sig.blockstore.database.ColumnFamily;
const Database = sig.blockstore.database.Database;
const IteratorDirection = sig.blockstore.database.IteratorDirection;
const Logger = sig.trace.Logger;
const SortedMap = sig.utils.collections.SortedMap;

const find = sig.utils.collections.find;

pub const SharedHashMapDB = struct {
    allocator: Allocator,
    maps: []SharedHashMap,
    /// shared lock is required to call locking map methods.
    /// exclusive lock is required to call non-locking map methods.
    transaction_lock: DefaultRwLock = .{},

    const Self = @This();

    pub const Batch = MapBatch;
    pub const Iterator = MapIterator;

    pub fn open(
        allocator: Allocator,
        _: Logger,
        _: []const u8,
        column_families: []const ColumnFamily,
    ) !SharedHashMapDB {
        var maps = try allocator.alloc(SharedHashMap, column_families.len);
        errdefer allocator.free(maps);
        errdefer for (maps) |*m| m.deinit();
        inline for (0..column_families.len) |i| {
            maps[i] = try SharedHashMap.init(allocator);
        }
        return .{ .allocator = allocator, .maps = maps };
    }

    pub fn deinit(self_: Self) void {
        var self = self_;
        for (self.maps) |*map_| {
            map_.deinit();
        }
        self.allocator.free(self.maps);
    }

    pub fn put(
        self: *Self,
        comptime cf: ColumnFamily,
        cf_index: usize,
        key: cf.Key,
        value: cf.Value,
    ) !void {
        const key_bytes = try cf.key().serializeAlloc(self.allocator, key);
        errdefer self.allocator.free(key_bytes);
        const val_bytes = try cf.value().serializeAlloc(self.allocator, value);
        errdefer self.allocator.free(val_bytes);
        self.transaction_lock.lockShared();
        defer self.transaction_lock.unlockShared();
        return try self.maps[cf_index].put(key_bytes, val_bytes);
    }

    pub fn get(
        self: *Self,
        comptime cf: ColumnFamily,
        cf_index: usize,
        key: cf.Key,
    ) !?cf.Value {
        const key_bytes = try cf.key().serializeAlloc(self.allocator, key);
        defer self.allocator.free(key_bytes);
        const map = &self.maps[cf_index];

        self.transaction_lock.lockShared();
        defer self.transaction_lock.unlockShared();
        map.lock.lockShared();
        defer map.lock.unlockShared();

        const val_bytes = map.getPreLocked(key_bytes) orelse return null;

        return try cf.value().deserialize(cf.Value, self.allocator, val_bytes);
    }

    pub fn getBytes(
        self: *Self,
        comptime cf: ColumnFamily,
        cf_index: usize,
        key: cf.Key,
    ) !?BytesRef {
        const key_bytes = try cf.key().serializeAlloc(self.allocator, key);
        defer self.allocator.free(key_bytes);
        var map = self.maps[cf_index];

        self.transaction_lock.lockShared();
        defer self.transaction_lock.unlockShared();
        map.lock.lockShared();
        defer map.lock.unlockShared();

        const val_bytes = map.getPreLocked(key_bytes) orelse return null;

        const ret = try self.allocator.alloc(u8, val_bytes.len);
        @memcpy(ret, val_bytes);
        return .{
            .allocator = self.allocator,
            .data = ret,
        };
    }

    pub fn delete(
        self: *Self,
        comptime cf: ColumnFamily,
        cf_index: usize,
        key: cf.Key,
    ) !void {
        const key_bytes = try cf.key().serializeAlloc(self.allocator, key);
        defer self.allocator.free(key_bytes);
        self.transaction_lock.lockShared();
        defer self.transaction_lock.unlockShared();
        _ = self.maps[cf_index].delete(self.allocator, key_bytes);
    }

    pub fn writeBatch(self: *Self) MapBatch {
        return .{
            .allocator = self.allocator,
            .instructions = .{},
        };
    }

    pub fn initBatch(self: *Self) MapBatch {
        return MapBatch.init(self.allocator);
    }

    /// Atomicity may be violated if there is insufficient
    /// memory to complete a PUT.
    pub fn commit(self: *Self, batch: MapBatch) !void {
        self.transaction_lock.lock();
        defer self.transaction_lock.unlock();

        for (batch.instructions.items) |ix| {
            switch (ix) {
                .put => |put_ix| {
                    const cf_index, const key, const value = put_ix;
                    try self.maps[cf_index].put(key, value);
                },
                .delete => |delete_ix| {
                    const cf_index, const key = delete_ix;
                    self.maps[cf_index].delete(batch.allocator, key);
                },
            }
        }
    }

    pub fn iterator(
        self: *Self,
        comptime cf: ColumnFamily,
        cf_index: usize,
        comptime direction: IteratorDirection,
        start: ?cf.Key,
    ) !Iterator(cf, direction) {
        const map = &self.maps[cf_index].map;
        const keys, const values = if (start) |start_| b: {
            const search_bytes = try cf.key().serializeAlloc(self.allocator, start_);
            defer self.allocator.free(search_bytes);
            break :b switch (direction) {
                .forward => map.rangeCustom(.{ .inclusive = search_bytes }, null),
                .reverse => map.rangeCustom(null, .{ .inclusive = search_bytes }),
            };
        } else map.items();
        std.debug.assert(keys.len == values.len);

        return .{
            .allocator = self.allocator,
            .keys = keys,
            .vals = values,
            .cursor = 0,
            .size = keys.len,
        };
    }
};

pub const MapBatch = struct {
    allocator: Allocator,
    instructions: std.ArrayListUnmanaged(Instruction),

    const Instruction = union(enum) {
        put: struct { usize, []const u8, []const u8 },
        delete: struct { usize, []const u8 },
    };

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .instructions = std.ArrayListUnmanaged(Instruction){},
        };
    }

    pub fn deinit(self: Self) void {
        self.instructions.deinit(self.allocator);
    }

    pub fn put(
        self: *Self,
        comptime cf: ColumnFamily,
        cf_index: usize,
        key: cf.Key,
        value: cf.Value,
    ) !void {
        const k_bytes = try cf.key().serializeAlloc(self.allocator, key);
        errdefer self.allocator.free(k_bytes);
        const v_bytes = try cf.value().serializeAlloc(self.allocator, value);
        errdefer self.allocator.free(v_bytes);
        return try self.instructions.append(
            self.allocator,
            .{ .put = .{ cf_index, k_bytes, v_bytes } },
        );
    }

    pub fn delete(
        self: *Self,
        comptime cf: ColumnFamily,
        cf_index: usize,
        key: cf.Key,
    ) !void {
        const k_bytes = try cf.key().serializeAlloc(self.allocator, key);
        errdefer self.allocator.free(k_bytes);
        return try self.instructions.append(
            self.allocator,
            .{ .delete = .{ cf_index, k_bytes } },
        );
    }
};

fn MapIterator(
    cf: ColumnFamily,
    direction: IteratorDirection,
) type {
    return struct {
        allocator: Allocator,
        keys: []const []const u8,
        vals: []const []const u8,
        cursor: usize = 0,
        size: usize,

        pub fn nextBytes(self: *@This()) !?struct { cf.Key, []const u8 } {
            const index = try self.nextIndex() orelse return null;
            return .{
                try cf.key().deserialize(cf.Key, self.allocator, self.keys[index]),
                self.vals[index],
            };
        }

        fn nextIndex(self: *@This()) !?usize {
            switch (direction) {
                .forward => if (self.cursor >= self.size) return null,
                .reverse => if (self.cursor == 0) return null else {
                    self.cursor -= 1;
                },
            }
            defer if (direction == .forward) {
                self.cursor += 1;
            };
            return self.cursor;
        }
    };
}

const SharedHashMap = struct {
    allocator: Allocator,
    map: SortedMap([]const u8, []const u8),
    lock: DefaultRwLock = .{},

    const Self = @This();

    fn init(allocator: Allocator) Allocator.Error!Self {
        return .{
            .allocator = allocator,
            .map = SortedMap([]const u8, []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        const keys, const values = self.map.items();
        for (keys, values) |key, value| {
            self.allocator.free(key);
            self.allocator.free(value);
        }
        self.map.deinit();
    }

    pub fn free(self: Self, bytes: []const u8) void {
        self.allocator.free(bytes);
    }

    pub fn put(self: *Self, key: []const u8, value: []const u8) Allocator.Error!void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.map.put(key, value);
    }

    /// Only call this while holding the lock
    pub fn getPreLocked(self: *Self, key: []const u8) ?[]const u8 {
        return self.map.get(key) orelse return null;
    }

    pub fn delete(self: *Self, liberator: Allocator, key_: []const u8) void {
        const key, const value = lock: {
            self.lock.lock();
            defer self.lock.unlock();
            const entry = self.map.fetchSwapRemove(key_) orelse return;
            break :lock .{ entry.key, entry.value };
        };
        liberator.free(key);
        liberator.free(value);
    }
};

test "hashmap database" {
    try Database(SharedHashMapDB, &.{}).runTest();
}
