const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const DefaultRwLock = std.Thread.RwLock.DefaultRwLock;

const BytesRef = sig.ledger.database.BytesRef;
const ColumnFamily = sig.ledger.database.ColumnFamily;
const IteratorDirection = sig.ledger.database.IteratorDirection;
const Logger = sig.trace.Logger;
const SortedMap = sig.utils.collections.SortedMap;

const key_serializer = sig.ledger.database.key_serializer;
const value_serializer = sig.ledger.database.value_serializer;

pub fn SharedHashMapDB(comptime column_families: []const ColumnFamily) type {
    return struct {
        allocator: Allocator,
        maps: []SharedHashMap,
        /// shared lock is required to call locking map methods.
        /// exclusive lock is required to call non-locking map methods.
        transaction_lock: DefaultRwLock = .{},

        const Self = @This();

        pub fn open(
            allocator: Allocator,
            _: Logger,
            _: []const u8,
        ) Allocator.Error!Self {
            var maps = try allocator.alloc(SharedHashMap, column_families.len);
            errdefer {
                for (maps) |*m| m.deinit();
                allocator.free(maps);
            }
            inline for (0..column_families.len) |i| {
                maps[i] = try SharedHashMap.init(allocator);
            }
            return .{ .allocator = allocator, .maps = maps };
        }

        pub fn deinit(self: *Self, _: bool) void {
            for (self.maps) |*map| {
                map.deinit();
            }
            self.allocator.free(self.maps);
        }

        pub fn put(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
            value: cf.Value,
        ) anyerror!void {
            const key_bytes = try key_serializer.serializeAlloc(self.allocator, key);
            errdefer self.allocator.free(key_bytes);

            const val_bytes = try value_serializer.serializeAlloc(self.allocator, value);
            errdefer self.allocator.free(val_bytes);

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();

            return try self.maps[cf.find(column_families)].put(key_bytes, val_bytes);
        }

        pub fn get(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!?cf.Value {
            const key_bytes = try key_serializer.serializeAlloc(self.allocator, key);
            defer self.allocator.free(key_bytes);
            const map = &self.maps[cf.find(column_families)];

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            map.lock.lockShared();
            defer map.lock.unlockShared();

            const val_bytes = map.getPreLocked(key_bytes) orelse return null;

            return try value_serializer.deserialize(cf.Value, self.allocator, val_bytes);
        }

        pub fn getBytes(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!?BytesRef {
            const key_bytes = try key_serializer.serializeAlloc(self.allocator, key);
            defer self.allocator.free(key_bytes);
            var map = self.maps[cf.find(column_families)];

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
            key: cf.Key,
        ) anyerror!void {
            const key_bytes = try key_serializer.serializeAlloc(self.allocator, key);
            defer self.allocator.free(key_bytes);
            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            _ = self.maps[cf.find(column_families)].delete(self.allocator, key_bytes);
        }

        pub fn deleteFilesRange(
            self: *Self,
            comptime cf: ColumnFamily,
            start: cf.Key,
            end: cf.Key,
        ) anyerror!void {
            _ = self;
            _ = start;
            _ = end;
        }

        pub fn initWriteBatch(self: *Self) error{}!WriteBatch {
            return .{
                .allocator = self.allocator,
                .instructions = .{},
            };
        }

        /// Atomicity may be violated if there is insufficient
        /// memory to complete a PUT.
        pub fn commit(self: *Self, batch: WriteBatch) Allocator.Error!void {
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
                    .delete_range => {
                        // TODO
                        @panic("not implemented");
                    },
                }
            }
        }

        /// A write batch is a sequence of operations that execute atomically.
        /// This is typically called a "transaction" in most databases.
        ///
        /// Use this instead of Database.put or Database.delete when you need
        /// to ensure that a group of operations are either all executed
        /// successfully, or none of them are executed.
        ///
        /// It is called a write batch instead of a transaction because:
        /// - rocksdb uses the name "write batch" for this concept
        /// - this name avoids confusion with solana transactions
        pub const WriteBatch = struct {
            allocator: Allocator,
            instructions: std.ArrayListUnmanaged(Instruction),

            const Instruction = union(enum) {
                put: struct { usize, []const u8, []const u8 },
                delete: struct { usize, []const u8 },
                delete_range: struct { usize, []const u8, []const u8 },
            };

            fn deinit(self: WriteBatch) void {
                self.instructions.deinit(self.allocator);
            }

            pub fn put(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
                value: cf.Value,
            ) anyerror!void {
                const k_bytes = try key_serializer.serializeAlloc(self.allocator, key);
                errdefer self.allocator.free(k_bytes);
                const v_bytes = try value_serializer.serializeAlloc(self.allocator, value);
                errdefer self.allocator.free(v_bytes);
                return try self.instructions.append(
                    self.allocator,
                    .{ .put = .{ cf.find(column_families), k_bytes, v_bytes } },
                );
            }

            pub fn delete(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
            ) anyerror!void {
                const k_bytes = try key_serializer.serializeAlloc(self.allocator, key);
                errdefer self.allocator.free(k_bytes);
                return try self.instructions.append(
                    self.allocator,
                    .{ .delete = .{ cf.find(column_families), k_bytes } },
                );
            }

            pub fn deleteRange(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                start: cf.Key,
                end: cf.Key,
            ) anyerror!void {
                const start_bytes = try key_serializer.serializeAlloc(self.allocator, start);
                errdefer self.allocator.free(start_bytes);
                const end_bytes = try key_serializer.serializeAlloc(self.allocator, end);
                errdefer self.allocator.free(end_bytes);
                const cf_index = cf.find(column_families);
                self.instructions.append(
                    self.allocator,
                    .{ .delete_range = .{ cf_index, start_bytes, end_bytes } },
                );
            }
        };

        pub fn iterator(
            self: *Self,
            comptime cf: ColumnFamily,
            comptime direction: IteratorDirection,
            start: ?cf.Key,
        ) anyerror!Iterator(cf, direction) {
            const shared_map = &self.maps[cf.find(column_families)];
            const map = &shared_map.map;

            shared_map.lock.lockShared();
            defer shared_map.lock.unlockShared();

            const keys, const vals = if (start) |start_| b: {
                const search_bytes = try key_serializer.serializeAlloc(self.allocator, start_);
                defer self.allocator.free(search_bytes);
                break :b switch (direction) {
                    .forward => map.rangeCustom(.{ .inclusive = search_bytes }, null),
                    .reverse => map.rangeCustom(null, .{ .inclusive = search_bytes }),
                };
            } else map.items();
            std.debug.assert(keys.len == vals.len);

            // TODO perf: reduce copying, e.g. copy-on-write or reference counting
            const copied_keys = self.allocator.alloc([]const u8, keys.len);
            const copied_vals = self.allocator.alloc([]const u8, vals.len);
            for (0..keys.len) |i| {
                copied_keys[i] = self.allocator.dupe(u8, keys[i]);
                copied_vals[i] = self.allocator.dupe(u8, vals[i]);
            }

            return .{
                .allocator = self.allocator,
                .keys = copied_keys,
                .vals = copied_vals,
                .cursor = 0,
                .size = keys.len,
            };
        }

        pub fn Iterator(cf: ColumnFamily, direction: IteratorDirection) type {
            return struct {
                allocator: Allocator,
                keys: []const []const u8,
                vals: []const []const u8,
                cursor: usize = 0,
                size: usize,

                pub fn deinit(self: *@This()) void {
                    inline for (.{ self.keys, self.vals }) |slices| {
                        for (slices) |slice| {
                            self.allocator.free(slice);
                        }
                        self.allocator.free(slices);
                    }
                }

                pub fn next(self: *@This()) anyerror!?cf.Entry() {
                    const index = self.nextIndex() orelse return null;
                    return .{
                        key_serializer.deserialize(cf.Key, self.allocator, self.keys[index]),
                        value_serializer.deserialize(cf.Value, self.allocator, self.vals[index]),
                    };
                }

                pub fn nextKey(self: *@This()) anyerror!?cf.Key {
                    const index = self.nextIndex() orelse return null;
                    return key_serializer.deserialize(cf.Key, self.allocator, self.keys[index]);
                }

                pub fn nextValue(self: *@This()) anyerror!?cf.Value {
                    const index = self.nextIndex() orelse return null;
                    return value_serializer.deserialize(cf.Value, self.allocator, self.vals[index]);
                }

                pub fn nextBytes(self: *@This()) error{}!?[2]BytesRef {
                    const index = self.nextIndex() orelse return null;
                    return .{
                        .{ .allocator = null, .data = self.keys[index] },
                        .{ .allocator = null, .data = self.vals[index] },
                    };
                }

                fn nextIndex(self: *@This()) ?usize {
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
    try sig.ledger.database.testDatabase(SharedHashMapDB);
}
