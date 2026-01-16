const std = @import("std");
const sig = @import("../../sig.zig");
const database = @import("lib.zig");

const Allocator = std.mem.Allocator;
const RwLock = std.Thread.RwLock;

const BatchAllocator = sig.utils.allocators.BatchAllocator;
const BytesRef = database.interface.BytesRef;
const ColumnFamily = database.interface.ColumnFamily;
const DiskMemoryAllocator = sig.utils.allocators.DiskMemoryAllocator;
const IteratorDirection = database.interface.IteratorDirection;
const RcSlice = sig.sync.RcSlice;
const SortedMap = sig.utils.collections.SortedMap;

const key_serializer = database.interface.key_serializer;
const value_serializer = database.interface.value_serializer;

pub fn SharedHashMapDB(comptime column_families: []const ColumnFamily) type {
    return struct {
        /// For small amounts of metadata or ephemeral state.
        fast_allocator: Allocator,
        /// For database storage.
        storage_allocator: Allocator,
        /// Implementation for storage_allocator
        batch_allocator_state: *BatchAllocator,
        /// Backing allocator for the batch allocator
        disk_allocator_state: *DiskMemoryAllocator,
        /// Database state: one map per column family
        maps: []SharedHashMap,
        /// shared lock is required to call locking map methods.
        /// exclusive lock is required to call non-locking map methods.
        /// to avoid deadlocks, always acquire the shared lock *before* acquiring the map lock.
        transaction_lock: *RwLock,

        const Self = @This();
        pub const name: []const u8 = "SharedHashMapDB";

        pub fn open(
            allocator: Allocator,
            logger: database.interface.Logger,
            path: []const u8,
        ) anyerror!Self {
            logger.info().log("Initializing SharedHashMapDB");
            const actual_path = try std.fmt.allocPrint(allocator, "{s}/hashmapdb", .{path});
            defer allocator.free(actual_path);

            const disk_allocator = try allocator.create(DiskMemoryAllocator);
            disk_allocator.* = DiskMemoryAllocator{
                .dir = try std.fs.cwd().makeOpenPath(actual_path, .{}),
                .logger = logger.withScope(@typeName(DiskMemoryAllocator)),
                .mmap_ratio = 8,
            };
            const batch_allocator = try allocator.create(BatchAllocator);
            batch_allocator.* = BatchAllocator{
                .backing_allocator = disk_allocator.allocator(),
                .batch_size = 1 << 30,
            };

            var maps = try allocator.alloc(SharedHashMap, column_families.len);
            const lock = try allocator.create(RwLock);
            lock.* = .{};
            errdefer {
                for (maps) |*m| m.deinit();
                allocator.free(maps);
            }
            inline for (0..column_families.len) |i| {
                maps[i] = SharedHashMap.init(batch_allocator.allocator());
            }
            return .{
                .fast_allocator = allocator,
                .storage_allocator = batch_allocator.allocator(),
                .disk_allocator_state = disk_allocator,
                .batch_allocator_state = batch_allocator,
                .maps = maps,
                .transaction_lock = lock,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.maps) |*map| {
                map.deinit();
            }
            self.fast_allocator.free(self.maps);
            self.fast_allocator.destroy(self.transaction_lock);
            self.batch_allocator_state.deinit();
            self.disk_allocator_state.dir.close();
            self.fast_allocator.destroy(self.batch_allocator_state);
            self.fast_allocator.destroy(self.disk_allocator_state);
        }

        pub fn count(self: *Self, comptime cf: ColumnFamily) anyerror!u64 {
            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();

            return self.maps[cf.find(column_families)].count();
        }

        pub fn put(
            self: Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
            value: cf.Value,
        ) anyerror!void {
            const key_bytes = try key_serializer.serializeAlloc(self.storage_allocator, key);
            errdefer self.storage_allocator.free(key_bytes);

            const val_bytes = try serializeValue(self.storage_allocator, value);
            errdefer val_bytes.deinit(self.storage_allocator);

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();

            return try self.maps[cf.find(column_families)].put(key_bytes, val_bytes);
        }

        pub fn get(
            self: *Self,
            allocator: Allocator,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!?cf.Value {
            const key_bytes = try key_serializer.serializeAlloc(self.fast_allocator, key);
            defer self.fast_allocator.free(key_bytes);
            const map = &self.maps[cf.find(column_families)];

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            map.lock.lockShared();
            defer map.lock.unlockShared();

            const val_bytes = map.getPreLocked(key_bytes) orelse return null;

            return try value_serializer.deserialize(cf.Value, allocator, val_bytes.payload());
        }

        pub fn getBytes(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!?BytesRef {
            const key_bytes = try key_serializer.serializeAlloc(self.fast_allocator, key);
            defer self.fast_allocator.free(key_bytes);
            const map = &self.maps[cf.find(column_families)];

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();

            map.lock.lockShared();
            defer map.lock.unlockShared();

            const val_bytes = map.getPreLocked(key_bytes) orelse return null;

            return .{
                .deinitializer = .{ .rc_slice = self.fast_allocator },
                .data = val_bytes.acquire().payload(),
            };
        }

        pub fn contains(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!bool {
            const key_bytes = try key_serializer.serializeAlloc(self.fast_allocator, key);
            defer self.fast_allocator.free(key_bytes);
            const map = &self.maps[cf.find(column_families)];

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            map.lock.lockShared();
            defer map.lock.unlockShared();

            return map.map.contains(key_bytes);
        }

        pub fn delete(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!void {
            const key_bytes = try key_serializer.serializeAlloc(self.fast_allocator, key);
            defer self.fast_allocator.free(key_bytes);
            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            _ = self.maps[cf.find(column_families)].delete(key_bytes);
        }

        pub fn deleteFilesInRange(
            self: *Self,
            comptime cf: ColumnFamily,
            start: cf.Key,
            end: cf.Key,
        ) anyerror!void {
            _ = self;
            _ = start;
            _ = end;
        }

        pub fn initWriteBatch(self: *Self) Allocator.Error!WriteBatch {
            const executed = try self.fast_allocator.create(bool);
            executed.* = false;
            return .{
                .fast_allocator = self.fast_allocator,
                .storage_allocator = self.storage_allocator,
                .instructions = .{},
                .executed = executed,
            };
        }

        /// Atomicity may be violated if there is insufficient
        /// memory to complete a PUT.
        pub fn commit(self: *Self, batch: *WriteBatch) Allocator.Error!void {
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
                        self.maps[cf_index].delete(key);
                    },
                    .delete_range => |delete_range_ix| {
                        const cf_index, const start, const end = delete_range_ix;

                        var iter = self.maps[cf_index].map.iteratorRanged(start, end, .start);
                        var to_delete: std.ArrayListUnmanaged([]const u8) = .empty;
                        defer to_delete.deinit(batch.fast_allocator);

                        while (iter.next()) |entry| {
                            try to_delete.append(batch.fast_allocator, entry.key_ptr.*);
                        }

                        for (to_delete.items) |delete_key| {
                            self.maps[cf_index].delete(delete_key);
                        }
                    },
                }
            }
            batch.executed.* = true;
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
            fast_allocator: Allocator,
            storage_allocator: Allocator,
            instructions: std.ArrayListUnmanaged(Instruction),
            executed: *bool,

            const Instruction = union(enum) {
                put: struct { usize, []const u8, RcSlice(u8) },
                delete: struct { usize, []const u8 },
                delete_range: struct { usize, []const u8, []const u8 },
            };

            pub fn deinit(self: *WriteBatch) void {
                for (self.instructions.items) |ix| switch (ix) {
                    .put => |data| if (!self.executed.*) {
                        self.storage_allocator.free(data[1]);
                        data[2].deinit(self.storage_allocator);
                    },
                    .delete => |data| {
                        self.fast_allocator.free(data[1]);
                    },
                    .delete_range => |data| {
                        self.fast_allocator.free(data[1]);
                        self.fast_allocator.free(data[2]);
                    },
                };
                self.instructions.deinit(self.fast_allocator);
                self.fast_allocator.destroy(self.executed);
            }

            pub fn put(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
                value: cf.Value,
            ) anyerror!void {
                std.debug.assert(!self.executed.*);
                const k_bytes = try key_serializer.serializeAlloc(self.storage_allocator, key);
                errdefer self.storage_allocator.free(k_bytes);
                const v_bytes = try serializeValue(self.storage_allocator, value);
                errdefer v_bytes.deinit(self.storage_allocator);
                return try self.instructions.append(
                    self.fast_allocator,
                    .{ .put = .{ cf.find(column_families), k_bytes, v_bytes } },
                );
            }

            pub fn delete(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
            ) anyerror!void {
                std.debug.assert(!self.executed.*);
                const k_bytes = try key_serializer.serializeAlloc(self.fast_allocator, key);
                errdefer self.fast_allocator.free(k_bytes);
                return try self.instructions.append(
                    self.fast_allocator,
                    .{ .delete = .{ cf.find(column_families), k_bytes } },
                );
            }

            pub fn deleteRange(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                start: cf.Key,
                end: cf.Key,
            ) anyerror!void {
                std.debug.assert(!self.executed.*);
                const start_bytes = try key_serializer.serializeAlloc(self.fast_allocator, start);
                errdefer self.fast_allocator.free(start_bytes);
                const end_bytes = try key_serializer.serializeAlloc(self.fast_allocator, end);
                errdefer self.fast_allocator.free(end_bytes);
                const cf_index = cf.find(column_families);
                try self.instructions.append(
                    self.fast_allocator,
                    .{ .delete_range = .{ cf_index, start_bytes, end_bytes } },
                );
            }
        };

        pub fn iterator(
            self: Self,
            comptime cf: ColumnFamily,
            comptime direction: IteratorDirection,
            start: ?cf.Key,
        ) anyerror!Iterator(cf, direction) {
            const shared_map = &self.maps[cf.find(column_families)];
            const map = &shared_map.map;

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            shared_map.lock.lockShared();
            defer shared_map.lock.unlockShared();

            var iter = if (start == null)
                map.iterator()
            else switch (direction) {
                .forward => map.iteratorRanged(
                    try key_serializer.serializeAlloc(self.fast_allocator, start.?),
                    null,
                    .start,
                ),
                .reverse => map.iteratorRanged(
                    null,
                    try key_serializer.serializeAlloc(self.fast_allocator, start.?),
                    .start,
                ),
            };
            defer {
                if (iter.start) |start_bytes| self.fast_allocator.free(start_bytes);
                if (iter.end) |end_bytes| self.fast_allocator.free(end_bytes);
            }

            const len = blk: {
                var iter_copied = iter;
                break :blk iter_copied.countForwardsInclusive();
            };

            var copied_keys: std.ArrayListUnmanaged([]const u8) = try .initCapacity(self.storage_allocator, len);
            errdefer {
                for (copied_keys.items) |key| self.storage_allocator.free(key);
                copied_keys.deinit(self.storage_allocator);
            }

            var copied_vals: std.ArrayListUnmanaged(RcSlice(u8)) = try .initCapacity(self.storage_allocator, len);
            errdefer {
                for (copied_vals.items) |val| val.deinit(self.storage_allocator);
                copied_vals.deinit(self.storage_allocator);
            }

            while (iter.nextInclusive()) |entry| {
                copied_keys.appendAssumeCapacity(try self.storage_allocator.dupe(u8, entry.key_ptr.*));
                copied_vals.appendAssumeCapacity(entry.value_ptr.acquire());
            }

            return .{
                .allocator = self.fast_allocator,
                .storage_allocator = self.storage_allocator,
                .keys = try copied_keys.toOwnedSlice(self.storage_allocator),
                .vals = try copied_vals.toOwnedSlice(self.storage_allocator),
                .cursor = switch (direction) {
                    .forward => 0,
                    .reverse => len,
                },
                .size = len,
            };
        }

        pub fn Iterator(cf: ColumnFamily, direction: IteratorDirection) type {
            return struct {
                allocator: Allocator,
                storage_allocator: Allocator,
                keys: []const []const u8,
                vals: []const RcSlice(u8),
                cursor: usize = 0,
                size: usize,

                pub fn deinit(self: *@This()) void {
                    for (self.keys) |slice| {
                        self.storage_allocator.free(slice);
                    }
                    for (self.vals) |rc_slice| {
                        rc_slice.deinit(self.storage_allocator);
                    }
                    self.storage_allocator.free(self.keys);
                    self.storage_allocator.free(self.vals);
                }

                pub fn next(self: *@This()) anyerror!?cf.Entry() {
                    const index = self.nextIndex() orelse return null;
                    return .{
                        try key_serializer.deserialize(cf.Key, self.allocator, self.keys[index]),
                        try value_serializer.deserialize(
                            cf.Value,
                            self.allocator,
                            self.vals[index].payload(),
                        ),
                    };
                }

                pub fn nextKey(self: *@This()) anyerror!?cf.Key {
                    const index = self.nextIndex() orelse return null;
                    return try key_serializer.deserialize(cf.Key, self.allocator, self.keys[index]);
                }

                pub fn nextValue(self: *@This()) anyerror!?cf.Value {
                    const index = self.nextIndex() orelse return null;
                    return try value_serializer.deserialize(
                        cf.Value,
                        self.allocator,
                        self.vals[index].payload(),
                    );
                }

                pub fn nextBytes(self: *@This()) error{}!?[2]BytesRef {
                    const index = self.nextIndex() orelse return null;
                    return .{
                        .{ .deinitializer = null, .data = self.keys[index] },
                        .{ .deinitializer = null, .data = self.vals[index].payload() },
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

        pub fn flush(_: *Self, comptime _: ColumnFamily) anyerror!void {}
    };
}

fn serializeValue(allocator: Allocator, value: anytype) !RcSlice(u8) {
    const size = value_serializer.serializedSize(value);
    const rc_slice = try RcSlice(u8).alloc(allocator, size);
    std.debug.assert(size == rc_slice.payload().len);
    const written = try value_serializer.serializeToBuf(rc_slice.payload(), value);
    std.debug.assert(size == written.len);
    return rc_slice;
}

const SharedHashMap = struct {
    /// must be the same as SharedHashmapDB.storage_allocator
    allocator: Allocator,
    map: SortedMap([]const u8, RcSlice(u8), .{
        .empty_key = &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    }),
    lock: RwLock,

    const Self = @This();

    fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .map = .empty,
            .lock = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.map.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.map.deinit(self.allocator);
    }

    pub fn count(self: *Self) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.map.count();
    }

    /// value *must* be allocated with SharedHashMap.allocator
    pub fn put(self: *Self, key: []const u8, value: RcSlice(u8)) Allocator.Error!void {
        self.lock.lock();
        defer self.lock.unlock();
        const entry = try self.map.getOrPut(self.allocator, key);
        if (entry.found_existing) {
            self.allocator.free(key);
            entry.value_ptr.deinit(self.allocator);
        }
        entry.value_ptr.* = value;
    }

    /// Only call this while holding the lock
    pub fn getPreLocked(self: *Self, key: []const u8) ?RcSlice(u8) {
        return self.map.get(key) orelse return null;
    }

    pub fn delete(self: *Self, key_: []const u8) void {
        const key, const value = lock: {
            self.lock.lock();
            defer self.lock.unlock();
            const entry = self.map.fetchRemove(key_) orelse return;
            break :lock .{ entry.key, entry.value };
        };
        self.allocator.free(key);
        value.deinit(self.allocator);
    }
};

test {
    _ = &database.interface.testDatabase(SharedHashMapDB);
}
