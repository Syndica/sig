const std = @import("std");
const sig = @import("../../sig.zig");
const database = @import("lib.zig");
const build_options = @import("build-options");

const Allocator = std.mem.Allocator;
const RwLock = std.Thread.RwLock;

const BytesRef = database.interface.BytesRef;
const ColumnFamily = database.interface.ColumnFamily;
const DiskMemoryAllocator = sig.utils.allocators.DiskMemoryAllocator;
const BatchAllocator = sig.utils.allocators.BatchAllocator;
const IteratorDirection = database.interface.IteratorDirection;
const Logger = sig.trace.Logger;
const SortedMap = sig.utils.collections.SortedMap;

const key_serializer = database.interface.key_serializer;
const value_serializer = database.interface.value_serializer;

pub fn SharedHashMapDB(comptime column_families: []const ColumnFamily) type {
    return struct {
        ram_allocator: Allocator,
        disk_allocator: Allocator,
        batch_allocator_state: *BatchAllocator,
        disk_allocator_state: *DiskMemoryAllocator,
        maps: []SharedHashMap,
        /// shared lock is required to call locking map methods.
        /// exclusive lock is required to call non-locking map methods.
        /// to avoid deadlocks, always acquire the shared lock *before* acquiring the map lock.
        transaction_lock: *RwLock,

        const Self = @This();

        pub fn open(
            allocator: Allocator,
            logger: Logger,
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
                .backing_allocator = std.testing.allocator,
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
                maps[i] = try SharedHashMap.init(disk_allocator.allocator());
            }
            return .{
                .ram_allocator = allocator,
                .disk_allocator = batch_allocator.allocator(),
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
            self.ram_allocator.free(self.maps);
            self.ram_allocator.destroy(self.transaction_lock);
            self.disk_allocator_state.dir.close();
            self.ram_allocator.destroy(self.disk_allocator_state);
        }

        pub fn count(self: *Self, comptime cf: ColumnFamily) anyerror!u64 {
            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();

            return self.maps[cf.find(column_families)].count();
        }

        pub fn put(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
            value: cf.Value,
        ) anyerror!void {
            const key_bytes = try key_serializer.serializeAlloc(self.disk_allocator, key);
            errdefer self.disk_allocator.free(key_bytes);

            const val_bytes = try value_serializer.serializeAlloc(self.disk_allocator, value);
            errdefer self.disk_allocator.free(val_bytes);

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
            const key_bytes = try key_serializer.serializeAlloc(self.ram_allocator, key);
            defer self.ram_allocator.free(key_bytes);
            const map = &self.maps[cf.find(column_families)];

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            map.lock.lockShared();
            defer map.lock.unlockShared();

            const val_bytes = map.getPreLocked(key_bytes) orelse return null;

            return try value_serializer.deserialize(cf.Value, allocator, val_bytes);
        }

        pub fn getBytes(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!?BytesRef {
            const key_bytes = try key_serializer.serializeAlloc(self.ram_allocator, key);
            defer self.ram_allocator.free(key_bytes);
            var map = self.maps[cf.find(column_families)];

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            map.lock.lockShared();
            defer map.lock.unlockShared();

            const val_bytes = map.getPreLocked(key_bytes) orelse return null;

            const ret = try self.ram_allocator.alloc(u8, val_bytes.len);
            @memcpy(ret, val_bytes);
            return .{
                .deinitializer = .{ .allocator = self.ram_allocator },
                .data = ret,
            };
        }

        pub fn contains(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!bool {
            const key_bytes = try key_serializer.serializeAlloc(self.ram_allocator, key);
            defer self.ram_allocator.free(key_bytes);
            var map = self.maps[cf.find(column_families)];

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
            const key_bytes = try key_serializer.serializeAlloc(self.ram_allocator, key);
            defer self.ram_allocator.free(key_bytes);
            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            _ = self.maps[cf.find(column_families)].delete(self.disk_allocator, key_bytes);
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
            const executed = try self.ram_allocator.create(bool);
            executed.* = false;
            return .{
                .ram_allocator = self.ram_allocator,
                .disk_allocator = self.disk_allocator,
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
                        self.maps[cf_index].delete(self.disk_allocator, key);
                    },
                    .delete_range => |delete_range_ix| {
                        const cf_index, const start, const end = delete_range_ix;
                        const keys, _ = self.maps[cf_index].map.range(start, end);
                        const to_delete = try batch.ram_allocator.alloc([]const u8, keys.len);
                        defer batch.ram_allocator.free(to_delete);
                        for (keys, 0..) |key, i| {
                            to_delete[i] = key;
                        }
                        for (to_delete) |delete_key| {
                            self.maps[cf_index].delete(self.disk_allocator, delete_key);
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
            ram_allocator: Allocator,
            disk_allocator: Allocator,
            instructions: std.ArrayListUnmanaged(Instruction),
            executed: *bool,

            const Instruction = union(enum) {
                put: struct { usize, []const u8, []const u8 },
                delete: struct { usize, []const u8 },
                delete_range: struct { usize, []const u8, []const u8 },
            };

            pub fn deinit(self: *WriteBatch) void {
                for (self.instructions.items) |ix| switch (ix) {
                    .put => |data| if (!self.executed.*) {
                        self.disk_allocator.free(data[1]);
                        self.disk_allocator.free(data[2]);
                    },
                    .delete => |data| {
                        self.ram_allocator.free(data[1]);
                    },
                    .delete_range => |data| {
                        self.ram_allocator.free(data[1]);
                        self.ram_allocator.free(data[2]);
                    },
                };
                self.instructions.deinit(self.ram_allocator);
                self.ram_allocator.destroy(self.executed);
            }

            pub fn put(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
                value: cf.Value,
            ) anyerror!void {
                std.debug.assert(!self.executed.*);
                const k_bytes = try key_serializer.serializeAlloc(self.disk_allocator, key);
                errdefer self.disk_allocator.free(k_bytes);
                const v_bytes = try value_serializer.serializeAlloc(self.disk_allocator, value);
                errdefer self.disk_allocator.free(v_bytes);
                return try self.instructions.append(
                    self.ram_allocator,
                    .{ .put = .{ cf.find(column_families), k_bytes, v_bytes } },
                );
            }

            pub fn delete(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
            ) anyerror!void {
                std.debug.assert(!self.executed.*);
                const k_bytes = try key_serializer.serializeAlloc(self.ram_allocator, key);
                errdefer self.ram_allocator.free(k_bytes);
                return try self.instructions.append(
                    self.ram_allocator,
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
                const start_bytes = try key_serializer.serializeAlloc(self.ram_allocator, start);
                errdefer self.ram_allocator.free(start_bytes);
                const end_bytes = try key_serializer.serializeAlloc(self.ram_allocator, end);
                errdefer self.ram_allocator.free(end_bytes);
                const cf_index = cf.find(column_families);
                try self.instructions.append(
                    self.ram_allocator,
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

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            shared_map.lock.lockShared();
            defer shared_map.lock.unlockShared();

            const keys, const vals = if (start) |start_| b: {
                const search_bytes = try key_serializer.serializeAlloc(self.ram_allocator, start_);
                defer self.ram_allocator.free(search_bytes);
                break :b switch (direction) {
                    .forward => map.rangeCustom(.{ .inclusive = search_bytes }, null),
                    .reverse => map.rangeCustom(null, .{ .inclusive = search_bytes }),
                };
            } else map.items();
            std.debug.assert(keys.len == vals.len);

            // TODO perf: reduce copying, e.g. copy-on-write or reference counting
            const copied_keys = try self.disk_allocator.alloc([]const u8, keys.len);
            errdefer self.disk_allocator.free(copied_keys);
            const copied_vals = try self.disk_allocator.alloc([]const u8, vals.len);
            errdefer self.disk_allocator.free(copied_vals);
            for (0..keys.len) |i| {
                errdefer for (0..i) |n| {
                    self.disk_allocator.free(copied_keys[n]);
                    self.disk_allocator.free(copied_vals[n]);
                };
                copied_keys[i] = try self.disk_allocator.dupe(u8, keys[i]);
                errdefer self.disk_allocator.free(copied_keys[i]);
                copied_vals[i] = try self.disk_allocator.dupe(u8, vals[i]);
            }

            return .{
                .allocator = self.ram_allocator,
                .storage_allocator = self.disk_allocator,
                .keys = copied_keys,
                .vals = copied_vals,
                .cursor = switch (direction) {
                    .forward => 0,
                    .reverse => keys.len,
                },
                .size = keys.len,
            };
        }

        pub fn Iterator(cf: ColumnFamily, direction: IteratorDirection) type {
            return struct {
                allocator: Allocator,
                storage_allocator: Allocator,
                keys: []const []const u8,
                vals: []const []const u8,
                cursor: usize = 0,
                size: usize,

                pub fn deinit(self: *@This()) void {
                    inline for (.{ self.keys, self.vals }) |slices| {
                        for (slices) |slice| {
                            self.storage_allocator.free(slice);
                        }
                        self.storage_allocator.free(slices);
                    }
                }

                pub fn next(self: *@This()) anyerror!?cf.Entry() {
                    const index = self.nextIndex() orelse return null;
                    return .{
                        try key_serializer.deserialize(cf.Key, self.allocator, self.keys[index]),
                        try value_serializer.deserialize(cf.Value, self.allocator, self.vals[index]),
                    };
                }

                pub fn nextKey(self: *@This()) anyerror!?cf.Key {
                    const index = self.nextIndex() orelse return null;
                    return try key_serializer.deserialize(cf.Key, self.allocator, self.keys[index]);
                }

                pub fn nextValue(self: *@This()) anyerror!?cf.Value {
                    const index = self.nextIndex() orelse return null;
                    return try value_serializer.deserialize(cf.Value, self.allocator, self.vals[index]);
                }

                pub fn nextBytes(self: *@This()) error{}!?[2]BytesRef {
                    const index = self.nextIndex() orelse return null;
                    return .{
                        .{ .deinitializer = null, .data = self.keys[index] },
                        .{ .deinitializer = null, .data = self.vals[index] },
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
    lock: RwLock = .{},

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

    pub fn count(self: *Self) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.map.count();
    }

    pub fn put(self: *Self, key: []const u8, value: []const u8) Allocator.Error!void {
        self.lock.lock();
        defer self.lock.unlock();
        const entry = try self.map.getOrPut(key);
        if (entry.found_existing) {
            self.allocator.free(key);
            self.allocator.free(entry.value_ptr.*);
        }
        entry.value_ptr.* = value;
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

comptime {
    _ = &database.interface.testDatabase(SharedHashMapDB);
}
