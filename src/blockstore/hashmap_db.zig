const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const DefaultRwLock = std.Thread.RwLock.DefaultRwLock;

const BytesRef = sig.blockstore.database.BytesRef;
const ColumnFamily = sig.blockstore.database.ColumnFamily;
const Logger = sig.trace.Logger;

const serializeAlloc = sig.blockstore.database.serializer.serializeAlloc;
const deserialize = sig.blockstore.database.serializer.deserialize;

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

        pub fn deinit(self: *Self) void {
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
        ) Allocator.Error!void {
            const key_bytes = try serializeAlloc(self.allocator, key);
            errdefer self.allocator.free(key_bytes);

            const val_bytes = try serializeAlloc(self.allocator, value);
            errdefer self.allocator.free(val_bytes);

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();

            return try self.maps[cf.find(column_families)].put(key_bytes, val_bytes);
        }

        pub fn get(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) Allocator.Error!?cf.Value {
            const key_bytes = try serializeAlloc(self.allocator, key);
            defer self.allocator.free(key_bytes);
            const map = &self.maps[cf.find(column_families)];

            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            map.lock.lockShared();
            defer map.lock.unlockShared();

            const val_bytes = map.getPreLocked(key_bytes) orelse return null;

            return try deserialize(cf.Value, self.allocator, val_bytes);
        }

        pub fn getBytes(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) Allocator.Error!?BytesRef {
            const key_bytes = try serializeAlloc(self.allocator, key);
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
        ) Allocator.Error!void {
            const key_bytes = try serializeAlloc(self.allocator, key);
            defer self.allocator.free(key_bytes);
            self.transaction_lock.lockShared();
            defer self.transaction_lock.unlockShared();
            _ = self.maps[cf.find(column_families)].delete(self.allocator, key_bytes);
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
            };

            fn deinit(self: WriteBatch) void {
                self.instructions.deinit(self.allocator);
            }

            pub fn put(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
                value: cf.Value,
            ) Allocator.Error!void {
                const k_bytes = try serializeAlloc(self.allocator, key);
                errdefer self.allocator.free(k_bytes);
                const v_bytes = try serializeAlloc(self.allocator, value);
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
            ) Allocator.Error!void {
                const k_bytes = try serializeAlloc(self.allocator, key);
                errdefer self.allocator.free(k_bytes);
                return try self.instructions.append(
                    self.allocator,
                    .{ .delete = .{ cf.find(column_families), k_bytes } },
                );
            }
        };
    };
}

const SharedHashMap = struct {
    allocator: Allocator,
    map: std.StringHashMapUnmanaged([]const u8) = .{},
    lock: DefaultRwLock = .{},

    const Self = @This();

    fn init(allocator: Allocator) Allocator.Error!Self {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.map.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit(self.allocator);
    }

    pub fn put(self: *Self, key: []const u8, value: []const u8) Allocator.Error!void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.map.put(self.allocator, key, value);
    }

    /// Only call this while holding the lock
    pub fn getPreLocked(self: *Self, key: []const u8) ?[]const u8 {
        return self.map.get(key) orelse return null;
    }

    pub fn delete(self: *Self, liberator: Allocator, key_: []const u8) void {
        const key, const value = lock: {
            self.lock.lock();
            defer self.lock.unlock();
            const entry = self.map.getEntry(key_) orelse return;
            const key = entry.key_ptr.*;
            const val = entry.value_ptr.*;
            defer self.map.removeByPtr(entry.key_ptr);
            break :lock .{ key, val };
        };
        liberator.free(key);
        liberator.free(value);
    }
};

test "hashmap database" {
    sig.blockstore.database.testDatabase(SharedHashMapDB);
}
