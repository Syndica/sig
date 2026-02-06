const std = @import("std");
const sig = @import("../../sig.zig");
const ledger = @import("../lib.zig");

const Allocator = std.mem.Allocator;

pub const Logger = sig.trace.Logger("ledger.database");

pub fn assertIsDatabase(comptime Impl: type) void {
    sig.utils.interface.assertSameInterface(Database(Impl), Impl, .subset);
    sig.utils.interface.assertSameInterface(Database(Impl).WriteBatch, Impl.WriteBatch, .subset);
    const dummy_cf = ColumnFamily{ .name = "", .Key = void, .Value = void };
    sig.utils.interface.assertSameInterface(
        Database(Impl).Iterator(dummy_cf, .forward),
        Impl.Iterator(dummy_cf, .forward),
        .subset,
    );
}

/// Interface defining the ledger's dependency on a database
pub fn Database(comptime Impl: type) type {
    return struct {
        impl: Impl,

        const Self = @This();
        pub const name: []const u8 = Impl.name;

        pub fn open(
            allocator: Allocator,
            logger: Logger,
            path: []const u8,
            read_only: bool,
        ) anyerror!Database(Impl) {
            return .{
                .impl = try Impl.open(allocator, logger, path, read_only),
            };
        }

        pub fn deinit(self: *Self) void {
            self.impl.deinit();
        }

        pub fn count(self: *Self, comptime cf: ColumnFamily) anyerror!u64 {
            return self.impl.count(cf);
        }

        pub fn put(
            self: Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
            value: cf.Value,
        ) anyerror!void {
            return try self.impl.put(cf, key, value);
        }

        // TODO: split into two methods: get and getAlloc, where "get" is used for
        //       types that do not need an allocator to deserialize them.
        //       this will need some changes to bincode.
        pub fn get(
            self: *Self,
            allocator: Allocator,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!?cf.Value {
            return try self.impl.get(allocator, cf, key);
        }

        /// Returns a reference to the serialized bytes.
        ///
        /// This is useful in two situations:
        ///
        /// 1. You don't plan to deserialize the data, and just need the bytes.
        ///
        /// 2. `cf.Value` is []const u8, and you don't need an owned slice. In this
        ///    case, getBytes is faster than get. But if you *do* need an owned slice,
        ///    then it's faster to call `get` insted of calling this function followed
        ///    by memcpy.
        pub fn getBytes(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!?BytesRef {
            return try self.impl.getBytes(cf, key);
        }

        pub fn contains(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!bool {
            return try self.impl.contains(cf, key);
        }

        pub fn delete(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!void {
            return try self.impl.delete(cf, key);
        }

        pub fn deleteFilesInRange(
            self: *Self,
            comptime cf: ColumnFamily,
            start: cf.Key,
            end: cf.Key,
        ) anyerror!void {
            return try self.impl.deleteFilesInRange(cf, start, end);
        }

        pub fn initWriteBatch(self: *Self) anyerror!WriteBatch {
            return .{ .impl = try self.impl.initWriteBatch() };
        }

        pub fn commit(self: *Self, batch: *WriteBatch) anyerror!void {
            return self.impl.commit(&batch.impl);
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
            impl: Impl.WriteBatch,

            pub fn deinit(self: *WriteBatch) void {
                self.impl.deinit();
            }

            pub fn put(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
                value: cf.Value,
            ) anyerror!void {
                return try self.impl.put(cf, key, value);
            }

            pub fn delete(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
            ) anyerror!void {
                return try self.impl.delete(cf, key);
            }

            pub fn deleteRange(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                start: cf.Key,
                end: cf.Key,
            ) anyerror!void {
                return try self.impl.deleteRange(cf, start, end);
            }
        };

        pub fn iterator(
            self: Self,
            comptime cf: ColumnFamily,
            comptime direction: IteratorDirection,
            start: ?cf.Key,
        ) anyerror!Iterator(cf, direction) {
            return .{ .impl = try self.impl.iterator(cf, direction, start) };
        }

        pub fn Iterator(cf: ColumnFamily, direction: IteratorDirection) type {
            return struct {
                impl: Impl.Iterator(cf, direction),

                pub fn deinit(self: *@This()) void {
                    return self.impl.deinit();
                }

                pub fn next(self: *@This()) anyerror!?cf.Entry() {
                    return try self.impl.next();
                }

                pub fn nextKey(self: *@This()) anyerror!?cf.Key {
                    return try self.impl.nextKey();
                }

                pub fn nextValue(self: *@This()) anyerror!?cf.Value {
                    return try self.impl.nextValue();
                }

                pub fn nextBytes(self: *@This()) anyerror!?[2]BytesRef {
                    return try self.impl.nextBytes();
                }
            };
        }

        pub fn flush(self: *Self, comptime cf: ColumnFamily) anyerror!void {
            self.impl.flush(cf);
        }
    };
}

pub const IteratorDirection = enum { forward, reverse };

pub const ColumnFamily = struct {
    name: [:0]const u8,
    Key: type,
    Value: type,

    const Self = @This();

    pub fn Entry(self: Self) type {
        return struct { self.Key, self.Value };
    }

    /// At comptime, find this family in a slice. Useful for for fast runtime
    /// accesses of data in other slices that are one-to-one with this slice.
    pub fn find(comptime self: Self, comptime column_families: []const Self) comptime_int {
        for (column_families, 0..) |column_family, i| {
            if (std.mem.eql(u8, column_family.name, self.name)) {
                return i;
            }
        }
        @compileError("not found");
    }
};

pub const key_serializer = serializer(.big);
pub const value_serializer = serializer(.little);

/// Bincode-based serializer that should be usable by database implementations.
fn serializer(endian: std.builtin.Endian) type {
    return struct {
        /// Returned slice is owned by the caller. Free with `allocator.free`.
        pub fn serializeAlloc(allocator: Allocator, item: anytype) ![]const u8 {
            if (@TypeOf(item) == []const u8 or @TypeOf(item) == []u8) {
                return try allocator.dupe(u8, item);
            } else {
                const buf = try allocator.alloc(u8, sig.bincode.sizeOf(item, .{}));
                return sig.bincode.writeToSlice(buf, item, .{ .endian = endian });
            }
        }

        pub fn serializeToBuf(buf: []u8, item: anytype) ![]const u8 {
            if (@TypeOf(item) == []const u8 or @TypeOf(item) == []u8) {
                @memcpy(buf, item);
                return buf;
            } else {
                return sig.bincode.writeToSlice(buf, item, .{ .endian = endian });
            }
        }

        pub fn serializedSize(item: anytype) usize {
            return if (@TypeOf(item) == []const u8 or @TypeOf(item) == []u8)
                item.len
            else
                sig.bincode.sizeOf(item, .{});
        }

        /// Returned data may or may not be owned by the caller.
        /// Do both:
        ///  - Assume the data is owned by the scope where `item` originated,
        ///    so finish using the slice before returning from the caller (do not store slice as-is)
        ///  - Call BytesRef.deinit before returning from the caller (as if you own it).
        ///
        /// Use this if the database backend accepts a pointer and immediately calls memcpy.
        pub fn serializeToRef(allocator: Allocator, item: anytype) !BytesRef {
            return if (@TypeOf(item) == []const u8 or @TypeOf(item) == []u8) .{
                .deinitializer = null,
                .data = item,
            } else .{
                .deinitializer = .{ .allocator = allocator },
                .data = try serializeAlloc(allocator, item),
            };
        }

        /// Returned data is owned by the caller. Free with `allocator.free`.
        pub fn deserialize(comptime T: type, allocator: Allocator, bytes: []const u8) !T {
            comptime if (T == []const u8 or T == []u8) {
                // it's probably a mistake to call deserialize in this case because it would
                // need to memcpy the bytes to satisfy the ownership contract, but that's
                // probably not what you actually want, since it is wasteful. so this is
                // currently not supported, just to avoid mistakes. if needed, it can be
                // implemented with memcpy, or by writing a separate function that explicitly
                // returns references.
                @compileError("not supported");
            };
            return try sig.bincode.readFromSlice(allocator, T, bytes, .{ .endian = endian });
        }
    };
}

pub const BytesRef = struct {
    data: []const u8,
    deinitializer: ?Deinitializer = null,

    pub fn deinit(self: BytesRef) void {
        if (self.deinitializer) |d| d.deinit(self.data);
    }

    pub fn clone(self: BytesRef, allocator: Allocator) Allocator.Error!BytesRef {
        return .{
            .data = try allocator.dupe(u8, self.data),
            .deinitializer = .{ .allocator = allocator },
        };
    }

    pub const Deinitializer = union(enum) {
        allocator: Allocator,
        rocksdb: *const fn (?*anyopaque) callconv(.c) void,
        rc_slice: Allocator,

        pub fn deinit(self: Deinitializer, data: []const u8) void {
            switch (self) {
                .allocator => |allocator| allocator.free(data),
                .rocksdb => |func| func(@ptrCast(@constCast(data))),
                .rc_slice => |allocator| sig.sync.RcSlice(u8).fromPayload(data).deinit(allocator),
            }
        }
    };
};

/// Test cases that can be applied to any implementation of Database
pub fn testDatabase(comptime Impl: fn ([]const ColumnFamily) type) type {
    const T = Impl(&.{});
    assertIsDatabase(T);

    @setEvalBranchQuota(10_000);
    const test_dir = sig.TEST_STATE_DIR ++ "ledger/database/" ++ T.name ++ "/";

    const Value1 = struct { hello: u16 };
    const Value2 = struct { world: u16 };
    const cf1 = ColumnFamily{
        .name = "one",
        .Key = u64,
        .Value = Value1,
    };
    const cf2 = ColumnFamily{
        .name = "two",
        .Key = u64,
        .Value = Value2,
    };
    const DB = Database(Impl(&.{ cf1, cf2 }));

    return struct {
        test "basic" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 123, .{ .hello = 345 });
            const got = try db.get(allocator, cf1, 123);
            try std.testing.expect(345 == got.?.hello);
            const not = try db.get(allocator, cf2, 123);
            try std.testing.expect(null == not);
            const wrong_was_deleted = try db.delete(cf2, 123);
            _ = wrong_was_deleted;
            // try std.testing.expect(!wrong_was_deleted); // FIXME
            const was_deleted = try db.delete(cf1, 123);
            _ = was_deleted;
            // try std.testing.expect(was_deleted);
            const not_now = try db.get(allocator, cf1, 123);
            try std.testing.expect(null == not_now);
        }

        test "write batch" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 0, .{ .hello = 99 });

            var batch = try db.initWriteBatch();
            defer batch.deinit();

            try batch.delete(cf1, 0);
            try batch.put(cf1, 123, .{ .hello = 100 });
            try batch.put(cf2, 321, .{ .world = 444 });
            try batch.delete(cf2, 321);
            try batch.put(cf2, 133, .{ .world = 555 });
            try batch.put(cf2, 133, .{ .world = 666 });

            try std.testing.expectEqual(Value1{ .hello = 99 }, try db.get(allocator, cf1, 0));
            try std.testing.expectEqual(null, try db.get(allocator, cf1, 123));
            try std.testing.expectEqual(null, try db.get(allocator, cf2, 321));
            try std.testing.expectEqual(null, try db.get(allocator, cf2, 333));

            try db.commit(&batch);

            try std.testing.expectEqual(null, try db.get(allocator, cf1, 0));
            try std.testing.expectEqual(Value1{ .hello = 100 }, try db.get(allocator, cf1, 123));
            try std.testing.expectEqual(null, try db.get(allocator, cf2, 321));
            try std.testing.expectEqual(Value2{ .world = 666 }, try db.get(allocator, cf2, 133));
        }

        test "iterator forward" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 4, .{ .hello = 44 });
            try db.put(cf1, 1, .{ .hello = 111 });
            try db.put(cf1, 3, .{ .hello = 33 });
            try db.put(cf1, 2, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .forward, null);
            defer iter.deinit();

            var next = (try iter.next()).?;
            try std.testing.expectEqual(1, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 111 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(2, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 222 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(3, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 33 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(4, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 44 }, next[1]);

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator forward start exact" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 40, .{ .hello = 44 });
            try db.put(cf1, 10, .{ .hello = 111 });
            try db.put(cf1, 30, .{ .hello = 33 });
            try db.put(cf1, 20, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .forward, 20);
            defer iter.deinit();

            var next = (try iter.next()).?;
            try std.testing.expectEqual(20, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 222 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(30, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 33 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(40, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 44 }, next[1]);

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator forward start between" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 40, .{ .hello = 44 });
            try db.put(cf1, 10, .{ .hello = 111 });
            try db.put(cf1, 30, .{ .hello = 33 });
            try db.put(cf1, 20, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .forward, 11);
            defer iter.deinit();

            var next = (try iter.next()).?;
            try std.testing.expectEqual(20, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 222 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(30, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 33 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(40, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 44 }, next[1]);

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator reverse" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 4, .{ .hello = 44 });
            try db.put(cf1, 1, .{ .hello = 111 });
            try db.put(cf1, 3, .{ .hello = 33 });
            try db.put(cf1, 2, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .reverse, null);
            defer iter.deinit();

            var next = (try iter.next()).?;
            try std.testing.expectEqual(4, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 44 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(3, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 33 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(2, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 222 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(1, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 111 }, next[1]);

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator reverse start at end" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 4, .{ .hello = 44 });
            try db.put(cf1, 1, .{ .hello = 111 });
            try db.put(cf1, 3, .{ .hello = 33 });
            try db.put(cf1, 2, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .reverse, 4);
            defer iter.deinit();

            var next = (try iter.next()).?;
            try std.testing.expectEqual(4, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 44 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(3, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 33 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(2, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 222 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(1, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 111 }, next[1]);

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator reverse start exact" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 40, .{ .hello = 44 });
            try db.put(cf1, 10, .{ .hello = 111 });
            try db.put(cf1, 30, .{ .hello = 33 });
            try db.put(cf1, 20, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .reverse, 30);
            defer iter.deinit();

            var next = (try iter.next()).?;
            try std.testing.expectEqual(30, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 33 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(20, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 222 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(10, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 111 }, next[1]);

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator reverse start between" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 40, .{ .hello = 44 });
            try db.put(cf1, 10, .{ .hello = 111 });
            try db.put(cf1, 30, .{ .hello = 33 });
            try db.put(cf1, 20, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .reverse, 39);
            defer iter.deinit();

            var next = (try iter.next()).?;
            try std.testing.expectEqual(30, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 33 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(20, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 222 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(10, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 111 }, next[1]);

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator forward start before all" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 40, .{ .hello = 44 });
            try db.put(cf1, 10, .{ .hello = 111 });
            try db.put(cf1, 30, .{ .hello = 33 });
            try db.put(cf1, 20, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .forward, 5);
            defer iter.deinit();

            var next = (try iter.next()).?;
            try std.testing.expectEqual(10, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 111 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(20, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 222 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(30, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 33 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(40, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 44 }, next[1]);

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator forward start after all" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 40, .{ .hello = 44 });
            try db.put(cf1, 10, .{ .hello = 111 });
            try db.put(cf1, 30, .{ .hello = 33 });
            try db.put(cf1, 20, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .forward, 50);
            defer iter.deinit();

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator reverse start before all" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 40, .{ .hello = 44 });
            try db.put(cf1, 10, .{ .hello = 111 });
            try db.put(cf1, 30, .{ .hello = 33 });
            try db.put(cf1, 20, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .reverse, 50);
            defer iter.deinit();

            var next = (try iter.next()).?;
            try std.testing.expectEqual(40, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 44 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(30, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 33 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(20, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 222 }, next[1]);
            next = (try iter.next()).?;
            try std.testing.expectEqual(10, next[0]);
            try std.testing.expectEqual(Value1{ .hello = 111 }, next[1]);

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator reverse start after all" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 40, .{ .hello = 44 });
            try db.put(cf1, 10, .{ .hello = 111 });
            try db.put(cf1, 30, .{ .hello = 33 });
            try db.put(cf1, 20, .{ .hello = 222 });

            var iter = try db.iterator(cf1, .reverse, 5);
            defer iter.deinit();

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator forward empty" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            var iter = try db.iterator(cf1, .forward, 1);
            defer iter.deinit();

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator reverse empty" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            var iter = try db.iterator(cf1, .reverse, 1);
            defer iter.deinit();

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator forward empty with null start" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            var iter = try db.iterator(cf1, .forward, null);
            defer iter.deinit();

            try std.testing.expectEqual(null, try iter.next());
        }

        test "iterator reverse empty with null start" {
            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            var iter = try db.iterator(cf1, .reverse, null);
            defer iter.deinit();

            try std.testing.expectEqual(null, try iter.next());
        }

        test "WriteBatch.deleteRange" {
            if (true) return error.SkipZigTest;

            const allocator = std.testing.allocator;
            const path = test_dir ++ @src().fn_name;
            try ledger.tests.freshDir(path);
            var db = try DB.open(allocator, .noop, path, false);
            defer db.deinit();

            try db.put(cf1, 40, .{ .hello = 44 });
            try db.put(cf1, 10, .{ .hello = 111 });
            try db.put(cf1, 30, .{ .hello = 33 });
            try db.put(cf1, 20, .{ .hello = 222 });

            var batch = try db.initWriteBatch();
            defer batch.deinit();
            try batch.deleteRange(cf1, 15, 35);
            try db.commit(&batch);

            try std.testing.expect(null != try db.get(allocator, cf1, 10));
            try std.testing.expectEqual(null, try db.get(allocator, cf1, 20));
            try std.testing.expectEqual(null, try db.get(allocator, cf1, 30));
            try std.testing.expect(null != try db.get(allocator, cf1, 40));
        }
    };
}
