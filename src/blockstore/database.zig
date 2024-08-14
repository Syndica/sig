const std = @import("std");
const sig = @import("../lib.zig");
const blockstore = @import("lib.zig");

const Allocator = std.mem.Allocator;

const Logger = sig.trace.Logger;

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

/// Runs all tests in `tests`
pub fn testDatabase(comptime Impl: fn ([]const ColumnFamily) type) !void {
    assertIsDatabase(Impl(&.{}));
    inline for (@typeInfo(tests(Impl)).Struct.decls) |decl| {
        try @call(.auto, @field(tests(Impl), decl.name), .{});
    }
}

/// Interface defining the blockstore's dependency on a database
pub fn Database(comptime Impl: type) type {
    return struct {
        impl: Impl,

        const Self = @This();

        pub fn open(
            allocator: Allocator,
            logger: Logger,
            path: []const u8,
        ) anyerror!Database(Impl) {
            return .{
                .impl = try Impl.open(allocator, logger, path),
            };
        }

        pub fn deinit(self: *Self, delete_mem: bool) void {
            self.impl.deinit(delete_mem);
        }

        pub fn put(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
            value: cf.Value,
        ) anyerror!void {
            return try self.impl.put(cf, key, value);
        }

        pub fn get(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!?cf.Value {
            return try self.impl.get(cf, key);
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
        pub fn getBytes(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!?BytesRef {
            return try self.impl.getBytes(cf, key);
        }

        pub fn delete(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!void {
            return try self.impl.delete(cf, key);
        }

        pub fn initWriteBatch(self: *Self) anyerror!WriteBatch {
            return .{ .impl = self.impl.initBatch() };
        }

        pub fn commit(self: *Self, batch: WriteBatch) anyerror!void {
            return self.impl.commit(batch.impl);
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

            pub fn put(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
                value: cf.Value,
            ) anyerror!void {
                return try self.impl.put(cf, key, value);
            }

            pub fn delete(self: *WriteBatch, comptime cf: ColumnFamily, key: cf.Key) anyerror!void {
                return try self.impl.delete(cf, key);
            }
        };

        pub fn iterator(
            self: *Self,
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

        pub fn rawIterator(self: *Self, comptime cf: ColumnFamily) anyerror!RawIterator {
            return .{ .impl = try self.impl.rawIterator(cf) };
        }

        pub const RawIterator = struct {};
    };
}

pub const IteratorDirection = enum { forward, reverse };

pub const ColumnFamily = struct {
    name: []const u8,
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
            const buf = try allocator.alloc(u8, sig.bincode.sizeOf(item, .{}));
            return sig.bincode.writeToSlice(buf, item, .{ .endian = endian });
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
                .allocator = null,
                .data = item,
            } else .{
                .allocator = allocator,
                .data = try serializeAlloc(allocator, item),
            };
        }

        /// Returned data is owned by the caller. Free with `allocator.free`.
        pub fn deserialize(comptime T: type, allocator: Allocator, bytes: []const u8) !T {
            return try sig.bincode.readFromSlice(allocator, T, bytes, .{ .endian = endian });
        }
    };
}

pub const BytesRef = struct {
    allocator: ?Allocator = null,
    data: []const u8,

    pub fn deinit(self: @This()) void {
        if (self.allocator) |a| a.free(self.data);
    }
};

/// Test cases that can be applied to any implementation of Database
fn tests(comptime Impl: fn ([]const ColumnFamily) type) type {
    @setEvalBranchQuota(10_000);
    const impl_id = sig.core.Hash.generateSha256Hash(@typeName(Impl(&.{}))).base58String();
    const test_dir = std.fmt.comptimePrint("test_data/blockstore/database/{s}", .{impl_id.buffer});

    return struct {
        pub fn basic() !void {
            const Value = struct { hello: u16 };
            const cf1 = ColumnFamily{
                .name = "one",
                .Key = u64,
                .Value = Value,
            };
            const cf2 = ColumnFamily{
                .name = "two",
                .Key = u64,
                .Value = Value,
            };
            const path = std.fmt.comptimePrint("{s}/basic", .{test_dir});
            try blockstore.tests.freshDir(path);
            const allocator = std.testing.allocator;
            const logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
            defer logger.deinit();
            var db = try Database(Impl(&.{ cf1, cf2 })).open(allocator, logger, path);
            defer db.deinit(true);

            try db.put(cf1, 123, .{ .hello = 345 });
            const got = try db.get(cf1, 123);
            try std.testing.expect(345 == got.?.hello);
            const not = try db.get(cf2, 123);
            try std.testing.expect(null == not);
            const wrong_was_deleted = try db.delete(cf2, 123);
            _ = wrong_was_deleted;
            // try std.testing.expect(!wrong_was_deleted); // FIXME
            const was_deleted = try db.delete(cf1, 123);
            _ = was_deleted;
            // try std.testing.expect(was_deleted);
            const not_now = try db.get(cf1, 123);
            try std.testing.expect(null == not_now);
        }
    };
}
