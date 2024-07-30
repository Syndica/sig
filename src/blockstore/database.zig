const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;

const Logger = sig.trace.Logger;

/// Interface defining the blockstore's dependency on a database
pub fn Database(
    comptime Impl: type,
    comptime column_families: []const ColumnFamily,
) type {
    return struct {
        impl: Impl,

        const Self = @This();

        pub const Batch = BatchImpl(Impl.Batch, column_families);

        pub fn open(
            allocator: Allocator,
            logger: Logger,
            path: []const u8,
        ) !Database(Impl, column_families) {
            return .{
                .impl = try Impl.open(allocator, logger, path, column_families),
            };
        }

        pub fn deinit(self: Self) void {
            self.impl.deinit();
        }

        pub fn put(self: *Self, comptime cf: ColumnFamily, key: cf.Key, value: cf.Value) !void {
            return try self.impl.put(cf, comptime cf.find(column_families), key, value);
        }

        pub fn get(self: *Self, comptime cf: ColumnFamily, key: cf.Key) !?cf.Value {
            return try self.impl.get(cf, comptime cf.find(column_families), key);
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
        ) !?BytesRef {
            return try self.impl.getBytes(cf, comptime cf.find(column_families), key);
        }

        pub fn delete(self: *Self, comptime cf: ColumnFamily, key: cf.Key) !void {
            return try self.impl.delete(cf, comptime cf.find(column_families), key);
        }

        pub fn initBatch(self: *Self) !Batch {
            return .{ .impl = self.impl.initBatch() };
        }

        pub fn commit(self: *Self, batch: Batch) !void {
            return self.impl.commit(batch.impl);
        }

        pub fn iterator(
            self: *Self,
            comptime cf: ColumnFamily,
            comptime direction: IteratorDirection,
            start: ?cf.Key,
        ) !Iterator(Impl.Iterator(cf, direction), cf) {
            return .{ .impl = try self.impl.iterator(
                cf,
                comptime cf.find(column_families),
                direction,
                start,
            ) };
        }

        pub fn runTest() !void {
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
            const allocator = std.testing.allocator;
            const logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
            defer logger.deinit();
            var db = try Database(Impl, &.{ cf1, cf2 }).open(
                allocator,
                logger,
                "test_data/bsdb",
            );
            defer db.deinit();
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

pub fn BatchImpl(
    comptime Impl: type,
    comptime column_families: []const ColumnFamily,
) type {
    return struct {
        impl: Impl,

        const Self = @This();

        pub fn put(self: *Self, comptime cf: ColumnFamily, key: cf.Key, value: cf.Value) !void {
            return try self.impl.put(cf, comptime cf.find(column_families), key, value);
        }

        pub fn delete(self: *Self, comptime cf: ColumnFamily, key: cf.Key) !void {
            return try self.impl.delete(cf, comptime cf.find(column_families), key);
        }
    };
}

pub const IteratorDirection = enum { forward, reverse };

pub fn Iterator(comptime Impl: type, comptime column_family: ColumnFamily) type {
    return struct {
        impl: Impl,

        pub fn nextBytes(self: *@This()) !?struct { column_family.Key, []const u8 } {
            return try self.impl.nextBytes();
        }
    };
}

pub const ColumnFamily = struct {
    name: []const u8,
    Key: type,
    Value: type,
    KeySerializer: type = BincodeSerializer(.{ .endian = .big }),
    ValueSerializer: type = BincodeSerializer(.{}),

    const Self = @This();

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

    pub fn key(comptime self: Self) Serializer(self.KeySerializer) {
        return .{};
    }

    pub fn value(comptime self: Self) Serializer(self.ValueSerializer) {
        return .{};
    }
};

pub fn Serializer(comptime S: type) type {
    return struct {
        const Self = @This();

        /// Returns data that is not owned by the current scope.
        /// The slice should be immediately copied and deinitialized.
        /// Use this if the database backend accepts a pointer and calls memcpy.
        pub fn serializeToRef(
            comptime self: Self,
            allocator: Allocator,
            item: anytype,
        ) !BytesRef {
            if (@hasDecl(S, "serializeToRef")) {
                return S.serializeToRef(allocator, item);
            } else {
                return .{
                    .allocator = allocator,
                    .data = try self.serializeAlloc(allocator, item),
                };
            }
        }

        pub fn serializeAlloc(comptime self: Self, allocator: Allocator, item: anytype) ![]const u8 {
            const buf = try allocator.alloc(u8, try self.serializedSize(item));
            return self.serializeToSlice(item, buf);
        }

        pub fn serializeToSlice(comptime self: Self, item: anytype, buf: []u8) ![]const u8 {
            var stream = std.io.fixedBufferStream(buf);
            try self.serialize(stream.writer(), item);
            return stream.getWritten();
        }

        pub inline fn serialize(comptime _: Self, writer: anytype, item: anytype) !void {
            return S.serialize(writer, item);
        }

        pub inline fn serializedSize(comptime _: Self, item: anytype) !usize {
            return S.serializedSize(item);
        }

        pub inline fn deserialize(
            comptime _: Self,
            comptime T: type,
            allocator: Allocator,
            bytes: []const u8,
        ) !T {
            return S.deserialize(T, allocator, bytes);
        }
    };
}

pub fn BincodeSerializer(params: sig.bincode.Params) type {
    return struct {
        pub fn serialize(writer: anytype, item: anytype) !void {
            return sig.bincode.write(writer, item, params);
        }

        pub fn serializedSize(item: anytype) usize {
            return sig.bincode.sizeOf(item, params);
        }

        pub fn deserialize(comptime T: type, allocator: Allocator, bytes: []const u8) !T {
            return try sig.bincode.readFromSlice(allocator, T, bytes, params);
        }
    };
}

pub const BytesSerializer = struct {
    pub fn serialize(writer: anytype, item: []const u8) !void {
        return writer.writeAll(item);
    }

    pub fn serializeToRef(item: []const u8) !BytesRef {
        return .{ .data = item };
    }

    pub fn serializedSize(item: anytype) usize {
        return item.len;
    }

    pub fn deserialize(comptime T: type, allocator: Allocator, bytes: []const u8) !T {
        const ret = try allocator.alloc(u8, bytes.len);
        @memcpy(ret, bytes);
        return ret;
    }
};

pub const BytesRef = struct {
    allocator: ?Allocator = null,
    data: []const u8,

    pub fn deinit(self: @This()) void {
        if (self.allocator) |a| a.free(self.data);
    }
};
