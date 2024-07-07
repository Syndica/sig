const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;

const Logger = sig.trace.Logger;

/// Interface defining the blockstore's dependency on a database
pub fn Database(comptime Impl: type) type {
    return struct {
        allocator: Allocator,
        impl: Impl,
        cfs: []const ColumnFamily(CF),

        pub const CF: type = Impl.CF;

        const Self = @This();

        pub fn open(
            allocator: Allocator,
            logger: Logger,
            path: []const u8,
            column_family_names: []const []const u8,
        ) !struct { Self, []ColumnFamily(CF) } {
            const impl, const cfs = try Impl.open(allocator, logger, path, column_family_names);
            defer allocator.free(cfs);
            const wcfs = try allocator.alloc(ColumnFamily(CF), column_family_names.len);
            for (0..column_family_names.len) |i| {
                wcfs[i] = .{
                    .impl = cfs[i],
                    .name = column_family_names[i],
                };
            }
            return .{
                .{ .allocator = allocator, .impl = impl, .cfs = wcfs },
                wcfs,
            };
        }

        pub fn deinit(self: Self) void {
            self.impl.deinit();
            for (self.cfs) |cf| {
                cf.deinit();
            }
            self.allocator.free(self.cfs);
        }

        pub fn runTest() !void {
            const allocator = std.testing.allocator;
            const logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
            defer logger.deinit();
            const database, const cfs = try Self.open(
                allocator,
                logger,
                "test_data/bsdb",
                &.{ "cf1", "cf2" },
            );
            defer database.deinit();
            // defer allocator.free(cfs);
            try std.testing.expect(2 == cfs.len);
            try cfs[0].put("123", "345");
            const got = try cfs[0].get("123");
            try std.testing.expect(std.mem.eql(u8, "345", got.?));
            cfs[0].free(got.?);
            const not = try cfs[1].get("123");
            try std.testing.expect(null == not);
            const wrong_was_deleted = try cfs[1].delete("123");
            _ = wrong_was_deleted;
            // try std.testing.expect(!wrong_was_deleted); // FIXME
            const was_deleted = try cfs[0].delete("123");
            try std.testing.expect(was_deleted);
            const not_now = try cfs[0].get("123");
            try std.testing.expect(null == not_now);
        }
    };
}

/// Interface defining the blockstore's dependency on column families
pub fn ColumnFamily(comptime Impl: type) type {
    return struct {
        impl: Impl,
        name: []const u8,

        const Self = @This();

        pub inline fn deinit(self: Self) void {
            self.impl.deinit();
        }

        pub inline fn free(self: Self, bytes: []const u8) void {
            self.impl.free(bytes);
        }

        pub inline fn put(self: Self, key: []const u8, value: []const u8) !void {
            return self.impl.put(key, value);
        }

        pub inline fn get(self: Self, key: []const u8) !?[]const u8 {
            return self.impl.get(key);
        }

        pub inline fn delete(self: Self, key: []const u8) !bool {
            return self.impl.delete(key);
        }
    };
}
