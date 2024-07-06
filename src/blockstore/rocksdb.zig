const std = @import("std");
const rocks = @import("rocksdb");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const DefaultRwLock = std.Thread.RwLock.DefaultRwLock;

const Logger = sig.trace.Logger;
const Return = sig.utils.types.Return;

pub const RocksDB = struct {
    db: rocks.DB,
    logger: Logger,

    pub const CF = RocksCF;

    const Self = @This();

    pub fn open(
        allocator: Allocator,
        logger: Logger,
        path: []const u8,
        column_families: []const []const u8,
    ) !struct { RocksDB, []RocksCF } {
        var err_str: ?rocks.Data = null;
        const column_family_descriptions = try allocator
            .alloc(rocks.ColumnFamilyDescription, column_families.len + 1);
        defer allocator.free(column_family_descriptions);
        column_family_descriptions[0] = .{ .name = "default", .options = .{} };
        for (column_families, 1..) |cf, i| {
            column_family_descriptions[i] = .{ .name = cf, .options = .{} };
        }
        const database, const cfs = rocks.DB.openCf(
            allocator,
            path,
            .{ .create_if_missing = true, .create_missing_column_families = true },
            column_family_descriptions,
            &err_str,
        ) catch |e| {
            std.debug.print("_\n\n{} while opening RocksDB: {s}\n\n", .{ e, err_str.? });
            logger.errf("{} while opening RocksDB: {s}", .{ e, err_str.? });
            std.time.sleep(10_000_000);
            return e;
        };
        defer allocator.free(cfs);
        const self = Self{ .db = database, .logger = logger };
        const maps = try allocator.alloc(RocksCF, column_families.len);
        for (1..cfs.len) |i| {
            maps[i - 1] = .{
                .db = self.db.withDefaultColumnFamily(cfs[i].handle),
                .logger = logger,
            };
        }
        return .{ self, maps };
    }

    pub fn deinit(self: RocksDB) void {
        self.db.deinit();
    }
};

const RocksCF = struct {
    db: rocks.DB,
    logger: Logger,

    const Self = @This();

    pub fn deinit(_: RocksCF) void {}

    pub fn free(_: Self, bytes: []const u8) void {
        rocks.free(bytes);
    }

    pub fn put(self: Self, key: []const u8, value: []const u8) !void {
        return self.callRocks(rocks.DB.put, .{ key, value });
    }

    pub fn get(self: Self, key: []const u8) !?[]const u8 {
        // FIXME: leak
        return ((try self.callRocks(rocks.DB.get, .{key})) orelse return null).data;
    }

    pub fn delete(self: Self, key: []const u8) !bool {
        try self.callRocks(rocks.DB.delete, .{key});
        return true; // FIXME
    }

    fn callRocks(self: Self, comptime func: anytype, args: anytype) Return(@TypeOf(func)) {
        var err_str: ?rocks.Data = null;
        return @call(.auto, func, .{ &self.db, null } ++ args ++ .{&err_str}) catch |e| {
            self.logger.errf("rocksdb: {} - {s}", .{ e, err_str.? });
            return e;
        };
    }
};
