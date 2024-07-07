const std = @import("std");
const rocks = @import("rocksdb");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const DefaultRwLock = std.Thread.RwLock.DefaultRwLock;

const Database = sig.blockstore.database.Database;
const ColumnFamily = sig.blockstore.database.ColumnFamily;
const Logger = sig.trace.Logger;
const Return = sig.utils.types.Return;

pub const SharedHashMapDB = struct {
    pub const CF = *SharedHashMap;

    pub fn open(
        allocator: Allocator,
        _: Logger,
        _: []const u8,
        column_families: []const []const u8,
    ) !struct { SharedHashMapDB, []*SharedHashMap } {
        const maps = try allocator.alloc(*SharedHashMap, column_families.len);
        for (0..column_families.len) |i| {
            maps[i] = try SharedHashMap.create(allocator);
        }
        return .{ .{}, maps };
    }

    pub fn deinit(_: @This()) void {}
};

const SharedHashMap = struct {
    allocator: Allocator,
    map: std.StringHashMap([]const u8),
    lock: DefaultRwLock,

    const Self = @This();

    fn create(allocator: Allocator) Allocator.Error!*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .map = std.StringHashMap([]const u8).init(allocator),
            .lock = .{},
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        var iter = self.map.keyIterator();
        while (iter.next()) |k| {
            self.allocator.free(k.*);
        }
        self.map.deinit();
        self.allocator.destroy(self);
    }

    pub fn free(self: Self, bytes: []const u8) void {
        self.allocator.free(bytes);
    }

    pub fn put(self: *Self, key: []const u8, value: []const u8) Allocator.Error!void {
        const owned_key = try self.allocator.alloc(u8, key.len);
        const owned_val = try self.allocator.alloc(u8, value.len);
        @memcpy(owned_key, key);
        @memcpy(owned_val, value);
        self.lock.lock();
        defer self.lock.unlock();
        try self.map.put(owned_key, owned_val);
    }

    pub fn get(self: *Self, key: []const u8) Allocator.Error!?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const value = self.map.get(key) orelse return null;
        const owned_val = try self.allocator.alloc(u8, value.len);
        @memcpy(owned_val, value);
        return owned_val;
    }

    pub fn delete(self: *Self, key_: []const u8) bool {
        const key, const value = lock: {
            self.lock.lock();
            defer self.lock.unlock();
            const entry = self.map.getEntry(key_) orelse return false;
            const key = entry.key_ptr.*;
            const val = entry.value_ptr.*;
            defer self.map.removeByPtr(entry.key_ptr);
            break :lock .{ key, val };
        };
        self.allocator.free(key);
        self.allocator.free(value);
        return true;
    }
};

test "hashmap database" {
    try Database(SharedHashMapDB).runTest();
}
