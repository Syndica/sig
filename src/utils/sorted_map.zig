const std = @import("std");
const sig = @import("../sig.zig");

const defaultOrderFn = sig.utils.collections.defaultOrderFn;

pub fn SortedSet(
    comptime Key: type,
    comptime options: struct {
        orderFn: fn (Key, Key) std.math.Order = defaultOrderFn(Key),
    },
) type {
    return SortedMap(Key, void, .{
        .orderFn = options.orderFn,
    });
}

pub fn SortedMap(
    comptime Key: type,
    comptime Value: type,
    comptime options: struct {
        orderFn: fn (Key, Key) std.math.Order = defaultOrderFn(Key),
    },
) type {
    const orderFn = options.orderFn;

    return struct {
        levels: u32,
        prng: std.Random.DefaultPrng,
        tail: u32,
        inserted: u32,
        free_list: u32,
        nodes: std.ArrayListUnmanaged(Node),

        pub const empty: Self = .{
            .levels = 0,
            .prng = .init(0),
            .tail = 0,
            .inserted = 0,
            .free_list = 0,
            .nodes = .{},
        };

        const Self = @This();
        const Node = struct {
            key: Key,
            value: Value,
            prev: u32,
            next: [max_levels + 1]u32,
        };

        const max_objects = 1 << 24; // 16 million objects
        const max_levels = blk: {
            @setEvalBranchQuota(10_000);
            var levels: u32 = 0;
            while (true) : (levels += 1) {
                const limit = std.math.pow(f64, std.math.e, @floatFromInt(levels));
                if (limit >= max_objects) break;
            }
            break :blk levels;
        };

        const probability_table = blk: {
            @setEvalBranchQuota(10_000);
            var table: [max_levels]f64 = undefined;
            for (&table, 0..) |*probability, i| {
                probability.* = std.math.pow(f64, @as(f64, 1) / std.math.e, @floatFromInt(i));
            }
            break :blk table;
        };

        pub fn deinit(const_self: Self, allocator: std.mem.Allocator) void {
            var self = const_self;
            self.nodes.deinit(allocator);
        }

        pub fn count(self: *const Self) usize {
            return self.inserted;
        }

        fn search(self: *const Self, key: Key, path: *[max_levels + 2]u32) ?u32 {
            if (self.count() == 0) return null;

            var node_idx: u32 = 0;
            var level = self.levels;
            while (level != std.math.maxInt(u32)) : (level -%= 1) {
                while (true) {
                    const next_idx = self.nodes.items[node_idx].next[level];
                    if (next_idx == 0) break;
                    const next = &self.nodes.items[next_idx];
                    if (orderFn(next.key, key) != .lt) break;
                    node_idx = next_idx;
                }
                path[level] = node_idx;
            }

            node_idx = self.nodes.items[node_idx].next[0];
            path[max_levels + 1] = node_idx;
            if (node_idx != 0) {
                const node = &self.nodes.items[node_idx];
                if (orderFn(node.key, key) == .eq) return node_idx;
            }

            return null;
        }

        pub fn contains(self: *const Self, key: Key) bool {
            return if (self.getPtr(key)) |_| true else false;
        }

        pub fn get(self: *const Self, key: Key) ?Value {
            const value_ptr = self.getPtr(key) orelse return null;
            return value_ptr.*;
        }

        pub fn getPtr(self: *const Self, key: Key) ?*Value {
            const entry = self.getEntry(key) orelse return null;
            return entry.value_ptr;
        }

        pub const Entry = struct {
            key_ptr: *Key,
            value_ptr: *Value,
        };

        pub fn getEntry(self: *const Self, key: Key) ?Entry {
            var path: [max_levels + 2]u32 = undefined;
            const idx = self.search(key, &path) orelse return null;
            const node = &self.nodes.items[idx];
            return .{
                .key_ptr = &node.key,
                .value_ptr = &node.value,
            };
        }

        pub const GetOrPutResult = struct {
            key_ptr: *const Key,
            value_ptr: *Value,
            found_existing: bool,
        };

        pub fn getOrPut(self: *Self, allocator: std.mem.Allocator, key: Key) !GetOrPutResult {
            // lazy init
            if (self.nodes.items.len == 0) {
                @branchHint(.unlikely);
                (try self.nodes.addOne(allocator)).* = .{
                    .key = undefined,
                    .value = undefined,
                    .prev = 0,
                    .next = @splat(0),
                };
            }

            var path: [max_levels + 2]u32 = @splat(0);
            if (self.search(key, &path)) |idx| {
                const node = &self.nodes.items[idx];
                return .{ .key_ptr = &node.key, .value_ptr = &node.value, .found_existing = true };
            }

            const rand_level = blk: {
                const r = self.prng.random().float(f64);
                var level: u32 = 1;
                while (level < max_levels and r < probability_table[level]) level += 1;
                break :blk level;
            };

            if (rand_level > self.levels) {
                for (self.levels + 1..rand_level + 1) |i| path[i] = 0;
                self.levels = rand_level;
            }

            self.inserted += 1;
            std.debug.assert(self.inserted <= max_objects);

            var new_idx = self.free_list;
            if (new_idx > 0) {
                self.free_list = self.nodes.items[new_idx].prev;
                std.debug.assert(self.free_list < self.nodes.items.len);
            } else {
                new_idx = @intCast(self.nodes.items.len);
                _ = try self.nodes.addOne(allocator);
            }

            self.nodes.items[new_idx] = .{
                .key = undefined,
                .value = undefined,
                .prev = path[0],
                .next = @splat(0),
            };

            for (0..rand_level + 1) |i| {
                const path_link = &self.nodes.items[path[i]].next[i];
                const node_link = &self.nodes.items[new_idx].next[i];
                node_link.* = path_link.*;
                path_link.* = new_idx;
            }

            const node = &self.nodes.items[new_idx];
            if (node.next[0] == 0) {
                self.tail = new_idx;
            }

            return .{
                .key_ptr = &node.key,
                .value_ptr = &node.value,
                .found_existing = false,
            };
        }

        pub const KV = struct {
            key: Key,
            value: Value,
        };

        pub fn fetchPut(self: *Self, allocator: std.mem.Allocator, key: Key, value: Value) !?KV {
            const gop = try self.getOrPut(allocator, key);
            const result: ?KV = if (gop.found_existing)
                .{ .key = gop.key_ptr.*, .value = gop.value_ptr.* }
            else
                null;

            gop.value_ptr.* = value;
            return result;
        }

        pub fn put(self: *Self, allocator: std.mem.Allocator, key: Key, value: Value) !void {
            const gop = try self.getOrPut(allocator, key);
            gop.value_ptr.* = value;
        }

        pub fn fetchRemove(self: *Self, key: Key) ?KV {
            var kv: KV = undefined;
            return if (self.removeByKey(key, &kv)) kv else null;
        }

        pub fn remove(self: *Self, key: Key) bool {
            return self.removeByKey(key, null);
        }

        fn removeByKey(self: *Self, key: Key, maybe_out_kv: ?*KV) bool {
            var path: [max_levels + 2]u32 = @splat(0);
            const idx = self.search(key, &path) orelse return false;

            const node = &self.nodes.items[idx];
            if (maybe_out_kv) |kv_ptr| {
                kv_ptr.key = node.key;
                kv_ptr.value = node.value;
            }

            // Update .prev link of next.
            const next_idx = node.next[0];
            if (next_idx != 0) {
                const next = &self.nodes.items[next_idx];
                std.debug.assert(next.prev == idx);
                next.prev = node.prev;
            } else {
                std.debug.assert(self.tail == idx);
                self.tail = node.prev;
            }

            node.prev = self.free_list;
            self.free_list = idx;
            self.inserted -= 1;

            // Update .next links of prev
            for (0..self.levels + 1) |i| {
                const path_link = &self.nodes.items[path[i]].next[i];
                if (path_link.* != idx) break;
                path_link.* = self.nodes.items[idx].next[i];
            }

            while (self.levels > 0 and self.nodes.items[0].next[self.levels] == 0)
                self.levels -= 1;

            return true;
        }

        pub fn clone(self: *const Self, allocator: std.mem.Allocator) !Self {
            return Self{
                .levels = self.levels,
                .prng = self.prng,
                .tail = self.tail,
                .inserted = self.inserted,
                .free_list = self.free_list,
                .nodes = try self.nodes.clone(allocator),
            };
        }

        pub fn minEntry(self: *const Self) ?Entry {
            if (self.count() == 0) return null;
            const min_idx = self.nodes.items[0].next[0];
            if (min_idx == 0) return null;
            const node = &self.nodes.items[min_idx];
            return .{ .key_ptr = &node.key, .value_ptr = &node.value };
        }

        pub fn maxEntry(self: *const Self) ?Entry {
            if (self.count() == 0) return null;
            const node = &self.nodes.items[self.tail];
            return .{ .key_ptr = &node.key, .value_ptr = &node.value };
        }

        pub fn eql(self: *const Self, other: *const Self) bool {
            var self_it = self.iterator();
            var other_it = other.iterator();
            while (true) {
                const a = self_it.next() orelse (return other_it.next() == null);
                const b = other_it.next() orelse return false;
                if (orderFn(a.key_ptr.*, b.key_ptr.*) != .eq) return false;
            }
        }

        pub fn iterator(self: *const Self) Iterator {
            return self.iteratorRanged(null, null, .start);
        }

        pub fn iteratorRanged(
            self: *const Self,
            maybe_start: ?Key,
            maybe_end: ?Key,
            begin: enum { start, end },
        ) Iterator {
            var path: [max_levels + 2]u32 = @splat(0);
            const idx = switch (begin) {
                .start => blk: {
                    if (maybe_start) |key| {
                        _ = self.search(key, &path);
                        break :blk path[max_levels + 1];
                    }
                    break :blk if (self.count() == 0) 0 else self.nodes.items[0].next[0];
                },
                .end => blk: {
                    if (maybe_end) |key| {
                        _ = self.search(key, &path);
                        break :blk path[max_levels + 1];
                    }
                    break :blk self.tail;
                },
            };

            return .{
                .map = self,
                .idx = idx,
                .start = maybe_start,
                .end = maybe_end,
            };
        }

        pub const Iterator = struct {
            map: *const Self,
            idx: u32,
            start: ?Key,
            end: ?Key,

            pub fn countForwardsInclusive(self: *const Iterator) u32 {
                return self.countForwardWith(.inclusive);
            }

            pub fn countForwards(self: *const Iterator) u32 {
                return self.countForwardWith(.exclusive);
            }

            fn countForwardWith(self: *const Iterator, include: enum { inclusive, exclusive }) u32 {
                // TODO: make this not O(N)
                var n: u32 = 0;
                var it = self.*;
                while (it.advance(
                    .forward,
                    if (include == .inclusive) .inclusive else .exclusive,
                ) != null) n += 1;
                return n;
            }

            pub fn next(self: *Iterator) ?Entry {
                return self.advance(.forward, .exclusive);
            }

            pub fn nextInclusive(self: *Iterator) ?Entry {
                return self.advance(.forward, .inclusive);
            }

            pub fn prev(self: *Iterator) ?Entry {
                return self.advance(.backward, .inclusive);
            }

            fn advance(
                self: *Iterator,
                direction: enum { forward, backward },
                include: enum { inclusive, exclusive },
            ) ?Entry {
                std.debug.assert(self.idx < self.map.nodes.items.len);
                if (self.idx == 0) {
                    if (self.map.count() == 0) return null;
                    switch (direction) {
                        .forward => {
                            self.idx = self.map.nodes.items[0].next[0];
                            if (self.idx == 0) return null;
                        },
                        .backward => return null,
                    }
                }

                const node = &self.map.nodes.items[self.idx];
                switch (direction) {
                    .forward => {
                        if (self.end) |end_key| {
                            switch (include) {
                                .inclusive => if (orderFn(node.key, end_key) == .gt) return null,
                                .exclusive => if (orderFn(node.key, end_key) != .lt) return null,
                            }
                        }
                        self.idx = node.next[0];
                    },
                    .backward => {
                        if (self.start) |start_key| {
                            switch (include) {
                                .inclusive => if (orderFn(start_key, node.key) == .gt) return null,
                                .exclusive => if (orderFn(start_key, node.key) != .lt) return null,
                            }
                        }
                        self.idx = node.prev;
                    },
                }
                return .{ .key_ptr = &node.key, .value_ptr = &node.value };
            }
        };
    };
}

test "SortedMap basics" {
    const allocator = std.testing.allocator;

    var x: SortedMap(i32, u128, .{}) = .empty;
    defer x.deinit(allocator);

    const values: []const struct { i32, u128 } = &.{
        .{ 1, 9 },
        .{ 2, 8 },
        .{ 3, 7 },
        .{ 4, 6 },
        .{ 5, 5 },
        .{ 6, 4 },
        .{ 7, 3 },
        .{ 8, 2 },
        .{ 9, 1 },

        .{ -1, 9 },
        .{ -2, 8 },
        .{ -3, 7 },
        .{ -4, 6 },
        .{ -5, 5 },
        .{ -6, 4 },
        .{ -7, 3 },
        .{ -8, 2 },
        .{ -9, 1 },

        .{ 11, 9 },
        .{ 12, 8 },
        .{ 13, 7 },
        .{ 14, 6 },
        .{ 15, 5 },
        .{ 16, 4 },
        .{ 17, 3 },
        .{ 18, 2 },
        .{ 19, 1 },

        .{ 21, 9 },
        .{ 22, 8 },
        .{ 23, 7 },
        .{ 24, 6 },
        .{ 25, 5 },
        .{ 26, 4 },
        .{ 27, 3 },
        .{ 28, 2 },
        .{ 29, 1 },

        .{ 0, 0 },

        .{ 31, 9 },
        .{ 32, 8 },
        .{ 33, 7 },
        .{ 34, 6 },
        .{ 35, 5 },
        .{ 36, 4 },
        .{ 37, 3 },
        .{ 38, 2 },
        .{ 39, 1 },

        .{ 41, 9 },
        .{ 42, 8 },
        .{ 43, 7 },
        .{ 44, 6 },
        .{ 45, 5 },
        .{ 46, 4 },
        .{ 47, 3 },
        .{ 48, 2 },
        .{ 49, 1 },

        .{ 51, 9 },
        .{ 52, 8 },
        .{ 53, 7 },
        .{ 54, 6 },
        .{ 55, 5 },
        .{ 56, 4 },
        .{ 57, 3 },
        .{ 58, 2 },
        .{ 59, 1 },

        .{ 61, 9 },
        .{ 62, 8 },
        .{ 63, 7 },
        .{ 64, 6 },
        .{ 65, 5 },
        .{ 66, 4 },
        .{ 67, 3 },
        .{ 68, 2 },
        .{ 69, 1 },

        .{ 71, 9 },
        .{ 72, 8 },
        .{ 73, 7 },
        .{ 74, 6 },
        .{ 75, 5 },
        .{ 76, 4 },
        .{ 77, 3 },
        .{ 78, 2 },
        .{ 79, 1 },

        .{ 81, 9 },
        .{ 82, 8 },
        .{ 83, 7 },
        .{ 84, 6 },
        .{ 85, 5 },
        .{ 86, 4 },
        .{ 87, 3 },
        .{ 88, 2 },
        .{ 89, 1 },

        .{ 91, 9 },
        .{ 92, 8 },
        .{ 93, 7 },
        .{ 94, 6 },
        .{ 95, 5 },
        .{ 96, 4 },
        .{ 97, 3 },
        .{ 98, 2 },
        .{ 99, 1 },

        .{ 101, 9 },
        .{ 102, 8 },
        .{ 103, 7 },
        .{ 104, 6 },
        .{ 105, 5 },
        .{ 106, 4 },
        .{ 107, 3 },
        .{ 108, 2 },
        .{ 109, 1 },

        .{ 101, 9 },
        .{ 102, 8 },
        .{ 103, 7 },
        .{ 104, 6 },
        .{ 105, 5 },
        .{ 106, 4 },
        .{ 107, 3 },
        .{ 108, 2 },
        .{ 109, 1 },
    };

    for (values) |val| {
        try x.put(allocator, val.@"0", val.@"1");
    }

    for (values) |val| {
        try std.testing.expectEqual(val.@"1", x.get(val.@"0"));
    }

    try std.testing.expect(x.remove(109));
    try std.testing.expect(x.remove(-9));
    try std.testing.expect(x.remove(69));

    try std.testing.expect(!x.remove(100000000));
    try std.testing.expect(!x.remove(-123131231));
    try std.testing.expect(!x.remove(345635635));
}

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

test SortedSet {
    const allocator = std.testing.allocator;

    var set: SortedSet(u64, .{}) = .empty;
    defer set.deinit(allocator);

    // add/contains
    try expect(!set.contains(3));
    try set.put(allocator, 3, {});
    try expect(set.contains(3));
    try set.put(allocator, 0, {});
    try set.put(allocator, 2, {});
    try set.put(allocator, 1, {});
    try set.put(allocator, 4, {});
    try set.put(allocator, 5, {});

    // remove
    try expect(set.remove(5));
    try expect(!set.contains(5));
    try expect(!set.remove(5));
    try set.put(allocator, 5, {});
    try expect(set.contains(5));

    var iter = set.iterator();
    var i: u64 = 0;
    while (iter.next()) |entry| : (i += 1) {
        try expectEqual(i, entry.key_ptr.*);
    }

    var j: u64 = i;
    while (iter.prev()) |entry| {
        j -= 1;
        try expectEqual(j, entry.key_ptr.*);
    }
}

test "SortedMap iterate large" {
    const allocator = std.testing.allocator;

    const Key = u32;
    var map: SortedMap(Key, void, .{
        .orderFn = struct {
            fn order(a: Key, b: Key) std.math.Order {
                return std.math.order(a, b);
            }
        }.order,
    }) = .empty;
    defer map.deinit(allocator);

    const array = try allocator.alloc(Key, 1000);
    defer allocator.free(array);

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    for (array, 0..) |*a, i| a.* = @intCast(i);

    prng.random().shuffle(Key, array);
    for (array) |x| try map.put(allocator, x, {});
    std.mem.sort(Key, array, {}, std.sort.asc(Key));

    var it = map.iterator();
    for (array) |x| {
        const e = it.next().?;
        try std.testing.expectEqual(x, e.key_ptr.*);
    }
}

test "SortedMap bincode round trip does not break sorting" {
    const allocator = std.testing.allocator;

    const Set = SortedSet(u8, .{});

    var set: Set = .empty;
    defer set.deinit(allocator);

    try set.put(allocator, 5, {});
    try set.put(allocator, 3, {});

    const ser = try sig.bincode.writeAlloc(allocator, set, .{});
    defer allocator.free(ser);

    var des = try sig.bincode.readFromSlice(allocator, Set, ser, .{});
    defer des.deinit(allocator);

    var iter = set.iterator();
    try std.testing.expectEqual(3, iter.next().?.key_ptr.*);
    try std.testing.expectEqual(5, iter.next().?.key_ptr.*);
}

fn testRange(
    expected: []const u8,
    iterator: SortedSet(u8, .{}).Iterator,
) !void {
    const allocator = std.testing.allocator;

    var found_data: std.ArrayListUnmanaged(u8) = .empty;
    defer found_data.deinit(allocator);

    var iter = iterator;
    while (iter.next()) |entry| {
        try found_data.append(allocator, entry.key_ptr.*);
    }

    try std.testing.expectEqualSlices(u8, expected, found_data.items);
}

test "SortedMap.iteratorRanged" {
    const allocator = std.testing.allocator;

    var set: SortedSet(u8, .{}) = .empty;
    defer set.deinit(allocator);

    try set.put(allocator, 5, {});
    try set.put(allocator, 3, {});
    try set.put(allocator, 1, {});
    try set.put(allocator, 3, {});

    try testRange(&.{ 1, 3, 5 }, set.iteratorRanged(null, null, .start));
    try testRange(&.{}, set.iteratorRanged(0, 0, .start));
    try testRange(&.{}, set.iteratorRanged(10, 10, .start));
    try testRange(&.{}, set.iteratorRanged(10, 11, .start));
    try testRange(&.{}, set.iteratorRanged(12, 11, .start));
    try testRange(&.{1}, set.iteratorRanged(null, 3, .start));
    try testRange(&.{ 1, 3 }, set.iteratorRanged(null, 4, .start));
    try testRange(&.{ 1, 3 }, set.iteratorRanged(null, 5, .start));
    try testRange(&.{ 1, 3, 5 }, set.iteratorRanged(null, 6, .start));
    try testRange(&.{ 1, 3, 5 }, set.iteratorRanged(0, null, .start));
    try testRange(&.{ 1, 3, 5 }, set.iteratorRanged(1, null, .start));
    try testRange(&.{ 3, 5 }, set.iteratorRanged(2, null, .start));
    try testRange(&.{ 3, 5 }, set.iteratorRanged(3, null, .start));
    try testRange(&.{5}, set.iteratorRanged(4, null, .start));
    try testRange(&.{5}, set.iteratorRanged(5, null, .start));
    try testRange(&.{ 1, 3, 5 }, set.iteratorRanged(1, 6, .start));
    try testRange(&.{ 1, 3 }, set.iteratorRanged(1, 5, .start));
    try testRange(&.{ 1, 3 }, set.iteratorRanged(1, 4, .start));
    try testRange(&.{1}, set.iteratorRanged(1, 3, .start));
    try testRange(&.{1}, set.iteratorRanged(1, 2, .start));
    try testRange(&.{}, set.iteratorRanged(1, 1, .start));
    try testRange(&.{ 3, 5 }, set.iteratorRanged(2, 6, .start));
    try testRange(&.{ 3, 5 }, set.iteratorRanged(3, 6, .start));
    try testRange(&.{5}, set.iteratorRanged(4, 6, .start));
    try testRange(&.{5}, set.iteratorRanged(5, 6, .start));
    try testRange(&.{3}, set.iteratorRanged(3, 4, .start));
    try testRange(&.{}, set.iteratorRanged(3, 3, .start));
    try testRange(&.{}, set.iteratorRanged(2, 3, .start));
    try testRange(&.{}, set.iteratorRanged(2, 2, .start));
}

test "SortedMap" {
    const allocator = std.testing.allocator;

    var map: SortedMap(u64, u64, .{}) = .empty;
    defer map.deinit(allocator);

    try map.put(allocator, 3, 30);
    try map.put(allocator, 1, 10);
    try map.put(allocator, 2, 20);
    try map.put(allocator, 4, 40);
    try map.put(allocator, 5, 50);

    // Check that the keys and values are sorted.
    var iter = map.iterator();
    var i: u64 = 0;
    while (iter.next()) |entry| : (i += 1) {
        // Keys should be 1, 2, 3, 4, 5
        try expectEqual(entry.key_ptr.*, i + 1);
        // Values should be 10, 20, 30, 40, 50
        try expectEqual(entry.value_ptr.*, (i + 1) * 10);
    }

    // Remove a non terminal item with no sort.
    try expect(map.remove(3));
    try expect(!map.remove(3));
    try expect(map.remove(1));
}

test "SortedMap.put primitives" {
    const allocator = std.testing.allocator;

    var map: SortedMap(i32, u128, .{}) = .empty;
    defer map.deinit(allocator);
    try std.testing.expectEqual(0, map.count());

    try map.put(allocator, 5, 500);
    try std.testing.expectEqual(1, map.count());
    try std.testing.expectEqual(@as(?u128, 500), map.get(5));

    try map.put(allocator, 5, 600);
    try std.testing.expectEqual(@as(u32, 1), map.count());
    try std.testing.expectEqual(@as(?u128, 600), map.get(5));

    try map.put(allocator, 1, 100);
    try map.put(allocator, 3, 300);
    try map.put(allocator, 2, 200);
    try map.put(allocator, 4, 400);
    try map.put(allocator, 5, 500);

    var iter = map.iterator();
    var i: u16 = 1;
    while (iter.next()) |entry| : (i += 1) {
        try std.testing.expectEqual(i, entry.key_ptr.*);
        try std.testing.expectEqual(i * 100, entry.value_ptr.*);
    }

    var large_map: SortedMap(i32, i32, .{}) = .empty;
    defer large_map.deinit(allocator);

    for (0..100) |j| {
        try large_map.put(allocator, @intCast(j), @intCast(j * 10));
    }
    try std.testing.expectEqual(@as(u32, 100), large_map.count());

    var large_iter = large_map.iterator();
    var count: u32 = 0;
    while (large_iter.next()) |_| count += 1;
    try std.testing.expectEqual(@as(u32, 100), count);
}

test "SortedMap.getOrPut" {
    const allocator = std.testing.allocator;

    var map: SortedMap(i32, i32, .{}) = .empty;
    defer map.deinit(allocator);

    const entry1 = try map.getOrPut(allocator, 100);
    try std.testing.expect(!entry1.found_existing);
    try std.testing.expectEqual(100, entry1.key_ptr.*);
    try std.testing.expectEqual(1, map.count());
    entry1.value_ptr.* = 500;

    const entry2 = try map.getOrPut(allocator, 100);
    try std.testing.expect(entry2.found_existing);
    try std.testing.expectEqual(100, entry2.key_ptr.*);
    try std.testing.expectEqual(500, entry2.value_ptr.*);
    try std.testing.expectEqual(1, map.count());

    try std.testing.expectEqual(entry1.value_ptr, entry2.value_ptr);

    (try map.getOrPut(allocator, 200)).value_ptr.* = 2000;
    (try map.getOrPut(allocator, 300)).value_ptr.* = 3000;

    try std.testing.expectEqual(3, map.count());
    try std.testing.expectEqual(2000, map.get(200).?);
    try std.testing.expectEqual(3000, map.get(300).?);
}

test "SortedMap.iteratorRanged bidirectional" {
    const allocator = std.testing.allocator;

    var map: SortedMap(i32, i32, .{}) = .empty;
    defer map.deinit(allocator);

    try map.put(allocator, 0, 0);
    try map.put(allocator, 1, 10);
    try map.put(allocator, 2, 20);
    try map.put(allocator, 3, 30);

    // forward iteration
    {
        var iter = map.iteratorRanged(null, null, .start);
        var count: u32 = 0;
        var keys: [4]i32 = undefined;

        while (iter.next()) |entry| {
            keys[count] = entry.key_ptr.*;
            count += 1;
        }

        try std.testing.expectEqual(4, count);
        try std.testing.expectEqualSlices(i32, &.{ 0, 1, 2, 3 }, &keys);
    }

    // backward iteration
    {
        var iter = map.iteratorRanged(null, null, .end);
        var count: u32 = 0;
        var keys: [4]i32 = undefined;

        while (iter.prev()) |entry| {
            keys[count] = entry.key_ptr.*;
            count += 1;
        }

        try std.testing.expectEqual(4, count);
        try std.testing.expectEqualSlices(i32, &.{ 3, 2, 1, 0 }, &keys);
    }

    // backward ranged
    {
        var iter = map.iteratorRanged(1, 3, .end);
        var count: u32 = 0;
        var keys: [3]i32 = undefined;

        while (iter.prev()) |entry| {
            keys[count] = entry.key_ptr.*;
            count += 1;
        }

        try std.testing.expectEqual(3, count);
        try std.testing.expectEqualSlices(i32, &.{ 3, 2, 1 }, &keys);
    }
}
