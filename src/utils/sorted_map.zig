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
        len: u32,
        tail: u32,
        free_list: u32,

        levels: u32,
        prng: std.Random.DefaultPrng,
        nodes: std.ArrayListUnmanaged(Node),

        pub const empty: Self = .{
            .len = 0,
            .tail = 0,
            .free_list = 0,

            .levels = 0,
            .prng = .init(0),
            .nodes = .{},
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

        const Self = @This();
        const Node = struct {
            key: Key,
            value: Value,
            prev: u32,
            next: [max_levels + 1]u32,
        };

        pub fn deinit(const_self: Self, allocator: std.mem.Allocator) void {
            var self = const_self;
            self.nodes.deinit(allocator);
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        fn search(self: *const Self, key: Key, update: *[max_levels + 1]u32) ?u32 {
            if (self.count() == 0) return null;
            
            var prev: u32 = 0;
            var i = self.levels;
            while (i != std.math.maxInt(u32)) : (i -%= 1) {
                while (true) {
                    const next = self.nodes.items[prev].next[i];
                    if (next == 0) break;
                    if (orderFn(self.nodes.items[next].key, key) != .lt) break;
                    prev = next;
                }
                update[i] = prev;
            }

            const next = self.nodes.items[prev].next[0];
            if (next > 0 and orderFn(self.nodes.items[next].key, key) == .eq) {
                return next;
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
            var update: [max_levels + 1]u32 = undefined;
            const idx = self.search(key, &update) orelse return null;
            const node = &self.nodes.items[idx];
            return .{ .key_ptr = &node.key, .value_ptr = &node.value };
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

            var update: [max_levels + 1]u32 = @splat(0);
            if (self.search(key, &update)) |idx| {
                const node = &self.nodes.items[idx];
                return .{ .key_ptr = &node.key, .value_ptr = &node.value, .found_existing = true };
            }

            // allocate new node idx.
            var idx = self.free_list;
            if (idx > 0) {
                self.free_list = self.nodes.items[idx].next[0];
            } else {
                idx = @intCast(self.nodes.items.len);
                _ = try self.nodes.addOne(allocator);
            }

            const node = &self.nodes.items[idx];
            node.* = .{ .key = key, .value = undefined, .prev = update[0], .next = @splat(0) };

            const lvl = self.prng.random().uintAtMost(u32, max_levels);
            if (lvl > self.levels) {
                for (self.levels + 1 .. lvl + 1) |i| update[i] = 0;
                self.levels = lvl;
            }           

            for (0..lvl + 1) |i| {
                const update_node = &self.nodes.items[update[i]];
                node.next[i] = update_node.next[i];
                update_node.next[i] = idx;
            }

            if (node.next[0] > 0) {
                std.debug.assert(self.nodes.items[node.next[0]].prev == update[0]);
                self.nodes.items[node.next[0]].prev = idx;
            } else {
                std.debug.assert(self.tail == update[0]);
                self.tail = idx;
            }

            self.len += 1;
            std.debug.assert(self.len <= max_objects);
            return .{ .key_ptr = &node.key, .value_ptr = &node.value, .found_existing = false };
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
            var update: [max_levels + 1]u32 = @splat(0);
            const idx = self.search(key, &update) orelse return false;

            const node = &self.nodes.items[idx];
            std.debug.assert(node.prev == update[0]);

            if (maybe_out_kv) |out_kv| {
                out_kv.key = node.key;
                out_kv.value = node.value;
            }

            self.len -= 1;
            if (node.next[0] > 0) {
                std.debug.assert(idx != self.tail);
                std.debug.assert(self.nodes.items[node.next[0]].prev == idx);
                self.nodes.items[node.next[0]].prev = node.prev;
            } else {
                std.debug.assert(idx == self.tail);
                self.tail = node.prev;
            }

            for (0..self.levels + 1) |i| {
                const update_node = &self.nodes.items[update[i]];
                if (update_node.next[i] != idx) break;
                update_node.next[i] = node.next[i];
            }

            while (self.levels > 0 and self.nodes.items[0].next[self.levels] == 0)
                self.levels -= 1;

            node.next[0] = self.free_list;
            self.free_list = idx;
            return true;
        }

        pub fn clone(self: *const Self, allocator: std.mem.Allocator) !Self {
            return Self{
                .len = self.len,
                .tail = self.tail,
                .free_list = self.free_list,
                .levels = self.levels,
                .prng = self.prng,
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
            const idx = blk: {
                if (self.count() == 0) break :blk 0;
                const key = switch (begin) {
                    .start => maybe_start orelse break :blk 0, // min
                    .end => maybe_end orelse break :blk self.tail, // max,
                };
                
                var update: [max_levels + 1]u32 = undefined;
                break :blk self.search(key, &update) orelse update[0];
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
                if (self.map.count() == 0) return null;
                while (true) {
                    // start of range
                    if (self.idx == 0) {
                        self.idx = switch (direction) {
                            .backward => return null,
                            .forward => switch (self.map.nodes.items[0].next[0]) {
                                0 => std.math.maxInt(u32),
                                else => |idx| idx,
                            },
                        };
                    }
                    // end of range
                    if (self.idx == std.math.maxInt(u32)) {
                        switch (direction) {
                            .forward => return null,
                            .backward => {
                                self.idx = self.map.tail;
                                std.debug.assert(self.idx != std.math.maxInt(u32));
                                continue;
                            },
                        }
                    }
                    // valid node
                    const node_idx = self.idx;
                    const node = &self.map.nodes.items[self.idx];
                    self.idx = switch (direction) {
                        .backward => node.prev,
                        .forward => switch (node.next[0]) {
                            0 => std.math.maxInt(u32),
                            else => |idx| idx,
                        },
                    };
                    // skip nodes outside range
                    if (self.start) |start_key| {
                        switch (direction) {
                            .forward => if (orderFn(start_key, node.key) == .gt) continue,
                            .backward => if (orderFn(start_key, node.key) == .gt) {
                                self.idx = node_idx; // stay on this one
                                return null;
                            }
                        }
                    }
                    if (self.end) |end_key| {
                        switch (include) {
                            .inclusive => if (orderFn(node.key, end_key) == .gt) continue,
                            .exclusive => if (orderFn(node.key, end_key) != .lt) continue,
                        }
                    }
                    // found node in range
                    return .{ .key_ptr = &node.key, .value_ptr = &node.value };
                }
            }
        };
    };
}
