const std = @import("std");
const Allocator = std.mem.Allocator;
const TailQueue = std.TailQueue;
const testing = std.testing;
const assert = std.debug.assert;

/// A thread-safe LRU Cache
///
// TODO: allow for passing custom hash context to use in std.ArrayHashMap for performance.
pub fn LruCache(comptime K: type, comptime V: type) type {
    return struct {
        allocator: Allocator,
        hashmap: if (K == []const u8) std.StringArrayHashMap(*Node) else std.AutoArrayHashMap(K, *Node),
        dbl_link_list: TailQueue(LruEntry),
        max_items: usize,
        len: usize = 0,

        const Self = @This();

        pub const LruEntry = struct {
            key: K,
            value: V,

            const Self = @This();

            pub fn init(key: K, val: V) LruEntry {
                return LruEntry{
                    .key = key,
                    .value = val,
                };
            }
        };

        const Node = TailQueue(LruEntry).Node;

        fn initNode(self: *Self, key: K, val: V) error{OutOfMemory}!*Node {
            self.len += 1;
            var node = try self.allocator.create(Node);
            node.* = .{ .data = LruEntry.init(key, val) };
            return node;
        }

        fn deinitNode(self: *Self, node: *Node) void {
            self.len -= 1;
            self.allocator.destroy(node);
        }

        pub fn init(allocator: Allocator, max_items: usize) error{OutOfMemory}!Self {
            var hashmap = if (K == []const u8) std.StringArrayHashMap(*Node).init(allocator) else std.AutoArrayHashMap(K, *Node).init(allocator);
            var self = Self{
                .allocator = allocator,
                .hashmap = hashmap,
                .dbl_link_list = TailQueue(LruEntry){},
                .max_items = max_items,
            };

            // pre allocate enough capacity for max items since we will use
            // assumed capacity and non-clobber methods
            try self.hashmap.ensureTotalCapacity(self.max_items);

            return self;
        }

        pub fn deinit(self: *Self) void {
            while (self.dbl_link_list.pop()) |node| {
                self.deinitNode(node);
            }
            self.hashmap.deinit();
        }

        /// Recycles an old node if LruCache capacity is full. If replaced, first element of tuple is replaced
        /// Entry (otherwise null) and second element of tuple is inserted Entry.
        fn internal_recycle_or_create_node(self: *Self, key: K, value: V) error{OutOfMemory}!struct { ?LruEntry, LruEntry } {
            if (self.dbl_link_list.len == self.max_items) {
                var recycled_node = self.dbl_link_list.popFirst().?;
                assert(self.hashmap.swapRemove(recycled_node.data.key));
                // after swap, this node is thrown away
                var node_to_swap: Node = .{
                    .data = LruEntry.init(key, value),
                    .next = null,
                    .prev = null,
                };
                std.mem.swap(Node, recycled_node, &node_to_swap);
                self.dbl_link_list.append(recycled_node);
                self.hashmap.putAssumeCapacityNoClobber(key, recycled_node);
                return .{ node_to_swap.data, recycled_node.data };
            }

            // key not exist, alloc a new node
            var node = try self.initNode(key, value);
            self.hashmap.putAssumeCapacityNoClobber(key, node);
            self.dbl_link_list.append(node);
            return .{ null, node.data };
        }

        fn internal_insert(self: *Self, key: K, value: V) LruEntry {
            // if key exists, we update it
            if (self.hashmap.get(key)) |existing_node| {
                existing_node.data.value = value;
                self.internal_reorder(existing_node);
                return existing_node.data;
            }

            var replaced_and_created_node = self.internal_recycle_or_create_node(key, value) catch |e| {
                std.debug.print("replace_or_create_node returned error: {any}", .{e});
                @panic("could not recycle_or_create_node");
            };
            var new_lru_entry = replaced_and_created_node[1];
            return new_lru_entry;
        }

        /// Inserts key/value if key doesn't exist, updates only value if it does.
        /// In any case, it will affect cache ordering.
        pub fn insert(self: *Self, key: K, value: V) error{OutOfMemory}!void {
            _ = self.internal_insert(key, value);
            return;
        }

        /// Whether or not contains key.
        /// NOTE: doesn't affect cache ordering.
        pub fn contains(self: *Self, key: K) bool {
            return self.hashmap.contains(key);
        }

        /// Most recently used entry
        pub fn mru(self: *Self) ?LruEntry {
            if (self.dbl_link_list.last) |node| {
                return node.data;
            }
            return null;
        }

        /// Least recently used entry
        pub fn lru(self: *Self) ?LruEntry {
            if (self.dbl_link_list.first) |node| {
                return node.data;
            }
            return null;
        }

        // reorder Node to the top
        fn internal_reorder(self: *Self, node: *Node) void {
            self.dbl_link_list.remove(node);
            self.dbl_link_list.append(node);
        }

        /// Gets value associated with key if exists
        pub fn get(self: *Self, key: K) ?V {
            if (self.hashmap.get(key)) |node| {
                self.dbl_link_list.remove(node);
                self.dbl_link_list.append(node);
                return node.data.value;
            }
            return null;
        }

        pub fn pop(self: *Self, k: K) ?V {
            if (self.hashmap.fetchSwapRemove(k)) |kv| {
                self.dbl_link_list.remove(kv.value);
                return kv.value.data.value;
            }
            return null;
        }

        pub fn peek(self: *Self, key: K) ?V {

            if (self.hashmap.get(key)) |node| {
                return node.data.value;
            }

            return null;
        }

        /// Puts a key-value pair into cache. If the key already exists in the cache, then it updates
        /// the key's value and returns the old value. Otherwise, `null` is returned.
        pub fn put(self: *Self, key: K, value: V) ?V {

            if (self.hashmap.getEntry(key)) |existing_entry| {
                var existing_node: *Node = existing_entry.value_ptr.*;
                var old_value = existing_node.data.value;
                existing_node.data.value = value;
                self.internal_reorder(existing_node);
                return old_value;
            }

            _ = self.internal_insert(key, value);
            return null;
        }

        /// Removes key from cache. Returns true if found, false if not.
        pub fn remove(self: *Self, key: K) bool {

            if (self.hashmap.fetchSwapRemove(key)) |kv| {
                var node = kv.value;
                self.dbl_link_list.remove(node);
                self.deinitNode(node);
                return true;
            }
            return false;
        }
    };
}

test "common.lru: LruCache state is correct" {
    var cache = try LruCache(u64, []const u8).init(testing.allocator, 4);
    defer cache.deinit();

    try cache.insert(1, "one");
    try cache.insert(2, "two");
    try cache.insert(3, "three");
    try cache.insert(4, "four");
    try testing.expectEqual(@as(usize, 4), cache.dbl_link_list.len);
    try testing.expectEqual(@as(usize, 4), cache.hashmap.keys().len);
    try testing.expectEqual(@as(usize, 4), cache.len);

    var val = cache.get(2);
    try testing.expectEqual(val.?, "two");
    try testing.expectEqual(cache.mru().?.value, "two");
    try testing.expectEqual(cache.lru().?.value, "one");

    try cache.insert(5, "five");
    try testing.expectEqual(cache.mru().?.value, "five");
    try testing.expectEqual(cache.lru().?.value, "three");
    try testing.expectEqual(@as(usize, 4), cache.dbl_link_list.len);
    try testing.expectEqual(@as(usize, 4), cache.hashmap.keys().len);
    try testing.expectEqual(@as(usize, 4), cache.len);

    try testing.expect(!cache.contains(1));
    try testing.expect(cache.contains(4));

    try testing.expect(cache.remove(5));
    try testing.expectEqualStrings("two", cache.mru().?.value);
    try testing.expectEqual(cache.len, 3);
}

test "common.lru: put works as expected" {
    var cache = try LruCache([]const u8, usize).init(testing.allocator, 4);
    defer cache.deinit();

    try cache.insert("a", 1);

    var old = cache.put("a", 2);

    try testing.expectEqual(@as(usize, 1), old.?);
    try testing.expectEqual(@as(usize, 2), cache.get("a").?);

    var possible_old = cache.put("b", 3);
    try testing.expectEqual(possible_old, null);
    try testing.expectEqual(@as(usize, 3), cache.get("b").?);
}
