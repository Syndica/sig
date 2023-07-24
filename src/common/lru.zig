const std = @import("std");
const Allocator = std.mem.Allocator;
const TailQueue = std.TailQueue;
const testing = std.testing;
const assert = std.debug.assert;

/// A thread-safe LRU Cache
///
// TODO: allow for passing custom hash context to use in std.ArrayHashMap for performance.
pub fn LruCache(comptime K: type, comptime V: type, comptime max_items: usize) type {
    return struct {
        allocator: Allocator,
        hashmap: std.AutoArrayHashMap(K, *Node),
        dbl_link_list: TailQueue(Entry),
        max_items: usize,
        len: usize = 0,
        mux: std.Thread.Mutex,

        const Self = @This();

        pub const Entry = struct {
            key: K,
            value: V,

            const Self = @This();

            pub fn init(key: K, val: V) Entry {
                return Entry{
                    .key = key,
                    .value = val,
                };
            }
        };

        const Node = TailQueue(Entry).Node;

        fn initNode(self: *Self, key: K, val: V) Allocator.Error!*Node {
            self.len += 1;
            var node = try self.allocator.create(Node);
            node.* = .{ .data = Entry.init(key, val) };
            return node;
        }

        fn deinitNode(self: *Self, node: *Node) void {
            self.len -= 1;
            self.allocator.destroy(node);
        }

        pub fn init(allocator: Allocator) Allocator.Error!Self {
            var self = Self{
                .allocator = allocator,
                .hashmap = std.AutoArrayHashMap(K, *Node).init(allocator),
                .dbl_link_list = TailQueue(Entry){},
                .max_items = max_items,
                .mux = std.Thread.Mutex{},
            };

            // pre allocate enough capacity for max items since we will use
            // assumed capacity and non-clobber methods
            try self.hashmap.ensureTotalCapacity(self.max_items);

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.mux.lock();
            defer self.mux.unlock();
            while (self.dbl_link_list.pop()) |node| {
                self.deinitNode(node);
            }
            self.hashmap.deinit();
        }

        /// Inserts key/value if key doesn't exist, updates only value if it does.
        /// In any case, it will affect cache ordering.
        pub fn insert(self: *Self, key: K, value: V) Allocator.Error!void {
            self.mux.lock();
            defer self.mux.unlock();

            // if key exists, we update it
            if (self.hashmap.get(key)) |existing_node| {
                self.dbl_link_list.remove(existing_node);
                existing_node.data.value = value;
                self.dbl_link_list.append(existing_node);
                return;
            }

            if (self.dbl_link_list.len + 1 > self.max_items) {
                var recycled_node = self.dbl_link_list.popFirst().?;
                assert(self.hashmap.swapRemove(recycled_node.data.key));
                // after swap, this node is thrown away
                var node_to_swap: Node = .{
                    .data = Entry.init(key, value),
                    .next = null,
                    .prev = null,
                };
                std.mem.swap(Node, recycled_node, &node_to_swap);
                self.dbl_link_list.append(recycled_node);
                self.hashmap.putAssumeCapacityNoClobber(key, recycled_node);
                return;
            }

            // key not exist, alloc a new node
            var node = try self.initNode(key, value);
            self.hashmap.putAssumeCapacityNoClobber(key, node);
            self.dbl_link_list.append(node);
        }

        /// Whether or not contains key.
        /// NOTE: doesn't affect cache ordering.
        pub fn contains(self: *Self, key: K) bool {
            self.mux.lock();
            defer self.mux.unlock();
            return self.hashmap.contains(key);
        }

        /// Most recently used entry
        pub fn mru(self: *Self) ?Entry {
            self.mux.lock();
            defer self.mux.unlock();
            if (self.dbl_link_list.last) |node| {
                return node.data;
            }
            return null;
        }

        /// Least recently used entry
        pub fn lru(self: *Self) ?Entry {
            self.mux.lock();
            defer self.mux.unlock();
            if (self.dbl_link_list.first) |node| {
                return node.data;
            }
            return null;
        }

        /// Gets value associated with key if exists
        pub fn get(self: *Self, key: K) ?V {
            self.mux.lock();
            defer self.mux.unlock();

            if (self.hashmap.get(key)) |node| {
                self.dbl_link_list.remove(node);
                self.dbl_link_list.append(node);
                return node.data.value;
            }
            return null;
        }

        /// Removes key from cache. Returns true if found, false if not.
        pub fn remove(self: *Self, key: K) bool {
            self.mux.lock();
            defer self.mux.unlock();
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
    var cache = try LruCache(u64, []const u8, 4).init(testing.allocator);
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
