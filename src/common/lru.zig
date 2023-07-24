const std = @import("std");
const Allocator = std.mem.Allocator;
const TailQueue = std.TailQueue;
const testing = std.testing;
const assert = std.debug.assert;

pub fn LruCache(comptime K: type, comptime V: type, comptime max_items: usize) type {
    return struct {
        allocator: Allocator,
        hashmap: std.AutoArrayHashMap(K, *Node),
        dbl_link_list: TailQueue(Entry),
        max_items: usize,
        mux: std.Thread.Mutex,

        const Self = @This();

        const Entry = struct {
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
            var node = try self.allocator.create(Node);
            node.* = .{ .data = Entry.init(key, val) };
            return node;
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
            while (self.dbl_link_list.pop()) |node| {
                self.allocator.destroy(node);
            }
            self.hashmap.deinit();
        }

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

            // key not exist, alloc a new node
            var node = try self.initNode(key, value);
            self.hashmap.putAssumeCapacityNoClobber(key, node);
            self.dbl_link_list.append(node);

            if (self.dbl_link_list.len > self.max_items) {
                var lru_node = self.dbl_link_list.popFirst().?;
                assert(self.hashmap.swapRemove(lru_node.data.key));
                self.allocator.destroy(lru_node);
                return;
            }
        }

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

    var val = cache.get(2);
    try testing.expectEqual(val.?, "two");
    try testing.expectEqual(cache.dbl_link_list.last.?.data.key, 2);
    try testing.expectEqual(cache.dbl_link_list.first.?.data.key, 1);

    try cache.insert(5, "five");
    try testing.expectEqual(cache.dbl_link_list.last.?.data.key, 5);
    try testing.expectEqual(cache.dbl_link_list.first.?.data.key, 3);
    try testing.expectEqual(@as(usize, 4), cache.dbl_link_list.len);
    try testing.expectEqual(@as(usize, 4), cache.hashmap.keys().len);
}
