const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const DoublyLinkedList = std.DoublyLinkedList;
const testing = std.testing;
const Mutex = std.Thread.Mutex;

const normalizeDeinitFunction = sig.sync.normalizeDeinitFunction;

pub const Kind = enum {
    locking,
    non_locking,
};

pub fn LruCache(
    comptime kind: Kind,
    comptime K: type,
    comptime V: type,
) type {
    return LruCacheCustom(kind, K, V, void, struct {
        fn noop(_: *V, _: void) void {}
    }.noop);
}

/// LruCache that allows you to specify a custom deinit function
/// to call on a node's data when the node is removed.
///
/// TODO: allow for passing custom hash context to use in std.ArrayHashMap for performance.
pub fn LruCacheCustom(
    comptime kind: Kind,
    comptime K: type,
    comptime V: type,
    comptime DeinitContext: type,
    comptime deinitFn_: anytype,
) type {
    const deinitFn = normalizeDeinitFunction(V, DeinitContext, deinitFn_);
    return struct {
        mux: if (kind == .locking) Mutex else void,
        allocator: Allocator,
        hashmap: if (K == []const u8)
            std.StringArrayHashMap(*Node)
        else
            std.AutoArrayHashMap(K, *Node),
        dbl_link_list: DoublyLinkedList(LruEntry),
        max_items: usize,
        len: usize = 0,
        deinit_context: DeinitContext,

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

        const Node = DoublyLinkedList(LruEntry).Node;

        fn initNode(self: *Self, key: K, val: V) error{OutOfMemory}!*Node {
            self.len += 1;
            const node = try self.allocator.create(Node);
            node.* = .{ .data = LruEntry.init(key, val) };
            return node;
        }

        fn deinitNode(self: *Self, node: *Node) void {
            self.len -= 1;
            deinitFn(&node.data.value, self.deinit_context);
            self.allocator.destroy(node);
        }

        /// Use if DeinitContext is void.
        pub fn init(allocator: Allocator, max_items: usize) error{OutOfMemory}!Self {
            return Self.initWithContext(allocator, max_items, void{});
        }

        /// Use if DeinitContext is not void.
        pub fn initWithContext(
            allocator: Allocator,
            max_items: usize,
            deinit_context: DeinitContext,
        ) error{OutOfMemory}!Self {
            const hashmap = if (K == []const u8)
                std.StringArrayHashMap(*Node).init(allocator)
            else
                std.AutoArrayHashMap(K, *Node).init(allocator);
            var self = Self{
                .allocator = allocator,
                .hashmap = hashmap,
                .dbl_link_list = DoublyLinkedList(LruEntry){},
                .max_items = max_items,
                .mux = if (kind == .locking) Mutex{} else undefined,
                .deinit_context = deinit_context,
            };
            errdefer self.hashmap.deinit();

            // pre allocate enough capacity for max items since we will use
            // assumed capacity and non-clobber methods
            try self.hashmap.ensureTotalCapacity(self.max_items);

            return self;
        }

        pub fn deinit(self: *Self) void {
            while (self.dbl_link_list.pop()) |node| {
                self.deinitNode(node);
            }
            std.debug.assert(self.len == 0); // no leaks
            self.hashmap.deinit();
        }

        /// Recycles an old node if LruCache capacity is full.
        /// If replaced, first element of tuple is replaced.
        /// Entry (otherwise null) and second element of tuple is inserted Entry.
        fn internalRecycleOrCreateNode(
            self: *Self,
            key: K,
            value: V,
        ) error{OutOfMemory}!struct { ?LruEntry, LruEntry } {
            if (self.dbl_link_list.len == self.max_items) {
                const recycled_node = self.dbl_link_list.popFirst().?;
                deinitFn(&recycled_node.data.value, self.deinit_context);
                std.debug.assert(self.hashmap.swapRemove(recycled_node.data.key));
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
            const node = try self.initNode(key, value);
            self.hashmap.putAssumeCapacityNoClobber(key, node);
            self.dbl_link_list.append(node);
            return .{ null, node.data };
        }

        fn internalInsert(self: *Self, key: K, value: V) LruEntry {
            // if key exists, we update it
            if (self.hashmap.get(key)) |existing_node| {
                existing_node.data.value = value;
                self.internalReorder(existing_node);
                return existing_node.data;
            }

            const replaced_node = self.internalRecycleOrCreateNode(key, value) catch |e| {
                std.debug.panic("recycle_or_create_node returned error: {any}", .{e});
            };
            return replaced_node[1];
        }

        /// Inserts key/value if key doesn't exist, updates only value if it does.
        /// In any case, it will affect cache ordering.
        pub fn insert(self: *Self, key: K, value: V) error{OutOfMemory}!void {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            _ = self.internalInsert(key, value);
            return;
        }

        /// Whether or not contains key.
        /// NOTE: doesn't affect cache ordering.
        pub fn contains(self: *Self, key: K) bool {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            return self.hashmap.contains(key);
        }

        /// Most recently used entry
        pub fn mru(self: *Self) ?LruEntry {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            if (self.dbl_link_list.last) |node| {
                return node.data;
            }
            return null;
        }

        /// Least recently used entry
        pub fn lru(self: *Self) ?LruEntry {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            if (self.dbl_link_list.first) |node| {
                return node.data;
            }
            return null;
        }

        // reorder Node to the top
        fn internalReorder(self: *Self, node: *Node) void {
            self.dbl_link_list.remove(node);
            self.dbl_link_list.append(node);
        }

        /// Gets value associated with key if exists
        pub fn get(self: *Self, key: K) ?V {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            if (self.hashmap.get(key)) |node| {
                self.dbl_link_list.remove(node);
                self.dbl_link_list.append(node);
                return node.data.value;
            }
            return null;
        }

        pub fn pop(self: *Self, k: K) ?V {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            if (self.hashmap.fetchSwapRemove(k)) |kv| {
                const node = kv.value;
                self.dbl_link_list.remove(node);
                defer self.deinitNode(node);
                return node.data.value;
            }
            return null;
        }

        pub fn peek(self: *Self, key: K) ?V {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            if (self.hashmap.get(key)) |node| {
                return node.data.value;
            }

            return null;
        }

        /// Puts a key-value pair into cache. If the key already exists in the cache,
        /// then it updates the key's value and returns the old value.
        /// Otherwise, `null` is returned.
        pub fn put(self: *Self, key: K, value: V) ?V {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            if (self.hashmap.getEntry(key)) |existing_entry| {
                var existing_node: *Node = existing_entry.value_ptr.*;
                const old_value = existing_node.data.value;
                existing_node.data.value = value;
                self.internalReorder(existing_node);
                return old_value;
            }

            _ = self.internalInsert(key, value);
            return null;
        }

        pub fn putNoClobber(self: *Self, key: K, value: V) !void {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            if (self.hashmap.contains(key)) return error.EntryAlreadyExists;

            _ = self.internalInsert(key, value);
        }

        /// Removes key from cache. Returns true if found, false if not.
        pub fn remove(self: *Self, key: K) bool {
            if (kind == .locking) self.mux.lock();
            defer if (kind == .locking) self.mux.unlock();

            if (self.hashmap.fetchSwapRemove(key)) |kv| {
                const node = kv.value;
                self.dbl_link_list.remove(node);
                self.deinitNode(node);
                return true;
            }
            return false;
        }
    };
}

test "common.lru: LruCache state is correct" {
    var cache = try LruCache(.locking, u64, []const u8).init(testing.allocator, 4);
    defer cache.deinit();

    try cache.insert(1, "one");
    try cache.insert(2, "two");
    try cache.insert(3, "three");
    try cache.insert(4, "four");
    try testing.expectEqual(@as(usize, 4), cache.dbl_link_list.len);
    try testing.expectEqual(@as(usize, 4), cache.hashmap.keys().len);
    try testing.expectEqual(@as(usize, 4), cache.len);

    const val = cache.get(2);
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
    var cache = try LruCache(.non_locking, []const u8, usize).init(testing.allocator, 4);
    defer cache.deinit();

    try cache.insert("a", 1);

    const old = cache.put("a", 2);

    try testing.expectEqual(@as(usize, 1), old.?);
    try testing.expectEqual(@as(usize, 2), cache.get("a").?);

    const possible_old = cache.put("b", 3);
    try testing.expectEqual(possible_old, null);
    try testing.expectEqual(@as(usize, 3), cache.get("b").?);
}

test "common.lru: locked put is thread safe" {
    var cache = try LruCache(.locking, usize, usize).init(testing.allocator, 4);
    defer cache.deinit();
    var threads = std.array_list.Managed(std.Thread).init(testing.allocator);
    defer threads.deinit();
    for (0..2) |_| try threads.append(try std.Thread.spawn(.{}, testPut, .{ &cache, 1 }));
    for (threads.items) |thread| thread.join();
}

test "common.lru: locked insert is thread safe" {
    var cache = try LruCache(.locking, usize, usize).init(testing.allocator, 4);
    defer cache.deinit();
    var threads = std.array_list.Managed(std.Thread).init(testing.allocator);
    defer threads.deinit();
    for (0..2) |_| try threads.append(try std.Thread.spawn(.{}, testInsert, .{ &cache, 1 }));
    for (threads.items) |thread| thread.join();
}

fn testPut(lru_cache: *LruCache(.locking, usize, usize), k: usize) void {
    _ = lru_cache.put(k, 2);
}
fn testInsert(lru_cache: *LruCache(.locking, usize, usize), k: usize) void {
    _ = lru_cache.insert(k, 2) catch unreachable;
}
