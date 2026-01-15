const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub fn PubkeyMap(T: type) type {
    // TODO: benchmark true vs false?
    return std.ArrayHashMapUnmanaged(sig.core.Pubkey, T, MapContext, true);
}

pub fn PubkeyMapManaged(T: type) type {
    return std.ArrayHashMap(sig.core.Pubkey, T, MapContext, true);
}

const MapContext = struct {
    // Applies a Murmur-like LCG to the public key, in order to alivate a
    // bit of the bucketing that may happen if we load many vanity public keys,
    // where the first bytes are mined.
    pub fn hash(_: MapContext, pubkey: sig.core.Pubkey) u32 {
        var h: u32 = 0;
        const pk: [8]u32 = @bitCast(pubkey.data);
        for (pk) |k| h ^= k +% 1;
        h ^= h >> 16;
        h *%= 0x85ebca6b;
        h ^= h >> 13;
        h *%= 0xc2b2ae35;
        h ^= h >> 16;
        return h;
    }

    pub fn eql(_: MapContext, a: sig.core.Pubkey, b: sig.core.Pubkey, _: usize) bool {
        return a.equals(&b);
    }
};

/// A list that recycles items that were removed from the list.
///
/// Useful for types that are expensive to instantiate, like
/// those that include allocations.
///
/// When you call `addOne`, it returns a pointer to an item of type
/// type T, which could either be a new item created with initBlank,
/// or one that was previously removed from the list and had
/// resetItem called on it.
pub fn RecyclingList(
    comptime T: type,
    comptime initBlank: fn (Allocator) T,
    comptime resetItem: fn (*T) void,
    comptime deinitOne: fn (T) void,
) type {
    return struct {
        /// Contains valid items up to `len`
        /// Any other items beyond len in this arraylist are not valid.
        private: ArrayList(T),
        len: usize = 0,

        const Self = @This();

        pub fn init(allocator: Allocator) Self {
            return .{ .private = ArrayList(T).init(allocator) };
        }

        pub fn deinit(self: Self) void {
            for (self.private.items) |item| deinitOne(item);
            self.private.deinit();
        }

        pub fn items(self: *const Self) []const T {
            return self.private.items[0..self.len];
        }

        pub fn clearRetainingCapacity(self: *Self) void {
            self.len = 0;
        }

        pub fn addOne(self: *Self) Allocator.Error!*T {
            if (self.len < self.private.items.len) {
                const item = &self.private.items[self.len];
                resetItem(item);
                self.len += 1;
                return item;
            } else {
                const item = try self.private.addOne();
                item.* = initBlank(self.private.allocator);
                self.len += 1;
                return item;
            }
        }

        pub fn drop(self: *Self, n: usize) void {
            self.len -|= n;
        }
    };
}

/// Efficiently stores a collection of instances of a tagged union.
///
/// - Uses less memory than an ArrayList (for heterogeneously sized unions)
/// - Does not preserve insertion order (items are indexed with a struct)
///
/// This reduces space compared to an ArrayList by storing the union
/// fields' inner data types rather than storing the union itself.
/// Normally when you store the union directly, each instance of that
/// union uses the amount of memory of the *largest* variant of that
/// union. With this approach, each instance only uses the amount of
/// memory needed for that specific variant of the union.
///
/// This is accomplished by storing a struct of lists, with one list
/// for each union variant, instead of storing a list of the union.
pub fn SplitUnionList(TaggedUnion: type) type {
    const Tag = @typeInfo(TaggedUnion).@"union".tag_type.?;

    return struct {
        lists: sig.utils.types.EnumStruct(Tag, List),

        const Self = @This();

        pub const Index = struct {
            tag: Tag,
            index: usize,
        };

        fn List(tag: Tag) type {
            return std.ArrayListUnmanaged(FieldType(tag));
        }

        fn FieldType(tag: Tag) type {
            inline for (@typeInfo(TaggedUnion).@"union".fields) |field| {
                if (std.mem.eql(u8, field.name, @tagName(tag))) {
                    return field.type;
                }
            }
        }

        pub fn init() Self {
            var lists: sig.utils.types.EnumStruct(Tag, List) = undefined;
            inline for (@typeInfo(Tag).@"enum".fields) |f| {
                @field(lists, f.name) = .{};
            }
            return .{ .lists = lists };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            inline for (@typeInfo(Tag).@"enum".fields) |f| {
                @field(self.lists, f.name).deinit(allocator);
            }
        }

        pub fn append(self: *Self, allocator: Allocator, item: TaggedUnion) Allocator.Error!Index {
            switch (@as(Tag, item)) {
                inline else => |tag| {
                    const list = self.listMut(tag);
                    const unwrapped_item = @field(item, @tagName(tag));
                    try list.append(allocator, unwrapped_item);
                    return .{
                        .tag = tag,
                        .index = list.items.len - 1,
                    };
                },
            }
        }

        pub fn addOne(self: *Self, allocator: Allocator, tag: Tag) Allocator.Error!Entry {
            switch (tag) {
                inline else => |comptime_tag| {
                    const list = self.listMut(comptime_tag);
                    return .{
                        .ptr = try list.addOne(allocator),
                        .index = .{
                            .tag = tag,
                            .index = list.items.len - 1,
                        },
                    };
                },
            }
        }

        pub const Entry = struct {
            ptr: *anyopaque,
            index: Index,

            pub fn read(self: Entry) TaggedUnion {
                switch (self.index.tag) {
                    inline else => |tag| {
                        const ptr: *FieldType(tag) = @ptrCast(@alignCast(self.ptr));
                        return @unionInit(TaggedUnion, @tagName(tag), ptr.*);
                    },
                }
            }

            pub fn write(self: Entry, item: TaggedUnion) void {
                switch (self.index.tag) {
                    inline else => |tag| {
                        const ptr: *FieldType(tag) = @ptrCast(@alignCast(self.ptr));
                        ptr.* = @field(item, @tagName(tag)); // implicitly asserts tag is correct
                    },
                }
            }
        };

        pub fn swapRemove(self: *Self, index: Index) TaggedUnion {
            switch (index.tag) {
                inline else => |tag| {
                    const list = self.listMut(tag);
                    const item = list.swapRemove(index.index);
                    return @unionInit(TaggedUnion, @tagName(tag), item);
                },
            }
        }

        /// returns the number of contained items with this tag.
        pub fn tagLen(self: *const Self, tag: Tag) usize {
            return switch (tag) {
                inline else => |comptime_tag| self.listConst(comptime_tag).items.len,
            };
        }

        pub fn get(self: *const Self, index: Index) TaggedUnion {
            return switch (index.tag) {
                inline else => |comptime_tag| @unionInit(
                    TaggedUnion,
                    @tagName(comptime_tag),
                    self.listConst(comptime_tag).items[index.index],
                ),
            };
        }

        pub fn getEntry(self: *const Self, index: Index) Entry {
            return switch (index.tag) {
                inline else => |comptime_tag| .{
                    .index = index,
                    .ptr = &self.listConst(comptime_tag).items[index.index],
                },
            };
        }

        pub fn getTypedConst(
            self: *const Self,
            comptime tag: Tag,
            index: Index,
        ) *const FieldType(tag) {
            return &self.listConst(tag).items[index.index];
        }

        pub fn getTypedMut(self: *Self, comptime tag: Tag, index: Index) *FieldType(tag) {
            return &self.listMut(tag).items[index.index];
        }

        fn listConst(self: *const Self, comptime tag: Tag) *const List(tag) {
            return &@field(self.lists, @tagName(tag));
        }

        fn listMut(self: *Self, comptime tag: Tag) *List(tag) {
            return &@field(self.lists, @tagName(tag));
        }
    };
}

test "SplitUnionList: addOne, get, and swapRemove" {
    const allocator = std.testing.allocator;
    const Union = union(enum) { one: u8, two: u32, three: u64 };
    var list = SplitUnionList(Union).init();
    defer list.deinit(allocator);
    var entry = try list.addOne(allocator, .one);
    entry.write(.{ .one = 0 });
    entry = try list.addOne(allocator, .one);
    entry.write(.{ .one = 1 });
    entry = try list.addOne(allocator, .one);
    entry.write(.{ .one = 2 });
    entry = try list.addOne(allocator, .one);
    entry.write(.{ .one = 3 });
    try std.testing.expectEqual(Union{ .one = 0 }, list.get(.{ .tag = .one, .index = 0 }));
    try std.testing.expectEqual(Union{ .one = 1 }, list.get(.{ .tag = .one, .index = 1 }));
    try std.testing.expectEqual(Union{ .one = 2 }, list.get(.{ .tag = .one, .index = 2 }));
    try std.testing.expectEqual(Union{ .one = 3 }, list.get(.{ .tag = .one, .index = 3 }));

    _ = list.swapRemove(.{ .tag = .one, .index = 1 });
    try std.testing.expectEqual(Union{ .one = 0 }, list.get(.{ .tag = .one, .index = 0 }));
    try std.testing.expectEqual(Union{ .one = 3 }, list.get(.{ .tag = .one, .index = 1 }));
    try std.testing.expectEqual(Union{ .one = 2 }, list.get(.{ .tag = .one, .index = 2 }));

    _ = list.swapRemove(.{ .tag = .one, .index = 0 });
    try std.testing.expectEqual(Union{ .one = 2 }, list.get(.{ .tag = .one, .index = 0 }));
    try std.testing.expectEqual(Union{ .one = 3 }, list.get(.{ .tag = .one, .index = 1 }));

    _ = list.swapRemove(.{ .tag = .one, .index = 0 });
    try std.testing.expectEqual(Union{ .one = 3 }, list.get(.{ .tag = .one, .index = 0 }));

    _ = list.swapRemove(.{ .tag = .one, .index = 0 });
}

pub fn SortedTreeConfig(comptime Key: type) type {
    const can_default_key = switch (@typeInfo(Key)) {
        .@"struct", .@"enum", .@"union" => @hasDecl(Key, "empty") and @TypeOf(Key.empty) == Key,
        else => false,
    };

    const eql = struct {
        fn f(a: Key, b: Key) bool {
            return if (Key == []const u8)
                std.mem.eql(u8, a, b)
            else
                std.meta.eql(a, b);
        }
    }.f;

    return if (can_default_key)
        struct {
            orderFn: fn (a: anytype, b: anytype) std.math.Order = order,
            eql_fn: fn (a: Key, b: Key) bool = eql,
            empty_key: Key = Key.empty,
        }
    else
        struct {
            orderFn: fn (a: anytype, b: anytype) std.math.Order = order,
            eql_fn: fn (a: Key, b: Key) bool = eql,
            empty_key: Key,
        };
}

pub fn SortedSet(comptime Key: type, comptime config: SortedTreeConfig(Key)) type {
    return SortedMap(Key, void, config);
}

pub fn SortedMap(
    comptime Key: type,
    comptime Value: type,
    comptime config: SortedTreeConfig(Key),
) type {
    return struct {
        data: std.ArrayListAlignedUnmanaged(u8, node_alignment),
        tree: struct { root: Offset, height: u8, count: u32 },

        pub const empty: Self = .{
            .data = .empty,
            .tree = .{ .root = no_root, .height = 0, .count = 0 },
        };

        const Self = @This();
        const Offset = u32; // index into self.data

        const no_root = std.math.maxInt(Offset); // root is allocated on first insert
        const B = 32;
        const max_height = 8; // allows for `pow(B / 2, height)` max entries
        const EMPTY_KEY = config.empty_key;

        const Path = struct {
            key: Key,
            idx_stack: [max_height]u8,
            node_stack: [max_height]Offset,
        };
        const InnerNode = struct { keys: [B]Key, values: [B]Offset };
        const LeafNode = struct {
            keys: [B]Key,
            values: [B]Value,

            fn relativeOffset(kind: enum { key, value }, idx: u8) u32 {
                return switch (kind) {
                    .key => 0 +
                        @as(u32, idx) * @sizeOf(Key),
                    .value => @offsetOf(LeafNode, "values") +
                        @as(u32, idx) * @sizeOf(Value),
                };
            }
        };

        const node_alignment = @max(
            @alignOf(LeafNode),
            @alignOf(InnerNode),
            @alignOf(Value),
        );

        pub const Entry = struct {
            key_ptr: *const Key,
            value_ptr: *Value,
        };

        pub const GetOrPutResult = struct {
            key_ptr: *const Key,
            value_ptr: *Value,
            found_existing: bool,
        };

        pub const KV = struct {
            key: Key,
            value: Value,
        };

        /// An entry iterator. NOTE: any insertion or deletion performed while iterating will
        /// invalide the iterator.
        pub const Iterator = struct {
            sorted_tree: *const Self,
            path: Path,
            end: ?Key = null,
            start: ?Key = null,

            pub fn next(self: *Iterator) ?Entry {
                return self.nextInner(.exclusive);
            }

            pub fn nextInclusive(self: *Iterator) ?Entry {
                return self.nextInner(.inclusive);
            }

            fn nextInner(self: *Iterator, mode: enum { inclusive, exclusive }) ?Entry {
                if (self.sorted_tree.tree.root == no_root) return null;

                var node_offset: Offset = self.path.node_stack[self.sorted_tree.tree.height];

                while (true) {
                    const leaf = self.sorted_tree.asPtr(LeafNode, node_offset);
                    const idx = self.path.idx_stack[self.sorted_tree.tree.height];

                    // at a leaf node, return next value if there is one
                    if (idx < B and !keysEql(leaf.keys[idx], EMPTY_KEY)) {
                        // support ending early
                        if (self.end) |end_key| {
                            const early_return = switch (mode) {
                                .exclusive => config.orderFn(leaf.keys[idx], end_key) != .lt,
                                .inclusive => config.orderFn(leaf.keys[idx], end_key) == .gt,
                            };
                            if (early_return) return null;
                        }

                        const result: Entry = .{
                            .key_ptr = &leaf.keys[idx],
                            .value_ptr = &leaf.values[idx],
                        };
                        // NOTE: this allows idx_stack to store indexes which equal B.
                        // This means that it would be an out of bounds access if used.
                        self.path.idx_stack[self.sorted_tree.tree.height] += 1;
                        return result;
                    }

                    // try to find next leaf node
                    var found_parent = false;
                    var h = self.sorted_tree.tree.height;
                    while (h > 0) {
                        h -= 1;
                        const parent_node = self.path.node_stack[h];
                        const parent_idx = self.path.idx_stack[h];
                        const parent_inner = self.sorted_tree.asPtr(InnerNode, parent_node);

                        if (parent_idx < B and !keysEql(parent_inner.keys[parent_idx], EMPTY_KEY)) {
                            node_offset = parent_inner.values[parent_idx + 1];
                            self.path.idx_stack[h] += 1;

                            // Descend to leftmost leaf
                            var hh: u8 = h + 1;
                            while (hh <= self.sorted_tree.tree.height) : (hh += 1) {
                                self.path.idx_stack[hh] = 0;
                                self.path.node_stack[hh] = node_offset;

                                if (hh == self.sorted_tree.tree.height) break;
                                const inner = self.sorted_tree.asPtr(InnerNode, node_offset);
                                node_offset = inner.values[0];
                            }

                            found_parent = true;
                            break;
                        }
                    }

                    if (!found_parent) return null; // iteration finished
                }
            }

            pub fn prev(self: *Iterator) ?Entry {
                if (self.sorted_tree.tree.root == no_root) return null;

                var node_offset: Offset = self.path.node_stack[self.sorted_tree.tree.height];

                while (true) {
                    const leaf = self.sorted_tree.asPtr(LeafNode, node_offset);
                    const idx = self.path.idx_stack[self.sorted_tree.tree.height];

                    if (idx < B and !keysEql(leaf.keys[idx], EMPTY_KEY)) {
                        if (self.start) |start_key| {
                            if (config.orderFn(leaf.keys[idx], start_key) == .lt) return null;
                        }

                        const result: Entry = .{
                            .key_ptr = &leaf.keys[idx],
                            .value_ptr = &leaf.values[idx],
                        };

                        self.path.idx_stack[self.sorted_tree.tree.height] -%= 1;

                        return result;
                    }

                    // try to find previous leaf node
                    var found_parent = false;
                    var h = self.sorted_tree.tree.height;
                    while (h > 0) {
                        h -= 1;
                        const parent_node = self.path.node_stack[h];
                        const parent_idx = self.path.idx_stack[h];
                        const parent_inner = self.sorted_tree.asPtr(InnerNode, parent_node);
                        if (parent_idx > 0 and
                            !keysEql(parent_inner.keys[parent_idx - 1], EMPTY_KEY))
                        {
                            node_offset = parent_inner.values[parent_idx - 1];
                            self.path.idx_stack[h] = parent_idx - 1;
                            // Descend to rightmost leaf
                            var hh: u8 = h + 1;
                            while (hh <= self.sorted_tree.tree.height) : (hh += 1) {
                                const inner = self.sorted_tree.asPtr(InnerNode, node_offset);
                                const last_idx = lastNonEmpty(&inner.keys);
                                self.path.idx_stack[hh] = last_idx;
                                self.path.node_stack[hh] = node_offset;
                                if (hh == self.sorted_tree.tree.height) break;
                                node_offset = inner.values[last_idx];
                            }
                            found_parent = true;
                            break;
                        }
                    }
                    if (!found_parent) return null; // iteration finished
                }
            }

            pub fn countForwards(self: *Iterator) u32 {
                var i: u32 = 0;
                while (self.next()) |_| i += 1;
                return i;
            }

            pub fn countBackwards(self: *Iterator) u32 {
                var i: u32 = 0;
                while (self.prev()) |_| i += 1;
                return i;
            }

            pub fn countForwardsInclusive(self: *Iterator) u32 {
                var i: u32 = 0;
                while (self.nextInclusive()) |_| i += 1;
                return i;
            }

            pub fn countBackwardsInclusive(self: *Iterator) u32 {
                var i: u32 = 0;
                while (self.prev()) |_| i += 1;
                return i;
            }
        };

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.data.deinit(allocator);
        }

        pub fn get(self: *const Self, key: Key) ?Value {
            const val_ptr = self.getPtr(key) orelse return null;
            return val_ptr.*;
        }

        pub fn getPtr(self: *const Self, key: Key) ?*Value {
            if (keysEql(key, EMPTY_KEY)) unreachable; // likely a mistake
            if (self.tree.root == no_root) return null;

            var path: Path = undefined;
            return (self.lookup(&path, key) orelse return null).value_ptr;
        }

        pub fn getEntry(self: *const Self, key: Key) ?Entry {
            if (keysEql(key, EMPTY_KEY)) unreachable; // likely a mistake
            if (self.tree.root == no_root) return null;

            var path: Path = undefined;
            return self.lookup(&path, key);
        }

        pub fn getOrPut(
            self: *Self,
            allocator: std.mem.Allocator,
            key: Key,
        ) !GetOrPutResult {
            if (keysEql(key, EMPTY_KEY)) unreachable; // likely a mistake

            if (self.tree.root == no_root) {
                self.tree.root = try self.allocNode(allocator, LeafNode);
            }

            var path: Path = undefined;
            var found_existing: bool = true;
            const entry = self.lookup(&path, key) orelse blk: {
                found_existing = false;
                break :blk try self.insert(allocator, &path, key);
            };

            return .{
                .key_ptr = entry.key_ptr,
                .value_ptr = entry.value_ptr,
                .found_existing = found_existing,
            };
        }

        pub fn contains(self: *const Self, key: Key) bool {
            if (keysEql(key, EMPTY_KEY)) unreachable; // likely a mistake
            if (self.tree.root == no_root) return false;

            var path: Path = undefined;
            _ = self.lookup(&path, key) orelse return false;
            return true;
        }

        pub fn put(self: *Self, allocator: std.mem.Allocator, key: Key, value: Value) !void {
            if (keysEql(key, EMPTY_KEY)) unreachable; // likely a mistake

            if (self.tree.root == no_root) {
                self.tree.root = try self.allocNode(allocator, LeafNode);
            }

            var path: Path = undefined;
            const entry = self.lookup(&path, key) orelse
                try self.insert(allocator, &path, key);
            entry.value_ptr.* = value;
        }

        pub fn fetchPut(self: *Self, allocator: std.mem.Allocator, key: Key, value: Value) !?KV {
            const entry = try self.getOrPut(allocator, key);
            var result: ?KV = null;
            if (entry.found_existing) {
                result = KV{
                    .key = entry.key_ptr.*,
                    .value = entry.value_ptr.*,
                };
            }
            entry.value_ptr.* = value;
            return result;
        }

        pub fn fetchRemove(self: *Self, key: Key) ?KV {
            const entry = self.getEntry(key) orelse return null;

            const result: KV = .{
                .key = entry.key_ptr.*,
                .value = entry.value_ptr.*,
            };

            std.debug.assert(self.remove(key)); // TODO: skip this double lookup

            return result;
        }

        pub fn remove(self: *Self, key: Key) bool {
            if (keysEql(key, EMPTY_KEY)) unreachable; // likely a mistake
            if (self.tree.root == no_root) return false;

            var path: Path = undefined;
            _ = self.lookup(&path, key) orelse return false;
            self.tree.count -= 1;

            const leaf_node: Offset = path.node_stack[self.tree.height];
            const idx: u8 = path.idx_stack[self.tree.height];

            const leaf = self.asPtr(LeafNode, leaf_node);

            const n_used_keys = countLessThan(&leaf.keys, EMPTY_KEY);
            std.mem.copyForwards(Key, leaf.keys[idx .. B - 1], leaf.keys[idx + 1 ..]);
            std.mem.copyForwards(Value, leaf.values[idx .. B - 1], leaf.values[idx + 1 ..]);
            leaf.keys[n_used_keys] = EMPTY_KEY;

            return true;
        }

        // Iterate over keys from start (inclusive) to end (exclusive)
        pub fn iteratorRanged(
            self: *const Self,
            maybe_start: ?Key,
            maybe_end: ?Key,
            begin: enum { start, end },
        ) Iterator {
            var path: Path = undefined;

            // This iterator will only return null
            if (self.tree.root == no_root) return .{
                .sorted_tree = self,
                .path = path,
                .end = maybe_end,
                .start = maybe_start,
            };

            switch (begin) {
                .start => if (maybe_start) |start| {
                    _ = self.lookup(&path, start);
                } else self.minPath(&path),
                .end => if (maybe_end) |end| {
                    _ = self.lookup(&path, end);
                } else self.maxPath(&path),
            }

            return .{
                .sorted_tree = self,
                .path = path,
                .end = maybe_end,
                .start = maybe_start,
            };
        }

        pub fn iterator(self: *const Self) Iterator {
            return self.iteratorRanged(null, null, .start);
        }

        pub fn count(self: *const Self) u32 {
            return self.tree.count;
        }

        pub fn clone(self: *const Self, allocator: std.mem.Allocator) !Self {
            const cloned_data = try self.data.clone(allocator);
            return .{
                .data = cloned_data,
                .tree = self.tree,
            };
        }

        pub fn maxEntry(self: *const Self) ?Entry {
            if (self.tree.root == no_root) return null;

            var path: Path = undefined;
            self.maxPath(&path);

            const leaf = self.asPtr(LeafNode, path.node_stack[self.tree.height]);
            const idx = path.idx_stack[self.tree.height];

            if (keysEql(leaf.keys[idx], EMPTY_KEY)) return null;

            return .{
                .value_ptr = &leaf.values[idx],
                .key_ptr = &leaf.keys[idx],
            };
        }

        pub fn minEntry(self: *const Self) ?Entry {
            if (self.tree.root == no_root) return null;

            var path: Path = undefined;
            self.minPath(&path);

            const leaf = self.asPtr(LeafNode, path.node_stack[self.tree.height]);
            const idx = path.idx_stack[self.tree.height];

            if (keysEql(leaf.keys[idx], EMPTY_KEY)) return null;

            return .{
                .value_ptr = &leaf.values[idx],
                .key_ptr = &leaf.keys[idx],
            };
        }

        // NOTE: this function assumes a total ordering - comparing two trees with a partial
        // ordering would require using memory.
        pub fn eql(self: *const Self, other: *const Self) bool {
            var self_iter = self.iterator();
            var other_iter = other.iterator();

            while (true) {
                const maybe_elem = self_iter.next();
                const maybe_other_elem = other_iter.next();

                if (maybe_elem == null and maybe_other_elem == null) return true;
                if (maybe_elem != null and maybe_other_elem == null) return false;
                if (maybe_elem == null and maybe_other_elem != null) return false;

                const elem = maybe_elem.?;
                const other_elem = maybe_other_elem.?;

                if (elem.value_ptr.* != other_elem.value_ptr.*) return false;
            }
        }

        fn minPath(self: *const Self, path: *Path) void {
            // Traverse down inner nodes until we reach the highest LeafNode, recording the path.
            var node = self.tree.root;
            for (0..self.tree.height) |h| {
                const inner = self.asPtr(InnerNode, node);
                const idx = firstNonEmpty(&inner.keys);
                path.idx_stack[h] = idx;
                path.node_stack[h] = node;
                node = inner.values[idx];
            }

            // Find higher bound in leaf
            const leaf = self.asPtr(LeafNode, node);
            const idx = @min(B - 1, firstNonEmpty(&leaf.keys));

            path.idx_stack[self.tree.height] = idx;
            path.node_stack[self.tree.height] = node;
        }

        fn maxPath(self: *const Self, path: *Path) void {
            // Traverse down inner nodes until we reach the lowest LeafNode, recording the path.
            var node = self.tree.root;
            for (0..self.tree.height) |h| {
                const inner = self.asPtr(InnerNode, node);
                const idx = lastNonEmpty(&inner.keys);
                path.idx_stack[h] = idx;
                path.node_stack[h] = node;
                node = inner.values[idx];
            }

            // Find lower bound in leaf
            const leaf = self.asPtr(LeafNode, node);
            const idx = @min(B - 1, lastNonEmpty(&leaf.keys));

            path.idx_stack[self.tree.height] = idx;
            path.node_stack[self.tree.height] = node;
        }

        fn countLessThan(keys: *const [B]Key, key: Key) u8 {
            if (@typeInfo(Key) == .int and EMPTY_KEY == std.math.maxInt(Key)) {
                const key_vec: @Vector(B, Key) = @splat(key);
                const keys_vec: @Vector(B, Key) = keys.*;
                const lt_mask: std.meta.Int(.unsigned, B) = @bitCast(keys_vec < key_vec);
                return @popCount(lt_mask);
            } else {
                var i: u8 = 0;
                comptime var len: u8 = keys.len;
                inline while (len > 1) {
                    const half = len / 2;
                    len -= half;
                    i += half * @intFromBool(config.orderFn(keys[i + (half - 1)], key) == .lt);
                }
                return i;
            }
        }

        fn keysEql(a: Key, b: Key) bool {
            return config.eql_fn(a, b);
        }

        fn allocNode(self: *Self, allocator: std.mem.Allocator, Node: type) !Offset {
            const padding_len = std.mem.alignForward(usize, self.data.items.len, node_alignment) -
                self.data.items.len;

            try self.data.ensureUnusedCapacity(allocator, @sizeOf(Node) + padding_len);

            const new_node_offset: Offset = @intCast(self.data.items.len + padding_len);
            self.data.items.len += @sizeOf(Node);
            const node: *Node = @alignCast(@ptrCast(
                self.data.items[padding_len..][new_node_offset..][0..@sizeOf(Node)],
            ));
            node.* = .{ .keys = @splat(EMPTY_KEY), .values = @splat(undefined) };
            return new_node_offset;
        }

        fn firstNonEmpty(keys: []const Key) u8 {
            std.debug.assert(keys.len <= B);

            var n_empty: u8 = 0;
            for (keys) |k| {
                if (!keysEql(k, EMPTY_KEY)) break;
                n_empty += 1;
            }
            return n_empty;
        }

        fn lastNonEmpty(keys: []const Key) u8 {
            std.debug.assert(keys.len <= B);

            var i: u8 = @intCast(keys.len);
            while (i > 0) {
                i -= 1;
                if (!keysEql(keys[i], EMPTY_KEY)) break;
            }
            return i;
        }

        fn getSlice(self: *const Self, T: type, offset: Offset, len: usize) []T {
            if (len == 0) return &.{};
            const bytes = self.data.items[offset..][0 .. @sizeOf(T) * len];
            return @as([*]T, @ptrCast(@alignCast(bytes.ptr)))[0..len];
        }

        /// warning: these pointers will be regularly invalidated by arraylist growth
        fn asPtr(self: *const Self, T: type, offset: Offset) *T {
            return @ptrCast(self.getSlice(T, offset, 1).ptr);
        }

        fn lookup(self: *const Self, path: *Path, key: Key) ?Entry {
            path.key = key;

            // Traverse down inner nodes until we reach a LeafNode, recording the path.
            var node = self.tree.root;
            for (0..self.tree.height) |h| {
                const inner = self.asPtr(InnerNode, node);
                const idx = countLessThan(&inner.keys, key);
                path.idx_stack[h] = idx;
                path.node_stack[h] = node;
                node = inner.values[idx];
            }

            // Find lower bound in leaf
            const leaf = self.asPtr(LeafNode, node);
            const idx = countLessThan(&leaf.keys, key);
            path.idx_stack[self.tree.height] = idx;
            path.node_stack[self.tree.height] = node;

            if (keysEql(leaf.keys[idx], key)) return .{
                .value_ptr = &leaf.values[idx],
                .key_ptr = &leaf.keys[idx],
            };

            return null;
        }

        fn insertAt(array: anytype, idx: u32, value: @TypeOf(array[0])) void {
            std.mem.copyBackwards(@TypeOf(array[0]), array[idx + 1 ..], array[idx .. B - 1]);
            array[idx] = value;
        }

        fn moveHalf(noalias old_node: anytype, noalias new_node: @TypeOf(old_node)) void {
            @memset(new_node.keys[B / 2 ..], EMPTY_KEY);
            @memcpy(new_node.keys[0 .. B / 2], old_node.keys[B / 2 ..]);
            @memset(old_node.keys[B / 2 ..], EMPTY_KEY);
            @memcpy(new_node.values[0 .. B / 2], old_node.values[B / 2 ..]);
        }

        fn insert(self: *Self, allocator: std.mem.Allocator, path: *Path, key: Key) !Entry {
            const max_entries = comptime std.math.pow(u64, B / 2, max_height);
            if (self.tree.count == max_entries) return error.SortedTreeTooBig;
            self.tree.count += 1;

            std.debug.assert(keysEql(key, path.key));

            var k = path.key;
            var idx = path.idx_stack[self.tree.height];
            var node = path.node_stack[self.tree.height];

            const leaf_node: Offset = node;

            // NOTE: here we store an Offset, as the pointer may be invalidated in self.allocNode
            var value: Offset, var key_offset: Offset, var filled: bool = blk: {
                const leaf: *LeafNode = self.asPtr(LeafNode, leaf_node);
                std.debug.assertReadable(std.mem.asBytes(leaf[0..1]));

                const value_offset = leaf_node + LeafNode.relativeOffset(.value, idx);
                const value: Value = self.asPtr(Value, value_offset).*;

                insertAt(&leaf.keys, idx, k);
                insertAt(&leaf.values, idx, value);

                break :blk .{
                    value_offset,
                    leaf_node + LeafNode.relativeOffset(.key, idx),
                    !keysEql(leaf.keys[B - 2], EMPTY_KEY),
                };
            };

            if (filled) split: {
                @branchHint(.unlikely);

                // The leaf was filled & needs to be split into a new one.
                var new_node = try self.allocNode(allocator, LeafNode);

                {
                    const new_leaf = self.asPtr(LeafNode, new_node);
                    const leaf: *LeafNode = self.asPtr(LeafNode, leaf_node);

                    std.debug.assertReadable(std.mem.asBytes(leaf[0..1]));
                    std.debug.assertReadable(std.mem.asBytes(new_leaf[0..1]));

                    moveHalf(leaf, new_leaf);
                    k = leaf.keys[B / 2 - 1];
                }

                // Branchlessly reassign the value if it was moved to the new_leaf.
                const new_idx = idx -% (B / 2);
                const new_value_offset = new_node + LeafNode.relativeOffset(.value, new_idx);

                if (new_idx < idx) {
                    value = new_value_offset;
                    key_offset = new_node + LeafNode.relativeOffset(.key, new_idx);
                }

                // Ascend up the tree until we reach either the root or an non-full node
                var h = @as(u32, self.tree.height) -% 1;
                while (h != std.math.maxInt(u32)) : (h -%= 1) {
                    idx = path.idx_stack[h];
                    node = path.node_stack[h];

                    // Insert to inner node
                    const inner = self.asPtr(InnerNode, node);
                    filled = !keysEql(inner.keys[B - 3], EMPTY_KEY);
                    insertAt(&inner.keys, idx, k);
                    insertAt(&inner.values, idx + 1, new_node);
                    if (!filled) break :split;

                    // The inner was filled & needs to be split into a new one.
                    new_node = try self.allocNode(allocator, InnerNode);
                    const new_inner = self.asPtr(InnerNode, new_node);
                    moveHalf(inner, new_inner);

                    k = inner.keys[(B / 2) - 1];
                    inner.keys[(B / 2) - 1] = EMPTY_KEY;
                }

                // Reached the root which needs to be split
                const new_root = try self.allocNode(allocator, InnerNode);
                const new_inner = self.asPtr(InnerNode, new_root);
                new_inner.keys[0] = k;
                new_inner.values[0] = self.tree.root;
                new_inner.values[1] = new_node;

                self.tree.root = new_root;
                self.tree.height += 1;
            }

            return .{
                .value_ptr = self.asPtr(Value, value),
                .key_ptr = self.asPtr(Key, key_offset),
            };
        }
    };
}

test "SortedMap basics" {
    const allocator = std.testing.allocator;

    var x: SortedMap(i32, u128, .{ .empty_key = std.math.maxInt(i32) }) = .empty;
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

pub fn Bound(comptime T: type) type {
    return union(enum) {
        inclusive: T,
        exclusive: T,

        pub fn val(self: @This()) T {
            return switch (self) {
                inline .inclusive, .exclusive => |x| x,
            };
        }
    };
}

fn defaultOrderFn(comptime K: type) fn (lhs: K, rhs: K) std.math.Order {
    return struct {
        fn orderFn(lhs: K, rhs: K) std.math.Order {
            switch (@typeInfo(K)) {
                .int, .float => return std.math.order(lhs, rhs),
                .@"struct", .@"enum", .@"union", .@"opaque" => {
                    if (@hasDecl(K, "order") and
                        (@TypeOf(K.order) == fn (lhs: K, rhs: K) std.math.Order or
                            @TypeOf(K.order) == fn (lhs: anytype, rhs: anytype) std.math.Order))
                    {
                        return K.order(lhs, rhs);
                    }
                },
                .pointer => |info| {
                    const child = @typeInfo(info.child);
                    if (info.size == .slice and (child == .int or child == .float)) {
                        return orderSlices(info.child, std.math.order, lhs, rhs);
                    }
                },
                else => {},
            }
            @compileError("default order not supported for " ++ @typeName(K));
        }
    }.orderFn;
}

pub const BinarySearchResult = union(enum) {
    /// item was found at this index
    found: usize,
    /// not found, but it's between this and the next index
    after: usize,
    /// the search term is less than all items in the slice
    less,
    /// the search term is greater than all items in the slice
    greater,
    /// the input slice is empty
    empty,
};

/// binary search that is very specific about the outcome.
/// only works with numbers
pub fn binarySearch(
    comptime T: type,
    /// slice to look for the item
    items: []const T,
    /// item to search for
    search_term: T,
    /// If the number appears multiple times in the list,
    /// this decides which one to return.
    comptime which: enum { any, first, last },
    /// should have one of the following types:
    /// - fn(a: T, b: T) std.math.Order
    /// - fn(a: anytype, b: anytype) std.math.Order
    comptime orderFn: anytype,
) BinarySearchResult {
    if (items.len == 0) return .empty;

    // binary search for the item
    var left: usize = 0;
    var right: usize = items.len;
    const maybe_index = while (left < right) {
        const mid = left + (right - left) / 2;
        switch (orderFn(search_term, items[mid])) {
            .eq => break mid,
            .gt => left = mid + 1,
            .lt => right = mid,
        }
    } else null;

    // handle no match
    if (maybe_index == null) {
        return if (right == 0)
            .less
        else if (left == items.len)
            .greater
        else if (orderFn(items[left], search_term) == .gt)
            .{ .after = left - 1 }
        else if (orderFn(items[left], search_term) == .lt)
            .{ .after = left }
        else
            unreachable;
    }
    var index = maybe_index.?;

    // match found, move to edge if there are duplicates
    switch (which) {
        .any => {},
        .first => while (index > 0 and items[index - 1] == search_term) {
            index -= 1;
        },
        .last => while (index < items.len - 1 and items[index + 1] == search_term) {
            index += 1;
        },
    }

    return .{ .found = index };
}

pub fn orderSlices(
    comptime T: type,
    /// should have one of the following types:
    /// - fn(a: T, b: T) std.math.Order
    /// - fn(a: anytype, b: anytype) std.math.Order
    comptime orderElem: anytype,
    a: []const T,
    b: []const T,
) std.math.Order {
    var i: usize = 0;
    while (i < a.len and i < b.len) : (i += 1) {
        const order_ = orderElem(a[i], b[i]);
        if (order_ == .eq) {
            continue;
        } else {
            return order_;
        }
    }
    return if (a.len == b.len) .eq else if (a.len > b.len) .gt else .lt;
}

/// Stores a range of values centered at a particular index that may
/// change with respect to time.
///
/// This is useful when you are tracking multiple different states
/// that occur in a sequence, and they each have a predefined lifetime.
///
/// For example, let's say you need to create a new data structure to
/// represent every Epoch. At any point in time, you'd like store to
/// the struct for the current Epoch as well as the next Epoch and
/// the prior Epoch. You can create a Window with a size of 3 centered
/// at the current Epoch. It will allow you to store all three of the
/// Epochs you care about. When transitioning Epochs, call `realign`
/// to adjust the center to the new Epoch. This will delete the state
/// from the old Epoch out of the Window, and open up a slot for you
/// to insert the next Epoch.
pub fn Window(T: type) type {
    return struct {
        state: []?T,
        center: usize,
        offset: usize,

        const Self = @This();

        pub fn init(allocator: Allocator, len: usize, start: usize) !Self {
            const state = try allocator.alloc(?T, len);
            @memset(state, null);
            return .{
                .state = state,
                .center = start,
                .offset = len - (start % len),
            };
        }

        pub fn deinit(self: Self, allocator: Allocator) void {
            allocator.free(self.state);
        }

        /// Inserts the item into the Window, as long as its index
        /// is within the current allowed bounds of the Window.
        pub fn put(self: *Self, index: usize, item: T) error{OutOfBounds}!?T {
            if (!self.isInRange(index)) {
                return error.OutOfBounds;
            }
            const ptr = self.getAssumed(index);
            const old = ptr.*;
            ptr.* = item;
            return old;
        }

        /// Returns the requested value if its index is within the
        /// bounds and has been populated by `put`.
        pub fn get(self: *Self, index: usize) ?T {
            return if (self.isInRange(index)) self.getAssumed(index).* else null;
        }

        pub fn contains(self: *Self, index: usize) bool {
            return self.isInRange(index) and self.getAssumed(index).* != null;
        }

        /// Changes the center of the window, deleting any evicted values.
        /// The evicted values will be populated in the deletion_buf with
        /// the relevant subslice returned.
        pub fn realignGet(self: *Self, new_center: usize, deletion_buf: []?T) []?T {
            return self.realignImpl(new_center, deletion_buf).?;
        }

        /// Changes the center of the window, removing any evicted values.
        pub fn realign(self: *Self, new_center: usize) void {
            _ = self.realignImpl(new_center, null);
        }

        fn realignImpl(self: *Self, new_center: usize, optional_deletion_buf: ?[]?T) ?[]?T {
            var return_buf: ?[]?T = null;
            if (self.center < new_center) {
                const num_to_delete = @min(new_center - self.center, self.state.len);
                const low = self.lowest();
                return_buf = self.deleteRange(low, low + num_to_delete, optional_deletion_buf);
            } else if (self.center > new_center) {
                const num_to_delete = @min(self.center - new_center, self.state.len);
                const top = self.highest() + 1;
                return_buf = self.deleteRange(top - num_to_delete, top, optional_deletion_buf);
            }
            self.center = new_center;
            return return_buf;
        }

        fn isInRange(self: *const Self, index: usize) bool {
            return index <= self.highest() and index >= self.lowest();
        }

        fn highest(self: *const Self) usize {
            return self.center + self.state.len / 2 - (self.state.len + 1) % 2;
        }

        fn lowest(self: *const Self) usize {
            return self.center -| self.state.len / 2;
        }

        fn getAssumed(self: *Self, index: usize) *?T {
            return &self.state[(index + self.offset) % self.state.len];
        }

        fn deleteRange(self: *Self, start: usize, end: usize, optional_deletion_buf: ?[]?T) ?[]?T {
            for (start..end, 0..) |in_index, out_index| {
                const item = self.getAssumed(in_index);
                if (optional_deletion_buf) |deletion_buf| {
                    deletion_buf[out_index] = item.*;
                }
                item.* = null;
            }
            return if (optional_deletion_buf) |buf| buf[0 .. end - start] else null;
        }
    };
}

pub fn cloneMapAndValues(allocator: Allocator, map: anytype) Allocator.Error!@TypeOf(map) {
    var cloned: @TypeOf(map) = .{};
    errdefer deinitMapAndValues(allocator, cloned);

    try cloned.ensureTotalCapacity(allocator, map.count());
    for (map.keys(), map.values()) |key, value| {
        cloned.putAssumeCapacityNoClobber(key, try value.clone(allocator));
    }

    return cloned;
}

pub fn deinitMapAndValues(allocator: Allocator, const_map: anytype) void {
    var map = const_map;
    for (map.values()) |*value| value.deinit(allocator);
    (&map).deinit(allocator);
}

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

test SortedSet {
    const allocator = std.testing.allocator;

    var set: SortedSet(u64, .{ .empty_key = std.math.maxInt(u64) }) = .empty;
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

test "SortedMap bincode round trip does not break sorting" {
    const allocator = std.testing.allocator;

    const Set = SortedSet(u8, .{ .empty_key = std.math.maxInt(u8) });

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
    iterator: SortedSet(u8, .{ .empty_key = std.math.maxInt(u8) }).Iterator,
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

    var set: SortedSet(u8, .{ .empty_key = std.math.maxInt(u8) }) = .empty;
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

test binarySearch {
    const items: [4]u8 = .{ 1, 3, 3, 5 };
    inline for (.{ .any, .first, .last }) |w| {
        try expectEqual(binarySearch(u8, &items, 0, w, std.math.order), .less);
        try expectEqual(binarySearch(u8, &items, 1, w, std.math.order).found, 0);
        try expectEqual(binarySearch(u8, &items, 2, w, std.math.order).after, 0);
        try expectEqual(binarySearch(u8, &items, 4, w, std.math.order).after, 2);
        try expectEqual(binarySearch(u8, &items, 5, w, std.math.order).found, 3);
        try expectEqual(binarySearch(u8, &items, 6, w, std.math.order), .greater);
    }
    expect(binarySearch(u8, &items, 3, .any, std.math.order).found == 1) catch {
        try expectEqual(binarySearch(u8, &items, 3, .any, std.math.order).found, 2);
    };
    try expectEqual(binarySearch(u8, &items, 3, .first, std.math.order).found, 1);
    try expectEqual(binarySearch(u8, &items, 3, .last, std.math.order).found, 2);
}

test "order slices" {
    const a: [3]u8 = .{ 1, 2, 3 };
    const b: [3]u8 = .{ 2, 2, 3 };
    const c: [3]u8 = .{ 1, 2, 4 };
    const d: [3]u8 = .{ 1, 2, 3 };
    const e: [4]u8 = .{ 1, 2, 3, 4 };
    try expectEqual(orderSlices(u8, std.math.order, &a, &b), .lt);
    try expectEqual(orderSlices(u8, std.math.order, &b, &a), .gt);
    try expectEqual(orderSlices(u8, std.math.order, &a, &c), .lt);
    try expectEqual(orderSlices(u8, std.math.order, &c, &a), .gt);
    try expectEqual(orderSlices(u8, std.math.order, &a, &d), .eq);
    try expectEqual(orderSlices(u8, std.math.order, &d, &a), .eq);
    try expectEqual(orderSlices(u8, std.math.order, &a, &e), .lt);
    try expectEqual(orderSlices(u8, std.math.order, &e, &a), .gt);

    try expectEqual(orderSlices(u8, std.math.order, &b, &c), .gt);
    try expectEqual(orderSlices(u8, std.math.order, &c, &b), .lt);
    try expectEqual(orderSlices(u8, std.math.order, &b, &e), .gt);
    try expectEqual(orderSlices(u8, std.math.order, &e, &b), .lt);
}

test "binarySearch slice of slices" {
    const slices = [4][]const u8{
        &.{ 0, 0, 10 },
        &.{ 0, 0, 20 },
        &.{ 0, 0, 30 },
        &.{ 0, 0, 40 },
    };

    const order = defaultOrderFn([]const u8);
    try std.testing.expectEqual(
        BinarySearchResult{ .found = 3 },
        binarySearch([]const u8, &slices, &.{ 0, 0, 40 }, .any, order),
    );
    try std.testing.expectEqual(
        BinarySearchResult{ .after = 2 },
        binarySearch([]const u8, &slices, &.{ 0, 0, 39 }, .any, order),
    );
    try std.testing.expectEqual(
        BinarySearchResult.greater,
        binarySearch([]const u8, &slices, &.{ 0, 0, 41 }, .any, order),
    );

    try std.testing.expectEqual(
        BinarySearchResult{ .found = 0 },
        binarySearch([]const u8, &slices, &.{ 0, 0, 10 }, .any, order),
    );
    try std.testing.expectEqual(
        BinarySearchResult{ .after = 0 },
        binarySearch([]const u8, &slices, &.{ 0, 0, 11 }, .any, order),
    );
    try std.testing.expectEqual(
        BinarySearchResult.less,
        binarySearch([]const u8, &slices, &.{ 0, 0, 9 }, .any, order),
    );

    try std.testing.expectEqual(
        BinarySearchResult{ .found = 1 },
        binarySearch([]const u8, &slices, &.{ 0, 0, 20 }, .any, order),
    );
    try std.testing.expectEqual(
        BinarySearchResult{ .after = 1 },
        binarySearch([]const u8, &slices, &.{ 0, 0, 21 }, .any, order),
    );
}

test "Window starts empty" {
    var window = try Window(u64).init(std.testing.allocator, 5, 7);
    defer window.deinit(std.testing.allocator);
    for (0..20) |i| {
        try std.testing.expect(null == window.get(i));
    }
}

test "Window populates and repopulates (odd)" {
    var window = try Window(u64).init(std.testing.allocator, 5, 7);
    defer window.deinit(std.testing.allocator);
    for (0..20) |i| {
        const result = window.put(i, i * 10);
        if (i < 5 or i > 9) {
            try std.testing.expectError(error.OutOfBounds, result);
        } else {
            try std.testing.expectEqual(null, try result);
        }
    }
    for (0..20) |i| {
        const result = window.put(i, i * 100);
        if (i < 5 or i > 9) {
            try std.testing.expectError(error.OutOfBounds, result);
        } else {
            try std.testing.expectEqual(i * 10, try result);
        }
    }
    for (0..20) |i| {
        const result = window.get(i);
        if (i < 5 or i > 9) {
            try std.testing.expectEqual(null, result);
        } else {
            try std.testing.expectEqual(i * 100, result);
        }
    }
}

test "Window populates (even)" {
    var window = try Window(u64).init(std.testing.allocator, 4, 7);
    defer window.deinit(std.testing.allocator);
    for (0..20) |i| {
        const result = window.put(i, i * 10);
        if (i < 5 or i > 8) {
            try std.testing.expectError(error.OutOfBounds, result);
        } else {
            try std.testing.expectEqual(null, try result);
        }
    }
    for (0..20) |i| {
        const result = window.get(i);
        if (i < 5 or i > 8) {
            try std.testing.expectEqual(null, result);
        } else {
            try std.testing.expectEqual(i * 10, result);
        }
    }
}

test "Window realigns" {
    var window = try Window(u64).init(std.testing.allocator, 4, 0);
    defer window.deinit(std.testing.allocator);
    window.realign(7);
    for (5..9) |i| {
        _ = try window.put(i, i * 10);
    }
    var deletion_buf: [4]?u64 = undefined;

    const deletion = window.realignGet(8, deletion_buf[0..]);
    try std.testing.expectEqual(1, deletion.len);
    try std.testing.expectEqual(50, deletion[0]);

    const deletion2 = window.realignGet(6, deletion_buf[0..]);
    try std.testing.expectEqual(2, deletion2.len);
    try std.testing.expectEqual(80, deletion2[0]);
    try std.testing.expectEqual(null, deletion2[1]);

    for (0..20) |i| {
        const result = window.get(i);
        if (i < 6 or i > 7) {
            try std.testing.expectEqual(null, result);
        } else {
            try std.testing.expectEqual(i * 10, result);
        }
    }

    const deletion3 = window.realignGet(20, deletion_buf[0..]);
    try std.testing.expectEqual(4, deletion3.len);
    try std.testing.expectEqual(null, deletion3[0]);
    try std.testing.expectEqual(null, deletion3[1]);
    try std.testing.expectEqual(60, deletion3[2]);
    try std.testing.expectEqual(70, deletion3[3]);

    for (0..40) |i| {
        try std.testing.expectEqual(null, window.get(i));
    }
}

test "SortedMap" {
    const allocator = std.testing.allocator;

    var map: SortedMap(
        u64,
        u64,
        .{ .empty_key = std.math.maxInt(u64) },
    ) = .empty;
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

    var map: SortedMap(i32, u128, .{ .empty_key = std.math.maxInt(i32) }) = .empty;
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

    var large_map: SortedMap(i32, i32, .{ .empty_key = std.math.maxInt(i32) }) = .empty;
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

    var map: SortedMap(i32, i32, .{ .empty_key = std.math.maxInt(i32) }) = .empty;
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

    var map: SortedMap(i32, i32, .{ .empty_key = std.math.maxInt(i32) }) = .empty;
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

test "checkAllAllocationFailures in cloneMapAndValues" {
    const Clonable = struct {
        inner: []const u8,

        const Self = @This();

        pub fn clone(self: *const Self, allocator: Allocator) Allocator.Error!Self {
            return .{ .inner = try allocator.dupe(u8, self.inner) };
        }

        pub fn deinit(self: *const Self, allocator: Allocator) void {
            return allocator.free(self.inner);
        }

        pub fn runTest(allocator: std.mem.Allocator) !void {
            var map = std.AutoArrayHashMapUnmanaged(u64, Self){};
            defer deinitMapAndValues(allocator, map);

            for (0..100) |i| {
                const item = try allocator.alloc(u8, i * 100);
                errdefer allocator.free(item);
                try map.put(allocator, i, .{ .inner = item });
            }

            const cloned = try cloneMapAndValues(allocator, map);
            deinitMapAndValues(allocator, cloned);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, Clonable.runTest, .{});
}
