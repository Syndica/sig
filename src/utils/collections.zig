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

/// DEPRECATED: use the unmanaged variant instead
pub fn SortedSet(comptime T: type) type {
    return SortedSetCustom(T, .{});
}

/// DEPRECATED: use the unmanaged variant instead
pub fn SortedSetCustom(comptime T: type, comptime config: SortedMapConfig(T)) type {
    return struct {
        map: SortedMapCustom(T, void, config),
        const SortedSetSelf = @This();

        pub fn init(allocator: Allocator) SortedSetSelf {
            return .{ .map = .init(allocator) };
        }

        pub fn deinit(self: SortedSetSelf) void {
            self.map.deinit();
        }

        pub fn clone(self: SortedSetSelf) !SortedSetSelf {
            return .{ .map = try self.map.clone() };
        }

        pub fn eql(self: *SortedSetSelf, other: *SortedSetSelf) bool {
            return self.map.eql(&other.map);
        }

        pub fn put(self: *SortedSetSelf, item: T) !void {
            try self.map.put(item, {});
        }

        pub fn orderedRemove(self: *SortedSetSelf, item: T) bool {
            return self.map.orderedRemove(item);
        }

        pub fn contains(self: SortedSetSelf, item: T) bool {
            return self.map.contains(item);
        }

        pub fn count(self: SortedSetSelf) usize {
            return self.map.count();
        }

        pub fn items(self: *SortedSetSelf) []const T {
            return self.map.keys();
        }

        /// subslice of items ranging from start (inclusive) to end (exclusive)
        pub fn range(self: *SortedSetSelf, start: ?T, end: ?T) []const T {
            return self.map.range(start, end)[0];
        }

        /// subslice of items ranging from start (inclusive) to end (exclusive)
        pub fn rangeCustom(self: *SortedSetSelf, start: ?Bound(T), end: ?Bound(T)) []const T {
            return self.map.rangeCustom(start, end)[0];
        }
    };
}

/// A set that guarantees the contained items will be sorted whenever
/// accessed through public methods like `items` and `range`.
///
/// Compatible with numbers, slices of numbers, and types that have an "order" method
pub fn SortedSetUnmanaged(comptime T: type) type {
    return SortedSetUnmanagedCustom(T, .{});
}

/// A set that guarantees the contained items will be sorted whenever
/// accessed through public methods like `items` and `range`.
pub fn SortedSetUnmanagedCustom(comptime T: type, comptime config: SortedMapConfig(T)) type {
    return struct {
        map: SortedMapUnmanagedCustom(T, void, config),
        const SortedSetSelf = @This();

        pub const empty: SortedSetSelf = .{
            .map = .empty,
        };

        pub fn deinit(self: SortedSetSelf, allocator: std.mem.Allocator) void {
            self.map.deinit(allocator);
        }

        pub fn clearRetainingCapacity(self: *SortedSetSelf) void {
            return self.map.inner.clearRetainingCapacity();
        }

        pub fn clone(
            self: SortedSetSelf,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!SortedSetSelf {
            return .{ .map = try self.map.clone(allocator) };
        }

        pub fn eql(self: *SortedSetSelf, other: *SortedSetSelf) bool {
            return self.map.eql(&other.map);
        }

        pub fn put(
            self: *SortedSetSelf,
            allocator: std.mem.Allocator,
            item: T,
        ) std.mem.Allocator.Error!void {
            try self.map.put(allocator, item, {});
        }

        pub fn orderedRemove(self: *SortedSetSelf, item: T) bool {
            return self.map.orderedRemove(item);
        }

        pub fn pop(self: *SortedSetSelf) ?T {
            self.map.sort();
            const kv = self.map.inner.pop() orelse return null;
            return kv.key;
        }

        pub fn contains(self: SortedSetSelf, item: T) bool {
            return self.map.contains(item);
        }

        pub fn count(self: SortedSetSelf) usize {
            return self.map.count();
        }

        pub fn items(self: *SortedSetSelf) []const T {
            return self.map.keys();
        }

        /// subslice of items ranging from start (inclusive) to end (exclusive)
        pub fn range(self: *SortedSetSelf, start: ?T, end: ?T) []const T {
            return self.map.range(start, end)[0];
        }

        /// subslice of items ranging from start (inclusive) to end (exclusive)
        pub fn rangeCustom(self: *SortedSetSelf, start: ?Bound(T), end: ?Bound(T)) []const T {
            return self.map.rangeCustom(start, end)[0];
        }
    };
}

/// DEPRECATED: use the unmanaged variant instead
pub fn SortedMap(comptime K: type, comptime V: type) type {
    return SortedMapCustom(K, V, .{});
}

/// DEPRECATED: use the unmanaged variant instead
pub fn SortedMapCustom(
    comptime K: type,
    comptime V: type,
    comptime config: SortedMapConfig(K),
) type {
    return struct {
        allocator: std.mem.Allocator,
        unmanaged: Unmanaged,
        const SortedMapSelf = @This();

        const Unmanaged = SortedMapUnmanagedCustom(K, V, config);

        pub const @"!bincode-config": sig.bincode.FieldConfig(SortedMapSelf) = .{
            .deserializer = bincodeDeserialize,
            .serializer = bincodeSerialize,
            .free = bincodeFree,
        };

        pub fn init(allocator: Allocator) SortedMapSelf {
            return .{
                .allocator = allocator,
                .unmanaged = .empty,
            };
        }

        pub fn deinit(self: SortedMapSelf) void {
            var self_mut = self;
            self_mut.unmanaged.deinit(self.allocator);
        }

        pub fn clone(self: SortedMapSelf) std.mem.Allocator.Error!SortedMapSelf {
            return .{
                .allocator = self.allocator,
                .unmanaged = try self.unmanaged.clone(self.allocator),
            };
        }

        pub fn eql(self: *SortedMapSelf, other: *SortedMapSelf) bool {
            return self.unmanaged.eql(&other.unmanaged);
        }

        pub fn get(self: SortedMapSelf, key: K) ?V {
            return self.unmanaged.get(key);
        }

        pub fn getEntry(self: SortedMapSelf, key: K) ?Unmanaged.Entry {
            return self.unmanaged.getEntry(key);
        }

        pub fn fetchSwapRemove(self: *SortedMapSelf, key: K) ?Unmanaged.Inner.KV {
            return self.unmanaged.fetchSwapRemove(key);
        }

        pub fn swapRemoveNoSort(self: *SortedMapSelf, key: K) bool {
            return self.unmanaged.swapRemoveNoSort(key);
        }

        pub fn getOrPut(
            self: *SortedMapSelf,
            key: K,
        ) std.mem.Allocator.Error!Unmanaged.Inner.GetOrPutResult {
            return self.unmanaged.getOrPut(self.allocator, key);
        }

        pub fn put(self: *SortedMapSelf, key: K, value: V) std.mem.Allocator.Error!void {
            try self.unmanaged.put(self.allocator, key, value);
        }

        pub fn orderedRemove(self: *SortedMapSelf, key: K) bool {
            return self.unmanaged.orderedRemove(key);
        }

        pub fn contains(self: SortedMapSelf, key: K) bool {
            return self.unmanaged.contains(key);
        }

        pub fn count(self: SortedMapSelf) usize {
            return self.unmanaged.count();
        }

        pub fn keys(self: *SortedMapSelf) []const K {
            return self.unmanaged.keys();
        }

        pub fn mutableKeys(self: *SortedMapSelf) []K {
            return self.unmanaged.mutableKeys();
        }

        pub fn items(self: *SortedMapSelf) struct { []const K, []const V } {
            return self.unmanaged.items();
        }

        pub fn iterator(self: *SortedMapSelf) Unmanaged.Inner.Iterator {
            return self.unmanaged.iterator();
        }

        /// subslice of items ranging from start (inclusive) to end (exclusive)
        pub fn range(self: *SortedMapSelf, start: ?K, end: ?K) struct { []const K, []const V } {
            return self.unmanaged.range(start, end);
        }

        /// subslice of items ranging from start to end
        pub fn rangeCustom(
            self: *SortedMapSelf,
            start_bound: ?Bound(K),
            end_bound: ?Bound(K),
        ) struct { []const K, []const V } {
            return self.unmanaged.rangeCustom(start_bound, end_bound);
        }

        pub fn sort(self: *SortedMapSelf) void {
            self.unmanaged.sort();
        }

        fn bincodeDeserialize(
            limit_allocator: *sig.bincode.LimitAllocator,
            reader: anytype,
            params: sig.bincode.Params,
        ) !SortedMapSelf {
            const unmanaged =
                try sig.bincode.readWithLimit(limit_allocator, Unmanaged, reader, params);
            return .{
                .allocator = limit_allocator.backing_allocator, // patch persistent.
                .unmanaged = unmanaged,
            };
        }

        fn bincodeSerialize(
            writer: anytype,
            data: anytype,
            params: sig.bincode.Params,
        ) !void {
            try sig.bincode.write(writer, data.unmanaged, params);
        }

        fn bincodeFree(_: std.mem.Allocator, data: anytype) void {
            data.deinit();
        }
    };
}

/// A map that guarantees the contained items will be sorted by key
/// whenever accessed through public methods like `keys` and `range`.
///
/// Compatible with numbers, slices of numbers, and types that have an "order" method
pub fn SortedMapUnmanaged(comptime K: type, comptime V: type) type {
    return SortedMapUnmanagedCustom(K, V, .{});
}

/// A map that guarantees the contained items will be sorted by key
/// whenever accessed through public methods like `keys` and `range`.
///
/// TODO consider reimplementing with something faster (e.g. binary tree)
pub fn SortedMapUnmanagedCustom(
    comptime K: type,
    comptime V: type,
    comptime config: SortedMapConfig(K),
) type {
    const order = config.orderFn;

    return struct {
        inner: Inner,
        max: ?K,
        is_sorted: bool,

        const SortedMapSelf = @This();

        const Inner = std.ArrayHashMapUnmanaged(K, V, config.Context, config.store_hash);

        pub const Entry = Inner.Entry;

        pub const empty: SortedMapSelf = .{
            .inner = .empty,
            .max = null,
            .is_sorted = true,
        };

        pub fn deinit(self: SortedMapSelf, allocator: std.mem.Allocator) void {
            var self_mut = self;
            self_mut.inner.deinit(allocator);
        }

        pub fn init(
            allocator: std.mem.Allocator,
            keys_init: []const K,
            values_init: []const V,
        ) std.mem.Allocator.Error!SortedMapSelf {
            var result: SortedMapSelf = .empty;
            errdefer result.deinit(allocator);
            try result.inner.reinit(allocator, keys_init, values_init);
            result.sort();
            return result;
        }

        pub fn clone(
            self: SortedMapSelf,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!SortedMapSelf {
            return .{
                .inner = try self.inner.clone(allocator),
                .max = self.max,
                .is_sorted = self.is_sorted,
            };
        }

        pub fn eql(self: *SortedMapSelf, other: *SortedMapSelf) bool {
            if (self.count() != other.count()) return false;
            self.sort();
            other.sort();
            for (
                self.inner.keys(),
                self.inner.values(),
                other.inner.keys(),
                other.inner.values(),
            ) |sk, sv, ok, ov| {
                if (sk != ok or sv != ov) return false;
            }
            return true;
        }

        pub fn get(self: SortedMapSelf, key: K) ?V {
            return self.inner.get(key);
        }

        pub fn getPtr(self: SortedMapSelf, key: K) ?*V {
            return self.inner.getPtr(key);
        }

        pub fn getEntry(self: SortedMapSelf, key: K) ?Inner.Entry {
            return self.inner.getEntry(key);
        }

        pub fn fetchSwapRemove(self: *SortedMapSelf, key: K) ?Inner.KV {
            const item = self.inner.fetchSwapRemove(key);
            if (item != null and !self.resetMaxOnRemove(key)) {
                self.is_sorted = false;
            }
            return item;
        }

        pub fn swapRemoveNoSort(self: *SortedMapSelf, key: K) bool {
            const was_removed = self.inner.swapRemove(key);
            if (was_removed and !self.resetMaxOnRemove(key)) {
                self.is_sorted = false;
            }
            return was_removed;
        }

        pub fn getOrPut(
            self: *SortedMapSelf,
            allocator: std.mem.Allocator,
            key: K,
        ) std.mem.Allocator.Error!Inner.GetOrPutResult {
            const result = try self.inner.getOrPut(allocator, key);
            if (self.max == null or order(key, self.max.?) == .gt) {
                self.max = key;
            } else {
                self.is_sorted = false;
            }
            return result;
        }

        pub fn put(
            self: *SortedMapSelf,
            allocator: std.mem.Allocator,
            key: K,
            value: V,
        ) std.mem.Allocator.Error!void {
            try self.ensureUnusedCapacity(allocator, 1);
            self.putAssumeCapacity(key, value);
        }

        pub fn putAssumeCapacity(self: *SortedMapSelf, key: K, value: V) void {
            self.inner.putAssumeCapacity(key, value);
            if (self.max == null or order(key, self.max.?) == .gt) {
                self.max = key;
            } else {
                self.is_sorted = false;
            }
        }

        /// Inserts a new `Entry` into the hash map, returning the previous one, if any.
        pub fn fetchPut(
            self: *SortedMapSelf,
            allocator: Allocator,
            key: K,
            value: V,
        ) std.mem.Allocator.Error!?Inner.KV {
            const gop = try self.getOrPut(allocator, key);
            const result: ?Inner.KV = if (!gop.found_existing) null else .{
                .key = gop.key_ptr.*,
                .value = gop.value_ptr.*,
            };
            gop.key_ptr.* = key;
            gop.value_ptr.* = value;
            return result;
        }

        pub fn orderedRemove(self: *SortedMapSelf, key: K) bool {
            const was_removed = self.inner.orderedRemove(key);
            if (was_removed) _ = self.resetMaxOnRemove(key);
            return was_removed;
        }

        /// - returns whether the key was the prior max.
        /// - don't call this unless an item was definitely removed.
        fn resetMaxOnRemove(self: *SortedMapSelf, removed_key: K) bool {
            std.debug.assert(self.max != null);
            if (self.count() == 0) {
                self.max = null;
                return true;
            } else switch (order(removed_key, self.max.?)) {
                .eq => {
                    const sorted_keys = self.keys();
                    self.max = sorted_keys[sorted_keys.len - 1];
                    return true;
                },
                .gt => unreachable,
                .lt => return false,
            }
        }

        pub fn contains(self: SortedMapSelf, key: K) bool {
            return self.inner.contains(key);
        }

        pub fn count(self: SortedMapSelf) usize {
            return self.inner.count();
        }

        pub fn keys(self: *SortedMapSelf) []const K {
            self.sort();
            return self.inner.keys();
        }

        pub fn mutableKeys(self: *SortedMapSelf) []K {
            self.sort();
            return self.inner.keys();
        }

        pub fn values(self: *SortedMapSelf) []V {
            self.sort();
            return self.inner.values();
        }

        pub fn items(self: *SortedMapSelf) struct { []const K, []const V } {
            self.sort();
            return .{ self.inner.keys(), self.inner.values() };
        }

        pub fn iterator(self: *SortedMapSelf) Inner.Iterator {
            self.sort();
            return self.inner.iterator();
        }

        /// subslice of items ranging from start (inclusive) to end (exclusive)
        pub fn range(self: *SortedMapSelf, start: ?K, end: ?K) struct { []const K, []const V } {
            return self.rangeCustom(
                if (start) |b| .{ .inclusive = b } else null,
                if (end) |b| .{ .exclusive = b } else null,
            );
        }

        /// subslice of items ranging from start to end
        pub fn rangeCustom(
            self: *SortedMapSelf,
            start_bound: ?Bound(K),
            end_bound: ?Bound(K),
        ) struct { []const K, []const V } {
            // TODO: can the code in this fn be simplified while retaining identical logic?
            const len = self.count();
            if (len == 0) return .{ &.{}, &.{} };

            // extract relevant info from bounds
            const start, const incl_start = if (start_bound) |b|
                .{ b.val(), b == .inclusive }
            else
                .{ null, false };
            const end, const excl_end = if (end_bound) |b|
                .{ b.val(), b == .exclusive }
            else
                .{ null, false };

            // edge case: check if bounds could permit any items
            if (start) |s| if (end) |e| {
                if (incl_start and !excl_end) {
                    if (order(e, s) == .lt) return .{ &.{}, &.{} };
                } else if (order(e, s) != .gt) return .{ &.{}, &.{} };
            };

            self.sort();
            var keys_ = self.inner.keys();
            var values_ = self.inner.values();
            if (start) |start_| {
                // .any instead of .first because uniqueness is guaranteed
                const start_index = switch (binarySearch(K, keys_, start_, .any, order)) {
                    .found => |index| if (incl_start) index else @min(len - 1, index + 1),
                    .after => |index| index + 1,
                    .less => 0,
                    .greater => return .{ &.{}, &.{} },
                    .empty => unreachable, // count checked above
                };
                keys_ = keys_[start_index..];
                values_ = values_[start_index..];
            }
            if (end) |end_| {
                // .any instead of .last because uniqueness is guaranteed
                const end_index = switch (binarySearch(K, keys_, end_, .any, order)) {
                    .found => |index| if (excl_end) index else index + 1,
                    .after => |index| index + 1,
                    .less => return .{ &.{}, &.{} },
                    .greater => keys_.len,
                    .empty => unreachable, // count checked above
                };
                keys_ = keys_[0..end_index];
                values_ = values_[0..end_index];
            }
            return .{ keys_, values_ };
        }

        pub fn sort(self: *SortedMapSelf) void {
            if (self.is_sorted) return;
            self.inner.sort(struct {
                items: std.MultiArrayList(Inner.Data).Slice,
                pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                    return order(ctx.items.get(a_index).key, ctx.items.get(b_index).key) == .lt;
                }
            }{ .items = self.inner.entries.slice() });
            self.is_sorted = true;
        }

        pub fn capacity(self: *const SortedMapSelf) usize {
            return self.inner.capacity();
        }

        pub fn unusedCapacity(self: *const SortedMapSelf) usize {
            return self.inner.capacity() - self.count();
        }

        pub fn ensureUnusedCapacity(
            self: *SortedMapSelf,
            gpa: std.mem.Allocator,
            additional_capacity: usize,
        ) Allocator.Error!void {
            try self.inner.ensureUnusedCapacity(gpa, additional_capacity);
        }
    };
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

pub fn SortedMapConfig(comptime K: type) type {
    const default_Context, const default_store_hash = if (K == []const u8 or K == []u8)
        .{ std.array_hash_map.StringContext, true }
    else
        .{ std.array_hash_map.AutoContext(K), !std.array_hash_map.autoEqlIsCheap(K) };

    return struct {
        orderFn: fn (a: K, b: K) std.math.Order = defaultOrderFn(K),
        /// passthrough to std.ArrayHashMap
        Context: type = default_Context,
        /// passthrough to std.ArrayHashMap
        store_hash: bool = default_store_hash,
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
const expectEqualSlices = std.testing.expectEqualSlices;

test SortedSet {
    var set = SortedSet(u64).init(std.testing.allocator);
    defer set.deinit();

    // add/contains
    try expect(!set.contains(3));
    try set.put(3);
    try expect(set.contains(3));
    try set.put(0);
    try set.put(2);
    try set.put(1);
    try set.put(4);
    try set.put(5);

    // remove
    try expect(set.orderedRemove(5));
    try expect(!set.contains(5));
    try expect(!set.orderedRemove(5));
    try set.put(5);
    try expect(set.contains(5));

    // ordering
    for (set.items(), 0..) |key, i| {
        try expect(key == i);
    }
}

test "SortedSet bincode round trip does not break sorting" {
    var set = SortedSet(u8).init(std.testing.allocator);
    defer set.deinit();

    try set.put(5);
    try set.put(3);

    const ser = try sig.bincode.writeAlloc(std.testing.allocator, set, .{});
    defer std.testing.allocator.free(ser);

    var des = try sig.bincode.readFromSlice(std.testing.allocator, SortedSet(u8), ser, .{});
    defer des.deinit();

    const items = des.items();
    try std.testing.expectEqual(3, items[0]);
    try std.testing.expectEqual(5, items[1]);
}

test "SortedSet range" {
    var set = SortedSet(u8).init(std.testing.allocator);
    defer set.deinit();

    try set.put(5);
    try set.put(3);
    try set.put(1);
    try set.put(3);

    try expectEqualSlices(u8, &.{ 1, 3, 5 }, set.range(null, null));
    try expectEqualSlices(u8, &.{}, set.range(0, 0));
    try expectEqualSlices(u8, &.{}, set.range(10, 10));
    try expectEqualSlices(u8, &.{}, set.range(10, 11));
    try expectEqualSlices(u8, &.{}, set.range(12, 11));
    try expectEqualSlices(u8, &.{1}, set.range(null, 3));
    try expectEqualSlices(u8, &.{ 1, 3 }, set.range(null, 4));
    try expectEqualSlices(u8, &.{ 1, 3 }, set.range(null, 5));
    try expectEqualSlices(u8, &.{ 1, 3, 5 }, set.range(null, 6));
    try expectEqualSlices(u8, &.{ 1, 3, 5 }, set.range(0, null));
    try expectEqualSlices(u8, &.{ 1, 3, 5 }, set.range(1, null));
    try expectEqualSlices(u8, &.{ 3, 5 }, set.range(2, null));
    try expectEqualSlices(u8, &.{ 3, 5 }, set.range(3, null));
    try expectEqualSlices(u8, &.{5}, set.range(4, null));
    try expectEqualSlices(u8, &.{5}, set.range(5, null));
    try expectEqualSlices(u8, &.{ 1, 3, 5 }, set.range(1, 6));
    try expectEqualSlices(u8, &.{ 1, 3 }, set.range(1, 5));
    try expectEqualSlices(u8, &.{ 1, 3 }, set.range(1, 4));
    try expectEqualSlices(u8, &.{1}, set.range(1, 3));
    try expectEqualSlices(u8, &.{1}, set.range(1, 2));
    try expectEqualSlices(u8, &.{}, set.range(1, 1));
    try expectEqualSlices(u8, &.{ 3, 5 }, set.range(2, 6));
    try expectEqualSlices(u8, &.{ 3, 5 }, set.range(3, 6));
    try expectEqualSlices(u8, &.{5}, set.range(4, 6));
    try expectEqualSlices(u8, &.{5}, set.range(5, 6));
    try expectEqualSlices(u8, &.{3}, set.range(3, 4));
    try expectEqualSlices(u8, &.{}, set.range(3, 3));
    try expectEqualSlices(u8, &.{}, set.range(2, 3));
    try expectEqualSlices(u8, &.{}, set.range(2, 2));
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

test "sorted set slice range" {
    var set = SortedSet([]const u8).init(std.testing.allocator);
    defer set.deinit();
    try set.put(&.{ 0, 0, 10 });
    try set.put(&.{ 0, 0, 20 });
    try set.put(&.{ 0, 0, 30 });
    try set.put(&.{ 0, 0, 40 });

    const range = set.rangeCustom(null, .{ .inclusive = &.{ 0, 0, 40 } });

    try std.testing.expectEqual(4, range.len);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 10 }, range[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 20 }, range[1]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 30 }, range[2]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 40 }, range[3]);
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
    var map = SortedMap(u64, u64).init(std.testing.allocator);
    defer map.deinit();

    try map.put(3, 30);
    try map.put(1, 10);
    try map.put(2, 20);
    try map.put(4, 40);
    try map.put(5, 50);

    // Get the keys and values
    const items = map.items();
    const keys = items[0];
    const values = items[1];

    // Check that the keys and values are sorted.
    for (keys, 0..) |key, i| {
        // Keys should be 1, 2, 3, 4, 5
        try expectEqual(key, i + 1);
        // Values should be 10, 20, 30, 40, 50
        try expectEqual(values[i], (i + 1) * 10);
    }
    // Check that the map is sorted
    try expect(map.unmanaged.is_sorted);

    // Remove a non terminal item with no sort.
    try expect(map.swapRemoveNoSort(3));
    try expect(!map.swapRemoveNoSort(3));
    try expect(map.swapRemoveNoSort(1));

    try expect(!map.unmanaged.is_sorted);
    map.sort();
    try expect(map.unmanaged.is_sorted);
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
