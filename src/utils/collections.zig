const std = @import("std");
const sig = @import("../sig.zig");
const sorted_map = @import("sorted_map.zig");

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

pub const SortedSet = sorted_map.SortedSet;
pub const SortedMap = sorted_map.SortedMap;

pub fn defaultOrderFn(comptime K: type) fn (lhs: K, rhs: K) std.math.Order {
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
        .{},
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
