const std = @import("std");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

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

/// A set that guarantees the contained items will be sorted whenever
/// accessed through public methods like `items` and `range`.
///
/// Only works with numbers.
///
/// TODO consider reimplementing with something faster (e.g. binary tree)
pub fn SortedSet(comptime T: type) type {
    return struct {
        map: std.AutoArrayHashMap(T, void),
        max: ?T = null,
        is_sorted: bool = true,

        const Self = @This();

        pub fn init(allocator: Allocator) Self {
            return .{ .map = std.AutoArrayHashMap(T, void).init(allocator) };
        }

        pub fn deinit(self: *Self) void {
            self.map.deinit();
        }

        pub fn clone(self: Self) !Self {
            return .{
                .map = try self.map.clone(),
                .max = self.max,
                .is_sorted = self.is_sorted,
            };
        }

        pub fn eql(self: *Self, other: *Self) bool {
            self.sort();
            other.sort();
            for (self.map.keys(), other.map.keys()) |s, o| {
                if (s != o) return false;
            }
            return true;
        }

        pub fn put(self: *Self, item: T) !void {
            try self.map.put(item, {});
            if (self.max == null or item > self.max.?) {
                self.max = item;
            } else {
                self.is_sorted = false;
            }
        }

        pub fn remove(self: *Self, item: T) bool {
            return self.map.orderedRemove(item);
        }

        pub fn contains(self: Self, item: T) bool {
            return self.map.contains(item);
        }

        pub fn count(self: Self) usize {
            return self.map.count();
        }

        pub fn items(self: *Self) []const T {
            self.sort();
            return self.map.keys();
        }

        /// subslice of items ranging from start (inclusive) to end (exclusive)
        pub fn range(self: *Self, start: ?T, end: ?T) []const T {
            if (self.count() == 0) return &.{};
            if (start) |s| if (end) |e| if (e <= s) return &.{};
            self.sort();
            var items_ = self.items();
            if (start) |start_| {
                // .any instead of .first because uniqueness is guaranteed
                const start_index = switch (binarySearch(T, items_, start_, .any)) {
                    .found => |index| index,
                    .after => |index| index + 1,
                    .less => 0,
                    .greater => return &.{},
                    .empty => unreachable, // count checked above
                };
                items_ = items_[start_index..];
            }
            if (end) |end_| {
                // .any instead of .last because uniqueness is guaranteed
                const end_index = switch (binarySearch(T, items_, end_, .any)) {
                    .found => |index| index,
                    .after => |index| index + 1,
                    .less => return &.{},
                    .greater => items_.len,
                    .empty => unreachable, // count checked above
                };
                items_ = items_[0..end_index];
            }
            return items_;
        }

        fn sort(self: *Self) void {
            if (self.is_sorted) return;
            self.map.sort(struct {
                items: std.MultiArrayList(std.AutoArrayHashMap(T, void).Unmanaged.Data).Slice,
                pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                    return ctx.items.get(a_index).key < ctx.items.get(b_index).key;
                }
            }{ .items = self.map.unmanaged.entries.slice() });
            self.is_sorted = true;
        }
    };
}

/// binary search that is very specific about the outcome.
/// only works with numbers
fn binarySearch(
    comptime T: type,
    /// slice to look for the item
    items: []const T,
    /// item to search for
    search_term: T,
    /// If the number appears multiple times in the list,
    /// this decides which one to return.
    comptime which: enum { any, first, last },
) union(enum) {
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
} {
    if (items.len == 0) return .empty;

    // binary search for the item
    var left: usize = 0;
    var right: usize = items.len;
    const maybe_index = while (left < right) {
        const mid = left + (right - left) / 2;
        switch (std.math.order(search_term, items[mid])) {
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
        else if (items[left] > search_term)
            .{ .after = left - 1 }
        else if (items[left] < search_term)
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
    try expect(set.remove(5));
    try expect(!set.contains(5));
    try expect(!set.remove(5));
    try set.put(5);
    try expect(set.contains(5));

    // ordering
    for (set.items(), 0..) |key, i| {
        try expect(key == i);
    }
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
        try expectEqual(binarySearch(u8, &items, 0, w), .less);
        try expectEqual(binarySearch(u8, &items, 1, w).found, 0);
        try expectEqual(binarySearch(u8, &items, 2, w).after, 0);
        try expectEqual(binarySearch(u8, &items, 4, w).after, 2);
        try expectEqual(binarySearch(u8, &items, 5, w).found, 3);
        try expectEqual(binarySearch(u8, &items, 6, w), .greater);
    }
    expect(binarySearch(u8, &items, 3, .any).found == 1) catch {
        try expectEqual(binarySearch(u8, &items, 3, .any).found, 2);
    };
    try expectEqual(binarySearch(u8, &items, 3, .first).found, 1);
    try expectEqual(binarySearch(u8, &items, 3, .last).found, 2);
}
