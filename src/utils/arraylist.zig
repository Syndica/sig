const std = @import("std");
const bincode = @import("../bincode/bincode.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub fn ArrayListConfig(comptime Child: type) bincode.FieldConfig(std.ArrayList(Child)) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            const list: std.ArrayList(Child) = data;
            try bincode.write(writer, @as(u64, list.items.len), params);
            for (list.items) |item| {
                try bincode.write(writer, item, params);
            }
            return;
        }

        pub fn deserialize(allocator: ?std.mem.Allocator, reader: anytype, params: bincode.Params) !std.ArrayList(Child) {
            const ally = allocator.?;
            const len = try bincode.read(ally, u64, reader, params);
            var list = try std.ArrayList(Child).initCapacity(ally, @as(usize, len));
            for (0..len) |_| {
                const item = try bincode.read(ally, Child, reader, params);
                try list.append(item);
            }
            return list;
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            _ = allocator;
            data.deinit();
        }
    };

    return bincode.FieldConfig(std.ArrayList(Child)){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn defaultArrayListOnEOFConfig(comptime T: type) bincode.FieldConfig(std.ArrayList(T)) {
    const S = struct {
        fn defaultEOF(allocator: std.mem.Allocator) std.ArrayList(T) {
            return std.ArrayList(T).init(allocator);
        }

        fn free(_: std.mem.Allocator, data: anytype) void {
            data.deinit();
        }
    };

    return bincode.FieldConfig(std.ArrayList(T)){
        .default_on_eof = true,
        .free = S.free,
        .default_fn = S.defaultEOF,
    };
}

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

        pub fn addOne(self: *Self) !*T {
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
