const std = @import("std");
const sig = @import("../sig.zig");
const bincode = sig.bincode;

const arrayListInfo = sig.utils.types.arrayListInfo;

const Params = bincode.Params;

const readIntAsLength = bincode.readIntAsLength;

/// The standard bincode serialization for an ArrayList
pub fn standardConfig(comptime List: type) bincode.FieldConfig(List) {
    const list_info = arrayListInfo(List).?;

    const S = struct {
        fn serialize(writer: anytype, data: anytype, params: bincode.Params) anyerror!void {
            try bincode.write(writer, data.items.len, params);
            for (data.items) |item| try bincode.write(writer, item, params);
        }

        fn deserialize(
            limit_allocator: *bincode.LimitAllocator,
            reader: anytype,
            params: Params,
        ) anyerror!List {
            const len = (try readIntAsLength(usize, reader, params)) orelse return error.ArrayListTooBig;

            const allocator = limit_allocator.allocator(); // List allocation is limit checked.
            var data: List = try List.initCapacity(allocator, len);
            errdefer free(allocator, data);

            for (0..len) |_| {
                const elem =
                    try bincode.readWithLimit(limit_allocator, list_info.Elem, reader, params);
                data.appendAssumeCapacity(elem);
            }

            // Before returning List, the persistent allocator.
            if (list_info.management == .managed) {
                data.allocator = limit_allocator.backing_allocator;
            }

            return data;
        }

        fn free(allocator: std.mem.Allocator, data: anytype) void {
            var copy = data;
            for (copy.items) |value| bincode.free(allocator, value);
            switch (list_info.management) {
                .managed => copy.deinit(),
                .unmanaged => copy.deinit(allocator),
            }
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

/// Defaults the field of type `List` to an empty state on EOF.
pub fn defaultOnEofConfig(comptime List: type) bincode.FieldConfig(List) {
    const al_info = arrayListInfo(List) orelse @compileError("Expected std.ArrayList[Unmanaged]Aligned(T), got " ++ @typeName(List));
    const S = struct {
        fn deserialize(limit_allocator: *bincode.LimitAllocator, reader: anytype, params: bincode.Params) anyerror!List {
            const len = if (bincode.readIntAsLength(usize, reader, params)) |maybe_len|
                (maybe_len orelse return error.ArrayListTooBig)
            else |err| switch (err) {
                error.EndOfStream,
                => return switch (al_info.management) {
                    .managed => List.init(limit_allocator.backing_allocator),
                    .unmanaged => .{},
                },
                else => |e| return e,
            };

            const allocator = limit_allocator.allocator(); // make sure allocs are limit tested.
            const slice = try allocator.alignedAlloc(al_info.Elem, al_info.alignment, len);
            errdefer allocator.free(slice);

            return switch (al_info.management) {
                .managed => List.fromOwnedSlice(limit_allocator.backing_allocator, slice),
                .unmanaged => List.fromOwnedSlice(slice),
            };
        }

        fn free(allocator: std.mem.Allocator, data: anytype) void {
            var copy = data;
            for (copy.items) |value| bincode.free(allocator, value);
            switch (al_info.management) {
                .managed => copy.deinit(),
                .unmanaged => copy.deinit(allocator),
            }
        }
    };

    return .{
        .deserializer = S.deserialize,
        .free = S.free,
    };
}
