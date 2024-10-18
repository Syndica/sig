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
            for (data.items) |item| {
                try bincode.write(writer, item, params);
            }
        }

        fn deserialize(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: Params,
        ) anyerror!List {
            const len = (try readIntAsLength(usize, reader, params)) orelse return error.ArrayListTooBig;

            var data: List = try List.initCapacity(allocator, len);
            errdefer bincode.free(allocator, data);
            for (0..len) |_| {
                data.appendAssumeCapacity(try bincode.read(allocator, list_info.Elem, reader, params));
            }
            return data;
        }

        fn free(allocator: std.mem.Allocator, data: anytype) void {
            if (list_info.management == .managed) {
                data.deinit();
            } else {
                data.deinit(allocator);
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
        fn deserialize(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) anyerror!List {
            const len = if (bincode.readIntAsLength(usize, reader, params)) |maybe_len|
                (maybe_len orelse return error.ArrayListTooBig)
            else |err| switch (err) {
                error.EndOfStream,
                => return switch (al_info.management) {
                    .managed => List.init(allocator),
                    .unmanaged => .{},
                },
                else => |e| return e,
            };

            const slice = try allocator.alignedAlloc(al_info.Elem, al_info.alignment, len);
            errdefer allocator.free(slice);

            return switch (al_info.management) {
                .managed => List.fromOwnedSlice(allocator, slice),
                .unmanaged => List.fromOwnedSlice(slice),
            };
        }

        fn free(allocator: std.mem.Allocator, data: anytype) void {
            var copy = data;
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
