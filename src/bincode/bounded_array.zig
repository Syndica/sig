const std = @import("std");
const sig = @import("../sig.zig");
const bincode = sig.bincode;

/// The standard bincode serialization for an ArrayList
pub fn standardConfig(comptime List: type) bincode.FieldConfig(List) {
    const list_info = sig.utils.types.boundedArrayInfo(List).?;

    const S = struct {
        fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            try bincode.write(writer, data.constSlice(), params);
        }

        fn deserialize(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) !List {
            const len = (try bincode.readIntAsLength(usize, reader, params)) orelse
                return error.BoundedArrayTooBig;
            if (len > list_info.capacity) return error.DataTooLarge;

            if (list_info.Elem == u8) {
                var data: List = .{};
                data.len = @intCast(len);
                const bytes_read = try reader.readAll(data.slice());
                std.debug.assert(bytes_read <= len);
                if (bytes_read != len) return error.EndOfStream;
                return data;
            } else {
                var data: List = .{};
                errdefer for (data.constSlice()) |elem| bincode.free(allocator, elem);

                for (0..len) |_| {
                    const elem = try bincode.read(allocator, list_info.Elem, reader, params);
                    data.appendAssumeCapacity(elem);
                }

                return data;
            }
        }

        fn free(allocator: std.mem.Allocator, data: anytype) void {
            if (list_info.Elem != u8) {
                for (data.constSlice()) |value| bincode.free(allocator, value);
            }
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}
