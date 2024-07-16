const std = @import("std");
const sig = @import("../lib.zig");
const bincode = sig.bincode;

pub fn defaultArrayListUnmanagedOnEOFConfig(comptime T: type) bincode.FieldConfig(std.ArrayListUnmanaged(T)) {
    const S = struct {
        fn deserialize(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) anyerror!std.ArrayListUnmanaged(T) {
            const len = if (bincode.readIntAsLength(usize, reader, params)) |maybe_len|
                (maybe_len orelse return error.ArrayListTooBig)
            else |err| {
                if (err == error.EndOfStream) return .{};
                return err;
            };

            const slice = try allocator.alloc(T, len);
            errdefer allocator.free(slice);

            return std.ArrayListUnmanaged(T).fromOwnedSlice(slice);
        }

        fn free(allocator: std.mem.Allocator, data: anytype) void {
            data.deinit(allocator);
        }
    };

    return .{
        .deserializer = S.deserialize,
        .free = S.free,
    };
}
pub fn defaultArrayListOnEOFConfig(comptime T: type) bincode.FieldConfig(std.ArrayList(T)) {
    const S = struct {
        fn deserialize(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) anyerror!std.ArrayList(T) {
            var unmanaged = try defaultArrayListUnmanagedOnEOFConfig(T).deserializer.?(allocator, reader, params);
            return unmanaged.toManaged(allocator);
        }

        fn free(_: std.mem.Allocator, data: anytype) void {
            data.deinit();
        }
    };

    return .{
        .deserializer = S.deserialize,
        .free = S.free,
    };
}
