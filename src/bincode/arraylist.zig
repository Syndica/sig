const std = @import("std");
const sig = @import("../sig.zig");
const bincode = sig.bincode;

const ArrayListInfo = sig.utils.types.ArrayListInfo;
const arrayListInfo = sig.utils.types.arrayListInfo;

const FieldConfig = bincode.FieldConfig;
const Params = bincode.Params;

const readFieldWithConfig = bincode.readFieldWithConfig;
const readIntAsLength = bincode.readIntAsLength;
const write = bincode.write;
const writeFieldWithConfig = bincode.writeFieldWithConfig;

/// The standard bincode serialization for an ArrayList
pub fn arrayListFieldConfig(comptime ArrayListType: type) bincode.FieldConfig(ArrayListType) {
    const list_info = arrayListInfo(ArrayListType).?;

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
        ) anyerror!ArrayListType {
            const len = (try readIntAsLength(usize, reader, params)) orelse return error.ArrayListTooBig;

            var data: ArrayListType = try ArrayListType.initCapacity(allocator, len);
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
