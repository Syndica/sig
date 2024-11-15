const std = @import("std");
const sig = @import("../sig.zig");
const bincode = @import("bincode.zig");

const hashMapInfo = sig.utils.types.hashMapInfo;

const FieldConfig = bincode.FieldConfig;
const Params = bincode.Params;

const readFieldWithConfig = bincode.readFieldWithConfig;
const readIntAsLength = bincode.readIntAsLength;
const write = bincode.write;
const writeFieldWithConfig = bincode.writeFieldWithConfig;

/// The standard bincode serialization for a HashMap
pub fn hashMapFieldConfig(
    comptime HashMapType: type,
    comptime config: HashMapConfig(hashMapInfo(HashMapType).?),
) FieldConfig(HashMapType) {
    const hm_info = hashMapInfo(HashMapType).?;

    const S = struct {
        fn serialize(writer: anytype, data: anytype, params: Params) anyerror!void {
            const T = @TypeOf(data);

            // NOTE: we need to use unmanaged here because managed requires a mutable reference
            if (data.count() > std.math.maxInt(u64)) return error.HashMapTooBig;
            const len: u64 = @intCast(data.count());
            try write(writer, len, params);

            const key_info = std.meta.fieldInfo(T.KV, .key);
            const value_info = std.meta.fieldInfo(T.KV, .value);

            var iter = data.iterator();
            while (iter.next()) |entry| {
                try writeFieldWithConfig(
                    key_info,
                    config.key,
                    writer,
                    entry.key_ptr.*,
                    params,
                );
                try writeFieldWithConfig(
                    value_info,
                    config.value,
                    writer,
                    entry.value_ptr.*,
                    params,
                );
            }
        }

        fn deserialize(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: Params,
        ) anyerror!HashMapType {
            const Size = if (hm_info.kind == .unordered) HashMapType.Size else usize;
            const len = try readIntAsLength(Size, reader, params) orelse
                return error.HashMapTooBig;

            var data: HashMapType = switch (hm_info.management) {
                .managed => HashMapType.init(allocator),
                .unmanaged => .{},
            };
            errdefer free(allocator, data);

            switch (hm_info.management) {
                .managed => try data.ensureTotalCapacity(len),
                .unmanaged => try data.ensureTotalCapacity(allocator, len),
            }

            const key_field = std.meta.fieldInfo(HashMapType.KV, .key);
            const value_field = std.meta.fieldInfo(HashMapType.KV, .value);
            for (0..len) |_| {
                const key = try readFieldWithConfig(
                    allocator,
                    reader,
                    params,
                    key_field,
                    config.key,
                );
                errdefer bincode.free(allocator, key);

                const value = try readFieldWithConfig(
                    allocator,
                    reader,
                    params,
                    value_field,
                    config.value,
                );
                errdefer bincode.free(allocator, value);

                const gop = data.getOrPutAssumeCapacity(key);
                if (gop.found_existing) return error.DuplicateHashMapEntries;
                gop.value_ptr.* = value;
            }

            return data;
        }

        fn free(allocator: std.mem.Allocator, data: anytype) void {
            var copy = data;
            var iter = copy.iterator();
            while (iter.next()) |entry| {
                bincode.free(allocator, entry.key_ptr.*);
                bincode.free(allocator, entry.value_ptr.*);
            }
            switch (hm_info.management) {
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

/// Individually configure the FieldConfig for the key and value.
pub fn HashMapConfig(comptime hm_info: sig.utils.types.HashMapInfo) type {
    return struct {
        key: FieldConfig(hm_info.Key) = .{},
        value: FieldConfig(hm_info.Value) = .{},
    };
}
