const std = @import("std");
const sig = @import("../sig.zig");
const bincode = @import("bincode.zig");

const hashMapInfo = sig.utils.types.hashMapInfo;

const FieldConfig = bincode.FieldConfig;
const Params = bincode.Params;

const writeFieldWithConfig = bincode.writeFieldWithConfig;

pub fn readCtx(
    allocator: std.mem.Allocator,
    comptime H: type,
    reader: anytype,
    params: bincode.Params,
    /// Expects void, or value/namespace with methods (implied `ctx: @TypeOf(ctx)` first parameter):
    /// * `fn readKey(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) !Key`, or `pub const readKey = {}`.
    /// * `fn freeKey(allocator: std.mem.Allocator, key: Key) void`, or `pub const freeKey = {}`.
    /// * `fn readValue(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) !Value`, or `pub const readValue = {}`.
    /// * `fn freeValue(allocator: std.mem.Allocator, value: Value) void`, or `pub const freeValue = {}`.
    ///
    /// Void is an indication to utilize default behavior.
    ctx: anytype,
) !H {
    const hm_info = hashMapInfo(H).?;

    const Unmanaged = comptime U: {
        var unmanaged_info = hm_info;
        unmanaged_info.management = .unmanaged;
        break :U unmanaged_info.Type();
    };

    const ctx_maybe_namespace = if (@TypeOf(ctx) != void) ctx else struct {
        pub const readKey = {};
        pub const freeKey = {};
        pub const readValue = {};
        pub const freeValue = {};
    };
    const ctx_impl = if (@TypeOf(ctx_maybe_namespace) != type) ctx_maybe_namespace else struct {
        pub fn readKey(
            _allocator: std.mem.Allocator,
            _reader: anytype,
            _params: bincode.Params,
        ) !hm_info.Key {
            if (@TypeOf(ctx_maybe_namespace.readKey) != void) {
                return try ctx_maybe_namespace.readKey(_allocator, _reader, _params);
            } else {
                return bincode.read(_allocator, hm_info.Key, _reader, _params);
            }
        }

        pub fn freeKey(_allocator: std.mem.Allocator, key: hm_info.Key) void {
            if (@TypeOf(ctx_maybe_namespace.freeKey) != void) {
                ctx_maybe_namespace.freeKey(_allocator, key);
            } else {
                bincode.free(_allocator, key);
            }
        }

        pub fn readValue(
            _allocator: std.mem.Allocator,
            _reader: anytype,
            _params: bincode.Params,
        ) !hm_info.Value {
            if (@TypeOf(ctx_maybe_namespace.readValue) != void) {
                return try ctx_maybe_namespace.readValue(_allocator, _reader, _params);
            } else {
                return bincode.read(_allocator, hm_info.Value, _reader, _params);
            }
        }

        pub fn freeValue(_allocator: std.mem.Allocator, value: hm_info.Value) void {
            if (@TypeOf(ctx_maybe_namespace.freeValue) != void) {
                ctx_maybe_namespace.freeValue(_allocator, value);
            } else {
                bincode.free(_allocator, value);
            }
        }
    };

    const file_map_len = try bincode.readIntAsLength(
        hm_info.Size(),
        reader,
        params,
    ) orelse return error.HashMapTooBig;

    var hash_map: Unmanaged = .{};
    errdefer hash_map.deinit(allocator);
    try hash_map.ensureTotalCapacity(allocator, file_map_len);

    errdefer {
        var iter = hash_map.iterator();
        while (iter.next()) |entry| {
            ctx_impl.freeKey(allocator, entry.key_ptr.*);
            ctx_impl.freeValue(allocator, entry.value_ptr.*);
        }
    }

    for (0..file_map_len) |_| {
        const key = try ctx_impl.readKey(allocator, reader, params);
        errdefer ctx_impl.freeKey(allocator, key);

        const gop = hash_map.getOrPutAssumeCapacity(key);
        if (gop.found_existing) return error.DuplicateFileMapEntry;

        const value = try ctx_impl.readValue(allocator, reader, params);
        gop.value_ptr.* = value;
    }

    return switch (hm_info.management) {
        .managed => hash_map.promote(allocator),
        .unmanaged => hash_map,
    };
}

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
            try bincode.write(writer, len, params);

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
            return readCtx(allocator, HashMapType, reader, params, struct {
                pub fn readKey(
                    _allocator: std.mem.Allocator,
                    _reader: anytype,
                    _params: Params,
                ) !hm_info.Key {
                    return bincode.readWithConfig(
                        _allocator,
                        hm_info.Key,
                        _reader,
                        _params,
                        config.key,
                    );
                }
                pub fn freeKey(_allocator: std.mem.Allocator, key: hm_info.Key) void {
                    bincode.freeWithConfig(_allocator, key, config.key);
                }
                pub fn readValue(
                    _allocator: std.mem.Allocator,
                    _reader: anytype,
                    _params: bincode.Params,
                ) !hm_info.Value {
                    return bincode.readWithConfig(
                        _allocator,
                        hm_info.Value,
                        _reader,
                        _params,
                        config.value,
                    );
                }
                pub fn freeValue(_allocator: std.mem.Allocator, value: hm_info.Value) void {
                    bincode.freeWithConfig(_allocator, value, config.value);
                }
            });
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
