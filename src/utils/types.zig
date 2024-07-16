//! Generic type reflection.

const std = @import("std");

/// Tuple type representing the args of a function. This is
/// the type you are required to pass into the @call builtin.
///
/// ```zig
/// fn doThing(name: []const u8, count: usize) !u64 { ... }
///
/// ParamsTuple(doThing) == struct { []const u8, usize }
///
/// const args: ParamsTuple(doThing) = undefined;
/// const out: u64 = try @call(.auto, doThing, args);
/// ```
pub fn ParamsTuple(comptime function: anytype) type {
    const params = @typeInfo(@TypeOf(function)).Fn.params;
    var fields: [params.len]std.builtin.Type.StructField = undefined;
    for (params, 0..) |param, i| {
        fields[i] = .{
            .name = std.fmt.comptimePrint("{}", .{i}),
            .type = param.type.?,
            .default_value = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }
    return @Type(.{ .Struct = std.builtin.Type.Struct{
        .layout = .auto,
        .fields = &fields,
        .is_tuple = true,
        .decls = &.{},
    } });
}

pub const AllocManagement = enum {
    managed,
    unmanaged,
};

pub const ArrayListInfo = struct {
    Elem: type,
    alignment: usize,
    management: AllocManagement,
};

/// Returns information about `T` if it is either of:
/// * `std.ArrayListAligned(Elem, alignment)`
/// * `std.ArrayListAlignedUnmanaged(Elem, alignment)`
/// and null otherwise.
pub fn arrayListInfo(comptime T: type) ?ArrayListInfo {
    if (@typeInfo(T) != .Struct) return null;
    if (!@hasDecl(T, "Slice")) return null;
    if (@TypeOf(T.Slice) != type) return null;
    const ptr_info = switch (@typeInfo(T.Slice)) {
        .Pointer => |info| info,
        else => return null,
    };
    if (ptr_info.size != .Slice) return null;
    if (ptr_info.alignment > std.math.maxInt(usize)) return null;
    const alignment = if (@sizeOf(ptr_info.child) != 0) ptr_info.alignment else null;
    const management: AllocManagement = switch (T) {
        std.ArrayListAligned(ptr_info.child, alignment) => .managed,
        std.ArrayListAlignedUnmanaged(ptr_info.child, alignment) => .unmanaged,
        else => return null,
    };
    return .{
        .Elem = ptr_info.child,
        .alignment = ptr_info.alignment,
        .management = management,
    };
}

pub const HashMapInfo = struct {
    Key: type,
    Value: type,
    Context: type,
    kind: Kind,
    management: AllocManagement,

    pub const Kind = union(enum) {
        /// `std.ArrayHashMap`|`std.ArrayHashMapUnmanaged`
        /// The `store_hash` parameter
        array: bool,
        /// `std.HashMap`|`std.HashMapUnmanaged`
        /// The `max_load_percentage` parameter
        unordered: std.math.IntFittingRange(1, 99),
    };
};

pub fn hashMapInfo(comptime T: type) ?HashMapInfo {
    if (@typeInfo(T) != .Struct) return null;

    if (!@hasDecl(T, "KV")) return null;
    if (@TypeOf(T.KV) != type) return null;
    const KV = T.KV;

    if (!@hasDecl(T, "Hash")) return null;
    if (@TypeOf(T.Hash) != type) return null;
    const Hash = T.Hash;

    if (!@hasField(KV, "key")) return null;
    if (!@hasField(KV, "value")) return null;

    const Key = @TypeOf(@as(KV, undefined).key);
    const Value = @TypeOf(@as(KV, undefined).value);

    const management: AllocManagement = blk: {
        const is_managed = @hasDecl(T, "Unmanaged") and @TypeOf(T.Unmanaged) == type;
        const is_unmanaged = @hasDecl(T, "Managed") and @TypeOf(T.Managed) == type;
        if (is_managed and is_unmanaged) return null;
        if (is_unmanaged) break :blk .unmanaged;
        if (is_managed) break :blk .managed;
        return null;
    };
    const Managed = switch (management) {
        .managed => T,
        .unmanaged => T.Managed,
    };
    if (@typeInfo(Managed) != .Struct) return null;
    if (!@hasField(Managed, "ctx")) return null;
    const Context = @TypeOf(@as(Managed, undefined).ctx);

    const HashMapFn, const ArrayHashMapFn = switch (management) {
        .managed => .{ std.HashMap, std.ArrayHashMap },
        .unmanaged => .{ std.HashMapUnmanaged, std.ArrayHashMapUnmanaged },
    };

    switch (Hash) {
        u32, void => {
            const store_hash: bool = switch (Hash) {
                u32 => true,
                void => false,
                else => unreachable,
            };
            const Expected = ArrayHashMapFn(Key, Value, Context, store_hash);
            if (T != Expected) return null;
            return .{
                .Key = Key,
                .Value = Value,
                .Context = Context,
                .kind = .{ .array = store_hash },
                .management = management,
            };
        },
        u64 => {
            if (T == HashMapFn(Key, Value, Context, std.hash_map.default_max_load_percentage)) return .{
                .Key = Key,
                .Value = Value,
                .Context = Context,
                .kind = .{ .unordered = std.hash_map.default_max_load_percentage },
                .management = management,
            };
            @setEvalBranchQuota(99 * 1000 * 2 + 1);
            for (1..100) |load_pctg| {
                if (load_pctg == std.hash_map.default_max_load_percentage) continue;
                if (T == HashMapFn(Key, Value, Context, load_pctg)) return .{
                    .Key = Key,
                    .Value = Value,
                    .Context = Context,
                    .kind = .{ .unordered = load_pctg },
                    .management = management,
                };
            }
            return null;
        },
        else => return null,
    }
}

pub inline fn defaultValue(comptime field: std.builtin.Type.StructField) ?field.type {
    comptime {
        const ptr = field.default_value orelse return null;
        return comptimeZeroSizePtrCast(field.type, ptr);
    }
}

/// This facilitates casts from a comptime type-erased pointer to zero-sized types,
/// such as `type`, `comptime_int`, `comptime_float`, `@TypeOf(.enum_literal)`, and
/// composites thereof.
pub inline fn comptimeZeroSizePtrCast(comptime T: type, comptime ptr: *const anyopaque) T {
    comptime {
        const Dummy = @Type(.{ .Struct = .{
            .layout = .auto,
            .backing_integer = null,
            .decls = &.{},
            .is_tuple = false,
            .fields = &.{.{
                .name = "value",
                .type = T,
                .default_value = ptr,
                .is_comptime = true,
                .alignment = 0,
            }},
        } });
        const dummy: Dummy = .{};
        return dummy.value;
    }
}
