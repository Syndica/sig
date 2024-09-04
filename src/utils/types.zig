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

/// Gets the return type of a function or function pointer
pub fn ReturnType(comptime FnPtr: type) type {
    return switch (@typeInfo(FnPtr)) {
        .Fn => |fun| fun.return_type.?,
        .Pointer => |ptr| @typeInfo(ptr.child).Fn.return_type.?,
        else => @compileError("not a function or function pointer"),
    };
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

    pub fn Type(comptime info: HashMapInfo) type {
        const K = info.Key;
        const V = info.Value;
        const Ctx = info.Context;
        return switch (info.kind) {
            .array => |store_hash| switch (info.management) {
                .managed => std.ArrayHashMap(K, V, Ctx, store_hash),
                .unmanaged => std.ArrayHashMapUnmanaged(K, V, Ctx, store_hash),
            },
            .unordered => |max_load_percentage| switch (info.management) {
                .managed => std.HashMap(K, V, Ctx, max_load_percentage),
                .unmanaged => std.HashMapUnmanaged(K, V, Ctx, max_load_percentage),
            },
        };
    }

    pub fn Size(comptime info: HashMapInfo) type {
        return switch (info.kind) {
            .unordered => info.Type().Size,
            .array => {
                comptime std.debug.assert(!@hasDecl(info.Type(), "Size"));
                return usize;
            },
        };
    }
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

pub const BoundedArrayInfo = struct {
    Elem: type,
    capacity: usize,
    alignment: usize,

    pub fn Type(comptime info: BoundedArrayInfo) type {
        return std.BoundedArrayAligned(info.Elem, info.alignment, info.capacity);
    }
};
pub fn boundedArrayInfo(comptime T: type) ?BoundedArrayInfo {
    const structure = switch (@typeInfo(T)) {
        .Struct => |info| info,
        else => return null,
    };
    if (!@hasField(T, "buffer")) return null;
    const buffer_field = structure.fields[std.meta.fieldIndex(T, "buffer").?];
    const alignment = buffer_field.alignment;
    const Elem, const capacity = switch (@typeInfo(buffer_field.type)) {
        .Array => |array| .{ array.child, array.len },
        else => return null,
    };

    const Actual = std.BoundedArrayAligned(Elem, alignment, capacity);
    if (T != Actual) return null;

    return .{
        .Elem = Elem,
        .capacity = capacity,
        .alignment = alignment,
    };
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

pub const EqlConfig = struct {
    /// whether to compare the pointer itself or
    /// "follow" the pointer and compare the data it points to
    follow_pointers: enum { no, yes, only_slices } = .yes,
    /// whether to use an `eql` method if defined for the type,
    /// instead of standard recursive approach implemented in eql.
    use_eql_method: enum { no, yes, only_for_nested_types } = .yes,
};

/// Compare equality of two items with the same type.
///
/// see eqlCustom for more information.
/// use eqlCustom to customize the behavior.
pub inline fn eql(a: anytype, b: @TypeOf(a)) bool {
    return eqlCustom(a, b, .{});
}

/// Compare equality of two items with the same type.
///
/// By default:
/// - follows pointers
/// - treats Allocators as equal
/// - uses an `eql` method if defined for the type
/// - compares only the `items` field in ArrayLists
pub fn eqlCustom(a: anytype, b: @TypeOf(a), config_: EqlConfig) bool {
    var config = config_;
    const T: type = @TypeOf(a);

    // custom handlers for specific types -- TODO: ideally these would be part of EqlConfig
    if (@TypeOf(a) == std.mem.Allocator) {
        return true;
    }
    if (arrayListInfo(@TypeOf(a))) |_| {
        return eqlCustom(a.items, b.items, config);
    }

    // use the type's eql method if it exists
    if (config.use_eql_method == .yes) {
        switch (@typeInfo(T)) {
            inline .Struct, .Enum, .Union, .Opaque => {
                if (@hasDecl(T, "eql") and
                    @typeInfo(@TypeOf(T.eql)) == .Fn and
                    @typeInfo(ParamsTuple(T.eql)).Struct.fields.len == 2 and
                    ReturnType(@TypeOf(T.eql)) == bool)
                {
                    const param1 = @typeInfo(@typeInfo(ParamsTuple(T.eql)).Struct.fields[0].type);
                    const param2 = @typeInfo(@typeInfo(ParamsTuple(T.eql)).Struct.fields[1].type);

                    if (param1 == .Pointer and param2 == .Pointer) {
                        var a_copy = a;
                        var b_copy = b;
                        return T.eql(&a_copy, &b_copy);
                    } else if (param1 != .Pointer and param2 == .Pointer) {
                        var b_copy = b;
                        return T.eql(a, &b_copy);
                    } else if (param1 == .Pointer and param2 != .Pointer) {
                        var a_copy = a;
                        return T.eql(&a_copy, b);
                    } else {
                        return T.eql(a, b);
                    }
                }
            },
            else => {},
        }
    }
    if (config.use_eql_method == .only_for_nested_types) {
        config.use_eql_method = .yes;
    }

    // basic equality comparison
    switch (@typeInfo(T)) {
        .Struct => {
            inline for (@typeInfo((T)).Struct.fields) |field| {
                if (!eqlCustom(@field(a, field.name), @field(b, field.name), config)) {
                    return false;
                }
            }
            return true;
        },
        .ErrorUnion => {
            if (a) |a_p| {
                if (b) |b_p| return eqlCustom(a_p, b_p, config) else |_| return false;
            } else |a_e| {
                if (b) |_| return false else |b_e| return a_e == b_e;
            }
        },
        .Union => |info| {
            if (info.tag_type) |UnionTag| {
                if (@intFromEnum(a) != @intFromEnum(b)) return false;
                inline for (info.fields) |field_info| {
                    if (@field(UnionTag, field_info.name) == @as(std.meta.Tag(T), a)) {
                        return eqlCustom(
                            @field(a, field_info.name),
                            @field(b, field_info.name),
                            config,
                        );
                    }
                }
                return false;
            }
            @compileError("cannot compare untagged union type " ++ @typeName(T));
        },
        .Array => |array| return sliceEql(array.child, &a, &b, config),
        .Pointer => |pointer| return switch (pointer.size) {
            .Slice => if (config.follow_pointers != .no) {
                return sliceEql(pointer.child, a, b, config);
            } else {
                return a.len == b.len and a.ptr == b.ptr;
            },
            else => if (config.follow_pointers == .yes) {
                return eqlCustom(a.*, b.*, config);
            } else {
                return a == b;
            },
        },
        .Optional => return a == null and b == null or
            a != null and b != null and eqlCustom(a.?, b.?, config),

        else => return a == b,
    }
}

/// copy of `std.mem.eql` except it uses `eql` (above) instead of `==`
fn sliceEql(comptime T: type, a: []const T, b: []const T, config: EqlConfig) bool {
    if (@sizeOf(T) == 0) return true;

    if (!@inComptime() and
        std.meta.hasUniqueRepresentation(T) and
        backend_can_use_eql_bytes and
        (config.follow_pointers == .no or !(containsPointer(T) orelse true)))
    {
        // This is a performance optimization. We directly compare the bytes in the slice, instead
        // of iterating over each item and comparing them for equality.
        return eqlBytes(std.mem.sliceAsBytes(a), std.mem.sliceAsBytes(b));
    }

    if (a.len != b.len) return false;
    if (a.len == 0 or a.ptr == b.ptr) return true;

    for (a, b) |a_elem, b_elem| {
        if (!eqlCustom(a_elem, b_elem, config)) return false;
    }
    return true;
}

const backend_can_use_eql_bytes = switch (@import("builtin").zig_backend) {
    // The SPIR-V backend does not support the optimized path yet.
    .stage2_spirv64 => false,
    // The RISC-V does not support vectors.
    .stage2_riscv64 => false,
    else => true,
};

/// Returns whether a type has any pointers within it, at any level of nesting.
/// Returns null if the answer cannot be determined.
pub fn containsPointer(comptime T: type) ?bool {
    return switch (@typeInfo(T)) {
        .Pointer => true,

        inline .Array, .Optional => |info| containsPointer(info.child),

        .ErrorUnion => |info| containsPointer(info.payload),

        inline .Struct, .Union => |info| inline for (info.fields) |field| {
            const field_has_pointer = containsPointer(field.type);
            if (field_has_pointer != false) break field_has_pointer;
        } else false,

        .Opaque, .Frame => null,

        .AnyFrame => |info| if (info.child) |c| containsPointer(c) else null,

        .Type, .Void, .Bool, .NoReturn, .Int, .Float, .ComptimeFloat, .ComptimeInt => false,
        .Undefined, .Null, .ErrorSet, .Enum, .Fn, .Vector, .EnumLiteral => false,
    };
}

/// This is an exact copy of std.mem.eqlBytes because it is private
fn eqlBytes(a: []const u8, b: []const u8) bool {
    if (!backend_can_use_eql_bytes) {
        return eqlCustom(u8, a, b);
    }

    if (a.len != b.len) return false;
    if (a.len == 0 or a.ptr == b.ptr) return true;

    if (a.len <= 16) {
        if (a.len < 4) {
            const x = (a[0] ^ b[0]) | (a[a.len - 1] ^ b[a.len - 1]) | (a[a.len / 2] ^ b[a.len / 2]);
            return x == 0;
        }
        var x: u32 = 0;
        for ([_]usize{ 0, a.len - 4, (a.len / 8) * 4, a.len - 4 - ((a.len / 8) * 4) }) |n| {
            x |= @as(u32, @bitCast(a[n..][0..4].*)) ^ @as(u32, @bitCast(b[n..][0..4].*));
        }
        return x == 0;
    }

    // Figure out the fastest way to scan through the input in chunks.
    // Uses vectors when supported and falls back to usize/words when not.
    const Scan = if (std.simd.suggestVectorLength(u8)) |vec_size|
        struct {
            pub const size = vec_size;
            pub const Chunk = @Vector(size, u8);
            pub inline fn isNotEqual(chunk_a: Chunk, chunk_b: Chunk) bool {
                return @reduce(.Or, chunk_a != chunk_b);
            }
        }
    else
        struct {
            pub const size = @sizeOf(usize);
            pub const Chunk = usize;
            pub inline fn isNotEqual(chunk_a: Chunk, chunk_b: Chunk) bool {
                return chunk_a != chunk_b;
            }
        };

    inline for (1..6) |s| {
        const n = 16 << s;
        if (n <= Scan.size and a.len <= n) {
            const V = @Vector(n / 2, u8);
            var x = @as(V, a[0 .. n / 2].*) ^ @as(V, b[0 .. n / 2].*);
            x |= @as(V, a[a.len - n / 2 ..][0 .. n / 2].*) ^ @as(V, b[a.len - n / 2 ..][0 .. n / 2].*);
            const zero: V = @splat(0);
            return !@reduce(.Or, x != zero);
        }
    }
    // Compare inputs in chunks at a time (excluding the last chunk).
    for (0..(a.len - 1) / Scan.size) |i| {
        const a_chunk: Scan.Chunk = @bitCast(a[i * Scan.size ..][0..Scan.size].*);
        const b_chunk: Scan.Chunk = @bitCast(b[i * Scan.size ..][0..Scan.size].*);
        if (Scan.isNotEqual(a_chunk, b_chunk)) return false;
    }

    // Compare the last chunk using an overlapping read (similar to the previous size strategies).
    const last_a_chunk: Scan.Chunk = @bitCast(a[a.len - Scan.size ..][0..Scan.size].*);
    const last_b_chunk: Scan.Chunk = @bitCast(b[a.len - Scan.size ..][0..Scan.size].*);
    return !Scan.isNotEqual(last_a_chunk, last_b_chunk);
}

test "eql follows slices" {
    const Foo = struct {
        slice: []const u8,
    };
    const a_slice = try std.testing.allocator.alloc(u8, 1);
    defer std.testing.allocator.free(a_slice);
    const b_slice = try std.testing.allocator.alloc(u8, 1);
    defer std.testing.allocator.free(b_slice);
    a_slice[0] = 1;
    b_slice[0] = 1;
    const a = Foo{ .slice = a_slice };
    const b = Foo{ .slice = b_slice };
    try std.testing.expect(eql(a, b));
    try std.testing.expect(!eqlCustom(a, b, .{ .follow_pointers = .no }));
    try std.testing.expect(!std.meta.eql(a, b));
}
