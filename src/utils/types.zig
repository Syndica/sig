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
pub fn Return(comptime FnPtr: type) type {
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

/// Throws compile error if T and U do not share the same interface.
///
/// This is a stricter version of assertImplements that requires each
/// type to mutually implement the other. They are required to have
/// the exact same set of decl names and types.
pub fn assertSameInterface(
    comptime T: type,
    comptime U: type,
    comptime U_errors_must_be: SetRelationship,
) void {
    comptime {
        assertImplements(T, U, U_errors_must_be);
        assertImplements(U, T, U_errors_must_be.invert());
    }
}

/// Throws compile error if `Impl` does not implement the interface
/// defined by `Trait`.
///
/// Implementing an interface means:
///   For each pub decl in `Trait`, `Impl` has a decl with the same
///   name and the same type. The decls do *not* need to have the
///   same value, only the same type.
///
/// This can be useful when implementing a pattern analogous to
/// trait (rust), interface (go/java), or typeclass (haskell).
pub fn assertImplements(
    comptime Trait: type,
    comptime Impl: type,
    /// Decide whether to allow Impl functions to return different errors.
    comptime impl_errors_must_be: SetRelationship,
) void {
    const errors = comptime checkImplements(Trait, Impl, impl_errors_must_be);
    if (errors.len != 0) {
        @compileError(errors);
    }
}

/// implementation for assertImplements that just returns an error string
/// instead of throwing a compile error. If string.len > 0, there
/// was an error.
fn checkImplements(
    comptime Trait: type,
    comptime Impl: type,
    comptime impl_errors_must_be: SetRelationship,
) []const u8 {
    const trait_decls, _ = comptime declTypes(Trait);
    _, const impl_decls = comptime declTypes(Impl);
    comptime var errors = ComptimeStringBuilder{};

    // check that Impl contains type definitions for each type in Trait
    // also track the mapping from Trait type to Impl type
    comptime var types_buf: [1 + trait_decls.len][2]type = undefined;
    types_buf[0] = .{ Trait, Impl };
    comptime var types_num = 1;
    inline for (trait_decls) |trait_decl| if (trait_decl.type == type) {
        if (impl_decls.get(trait_decl.name)) |ImplDeclType| {
            if (type == ImplDeclType) {
                types_buf[types_num] = .{
                    @field(Trait, trait_decl.name),
                    @field(Impl, trait_decl.name),
                };
                types_num += 1;
            } else comptime errors.print(
                "{}.{s} must be a type for compatibility with {}, but it is a {}\n\n",
                .{ Impl, trait_decl.name, Trait, ImplDeclType },
            );
        } else comptime errors.print(
            "{} is missing the type definition '{s}' required for compatibility with {}\n\n",
            .{ Impl, trait_decl.name, Trait },
        );
    };
    const types = types_buf[0..types_num];

    // check that Impl contains decls for each non-type decl in Trait
    inline for (trait_decls) |trait_decl| if (trait_decl.type != type) {
        if (impl_decls.get(trait_decl.name)) |ImplDeclType| {
            const fmt = .{
                \\{}.{s} is not compatible with {}.{s}:
                \\    required: {}
                \\      actual: {}
                \\
                \\
                ,
                .{ Impl, trait_decl.name, Trait, trait_decl.name },
            };
            switch (@typeInfo(trait_decl.type)) {
                .Fn => |trait_fn| {
                    if (@typeInfo(ImplDeclType) != .Fn) {
                        comptime errors.print(
                            "{}.{s} is a {} but it must be a function to be compatible with {}\n\n",
                            .{ Impl, trait_decl.name, ImplDeclType, Trait },
                        );
                    }
                    const required = FunctionSignature.init(trait_fn).convertTypes(types);
                    const actual = FunctionSignature.init(@typeInfo(ImplDeclType).Fn);
                    comptime if (!actual.eql(required, impl_errors_must_be)) {
                        errors.print(fmt[0], fmt[1] ++ .{ required, actual });
                    };
                },
                else => if (false) {
                    comptime errors.print(fmt[0], fmt[1] ++ .{ trait_decl.type, ImplDeclType });
                },
            }
        } else comptime errors.print(
            "{} does not implement {}.{s}\n    required: {}\n\n",
            .{ Impl, Trait, trait_decl.name, trait_decl.type },
        );
    };

    return errors.string;
}

const SetRelationship = enum {
    identical,
    any,
    subset,
    superset,

    fn invert(self: SetRelationship) SetRelationship {
        return switch (self) {
            .subset => .superset,
            .superset => .subset,
            else => self,
        };
    }
};

/// This can be used to determine if two functions are interchangeable
/// when comparing the actual function types would be too strict.
const FunctionSignature = struct {
    params: []?type,
    Return: ?type,

    pub fn init(fun: std.builtin.Type.Fn) FunctionSignature {
        var params: [fun.params.len]?type = undefined;
        inline for (fun.params, 0..) |param, i| {
            params[i] = param.type;
        }
        return .{
            .params = &params,
            .Return = fun.return_type,
        };
    }

    pub fn eql(
        self: FunctionSignature,
        other: FunctionSignature,
        self_errors_must_be: SetRelationship,
    ) bool {
        for (self.params, other.params) |SelfParam, OtherParam| {
            if (SelfParam != OtherParam) {
                return false;
            }
        }
        if (self.Return != null and other.Return != null and
            @typeInfo(self.Return.?) == .ErrorUnion and @typeInfo(other.Return.?) == .ErrorUnion)
        {
            const self_union = @typeInfo(self.Return.?).ErrorUnion;
            const other_union = @typeInfo(other.Return.?).ErrorUnion;
            if (self_union.payload != other_union.payload) {
                return false;
            }
            const super, const sub = switch (self_errors_must_be) {
                .identical => return self.Return == other.Return,
                .any => .{ error{}, error{} },
                .subset => .{ other_union.error_set, self_union.error_set },
                .superset => .{ self_union.error_set, other_union.error_set },
            };
            if (@typeInfo(sub).ErrorSet) |sub_set| if (@typeInfo(super).ErrorSet) |super_set| {
                sub: for (sub_set) |sub_err| {
                    for (super_set) |super_err| {
                        if (std.mem.eql(sub_err.name, super_err.name)) {
                            continue :sub;
                        }
                    }
                    return false;
                }
            };
            return self_union.payload == other_union.payload;
        }
        return self.Return == other.Return;
    }

    pub fn convertTypes(
        comptime self: FunctionSignature,
        comptime map: []const [2]type,
    ) FunctionSignature {
        var ret = self;
        ret.Return = if (self.Return) |R| convertType(R, map) else null;
        for (ret.params) |*maybe_param| if (maybe_param.*) |*param| {
            param.* = convertType(param.*, map);
        };
        return ret;
    }

    pub fn format(
        self: FunctionSignature,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("fn (", .{});
        for (self.params, 0..) |param, i| {
            if (param) |P| try writer.print("{}", .{P}) else try writer.print("???", .{});
            if (i + 1 != self.params.len) try writer.print(", ", .{});
        }
        try writer.print(") ", .{});
        if (self.Return) |R| try writer.print("{}", .{R}) else try writer.print("???", .{});
    }
};

pub const ComptimeStringBuilder = struct {
    string: []const u8 = "",

    pub fn print(comptime self: *@This(), comptime fmt: []const u8, comptime args: anytype) void {
        const message = std.fmt.comptimePrint(fmt, args);
        self.string = std.fmt.comptimePrint("{s}{s}", .{ self.string, message });
    }
};

/// Replaces T with its associated type in map if found, otherwise recursively
/// inspects T for nested types that can be found in map, and replaces those.
fn convertType(comptime T: type, comptime map: []const [2]type) type {
    return if (get(map, T)) |NewT|
        NewT
    else switch (@typeInfo(T)) {
        .Pointer => |ptr| {
            var new_ptr = ptr;
            new_ptr.child = convertType(new_ptr.child, map);
            return @Type(.{ .Pointer = new_ptr });
        },
        .ErrorUnion => |eu| {
            var new_eu = eu;
            new_eu.payload = convertType(eu.payload, map);
            new_eu.error_set = convertType(eu.error_set, map);
            return @Type(.{ .ErrorUnion = new_eu });
        },
        else => T,
    };
}

fn get(comptime map: []const [2]type, comptime T: type) ?type {
    inline for (map) |pair| {
        if (pair[0] == T) return pair[1];
    }
    return null;
}

test {
    try std.testing.expectEqual(*u64, convertType(*usize, &.{.{ usize, u64 }}));
    try std.testing.expectEqual(anyerror!u64, convertType(anyerror!usize, &.{.{ usize, u64 }}));
    try std.testing.expectEqual(anyerror!*u64, convertType(anyerror!*usize, &.{.{ usize, u64 }}));
    try std.testing.expectEqual(*anyerror!u64, convertType(*anyerror!usize, &.{.{ usize, u64 }}));
}

fn compileError(comptime fmt: []const u8, comptime args: anytype) noreturn {
    @compileError(std.fmt.comptimePrint(fmt, args));
}

const DeclType = struct { name: []const u8, type: type };

fn declTypes(comptime T: type) struct {
    [std.meta.declarations(T).len]DeclType,
    std.StaticStringMap(type),
} {
    const decls = std.meta.declarations(T);
    var decl_types: [decls.len]DeclType = undefined;
    var tuples: [decls.len]struct { []const u8, type } = undefined;
    for (decls, 0..) |decl, i| {
        decl_types[i] = .{ .name = decl.name, .type = @TypeOf(@field(T, decl.name)) };
        tuples[i] = .{ decl.name, @TypeOf(@field(T, decl.name)) };
    }
    const map = std.StaticStringMap(type).initComptime(tuples);
    return .{ decl_types, map };
}

test "assertImplements happy path" {
    const MyTrait = struct {
        pub const Hello = struct {};
        pub fn hello(_: Hello) Hello {
            unreachable;
        }
    };
    const MyImpl = struct {
        pub const Hello = struct {};
        pub fn hello(_: Hello) Hello {
            unreachable;
        }
    };
    assertImplements(MyTrait, MyImpl, .identical);
}

test "assertImplements catches: missing type" {
    const MyTrait = struct {
        pub const Hello = struct {};
    };
    const MyImpl = struct {};
    try std.testing.expect(checkImplements(MyTrait, MyImpl, .identical).len > 0);
}

test "assertImplements catches: type not a type" {
    const MyTrait = struct {
        pub const Hello = struct {};
    };
    const MyImpl = struct {
        pub const Hello = 0;
    };
    try std.testing.expect(checkImplements(MyTrait, MyImpl, .identical).len > 0);
}

test "assertImplements catches: wrong function signature" {
    const MyTrait = struct {
        pub const Hello = struct {};
        pub fn hello(_: Hello) Hello {
            unreachable;
        }
    };
    const MyImpl = struct {
        pub const Hello = struct {};
        pub fn hello(_: Hello) MyTrait.Hello {
            unreachable;
        }
    };
    try std.testing.expect(checkImplements(MyTrait, MyImpl, .identical).len > 0);
}

test "assertImplements catches: missing function" {
    const MyTrait = struct {
        pub fn hello(_: usize) usize {
            unreachable;
        }
    };
    const MyImpl = struct {};
    try std.testing.expect(checkImplements(MyTrait, MyImpl, .identical).len > 0);
}

test "assertImplements catches: missing const" {
    const MyTrait = struct {
        pub const number = 1;
    };
    const MyImpl = struct {};
    try std.testing.expect(checkImplements(MyTrait, MyImpl, .identical).len > 0);
}
