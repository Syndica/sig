const std = @import("std");

/// Throws a compile error if `Impl` does not implement the interface
/// defined by `Interface`.
///
/// Implementing an interface means:
///   For each pub decl in `Interface`, `Impl` has a decl with the same
///   name and the same[1] type. The decls do *not* need to have the
///   same value, only the same type.
///
/// This can be useful when implementing a pattern analogous to
/// trait (rust), interface (go/java), or typeclass (haskell).
///
/// [1] Declarations in the Impl are expected to have a different type from
/// those in the Interface when the Interface declaration contains a type
/// that is defined within the interface. For example, this is a compliant
/// implementation because it implements its own version of Foo and then
/// returns its own Foo from its implementation of getFoo. The two getFoo
/// functions have different types because their return types are different,
/// but they are the correct types required for compliance.
/// ```zig
/// const Interface {
///     pub const Foo = struct {};
///     pub fn getFoo() Foo {
///         return .{};
///     }
/// }
/// const Implemenation {
///     pub const Foo = struct {
///         custom_field = 1,
///     };
///     pub fn getFoo() Foo {
///         return .{ .custom_field = 123 };
///     }
/// }
/// ```
pub fn assertImplements(
    comptime Interface: type,
    comptime Impl: type,
    /// Specify how error sets returned by Impl functions are expected
    /// to relate to error sets returned by Interface functions.
    comptime impl_errors_must_be: SetRelationship,
) void {
    const errors = comptime checkImplements(Interface, Impl, impl_errors_must_be);
    if (errors.len != 0) {
        @compileError(errors);
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
    /// Specify how error sets returned by Impl functions are expected
    /// to relate to error sets returned by Interface functions.
    comptime U_errors_must_be: SetRelationship,
) void {
    comptime {
        assertImplements(T, U, U_errors_must_be);
        assertImplements(U, T, U_errors_must_be.invert());
    }
}

const SetRelationship = enum {
    equal,
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

/// implementation for assertImplements that just returns an error string
/// instead of throwing a compile error. If string.len > 0, there
/// was an error.
fn checkImplements(
    comptime Interface: type,
    comptime Impl: type,
    comptime impl_errors_must_be: SetRelationship,
) []const u8 {
    return comptime blk: {
        @setEvalBranchQuota(10_000);
        const iface_decls, _ = declTypes(Interface);
        _, const impl_decls = declTypes(Impl);
        var errors = ComptimeStringBuilder{};
        const state: CheckState = .{
            .Interface = Interface,
            .Impl = Impl,
            .impl_errors_must_be = impl_errors_must_be,
            .impl_decls = impl_decls,
            .errors = &errors,
        };

        // init the mapping from Interface type to Impl type
        var types_buf: [1 + iface_decls.len][2]type = undefined;
        var types_num = 1;
        types_buf[0] = .{ state.Interface, state.Impl };

        // check that Impl contains type definitions for each type in Interface
        for (iface_decls) |iface_decl| if (iface_decl.type.isType()) {
            if (checkOneDecl(state, iface_decl, &.{})) {
                // store the type mapping
                types_buf[types_num] = .{
                    @field(Interface, iface_decl.name),
                    @field(Impl, iface_decl.name),
                };
                types_num += 1;
            }
        };

        // a map from each type defined into the interface to the type defined in the impl
        const types_map = types_buf[0..types_num];

        // check that Impl contains decls for each non-type decl in Interface
        for (iface_decls) |iface_decl| if (!iface_decl.type.isType()) {
            _ = checkOneDecl(state, iface_decl, types_map);
        };

        break :blk errors.string;
    };
}

const CheckState = struct {
    Interface: type,
    Impl: type,
    impl_errors_must_be: SetRelationship,
    impl_decls: std.StaticStringMap(DeclType),
    errors: *ComptimeStringBuilder,
};

fn checkOneDecl(state: CheckState, iface_decl: Decl, types_map: []const [2]type) bool {
    const expected_type = iface_decl.type.convert(types_map);
    if (state.impl_decls.get(iface_decl.name)) |actual_type| {
        // there *is* a decl with the same name
        if (!actual_type.eql(expected_type, state.impl_errors_must_be)) {
            // that decl has the wrong type
            state.errors.print(
                \\The implementation of `{[decl]s}` does not conform to the interface.
                \\         Interface: {[interface]any}.{[decl]s}
                \\    Implementation: {[impl]any}.{[decl]s}
                \\      It should be: {[expected]any}
                \\      ...but it is: {[actual]any}
                \\
                \\
            ,
                .{
                    .decl = iface_decl.name,
                    .interface = state.Interface,
                    .impl = state.Impl,
                    .expected = expected_type,
                    .actual = actual_type,
                },
            );
            return false;
        }
    } else {
        // there is *no* decl with the same name
        state.errors.print(
            \\`{[decl]s}` is required by the interface, but missing from the implementation.
            \\         Interface: {[interface]any}.{[decl]s}
            \\    Implementation: {[impl]any}
            \\          Expected: {[expected]any}
            \\
            \\
        ,
            .{
                .decl = iface_decl.name,
                .interface = state.Interface,
                .impl = state.Impl,
                .expected = iface_decl.type,
            },
        );
        return false;
    }
    return true;
}

const Decl = struct {
    name: []const u8,
    type: DeclType,
};

/// Represents a type, but with minimally specified function types.
/// This allows relaxed compatibility checks.
const DeclType = union(enum) {
    type: type,
    func: FunctionSignature,

    pub fn init(comptime T: type) DeclType {
        if (@typeInfo(T) == .@"fn") {
            return .{ .func = FunctionSignature.init(@typeInfo(T).@"fn") };
        } else {
            return .{ .type = T };
        }
    }

    pub fn eql(self: DeclType, other: DeclType, self_errors_must_be: SetRelationship) bool {
        return if (self == .type and other == .type)
            self.type == other.type
        else if (self == .func and other == .func)
            self.func.eql(other.func, self_errors_must_be)
        else
            false;
    }

    pub fn format(
        self: DeclType,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .type => |T| try std.fmt.format(writer, "{}", .{T}),
            .func => |f| try f.format(fmt, options, writer),
        }
    }

    pub fn convert(self: DeclType, map: []const [2]type) DeclType {
        return switch (self) {
            .type => |T| .{ .type = convertType(T, map) },
            .func => |F| .{ .func = F.convertTypes(map) },
        };
    }

    /// This type is `type`
    pub fn isType(self: DeclType) bool {
        return self == .type and self.type == type;
    }
};

fn declTypes(comptime T: type) struct {
    [std.meta.declarations(T).len]Decl,
    std.StaticStringMap(DeclType),
} {
    const declarations = std.meta.declarations(T);
    var decls: [declarations.len]Decl = undefined;
    var tuples: [declarations.len]struct { []const u8, DeclType } = undefined;
    for (declarations, 0..) |decl, i| {
        const decl_type = DeclType.init(@TypeOf(@field(T, decl.name)));
        decls[i] = .{ .name = decl.name, .type = decl_type };
        tuples[i] = .{ decl.name, decl_type };
    }
    const map = std.StaticStringMap(DeclType).initComptime(tuples);
    return .{ decls, map };
}

/// This can be used to determine if two functions are interchangeable,
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
            @typeInfo(self.Return.?) == .error_union and @typeInfo(other.Return.?) == .error_union)
        {
            const self_union = @typeInfo(self.Return.?).error_union;
            const other_union = @typeInfo(other.Return.?).error_union;
            if (self_union.payload != other_union.payload) {
                return false;
            }
            const super, const sub = switch (self_errors_must_be) {
                .equal => return self.Return == other.Return,
                .any => .{ error{}, error{} },
                .subset => .{ other_union.error_set, self_union.error_set },
                .superset => .{ self_union.error_set, other_union.error_set },
            };
            if (@typeInfo(sub).error_set) |sub_set| if (@typeInfo(super).error_set) |super_set| {
                sub: for (sub_set) |sub_err| {
                    for (super_set) |super_err| {
                        if (std.mem.eql(u8, sub_err.name, super_err.name)) {
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
            if (param) |P| try writer.print("{any}", .{P}) else try writer.print("???", .{});
            if (i + 1 != self.params.len) try writer.print(", ", .{});
        }
        try writer.print(") ", .{});
        if (self.Return) |R| try writer.print("{any}", .{R}) else try writer.print("???", .{});
    }
};

pub const ComptimeStringBuilder = struct {
    string: []const u8 = "",

    pub fn print(comptime self: *@This(), comptime fmt: []const u8, comptime args: anytype) void {
        comptime {
            const message = std.fmt.comptimePrint(fmt, args);
            self.string = std.fmt.comptimePrint("{s}{s}", .{ self.string, message });
        }
    }
};

/// Replaces T with its associated type in map if found, otherwise recursively
/// inspects T for nested types that can be found in map, and replaces those.
fn convertType(comptime T: type, comptime map: []const [2]type) type {
    return if (get(map, T)) |NewT|
        NewT
    else switch (@typeInfo(T)) {
        .pointer => |ptr| {
            var new_ptr = ptr;
            new_ptr.child = convertType(new_ptr.child, map);
            return @Type(.{ .pointer = new_ptr });
        },
        .error_union => |eu| {
            var new_eu = eu;
            new_eu.payload = convertType(eu.payload, map);
            new_eu.error_set = convertType(eu.error_set, map);
            return @Type(.{ .error_union = new_eu });
        },
        .optional => |opt| {
            var new_opt = opt;
            new_opt.child = convertType(opt.child, map);
            return @Type(.{ .optional = new_opt });
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

test convertType {
    try std.testing.expectEqual(*u64, convertType(*usize, &.{.{ usize, u64 }}));
    try std.testing.expectEqual(anyerror!u64, convertType(anyerror!usize, &.{.{ usize, u64 }}));
    try std.testing.expectEqual(anyerror!*u64, convertType(anyerror!*usize, &.{.{ usize, u64 }}));
    try std.testing.expectEqual(*anyerror!u64, convertType(*anyerror!usize, &.{.{ usize, u64 }}));
}

test "assertImplements happy path" {
    const MyInterface = struct {
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
    assertImplements(MyInterface, MyImpl, .equal);
}

test "assertImplements catches: missing type" {
    const MyInterface = struct {
        pub const Hello = struct {};
    };
    const MyImpl = struct {};
    try std.testing.expect(checkImplements(MyInterface, MyImpl, .equal).len > 0);
}

test "assertImplements catches: type not a type" {
    const MyInterface = struct {
        pub const Hello = struct {};
    };
    const MyImpl = struct {
        pub const Hello = 0;
    };
    try std.testing.expect(checkImplements(MyInterface, MyImpl, .equal).len > 0);
}

test "assertImplements catches: wrong function signature" {
    const MyInterface = struct {
        pub const Hello = struct {};
        pub fn hello(_: Hello) Hello {
            unreachable;
        }
    };
    const MyImpl = struct {
        pub const Hello = struct {};
        pub fn hello(_: Hello) MyInterface.Hello {
            unreachable;
        }
    };
    try std.testing.expect(checkImplements(MyInterface, MyImpl, .equal).len > 0);
}

test "assertImplements catches: missing function" {
    const MyInterface = struct {
        pub fn hello(_: usize) usize {
            unreachable;
        }
    };
    const MyImpl = struct {};
    try std.testing.expect(checkImplements(MyInterface, MyImpl, .equal).len > 0);
}

test "assertImplements catches: missing const" {
    const MyInterface = struct {
        pub const number = 1;
    };
    const MyImpl = struct {};
    try std.testing.expect(checkImplements(MyInterface, MyImpl, .equal).len > 0);
}
