//! Generic type reflection.

const std = @import("std");

/// Given the string name of an enum variant,
/// return the instance of the enum with that name.
pub fn enumFromName(comptime T: type, variant_name: []const u8) error{UnknownVariant}!T {
    inline for (@typeInfo(T).Enum.fields) |field| {
        if (std.mem.eql(u8, field.name, variant_name)) {
            return @enumFromInt(field.value);
        }
    }
    return error.UnknownVariant;
}

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

pub fn fieldNames(comptime Struct: type) [@typeInfo(Struct).Struct.fields.len][:0]const u8 {
    const fields = @typeInfo(Struct).Struct.fields;
    var names: [fields.len][:0]const u8 = undefined;
    for (fields, 0..) |field, i| {
        names[i] = field.name;
    }
    return names;
}
