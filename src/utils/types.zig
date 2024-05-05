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
