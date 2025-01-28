const std = @import("std");

/// Same as std.EnumFieldStruct, except every field may be a different type
pub fn EnumFieldStructMultiType(comptime E: type, comptime Data: fn (E) type) type {
    @setEvalBranchQuota(@typeInfo(E).Enum.fields.len + 5);
    var struct_fields: [@typeInfo(E).Enum.fields.len]std.builtin.Type.StructField = undefined;
    for (&struct_fields, @typeInfo(E).Enum.fields) |*struct_field, enum_field| {
        const T = Data(@field(E, enum_field.name));
        struct_field.* = .{
            .name = enum_field.name ++ "",
            .type = T,
            .default_value = null,
            .is_comptime = false,
            .alignment = if (@sizeOf(T) > 0) @alignOf(T) else 0,
        };
    }
    return @Type(.{ .Struct = .{
        .layout = .auto,
        .fields = &struct_fields,
        .decls = &.{},
        .is_tuple = false,
    } });
}

/// Same as EnumFieldStructMultiType, except it produces a union instead of a struct
pub fn EnumFieldUnion(comptime E: type, comptime Data: fn (E) type) type {
    @setEvalBranchQuota(@typeInfo(E).Enum.fields.len + 5);
    var union_fields: [@typeInfo(E).Enum.fields.len]std.builtin.Type.UnionField = undefined;
    for (&union_fields, @typeInfo(E).Enum.fields) |*union_field, enum_field| {
        const T = Data(@field(E, enum_field.name));
        union_field.* = .{
            .name = enum_field.name ++ "",
            .type = T,
            .alignment = if (@sizeOf(T) > 0) @alignOf(T) else 0,
        };
    }
    return @Type(.{ .Union = .{
        .layout = .auto,
        .tag_type = E,
        .fields = &union_fields,
        .decls = &.{},
    } });
}
