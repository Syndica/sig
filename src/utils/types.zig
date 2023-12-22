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
