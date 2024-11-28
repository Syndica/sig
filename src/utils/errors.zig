const std = @import("std");

/// Error set that includes every variant defined in std.posix.system.E, with two exceptions:
/// - excludes `SUCCESS`
/// - includes `UnknownErrno` since `E` is not exhaustive
///
/// Explicitly defined, it would look something like this:
/// ```zig
/// pub const LibcError = error {
///     PERM,
///     NOENT,
///     SRCH,
///     INTR,
///     IO,
///     ... many more items ...
///     UnknownErrno,
/// };
/// ```
pub const LibcError: type = blk: {
    const enum_variants = @typeInfo(std.posix.E).Enum.fields;
    var error_set: [enum_variants.len]std.builtin.Type.Error = undefined;
    for (enum_variants[1..], 0..) |enum_variant, i| {
        error_set[i].name = enum_variant.name;
    }
    error_set[enum_variants.len - 1].name = "UnknownErrno";
    break :blk @Type(.{ .ErrorSet = &error_set });
};

/// Converts errno enum into an error union.
/// - void for SUCCESS
/// - SystemError for any other value
pub fn errnoToError(errno: std.posix.E) LibcError!void {
    if (errno == .SUCCESS) return;

    const enum_variants = @typeInfo(std.posix.E).Enum.fields;
    const Entry = struct { u16, LibcError };
    const map: [enum_variants.len - 1]Entry = comptime blk: {
        var map: [enum_variants.len - 1]Entry = undefined;
        for (enum_variants[1..], 0..) |enum_variant, i| {
            std.debug.assert(enum_variant.value > enum_variants[i].value);
            map[i] = .{ enum_variant.value, @field(LibcError, enum_variant.name) };
        }
        break :blk map;
    };

    const search_result = std.sort.binarySearch(Entry, @intFromEnum(errno), &map, {}, struct {
        fn compareFn(_: void, key: u16, mid_item: Entry) std.math.Order {
            return std.math.order(key, mid_item[0]);
        }
    }.compareFn);

    return if (search_result) |entry|
        map[entry][1]
    else
        LibcError.UnknownErrno;
}

test errnoToError {
    try errnoToError(std.posix.E.SUCCESS);
    try std.testing.expectError(LibcError.MFILE, errnoToError(std.posix.E.MFILE));
    try std.testing.expectError(LibcError.NOMSG, errnoToError(std.posix.E.NOMSG));
}
