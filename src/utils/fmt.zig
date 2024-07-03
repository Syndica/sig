const std = @import("std");

/// The only circumstance in which this function would return `error.Overflow` is if
/// the `max_args` tuple posseses any incorrect (non-maximum) values.
pub fn boundedFmt(
    comptime fmt_str: []const u8,
    args: anytype,
    /// Each argument should have a value which is formatted as the maximum logical length of the corresponding runtime argument.
    /// For example, if `@TypeOf(args[0]) == u64`, then it should follow that `max_args[0] == std.math.maxInt(u64)`.
    comptime max_args: @TypeOf(args),
) error{Overflow}!std.BoundedArray(u8, std.fmt.count(fmt_str, max_args)) {
    var result: std.BoundedArray(u8, std.fmt.count(fmt_str, max_args)) = .{};
    try result.writer().print(fmt_str, args);
    return result;
}
