const std = @import("std");

pub fn Option(comptime T: type) type {
    return union(enum(u8)) {
        none,
        some: T,

        const Self = @This();

        pub fn Some(val: T) Self {
            return .{ .some = val };
        }

        pub fn None() Self {
            return .none;
        }

        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, w: anytype) !void {
            switch (self) {
                .none => try w.writeAll("(none)"),
                .some => |v| try w.print("{any}", .{v}),
            }
        }
    };
}
