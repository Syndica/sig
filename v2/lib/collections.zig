const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

pub const Pool = @import("collections/pool.zig").Pool;
pub const LCRSTree = @import("collections/lcrs_tree.zig").LCRSTree;

pub fn Id(IdInt: type) type {
    const expected_idx_ints: []const type = &.{ u8, u16, u32, u64 };
    if (std.mem.indexOfScalar(type, expected_idx_ints, IdInt) == null)
        @compileError("Unexpected integer type");

    return enum(IdInt) {
        null = std.math.maxInt(IdInt),
        _,

        const Self = @This();

        pub fn index(self: Self) ?IdInt {
            if (self == .null) return null;
            return @intFromEnum(self);
        }

        pub fn fromInt(int: IdInt) Self {
            return @enumFromInt(int);
        }
    };
}
