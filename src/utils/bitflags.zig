pub fn BitFlags(comptime FlagEnum: type) type {
    return packed struct {
        state: @typeInfo(FlagEnum).Enum.tag_type = 0,

        const Self = @This();

        pub const Flag = FlagEnum;

        pub fn from(flag: FlagEnum) Self {
            return .{ .state = @intFromEnum(flag) };
        }

        pub fn set(self: *Self, flag: FlagEnum) void {
            self.state |= @intFromEnum(flag);
        }

        pub fn unset(self: *Self, flag: FlagEnum) void {
            self.state &= ~@intFromEnum(flag);
        }

        pub fn isSet(self: *const Self, flag: FlagEnum) bool {
            return self.state & @intFromEnum(flag) == @intFromEnum(flag);
        }

        pub fn intersects(self: *const Self, flag: FlagEnum) bool {
            return self.state & @intFromEnum(flag) != 0;
        }

        pub fn intersection(self: Self, flag: FlagEnum) Self {
            return .{ .state = self.state & @intFromEnum(flag) };
        }
    };
}
