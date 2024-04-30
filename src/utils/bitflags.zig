pub fn BitFlags(comptime FlagEnum: type) type {
    return packed struct {
        state: @typeInfo(FlagEnum).Enum.tag_type,

        const Self = @This();

        pub const Flag = FlagEnum;

        pub fn isSet(self: *const Self, flag: FlagEnum) bool {
            return self.state & @intFromEnum(flag) == @intFromEnum(flag);
        }

        pub fn set(self: *Self, flag: FlagEnum) void {
            self.state |= @intFromEnum(flag);
        }

        pub fn unset(self: *Self, flag: FlagEnum) void {
            self.state &= ~@intFromEnum(flag);
        }
    };
}
