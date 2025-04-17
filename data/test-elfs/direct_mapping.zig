const std = @import("std");

/// hashed as `sol_memcpy_`
const memcpy: *align(1) const fn (
    dst: [*]u8,
    src: [*]const u8,
    len: usize,
) void = @ptrFromInt(0x717cc4a3);

export fn entrypoint(input: [*]u8) i32 {
    memcpy(input, &.{ 10, 20, 30 }, 3);
    return 0;
}
