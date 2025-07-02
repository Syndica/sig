const std = @import("std");

/// ***FnvHasher*** is a FNV-1 (64-bit) hasher implementation.
/// See: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
pub const FnvHasher = struct {
    accumulator: u64,

    const PRIME: u64 = 0x100000001b3;
    pub const DEFAULT_OFFSET: u64 = 0xcbf29ce484222325;

    pub const init: FnvHasher = .{ .accumulator = DEFAULT_OFFSET };

    pub fn initWithOffset(offset: u64) FnvHasher {
        return .{ .accumulator = offset };
    }

    pub fn update(self: *FnvHasher, input: []const u8) void {
        for (input) |byte| {
            self.accumulator ^= byte;
            self.accumulator *%= PRIME;
        }
    }

    pub fn final(self: *FnvHasher) u64 {
        return self.accumulator;
    }

    pub fn hash(input: []const u8) u64 {
        var c = init;
        c.update(input);
        return c.final();
    }

    pub fn hashWithOffset(input: []const u8, offset: u64) u64 {
        var c = initWithOffset(offset);
        c.update(input);
        return c.final();
    }
};

test "fnv hasher with default is correct" {
    const exp: u64 = 12638152016183539244;

    var hasher = FnvHasher.init;
    hasher.update(&.{1});
    const result = hasher.final();
    try std.testing.expectEqual(exp, result);
}

test "fnv hasher with offset is correct" {
    const exp: u64 = 11233064889143142093;

    var hasher = FnvHasher.initWithOffset(19);
    hasher.update(&.{ 1, 2, 3 });
    const result = hasher.final();
    try std.testing.expectEqual(exp, result);
}
