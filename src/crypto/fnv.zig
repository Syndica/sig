const std = @import("std");

/// ***FnvHasher*** is a FNV-1 (64-bit) hasher implementation.
/// See: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
pub const FnvHasher = struct {
    hashh: u64,

    const Self = @This();
    const prime: u64 = 0x100000001b3;
    pub const DEFAULT_OFFSET: u64 = 0xcbf29ce484222325;

    pub fn init() Self {
        return Self{
            .hashh = DEFAULT_OFFSET,
        };
    }

    pub fn initWithOffset(offset: u64) Self {
        return Self{
            .hashh = offset,
        };
    }

    pub fn update(self: *Self, input: []const u8) void {
        for (input) |byte| {
            self.hashh ^= byte;
            self.hashh *%= prime;
        }
    }

    pub fn final(self: *Self) u64 {
        return self.hashh;
    }

    pub fn hash(input: []const u8) u64 {
        var c = Self.init();
        c.update(input);
        return c.final();
    }

    pub fn hashWithOffset(input: []const u8, offset: u64) u64 {
        var c = Self.initWithOffset(offset);
        c.update(input);
        return c.final();
    }
};

test "fnv hasher with default is correct" {
    const exp = 12638152016183539244; 

    var hasher = FnvHasher.init();
    hasher.hash(&.{ 1 });
    const result = hasher.final();
    try std.testing.expectEqual(exp, result);
}

test "fnv hasher with offset is correct" {
    const exp = 11233064889143142093; 

    var hasher = FnvHasher.initWithOffset(19);
    hasher.hash(&.{ 1, 2, 3 });
    const result = hasher.final();
    try std.testing.expectEqual(exp, result);
}