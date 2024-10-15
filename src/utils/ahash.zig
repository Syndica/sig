const std = @import("std");
const sig = @import("../sig.zig");

const AtomicU64 = std.atomic.Value(u64);
const Random = std.rand.Random;

/// AHasher is a minimal impelementation of the AHash, a fast, DOS-resistant hash algorithm (https://github.com/tkaitchuck/aHash).
/// Currently, only the functionality required to replicate the agave Deduper is implemented.
pub const AHasher = struct {
    buffer: u64,
    pad: u64,
    extra_keys: [2]u64,

    // This constant comes from Kunth's prng (Empirically it works better than those from splitmix32).
    const MULTIPLE: u64 = 6364136223846793005;
    const ROTATE: u32 = 23;

    pub fn fromRandomState(rand_state: RandomState) AHasher {
        return .{
            .buffer = rand_state.k0,
            .pad = rand_state.k1,
            .extra_keys = .{ rand_state.k2, rand_state.k3 },
        };
    }

    pub fn hash(self: *AHasher, comptime T: type, data: *const T) void {
        switch (@typeInfo(T)) {
            .Int => {
                self.update(@intCast(data.*));
            },
            .Array => |array_info| {
                self.hashSlice(array_info.child, data);
            },
            .Pointer => |pointer| {
                switch (pointer.size) {
                    .Slice => self.hashSlice(pointer.child, data.*),
                    else => {
                        std.debug.print("Unsupported pointer size: type={} pointer.size={}\n", .{ T, pointer.size });
                        std.debug.panic("Unsupported pointer size: type={} pointer.size={}\n", .{ T, pointer.size });
                    },
                }
            },
            .Struct => |struct_info| {
                inline for (struct_info.fields) |field| {
                    self.hash(field.type, &@field(data, field.name));
                }
            },
            .Enum => |_| {
                self.hash(u32, &@as(u32, @intFromEnum(data.*)));
            },
            else => {
                std.debug.print("Unsupported type: type={} data={any}\n", .{ T, data });
                std.debug.panic("Unsupported type: type={} data={any}\n", .{ T, data });
            },
        }
    }

    pub fn finish(self: *const AHasher) u64 {
        const rot: u32 = @intCast(self.buffer & 63);
        return std.math.rotl(u64, foldedMultiply(self.buffer, self.pad), rot);
    }

    inline fn hashSlice(self: *AHasher, comptime T: type, data: []const T) void {
        self.update(data.len);
        self.write(@as([]const u8, data));
    }

    inline fn update(self: *AHasher, new_data: u64) void {
        self.buffer = foldedMultiply(new_data ^ self.buffer, MULTIPLE);
    }

    inline fn largeUpdate(self: *AHasher, new_data: u128) void {
        const high: u64 = @intCast(new_data >> 64); // 0..0[0..64]
        const low: u64 = @intCast((new_data << 64) >> 64); // 0..0[64..127]
        const combined = foldedMultiply(low ^ self.extra_keys[0], high ^ self.extra_keys[1]);
        self.buffer = std.math.rotl(u64, ((self.buffer +% self.pad) ^ combined), ROTATE);
    }

    fn write(self: *AHasher, input: []const u8) void {
        var data = input;
        const len: u64 = @intCast(data.len);
        self.buffer = (self.buffer +% len) *% MULTIPLE;
        if (data.len > 8) {
            if (data.len > 16) {
                self.largeUpdate(readLastInt(u128, data));
                while (data.len > 16) {
                    self.largeUpdate(readFirstInt(u128, data));
                    data = data[16..];
                }
            } else {
                self.largeUpdate(readFirstInt(u128, data[0..8] ++ data[(data.len - 8)..][0..8]));
            }
        } else {
            var parts = [2]u64{ 0, 0 };
            if (data.len >= 2) {
                if (data.len >= 4) {
                    parts = .{ @as(u64, readFirstInt(u32, data)), @as(u64, readLastInt(u32, data)) };
                } else {
                    parts = .{ @as(u64, readFirstInt(u16, data)), @as(u64, data[data.len - 1]) };
                }
            } else if (data.len > 0) {
                parts = .{ @as(u64, data[0]), @as(u64, data[0]) };
            }
            self.largeUpdate(readFirstInt(u128, std.mem.asBytes(&parts[0]) ++ std.mem.asBytes(&parts[1])));
        }
    }
};

pub const RandomState = struct {
    k0: u64,
    k1: u64,
    k2: u64,
    k3: u64,

    const PI2 = [_]u64{
        0x4528_21e6_38d0_1377,
        0xbe54_66cf_34e9_0c6c,
        0xc0ac_29b7_c97c_50dd,
        0x3f84_d5b5_b547_0917,
    };

    pub fn fromRng(rng: Random) RandomState {
        return RandomState.fromSeeds(
            rng.int(u64),
            rng.int(u64),
            rng.int(u64),
            rng.int(u64),
        );
    }

    pub fn fromSeeds(k0: u64, k1: u64, k2: u64, k3: u64) RandomState {
        return .{
            .k0 = k0 ^ PI2[0],
            .k1 = k1 ^ PI2[1],
            .k2 = k2 ^ PI2[2],
            .k3 = k3 ^ PI2[3],
        };
    }
};

inline fn readFirstInt(comptime T: type, data: []const u8) T {
    return std.mem.readInt(T, data[0..@sizeOf(T)], .little);
}

inline fn readLastInt(comptime T: type, data: []const u8) T {
    const size: usize = @sizeOf(T);
    return std.mem.readInt(T, data[(data.len - size)..][0..size], .little);
}

inline fn foldedMultiply(s: u64, by: u64) u64 {
    const prod = @as(u128, s) *% @as(u128, by);
    const left: u64 = @intCast(prod & 0xffff_ffff_ffff_ffff);
    const right: u64 = @intCast(prod >> 64);
    return left ^ right;
}

test "AHasher.write" {
    // Test cases are derived from running the reference implementation in Rust.
    const random_state = RandomState.fromSeeds(0, 0, 0, 0);
    {
        var hasher = AHasher.fromRandomState(random_state);
        hasher.write(&[_]u8{});
        try std.testing.expectEqual(13476623659777435794, hasher.finish());
    }
    {
        var hasher = AHasher.fromRandomState(random_state);
        hasher.write(&[_]u8{0});
        try std.testing.expectEqual(4433649978346923560, hasher.finish());
    }
    {
        var hasher = AHasher.fromRandomState(random_state);
        hasher.write(&[_]u8{ 91, 243, 18, 129, 64, 220, 188, 11 });
        try std.testing.expectEqual(17851898492460713816, hasher.finish());
    }
    {
        var hasher = AHasher.fromRandomState(random_state);
        hasher.write(&[_]u8{ 21, 37, 138, 62, 157, 245, 23, 48, 98, 184, 127, 221, 73, 156, 24, 56 });
        try std.testing.expectEqual(15170204645034903865, hasher.finish());
    }
}

test "AHasher.hash" {
    // Test cases are derived from running the reference implementation in Rust.
    const random_state = RandomState.fromSeeds(0, 0, 0, 0);
    {
        var hasher = AHasher.fromRandomState(random_state);
        const data: u32 = 10;
        hasher.hash(@TypeOf(data), &data);
        hasher.hash(@TypeOf(data), &data);
        hasher.hash(@TypeOf(data), &data);
        try std.testing.expectEqual(12791420710718635355, hasher.finish());
    }
    {
        var hasher = AHasher.fromRandomState(random_state);
        const data = [_]u8{};
        hasher.hash(@TypeOf(data), &data);
        hasher.hash(@TypeOf(data), &data);
        hasher.hash(@TypeOf(data), &data);
        try std.testing.expectEqual(6946764487996054145, hasher.finish());
    }
    {
        var hasher = AHasher.fromRandomState(random_state);
        const data = [_]u8{ 10, 3, 5 };
        hasher.hash(@TypeOf(data), &data);
        hasher.hash(@TypeOf(data), &data);
        hasher.hash(@TypeOf(data), &data);
        try std.testing.expectEqual(15306412442377278323, hasher.finish());
    }
}
