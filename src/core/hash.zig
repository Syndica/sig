const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;
const base58 = @import("base58-zig");
const CompareOperator = std.math.CompareOperator;

pub const HASH_SIZE: usize = 32;

pub const Hash = struct {
    data: [HASH_SIZE]u8,

    const Self = @This();

    pub fn default() Self {
        return .{ .data = [_]u8{0} ** HASH_SIZE };
    }
    // used in tests
    pub fn random() Self {
        var seed = @as(u64, @intCast(std.time.milliTimestamp()));
        var rand = std.rand.DefaultPrng.init(seed);
        var data: [HASH_SIZE]u8 = undefined;

        for (0..HASH_SIZE) |i| {
            data[i] = rand.random().int(u8);
        }
        return Self{
            .data = data,
        };
    }

    pub fn generateSha256Hash(bytes: []const u8) Self {
        var hash = Hash{
            .data = undefined,
        };
        Sha256.hash(bytes, &hash.data, .{});
        return hash;
    }

    pub fn cmp(a: *const Self, b: *const Self) CompareOperator {
        for (0..HASH_SIZE) |i| {
            if (a.data[i] > b.data[i]) {
                return .gt;
            } else if (a.data[i] < b.data[i]) {
                return .lt;
            }
        }
        return .eq;
    }

    pub fn extendAndHash(
        alloc: Allocator,
        id: Hash,
        val: []u8,
    ) Allocator.Error!Self {
        var hash_data = try std.ArrayList(u8).initCapacity(alloc, val.len + id.data.len);
        defer hash_data.deinit();
        hash_data.appendSliceAssumeCapacity(&id.data);
        hash_data.appendSliceAssumeCapacity(val);
        const hash = generateSha256Hash(hash_data.items);
        return hash;
    }

    pub fn format(self: Hash, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const b58_encoder = base58.Encoder.init(.{});
        var buf: [44]u8 = undefined;
        const size = b58_encoder.encode(&self.data, &buf) catch unreachable;
        return writer.print("{s}", .{buf[0..size]});
    }
};
