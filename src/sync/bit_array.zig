const std = @import("std");

const Atomic = std.atomic.Atomic;
const Ordering = std.atomic.Ordering;

pub fn AtomicBitArray(comptime size: usize) type {
    const num_bytes = (size + 7) / 8;
    return struct {
        bytes: [num_bytes]Atomic(u8) = .{.{ .value = 0 }} ** num_bytes,

        pub const len = size;

        const Self = @This();

        pub fn get(self: *Self, index: usize, comptime ordering: Ordering) !bool {
            if (index >= size) return error.OutOfBounds;
            const bitmask = mask(index);
            return self.bytes[index / 8].load(ordering) & bitmask == bitmask;
        }

        pub fn set(self: *Self, index: usize, comptime ordering: Ordering) !void {
            if (index >= size) return error.OutOfBounds;
            _ = self.bytes[index / 8].fetchOr(mask(index), ordering);
        }

        pub fn unset(self: *Self, index: usize, comptime ordering: Ordering) !void {
            if (index >= size) return error.OutOfBounds;
            _ = self.bytes[index / 8].fetchAnd(~mask(index), ordering);
        }

        fn mask(index: usize) u8 {
            return @as(u8, 1) << @intCast(index % 8);
        }
    };
}

test "sync.bit_array" {
    var x = AtomicBitArray(3){};
    try std.testing.expect(!try x.get(0, .Monotonic));
    try std.testing.expect(!try x.get(1, .Monotonic));
    try std.testing.expect(!try x.get(2, .Monotonic));

    try x.set(1, .Monotonic);

    try std.testing.expect(!try x.get(0, .Monotonic));
    try std.testing.expect(try x.get(1, .Monotonic));
    try std.testing.expect(!try x.get(2, .Monotonic));

    try x.set(0, .Monotonic);
    try x.set(1, .Monotonic);
    try x.set(2, .Monotonic);

    try std.testing.expect(try x.get(0, .Monotonic));
    try std.testing.expect(try x.get(1, .Monotonic));
    try std.testing.expect(try x.get(2, .Monotonic));

    try x.unset(2, .Monotonic);
    try x.unset(1, .Monotonic);
    try x.unset(2, .Monotonic);

    try std.testing.expect(try x.get(0, .Monotonic));
    try std.testing.expect(!try x.get(1, .Monotonic));
    try std.testing.expect(!try x.get(2, .Monotonic));

    if (x.get(3, .Monotonic)) |_| @panic("") else |_| {}
    if (x.set(3, .Monotonic)) |_| @panic("") else |_| {}
    if (x.unset(3, .Monotonic)) |_| @panic("") else |_| {}
    if (x.get(3, .Monotonic)) |_| @panic("") else |_| {}
}
