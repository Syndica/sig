const std = @import("std");
const Slot = @import("time.zig").Slot;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

pub const HardForks = struct {
    forks: std.ArrayListUnmanaged(Fork) = .{},

    pub const Fork = extern struct { slot: Slot, count: u64 };

    pub fn register(self: *HardForks, allocator: std.mem.Allocator, new_slot: Slot) !void {
        const maybe_index: ?u64 = for (self.forks.items, 0..) |hard_fork, index| {
            if (hard_fork.slot == new_slot) break index;
        } else null;

        if (maybe_index) |index| {
            self.forks.items[index] = .{
                .slot = new_slot,
                .count = self.forks.items[index].count +| 1,
            };
        } else {
            try self.forks.append(allocator, .{ .slot = new_slot, .count = 1 });
        }

        std.mem.sort(Fork, self.forks.items, {}, lessThan);
    }

    fn lessThan(_: void, a: Fork, b: Fork) bool {
        return a.slot < b.slot;
    }

    pub fn deinit(self: *HardForks, allocator: std.mem.Allocator) void {
        self.forks.deinit(allocator);
    }

    pub fn getHashData(self: *const HardForks, slot: Slot, parent_slot: Slot) ?[8]u8 {
        var fork_count: u64 = 0;
        for (self.forks.items) |hard_fork| {
            if (parent_slot < hard_fork.slot and slot >= hard_fork.slot) {
                fork_count += hard_fork.count;
            }
        }

        if (fork_count > 0) {
            return @bitCast(fork_count);
        } else {
            return null;
        }
    }
};

test HardForks {
    const allocator = std.testing.allocator;

    var hard_forks: HardForks = .{};
    defer hard_forks.deinit(allocator);

    try hard_forks.register(allocator, 10);
    try hard_forks.register(allocator, 20);

    try expectEqual(10, hard_forks.forks.items[0].slot);
    try expectEqual(1, hard_forks.forks.items[1].count);
    try expectEqual(20, hard_forks.forks.items[1].slot);
    try expectEqual(1, hard_forks.forks.items[1].count);

    try expectEqual(null, hard_forks.getHashData(9, 0));

    try expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 0, 0 }, &hard_forks.getHashData(10, 0).?);

    try expectEqualSlices(u8, &.{ 2, 0, 0, 0, 0, 0, 0, 0 }, &hard_forks.getHashData(20, 0).?);
    try expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 0, 0 }, &hard_forks.getHashData(20, 10).?);
    try expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 0, 0 }, &hard_forks.getHashData(20, 11).?);
    try expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 0, 0 }, &hard_forks.getHashData(21, 11).?);
    try expectEqual(null, hard_forks.getHashData(21, 20));
}
