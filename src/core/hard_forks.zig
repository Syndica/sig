const std = @import("std");

const Allocator = std.mem.Allocator;
const Slot = @import("time.zig").Slot;

/// TODO: It may be more efficient to store hard forks as a hash map, and only sort when required.
pub const HardForks = struct {
    entries: std.ArrayListUnmanaged(HardFork) = .empty,

    pub const HardFork = extern struct {
        slot: Slot,
        count: u64,

        pub fn sortCmp(_: void, a: HardFork, b: HardFork) bool {
            return a.slot < b.slot; // Sort by ascending slot
        }

        pub fn searchCmp(slot: Slot, b: HardFork) std.math.Order {
            return std.math.order(slot, b.slot);
        }
    };

    pub fn deinit(self: HardForks, allocator: Allocator) void {
        allocator.free(self.entries.allocatedSlice());
    }

    pub fn clone(
        self: HardForks,
        allocator: Allocator,
    ) Allocator.Error!HardForks {
        return .{ .entries = try self.entries.clone(allocator) };
    }

    pub fn register(self: *HardForks, allocator: Allocator, new_slot: Slot) !void {
        const index = std.sort.lowerBound(
            HardFork,
            self.entries.items,
            new_slot,
            HardFork.searchCmp,
        );

        if (index == self.entries.items.len)
            try self.entries.append(allocator, .{ .slot = new_slot, .count = 1 })
        else if (self.entries.items[index].slot == new_slot)
            self.entries.items[index].count +|= 1
        else
            try self.entries.insert(allocator, index, .{ .slot = new_slot, .count = 1 });
    }

    pub fn getHashData(self: *const HardForks, slot: Slot, parent_slot: Slot) ?[8]u8 {
        var fork_count: u64 = 0;
        for (self.entries.items) |hard_fork| {
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

    pub fn initRandom(
        random: std.Random,
        allocator: Allocator,
        max_list_entries: usize,
    ) Allocator.Error!HardForks {
        const hard_forks_len = random.uintAtMost(usize, max_list_entries);

        var self = try std.ArrayListUnmanaged(HardFork).initCapacity(
            allocator,
            hard_forks_len,
        );
        errdefer allocator.free(self);

        for (0..hard_forks_len) |_| self.appendAssumeCapacity(.{
            .slot = random.int(Slot),
            .count = random.int(usize),
        });

        std.sort.heap(HardFork, self.items, {}, HardFork.sortCmp);

        return .{ .entries = self };
    }
};

test HardForks {
    const allocator = std.testing.allocator;

    var hard_forks: HardForks = .{};
    defer hard_forks.deinit(allocator);

    try hard_forks.register(allocator, 10);
    try hard_forks.register(allocator, 20);

    try std.testing.expectEqual(10, hard_forks.entries.items[0].slot);
    try std.testing.expectEqual(1, hard_forks.entries.items[1].count);
    try std.testing.expectEqual(20, hard_forks.entries.items[1].slot);
    try std.testing.expectEqual(1, hard_forks.entries.items[1].count);

    try std.testing.expectEqual(null, hard_forks.getHashData(9, 0));

    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 0, 0, 0, 0, 0, 0, 0 },
        &hard_forks.getHashData(10, 0).?,
    );

    try std.testing.expectEqualSlices(
        u8,
        &.{ 2, 0, 0, 0, 0, 0, 0, 0 },
        &hard_forks.getHashData(20, 0).?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 0, 0, 0, 0, 0, 0, 0 },
        &hard_forks.getHashData(20, 10).?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 0, 0, 0, 0, 0, 0, 0 },
        &hard_forks.getHashData(20, 11).?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 0, 0, 0, 0, 0, 0, 0 },
        &hard_forks.getHashData(21, 11).?,
    );
    try std.testing.expectEqual(null, hard_forks.getHashData(21, 20));
}
