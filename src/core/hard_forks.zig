const std = @import("std");
const ArrayList = std.ArrayList;
const allocator = std.mem.Allocator;
const Slot = @import("time.zig").Slot;
const expect = std.testing.expect;
const eql = std.mem.eql;

pub const HardFork = struct { slot: Slot, count: usize };
pub const HardForks = struct {
    hard_forks: ArrayList(HardFork),

    const Self = @This();

    pub fn default(alloc: allocator) Self {
        return .{ .hard_forks = ArrayList(HardFork).init(alloc) };
    }

    pub fn register(self: *Self, new_slot: Slot) !void {
        const maybe_index = for (self.hard_forks.items, 0..) |hard_fork, index| {
            if (hard_fork.slot == new_slot) break index;
        } else null;

        if (maybe_index) |index| {
            self.hard_forks.items[index] = .{ .slot = new_slot, .count = self.hard_forks.items[index].count +| 1 };
        } else {
            try self.hard_forks.append(.{ .slot = new_slot, .count = 1 });
        }
        std.mem.sort(HardFork, self.hard_forks.items, {}, struct {
            pub fn lessThan(_: void, a: HardFork, b: HardFork) bool {
                return a.slot < b.slot;
            }
        }.lessThan);
    }

    pub fn deinit(self: *Self) void {
        self.hard_forks.deinit();
    }

    pub fn get_forks(self: *const Self) []HardFork {
        return self.hard_forks.items;
    }

    pub fn get_hash_data(self: *const Self, slot: Slot, parent_slot: Slot) ?[8]u8 {
        var fork_count: u64 = 0;
        for (self.hard_forks.items) |hard_fork| {
            const current_fork_slot = hard_fork.slot;
            const current_fork_count = hard_fork.count;

            if (parent_slot < current_fork_slot and slot >= current_fork_slot) {
                fork_count += current_fork_count;
            }
        }

        if (fork_count > 0) {
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, fork_count, .little);
            return buf;
        } else {
            return null;
        }
    }
};

test "core.hard_forks: test hardforks" {
    const Logger = @import("../trace/log.zig").Logger;
    const TestingLogger = @import("../trace/log.zig").DirectPrintLogger;
    const testing_alloc = std.testing.allocator;

    const test_logger = TestingLogger.init(.{
        .allocator = testing_alloc,
        .max_level = Logger.TEST_DEFAULT_LEVEL,
    });
    defer test_logger.deinit();

    const logger = test_logger.logger();

    var hard_forks = HardForks.default(testing_alloc);
    defer hard_forks.deinit();

    try hard_forks.register(10);
    try hard_forks.register(20);

    try expect(hard_forks.get_forks()[0].slot == 10);
    try expect(hard_forks.get_forks()[1].count == 1);
    try expect(hard_forks.get_forks()[1].slot == 20);
    try expect(hard_forks.get_forks()[1].count == 1);

    const hash_data_one = hard_forks.get_hash_data(9, 0);
    try expect(hash_data_one == null);

    logger.debug().logf("hash_data_one: {any}", .{hash_data_one});

    var hash_data_two = hard_forks.get_hash_data(10, 0);
    try expect(hash_data_two != null);
    try expect(std.mem.eql(u8, &hash_data_two.?, &[8]u8{ 1, 0, 0, 0, 0, 0, 0, 0 }));

    logger.debug().logf("hard_forks_two: {any}", .{hash_data_two});

    try expect(eql(u8, &hard_forks.get_hash_data(19, 0).?, &[8]u8{ 1, 0, 0, 0, 0, 0, 0, 0 }));
    try expect(eql(u8, &hard_forks.get_hash_data(20, 0).?, &[8]u8{ 2, 0, 0, 0, 0, 0, 0, 0 }));
    try expect(eql(u8, &hard_forks.get_hash_data(20, 10).?, &[8]u8{ 1, 0, 0, 0, 0, 0, 0, 0 }));
    try expect(eql(u8, &hard_forks.get_hash_data(20, 11).?, &[8]u8{ 1, 0, 0, 0, 0, 0, 0, 0 }));
    try expect(eql(u8, &hard_forks.get_hash_data(21, 11).?, &[8]u8{ 1, 0, 0, 0, 0, 0, 0, 0 }));
    try expect(hard_forks.get_hash_data(21, 20) == null);
}
