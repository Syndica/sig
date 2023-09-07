const std = @import("std");
const ArrayList = std.ArrayList;
const allocator = std.mem.Allocator;
const Slot = @import("slot.zig").Slot;
pub const HardFork = struct { Slot, usize };
pub const HardForks = struct {
    hard_forks: ArrayList(HardFork),

    const Self = @This();
    pub fn default(alloc: allocator) Self {
        return .{ .hard_forks = ArrayList(HardFork).init(alloc) };
    }
    pub fn register(self: *Self, new_slot: Slot) !void {
        const index = for (self.hard_forks.items, 0..) |hf, i| {
            if (hf[0].value == new_slot.value) break i;
        } else null;

        if (index != null) {
            try self.hard_forks.append(.{ new_slot, self.hard_forks.items[index.?][1] +| 1 });
        } else {
            try self.hard_forks.append(.{ new_slot, 1 });
        }
        std.mem.sort(HardFork, self.hard_forks.items, {}, struct {
            pub fn lessThan(_: void, a: HardFork, b: HardFork) bool {
                return a[0].value < b[0].value;
            }
        }.lessThan);
    }
    pub fn deinit(self: *Self) void {
        self.hard_forks.deinit();
    }
    pub fn get_forks(self: *const Self) []HardFork {
        return self.hard_forks.items;
    }
    pub fn get_hash_data(self: *Self, slot: Slot, parent_slot: Slot) ?[8]u8 {
        var fork_count: usize = 0;
        for (self.hard_forks.items) |hard_fork| {
            var current_fork_slot = hard_fork[0].value;
            var current_fork_count = hard_fork[1];

            if (parent_slot.value < current_fork_slot and slot.value >= current_fork_slot) {
                fork_count += current_fork_count;
            }
        }

        if (fork_count > 0) {
            var buf = [_]u8{0} ** 8;
            std.mem.writeIntLittle(u64, &buf, @as(u64, fork_count));
            return buf;
        } else {
            return null;
        }
    }
};

test "core.hard_forks: test hardforks" {
    const testing_alloc = std.testing.allocator;

    var hard_forks = HardForks.default(testing_alloc);
    defer hard_forks.deinit();

    var slot_one = Slot.init(10);
    var slot_two = Slot.init(20);
    try hard_forks.register(slot_one);
    try hard_forks.register(slot_two);

    try std.testing.expect(hard_forks.get_forks()[0][0].value == 10);
    try std.testing.expect(hard_forks.get_forks()[1][1] == 1);
    try std.testing.expect(hard_forks.get_forks()[1][0].value == 20);
    try std.testing.expect(hard_forks.get_forks()[1][1] == 1);

    var slot_three = Slot.init(10);
    var slot_four = Slot.init(0);
    var hash_data_one = hard_forks.get_hash_data(slot_three, slot_four);
    try std.testing.expect(hash_data_one != null);
    try std.testing.expect(std.mem.eql(u8, &hash_data_one.?, &[8]u8{ 1, 0, 0, 0, 0, 0, 0, 0 }));

    std.debug.print("hard_forks_one: {any}\n", .{hash_data_one});
    var slot_five = Slot.init(9);
    var slot_six = Slot.init(0);
    var hash_data_two = hard_forks.get_hash_data(slot_five, slot_six);
    try std.testing.expect(hash_data_two == null);

    std.debug.print("hard_forks_two: {any}\n", .{hash_data_two});
}
