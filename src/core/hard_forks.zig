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
    pub fn get_forks(self: *Self) []HardFork {
        return self.hard_forks.items;
    }
};

test "core.hard_forks: test hardforks" {
    const testing_alloc = std.testing.allocator;

    var hard_forks = HardForks.default(testing_alloc);
    defer hard_forks.deinit();
    var slot = Slot.init(1);
    try hard_forks.register(slot);
    //std.debug.print("hard forks test {any}", .{hard_forks.get_forks()});

    try std.testing.expect(hard_forks.get_forks()[0][0].value == 1);
    try std.testing.expect(hard_forks.get_forks()[0][1] == 1);

    var slot_two = Slot.init(2);
    try hard_forks.register(slot_two);

    try std.testing.expect(hard_forks.get_forks()[1][0].value == 2);
    try std.testing.expect(hard_forks.get_forks()[1][1] == 1);
    //std.debug.print("hard forks test {any}", .{hard_forks.get_forks()});
}
