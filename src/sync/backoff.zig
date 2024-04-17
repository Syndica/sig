const std = @import("std");

const SPIN_LIMIT: u6 = 14;
const YIELD_LIMIT: u32 = 28;

pub const Backoff = struct {
    step: u6,

    const Self = @This();

    pub fn init() Self {
        return .{
            .step = 0,
        };
    }

    pub fn reset(self: *Self) void {
        self.step = 0;
    }

    pub inline fn spin(self: *Self) void {
        for (0..@as(u64, 1) << @min(self.step, SPIN_LIMIT)) |_| {
            std.atomic.spinLoopHint();
        }

        if (self.step <= SPIN_LIMIT) {
            self.step = self.step +| 1;
        }
    }

    pub inline fn snooze(self: *Self) void {
        if (self.step <= SPIN_LIMIT) {
            for (0..@as(u64, 1) << self.step) |_| {
                std.atomic.spinLoopHint();
            }
        } else {
            std.Thread.yield() catch {};
        }

        if (self.step <= YIELD_LIMIT) {
            self.step +|= 1;
        }
    }

    pub inline fn isCompleted(self: *const Self) bool {
        return self.step > YIELD_LIMIT;
    }
};

test "sync.backoff: backoff mechanism works" {
    var backoff = Backoff.init();
    try std.testing.expect(!backoff.isCompleted());
    try std.testing.expect(backoff.step == 0);
    backoff.spin();
    try std.testing.expect(!backoff.isCompleted());
    try std.testing.expect(backoff.step == 1);
    backoff.reset();
    backoff.snooze();
}
