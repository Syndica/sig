const std = @import("std");
const builtin = @import("builtin");

pub const Backoff = struct {
    step: u32 = 0,

    const SPIN_LIMIT = 6;

    pub fn snooze(_: *Backoff) void {
        switch (builtin.cpu.arch) {
            .aarch64 => asm volatile ("wfe" ::: "memory"),
            else => std.Thread.yield() catch unreachable,
        }
    }

    pub fn spin(b: *Backoff) void {
        for (0..(@as(u32, 1) << @intCast(b.step))) |_| {
            std.atomic.spinLoopHint();
        }

        if (b.step <= SPIN_LIMIT) {
            b.step += 1;
        }
    }
};
