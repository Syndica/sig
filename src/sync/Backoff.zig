const std = @import("std");
const builtin = @import("builtin");
const Backoff = @This();

const SPIN_LIMIT = 6;
const YIELD_LIMIT = 10;

step: u32,

pub fn init() Backoff {
    return .{ .step = 0 };
}

pub fn snooze(_: *Backoff) void {
    switch (builtin.cpu.arch) {
        .aarch64 => asm volatile ("wfe" ::: "memory"),
        else => std.atomic.spinLoopHint(),
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
