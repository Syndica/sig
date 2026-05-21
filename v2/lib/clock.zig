const std = @import("std");
const builtin = @import("builtin");

const linux = std.os.linux;

comptime {
    if (!builtin.link_libc) {
        @compileError("lib.clock requires libc clock_gettime");
    }
}

pub const Unit = enum {
    /// Nanoseconds.
    ns,
    /// Microseconds.
    us,
    /// Milliseconds.
    ms,
    /// Seconds.
    s,
};

/// Returns elapsed-time clock ticks from Linux `CLOCK_MONOTONIC`.
///
/// The epoch is unspecified. Use this only for measuring durations within this process.
/// Values are scaled down to `unit` with truncating integer division.
pub fn monotonic(comptime unit: Unit) u64 {
    return clockGetTime(.MONOTONIC, unit);
}

/// Returns realtime clock ticks from Linux `CLOCK_REALTIME`.
///
/// This is Unix-epoch based. It can move forwards or backwards if the system
/// clock is adjusted by NTP or an operator.
///
/// Values are scaled down to `unit` with truncating integer division.
pub fn wallclock(comptime unit: Unit) u64 {
    return clockGetTime(.REALTIME, unit);
}

/// Initializes libc's clock path before services install seccomp.
pub fn warmup() void {
    std.mem.doNotOptimizeAway(wallclock(.ns));
    std.mem.doNotOptimizeAway(monotonic(.ns));
}

fn clockGetTime(clock_id: linux.clockid_t, comptime unit: Unit) u64 {
    var ts: linux.timespec = undefined;
    const ret = std.c.clock_gettime(clock_id, &ts);

    if (ret != 0) {
        std.debug.panic("clock_gettime failed: {}", .{std.posix.errno(ret)});
    }

    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return switch (unit) {
        .ns => sec * std.time.ns_per_s + nsec,
        .us => sec * std.time.us_per_s + nsec / std.time.ns_per_us,
        .ms => sec * std.time.ms_per_s + nsec / std.time.ns_per_ms,
        .s => sec,
    };
}
