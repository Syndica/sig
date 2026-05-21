const std = @import("std");

const linux = std.os.linux;

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

fn clockGetTime(clock_id: linux.clockid_t, comptime unit: Unit) u64 {
    var ts: linux.timespec = undefined;
    const ret = linux.clock_gettime(clock_id, &ts);

    switch (linux.E.init(ret)) {
        .SUCCESS => {},
        else => |err| std.debug.panic("clock_gettime failed: {}", .{err}),
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
