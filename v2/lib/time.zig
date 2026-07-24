const std = @import("std");

pub const Instant = struct {
    timestamp: std.posix.timespec,

    pub const EPOCH_ZERO: Instant = .{
        .timestamp = .{
            .sec = 0,
            .nsec = 0,
        },
    };

    /// Queries the system for the current moment of time as an Instant.
    /// This is not guaranteed to be monotonic or steadily increasing, but for
    /// most implementations it is.
    /// Returns `error.Unsupported` when a suitable clock is not detected.
    pub fn now() Instant {
        const clock_id: std.posix.CLOCK = .BOOTTIME;
        const ts = std.posix.clock_gettime(clock_id) catch |err| {
            std.debug.panic("clock_gettime unsupported: {}", .{err});
        };
        return .{ .timestamp = ts };
    }

    /// Quickly compares two instances between each other.
    pub fn order(self: Instant, other: Instant) std.math.Order {
        var ord = std.math.order(self.timestamp.sec, other.timestamp.sec);
        if (ord == .eq) {
            ord = std.math.order(self.timestamp.nsec, other.timestamp.nsec);
        }
        return ord;
    }

    /// Returns elapsed time in nanoseconds since the `earlier` Instant.
    /// This assumes that the `earlier` Instant represents a moment in time before or equal to `self`.
    /// This also assumes that the time that has passed between both Instants fits inside a u64 (~585 yrs).
    pub fn since(self: Instant, earlier: Instant) u64 {
        // Convert timespec diff to ns
        const seconds = @as(u64, @intCast(self.timestamp.sec - earlier.timestamp.sec));
        const elapsed = (seconds * std.time.ns_per_s) + @as(u32, @intCast(self.timestamp.nsec));
        return elapsed - @as(u32, @intCast(earlier.timestamp.nsec));
    }
};

pub const Timer = struct {
    started: Instant,
    previous: Instant,

    /// Initialize the timer by querying for a supported clock.
    /// Returns `error.TimerUnsupported` when such a clock is unavailable.
    /// This should only fail in hostile environments such as linux seccomp misuse.
    pub fn start() Timer {
        const current: Instant = .now();
        return .{
            .started = current,
            .previous = current,
        };
    }

    /// Reads the timer value since start or the last reset in nanoseconds.
    pub fn read(self: *Timer) u64 {
        const current = self.sample();
        return current.since(self.started);
    }

    /// Resets the timer value to 0/now.
    pub fn reset(self: *Timer) void {
        const current = self.sample();
        self.started = current;
    }

    /// Returns the current value of the timer in nanoseconds, then resets it.
    pub fn lap(self: *Timer) u64 {
        const current = self.sample();
        defer self.started = current;
        return current.since(self.started);
    }

    /// Returns an Instant sampled at the callsite that is
    /// guaranteed to be monotonic with respect to the timer's starting point.
    pub fn sample(self: *Timer) Instant {
        const current = Instant.now();
        if (current.order(self.previous) == .gt) {
            self.previous = current;
        }
        return self.previous;
    }
};
