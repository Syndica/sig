const std = @import("std");
const builtin = @import("builtin");
pub const estimate = @import("estimate.zig");

pub var clock: Clock = .{};

pub const Clock = struct {
    /// Returns current time in milliseconds
    pub fn now(cl: *const Clock) u64 {
        _ = cl;
        return @intCast(std.time.milliTimestamp());
    }

    /// Returns an `Instant` sampled at the callsite
    pub fn sample(cl: *const Clock) std.time.Instant {
        _ = cl;
        return std.time.Instant.now() catch unreachable;
    }

    pub fn tick(cl: *Clock, ns: u64) void {
        _ = cl;
        _ = ns;
    }
};

// Based on Howard Hinnant's civil calendar date alogrithms.
// https://howardhinnant.github.io/date_algorithms.html
pub const DateTime = packed struct(u64) {
    year: u28,
    month: u4, // 1-12
    day: u5, // 1-31
    hour: u5, // 0-23
    minute: u6, // 0-59
    second: u6, // 0-59
    millisecond: u10, // 0-999

    pub fn fromEpoch(epoch: u64) DateTime {
        return .fromEpochMs(epoch * std.time.ms_per_s);
    }

    pub fn fromEpochMs(epoch_ms: u64) DateTime {
        const day_since_epoch = (epoch_ms / std.time.ms_per_day) + 719468;
        const era = day_since_epoch / 146097;
        const doe = day_since_epoch - era * 146097;
        const yoe = (doe - (doe / 1460) + (doe / 36524) - (doe / 146096)) / 365;
        const doy = doe - (365 * yoe + (yoe / 4) - (yoe / 100));
        const month_prefix = (5 * doy + 2) / 153;
        const ms_today = epoch_ms % std.time.ms_per_day;

        const millisecond = ms_today % std.time.ms_per_s;
        const second = (ms_today / std.time.ms_per_s) % std.time.s_per_min;
        const minute = (ms_today / std.time.ms_per_min) % 60;
        const hour = (ms_today / std.time.ms_per_hour) % 24;
        const day = doy - ((153 * month_prefix + 2) / 5) + 1;
        const month = if (month_prefix < 10) month_prefix + 3 else month_prefix - 9;
        const year = yoe + era * 400 + @intFromBool(month <= 2);

        return .{
            .year = @intCast(year),
            .month = @intCast(month),
            .day = @intCast(day),
            .hour = @intCast(hour),
            .minute = @intCast(minute),
            .second = @intCast(second),
            .millisecond = @intCast(millisecond),
        };
    }

    pub fn toEpoch(dt: DateTime) u64 {
        const year: u64 = if (dt.month <= 2) dt.year - 1 else dt.year;
        const month: u64 = if (dt.month <= 2) dt.month + 12 else dt.month;
        const hour: u64 = dt.hour;
        const minute: u64 = dt.minute;
        const second: u64 = dt.second;
        const era = year / 400;
        const yoe = year - era * 400;
        const doy = (153 * (month - 3) + 2) / 5 + dt.day - 1;
        const doe = yoe * 365 + (yoe / 4) - (yoe / 100) + doy;
        const day_since_march_1_year_0 = era * 146097 + doe;
        const day_since_epoch = day_since_march_1_year_0 - 719468;
        const second_from_date = day_since_epoch * std.time.s_per_day;
        const second_from_time = hour * std.time.s_per_hour + minute * 60 + second;
        return second_from_date + second_from_time;
    }

    pub fn toEpochMs(dt: DateTime) u64 {
        return dt.toEpoch() * std.time.ms_per_s + dt.millisecond;
    }

    // zig fmt: off
    // https://momentjs.com/docs/#/displaying/format
    const FormatSeq = enum {
        YYY, YYYY,
        M, MM, MMM, MMMM,
        D, DD,
        A, a,
        H, HH,
        h, hh,
        m, mm,
        s, ss, S, SS, SSS,
        x, X,
    };
    // zig fmt: on

    const MONTH_NAMES_SHORT = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    const MONTH_NAMES_LONG = [_][]const u8{
        "January", "February", "March",     "April",   "May",      "June",
        "July",    "August",   "September", "October", "November", "December",
    };

    pub fn format(
        dt: DateTime,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;

        if (fmt.len == 0) @compileError("DateTime: format string can't be empty");
        const seq = comptime std.meta.stringToEnum(FormatSeq, fmt) orelse
            @compileError("DateTime: invalid format sequence '" ++ fmt ++ "'");

        switch (seq) {
            .YYY => try writer.print("{}", .{dt.year}),
            .YYYY => try writer.print("{:0>4}", .{dt.year}),
            .M => try writer.print("{}", .{dt.month}),
            .MM => try writer.print("{:0>2}", .{dt.month}),
            .MMM => try writer.writeAll(MONTH_NAMES_SHORT[dt.month - 1]),
            .MMMM => try writer.writeAll(MONTH_NAMES_LONG[dt.month - 1]),
            .D => try writer.print("{}", .{dt.day}),
            .DD => try writer.print("{:0>2}", .{dt.day}),
            .A => try writer.writeAll(if (dt.hour / 12 == 0) "AM" else "PM"),
            .a => try writer.writeAll(if (dt.hour / 12 == 0) "am" else "pm"),
            .H => try writer.print("{}", .{dt.hour}),
            .HH => try writer.print("{:0>2}", .{dt.hour}),
            .h => try writer.print("{}", .{if (dt.hour % 12 == 0) dt.hour else dt.hour % 12}),
            .hh => try writer.print("{:0>2}", .{if (dt.hour % 12 == 0) dt.hour else dt.hour % 12}),
            .m => try writer.print("{}", .{dt.minute}),
            .mm => try writer.print("{:0>2}", .{dt.minute}),
            .s => try writer.print("{}", .{dt.second}),
            .ss => try writer.print("{:0>2}", .{dt.second}),
            .S => try writer.print("{}", .{dt.millisecond / 100}),
            .SS => try writer.print("{:0>2}", .{dt.millisecond / 10}),
            .SSS => try writer.print("{:0>3}", .{dt.millisecond}),
            .x => try writer.print("{}", .{dt.toEpochMs()}),
            .X => try writer.print("{}", .{dt.toEpoch()}),
        }
    }
};

test DateTime {
    try std.testing.expectEqual(0, DateTime.fromEpochMs(0).toEpochMs());
    try std.testing.expectEqual(1577836801234, DateTime.fromEpochMs(1577836801234).toEpochMs());
    try std.testing.expectEqual(1577836801, DateTime.fromEpochMs(1577836801234).toEpoch());
    try std.testing.expectEqual(1703980800, DateTime.fromEpoch(1703980800).toEpoch());

    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try fbs.writer().print(
        \\{[0]YYY} {[0]YYYY} {[0]M} {[0]MM} {[0]MMM} {[0]MMMM}
        \\{[0]D} {[0]DD} {[0]A} {[0]a}
        \\{[0]H} {[0]HH} {[0]h} {[0]hh} {[0]m} {[0]mm}
        \\{[0]s} {[0]ss} {[0]S} {[0]SS} {[0]SSS}
        \\{[0]x} {[0]X}
    , .{DateTime.fromEpoch(1145169000)});

    try std.testing.expectEqualStrings(
        \\2006 2006 4 04 Apr April
        \\16 16 AM am
        \\6 06 6 06 30 30
        \\0 00 0 00 000
        \\1145169000000 1145169000
    , fbs.getWritten());
}

pub const Duration = enum(u64) {
    zero,
    _,

    pub fn fromMinutes(m: u64) Duration {
        return .fromNanos(m * std.time.ns_per_min);
    }

    pub fn fromSecs(s: u64) Duration {
        return .fromNanos(s * std.time.ns_per_s);
    }

    pub fn fromMillis(ms: u64) Duration {
        return .fromNanos(ms * std.time.ns_per_ms);
    }

    pub fn fromMicros(us: u64) Duration {
        return .fromNanos(us * std.time.ns_per_us);
    }

    pub fn fromNanos(ns: u64) Duration {
        return @enumFromInt(ns);
    }

    pub fn asInstant(dur: Duration) std.time.Instant {
        return switch (builtin.os.tag) {
            .windows, .uefi, .wasi => .{ .timestamp = dur.asNanos() },
            else => .{ .timestamp = .{
                .sec = @intCast(dur.asSecs()),
                .nsec = @intCast(dur.asNanos() % std.time.ns_per_s),
            } },
        };
    }

    pub fn asSecsFloat(dur: Duration) f64 {
        return @as(f64, @floatFromInt(dur.asNanos())) / @as(f64, std.time.ns_per_s);
    }

    pub fn asSecs(dur: Duration) u64 {
        return dur.asNanos() / std.time.ns_per_s;
    }

    pub fn asMillis(dur: Duration) u64 {
        return dur.asNanos() / std.time.ns_per_ms;
    }

    pub fn asMicros(dur: Duration) u64 {
        return dur.asNanos() / std.time.ns_per_us;
    }

    pub fn asNanos(dur: Duration) u64 {
        return @intFromEnum(dur);
    }

    pub fn format(
        dur: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return writer.print("{}", .{std.fmt.fmtDuration(dur.asNanos())});
    }
};

pub const Timer = struct {
    inner: std.time.Timer,

    pub const Error = std.time.Timer.Error;

    pub fn start() Error!Timer {
        return .{ .inner = try std.time.Timer.start() };
    }

    pub fn read(self: *Timer) Duration {
        return .fromNanos(self.inner.read());
    }

    pub fn reset(self: *Timer) void {
        self.inner.reset();
    }

    pub fn lap(self: *Timer) Duration {
        return .fromNanos(self.inner.lap());
    }

    pub fn sample(self: *Timer) std.time.Instant {
        return self.inner.sample();
    }
};
