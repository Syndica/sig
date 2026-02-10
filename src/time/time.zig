//! Source: https://github.com/nektro/zig-time/commit/ca9c0e6b644d74c1d549cc2c1ee22113aa021bd8
//!
//! MIT License
//!
//! Copyright (c) 2021 Meghan Denny
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy of
//! this software and associated documentation files (the "Software"), to deal in
//! the Software without restriction, including without limitation the rights to
//! use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
//! the Software, and to permit persons to whom the Software is furnished to do so,
//! subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
//! FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
//! COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
//! IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
//! CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

const std = @import("std");
const builtin = @import("builtin");
const time = @This();

pub const DateTime = struct {
    ms: u16,
    seconds: u16,
    minutes: u16,
    hours: u16,
    days: u16,
    months: u16,
    years: u16,
    timezone: TimeZone,
    weekday: WeekDay,
    era: Era,

    const Self = @This();

    pub fn initUnixMs(unix: u64) Self {
        return epoch_unix.addMs(unix);
    }

    pub fn initUnix(unix: u64) Self {
        return epoch_unix.addSecs(unix);
    }

    /// Caller asserts that this is > epoch
    pub fn init(year: u16, month: u16, day: u16, hr: u16, min: u16, sec: u16) Self {
        return epoch_unix
            .addYears(year - epoch_unix.years)
            .addMonths(month)
            .addDays(day)
            .addHours(hr)
            .addMins(min)
            .addSecs(sec);
    }

    pub fn now() Self {
        return initUnixMs(@as(u64, @intCast(std.time.milliTimestamp())));
    }

    pub const epoch_unix = Self{
        .ms = 0,
        .seconds = 0,
        .minutes = 0,
        .hours = 0,
        .days = 0,
        .months = 0,
        .years = 1970,
        .timezone = .UTC,
        .weekday = .Thu,
        .era = .AD,
    };

    pub fn eql(self: Self, other: Self) bool {
        return self.ms == other.ms and
            self.seconds == other.seconds and
            self.minutes == other.minutes and
            self.hours == other.hours and
            self.days == other.days and
            self.months == other.months and
            self.years == other.years and
            self.timezone == other.timezone and
            self.weekday == other.weekday;
    }

    pub fn addMs(self: Self, count: u64) Self {
        if (count == 0) return self;
        var result = self;
        result.ms += @as(u16, @intCast(count % 1000));
        return result.addSecs(count / 1000);
    }

    pub fn addSecs(self: Self, count: u64) Self {
        if (count == 0) return self;
        var result = self;
        result.seconds += @as(u16, @intCast(count % 60));
        return result.addMins(count / 60);
    }

    pub fn addMins(self: Self, count: u64) Self {
        if (count == 0) return self;
        var result = self;
        result.minutes += @as(u16, @intCast(count % 60));
        return result.addHours(count / 60);
    }

    pub fn addHours(self: Self, count: u64) Self {
        if (count == 0) return self;
        var result = self;
        result.hours += @as(u16, @intCast(count % 24));
        return result.addDays(count / 24);
    }

    pub fn addDays(self: Self, count: u64) Self {
        if (count == 0) return self;
        var result = self;
        var input = count;

        while (true) {
            const year_len = result.daysThisYear();
            if (input >= year_len) {
                result.years += 1;
                input -= year_len;
                result.incrementWeekday(year_len);
                continue;
            }
            break;
        }
        while (true) {
            const month_len = result.daysThisMonth();
            if (input >= month_len) {
                result.months += 1;
                input -= month_len;
                result.incrementWeekday(month_len);

                if (result.months == 12) {
                    result.years += 1;
                    result.months = 0;
                }
                continue;
            }
            break;
        }
        {
            const month_len = result.daysThisMonth();
            if (result.days + input > month_len) {
                const left = month_len - result.days;
                input -= left;
                result.months += 1;
                result.days = 0;
                result.incrementWeekday(left);
            }
            result.days += @as(u16, @intCast(input));
            result.incrementWeekday(input);

            if (result.months == 12) {
                result.years += 1;
                result.months = 0;
            }
        }

        return result;
    }

    pub fn addMonths(self: Self, count: u64) Self {
        if (count == 0) return self;
        var result = self;
        var input = count;
        while (input > 0) {
            const new = result.addDays(result.daysThisMonth());
            result = new;
            input -= 1;
        }
        return result;
    }

    pub fn addYears(self: Self, count: u64) Self {
        if (count == 0) return self;
        return self.addMonths(count * 12);
    }

    pub fn isLeapYear(self: Self) bool {
        return time.isLeapYear(self.years);
    }

    pub fn daysThisYear(self: Self) u16 {
        return time.daysInYear(self.years);
    }

    pub fn daysThisMonth(self: Self) u16 {
        return self.daysInMonth(self.months);
    }

    fn daysInMonth(self: Self, month: u16) u16 {
        return time.daysInMonth(self.years, month);
    }

    fn incrementWeekday(self: *Self, count: u64) void {
        var i = count % 7;
        while (i > 0) : (i -= 1) {
            self.weekday = self.weekday.next();
        }
    }

    pub fn dayOfThisYear(self: Self) u16 {
        var ret: u16 = 0;
        for (0..self.months) |item| {
            ret += self.daysInMonth(@as(u16, @intCast(item)));
        }
        ret += self.days;
        return ret;
    }

    pub fn toUnix(self: Self) u64 {
        const x = self.toUnixMilli();
        return x / 1000;
    }

    pub fn toUnixMilli(self: Self) u64 {
        var res: u64 = 0;
        res += self.ms;
        res += @as(u64, self.seconds) * std.time.ms_per_s;
        res += @as(u64, self.minutes) * std.time.ms_per_min;
        res += @as(u64, self.hours) * std.time.ms_per_hour;
        res += self.daysSinceEpoch() * std.time.ms_per_day;
        return res;
    }

    fn daysSinceEpoch(self: Self) u64 {
        var res: u64 = 0;
        res += self.days;
        for (0..self.years - epoch_unix.years) |i| res += time.daysInYear(@as(u16, @intCast(i)));
        for (0..self.months) |i| res += self.daysInMonth(@as(u16, @intCast(i)));
        return res;
    }

    /// fmt is based on https://momentjs.com/docs/#/displaying/format/
    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;

        if (fmt.len == 0) @compileError("DateTime: format string can't be empty");

        @setEvalBranchQuota(100000);

        comptime var s = 0;
        comptime var e = 0;
        comptime var next: ?FormatSeq = null;
        inline for (fmt, 0..) |c, i| {
            e = i + 1;

            if (comptime std.meta.stringToEnum(FormatSeq, fmt[s..e])) |tag| {
                next = tag;
                if (i < fmt.len - 1) continue;
            }

            if (next) |tag| {
                switch (tag) {
                    .MM => try writer.print("{:0>2}", .{self.months + 1}),
                    .M => try writer.print("{}", .{self.months + 1}),
                    .Mo => try printOrdinal(writer, self.months + 1),
                    .MMM => try printLongName(writer, self.months, &.{
                        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
                    }),
                    .MMMM => try printLongName(writer, self.months, &.{
                        "January", "February", "March",     "April",   "May",      "June",
                        "July",    "August",   "September", "October", "November", "December",
                    }),

                    .Q => try writer.print("{}", .{self.months / 3 + 1}),
                    .Qo => try printOrdinal(writer, self.months / 3 + 1),

                    .D => try writer.print("{}", .{self.days + 1}),
                    .Do => try printOrdinal(writer, self.days + 1),
                    .DD => try writer.print("{:0>2}", .{self.days + 1}),

                    .DDD => try writer.print("{}", .{self.dayOfThisYear() + 1}),
                    .DDDo => try printOrdinal(writer, self.dayOfThisYear() + 1),
                    .DDDD => try writer.print("{:0>3}", .{self.dayOfThisYear() + 1}),

                    .d => try writer.print("{}", .{@intFromEnum(self.weekday)}),
                    .do => try printOrdinal(writer, @intFromEnum(self.weekday)),
                    .dd => try writer.writeAll(@tagName(self.weekday)[0..2]),
                    .ddd => try writer.writeAll(@tagName(self.weekday)),
                    .dddd => try printLongName(writer, @intFromEnum(self.weekday), &.{
                        "Sunday",   "Monday",
                        "Tuesday",  "Wednesday",
                        "Thursday", "Friday",
                        "Saturday",
                    }),
                    .e => try writer.print("{}", .{@intFromEnum(self.weekday)}),
                    .E => try writer.print("{}", .{@intFromEnum(self.weekday) + 1}),

                    .w => try writer.print("{}", .{self.dayOfThisYear() / 7 + 1}),
                    .wo => try printOrdinal(writer, self.dayOfThisYear() / 7 + 1),
                    .ww => try writer.print("{:0>2}", .{self.dayOfThisYear() / 7 + 1}),

                    .Y => try writer.print("{}", .{self.years + 10000}),
                    .YY => try writer.print("{:0>2}", .{self.years % 100}),
                    .YYY => try writer.print("{}", .{self.years}),
                    .YYYY => try writer.print("{:0>4}", .{self.years}),

                    .N => try writer.writeAll(@tagName(self.era)),
                    .NN => try writer.writeAll("Anno Domini"),

                    .A => try printLongName(writer, self.hours / 12, &[_][]const u8{ "AM", "PM" }),
                    .a => try printLongName(writer, self.hours / 12, &[_][]const u8{ "am", "pm" }),

                    .H => try writer.print("{}", .{self.hours}),
                    .HH => try writer.print("{:0>2}", .{self.hours}),
                    .h => try writer.print("{}", .{wrap(self.hours, 12)}),
                    .hh => try writer.print("{:0>2}", .{wrap(self.hours, 12)}),
                    .k => try writer.print("{}", .{wrap(self.hours, 24)}),
                    .kk => try writer.print("{:0>2}", .{wrap(self.hours, 24)}),

                    .m => try writer.print("{}", .{self.minutes}),
                    .mm => try writer.print("{:0>2}", .{self.minutes}),

                    .s => try writer.print("{}", .{self.seconds}),
                    .ss => try writer.print("{:0>2}", .{self.seconds}),

                    .S => try writer.print("{}", .{self.ms / 100}),
                    .SS => try writer.print("{:0>2}", .{self.ms / 10}),
                    .SSS => try writer.print("{:0>3}", .{self.ms}),

                    .z => try writer.writeAll(@tagName(self.timezone)),
                    .Z => try writer.writeAll("+00:00"),
                    .ZZ => try writer.writeAll("+0000"),

                    .x => try writer.print("{}", .{self.toUnixMilli()}),
                    .X => try writer.print("{}", .{self.toUnix()}),
                }
                next = null;
                s = i;
            }

            switch (c) {
                ',',
                ' ',
                ':',
                '-',
                '.',
                'T',
                'W',
                => {
                    try writer.writeAll(&.{c});
                    s = i + 1;
                    continue;
                },
                else => {},
            }
        }
    }

    pub fn formatAlloc(
        self: Self,
        alloc: std.mem.Allocator,
        comptime fmt: []const u8,
    ) ![]const u8 {
        var list = std.array_list.Managed(u8).init(alloc);
        defer list.deinit();

        try self.format(fmt, .{}, list.writer());
        return list.toOwnedSlice();
    }

    const FormatSeq = enum {
        M, // 1 2 ... 11 12
        Mo, // 1st 2nd ... 11th 12th
        MM, // 01 02 ... 11 12
        MMM, // Jan Feb ... Nov Dec
        MMMM, // January February ... November December
        Q, // 1 2 3 4
        Qo, // 1st 2nd 3rd 4th
        D, // 1 2 ... 30 31
        Do, // 1st 2nd ... 30th 31st
        DD, // 01 02 ... 30 31
        DDD, // 1 2 ... 364 365
        DDDo, // 1st 2nd ... 364th 365th
        DDDD, // 001 002 ... 364 365
        d, // 0 1 ... 5 6
        do, // 0th 1st ... 5th 6th
        dd, // Su Mo ... Fr Sa
        ddd, // Sun Mon ... Fri Sat
        dddd, // Sunday Monday ... Friday Saturday
        e, // 0 1 ... 5 6 (locale)
        E, // 1 2 ... 6 7 (ISO)
        w, // 1 2 ... 52 53
        wo, // 1st 2nd ... 52nd 53rd
        ww, // 01 02 ... 52 53
        Y, // 11970 11971 ... 19999 20000 20001 (Holocene calendar)
        YY, // 70 71 ... 29 30
        YYY, // 1 2 ... 1970 1971 ... 2029 2030
        YYYY, // 0001 0002 ... 1970 1971 ... 2029 2030
        N, // BC AD
        NN, // Before Christ ... Anno Domini
        A, // AM PM
        a, // am pm
        H, // 0 1 ... 22 23
        HH, // 00 01 ... 22 23
        h, // 1 2 ... 11 12
        hh, // 01 02 ... 11 12
        k, // 1 2 ... 23 24
        kk, // 01 02 ... 23 24
        m, // 0 1 ... 58 59
        mm, // 00 01 ... 58 59
        s, // 0 1 ... 58 59
        ss, // 00 01 ... 58 59
        S, // 0 1 ... 8 9 (second fraction)
        SS, // 00 01 ... 98 99
        SSS, // 000 001 ... 998 999
        z, // EST CST ... MST PST
        Z, // -07:00 -06:00 ... +06:00 +07:00
        ZZ, // -0700 -0600 ... +0600 +0700
        x, // unix milli
        X, // unix
    };

    pub fn since(self: Self, other_in_the_past: Self) Duration {
        return Duration.fromMillis(self.toUnixMilli() - other_in_the_past.toUnixMilli());
    }
};

pub const format = struct {
    pub const LT = "";
    pub const LTS = "";
    pub const L = "";
    pub const l = "";
    pub const LL = "";
    pub const ll = "";
    pub const LLL = "";
    pub const lll = "";
    pub const LLLL = "";
    pub const llll = "";
};

pub const TimeZone = enum {
    UTC,
};

pub const WeekDay = enum {
    Sun,
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,

    pub fn next(self: WeekDay) WeekDay {
        return switch (self) {
            .Sun => .Mon,
            .Mon => .Tue,
            .Tue => .Wed,
            .Wed => .Thu,
            .Thu => .Fri,
            .Fri => .Sat,
            .Sat => .Sun,
        };
    }
};

pub const Era = enum {
    // BC,
    AD,
};

pub fn isLeapYear(year: u16) bool {
    var ret = false;
    if (year % 4 == 0) ret = true;
    if (year % 100 == 0) ret = false;
    if (year % 400 == 0) ret = true;
    return ret;
}

pub fn daysInYear(year: u16) u16 {
    return if (isLeapYear(year)) 366 else 365;
}

fn daysInMonth(year: u16, month: u16) u16 {
    const norm = [12]u16{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const leap = [12]u16{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const month_days = if (!isLeapYear(year)) norm else leap;
    return month_days[month];
}

fn printOrdinal(writer: anytype, num: u16) !void {
    try writer.print("{}", .{num});
    try writer.writeAll(switch (num) {
        1 => "st",
        2 => "nd",
        3 => "rd",
        else => "th",
    });
}

fn printLongName(writer: anytype, index: u16, names: []const []const u8) !void {
    try writer.writeAll(names[index]);
}

fn wrap(val: u16, at: u16) u16 {
    const tmp = val % at;
    return if (tmp == 0) at else tmp;
}

pub const Duration = struct {
    ns: u64,

    pub fn zero() Duration {
        return .{ .ns = 0 };
    }

    pub fn fromMinutes(m: u64) Duration {
        return .{ .ns = m * std.time.ns_per_min };
    }

    pub fn fromSecs(s: u64) Duration {
        return .{ .ns = s * std.time.ns_per_s };
    }

    pub fn fromMillis(ms: u64) Duration {
        return .{ .ns = ms * std.time.ns_per_ms };
    }

    pub fn fromMicros(us: u64) Duration {
        return .{ .ns = us * std.time.ns_per_us };
    }

    pub fn fromNanos(ns: u64) Duration {
        return .{ .ns = ns };
    }

    pub fn asSecs(self: Duration) u64 {
        return self.ns / std.time.ns_per_s;
    }

    pub fn asSecsFloat(self: Duration) f64 {
        return @as(f64, @floatFromInt(self.ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
    }

    pub fn asMillis(self: Duration) u64 {
        return self.ns / std.time.ns_per_ms;
    }

    pub fn asMicros(self: Duration) u64 {
        return self.ns / std.time.ns_per_us;
    }

    pub fn asNanos(self: Duration) u64 {
        return self.ns;
    }

    pub fn gt(self: Duration, other: Duration) bool {
        return self.ns > other.ns;
    }

    pub fn gte(self: Duration, other: Duration) bool {
        return self.ns >= other.ns;
    }

    pub fn lt(self: Duration, other: Duration) bool {
        return self.ns < other.ns;
    }

    pub fn lte(self: Duration, other: Duration) bool {
        return self.ns <= other.ns;
    }

    pub fn eql(self: Duration, other: Duration) bool {
        return self.ns == other.ns;
    }

    pub fn min(self: Duration, other: Duration) Duration {
        return .{ .ns = @min(self.ns, other.ns) };
    }

    pub fn max(self: Duration, other: Duration) Duration {
        return .{ .ns = @min(self.ns, other.ns) };
    }

    pub fn saturatingSub(self: Duration, other: Duration) Duration {
        return .{ .ns = self.ns -| other.ns };
    }

    pub fn div(self: Duration, divisor: u64) Duration {
        return .{ .ns = self.ns / divisor };
    }

    pub fn mul(self: Duration, factor: u64) Duration {
        return .{ .ns = self.ns * factor };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return try writer.print("{s}", .{std.fmt.fmtDuration(self.ns)});
    }
};

pub const Instant = struct {
    uptime_ns: u64,

    pub const EPOCH_ZERO = Instant{ .uptime_ns = 0 };

    pub fn now() Instant {
        var ts: std.posix.timespec = undefined;
        if (builtin.os.tag.isDarwin()) {
            ts = std.posix.clock_gettime(.UPTIME_RAW) catch @panic("clock_gettime unsupported");
        } else if (builtin.os.tag == .linux) {
            ts = std.posix.clock_gettime(.BOOTTIME) catch @panic("clock_gettime unsupported");
        } else {
            @compileError("unsupported arch");
        }

        const ns = (@as(i64, ts.sec) *| std.time.ns_per_s) + @as(i64, ts.nsec);
        return .{ .uptime_ns = std.math.lossyCast(u64, ns) };
    }

    pub fn elapsed(self: Instant) Duration {
        return Instant.now().elapsedSince(self);
    }

    pub fn elapsedSince(self: Instant, earlier: Instant) Duration {
        return Duration.fromNanos(self.uptime_ns -| earlier.uptime_ns);
    }

    pub fn plus(self: Instant, duration: Duration) Instant {
        return .{ .uptime_ns = self.uptime_ns +| duration.asNanos() };
    }

    pub fn sub(self: Instant, duration: Duration) Instant {
        return .{ .uptime_ns = self.uptime_ns -| duration.asNanos() };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return try writer.print("{s}", .{std.fmt.fmtDuration(self.uptime_ns)});
    }
};

pub const Timer = struct {
    inner: std.time.Timer,

    pub const Error = std.time.Timer.Error;

    pub fn start() Timer {
        return .{ .inner = std.time.Timer.start() catch unreachable };
    }

    pub fn read(self: *Timer) Duration {
        return Duration.fromNanos(self.inner.read());
    }

    pub fn reset(self: *Timer) void {
        self.inner.reset();
    }

    pub fn lap(self: *Timer) Duration {
        return Duration.fromNanos(self.inner.lap());
    }

    pub fn sample(self: *Timer) std.time.Instant {
        return self.inner.sample();
    }
};
