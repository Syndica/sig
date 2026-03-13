const std = @import("std");
const obs = @import("../observability.zig");
const Ring = @import("../ring.zig").Ring;

pub const Level = enum(u8) {
    /// Critical failure; may or may not be recoverable.
    err,
    /// Non-critical failure; worth investigating.
    warn,
    /// Informational log concerning relevant state of the program.
    info,
    /// Debugging-level messages for diagnosing program behaviour.
    debug,
    /// Fine-grained messages that track execution flow.
    trace,

    pub fn text(level: Level) [:0]const u8 {
        return switch (level) {
            .err => "error",
            else => |tag| @tagName(tag),
        };
    }
};

pub const MessageStream = extern struct {
    name: Name,
    ring: RingBuffer,

    /// 100 MiB byte ring buffer.
    pub const RingBuffer = Ring(100 * 1024 * 1024, u8);

    pub const Name = extern struct {
        len: Len,
        buf: [MAX_LEN]u8,

        pub const Len = u8;
        pub const MAX_LEN = std.math.maxInt(u8);

        /// Assumes `str.len <= MAX_LEN`.
        pub fn init(self: *Name, str: []const u8) void {
            @memcpy(self.buf[0..str.len], str);
            self.len = @intCast(str.len);
        }

        pub fn slice(self: *const Name) []const u8 {
            return self.buf[0..self.len];
        }
    };
};

pub const MessageSink = union(enum) {
    noop,
    writer: *std.Io.Writer,
    ring: *MessageStream.RingBuffer,

    /// If `self == .ring`, and there isn't enough space
    /// to write the message, the ring will not advance.
    pub fn sendMessage(
        self: MessageSink,
        /// Milliseconds since epoch Jan 1, 1970 at 12:00 AM.
        epoch_millis: u64,
        level: Level,
        scope: []const u8,
        fields: []const EntryField,
        comptime message_fmt_str: []const u8,
        message_args: anytype,
    ) error{ WriteFailed, Full }!void {
        switch (self) {
            .noop => {},
            inline .ring, .writer => |sink, tag| {
                const is_ring = comptime switch (tag) {
                    .noop => unreachable,
                    .writer => false,
                    .ring => true,
                };
                var ring_slice = if (is_ring) try sink.getWritable() else {};
                var w_state_buf: [@sizeOf(MessageHeader) - 1]u8 = undefined;
                var w_state = if (is_ring) ring_slice.writer(&w_state_buf) else {};
                const w: *std.Io.Writer = if (is_ring) &w_state.interface else sink;
                const header = try MessageHeader.writeMessage(
                    w,
                    epoch_millis,
                    level,
                    scope,
                    fields,
                    message_fmt_str,
                    message_args,
                );
                if (is_ring) {
                    try w.flush();
                    w_state.commit(header.encodedLength());
                }
            },
        }
    }
};

pub const MessageHeader = extern struct {
    /// Milliseconds since epoch Jan 1, 1970 at 12:00 AM.
    epoch_millis: u64,
    scope_len: u32,
    fields_len: u32,
    msg_len: u32,
    level: Level,

    magic: enum(u32) { valid = 0xAA_BB_CC_DD, _ } align(1) = .valid,

    /// IMPORTANT: This should be kept in sync with `writeMessage`.
    pub fn compute(
        epoch_millis: u64,
        level: Level,
        scope: []const u8,
        fields: []const EntryField,
        comptime message_fmt_str: []const u8,
        message_args: anytype,
    ) MessageHeader {
        return .{
            .epoch_millis = epoch_millis,
            .level = level,
            .scope_len = @intCast(scope.len),
            .fields_len = @intCast(std.fmt.count("{f}", .{EntryField.listFmt(fields)})),
            .msg_len = @intCast(std.fmt.count(message_fmt_str, message_args)),
        };
    }

    /// IMPORTANT: This should be kept in sync with `logfmtStream` & `compute`.
    pub fn writeMessage(
        w: *std.Io.Writer,
        /// Milliseconds since epoch Jan 1, 1970 at 12:00 AM.
        epoch_millis: u64,
        level: Level,
        scope: []const u8,
        fields: []const EntryField,
        comptime message_fmt_str: []const u8,
        message_args: anytype,
    ) std.Io.Writer.Error!MessageHeader {
        const header: MessageHeader = .compute(
            epoch_millis,
            level,
            scope,
            fields,
            message_fmt_str,
            message_args,
        );
        try w.writeStruct(header, obs.endian);
        try w.writeAll(scope);
        try EntryField.writeFields(fields, w);
        try w.print(message_fmt_str, message_args);
        return header;
    }

    /// Stream the log message described by `self` from `src` to `dst`,
    /// including the fields stored in `self`.
    /// Also allows injecting `extra_fields` after the main fields, before the message field.
    ///
    /// IMPORTANT: This should be kept in sync with `writeMessage`.
    pub fn logfmtStream(
        self: MessageHeader,
        extra_fields: []const EntryField,
        dst: *std.Io.Writer,
        src: *std.Io.Reader,
    ) std.Io.Reader.StreamError!void {
        std.debug.assert(self.magic == .valid);

        // time
        try dst.print("time={f}", .{Iso8601Fmt.fromEpochMillis(self.epoch_millis)});

        // level
        try dst.writeByte(' ');
        try dst.print("level={s}", .{@tagName(self.level)});

        // scope
        try dst.writeByte(' ');
        try dst.writeAll("scope=");
        try src.streamExact(dst, self.scope_len);

        if (self.fields_len != 0) {
            // other fields streamed directly as a string
            try dst.writeByte(' ');
            try src.streamExact(dst, self.fields_len);
        }

        if (extra_fields.len != 0) {
            try dst.writeByte(' ');
            try EntryField.writeFields(extra_fields, dst);
        }

        // message
        try dst.writeByte(' ');
        try dst.writeAll("message=");
        try dst.writeByte('"');
        try src.streamExact(dst, self.msg_len);
        try dst.writeByte('"');
    }

    pub fn encodedLength(self: MessageHeader) u32 {
        return @sizeOf(MessageHeader) +
            self.scope_len +
            self.fields_len +
            self.msg_len;
    }
};

test MessageHeader {
    const gpa = std.testing.allocator;

    const expected_header: MessageHeader = .{
        .epoch_millis = 0,
        .level = .err,
        .scope_len = "foo".len,
        .fields_len = "fizz=buzz".len,
        .msg_len = "bar".len,
    };
    try std.testing.expectEqual(
        expected_header,
        MessageHeader.compute(
            0,
            .err,
            "foo",
            &.{.init("fizz", .fromValue(.literal, "{s}", &"buzz"))},
            "{s}",
            .{"bar"},
        ),
    );

    var encoded: std.Io.Writer.Allocating = .init(gpa);
    defer encoded.deinit();
    const written_header = try MessageHeader.writeMessage(
        &encoded.writer,
        1_999,
        .debug,
        "scope1",
        &.{
            .init("field_a", .fromValue(.quoted, "0x{X}", &0xFAF0)),
            .init("field_b", .fromValue(.literal, "{s}", &"value")),
        },
        "message {s} here",
        .{"goes"},
    );

    var encoded_r: std.Io.Reader = .fixed(encoded.written());
    const decoded_header = try encoded_r.takeStruct(MessageHeader, obs.endian);
    try std.testing.expectEqual(written_header, decoded_header);

    var decoded: std.Io.Writer.Allocating = .init(gpa);
    defer decoded.deinit();
    try decoded_header.logfmtStream(&.{}, &decoded.writer, &encoded_r);
    try std.testing.expectEqualStrings(
        "time=1970-01-01T00:00:01.999Z" ++
            " level=debug" ++
            " scope=scope1" ++
            " field_a=\"0xFAF0\"" ++
            " field_b=value" ++
            " message=\"message goes here\"",
        decoded.written(),
    );

    encoded_r.seek = 0;
    try std.testing.expectEqual(
        decoded_header,
        encoded_r.takeStruct(MessageHeader, obs.endian),
    );

    decoded.clearRetainingCapacity();
    try decoded_header.logfmtStream(
        &.{
            .init("field_c", .fromFmt(.literal, "{}{d}", &.{ .foo, 178 })),
        },
        &decoded.writer,
        &encoded_r,
    );
    try std.testing.expectEqualStrings(
        "time=1970-01-01T00:00:01.999Z" ++
            " level=debug" ++
            " scope=scope1" ++
            " field_a=\"0xFAF0\"" ++
            " field_b=value" ++
            " field_c=.foo178" ++
            " message=\"message goes here\"",
        decoded.written(),
    );
}

pub const EntryField = struct {
    name: []const u8,
    value: EntryValueFmt,

    pub fn init(name: []const u8, value: EntryValueFmt) EntryField {
        return .{ .name = name, .value = value };
    }

    pub fn format(
        self: EntryField,
        w: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try w.print("{s}={f}", .{ self.name, self.value });
    }

    pub fn writeFields(list: []const EntryField, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (list.len == 0) return;
        try list[0].format(w);
        for (list[1..]) |entry| {
            try w.writeByte(' ');
            try entry.format(w);
        }
    }

    pub fn listFmt(list: []const EntryField) std.fmt.Alt([]const EntryField, writeFields) {
        return .{ .data = list };
    }
};

test EntryField {
    try std.testing.expectFmt("foo=bar", "{f}", .{
        EntryField.init("foo", .fromValue(.literal, "{s}", &"bar")),
    });
    try std.testing.expectFmt("", "{f}", .{EntryField.listFmt(&.{})});
    try std.testing.expectFmt("foo=\"bar\"", "{f}", .{
        EntryField.listFmt(&.{.init("foo", .fromValue(.quoted, "{s}", &"bar"))}),
    });
}

/// Type-erased formatter.
pub const EntryValueFmt = struct {
    surround: Surround,
    ptr: *const anyopaque,
    formatFn: *const fn (
        surround: Surround,
        value: *const anyopaque,
        w: *std.Io.Writer,
    ) std.Io.Writer.Error!void,

    pub fn format(self: EntryValueFmt, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try self.formatFn(self.surround, self.ptr, w);
    }

    pub const Surround = enum {
        literal,
        quoted,

        fn str(surround: Surround) []const u8 {
            return switch (surround) {
                .literal => "",
                .quoted => "\"",
            };
        }
    };

    /// Resulting formatter will write the equivalent of:
    /// `std.Io.Writer.print(w, fmt_str, .{value_ptr.*})`.
    pub fn fromValue(
        surround_value: Surround,
        comptime fmt_str: []const u8,
        /// Pointer to an integer.
        value_ptr: anytype,
    ) EntryValueFmt {
        const is_comptime_known = isComptimeKnown(value_ptr.*);
        const erased = struct {
            fn formatImpl(
                surround: Surround,
                ptr: *const anyopaque,
                w: *std.Io.Writer,
            ) std.Io.Writer.Error!void {
                const value: @TypeOf(value_ptr) = if (is_comptime_known)
                    value_ptr
                else
                    @ptrCast(@alignCast(ptr));
                try w.writeAll(surround.str());
                try w.print(fmt_str, .{value.*});
                try w.writeAll(surround.str());
            }
        };
        return .{
            .surround = surround_value,
            .ptr = @ptrCast(value_ptr),
            .formatFn = erased.formatImpl,
        };
    }

    /// Resulting formatter will write the equivalent of:
    /// `std.Io.Writer.print(w, fmt_strs, args_ptr.*)`.
    pub fn fromFmt(
        surround_value: Surround,
        comptime fmt_str: []const u8,
        /// Pointer to a tuple of arguments, instead of the value.
        /// Must outlive the return value.
        args_ptr: anytype,
    ) EntryValueFmt {
        const erased = struct {
            fn formatImpl(
                surround: Surround,
                ptr: *const anyopaque,
                w: *std.Io.Writer,
            ) std.Io.Writer.Error!void {
                const args: @TypeOf(args_ptr) = @ptrCast(@alignCast(ptr));
                try w.writeAll(surround.str());
                try w.print(fmt_str, args.*);
                try w.writeAll(surround.str());
            }
        };
        return .{
            .surround = surround_value,
            .ptr = @ptrCast(args_ptr),
            .formatFn = erased.formatImpl,
        };
    }
};

test EntryValueFmt {
    try std.testing.expectFmt("123", "{f}", .{
        EntryValueFmt.fromValue(.literal, "{d}", &123),
    });
    try std.testing.expectFmt("321 foo", "{f}", .{
        EntryValueFmt.fromFmt(.literal, "{d} {s}", &.{ 321, "foo" }),
    });
}

/// Formats epoch milliseconds as `YYYY-MM-DDTHH:mm:ss.SSSZ`
const Iso8601Fmt = struct {
    /// Milliseconds since epoch Jan 1, 1970 at 12:00 AM
    epoch_milliseconds: u64,

    pub fn fromEpochMillis(e_ms: u64) Iso8601Fmt {
        return .{ .epoch_milliseconds = e_ms };
    }

    pub fn format(
        self: Iso8601Fmt,
        w: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        const epoch_secs: std.time.epoch.EpochSeconds = .{
            .secs = self.epoch_milliseconds / std.time.ms_per_s,
        };
        const epoch_day = epoch_secs.getEpochDay();
        const day_secs = epoch_secs.getDaySeconds();

        const year_and_day = epoch_day.calculateYearDay();
        const month_and_day = year_and_day.calculateMonthDay();

        try w.print("{[YYYY]d:0>4}-{[MM]d:0>2}-{[DD]d:0>2}", .{
            .YYYY = year_and_day.year,
            .MM = month_and_day.month.numeric(),
            .DD = month_and_day.day_index + 1,
        });
        try w.writeByte('T');
        try w.print("{[HH]d:0>2}:{[mm]d:0>2}:{[ss]d:0>2}.{[SSS]d:0>3}", .{
            .HH = day_secs.getHoursIntoDay(),
            .mm = day_secs.getMinutesIntoHour(),
            .ss = day_secs.getSecondsIntoMinute(),
            .SSS = self.epoch_milliseconds % std.time.ms_per_s,
        });
        try w.writeByte('Z');
    }
};

test Iso8601Fmt {
    try std.testing.expectFmt("1970-01-01T00:00:00.000Z", "{f}", .{
        Iso8601Fmt.fromEpochMillis(0),
    });
    try std.testing.expectFmt("1970-01-01T00:00:00.001Z", "{f}", .{
        Iso8601Fmt.fromEpochMillis(1),
    });
    try std.testing.expectFmt("1970-01-01T00:00:00.999Z", "{f}", .{
        Iso8601Fmt.fromEpochMillis(999),
    });
    try std.testing.expectFmt("1970-01-01T00:00:01.000Z", "{f}", .{
        Iso8601Fmt.fromEpochMillis(1 * std.time.ms_per_s),
    });
    try std.testing.expectFmt("1971-01-01T00:00:00.000Z", "{f}", .{
        Iso8601Fmt.fromEpochMillis(365 * std.time.ms_per_day),
    });
    try std.testing.expectFmt("2000-01-01T00:00:00.000Z", "{f}", .{
        Iso8601Fmt.fromEpochMillis(std.time.ms_per_day * days_in_thirty_years: {
            var days: u64 = 0;
            for (1970..2000, 0..30) |year, _| {
                days += std.time.epoch.getDaysInYear(@intCast(year));
            }
            break :days_in_thirty_years days;
        }),
    });
}

inline fn isComptimeKnown(value: anytype) bool {
    return @typeInfo(@TypeOf(.{value})).@"struct".fields[0].is_comptime;
}
