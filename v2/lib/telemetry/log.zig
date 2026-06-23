const std = @import("std");
const tel = @import("../telemetry.zig");

pub const Level = enum(u8) {
    /// Fatal failure, definitely not recoverable.
    fatal,
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

    pub fn fromText(str: []const u8) ?Level {
        const Text = enum(u8) {
            fatal = @intFromEnum(Level.fatal),
            @"error" = @intFromEnum(Level.err),
            warn = @intFromEnum(Level.warn),
            info = @intFromEnum(Level.info),
            debug = @intFromEnum(Level.debug),
            trace = @intFromEnum(Level.trace),
        };
        const str_text = std.meta.stringToEnum(Text, str) orelse return null;
        return @enumFromInt(@intFromEnum(str_text));
    }

    pub fn order(self: Level, other: Level) std.math.Order {
        return std.math.order(@intFromEnum(self), @intFromEnum(other));
    }
};

pub const MessageStream = extern struct {
    name: Name,
    swap_buffer: SwapBuffer,

    pub const Name = extern struct {
        len: Len,
        buf: [MAX_LEN]u8,

        pub const Len = u8;
        pub const MAX_LEN = std.math.maxInt(u8);

        /// Asserts `str.len <= MAX_LEN`.
        pub fn init(self: *Name, str: []const u8) void {
            std.debug.assert(str.len <= MAX_LEN);
            @memcpy(self.buf[0..str.len], str);
            self.len = @intCast(str.len);
        }

        pub fn slice(self: *const Name) []const u8 {
            return self.buf[0..self.len];
        }
    };

    pub const SwapBuffer = extern struct {
        sync: std.atomic.Value(Sync),
        /// 50MiB per buffer (hot & cold)
        buffers: [2][capacity / 2]u8,

        /// 100MiB total capacity (not equivalent to full usable capacity).
        const capacity = 100 * 1024 * 1024;

        pub const Len = u62;

        const Sync = packed struct(u64) {
            len: Len = 0,
            writing: u1 = 0,
            side: u1 = 0,
        };

        pub fn init(self: *SwapBuffer) void {
            self.sync = .init(.{});
            const buffers: []u8 = @ptrCast(&self.buffers);
            @memset(buffers, 0);
        }

        /// Atomically write a full message.
        pub fn getWritable(self: *SwapBuffer) Writable {
            const sync_writing: Sync = .{ .writing = 1 };
            const old_sync: Sync = self.sync.fetchAdd(sync_writing, .acquire);
            std.debug.assert(old_sync.writing == 0);
            return .{
                .sync = &self.sync,
                .old_sync = old_sync,
                .slice = self.buffers[old_sync.side][old_sync.len..],
            };
        }

        pub const Writable = struct {
            sync: *std.atomic.Value(Sync),
            old_sync: Sync,
            slice: []u8,

            pub fn commit(self: *const Writable, n: Len) void {
                std.debug.assert(n <= self.slice.len);
                var new_sync = self.old_sync;
                new_sync.len += n;
                self.sync.store(new_sync, .release);
            }
        };

        pub fn swap(self: *SwapBuffer) []const u8 {
            while (true) : (std.atomic.spinLoopHint()) {
                const s: Sync = self.sync.load(.monotonic);
                if (s.writing == 1) continue;
                std.debug.assert(s.writing == 0);
                if (s.len == 0) return &.{};
                var new = s;
                new.len = 0;
                new.side = ~new.side;
                if (self.sync.cmpxchgStrong(s, new, .acq_rel, .monotonic) == null) {
                    return self.buffers[s.side][0..s.len];
                }
            }
        }
    };
};

pub const MessageSink = union(enum) {
    noop,
    writer: *std.Io.Writer,
    swap_buffer: *MessageStream.SwapBuffer,
};

pub const Message = struct {
    /// Milliseconds since epoch Jan 1, 1970 at 12:00 AM.
    epoch_millis: u64,
    scope: []const u8,
    fields: []const EntryField,
    /// It is assumed/asserted that `msg.surround = .literal`. The message quotes are implicit.
    msg: EntryValueFmt,
    level: Level,

    /// IMPORTANT: This should be kept in sync with `write`.
    pub fn computeHeader(self: Message) Header {
        std.debug.assert(self.msg.surround == .literal);
        return .{
            .epoch_millis = self.epoch_millis,
            .scope_len = @intCast(self.scope.len),
            .fields_len = @intCast(std.fmt.count("{f}", .{EntryField.listFmt(self.fields)})),
            .msg_len = @intCast(std.fmt.count("{f}", .{self.msg})),
            .level = self.level,
        };
    }

    /// IMPORTANT: This should be kept in sync with `computeHeader` & `Header.logfmtStream`.
    pub fn write(self: Message, w: *std.Io.Writer) std.Io.Writer.Error!Header {
        const header = self.computeHeader();
        try w.writeStruct(header, tel.endian);
        try w.writeAll(self.scope);
        try EntryField.writeFields(self.fields, w);
        std.debug.assert(self.msg.surround == .literal);
        try self.msg.format(w);
        return header;
    }

    pub const Header = extern struct {
        /// Milliseconds since epoch Jan 1, 1970 at 12:00 AM.
        epoch_millis: u64,
        scope_len: u32,
        fields_len: u32,
        msg_len: u32,
        level: Level,

        magic: enum(u32) { valid = 0xAA_BB_CC_DD, _ } align(1) = .valid,

        pub const Slices = struct {
            scope: []const u8,
            fields_str: []const u8,
            msg: []const u8,
        };

        /// Returns `null` if `fbr` does not have all of the expected slices buffered.
        /// If `null` is returned, `fbr` will remain unchanged.
        pub fn getSlicesFromFixedBuffer(
            self: Header,
            /// Assumed to behave the same as `std.Io.Reader.fixed`.
            fbr: *std.Io.Reader,
        ) ?Slices {
            if (fbr.bufferedLen() < self.encodedLength() - @sizeOf(Header)) {
                return null;
            }
            return .{
                .scope = fbr.take(self.scope_len) catch unreachable,
                .fields_str = fbr.take(self.fields_len) catch unreachable,
                .msg = fbr.take(self.msg_len) catch unreachable,
            };
        }

        pub fn encodedLength(self: Header) u32 {
            return @sizeOf(Header) +
                self.scope_len +
                self.fields_len +
                self.msg_len;
        }
    };
};

test Message {
    const gpa = std.testing.allocator;

    {
        const msg: Message = .{
            .epoch_millis = 0,
            .level = .err,
            .scope = "foo",
            .fields = &.{.init("fizz", .fromValue(.literal, "{s}", &"buzz"))},
            .msg = .fromFmt(.literal, "{s}", &.{"bar"}),
        };
        const expected_header: Message.Header = .{
            .epoch_millis = 0,
            .level = .err,
            .scope_len = "foo".len,
            .fields_len = "fizz=buzz".len,
            .msg_len = "bar".len,
        };
        try std.testing.expectEqual(expected_header, msg.computeHeader());
    }

    var encoded: std.Io.Writer.Allocating = .init(gpa);
    defer encoded.deinit();
    const written_header = try Message.write(
        .{
            .epoch_millis = 1_999,
            .level = .debug,
            .scope = "scope1",
            .fields = &.{
                .init("field_a", .fromValue(.quoted, "0x{X}", &0xFAF0)),
                .init("field_b", .fromValue(.literal, "{s}", &"value")),
            },
            .msg = .fromFmt(.literal, "message {s} here", &.{"goes"}),
        },
        &encoded.writer,
    );

    var encoded_r: std.Io.Reader = .fixed(encoded.written());
    const decoded_header = try encoded_r.takeStruct(Message.Header, tel.endian);
    try std.testing.expectEqual(written_header, decoded_header);

    const decoded_slices = decoded_header.getSlicesFromFixedBuffer(&encoded_r) orelse
        return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("message goes here", decoded_slices.msg);
    try std.testing.expectEqualStrings("scope1", decoded_slices.scope);
    try std.testing.expectEqualStrings(
        "field_a=\"0xFAF0\" field_b=value",
        decoded_slices.fields_str,
    );
}

pub const Filter = struct {
    service: ?[]const u8,
    scope: ?[]const u8,
    level: Level,

    pub fn initLevel(level: Level) Filter {
        return .{
            .service = null,
            .scope = null,
            .level = level,
        };
    }

    /// Returns true if `self` only applies a level filter (`service == null and scope == null`).
    pub fn isLevelOnly(self: Filter) bool {
        return self.service == null and self.scope == null;
    }

    pub const LevelOrder = enum {
        /// Filters sorted by level will have fatal ordered first, ascending.
        fatal_first,
        /// Filters sorted by level will have fatal ordered last, descending.
        fatal_last,
    };

    /// Orders filters from least to most information, first by `service`, and then `scope`; where the
    /// amount of information is equal (both or neither `!= null`), they are ordered lexicographically
    /// in the same order of priority, and then by `level` (based on `params.level_order`).
    ///
    /// NOTE: having multiple filters that would compare equal if the `level` were ignored doesn't make a lot of sense.
    pub fn order(
        self: Filter,
        other: Filter,
        params: struct {
            level_order: LevelOrder,
        },
    ) std.math.Order {
        const Mask = packed struct(u2) {
            scope: bool,
            service: bool,

            fn from(filter: Filter) @This() {
                return .{
                    .scope = filter.scope != null,
                    .service = filter.service != null,
                };
            }
        };
        const self_mask: u2 = @bitCast(Mask.from(self));
        const other_mask: u2 = @bitCast(Mask.from(other));
        switch (std.math.order(self_mask, other_mask)) {
            .lt, .gt => |ord| return ord,
            .eq => {},
        }

        if (self.service != null) switch (std.mem.order(u8, self.service.?, other.service.?)) {
            .lt, .gt => |ord| return ord,
            .eq => {},
        };
        if (self.scope != null) switch (std.mem.order(u8, self.scope.?, other.scope.?)) {
            .lt, .gt => |ord| return ord,
            .eq => {},
        };

        const level_order = self.level.order(other.level);
        return switch (params.level_order) {
            .fatal_first => level_order,
            .fatal_last => level_order.invert(),
        };
    }

    /// For convenient use with `std.sort` APIs.
    /// Sorts from "strictest" filters to "broadest" filters.
    pub fn sortLessThanInverted(_: void, a: Filter, b: Filter) bool {
        return a.order(b, .{ .level_order = .fatal_last }).invert() == .lt;
    }

    /// Returns the index of the filter in a sorted list that most specifically applies to the given service & scope pair.
    pub fn findClosestFilter(
        params: struct {
            /// Should be sorted such that `sortLessThanInverted({}, filters[n], filters[n + 1]) == true`.
            filters: []const Filter,
            service: []const u8,
            scope: []const u8,
        },
    ) usize {
        const filters = params.filters;
        const service = params.service;
        const scope = params.scope;

        std.debug.assert(filters[filters.len - 1].isLevelOnly());
        return for (filters, 0..) |filter, i| {
            if (i != 0) {
                const prev = filters[i - 1];
                std.debug.assert(Filter.sortLessThanInverted({}, prev, filter)); // must be sorted
            }

            if (filter.service) |filter_service| {
                if (!std.mem.eql(u8, filter_service, service)) continue;
                if (filter.scope) |filter_scope| {
                    if (!std.mem.eql(u8, filter_scope, scope)) continue;
                }
                break i;
            } // if `filter.service` is null, that means every filter after this point will also have it as null.

            if (filter.scope) |filter_scope| {
                if (!std.mem.eql(u8, filter_scope, scope)) continue;
                break i;
            } // if `filter.scope` is null, that means every filter after this point will also have it as null.

            // there should be one level-only filter at the end
            std.debug.assert(i == filters.len - 1);
            break i;
        } else unreachable;
    }

    pub const ParseError = error{InvalidLogLevel};
    pub fn parse(str: []const u8) ParseError!Filter {
        const eql_idx = std.mem.indexOfScalarPos(u8, str, 0, '=') orelse {
            return .{
                .service = null,
                .scope = null,
                .level = Level.fromText(str) orelse return error.InvalidLogLevel,
            };
        };
        const level = Level.fromText(str[eql_idx + 1 ..]) orelse return error.InvalidLogLevel;
        const colon_idx = std.mem.indexOfScalarPos(u8, str[0..eql_idx], 0, ':') orelse {
            const service = str[0..eql_idx];
            return .{
                .service = if (service.len == 0) null else service,
                .scope = null,
                .level = level,
            };
        };

        const service = str[0..colon_idx];
        const scope = str[colon_idx + 1 .. eql_idx];
        return .{
            .service = if (service.len == 0) null else service,
            .scope = if (scope.len == 0) null else scope,
            .level = level,
        };
    }

    /// Parses `str` as a comma-separated list of `Filter`s (`std.mem.splitScalar` & `Filter.parse`).
    /// If a default filter is missing (ie a filter for which `filter.isLevelOnly() == true`), the
    /// provided `default_root_log_level` will be used instead.
    /// `str.len == 0` is treated as an empty list (`default_log_level` will always be written).
    pub fn parseListAndWriteBinary(
        w: *std.Io.Writer,
        default_log_level: Level,
        str: []const u8,
    ) (std.Io.Writer.Error || ParseError)!void {
        var missing_default_level = true;

        if (str.len != 0) {
            var iter = std.mem.splitScalar(u8, str, ',');
            while (iter.next()) |filter_str| {
                const filter: Filter = try .parse(filter_str);
                try filter.writeBinary(w);
                missing_default_level = missing_default_level and !filter.isLevelOnly();
            }
        }

        if (missing_default_level) {
            const level_filter: Filter = .initLevel(default_log_level);
            try writeBinary(level_filter, w);
        }
    }

    /// Returns the length that would be written by `parseListAndWriteBinary`.
    pub fn calcParseListAndWriteBinaryLength(
        default_log_level: Level,
        str: []const u8,
    ) ParseError!u64 {
        var discarding: std.Io.Writer.Discarding = .init(&.{});
        parseListAndWriteBinary(
            &discarding.writer,
            default_log_level,
            str,
        ) catch |err| switch (err) {
            error.WriteFailed => unreachable,
            error.InvalidLogLevel => |e| return e,
        };
        return discarding.fullCount();
    }

    /// Like `parseListAndWriteBinary`, but runs at comptime and directly returns the encoded bytes.
    /// Returns null instead of an error.
    pub inline fn parseListStrLitIntoBinary(
        comptime default_log_level: Level,
        comptime str: []const u8,
    ) ?[]const u8 {
        comptime {
            const len = calcParseListAndWriteBinaryLength(default_log_level, str) catch return null;
            var result: [len]u8 = @splat(255);
            var fbw: std.Io.Writer = .fixed(&result);
            parseListAndWriteBinary(&fbw, default_log_level, str) catch |err| switch (err) {
                error.WriteFailed => unreachable,
                error.InvalidLogLevel => return null,
            };
            const copy = fbw.buffered()[0..].*;
            return &copy;
        }
    }

    pub fn writeBinary(
        self: Filter,
        w: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try w.writeStruct(self.computeHeader(), tel.endian);
        if (self.service) |service| try w.writeAll(service);
        if (self.scope) |scope| try w.writeAll(scope);
    }

    pub fn computeHeader(self: Filter) Header {
        return .{
            .service_len = if (self.service) |service| @intCast(service.len) else 0,
            .scope_len = if (self.scope) |scope| @intCast(scope.len) else 0,
            .level = self.level,
        };
    }

    pub const Header = extern struct {
        /// Length of zero represents `null`.
        service_len: u32 align(1),
        /// Length of zero represents `null`.
        scope_len: u32 align(1),
        level: Level,

        pub fn encodedLength(self: Header) u32 {
            return @sizeOf(Header) +
                self.service_len +
                self.scope_len;
        }

        /// Returns `null` if `fbr` does not have all of the expected slices buffered.
        /// If `null` is returned, `fbr` will remain unchanged.
        pub fn getFilterFromFixedReader(
            self: Header,
            /// Assumed to behave the same as `std.Io.Reader.fixed`.
            fbr: *std.Io.Reader,
        ) ?Filter {
            if (fbr.bufferedLen() < self.encodedLength() - @sizeOf(Header)) {
                return null;
            }
            const service = fbr.take(self.service_len) catch unreachable;
            const scope = fbr.take(self.scope_len) catch unreachable;
            return .{
                .service = if (service.len == 0) null else service,
                .scope = if (scope.len == 0) null else scope,
                .level = self.level,
            };
        }
    };

    pub fn format(self: Filter, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.service) |service| try w.writeAll(service);
        if (self.scope) |scope| {
            try w.writeByte(':');
            try w.writeAll(scope);
        }
        try w.writeByte('=');
        try w.writeAll(self.level.text());
    }
};

test Filter {
    // Empty filter str case.
    {
        const encoded = comptime Filter.parseListStrLitIntoBinary(.fatal, "").?;
        var reader: std.Io.Reader = .fixed(encoded);

        const header = try reader.takeStruct(Filter.Header, tel.endian);
        const filter = header.getFilterFromFixedReader(&reader) orelse
            return error.TestExpectedNonNull;
        try std.testing.expectEqual(Filter.initLevel(.fatal), filter);
        try std.testing.expectEqual(0, reader.bufferedLen());
    }

    // case for filter str = "replay:main=info".
    {
        const encoded = comptime Filter.parseListStrLitIntoBinary(
            .fatal,
            "replay:main=info",
        ).?;
        var reader: std.Io.Reader = .fixed(encoded);

        const replay_header = try reader.takeStruct(Filter.Header, tel.endian);
        const replay_filter = replay_header.getFilterFromFixedReader(&reader) orelse
            return error.TestExpectedNonNull;
        try std.testing.expectEqual(.info, replay_filter.level);
        try std.testing.expectEqualStrings("replay", replay_filter.service.?);
        try std.testing.expectEqualStrings("main", replay_filter.scope.?);

        const default_header = try reader.takeStruct(Filter.Header, tel.endian);
        const default_filter = default_header.getFilterFromFixedReader(&reader) orelse
            return error.TestExpectedNonNull;
        try std.testing.expectEqual(Filter.initLevel(.fatal), default_filter);
        try std.testing.expectEqual(0, reader.bufferedLen());
    }
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

pub fn streamLogs(
    params: struct {
        output: *std.Io.Writer,
        service_name: []const u8,
        log_messages_buffer: []const u8,
        /// Must satisfy the ordering constraints of `Filter.findClosestFilter`.
        filters: []const Filter,
    },
) (std.Io.Writer.Error || error{ InvalidMagicField, TruncatedLog })!void {
    const output = params.output;
    const service_name = params.service_name;
    const log_messages_buffer = params.log_messages_buffer;
    const filters = params.filters;

    var log_reader: std.Io.Reader = .fixed(log_messages_buffer);
    while (log_reader.bufferedLen() != 0) {
        const log_msg_header = log_reader.takeStruct(
            Message.Header,
            tel.endian,
        ) catch |err| switch (err) {
            error.ReadFailed => unreachable,
            error.EndOfStream => {
                std.log.err("Expected log message header, found end of stream.", .{});
                return error.TruncatedLog;
            },
        };

        if (log_msg_header.magic != .valid) {
            std.log.err(
                "Invalid magic field with value '{d}'.",
                .{@intFromEnum(log_msg_header.magic)},
            );
            return error.InvalidMagicField;
        }

        const slices = log_msg_header.getSlicesFromFixedBuffer(&log_reader) orelse {
            std.log.err("Expected log message slices, found end of stream.", .{});
            return error.TruncatedLog;
        };

        const filter_index = Filter.findClosestFilter(.{
            .filters = filters,
            .service = service_name,
            .scope = slices.scope,
        });
        if (log_msg_header.level.order(filters[filter_index].level) == .gt) continue;

        // time
        try output.print("time={f}", .{Iso8601Fmt.fromEpochMillis(log_msg_header.epoch_millis)});

        // level
        try output.writeByte(' ');
        try output.print("level={s}", .{@tagName(log_msg_header.level)});

        // scope
        try output.writeByte(' ');
        try output.print("scope={s}", .{slices.scope});

        // additional fields
        if (log_msg_header.fields_len != 0) {
            // other fields streamed directly as a string
            try output.writeByte(' ');
            try output.writeAll(slices.fields_str);
        }

        try output.writeByte(' ');
        try output.print("service={s}", .{service_name});

        // message
        try output.writeByte(' ');
        try output.print("message=\"{s}\"", .{slices.msg});

        try output.writeByte('\n');
    }
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
