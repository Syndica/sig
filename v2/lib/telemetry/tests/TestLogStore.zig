//! Captures telemetry logs for in-process tests and optionally panics on alert fields.

const std = @import("std");
const lib = @import("../../lib.zig");
const tel = lib.telemetry;

state: *State,

const TestLogStore = @This();

pub const PanicOnAlert = enum {
    none,
    dev,
    operator,
    all,

    fn includes(self: PanicOnAlert, alert: tel.log.Alert) bool {
        return switch (self) {
            .none => false,
            .dev => alert == .dev,
            .operator => alert == .operator,
            .all => true,
        };
    }
};

pub const Options = struct {
    panic_on_alert: PanicOnAlert = .all,
};

/// Stable backing state for captured records, the writer, and alert policy.
const State = struct {
    allocator: std.mem.Allocator,
    writer: std.Io.Writer,
    encoded: std.ArrayListUnmanaged(u8),
    processed_len: usize,
    panic_on_alert: PanicOnAlert,

    /// Appends writer output and inspects each newly completed message.
    fn drain(
        writer: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const self: *State = @alignCast(@fieldParentPtr("writer", writer));
        std.debug.assert(data.len != 0);

        const rest = data[0 .. data.len - 1];
        const pattern = data[data.len - 1];
        const consumed = std.Io.Writer.countSplat(data, splat);

        self.encoded.ensureUnusedCapacity(self.allocator, consumed) catch
            @panic("out of memory");
        for (rest) |bytes| self.encoded.appendSliceAssumeCapacity(bytes);
        for (0..splat) |_| self.encoded.appendSliceAssumeCapacity(pattern);

        // Inspect immediately so an alert panic's stack trace includes the logging call.
        self.inspectCompleteMessages();
        return consumed;
    }

    /// Decodes complete messages not previously inspected for alerts.
    fn inspectCompleteMessages(self: *State) void {
        while (true) {
            const remaining = self.encoded.items[self.processed_len..];
            if (remaining.len < @sizeOf(tel.log.Message.Header)) return;

            var reader: std.Io.Reader = .fixed(remaining);
            const header = reader.takeStruct(tel.log.Message.Header, tel.endian) catch unreachable;
            if (header.magic != .valid) @panic("invalid captured log message magic");

            const encoded_len: usize = header.encodedLength();
            if (remaining.len < encoded_len) return;
            const slices = header.getSlicesFromFixedBuffer(&reader) orelse unreachable;
            self.inspectAlert(.fromMessage(header, slices));
            self.processed_len += encoded_len;
        }
    }

    /// Applies the configured panic policy to a record's alert field.
    fn inspectAlert(self: *State, record: Record) void {
        var fields = record.fieldIterator();
        var found_alert: ?tel.log.Alert = null;
        while (fields.next()) |field| {
            if (!std.mem.eql(u8, field.name, "alert")) continue;
            if (found_alert != null) @panic("log message contains multiple alert fields");
            found_alert = std.meta.stringToEnum(tel.log.Alert, field.value) orelse
                @panic("log message contains invalid alert field");
        }

        const alert = found_alert orelse return;
        if (!self.panic_on_alert.includes(alert)) return;
        std.debug.panic(
            "alert log emitted: alert={s} scope={s} message={s}",
            .{ @tagName(alert), record.scope, record.message },
        );
    }
};

pub const Field = struct {
    name: []const u8,
    /// Serialized value with surrounding quotes removed and escape sequences retained.
    value: []const u8,
};

pub const FieldIterator = struct {
    fields: []const u8,
    index: usize = 0,

    /// Returns the next serialized logfmt field.
    pub fn next(self: *FieldIterator) ?Field {
        while (self.index < self.fields.len and self.fields[self.index] == ' ') {
            self.index += 1;
        }
        if (self.index == self.fields.len) return null;

        const name_start = self.index;
        const equals_index = std.mem.indexOfScalarPos(
            u8,
            self.fields,
            name_start,
            '=',
        ) orelse @panic("captured log field is missing '='");

        const value_start = equals_index + 1;

        if (value_start < self.fields.len and self.fields[value_start] == '"') {
            // value is quoted, skip escaped characters to find the closing quote
            const unquoted_start = value_start + 1;
            var quote_index = unquoted_start;
            while (quote_index < self.fields.len) {
                switch (self.fields[quote_index]) {
                    '\\' => {
                        quote_index += 1;
                        if (quote_index == self.fields.len) {
                            @panic("captured quoted log field has an incomplete escape sequence");
                        }
                    },
                    '"' => break,
                    else => {},
                }
                quote_index += 1;
            }
            if (quote_index == self.fields.len) {
                @panic("captured quoted log field is unterminated");
            }
            self.index = quote_index + 1;
            if (self.index < self.fields.len and self.fields[self.index] != ' ') {
                @panic("captured quoted log field has trailing data");
            }
            return .{
                .name = self.fields[name_start..equals_index],
                .value = self.fields[unquoted_start..quote_index],
            };
        }

        // value is unquoted, consume until the next space or end of string
        const value_end = std.mem.indexOfScalarPos(
            u8,
            self.fields,
            value_start,
            ' ',
        ) orelse self.fields.len;
        self.index = value_end;
        return .{
            .name = self.fields[name_start..equals_index],
            .value = self.fields[value_start..value_end],
        };
    }
};

pub const Record = struct {
    epoch_millis: u64,
    level: tel.log.Level,
    scope: []const u8,
    fields: []const u8,
    message: []const u8,

    fn fromMessage(
        header: tel.log.Message.Header,
        slices: tel.log.Message.Header.Slices,
    ) Record {
        return .{
            .epoch_millis = header.epoch_millis,
            .level = header.level,
            .scope = slices.scope,
            .fields = slices.fields_str,
            .message = slices.msg,
        };
    }

    /// Iterates over this record's structured fields.
    pub fn fieldIterator(self: Record) FieldIterator {
        return .{ .fields = self.fields };
    }

    /// Returns the serialized value of the first field with the given name.
    pub fn field(self: Record, name: []const u8) ?[]const u8 {
        var fields = self.fieldIterator();
        while (fields.next()) |field_value| {
            if (std.mem.eql(u8, field_value.name, name)) return field_value.value;
        }
        return null;
    }
};

pub const Iterator = struct {
    reader: std.Io.Reader,

    /// Returns the next captured log record.
    pub fn next(self: *Iterator) ?Record {
        if (self.reader.bufferedLen() == 0) return null;
        const header = self.reader.takeStruct(tel.log.Message.Header, tel.endian) catch
            @panic("captured log message is truncated");
        if (header.magic != .valid) @panic("invalid captured log message magic");
        const slices = header.getSlicesFromFixedBuffer(&self.reader) orelse
            @panic("captured log message is truncated");
        return .fromMessage(header, slices);
    }
};

/// Creates an empty log store with the requested alert policy.
pub fn init(allocator: std.mem.Allocator, options: Options) !TestLogStore {
    const state = try allocator.create(State);
    state.* = .{
        .allocator = allocator,
        .writer = .{
            .vtable = &.{ .drain = State.drain },
            .buffer = &.{},
        },
        .encoded = .empty,
        .processed_len = 0,
        .panic_on_alert = options.panic_on_alert,
    };
    return .{ .state = state };
}

/// Releases all memory owned by the store.
pub fn deinit(self: *TestLogStore) void {
    const allocator = self.state.allocator;
    self.state.encoded.deinit(allocator);
    allocator.destroy(self.state);
}

/// Returns a logger that writes records into this store.
pub fn logger(self: *TestLogStore, comptime scope: []const u8) tel.Logger(scope) {
    return .{ .sink = .{ .writer = &self.state.writer } };
}

/// Returned records and iterators are invalidated by the next log, reset, or deinit.
pub fn iterator(self: *const TestLogStore) Iterator {
    return .{ .reader = .fixed(self.state.encoded.items) };
}

/// Invalidates records and iterators previously returned by this store.
pub fn reset(self: *TestLogStore) void {
    self.state.encoded.clearRetainingCapacity();
    self.state.processed_len = 0;
}

/// Changes which alert audiences panic when subsequently logged.
pub fn setPanicOnAlert(self: *TestLogStore, panic_on_alert: PanicOnAlert) void {
    self.state.panic_on_alert = panic_on_alert;
}

test "empty store is ok with no records" {
    const allocator = std.testing.allocator;
    var logs = try TestLogStore.init(allocator, .{});
    defer logs.deinit();

    var records = logs.iterator();
    try std.testing.expectEqual(null, records.next());
}

test "captures structured log records" {
    const allocator = std.testing.allocator;
    var logs = try TestLogStore.init(allocator, .{ .panic_on_alert = .none });
    defer logs.deinit();

    const count: u64 = 42;
    const detail = "two \"quoted\" words";
    const equation = "a=b";
    const quoted_equation = "value a=b";
    const path = "path\\to\\file";
    const quoted_path = "path\\to file";
    logs.logger("test_scope").info()
        .field("count", &count)
        .field("detail", &detail)
        .field("equation", &equation)
        .field("quoted_equation", &quoted_equation)
        .field("path", &path)
        .field("quoted_path", &quoted_path)
        .log("captured");

    var records = logs.iterator();
    const record = records.next() orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(tel.log.Level.info, record.level);
    try std.testing.expectEqualStrings("test_scope", record.scope);
    try std.testing.expectEqualStrings("captured", record.message);
    try std.testing.expectEqualStrings("42", record.field("count").?);
    try std.testing.expectEqualStrings("two \\\"quoted\\\" words", record.field("detail").?);
    try std.testing.expectEqualStrings("a=b", record.field("equation").?);
    try std.testing.expectEqualStrings("value a=b", record.field("quoted_equation").?);
    try std.testing.expectEqualStrings("path\\to\\file", record.field("path").?);
    try std.testing.expectEqualStrings("path\\\\to file", record.field("quoted_path").?);
    try std.testing.expectEqual(null, records.next());
}

test "captures multiple records in order" {
    const allocator = std.testing.allocator;
    var logs = try TestLogStore.init(allocator, .{});
    defer logs.deinit();

    logs.logger("first_scope").debug().log("first");
    logs.logger("second_scope").err().log("second entry");

    var records = logs.iterator();
    const first = records.next() orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(tel.log.Level.debug, first.level);
    try std.testing.expectEqualStrings("first_scope", first.scope);
    try std.testing.expectEqualStrings("first", first.message);

    const second = records.next() orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(tel.log.Level.err, second.level);
    try std.testing.expectEqualStrings("second_scope", second.scope);
    try std.testing.expectEqualStrings("\"second entry\"", second.message);
    try std.testing.expectEqual(null, records.next());
}

test "captures allowed alert records" {
    const allocator = std.testing.allocator;
    var logs = try TestLogStore.init(allocator, .{});
    defer logs.deinit();
    logs.setPanicOnAlert(.dev);

    logs.logger("test_scope").warn().alert(.operator).log("expected");

    var records = logs.iterator();
    const record = records.next() orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("operator", record.field("alert").?);
}

test "reset clears captured records and preserves alert policy" {
    const allocator = std.testing.allocator;
    var logs = try TestLogStore.init(allocator, .{ .panic_on_alert = .dev });
    defer logs.deinit();

    logs.logger("test_scope").info().log("before reset");
    logs.reset();
    logs.logger("test_scope").warn().alert(.operator).log("after reset");

    var records = logs.iterator();
    const record = records.next() orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("\"after reset\"", record.message);
    try std.testing.expectEqualStrings("operator", record.field("alert").?);
    try std.testing.expectEqual(null, records.next());
}

test PanicOnAlert {
    try std.testing.expect(!PanicOnAlert.none.includes(.dev));
    try std.testing.expect(PanicOnAlert.dev.includes(.dev));
    try std.testing.expect(!PanicOnAlert.dev.includes(.operator));
    try std.testing.expect(!PanicOnAlert.operator.includes(.dev));
    try std.testing.expect(PanicOnAlert.operator.includes(.operator));
    try std.testing.expect(PanicOnAlert.all.includes(.dev));
    try std.testing.expect(PanicOnAlert.all.includes(.operator));
}
