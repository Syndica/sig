const std = @import("std");
const time = @import("../time/time.zig");
const Field = @import("field.zig").Field;
const Level = @import("level.zig").Level;
const logfmt = @import("logfmt.zig");
const Logger = @import("./log.zig").Logger;
const Channel = @import("../sync/channel.zig").Channel;
const testing = std.testing;
const AtomicBool = std.atomic.Value(bool);

pub const Entry = union(enum) {
    standard: *StandardEntry,
    noop,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, channel: *Channel(*StandardEntry), max_level: Level) Self {
        return .{ .standard = StandardEntry.init(allocator, channel, max_level) };
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .standard => |entry| {
                entry.deinit();
            },
            .noop => {},
        }
    }

    pub fn field(self: Self, name: []const u8, value: anytype) Self {
        switch (self) {
            .standard => |entry| {
                _ = entry.field(name, value);
                return self;
            },
            .noop => {
                return self;
            },
        }
    }

    pub fn debugf(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.debug, fmt, args);
    }

    pub fn errf(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.err, fmt, args);
    }

    pub fn warnf(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.warn, fmt, args);
    }

    pub fn infof(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.info, fmt, args);
    }

    pub fn info(self: Self, msg: []const u8) void {
        self.log(.info, msg);
    }

    pub fn debug(self: Self, msg: []const u8) void {
        self.log(.debug, msg);
    }

    pub fn err(self: Self, msg: []const u8) void {
        self.log(.err, msg);
    }

    pub fn warn(self: Self, msg: []const u8) void {
        self.log(.warn, msg);
    }

    pub fn logf(self: Self, level: Level, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            .standard => |entry| {
                entry.logf(level, fmt, args);
            },
            .noop => {},
        }
    }

    pub fn log(self: Self, level: Level, msg: []const u8) void {
        switch (self) {
            .standard => |entry| {
                entry.log(level, msg);
            },
            .noop => {},
        }
    }

    pub fn format(
        self: *const Self,
        fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .standard => |entry| {
                try entry.format(fmt, options, writer);
            },
            .noop => {},
        }
    }

    pub fn custom_format(self: *const Self, formatter: anytype, writer: anytype) !void {
        switch (self) {
            .standard => |entry| {
                try formatter(entry, writer);
            },
            .noop => {},
        }
    }
};

pub const StandardEntry = struct {
    /// Log levels more granular than this will not be logged.
    max_level: Level,
    /// Level to log this message as.
    level: Level,
    allocator: std.mem.Allocator,
    fields: std.ArrayList(Field),
    time: time.DateTime,
    message: std.ArrayList(u8),
    channel: *Channel(*StandardEntry),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, channel: *Channel(*StandardEntry), max_level: Level) *Self {
        const self = allocator.create(Self) catch @panic("could not allocate.Create Entry");
        self.* = Self{
            .allocator = allocator,
            .fields = std.ArrayList(Field).init(allocator),
            .max_level = max_level,
            .level = Level.debug,
            .channel = channel,
            .time = time.DateTime.epoch_unix,
            .message = std.ArrayList(u8).init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        for (self.fields.items) |*f| {
            f.deinit(self.allocator);
        }
        self.fields.deinit();
        self.message.deinit();
        self.allocator.destroy(self);
    }

    pub fn field(self: *Self, name: []const u8, value: anytype) *Self {
        self.fields.append(Field.init(self.allocator, name, value)) catch @panic("could not append Field");
        return self;
    }

    pub fn logf(self: *Self, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(self.max_level) < @intFromEnum(level)) {
            self.deinit();
            return;
        }
        var message = std.ArrayList(u8).initCapacity(self.allocator, fmt.len * 2) catch @panic("could not initCapacity for message");
        std.fmt.format(message.writer(), fmt, args) catch @panic("could not format");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = level;
        self.channel.send(self) catch @panic("could not send to channel");
    }

    pub fn log(self: *Self, level: Level, msg: []const u8) void {
        if (@intFromEnum(self.max_level) < @intFromEnum(level)) {
            self.deinit();
            return;
        }
        var message = std.ArrayList(u8).initCapacity(self.allocator, msg.len) catch @panic("could not initCapacity for message");
        message.appendSlice(msg[0..]) catch @panic("could not appendSlice for message");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = level;
        self.channel.send(self) catch @panic("could not send to channel");
    }

    pub fn format(
        self: *const Self,
        _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        // default formatting style
        try logfmt.formatter(self, writer);
    }

    pub fn custom_format(self: *const Self, formatter: anytype, writer: anytype) !void {
        try formatter(self, writer);
    }
};

const A = enum(u8) {
    some_enum_variant,
};

test "trace.entry: should info log correctly" {
    var logger = Logger.init(testing.allocator, Level.info);
    defer logger.deinit();
    var entry = StandardEntry.init(testing.allocator, logger.standard.channel, .debug);
    defer entry.deinit();

    const anull: ?u8 = null;

    entry
        .field("some_val", true)
        .field("enum_field", A.some_enum_variant)
        .field("name", "a-mod")
        .field("elapsed", @as(i48, 135133340042))
        .field("possible_value", anull)
        .logf(.info, "hello, {s}", .{"world!"});
}
