const std = @import("std");
const time = @import("../time/time.zig");
const Field = @import("field.zig").Field;
const Level = @import("level.zig").Level;
const logfmt = @import("logfmt.zig");
const Logger = @import("./log.zig").Logger;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Atomic(bool);

pub const Entry = struct {
    level: Level,
    allocator: std.mem.Allocator,
    fields: std.ArrayList(Field),
    time: time.DateTime,
    message: std.ArrayList(u8),
    logger: *Logger,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, logger: *Logger) *Self {
        var self = allocator.create(Self) catch @panic("could not allocate.Create Entry");
        self.* = Self{
            .allocator = allocator,
            .fields = std.ArrayList(Field).init(allocator),
            .level = Level.debug,
            .logger = logger,
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

    pub fn infof(self: *Self, comptime fmt: []const u8, args: anytype) void {
        var message = std.ArrayList(u8).initCapacity(self.allocator, fmt.len * 2) catch @panic("could not initCapacity for message");
        std.fmt.format(message.writer(), fmt, args) catch @panic("could not format");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = .info;
        self.logger.appendEntry(self);
    }

    pub fn debugf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        var message = std.ArrayList(u8).initCapacity(self.allocator, fmt.len * 2) catch @panic("could not initCapacity for message");
        std.fmt.format(message.writer(), fmt, args) catch @panic("could not format");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = .debug;
        self.logger.appendEntry(self);
    }

    pub fn errf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        var message = std.ArrayList(u8).initCapacity(self.allocator, fmt.len * 2) catch @panic("could not initCapacity for message");
        std.fmt.format(message.writer(), fmt, args) catch @panic("could not format");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = .err;
        self.logger.appendEntry(self);
    }

    pub fn warnf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        var message = std.ArrayList(u8).initCapacity(self.allocator, fmt.len * 2) catch @panic("could not initCapacity for message");
        std.fmt.format(message.writer(), fmt, args) catch @panic("could not format");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = .warn;
        self.logger.appendEntry(self);
    }

    pub fn info(self: *Self, comptime msg: []const u8) void {
        var message = std.ArrayList(u8).initCapacity(self.allocator, msg.len) catch @panic("could not initCapacity for message");
        message.appendSlice(msg[0..]) catch @panic("could not appendSlice for message");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = .info;
        self.logger.appendEntry(self);
    }

    pub fn debug(self: *Self, comptime msg: []const u8) void {
        var message = std.ArrayList(u8).initCapacity(self.allocator, msg.len) catch @panic("could not initCapacity for message");
        message.appendSlice(msg[0..]) catch @panic("could not appendSlice for message");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = .debug;
        self.logger.appendEntry(self);
    }

    pub fn err(self: *Self, comptime msg: []const u8) void {
        var message = std.ArrayList(u8).initCapacity(self.allocator, msg.len) catch @panic("could not initCapacity for message");
        message.appendSlice(msg[0..]) catch @panic("could not appendSlice for message");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = .err;
        self.logger.appendEntry(self);
    }

    pub fn warn(self: *Self, comptime msg: []const u8) void {
        var message = std.ArrayList(u8).initCapacity(self.allocator, msg.len) catch @panic("could not initCapacity for message");
        message.appendSlice(msg[0..]) catch @panic("could not appendSlice for message");
        self.message = message;
        self.time = time.DateTime.now();
        self.level = .warn;
        self.logger.appendEntry(self);
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
    var entry = Entry.init(testing.allocator, logger);

    var anull: ?u8 = null;

    entry
        .field("some_val", true)
        .field("enum_field", A.some_enum_variant)
        .field("name", "a-mod")
        .field("elapsed", @as(i48, 135133340042))
        .field("possible_value", anull)
        .infof("hello, {s}", .{"world!"});

    std.debug.print("{any}\n\n", .{logger});
}
