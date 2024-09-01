const std = @import("std");
const Level = @import("level.zig").Level;
const logfmt = @import("logfmt.zig");
const sig = @import("../sig.zig");
// TODO Improve import.
const Channel = @import("../sync/channel.zig").Channel;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const RecycleFBA = sig.utils.allocators.RecycleFBA;

pub const Config = struct {
    max_level: Level = Level.debug,
    allocator: std.mem.Allocator,
    /// Maximum memory that logger can use.
    max_buffer: u64,
    exit_sig: *std.atomic.Value(bool),
};

const INITIAL_LOG_CHANNEL_SIZE: usize = 1024;

const LogType = enum {
    standard,
    noop,
};

const UnscopedLogger = StandardLogger(null);
pub fn StandardLogger(comptime scope: ?type) type {
    const StanardErrLogger = struct {
        const Self = @This();
        max_level: Level,
        exit_sig: *std.atomic.Value(bool),
        allocator: Allocator,
        recycle_fba: RecycleFBA,
        max_buffer: u64,
        channel: *Channel(logfmt.LogMsg),
        handle: ?std.Thread,

        pub fn init(config: Config) Self {
            return .{
                .allocator = config.allocator,
                .recycle_fba = RecycleFBA.init(config.allocator, config.max_buffer) catch @panic("could not create RecycleFBA"),
                .max_buffer = config.max_buffer,
                .max_level = config.max_level,
                .exit_sig = config.exit_sig,
                .channel = Channel(logfmt.LogMsg).init(config.allocator, INITIAL_LOG_CHANNEL_SIZE),
                .handle = null,
            };
        }

        fn unscoped(self: *Self) *UnscopedLogger {
            return @ptrCast(self);
        }

        fn withScope(self: *Self, comptime new_scope: anytype) *StandardLogger(new_scope) {
            return @ptrCast(self);
        }

        pub fn spawn(self: *Self) void {
            self.handle = std.Thread.spawn(.{}, Self.run, .{self}) catch @panic("could not spawn Logger");
        }

        pub fn deinit(self: *Self) void {
            self.channel.close();
            if (self.handle) |handle| {
                self.exit_sig.store(true, .seq_cst);
                handle.join();
            }
            self.channel.deinit();
            self.recycle_fba.deinit();
        }

        pub fn run(self: *Self) void {
            while (!self.exit_sig.load(.seq_cst)) {
                std.time.sleep(std.time.ns_per_ms * 5);
                const messages = self.channel.drain() orelse {
                    // channel is closed
                    return;
                };
                defer self.channel.allocator.free(messages);

                for (messages) |message| {
                    logfmt.writeLog(message) catch @panic("logging failed");
                }
            }
        }

        fn createLogMessage(
            self: *Self,
            level: Level,
            maybe_scope: ?[]const u8,
            maybe_msg: ?[]const u8,
            maybe_fields: anytype,
            comptime maybe_fmt: ?[]const u8,
            args: anytype,
        ) logfmt.LogMsg {
            // obtain a memory to write to
            self.recycle_fba.mux.lock();
            const buf = blk: while (true) {
                // TODO allocate based on need.
                const buf = self.recycle_fba.allocator().alloc(u8, 256) catch {
                    // no memory available rn - unlock and wait
                    self.recycle_fba.mux.unlock();
                    std.time.sleep(std.time.ns_per_ms);
                    self.recycle_fba.mux.lock();
                    continue;
                };
                break :blk buf;
            };
            self.recycle_fba.mux.unlock();
            errdefer {
                self.recycle_fba.mux.lock();
                self.recycle_fba.allocator().free(buf);
                self.recycle_fba.mux.unlock();
            }
            var fmt_message = std.io.fixedBufferStream(buf);
            const writer = fmt_message.writer();

            if (maybe_fmt) |fmt| {
                std.fmt.format(writer, fmt, args) catch @panic("could not format");
            }
            const log_message = fmt_message.getWritten();
            // Reset buffer before re-using to construct fields.
            fmt_message.reset();
            return logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = maybe_msg,
                .maybe_fields = logfmt.fieldsToStr(buf, maybe_fields),
                .maybe_fmt = log_message,
            };
        }

        pub fn log(self: *Self, level: Level, message: []const u8) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };

            const logMessage = self.createLogMessage(level, maybe_scope, message, null, null, null);
            self.channel.send(logMessage) catch @panic("could not send to channel");
        }

        pub fn logWithFields(self: *Self, level: Level, message: []const u8, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };
            const logMessage = self.createLogMessage(level, maybe_scope, message, fields, null, null);
            self.channel.send(logMessage) catch @panic("could not send to channel");
        }

        pub fn logf(self: *Self, level: Level, comptime fmt: []const u8, args: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };
            const logMessage = self.createLogMessage(level, maybe_scope, null, null, fmt, args);
            self.channel.send(logMessage) catch @panic("could not send to channel");
        }

        pub fn logfWithFields(self: *Self, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };
            const logMessage = self.createLogMessage(level, maybe_scope, null, fields, fmt, args);
            self.channel.send(logMessage) catch @panic("could not send to channel");
        }
    };

    return union(LogType) {
        const Self = @This();
        standard: StanardErrLogger,
        noop: void,
        pub fn init(config: Config) Self {
            return .{ .standard = StanardErrLogger.init(.{
                .allocator = config.allocator,
                .exit_sig = config.exit_sig,
                .max_level = config.max_level,
                .max_buffer = config.max_buffer,
            }) };
        }

        pub fn deinit(self: *Self) void {
            switch (self.*) {
                .standard => |logger| {
                    var standard = logger;
                    standard.deinit();
                },
                .noop => {},
            }
        }

        pub fn spawn(self: *Self) void {
            switch (self.*) {
                .standard => |*logger| {
                    logger.spawn();
                },
                .noop => {},
            }
        }

        pub fn unscoped(self: *Self) *UnscopedLogger {
            return @ptrCast(self);
        }

        pub fn withScope(self: *Self, comptime new_scope: anytype) *StandardLogger(new_scope) {
            return @ptrCast(self);
        }

        pub fn log(self: *Self, level: Level, message: []const u8) void {
            switch (self.*) {
                .standard => |*logger| {
                    logger.log(level, message);
                },
                .noop => {},
            }
        }

        pub fn logf(self: *Self, level: Level, comptime fmt: []const u8, args: anytype) void {
            switch (self.*) {
                .standard => |*logger| {
                    logger.logf(level, fmt, args);
                },
                .noop => {},
            }
        }

        pub fn logWithFields(self: *Self, level: Level, message: []const u8, fields: anytype) void {
            switch (self.*) {
                .standard => |*logger| {
                    logger.logWithFields(level, message, fields);
                },
                .noop => {},
            }
        }

        pub fn logfWithFields(self: *Self, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            switch (self.*) {
                .standard => |*logger| {
                    logger.logfWithFields(level, fmt, args, fields);
                },
                .noop => {},
            }
        }
    };
}

const Stuff = struct {
    logger: *StandardLogger(Stuff),

    pub fn init(logger: *UnscopedLogger) Stuff {
        return .{ .logger = logger.withScope(Stuff) };
    }

    pub fn doStuff(self: *Stuff) void {
        self.logger.log(.info, "doing stuff");
        var child = StuffChild.init(self.logger.unscoped());
        child.doStuffDetails();
    }
};

const StuffChild = struct {
    logger: *StandardLogger(StuffChild),

    pub fn init(logger: *UnscopedLogger) StuffChild {
        return .{ .logger = logger.withScope(StuffChild) };
    }

    pub fn doStuffDetails(self: *StuffChild) void {
        self.logger.log(.info, "doing stuff details");
    }
};

test "trace_ng: scope switch" {
    const allocator = std.testing.allocator;

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var logger = StandardLogger(null).init(.{
        .allocator = allocator,
        .exit_sig = exit,
        .max_level = Level.info,
        .max_buffer = 2048,
    });
    defer logger.deinit();
    logger.spawn();

    var stuff = Stuff.init(&logger);
    stuff.doStuff();
}

test "trace_ng: testing.allocator" {
    const allocator = std.testing.allocator;

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var logger = StandardLogger(null).init(.{
        .allocator = allocator,
        .exit_sig = exit,
        .max_level = Level.info,
        .max_buffer = 2048,
    });

    defer logger.deinit();
    logger.spawn();

    logger.log(.info, "Logging with log");
    logger.logf(
        .info,
        "{s}",
        .{"Logging with logf"},
    );
    logger.logWithFields(
        .info,
        "Logging with logWithFields",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );
    logger.logfWithFields(
        .info,
        "{s}",
        .{"Logging with logfWithFields"},
        .{
            .f_agent = "Firefox",
            .f_version = 120,
            .f_local = "en",
            .f_stock = "nvidia",
        },
    );
}

test "trace_ng: level" {
    const allocator = std.testing.allocator;

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var logger = StandardLogger(null).init(.{
        .allocator = allocator,
        .exit_sig = exit,
        .max_level = Level.err,
        .max_buffer = 2048,
    });

    defer logger.deinit();
    logger.spawn();

    // None should log as they are higher than set max_log.
    logger.log(.warn, "Logging with log");
    logger.logf(
        .info,
        "{s}",
        .{"Logging with logf"},
    );
    logger.logWithFields(
        .debug,
        "Logging with logWithFields",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );
    logger.logfWithFields(
        .debug,
        "{s}",
        .{"Logging with logfWithFields"},
        .{
            .f_agent = "Firefox",
            .f_version = 120,
            .f_local = "en",
            .f_stock = "nvidia",
        },
    );
}
