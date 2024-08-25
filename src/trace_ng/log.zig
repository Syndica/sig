const std = @import("std");
const Level = @import("level.zig").Level;
const entry = @import("entry.zig");

const Entry = entry.Entry;
const StdEntry = entry.StdEntry;
const NoopEntry = entry.NoopEntry;

pub const LogConfig = struct {
    level: Level = Level.debug,
    buff_size: usize = 64,
};

const Logger = ScopedLogger(null);
pub fn ScopedLogger(comptime scope: ?type) type {
    return struct {
        max_level: Level,

        const Self = @This();

        pub fn init(config: LogConfig) Self {
            return .{ .max_level = config.level };
        }

        fn unscoped(self: @This()) Logger {
            return .{ .max_level = self.max_level };
        }

        fn withScope(self: @This(), comptime new_scope: anytype) ScopedLogger(new_scope) {
            return .{ .max_level = self.max_level };
        }

        pub fn info(self: @This()) Entry {
            if (@intFromEnum(self.max_level) >= @intFromEnum(Level.info)) {
                return Entry{ .standard = StdEntry.init(scope, Level.info) };
            }
            return Entry{ .noop = NoopEntry{} };
        }
    };
}

test "trace_ng" {
    //var logger = Logger.init(.{});
    var logger = ScopedLogger(@This()).init(.{});
    logger.info().add("f_agent", "firefox").add("f_version", "v2").log("Hello Logger");
    logger.info().log("Hello Logger");
}

const Stuff = struct {
    logger: ScopedLogger(@This()),

    pub fn init(logger: Logger) @This() {
        return .{ .logger = logger.withScope(@This()) };
    }

    pub fn doStuff(self: @This()) void {
        self.logger.info().log("doing stuff");
        const child = StuffChild.init(self.logger.unscoped());
        child.doStuffDetails();
    }
};

const StuffChild = struct {
    logger: ScopedLogger(@This()),

    pub fn init(logger: Logger) @This() {
        return .{ .logger = logger.withScope(@This()) };
    }

    pub fn doStuffDetails(self: @This()) void {
        self.logger.info().log("doing stuff details");
    }
};

test "trace_ng: scope switch" {
    const logger: Logger = Logger.init(.{});
    logger.info().log("starting the app");
    const stuff = Stuff.init(logger);
    stuff.doStuff();
}
