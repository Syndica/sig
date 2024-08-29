const std = @import("std");
const Level = @import("level.zig").Level;
const entry = @import("entry.zig");
const logfmt = @import("logfmt.zig");
const sig = @import("../sig.zig");
// TODO Improve import.
const Channel = @import("../sync/channel.zig").Channel;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const RecycleFBA = sig.utils.allocators.RecycleFBA;

const Entry = entry.Entry;
const StdEntry = entry.StdEntry;
const NoopEntry = entry.NoopEntry;

pub const LogConfig = struct {
    level: Level = Level.debug,
    buff_size: usize = 64,
};

// // Start: Trying out polymorphism via vtable.
// const LoggerInterface = struct {
//     // pointer to the logger object
//     ptr: *anyopaque,
//     infoFn: *const fn (ptr: *anyopaque) Entry,
//     // infoFn: fn (*anyopaque) Entry,
//     pub fn info(self: LoggerInterface) Entry {
//         return self.infoFn(self.ptr);
//     }
// };

// const StandardLogger = struct {
//     max_level: Level,
//     pub fn init(max_level: Level) StandardLogger {
//         return .{
//             .max_level = max_level,
//         };
//     }
//     pub fn logger(self: *StandardLogger) LoggerInterface {
//         return LoggerInterface{
//             .ptr = self,
//             .infoFn = info,
//         };
//     }

//     pub fn info(ptr: *anyopaque) Entry {
//         std.debug.print("{s}", .{"Hello World"});
//         const self: *StandardLogger = @ptrCast(@alignCast(ptr));
//         return Entry{ .standard = StdEntry.init(@This(), self.max_level) };
//     }
// };

pub const Config = struct {
    level: Level = Level.debug,
    allocator: std.mem.Allocator,
    fba_bytes: u64,
};

const INITIAL_LOG_CHANNEL_SIZE: usize = 1024;

const UnScoppedLogger = StandardLogger(null);
pub fn StandardLogger(comptime scope: ?type) type {
    return struct {
        const Self = @This();
        level: Level,
        exit_sig: AtomicBool,
        allocator: Allocator,
        free_fba: RecycleFBA,
        fba_bytes: u64,
        channel: *Channel(logfmt.LogMsg),
        handle: ?std.Thread,

        pub fn init(config: Config) Self {
            return .{
                .allocator = config.allocator,
                .free_fba = RecycleFBA.init(config.allocator, config.fba_bytes) catch @panic("could not create RecycleFBA"),
                .fba_bytes = config.fba_bytes,
                .level = config.level,
                .exit_sig = AtomicBool.init(false),
                .channel = Channel(logfmt.LogMsg).init(config.allocator, INITIAL_LOG_CHANNEL_SIZE),
                .handle = null,
            };
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
            self.free_fba.deinit();
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
                    logfmt.formatterLog(&self.free_fba, self.fba_bytes, message) catch @panic("logging failed");
                }
            }
        }

        pub fn log(self: Self, message: []const u8) void {
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };

            const logMessage = logfmt.LogMsg{
                .level = self.level,
                .maybe_scope = maybe_scope,
                .maybe_msg = message,
            };

            self.channel.send(logMessage) catch @panic("could not send to channel");
        }

        pub fn logWithFields(self: Self, message: []const u8, keyvalue: anytype) void {
            const stderr = std.io.getStdErr().writer();
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };
            logfmt.formatter(stderr, self.level, maybe_scope, null, message, null, null, keyvalue) catch unreachable();
        }

        pub fn logf(self: Self, comptime fmt: []const u8, args: anytype) void {
            const stderr = std.io.getStdErr().writer();
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };
            // TODO take struct as input instead.
            logfmt.formatter(stderr, self.level, maybe_scope, null, null, fmt, args, null) catch unreachable();
        }

        pub fn logfWithFields(self: Self, comptime fmt: []const u8, args: anytype, keyvalue: anytype) void {
            const stderr = std.io.getStdErr().writer();
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };
            // TODO take struct as input instead.
            logfmt.formatter(stderr, self.level, maybe_scope, null, null, fmt, args, keyvalue) catch unreachable();
        }
    };
}

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

test "trace_ng: chaining" {
    //var logger = Logger.init(.{});
    var logger = ScopedLogger(@This()).init(.{});
    logger.info()
        .add("f_agent", "firefox")
        .add("f_version", "v2")
        .log("Hello Logger");

    logger.info()
        .log("Hello Logger");
}

test "trace_ng: multiple methods" {
    // const buffer_size = 1 * 1024 * 1024; // 1MB
    // var buffer: [buffer_size]u8 = undefined;
    // var fba = std.heap.FixedBufferAllocator.init(&buffer);
    // const allocator = fba.allocator();

//     level: Level = Level.debug,
//    allocator: std.mem.Allocator,
//    fba_bytes: u64,

    const allocator = std.heap.page_allocator;

    var logger = StandardLogger(null).init(.{.allocator = allocator, .level = Level.info, .fba_bytes = 1 << 18 });
    defer logger.deinit();
    logger.spawn();

    logger.log("Logging via channel: Starting the app");
    logger.logWithFields(
        "Starting the app",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );
    logger.logf(
        "{s}",
        .{"Starting the app"},
    );
    logger.logfWithFields(
        "{s}",
        .{"Starting the app"},
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );
}
