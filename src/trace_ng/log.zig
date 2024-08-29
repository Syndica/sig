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
                    logfmt.formatterLog(message) catch @panic("logging failed");
                }
            }
        }

        fn createLogMessage(
            _: Self,
            free_fba: *RecycleFBA,
            total_len: u64,
            level: Level,
            maybe_scope: ?[]const u8,
            maybe_msg: ?[]const u8,
            maybe_kv: ?[]const u8,
            comptime maybe_fmt: ?[]const u8,
            args: anytype,
        ) logfmt.LogMsg {
            // obtain a memory to write to
            free_fba.mux.lock();
            const buf = blk: while (true) {
                const buf = free_fba.allocator().alloc(u8, total_len) catch {
                    // no memory available rn - unlock and wait
                    free_fba.mux.unlock();
                    std.time.sleep(std.time.ns_per_ms);
                    free_fba.mux.lock();
                    continue;
                };
                break :blk buf;
            };
            free_fba.mux.unlock();
            errdefer {
                free_fba.mux.lock();
                free_fba.allocator().free(buf);
                free_fba.mux.unlock();
            }
            var fmt_message = std.io.fixedBufferStream(buf);
            const writer = fmt_message.writer();

            if (maybe_fmt) |fmt| {
                std.fmt.format(writer, fmt, args) catch @panic("could not format");
            }
            const log_message = fmt_message.getWritten();
            return logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = maybe_msg,
                .maybe_kv = maybe_kv,
                .maybe_fmt = log_message,
            };
        }

        pub fn log(self: Self, message: []const u8) void {
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };

            var free_fba = self.free_fba;
            const logMessage = self.createLogMessage(&free_fba, self.fba_bytes, self.level, maybe_scope, message, null, null, null);
            self.channel.send(logMessage) catch @panic("could not send to channel");
        }

        pub fn logWithFields(self: Self, message: []const u8, keyvalue: anytype) void {
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };
            const kv_str = logfmt.keyValueToString(keyvalue) catch @panic("Could not parse key values");
            // TODO Revisit why this is needed to remove the Unicode replacement character.
            var slice: [logfmt.keyValueSize(keyvalue)]u8 = undefined;
            @memcpy(slice[0..kv_str.len], kv_str);
            var free_fba = self.free_fba;
            const logMessage = self.createLogMessage(&free_fba, self.fba_bytes, self.level, maybe_scope, message, &slice, null, null);
            self.channel.send(logMessage) catch @panic("could not send to channel");
        }

        pub fn logf(self: Self, comptime fmt: []const u8, args: anytype) void {
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };
            var free_fba = self.free_fba;
            const logMessage = self.createLogMessage(&free_fba, self.fba_bytes, self.level, maybe_scope, null, null, fmt, args);
            self.channel.send(logMessage) catch @panic("could not send to channel");
        }

        pub fn logfWithFields(self: Self, comptime fmt: []const u8, args: anytype, keyvalue: anytype) void {
            const maybe_scope = blk: {
                if (scope) |s| {
                    break :blk @typeName(s);
                } else {
                    break :blk null;
                }
            };
            const kv_str = logfmt.keyValueToString(keyvalue) catch @panic("Could not parse key values");

            // TODO Revisit why this is needed to remove the Unicode replacement character.
            var slice: [logfmt.keyValueSize(keyvalue)]u8 = undefined;
            @memcpy(slice[0..kv_str.len], kv_str);

            var free_fba = self.free_fba;
            const logMessage = self.createLogMessage(&free_fba, self.fba_bytes, self.level, maybe_scope, null, &slice, fmt, args);
            self.channel.send(logMessage) catch @panic("could not send to channel");
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

    // TODO switch to testing allocator and fix any leaks.
    const allocator = std.heap.page_allocator;

    var logger = StandardLogger(null).init(.{ .allocator = allocator, .level = Level.info, .fba_bytes = 1 << 25 });
    defer logger.deinit();
    logger.spawn();

    logger.log("Logging with log");
    logger.logf(
        "{s}",
        .{"Logging with logf"},
    );
    logger.logWithFields(
        "Logging with logWithFields",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );
    logger.logfWithFields(
        "{s}",
        .{"Logging with logfWithFields"},
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
            .f_local = "en",
            .f_stock = "nvidia",
        },
    );
}
