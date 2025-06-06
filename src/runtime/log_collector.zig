const builtin = @import("builtin");
const std = @import("std");

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L4
const DEFAULT_MAX_BYTES_LIMIT: usize = 10 * 1000;

/// `LogCollector` is used to collect logs at the transaction level. Each `TransactionContext` has its own log collector
/// which may be used to collect and emit logs as part of the transaction processing result.
///
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L6
pub const LogCollector = struct {
    messages: std.ArrayListUnmanaged([]const u8),
    bytes_written: usize,
    bytes_limit: ?usize,
    bytes_limit_reached: bool,

    pub fn init(bytes_limit: ?usize) LogCollector {
        return .{
            .messages = .{},
            .bytes_written = 0,
            .bytes_limit = bytes_limit,
            .bytes_limit_reached = false,
        };
    }

    pub fn default() LogCollector {
        return LogCollector.init(DEFAULT_MAX_BYTES_LIMIT);
    }

    pub fn deinit(self: *LogCollector, allocator: std.mem.Allocator) void {
        for (self.messages.items) |message| allocator.free(message);
        self.messages.deinit(allocator);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L43
    pub fn collect(self: LogCollector) []const []const u8 {
        return self.messages.items;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L25
    pub fn log(
        self: *LogCollector,
        allocator: std.mem.Allocator,
        comptime fmt: []const u8,
        args: anytype,
    ) error{OutOfMemory}!void {
        if (self.bytes_limit_reached) return;

        const message = try std.fmt.allocPrint(allocator, fmt, args);

        if (self.bytes_limit) |bl| {
            const bytes_written = self.bytes_written +| message.len;
            if (bytes_written >= bl and !self.bytes_limit_reached) {
                allocator.free(message);
                self.bytes_limit_reached = true;
                try self.messages.append(
                    allocator,
                    try std.fmt.allocPrint(allocator, "Log truncated", .{}),
                );
            } else {
                self.bytes_written = bytes_written;
                try self.messages.append(allocator, message);
            }
        } else {
            try self.messages.append(allocator, message);
        }
    }
};

test "bytes_limit" {
    const allocator = std.testing.allocator;

    {
        var log_collector = LogCollector.init(10);
        defer log_collector.deinit(allocator);

        try log_collector.log(allocator, "Hello", .{});
        try log_collector.log(allocator, "World", .{}); // This message will be truncated

        try expectEqualLogs(
            &.{
                "Hello",
                "Log truncated",
            },
            log_collector.collect(),
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L108
    {
        var log_collector = LogCollector.default();
        defer log_collector.deinit(allocator);

        for (0..DEFAULT_MAX_BYTES_LIMIT * 2) |_| try log_collector.log(allocator, "x", .{});

        const messages = log_collector.collect();
        try std.testing.expectEqual(DEFAULT_MAX_BYTES_LIMIT, messages.len);
        for (messages[0 .. DEFAULT_MAX_BYTES_LIMIT - 1]) |msg|
            try std.testing.expectEqualStrings("x", msg);
        try std.testing.expectEqualStrings("Log truncated", messages[DEFAULT_MAX_BYTES_LIMIT - 1]);
    }
}

fn expectEqualLogs(expected: []const []const u8, actual: []const []const u8) !void {
    if (!builtin.is_test)
        @compileError("expectEqualLogs is only available in test mode");

    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, 0..) |expected_message, i|
        try std.testing.expectEqualStrings(expected_message, actual[i]);
}
