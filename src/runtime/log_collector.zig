const std = @import("std");

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L4
const DEFAULT_MAX_BYTES_LIMIT: usize = 10 * 1000;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L6
pub const LogCollector = struct {
    allocator: std.mem.Allocator,
    messages: std.ArrayListUnmanaged([]const u8),
    bytes_written: usize,
    maybe_bytes_limit: ?usize,
    bytes_limit_reached: bool,

    pub fn init(allocator: std.mem.Allocator, maybe_bytes_limit: ?usize) LogCollector {
        return .{
            .allocator = allocator,
            .messages = .{},
            .bytes_written = 0,
            .maybe_bytes_limit = maybe_bytes_limit,
            .bytes_limit_reached = false,
        };
    }

    pub fn default(allocator: std.mem.Allocator) LogCollector {
        return LogCollector.init(allocator, DEFAULT_MAX_BYTES_LIMIT);
    }

    pub fn deinit(self: LogCollector) void {
        for (self.messages.items) |message| self.allocator.free(message);
        self.allocator.free(self.messages.allocatedSlice());
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L43
    pub fn collect(self: LogCollector) []const []const u8 {
        return self.messages.items;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L25
    pub fn log(
        self: *LogCollector,
        comptime fmt: []const u8,
        args: anytype,
    ) error{OutOfMemory}!void {
        if (self.bytes_limit_reached) return;

        const message = try std.fmt.allocPrint(self.allocator, fmt, args);

        if (self.maybe_bytes_limit) |bytes_limit| {
            const bytes_written = self.bytes_written +| message.len;
            if (bytes_written >= bytes_limit and !self.bytes_limit_reached) {
                self.allocator.free(message);
                self.bytes_limit_reached = true;
                try self.messages.append(
                    self.allocator,
                    try std.fmt.allocPrint(self.allocator, "Log truncated", .{}),
                );
            } else {
                self.bytes_written = bytes_written;
                try self.messages.append(self.allocator, message);
            }
        } else {
            try self.messages.append(self.allocator, message);
        }
    }
};

test "bytes_limit" {
    const allocator = std.testing.allocator;

    {
        var log_collector = LogCollector.init(allocator, 10);
        defer log_collector.deinit();

        try log_collector.log("Hello", .{});
        try log_collector.log("World", .{}); // This message will be truncated

        try testing.expectEqualLogs(
            &.{
                "Hello",
                "Log truncated",
            },
            log_collector.collect(),
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L108
    {
        var log_collector = LogCollector.default(allocator);
        defer log_collector.deinit();

        for (0..DEFAULT_MAX_BYTES_LIMIT * 2) |_| try log_collector.log("x", .{});

        const messages = log_collector.collect();
        try std.testing.expectEqual(DEFAULT_MAX_BYTES_LIMIT, messages.len);
        for (messages[0 .. DEFAULT_MAX_BYTES_LIMIT - 1]) |msg|
            try std.testing.expectEqualStrings("x", msg);
        try std.testing.expectEqualStrings("Log truncated", messages[DEFAULT_MAX_BYTES_LIMIT - 1]);
    }
}

const testing = struct {
    fn expectEqualLogs(expected: []const []const u8, actual: []const []const u8) !void {
        try std.testing.expectEqual(expected.len, actual.len);
        for (expected, 0..) |expected_message, i|
            try std.testing.expectEqualStrings(expected_message, actual[i]);
    }
};
