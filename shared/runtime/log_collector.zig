const builtin = @import("builtin");
const std = @import("std");

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L4
const DEFAULT_MAX_BYTES_LIMIT: usize = 10 * 1000;
const LOG_TRUNCATE_MSG = "Log truncated";

/// `LogCollector` is used to collect logs at the transaction level. Each `TransactionContext` has its own log collector
/// which may be used to collect and emit logs as part of the transaction processing result.
///
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L6
pub const LogCollector = struct {
    message_pool: std.ArrayListUnmanaged(u8),
    message_indices: std.ArrayListUnmanaged(usize),
    bytes_written: usize,
    bytes_limit: ?usize,
    bytes_limit_reached: bool,

    pub fn init(allocator: std.mem.Allocator, bytes_limit: ?usize) !LogCollector {
        return .{
            .message_pool = try .initCapacity(
                allocator,
                bytes_limit orelse DEFAULT_MAX_BYTES_LIMIT,
            ),
            .message_indices = try .initCapacity(
                allocator,
                (bytes_limit orelse DEFAULT_MAX_BYTES_LIMIT) / 100,
            ),
            .bytes_written = 0,
            .bytes_limit = bytes_limit,
            .bytes_limit_reached = false,
        };
    }

    pub fn default(allocator: std.mem.Allocator) !LogCollector {
        return LogCollector.init(allocator, DEFAULT_MAX_BYTES_LIMIT);
    }

    pub fn deinit(self: LogCollector, allocator: std.mem.Allocator) void {
        var copy = self;
        copy.message_pool.deinit(allocator);
        copy.message_indices.deinit(allocator);
    }

    pub fn eql(self: LogCollector, other: LogCollector) bool {
        return std.mem.eql(u8, self.message_pool.items, other.message_pool.items);
    }

    pub fn iterator(self: LogCollector) Iterator {
        return .{
            .message_pool = self.message_pool.items,
            .message_indices = self.message_indices.items,
            .index = 0,
        };
    }

    pub const Iterator = struct {
        message_pool: []const u8,
        message_indices: []const usize,
        index: usize,

        pub fn count(it: Iterator) usize {
            return it.message_indices.len - it.index;
        }

        pub fn next(it: *Iterator) ?[:0]const u8 {
            if (it.index >= it.message_indices.len) return null;
            const end_idx = blk: {
                if (it.index + 1 == it.message_indices.len) break :blk it.message_pool.len;
                break :blk it.message_indices[it.index + 1];
            };
            const msg = it.message_pool[it.message_indices[it.index]..end_idx];
            it.index += 1;
            return @ptrCast(msg);
        }
    };

    /// Append a formatted message to the log, respecting `bytes_limit`.
    ///
    /// Truncation semantics must mirror agave exactly — consensus-relevant programs
    /// observe the resulting log buffer via CPI return paths and runtime trailers:
    ///   1. If the message fits, it is appended and `bytes_written` advances.
    ///   2. If the message would overflow `bytes_limit`, the message is dropped,
    ///      `bytes_written` is NOT advanced, and `"Log truncated"` is appended
    ///      exactly once (the first time overflow occurs).
    ///   3. Because `bytes_written` does not advance on overflow, a subsequent
    ///      shorter message that still fits under the limit must still be
    ///      admitted. Do NOT add an early `if (bytes_limit_reached) return;`
    ///      guard — it would silently drop messages agave would keep, and break
    ///      conformance for programs that log after a truncation event.
    ///
    /// [agave] https://github.com/anza-xyz/agave/blob/v4.0/svm-log-collector/src/lib.rs#L26
    pub fn log(
        self: *LogCollector,
        allocator: std.mem.Allocator,
        comptime fmt: []const u8,
        args: anytype,
    ) error{OutOfMemory}!void {
        if (self.bytes_limit) |bl| {
            const msg_len: usize = @intCast(std.fmt.count(fmt, args));
            const bytes_written = self.bytes_written +| msg_len;
            if (bytes_written >= bl) {
                // Overflow path: emit "Log truncated" once, leave bytes_written
                // unchanged so later shorter messages can still fit.
                if (!self.bytes_limit_reached) {
                    self.bytes_limit_reached = true;
                    try self.message_indices.append(allocator, self.message_pool.items.len);
                    try self.message_pool.appendSlice(allocator, LOG_TRUNCATE_MSG);
                }
            } else {
                self.bytes_written = bytes_written;
                try self.message_indices.append(allocator, self.message_pool.items.len);
                try self.message_pool.writer(allocator).print(fmt, args);
            }
        } else {
            try self.message_indices.append(allocator, self.message_pool.items.len);
            try self.message_pool.writer(allocator).print(fmt, args);
        }
    }
};

test "bytes_limit" {
    const allocator = std.testing.allocator;

    {
        var log_collector = try LogCollector.init(allocator, 10);
        defer log_collector.deinit(allocator);

        try log_collector.log(allocator, "Hello", .{});
        try log_collector.log(allocator, "World", .{}); // This message will be truncated

        var iter = log_collector.iterator();
        try expectEqualLogs(
            &.{ "Hello", LOG_TRUNCATE_MSG },
            &.{ iter.next().?, iter.next().? },
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L108
    {
        var log_collector = try LogCollector.default(allocator);
        defer log_collector.deinit(allocator);

        for (0..DEFAULT_MAX_BYTES_LIMIT * 2) |_| try log_collector.log(allocator, "x", .{});

        var msg_iter = log_collector.iterator();
        while (msg_iter.next()) |msg| {
            if (msg_iter.index == DEFAULT_MAX_BYTES_LIMIT) {
                try std.testing.expectEqualStrings(LOG_TRUNCATE_MSG, msg);
            } else {
                try std.testing.expectEqualStrings("x", msg);
            }
        }
        try std.testing.expectEqual(
            DEFAULT_MAX_BYTES_LIMIT,
            msg_iter.message_pool.len - LOG_TRUNCATE_MSG.len + 1,
        );
    }
}

// Regression test for a subtle agave-parity bug: after `"Log truncated"` is
// emitted, a later message that would still fit under `bytes_limit` must be
// admitted normally. The fix matters because `bytes_written` is intentionally
// not advanced when a message overflows, so the remaining budget is still
// available for shorter follow-up messages. Adding an early
// `if (bytes_limit_reached) return;` guard at the top of `log()` would pass
// the other tests in this file while silently breaking conformance — this test
// exists to fail loudly if that regression is reintroduced.
test "log admits fitting messages after truncation (agave parity)" {
    const allocator = std.testing.allocator;

    var log_collector = try LogCollector.init(allocator, 20);
    defer log_collector.deinit(allocator);

    // bytes_written = 2, fits under limit.
    try log_collector.log(allocator, "AB", .{});
    // 2 + 25 >= 20 → drop the message, emit "Log truncated", bytes_written
    // stays at 2.
    try log_collector.log(allocator, "{s}", .{"X" ** 25});
    // 2 + 2 < 20 → must still be admitted; under the previous early-return
    // implementation this message was silently dropped.
    try log_collector.log(allocator, "CD", .{});

    var iter = log_collector.iterator();
    try expectEqualLogs(
        &.{ "AB", LOG_TRUNCATE_MSG, "CD" },
        &.{ iter.next().?, iter.next().?, iter.next().? },
    );
    try std.testing.expectEqual(null, iter.next());
    try std.testing.expect(log_collector.bytes_limit_reached);
    try std.testing.expectEqual(@as(usize, 4), log_collector.bytes_written);
}

test "iterator count" {
    const allocator = std.testing.allocator;

    var log_collector = try LogCollector.init(allocator, null);
    defer log_collector.deinit(allocator);

    try log_collector.log(allocator, "Hello", .{});
    try log_collector.log(allocator, "World", .{});

    var iterator = log_collector.iterator();
    try std.testing.expectEqual(2, iterator.count());
    try std.testing.expectEqualStrings("Hello", iterator.next().?);
    try std.testing.expectEqual(1, iterator.count());
    try std.testing.expectEqualStrings("World", iterator.next().?);
    try std.testing.expectEqual(0, iterator.count());
    try std.testing.expectEqual(null, iterator.next());
}

test "iterator count empty collector" {
    const allocator = std.testing.allocator;

    var log_collector = try LogCollector.init(allocator, null);
    defer log_collector.deinit(allocator);

    var iterator = log_collector.iterator();
    try std.testing.expectEqual(0, iterator.count());
    try std.testing.expectEqual(null, iterator.next());
    try std.testing.expectEqual(0, iterator.count());
}

fn expectEqualLogs(expected: []const []const u8, actual: []const []const u8) !void {
    if (!builtin.is_test)
        @compileError("expectEqualLogs is only available in test mode");

    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, 0..) |expected_message, i|
        try std.testing.expectEqualStrings(expected_message, actual[i]);
}
