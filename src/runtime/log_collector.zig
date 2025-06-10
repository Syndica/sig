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

    pub fn deinit(self: *LogCollector, allocator: std.mem.Allocator) void {
        self.message_pool.deinit(allocator);
        self.message_indices.deinit(allocator);
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

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L25
    pub fn log(
        self: *LogCollector,
        allocator: std.mem.Allocator,
        comptime fmt: []const u8,
        args: anytype,
    ) error{OutOfMemory}!void {
        if (self.bytes_limit_reached) return;

        try self.message_indices.append(allocator, self.message_pool.items.len);
        if (self.bytes_limit) |bl| {
            const msg_len: usize = @intCast(std.fmt.count(fmt, args));
            const bytes_written = self.bytes_written +| msg_len;
            if (bytes_written >= bl and !self.bytes_limit_reached) {
                self.bytes_limit_reached = true;
                try self.message_pool.appendSlice(allocator, LOG_TRUNCATE_MSG);
            } else {
                self.bytes_written = bytes_written;
                try self.message_pool.writer(allocator).print(fmt, args);
            }
        } else {
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

fn expectEqualLogs(expected: []const []const u8, actual: []const []const u8) !void {
    if (!builtin.is_test)
        @compileError("expectEqualLogs is only available in test mode");

    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, 0..) |expected_message, i|
        try std.testing.expectEqualStrings(expected_message, actual[i]);
}
