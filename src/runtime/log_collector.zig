// TODO: add comments and permalinks

const std = @import("std");
const sig = @import("../sig.zig");

const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;

pub const LogCollector = struct {
    allocator: std.mem.Allocator,
    messages: std.ArrayListUnmanaged([]const u8),
    bytes_written: usize,
    maybe_bytes_limit: ?usize,
    bytes_limit_reached: bool,

    pub fn init(allocator: std.mem.Allocator) LogCollector {
        return .{
            .allocator = allocator,
            .messages = .{},
            .bytes_written = 0,
            .bytes_limit = null,
            .limit_warning = false,
        };
    }

    pub fn deinit(self: LogCollector) void {
        for (self.messages.items) |message| self.allocator.free(message);
        self.messages.deinit();
    }

    pub fn log(self: LogCollector, comptime fmt: []const u8, args: anytype) !void {
        if (self.bytes_limit_reached) return;

        const message = try std.fmt.allocPrint(self.allocator, fmt, args);

        if (self.maybe_bytes_limit) |bytes_limit| {
            const bytes_written = self.bytes_written +| message.len;
            if (bytes_written >= bytes_limit and !self.bytes_limit_reached) {
                self.bytes_limit_reached = true;
                self.messages.append(self.allocator, "Log truncated");
            } else {
                self.bytes_written = bytes_written;
                self.messages.append(self.allocator, message);
            }
        } else {
            self.messages.append(self.allocator, message);
        }
    }
};
