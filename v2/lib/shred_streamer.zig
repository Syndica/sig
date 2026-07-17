const std = @import("std");

/// Shared-memory configuration for the shred_streamer service.
/// Contains the raw CLI args string that the service will parse.
/// This is an extern struct so it can live in a shared memory region.
pub const Config = extern struct {
    args_len: u32,
    args_data: [max_args_len]u8,

    pub const max_args_len = 4096;

    pub fn getArgs(self: *const Config) []const u8 {
        return self.args_data[0..self.args_len];
    }

    /// Populate the config from a slice of arg strings (joins with spaces).
    pub fn populate(self: *Config, args: []const []const u8) error{ArgsTooLong}!void {
        var pos: usize = 0;
        for (args, 0..) |arg, i| {
            if (i > 0) {
                if (pos >= max_args_len) return error.ArgsTooLong;
                self.args_data[pos] = ' ';
                pos += 1;
            }
            if (pos + arg.len > max_args_len) return error.ArgsTooLong;
            @memcpy(self.args_data[pos..][0..arg.len], arg);
            pos += arg.len;
        }
        self.args_len = @intCast(pos);
    }
};

test "Config populate and getArgs round-trip" {
    var config: Config = undefined;
    try config.populate(&.{ "--ledger", "/path/to/ledger", "--start-slot", "100" });
    try std.testing.expectEqualStrings(
        "--ledger /path/to/ledger --start-slot 100",
        config.getArgs(),
    );
}

test "Config populate empty args" {
    var config: Config = undefined;
    try config.populate(&.{});
    try std.testing.expectEqualStrings("", config.getArgs());
}
