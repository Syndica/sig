const std = @import("std");
const sdk = @import("sdk.zig");

// const log = sdk.defineSyscall("sol_log_");
// const abort = sdk.defineSyscall("abort");

const log = sdk.defineSyscall("sol_log_");

pub fn deserialize(input: [*]const u8) void {
    var offset: u64 = 0;

    const num_accounts = std.mem.readInt(u64, input[offset..][0..8], .little);
    offset += @sizeOf(u64);

    print("num accounts: {}\n", .{num_accounts});
}

fn print(comptime fmt: []const u8, args: anytype) void {
    var buffer: [512]u8 = undefined;
    const message = std.fmt.bufPrint(&buffer, fmt, args) catch
        unreachable;
    log(message.ptr, message.len);
}
