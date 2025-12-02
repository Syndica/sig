pub const log = @import("log.zig");
pub const level = @import("level.zig");
pub const logfmt = @import("logfmt.zig");
pub const entry = @import("entry.zig");

pub const Logger = log.Logger;
pub const NewEntry = entry.NewEntry;
pub const Entry = entry.Entry;
pub const Level = level.Level;
pub const DirectPrintLogger = log.DirectPrintLogger;
pub const ChannelPrintLogger = log.ChannelPrintLogger;

pub inline fn assert(ok: bool) void {
    if (!ok) {
        @branchHint(.cold);
        @import("std").debug.panic("assertion failed", .{});
    }
}
