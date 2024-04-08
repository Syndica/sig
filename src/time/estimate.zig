const std = @import("std");
const sig = @import("../lib.zig");

const Logger = sig.trace.Logger;

// TODO: change to writer interface when logger has improved
pub fn printTimeEstimate(
    logger: Logger,
    // timer should be started at the beginning of the loop
    timer: *std.time.Timer,
    total: usize,
    i: usize,
    comptime name: []const u8,
    other_info: ?[]const u8,
) void {
    if (i == 0 or total == 0) return;
    if (i > total) {
        logger.infof("{s}: {d}/{d} (?%) (time left: ...) (elp: {s})\r", .{
            name,
            i,
            total,
            std.fmt.fmtDuration(timer.read()),
        });
        return;
    }

    const p_done = i * 100 / total;
    const left = total - i;

    const elapsed = timer.read();
    const ns_per_vec = elapsed / i;
    const ns_left = ns_per_vec * left;

    if (other_info) |info| {
        logger.infof("{s}: {d}/{d} ({d}%) {s} (time left: {s}) (elp: {s})\r", .{
            name,
            i,
            total,
            p_done,
            info,
            std.fmt.fmtDuration(ns_left),
            std.fmt.fmtDuration(timer.read()),
        });
    } else {
        logger.infof("{s}: {d}/{d} ({d}%) (time left: {s}) (elp: {s})\r", .{
            name,
            i,
            total,
            p_done,
            std.fmt.fmtDuration(ns_left),
            std.fmt.fmtDuration(timer.read()),
        });
    }
}
