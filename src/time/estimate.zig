const std = @import("std");
const sig = @import("../sig.zig");

// TODO: change to writer interface when logger has improved
pub fn printTimeEstimate(
    logger: anytype,
    // timer should be started at the beginning of the loop
    timer: *sig.time.Timer,
    total: usize,
    i: usize,
    comptime name: []const u8,
    other_info: ?[]const u8,
) void {
    if (i == 0 or total == 0) return;
    if (i > total) {
        if (other_info) |info| {
            logger
                .info()
                .logf("{s} [{s}]: {d}/{d} (?%) (est: ? elp: {f})", .{
                name,
                info,
                i,
                total,
                timer.read(),
            });
        } else {
            logger.info().logf("{s}: {d}/{d} (?%) (est: ? elp: {f})", .{
                name,
                i,
                total,
                timer.read(),
            });
        }
        return;
    }

    const p_done = i * 100 / total;
    const left = total - i;

    const elapsed = timer.read().asNanos();
    const ns_per_vec = elapsed / i;
    const ns_left = ns_per_vec * left;

    if (other_info) |info|
        logger.info().logf(
            "{s} [{s}]: {d}/{d} ({d}%) (est: {D} elp: {f})",
            .{ name, info, i, total, p_done, ns_left, timer.read() },
        )
    else
        logger.info().logf(
            "{s}: {d}/{d} ({d}%) (est: {D} elp: {f})",
            .{ name, i, total, p_done, ns_left, timer.read() },
        );
}

pub fn printTimeEstimateStderr(
    // timer should be started at the beginning of the loop
    timer: *sig.time.Timer,
    total: usize,
    i: usize,
    comptime name: []const u8,
    other_info: ?[]const u8,
) void {
    if (i == 0 or total == 0) return;
    if (i > total) {
        if (other_info) |info| {
            std.debug.print("{s} [{s}]: {d}/{d} (?%) (est: ? elp: {f})\r", .{
                name,
                info,
                i,
                total,
                timer.read(),
            });
        } else {
            std.debug.print("{s}: {d}/{d} (?%) (est: ? elp: {f})\r", .{
                name,
                i,
                total,
                timer.read(),
            });
        }
        return;
    }

    const p_done = i * 100 / total;
    const left = total - i;

    const elapsed = timer.read().asNanos();
    const ns_per_vec = elapsed / i;
    const ns_left = ns_per_vec * left;

    if (other_info) |info|
        std.debug.print(
            "{s} [{s}]: {d}/{d} ({d}%) (est: {D} elp: {f})\r",
            .{ name, info, i, total, p_done, ns_left, timer.read() },
        )
    else
        std.debug.print(
            "{s}: {d}/{d} ({d}%) (est: {D} elp: {f})\r",
            .{ name, i, total, p_done, ns_left, timer.read() },
        );
}
