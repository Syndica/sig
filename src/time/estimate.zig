const std = @import("std");

pub fn printTimeEstimate(
    // timer should be started at the beginning of the loop
    timer: *std.time.Timer,
    total: usize,
    i: usize,
    comptime name: []const u8,
    other_info: ?[]const u8,
) void {
    if (i == 0 or total == 0) return;
    if (i > total) {
        std.debug.print("{s}: {d}/{d} (?%) (time left: ...)\r", .{
            name,
            i,
            total,
        });
        return;
    }

    const p_done = i * 100 / total;
    const left = total - i;

    const elapsed = timer.read();
    const ns_per_vec = elapsed / i;
    const ns_left = ns_per_vec * left;

    if (other_info) |info| {
        std.debug.print("{s}: {d}/{d} ({d}%) {s} (time left: {s})\r", .{
            name,
            i,
            total,
            p_done,
            info,
            std.fmt.fmtDuration(ns_left),
        });
    } else {
        std.debug.print("{s}: {d}/{d} ({d}%) (time left: {s})\r", .{
            name,
            i,
            total,
            p_done,
            std.fmt.fmtDuration(ns_left),
        });
    }
}
