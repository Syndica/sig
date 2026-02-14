const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;

/// Utility to detect file descriptor leaks in tests.
///
/// Snapshots the open FD count at baseline and asserts no new FDs are leaked
/// after cleanup. FD counts are process-wide, so tests using this should be
/// run serially to avoid false positives from concurrent tests.
///
/// Usage:
/// ```zig
/// const fd_check = FdLeakDetector.baseline();
/// defer fd_check.assertNoLeaks();
/// // ... test body ...
/// ```
pub const FdLeakDetector = struct {
    baseline_count: usize,

    /// Snapshot current open FD count. Call as first line of test.
    pub fn baseline() FdLeakDetector {
        return .{ .baseline_count = countOpenFds() };
    }

    /// Assert FD count matches baseline. Panics with count delta on failure.
    pub fn assertNoLeaks(self: *const FdLeakDetector) void {
        const current = countOpenFds();
        if (current != self.baseline_count) {
            const cur: isize = @intCast(current);
            const base: isize = @intCast(self.baseline_count);
            const delta: isize = cur - base;
            std.debug.panic(
                "FD leak detected: {d} more FDs open " ++
                    "than at baseline (baseline={d}, current={d})",
                .{ delta, base, current },
            );
        }
    }
};

fn countOpenFds() usize {
    if (native_os == .macos) {
        return countOpenFdsDarwin();
    } else if (native_os == .linux) {
        return countOpenFdsLinux();
    } else {
        @compileError("FD leak detection not supported on this platform");
    }
}

/// macOS `proc_pidinfo` flavor to list open file descriptors.
const PROC_PIDLISTFDS: c_int = 1;

const proc_fdinfo = extern struct {
    proc_fd: i32,
    proc_fdtype: u32,
};

extern "c" fn proc_pidinfo(
    pid: c_int,
    flavor: c_int,
    arg: u64,
    buffer: ?*anyopaque,
    buffersize: c_int,
) c_int;

fn countOpenFdsDarwin() usize {
    // Two-call pattern: first call with null buffer returns the FD table capacity
    // (in bytes). Second call with a real buffer returns the actual bytes written
    // for open FDs only.
    const pid = std.posix.system.getpid();
    const buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, null, 0);
    if (buf_size <= 0) {
        std.debug.panic("proc_pidinfo(PROC_PIDLISTFDS) sizing call failed", .{});
    }

    const buf = std.heap.c_allocator.alloc(u8, @intCast(buf_size)) catch {
        std.debug.panic("Failed to allocate buffer for proc_pidinfo", .{});
    };
    defer std.heap.c_allocator.free(buf);

    const actual_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf.ptr, buf_size);
    if (actual_bytes <= 0) {
        std.debug.panic("proc_pidinfo(PROC_PIDLISTFDS) list call failed", .{});
    }
    return @as(usize, @intCast(actual_bytes)) / @sizeOf(proc_fdinfo);
}

fn countOpenFdsLinux() usize {
    var count: usize = 0;
    var dir = std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true }) catch {
        std.debug.panic("Failed to open /proc/self/fd for FD counting", .{});
    };
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |_| {
        count += 1;
    }
    // Subtract 1 for the directory FD itself (opened above).
    return count -| 1;
}

test "FdLeakDetector: no leak when no FDs opened" {
    const detector = FdLeakDetector.baseline();
    // No FDs opened — should not panic.
    detector.assertNoLeaks();
}

test "FdLeakDetector: detects leaked FD" {
    const detector = FdLeakDetector.baseline();

    // Open a file to leak an FD.
    const leaked_fd = std.posix.open("/dev/null", .{}, 0) catch return;
    // Don't close it — simulate a leak.

    const current = countOpenFds();
    // Verify our counting works: current should be > baseline.
    std.debug.assert(current > detector.baseline_count);

    // Clean up so we don't actually leak.
    std.posix.close(leaked_fd);

    // Now it should pass.
    detector.assertNoLeaks();
}

test "countOpenFds returns reasonable value" {
    const count = countOpenFds();
    // A running process should have at least stdin, stdout, stderr.
    std.debug.assert(count >= 3);
}
