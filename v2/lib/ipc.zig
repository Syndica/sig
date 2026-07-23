const std = @import("std");
const lib = @import("lib.zig");

pub const Ring = @import("ipc/ring.zig").Ring;
comptime {
    if (@import("builtin").is_test) {
        _ = @import("ipc/ring.zig");
    }
}

pub const ResolvedArgs = extern struct {
    stderr: std.os.linux.fd_t,
    runner: *align(page_size_min) lib.runner.Region,

    rw: [max_regions]?[*]align(page_size_min) u8,
    rw_len: [max_regions]usize,
    ro: [max_regions]?[*]align(page_size_min) const u8,
    ro_len: [max_regions]usize,

    /// Opaque context created by the service initializer. Services must not inspect it,
    /// only pass it back to `thread_crash_fn`.
    thread_crash_ctx: ?*anyopaque,
    thread_crash_fn: ?ThreadCrashFn,
    service_idx: u16,

    pub const ThreadCrashFn = *const fn (?*anyopaque, u16) callconv(.c) void;
    pub const max_regions = 16; // chosen arbitrarily
    const page_size_min = std.heap.page_size_min;
};

pub const ServiceFn = *const fn (ResolvedArgs) callconv(.c) void;
