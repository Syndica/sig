const std = @import("std");

pub fn setTcpNoDelay(fd: std.posix.fd_t) !void {
    var enabled: c_int = 1;
    try std.posix.setsockopt(
        fd,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&enabled),
    );
}
