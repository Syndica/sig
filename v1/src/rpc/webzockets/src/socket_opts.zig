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

pub fn setNonBlocking(fd: std.posix.fd_t) !void {
    const FlagsInt = @typeInfo(std.posix.O).@"struct".backing_integer.?;
    var flags_int: FlagsInt = @intCast(try std.posix.fcntl(fd, std.posix.F.GETFL, 0));
    const flags = std.mem.bytesAsValue(std.posix.O, std.mem.asBytes(&flags_int));
    if (!flags.NONBLOCK) {
        flags.NONBLOCK = true;
        _ = try std.posix.fcntl(fd, std.posix.F.SETFL, flags_int);
    }
}
