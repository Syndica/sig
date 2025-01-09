const builtin = @import("builtin");
const std = @import("std");

pub fn getSockName(
    socket_handle: std.posix.socket_t,
) std.posix.GetSockNameError!std.net.Address {
    var addr: std.net.Address = .{ .any = undefined };
    var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr.any));
    try std.posix.getsockname(socket_handle, &addr.any, &addr_len);
    return addr;
}

pub const WithLazyAddr = struct {
    stream: std.net.Stream,
    address: ?std.net.Address,

    pub fn toStdConnection(self: WithLazyAddr) std.posix.GetSockNameError!std.net.Server.Connection {
        return .{
            .stream = self.stream,
            .address = try self.getAddress(),
        };
    }

    pub fn getAddress(self: WithLazyAddr) std.posix.GetSockNameError!std.net.Address {
        return self.address orelse try getSockName(self.stream.handle);
    }

    pub fn getAndCacheAddress(self: *WithLazyAddr) std.posix.GetSockNameError!std.net.Address {
        const address = try self.getAddress();
        self.address = address;
        return address;
    }
};

pub const HandleAcceptError = error{
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    ProtocolFailure,
    BlockedByFirewall,
} || std.posix.UnexpectedError;

pub const HandleAcceptResult = enum {
    success,
    intr,
    again,
    conn_aborted,
};

/// Resembles the error handling of `std.posix.accept`.
pub fn handleAcceptResult(
    /// Must be the result of `std.posix.accept` or equivalent (ie io_uring cqe.err()).
    rc: std.posix.E,
) HandleAcceptError!HandleAcceptResult {
    comptime std.debug.assert( //
        builtin.target.isDarwin() or builtin.target.os.tag == .linux //
    );
    return switch (rc) {
        .SUCCESS => .success,
        .INTR => .intr,
        .AGAIN => .again,
        .CONNABORTED => .conn_aborted,

        .BADF, // always a race condition
        .FAULT, // don't address bad memory
        .NOTSOCK, // don't call accept on a non-socket
        .OPNOTSUPP, // socket must support accept
        .INVAL, // socket must be listening
        => |e| std.debug.panic("{s}", .{@tagName(e)}),

        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        .PROTO => return error.ProtocolFailure,
        .PERM => return error.BlockedByFirewall,
        else => |err| return std.posix.unexpectedErrno(err),
    };
}

pub const HandleRecvError = error{
    SystemResources,
} || std.posix.UnexpectedError;

pub const HandleRecvResult = enum {
    success,
    intr,
    again,
    conn_refused,
    conn_reset,
    timed_out,
};

/// Resembles the error handling of `std.posix.recv`.
pub fn handleRecvResult(
    /// Must be the result of `std.posix.recv` or equivalent (ie io_uring cqe.err()).
    rc: std.posix.E,
) HandleRecvError!HandleRecvResult {
    comptime std.debug.assert( //
        builtin.target.isDarwin() or builtin.target.os.tag == .linux //
    );
    return switch (rc) {
        .SUCCESS => .success,
        .INTR => .intr,
        .AGAIN => .again,
        .CONNREFUSED => .conn_refused,
        .CONNRESET => .conn_reset,
        .TIMEDOUT => .timed_out,

        .BADF, // always a race condition
        .FAULT, // don't address bad memory
        .INVAL, // socket must be listening
        .NOTSOCK, // don't call accept on a non-socket
        .NOTCONN, // we should always be connected
        => |e| std.debug.panic("{s}", .{@tagName(e)}),

        .NOMEM => return error.SystemResources,
        else => |err| return std.posix.unexpectedErrno(err),
    };
}

pub const HandleSpliceError = error{
    ///  One or both file descriptors are not valid, or do not have proper read-write mode.
    BadFileDescriptors,
    /// Either off_in or off_out was not NULL, but the corresponding file descriptor refers to a pipe.
    BadFdOffset,
    /// Could be one of many reasons, see the manpage for splice.
    InvalidSplice,
    /// Out of memory.
    SystemResources,
};

pub const HandleSpliceResult = enum {
    success,
    again,
};

pub fn handleSpliceResult(
    /// Must be the result of calling the `splice` syscall or equivalent (ie io_uring cqe.err()).
    rc: std.posix.E,
) HandleSpliceError!HandleSpliceResult {
    comptime std.debug.assert( //
        builtin.target.os.tag == .linux //
    );
    return switch (rc) {
        .SUCCESS => .success,
        .AGAIN => .again,
        .INVAL => return error.InvalidSplice,
        .SPIPE => return error.BadFdOffset,
        .BADF => return error.BadFileDescriptors,
        .NOMEM => return error.SystemResources,
        else => |err| std.posix.unexpectedErrno(err),
    };
}
