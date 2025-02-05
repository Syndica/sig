const builtin = @import("builtin");
const std = @import("std");

/// When this is false, it means `accept[Handled]` can't apply
/// flags to the accepted socket, and the caller will have to
/// to ensure relevant flags are enabled/disabled after acceptance.
pub const HAVE_ACCEPT4 = !builtin.target.isDarwin();

pub const GetSockNameError = std.posix.GetSockNameError;

pub fn getSockName(
    socket_handle: std.posix.socket_t,
) GetSockNameError!std.net.Address {
    var addr: std.net.Address = .{ .any = undefined };
    var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr.any));
    try std.posix.getsockname(socket_handle, &addr.any, &addr_len);
    return addr;
}

pub const AcceptHandledError = HandleAcceptError || error{
    ConnectionAborted,
    ProtocolFailure,
    WouldBlock,
};

pub fn acceptHandled(
    tcp_server: std.net.Server,
    /// NOTE: this is *only* a hint, and may not apply on all platforms.
    /// See `have_accept4`.
    sync_hint: enum { blocking, nonblocking },
) AcceptHandledError!std.net.Server.Connection {
    var accept_flags: u32 = std.posix.SOCK.CLOEXEC;
    accept_flags |= switch (sync_hint) {
        .blocking => 0,
        .nonblocking => std.posix.SOCK.NONBLOCK,
    };

    while (true) {
        var addr: std.net.Address = .{ .any = undefined };
        var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr.any));
        const rc = if (HAVE_ACCEPT4)
            std.posix.system.accept4(
                tcp_server.stream.handle,
                &addr.any,
                &addr_len,
                accept_flags,
            )
        else
            std.posix.system.accept(
                tcp_server.stream.handle,
                &addr.any,
                &addr_len,
            );

        return switch (try handleAcceptResult(std.posix.errno(rc))) {
            .intr => continue,
            .conn_aborted => error.ConnectionAborted,
            .proto_fail => error.ProtocolFailure,
            .again => error.WouldBlock,
            .success => .{
                .stream = .{ .handle = rc },
                .address = addr,
            },
        };
    }
}

pub const SetSocketSyncError = std.posix.FcntlError;

/// Ensure the socket is set to be blocking or nonblocking.
pub fn setSocketSync(
    socket: std.posix.socket_t,
    sync: enum { blocking, nonblocking },
) SetSocketSyncError!void {
    const FlagsInt = @typeInfo(std.posix.O).Struct.backing_integer.?;
    var flags_int: FlagsInt = @intCast(try std.posix.fcntl(socket, std.posix.F.GETFL, 0));
    const flags = std.mem.bytesAsValue(std.posix.O, std.mem.asBytes(&flags_int));

    const nonblock_wanted = switch (sync) {
        .blocking => false,
        .nonblocking => true,
    };
    if (flags.NONBLOCK != nonblock_wanted) {
        flags.NONBLOCK = nonblock_wanted;
        _ = try std.posix.fcntl(socket, std.posix.F.SETFL, flags_int);
    }
}

pub const HandleAcceptError = error{
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    BlockedByFirewall,
} || std.posix.UnexpectedError;

pub const HandleAcceptResult = enum {
    success,
    intr,
    again,
    conn_aborted,
    proto_fail,
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
        .PROTO => .proto_fail,

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

pub const HandleSendError = error{
    AccessDenied,
    FastOpenAlreadyInProgress,
    MessageTooBig,
    SystemResources,
    NetworkSubsystemFailed,
} || std.posix.UnexpectedError;

pub const HandleSendResult = enum {
    success,
    intr,
    again,
    conn_reset,
    broken_pipe,
};

pub fn handleSendResult(
    /// Must be the result of `std.posix.send` or equivalent (ie io_uring cqe.err()).
    rc: std.posix.E,
) HandleSendError!HandleSendResult {
    comptime std.debug.assert( //
        builtin.target.isDarwin() or builtin.target.os.tag == .linux //
    );
    return switch (rc) {
        .SUCCESS => .success,
        .INTR => .intr,
        .AGAIN => .again,
        .CONNRESET => .conn_reset,
        .PIPE => .broken_pipe,

        .BADF, // always a race condition
        .DESTADDRREQ, // The socket is not connection-mode, and no peer address is set.
        .FAULT, // An invalid user space address was specified for an argument.
        .ISCONN, // connection-mode socket was connected already but a recipient was specified
        .NOTSOCK, // The file descriptor sockfd does not refer to a socket.
        .OPNOTSUPP, // Some bit in the flags argument is inappropriate for the socket type.

        // these are all reachable through `sendto`, but unreachable through `send`.
        .AFNOSUPPORT,
        .LOOP,
        .NAMETOOLONG,
        .NOENT,
        .NOTDIR,
        .HOSTUNREACH,
        .NETUNREACH,
        .NOTCONN,
        .INVAL,
        => |e| std.debug.panic("{s}", .{@tagName(e)}),

        .ACCES => return error.AccessDenied,
        .ALREADY => return error.FastOpenAlreadyInProgress,
        .MSGSIZE => return error.MessageTooBig,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .NETDOWN => return error.NetworkSubsystemFailed,
        else => |e| std.posix.unexpectedErrno(e),
    };
}

pub const HandleSpliceError = error{
    SystemResources,
} || std.posix.UnexpectedError;

pub const HandleSpliceResult = enum {
    success,
    again,
    /// One or both file descriptors are not valid, or do not have proper read-write mode.
    bad_file_descriptors,
    /// Either off_in or off_out was not NULL, but the corresponding file descriptor refers to a pipe.
    bad_fd_offset,
    /// Could be one of many reasons, see the manpage for splice.
    invalid_splice,
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
        .INVAL => .invalid_splice,
        .SPIPE => .bad_fd_offset,
        .BADF => .bad_file_descriptors,
        .NOMEM => return error.SystemResources,
        else => |err| std.posix.unexpectedErrno(err),
    };
}
