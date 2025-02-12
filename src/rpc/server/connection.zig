const builtin = @import("builtin");
const std = @import("std");

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
