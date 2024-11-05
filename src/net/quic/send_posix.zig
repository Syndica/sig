const std = @import("std");

// zig stdlib does not define the msghdr{_const} for macos.
pub const msghdr_const = extern struct {
    name: ?*const std.posix.sockaddr,
    namelen: std.posix.socklen_t,
    iov: [*]const std.posix.iovec_const,
    iovlen: usize,
    control: ?*const anyopaque,
    controllen: usize,
    flags: i32,
};

extern "c" fn sendmsg(sockfd: std.posix.fd_t, msg: *const msghdr_const, flags: u32) isize;

pub fn sendmsgPosix(
    /// The file descriptor of the sending socket.
    sockfd: std.posix.fd_t,
    /// Message header and iovecs
    msg: *const msghdr_const,
    flags: u32,
) std.posix.SendMsgError!usize {
    while (true) {
        const rc = sendmsg(sockfd, msg, flags);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .ACCES => return error.AccessDenied,
            .AGAIN => return error.WouldBlock,
            .ALREADY => return error.FastOpenAlreadyInProgress,
            .BADF => unreachable, // always a race condition
            .CONNRESET => return error.ConnectionResetByPeer,
            .DESTADDRREQ => unreachable, // The socket is not connection-mode, and no peer address is set.
            .FAULT => unreachable, // An invalid user space address was specified for an argument.
            .INTR => continue,
            .INVAL => unreachable, // Invalid argument passed.
            .ISCONN => unreachable, // connection-mode socket was connected already but a recipient was specified
            .MSGSIZE => return error.MessageTooBig,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
            .OPNOTSUPP => unreachable, // Some bit in the flags argument is inappropriate for the socket type.
            .PIPE => return error.BrokenPipe,
            .AFNOSUPPORT => return error.AddressFamilyNotSupported,
            .LOOP => return error.SymLinkLoop,
            .NAMETOOLONG => return error.NameTooLong,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDir,
            .HOSTUNREACH => return error.NetworkUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NOTCONN => return error.SocketNotConnected,
            .NETDOWN => return error.NetworkSubsystemFailed,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}
