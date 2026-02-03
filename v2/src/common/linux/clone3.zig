const std = @import("std");

// zig fmt: off
pub const Flags = packed struct(u64) { 
    _unused_0_6    :u7   = 0    , // 0..=6
    newtime        :bool = false, // 7
    vm             :bool = false, // 8
    fs             :bool = false, // 9
    files          :bool = false, // 10
    sighand        :bool = false, // 11
    pidfd          :bool = false, // 12
    ptrace         :bool = false, // 13
    vfork          :bool = false, // 14
    parent         :bool = false, // 15
    thread         :bool = false, // 16
    newns          :bool = false, // 17
    sysvsem        :bool = false, // 18
    settls         :bool = false, // 19
    parent_settid  :bool = false, // 20
    child_cleartid :bool = false, // 21
    detached       :bool = false, // 22
    untraced       :bool = false, // 23
    child_settid   :bool = false, // 24
    newcgroup      :bool = false, // 25
    newuts         :bool = false, // 26
    newipc         :bool = false, // 27
    newuser        :bool = false, // 28
    newpid         :bool = false, // 29
    newnet         :bool = false, // 30
    io             :bool = false, // 31
    clear_sighand  :bool = false, // 32
    into_cgroup    :bool = false, // 33
    _unused_34_64  :u30  = 0    , // 34..=64
};
// zig fmt: on

comptime {
    const expectEqual = std.testing.expectEqual;

    expectEqual(0x00000080, @as(u64, @bitCast(Flags{ .newtime = true }))) catch unreachable;
    expectEqual(0x00000100, @as(u64, @bitCast(Flags{ .vm = true }))) catch unreachable;
    expectEqual(0x00000200, @as(u64, @bitCast(Flags{ .fs = true }))) catch unreachable;
    expectEqual(0x00000400, @as(u64, @bitCast(Flags{ .files = true }))) catch unreachable;
    expectEqual(0x00000800, @as(u64, @bitCast(Flags{ .sighand = true }))) catch unreachable;
    expectEqual(0x00001000, @as(u64, @bitCast(Flags{ .pidfd = true }))) catch unreachable;
    expectEqual(0x00002000, @as(u64, @bitCast(Flags{ .ptrace = true }))) catch unreachable;
    expectEqual(0x00004000, @as(u64, @bitCast(Flags{ .vfork = true }))) catch unreachable;
    expectEqual(0x00008000, @as(u64, @bitCast(Flags{ .parent = true }))) catch unreachable;
    expectEqual(0x00010000, @as(u64, @bitCast(Flags{ .thread = true }))) catch unreachable;
    expectEqual(0x00020000, @as(u64, @bitCast(Flags{ .newns = true }))) catch unreachable;
    expectEqual(0x00040000, @as(u64, @bitCast(Flags{ .sysvsem = true }))) catch unreachable;
    expectEqual(0x00080000, @as(u64, @bitCast(Flags{ .settls = true }))) catch unreachable;
    expectEqual(0x00100000, @as(u64, @bitCast(Flags{ .parent_settid = true }))) catch unreachable;
    expectEqual(0x00200000, @as(u64, @bitCast(Flags{ .child_cleartid = true }))) catch unreachable;
    expectEqual(0x00400000, @as(u64, @bitCast(Flags{ .detached = true }))) catch unreachable;
    expectEqual(0x00800000, @as(u64, @bitCast(Flags{ .untraced = true }))) catch unreachable;
    expectEqual(0x01000000, @as(u64, @bitCast(Flags{ .child_settid = true }))) catch unreachable;
    expectEqual(0x02000000, @as(u64, @bitCast(Flags{ .newcgroup = true }))) catch unreachable;
    expectEqual(0x04000000, @as(u64, @bitCast(Flags{ .newuts = true }))) catch unreachable;
    expectEqual(0x08000000, @as(u64, @bitCast(Flags{ .newipc = true }))) catch unreachable;
    expectEqual(0x10000000, @as(u64, @bitCast(Flags{ .newuser = true }))) catch unreachable;
    expectEqual(0x20000000, @as(u64, @bitCast(Flags{ .newpid = true }))) catch unreachable;
    expectEqual(0x40000000, @as(u64, @bitCast(Flags{ .newnet = true }))) catch unreachable;
    expectEqual(0x80000000, @as(u64, @bitCast(Flags{ .io = true }))) catch unreachable;
    expectEqual(0x100000000, @as(u64, @bitCast(Flags{ .clear_sighand = true }))) catch unreachable;
    expectEqual(0x200000000, @as(u64, @bitCast(Flags{ .into_cgroup = true }))) catch unreachable;
}

/// original:
///
/// struct __clone_args {
///     __aligned_u64 flags;
///     __aligned_u64 pidfd;
///     __aligned_u64 child_tid;
///     __aligned_u64 parent_tid;
///     __aligned_u64 exit_signal;
///     __aligned_u64 stack;
///     __aligned_u64 stack_size;
///     __aligned_u64 tls;
///     __aligned_u64 set_tid;
///     __aligned_u64 set_tid_size;
///     __aligned_u64 cgroup;
/// };
pub const Args = extern struct {
    /// Flags bit mask
    flags: Flags = Flags{},
    /// Where to store PID file descriptor
    pidfd: ?*std.posix.fd_t = null,
    /// Where to store child TID, in child's memory
    child_id: ?*std.posix.pid_t = null,

    parent_tid: ?*std.posix.pid_t = null,
    /// Signal to deliver to parent on child termination
    exit_signal: u64 = 0,
    /// Pointer to lowest byte of stack
    stack: ?*const anyopaque = null,
    /// Size of stack
    stack_size: u64 = 0,
    // Location of new TLS
    tls: ?*anyopaque = null,
    /// Pointer to a pid_t array
    set_tid: ?[*]std.posix.pid_t = null,
    /// Number of elements in set_tid
    set_tid_size: u64 = 0,
    /// File descriptor for target cgroup of child
    cgroup: u64 = 0,
};

pub fn clone3(args: *const Args) ?i32 {
    const ret = std.os.linux.syscall2(.clone3, @intFromPtr(args), @sizeOf(Args));
    const err = std.os.linux.E.init(ret);
    if (err != .SUCCESS) std.debug.panic("clone3 err: {}", .{err});

    if (ret == 0) return null; // child
    return @intCast(ret); // child's pid
}
