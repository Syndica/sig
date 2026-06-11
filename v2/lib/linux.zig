const std = @import("std");

const linux = std.os.linux;
const E = linux.E;
const e = E.init;
const page_size_min = std.heap.page_size_min;

pub const clone3 = struct {
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

        // sig fmt: off
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
        // sig fmt: on
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
};

pub const Memfd = extern struct {
    fd: linux.fd_t,
    size: usize,

    pub const empty: Memfd = .{ .fd = -1, .size = 0 };

    pub const Args = struct {
        name: [:0]const u8,
        size: usize,
    };

    pub fn init(args: Args) !Memfd {
        // Create a new memfd
        const fd_rw: linux.fd_t = blk: {
            // include/uapi/linux/memfd.h
            const CLOEXEC = linux.MFD.CLOEXEC; // this fd will be closed if we ever exec
            const ALLOW_SEALING = linux.MFD.ALLOW_SEALING; // allow sealing (needed below)
            const NOEXEC_SEAL = 0x8; // create it with exec disabled *permanently*

            const fd = linux.memfd_create(args.name, CLOEXEC | ALLOW_SEALING | NOEXEC_SEAL);
            switch (e(fd)) {
                .SUCCESS => {},
                else => |err| std.debug.panic("memfd_create failed with: {t}\n", .{err}),
            }
            break :blk @intCast(fd);
        };

        // Set file to correct size
        try std.posix.ftruncate(fd_rw, args.size);

        // Make sure the file cannot be later resized.
        {
            // include/uapi/linux/fcntl.h
            const F_LINUX_SPECIFIC_BASE = 1024;
            const F_ADD_SEALS = F_LINUX_SPECIFIC_BASE + 9;
            const F_SEAL_SHRINK = 0x0002; // prevent file shrink
            const F_SEAL_GROW = 0x0004; // prevent file grow

            _ = try std.posix.fcntl(fd_rw, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW);
        }

        return .{
            .fd = fd_rw,
            .size = args.size,
        };
    }

    pub const Access = enum { rw, ro };

    pub const MapArgs = struct {
        at_ptr: ?[*]align(page_size_min) u8 = null,
        populate: bool = false,
    };

    /// If `access == .ro`, this will also create a temporary read-only file handle to the same
    /// underlying memfd, and use it to create the memory mapping. This ensures it cannot be
    /// upgraded to a read-write mapping with `mprotect`. The read-only handle is closed before
    /// returning.
    pub fn mmapRaw(
        self: Memfd,
        access: Access,
        args: MapArgs,
    ) ![]align(page_size_min) u8 {
        const prot: u32 = switch (access) {
            .rw => linux.PROT.READ | linux.PROT.WRITE,
            .ro => linux.PROT.READ,
        };

        const fd: linux.fd_t, //
        const close_fd: bool //
        = switch (access) {
            .rw => .{ self.fd, false },
            .ro => ro: {
                const path_fmt_str = "/proc/self/fd/{d}";
                const path_max_len = comptime @max(
                    std.fmt.count(path_fmt_str, .{std.math.minInt(linux.fd_t)}),
                    std.fmt.count(path_fmt_str, .{std.math.maxInt(linux.fd_t)}),
                );
                var buf: [path_max_len]u8 = undefined;
                const path = std.fmt.bufPrint(&buf, path_fmt_str, .{self.fd}) catch unreachable;
                const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
                break :ro .{ file.handle, true };
            },
        };
        defer if (close_fd) std.posix.close(fd);

        // TODO: HUGEPAGE support
        return try std.posix.mmap(
            args.at_ptr,
            self.size,
            prot,
            .{ .TYPE = .SHARED, .POPULATE = args.populate },
            fd,
            0,
        );
    }

    pub fn MapTypedArgs(comptime T: type) type {
        return struct {
            at_ptr: ?*align(page_size_min) T = null,
            populate: bool = false,
            const MapTypedArgsSelf = @This();

            fn toAny(self: MapTypedArgsSelf) MapArgs {
                return .{
                    .at_ptr = @ptrCast(self.at_ptr),
                    .populate = self.populate,
                };
            }
        };
    }

    /// Helper equivalent to `mmap`, but casts to defined-layout `T`, asserting the runtime size matches.
    /// This is to be used for mapping a structure whose entire layout is statically-known.
    pub fn mmapStaticSize(
        self: Memfd,
        access: Access,
        comptime T: type,
        args: MapTypedArgs(T),
    ) !*align(page_size_min) T {
        if (verifyIpcMmapType(T)) |err_msg| {
            @compileError(err_msg ++ " are not supported: " ++ @typeName(T));
        }
        const expected_size = @sizeOf(T);
        std.debug.assert(self.size == expected_size); // memfd size does not match mmap type
        return @ptrCast(try self.mmapRaw(access, args.toAny()));
    }

    /// Helper equivalent to `mmap`, but casts to defined-layout `T`, asserting the runtime size suffices.
    /// This is to be used for mapping a structure with a statically-sized "header" followed by runtime-sized data.
    pub fn mmapDynamicSize(
        self: Memfd,
        access: Access,
        comptime T: type,
        args: MapTypedArgs(T),
    ) !*align(page_size_min) T {
        if (verifyIpcMmapType(T)) |err_msg| {
            @compileError(err_msg ++ " are not supported: " ++ @typeName(T));
        }
        const minimum_size = @sizeOf(T);
        std.debug.assert(self.size >= minimum_size); // memfd size does not fit mmap type
        return @ptrCast(try self.mmapRaw(access, args.toAny()));
    }

    /// Returns `null` if `T` is a supported, mmapable, fixed-size type.
    /// Otherwise returns a general description of the type which can be used
    /// like `desc ++ " are not supported"`
    inline fn verifyIpcMmapType(comptime T: type) ?[]const u8 {
        comptime {
            switch (@typeInfo(T)) {
                .int => |info| if (@popCount(info.bits) != 1) {
                    return "integers with non-power of two bit sizes";
                },
                .float => |info| if (@popCount(info.bits) != 1) {
                    return "floats with non-power of two bit sizes";
                },
                .@"enum" => |info| if (@popCount(@bitSizeOf(info.tag_type)) != 1) {
                    return "enums with non-power of two bit sizes";
                },
                inline //
                .@"struct",
                .@"union",
                => |info, tag| switch (info.layout) {
                    .auto => return "auto layout " ++ @tagName(tag) ++ "s",
                    .@"packed" => if (@popCount(@bitSizeOf(info.tag_type)) != 1) {
                        return "packed structs with non-power of two bit sizes";
                    },
                    .@"extern" => {},
                },
                .array => |info| if (verifyIpcMmapType(info.child)) |child_desc| {
                    return "arrays of " ++ child_desc;
                },
                inline else => |_, tag| return @tagName(tag) ++ "s",
            }
            return null;
        }
    }
};

pub const bpf = struct {
    const SECCOMP = std.os.linux.SECCOMP;
    const syscalls = std.os.linux.SYS;

    pub const sock_filter = extern struct {
        code: u16, // filter code
        jt: u8, // jump true
        jf: u8, // jump false
        k: u32, // generic field
    };

    pub const sock_fprog = extern struct {
        len: c_ushort,
        sock_filter: [*]const sock_filter,
    };

    pub fn stmt(code: u16, k: u32) sock_filter {
        return .{ .code = code, .jt = 0, .jf = 0, .k = k };
    }
    pub fn jump(code: u16, k: u32, jt: u8, jf: u8) sock_filter {
        return .{ .code = code, .jt = jt, .jf = jf, .k = k };
    }

    pub fn allowSyscall(syscall: u32) [2]sock_filter {
        return .{
            jump(JMP | JEQ | K, syscall, 0, 1), // != syscall => skip over rule
            stmt(RET | K, SECCOMP.RET.ALLOW),
        };
    }

    const default_deny_action = SECCOMP.RET.TRAP;

    pub fn allowSyscallOnFd(syscall: u32, fd: u32) [5]sock_filter {
        const off_args0 = @offsetOf(SECCOMP.data, "arg0");
        return .{
            jump(JMP | JEQ | K, syscall, 0, 4), // != syscall => skip over rule
            stmt(LD + W + ABS, off_args0), // load args[0]
            jump(JMP | JEQ | K, fd, 0, 1), // fd != fd TRAP
            stmt(RET | K, SECCOMP.RET.ALLOW),
            stmt(RET | K, default_deny_action),
        };
    }

    /// Only allows writing to stderr, sleeping, and exiting.
    pub fn printSleepExit(maybe_stderr: ?std.os.linux.fd_t) [66]sock_filter {
        // load syscall number
        const preamble = .{stmt(LD + W + ABS, @offsetOf(SECCOMP.data, "nr"))};

        const syscall_fd_filters = if (maybe_stderr) |stderr_fd| blk: {
            const stderr = std.math.cast(u32, stderr_fd) orelse
                std.debug.panic("Negative fd supplied? {}\n", .{stderr_fd});

            break :blk allowSyscallOnFd(@intFromEnum(syscalls.write), stderr) ++
                allowSyscallOnFd(@intFromEnum(syscalls.writev), stderr);
        } else
            // forward unconditional + noops
            .{jump(JMP, 0, 9, 9)} ++ .{jump(JMP, 0, 0, 0)} ** 9;

        const fall_through = .{stmt(RET + K, default_deny_action)};

        return preamble ++
            allowSyscall(@intFromEnum(syscalls.clock_nanosleep)) ++
            allowSyscall(@intFromEnum(syscalls.exit)) ++
            allowSyscall(@intFromEnum(syscalls.exit_group)) ++
            // net tile
            allowSyscall(@intFromEnum(syscalls.sendto)) ++
            allowSyscall(@intFromEnum(syscalls.recvfrom)) ++
            allowSyscall(@intFromEnum(syscalls.close)) ++
            allowSyscall(@intFromEnum(syscalls.bind)) ++
            allowSyscall(@intFromEnum(syscalls.socket)) ++
            // telemetry
            allowSyscall(@intFromEnum(syscalls.getsockname)) ++
            allowSyscall(@intFromEnum(syscalls.listen)) ++
            allowSyscall(@intFromEnum(syscalls.accept4)) ++
            allowSyscall(@intFromEnum(syscalls.pwritev)) ++
            allowSyscall(@intFromEnum(syscalls.readv)) ++
            allowSyscall(@intFromEnum(syscalls.sendmsg)) ++
            allowSyscall(@intFromEnum(syscalls.setsockopt)) ++
            // snapshot
            allowSyscall(@intFromEnum(syscalls.io_uring_setup)) ++
            allowSyscall(@intFromEnum(syscalls.io_uring_enter)) ++
            allowSyscall(@intFromEnum(syscalls.mmap)) ++ // used by io_uring init
            allowSyscall(@intFromEnum(syscalls.munmap)) ++ // used by io_uring init
            allowSyscall(@intFromEnum(syscalls.openat)) ++
            allowSyscall(@intFromEnum(syscalls.getdents64)) ++
            allowSyscall(@intFromEnum(syscalls.mkdirat)) ++
            allowSyscall(@intFromEnum(syscalls.lseek)) ++
            allowSyscall(@intFromEnum(syscalls.pipe2)) ++
            allowSyscall(@intFromEnum(syscalls.renameat)) ++
            allowSyscall(@intFromEnum(syscalls.unlinkat)) ++
            // accounts_db
            allowSyscall(@intFromEnum(syscalls.fsync)) ++
            //
            syscall_fd_filters ++
            fall_through;
    }

    // instr classes
    pub const LD = 0x00;
    pub const LDX = 0x01;
    pub const ST = 0x02;
    pub const STX = 0x03;
    pub const ALU = 0x04;
    pub const JMP = 0x05;
    pub const RET = 0x06;
    pub const MISC = 0x07;

    // ld/ldx fields
    pub const W = 0x00;
    pub const H = 0x08;
    pub const B = 0x10;
    pub const IMM = 0x00;
    pub const ABS = 0x20;
    pub const IND = 0x40;
    pub const MEM = 0x60;
    pub const LEN = 0x80;
    pub const MSH = 0xa0;

    // alu/jmp fields
    pub const ADD = 0x00;
    pub const SUB = 0x10;
    pub const MUL = 0x20;
    pub const DIV = 0x30;
    pub const OR = 0x40;
    pub const AND = 0x50;
    pub const LSH = 0x60;
    pub const RSH = 0x70;
    pub const NEG = 0x80;
    pub const MOD = 0x90;
    pub const XOR = 0xa0;
    pub const JA = 0x00;
    pub const JEQ = 0x10;
    pub const JGT = 0x20;
    pub const JGE = 0x30;
    pub const JSET = 0x40;
    pub const K = 0x00;
    pub const X = 0x08;
};
