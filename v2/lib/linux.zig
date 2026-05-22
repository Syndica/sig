const std = @import("std");

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

pub const memfd = struct {
    const linux = std.os.linux;
    const E = linux.E;
    const e = E.init;
    const page_size_min = std.heap.page_size_min;

    pub const RW = extern struct {
        fd: linux.fd_t,
        size: usize,

        pub const empty: RW = .{ .fd = -1, .size = 0 };

        pub const Args = struct {
            name: [:0]const u8,
            size: usize,
        };

        pub fn init(args: Args) !RW {
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

        pub const mmap = mmapInner;
    };

    pub const RO = extern struct {
        fd: linux.fd_t,
        size: usize,

        pub const empty: RO = .{ .fd = -1, .size = 0 };

        pub fn fromRW(rw: RW) !RO {
            var buf: [100]u8 = undefined;
            const path = try std.fmt.bufPrint(&buf, "/proc/self/fd/{}", .{rw.fd});
            const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });

            return .{
                .fd = file.handle,
                .size = rw.size,
            };
        }

        pub const mmap = mmapInner;
    };

    fn mmapInner(self: anytype, ptr: ?[*]align(page_size_min) u8) ![]align(page_size_min) u8 {
        const access = switch (@TypeOf(self)) {
            *const RW, *RW, RW => linux.PROT.READ | linux.PROT.WRITE,
            *const RO, *RO, RO => linux.PROT.READ,
            else => @compileError("unsupported type"),
        };

        return try std.posix.mmap(
            ptr,
            self.size,
            access,
            .{ .TYPE = .SHARED },
            self.fd,
            0,
        );
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

    /// Configuration for a single allowed syscall in a per-service seccomp filter.
    /// Each entry allows one syscall, optionally restricted by arg0 value.
    ///
    /// Ref: [REF-SECCOMP-MAN] https://man7.org/linux/man-pages/man2/seccomp.2.html
    ///      struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; }
    pub const SyscallConfig = struct {
        syscall: std.os.linux.SYS,
        arg0: ArgMatch = .anything,

        pub const ArgMatch = union(enum) {
            /// Allow this syscall unconditionally (no argument checking).
            anything,
            /// Allow this syscall only when arg0 equals this value.
            only: usize,
        };

        /// Number of BPF instructions this config generates.
        /// Unconditional allow = 2 (JEQ + RET ALLOW).
        /// Arg0-restricted = 5 (JEQ + LD arg0 + JEQ + RET ALLOW + RET DENY).
        pub fn instrCount(self: SyscallConfig) usize {
            return switch (self.arg0) {
                .anything => 2,
                .only => 5,
            };
        }
    };

    /// Base syscalls every service gets. These provide minimal process lifecycle
    /// support per the sandboxing model:
    /// - clock_nanosleep: std.Thread.sleep on Linux x86-64 (Zig 0.15.2)
    /// - exit/exit_group: process termination
    ///
    /// Note: write/writev to stderr are handled separately with fd-restriction.
    pub const base_syscall_configs: []const SyscallConfig = &.{
        .{ .syscall = .clock_nanosleep },
        .{ .syscall = .exit },
        .{ .syscall = .exit_group },
    };

    /// Compute total BPF instruction count for a per-service seccomp filter.
    ///
    /// Layout: preamble(1) + base_rules + service_rules + stderr_rules(10) + deny(1)
    ///
    /// - preamble: LD ABS seccomp_data.nr (1 instruction)
    /// - base_rules: base_syscall_configs entries (always unconditional = 2 each)
    /// - service_rules: service-specific entries (2 or 5 each depending on arg0)
    /// - stderr_rules: write + writev fd-restricted to stderr (2 × 5 = 10)
    /// - deny: RET TRAP fallthrough (1 instruction)
    ///
    /// Max BPF instructions per filter: 4096 (BPF_MAXINSNS) [REF-SECCOMP-MAN].
    pub fn computeFilterLen(comptime service_configs: []const SyscallConfig) comptime_int {
        var len: usize = 1; // preamble: LD ABS seccomp_data.nr
        for (base_syscall_configs) |cfg| len += cfg.instrCount();
        for (service_configs) |cfg| len += cfg.instrCount();
        len += 10; // stderr write + writev (2 × allowSyscallOnFd = 2 × 5)
        len += 1; // fall-through: RET TRAP
        return len;
    }

    /// Compute total BPF instruction count for a comptime config slice.
    fn comptimeRulesLen(comptime configs: []const SyscallConfig) comptime_int {
        var len: usize = 0;
        for (configs) |cfg| len += cfg.instrCount();
        return len;
    }

    /// Generate BPF instructions for a comptime-known slice of SyscallConfigs.
    /// Each unconditional entry produces 2 instructions (JEQ + RET ALLOW).
    /// Each arg0-restricted entry produces 5 instructions (JEQ + LD arg0 + JEQ + RET ALLOW + RET DENY).
    ///
    /// The accumulator is preserved (holds syscall NR) through skipped blocks because:
    /// - If syscall matches: block terminates with RET (no fall-through)
    /// - If syscall doesn't match: JEQ jumps over entire block, accumulator unchanged
    fn genRules(comptime configs: []const SyscallConfig) [comptimeRulesLen(configs)]sock_filter {
        comptime var result: [comptimeRulesLen(configs)]sock_filter = undefined;
        comptime var offset: usize = 0;
        inline for (configs) |cfg| {
            switch (cfg.arg0) {
                .anything => {
                    result[offset] = jump(JMP | JEQ | K, @intFromEnum(cfg.syscall), 0, 1);
                    result[offset + 1] = stmt(RET | K, SECCOMP.RET.ALLOW);
                    offset += 2;
                },
                .only => |val| {
                    result[offset] = jump(JMP | JEQ | K, @intFromEnum(cfg.syscall), 0, 4);
                    result[offset + 1] = stmt(LD + W + ABS, @offsetOf(SECCOMP.data, "arg0"));
                    result[offset + 2] = jump(JMP | JEQ | K, @intCast(val), 0, 1);
                    result[offset + 3] = stmt(RET | K, SECCOMP.RET.ALLOW);
                    result[offset + 4] = stmt(RET | K, default_deny_action);
                    offset += 5;
                },
            }
        }
        return result;
    }

    /// Generate a per-service seccomp BPF filter.
    ///
    /// Base rules (exit, exit_group, clock_nanosleep) are always included.
    /// stderr write/writev are fd-restricted to the given fd.
    /// All other syscalls are denied with SECCOMP_RET_TRAP (delivers SIGSYS).
    ///
    /// Ref: [REF-SECCOMP-MAN] https://man7.org/linux/man-pages/man2/seccomp.2.html
    ///      for seccomp_data layout and BPF semantics.
    /// Ref: [REF-SECCOMP-KERNEL] https://docs.kernel.org/userspace-api/seccomp_filter.html
    ///      for filter installation requirements.
    pub fn serviceFilter(
        comptime service_configs: []const SyscallConfig,
        maybe_stderr: ?std.os.linux.fd_t,
    ) [computeFilterLen(service_configs)]sock_filter {
        // Load syscall number into accumulator
        const preamble = .{stmt(LD + W + ABS, @offsetOf(SECCOMP.data, "nr"))};

        // Base rules: always-allowed syscalls (comptime)
        const base_rules = comptime genRules(base_syscall_configs);

        // Service-specific rules (comptime)
        const svc_rules = comptime genRules(service_configs);

        // Stderr fd-restricted rules (runtime fd value)
        const stderr_rules = if (maybe_stderr) |fd| blk: {
            const stderr: u32 = std.math.cast(u32, fd) orelse
                std.debug.panic("Negative fd: {}", .{fd});
            break :blk allowSyscallOnFd(@intFromEnum(syscalls.write), stderr) ++
                allowSyscallOnFd(@intFromEnum(syscalls.writev), stderr);
        } else
            // No stderr: fill with nops to maintain constant array size
            .{jump(JMP, 0, 9, 9)} ++ .{jump(JMP, 0, 0, 0)} ** 9;

        // Deny all unmatched syscalls with SIGSYS
        const deny = .{stmt(RET + K, default_deny_action)};

        return preamble ++ base_rules ++ svc_rules ++ stderr_rules ++ deny;
    }

    /// Only allows writing to stderr, sleeping, and exiting.
    pub fn printSleepExit(maybe_stderr: ?std.os.linux.fd_t) [64]sock_filter {
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
            allowSyscall(@intFromEnum(syscalls.mmap)) ++
            allowSyscall(@intFromEnum(syscalls.munmap)) ++
            allowSyscall(@intFromEnum(syscalls.openat)) ++
            allowSyscall(@intFromEnum(syscalls.getdents64)) ++
            allowSyscall(@intFromEnum(syscalls.mkdirat)) ++
            allowSyscall(@intFromEnum(syscalls.lseek)) ++
            allowSyscall(@intFromEnum(syscalls.pipe2)) ++
            allowSyscall(@intFromEnum(syscalls.renameat)) ++
            allowSyscall(@intFromEnum(syscalls.unlinkat)) ++
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

// Tests for SyscallConfig, instrCount, and computeFilterLen
const testing = std.testing;

test "SyscallConfig.instrCount: unconditional returns 2" {
    const cfg: bpf.SyscallConfig = .{ .syscall = .exit };
    try testing.expectEqual(@as(usize, 2), cfg.instrCount());
}

test "SyscallConfig.instrCount: arg0-restricted returns 5" {
    const cfg: bpf.SyscallConfig = .{ .syscall = .write, .arg0 = .{ .only = 2 } };
    try testing.expectEqual(@as(usize, 5), cfg.instrCount());
}

test "base_syscall_configs has 3 entries" {
    try testing.expectEqual(@as(usize, 3), bpf.base_syscall_configs.len);
}

test "base_syscall_configs entries are all unconditional" {
    for (bpf.base_syscall_configs) |cfg| {
        try testing.expectEqual(@as(usize, 2), cfg.instrCount());
    }
}

test "base_syscall_configs contains expected syscalls" {
    const configs = bpf.base_syscall_configs;
    try testing.expectEqual(std.os.linux.SYS.clock_nanosleep, configs[0].syscall);
    try testing.expectEqual(std.os.linux.SYS.exit, configs[1].syscall);
    try testing.expectEqual(std.os.linux.SYS.exit_group, configs[2].syscall);
}

test "computeFilterLen: empty service list" {
    // preamble(1) + base(3×2=6) + service(0) + stderr(10) + deny(1) = 18
    const len = comptime bpf.computeFilterLen(&.{});
    try testing.expectEqual(18, len);
}

test "computeFilterLen: with unconditional entries" {
    // preamble(1) + base(6) + service(2×2=4) + stderr(10) + deny(1) = 22
    const configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .socket },
        .{ .syscall = .bind },
    };
    const len = comptime bpf.computeFilterLen(configs);
    try testing.expectEqual(22, len);
}

test "computeFilterLen: with arg0-restricted entries" {
    // preamble(1) + base(6) + service(5×2=10) + stderr(10) + deny(1) = 28
    const configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .read, .arg0 = .{ .only = 0 } },
        .{ .syscall = .write, .arg0 = .{ .only = 1 } },
    };
    const len = comptime bpf.computeFilterLen(configs);
    try testing.expectEqual(28, len);
}

test "computeFilterLen: mixed unconditional and arg0-restricted" {
    // preamble(1) + base(6) + service(2+5=7) + stderr(10) + deny(1) = 25
    const configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .socket },
        .{ .syscall = .write, .arg0 = .{ .only = 3 } },
    };
    const len = comptime bpf.computeFilterLen(configs);
    try testing.expectEqual(25, len);
}

test "computeFilterLen: all services under BPF_MAXINSNS (4096)" {
    // Largest expected service is snapshot with 13 unconditional entries:
    // preamble(1) + base(6) + service(13×2=26) + stderr(10) + deny(1) = 44
    const snapshot_configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .io_uring_setup },
        .{ .syscall = .io_uring_enter },
        .{ .syscall = .mmap },
        .{ .syscall = .munmap },
        .{ .syscall = .socket },
        .{ .syscall = .pipe2 },
        .{ .syscall = .close },
        .{ .syscall = .openat },
        .{ .syscall = .mkdirat },
        .{ .syscall = .getdents64 },
        .{ .syscall = .lseek },
        .{ .syscall = .renameat },
        .{ .syscall = .unlinkat },
    };
    const len = comptime bpf.computeFilterLen(snapshot_configs);
    try testing.expectEqual(44, len);
    try testing.expect(len < 4096); // BPF_MAXINSNS
}

test "computeFilterLen: net service (5 entries)" {
    const net_configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .socket },
        .{ .syscall = .bind },
        .{ .syscall = .sendto },
        .{ .syscall = .recvfrom },
        .{ .syscall = .close },
    };
    // preamble(1) + base(6) + service(5×2=10) + stderr(10) + deny(1) = 28
    const len = comptime bpf.computeFilterLen(net_configs);
    try testing.expectEqual(28, len);
}

test "computeFilterLen: replay/shred_receiver (0 entries) equals minimal" {
    const empty: []const bpf.SyscallConfig = &.{};
    const len = comptime bpf.computeFilterLen(empty);
    try testing.expectEqual(18, len);
}

// Tests for serviceFilter

test "serviceFilter: empty config produces valid minimal filter" {
    const filter = bpf.serviceFilter(&.{}, 2);
    // Length = 18 (preamble + base + stderr + deny)
    try testing.expectEqual(18, filter.len);
    // First instruction: LD ABS seccomp_data.nr
    try testing.expectEqual(bpf.LD + bpf.W + bpf.ABS, filter[0].code);
    try testing.expectEqual(@offsetOf(std.os.linux.SECCOMP.data, "nr"), filter[0].k);
    // Last instruction: RET TRAP
    try testing.expectEqual(bpf.RET + bpf.K, filter[filter.len - 1].code);
    try testing.expectEqual(std.os.linux.SECCOMP.RET.TRAP, filter[filter.len - 1].k);
}

test "serviceFilter: includes base syscalls (clock_nanosleep, exit, exit_group)" {
    const filter = bpf.serviceFilter(&.{}, 2);
    // Instructions 1-2: clock_nanosleep
    try testing.expectEqual(bpf.JMP | bpf.JEQ | bpf.K, filter[1].code);
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.clock_nanosleep), filter[1].k);
    try testing.expectEqual(bpf.RET | bpf.K, filter[2].code);
    try testing.expectEqual(std.os.linux.SECCOMP.RET.ALLOW, filter[2].k);
    // Instructions 3-4: exit
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.exit), filter[3].k);
    try testing.expectEqual(std.os.linux.SECCOMP.RET.ALLOW, filter[4].k);
    // Instructions 5-6: exit_group
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.exit_group), filter[5].k);
    try testing.expectEqual(std.os.linux.SECCOMP.RET.ALLOW, filter[6].k);
}

test "serviceFilter: service-specific unconditional rules" {
    const configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .socket },
        .{ .syscall = .bind },
    };
    const filter = bpf.serviceFilter(configs, 2);
    // Service rules start after preamble(1) + base(6) = offset 7
    try testing.expectEqual(bpf.JMP | bpf.JEQ | bpf.K, filter[7].code);
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.socket), filter[7].k);
    try testing.expectEqual(std.os.linux.SECCOMP.RET.ALLOW, filter[8].k);
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.bind), filter[9].k);
    try testing.expectEqual(std.os.linux.SECCOMP.RET.ALLOW, filter[10].k);
}

test "serviceFilter: arg0-restricted rule generates 5 instructions" {
    const configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .read, .arg0 = .{ .only = 7 } },
    };
    const filter = bpf.serviceFilter(configs, 2);
    // Arg0-restricted rule starts at offset 7 (after preamble + base)
    const offset = 7;
    // [0] JEQ syscall, skip 4 on miss
    try testing.expectEqual(bpf.JMP | bpf.JEQ | bpf.K, filter[offset].code);
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.read), filter[offset].k);
    try testing.expectEqual(@as(u8, 0), filter[offset].jt); // match: fall through
    try testing.expectEqual(@as(u8, 4), filter[offset].jf); // miss: skip 4
    // [1] LD arg0
    try testing.expectEqual(bpf.LD + bpf.W + bpf.ABS, filter[offset + 1].code);
    try testing.expectEqual(@offsetOf(std.os.linux.SECCOMP.data, "arg0"), filter[offset + 1].k);
    // [2] JEQ arg0 value
    try testing.expectEqual(bpf.JMP | bpf.JEQ | bpf.K, filter[offset + 2].code);
    try testing.expectEqual(@as(u32, 7), filter[offset + 2].k);
    // [3] RET ALLOW
    try testing.expectEqual(std.os.linux.SECCOMP.RET.ALLOW, filter[offset + 3].k);
    // [4] RET DENY
    try testing.expectEqual(std.os.linux.SECCOMP.RET.TRAP, filter[offset + 4].k);
}

test "serviceFilter: null stderr produces nop jumps" {
    const filter = bpf.serviceFilter(&.{}, null);
    // Stderr rules at offset 7 (after preamble + base, no service rules)
    // First nop should be JMP with k=0
    try testing.expectEqual(bpf.JMP, filter[7].code);
    try testing.expectEqual(@as(u32, 0), filter[7].k);
}

test "serviceFilter: valid stderr produces fd-restricted write/writev" {
    const filter = bpf.serviceFilter(&.{}, 5);
    // Stderr rules start at offset 7 (after preamble + base)
    // write fd-restricted block: 5 instructions
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.write), filter[7].k);
    try testing.expectEqual(@offsetOf(std.os.linux.SECCOMP.data, "arg0"), filter[8].k);
    try testing.expectEqual(@as(u32, 5), filter[9].k); // fd = 5
    try testing.expectEqual(std.os.linux.SECCOMP.RET.ALLOW, filter[10].k);
    try testing.expectEqual(std.os.linux.SECCOMP.RET.TRAP, filter[11].k);
    // writev fd-restricted block: 5 instructions
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.writev), filter[12].k);
    try testing.expectEqual(@as(u32, 5), filter[14].k); // fd = 5
}

test "serviceFilter: filter length matches computeFilterLen" {
    const configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .socket },
        .{ .syscall = .bind },
        .{ .syscall = .close },
    };
    const filter = bpf.serviceFilter(configs, 2);
    const expected_len = comptime bpf.computeFilterLen(configs);
    try testing.expectEqual(expected_len, filter.len);
}

test "serviceFilter: net service filter (5 unconditional)" {
    const net_configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .socket },
        .{ .syscall = .bind },
        .{ .syscall = .sendto },
        .{ .syscall = .recvfrom },
        .{ .syscall = .close },
    };
    const filter = bpf.serviceFilter(net_configs, 2);
    try testing.expectEqual(28, filter.len);
    // All service rules should be JEQ+RET pairs
    var i: usize = 7; // start of service rules
    while (i < 7 + 10) : (i += 2) { // 5 rules × 2 instructions
        try testing.expectEqual(bpf.JMP | bpf.JEQ | bpf.K, filter[i].code);
        try testing.expectEqual(bpf.RET | bpf.K, filter[i + 1].code);
    }
}

test "serviceFilter: snapshot service filter (13 unconditional)" {
    const snapshot_configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .io_uring_setup },
        .{ .syscall = .io_uring_enter },
        .{ .syscall = .mmap },
        .{ .syscall = .munmap },
        .{ .syscall = .socket },
        .{ .syscall = .pipe2 },
        .{ .syscall = .close },
        .{ .syscall = .openat },
        .{ .syscall = .mkdirat },
        .{ .syscall = .getdents64 },
        .{ .syscall = .lseek },
        .{ .syscall = .renameat },
        .{ .syscall = .unlinkat },
    };
    const filter = bpf.serviceFilter(snapshot_configs, 2);
    try testing.expectEqual(44, filter.len);
}

test "serviceFilter: replay/shred_receiver get minimal filter (18 instructions)" {
    const filter = bpf.serviceFilter(&.{}, 2);
    try testing.expectEqual(18, filter.len);
}

test "serviceFilter: deny action is SECCOMP_RET_TRAP" {
    const filter = bpf.serviceFilter(&.{}, 2);
    const last = filter[filter.len - 1];
    try testing.expectEqual(bpf.RET + bpf.K, last.code);
    try testing.expectEqual(std.os.linux.SECCOMP.RET.TRAP, last.k);
}

test "serviceFilter: all instructions have valid BPF opcodes" {
    const filter = bpf.serviceFilter(&.{ .{ .syscall = .socket } }, 2);
    for (filter) |insn| {
        const cls = insn.code & 0x07;
        const valid = (cls == bpf.LD) or (cls == bpf.JMP) or (cls == bpf.RET);
        try testing.expect(valid);
    }
}

test "serviceFilter: mixed unconditional and arg0-restricted" {
    const configs: []const bpf.SyscallConfig = &.{
        .{ .syscall = .socket }, // unconditional: 2 instructions
        .{ .syscall = .write, .arg0 = .{ .only = 2 } }, // arg0-restricted: 5 instructions
        .{ .syscall = .close }, // unconditional: 2 instructions
    };
    const filter = bpf.serviceFilter(configs, 2);
    // preamble(1) + base(6) + service(2+5+2=9) + stderr(10) + deny(1) = 27
    try testing.expectEqual(27, filter.len);
    // Verify the arg0-restricted rule at offset 9 (after preamble + base + first unconditional)
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.write), filter[9].k);
    try testing.expectEqual(@as(u8, 4), filter[9].jf); // skip 4 on miss
    // Verify the third rule (close) after the arg0-restricted block
    try testing.expectEqual(@intFromEnum(std.os.linux.SYS.close), filter[14].k);
}
