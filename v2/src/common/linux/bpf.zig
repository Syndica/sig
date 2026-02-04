const std = @import("std");

const SECCOMP = std.os.linux.SECCOMP;
const syscalls = std.os.linux.syscalls.X64;

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
pub fn printSleepExit(maybe_stderr: ?std.os.linux.fd_t) [33]sock_filter {
    // load syscall number
    const preamble = .{stmt(LD + W + ABS, @offsetOf(SECCOMP.data, "nr"))};

    const syscall_fd_filters = if (maybe_stderr) |stderr_fd| blk: {
        const stderr = std.math.cast(u32, stderr_fd) orelse
            std.debug.panic("Negative fd supplied? {}\n", .{stderr_fd});

        break :blk allowSyscallOnFd(@intFromEnum(syscalls.write), stderr) ++
            allowSyscallOnFd(@intFromEnum(syscalls.writev), stderr) ++
            allowSyscallOnFd(@intFromEnum(syscalls.pwritev), stderr);
    } else
        // forward unconditional + noops
        .{jump(JMP, 0, 14, 14)} ++ .{jump(JMP, 0, 0, 0)} ** 14;

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
