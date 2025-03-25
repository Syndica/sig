//! Root of the SDK

const std = @import("std");
const sig = @import("sig");
const builtin = @import("builtin");
pub const poseidon = @import("poseidon.zig");
pub const serial = @import("serial.zig");

/// "v0" is a Solana idea, Zig can't represent it. So we use v1 instead.
const is_sbpfv0 = std.mem.eql(u8, builtin.cpu.model.name, "v1");
pub const deserialize = serial.deserialize;

const sbpf = sig.vm.sbpf;
const Pubkey = sig.core.Pubkey;

pub const SolBytes = extern struct {
    addr: [*]const u8,
    len: u64,
};

pub const SolAccountInfo = extern struct {
    key: *Pubkey,
    lamports: *u64,
    data_len: u64,
    data: [*]const u8,
    owner: *Pubkey,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
};

pub const SolParameters = extern struct {
    account_info: [*]SolAccountInfo,
    /// Number of accounts in `account_info`.
    num_accounts: u64,
    /// The instruction data.
    data: [*]const u8,
    /// Length in byte of the instruction data.
    data_len: u64,
    /// `program_id` of the currently executing program.
    program_id: *const Pubkey,
};

const syscall_map = std.StaticStringMap(type).initComptime(&.{
    .{ "sol_panic_", fn ([*]const u8, u64, u64, u64) void },
    .{ "sol_poseidon", fn (
        parameters: u64,
        endianness: u64,
        bytes: [*]const SolBytes,
        bytes_len: u64,
        result: [*]u8,
    ) void },
    .{ "abort", fn () noreturn },
    .{ "sol_log_", fn (msg: [*]const u8, len: u64) void },
});

fn SyscallType(comptime name: []const u8) type {
    const ty = syscall_map.get(name) orelse @compileError("unknown syscall: " ++ name);
    if (is_sbpfv0) {
        var ti = @typeInfo(ty);
        ti.Fn.calling_convention = .C;
        return @Type(ti);
    } else return ty;
}

pub inline fn defineSyscall(
    comptime name: []const u8,
) *align(1) const SyscallType(name) {
    comptime {
        if (std.mem.eql(u8, builtin.cpu.model.name, "v1")) {
            return @extern(*const SyscallType(name), .{ .name = name });
        } else {
            const hash = sbpf.hashSymbolName(name);
            return @ptrFromInt(hash);
        }
    }
}
