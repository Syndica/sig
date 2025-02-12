const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");
const lib = @import("lib.zig");

const testElfWithSyscalls = @import("tests.zig").testElfWithSyscalls;
const Vm = lib.Vm;
const Pubkey = sig.core.Pubkey;

pub const Syscall = struct {
    name: []const u8,
    builtin_fn: *const fn (*Vm) Error!void,
};

pub const Error = error{
    InvalidVirtualAddress,
    AccessNotMapped,
    SyscallAbort,
    AccessViolation,
    VirtualAccessTooLong,
    Overflow,
};

// logging
pub fn log(vm: *Vm) Error!void {
    const vm_addr = vm.registers.get(.r1);
    const len = vm.registers.get(.r2);
    const host_addr = try vm.memory_map.vmap(.constant, vm_addr, len);
    const string = std.mem.sliceTo(host_addr, 0);
    if (!builtin.is_test) std.debug.print("{x}", .{string});
}

pub fn log64(vm: *Vm) Error!void {
    const arg1 = vm.registers.get(.r1);
    const arg2 = vm.registers.get(.r2);
    const arg3 = vm.registers.get(.r3);
    const arg4 = vm.registers.get(.r4);
    const arg5 = vm.registers.get(.r5);

    std.debug.print(
        "log: 0x{x} 0x{x} 0x{x} 0x{x} 0x{x}\n",
        .{ arg1, arg2, arg3, arg4, arg5 },
    );
}

pub fn logPubkey(vm: *Vm) Error!void {
    const pubkey_addr = vm.registers.get(.r1);
    const pubkey_bytes = try vm.memory_map.vmap(.constant, pubkey_addr, @sizeOf(Pubkey));
    const pubkey: Pubkey = @bitCast(pubkey_bytes[0..@sizeOf(Pubkey)].*);
    std.debug.print("log: {}\n", .{pubkey});
}

pub fn logComputeUnits(_: *Vm) Error!void {
    std.debug.print("TODO: compute budget calculations\n", .{});
}

// memory operators
pub fn memset(vm: *Vm) Error!void {
    const dst_addr = vm.registers.get(.r1);
    const scalar = vm.registers.get(.r2);
    const len = vm.registers.get(.r3);

    const host_addr = try vm.memory_map.vmap(.mutable, dst_addr, len);
    @memset(host_addr, @truncate(scalar));
}

pub fn memcpy(vm: *Vm) Error!void {
    const dst_addr = vm.registers.get(.r1);
    const src_addr = vm.registers.get(.r2);
    const len = vm.registers.get(.r3);

    const dst_host = try vm.memory_map.vmap(.mutable, dst_addr, len);
    const src_host = try vm.memory_map.vmap(.constant, src_addr, len);
    @memcpy(dst_host, src_host);
}

// special
pub fn abort(_: *Vm) Error!void {
    return error.SyscallAbort;
}
