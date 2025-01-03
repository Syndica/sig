const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const Vm = @import("Vm.zig");
const Executable = @import("Executable.zig");

const Pubkey = sig.core.Pubkey;

// logging
pub fn printString(vm: *Vm) Executable.SyscallError!void {
    const vm_addr = vm.registers.get(.r1);
    const len = vm.registers.get(.r2);
    const host_addr = try vm.memory_map.vmap(.constant, vm_addr, len);
    const string = std.mem.sliceTo(host_addr, 0);
    if (!builtin.is_test) std.debug.print("{s}", .{string});
}

pub fn log(vm: *Vm) Executable.SyscallError!void {
    const vm_addr = vm.registers.get(.r1);
    const len = vm.registers.get(.r2);
    const host_addr = try vm.memory_map.vmap(.constant, vm_addr, len);
    std.debug.print("log: {s}\n", .{host_addr});
}

pub fn log64(vm: *Vm) Executable.SyscallError!void {
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

pub fn logPubkey(vm: *Vm) Executable.SyscallError!void {
    const pubkey_addr = vm.registers.get(.r1);
    const pubkey_bytes = try vm.memory_map.vmap(.constant, pubkey_addr, @sizeOf(Pubkey));
    const pubkey: Pubkey = @bitCast(pubkey_bytes[0..@sizeOf(Pubkey)].*);
    std.debug.print("log: {}\n", .{pubkey});
}

pub fn logComputeUnits(_: *Vm) Executable.SyscallError!void {
    std.debug.print("TODO: compute budget calculations\n", .{});
}

// memory operators
pub fn memset(vm: *Vm) Executable.SyscallError!void {
    const dst_addr = vm.registers.get(.r1);
    const scalar = vm.registers.get(.r2);
    const len = vm.registers.get(.r3);

    const host_addr = try vm.memory_map.vmap(.mutable, dst_addr, len);
    @memset(host_addr, @truncate(scalar));
}

pub fn memcpy(vm: *Vm) Executable.SyscallError!void {
    const dst_addr = vm.registers.get(.r1);
    const src_addr = vm.registers.get(.r2);
    const len = vm.registers.get(.r3);

    const dst_host = try vm.memory_map.vmap(.mutable, dst_addr, len);
    const src_host = try vm.memory_map.vmap(.constant, src_addr, len);
    @memcpy(dst_host, src_host);
}

// special
pub fn abort(_: *Vm) Executable.SyscallError!void {
    return error.SyscallAbort;
}
