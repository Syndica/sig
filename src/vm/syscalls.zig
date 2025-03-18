const std = @import("std");
const builtin = @import("builtin");
const phash = @import("poseidon");
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
    InvalidLength,
    NonCanonical,
    Unexpected,
};

// logging
pub fn log(vm: *Vm) Error!void {
    const vm_addr = vm.registers.get(.r1);
    const len = vm.registers.get(.r2);
    const host_addr = try vm.memory_map.vmap(.constant, vm_addr, len);
    const string = std.mem.sliceTo(host_addr, 0);
    vm.logger.logf(.info, "{s}", .{string});
}

pub fn log64(vm: *Vm) Error!void {
    const arg1 = vm.registers.get(.r1);
    const arg2 = vm.registers.get(.r2);
    const arg3 = vm.registers.get(.r3);
    const arg4 = vm.registers.get(.r4);
    const arg5 = vm.registers.get(.r5);

    vm.logger.logf(
        .info,
        "log: 0x{x} 0x{x} 0x{x} 0x{x} 0x{x}",
        .{ arg1, arg2, arg3, arg4, arg5 },
    );
}

pub fn logPubkey(vm: *Vm) Error!void {
    const pubkey_addr = vm.registers.get(.r1);
    const pubkey_bytes = try vm.memory_map.vmap(.constant, pubkey_addr, @sizeOf(Pubkey));
    const pubkey: Pubkey = @bitCast(pubkey_bytes[0..@sizeOf(Pubkey)].*);
    vm.logger.logf(.info, "log: {}", .{pubkey});
}

pub fn logComputeUnits(vm: *Vm) Error!void {
    vm.logger.log(.warn, "TODO: compute budget calculations");
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

pub fn memcmp(vm: *Vm) Error!void {
    const a_addr = vm.registers.get(.r1);
    const b_addr = vm.registers.get(.r2);
    const n = vm.registers.get(.r3);
    const cmp_result_addr = vm.registers.get(.r4);

    const a = try vm.memory_map.vmap(.constant, a_addr, n);
    const b = try vm.memory_map.vmap(.constant, b_addr, n);
    const cmp_result_slice = try vm.memory_map.vmap(
        .mutable,
        cmp_result_addr,
        @sizeOf(u32),
    );
    const cmp_result: *align(1) u32 = @ptrCast(cmp_result_slice.ptr);

    const result = std.mem.order(u8, a, b);
    cmp_result.* = @intFromEnum(result);
}

// hashing
const Parameters = enum(u64) {
    Bn254X5 = 0,
};

const Slice = extern struct {
    addr: [*]const u8,
    len: u64,
};

pub fn poseidon(vm: *Vm) Error!void {
    // const parameters: Parameters = @enumFromInt(vm.registers.get(.r1));
    const endianness: std.builtin.Endian = @enumFromInt(vm.registers.get(.r2));
    const addr = vm.registers.get(.r3);
    const len = vm.registers.get(.r4);
    const result_addr = vm.registers.get(.r5);

    if (len > 12) {
        return error.InvalidLength;
    }

    const hash_result = try vm.memory_map.vmap(.mutable, result_addr, 32);
    const input_bytes = try vm.memory_map.vmap(
        .constant,
        addr,
        len * @sizeOf(Slice),
    );
    const inputs = std.mem.bytesAsSlice(Slice, input_bytes);

    var hasher = phash.Hasher.init(endianness);
    for (inputs) |input| {
        const slice = try vm.memory_map.vmap(
            .constant,
            @intFromPtr(input.addr),
            input.len,
        );
        try hasher.append(slice[0..32]);
    }
    const result = try hasher.finish();
    @memcpy(hash_result, &result);
}

// special
pub fn abort(_: *Vm) Error!void {
    return error.SyscallAbort;
}

pub fn panic(vm: *Vm) Error!void {
    const file = vm.registers.get(.r1);
    const len = vm.registers.get(.r2);
    // const line = vm.registers.get(.r3);
    // const column = vm.registers.get(.r4);

    const message = try vm.memory_map.vmap(.constant, file, len);
    vm.logger.logf(.err, "panic: {s}", .{message});
    return error.SyscallAbort;
}

test poseidon {
    try testElfWithSyscalls(
        .{},
        sig.ELF_DATA_DIR ++ "poseidon_test.so",
        &.{
            .{ .name = "sol_poseidon", .builtin_fn = poseidon },
            .{ .name = "log", .builtin_fn = log },
            .{ .name = "panic", .builtin_fn = panic },
        },
        0,
    );
}
