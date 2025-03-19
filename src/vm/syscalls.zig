const std = @import("std");
const builtin = @import("builtin");
const phash = @import("poseidon");
const sig = @import("../sig.zig");
const lib = @import("lib.zig");

const testElfWithSyscalls = @import("tests.zig").testElfWithSyscalls;
const Vm = lib.Vm;
const Pubkey = sig.core.Pubkey;

pub const Error = error{
    InvalidVirtualAddress,
    AccessNotMapped,
    SyscallAbort,
    AccessViolation,
    VirtualAccessTooLong,
    Overflow,
    Underflow,
    InvalidLength,
    NonCanonical,
    Unexpected,
    ComputationalBudgetExceeded,
} || std.fs.File.WriteError;

pub fn syscalls(Context: type) type {
    return struct {
        pub const Syscall = struct {
            name: []const u8,
            builtin_fn: *const fn (*Vm(Context)) Error!void,
        };

        // logging
        /// https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L3-L33
        pub fn log(vm: *Vm(Context)) Error!void {
            const vm_addr = vm.registers.get(.r1);
            const len = vm.registers.get(.r2);

            // https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L15-L19
            const cost = @max(vm.context.getComputeBudget().syscall_base_cost, len);
            try vm.context.consumeCompute(cost);

            const host_addr = try vm.memory_map.vmap(.constant, vm_addr, len);
            const string = std.mem.sliceTo(host_addr, 0);
            try vm.context.log("{s}", .{string});
        }

        /// https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L35-L56
        pub fn log64(vm: *Vm(Context)) Error!void {
            // https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L47-L48
            const cost = vm.context.getComputeBudget().log_64_units;
            try vm.context.consumeCompute(cost);

            const arg1 = vm.registers.get(.r1);
            const arg2 = vm.registers.get(.r2);
            const arg3 = vm.registers.get(.r3);
            const arg4 = vm.registers.get(.r4);
            const arg5 = vm.registers.get(.r5);

            try vm.context.log(
                "0x{x} 0x{x} 0x{x} 0x{x} 0x{x}",
                .{ arg1, arg2, arg3, arg4, arg5 },
            );
        }

        /// https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L82-L105
        pub fn logPubkey(vm: *Vm(Context)) Error!void {
            // https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L94-L95
            const cost = vm.context.getComputeBudget().log_pubkey_units;
            try vm.context.consumeCompute(cost);

            const pubkey_addr = vm.registers.get(.r1);
            const pubkey_bytes = try vm.memory_map.vmap(.constant, pubkey_addr, @sizeOf(Pubkey));
            const pubkey: Pubkey = @bitCast(pubkey_bytes[0..@sizeOf(Pubkey)].*);
            try vm.context.log("log: {}", .{pubkey});
        }

        /// https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L58-L80
        pub fn logComputeUnits(vm: *Vm(Context)) Error!void {
            // https://github.com/anza-xyz/agave/blob/6f95c6aec57c74e3bed37265b07f44fcc0ae8333/programs/bpf_loader/src/syscalls/logging.rs#L70-L71
            const cost = vm.context.getComputeBudget().syscall_base_cost;
            try vm.context.consumeCompute(cost);

            try vm.context.log("TODO: compute budget calculations", .{});
        }

        // memory operators

        /// https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L130-L162
        pub fn memset(vm: *Vm(Context)) Error!void {
            const dst_addr = vm.registers.get(.r1);
            const scalar = vm.registers.get(.r2);
            const len = vm.registers.get(.r3);

            // https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L142
            try consumeMemoryCompute(vm.context, len);

            const host_addr = try vm.memory_map.vmap(.mutable, dst_addr, len);
            @memset(host_addr, @truncate(scalar));
        }

        /// https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L31-L52
        pub fn memcpy(vm: *Vm(Context)) Error!void {
            const dst_addr = vm.registers.get(.r1);
            const src_addr = vm.registers.get(.r2);
            const len = vm.registers.get(.r3);

            // https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L43
            try consumeMemoryCompute(vm.context, len);

            const dst_host = try vm.memory_map.vmap(.mutable, dst_addr, len);
            const src_host = try vm.memory_map.vmap(.constant, src_addr, len);
            @memcpy(dst_host, src_host);
        }

        /// https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L72-L128
        pub fn memcmp(vm: *Vm(Context)) Error!void {
            const a_addr = vm.registers.get(.r1);
            const b_addr = vm.registers.get(.r2);
            const n = vm.registers.get(.r3);
            const cmp_result_addr = vm.registers.get(.r4);

            // https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L84
            try consumeMemoryCompute(vm.context, n);

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

        /// https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L8-L15
        fn consumeMemoryCompute(ctx: *Context, length: u64) !void {
            const budget = ctx.getComputeBudget();
            const cost = @max(budget.mem_op_base_cost, length / budget.cpi_bytes_per_unit);
            try ctx.consumeCompute(cost);
        }

        // hashing
        const Parameters = enum(u64) {
            Bn254X5 = 0,
        };

        const Slice = extern struct {
            addr: [*]const u8,
            len: u64,
        };

        pub fn poseidon(vm: *Vm(Context)) Error!void {
            // const parameters: Parameters = @enumFromInt(vm.registers.get(.r1));
            const endianness: std.builtin.Endian = @enumFromInt(vm.registers.get(.r2));
            const addr = vm.registers.get(.r3);
            const len = vm.registers.get(.r4);
            const result_addr = vm.registers.get(.r5);

            if (len > 12) {
                return error.InvalidLength;
            }

            const budget = vm.context.getComputeBudget();
            // TODO: Agave logs a specific message when this overflows.
            // https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L1923-L1926
            const cost = try budget.poseidonCost(len);
            try vm.context.consumeCompute(cost);

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
        pub fn abort(_: *Vm(Context)) Error!void {
            return error.SyscallAbort;
        }

        pub fn panic(vm: *Vm(Context)) Error!void {
            const file = vm.registers.get(.r1);
            const len = vm.registers.get(.r2);
            // const line = vm.registers.get(.r3);
            // const column = vm.registers.get(.r4);

            const message = try vm.memory_map.vmap(.constant, file, len);
            try vm.context.log("panic: {s}", .{message});
            return error.SyscallAbort;
        }

        test poseidon {
            try testElfWithSyscalls(
                .{},
                sig.ELF_DATA_DIR ++ "poseidon_test.so",
                &.{
                    .{ .name = "sol_poseidon", .builtin_fn = poseidon },
                    .{ .name = "log", .builtin_fn = log },
                    .{ .name = "sol_panic_", .builtin_fn = panic },
                },
                .{ 0, 48526 },
            );
        }
    };
}
