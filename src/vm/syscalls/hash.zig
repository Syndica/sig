//! Hashing syscalls
const std = @import("std");
const phash = @import("poseidon");
const sig = @import("../../sig.zig");

const MemoryMap = sig.vm.memory.MemoryMap;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const TransactionContext = sig.runtime.TransactionContext;
const Error = sig.vm.syscalls.Error;
const Syscall = sig.vm.syscalls.Syscall;
const SyscallError = sig.vm.SyscallError;
const memory = sig.vm.memory;

const Parameters = enum(u64) {
    Bn254X5 = 0,
};

pub fn poseidon(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const parameters = std.meta.intToEnum(Parameters, registers.get(.r1)) catch
        return error.InvalidParameters;
    std.debug.assert(parameters == .Bn254X5);
    const endianness = std.meta.intToEnum(std.builtin.Endian, registers.get(.r2)) catch
        return error.InvalidEndianness;
    const addr = registers.get(.r3);
    const len = registers.get(.r4);
    const result_addr = registers.get(.r5);

    if (len > 12) {
        try tc.log("Poseidon hashing {d} sequences is not supported", .{len});
        return error.InvalidLength;
    }

    const budget = tc.compute_budget;
    const cost = budget.poseidonCost(@intCast(len));
    try tc.consumeCompute(cost);

    const hash_result = try memory_map.translateType(
        [32]u8,
        .mutable,
        result_addr,
        tc.getCheckAligned(),
    );
    const inputs = try memory_map.translateSlice(
        memory.VmSlice,
        .constant,
        addr,
        len,
        tc.getCheckAligned(),
    );

    // We need to translateSlice all of the inputs before checking the length for zero.
    // We already know the top bound of the length is 12, so a BoundedArray works just fine.
    var slices: sig.utils.BoundedArray([]const u8, 12) = .{};
    for (inputs) |input| {
        slices.appendAssumeCapacity(try memory_map.translateSlice(
            u8,
            .constant,
            input.ptr,
            input.len,
            tc.getCheckAligned(),
        ));
    }

    if (len == 0) {
        registers.set(.r0, 1);
        return;
    }

    // Agave handles poseidon errors in an annoying way.
    // The feature SIMPLIFY_ALT_BN_128_SYSCALL_ERROR_CODES simplifies this handling.
    // It is acitvated on all clusters, we still check for activation here and panic if it is not active.
    // [agave] https://github.com/firedancer-io/agave/blob/66ea0a11f2f77086d33253b4028f6ae7083d78e4/programs/bpf_loader/src/syscalls/mod.rs#L1815-L1825
    var hasher = phash.Hasher.init(endianness);
    for (slices.constSlice()) |slice| {
        // Makes sure the input is a valid size, soft-error if it isn't.
        // [fd] https://github.com/firedancer-io/firedancer/blob/211dfccc1d84a50191a487a6abffd962f7954179/src/ballet/bn254/fd_poseidon.c#L101-L104
        if (slice.len == 0 or slice.len > 32) {
            registers.set(.r0, 1);
            return;
        }

        // If the input isn't 32-bytes long, we pad the rest with zeroes.
        var buffer: [32]u8 = .{0} ** 32;
        switch (endianness) {
            .little => @memcpy(buffer[0..slice.len], slice),
            .big => @memcpy(buffer[32 - slice.len ..], slice),
        }

        hasher.append(&buffer) catch {
            if (tc.feature_set.active(.simplify_alt_bn128_syscall_error_codes, tc.slot)) {
                registers.set(.r0, 1);
                return;
            } else @panic("SIMPLIFY_ALT_BN_128_SYSCALL_ERROR_CODES not active");
        };
    }

    const result = hasher.finish();
    @memcpy(hash_result, &result);
}

fn hashSyscall(comptime H: type) Syscall {
    const S = struct {
        fn syscall(
            tc: *TransactionContext,
            memory_map: *MemoryMap,
            registers: *RegisterMap,
        ) Error!void {
            const vals_addr = registers.get(.r1);
            const vals_len = registers.get(.r2);
            const result_addr = registers.get(.r3);

            if (tc.compute_budget.sha256_max_slices < vals_len) {
                try tc.log(
                    "{s} Hashing {} sequences in one syscall is over the limit {}",
                    .{
                        H.name,
                        vals_len,
                        tc.compute_budget.sha256_max_slices,
                    },
                );
                return SyscallError.TooManySlices;
            }

            try tc.consumeCompute(tc.compute_budget.sha256_base_cost);

            const hash_result = try memory_map.translateType(
                [32]u8,
                .mutable,
                result_addr,
                tc.getCheckAligned(),
            );

            var hasher = H.Hasher.init(.{});
            if (vals_len > 0) {
                const vals = try memory_map.translateSlice(
                    memory.VmSlice,
                    .constant,
                    vals_addr,
                    vals_len,
                    tc.getCheckAligned(),
                );

                for (vals) |val| {
                    const bytes = try memory_map.translateSlice(
                        u8,
                        .constant,
                        val.ptr,
                        val.len,
                        tc.getCheckAligned(),
                    );
                    const cost = @max(
                        tc.compute_budget.mem_op_base_cost,
                        tc.compute_budget.sha256_byte_cost *% (val.len / 2),
                    );
                    try tc.consumeCompute(cost);
                    hasher.update(bytes);
                }
            }

            hasher.final(hash_result);
        }
    };
    return S.syscall;
}

pub const sha256 = hashSyscall(struct {
    const Hasher = std.crypto.hash.sha2.Sha256;
    const name = "Sha256";
});
pub const blake3 = hashSyscall(struct {
    const Hasher = std.crypto.hash.Blake3;
    const name = "Blake3";
});
pub const keccak256 = hashSyscall(struct {
    const Hasher = std.crypto.hash.sha3.Keccak256;
    const name = "Keccak256";
});

test poseidon {
    try sig.vm.tests.testElfWithSyscalls(
        .{},
        sig.ELF_DATA_DIR ++ "poseidon_test.so",
        &.{
            .{ .name = "sol_poseidon", .builtin_fn = poseidon },
            .{ .name = "log", .builtin_fn = sig.vm.syscalls.log },
            .{ .name = "sol_panic_", .builtin_fn = sig.vm.syscalls.panic },
        },
        .{ 0, 48596 },
    );
}

test "poseidon len 0" {
    const budget = sig.runtime.ComputeBudget.default(1_400_000);
    const total_compute = budget.poseidonCost(0); // enough for one call
    var buffer: [32]u8 = undefined;
    try sig.vm.tests.testSyscall(
        poseidon,
        &.{
            memory.Region.init(.mutable, &buffer, memory.RODATA_START),
        },
        &.{
            .{ .{ 0, 0, 0, 0, memory.RODATA_START }, 1 }, // fails because len == 0
            // Make sure len == 0 still consumes compute
            .{ .{ 0, 0, 0, 0, 0 }, error.ComputationalBudgetExceeded },
        },
        null,
        .{ .compute_meter = total_compute },
    );
}

test sha256 {
    const bytes1: []const u8 = "Gaggablaghblagh!";
    const bytes2: []const u8 = "flurbos";

    const mock_slice1: memory.VmSlice = .{
        .ptr = memory.HEAP_START,
        .len = bytes1.len,
    };
    const mock_slice2: memory.VmSlice = .{
        .ptr = memory.INPUT_START,
        .len = bytes2.len,
    };

    const bytes_to_hash: [2]memory.VmSlice = .{ mock_slice1, mock_slice2 };
    var hash_result: [32]u8 = .{0} ** 32;

    const compute_budget = sig.runtime.ComputeBudget.default(1_400_000);
    const total_compute = (compute_budget.sha256_base_cost + @max(
        compute_budget.mem_op_base_cost,
        compute_budget.sha256_byte_cost * (bytes1.len + bytes2.len) / 2,
    )) * 4;

    try sig.vm.tests.testSyscall(
        sha256,
        // zig fmt: off
        &.{
            memory.Region.init(.constant, std.mem.sliceAsBytes(&bytes_to_hash), memory.RODATA_START),
            memory.Region.init(.mutable,  &hash_result,                         memory.STACK_START),
            memory.Region.init(.constant, bytes1,                               bytes_to_hash[0].ptr),
            memory.Region.init(.constant, bytes2,                               bytes_to_hash[1].ptr),
        },
        &.{
            .{ .{ memory.RODATA_START,     2, memory.STACK_START,     0, 0 }, 0 },
            .{ .{ memory.RODATA_START - 1, 2, memory.STACK_START,     0, 0 }, error.AccessViolation },
            .{ .{ memory.RODATA_START,     3, memory.STACK_START,     0, 0 }, error.AccessViolation }, 
            .{ .{ memory.RODATA_START,     2, memory.STACK_START - 1, 0, 0 }, error.AccessViolation }, 
            .{ .{ memory.RODATA_START,     2, memory.STACK_START,     0, 0 }, error.ComputationalBudgetExceeded },
        },
        // zig fmt: on
        struct {
            fn verify(tc: *TransactionContext, memory_map: *MemoryMap, args: anytype) !void {
                _, _, const result_addr, _, _ = args;

                const result_slice = try memory_map.translateSlice(
                    u8,
                    .constant,
                    result_addr,
                    32,
                    tc.getCheckAligned(),
                );

                var hasher = std.crypto.hash.sha2.Sha256.init(.{});
                hasher.update(bytes1);
                hasher.update(bytes2);

                var hash_local: [32]u8 = undefined;
                hasher.final(&hash_local);

                try std.testing.expectEqualSlices(u8, &hash_local, result_slice);
            }
        }.verify,
        .{ .compute_meter = total_compute },
    );
}
