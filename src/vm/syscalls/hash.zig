//! Hashing syscalls
const phash = @import("poseidon");
const std = @import("std");
const cpi = @import("cpi.zig");
const sig = @import("../../sig.zig");

const features = sig.runtime.features;

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

    if (len > 12) return error.InvalidNumberOfInputs;

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
        cpi.VmSlice,
        .constant,
        addr,
        len,
        tc.getCheckAligned(),
    );

    // Agave handles poseidon errors in an annoying way.
    // The feature SIMPLIFY_ALT_BN_128_SYSCALL_ERROR_CODES simplifies this handling.
    // It is acitvated on all clusters, we still check for activation here and panic if it is not active.
    // [agave] https://github.com/firedancer-io/agave/blob/66ea0a11f2f77086d33253b4028f6ae7083d78e4/programs/bpf_loader/src/syscalls/mod.rs#L1815-L1825
    var hasher = phash.Hasher.init(endianness);
    for (inputs) |input| {
        const slice = try memory_map.translateSlice(
            u8,
            .constant,
            input.ptr,
            input.len,
            tc.getCheckAligned(),
        );

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
            .big => std.mem.copyBackwards(u8, &buffer, slice),
        }
        hasher.append(&buffer) catch {
            if (tc.ec.feature_set.active.contains(
                features.SIMPLIFY_ALT_BN128_SYSCALL_ERROR_CODES,
            )) {
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

            const hash_base_cost = @field(tc.compute_budget, H.base_cost);
            const hash_byte_cost = @field(tc.compute_budget, H.byte_cost);
            const hash_max_slices = @field(tc.compute_budget, H.max_slices);

            if (hash_max_slices < vals_len) {
                try tc.log(
                    "{s} Hashing {} sequences in one syscall is over the limit {}",
                    .{
                        H.name,
                        vals_len,
                        hash_max_slices,
                    },
                );
                return SyscallError.TooManySlices;
            }

            try tc.consumeCompute(hash_base_cost);

            const hash_result = try memory_map.translateSlice(
                u8,
                .mutable,
                result_addr,
                @sizeOf(H.Output),
                tc.getCheckAligned(),
            );

            var hasher = H.Hasher.init(.{});
            if (vals_len > 0) {
                const vals = try memory_map.translateSlice(
                    cpi.VmSlice,
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
                        hash_byte_cost *% (val.len / 2),
                    );
                    try tc.consumeCompute(cost);
                    hasher.update(bytes);
                }
            }

            hasher.final(hash_result[0..@sizeOf(H.Output)]);
        }
    };
    return S.syscall;
}

const Sha256 = struct {
    const Hasher = std.crypto.hash.sha2.Sha256;
    const Output = [32]u8;
    const name = "Sha256";

    const base_cost = "sha256_base_cost";
    const byte_cost = "sha256_byte_cost";
    const max_slices = "sha256_max_slices";
};

const Blake3 = struct {
    const Hasher = std.crypto.hash.Blake3;
    const Output = [32]u8;
    const name = "Blake3";

    const base_cost = "sha256_base_cost";
    const byte_cost = "sha256_byte_cost";
    const max_slices = "sha256_max_slices";
};

const Keccak256 = struct {
    const Hasher = std.crypto.hash.sha3.Keccak256;
    const Output = [32]u8;
    const name = "Keccak256";

    const base_cost = "sha256_base_cost";
    const byte_cost = "sha256_byte_cost";
    const max_slices = "sha256_max_slices";
};

pub const sha256 = hashSyscall(Sha256);
pub const blake3 = hashSyscall(Blake3);
pub const keccak256 = hashSyscall(Keccak256);

test poseidon {
    try sig.vm.tests.testElfWithSyscalls(
        .{},
        sig.ELF_DATA_DIR ++ "poseidon_test.so",
        &.{
            .{ .name = "sol_poseidon", .builtin_fn = poseidon },
            .{ .name = "log", .builtin_fn = sig.vm.syscalls.log },
            .{ .name = "sol_panic_", .builtin_fn = sig.vm.syscalls.panic },
        },
        .{ 0, 48526 },
    );
}

test sha256 {
    const bytes1: []const u8 = "Gaggablaghblagh!";
    const bytes2: []const u8 = "flurbos";

    const mock_slice1: cpi.VmSlice = .{
        .ptr = memory.HEAP_START,
        .len = bytes1.len,
    };
    const mock_slice2: cpi.VmSlice = .{
        .ptr = memory.INPUT_START,
        .len = bytes2.len,
    };

    const bytes_to_hash: [2]cpi.VmSlice = .{ mock_slice1, mock_slice2 };
    var hash_result: [32]u8 = .{0} ** 32;

    const compute_budget = sig.runtime.ComputeBudget.default(1_400_000);
    const total_compute = (compute_budget.sha256_base_cost + @max(
        compute_budget.mem_op_base_cost,
        compute_budget.sha256_byte_cost * (bytes1.len + bytes2.len) / 2,
    )) * 4;

    try sig.vm.tests.testSyscall(
        sha256,
        &.{
            memory.Region.init(
                .constant,
                std.mem.sliceAsBytes(&bytes_to_hash),
                memory.RODATA_START,
            ),
            memory.Region.init(.mutable, &hash_result, memory.STACK_START),
            memory.Region.init(.constant, bytes1, bytes_to_hash[0].ptr),
            memory.Region.init(.constant, bytes2, bytes_to_hash[1].ptr),
        },
        &.{
            // zig fmt: off
            .{ .{ memory.RODATA_START,     2, memory.STACK_START,     0 }, {} },
            .{ .{ memory.RODATA_START - 1, 2, memory.STACK_START,     0 }, error.AccessViolation },
            .{ .{ memory.RODATA_START,     3, memory.STACK_START,     0 }, error.AccessViolation }, 
            .{ .{ memory.RODATA_START,     2, memory.STACK_START - 1, 0 }, error.AccessViolation }, 
            // zig fmt: on
            // only gave enough budget for 4 runs
            .{
                .{ memory.RODATA_START, 2, memory.STACK_START, 0 },
                error.ComputationalBudgetExceeded,
            },
        },
        struct {
            fn verify(tc: *TransactionContext, memory_map: *MemoryMap, args: anytype) !void {
                _, _, const result_addr, _ = args;

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
