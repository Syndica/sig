//! Syscalls that work with Elliptic Curves

const std = @import("std");
const sig = @import("../../sig.zig");

const bn254 = sig.crypto.bn254;
const bls12_381 = sig.crypto.bls12_381;

const MemoryMap = sig.vm.memory.MemoryMap;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const TransactionContext = sig.runtime.TransactionContext;
const Error = sig.vm.syscalls.Error;
const SyscallError = sig.vm.SyscallError;
const memory = sig.vm.memory;
const FeatureSet = sig.core.FeatureSet;

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const ed25519 = sig.crypto.ed25519;

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, Keccak256);

pub const CurveId = enum(u64) {
    edwards = 0,
    ristretto = 1,

    bls12_381_be = 4,
    bls12_381_le = 4 | 0x80,
    bls12_381_g1_be = 5,
    bls12_381_g1_le = 5 | 0x80,
    bls12_381_g2_be = 6,
    bls12_381_g2_le = 6 | 0x80,

    fn wrap(id: u64) ?CurveId {
        return std.meta.intToEnum(CurveId, id) catch null;
    }
};

pub const GroupOp = enum(u64) {
    add = 0,
    subtract = 1,
    multiply = 2,

    fn wrap(id: u64) ?GroupOp {
        if (id > 2) return null;
        return @enumFromInt(id);
    }
};

fn invalidError(tc: *const TransactionContext, registers: *RegisterMap) !void {
    if (tc.feature_set.active(.abort_on_invalid_curve, tc.slot)) {
        return SyscallError.InvalidAttribute;
    } else {
        registers.set(.r0, 1);
        return;
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/a3e2a62a942a497e00e4e091e888a1945dcdad53/syscalls/src/lib.rs#L978-L1111
pub fn curvePointValidation(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const curve_id = CurveId.wrap(registers.get(.r1)) orelse
        return invalidError(tc, registers);
    const point_addr = registers.get(.r2);

    // Only allow the BLS12-381 syscalls if the feature gate is enabled.
    if (!tc.feature_set.active(.enable_bls12_381_syscall, tc.slot)) {
        switch (curve_id) {
            .bls12_381_g1_be,
            .bls12_381_g1_le,
            .bls12_381_g2_be,
            .bls12_381_g2_le,
            => return SyscallError.InvalidAttribute,
            else => {},
        }
    }

    const cost = switch (curve_id) {
        .edwards => tc.compute_budget.curve25519_edwards_validate_point_cost,
        .ristretto => tc.compute_budget.curve25519_ristretto_validate_point_cost,
        .bls12_381_g1_be,
        .bls12_381_g1_le,
        => tc.compute_budget.bls12_381_g1_validate_cost,
        .bls12_381_g2_be,
        .bls12_381_g2_le,
        => tc.compute_budget.bls12_381_g2_validate_cost,
        else => return invalidError(tc, registers),
    };
    try tc.consumeCompute(cost);

    const is_error = switch (curve_id) {
        inline .edwards, .ristretto => |t| err: {
            const buffer = try memory_map.translateType(
                [32]u8,
                .constant,
                point_addr,
                tc.getCheckAligned(),
            );
            const result = switch (t) {
                .edwards => Edwards25519.fromBytes(buffer.*),
                .ristretto => Ristretto255.fromBytes(buffer.*),
                else => unreachable,
            };
            break :err std.meta.isError(result);
        },
        inline //
        .bls12_381_g1_be,
        .bls12_381_g1_le,
        .bls12_381_g2_be,
        .bls12_381_g2_le,
        => |t| err: {
            const degree: enum { g1, g2 }, //
            const endian: std.builtin.Endian = switch (t) {
                .bls12_381_g1_be => .{ .g1, .big },
                .bls12_381_g1_le => .{ .g1, .little },
                .bls12_381_g2_be => .{ .g2, .big },
                .bls12_381_g2_le => .{ .g2, .little },
                else => unreachable,
            };
            const size = switch (degree) {
                .g1 => 96,
                .g2 => 192,
            };
            const T = switch (degree) {
                .g1 => bls12_381.G1,
                .g2 => bls12_381.G2,
            };

            const buffer = try memory_map.translateType(
                [size]u8,
                .constant,
                point_addr,
                tc.getCheckAligned(),
            );

            const result = T.validate(buffer, endian);
            break :err std.meta.isError(result);
        },
        else => unreachable, // Unreachable via the cost switch above.
    };

    registers.set(.r0, @intFromBool(is_error));
}

/// [agave] https://github.com/anza-xyz/agave/blob/734a250745533616bd29e86bd69ac90dbc26f38c/syscalls/src/lib.rs#L1210-L1679
pub fn curveGroupOp(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const curve_id = CurveId.wrap(registers.get(.r1)) orelse
        return invalidError(tc, registers);
    const group_op = GroupOp.wrap(registers.get(.r2)) orelse
        return invalidError(tc, registers);

    // Only allow the BLS12-381 syscalls if the feature gate is enabled.
    // [agave] https://github.com/anza-xyz/agave/blob/734a250745533616bd29e86bd69ac90dbc26f38c/syscalls/src/lib.rs#L1239-L1246
    if (!tc.feature_set.active(.enable_bls12_381_syscall, tc.slot)) {
        switch (curve_id) {
            .bls12_381_g1_be,
            .bls12_381_g1_le,
            .bls12_381_g2_be,
            .bls12_381_g2_le,
            => return SyscallError.InvalidAttribute,
            else => {},
        }
    }

    // For `mul` group operations, the "left" side is the scalar.
    const left_input_addr = registers.get(.r3);
    const right_input_addr = registers.get(.r4);
    const result_point_addr = registers.get(.r5);
    const cost = tc.compute_budget.curveGroupOperationCost(curve_id, group_op);
    try tc.consumeCompute(cost);

    switch (curve_id) {
        inline //
        .edwards,
        .ristretto,
        .bls12_381_g1_be,
        .bls12_381_g1_le,
        .bls12_381_g2_be,
        .bls12_381_g2_le,
        => |id| {
            const T = switch (id) {
                .edwards => Edwards25519,
                .ristretto => Ristretto255,
                .bls12_381_g1_be, .bls12_381_g1_le => bls12_381.G1,
                .bls12_381_g2_be, .bls12_381_g2_le => bls12_381.G2,
                else => unreachable,
            };
            const right_size: u32 = switch (T) {
                Edwards25519, Ristretto255 => 32,
                bls12_381.G1 => 96,
                bls12_381.G2 => 192,
                else => unreachable,
            };

            switch (group_op) {
                inline .add, .subtract, .multiply => |op| {
                    const left_size = switch (op) {
                        .add, .subtract => right_size,
                        .multiply => 32,
                    };

                    const check_aligned = tc.getCheckAligned();
                    const left_data = try memory_map.translateType(
                        [left_size]u8,
                        .constant,
                        left_input_addr,
                        check_aligned,
                    );
                    const right_data = try memory_map.translateType(
                        [right_size]u8,
                        .constant,
                        right_input_addr,
                        check_aligned,
                    );

                    switch (T) {
                        Edwards25519, Ristretto255 => {
                            const result = edwardsGroupOp(
                                T,
                                group_op,
                                left_data.*,
                                right_data.*,
                            ) catch {
                                registers.set(.r0, 1);
                                return;
                            };
                            const result_ptr = try memory_map.translateType(
                                [right_size]u8,
                                .mutable,
                                result_point_addr,
                                check_aligned,
                            );
                            result_ptr.* = result.toBytes();
                        },
                        bls12_381.G1, bls12_381.G2 => {
                            const endian: std.builtin.Endian = switch (id) {
                                .bls12_381_g1_be, .bls12_381_g2_be => .big,
                                .bls12_381_g1_le, .bls12_381_g2_le => .little,
                                else => unreachable,
                            };
                            var result: [right_size]u8 = undefined;
                            // {G1, G2}.{add,sub,mul}
                            @field(T, @tagName(op))(&result, left_data, right_data, endian) catch {
                                registers.set(.r0, 1);
                                return;
                            };
                            // NOTE: We write the operation result into a temporary buffer `result`
                            // before copying it in. It's important to perform the operation before
                            // the result memory access, as the former is a soft-error while the latter
                            // will hard-error.
                            const result_ptr = try memory_map.translateType(
                                [right_size]u8,
                                .mutable,
                                result_point_addr,
                                check_aligned,
                            );
                            @memcpy(result_ptr, &result);
                        },
                        else => unreachable,
                    }
                },
            }
        },
        else => return invalidError(tc, registers),
    }
}

/// A small wrapper around performing the Edwards-based group operations to simplify catching
/// the soft error returned by any of the errors inside.
fn edwardsGroupOp(comptime T: type, group_op: GroupOp, left_bytes: [32]u8, right_bytes: [32]u8) !T {
    switch (group_op) {
        .add, .subtract => {
            const left = try T.fromBytes(left_bytes);
            const right = try T.fromBytes(right_bytes);
            return switch (group_op) {
                .add => left.add(right),
                // TODO:(0.15) Use the alias https://github.com/ziglang/zig/pull/23724
                .subtract => switch (T) {
                    Edwards25519 => left.sub(right),
                    Ristretto255 => .{ .p = left.p.sub(right.p) },
                    else => unreachable,
                },
                else => unreachable,
            };
        },
        .multiply => {
            try Edwards25519.scalar.rejectNonCanonical(left_bytes);
            const input_point = try T.fromBytes(right_bytes);
            return ed25519.mul(T == Ristretto255, input_point, left_bytes);
        },
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/734a250745533616bd29e86bd69ac90dbc26f38c/syscalls/src/lib.rs#L1681-L1797
pub fn curveMultiscalarMul(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const attribute_id = registers.get(.r1);
    const scalars_addr = registers.get(.r2);
    const points_addr = registers.get(.r3);
    const points_len = registers.get(.r4);
    const result_point_addr = registers.get(.r5);

    if (points_len > 512) return SyscallError.InvalidLength;

    const curve_id = CurveId.wrap(attribute_id) orelse
        return invalidError(tc, registers);

    const cost = switch (curve_id) {
        .edwards => tc.compute_budget.curve25519_edwards_msm_base_cost,
        .ristretto => tc.compute_budget.curve25519_ristretto_msm_base_cost,
        else => return invalidError(tc, registers),
    };
    const incremental_cost = switch (curve_id) {
        .edwards => tc.compute_budget.curve25519_edwards_msm_incremental_cost,
        .ristretto => tc.compute_budget.curve25519_ristretto_msm_incremental_cost,
        else => unreachable, // Unreachable due to cost switch above.
    } * (points_len -| 1);
    try tc.consumeCompute(cost + incremental_cost);

    const scalars = try memory_map.translateSlice(
        [32]u8,
        .constant,
        scalars_addr,
        points_len,
        tc.getCheckAligned(),
    );

    const point_data = try memory_map.translateSlice(
        [32]u8,
        .constant,
        points_addr,
        points_len,
        tc.getCheckAligned(),
    );

    switch (curve_id) {
        inline .edwards, .ristretto => |id| {
            for (scalars) |scalar| {
                Edwards25519.scalar.rejectNonCanonical(scalar) catch {
                    registers.set(.r0, 1);
                    return;
                };
            }

            const msm = sig.crypto.ed25519.mulMultiRuntime(
                512,
                true,
                id == .ristretto,
                point_data,
                scalars,
            ) catch {
                registers.set(.r0, 1);
                return;
            };

            const result_point_data = try memory_map.translateType(
                [32]u8,
                .mutable,
                result_point_addr,
                tc.getCheckAligned(),
            );
            result_point_data.* = msm.toBytes();
        },
        else => unreachable, // Unreachable due to cost switch above.
    }
}

const AltBn128GroupOp = enum(u8) {
    add = 0,
    sub = 1,
    mul = 2,
    pairing = 3,

    fn wrap(id: u64) ?AltBn128GroupOp {
        if (id > 3) return null;
        return @enumFromInt(id);
    }
};

const AltBn128CompressionOp = enum(u8) {
    g1_compress = 0,
    g1_decompress = 1,
    g2_compress = 2,
    g2_decompress = 3,

    fn wrap(id: u64) ?AltBn128CompressionOp {
        if (id > 3) return null;
        return @enumFromInt(id);
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/programs/bpf_loader/src/syscalls/mod.rs#L1687-L1789
pub fn altBn128GroupOp(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const attribute_id = registers.get(.r1);
    const input_addr = registers.get(.r2);
    const input_size = registers.get(.r3);
    const result_addr = registers.get(.r4);

    const group_op = AltBn128GroupOp.wrap(attribute_id) orelse {
        return SyscallError.InvalidAttribute;
    };

    const cb = tc.compute_budget;
    const cost, const output_length: u32 = switch (group_op) {
        .add => .{ cb.alt_bn128_addition_cost, 64 },
        .mul => .{ cb.alt_bn128_multiplication_cost, 64 },
        .pairing => blk: {
            const elem_length = input_size / 192;
            const cost = cb.alt_bn128_pairing_one_pair_cost_first +|
                (cb.alt_bn128_pairing_one_pair_cost_other *| (elem_length -| 1)) +|
                cb.sha256_base_cost +|
                input_size +|
                32;
            break :blk .{ cost, 32 };
        },
        .sub => return SyscallError.InvalidAttribute,
    };

    try tc.consumeCompute(cost);

    const input = try memory_map.translateSlice(
        u8,
        .constant,
        input_addr,
        input_size,
        tc.getCheckAligned(),
    );

    const call_result = try memory_map.translateSlice(
        u8,
        .mutable,
        result_addr,
        output_length,
        tc.getCheckAligned(),
    );

    // 64-bytes is the largest result we'll need.
    var result: [64]u8 = undefined;
    const result_point = altBn128Operation(
        group_op,
        input,
        &result,
        tc.feature_set,
        tc.slot,
    ) catch {
        if (tc.feature_set.active(.simplify_alt_bn128_syscall_error_codes, tc.slot)) {
            registers.set(.r0, 1);
            return;
        } else @panic("SIMPLIFY_ALT_BN_128_SYSCALL_ERROR_CODES not active");
    };
    // Can never happen after SIMPLIFY_ALT_BN128_SYSCALL_ERROR_CODES, which should always be enabled now.
    std.debug.assert(result_point.len == output_length);

    @memcpy(call_result, result_point);
}

pub fn altBn128Compression(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const attribute_id = registers.get(.r1);
    const input_addr = registers.get(.r2);
    const input_size = registers.get(.r3);
    const result_addr = registers.get(.r4);

    const group_op = AltBn128CompressionOp.wrap(attribute_id) orelse {
        return error.InvalidAttribute;
    };

    const cb = tc.compute_budget;
    const base_cost = cb.syscall_base_cost;
    const cost, const output_length: u32 = switch (group_op) {
        // zig fmt: off
        .g1_compress   => .{ base_cost +| cb.alt_bn128_g1_compress,   32 },
        .g1_decompress => .{ base_cost +| cb.alt_bn128_g1_decompress, 64 },
        .g2_compress   => .{ base_cost +| cb.alt_bn128_g2_compress,   64 },
        .g2_decompress => .{ base_cost +| cb.alt_bn128_g2_decompress, 128 },
        // zig fmt: on
    };

    try tc.consumeCompute(cost);

    const input = try memory_map.translateSlice(
        u8,
        .constant,
        input_addr,
        input_size,
        tc.getCheckAligned(),
    );
    const call_result = try memory_map.translateSlice(
        u8,
        .mutable,
        result_addr,
        output_length,
        tc.getCheckAligned(),
    );

    const needed_input_size: u32 = switch (group_op) {
        .g1_compress => 64,
        .g1_decompress => 32,
        .g2_compress => 128,
        .g2_decompress => 64,
    };
    // Must be exactly the correct length.
    if (input_size != needed_input_size) {
        if (tc.feature_set.active(.simplify_alt_bn128_syscall_error_codes, tc.slot)) {
            registers.set(.r0, 1);
            return;
        } else @panic("SIMPLIFY_ALT_BN_128_SYSCALL_ERROR_CODES not active");
    }

    // Largest result is 128-bytes from g2_decompress.
    var result: [128]u8 = undefined;
    (switch (group_op) {
        // zig fmt: off
        .g1_compress   => bn254.G1.compress(  result[0..32],  input[0..64] ),
        .g1_decompress => bn254.G1.decompress(result[0..64],  input[0..32] ),
        .g2_compress   => bn254.G2.compress(  result[0..64],  input[0..128]),
        .g2_decompress => bn254.G2.decompress(result[0..128], input[0..64] ),
        // zig fmt: on
    }) catch {
        if (tc.feature_set.active(.simplify_alt_bn128_syscall_error_codes, tc.slot)) {
            registers.set(.r0, 1);
            return;
        } else @panic("SIMPLIFY_ALT_BN_128_SYSCALL_ERROR_CODES not active");
    };

    @memcpy(call_result, result[0..output_length]);
}

fn altBn128Operation(
    group_op: AltBn128GroupOp,
    input: []const u8,
    out: *[64]u8,
    feature_set: *const FeatureSet,
    slot: sig.core.Slot,
) ![]const u8 {
    switch (group_op) {
        .add => {
            if (input.len > 128) return error.InvalidLength;

            // Pad the end with zeroes.
            var buffer: [128]u8 = .{0} ** 128;
            @memcpy(buffer[0..input.len], input);

            try bn254.addSyscall(out, &buffer);

            // Writes 64-bytes.
            return out;
        },
        .mul => {
            const expected_size: usize = if (feature_set.active(
                .fix_alt_bn128_multiplication_input_length,
                slot,
            )) 96 else 128;
            if (input.len > expected_size) return error.InvalidLength;

            // Copy over 96-bytes, padding out with zeroes if needed.
            var buffer: [96]u8 = .{0} ** 96;
            @memcpy(buffer[0..@min(input.len, 96)], input.ptr);

            try bn254.mulSyscall(out, &buffer);

            // Writes 64-bytes.
            return out;
        },
        .pairing => {
            // Originally Agave did not check that the input length is a multiple
            // of the pair size (192 bytes). They used `input.len().check_rem(192).is_none()`,
            // which made little sense, as `check_rem` only returns `None` if the RHS is zero.
            //
            // This ended up sort of working, since we perform a truncating integer division
            // in `pairingSyscall`, which ensures that the number of pairs read will always fit
            // the input size and ignores the remaining bytes.
            //
            // This is all fixed by the feature gate which enables us to perform the correct check.
            //
            // [fd] https://github.com/firedancer-io/firedancer/blob/d848e9b27a80cc344772521689671ef05de28653/src/ballet/bn254/fd_bn254.c#L227-L236
            // [agave] https://github.com/anza-xyz/solana-sdk/blob/master/bn254/src/pairing.rs#L66-L83
            if (feature_set.active(.fix_alt_bn128_pairing_length_check, slot)) {
                if (input.len % 192 != 0) return error.InvalidLength;
            }

            try bn254.pairingSyscall(out[0..32], input);

            // Writes to the first 32-bytes.
            return out[0..32];
        },
        .sub => unreachable,
    }
}

pub fn secp256k1Recover(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const hash_addr = registers.get(.r1);
    const recovery_id_val = registers.get(.r2);
    const signature_addr = registers.get(.r3);
    const result_addr = registers.get(.r4);

    const cost = tc.compute_budget.secp256k1_recover_cost;
    try tc.consumeCompute(cost);

    const recovery_result = try memory_map.translateSlice(
        u8,
        .mutable,
        result_addr,
        64,
        tc.getCheckAligned(),
    );
    const hash = try memory_map.translateType(
        [32]u8,
        .constant,
        hash_addr,
        tc.getCheckAligned(),
    );
    const signature = try memory_map.translateType(
        sig.crypto.EcdsaSignature,
        .constant,
        signature_addr,
        tc.getCheckAligned(),
    );

    if (recovery_id_val >= 4) {
        registers.set(.r0, 2); // InvalidRecoveryId
        return;
    }

    const pubkey = sig.runtime.program.precompiles.secp256k1.recoverSecp256k1Pubkey(
        hash,
        &signature.to(),
        @intCast(recovery_id_val),
    ) catch {
        registers.set(.r0, 3); // InvalidSignature
        return;
    };
    @memcpy(recovery_result, pubkey.toUncompressedSec1()[1..65]);
}

pub fn curveDecompress(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const attribute_id = registers.get(.r1);
    const point_addr = registers.get(.r2);
    const result_addr = registers.get(.r3);

    const curve_id = CurveId.wrap(attribute_id) orelse
        return SyscallError.InvalidAttribute;

    switch (curve_id) {
        inline //
        .bls12_381_g1_be,
        .bls12_381_g1_le,
        .bls12_381_g2_be,
        .bls12_381_g2_le,
        => |t| {
            const degree: enum { g1, g2 }, //
            const endian: std.builtin.Endian = switch (t) {
                .bls12_381_g1_be => .{ .g1, .big },
                .bls12_381_g1_le => .{ .g1, .little },
                .bls12_381_g2_be => .{ .g2, .big },
                .bls12_381_g2_le => .{ .g2, .little },
                else => unreachable,
            };
            const T = switch (degree) {
                .g1 => bls12_381.G1,
                .g2 => bls12_381.G2,
            };
            const out = switch (degree) {
                .g1 => 96,
                .g2 => 192,
            };

            const compressed = try memory_map.translateType(
                [out / 2]u8,
                .constant,
                point_addr,
                tc.getCheckAligned(),
            );

            var result: [out]u8 = undefined;
            T.decompress(compressed, &result, endian) catch {
                registers.set(.r0, 1);
                return;
            };

            const result_ptr = try memory_map.translateType(
                [out]u8,
                .mutable,
                result_addr,
                tc.getCheckAligned(),
            );
            @memcpy(result_ptr, &result);
        },
        else => return SyscallError.InvalidAttribute,
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/a3e2a62a942a497e00e4e091e888a1945dcdad53/syscalls/src/lib.rs#L1799-L1876
pub fn curvePairingMap(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const curve_id = CurveId.wrap(registers.get(.r1)) orelse
        return SyscallError.InvalidAttribute;
    const num_pairs = registers.get(.r2);
    const g1_points_addr = registers.get(.r3);
    const g2_points_addr = registers.get(.r4);
    const result_addr = registers.get(.r5);

    // [agave] https://github.com/anza-xyz/agave/blob/a3e2a62a942a497e00e4e091e888a1945dcdad53/syscalls/src/lib.rs#L1825
    const cost = tc.compute_budget.bls12_381_one_pair_cost +|
        (tc.compute_budget.bls12_381_additional_pair_cost *| (num_pairs -| 1));
    try tc.consumeCompute(cost);

    const endian: std.builtin.Endian = switch (curve_id) {
        .bls12_381_be => .big,
        .bls12_381_le => .little,
        else => return SyscallError.InvalidAttribute,
    };

    const g1_points = try memory_map.translateSlice(
        u8,
        .constant,
        g1_points_addr,
        // [fd] https://github.com/firedancer-io/firedancer/blob/f02626d7483e689e3724959b11e697406759a3b9/src/flamenco/vm/syscall/fd_vm_syscall_curve.c#L707
        num_pairs *| 96, // Size of an uncompressed G1 point
        tc.getCheckAligned(),
    );
    const g2_points = try memory_map.translateSlice(
        u8,
        .constant,
        g2_points_addr,
        // [fd] https://github.com/firedancer-io/firedancer/blob/f02626d7483e689e3724959b11e697406759a3b9/src/flamenco/vm/syscall/fd_vm_syscall_curve.c#L710
        num_pairs *| 192, // Size of an uncompressed G2 point
        tc.getCheckAligned(),
    );

    var result: [48 * 12]u8 = undefined;
    bls12_381.pairingSyscall(&result, g1_points, g2_points, num_pairs, endian) catch {
        registers.set(.r0, 1);
        return;
    };

    const result_ptr = try memory_map.translateType(
        [48 * 12]u8,
        .mutable,
        result_addr,
        tc.getCheckAligned(),
    );
    @memcpy(result_ptr, &result);
}

test "edwards curve point validation" {
    const valid_bytes = [_]u8{
        201, 179, 241, 122, 180, 185, 239, 50,  183, 52,  221, 0,  153,
        195, 43,  18,  22,  38,  187, 206, 179, 192, 210, 58,  53, 45,
        150, 98,  89,  17,  158, 11,
    };
    const valid_bytes_addr = 0x100000000;

    const invalid_bytes = [_]u8{
        120, 140, 152, 233, 41,  227, 203, 27, 87,  115, 25,  251, 219,
        5,   84,  148, 117, 38,  84,  60,  87, 144, 161, 146, 42,  34,
        91,  155, 158, 189, 121, 79,
    };
    const invalid_bytes_addr = 0x200000000;

    const compute_budget = sig.runtime.ComputeBudget.DEFAULT;
    const total_compute = compute_budget.curve25519_edwards_validate_point_cost * 2;

    try sig.vm.tests.testSyscall(
        curvePointValidation,
        &.{
            memory.Region.init(.constant, &valid_bytes, valid_bytes_addr),
            memory.Region.init(.constant, &invalid_bytes, invalid_bytes_addr),
        },
        // zig fmt: off
        &.{
            .{ .{ 0, valid_bytes_addr,   0, 0, 0 }, 0 }, // success
            .{ .{ 0, invalid_bytes_addr, 0, 0, 0 }, 1 }, // failed
            .{ .{ 8, valid_bytes_addr,   0, 0, 0 }, 1 }, // invalid curve ID
            .{ .{ 0, valid_bytes_addr,   0, 0, 0 }, error.ComputationalBudgetExceeded },
        },
        // zig fmt: on
        null,
        .{ .compute_meter = total_compute },
    );
}

test "ristretto curve point validation" {
    const valid_bytes = [_]u8{
        226, 242, 174, 10,  106, 188, 78,  113, 168, 132, 169, 97,  197,
        0,   81,  95,  88,  227, 11,  106, 165, 130, 221, 141, 182, 166,
        89,  69,  224, 141, 45,  118,
    };
    const valid_bytes_addr = 0x100000000;

    const invalid_bytes = [_]u8{
        120, 140, 152, 233, 41,  227, 203, 27, 87,  115, 25,  251, 219,
        5,   84,  148, 117, 38,  84,  60,  87, 144, 161, 146, 42,  34,
        91,  155, 158, 189, 121, 79,
    };
    const invalid_bytes_addr = 0x200000000;

    const compute_budget = sig.runtime.ComputeBudget.DEFAULT;
    const total_compute = compute_budget.curve25519_ristretto_validate_point_cost * 2;

    try sig.vm.tests.testSyscall(
        curvePointValidation,
        &.{
            memory.Region.init(.constant, &valid_bytes, valid_bytes_addr),
            memory.Region.init(.constant, &invalid_bytes, invalid_bytes_addr),
        },
        // zig fmt: off
        &.{
            .{ .{ 1, valid_bytes_addr,   0, 0, 0 }, 0 }, // success
            .{ .{ 1, invalid_bytes_addr, 0, 0, 0 }, 1 }, // failed
            .{ .{ 8, valid_bytes_addr,   0, 0, 0 }, 1 }, // invalid curve ID
            .{ .{ 1, valid_bytes_addr,   0, 0, 0 }, error.ComputationalBudgetExceeded },
        },
        // zig fmt: on
        null,
        .{ .compute_meter = total_compute },
    );
}

test "edwards curve group operations" {
    const allocator = std.testing.allocator;

    const left_point = [_]u8{
        33,  124, 71,  170, 117, 69,  151, 247, 59, 12,  95,
        125, 133, 166, 64,  5,   2,   27,  90,  27, 200, 167,
        59,  164, 52,  54,  52,  200, 29,  13,  34, 213,
    };
    const left_point_addr = 0x100000000;

    const right_point = [_]u8{
        70,  222, 137, 221, 253, 204, 71,  51,  78,  8,   124,
        1,   67,  200, 102, 225, 122, 228, 111, 183, 129, 14,
        131, 210, 212, 95,  109, 246, 55,  10,  159, 91,
    };
    const right_point_addr = 0x200000000;

    const scalar = [_]u8{
        254, 198, 23,  138, 67,  243, 184, 110, 236, 115, 236,
        205, 205, 215, 79,  114, 45,  250, 78,  137, 3,   107,
        136, 237, 49,  126, 117, 223, 37,  191, 88,  6,
    };
    const scalar_addr = 0x300000000;

    const invalid_point = [_]u8{
        120, 140, 152, 233, 41,  227, 203, 27,  87,  115, 25,
        251, 219, 5,   84,  148, 117, 38,  84,  60,  87,  144,
        161, 146, 42,  34,  91,  155, 158, 189, 121, 79,
    };
    const invalid_point_addr = 0x400000000;

    var result_point: [32]u8 = undefined;
    const result_point_addr = 0x500000000;

    const compute_budget = sig.runtime.ComputeBudget.DEFAULT;
    const total_compute = (compute_budget.curve25519_edwards_add_cost +
        compute_budget.curve25519_edwards_subtract_cost +
        compute_budget.curve25519_edwards_multiply_cost);

    const regions: []const memory.Region = &.{
        memory.Region.init(.constant, &left_point, left_point_addr),
        memory.Region.init(.constant, &right_point, right_point_addr),
        memory.Region.init(.constant, &scalar, scalar_addr),
        memory.Region.init(.constant, &invalid_point, invalid_point_addr),
        memory.Region.init(.mutable, &result_point, result_point_addr),
    };

    try sig.vm.tests.testSyscall(
        curveGroupOp,
        regions,
        // zig fmt: off
        &.{
            .{ .{ 0, 0, invalid_point_addr, right_point_addr,   result_point_addr }, 1 },
            .{ .{ 0, 1, invalid_point_addr, right_point_addr,   result_point_addr }, 1 },
            .{ .{ 0, 2, scalar_addr,        invalid_point_addr, result_point_addr }, 1 },
            .{ .{ 0, 2, scalar_addr,        invalid_point_addr, result_point_addr }, error.ComputationalBudgetExceeded },
        },
        // zig fmt: on
        null,
        .{ .compute_meter = total_compute },
    );

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{.{
                .pubkey = sig.core.Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            }},
            .compute_meter = total_compute,
        },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, regions, .v2, .{});
    defer memory_map.deinit(allocator);

    {
        registers.set(.r1, 0); // CURVE25519_EDWARDS
        registers.set(.r2, 0); // ADD
        registers.set(.r3, left_point_addr);
        registers.set(.r4, right_point_addr);
        registers.set(.r5, result_point_addr);

        try curveGroupOp(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            7,  251, 187, 86, 186, 232, 57,  242, 193, 236, 49, 200,
            90, 29,  254, 82, 46,  80,  83,  70,  244, 153, 23, 156,
            2,  138, 207, 51, 165, 38,  200, 85,
        }, &result_point);
    }

    {
        registers.set(.r1, 0); // CURVE25519_EDWARDS
        registers.set(.r2, 1); // SUB
        registers.set(.r3, left_point_addr);
        registers.set(.r4, right_point_addr);
        registers.set(.r5, result_point_addr);

        try curveGroupOp(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            60,  87,  90,  68,  232, 25, 7,   172, 247, 120, 158, 104,
            52,  127, 94,  244, 5,   79, 253, 15,  48,  69,  82,  134,
            155, 70,  188, 81,  108, 95, 212, 9,
        }, &result_point);
    }

    {
        registers.set(.r1, 0); // CURVE25519_EDWARDS
        registers.set(.r2, 2); // MUL
        registers.set(.r3, scalar_addr);
        registers.set(.r4, right_point_addr);
        registers.set(.r5, result_point_addr);

        try curveGroupOp(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            64,  150, 40,  55,  80,  49,  217, 209, 105, 229, 181, 65,
            241, 68,  2,   106, 220, 234, 211, 71,  159, 76,  156, 114,
            242, 68,  147, 31,  243, 211, 191, 124,
        }, &result_point);
    }
}

test "ristretto curve group operations" {
    const allocator = std.testing.allocator;

    const left_point = [_]u8{
        208, 165, 125, 204, 2,  100, 218, 17,  170, 194, 23, 9,  102, 156,
        134, 136, 217, 190, 98, 34,  183, 194, 228, 153, 92, 11, 108, 103,
        28,  57,  88,  15,
    };
    const left_point_addr = 0x100000000;

    const right_point = [_]u8{
        208, 241, 72,  163, 73, 53,  32,  174, 54, 194, 71, 8,  70,  181,
        244, 199, 93,  147, 99, 231, 162, 127, 25, 40,  39, 19, 140, 132,
        112, 212, 145, 108,
    };
    const right_point_addr = 0x200000000;

    const scalar = [_]u8{
        254, 198, 23, 138, 67, 243, 184, 110, 236, 115, 236, 205, 205, 215,
        79,  114, 45, 250, 78, 137, 3,   107, 136, 237, 49,  126, 117, 223,
        37,  191, 88, 6,
    };
    const scalar_addr = 0x300000000;

    const invalid_point = [_]u8{
        120, 140, 152, 233, 41, 227, 203, 27,  87,  115, 25, 251, 219, 5,
        84,  148, 117, 38,  84, 60,  87,  144, 161, 146, 42, 34,  91,  155,
        158, 189, 121, 79,
    };
    const invalid_point_addr = 0x400000000;

    var result_point: [32]u8 = undefined;
    const result_point_addr = 0x500000000;

    const compute_budget = sig.runtime.ComputeBudget.DEFAULT;
    const total_compute = (compute_budget.curve25519_ristretto_add_cost +
        compute_budget.curve25519_ristretto_subtract_cost +
        compute_budget.curve25519_ristretto_multiply_cost) * 2;

    const regions: []const memory.Region = &.{
        memory.Region.init(.constant, &left_point, left_point_addr),
        memory.Region.init(.constant, &right_point, right_point_addr),
        memory.Region.init(.constant, &scalar, scalar_addr),
        memory.Region.init(.constant, &invalid_point, invalid_point_addr),
        memory.Region.init(.mutable, &result_point, result_point_addr),
    };

    try sig.vm.tests.testSyscall(
        curveGroupOp,
        regions,
        // zig fmt: off
        &.{
            .{ .{ 1, 0, invalid_point_addr, right_point_addr,   result_point_addr }, 1 },
            .{ .{ 1, 1, invalid_point_addr, right_point_addr,   result_point_addr }, 1 },
            .{ .{ 1, 2, scalar_addr,        invalid_point_addr, result_point_addr }, 1 },
        },
        // zig fmt: on
        null,
        .{ .compute_meter = total_compute },
    );

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{.{
                .pubkey = sig.core.Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            }},
            .compute_meter = 10_000,
        },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, regions, .v2, .{});
    defer memory_map.deinit(allocator);

    {
        registers.set(.r1, 1); // CURVE25519_RISTRETTO
        registers.set(.r2, 0); // ADD
        registers.set(.r3, left_point_addr);
        registers.set(.r4, right_point_addr);
        registers.set(.r5, result_point_addr);

        try curveGroupOp(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            78,  173, 9,  241, 180, 224, 31,  107, 176, 210, 144,
            240, 118, 73, 70,  191, 128, 119, 141, 113, 125, 215,
            161, 71,  49, 176, 87,  38,  180, 177, 39,  78,
        }, &result_point);
    }

    {
        registers.set(.r1, 1); // CURVE25519_RISTRETTO
        registers.set(.r2, 1); // SUB
        registers.set(.r3, left_point_addr);
        registers.set(.r4, right_point_addr);
        registers.set(.r5, result_point_addr);

        try curveGroupOp(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            150, 72,  222, 61,  148, 79,  96,  130, 151, 176, 29,
            217, 231, 211, 0,   215, 76,  86,  212, 146, 110, 128,
            24,  151, 187, 144, 108, 233, 221, 208, 157, 52,
        }, &result_point);
    }

    {
        registers.set(.r1, 1); // CURVE25519_RISTRETTO
        registers.set(.r2, 2); // MUL
        registers.set(.r3, scalar_addr);
        registers.set(.r4, right_point_addr);
        registers.set(.r5, result_point_addr);

        try curveGroupOp(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            4,   16,  46,  2,   53,  151, 201, 133, 117, 149, 232, 164,
            119, 109, 136, 20,  153, 24,  124, 21,  101, 124, 80,  19,
            119, 100, 77,  108, 65,  187, 228, 5,
        }, &result_point);
    }
}

test "multiscalar multiplication" {
    const allocator = std.testing.allocator;

    const scalar_a = [_]u8{
        254, 198, 23, 138, 67, 243, 184, 110, 236, 115, 236, 205, 205, 215,
        79,  114, 45, 250, 78, 137, 3,   107, 136, 237, 49,  126, 117, 223,
        37,  191, 88, 6,
    };
    const scalar_b = [_]u8{
        254, 198, 23, 138, 67, 243, 184, 110, 236, 115, 236, 205, 205, 215,
        79,  114, 45, 250, 78, 137, 3,   107, 136, 237, 49,  126, 117, 223,
        37,  191, 88, 6,
    };
    const scalars: [2][32]u8 = .{ scalar_a, scalar_b };
    const scalars_addr = 0x100000000;

    const edwards_point_x = [_]u8{
        252, 31,  230, 46,  173, 95, 144, 148, 158, 157, 63, 10, 8,   68,
        58,  176, 142, 192, 168, 53, 61,  105, 194, 166, 43, 56, 246, 236,
        28,  146, 114, 133,
    };
    const edwards_point_y = [_]u8{
        10,  111, 8,   236, 97,  189, 124, 69,  89,  176, 222, 39,  199, 253,
        111, 11,  248, 186, 128, 90,  120, 128, 248, 210, 232, 183, 93,  104,
        111, 150, 7,   241,
    };
    const edwards_points: [2][32]u8 = .{ edwards_point_x, edwards_point_y };
    const edwards_points_addr = 0x200000000;

    const ristretto_point_x = [_]u8{
        130, 35,  97,  25,  18,  199, 33, 239, 85,  143, 119, 111, 49,  51,
        224, 40,  167, 185, 240, 179, 25, 194, 213, 41,  14,  155, 104, 18,
        181, 197, 15,  112,
    };
    const ristretto_point_y = [_]u8{
        152, 156, 155, 197, 152, 232, 92, 206, 219, 159, 193, 134, 121, 128,
        139, 36,  56,  191, 51,  143, 72, 204, 87,  76,  110, 124, 101, 96,
        238, 158, 42,  108,
    };
    const ristretto_points: [2][32]u8 = .{ ristretto_point_x, ristretto_point_y };
    const ristretto_points_addr = 0x300000000;

    var result_point: [32]u8 = undefined;
    const result_point_addr = 0x400000000;

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, &.{
        memory.Region.init(.constant, std.mem.sliceAsBytes(&scalars), scalars_addr),
        memory.Region.init(.constant, std.mem.sliceAsBytes(&edwards_points), edwards_points_addr),
        memory.Region.init(
            .constant,
            std.mem.sliceAsBytes(&ristretto_points),
            ristretto_points_addr,
        ),
        memory.Region.init(.mutable, &result_point, result_point_addr),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    const compute_budget = sig.runtime.ComputeBudget.DEFAULT;
    const total_compute = compute_budget.curve25519_edwards_msm_base_cost +
        compute_budget.curve25519_edwards_msm_incremental_cost +
        compute_budget.curve25519_ristretto_msm_base_cost +
        compute_budget.curve25519_ristretto_msm_incremental_cost;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{.{
                .pubkey = sig.core.Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            }},
            .compute_meter = total_compute,
        },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    {
        registers.set(.r1, 0); // CURVE25519_EDWARDS
        registers.set(.r2, scalars_addr);
        registers.set(.r3, edwards_points_addr);
        registers.set(.r4, 2);
        registers.set(.r5, result_point_addr);

        try curveMultiscalarMul(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            30,  174, 168, 34,  160, 70,  63,  166, 236, 18,  74, 144, 185,
            222, 208, 243, 5,   54,  223, 172, 185, 75,  244, 26, 70,  18,
            248, 46,  207, 184, 235, 60,
        }, &result_point);
    }

    {
        registers.set(.r1, 1); // CURVE25519_RISTRETTO
        registers.set(.r2, scalars_addr);
        registers.set(.r3, ristretto_points_addr);
        registers.set(.r4, 2);
        registers.set(.r5, result_point_addr);

        try curveMultiscalarMul(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            78,  120, 86,  111, 152, 64, 146, 84, 14,  236, 77,  147, 237,
            190, 251, 241, 136, 167, 21, 94,  84, 118, 92,  140, 120, 81,
            30,  246, 173, 140, 195, 86,
        }, &result_point);
    }
}

test "multiscalar multiplication large" {
    const allocator = std.testing.allocator;

    const scalar = [_]u8{
        254, 198, 23, 138, 67, 243, 184, 110, 236, 115, 236, 205, 205, 215,
        79,  114, 45, 250, 78, 137, 3,   107, 136, 237, 49,  126, 117, 223,
        37,  191, 88, 6,
    };
    const scalars: [513][32]u8 = .{scalar} ** 513;
    const scalars_addr = 0x100000000;

    const edwards_point = [_]u8{
        252, 31,  230, 46,  173, 95, 144, 148, 158, 157, 63, 10, 8,   68,
        58,  176, 142, 192, 168, 53, 61,  105, 194, 166, 43, 56, 246, 236,
        28,  146, 114, 133,
    };
    const edwards_points: [513][32]u8 = .{edwards_point} ** 513;
    const edwards_points_addr = 0x200000000;

    const ristretto_point = [_]u8{
        130, 35,  97,  25,  18,  199, 33, 239, 85,  143, 119, 111, 49,  51,
        224, 40,  167, 185, 240, 179, 25, 194, 213, 41,  14,  155, 104, 18,
        181, 197, 15,  112,
    };
    const ristretto_points: [513][32]u8 = .{ristretto_point} ** 513;
    const ristretto_points_addr = 0x300000000;

    var result_point: [32]u8 = undefined;
    const result_point_addr = 0x400000000;

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, &.{
        memory.Region.init(.constant, std.mem.sliceAsBytes(&scalars), scalars_addr),
        memory.Region.init(.constant, std.mem.sliceAsBytes(&edwards_points), edwards_points_addr),
        memory.Region.init(
            .constant,
            std.mem.sliceAsBytes(&ristretto_points),
            ristretto_points_addr,
        ),
        memory.Region.init(.mutable, &result_point, result_point_addr),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{.{
                .pubkey = sig.core.Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            }},
            .compute_meter = 500_000,
        },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    {
        tc.compute_meter = 500_000;

        registers.set(.r1, 0); // CURVE25519_EDWARDS
        registers.set(.r2, scalars_addr);
        registers.set(.r3, edwards_points_addr);
        registers.set(.r4, 512); // below maximum vector length
        registers.set(.r5, result_point_addr);

        try curveMultiscalarMul(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            20,  146, 226, 37, 22, 61,  86,  249, 208, 40, 38,  11,  126,
            101, 10,  82,  81, 77, 88,  209, 15,  76,  82, 251, 180, 133,
            84,  243, 162, 0,  11, 145,
        }, &result_point);
    }

    {
        tc.compute_meter = 500_000;

        registers.set(.r1, 0); // CURVE25519_EDWARDS
        registers.set(.r2, scalars_addr);
        registers.set(.r3, edwards_points_addr);
        registers.set(.r4, 513); // above maximum vector length
        registers.set(.r5, result_point_addr);

        try std.testing.expectError(
            error.InvalidLength,
            curveMultiscalarMul(&tc, &memory_map, &registers),
        );
    }

    {
        tc.compute_meter = 500_000;

        registers.set(.r1, 1); // CURVE25519_RISTRETTO
        registers.set(.r2, scalars_addr);
        registers.set(.r3, ristretto_points_addr);
        registers.set(.r4, 512); // below maximum vector length
        registers.set(.r5, result_point_addr);

        try curveMultiscalarMul(&tc, &memory_map, &registers);

        try std.testing.expectEqual(0, registers.get(.r0));
        try std.testing.expectEqualSlices(u8, &.{
            146, 224, 127, 193, 252, 64, 196, 181, 246, 104, 27, 116, 183, 52,
            200, 239, 2,   108, 21,  27, 97,  44,  95,  65,  26, 218, 223, 39,
            197, 132, 51,  49,
        }, &result_point);
    }

    {
        tc.compute_meter = 500_000;

        registers.set(.r1, 1); // CURVE25519_RISTRETTO
        registers.set(.r2, scalars_addr);
        registers.set(.r3, ristretto_points_addr);
        registers.set(.r4, 513); // above maximum vector length
        registers.set(.r5, result_point_addr);

        try std.testing.expectError(
            error.InvalidLength,
            curveMultiscalarMul(&tc, &memory_map, &registers),
        );
    }
}

test "alt_bn128 add" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 334 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const input: []const u8 = &.{
        0x18, 0xb1, 0x8a, 0xcf, 0xb4, 0xc2, 0xc3, 0x2,  0x76, 0xdb, 0x54,
        0x11, 0x36, 0x8e, 0x71, 0x85, 0xb3, 0x11, 0xdd, 0x12, 0x46, 0x91,
        0x61, 0xc,  0x5d, 0x3b, 0x74, 0x3,  0x4e, 0x9,  0x3d, 0xc9, 0x6,
        0x3c, 0x90, 0x9c, 0x47, 0x20, 0x84, 0xc,  0xb5, 0x13, 0x4c, 0xb9,
        0xf5, 0x9f, 0xa7, 0x49, 0x75, 0x57, 0x96, 0x81, 0x96, 0x58, 0xd3,
        0x2e, 0xfc, 0xd,  0x28, 0x81, 0x98, 0xf3, 0x72, 0x66, 0x7,  0xc2,
        0xb7, 0xf5, 0x8a, 0x84, 0xbd, 0x61, 0x45, 0xf0, 0xc,  0x9c, 0x2b,
        0xc0, 0xbb, 0x1a, 0x18, 0x7f, 0x20, 0xff, 0x2c, 0x92, 0x96, 0x3a,
        0x88, 0x1,  0x9e, 0x7c, 0x6a, 0x1,  0x4e, 0xed, 0x6,  0x61, 0x4e,
        0x20, 0xc1, 0x47, 0xe9, 0x40, 0xf2, 0xd7, 0xd,  0xa3, 0xf7, 0x4c,
        0x9a, 0x17, 0xdf, 0x36, 0x17, 0x6,  0xa4, 0x48, 0x5c, 0x74, 0x2b,
        0xd6, 0x78, 0x84, 0x78, 0xfa, 0x17, 0xd7,
    };
    const input_addr = 0x100000000;

    var result_point: [64]u8 = undefined;
    const result_point_addr = 0x200000000;

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, &.{
        memory.Region.init(.constant, input, input_addr),
        memory.Region.init(.mutable, &result_point, result_point_addr),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    registers.set(.r1, 0); // ADD
    registers.set(.r2, input_addr);
    registers.set(.r3, input.len);
    registers.set(.r4, result_point_addr);

    try altBn128GroupOp(&tc, &memory_map, &registers);

    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x22, 0x43, 0x52, 0x5c, 0x5e, 0xfd, 0x4b, 0x9c, 0x3d, 0x3c, 0x45,
            0xac, 0xc,  0xa3, 0xfe, 0x4d, 0xd8, 0x5e, 0x83, 0xa,  0x4c, 0xe6,
            0xb6, 0x5f, 0xa1, 0xee, 0xae, 0xe2, 0x2,  0x83, 0x97, 0x3,  0x30,
            0x1d, 0x1d, 0x33, 0xbe, 0x6d, 0xa8, 0xe5, 0x9,  0xdf, 0x21, 0xcc,
            0x35, 0x96, 0x47, 0x23, 0x18, 0xe,  0xed, 0x75, 0x32, 0x53, 0x7d,
            0xb9, 0xae, 0x5e, 0x7d, 0x48, 0xf1, 0x95, 0xc9, 0x15,
        },
        &result_point,
    );

    try std.testing.expectError(
        error.ComputationalBudgetExceeded,
        altBn128GroupOp(&tc, &memory_map, &registers),
    );
}

test "alt_bn128 mul" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 3_840 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const input: []const u8 = &.{
        0x2b, 0xd3, 0xe6, 0xd0, 0xf3, 0xb1, 0x42, 0x92, 0x4f, 0x5c, 0xa7, 0xb4,
        0x9c, 0xe5, 0xb9, 0xd5, 0x4c, 0x47, 0x3,  0xd7, 0xae, 0x56, 0x48, 0xe6,
        0x1d, 0x2,  0x26, 0x8b, 0x1a, 0xa,  0x9f, 0xb7, 0x21, 0x61, 0x1c, 0xe0,
        0xa6, 0xaf, 0x85, 0x91, 0x5e, 0x2f, 0x1d, 0x70, 0x30, 0x9,  0x9,  0xce,
        0x2e, 0x49, 0xdf, 0xad, 0x4a, 0x46, 0x19, 0xc8, 0x39, 0xc,  0xae, 0x66,
        0xce, 0xfd, 0xb2, 0x4,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
        0x0,  0x0,  0x0,  0x0,  0x11, 0x13, 0x8c, 0xe7, 0x50, 0xfa, 0x15, 0xc2,
    };
    const input_addr = 0x100000000;

    var result_point: [64]u8 = undefined;
    const result_point_addr = 0x200000000;

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, &.{
        memory.Region.init(.constant, input, input_addr),
        memory.Region.init(.mutable, &result_point, result_point_addr),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    registers.set(.r1, 2); // MUL
    registers.set(.r2, input_addr);
    registers.set(.r3, input.len);
    registers.set(.r4, result_point_addr);

    try altBn128GroupOp(&tc, &memory_map, &registers);

    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x7,  0xa,  0x8d, 0x6a, 0x98, 0x21, 0x53, 0xca, 0xe4, 0xbe, 0x29,
            0xd4, 0x34, 0xe8, 0xfa, 0xef, 0x8a, 0x47, 0xb2, 0x74, 0xa0, 0x53,
            0xf5, 0xa4, 0xee, 0x2a, 0x6c, 0x9c, 0x13, 0xc3, 0x1e, 0x5c, 0x3,
            0x1b, 0x8c, 0xe9, 0x14, 0xeb, 0xa3, 0xa9, 0xff, 0xb9, 0x89, 0xf9,
            0xcd, 0xd5, 0xb0, 0xf0, 0x19, 0x43, 0x7,  0x4b, 0xf4, 0xf0, 0xf3,
            0x15, 0x69, 0xe,  0xc3, 0xce, 0xc6, 0x98, 0x1a, 0xfc,
        },
        &result_point,
    );

    try std.testing.expectError(
        error.ComputationalBudgetExceeded,
        altBn128GroupOp(&tc, &memory_map, &registers),
    );
}

test "alt_bn128 pairing" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 48_986 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const input: []const u8 = &.{
        0x1c, 0x76, 0x47, 0x6f, 0x4d, 0xef, 0x4b, 0xb9, 0x45, 0x41, 0xd5, 0x7e,
        0xbb, 0xa1, 0x19, 0x33, 0x81, 0xff, 0xa7, 0xaa, 0x76, 0xad, 0xa6, 0x64,
        0xdd, 0x31, 0xc1, 0x60, 0x24, 0xc4, 0x3f, 0x59, 0x30, 0x34, 0xdd, 0x29,
        0x20, 0xf6, 0x73, 0xe2, 0x4,  0xfe, 0xe2, 0x81, 0x1c, 0x67, 0x87, 0x45,
        0xfc, 0x81, 0x9b, 0x55, 0xd3, 0xe9, 0xd2, 0x94, 0xe4, 0x5c, 0x9b, 0x3,
        0xa7, 0x6a, 0xef, 0x41, 0x20, 0x9d, 0xd1, 0x5e, 0xbf, 0xf5, 0xd4, 0x6c,
        0x4b, 0xd8, 0x88, 0xe5, 0x1a, 0x93, 0xcf, 0x99, 0xa7, 0x32, 0x96, 0x36,
        0xc6, 0x35, 0x14, 0x39, 0x6b, 0x4a, 0x45, 0x20, 0x3,  0xa3, 0x5b, 0xf7,
        0x4,  0xbf, 0x11, 0xca, 0x1,  0x48, 0x3b, 0xfa, 0x8b, 0x34, 0xb4, 0x35,
        0x61, 0x84, 0x8d, 0x28, 0x90, 0x59, 0x60, 0x11, 0x4c, 0x8a, 0xc0, 0x40,
        0x49, 0xaf, 0x4b, 0x63, 0x15, 0xa4, 0x16, 0x78, 0x2b, 0xb8, 0x32, 0x4a,
        0xf6, 0xcf, 0xc9, 0x35, 0x37, 0xa2, 0xad, 0x1a, 0x44, 0x5c, 0xfd, 0xc,
        0xa2, 0xa7, 0x1a, 0xcd, 0x7a, 0xc4, 0x1f, 0xad, 0xbf, 0x93, 0x3c, 0x2a,
        0x51, 0xbe, 0x34, 0x4d, 0x12, 0xa,  0x2a, 0x4c, 0xf3, 0xc,  0x1b, 0xf9,
        0x84, 0x5f, 0x20, 0xc6, 0xfe, 0x39, 0xe0, 0x7e, 0xa2, 0xcc, 0xe6, 0x1f,
        0xc,  0x9b, 0xb0, 0x48, 0x16, 0x5f, 0xe5, 0xe4, 0xde, 0x87, 0x75, 0x50,
        0x11, 0x1e, 0x12, 0x9f, 0x1c, 0xf1, 0x9,  0x77, 0x10, 0xd4, 0x1c, 0x4a,
        0xc7, 0xf,  0xcd, 0xfa, 0x5b, 0xa2, 0x2,  0x3c, 0x6f, 0xf1, 0xcb, 0xea,
        0xc3, 0x22, 0xde, 0x49, 0xd1, 0xb6, 0xdf, 0x7c, 0x20, 0x32, 0xc6, 0x1a,
        0x83, 0xe,  0x3c, 0x17, 0x28, 0x6d, 0xe9, 0x46, 0x2b, 0xf2, 0x42, 0xfc,
        0xa2, 0x88, 0x35, 0x85, 0xb9, 0x38, 0x70, 0xa7, 0x38, 0x53, 0xfa, 0xce,
        0x6a, 0x6b, 0xf4, 0x11, 0x19, 0x8e, 0x93, 0x93, 0x92, 0xd,  0x48, 0x3a,
        0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25, 0xf1, 0xaa, 0x49, 0x33,
        0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
        0x18, 0x0,  0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x0,  0x66,
        0x5e, 0x5c, 0x44, 0x79, 0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd,
        0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed, 0x9,  0x6,  0x89, 0xd0,
        0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99, 0xad, 0x69, 0xc,  0x33, 0x95,
        0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac, 0xda, 0xdc,
        0xd1, 0x22, 0x97, 0x5b, 0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb,
        0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f, 0xe3, 0xd1, 0xe7, 0x69,
        0xc,  0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x1,  0x66, 0xfa, 0x7d, 0xaa,
    };
    const input_addr = 0x100000000;

    var result_point: [32]u8 = undefined;
    const result_point_addr = 0x200000000;

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, &.{
        memory.Region.init(.constant, input, input_addr),
        memory.Region.init(.mutable, &result_point, result_point_addr),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    registers.set(.r1, 3); // PAIRING
    registers.set(.r2, input_addr);
    registers.set(.r3, input.len);
    registers.set(.r4, result_point_addr);

    try altBn128GroupOp(&tc, &memory_map, &registers);

    try std.testing.expectEqualSlices(
        u8,
        &.{
            // Is a valid pairing.
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
        },
        &result_point,
    );

    try std.testing.expectError(
        error.ComputationalBudgetExceeded,
        altBn128GroupOp(&tc, &memory_map, &registers),
    );
}

test "alt_bn128 g1 compress/decompress" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 628 * 2 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const input_addr = 0x100000000;
    const result_point_addr = 0x200000000;

    var buffer: [64]u8 = undefined;

    inline for (.{ &.{
        45,  206, 255, 166, 152, 55,  128, 138, 79,  217, 145, 164, 25,  74,  120, 234, 234, 217,
        68,  149, 162, 44,  133, 120, 184, 205, 12,  44,  175, 98,  168, 172, 20,  24,  216, 15,
        209, 175, 106, 75,  147, 236, 90,  101, 123, 219, 245, 151, 209, 202, 218, 104, 148, 8,
        32,  254, 243, 191, 218, 122, 42,  81,  193, 84,
    }, &.{
        45,  206, 255, 166, 152, 55,  128, 138, 79, 217, 145, 164, 25,  74,  120, 234, 234, 217,
        68,  149, 162, 44,  133, 120, 184, 205, 12, 44,  175, 98,  168, 172, 28,  75,  118, 99,
        15,  130, 53,  222, 36,  99,  235, 81,  5,  165, 98,  197, 197, 182, 144, 40,  212, 105,
        169, 142, 72,  96,  177, 156, 174, 43,  59, 243,
    } }) |entry| {
        var registers = sig.vm.interpreter.RegisterMap.initFill(0);
        var memory_map = try MemoryMap.init(allocator, &.{
            memory.Region.init(.constant, entry, input_addr),
            memory.Region.init(.mutable, &buffer, result_point_addr),
        }, .v2, .{});
        defer memory_map.deinit(allocator);

        {
            registers.set(.r1, 0); // g1_compress
            registers.set(.r2, input_addr);
            registers.set(.r3, entry.len);
            registers.set(.r4, result_point_addr);

            try altBn128Compression(&tc, &memory_map, &registers);
        }
        {
            registers.set(.r1, 1); // g1_decompress
            registers.set(.r2, result_point_addr);
            registers.set(.r3, 32);
            registers.set(.r4, result_point_addr);

            try altBn128Compression(&tc, &memory_map, &registers);
        }

        try std.testing.expectEqualSlices(u8, entry, &buffer);
    }

    try std.testing.expectEqual(0, tc.compute_meter);
}

test "alt_bn128 g2 compress/decompress" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 13_896 * 2 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const input_addr = 0x100000000;
    const result_point_addr = 0x200000000;

    inline for (.{ &.{
        40,  57,  233, 205, 180, 46,  35,  111, 215, 5,   23,  93,  12,  71,  118, 225, 7,   46,
        247, 147, 47,  130, 106, 189, 184, 80,  146, 103, 141, 52,  242, 25,  0,   203, 124, 176,
        110, 34,  151, 212, 66,  180, 238, 151, 236, 189, 133, 209, 17,  137, 205, 183, 168, 196,
        92,  159, 75,  174, 81,  168, 18,  86,  176, 56,  16,  26,  210, 20,  18,  81,  122, 142,
        104, 62,  251, 169, 98,  141, 21,  253, 50,  130, 182, 15,  33,  109, 228, 31,  79,  183,
        88,  147, 174, 108, 4,   22,  14,  129, 168, 6,   80,  246, 254, 100, 218, 131, 94,  49,
        247, 211, 3,   245, 22,  200, 177, 91,  60,  144, 147, 174, 90,  17,  19,  189, 62,  147,
        152, 18,
    }, &.{
        40,  57,  233, 205, 180, 46,  35,  111, 215, 5,   23,  93,  12,  71,  118, 225, 7,   46,
        247, 147, 47,  130, 106, 189, 184, 80,  146, 103, 141, 52,  242, 25,  0,   203, 124, 176,
        110, 34,  151, 212, 66,  180, 238, 151, 236, 189, 133, 209, 17,  137, 205, 183, 168, 196,
        92,  159, 75,  174, 81,  168, 18,  86,  176, 56,  32,  73,  124, 94,  206, 224, 37,  155,
        80,  17,  74,  13,  30,  244, 66,  96,  100, 254, 180, 130, 71,  3,   230, 109, 236, 105,
        51,  131, 42,  16,  249, 49,  33,  226, 166, 108, 144, 58,  161, 196, 221, 204, 231, 132,
        137, 174, 84,  104, 128, 184, 185, 54,  43,  225, 54,  222, 226, 15,  120, 89,  153, 233,
        101, 53,
    } }) |entry| {
        var buffer: [128]u8 = undefined;

        var registers = sig.vm.interpreter.RegisterMap.initFill(0);
        var memory_map = try MemoryMap.init(allocator, &.{
            memory.Region.init(.constant, entry, input_addr),
            memory.Region.init(.mutable, &buffer, result_point_addr),
        }, .v2, .{});
        defer memory_map.deinit(allocator);

        {
            registers.set(.r1, 2); // g2_compress
            registers.set(.r2, input_addr);
            registers.set(.r3, entry.len);
            registers.set(.r4, result_point_addr);

            try altBn128Compression(&tc, &memory_map, &registers);
        }
        {
            registers.set(.r1, 3); // g2_decompress
            registers.set(.r2, result_point_addr);
            registers.set(.r3, 64);
            registers.set(.r4, result_point_addr);

            try altBn128Compression(&tc, &memory_map, &registers);
        }

        try std.testing.expectEqualSlices(u8, entry, &buffer);
    }

    try std.testing.expectEqual(0, tc.compute_meter);
}

test "alt_bn128 compression failure cases" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{.{
                .pubkey = sig.core.Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            }},
            // one compress + two decompress + (3 * base_cost)
            .compute_meter = 86 + (13_610 * 2) + 300,
            .feature_set = &.{.{
                .feature = .simplify_alt_bn128_syscall_error_codes,
                .slot = 0,
            }},
        },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const input_addr = 0x100000000;
    const result_point_addr = 0x200000000;

    const entry: [128]u8 = .{
        40,  57,  233, 205, 180, 46,  35,  111, 215, 5,   23,  93,  12,  71,  118, 225, 7,   46,
        247, 147, 47,  130, 106, 189, 184, 80,  146, 103, 141, 52,  242, 25,  0,   203, 124, 176,
        110, 34,  151, 212, 66,  180, 238, 151, 236, 189, 133, 209, 17,  137, 205, 183, 168, 196,
        92,  159, 75,  174, 81,  168, 18,  86,  176, 56,  16,  26,  210, 20,  18,  81,  122, 142,
        104, 62,  251, 169, 98,  141, 21,  253, 50,  130, 182, 15,  33,  109, 228, 31,  79,  183,
        88,  147, 174, 108, 4,   22,  14,  129, 168, 6,   80,  246, 254, 100, 218, 131, 94,  49,
        247, 211, 3,   245, 22,  200, 177, 91,  60,  144, 147, 174, 90,  17,  19,  189, 62,  147,
        152, 18,
    };
    var buffer: [128]u8 = undefined;

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, &.{
        memory.Region.init(.constant, &entry, input_addr),
        memory.Region.init(.mutable, &buffer, result_point_addr),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    // failure case: invalid data passed to decompress

    {
        registers.set(.r1, 2); // g2_compress
        registers.set(.r2, input_addr);
        registers.set(.r3, entry.len);
        registers.set(.r4, result_point_addr);

        try altBn128Compression(&tc, &memory_map, &registers);
    }

    // oh no, something bad happened to the data!
    buffer[3] = 20;

    {
        registers.set(.r1, 3); // g2_decompress
        registers.set(.r2, result_point_addr);
        registers.set(.r3, 64);
        registers.set(.r4, result_point_addr);

        try altBn128Compression(&tc, &memory_map, &registers);

        // make sure 1 was written as the output
        try std.testing.expectEqual(1, registers.get(.r0));
    }

    // failure case: incorrect input length

    {
        registers.set(.r1, 3); // g2_decompress
        registers.set(.r2, result_point_addr);
        // wrong length! we choose a smaller length rather than a
        // larger one to avid out of bounds access violation
        registers.set(.r3, 32);
        registers.set(.r4, result_point_addr);

        try altBn128Compression(&tc, &memory_map, &registers);

        // make sure 1 was written as the output
        try std.testing.expectEqual(1, registers.get(.r0));
    }

    // make sure the compute was still taken
    try std.testing.expectEqual(0, tc.compute_meter);
}

test "alt_bn128 group op failure cases" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{.{
                .pubkey = sig.core.Pubkey.initRandom(prng.random()),
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            }},
            // one compress + two decompress + (3 * base_cost)
            .compute_meter = 334,
            .feature_set = &.{.{
                .feature = .simplify_alt_bn128_syscall_error_codes,
                .slot = 0,
            }},
        },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const input_addr = 0x100000000;
    const result_point_addr = 0x200000000;

    // Invalid input, doesn't create a valid projection.
    const entry: [64]u8 = @splat(0xAA);
    var buffer: [128]u8 = undefined;

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, &.{
        memory.Region.init(.constant, &entry, input_addr),
        memory.Region.init(.mutable, &buffer, result_point_addr),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    {
        registers.set(.r1, 0); // add
        registers.set(.r2, input_addr);
        registers.set(.r3, entry.len);
        registers.set(.r4, result_point_addr);

        try altBn128GroupOp(&tc, &memory_map, &registers);
    }

    try std.testing.expectEqual(0, tc.compute_meter);
}

test "secp256k1_recover" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 25_000,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const message_hash_addr = 0x100000000;
    const message_hash: [32]u8 = .{
        0xde, 0xa5, 0x66, 0xb6, 0x94, 0x3b, 0xe0, 0xe9, 0x62, 0x53, 0xc2, 0x21, 0x5b, 0x1b, 0xac,
        0x69, 0xe7, 0xa8, 0x1e, 0xdb, 0x41, 0xc5, 0x02, 0x8b, 0x4f, 0x5c, 0x45, 0xc5, 0x3b, 0x49,
        0x54, 0xd0,
    };

    const signature_addr = 0x200000000;
    const signature: [64]u8 = .{
        0x97, 0xa4, 0xee, 0x31, 0xfe, 0x82, 0x65, 0x72, 0x9f, 0x4a, 0xa6, 0x7d, 0x24,
        0xd4, 0xa7, 0x27, 0xf8, 0xc3, 0x15, 0xa4, 0xc8, 0xf9, 0x80, 0xeb, 0x4c, 0x4d,
        0x4a, 0xfa, 0x6e, 0xc9, 0x42, 0x41, 0x5d, 0x10, 0xd9, 0xc2, 0x8a, 0x90, 0xe9,
        0x92, 0x9c, 0x52, 0x4b, 0x2c, 0xfb, 0x65, 0xdf, 0xbc, 0xf6, 0x8c, 0xfd, 0x68,
        0xdb, 0x17, 0xf9, 0x5d, 0x23, 0x5f, 0x96, 0xd8, 0xf0, 0x72, 0x01, 0x2d,
    };

    const invalid_signature_addr = 0x300000000;
    const invalid_signature: [64]u8 = @splat(0);

    const result_point_addr = 0x400000000;
    var result_point: [64]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &message_hash, message_hash_addr),
        .init(.constant, &signature, signature_addr),
        .init(.constant, &invalid_signature, invalid_signature_addr),
        .init(.mutable, &result_point, result_point_addr),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0); // exit code
    registers.set(.r1, message_hash_addr);
    registers.set(.r2, 1); // recovery id
    registers.set(.r3, signature_addr);
    registers.set(.r4, result_point_addr);

    try secp256k1Recover(&tc, &memory_map, &registers);

    try std.testing.expectEqual(0, registers.get(.r0)); // unchanged (success)
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x42, 0xcd, 0x27, 0xe4, 0x0f, 0xdf, 0x7c, 0x97, 0x0a, 0xa2, 0xca, 0x0b, 0x88, 0x5b, 0x96,
            0x0f, 0x8b, 0x62, 0x8a, 0x41, 0xa1, 0x81, 0xe7, 0xe6, 0x8e, 0x03, 0xea, 0x0b, 0x84, 0x20,
            0x58, 0x9b, 0x32, 0x06, 0xbd, 0x66, 0x2f, 0x75, 0x65, 0xd6, 0x9d, 0xbd, 0x1d, 0x34, 0x29,
            0x6a, 0xd9, 0x35, 0x38, 0xed, 0x86, 0x9e, 0x99, 0x20, 0x43, 0xc3, 0xeb, 0xad, 0x65, 0x50,
            0xa0, 0x11, 0x6e, 0x5d,
        },
        &result_point,
    );
    try std.testing.expectError(
        error.ComputationalBudgetExceeded,
        secp256k1Recover(&tc, &memory_map, &registers),
    );

    tc.compute_meter += tc.compute_budget.secp256k1_recover_cost;
    registers.set(.r2, 4); // invalid recovery id
    try secp256k1Recover(&tc, &memory_map, &registers);
    try std.testing.expectEqual(2, registers.get(.r0)); // InvalidRecoveryId

    tc.compute_meter += tc.compute_budget.secp256k1_recover_cost;
    registers.set(.r0, 0);
    registers.set(.r2, 1);
    registers.set(.r3, invalid_signature_addr);
    try secp256k1Recover(&tc, &memory_map, &registers);
    try std.testing.expectEqual(3, registers.get(.r0)); // InvalidSignature

    try std.testing.expectEqual(0, tc.compute_meter);
}

test "bls12-381 g1 add" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 128 * 2,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const p1_bytes_be: [96]u8 = .{
        9,   86,  169, 212, 236, 245, 17,  101, 127, 183, 56,  13,  99,  100, 183, 133, 57,  107,
        96,  220, 198, 197, 2,   215, 225, 175, 212, 57,  168, 143, 104, 127, 117, 242, 180, 200,
        162, 135, 72,  155, 88,  154, 58,  90,  58,  46,  248, 176, 10,  206, 25,  112, 240, 1,
        57,  89,  10,  30,  165, 94,  164, 252, 219, 225, 133, 214, 161, 4,   118, 177, 123, 53,
        57,  53,  233, 255, 112, 117, 241, 247, 185, 195, 232, 36,  123, 31,  221, 6,   57,  176,
        251, 163, 195, 39,  35,  175,
    };
    const p2_bytes_be: [96]u8 = .{
        13,  32,  61,  215, 83,  124, 186, 189, 82,  0,   79,  244, 67,  167, 21,  50,  48,  229,
        8,   107, 51,  15,  19,  47,  75,  77,  246, 185, 63,  66,  143, 109, 237, 211, 153, 146,
        163, 175, 74,  69,  50,  198, 235, 218, 9,   170, 225, 46,  22,  211, 116, 84,  32,  115,
        130, 224, 106, 250, 205, 143, 238, 115, 74,  207, 238, 193, 232, 16,  59,  140, 20,  252,
        7,   34,  144, 47,  137, 56,  190, 170, 235, 189, 238, 45,  97,  58,  199, 202, 45,  164,
        139, 200, 190, 215, 9,   59,
    };
    const expected_sum_be: [96]u8 = .{
        23,  62,  255, 137, 157, 188, 98,  86,  192, 102, 136, 171, 187, 49,  155, 83,  204, 133,
        217, 144, 137, 103, 15,  4,   116, 75,  127, 65,  29,  89,  223, 147, 32,  161, 91,  104,
        96,  211, 239, 102, 233, 95,  48,  130, 207, 154, 19,  189, 18,  112, 102, 145, 36,  73,
        17,  27,  47,  96,  116, 45,  56,  25,  16,  191, 56,  21,  86,  216, 133, 245, 207, 71,
        158, 31,  29,  51,  84,  185, 134, 138, 64,  68,  55,  161, 55,  153, 214, 155, 250, 21,
        233, 4,   3,   117, 41,  239,
    };
    const p1_bytes_le: [96]u8 = .{
        176, 248, 46,  58,  90,  58,  154, 88,  155, 72,  135, 162, 200, 180, 242, 117, 127, 104,
        143, 168, 57,  212, 175, 225, 215, 2,   197, 198, 220, 96,  107, 57,  133, 183, 100, 99,
        13,  56,  183, 127, 101, 17,  245, 236, 212, 169, 86,  9,   175, 35,  39,  195, 163, 251,
        176, 57,  6,   221, 31,  123, 36,  232, 195, 185, 247, 241, 117, 112, 255, 233, 53,  57,
        53,  123, 177, 118, 4,   161, 214, 133, 225, 219, 252, 164, 94,  165, 30,  10,  89,  57,
        1,   240, 112, 25,  206, 10,
    };
    const p2_bytes_le: [96]u8 = .{
        46,  225, 170, 9,   218, 235, 198, 50,  69,  74,  175, 163, 146, 153, 211, 237, 109, 143,
        66,  63,  185, 246, 77,  75,  47,  19,  15,  51,  107, 8,   229, 48,  50,  21,  167, 67,
        244, 79,  0,   82,  189, 186, 124, 83,  215, 61,  32,  13,  59,  9,   215, 190, 200, 139,
        164, 45,  202, 199, 58,  97,  45,  238, 189, 235, 170, 190, 56,  137, 47,  144, 34,  7,
        252, 20,  140, 59,  16,  232, 193, 238, 207, 74,  115, 238, 143, 205, 250, 106, 224, 130,
        115, 32,  84,  116, 211, 22,
    };
    const expected_sum_le: [96]u8 = .{
        189, 19,  154, 207, 130, 48,  95,  233, 102, 239, 211, 96,  104, 91,  161, 32,  147, 223,
        89,  29,  65,  127, 75,  116, 4,   15,  103, 137, 144, 217, 133, 204, 83,  155, 49,  187,
        171, 136, 102, 192, 86,  98,  188, 157, 137, 255, 62,  23,  239, 41,  117, 3,   4,   233,
        21,  250, 155, 214, 153, 55,  161, 55,  68,  64,  138, 134, 185, 84,  51,  29,  31,  158,
        71,  207, 245, 133, 216, 86,  21,  56,  191, 16,  25,  56,  45,  116, 96,  47,  27,  17,
        73,  36,  145, 102, 112, 18,
    };

    const p1_be_va = 0x100000000;
    const p2_be_va = 0x200000000;
    const result_be_va = 0x300000000;
    const p1_le_va = 0x400000000;
    const p2_le_va = 0x500000000;
    const result_le_va = 0x600000000;

    var result_le: [96]u8 = undefined;
    var result_be: [96]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &p1_bytes_be, p1_be_va),
        .init(.constant, &p2_bytes_be, p2_be_va),
        .init(.mutable, &result_be, result_be_va),
        .init(.constant, &p1_bytes_le, p1_le_va),
        .init(.constant, &p2_bytes_le, p2_le_va),
        .init(.mutable, &result_le, result_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_be)); // Big endian
    registers.set(.r2, @intFromEnum(GroupOp.add));
    registers.set(.r3, p1_be_va);
    registers.set(.r4, p2_be_va);
    registers.set(.r5, result_be_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_sum_be, &result_be);

    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_le)); // Little endian
    registers.set(.r2, @intFromEnum(GroupOp.add));
    registers.set(.r3, p1_le_va);
    registers.set(.r4, p2_le_va);
    registers.set(.r5, result_le_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_sum_le, &result_le);
}

test "bls12-381 g1 sub" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 129 * 2,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const p1_bytes_be: [96]u8 = .{
        6,   126, 67,  177, 221, 168, 219, 147, 17,  32,  109, 112, 204, 95,  207, 179, 227, 202,
        32,  250, 118, 43,  195, 105, 176, 47,  188, 43,  181, 226, 123, 119, 132, 240, 97,  172,
        225, 247, 180, 76,  58,  229, 188, 121, 247, 28,  245, 198, 17,  128, 94,  239, 206, 10,
        10,  20,  148, 186, 226, 202, 12,  196, 71,  72,  167, 44,  87,  64,  24,  214, 238, 218,
        6,   166, 113, 165, 178, 8,   221, 0,   21,  154, 72,  160, 158, 70,  46,  244, 127, 4,
        250, 158, 31,  2,   130, 152,
    };
    const p2_bytes_be: [96]u8 = .{
        12,  173, 131, 106, 17,  172, 169, 46,  205, 228, 83,  25,  204, 216, 118, 223, 16,  102,
        52,  235, 202, 255, 183, 91,  99,  78,  141, 169, 14,  244, 161, 28,  240, 32,  214, 46,
        0,   93,  106, 73,  41,  176, 220, 160, 251, 37,  18,  110, 15,  86,  67,  210, 137, 114,
        71,  220, 167, 121, 177, 224, 142, 151, 152, 29,  206, 12,  35,  6,   46,  60,  53,  127,
        84,  78,  231, 88,  49,  95,  219, 36,  224, 182, 0,   253, 136, 115, 59,  15,  80,  229,
        136, 103, 27,  211, 120, 90,
    };
    const expected_sub_be: [96]u8 = .{
        13,  144, 131, 116, 67,  229, 136, 165, 135, 146, 181, 191, 197, 215, 68,  126, 103, 158,
        231, 50,  49,  105, 8,   243, 53,  209, 99,  16,  39,  177, 211, 99,  128, 164, 37,  101,
        139, 186, 14,  225, 84,  210, 120, 16,  203, 115, 160, 49,  10,  243, 68,  241, 87,  193,
        186, 179, 87,  214, 88,  39,  123, 126, 136, 31,  178, 134, 203, 222, 127, 206, 218, 240,
        135, 183, 93,  145, 136, 148, 174, 238, 159, 0,   117, 212, 171, 247, 148, 197, 206, 7,
        225, 81,  114, 74,  63,  201,
    };
    const p1_bytes_le: [96]u8 = .{
        198, 245, 28,  247, 121, 188, 229, 58,  76,  180, 247, 225, 172, 97,  240, 132, 119, 123,
        226, 181, 43,  188, 47,  176, 105, 195, 43,  118, 250, 32,  202, 227, 179, 207, 95,  204,
        112, 109, 32,  17,  147, 219, 168, 221, 177, 67,  126, 6,   152, 130, 2,   31,  158, 250,
        4,   127, 244, 46,  70,  158, 160, 72,  154, 21,  0,   221, 8,   178, 165, 113, 166, 6,
        218, 238, 214, 24,  64,  87,  44,  167, 72,  71,  196, 12,  202, 226, 186, 148, 20,  10,
        10,  206, 239, 94,  128, 17,
    };
    const p2_bytes_le: [96]u8 = .{
        110, 18,  37,  251, 160, 220, 176, 41,  73,  106, 93,  0,   46,  214, 32,  240, 28,  161,
        244, 14,  169, 141, 78,  99,  91,  183, 255, 202, 235, 52,  102, 16,  223, 118, 216, 204,
        25,  83,  228, 205, 46,  169, 172, 17,  106, 131, 173, 12,  90,  120, 211, 27,  103, 136,
        229, 80,  15,  59,  115, 136, 253, 0,   182, 224, 36,  219, 95,  49,  88,  231, 78,  84,
        127, 53,  60,  46,  6,   35,  12,  206, 29,  152, 151, 142, 224, 177, 121, 167, 220, 71,
        114, 137, 210, 67,  86,  15,
    };
    const expected_sub_le: [96]u8 = .{
        49,  160, 115, 203, 16,  120, 210, 84,  225, 14,  186, 139, 101, 37,  164, 128, 99,  211,
        177, 39,  16,  99,  209, 53,  243, 8,   105, 49,  50,  231, 158, 103, 126, 68,  215, 197,
        191, 181, 146, 135, 165, 136, 229, 67,  116, 131, 144, 13,  201, 63,  74,  114, 81,  225,
        7,   206, 197, 148, 247, 171, 212, 117, 0,   159, 238, 174, 148, 136, 145, 93,  183, 135,
        240, 218, 206, 127, 222, 203, 134, 178, 31,  136, 126, 123, 39,  88,  214, 87,  179, 186,
        193, 87,  241, 68,  243, 10,
    };

    const p1_be_va = 0x100000000;
    const p2_be_va = 0x200000000;
    const result_be_va = 0x300000000;
    const p1_le_va = 0x400000000;
    const p2_le_va = 0x500000000;
    const result_le_va = 0x600000000;

    var result_le: [96]u8 = undefined;
    var result_be: [96]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &p1_bytes_be, p1_be_va),
        .init(.constant, &p2_bytes_be, p2_be_va),
        .init(.mutable, &result_be, result_be_va),
        .init(.constant, &p1_bytes_le, p1_le_va),
        .init(.constant, &p2_bytes_le, p2_le_va),
        .init(.mutable, &result_le, result_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_be)); // Big endian
    registers.set(.r2, @intFromEnum(GroupOp.subtract));
    registers.set(.r3, p1_be_va);
    registers.set(.r4, p2_be_va);
    registers.set(.r5, result_be_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_sub_be, &result_be);

    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_le)); // Little endian
    registers.set(.r2, @intFromEnum(GroupOp.subtract));
    registers.set(.r3, p1_le_va);
    registers.set(.r4, p2_le_va);
    registers.set(.r5, result_le_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_sub_le, &result_le);
}

test "bls12-381 g1 mul" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 4_627 * 2,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const p1_bytes_be: [96]u8 = .{
        20,  18,  233, 201, 110, 206, 56,  32,  8,   44,  140, 121, 37,  196, 157, 56,  180, 134,
        164, 33,  180, 130, 147, 7,   26,  239, 183, 163, 219, 85,  143, 197, 247, 243, 117, 252,
        201, 171, 156, 90,  210, 7,   43,  92,  89,  130, 165, 224, 5,   101, 24,  54,  189, 22,
        73,  76,  145, 136, 99,  59,  51,  255, 124, 43,  61,  8,   121, 30,  118, 90,  254, 12,
        126, 92,  152, 78,  44,  231, 126, 56,  220, 35,  54,  117, 2,   175, 190, 105, 138, 188,
        202, 36,  171, 12,  231, 225,
    };
    const mul_scalar_be: [32]u8 = .{
        29,  192, 111, 151, 187, 37, 109, 91, 129, 223, 188, 225, 117, 3,   120, 162, 107, 66,
        159, 255, 61,  128, 41,  32, 242, 95, 232, 202, 106, 188, 154, 147,
    };
    const expected_mul_be: [96]u8 = .{
        22,  101, 72,  255, 3,   247, 39,  218, 234, 117, 208, 91,  158, 114, 126, 55,  166, 71,
        227, 205, 6,   124, 55,  255, 167, 66,  154, 237, 83,  143, 8,   179, 98,  185, 162, 164,
        170, 62,  141, 4,   1,   179, 41,  49,  95,  212, 139, 227, 18,  125, 245, 10,  169, 201,
        171, 172, 152, 1,   105, 81,  159, 160, 252, 184, 80,  59,  165, 170, 185, 114, 248, 208,
        228, 111, 229, 200, 221, 204, 9,   120, 153, 142, 88,  240, 228, 164, 157, 79,  72,  55,
        119, 239, 56,  104, 54,  58,
    };
    const p1_bytes_le: [96]u8 = .{
        224, 165, 130, 89,  92,  43,  7,   210, 90,  156, 171, 201, 252, 117, 243, 247, 197, 143,
        85,  219, 163, 183, 239, 26,  7,   147, 130, 180, 33,  164, 134, 180, 56,  157, 196, 37,
        121, 140, 44,  8,   32,  56,  206, 110, 201, 233, 18,  20,  225, 231, 12,  171, 36,  202,
        188, 138, 105, 190, 175, 2,   117, 54,  35,  220, 56,  126, 231, 44,  78,  152, 92,  126,
        12,  254, 90,  118, 30,  121, 8,   61,  43,  124, 255, 51,  59,  99,  136, 145, 76,  73,
        22,  189, 54,  24,  101, 5,
    };
    const mul_scalar_le: [32]u8 = .{
        147, 154, 188, 106, 202, 232, 95,  242, 32,  41,  128, 61,  255, 159, 66, 107, 162, 120, 3,
        117, 225, 188, 223, 129, 91,  109, 37,  187, 151, 111, 192, 29,
    };
    const expected_mul_le: [96]u8 = .{
        227, 139, 212, 95,  49,  41,  179, 1,  4,   141, 62,  170, 164, 162, 185, 98,  179, 8,
        143, 83,  237, 154, 66,  167, 255, 55, 124, 6,   205, 227, 71,  166, 55,  126, 114, 158,
        91,  208, 117, 234, 218, 39,  247, 3,  255, 72,  101, 22,  58,  54,  104, 56,  239, 119,
        55,  72,  79,  157, 164, 228, 240, 88, 142, 153, 120, 9,   204, 221, 200, 229, 111, 228,
        208, 248, 114, 185, 170, 165, 59,  80, 184, 252, 160, 159, 81,  105, 1,   152, 172, 171,
        201, 169, 10,  245, 125, 18,
    };

    const point_be_va = 0x100000000;
    const scalar_be_va = 0x200000000;
    const result_be_va = 0x300000000;
    const point_le_va = 0x400000000;
    const scalar_le_va = 0x500000000;
    const result_le_va = 0x600000000;

    var result_le: [96]u8 = undefined;
    var result_be: [96]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &p1_bytes_be, point_be_va),
        .init(.constant, &mul_scalar_be, scalar_be_va),
        .init(.mutable, &result_be, result_be_va),
        .init(.constant, &p1_bytes_le, point_le_va),
        .init(.constant, &mul_scalar_le, scalar_le_va),
        .init(.mutable, &result_le, result_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_be)); // Big endian
    registers.set(.r2, @intFromEnum(GroupOp.multiply));
    registers.set(.r3, scalar_be_va);
    registers.set(.r4, point_be_va);
    registers.set(.r5, result_be_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_mul_be, &result_be);

    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_le)); // Little endian
    registers.set(.r2, @intFromEnum(GroupOp.multiply));
    registers.set(.r3, scalar_le_va);
    registers.set(.r4, point_le_va);
    registers.set(.r5, result_le_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_mul_le, &result_le);
}

test "bls12-381 g2 add" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 203 * 2,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const p1_bytes_be: [192]u8 = .{
        11,  83,  21,  62,  4,   174, 123, 131, 163, 19,  62,  216, 192, 48,  25,  184, 57,  207,
        80,  70,  253, 51,  129, 169, 87,  182, 142, 1,   148, 102, 203, 99,  86,  111, 207, 55,
        204, 117, 82,  138, 199, 89,  131, 207, 158, 244, 204, 139, 18,  151, 214, 201, 158, 39,
        101, 252, 189, 53,  251, 236, 205, 27,  152, 163, 232, 101, 53,  197, 18,  238, 241, 70,
        182, 113, 111, 249, 99,  122, 42,  220, 55,  127, 55,  247, 172, 164, 183, 169, 146, 229,
        218, 185, 144, 176, 86,  174, 21,  132, 150, 29,  241, 241, 215, 77,  12,  75,  238, 103,
        23,  90,  189, 191, 85,  72,  181, 214, 85,  253, 183, 150, 158, 8,   250, 178, 220, 169,
        215, 243, 146, 213, 150, 12,  6,   40,  188, 197, 56,  210, 46,  125, 87,  5,   17,  7,
        24,  27,  160, 22,  99,  114, 9,   7,   244, 108, 179, 201, 38,  33,  153, 219, 10,  211,
        2,   212, 74,  95,  151, 223, 200, 96,  121, 166, 10,  186, 122, 40,  222, 87,  34,  227,
        49,  166, 195, 139, 37,  221, 44,  227, 86,  119, 190, 41,
    };
    const p2_bytes_be: [192]u8 = .{
        14,  110, 180, 174, 46,  74,  145, 125, 94,  28,  39,  205, 107, 126, 53,  188, 36,  69,
        162, 98,  105, 79,  49,  148, 136, 229, 5,   128, 197, 187, 0,   234, 141, 201, 246, 223,
        103, 75,  177, 33,  2,   75,  90,  33,  139, 152, 156, 89,  25,  91,  158, 100, 20,  12,
        135, 130, 191, 181, 5,   41,  94,  195, 89,  36,  181, 111, 238, 24,  187, 178, 179, 143,
        17,  181, 68,  203, 184, 134, 185, 195, 176, 27,  90,  2,   29,  165, 209, 16,  143, 11,
        224, 251, 63,  188, 218, 41,  23,  71,  91,  90,  202, 108, 80,  160, 200, 194, 162, 109,
        200, 96,  5,   102, 156, 245, 43,  247, 221, 139, 148, 254, 253, 183, 161, 83,  253, 247,
        22,  71,  133, 93,  36,  127, 162, 248, 49,  64,  173, 201, 17,  210, 8,   214, 18,  65,
        7,   222, 11,  4,   120, 17,  85,  49,  205, 95,  132, 208, 152, 136, 92,  19,  195, 176,
        136, 39,  90,  207, 17,  195, 14,  215, 33,  191, 232, 59,  3,   86,  78,  78,  149, 165,
        179, 145, 161, 190, 247, 67,  243, 252, 137, 1,   39,  71,
    };
    const expected_sum_be: [192]u8 = .{
        21,  157, 10,  251, 156, 56,  24,  174, 24,  91,  98,  201, 33,  37,  68,  76,  41,  161,
        12,  166, 16,  128, 161, 31,  108, 31,  92,  216, 56,  197, 198, 66,  210, 6,   64,  106,
        154, 96,  135, 57,  170, 119, 220, 210, 238, 73,  98,  83,  15,  146, 74,  122, 70,  40,
        186, 123, 191, 139, 11,  249, 221, 20,  12,  62,  81,  37,  191, 22,  248, 113, 78,  124,
        29,  157, 228, 220, 187, 6,   252, 15,  59,  236, 98,  198, 252, 205, 176, 190, 192, 199,
        154, 213, 92,  126, 189, 55,  2,   109, 8,   15,  128, 190, 31,  106, 180, 130, 96,  215,
        125, 50,  11,  124, 71,  119, 83,  28,  65,  209, 128, 47,  7,   46,  212, 157, 230, 199,
        51,  98,  143, 220, 157, 254, 179, 203, 186, 116, 41,  76,  35,  28,  123, 207, 54,  17,
        5,   248, 36,  247, 193, 201, 116, 118, 202, 201, 125, 201, 200, 13,  68,  244, 39,  207,
        70,  206, 12,  117, 206, 192, 9,   232, 62,  33,  137, 88,  73,  16,  121, 190, 139, 91,
        158, 80,  147, 207, 125, 23,  177, 93,  227, 132, 103, 89,
    };
    const p1_bytes_le: [192]u8 = .{
        174, 86,  176, 144, 185, 218, 229, 146, 169, 183, 164, 172, 247, 55,  127, 55,  220, 42,
        122, 99,  249, 111, 113, 182, 70,  241, 238, 18,  197, 53,  101, 232, 163, 152, 27,  205,
        236, 251, 53,  189, 252, 101, 39,  158, 201, 214, 151, 18,  139, 204, 244, 158, 207, 131,
        89,  199, 138, 82,  117, 204, 55,  207, 111, 86,  99,  203, 102, 148, 1,   142, 182, 87,
        169, 129, 51,  253, 70,  80,  207, 57,  184, 25,  48,  192, 216, 62,  19,  163, 131, 123,
        174, 4,   62,  21,  83,  11,  41,  190, 119, 86,  227, 44,  221, 37,  139, 195, 166, 49,
        227, 34,  87,  222, 40,  122, 186, 10,  166, 121, 96,  200, 223, 151, 95,  74,  212, 2,
        211, 10,  219, 153, 33,  38,  201, 179, 108, 244, 7,   9,   114, 99,  22,  160, 27,  24,
        7,   17,  5,   87,  125, 46,  210, 56,  197, 188, 40,  6,   12,  150, 213, 146, 243, 215,
        169, 220, 178, 250, 8,   158, 150, 183, 253, 85,  214, 181, 72,  85,  191, 189, 90,  23,
        103, 238, 75,  12,  77,  215, 241, 241, 29,  150, 132, 21,
    };
    const p2_bytes_le: [192]u8 = .{
        41,  218, 188, 63,  251, 224, 11,  143, 16,  209, 165, 29,  2,   90,  27,  176, 195, 185,
        134, 184, 203, 68,  181, 17,  143, 179, 178, 187, 24,  238, 111, 181, 36,  89,  195, 94,
        41,  5,   181, 191, 130, 135, 12,  20,  100, 158, 91,  25,  89,  156, 152, 139, 33,  90,
        75,  2,   33,  177, 75,  103, 223, 246, 201, 141, 234, 0,   187, 197, 128, 5,   229, 136,
        148, 49,  79,  105, 98,  162, 69,  36,  188, 53,  126, 107, 205, 39,  28,  94,  125, 145,
        74,  46,  174, 180, 110, 14,  71,  39,  1,   137, 252, 243, 67,  247, 190, 161, 145, 179,
        165, 149, 78,  78,  86,  3,   59,  232, 191, 33,  215, 14,  195, 17,  207, 90,  39,  136,
        176, 195, 19,  92,  136, 152, 208, 132, 95,  205, 49,  85,  17,  120, 4,   11,  222, 7,
        65,  18,  214, 8,   210, 17,  201, 173, 64,  49,  248, 162, 127, 36,  93,  133, 71,  22,
        247, 253, 83,  161, 183, 253, 254, 148, 139, 221, 247, 43,  245, 156, 102, 5,   96,  200,
        109, 162, 194, 200, 160, 80,  108, 202, 90,  91,  71,  23,
    };
    const expected_sum_le: [192]u8 = .{
        55,  189, 126, 92,  213, 154, 199, 192, 190, 176, 205, 252, 198, 98,  236, 59,  15,  252,
        6,   187, 220, 228, 157, 29,  124, 78,  113, 248, 22,  191, 37,  81,  62,  12,  20,  221,
        249, 11,  139, 191, 123, 186, 40,  70,  122, 74,  146, 15,  83,  98,  73,  238, 210, 220,
        119, 170, 57,  135, 96,  154, 106, 64,  6,   210, 66,  198, 197, 56,  216, 92,  31,  108,
        31,  161, 128, 16,  166, 12,  161, 41,  76,  68,  37,  33,  201, 98,  91,  24,  174, 24,
        56,  156, 251, 10,  157, 21,  89,  103, 132, 227, 93,  177, 23,  125, 207, 147, 80,  158,
        91,  139, 190, 121, 16,  73,  88,  137, 33,  62,  232, 9,   192, 206, 117, 12,  206, 70,
        207, 39,  244, 68,  13,  200, 201, 125, 201, 202, 118, 116, 201, 193, 247, 36,  248, 5,
        17,  54,  207, 123, 28,  35,  76,  41,  116, 186, 203, 179, 254, 157, 220, 143, 98,  51,
        199, 230, 157, 212, 46,  7,   47,  128, 209, 65,  28,  83,  119, 71,  124, 11,  50,  125,
        215, 96,  130, 180, 106, 31,  190, 128, 15,  8,   109, 2,
    };

    const p1_be_va = 0x100000000;
    const p2_be_va = 0x200000000;
    const result_be_va = 0x300000000;
    const p1_le_va = 0x400000000;
    const p2_le_va = 0x500000000;
    const result_le_va = 0x600000000;

    var result_le: [192]u8 = undefined;
    var result_be: [192]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &p1_bytes_be, p1_be_va),
        .init(.constant, &p2_bytes_be, p2_be_va),
        .init(.mutable, &result_be, result_be_va),
        .init(.constant, &p1_bytes_le, p1_le_va),
        .init(.constant, &p2_bytes_le, p2_le_va),
        .init(.mutable, &result_le, result_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_be)); // Big endian
    registers.set(.r2, @intFromEnum(GroupOp.add));
    registers.set(.r3, p1_be_va);
    registers.set(.r4, p2_be_va);
    registers.set(.r5, result_be_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_sum_be, &result_be);

    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_le)); // Little endian
    registers.set(.r2, @intFromEnum(GroupOp.add));
    registers.set(.r3, p1_le_va);
    registers.set(.r4, p2_le_va);
    registers.set(.r5, result_le_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_sum_le, &result_le);
}

test "bls12-381 g2 sub" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 204 * 2,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const p1_bytes_be: [192]u8 = .{
        1,   111, 113, 42,  165, 128, 194, 26,  130, 142, 58,  198, 61,  244, 113, 64,  25,  96,
        196, 12,  211, 55,  213, 85,  109, 210, 211, 177, 96,  48,  15,  122, 155, 173, 166, 16,
        113, 95,  253, 69,  196, 15,  187, 201, 207, 255, 81,  176, 15,  77,  24,  199, 78,  142,
        23,  177, 55,  118, 62,  248, 123, 41,  213, 72,  169, 177, 5,   176, 197, 158, 62,  1,
        5,   219, 190, 92,  36,  37,  117, 162, 202, 9,   231, 199, 13,  72,  102, 36,  246, 241,
        52,  68,  185, 44,  238, 23,  23,  1,   192, 28,  61,  103, 236, 74,  46,  28,  64,  67,
        194, 243, 208, 186, 46,  201, 142, 7,   166, 139, 114, 215, 101, 234, 108, 184, 93,  135,
        61,  176, 154, 208, 28,  79,  210, 132, 96,  21,  199, 11,  73,  210, 40,  241, 107, 215,
        8,   203, 156, 2,   211, 33,  203, 196, 124, 172, 148, 232, 121, 116, 109, 226, 15,  13,
        147, 241, 20,  70,  28,  10,  17,  51,  143, 140, 35,  127, 109, 7,   202, 220, 208, 97,
        11,  167, 119, 94,  192, 92,  165, 215, 230, 160, 16,  56,
    };
    const p2_bytes_be: [192]u8 = .{
        14,  73,  101, 89,  211, 85,  5,   115, 148, 81,  82,  216, 141, 148, 50,  174, 17,  86,
        246, 146, 42,  230, 181, 250, 40,  64,  248, 121, 6,   167, 117, 190, 219, 96,  57,  80,
        127, 234, 141, 179, 154, 109, 5,   82,  233, 254, 7,   48,  5,   108, 253, 196, 16,  144,
        81,  140, 252, 184, 236, 193, 97,  200, 129, 223, 132, 28,  135, 121, 129, 129, 60,  33,
        77,  43,  181, 180, 60,  224, 108, 127, 207, 112, 54,  66,  81,  185, 166, 120, 54,  169,
        55,  238, 32,  219, 172, 212, 24,  165, 106, 207, 20,  68,  130, 233, 190, 75,  177, 17,
        157, 112, 174, 88,  189, 182, 126, 219, 114, 136, 67,  15,  167, 133, 50,  172, 124, 94,
        8,   149, 203, 232, 35,  218, 144, 142, 74,  150, 94,  182, 33,  106, 111, 120, 203, 59,
        10,  121, 79,  248, 118, 165, 232, 57,  87,  60,  42,  223, 98,  104, 158, 238, 68,  152,
        59,  19,  172, 89,  20,  238, 63,  49,  204, 138, 108, 195, 10,  233, 81,  79,  215, 107,
        43,  197, 190, 231, 15,  14,  251, 203, 179, 205, 224, 195,
    };
    const expected_sub_be: [192]u8 = .{
        15,  192, 220, 234, 246, 126, 141, 163, 107, 162, 43,  117, 171, 158, 195, 132, 196, 214,
        237, 133, 98,  133, 112, 248, 161, 148, 3,   163, 20,  26,  49,  136, 161, 244, 36,  179,
        237, 204, 58,  22,  51,  106, 0,   4,   239, 244, 242, 89,  5,   14,  149, 31,  78,  213,
        70,  153, 147, 43,  84,  19,  223, 100, 235, 61,  172, 66,  136, 201, 11,  81,  168, 136,
        207, 46,  198, 208, 171, 144, 187, 35,  77,  58,  186, 147, 191, 243, 9,   12,  224, 22,
        230, 36,  112, 246, 114, 19,  13,  116, 186, 62,  158, 176, 201, 150, 187, 13,  32,  135,
        140, 108, 178, 174, 90,  212, 50,  184, 238, 17,  229, 167, 195, 104, 179, 156, 166, 251,
        99,  115, 133, 25,  144, 101, 45,  70,  19,  86,  91,  247, 236, 93,  252, 14,  106, 212,
        15,  42,  62,  104, 162, 216, 8,   180, 156, 52,  254, 179, 29,  95,  94,  16,  245, 215,
        165, 67,  115, 50,  186, 190, 227, 213, 71,  126, 29,  81,  217, 43,  157, 12,  100, 105,
        211, 172, 101, 212, 73,  140, 149, 109, 252, 180, 98,  22,
    };
    const p1_bytes_le: [192]u8 = .{
        23,  238, 44,  185, 68,  52,  241, 246, 36,  102, 72,  13,  199, 231, 9,   202, 162, 117,
        37,  36,  92,  190, 219, 5,   1,   62,  158, 197, 176, 5,   177, 169, 72,  213, 41,  123,
        248, 62,  118, 55,  177, 23,  142, 78,  199, 24,  77,  15,  176, 81,  255, 207, 201, 187,
        15,  196, 69,  253, 95,  113, 16,  166, 173, 155, 122, 15,  48,  96,  177, 211, 210, 109,
        85,  213, 55,  211, 12,  196, 96,  25,  64,  113, 244, 61,  198, 58,  142, 130, 26,  194,
        128, 165, 42,  113, 111, 1,   56,  16,  160, 230, 215, 165, 92,  192, 94,  119, 167, 11,
        97,  208, 220, 202, 7,   109, 127, 35,  140, 143, 51,  17,  10,  28,  70,  20,  241, 147,
        13,  15,  226, 109, 116, 121, 232, 148, 172, 124, 196, 203, 33,  211, 2,   156, 203, 8,
        215, 107, 241, 40,  210, 73,  11,  199, 21,  96,  132, 210, 79,  28,  208, 154, 176, 61,
        135, 93,  184, 108, 234, 101, 215, 114, 139, 166, 7,   142, 201, 46,  186, 208, 243, 194,
        67,  64,  28,  46,  74,  236, 103, 61,  28,  192, 1,   23,
    };
    const p2_bytes_le: [192]u8 = .{
        212, 172, 219, 32,  238, 55,  169, 54,  120, 166, 185, 81,  66,  54,  112, 207, 127, 108,
        224, 60,  180, 181, 43,  77,  33,  60,  129, 129, 121, 135, 28,  132, 223, 129, 200, 97,
        193, 236, 184, 252, 140, 81,  144, 16,  196, 253, 108, 5,   48,  7,   254, 233, 82,  5,
        109, 154, 179, 141, 234, 127, 80,  57,  96,  219, 190, 117, 167, 6,   121, 248, 64,  40,
        250, 181, 230, 42,  146, 246, 86,  17,  174, 50,  148, 141, 216, 82,  81,  148, 115, 5,
        85,  211, 89,  101, 73,  14,  195, 224, 205, 179, 203, 251, 14,  15,  231, 190, 197, 43,
        107, 215, 79,  81,  233, 10,  195, 108, 138, 204, 49,  63,  238, 20,  89,  172, 19,  59,
        152, 68,  238, 158, 104, 98,  223, 42,  60,  87,  57,  232, 165, 118, 248, 79,  121, 10,
        59,  203, 120, 111, 106, 33,  182, 94,  150, 74,  142, 144, 218, 35,  232, 203, 149, 8,
        94,  124, 172, 50,  133, 167, 15,  67,  136, 114, 219, 126, 182, 189, 88,  174, 112, 157,
        17,  177, 75,  190, 233, 130, 68,  20,  207, 106, 165, 24,
    };
    const expected_sub_le: [192]u8 = .{
        19,  114, 246, 112, 36,  230, 22,  224, 12,  9,   243, 191, 147, 186, 58,  77,  35,  187,
        144, 171, 208, 198, 46,  207, 136, 168, 81,  11,  201, 136, 66,  172, 61,  235, 100, 223,
        19,  84,  43,  147, 153, 70,  213, 78,  31,  149, 14,  5,   89,  242, 244, 239, 4,   0,
        106, 51,  22,  58,  204, 237, 179, 36,  244, 161, 136, 49,  26,  20,  163, 3,   148, 161,
        248, 112, 133, 98,  133, 237, 214, 196, 132, 195, 158, 171, 117, 43,  162, 107, 163, 141,
        126, 246, 234, 220, 192, 15,  22,  98,  180, 252, 109, 149, 140, 73,  212, 101, 172, 211,
        105, 100, 12,  157, 43,  217, 81,  29,  126, 71,  213, 227, 190, 186, 50,  115, 67,  165,
        215, 245, 16,  94,  95,  29,  179, 254, 52,  156, 180, 8,   216, 162, 104, 62,  42,  15,
        212, 106, 14,  252, 93,  236, 247, 91,  86,  19,  70,  45,  101, 144, 25,  133, 115, 99,
        251, 166, 156, 179, 104, 195, 167, 229, 17,  238, 184, 50,  212, 90,  174, 178, 108, 140,
        135, 32,  13,  187, 150, 201, 176, 158, 62,  186, 116, 13,
    };

    const p1_be_va = 0x100000000;
    const p2_be_va = 0x200000000;
    const result_be_va = 0x300000000;
    const p1_le_va = 0x400000000;
    const p2_le_va = 0x500000000;
    const result_le_va = 0x600000000;

    var result_le: [192]u8 = undefined;
    var result_be: [192]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &p1_bytes_be, p1_be_va),
        .init(.constant, &p2_bytes_be, p2_be_va),
        .init(.mutable, &result_be, result_be_va),
        .init(.constant, &p1_bytes_le, p1_le_va),
        .init(.constant, &p2_bytes_le, p2_le_va),
        .init(.mutable, &result_le, result_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_be)); // Big endian
    registers.set(.r2, @intFromEnum(GroupOp.subtract));
    registers.set(.r3, p1_be_va);
    registers.set(.r4, p2_be_va);
    registers.set(.r5, result_be_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_sub_be, &result_be);

    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_le)); // Little endian
    registers.set(.r2, @intFromEnum(GroupOp.subtract));
    registers.set(.r3, p1_le_va);
    registers.set(.r4, p2_le_va);
    registers.set(.r5, result_le_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_sub_le, &result_le);
}

test "bls12-381 g2 mul" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 8_255 * 2,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const p1_bytes_be: [192]u8 = .{
        1,   95,  16,  90,  117, 185, 253, 76,  25,  68,  54,  111, 154, 161, 125, 203, 121, 4,
        154, 67,  205, 157, 76,  9,   128, 224, 37,  81,  214, 226, 71,  59,  224, 187, 152, 153,
        199, 62,  58,  74,  137, 245, 46,  101, 155, 17,  212, 64,  5,   134, 0,   185, 19,  132,
        205, 101, 77,  204, 118, 63,  71,  172, 208, 29,  210, 61,  51,  4,   190, 191, 211, 175,
        105, 245, 204, 57,  56,  84,  210, 184, 235, 169, 231, 161, 128, 83,  252, 234, 227, 255,
        166, 219, 201, 176, 169, 16,  20,  218, 203, 38,  181, 98,  213, 89,  152, 123, 230, 201,
        4,   95,  42,  86,  29,  137, 67,  233, 230, 161, 206, 231, 201, 176, 79,  12,  197, 56,
        212, 36,  235, 216, 160, 27,  221, 99,  124, 220, 133, 76,  123, 209, 200, 78,  122, 36,
        16,  171, 18,  247, 111, 111, 132, 38,  240, 183, 27,  76,  135, 211, 136, 202, 55,  93,
        246, 235, 191, 146, 183, 161, 110, 129, 4,   58,  238, 59,  77,  242, 56,  88,  96,  150,
        146, 247, 137, 230, 137, 35,  9,   108, 95,  127, 75,  78,
    };
    const mul_scalar_be: [32]u8 = .{
        29,  192, 111, 151, 187, 37, 109, 91, 129, 223, 188, 225, 117, 3,   120, 162, 107, 66,
        159, 255, 61,  128, 41,  32, 242, 95, 232, 202, 106, 188, 154, 147,
    };
    const expected_mul_be: [192]u8 = .{
        10,  92,  88,  192, 26,  200, 38,  128, 188, 148, 254, 16,  202, 39,  174, 252, 33,  111,
        41,  121, 211, 9,   209, 138, 43,  104, 122, 214, 4,   251, 34,  81,  36,  92,  143, 19,
        151, 213, 111, 240, 100, 15,  33,  74,  123, 143, 181, 153, 6,   107, 82,  96,  141, 147,
        63,  200, 13,  31,  66,  5,   184, 135, 24,  82,  189, 240, 58,  250, 48,  61,  132, 13,
        23,  240, 31,  238, 252, 33,  191, 241, 38,  90,  221, 201, 164, 137, 98,  92,  148, 246,
        225, 22,  239, 99,  97,  179, 20,  251, 39,  114, 14,  156, 165, 182, 58,  233, 100, 41,
        34,  59,  119, 103, 40,  206, 50,  175, 223, 126, 146, 17,  161, 14,  84,  43,  149, 58,
        212, 197, 250, 15,  208, 122, 33,  4,   87,  219, 82,  201, 12,  11,  44,  76,  59,  182,
        18,  76,  38,  184, 175, 11,  211, 4,   64,  133, 41,  104, 185, 153, 63,  246, 39,  145,
        38,  113, 162, 183, 77,  2,   51,  134, 243, 196, 74,  111, 183, 169, 222, 228, 191, 53,
        129, 53,  186, 94,  97,  144, 31,  117, 218, 207, 214, 189,
    };
    const p1_bytes_le: [192]u8 = .{
        16,  169, 176, 201, 219, 166, 255, 227, 234, 252, 83,  128, 161, 231, 169, 235, 184, 210,
        84,  56,  57,  204, 245, 105, 175, 211, 191, 190, 4,   51,  61,  210, 29,  208, 172, 71,
        63,  118, 204, 77,  101, 205, 132, 19,  185, 0,   134, 5,   64,  212, 17,  155, 101, 46,
        245, 137, 74,  58,  62,  199, 153, 152, 187, 224, 59,  71,  226, 214, 81,  37,  224, 128,
        9,   76,  157, 205, 67,  154, 4,   121, 203, 125, 161, 154, 111, 54,  68,  25,  76,  253,
        185, 117, 90,  16,  95,  1,   78,  75,  127, 95,  108, 9,   35,  137, 230, 137, 247, 146,
        150, 96,  88,  56,  242, 77,  59,  238, 58,  4,   129, 110, 161, 183, 146, 191, 235, 246,
        93,  55,  202, 136, 211, 135, 76,  27,  183, 240, 38,  132, 111, 111, 247, 18,  171, 16,
        36,  122, 78,  200, 209, 123, 76,  133, 220, 124, 99,  221, 27,  160, 216, 235, 36,  212,
        56,  197, 12,  79,  176, 201, 231, 206, 161, 230, 233, 67,  137, 29,  86,  42,  95,  4,
        201, 230, 123, 152, 89,  213, 98,  181, 38,  203, 218, 20,
    };
    const mul_scalar_le: [32]u8 = .{
        147, 154, 188, 106, 202, 232, 95,  242, 32,  41,  128, 61,  255, 159, 66, 107, 162, 120, 3,
        117, 225, 188, 223, 129, 91,  109, 37,  187, 151, 111, 192, 29,
    };
    const expected_mul_le: [192]u8 = .{
        179, 97,  99,  239, 22,  225, 246, 148, 92,  98,  137, 164, 201, 221, 90,  38,  241, 191,
        33,  252, 238, 31,  240, 23,  13,  132, 61,  48,  250, 58,  240, 189, 82,  24,  135, 184,
        5,   66,  31,  13,  200, 63,  147, 141, 96,  82,  107, 6,   153, 181, 143, 123, 74,  33,
        15,  100, 240, 111, 213, 151, 19,  143, 92,  36,  81,  34,  251, 4,   214, 122, 104, 43,
        138, 209, 9,   211, 121, 41,  111, 33,  252, 174, 39,  202, 16,  254, 148, 188, 128, 38,
        200, 26,  192, 88,  92,  10,  189, 214, 207, 218, 117, 31,  144, 97,  94,  186, 53,  129,
        53,  191, 228, 222, 169, 183, 111, 74,  196, 243, 134, 51,  2,   77,  183, 162, 113, 38,
        145, 39,  246, 63,  153, 185, 104, 41,  133, 64,  4,   211, 11,  175, 184, 38,  76,  18,
        182, 59,  76,  44,  11,  12,  201, 82,  219, 87,  4,   33,  122, 208, 15,  250, 197, 212,
        58,  149, 43,  84,  14,  161, 17,  146, 126, 223, 175, 50,  206, 40,  103, 119, 59,  34,
        41,  100, 233, 58,  182, 165, 156, 14,  114, 39,  251, 20,
    };

    const point_be_va = 0x100000000;
    const scalar_be_va = 0x200000000;
    const result_be_va = 0x300000000;
    const point_le_va = 0x400000000;
    const scalar_le_va = 0x500000000;
    const result_le_va = 0x600000000;

    var result_le: [192]u8 = undefined;
    var result_be: [192]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &p1_bytes_be, point_be_va),
        .init(.constant, &mul_scalar_be, scalar_be_va),
        .init(.mutable, &result_be, result_be_va),
        .init(.constant, &p1_bytes_le, point_le_va),
        .init(.constant, &mul_scalar_le, scalar_le_va),
        .init(.mutable, &result_le, result_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_be)); // Big endian
    registers.set(.r2, @intFromEnum(GroupOp.multiply));
    registers.set(.r3, scalar_be_va);
    registers.set(.r4, point_be_va);
    registers.set(.r5, result_be_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_mul_be, &result_be);

    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_le)); // Little endian
    registers.set(.r2, @intFromEnum(GroupOp.multiply));
    registers.set(.r3, scalar_le_va);
    registers.set(.r4, point_le_va);
    registers.set(.r5, result_le_va);

    try curveGroupOp(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_mul_le, &result_le);
}

test "bls12-381 pairing be" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 25_445,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const g1_bytes: [96]u8 = .{
        3,   161, 104, 54,  242, 116, 16,  50,  15,  113, 42,  38,  108, 11,  127, 64,  43,  249,
        50,  133, 105, 8,   133, 238, 34,  6,   189, 119, 153, 36,  75,  65,  87,  249, 90,  109,
        133, 200, 203, 25,  127, 68,  251, 243, 14,  210, 204, 35,  18,  124, 149, 5,   68,  178,
        57,  230, 253, 154, 192, 163, 5,   146, 144, 100, 7,   102, 9,   76,  67,  251, 147, 45,
        27,  111, 204, 213, 219, 141, 58,  11,  235, 100, 6,   220, 77,  230, 232, 200, 210, 200,
        3,   184, 10,  80,  23,  164,
    };
    const g2_bytes: [192]u8 = .{
        8,   249, 218, 154, 232, 125, 250, 185, 153, 60,  132, 155, 188, 119, 50,  205, 32,  76,
        184, 181, 164, 158, 64,  12,  179, 181, 150, 95,  226, 9,   175, 51,  169, 185, 34,  178,
        249, 161, 27,  164, 210, 107, 171, 203, 246, 11,  158, 86,  14,  135, 197, 225, 7,   44,
        94,  243, 216, 200, 100, 199, 118, 14,  106, 181, 88,  202, 207, 156, 227, 101, 126, 236,
        46,  189, 238, 73,  220, 118, 151, 73,  255, 249, 103, 103, 255, 185, 91,  82,  212, 148,
        110, 19,  212, 111, 199, 197, 4,   144, 25,  145, 196, 142, 205, 252, 85,  85,  48,  243,
        209, 62,  57,  212, 44,  149, 81,  113, 171, 60,  193, 73,  40,  11,  36,  120, 19,  62,
        2,   25,  22,  232, 227, 50,  35,  75,  172, 205, 2,   37,  27,  65,  182, 6,   74,  43,
        1,   239, 105, 129, 184, 98,  215, 81,  15,  19,  171, 39,  252, 57,  176, 171, 181, 71,
        124, 251, 53,  202, 213, 33,  58,  175, 52,  41,  89,  230, 217, 177, 32,  24,  82,  166,
        240, 232, 223, 24,  141, 70,  121, 25,  51,  173, 30,  6,
    };
    const expected_gt: [48 * 12]u8 = .{
        14,  57,  164, 128, 118, 229, 58,  194, 163, 179, 7,   155, 19,  27,  195, 184, 247, 246,
        83,  76,  63,  71,  120, 72,  143, 130, 2,   192, 35,  251, 36,  232, 229, 122, 68,  126,
        54,  228, 197, 249, 112, 234, 93,  130, 133, 246, 75,  41,  13,  31,  232, 225, 105, 219,
        180, 105, 225, 184, 43,  57,  184, 10,  228, 147, 245, 227, 40,  68,  215, 217, 15,  164,
        14,  231, 119, 134, 120, 33,  210, 52,  64,  47,  39,  42,  171, 221, 225, 58,  249, 247,
        204, 161, 20,  16,  103, 1,   0,   168, 109, 157, 223, 60,  147, 11,  76,  2,   95,  86,
        174, 4,   100, 125, 124, 226, 31,  159, 199, 160, 49,  98,  76,  124, 221, 101, 6,   213,
        111, 44,  24,  172, 78,  42,  216, 137, 91,  68,  211, 40,  210, 172, 242, 29,  115, 220,
        11,  156, 249, 117, 118, 12,  59,  59,  87,  137, 217, 190, 144, 62,  249, 103, 244, 247,
        152, 112, 238, 31,  122, 136, 39,  9,   49,  215, 22,  180, 164, 120, 166, 115, 62,  130,
        4,   216, 57,  155, 8,   214, 116, 9,   222, 168, 34,  242, 19,  47,  183, 124, 196, 222,
        58,  135, 75,  97,  242, 231, 190, 238, 162, 50,  124, 230, 229, 172, 156, 140, 196, 163,
        213, 49,  153, 144, 167, 118, 122, 167, 70,  203, 145, 120, 237, 46,  135, 130, 0,   204,
        139, 61,  22,  10,  243, 232, 15,  38,  161, 146, 106, 138, 86,  198, 8,   167, 229, 125,
        95,  28,  120, 51,  23,  161, 250, 105, 125, 177, 169, 168, 97,  5,   0,   231, 143, 141,
        22,  92,  143, 148, 95,  66,  151, 154, 55,  169, 0,   91,  107, 5,   59,  252, 8,   140,
        0,   195, 64,  135, 197, 226, 235, 170, 127, 176, 217, 7,   180, 235, 222, 58,  195, 221,
        192, 130, 86,  143, 0,   199, 225, 53,  57,  181, 151, 152, 81,  183, 252, 251, 5,   124,
        61,  164, 133, 169, 14,  20,  206, 36,  56,  1,   197, 214, 23,  10,  32,  223, 128, 87,
        166, 33,  61,  29,  190, 90,  150, 82,  121, 109, 255, 211, 79,  46,  57,  48,  213, 125,
        8,   93,  10,  151, 162, 137, 133, 129, 237, 101, 77,  39,  85,  94,  234, 43,  85,  101,
        240, 233, 93,  57,  171, 13,  18,  38,  31,  29,  41,  169, 193, 49,  108, 119, 231, 130,
        97,  45,  35,  252, 149, 125, 116, 64,  163, 70,  40,  143, 160, 14,  15,  91,  168, 207,
        77,  40,  74,  208, 114, 50,  64,  119, 216, 182, 96,  218, 0,   185, 69,  105, 194, 103,
        19,  129, 33,  204, 250, 237, 191, 143, 122, 56,  234, 62,  8,   224, 1,   242, 110, 10,
        194, 178, 198, 220, 151, 167, 234, 235, 207, 148, 93,  249, 221, 153, 15,  86,  89,  76,
        49,  29,  18,  74,  0,   246, 42,  143, 89,  60,  48,  96,  23,  173, 209, 213, 156, 80,
        154, 159, 161, 12,  178, 225, 226, 77,  99,  249, 154, 246, 110, 96,  176, 79,  90,  2,
        190, 63,  189, 123, 170, 206, 119, 142, 138, 15,  93,  191, 230, 100, 159, 142, 50,  119,
        204, 157, 201, 230, 93,  57,  3,   125, 96,  195, 247, 195, 76,  24,  176, 99,  88,  206,
        86,  63,  204, 37,  173, 182, 116, 51,  240, 15,  155, 199, 199, 198, 183, 44,  241, 251,
        236, 35,  178, 36,  8,   107, 82,  153, 144, 28,  29,  229, 150, 157, 37,  216, 96,  116,
    };

    const g1_va = 0x100000000;
    const g2_va = 0x200000000;
    const result_va = 0x300000000;

    var result: [48 * 12]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &g1_bytes, g1_va),
        .init(.constant, &g2_bytes, g2_va),
        .init(.mutable, &result, result_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_be)); // Big endian
    registers.set(.r2, 1); // num pairs
    registers.set(.r3, g1_va);
    registers.set(.r4, g2_va);
    registers.set(.r5, result_va);

    try curvePairingMap(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_gt, &result);
}

test "bls12-381 pairing le" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 25_445,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const g1_bytes: [96]u8 = .{
        35,  204, 210, 14,  243, 251, 68,  127, 25,  203, 200, 133, 109, 90,  249, 87,  65,  75,
        36,  153, 119, 189, 6,   34,  238, 133, 8,   105, 133, 50,  249, 43,  64,  127, 11,  108,
        38,  42,  113, 15,  50,  16,  116, 242, 54,  104, 161, 3,   164, 23,  80,  10,  184, 3,
        200, 210, 200, 232, 230, 77,  220, 6,   100, 235, 11,  58,  141, 219, 213, 204, 111, 27,
        45,  147, 251, 67,  76,  9,   102, 7,   100, 144, 146, 5,   163, 192, 154, 253, 230, 57,
        178, 68,  5,   149, 124, 18,
    };
    const g2_bytes: [192]u8 = .{
        197, 199, 111, 212, 19,  110, 148, 212, 82,  91,  185, 255, 103, 103, 249, 255, 73,  151,
        118, 220, 73,  238, 189, 46,  236, 126, 101, 227, 156, 207, 202, 88,  181, 106, 14,  118,
        199, 100, 200, 216, 243, 94,  44,  7,   225, 197, 135, 14,  86,  158, 11,  246, 203, 171,
        107, 210, 164, 27,  161, 249, 178, 34,  185, 169, 51,  175, 9,   226, 95,  150, 181, 179,
        12,  64,  158, 164, 181, 184, 76,  32,  205, 50,  119, 188, 155, 132, 60,  153, 185, 250,
        125, 232, 154, 218, 249, 8,   6,   30,  173, 51,  25,  121, 70,  141, 24,  223, 232, 240,
        166, 82,  24,  32,  177, 217, 230, 89,  41,  52,  175, 58,  33,  213, 202, 53,  251, 124,
        71,  181, 171, 176, 57,  252, 39,  171, 19,  15,  81,  215, 98,  184, 129, 105, 239, 1,
        43,  74,  6,   182, 65,  27,  37,  2,   205, 172, 75,  35,  50,  227, 232, 22,  25,  2,
        62,  19,  120, 36,  11,  40,  73,  193, 60,  171, 113, 81,  149, 44,  212, 57,  62,  209,
        243, 48,  85,  85,  252, 205, 142, 196, 145, 25,  144, 4,
    };
    const expected_gt: [48 * 12]u8 = .{
        116, 96,  216, 37,  157, 150, 229, 29,  28,  144, 153, 82,  107, 8,   36,  178, 35,  236,
        251, 241, 44,  183, 198, 199, 199, 155, 15,  240, 51,  116, 182, 173, 37,  204, 63,  86,
        206, 88,  99,  176, 24,  76,  195, 247, 195, 96,  125, 3,   57,  93,  230, 201, 157, 204,
        119, 50,  142, 159, 100, 230, 191, 93,  15,  138, 142, 119, 206, 170, 123, 189, 63,  190,
        2,   90,  79,  176, 96,  110, 246, 154, 249, 99,  77,  226, 225, 178, 12,  161, 159, 154,
        80,  156, 213, 209, 173, 23,  96,  48,  60,  89,  143, 42,  246, 0,   74,  18,  29,  49,
        76,  89,  86,  15,  153, 221, 249, 93,  148, 207, 235, 234, 167, 151, 220, 198, 178, 194,
        10,  110, 242, 1,   224, 8,   62,  234, 56,  122, 143, 191, 237, 250, 204, 33,  129, 19,
        103, 194, 105, 69,  185, 0,   218, 96,  182, 216, 119, 64,  50,  114, 208, 74,  40,  77,
        207, 168, 91,  15,  14,  160, 143, 40,  70,  163, 64,  116, 125, 149, 252, 35,  45,  97,
        130, 231, 119, 108, 49,  193, 169, 41,  29,  31,  38,  18,  13,  171, 57,  93,  233, 240,
        101, 85,  43,  234, 94,  85,  39,  77,  101, 237, 129, 133, 137, 162, 151, 10,  93,  8,
        125, 213, 48,  57,  46,  79,  211, 255, 109, 121, 82,  150, 90,  190, 29,  61,  33,  166,
        87,  128, 223, 32,  10,  23,  214, 197, 1,   56,  36,  206, 20,  14,  169, 133, 164, 61,
        124, 5,   251, 252, 183, 81,  152, 151, 181, 57,  53,  225, 199, 0,   143, 86,  130, 192,
        221, 195, 58,  222, 235, 180, 7,   217, 176, 127, 170, 235, 226, 197, 135, 64,  195, 0,
        140, 8,   252, 59,  5,   107, 91,  0,   169, 55,  154, 151, 66,  95,  148, 143, 92,  22,
        141, 143, 231, 0,   5,   97,  168, 169, 177, 125, 105, 250, 161, 23,  51,  120, 28,  95,
        125, 229, 167, 8,   198, 86,  138, 106, 146, 161, 38,  15,  232, 243, 10,  22,  61,  139,
        204, 0,   130, 135, 46,  237, 120, 145, 203, 70,  167, 122, 118, 167, 144, 153, 49,  213,
        163, 196, 140, 156, 172, 229, 230, 124, 50,  162, 238, 190, 231, 242, 97,  75,  135, 58,
        222, 196, 124, 183, 47,  19,  242, 34,  168, 222, 9,   116, 214, 8,   155, 57,  216, 4,
        130, 62,  115, 166, 120, 164, 180, 22,  215, 49,  9,   39,  136, 122, 31,  238, 112, 152,
        247, 244, 103, 249, 62,  144, 190, 217, 137, 87,  59,  59,  12,  118, 117, 249, 156, 11,
        220, 115, 29,  242, 172, 210, 40,  211, 68,  91,  137, 216, 42,  78,  172, 24,  44,  111,
        213, 6,   101, 221, 124, 76,  98,  49,  160, 199, 159, 31,  226, 124, 125, 100, 4,   174,
        86,  95,  2,   76,  11,  147, 60,  223, 157, 109, 168, 0,   1,   103, 16,  20,  161, 204,
        247, 249, 58,  225, 221, 171, 42,  39,  47,  64,  52,  210, 33,  120, 134, 119, 231, 14,
        164, 15,  217, 215, 68,  40,  227, 245, 147, 228, 10,  184, 57,  43,  184, 225, 105, 180,
        219, 105, 225, 232, 31,  13,  41,  75,  246, 133, 130, 93,  234, 112, 249, 197, 228, 54,
        126, 68,  122, 229, 232, 36,  251, 35,  192, 2,   130, 143, 72,  120, 71,  63,  76,  83,
        246, 247, 184, 195, 27,  19,  155, 7,   179, 163, 194, 58,  229, 118, 128, 164, 57,  14,
    };

    const g1_va = 0x100000000;
    const g2_va = 0x200000000;
    const result_va = 0x300000000;

    var result: [48 * 12]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &g1_bytes, g1_va),
        .init(.constant, &g2_bytes, g2_va),
        .init(.mutable, &result, result_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_le)); // Big endian
    registers.set(.r2, 1); // num pairs
    registers.set(.r3, g1_va);
    registers.set(.r4, g2_va);
    registers.set(.r5, result_va);

    try curvePairingMap(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_gt, &result);
}

test "bls12-381 decompress g1" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 2_100 * 2,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const compressed_be: [48]u8 = .{
        175, 159, 245, 68,  142, 96,  188, 154, 113, 143, 70,  58,  193, 2,   189, 111, 135, 114,
        230, 70,  12,  25,  7,   106, 108, 137, 213, 128, 110, 90,  142, 244, 75,  111, 59,  138,
        240, 158, 55,  164, 229, 100, 152, 122, 38,  185, 222, 218,
    };
    const expected_affine_be: [96]u8 = .{
        15,  159, 245, 68,  142, 96,  188, 154, 113, 143, 70,  58,  193, 2,   189, 111, 135, 114,
        230, 70,  12,  25,  7,   106, 108, 137, 213, 128, 110, 90,  142, 244, 75,  111, 59,  138,
        240, 158, 55,  164, 229, 100, 152, 122, 38,  185, 222, 218, 18,  79,  1,   246, 62,  35,
        162, 234, 146, 109, 7,   85,  44,  104, 10,  250, 158, 31,  181, 244, 117, 193, 27,  53,
        184, 79,  160, 237, 168, 51,  41,  200, 58,  4,   107, 95,  246, 171, 241, 202, 120, 228,
        135, 135, 100, 50,  123, 58,
    };
    const compressed_le: [48]u8 = .{
        218, 222, 185, 38,  122, 152, 100, 229, 164, 55,  158, 240, 138, 59,  111, 75,  244, 142,
        90,  110, 128, 213, 137, 108, 106, 7,   25,  12,  70,  230, 114, 135, 111, 189, 2,   193,
        58,  70,  143, 113, 154, 188, 96,  142, 68,  245, 159, 175,
    };
    const expected_affine_le: [96]u8 = .{
        218, 222, 185, 38,  122, 152, 100, 229, 164, 55,  158, 240, 138, 59,  111, 75,  244, 142,
        90,  110, 128, 213, 137, 108, 106, 7,   25,  12,  70,  230, 114, 135, 111, 189, 2,   193,
        58,  70,  143, 113, 154, 188, 96,  142, 68,  245, 159, 15,  58,  123, 50,  100, 135, 135,
        228, 120, 202, 241, 171, 246, 95,  107, 4,   58,  200, 41,  51,  168, 237, 160, 79,  184,
        53,  27,  193, 117, 244, 181, 31,  158, 250, 10,  104, 44,  85,  7,   109, 146, 234, 162,
        35,  62,  246, 1,   79,  18,
    };

    const input_be_va = 0x100000000;
    const result_be_va = 0x200000000;
    const input_le_va = 0x300000000;
    const result_le_va = 0x400000000;

    var result_be: [96]u8 = undefined;
    var result_le: [96]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &compressed_be, input_be_va),
        .init(.mutable, &result_be, result_be_va),
        .init(.constant, &compressed_le, input_le_va),
        .init(.mutable, &result_le, result_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_be)); // Big endian
    registers.set(.r2, input_be_va);
    registers.set(.r3, result_be_va);

    try curveDecompress(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_affine_be, &result_be);

    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_le)); // Big endian
    registers.set(.r2, input_le_va);
    registers.set(.r3, result_le_va);

    try curveDecompress(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_affine_le, &result_le);
}

test "bls12-381 decompress g2" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 3_050 * 2,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const compressed_be: [96]u8 = .{
        143, 106, 18,  220, 40,  152, 4,   228, 139, 35,  104, 146, 179, 74,  205, 172, 146, 137,
        11,  106, 74,  42,  135, 137, 53,  249, 64,  251, 173, 232, 48,  209, 125, 222, 13,  209,
        121, 238, 185, 179, 111, 105, 71,  223, 39,  48,  195, 104, 23,  24,  170, 59,  111, 106,
        167, 51,  231, 186, 224, 182, 172, 73,  15,  18,  211, 143, 59,  2,   115, 190, 196, 163,
        111, 11,  36,  133, 86,  96,  188, 135, 16,  37,  216, 175, 71,  182, 222, 31,  207, 155,
        16,  255, 112, 78,  242, 111,
    };
    const expected_affine_be: [192]u8 = .{
        15,  106, 18,  220, 40,  152, 4,   228, 139, 35,  104, 146, 179, 74,  205, 172, 146, 137,
        11,  106, 74,  42,  135, 137, 53,  249, 64,  251, 173, 232, 48,  209, 125, 222, 13,  209,
        121, 238, 185, 179, 111, 105, 71,  223, 39,  48,  195, 104, 23,  24,  170, 59,  111, 106,
        167, 51,  231, 186, 224, 182, 172, 73,  15,  18,  211, 143, 59,  2,   115, 190, 196, 163,
        111, 11,  36,  133, 86,  96,  188, 135, 16,  37,  216, 175, 71,  182, 222, 31,  207, 155,
        16,  255, 112, 78,  242, 111, 11,  217, 244, 83,  201, 111, 182, 168, 171, 205, 183, 118,
        199, 85,  130, 157, 95,  69,  159, 126, 122, 27,  92,  84,  253, 147, 96,  176, 74,  57,
        13,  228, 178, 111, 246, 157, 74,  120, 174, 255, 146, 92,  32,  214, 164, 56,  206, 144,
        13,  59,  111, 251, 170, 85,  159, 219, 108, 187, 31,  15,  106, 176, 64,  191, 56,  77,
        217, 87,  144, 196, 148, 21,  12,  171, 99,  121, 128, 120, 187, 224, 192, 107, 104, 178,
        75,  205, 118, 64,  234, 168, 214, 11,  125, 153, 55,  5,
    };
    const compressed_le: [96]u8 = .{
        111, 242, 78,  112, 255, 16,  155, 207, 31,  222, 182, 71,  175, 216, 37,  16,  135, 188,
        96,  86,  133, 36,  11,  111, 163, 196, 190, 115, 2,   59,  143, 211, 18,  15,  73,  172,
        182, 224, 186, 231, 51,  167, 106, 111, 59,  170, 24,  23,  104, 195, 48,  39,  223, 71,
        105, 111, 179, 185, 238, 121, 209, 13,  222, 125, 209, 48,  232, 173, 251, 64,  249, 53,
        137, 135, 42,  74,  106, 11,  137, 146, 172, 205, 74,  179, 146, 104, 35,  139, 228, 4,
        152, 40,  220, 18,  106, 143,
    };
    const expected_affine_le: [192]u8 = .{
        111, 242, 78,  112, 255, 16,  155, 207, 31,  222, 182, 71,  175, 216, 37,  16,  135, 188,
        96,  86,  133, 36,  11,  111, 163, 196, 190, 115, 2,   59,  143, 211, 18,  15,  73,  172,
        182, 224, 186, 231, 51,  167, 106, 111, 59,  170, 24,  23,  104, 195, 48,  39,  223, 71,
        105, 111, 179, 185, 238, 121, 209, 13,  222, 125, 209, 48,  232, 173, 251, 64,  249, 53,
        137, 135, 42,  74,  106, 11,  137, 146, 172, 205, 74,  179, 146, 104, 35,  139, 228, 4,
        152, 40,  220, 18,  106, 15,  5,   55,  153, 125, 11,  214, 168, 234, 64,  118, 205, 75,
        178, 104, 107, 192, 224, 187, 120, 128, 121, 99,  171, 12,  21,  148, 196, 144, 87,  217,
        77,  56,  191, 64,  176, 106, 15,  31,  187, 108, 219, 159, 85,  170, 251, 111, 59,  13,
        144, 206, 56,  164, 214, 32,  92,  146, 255, 174, 120, 74,  157, 246, 111, 178, 228, 13,
        57,  74,  176, 96,  147, 253, 84,  92,  27,  122, 126, 159, 69,  95,  157, 130, 85,  199,
        118, 183, 205, 171, 168, 182, 111, 201, 83,  244, 217, 11,
    };

    const input_be_va = 0x100000000;
    const result_be_va = 0x200000000;
    const input_le_va = 0x300000000;
    const result_le_va = 0x400000000;

    var result_be: [192]u8 = undefined;
    var result_le: [192]u8 = undefined;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &compressed_be, input_be_va),
        .init(.mutable, &result_be, result_be_va),
        .init(.constant, &compressed_le, input_le_va),
        .init(.mutable, &result_le, result_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_be)); // Big endian
    registers.set(.r2, input_be_va);
    registers.set(.r3, result_be_va);

    try curveDecompress(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_affine_be, &result_be);

    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_le)); // Big endian
    registers.set(.r2, input_le_va);
    registers.set(.r3, result_le_va);

    try curveDecompress(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));
    try std.testing.expectEqualSlices(u8, &expected_affine_le, &result_le);
}

test "bls12-381 validate g1" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 1_565 * 4,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    var point_bytes_be: [96]u8 = .{
        22,  163, 250, 67,  197, 168, 103, 201, 128, 33, 170, 96,  74,  40,  45, 90,  105, 181,
        244, 124, 128, 107, 27,  142, 158, 96,  0,   46, 144, 27,  61,  205, 65, 38,  141, 165,
        55,  113, 114, 23,  36,  105, 252, 115, 147, 16, 12,  39,  11,  19,  53, 215, 107, 128,
        94,  68,  22,  46,  74,  179, 236, 232, 220, 30, 48,  169, 85,  16,  70, 112, 26,  37,
        73,  104, 203, 189, 42,  96,  141, 90,  167, 41, 61,  82,  184, 80,  93, 112, 204, 140,
        225, 245, 103, 130, 184, 194,
    };
    var point_bytes_le: [96]u8 = .{
        39,  12,  16,  147, 115, 252, 105, 36,  23,  114, 113, 55,  165, 141, 38,  65,  205, 61,
        27,  144, 46,  0,   96,  158, 142, 27,  107, 128, 124, 244, 181, 105, 90,  45,  40,  74,
        96,  170, 33,  128, 201, 103, 168, 197, 67,  250, 163, 22,  194, 184, 130, 103, 245, 225,
        140, 204, 112, 93,  80,  184, 82,  61,  41,  167, 90,  141, 96,  42,  189, 203, 104, 73,
        37,  26,  112, 70,  16,  85,  169, 48,  30,  220, 232, 236, 179, 74,  46,  22,  68,  94,
        128, 107, 215, 53,  19,  11,
    };

    const point_be_va = 0x100000000;
    const point_le_va = 0x200000000;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &point_bytes_be, point_be_va),
        .init(.constant, &point_bytes_le, point_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);

    // Success case
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_be)); // Big endian
    registers.set(.r2, point_be_va);
    try curvePointValidation(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));

    // Failure case
    point_bytes_be[2] = 10;
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_be)); // Big endian
    registers.set(.r2, point_be_va);
    try curvePointValidation(&tc, &memory_map, &registers);
    try std.testing.expectEqual(1, registers.get(.r0));

    // Success case
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_le)); // Little endian
    registers.set(.r2, point_le_va);
    try curvePointValidation(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));

    // Failure case
    point_bytes_le[2] = 10;
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g1_le)); // Little endian
    registers.set(.r2, point_le_va);
    try curvePointValidation(&tc, &memory_map, &registers);
    try std.testing.expectEqual(1, registers.get(.r0));
}

test "bls12-381 validate g2" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    var cache, var tc = try sig.runtime.testing.createTransactionContext(allocator, random, .{
        .compute_meter = 1_968 * 4,
        .accounts = &.{.{
            .pubkey = .initRandom(random),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .feature_set = &.{.{ .feature = .enable_bls12_381_syscall }},
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    var point_bytes_be: [192]u8 = .{
        0,   79,  207, 115, 91,  72,  0,   80,  49,  59,  203, 189, 178, 240, 18,  141, 223, 147,
        62,  79,  98,  131, 147, 33,  103, 151, 137, 12,  160, 13,  78,  180, 13,  221, 89,  239,
        178, 249, 141, 8,   38,  137, 23,  71,  213, 2,   28,  13,  24,  168, 51,  6,   34,  184,
        228, 22,  173, 11,  224, 168, 14,  103, 154, 18,  166, 51,  255, 154, 45,  230, 253, 149,
        145, 16,  251, 107, 248, 55,  53,  150, 37,  131, 133, 138, 156, 195, 70,  202, 131, 144,
        166, 164, 80,  251, 179, 167, 8,   54,  188, 153, 10,  235, 83,  14,  211, 95,  212, 54,
        120, 175, 148, 83,  253, 106, 53,  178, 157, 118, 208, 110, 0,   187, 111, 14,  140, 246,
        139, 200, 205, 178, 72,  36,  67,  140, 39,  100, 163, 104, 140, 78,  91,  123, 130, 197,
        12,  176, 70,  104, 65,  43,  104, 232, 102, 238, 229, 115, 253, 62,  61,  207, 116, 223,
        245, 206, 250, 163, 30,  200, 76,  101, 93,  69,  216, 240, 189, 198, 253, 27,  199, 32,
        215, 224, 12,  50,  78,  204, 106, 40,  117, 68,  44,  113,
    };
    var point_bytes_le: [192]u8 = .{
        167, 179, 251, 80,  164, 166, 144, 131, 202, 70,  195, 156, 138, 133, 131, 37,  150, 53,
        55,  248, 107, 251, 16,  145, 149, 253, 230, 45,  154, 255, 51,  166, 18,  154, 103, 14,
        168, 224, 11,  173, 22,  228, 184, 34,  6,   51,  168, 24,  13,  28,  2,   213, 71,  23,
        137, 38,  8,   141, 249, 178, 239, 89,  221, 13,  180, 78,  13,  160, 12,  137, 151, 103,
        33,  147, 131, 98,  79,  62,  147, 223, 141, 18,  240, 178, 189, 203, 59,  49,  80,  0,
        72,  91,  115, 207, 79,  0,   113, 44,  68,  117, 40,  106, 204, 78,  50,  12,  224, 215,
        32,  199, 27,  253, 198, 189, 240, 216, 69,  93,  101, 76,  200, 30,  163, 250, 206, 245,
        223, 116, 207, 61,  62,  253, 115, 229, 238, 102, 232, 104, 43,  65,  104, 70,  176, 12,
        197, 130, 123, 91,  78,  140, 104, 163, 100, 39,  140, 67,  36,  72,  178, 205, 200, 139,
        246, 140, 14,  111, 187, 0,   110, 208, 118, 157, 178, 53,  106, 253, 83,  148, 175, 120,
        54,  212, 95,  211, 14,  83,  235, 10,  153, 188, 54,  8,
    };

    const point_be_va = 0x100000000;
    const point_le_va = 0x200000000;

    var memory_map: MemoryMap = try .init(allocator, &.{
        .init(.constant, &point_bytes_be, point_be_va),
        .init(.constant, &point_bytes_le, point_le_va),
    }, .v2, .{});
    defer memory_map.deinit(allocator);

    var registers: sig.vm.interpreter.RegisterMap = .initFill(0);

    // Success case
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_be)); // Big endian
    registers.set(.r2, point_be_va);
    try curvePointValidation(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));

    // Failure case
    point_bytes_be[2] = 10;
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_be)); // Big endian
    registers.set(.r2, point_be_va);
    try curvePointValidation(&tc, &memory_map, &registers);
    try std.testing.expectEqual(1, registers.get(.r0));

    // Success case
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_le)); // Little endian
    registers.set(.r2, point_le_va);
    try curvePointValidation(&tc, &memory_map, &registers);
    try std.testing.expectEqual(0, registers.get(.r0));

    // Failure case
    point_bytes_le[2] = 10;
    registers.set(.r0, 0);
    registers.set(.r1, @intFromEnum(CurveId.bls12_381_g2_le)); // Little endian
    registers.set(.r2, point_le_va);
    try curvePointValidation(&tc, &memory_map, &registers);
    try std.testing.expectEqual(1, registers.get(.r0));
}
