//! Syscalls that work with Elliptic Curves

const std = @import("std");
const sig = @import("../../sig.zig");

const bn254 = sig.crypto.bn254;
const features = sig.core.features;

const MemoryMap = sig.vm.memory.MemoryMap;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const TransactionContext = sig.runtime.TransactionContext;
const Error = sig.vm.syscalls.Error;
const SyscallError = sig.vm.SyscallError;
const memory = sig.vm.memory;

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ristretto255 = std.crypto.ecc.Ristretto255;

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, Keccak256);

pub const CurveId = enum(u64) {
    edwards = 0,
    ristretto = 1,

    fn wrap(id: u64) ?CurveId {
        if (id > 1) return null;
        return @enumFromInt(id);
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

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L1042-L1106
pub fn curvePointValidation(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const curve_id = CurveId.wrap(registers.get(.r1)) orelse {
        if (tc.feature_set.active.contains(features.ABORT_ON_INVALID_CURVE)) {
            return SyscallError.InvalidAttribute;
        } else {
            registers.set(.r0, 1);
            return;
        }
    };
    const point_addr = registers.get(.r2);

    const cost = switch (curve_id) {
        .edwards => tc.compute_budget.curve25519_edwards_validate_point_cost,
        .ristretto => tc.compute_budget.curve25519_ristretto_validate_point_cost,
    };
    try tc.consumeCompute(cost);

    const buffer = try memory_map.translateType(
        [32]u8,
        .constant,
        point_addr,
        tc.getCheckAligned(),
    );

    const is_error = switch (curve_id) {
        .edwards => std.meta.isError(Edwards25519.fromBytes(buffer.*)),
        .ristretto => std.meta.isError(Ristretto255.fromBytes(buffer.*)),
    };

    registers.set(.r0, @intFromBool(is_error));
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L1108-L1332
pub fn curveGroupOp(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const curve_id = CurveId.wrap(registers.get(.r1)) orelse {
        if (tc.feature_set.active.contains(features.ABORT_ON_INVALID_CURVE)) {
            return SyscallError.InvalidAttribute;
        } else {
            registers.set(.r0, 1);
            return;
        }
    };
    const group_op = GroupOp.wrap(registers.get(.r2)) orelse {
        if (tc.feature_set.active.contains(features.ABORT_ON_INVALID_CURVE)) {
            return SyscallError.InvalidAttribute;
        } else {
            registers.set(.r0, 1);
            return;
        }
    };

    const left_input_addr = registers.get(.r3);
    const right_input_addr = registers.get(.r4);
    const result_point_addr = registers.get(.r5);

    const cost = tc.compute_budget.curveGroupOperationCost(curve_id, group_op);
    try tc.consumeCompute(cost);

    switch (curve_id) {
        inline .edwards, .ristretto => |id| {
            const T = switch (id) {
                .edwards => Edwards25519,
                .ristretto => Ristretto255,
            };

            const left_point_data = try memory_map.translateType(
                [32]u8,
                .constant,
                left_input_addr,
                tc.getCheckAligned(),
            );

            const right_point_data = try memory_map.translateType(
                [32]u8,
                .constant,
                right_input_addr,
                tc.getCheckAligned(),
            );

            const result = groupOp(
                T,
                group_op,
                left_point_data.*,
                right_point_data.*,
            ) catch {
                registers.set(.r0, 1);
                return;
            };

            const result_point = try memory_map.translateType(
                [32]u8,
                .mutable,
                result_point_addr,
                tc.getCheckAligned(),
            );
            result_point.* = result.toBytes();
        },
    }
}

pub const weak_mul = struct {
    inline fn cMov(p: *Edwards25519, a: Edwards25519, c: u64) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
        p.t.cMov(a.t, c);
    }

    inline fn pcSelect(comptime n: usize, pc: *const [n]Edwards25519, b: u8) Edwards25519 {
        var t = Edwards25519.identityElement;
        comptime var i: u8 = 1;
        inline while (i < pc.len) : (i += 1) {
            cMov(&t, pc[i], ((@as(usize, b ^ i) -% 1) >> 8) & 1);
        }
        return t;
    }

    fn pcMul16(pc: *const [16]Edwards25519, s: [32]u8, comptime vartime: bool) Edwards25519 {
        var q = Edwards25519.identityElement;
        var pos: usize = 252;
        while (true) : (pos -= 4) {
            const slot: u4 = @truncate((s[pos >> 3] >> @as(u3, @truncate(pos))));
            if (vartime) {
                if (slot != 0) {
                    q = q.add(pc[slot]);
                }
            } else {
                q = q.add(pcSelect(16, pc, slot));
            }
            if (pos == 0) break;
            q = q.dbl().dbl().dbl().dbl();
        }
        // try q.rejectIdentity();
        return q;
    }

    fn precompute(p: Edwards25519, comptime count: usize) [1 + count]Edwards25519 {
        var pc: [1 + count]Edwards25519 = undefined;
        pc[0] = Edwards25519.identityElement;
        pc[1] = p;
        var i: usize = 2;
        while (i <= count) : (i += 1) {
            pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
        }
        return pc;
    }

    fn slide(s: [32]u8) [2 * 32]i8 {
        const reduced = if ((s[s.len - 1] & 0x80) == 0) s else Edwards25519.scalar.reduce(s);
        var e: [2 * 32]i8 = undefined;
        for (reduced, 0..) |x, i| {
            e[i * 2 + 0] = @as(i8, @as(u4, @truncate(x)));
            e[i * 2 + 1] = @as(i8, @as(u4, @truncate(x >> 4)));
        }
        // Now, e[0..63] is between 0 and 15, e[63] is between 0 and 7
        var carry: i8 = 0;
        for (e[0..63]) |*x| {
            x.* += carry;
            carry = (x.* + 8) >> 4;
            x.* -= carry * 16;
        }
        e[63] += carry;
        // Now, e[*] is between -8 and 8, including e[63]
        return e;
    }

    const basePointPc = pc: {
        @setEvalBranchQuota(10000);
        break :pc precompute(Edwards25519.basePoint, 15);
    };

    /// NOTE: Does not perform checks for weak points!
    pub fn mul(p: Edwards25519, s: [32]u8) Edwards25519 {
        const xpc = if (p.is_base) basePointPc else precompute(p, 15);
        // xpc[4].rejectIdentity() catch return error.WeakPublicKey;
        return pcMul16(&xpc, s, false);
    }

    /// Multiscalar multiplication *IN VARIABLE TIME* for public data
    /// Computes ps0*ss0 + ps1*ss1 + ps2*ss2... faster than doing many of these operations individually
    ///
    /// NOTE: Does not perform checks for weak points!
    pub fn mulMulti(
        comptime count: usize,
        ps: [count]Edwards25519,
        ss: [count][32]u8,
    ) Edwards25519 {
        var pcs: [count][9]Edwards25519 = undefined;

        var bpc: [9]Edwards25519 = undefined;
        @memcpy(&bpc, basePointPc[0..bpc.len]);

        for (ps, 0..) |p, i| {
            if (p.is_base) {
                pcs[i] = bpc;
            } else {
                pcs[i] = precompute(p, 8);
                // pcs[i][4].rejectIdentity() catch return error.WeakPublicKey;
            }
        }
        var es: [count][2 * 32]i8 = undefined;
        for (ss, 0..) |s, i| {
            es[i] = slide(s);
        }
        var q = Edwards25519.identityElement;
        var pos: usize = 2 * 32 - 1;
        while (true) : (pos -= 1) {
            for (es, 0..) |e, i| {
                const slot = e[pos];
                if (slot > 0) {
                    q = q.add(pcs[i][@as(usize, @intCast(slot))]);
                } else if (slot < 0) {
                    q = q.sub(pcs[i][@as(usize, @intCast(-slot))]);
                }
            }
            if (pos == 0) break;
            q = q.dbl().dbl().dbl().dbl();
        }
        // try q.rejectIdentity();
        return q;
    }
};

fn groupOp(comptime T: type, group_op: GroupOp, left: [32]u8, right: [32]u8) !T {
    switch (group_op) {
        .add, .subtract => {
            const left_point = try T.fromBytes(left);
            const right_point = try T.fromBytes(right);
            return switch (group_op) {
                .add => left_point.add(right_point),
                // TODO:(0.15) Use the alias https://github.com/ziglang/zig/pull/23724
                .subtract => switch (T) {
                    Edwards25519 => left_point.sub(right_point),
                    Ristretto255 => .{ .p = left_point.p.sub(right_point.p) },
                    else => unreachable,
                },
                else => unreachable,
            };
        },
        .multiply => {
            try Edwards25519.scalar.rejectNonCanonical(left);
            const input_point = try T.fromBytes(right);
            return switch (T) {
                Edwards25519 => weak_mul.mul(input_point, left),
                Ristretto255 => .{ .p = weak_mul.mul(input_point.p, left) },
                else => unreachable,
            };
        },
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L1334-L1445
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

    const curve_id = CurveId.wrap(attribute_id) orelse {
        if (tc.feature_set.active.contains(features.ABORT_ON_INVALID_CURVE)) {
            return SyscallError.InvalidAttribute;
        } else {
            registers.set(.r0, 1);
            return;
        }
    };

    const cost = switch (curve_id) {
        .edwards => tc.compute_budget.curve25519_edwards_msm_base_cost,
        .ristretto => tc.compute_budget.curve25519_ristretto_msm_base_cost,
    };
    const incremental_cost = switch (curve_id) {
        .edwards => tc.compute_budget.curve25519_edwards_msm_incremental_cost,
        .ristretto => tc.compute_budget.curve25519_ristretto_msm_incremental_cost,
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

            const msm = sig.crypto.ed25519.pippenger.mulMulti(
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
    ) catch {
        if (tc.feature_set.active.contains(
            features.SIMPLIFY_ALT_BN128_SYSCALL_ERROR_CODES,
        )) {
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
        if (tc.feature_set.active.contains(
            features.SIMPLIFY_ALT_BN128_SYSCALL_ERROR_CODES,
        )) {
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
        if (tc.feature_set.active.contains(
            features.SIMPLIFY_ALT_BN128_SYSCALL_ERROR_CODES,
        )) {
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
    feature_set: *const features.FeatureSet,
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
            const expected_size: usize = if (feature_set.active.contains(
                features.FIX_ALT_BN128_MULTIPLICATION_INPUT_LENGTH,
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
            // Agave does not check that the input length is a multiple of the
            // pair size (192 bytes). That *would* make sense, however it turns out Agave
            // performs a useless check,
            // https://github.com/anza-xyz/solana-sdk/blob/8eef25b054c4e5ca6d8b879744456297a187db92/bn254/src/lib.rs#L321-L327
            //
            // To the untrained eye this may seem like a check that `input.len()` is a multiple of
            // the pairing size. You would be wrong! `check_rem` only returns `None`
            // if the RHS is zero. The only way this condition will be true is if the
            // `PAIRING_ELEMENT_LENGTH` constant were zero, which is impossible.
            //
            // The "correct" behaviour ends up being to *not* check the length, instead we perform
            // a truncating integer division in the pairing syscall implementation (ensuring that
            // the number of pairs read will always fit input size), and simply ignore the remaining
            // bytes.
            //
            // if (input.len % 192 != 0) return error.InvalidLength;

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
    const recovery_result = try memory_map.translateSlice(
        u8,
        .mutable,
        result_addr,
        64,
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

    const compute_budget = sig.runtime.ComputeBudget.default(1_400_000);
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
            .{ .{ 5, valid_bytes_addr,   0, 0, 0 }, 1 }, // invalid curve ID
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

    const compute_budget = sig.runtime.ComputeBudget.default(1_400_000);
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
            .{ .{ 5, valid_bytes_addr,   0, 0, 0 }, 1 }, // invalid curve ID
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

    const compute_budget = sig.runtime.ComputeBudget.default(1_400_000);
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

    var prng = std.Random.DefaultPrng.init(0);
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
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
        cache.deinit(allocator);
    }

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, regions, .v3, .{});
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

    const compute_budget = sig.runtime.ComputeBudget.default(1_400_000);
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

    var prng = std.Random.DefaultPrng.init(0);
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
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
        cache.deinit(allocator);
    }

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, regions, .v3, .{});
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
    }, .v3, .{});
    defer memory_map.deinit(allocator);

    const compute_budget = sig.runtime.ComputeBudget.default(1_400_000);
    const total_compute = compute_budget.curve25519_edwards_msm_base_cost +
        compute_budget.curve25519_edwards_msm_incremental_cost +
        compute_budget.curve25519_ristretto_msm_base_cost +
        compute_budget.curve25519_ristretto_msm_incremental_cost;

    var prng = std.Random.DefaultPrng.init(0);
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
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
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
    }, .v3, .{});
    defer memory_map.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(0);
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
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
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

    var prng = std.Random.DefaultPrng.init(0);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 334 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
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
    }, .v3, .{});
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

    var prng = std.Random.DefaultPrng.init(0);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 3_840 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
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
    }, .v3, .{});
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

    var prng = std.Random.DefaultPrng.init(0);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 48_986 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
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
    }, .v3, .{});
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

    var prng = std.Random.DefaultPrng.init(0);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 628 * 2 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
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
        }, .v3, .{});
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

    var prng = std.Random.DefaultPrng.init(0);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 13_896 * 2 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
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
        }, .v3, .{});
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

test "secp256k1_recover" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);
    var cache, var tc = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{ .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }}, .compute_meter = 25_000 },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
        cache.deinit(allocator);
    }

    const message_hash: []const u8 = &.{
        0xde, 0xa5, 0x66, 0xb6, 0x94, 0x3b, 0xe0, 0xe9, 0x62, 0x53, 0xc2, 0x21, 0x5b,
        0x1b, 0xac, 0x69, 0xe7, 0xa8, 0x1e, 0xdb, 0x41, 0xc5, 0x02, 0x8b, 0x4f, 0x5c,
        0x45, 0xc5, 0x3b, 0x49, 0x54, 0xd0,
    };
    const message_hash_addr = 0x100000000;

    const signature = &.{
        0x97, 0xa4, 0xee, 0x31, 0xfe, 0x82, 0x65, 0x72, 0x9f, 0x4a, 0xa6, 0x7d, 0x24,
        0xd4, 0xa7, 0x27, 0xf8, 0xc3, 0x15, 0xa4, 0xc8, 0xf9, 0x80, 0xeb, 0x4c, 0x4d,
        0x4a, 0xfa, 0x6e, 0xc9, 0x42, 0x41, 0x5d, 0x10, 0xd9, 0xc2, 0x8a, 0x90, 0xe9,
        0x92, 0x9c, 0x52, 0x4b, 0x2c, 0xfb, 0x65, 0xdf, 0xbc, 0xf6, 0x8c, 0xfd, 0x68,
        0xdb, 0x17, 0xf9, 0x5d, 0x23, 0x5f, 0x96, 0xd8, 0xf0, 0x72, 0x01, 0x2d,
    };
    const signature_addr = 0x200000000;

    var result_point: [64]u8 = undefined;
    const result_point_addr = 0x300000000;

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(allocator, &.{
        memory.Region.init(.constant, message_hash, message_hash_addr),
        memory.Region.init(.constant, signature, signature_addr),
        memory.Region.init(.mutable, &result_point, result_point_addr),
    }, .v3, .{});
    defer memory_map.deinit(allocator);

    registers.set(.r1, message_hash_addr);
    registers.set(.r2, 1); // recovery id
    registers.set(.r3, signature_addr);
    registers.set(.r4, result_point_addr);

    try secp256k1Recover(&tc, &memory_map, &registers);

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
}
