//! Syscalls that work with Elliptic Curves

const std = @import("std");
const sig = @import("../../sig.zig");

const features = sig.runtime.features;

const MemoryMap = sig.vm.memory.MemoryMap;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const TransactionContext = sig.runtime.TransactionContext;
const Error = sig.vm.syscalls.Error;
const SyscallError = sig.vm.SyscallError;
const memory = sig.vm.memory;

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ristretto255 = std.crypto.ecc.Ristretto255;

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

const weak_mul = struct {
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

    fn pcMul16(pc: *const [16]Edwards25519, s: [32]u8, comptime vartime: bool) !Edwards25519 {
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

    fn mul(p: Edwards25519, s: [32]u8) !Edwards25519 {
        const xpc = if (p.is_base) basePointPc else precompute(p, 15);
        // xpc[4].rejectIdentity() catch return error.WeakPublicKey;
        return pcMul16(&xpc, s, false);
    }

    /// Multiscalar multiplication *IN VARIABLE TIME* for public data
    /// Computes ps0*ss0 + ps1*ss1 + ps2*ss2... faster than doing many of these operations individually
    fn mulMulti(comptime count: usize, ps: [count]Edwards25519, ss: [count][32]u8) !Edwards25519 {
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
                Ristretto255 => .{ .p = try weak_mul.mul(input_point.p, left) },
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
            const T = switch (id) {
                .edwards => Edwards25519,
                .ristretto => Ristretto255,
            };

            const result = multiScalarMultiply(T, scalars, point_data) catch {
                registers.set(.r0, 1);
                return;
            };

            const result_point_data = try memory_map.translateType(
                [32]u8,
                .mutable,
                result_point_addr,
                tc.getCheckAligned(),
            );
            result_point_data.* = result.toBytes();
        },
    }
}

/// Batches scalar multiplication to the nearest power of 2 number of scalars.
///
/// TODO: Explore fixed-length padding with identies, if that's faster?
fn multiScalarMultiply(comptime T: type, scalars: []const [32]u8, point_data: []const [32]u8) !T {
    std.debug.assert(scalars.len == point_data.len);
    std.debug.assert(scalars.len <= 512);

    for (scalars) |scalar| {
        try Edwards25519.scalar.rejectNonCanonical(scalar);
    }

    var points: std.BoundedArray(Edwards25519, 512) = .{};
    for (point_data) |encoded| {
        const point = try T.fromBytes(encoded);
        points.appendAssumeCapacity(switch (T) {
            Edwards25519 => point,
            Ristretto255 => point.p,
            else => unreachable,
        });
    }

    var length = scalars.len;
    var accumulator = Edwards25519.identityElement;
    while (length > 0) {
        switch (std.math.floorPowerOfTwo(u64, length)) {
            inline 1, 2, 4, 8, 16, 32, 64, 128, 256, 512 => |N| {
                const current = scalars.len - length;
                const segment = try weak_mul.mulMulti(
                    N,
                    points.constSlice()[current..][0..N].*,
                    scalars[current..][0..N].*,
                );
                accumulator = accumulator.add(segment);
                length -= N;
            },
            else => unreachable,
        }
    }

    return switch (T) {
        Ristretto255 => .{ .p = accumulator },
        Edwards25519 => accumulator,
        else => unreachable,
    };
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
            .{ .{ 0, invalid_bytes_addr, 0, 0, 0}, 1 }, // failed
            .{ .{ 5, valid_bytes_addr,   0, 0, 0}, 1 }, // invalid curve ID
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
        33,  124, 71, 170, 117, 69,  151, 247, 59,  12, 95,  125, 133,
        166, 64,  5,  2,   27,  90,  27,  200, 167, 59, 164, 52,  54,
        52,  200, 29, 13,  34,  213,
    };
    const left_point_addr = 0x100000000;

    const right_point = [_]u8{
        70,  222, 137, 221, 253, 204, 71,  51,  78, 8,   124, 1,   67,
        200, 102, 225, 122, 228, 111, 183, 129, 14, 131, 210, 212, 95,
        109, 246, 55,  10,  159, 91,
    };
    const right_point_addr = 0x200000000;

    const scalar = [_]u8{
        254, 198, 23,  138, 67,  243, 184, 110, 236, 115, 236, 205, 205,
        215, 79,  114, 45,  250, 78,  137, 3,   107, 136, 237, 49,  126,
        117, 223, 37,  191, 88,  6,
    };
    const scalar_addr = 0x300000000;

    const invalid_point = [_]u8{
        120, 140, 152, 233, 41,  227, 203, 27, 87,  115, 25,  251, 219,
        5,   84,  148, 117, 38,  84,  60,  87, 144, 161, 146, 42,  34,
        91,  155, 158, 189, 121, 79,
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
    var tc = try sig.runtime.testing.createTransactionContext(
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
    defer sig.runtime.testing.deinitTransactionContext(allocator, &tc);

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
    var tc = try sig.runtime.testing.createTransactionContext(
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
    defer sig.runtime.testing.deinitTransactionContext(allocator, &tc);

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
    var tc = try sig.runtime.testing.createTransactionContext(
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
    defer sig.runtime.testing.deinitTransactionContext(allocator, &tc);

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
    var tc = try sig.runtime.testing.createTransactionContext(
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
    defer sig.runtime.testing.deinitTransactionContext(allocator, &tc);

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
