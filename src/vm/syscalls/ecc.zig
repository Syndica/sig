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
    add,
    subtract,
    multiply,

    fn wrap(id: u64) ?GroupOp {
        if (id > 2) return null;
        return @enumFromInt(id);
    }
};

pub fn curvePointValidation(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const curve_id = CurveId.wrap(registers.get(.r1)) orelse {
        if (tc.ec.feature_set.active.contains(features.ABORT_ON_INVALID_CURVE)) {
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

pub fn curveGroupOp(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const curve_id = CurveId.wrap(registers.get(.r1)) orelse {
        if (tc.ec.feature_set.active.contains(features.ABORT_ON_INVALID_CURVE)) {
            return SyscallError.InvalidAttribute;
        } else {
            registers.set(.r0, 1);
            return;
        }
    };
    const group_op = GroupOp.wrap(registers.get(.r2)) orelse {
        if (tc.ec.feature_set.active.contains(features.ABORT_ON_INVALID_CURVE)) {
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
        inline .edwards, .ristretto => |id| err: {
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

            const result: T = switch (group_op) {
                .add, .subtract => b: {
                    const left_point = T.fromBytes(left_point_data.*) catch break :err;
                    const right_point = T.fromBytes(right_point_data.*) catch break :err;
                    break :b switch (group_op) {
                        .add => left_point.add(right_point),
                        // TODO:(0.15) Use the alias https://github.com/ziglang/zig/pull/23724
                        .subtract => switch (id) {
                            .edwards => left_point.sub(right_point),
                            .ristretto => .{ .p = left_point.p.sub(right_point.p) },
                        },
                        else => unreachable,
                    };
                },
                .multiply => b: {
                    const input_point = T.fromBytes(right_point_data.*) catch break :err;
                    break :b input_point.mul(left_point_data.*) catch break :err;
                },
            };

            const result_point = try memory_map.translateType(
                [32]u8,
                .mutable,
                result_point_addr,
                tc.getCheckAligned(),
            );
            result_point.* = result.toBytes();

            registers.set(.r0, 0);
            return;
        },
    }

    registers.set(.r0, 1);
    return;
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
    const ec, const sc, var tc = try sig.runtime.testing.createExecutionContexts(
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
        ec.deinit();
        allocator.destroy(ec);
        sc.deinit();
        allocator.destroy(sc);
        tc.deinit();
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
    const ec, const sc, var tc = try sig.runtime.testing.createExecutionContexts(
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
        ec.deinit();
        allocator.destroy(ec);
        sc.deinit();
        allocator.destroy(sc);
        tc.deinit();
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
