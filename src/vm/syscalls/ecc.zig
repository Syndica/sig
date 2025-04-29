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
        201, 179, 241, 122, 180, 185, 239, 50,  183, 52, 221, 0,   153, 195, 43,
        18,  22,  38,  187, 206, 179, 192, 210, 58,  53, 45,  150, 98,  89,  17,
        158, 11,
    };
    const valid_bytes_addr = 0x100000000;

    const invalid_bytes = [_]u8{
        120, 140, 152, 233, 41,  227, 203, 27, 87,  115, 25,  251, 219, 5, 84, 148, 117, 38, 84,
        60,  87,  144, 161, 146, 42,  34,  91, 155, 158, 189, 121, 79,
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
            .{ .{ 0, valid_bytes_addr,   0, 0 }, 0 }, // success
            .{ .{ 0, invalid_bytes_addr, 0, 0 }, 1 }, // failed
            .{ .{ 5, valid_bytes_addr,   0, 0 }, 1 }, // invalid curve ID
            .{ .{ 0, valid_bytes_addr,   0, 0 }, error.ComputationalBudgetExceeded },
        },
        // zig fmt: on
        null,
        .{ .compute_meter = total_compute },
    );
}

test "ristretto curve point validation" {
    const valid_bytes = [_]u8{
        226, 242, 174, 10,  106, 188, 78,  113, 168, 132, 169, 97, 197, 0, 81, 95, 88, 227, 11,
        106, 165, 130, 221, 141, 182, 166, 89,  69,  224, 141, 45, 118,
    };
    const valid_bytes_addr = 0x100000000;

    const invalid_bytes = [_]u8{
        120, 140, 152, 233, 41,  227, 203, 27, 87,  115, 25,  251, 219, 5, 84, 148, 117, 38, 84,
        60,  87,  144, 161, 146, 42,  34,  91, 155, 158, 189, 121, 79,
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
            .{ .{ 1, valid_bytes_addr,   0, 0 }, 0 }, // success
            .{ .{ 1, invalid_bytes_addr, 0, 0 }, 1 }, // failed
            .{ .{ 5, valid_bytes_addr,   0, 0 }, 1 }, // invalid curve ID
            .{ .{ 1, valid_bytes_addr,   0, 0 }, error.ComputationalBudgetExceeded },
        },
        // zig fmt: on
        null,
        .{ .compute_meter = total_compute },
    );
}
