const std = @import("std");
const sig = @import("../../../sig.zig");

pub const ed25519 = @import("ed25519.zig");
pub const secp256k1 = @import("secp256k1.zig");
pub const secp256r1 = @import("secp256r1.zig");

const Slot = sig.core.Slot;
const FeatureSet = sig.core.FeatureSet;
const Feature = sig.core.features.Feature;
const Pubkey = sig.core.Pubkey;
const Ed25519 = std.crypto.sign.Ed25519;
const TransactionInstruction = sig.core.transaction.Instruction;
const TransactionError = sig.ledger.transaction_status.TransactionError;

/// https://github.com/anza-xyz/agave/blob/df063a8c6483ad1d2bbbba50ab0b7fd7290eb7f4/cost-model/src/block_cost_limits.rs#L15
/// Cluster averaged compute unit to micro-sec conversion rate
pub const COMPUTE_UNIT_TO_US_RATIO: u64 = 30;
/// Number of compute units for one signature verification.
pub const SIGNATURE_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 24;
/// Number of compute units for one secp256k1 signature verification.
pub const SECP256K1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 223;
/// Number of compute units for one ed25519 signature verification.
pub const ED25519_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 80;
/// Number of compute units for one secp256r1 signature verification.
pub const SECP256R1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 160;

pub const PRECOMPILES = [_]Precompile{
    .{
        .program_id = ed25519.ID,
        .function = ed25519.verify,
        .required_feature = null,
    },
    .{
        .program_id = secp256k1.ID,
        .function = secp256k1.verify,
        .required_feature = null,
    },
    .{
        .program_id = secp256r1.ID,
        .function = secp256r1.verify,
        .required_feature = .enable_secp256r1_precompile,
    },
};

// https://github.com/anza-xyz/agave/blob/f9d4939d1d6ad2783efc8ec60db058809bb87f55/cost-model/src/cost_model.rs#L115
// https://github.com/anza-xyz/agave/blob/6ea38fce866595908486a01c7d6b7182988f3b2d/sdk/program/src/message/sanitized.rs#L378
pub fn verifyPrecompilesComputeCost(
    transaction: sig.core.Transaction,
    feature_set: *const sig.core.FeatureSet,
) u64 {
    // TODO: support verify_strict feature https://github.com/anza-xyz/agave/pull/1876/
    _ = feature_set;

    var n_secp256k1_instruction_signatures: u64 = 0;
    var n_ed25519_instruction_signatures: u64 = 0;

    // https://github.com/anza-xyz/agave/blob/6ea38fce866595908486a01c7d6b7182988f3b2d/sdk/program/src/message/sanitized.rs#L385
    for (transaction.msg.instructions) |instruction| {
        if (instruction.data.len == 0) continue;

        const program_id = transaction.msg.account_keys[instruction.program_index];
        if (program_id.equals(&secp256k1.ID)) {
            n_secp256k1_instruction_signatures +|= instruction.data[0];
        }
        if (program_id.equals(&ed25519.ID)) {
            n_ed25519_instruction_signatures +|= instruction.data[0];
        }
    }

    return n_secp256k1_instruction_signatures *| SECP256K1_VERIFY_COST +|
        n_ed25519_instruction_signatures *| ED25519_VERIFY_COST;
}

pub fn verifyPrecompiles(
    allocator: std.mem.Allocator,
    transaction: *const sig.core.Transaction,
    feature_set: *const sig.core.FeatureSet,
    slot: sig.core.Slot,
) error{OutOfMemory}!?TransactionError {
    // could remove this alloc by passing in the transaction in directly, but maybe less clean
    var instruction_datas: ?[]const []const u8 = null;
    defer if (instruction_datas) |instr_datas| allocator.free(instr_datas);

    for (transaction.msg.instructions, 0..) |instruction, index| {
        const program_id = transaction.msg.account_keys[instruction.program_index];
        for (PRECOMPILES) |precompile| {
            if (!precompile.program_id.equals(&program_id)) continue;

            const precompile_feature_enabled = if (precompile.required_feature) |feature|
                feature_set.active(feature, slot)
            else
                true;
            if (!precompile_feature_enabled) continue;

            const datas = instruction_datas orelse blk: {
                const buf = try allocator.alloc([]const u8, transaction.msg.instructions.len);
                for (transaction.msg.instructions, 0..) |instr, i| buf[i] = instr.data;
                instruction_datas = buf;
                break :blk buf;
            };

            precompile.function(instruction.data, datas, feature_set, slot) catch {
                return .{ .InstructionError = .{
                    @intCast(index),
                    .{ .Custom = 0 },
                } };
            };
        }
    }

    return null;
}

pub const PrecompileFn = fn (
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
    feature_set: *const FeatureSet,
    slot: Slot,
) PrecompileProgramError!void;

pub const Precompile = struct {
    program_id: Pubkey,
    function: *const PrecompileFn,
    required_feature: ?Feature,
};

pub const PrecompileProgramError = error{
    InvalidPublicKey,
    InvalidRecoveryId,
    InvalidSignature,
    InvalidDataOffsets,
    InvalidInstructionDataSize,
};

pub fn intFromPrecompileProgramError(err: PrecompileProgramError) u32 {
    return switch (err) {
        error.InvalidPublicKey => 0,
        error.InvalidRecoveryId => 1,
        error.InvalidSignature => 2,
        error.InvalidDataOffsets => 3,
        error.InvalidInstructionDataSize => 4,
    };
}

pub fn getInstructionData(
    data: []const u8,
    instruction_data: []const []const u8,
    instruction_index: u16,
    start: u16,
    size: u64,
) error{InvalidDataOffsets}![]const u8 {
    const instruction: []const u8 = switch (instruction_index) {
        std.math.maxInt(u16) => data,
        else => b: {
            if (instruction_index >= instruction_data.len) {
                return error.InvalidDataOffsets;
            }
            break :b instruction_data[instruction_index];
        },
    };
    if (start +| size > instruction.len) return error.InvalidDataOffsets;
    return instruction[start..][0..size];
}

test "verify ed25519" {
    {
        const actual = try verifyPrecompiles(
            std.testing.allocator,
            &.EMPTY,
            &.ALL_DISABLED,
            0,
        );
        try std.testing.expectEqual(null, actual);
    }

    {
        const bad_ed25519_tx: sig.core.Transaction = .{
            .msg = .{
                .account_keys = &.{ed25519.ID},
                .instructions = &[_]TransactionInstruction{
                    .{
                        .program_index = 0,
                        .account_indexes = &.{0},
                        .data = "hello",
                    },
                },
                .signature_count = 0,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 0,
                .recent_blockhash = .ZEROES,
                .address_lookups = &.{},
            },
            .version = .legacy,
            .signatures = &.{},
        };
        const actual = try verifyPrecompiles(
            std.testing.allocator,
            &bad_ed25519_tx,
            &.ALL_DISABLED,
            0,
        );
        try std.testing.expectEqual(
            TransactionError{ .InstructionError = .{ 0, .{ .Custom = 0 } } },
            actual,
        );
    }

    {
        const message = "hello!";
        const keypair = Ed25519.KeyPair.generate();
        const signature = try keypair.sign(message, null);
        const ed25519_instruction = try ed25519.newInstruction(
            std.testing.allocator,
            &signature,
            &keypair.public_key,
            message,
        );
        defer std.testing.allocator.free(ed25519_instruction.data);

        const ed25519_tx: sig.core.Transaction = .{
            .msg = .{
                .account_keys = &.{ed25519.ID},
                .instructions = &.{
                    .{
                        .program_index = 0,
                        .account_indexes = &.{0},
                        .data = ed25519_instruction.data,
                    },
                },
                .signature_count = 1,
                .readonly_signed_count = 1,
                .readonly_unsigned_count = 0,
                .recent_blockhash = sig.core.Hash.ZEROES,
            },
            .version = .legacy,
            .signatures = &.{},
        };

        const actual = try verifyPrecompiles(
            std.testing.allocator,
            &ed25519_tx,
            &.ALL_DISABLED,
            0,
        );
        try std.testing.expectEqual(null, actual);
    }
}

test "verify cost" {
    const message = "hello!";
    const keypair = Ed25519.KeyPair.generate();
    const signature = try keypair.sign(message, null);
    const ed25519_instruction = try ed25519.newInstruction(
        std.testing.allocator,
        &signature,
        &keypair.public_key,
        message,
    );
    defer std.testing.allocator.free(ed25519_instruction.data);

    const ed25519_tx: sig.core.Transaction = .{
        .msg = .{
            .account_keys = &.{ed25519.ID},
            .instructions = &.{
                .{ .program_index = 0, .account_indexes = &.{0}, .data = ed25519_instruction.data },
            },
            .signature_count = 1,
            .readonly_signed_count = 1,
            .readonly_unsigned_count = 0,
            .recent_blockhash = sig.core.Hash.ZEROES,
        },
        .version = .legacy,
        .signatures = &.{},
    };

    const expected_cost = ED25519_VERIFY_COST;
    // ED25519_VERIFY_COST = 2400 (30 * 80), matching agave's ED25519_VERIFY_STRICT_COST
    try std.testing.expectEqual(2400, ED25519_VERIFY_COST);

    const compute_units = verifyPrecompilesComputeCost(ed25519_tx, &.ALL_DISABLED);
    try std.testing.expectEqual(expected_cost, compute_units);
}

test "verify secp256k1" {
    const bad_secp256k1_tx: sig.core.Transaction = .{
        .msg = .{
            .account_keys = &.{secp256k1.ID},
            .instructions = &[_]TransactionInstruction{
                .{
                    .program_index = 0,
                    .account_indexes = &.{0},
                    .data = "hello",
                },
            },
            .signature_count = 0,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .recent_blockhash = .ZEROES,
            .address_lookups = &.{},
        },
        .version = .legacy,
        .signatures = &.{},
    };

    const actual = try verifyPrecompiles(
        std.testing.allocator,
        &bad_secp256k1_tx,
        &.ALL_DISABLED,
        0,
    );
    try std.testing.expectEqual(
        TransactionError{ .InstructionError = .{ 0, .{ .Custom = 0 } } },
        actual,
    );
}
