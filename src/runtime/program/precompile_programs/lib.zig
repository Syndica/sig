const std = @import("std");
const sig = @import("../../../sig.zig");

pub const ed25519 = @import("ed25519.zig");
pub const secp256k1 = @import("secp256k1.zig");
pub const secp256r1 = @import("secp256r1.zig");

const Pubkey = sig.core.Pubkey;
const Ed25519 = std.crypto.sign.Ed25519;

pub const ed25519Verify = ed25519.verify;
pub const secp256k1Verify = secp256k1.verify;
pub const secp256r1Verify = secp256r1.verify;

/// https://github.com/anza-xyz/agave/blob/df063a8c6483ad1d2bbbba50ab0b7fd7290eb7f4/cost-model/src/block_cost_limits.rs#L15
/// Cluster averaged compute unit to micro-sec conversion rate
pub const COMPUTE_UNIT_TO_US_RATIO: u64 = 30;
/// Number of compute units for one signature verification.
pub const SIGNATURE_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 24;
/// Number of compute units for one secp256k1 signature verification.
pub const SECP256K1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 223;
/// Number of compute units for one ed25519 signature verification.
pub const ED25519_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 76;

// TODO: should be moved to global features file
pub const SECP256R1_FEATURE_ID =
    Pubkey.parseBase58String("sr11RdZWgbHTHxSroPALe6zgaT5A1K9LcE4nfsZS4gi") catch unreachable;

pub const PRECOMPILES = [_]Precompile{
    .{
        .program_id = sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID,
        .function = ed25519Verify,
        .required_feature = null,
    },
    .{
        .program_id = sig.runtime.ids.PRECOMPILE_SECP256K1_PROGRAM_ID,
        .function = secp256k1Verify,
        .required_feature = null,
    },
    .{
        .program_id = sig.runtime.ids.PRECOMPILE_SECP256R1_PROGRAM_ID,
        .function = secp256r1Verify,
        .required_feature = SECP256R1_FEATURE_ID,
    },
};

// https://github.com/anza-xyz/agave/blob/f9d4939d1d6ad2783efc8ec60db058809bb87f55/cost-model/src/cost_model.rs#L115
pub fn verifyPrecompilesComputeCost(
    transaction: sig.core.Transaction,
    feature_set: sig.runtime.FeatureSet,
) u64 {
    // TODO: support verify_strict feature https://github.com/anza-xyz/agave/pull/1876/
    _ = feature_set;

    var n_secp256k1_instruction_signatures: u64 = 0;
    var n_ed25519_instruction_signatures: u64 = 0;

    // https://github.com/anza-xyz/agave/blob/6ea38fce866595908486a01c7d6b7182988f3b2d/sdk/program/src/message/sanitized.rs#L385
    for (transaction.msg.instructions) |instruction| {
        if (instruction.data.len == 0) continue;

        const program_id = transaction.msg.account_keys[instruction.program_index];
        if (program_id.equals(&sig.runtime.ids.PRECOMPILE_SECP256K1_PROGRAM_ID)) {
            n_secp256k1_instruction_signatures +|= instruction.data[0];
        }
        if (program_id.equals(&sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID)) {
            n_ed25519_instruction_signatures +|= instruction.data[0];
        }
    }

    return transaction.msg.signature_count *| SIGNATURE_COST +|
        n_secp256k1_instruction_signatures *| SECP256K1_VERIFY_COST +|
        n_ed25519_instruction_signatures *| ED25519_VERIFY_COST;
}

pub fn verifyPrecompiles(
    allocator: std.mem.Allocator,
    transaction: sig.core.Transaction,
    feature_set: sig.runtime.FeatureSet,
) (PrecompileProgramError || error{OutOfMemory})!void {
    // could remove this alloc by passing in the transaction in directly, but maybe less clean
    var instruction_datas: ?[]const []const u8 = null;
    defer if (instruction_datas) |instr_datas| allocator.free(instr_datas);

    for (transaction.msg.instructions) |instruction| {
        const program_id = transaction.msg.account_keys[instruction.program_index];
        for (PRECOMPILES) |precompile| {
            if (!precompile.program_id.equals(&program_id)) continue;

            const precompile_feature_enabled = precompile.required_feature == null or
                feature_set.active.contains(precompile.required_feature.?);
            if (!precompile_feature_enabled) continue;

            const datas = instruction_datas orelse blk: {
                const buf = try allocator.alloc([]const u8, transaction.msg.instructions.len);
                for (transaction.msg.instructions, 0..) |instr, i| buf[i] = instr.data;
                instruction_datas = buf;
                break :blk buf;
            };

            try precompile.function(instruction.data, datas);
        }
    }
}

pub const PrecompileFn = fn (
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
) PrecompileProgramError!void;

pub const Precompile = struct {
    program_id: Pubkey,
    function: *const PrecompileFn,
    required_feature: ?Pubkey,
};

// custom errors
// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/precompile-error/src/lib.rs#L6
pub const PrecompileProgramError = error{
    InvalidPublicKey,
    InvalidRecoveryId,
    InvalidSignature,
    InvalidDataOffsets,
    InvalidInstructionDataSize,
};

pub fn getInstructionValue(
    T: type,
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
    instruction_idx: u16,
    offset: usize,
) error{InvalidDataOffsets}!*align(1) const T {
    return @ptrCast(try getInstructionData(
        @sizeOf(T),
        current_instruction_data,
        all_instruction_datas,
        instruction_idx,
        offset,
    ));
}

// https://github.com/firedancer-io/firedancer/blob/af74882ffb2c24783a82718dbc5111a94e1b5f6f/src/flamenco/runtime/program/fd_precompiles.c#L74
pub fn getInstructionData(
    len: usize,
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
    instruction_idx: u16,
    offset: usize,
) error{InvalidDataOffsets}![]const u8 {
    const data: []const u8 = if (instruction_idx == std.math.maxInt(u16))
        current_instruction_data
    else data: {
        if (instruction_idx >= all_instruction_datas.len) return error.InvalidDataOffsets;
        break :data all_instruction_datas[instruction_idx];
    };

    if (offset +| len > data.len) return error.InvalidDataOffsets;
    return data[offset..][0..len];
}

test "verify ed25519" {
    try verifyPrecompiles(
        std.testing.allocator,
        sig.core.Transaction.EMPTY,
        sig.runtime.FeatureSet.EMPTY,
    );

    const bad_ed25519_tx = std.mem.zeroInit(sig.core.Transaction, .{
        .msg = .{
            .account_keys = &.{sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID},
            .instructions = &.{
                .{
                    .program_index = 0,
                    .account_indexes = &.{0},
                    .data = "hello",
                },
            },
        },
        .version = .legacy,
    });

    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verifyPrecompiles(std.testing.allocator, bad_ed25519_tx, sig.runtime.FeatureSet.EMPTY),
    );

    const keypair = try Ed25519.KeyPair.create(null);
    const ed25519_instruction = try ed25519.newInstruction(
        std.testing.allocator,
        keypair,
        "hello!",
    );
    defer std.testing.allocator.free(ed25519_instruction.data);

    const ed25519_tx: sig.core.Transaction = .{
        .msg = .{
            .account_keys = &.{sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID},
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

    try verifyPrecompiles(std.testing.allocator, ed25519_tx, sig.runtime.FeatureSet.EMPTY);
}
