const std = @import("std");
const sig = @import("../../../lib.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("ed25519.zig");
        _ = @import("secp256k1.zig");
        _ = @import("secp256r1.zig");
    }
}

pub const ed25519 = @import("ed25519.zig");
pub const secp256k1 = @import("secp256k1.zig");
pub const secp256r1 = @import("secp256r1.zig");

const Feature = sig.core.features.Feature;
const Pubkey = sig.core.Pubkey;

/// https://github.com/anza-xyz/agave/blob/df063a8c6483ad1d2bbbba50ab0b7fd7290eb7f4/cost-model/src/block_cost_limits.rs#L15
/// Cluster averaged compute unit to micro-sec conversion rate
pub const COMPUTE_UNIT_TO_US_RATIO: u64 = 30;
/// Number of compute units for one signature verification.
pub const SIGNATURE_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 24;
/// Number of compute units for one secp256k1 signature verification.
pub const SECP256K1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 223;
/// Number of compute units for one ed25519 strict signature verification.
pub const ED25519_VERIFY_STRICT_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 80;
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
        .required_feature = null,
    },
};

pub const PrecompileFn = fn (
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
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
