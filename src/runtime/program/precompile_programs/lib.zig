const std = @import("std");
const sig = @import("../../../sig.zig");

pub const ed25519 = @import("ed25519.zig");
pub const secp256k1 = @import("secp256k1.zig");
pub const secp256r1 = @import("secp256r1.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;

const Pubkey = sig.core.Pubkey;

pub const ed25519Verify = ed25519.verify;
pub const secp256k1Verify = secp256k1.verify;
pub const secp256r1Verify = secp256r1.verify;

pub const COMPUTE_UNITS = 1; // does this consume compute units?

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
                for (0.., transaction.msg.instructions) |i, instr| buf[i] = instr.data;
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

// parsed internally
pub const PrecompileProgramInstruction = []const u8;

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
) error{ InvalidSignature, InvalidDataOffsets }!*const T {
    // aligncast potentially dangerous?
    return @alignCast(@ptrCast(try getInstructionData(
        @sizeOf(T),
        current_instruction_data,
        all_instruction_datas,
        instruction_idx,
        offset,
    )));
}

// https://github.com/firedancer-io/firedancer/blob/af74882ffb2c24783a82718dbc5111a94e1b5f6f/src/flamenco/runtime/program/fd_precompiles.c#L74
pub fn getInstructionData(
    len: usize,
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
    instruction_idx: u16,
    offset: usize,
) error{ InvalidSignature, InvalidDataOffsets }![]const u8 {
    const data: []const u8 = if (instruction_idx == std.math.maxInt(u16))
        current_instruction_data
    else data: {
        if (instruction_idx >= all_instruction_datas.len) return error.InvalidDataOffsets;
        break :data all_instruction_datas[instruction_idx];
    };

    if (offset + len > data.len) return error.InvalidSignature;
    return data[offset..][0..len];
}
