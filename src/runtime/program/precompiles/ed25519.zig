const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../../sig.zig");
const features = sig.runtime.features;

const Pubkey = sig.core.Pubkey;
const FeatureSet = features.FeatureSet;
const PrecompileProgramError = sig.runtime.program.precompiles.PrecompileProgramError;
const Ed25519 = std.crypto.sign.Ed25519;
const verifyPrecompiles = sig.runtime.program.precompiles.verifyPrecompiles;

pub const ID =
    Pubkey.parseBase58String("Ed25519SigVerify111111111111111111111111111") catch unreachable;

pub const ED25519_DATA_START = ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE +
    ED25519_SIGNATURE_OFFSETS_START;
pub const ED25519_PUBKEY_SERIALIZED_SIZE = 32;
pub const ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE = 14;
pub const ED25519_SIGNATURE_OFFSETS_START = 2;
pub const ED25519_SIGNATURE_SERIALIZED_SIZE = 64;

comptime {
    std.debug.assert(ED25519_PUBKEY_SERIALIZED_SIZE == Ed25519.PublicKey.encoded_length);
    std.debug.assert(ED25519_SIGNATURE_SERIALIZED_SIZE == Ed25519.Signature.encoded_length);
    std.debug.assert(ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE == @sizeOf(Ed25519SignatureOffsets));
}

pub const Ed25519SignatureOffsets = extern struct {
    /// Offset to ed25519 signature of 64 bytes.
    signature_offset: u16 = 0,
    /// Instruction index to find signature.
    signature_instruction_idx: u16 = 0,
    /// Offset to public key of 32 bytes.
    pubkey_offset: u16 = 0,
    /// Instruction index to find public key.
    pubkey_instruction_idx: u16 = 0,
    /// Offset to start of message data.
    message_data_offset: u16 = 0,
    /// Size of message data.
    message_data_size: u16 = 0,
    /// Index of instruction data to get message data.
    message_instruction_idx: u16 = 0,
};

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/ed25519_instruction.rs#L88
// https://github.com/firedancer-io/firedancer/blob/af74882ffb2c24783a82718dbc5111a94e1b5f6f/src/flamenco/runtime/program/fd_precompiles.c#L118
pub fn verify(
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
    feature_set: *const FeatureSet,
) PrecompileProgramError!void {
    const data = current_instruction_data;
    if (data.len < ED25519_DATA_START) {
        if (data.len == 2 and data[0] == 0) return;
        return error.InvalidInstructionDataSize;
    }

    const n_signatures = data[0];
    if (n_signatures == 0) return error.InvalidInstructionDataSize;

    const expected_data_size: u64 = ED25519_SIGNATURE_OFFSETS_START +
        @as(u64, n_signatures) * ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    if (data.len < expected_data_size) return error.InvalidInstructionDataSize;

    for (0..n_signatures) |i| {
        const offset = ED25519_SIGNATURE_OFFSETS_START +
            i * ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE;

        const sig_offsets: *align(1) const Ed25519SignatureOffsets = @ptrCast(data.ptr + offset);

        const signature = try getInstructionValue(
            Ed25519.Signature,
            data,
            all_instruction_datas,
            sig_offsets.signature_instruction_idx,
            sig_offsets.signature_offset,
        );
        const pubkey = try getInstructionValue(
            Ed25519.PublicKey,
            data,
            all_instruction_datas,
            sig_offsets.pubkey_instruction_idx,
            sig_offsets.pubkey_offset,
        );
        const msg = try getInstructionData(
            sig_offsets.message_data_size,
            data,
            all_instruction_datas,
            sig_offsets.message_instruction_idx,
            sig_offsets.message_data_offset,
        );

        var st = signature.verifier(pubkey.*) catch return error.InvalidSignature;
        st.update(msg);
        st.verify() catch return error.InvalidSignature;

        // https://github.com/dalek-cryptography/ed25519-dalek/blob/02001d8c3422fb0314b541fdb09d04760f7ab4ba/src/verifying.rs#L424-L427
        if (feature_set.isActive(features.ED25519_PRECOMPILE_VERIFY_STRICT)) {
            st.expected_r.rejectLowOrder() catch return error.InvalidSignature;
            st.a.rejectLowOrder() catch return error.InvalidSignature;
        }
    }
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/ed25519_instruction.rs#L163
pub fn getInstructionData(
    len: usize,
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
    instruction_idx: u16,
    offset: u16,
) error{InvalidDataOffsets}![]const u8 {
    const instruction: []const u8 = if (instruction_idx == std.math.maxInt(u16))
        current_instruction_data
    else blk: {
        if (instruction_idx >= all_instruction_datas.len) return error.InvalidDataOffsets;
        break :blk all_instruction_datas[instruction_idx];
    };

    if (offset +| len > instruction.len) return error.InvalidDataOffsets;
    return instruction[offset..][0..len];
}

fn getInstructionValue(
    T: type,
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
    instruction_idx: u16,
    offset: u16,
) error{InvalidDataOffsets}!*align(1) const T {
    return @ptrCast(try getInstructionData(
        @sizeOf(T),
        current_instruction_data,
        all_instruction_datas,
        instruction_idx,
        offset,
    ));
}

// https://github.com/anza-xyz/agave/blob/2d834361c096198176dbdc4524d5003bccf6c192/precompiles/src/ed25519.rs#L130
pub fn newInstruction(
    allocator: std.mem.Allocator,
    signature: *const Ed25519.Signature,
    public_key: *const Ed25519.PublicKey,
    message: []const u8,
) !sig.core.Instruction {
    if (!builtin.is_test) @compileError("newInstruction is only for use in tests");
    std.debug.assert(message.len <= std.math.maxInt(u16));

    const num_signatures: u8 = 1;
    const pubkey_offset = ED25519_DATA_START;
    const signature_offset = pubkey_offset + ED25519_PUBKEY_SERIALIZED_SIZE;
    const message_data_offset = signature_offset + ED25519_SIGNATURE_SERIALIZED_SIZE;

    const offsets: Ed25519SignatureOffsets = .{
        .signature_offset = signature_offset,
        .signature_instruction_idx = std.math.maxInt(u16),
        .pubkey_offset = pubkey_offset,
        .pubkey_instruction_idx = std.math.maxInt(u16),
        .message_data_offset = message_data_offset,
        .message_data_size = @intCast(message.len),
        .message_instruction_idx = std.math.maxInt(u16),
    };

    var instruction_data = try std.ArrayList(u8).initCapacity(
        allocator,
        message_data_offset + message.len,
    );
    errdefer instruction_data.deinit();

    // add 2nd byte for padding, so that offset structure is aligned
    instruction_data.appendSliceAssumeCapacity(&.{ num_signatures, 0 });
    instruction_data.appendSliceAssumeCapacity(std.mem.asBytes(&offsets));
    std.debug.assert(instruction_data.items.len == pubkey_offset);
    instruction_data.appendSliceAssumeCapacity(&public_key.toBytes());
    std.debug.assert(instruction_data.items.len == signature_offset);
    instruction_data.appendSliceAssumeCapacity(&signature.toBytes());
    std.debug.assert(instruction_data.items.len == message_data_offset);
    instruction_data.appendSliceAssumeCapacity(message);

    return .{
        .program_id = ID,
        .accounts = &.{},
        .data = try instruction_data.toOwnedSlice(),
    };
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/ed25519_instruction.rs#L258
fn testCase(
    num_signatures: u16,
    offsets: Ed25519SignatureOffsets,
) PrecompileProgramError!void {
    if (!builtin.is_test) @compileError("testCase is only for use in tests");

    var instruction_data: [ED25519_DATA_START]u8 align(2) = undefined;
    @memcpy(instruction_data[0..2], std.mem.asBytes(&num_signatures));
    @memcpy(instruction_data[2..], std.mem.asBytes(&offsets));

    return try verify(&instruction_data, &.{&(.{0} ** 100)}, &FeatureSet.EMPTY);
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/ed25519_instruction.rs#L279
test "ed25519 invalid offsets" {
    const allocator = std.testing.allocator;
    var instruction_data = try std.ArrayListAligned(u8, 2).initCapacity(
        allocator,
        ED25519_DATA_START,
    );
    defer instruction_data.deinit();

    const offsets: Ed25519SignatureOffsets = .{};

    // Set up instruction data with invalid size
    instruction_data.appendSliceAssumeCapacity(std.mem.asBytes(&1));
    instruction_data.appendSliceAssumeCapacity(std.mem.asBytes(&offsets));
    try instruction_data.resize(instruction_data.items.len - 1);

    try std.testing.expectEqual(
        verify(instruction_data.items, &.{}, &FeatureSet.EMPTY),
        error.InvalidInstructionDataSize,
    );

    // invalid signature instruction index
    const invalid_signature_offsets: Ed25519SignatureOffsets = .{
        .signature_instruction_idx = 1,
    };
    try std.testing.expectEqual(
        testCase(1, invalid_signature_offsets),
        error.InvalidDataOffsets,
    );

    // invalid message instruction index
    const invalid_message_offsets: Ed25519SignatureOffsets = .{
        .message_instruction_idx = 1,
    };
    try std.testing.expectEqual(
        testCase(1, invalid_message_offsets),
        error.InvalidDataOffsets,
    );

    // invalid public key instruction index
    const invalid_pubkey_offsets: Ed25519SignatureOffsets = .{
        .pubkey_instruction_idx = 1,
    };
    try std.testing.expectEqual(
        testCase(1, invalid_pubkey_offsets),
        error.InvalidDataOffsets,
    );
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/ed25519_instruction.rs#L326
test "ed25519 message data offsets" {
    {
        const offsets: Ed25519SignatureOffsets = .{
            .message_data_offset = 99,
            .message_data_size = 1,
        };
        try std.testing.expectError(
            error.InvalidSignature,
            testCase(1, offsets),
        );
    }

    {
        const offsets: Ed25519SignatureOffsets = .{
            .message_data_offset = 100,
            .message_data_size = 1,
        };
        try std.testing.expectError(
            error.InvalidDataOffsets,
            testCase(1, offsets),
        );
    }

    {
        const offsets: Ed25519SignatureOffsets = .{
            .message_data_offset = 100,
            .message_data_size = 1000,
        };
        try std.testing.expectError(
            error.InvalidDataOffsets,
            testCase(1, offsets),
        );
    }

    {
        const offsets: Ed25519SignatureOffsets = .{
            .message_data_offset = std.math.maxInt(u16),
            .message_data_size = std.math.maxInt(u16),
        };
        try std.testing.expectError(
            error.InvalidDataOffsets,
            testCase(1, offsets),
        );
    }
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/ed25519_instruction.rs#L369
test "ed25519 pubkey offset" {
    {
        const offsets: Ed25519SignatureOffsets = .{
            .pubkey_offset = std.math.maxInt(u16),
        };
        try std.testing.expectEqual(
            testCase(1, offsets),
            error.InvalidDataOffsets,
        );
    }

    {
        const offsets: Ed25519SignatureOffsets = .{
            .pubkey_offset = 100 - ED25519_PUBKEY_SERIALIZED_SIZE + 1,
        };
        try std.testing.expectEqual(
            testCase(1, offsets),
            error.InvalidDataOffsets,
        );
    }
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/ed25519_instruction.rs#L389-L390
test "ed25519 signature offset" {
    {
        const offsets: Ed25519SignatureOffsets = .{
            .signature_offset = std.math.maxInt(u16),
        };
        try std.testing.expectEqual(
            testCase(1, offsets),
            error.InvalidDataOffsets,
        );
    }

    {
        const offsets: Ed25519SignatureOffsets = .{
            .signature_offset = 100 - ED25519_SIGNATURE_SERIALIZED_SIZE + 1,
        };
        try std.testing.expectEqual(
            testCase(1, offsets),
            error.InvalidDataOffsets,
        );
    }
}

// https://github.com/anza-xyz/agave/blob/2d834361c096198176dbdc4524d5003bccf6c192/precompiles/src/ed25519.rs#L446
test "ed25519_malleability" {
    const all_feature_set = try FeatureSet.allEnabled(std.testing.allocator);
    defer all_feature_set.deinit(std.testing.allocator);

    {
        const message = "hello";
        const keypair = Ed25519.KeyPair.generate();
        const signature = try keypair.sign(message, null);
        const instruction = try newInstruction(
            std.testing.allocator,
            &signature,
            &keypair.public_key,
            message,
        );
        defer std.testing.allocator.free(instruction.data);
        const tx: sig.core.Transaction = .{
            .msg = .{
                .account_keys = &.{ID},
                .instructions = &.{
                    .{ .program_index = 0, .account_indexes = &.{0}, .data = instruction.data },
                },
                .signature_count = 1,
                .readonly_signed_count = 1,
                .readonly_unsigned_count = 0,
                .recent_blockhash = sig.core.Hash.ZEROES,
            },
            .version = .legacy,
            .signatures = &.{},
        };

        try verifyPrecompiles(std.testing.allocator, &tx, &FeatureSet.EMPTY);
        try verifyPrecompiles(std.testing.allocator, &tx, &all_feature_set);
    }

    {
        const message = "ed25519vectors 3";
        const pubkey: Ed25519.PublicKey = try .fromBytes(
            .{
                0x10, 0xeb, 0x7c, 0x3a, 0xcf, 0xb2, 0xbe, 0xd3,
                0xe0, 0xd6, 0xab, 0x89, 0xbf, 0x5a, 0x3d, 0x6a,
                0xfd, 0xdd, 0x11, 0x76, 0xce, 0x48, 0x12, 0xe3,
                0x8d, 0x9f, 0xd4, 0x85, 0x05, 0x8f, 0xdb, 0x1f,
            },
        );
        const signature: Ed25519.Signature = .fromBytes(
            .{
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x94, 0x72, 0xa6, 0x9c, 0xd9, 0xa7, 0x01, 0xa5,
                0x0d, 0x13, 0x0e, 0xd5, 0x21, 0x89, 0xe2, 0x45,
                0x5b, 0x23, 0x76, 0x7d, 0xb5, 0x2c, 0xac, 0xb8,
                0x71, 0x6f, 0xb8, 0x96, 0xff, 0xee, 0xac, 0x09,
            },
        );
        const instruction = try newInstruction(std.testing.allocator, &signature, &pubkey, message);
        defer std.testing.allocator.free(instruction.data);
        const tx: sig.core.Transaction = .{
            .msg = .{
                .account_keys = &.{ID},
                .instructions = &.{
                    .{ .program_index = 0, .account_indexes = &.{0}, .data = instruction.data },
                },
                .signature_count = 1,
                .readonly_signed_count = 1,
                .readonly_unsigned_count = 0,
                .recent_blockhash = sig.core.Hash.ZEROES,
            },
            .version = .legacy,
            .signatures = &.{},
        };

        try verifyPrecompiles(std.testing.allocator, &tx, &FeatureSet.EMPTY);
        try std.testing.expectError(
            error.InvalidSignature,
            verifyPrecompiles(std.testing.allocator, &tx, &all_feature_set),
        );
    }
}
