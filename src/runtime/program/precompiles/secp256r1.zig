const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../../sig.zig");

const precompile_programs = sig.runtime.program.precompiles;

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const FeatureSet = sig.core.FeatureSet;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;
const PrecompileProgramError = precompile_programs.PrecompileProgramError;
const TransactionError = sig.ledger.transaction_status.TransactionError;
const verifyPrecompiles = precompile_programs.verifyPrecompiles;
const getInstructionData = precompile_programs.getInstructionData;

const P256 = std.crypto.ecc.P256;
const Scalar = P256.scalar.Scalar;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const ID: Pubkey = .parse("Secp256r1SigVerify1111111111111111111111111");

const OFFSETS_START = 2;
const SERIALIZED_SIZE = 14;
const DATA_START = OFFSETS_START + SERIALIZED_SIZE;

const ORDER: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
const HALF_ORDER: u256 = (ORDER - 1) / 2;

const SignatureOffsets = extern struct {
    /// Offset to compact secp256r1 signature of 64 bytes
    signature_offset: u16 = 0,
    /// Instruction index where the signature can be found
    signature_instruction_index: u16 = 0,
    /// Offset to compressed public key of 33 bytes
    public_key_offset: u16 = 0,
    /// Instruction index where the public key can be found
    public_key_instruction_index: u16 = 0,
    /// Offset to the start of message data
    message_data_offset: u16 = 0,
    /// Size of message data in bytes
    message_data_size: u16 = 0,
    /// Instruction index where the message data can be found
    message_instruction_index: u16 = 0,
};

pub fn execute(_: std.mem.Allocator, ic: *InstructionContext) InstructionError!void {
    const instruction_data = ic.ixn_info.instruction_data;
    const instruction_datas = ic.tc.instruction_datas.?;

    verify(instruction_data, instruction_datas, ic.tc.feature_set, ic.tc.slot) catch {
        return error.Custom;
    };
}

// https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0075-precompile-for-secp256r1-sigverify.md
// https://github.com/firedancer-io/firedancer/blob/49056135a4c7ba024cb75a45925439239904238b/src/flamenco/runtime/program/fd_precompiles.c#L376
pub fn verify(
    data: []const u8,
    all_instruction_datas: []const []const u8,
    _: *const FeatureSet,
    _: Slot,
) PrecompileProgramError!void {
    if (data.len < OFFSETS_START) return error.InvalidInstructionDataSize;
    const num_signatures = data[0];

    if (num_signatures == 0 or num_signatures > 8) return error.InvalidInstructionDataSize;

    const expected_data_size = num_signatures * SERIALIZED_SIZE + OFFSETS_START;
    if (data.len < expected_data_size) return error.InvalidInstructionDataSize;

    for (0..num_signatures) |i| {
        const start = i * SERIALIZED_SIZE + OFFSETS_START;
        const offsets: *align(1) const SignatureOffsets = @ptrCast(data[start..].ptr);

        const signature_bytes = try getInstructionData(
            data,
            all_instruction_datas,
            offsets.signature_instruction_index,
            offsets.signature_offset,
            Ecdsa.Signature.encoded_length,
        );

        const pubkey_bytes = try getInstructionData(
            data,
            all_instruction_datas,
            offsets.public_key_instruction_index,
            offsets.public_key_offset,
            Ecdsa.PublicKey.compressed_sec1_encoded_length,
        );

        const msg = try getInstructionData(
            data,
            all_instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size,
        );

        const pubkey = Ecdsa.PublicKey.fromSec1(pubkey_bytes) catch return error.InvalidSignature;

        const signature: Ecdsa.Signature =
            .fromBytes(signature_bytes[0..Ecdsa.Signature.encoded_length].*);

        // check for low s in order to avoid malleable signatures
        const s: u256 = @bitCast(signature.s);
        if (@byteSwap(s) > HALF_ORDER) return error.InvalidSignature;

        signature.verify(msg, pubkey) catch return error.InvalidSignature;
    }
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/ed25519_instruction.rs#L258
fn testCase(
    num_signatures: u16,
    offsets: SignatureOffsets,
) PrecompileProgramError!void {
    if (!builtin.is_test) @compileError("testCase is only for use in tests");

    var instruction_data: [DATA_START]u8 align(2) = undefined;
    @memcpy(instruction_data[0..2], std.mem.asBytes(&num_signatures));
    @memcpy(instruction_data[2..], std.mem.asBytes(&offsets));

    try verify(&instruction_data, &.{&(.{0} ** 100)}, &.ALL_ENABLED_AT_GENESIS, 0);
}

pub fn newInstruction(
    allocator: std.mem.Allocator,
    signature: *const Ecdsa.Signature,
    public_key: *const Ecdsa.PublicKey,
    message: []const u8,
) !sig.core.Instruction {
    if (!builtin.is_test) @compileError("newInstruction is only for use in tests");
    std.debug.assert(message.len <= std.math.maxInt(u16));

    const num_signatures: u8 = 1;
    const public_key_offset = DATA_START;
    const signature_offset = public_key_offset + Ecdsa.PublicKey.compressed_sec1_encoded_length;
    const message_data_offset = signature_offset + Ecdsa.Signature.encoded_length;

    const offsets: SignatureOffsets = .{
        .signature_offset = signature_offset,
        .signature_instruction_index = std.math.maxInt(u16),
        .public_key_offset = public_key_offset,
        .public_key_instruction_index = std.math.maxInt(u16),
        .message_data_offset = message_data_offset,
        .message_data_size = @intCast(message.len),
        .message_instruction_index = std.math.maxInt(u16),
    };

    // if signature.s is larger than HALF_ORDER, replace it with ORDER - signature.s
    var s = try Scalar.fromBytes(signature.s, .big);
    if (@byteSwap(@as(u256, @bitCast(signature.s))) > HALF_ORDER) s = s.neg();
    const sanitized_signature: Ecdsa.Signature = .{
        .r = signature.r,
        .s = s.toBytes(.big),
    };

    var instruction_data = try std.ArrayList(u8).initCapacity(
        allocator,
        message_data_offset + message.len,
    );
    errdefer instruction_data.deinit();

    // add 2nd byte for padding, so that offset structure is aligned
    instruction_data.appendSliceAssumeCapacity(&.{ num_signatures, 0 });
    instruction_data.appendSliceAssumeCapacity(std.mem.asBytes(&offsets));
    std.debug.assert(instruction_data.items.len == public_key_offset);
    instruction_data.appendSliceAssumeCapacity(&public_key.toCompressedSec1());
    std.debug.assert(instruction_data.items.len == signature_offset);
    instruction_data.appendSliceAssumeCapacity(&sanitized_signature.toBytes());
    std.debug.assert(instruction_data.items.len == message_data_offset);
    instruction_data.appendSliceAssumeCapacity(message);

    return .{
        .program_id = ID,
        .accounts = &.{},
        .data = try instruction_data.toOwnedSlice(),
        .owned_data = true,
    };
}

test "invalid offsets" {
    const allocator = std.testing.allocator;
    var instruction_data = try std.ArrayList(u8).initCapacity(
        allocator,
        DATA_START,
    );
    defer instruction_data.deinit();

    const offsets: SignatureOffsets = .{};

    // Set up instruction data with invalid size
    instruction_data.appendSliceAssumeCapacity(std.mem.asBytes(&1));
    instruction_data.appendSliceAssumeCapacity(std.mem.asBytes(&offsets));
    try instruction_data.resize(instruction_data.items.len - 1);

    try std.testing.expectEqual(
        error.InvalidInstructionDataSize,
        verify(instruction_data.items, &.{}, &.ALL_ENABLED_AT_GENESIS, 0),
    );

    // invalid signature instruction index
    const invalid_signature_offsets: SignatureOffsets = .{
        .signature_instruction_index = 1,
    };
    try std.testing.expectEqual(
        error.InvalidDataOffsets,
        testCase(1, invalid_signature_offsets),
    );

    // invalid message instruction index
    const invalid_message_offsets: SignatureOffsets = .{
        .message_instruction_index = 1,
    };
    try std.testing.expectEqual(
        error.InvalidDataOffsets,
        testCase(1, invalid_message_offsets),
    );

    // invalid pubkey instruction index
    const invalid_pubkey_offsets: SignatureOffsets = .{
        .public_key_instruction_index = 1,
    };
    try std.testing.expectEqual(
        error.InvalidDataOffsets,
        testCase(1, invalid_pubkey_offsets),
    );
}

test "invalid signature data size" {
    // Test data.len() < SIGNATURE_OFFSETS_START
    const small_data: [OFFSETS_START - 1]u8 = @splat(0);
    try std.testing.expectEqual(
        error.InvalidInstructionDataSize,
        verify(&small_data, &.{&.{}}, &.ALL_ENABLED_AT_GENESIS, 0),
    );

    // Test num_signatures == 0
    var zero_sigs_data: [DATA_START]u8 = @splat(0);
    zero_sigs_data[0] = 0; // Set num_signatures to 0
    try std.testing.expectEqual(
        error.InvalidInstructionDataSize,
        verify(&zero_sigs_data, &.{&.{}}, &.ALL_ENABLED_AT_GENESIS, 0),
    );

    // Test num_signatures > 8
    var too_many_sigs: [DATA_START]u8 = @splat(0);
    too_many_sigs[0] = 9; // Set num_signatures to 9
    try std.testing.expectEqual(
        error.InvalidInstructionDataSize,
        verify(&too_many_sigs, &.{&.{}}, &.ALL_ENABLED_AT_GENESIS, 0),
    );
}

test "message data offsets" {
    {
        const offsets: SignatureOffsets = .{
            .message_data_offset = 99,
            .message_data_size = 1,
        };
        try std.testing.expectError(
            error.InvalidSignature,
            testCase(1, offsets),
        );
    }

    {
        const offsets: SignatureOffsets = .{
            .message_data_offset = 100,
            .message_data_size = 1,
        };
        try std.testing.expectError(
            error.InvalidDataOffsets,
            testCase(1, offsets),
        );
    }

    {
        const offsets: SignatureOffsets = .{
            .message_data_offset = 100,
            .message_data_size = 1000,
        };
        try std.testing.expectError(
            error.InvalidDataOffsets,
            testCase(1, offsets),
        );
    }

    {
        const offsets: SignatureOffsets = .{
            .message_data_offset = std.math.maxInt(u16),
            .message_data_size = std.math.maxInt(u16),
        };
        try std.testing.expectError(
            error.InvalidDataOffsets,
            testCase(1, offsets),
        );
    }
}

test "pubkey offset" {
    {
        const offsets: SignatureOffsets = .{
            .public_key_offset = std.math.maxInt(u16),
        };
        try std.testing.expectEqual(
            error.InvalidDataOffsets,
            testCase(1, offsets),
        );
    }

    {
        const offsets: SignatureOffsets = .{
            .public_key_offset = 100 - Ecdsa.PublicKey.compressed_sec1_encoded_length + 1,
        };
        try std.testing.expectEqual(
            error.InvalidDataOffsets,
            testCase(1, offsets),
        );
    }
}

test "ed25519 signature offset" {
    {
        const offsets: SignatureOffsets = .{
            .signature_offset = std.math.maxInt(u16),
        };
        try std.testing.expectEqual(
            testCase(1, offsets),
            error.InvalidDataOffsets,
        );
    }

    {
        const offsets: SignatureOffsets = .{
            .signature_offset = 100 - Ecdsa.Signature.encoded_length + 1,
        };
        try std.testing.expectEqual(
            testCase(1, offsets),
            error.InvalidDataOffsets,
        );
    }
}

test "sanity check" {
    const allocator = std.testing.allocator;

    const message = "hello";
    const keypair = Ecdsa.KeyPair.generate();
    const signature = try keypair.sign(message, null);
    const instruction = try newInstruction(
        allocator,
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

    _ = try verifyPrecompiles(std.testing.allocator, &tx, &FeatureSet.ALL_ENABLED_AT_GENESIS, 0);
}

test "high s" {
    const allocator = std.testing.allocator;

    const message = "hello";
    const keypair = Ecdsa.KeyPair.generate();
    const signature = try keypair.sign(message, null);
    var instruction = try newInstruction(
        allocator,
        &signature,
        &keypair.public_key,
        message,
    );
    // replace the instruction data with our own, so we can mutate it
    const data = try allocator.dupe(u8, instruction.data);
    allocator.free(instruction.data);
    instruction.data = data;
    defer allocator.free(instruction.data);

    const public_key_offset = DATA_START;
    const signature_offset = public_key_offset + Ecdsa.PublicKey.compressed_sec1_encoded_length;
    const s_offset = signature_offset + P256.Fe.encoded_length;

    // manipulate the signature to create a negative signature.s
    // since the curve is symmetric in an unsecure implementation this could pass the verification
    var s = try Scalar.fromBytes(data[s_offset..][0..32].*, .big);
    s = s.neg();
    @memcpy(data[s_offset..][0..32], &s.toBytes(.big));

    const bad_tx: sig.core.Transaction = .{
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

    const actual = try verifyPrecompiles(allocator, &bad_tx, &FeatureSet.ALL_ENABLED_AT_GENESIS, 0);
    try std.testing.expectEqual(
        TransactionError{ .InstructionError = .{ 0, .{ .Custom = 0 } } },
        actual,
    );
}

// sig fmt: off
test "verify" {
    {
        const msg = decode("deadbeef0000", 6);
        const signature_bytes = decode("65f479af7700ea826cdf4a2d30bbbfd5be5a8abb4dd6e8ef0bb0d5018b5f08160856e32671be561383d7eb408c6d24c28fd05141fd247dd8e67fc511d4f2ace9", 64);
        const pubkey_bytes = decode("030f5183ccd84510385acc742f2d9d83771190c83cd0a36c42b0877c1666598a31", 33);

        const signature: Ecdsa.Signature = .fromBytes(signature_bytes);
        const pubkey: Ecdsa.PublicKey = try .fromSec1(&pubkey_bytes);

        try signature.verify(&msg, pubkey);
    }
    {
        const msg = decode("deadbeef0001", 6);
        const signature_bytes = decode("dde6de58059a2edc745f3757a45b527c6a838e2f9944e7985cdbce18a9831444662257cde953020a5ba3dbd77dabc0e7ecf35dadf35754dd5c014e3197173ca7", 64);
        const pubkey_bytes = decode("032a18f703b754f728b4faa2cd9e81d82647b86fb4e22bce7348ddf2a977a4e9d9", 33);

        const signature: Ecdsa.Signature = .fromBytes(signature_bytes);
        const pubkey: Ecdsa.PublicKey = try .fromSec1(&pubkey_bytes);

        try signature.verify(&msg, pubkey);
    }
    {
        const msg = decode("deadbeef0002", 6);
        const signature_bytes = decode("d852239f6cdd19f530636fed1736f6c1fff499e988ffc14faf9098b6c359f53f24d8918494d158e562643da21939e3d8f4f733b2e135c63f205281c3cbae7cc1", 64);
        const pubkey_bytes = decode("025241d2133264e7d4b0f91c0d2b08d7b8e4c015cc84d68eafe8c5dfe4b8bf6753", 33);

        const signature: Ecdsa.Signature = .fromBytes(signature_bytes);
        const pubkey: Ecdsa.PublicKey = try .fromSec1(&pubkey_bytes);

        try signature.verify(&msg, pubkey);
    }
    // test malleability
    {
        const msg = "hello";
        const signature_bytes = decode("a940d67c9560a47c5dafb45ab1f39eb68c8fac9b51fc8c4e30b1f0e63e4967d3a79a96599c9b3c50c1102bde558038aec5ece23b96547e189e599b2c1b767b04", 64);
        const pubkey_bytes = decode("025241d2133264e7d4b0f91c0d2b08d7b8e4c015cc84d68eafe8c5dfe4b8bf6753", 33);

        const signature: Ecdsa.Signature = .fromBytes(signature_bytes);
        const pubkey: Ecdsa.PublicKey = try .fromSec1(&pubkey_bytes);

        try std.testing.expectError(error.SignatureVerificationFailed, signature.verify(msg, pubkey));
    }
    // same test as above, but correctly grouped signature
    {
        const msg = "hello";
        const signature_bytes = decode("a940d67c9560a47c5dafb45ab1f39eb68c8fac9b51fc8c4e30b1f0e63e4967d3586569a56364c3b03eefd421aa7fc750f6fa187210c3206c55602f96e0ecaa4d", 64);
        const pubkey_bytes = decode("02d8c82b3791c8b51cfe44aa50226217159596ca26e6075aaf8bf8be2d351b96ae", 33);

        const signature: Ecdsa.Signature = .fromBytes(signature_bytes);
        const pubkey: Ecdsa.PublicKey = try .fromSec1(&pubkey_bytes);

        try signature.verify(msg, pubkey);
    }
}
// sig fmt: on

fn decode(comptime string: []const u8, comptime num: usize) [num]u8 {
    if (!builtin.is_test) @compileError("should only be used in tests");
    var buffer: [num]u8 = undefined;
    const result = std.fmt.hexToBytes(&buffer, string) catch unreachable;
    std.debug.assert(result.len == num);
    return buffer;
}
