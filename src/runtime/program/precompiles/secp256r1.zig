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

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const ID: Pubkey = .parse("Secp256r1SigVerify1111111111111111111111111");

const START = 2;
const SERIALIZED_SIZE = 14;

const N: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
const HALF_ORDER: u256 = (N - 1) / 2;

const SignatureOffsets = extern struct {
    /// Offset to compact secp256r1 signature of 64 bytes
    signature_offset: u16,
    /// Instruction index where the signature can be found
    signature_instruction_index: u16,
    /// Offset to compressed public key of 33 bytes
    public_key_offset: u16,
    /// Instruction index where the public key can be found
    public_key_instruction_index: u16,
    /// Offset to the start of message data
    message_data_offset: u16,
    /// Size of message data in bytes
    message_data_size: u16,
    /// Instruction index where the message data can be found
    message_instruction_index: u16,
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
    if (data.len < START) return error.InvalidInstructionDataSize;
    const num_signatures = data[0];
    if (num_signatures == 0 or num_signatures > 8) return error.InvalidInstructionDataSize;

    const expected_data_size = num_signatures * SERIALIZED_SIZE + START;
    if (data.len < expected_data_size) return error.InvalidInstructionDataSize;

    for (0..num_signatures) |i| {
        const start = i * SERIALIZED_SIZE + START;
        const offsets: *align(1) const SignatureOffsets = @ptrCast(data[start..].ptr);

        const signature_bytes = try getInstructionData(
            data,
            all_instruction_datas,
            offsets.signature_instruction_index,
            offsets.signature_offset,
            Ecdsa.Signature.encoded_length,
        );
        const signature: Ecdsa.Signature =
            .fromBytes(signature_bytes[0..Ecdsa.Signature.encoded_length].*);

        const pubkey_bytes = try getInstructionData(
            data,
            all_instruction_datas,
            offsets.public_key_instruction_index,
            offsets.public_key_offset,
            Ecdsa.PublicKey.compressed_sec1_encoded_length,
        );
        const pubkey = Ecdsa.PublicKey.fromSec1(pubkey_bytes) catch return error.InvalidSignature;

        const msg = try getInstructionData(
            data,
            all_instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size,
        );

        // check for low s in order to avoid malleable signatures
        const s: u256 = @bitCast(signature.s);
        if (@byteSwap(s) > HALF_ORDER) return error.InvalidSignature;

        signature.verify(msg, pubkey) catch return error.InvalidSignature;
    }
}

fn getInstructionData(
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
    const end = start +| size;
    if (end > instruction.len) return error.InvalidDataOffsets;
    return instruction[start..end];
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
