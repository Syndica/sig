const std = @import("std");
const builtin = @import("builtin");
const libsecp256k1 = @import("secp256k1");
const sig = @import("../../../sig.zig");

const precompile_programs = sig.runtime.program.precompile_programs;
const PrecompileProgramError = precompile_programs.PrecompileProgramError;

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, Keccak256);

pub const SECP256K1_DATA_START = SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE +
    SECP256K1_SIGNATURE_OFFSETS_START;
pub const SECP256K1_PUBKEY_SERIALIZED_SIZE = 20;
pub const SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE = 11;
pub const SECP256K1_SIGNATURE_OFFSETS_START = 1;
pub const SECP256K1_SIGNATURE_SERIALIZED_SIZE = 64;

comptime {
    std.debug.assert(SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE ==
        @bitSizeOf(Secp256k1SignatureOffsets) / 8);
}

pub const Secp256k1SignatureOffsets = packed struct {
    /// Offset to 64-byte signature plus 1-byte recovery ID.
    signature_offset: u16 = 0,
    /// Within the transaction, the index of the instruction whose instruction data contains the signature.
    signature_instruction_idx: u8 = 0,
    /// Offset to 20-byte Ethereum address.
    eth_address_offset: u16 = 0,
    /// Within the transaction, the index of the instruction whose instruction data contains the address.
    eth_address_instruction_idx: u8 = 0,
    /// Offset to start of message data.
    message_data_offset: u16 = 0,
    /// Size of message data in bytes.
    message_data_size: u16 = 0,
    /// Within the transaction, the index of the instruction whose instruction data contains the message.
    message_instruction_idx: u8 = 0,
};

// https://github.com/firedancer-io/firedancer/blob/af74882ffb2c24783a82718dbc5111a94e1b5f6f/src/flamenco/runtime/program/fd_precompiles.c#L227
// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L925
pub fn verify(
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
) PrecompileProgramError!void {
    const data = current_instruction_data;

    if (data.len < SECP256K1_DATA_START) {
        if (data.len == 1 and data[0] == 0) return; // success
        return error.InvalidInstructionDataSize;
    }

    const n_signatures = data[0];
    if (n_signatures == 0 and data.len > 1) return error.InvalidInstructionDataSize;

    const expected_data_size = SECP256K1_SIGNATURE_OFFSETS_START +
        n_signatures * SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    if (data.len < expected_data_size) return error.InvalidInstructionDataSize;

    for (0..n_signatures) |i| {
        const offset = SECP256K1_SIGNATURE_OFFSETS_START +
            i * SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
        const sig_offsets: *align(1) const Secp256k1SignatureOffsets = @alignCast(
            @ptrCast(data.ptr + offset),
        );

        // This case isn't useful, but agave has it.
        if (sig_offsets.signature_instruction_idx >= all_instruction_datas.len) {
            return error.InvalidInstructionDataSize;
        }

        const signature_slice = try getInstructionData(
            SECP256K1_SIGNATURE_SERIALIZED_SIZE + 1, // + recovery_id
            all_instruction_datas,
            sig_offsets.signature_instruction_idx,
            sig_offsets.signature_offset,
        );

        const recovery_id: u2 = blk: {
            const rec_id = signature_slice[SECP256K1_SIGNATURE_SERIALIZED_SIZE];
            if (rec_id > 3) return error.InvalidRecoveryId;
            break :blk @intCast(rec_id);
        };
        // https://docs.rs/libsecp256k1/0.6.0/src/libsecp256k1/lib.rs.html#674-680

        const signature: *const Ecdsa.Signature = @ptrCast(
            signature_slice[0..SECP256K1_SIGNATURE_SERIALIZED_SIZE],
        );

        const eth_address = try getInstructionData(
            SECP256K1_PUBKEY_SERIALIZED_SIZE,
            all_instruction_datas,
            sig_offsets.eth_address_instruction_idx,
            sig_offsets.eth_address_offset,
        );

        const msg = try getInstructionData(
            sig_offsets.message_data_size,
            all_instruction_datas,
            sig_offsets.message_instruction_idx,
            sig_offsets.message_data_offset,
        );

        var msg_hash: [Keccak256.digest_length]u8 = undefined;
        Keccak256.hash(msg, &msg_hash, .{});

        comptime {
            std.debug.assert(Keccak256.digest_length == 32);
        }

        const pubkey = try recoverSecp256k1Pubkey(&msg_hash, signature, recovery_id);
        const recovered_eth_address = constructEthPubkey(&pubkey);

        if (!std.mem.eql(u8, eth_address, &recovered_eth_address)) {
            return error.InvalidSignature;
        }
    }
}

fn getInstructionData(
    len: usize,
    all_instruction_datas: []const []const u8,
    instruction_idx: u8,
    offset: u16,
) error{ InvalidDataOffsets, InvalidSignature }![]const u8 {
    if (instruction_idx >= all_instruction_datas.len) return error.InvalidDataOffsets;
    const instruction = all_instruction_datas[instruction_idx];
    if (offset +| len > instruction.len) return error.InvalidSignature;
    return instruction[offset..][0..len];
}

// https://docs.rs/libsecp256k1/0.6.0/src/libsecp256k1/lib.rs.html#764-770
// https://github.com/firedancer-io/firedancer/blob/341bba05a3a7ca18d3d550d6b58c1b6a9207184f/src/ballet/secp256k1/fd_secp256k1.c#L7
fn recoverSecp256k1Pubkey(
    message_hash: *const [Keccak256.digest_length]u8,
    signature: *const Ecdsa.Signature,
    recovery_id: u2,
) error{InvalidSignature}!Ecdsa.PublicKey {
    const sig_bytes = signature.toBytes();

    var recoverable_sig: libsecp256k1.secp256k1_ecdsa_recoverable_signature = undefined;
    if (libsecp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact(
        libsecp256k1.secp256k1_context_static,
        &recoverable_sig,
        &sig_bytes,
        recovery_id,
    ) == 0) return error.InvalidSignature;

    var internal_pubkey: libsecp256k1.secp256k1_pubkey = undefined;
    if (libsecp256k1.secp256k1_ecdsa_recover(
        libsecp256k1.secp256k1_context_static,
        &internal_pubkey,
        &recoverable_sig,
        message_hash,
    ) == 0) return error.InvalidSignature;

    var serialized_pubkey: [65]u8 = undefined;
    var pubkey_len = serialized_pubkey.len;
    if (libsecp256k1.secp256k1_ec_pubkey_serialize(
        libsecp256k1.secp256k1_context_static,
        &serialized_pubkey,
        &pubkey_len,
        &internal_pubkey,
        libsecp256k1.SECP256K1_EC_UNCOMPRESSED,
    ) == 0) return error.InvalidSignature;

    // note: firedancer chops off the first byte, which happens to be the recovery id, however
    // fromSec1 expects it to be there.
    return Ecdsa.PublicKey.fromSec1(&serialized_pubkey) catch return error.InvalidSignature;
}

/// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L903
/// https://ethereum.org/en/developers/docs/accounts/#keyfiles
/// > The public key is generated from the private key using
///   the Elliptic Curve Digital Signature Algorithm(opens in a
///   new tab). You get a public address for your account by
///   taking the last 20 bytes of the Keccak-256 hash of the
///   public key
fn constructEthPubkey(
    pubkey: *const Ecdsa.PublicKey,
) [SECP256K1_PUBKEY_SERIALIZED_SIZE]u8 {
    var pubkey_hash: [Keccak256.digest_length]u8 = undefined;
    const serialised_pubkey = pubkey.toUncompressedSec1();
    Keccak256.hash(serialised_pubkey[1..], &pubkey_hash, .{});
    return pubkey_hash[12..32].*;
}

fn signRecoverable(
    private_key: *const Ecdsa.SecretKey,
    message_hash: *const [Keccak256.digest_length]u8,
) !.{ u2, Ecdsa.Signature } {
    if (!builtin.is_test) @compileError("signRecoverable is only for use in tests");

    // note: this uses malloc
    const context = libsecp256k1.secp256k1_context_create(
        libsecp256k1.SECP256K1_CONTEXT_NONE,
    ) orelse return error.InvalidSignature;
    defer libsecp256k1.secp256k1_context_destroy(context);

    var recoverable_signature: libsecp256k1.secp256k1_ecdsa_recoverable_signature = undefined;
    if (libsecp256k1.secp256k1_ecdsa_sign_recoverable(
        context,
        &recoverable_signature,
        &message_hash,
        &private_key,
        null,
        null,
    ) == 0) return error.InvalidSignature;

    var signature: [64]u8 = undefined;
    var _recovery_id: c_int = undefined;

    if (libsecp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        context,
        &signature,
        &_recovery_id,
        &recoverable_signature,
    ) == 0) return error.InvalidSignature;

    std.debug.assert(_recovery_id <= 3);
    const recovery_id: u2 = @intCast(_recovery_id);

    return .{ recovery_id, Ecdsa.Signature.fromBytes(signature) };
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L842
fn newSecp256k1Instruction(
    allocator: std.mem.Allocator,
    keypair: *const Ecdsa.KeyPair,
    message: []const u8,
) !sig.core.Instruction {
    if (!builtin.is_test) @compileError("newSecp256k1Instruction is only for use in tests");
    std.debug.assert(message.len < std.math.maxInt(u16));

    const eth_pubkey = constructEthPubkey(&keypair.public_key);

    var message_hash: [Keccak256.digest_length]u8 = undefined;
    Keccak256.hash(message, &message_hash, .{});

    // note: this uses malloc
    const context = libsecp256k1.secp256k1_context_create(
        libsecp256k1.SECP256K1_CONTEXT_NONE,
    ) orelse return error.InvalidSignature;
    defer libsecp256k1.secp256k1_context_destroy(context);

    var recoverable_signature: libsecp256k1.secp256k1_ecdsa_recoverable_signature = undefined;
    const seckey = keypair.secret_key.toBytes();

    if (libsecp256k1.secp256k1_ecdsa_sign_recoverable(
        context,
        &recoverable_signature,
        &message_hash,
        &seckey,
        null,
        null,
    ) == 0) return error.InvalidSignature;

    var signature: [64]u8 = undefined;
    var _recovery_id: c_int = undefined;

    if (libsecp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        context,
        &signature,
        &_recovery_id,
        &recoverable_signature,
    ) == 0) return error.InvalidSignature;

    std.debug.assert(_recovery_id <= 3);
    const recovery_id: u2 = @intCast(_recovery_id);

    const instruction_data_len = SECP256K1_DATA_START +| eth_pubkey.len +| 64 +| message.len +| 1;

    const instruction_data = try allocator.alloc(u8, instruction_data_len);
    errdefer allocator.free(instruction_data);
    @memset(instruction_data, 0);

    const eth_address_offset = SECP256K1_DATA_START;
    @memcpy(instruction_data[eth_address_offset..][0..eth_pubkey.len], &eth_pubkey);

    const signature_offset = eth_address_offset +| eth_pubkey.len;
    @memcpy(instruction_data[signature_offset..][0..64], &signature);

    instruction_data[signature_offset +| 64] = recovery_id;

    const message_data_offset = signature_offset +| 64 +| 1;
    @memcpy(instruction_data[message_data_offset..], message);

    const num_signatures = 1;
    instruction_data[0] = num_signatures;

    const offsets: Secp256k1SignatureOffsets = .{
        .signature_offset = signature_offset,
        .signature_instruction_idx = 0,
        .eth_address_offset = eth_address_offset,
        .eth_address_instruction_idx = 0,
        .message_data_offset = message_data_offset,
        .message_data_size = @intCast(message.len),
        .message_instruction_idx = 0,
    };

    @memcpy(
        instruction_data[1..SECP256K1_DATA_START],
        std.mem.asBytes(&offsets)[0 .. @bitSizeOf(Secp256k1SignatureOffsets) / 8],
    );

    return .{
        .program_id = sig.runtime.ids.PRECOMPILE_SECP256K1_PROGRAM_ID,
        .accounts = &.{},
        .data = instruction_data,
    };
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L1046
fn testCase(
    num_signatures: u8,
    offsets: Secp256k1SignatureOffsets,
) PrecompileProgramError!void {
    if (!builtin.is_test) @compileError("testCase is only for use in tests");

    var instruction_data: [SECP256K1_DATA_START]u8 align(2) = undefined;
    instruction_data[0] = num_signatures;
    @memcpy(
        instruction_data[1..],
        std.mem.asBytes(&offsets)[0 .. @bitSizeOf(Secp256k1SignatureOffsets) / 8],
    );

    return try verify(&instruction_data, &.{&(.{0} ** 100)});
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L1059
test "secp256k1 invalid offsets" {
    {
        var instruction_data: [SECP256K1_DATA_START]u8 align(2) = undefined;
        instruction_data[0] = 1; // n_signatures
        @memcpy(
            instruction_data[1..],
            std.mem.asBytes(
                &Secp256k1SignatureOffsets{},
            )[0 .. @bitSizeOf(Secp256k1SignatureOffsets) / 8],
        );

        try std.testing.expectError(
            error.InvalidInstructionDataSize,
            verify(instruction_data[0 .. instruction_data.len - 1], &.{&(.{0} ** 100)}),
        );
    }

    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        testCase(1, .{ .signature_instruction_idx = 1 }),
    );
    try std.testing.expectError(
        error.InvalidDataOffsets,
        testCase(1, .{ .message_instruction_idx = 1 }),
    );
    try std.testing.expectError(
        error.InvalidDataOffsets,
        testCase(1, .{ .eth_address_instruction_idx = 1 }),
    );
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L1104
test "secp256k1 message data offsets" {
    try std.testing.expectError(
        error.InvalidSignature,
        testCase(1, .{
            .message_data_offset = 99,
            .message_data_size = 1,
        }),
    );

    try std.testing.expectError(
        error.InvalidSignature,
        testCase(1, .{
            .message_data_offset = 100,
            .message_data_size = 1,
        }),
    );

    try std.testing.expectError(
        error.InvalidSignature,
        testCase(1, .{
            .message_data_offset = 100,
            .message_data_size = 1000,
        }),
    );

    try std.testing.expectError(
        error.InvalidSignature,
        testCase(1, .{
            .message_data_offset = std.math.maxInt(u16),
            .message_data_size = std.math.maxInt(u16),
        }),
    );
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L1104
test "secp256k1 eth offset" {
    try std.testing.expectError(
        error.InvalidSignature,
        testCase(1, .{
            .eth_address_offset = std.math.maxInt(u16),
        }),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        testCase(1, .{
            .eth_address_offset = 100 - SECP256K1_PUBKEY_SERIALIZED_SIZE + 1,
        }),
    );
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L1168
test "secp256k1 signature offset" {
    try std.testing.expectError(
        error.InvalidSignature,
        testCase(1, .{
            .signature_offset = std.math.maxInt(u16),
        }),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        testCase(1, .{
            .signature_offset = 100 - SECP256K1_PUBKEY_SERIALIZED_SIZE + 1,
        }),
    );
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L1189
test "secp256k1 count is zero but sig data exists" {
    var instruction_data: [SECP256K1_DATA_START]u8 align(2) = undefined;
    instruction_data[0] = 0; // n_signatures
    @memcpy(
        instruction_data[1..],
        std.mem.asBytes(
            &Secp256k1SignatureOffsets{},
        )[0 .. @bitSizeOf(Secp256k1SignatureOffsets) / 8],
    );

    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(instruction_data[0 .. instruction_data.len - 1], &.{&(.{0} ** 100)}),
    );
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L1206
test "secp256k1" {
    const allocator = std.testing.allocator;

    const keypair = try Ecdsa.KeyPair.create(null);

    const instruction = try newSecp256k1Instruction(allocator, &keypair, "hello");
    defer allocator.free(instruction.data);

    try verify(instruction.data, &.{instruction.data});

    {
        // instruction.data is const, working around that
        const instruction_data = try allocator.dupe(u8, instruction.data);
        defer allocator.free(instruction_data);

        // https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L1229
        // agave uses unseeded random in this test for some reason, let's not do that.
        for (instruction_data) |*byte| {
            const old = byte.*;
            byte.* +%= 12;
            if (verify(instruction_data, &.{instruction_data})) |_| {
                try std.testing.expect(false); // should error
            } else |err| {
                _ = err catch {};
            }
            byte.* = old;
        }
    }
}

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L1244
test "secp256 malleability" {
    const allocator = std.testing.allocator;

    const keypair = try Ecdsa.KeyPair.create(null);
    const eth_address = constructEthPubkey(&keypair.public_key);
    const message = "hello";

    var message_hash: [Keccak256.digest_length]u8 = undefined;
    Keccak256.hash(message, &message_hash, .{});
}
