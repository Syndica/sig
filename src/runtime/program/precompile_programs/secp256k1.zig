const std = @import("std");
const libsecp256k1 = @import("secp256k1");
const sig = @import("../../../sig.zig");

const precompile_programs = sig.runtime.program.precompile_programs;
const PrecompileProgramError = precompile_programs.PrecompileProgramError;
const getInstructionData = precompile_programs.getInstructionData;

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, Keccak256);
const Scalar = Secp256k1.scalar.Scalar;
const Message = Scalar;
const Field = Secp256k1.Fe;

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

        const signature_slice = try getInstructionData(
            SECP256K1_SIGNATURE_SERIALIZED_SIZE + 1, // + recovery_id
            data,
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
            data,
            all_instruction_datas,
            sig_offsets.eth_address_instruction_idx,
            sig_offsets.eth_address_offset,
        );

        const msg = try getInstructionData(
            sig_offsets.message_data_size,
            data,
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
        const recovered_eth_address = constructEthPubkey(pubkey);

        if (!std.mem.eql(u8, eth_address, &recovered_eth_address)) {
            return error.InvalidSignature;
        }
    }
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

    return Ecdsa.PublicKey.fromSec1(serialized_pubkey[1..]) catch return error.InvalidSignature;
}

/// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L903
/// https://ethereum.org/en/developers/docs/accounts/#keyfiles
/// > The public key is generated from the private key using
///   the Elliptic Curve Digital Signature Algorithm(opens in a
///   new tab). You get a public address for your account by
///   taking the last 20 bytes of the Keccak-256 hash of the
///   public key
fn constructEthPubkey(
    pubkey: Ecdsa.PublicKey,
) [SECP256K1_PUBKEY_SERIALIZED_SIZE]u8 {
    var pubkey_hash: [Keccak256.digest_length]u8 = undefined;
    const serialised_pubkey = pubkey.toUncompressedSec1();
    Keccak256.hash(serialised_pubkey[1..], &pubkey_hash, .{});
    return pubkey_hash[12..32].*;
}

test "secp256k1 invalid offsets" {
    var instruction_data = std.mem.zeroes([SECP256K1_DATA_START]u8);
    instruction_data[0] = 1; // n_signatures
    try std.testing.expectError(
        error.InvalidDataOffsets,
        verify(&instruction_data, &.{&instruction_data}),
    );
}
