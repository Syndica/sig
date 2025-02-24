const std = @import("std");
const sig = @import("../../../sig.zig");
const precompile_programs = sig.runtime.program.precompile_programs;

const PrecompileProgramError = precompile_programs.PrecompileProgramError;
const getInstructionValue = precompile_programs.getInstructionValue;
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
    std.debug.assert(SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE == @bitSizeOf(Secp256k1SignatureOffsets) / 8);
}

pub const Secp256k1SignatureOffsets = packed struct {
    /// Offset to 64-byte signature plus 1-byte recovery ID.
    signature_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the signature.
    signature_instruction_idx: u8,
    /// Offset to 20-byte Ethereum address.
    eth_address_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the address.
    eth_address_instruction_idx: u8,
    /// Offset to start of message data.
    message_data_offset: u16,
    /// Size of message data in bytes.
    message_data_size: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the message.
    message_instruction_idx: u8,
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

    // firedancer seems to assume natural alignment in this loop? Need to prove it to myself.
    for (0..n_signatures) |i| {
        const offset = SECP256K1_SIGNATURE_OFFSETS_START +
            i * SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
        const sig_offsets: *const Secp256k1SignatureOffsets = @alignCast(@ptrCast(data.ptr + offset));

        const signature_slice = try getInstructionData(
            SECP256K1_SIGNATURE_SERIALIZED_SIZE + 1, // + recovery_id
            data,
            all_instruction_datas,
            sig_offsets.signature_instruction_idx,
            sig_offsets.signature_offset,
        );

        const recovery_id = signature_slice[SECP256K1_SIGNATURE_SERIALIZED_SIZE];
        // https://docs.rs/libsecp256k1/0.6.0/src/libsecp256k1/lib.rs.html#674-680
        if (recovery_id > 4) return error.InvalidRecoveryId;
        const signature: *const Ecdsa.Signature = @ptrCast(signature_slice[0..SECP256K1_SIGNATURE_SERIALIZED_SIZE]);

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

        const msg_scalar = Secp256k1.scalar.Scalar.fromBytes(msg_hash, .little) catch @panic("handle this");

        const pubkey = try recoverPubkey(&msg_scalar, signature, recovery_id);
        const recovered_eth_address = constructEthPubkey(pubkey);

        if (!std.mem.eql(u8, eth_address, &recovered_eth_address)) {
            return error.InvalidSignature;
        }
    }
}
// https://docs.rs/libsecp256k1/0.6.0/src/libsecp256k1/lib.rs.html#764-770
fn recoverPubkey(
    message: *const Message,
    signature: *const Ecdsa.Signature,
    recovery_id: u8,
) error{InvalidSignature}!Ecdsa.PublicKey {
    std.debug.assert(recovery_id < 4);
    _ = message;

    if (std.mem.allEqual(u8, &signature.r, 0)) return error.InvalidSignature;
    if (std.mem.allEqual(u8, &signature.s, 0)) return error.InvalidSignature;

    // I think zig std doesn't quite support the necessary operations
    @panic("TODO");
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
    const full_pubkey_bytes = pubkey.toUncompressedSec1();
    Keccak256.hash(full_pubkey_bytes[1..], &pubkey_hash, .{});
    return pubkey_hash[12..32].*;
}
