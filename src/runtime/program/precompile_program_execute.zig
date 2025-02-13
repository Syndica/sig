const std = @import("std");
const sig = @import("../../sig.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;

const nonce = sig.runtime.nonce;
const pubkey_utils = sig.runtime.pubkey_utils;
const precompile_program = sig.runtime.program.precompile_program;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

const PrecompileProgramInstruction = precompile_program.PrecompileProgramInstruction;
const PrecompileProgramError = precompile_program.PrecompileProgramError;

const ED25519_SIGNATURE_SERIALIZED_SIZE = 64;
const ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE = 14;
const ED25519_SIGNATURE_OFFSETS_START = 2;
const ED25519_DATA_START = (ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE + ED25519_SIGNATURE_OFFSETS_START);
const ED25519_PUBKEY_SERIALIZED_SIZE = 32;

const SECP256K1_PUBKEY_SERIALIZED_SIZE = 20;
const SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE = 11;
const SECP256K1_SIGNATURE_OFFSETS_START = 1;
const SECP256K1_DATA_START = (SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE + SECP256K1_SIGNATURE_OFFSETS_START);

const Ed25519SignatureOffsets = packed struct {
    /// Offset to ed25519 signature of 64 bytes.
    signature_offset: u16,
    /// Instruction index to find signature.
    signature_instruction_idx: u16,
    /// Offset to public key of 32 bytes.
    pubkey_offset: u16,
    /// Instruction index to find public key.
    pubkey_instruction_idx: u16,
    /// Offset to start of message data.
    message_data_offset: u16,
    /// Size of message data.
    message_data_size: u16,
    /// Index of instruction data to get message data.
    message_instruction_idx: u16,
};

comptime {
    if (@sizeOf(Ed25519SignatureOffsets) != ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE) {
        @compileError("bad size");
    }
}

const Secp256k1SignatureOffsets = packed struct {
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
comptime {
    if (@sizeOf(Secp256k1SignatureOffsets) != SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE) {
        @compileError("bad size");
    }
}

pub fn precompileProgramExecute(ic: *const InstructionContext, mode: enum { ed25519_verify, secp256k1_verify }) InstructionError!void {
    try ic.tc.consumeCompute(precompile_program.COMPUTE_UNITS);

    // not sure if we even need a switch like this, seems they're invoked as separate programs?
    (switch (mode) {
        .ed25519_verify => ed25519Verify(ic),
        .secp256k1_verify => secp256k1Verify(ic),
    }) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return err.Custom;
    };
}

fn ed25519Verify(ic: *const InstructionContext) PrecompileProgramError!void {
    const data = ic.instruction;
    const n_signatures = data[0];
    if (data.len < ED25519_DATA_START) {
        if (data.len == 2 and n_signatures == 0) return;
        return error.InvalidInstructionDataSize;
    }
    if (n_signatures == 0) return error.InvalidInstructionDataSize;

    const expected_data_size = ED25519_SIGNATURE_OFFSETS_START +
        n_signatures * ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    if (data.len < expected_data_size) return error.InvalidInstructionDataSize;

    // firedancer seems to assume natural alignment in this loop? Need to prove it to myself.
    for (0..n_signatures) |i| {
        const offset = ED25519_SIGNATURE_OFFSETS_START +
            i * ED25519_SIGNATURE_OFFSETS_SERIALIZED_SIZE;

        const sig_offsets: *const Ed25519SignatureOffsets = @ptrCast(data.ptr + offset);

        const signature = try getInstructionValue(
            Ed25519.Signature,
            data,
            sig_offsets.signature_instruction_idx,
            sig_offsets.signature_offset,
        );
        const pubkey = try getInstructionValue(
            Ed25519.PublicKey,
            data,
            sig_offsets.pubkey_instruction_idx,
            sig_offsets.pubkey_offset,
        );
        const msg = try getInstructionData(
            sig_offsets.message_data_size,
            data,
            sig_offsets.message_instruction_idx,
            sig_offsets.message_data_offset,
        );
        signature.verify(msg, pubkey) catch return error.InvalidSignature;
    }
}

// https://github.com/firedancer-io/firedancer/blob/af74882ffb2c24783a82718dbc5111a94e1b5f6f/src/flamenco/runtime/program/fd_precompiles.c#L227
fn secp256k1Verify(ic: *const InstructionContext) PrecompileProgramError!void {
    const data = ic.instruction;
    const n_signatures = data[0];
    if (data.len < SECP256K1_DATA_START) {
        if (data.len == 1 and n_signatures == 0) return;
        return error.InvalidInstructionDataSize;
    }
    if (n_signatures == 0 and data.len > 1) return error.InvalidInstructionDataSize;

    const expected_data_size = SECP256K1_SIGNATURE_OFFSETS_START +
        n_signatures * SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    if (data.len < expected_data_size) return error.InvalidInstructionDataSize;

    // firedancer seems to assume natural alignment in this loop? Need to prove it to myself.
    for (0..n_signatures) |i| {
        const offset = SECP256K1_SIGNATURE_OFFSETS_START +
            i * SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
        const sig_offsets: *const Secp256k1SignatureOffsets = @ptrCast(data.ptr + offset);

        sig_offsets = @panic("TODO");
    }
}

fn getInstructionValue(
    T: type,
    current_instruction_data: []const u8,
    instruction_idx: u16,
    offset: usize,
) error{InvalidSignature}!*const T {
    // aligncast potentially dangerous?
    return @alignCast(@ptrCast(try getInstructionData(
        instruction_idx,
        current_instruction_data,
        offset,
        @sizeOf(T),
    )));
}

// https://github.com/firedancer-io/firedancer/blob/af74882ffb2c24783a82718dbc5111a94e1b5f6f/src/flamenco/runtime/program/fd_precompiles.c#L74
fn getInstructionData(
    len: usize,
    current_instruction_data: []const u8,
    instruction_idx: u16,
    offset: usize,
) error{InvalidSignature}![]const u8 {
    const data: []const u8 = if (instruction_idx == std.math.maxInt(u16))
        current_instruction_data
    else
        @panic("todo: handle multiple instructions");

    if (offset + len > data.len) return error.InvalidSignature;
    return data[offset..][0..len];
}
