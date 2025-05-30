const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../../sig.zig");

const zksdk = sig.zksdk;
const zk_elgamal = sig.runtime.program.zk_elgamal;
const Pubkey = sig.core.Pubkey;
const program = sig.runtime.program;
const ElGamalKeypair = zksdk.ElGamalKeypair;

const ZeroCiphertextData = zksdk.ZeroCiphertextProofData;
const CiphertextCiphertextEqualityData = zksdk.CiphertextCiphertextEqualityData;
const PubkeyValidityProofData = zksdk.PubkeyValidityProofData;

const expectProgramExecuteResult = program.testing.expectProgramExecuteResult;
const expectProgramExecuteError = program.testing.expectProgramExecuteError;

test "zero balance" {
    const allocator = std.testing.allocator;

    const kp = ElGamalKeypair.random();
    const zero_ciphertext = zksdk.el_gamal.encrypt(u64, 0, &kp.public);

    const success_proof_data = ZeroCiphertextData.init(
        &kp,
        &zero_ciphertext,
    );

    const incorrect_keypair: ElGamalKeypair = .{
        .public = kp.public,
        .secret = .random(),
    };

    const fail_proof_data = ZeroCiphertextData.init(
        &incorrect_keypair,
        &zero_ciphertext,
    );

    try testVerifyProofWithoutContext(
        ZeroCiphertextData,
        allocator,
        .verify_zero_ciphertext,
        zk_elgamal.VERIFY_ZERO_BALANCE_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );
}

test "ciphertext ciphertext equality" {
    const allocator = std.testing.allocator;

    const source_kp = ElGamalKeypair.random();
    const dest_kp = ElGamalKeypair.random();

    const amount: u64 = 0;
    const source_ciphertext = zksdk.el_gamal.encrypt(u64, amount, &source_kp.public);

    const dest_opening = zksdk.pedersen.Opening.random();
    const dest_ciphertext = zksdk.el_gamal.encryptWithOpening(
        u64,
        amount,
        &dest_kp.public,
        &dest_opening,
    );

    const success_proof_data = CiphertextCiphertextEqualityData.init(
        &source_kp,
        &dest_kp.public,
        &source_ciphertext,
        &dest_ciphertext,
        &dest_opening,
        amount,
    );

    const incorrect_keypair: ElGamalKeypair = .{
        .public = source_kp.public,
        .secret = .random(),
    };

    const fail_proof_data = CiphertextCiphertextEqualityData.init(
        &incorrect_keypair,
        &dest_kp.public,
        &source_ciphertext,
        &dest_ciphertext,
        &dest_opening,
        amount,
    );

    try testVerifyProofWithoutContext(
        CiphertextCiphertextEqualityData,
        allocator,
        .verify_ciphertext_ciphertext_equality,
        zk_elgamal.VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );
}

test "pubkey validity" {
    const allocator = std.testing.allocator;
    const kp = ElGamalKeypair.random();

    const success_proof_data = PubkeyValidityProofData.init(&kp);

    const incorrect_kp: ElGamalKeypair = .{
        .public = kp.public,
        .secret = .random(),
    };
    const fail_proof_data = PubkeyValidityProofData.init(&incorrect_kp);

    try testVerifyProofWithoutContext(
        PubkeyValidityProofData,
        allocator,
        .verify_pubkey_validity,
        zk_elgamal.VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );
}

fn testVerifyProofWithoutContext(
    comptime Proof: type,
    allocator: std.mem.Allocator,
    instruction: zk_elgamal.ProofInstruction,
    compute_budget: u64,
    success_proof_data: Proof,
    fail_proof_data: Proof,
) !void {
    {
        var success_data: [Proof.BYTE_LEN + 1]u8 = undefined;
        success_data[0] = @intFromEnum(instruction);
        @memcpy(success_data[1..], &success_proof_data.toBytes());

        try expectProgramExecuteResult(
            allocator,
            zk_elgamal.ID,
            success_data,
            &.{},
            .{
                .accounts = &.{.{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                }},
                .compute_meter = compute_budget,
            },
            .{
                .accounts = &.{.{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                }},
                .compute_meter = 0,
            },
            .{},
        );
    }

    {
        var fail_data: [Proof.BYTE_LEN + 1]u8 = undefined;
        fail_data[0] = @intFromEnum(instruction);
        @memcpy(fail_data[1..], &fail_proof_data.toBytes());

        try expectProgramExecuteError(
            error.InvalidInstructionData,
            allocator,
            zk_elgamal.ID,
            fail_data,
            &.{},
            .{
                .accounts = &.{.{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                }},
                .compute_meter = compute_budget,
            },
            .{},
        );
    }
}
