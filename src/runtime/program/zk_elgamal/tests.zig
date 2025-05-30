const std = @import("std");
const sig = @import("../../../sig.zig");

const zksdk = sig.zksdk;
const zk_elgamal = sig.runtime.program.zk_elgamal;
const program = sig.runtime.program;
const ElGamalKeypair = zksdk.ElGamalKeypair;

const CiphertextCiphertextEqualityData = zksdk.CiphertextCiphertextEqualityData;
const CiphertextCommitmentEqualityData = zksdk.CiphertextCommitmentEqualityData;
const GroupedCiphertext2HandlesValidityData = zksdk.GroupedCiphertext2HandlesValidityData;
const PubkeyValidityProofData = zksdk.PubkeyValidityProofData;
const RangeProofU128Data = zksdk.RangeProofU128Data;
const RangeProofU256Data = zksdk.RangeProofU256Data;
const RangeProofU64Data = zksdk.RangeProofU64Data;
const ZeroCiphertextData = zksdk.ZeroCiphertextProofData;

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

test "batched range proof u64" {
    const allocator = std.testing.allocator;
    const amount_1: u64 = 23;
    const amount_2: u64 = 24;

    const commitment_1, const opening_1 = zksdk.pedersen.initValue(u64, amount_1);
    const commitment_2, const opening_2 = zksdk.pedersen.initValue(u64, amount_2);

    const success_proof_data = try RangeProofU64Data.init(
        &.{ commitment_1, commitment_2 },
        &.{ amount_1, amount_2 },
        &.{ 32, 32 },
        &.{ opening_1, opening_2 },
    );

    const incorrect_opening = zksdk.pedersen.Opening.random();
    const fail_proof_data = try RangeProofU64Data.init(
        &.{ commitment_1, commitment_2 },
        &.{ amount_1, amount_2 },
        &.{ 32, 32 },
        &.{ opening_1, incorrect_opening },
    );

    try testVerifyProofWithoutContext(
        RangeProofU64Data,
        allocator,
        .verify_batched_range_proof_u64,
        zk_elgamal.VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );
}

test "batched range proof u128" {
    const allocator = std.testing.allocator;
    const amount_1: u64 = 23;
    const amount_2: u64 = 24;

    const commitment_1, const opening_1 = zksdk.pedersen.initValue(u64, amount_1);
    const commitment_2, const opening_2 = zksdk.pedersen.initValue(u64, amount_2);

    const success_proof_data = try RangeProofU128Data.init(
        &.{ commitment_1, commitment_2 },
        &.{ amount_1, amount_2 },
        &.{ 64, 64 },
        &.{ opening_1, opening_2 },
    );

    const incorrect_opening = zksdk.pedersen.Opening.random();
    const fail_proof_data = try RangeProofU128Data.init(
        &.{ commitment_1, commitment_2 },
        &.{ amount_1, amount_2 },
        &.{ 64, 64 },
        &.{ opening_1, incorrect_opening },
    );

    try testVerifyProofWithoutContext(
        RangeProofU128Data,
        allocator,
        .verify_batched_range_proof_u128,
        zk_elgamal.VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );
}

test "batched range proof u256" {
    const allocator = std.testing.allocator;
    const amount_1: u64 = 23;
    const amount_2: u64 = 24;
    const amount_3: u64 = 25;
    const amount_4: u64 = 26;

    const commitment_1, const opening_1 = zksdk.pedersen.initValue(u64, amount_1);
    const commitment_2, const opening_2 = zksdk.pedersen.initValue(u64, amount_2);
    const commitment_3, const opening_3 = zksdk.pedersen.initValue(u64, amount_3);
    const commitment_4, const opening_4 = zksdk.pedersen.initValue(u64, amount_4);

    const success_proof_data = try RangeProofU256Data.init(
        &.{ commitment_1, commitment_2, commitment_3, commitment_4 },
        &.{ amount_1, amount_2, amount_3, amount_4 },
        &.{ 64, 64, 64, 64 },
        &.{ opening_1, opening_2, opening_3, opening_4 },
    );

    const incorrect_opening = zksdk.pedersen.Opening.random();
    const fail_proof_data = try RangeProofU256Data.init(
        &.{ commitment_1, commitment_2, commitment_3, commitment_4 },
        &.{ amount_1, amount_2, amount_3, amount_4 },
        &.{ 64, 64, 64, 64 },
        &.{ opening_1, opening_2, opening_3, incorrect_opening },
    );

    try testVerifyProofWithoutContext(
        RangeProofU256Data,
        allocator,
        .verify_batched_range_proof_u256,
        zk_elgamal.VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );
}

test "ciphertext commitment equality" {
    const allocator = std.testing.allocator;
    const kp = ElGamalKeypair.random();
    const amount: u64 = 55;
    const ciphertext = zksdk.el_gamal.encrypt(u64, amount, &kp.public);
    const commitment, const opening = zksdk.pedersen.initValue(u64, amount);

    const success_proof_data = CiphertextCommitmentEqualityData.init(
        &kp,
        &ciphertext,
        &commitment,
        &opening,
        amount,
    );

    const incorrect_kp: ElGamalKeypair = .{
        .public = kp.public,
        .secret = .random(),
    };

    const fail_proof_data = CiphertextCommitmentEqualityData.init(
        &incorrect_kp,
        &ciphertext,
        &commitment,
        &opening,
        amount,
    );

    try testVerifyProofWithoutContext(
        CiphertextCommitmentEqualityData,
        allocator,
        .verify_ciphertext_commitment_equality,
        zk_elgamal.VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );
}

test "grouped ciphertext 2 handles" {
    const allocator = std.testing.allocator;
    const dest_kp = ElGamalKeypair.random();
    const dest_public = dest_kp.public;

    const auditor_kp = ElGamalKeypair.random();
    const auditor_public = auditor_kp.public;

    const amount: u64 = 55;
    const opening = zksdk.pedersen.Opening.random();

    const grouped_ciphertext = zksdk.GroupedElGamalCiphertext(2).encryptWithOpening(
        .{ dest_public, auditor_public },
        amount,
        &opening,
    );

    const success_proof_data = GroupedCiphertext2HandlesValidityData.init(
        &dest_public,
        &auditor_public,
        &grouped_ciphertext,
        amount,
        &opening,
    );

    const incorrect_opening = zksdk.pedersen.Opening.random();
    const fail_proof_data = GroupedCiphertext2HandlesValidityData.init(
        &dest_public,
        &auditor_public,
        &grouped_ciphertext,
        amount,
        &incorrect_opening,
    );

    try testVerifyProofWithoutContext(
        GroupedCiphertext2HandlesValidityData,
        allocator,
        .verify_grouped_ciphertext2_handles_validity,
        zk_elgamal.VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );
}

const verify_instruction_types = [_]zk_elgamal.ProofInstruction{
    .verify_zero_ciphertext,
    .verify_ciphertext_ciphertext_equality,
    .verify_pubkey_validity,
    .verify_batched_range_proof_u64,
    .verify_batched_range_proof_u128,
    .verify_batched_range_proof_u256,
    .verify_ciphertext_commitment_equality,
    // TODO:
    // .verify_grouped_ciphertext2_handles_validity,
    // .verify_batched_grouped_ciphertext2_handles_validity,
    // .verify_percentage_with_cap,
    // .verify_grouped_ciphertext3_handles_validity,
    // .verify_batched_grouped_ciphertext3_handles_validity,
};

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

        // try to run a valid input data, but with the wrong instruction type
        for (verify_instruction_types) |wrong_type| {
            if (wrong_type == instruction) continue; // skip the same one

            var wrong_data: [Proof.BYTE_LEN + 1]u8 = undefined;
            wrong_data[0] = @intFromEnum(wrong_type);
            @memcpy(wrong_data[1..], &success_proof_data.toBytes());

            try expectProgramExecuteError(
                error.InvalidInstructionData,
                allocator,
                zk_elgamal.ID,
                wrong_data,
                &.{},
                .{
                    .accounts = &.{.{
                        .pubkey = zk_elgamal.ID,
                        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                    }},
                    .compute_meter = 500_000,
                },
                .{},
            );
        }
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
