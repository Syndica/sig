const std = @import("std");
const sig = @import("../../../sig.zig");

const zksdk = sig.zksdk;
const zk_elgamal = sig.runtime.program.zk_elgamal;
const program = sig.runtime.program;
const ElGamalKeypair = zksdk.ElGamalKeypair;

const CiphertextCiphertextData = zksdk.CiphertextCiphertextData;
const CiphertextCommitmentData = zksdk.CiphertextCommitmentData;
const GroupedCiphertext2HandlesData = zksdk.GroupedCiphertext2HandlesData;
const GroupedCiphertext3HandlesData = zksdk.GroupedCiphertext3HandlesData;
const BatchedGroupedCiphertext2HandlesData = zksdk.BatchedGroupedCiphertext2HandlesData;
const BatchedGroupedCiphertext3HandlesData = zksdk.BatchedGroupedCiphertext3HandlesData;
const PubkeyProofData = zksdk.PubkeyProofData;
const RangeProofU128Data = zksdk.RangeProofU128Data;
const RangeProofU256Data = zksdk.RangeProofU256Data;
const RangeProofU64Data = zksdk.RangeProofU64Data;
const ZeroCiphertextData = zksdk.ZeroCiphertextData;

const expectProgramExecuteResult = program.testing.expectProgramExecuteResult;
const expectProgramExecuteError = program.testing.expectProgramExecuteError;

test "zero ciphertext" {
    const allocator = std.testing.allocator;

    const kp = ElGamalKeypair.random();
    const zero_ciphertext = zksdk.elgamal.encrypt(u64, 0, &kp.public);

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
        zk_elgamal.VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testVerifyProofWithContext(
        ZeroCiphertextData,
        allocator,
        .verify_zero_ciphertext,
        zk_elgamal.VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        ZeroCiphertextData,
        allocator,
        .verify_zero_ciphertext,
        success_proof_data,
    );
}

test "ciphertext ciphertext equality" {
    const allocator = std.testing.allocator;

    const source_kp = ElGamalKeypair.random();
    const dest_kp = ElGamalKeypair.random();

    const amount: u64 = 0;
    const source_ciphertext = zksdk.elgamal.encrypt(u64, amount, &source_kp.public);

    const dest_opening = zksdk.pedersen.Opening.random();
    const dest_ciphertext = zksdk.elgamal.encryptWithOpening(
        u64,
        amount,
        &dest_kp.public,
        &dest_opening,
    );

    const success_proof_data = CiphertextCiphertextData.init(
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

    const fail_proof_data = CiphertextCiphertextData.init(
        &incorrect_keypair,
        &dest_kp.public,
        &source_ciphertext,
        &dest_ciphertext,
        &dest_opening,
        amount,
    );

    try testVerifyProofWithoutContext(
        CiphertextCiphertextData,
        allocator,
        .verify_ciphertext_ciphertext_equality,
        zk_elgamal.VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testVerifyProofWithContext(
        CiphertextCiphertextData,
        allocator,
        .verify_ciphertext_ciphertext_equality,
        zk_elgamal.VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        CiphertextCiphertextData,
        allocator,
        .verify_ciphertext_ciphertext_equality,
        success_proof_data,
    );
}

test "pubkey validity" {
    const allocator = std.testing.allocator;
    const kp = ElGamalKeypair.random();

    const success_proof_data = PubkeyProofData.init(&kp);

    const incorrect_kp: ElGamalKeypair = .{
        .public = kp.public,
        .secret = .random(),
    };
    const fail_proof_data = PubkeyProofData.init(&incorrect_kp);

    try testVerifyProofWithoutContext(
        PubkeyProofData,
        allocator,
        .verify_pubkey_validity,
        zk_elgamal.VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testVerifyProofWithContext(
        PubkeyProofData,
        allocator,
        .verify_pubkey_validity,
        zk_elgamal.VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        PubkeyProofData,
        allocator,
        .verify_pubkey_validity,
        success_proof_data,
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

    try testVerifyProofWithContext(
        RangeProofU64Data,
        allocator,
        .verify_batched_range_proof_u64,
        zk_elgamal.VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        RangeProofU64Data,
        allocator,
        .verify_batched_range_proof_u64,
        success_proof_data,
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

    try testVerifyProofWithContext(
        RangeProofU128Data,
        allocator,
        .verify_batched_range_proof_u128,
        zk_elgamal.VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        RangeProofU128Data,
        allocator,
        .verify_batched_range_proof_u128,
        success_proof_data,
    );
}

test "batched range proof u256" {
    if (!sig.build_options.long_tests) return error.SkipZigTest;

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

    try testVerifyProofWithContext(
        RangeProofU256Data,
        allocator,
        .verify_batched_range_proof_u256,
        zk_elgamal.VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        RangeProofU256Data,
        allocator,
        .verify_batched_range_proof_u256,
        success_proof_data,
    );
}

test "ciphertext commitment equality" {
    const allocator = std.testing.allocator;
    const kp = ElGamalKeypair.random();
    const amount: u64 = 55;
    const ciphertext = zksdk.elgamal.encrypt(u64, amount, &kp.public);
    const commitment, const opening = zksdk.pedersen.initValue(u64, amount);

    const success_proof_data = CiphertextCommitmentData.init(
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

    const fail_proof_data = CiphertextCommitmentData.init(
        &incorrect_kp,
        &ciphertext,
        &commitment,
        &opening,
        amount,
    );

    try testVerifyProofWithoutContext(
        CiphertextCommitmentData,
        allocator,
        .verify_ciphertext_commitment_equality,
        zk_elgamal.VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testVerifyProofWithContext(
        CiphertextCommitmentData,
        allocator,
        .verify_ciphertext_commitment_equality,
        zk_elgamal.VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        CiphertextCommitmentData,
        allocator,
        .verify_ciphertext_commitment_equality,
        success_proof_data,
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

    const success_proof_data = GroupedCiphertext2HandlesData.init(
        &dest_public,
        &auditor_public,
        &grouped_ciphertext,
        amount,
        &opening,
    );

    const incorrect_opening = zksdk.pedersen.Opening.random();
    const fail_proof_data = GroupedCiphertext2HandlesData.init(
        &dest_public,
        &auditor_public,
        &grouped_ciphertext,
        amount,
        &incorrect_opening,
    );

    try testVerifyProofWithoutContext(
        GroupedCiphertext2HandlesData,
        allocator,
        .verify_grouped_ciphertext2_handles_validity,
        zk_elgamal.VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testVerifyProofWithContext(
        GroupedCiphertext2HandlesData,
        allocator,
        .verify_grouped_ciphertext2_handles_validity,
        zk_elgamal.VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        GroupedCiphertext2HandlesData,
        allocator,
        .verify_grouped_ciphertext2_handles_validity,
        success_proof_data,
    );
}

test "batched grouped ciphertext 2 handles" {
    const allocator = std.testing.allocator;
    const dest_kp = ElGamalKeypair.random();
    const dest_public = dest_kp.public;

    const auditor_kp = ElGamalKeypair.random();
    const auditor_public = auditor_kp.public;

    const amount_lo: u64 = 55;
    const amount_hi: u64 = 22;

    const opening_lo = zksdk.pedersen.Opening.random();
    const opening_hi = zksdk.pedersen.Opening.random();

    const grouped_ciphertext_lo = zksdk.GroupedElGamalCiphertext(2).encryptWithOpening(
        .{ dest_public, auditor_public },
        amount_lo,
        &opening_lo,
    );
    const grouped_ciphertext_hi = zksdk.GroupedElGamalCiphertext(2).encryptWithOpening(
        .{ dest_public, auditor_public },
        amount_hi,
        &opening_hi,
    );

    const success_proof_data = BatchedGroupedCiphertext2HandlesData.init(
        &dest_public,
        &auditor_public,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        amount_lo,
        amount_hi,
        &opening_lo,
        &opening_hi,
    );

    const incorrect_opening = zksdk.pedersen.Opening.random();
    const fail_proof_data = BatchedGroupedCiphertext2HandlesData.init(
        &dest_public,
        &auditor_public,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        amount_lo,
        amount_hi,
        &incorrect_opening,
        &opening_hi,
    );

    try testVerifyProofWithoutContext(
        BatchedGroupedCiphertext2HandlesData,
        allocator,
        .verify_batched_grouped_ciphertext2_handles_validity,
        zk_elgamal.VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testVerifyProofWithContext(
        BatchedGroupedCiphertext2HandlesData,
        allocator,
        .verify_batched_grouped_ciphertext2_handles_validity,
        zk_elgamal.VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        BatchedGroupedCiphertext2HandlesData,
        allocator,
        .verify_batched_grouped_ciphertext2_handles_validity,
        success_proof_data,
    );
}

test "grouped ciphertext 3 handles" {
    const allocator = std.testing.allocator;
    const source_kp = ElGamalKeypair.random();
    const source_public = source_kp.public;

    const dest_kp = ElGamalKeypair.random();
    const dest_public = dest_kp.public;

    const auditor_kp = ElGamalKeypair.random();
    const auditor_public = auditor_kp.public;

    const amount: u64 = 55;
    const opening = zksdk.pedersen.Opening.random();
    const grouped_ciphertext = zksdk.GroupedElGamalCiphertext(3).encryptWithOpening(
        .{ source_public, dest_public, auditor_public },
        amount,
        &opening,
    );

    const success_proof_data = GroupedCiphertext3HandlesData.init(
        &source_public,
        &dest_public,
        &auditor_public,
        &grouped_ciphertext,
        amount,
        &opening,
    );

    const incorrect_opening = zksdk.pedersen.Opening.random();
    const fail_proof_data = GroupedCiphertext3HandlesData.init(
        &source_public,
        &dest_public,
        &auditor_public,
        &grouped_ciphertext,
        amount,
        &incorrect_opening,
    );

    try testVerifyProofWithoutContext(
        GroupedCiphertext3HandlesData,
        allocator,
        .verify_grouped_ciphertext3_handles_validity,
        zk_elgamal.VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testVerifyProofWithContext(
        GroupedCiphertext3HandlesData,
        allocator,
        .verify_grouped_ciphertext3_handles_validity,
        zk_elgamal.VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        GroupedCiphertext3HandlesData,
        allocator,
        .verify_grouped_ciphertext3_handles_validity,
        success_proof_data,
    );
}

test "batched grouped ciphertext 3 handles" {
    const allocator = std.testing.allocator;
    const source_kp = ElGamalKeypair.random();
    const source_public = source_kp.public;

    const dest_kp = ElGamalKeypair.random();
    const dest_public = dest_kp.public;

    const auditor_kp = ElGamalKeypair.random();
    const auditor_public = auditor_kp.public;

    const amount_lo: u64 = 55;
    const amount_hi: u64 = 22;

    const opening_lo = zksdk.pedersen.Opening.random();
    const opening_hi = zksdk.pedersen.Opening.random();

    const grouped_ciphertext_lo = zksdk.GroupedElGamalCiphertext(3).encryptWithOpening(
        .{ source_public, dest_public, auditor_public },
        amount_lo,
        &opening_lo,
    );
    const grouped_ciphertext_hi = zksdk.GroupedElGamalCiphertext(3).encryptWithOpening(
        .{ source_public, dest_public, auditor_public },
        amount_hi,
        &opening_hi,
    );

    const success_proof_data = BatchedGroupedCiphertext3HandlesData.init(
        &source_public,
        &dest_public,
        &auditor_public,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        amount_lo,
        amount_hi,
        &opening_lo,
        &opening_hi,
    );

    const incorrect_opening = zksdk.pedersen.Opening.random();
    const fail_proof_data = BatchedGroupedCiphertext3HandlesData.init(
        &source_public,
        &dest_public,
        &auditor_public,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        amount_lo,
        amount_hi,
        &incorrect_opening,
        &opening_hi,
    );

    try testVerifyProofWithoutContext(
        BatchedGroupedCiphertext3HandlesData,
        allocator,
        .verify_batched_grouped_ciphertext3_handles_validity,
        zk_elgamal.VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testVerifyProofWithContext(
        BatchedGroupedCiphertext3HandlesData,
        allocator,
        .verify_batched_grouped_ciphertext3_handles_validity,
        zk_elgamal.VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS,
        success_proof_data,
        fail_proof_data,
    );

    try testCloseState(
        BatchedGroupedCiphertext3HandlesData,
        allocator,
        .verify_batched_grouped_ciphertext3_handles_validity,
        success_proof_data,
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
    .verify_grouped_ciphertext2_handles_validity,
    .verify_batched_grouped_ciphertext2_handles_validity,
    .verify_percentage_with_cap,
    .verify_grouped_ciphertext3_handles_validity,
    .verify_batched_grouped_ciphertext3_handles_validity,
};

fn testVerifyProofWithoutContext(
    comptime Proof: type,
    allocator: std.mem.Allocator,
    instruction: zk_elgamal.ProofInstruction,
    compute_budget: u64,
    success_proof_data: Proof,
    fail_proof_data: Proof,
) !void {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var success_data: [Proof.BYTE_LEN + 1]u8 = undefined;
    success_data[0] = @intFromEnum(instruction);
    @memcpy(success_data[1..], &success_proof_data.toBytes());

    // case where you put the proof into the instruction data
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

    // case where the instruction data is a offset to an account containing the proof data
    const account_0_key = sig.core.Pubkey.initRandom(random);
    const owner_key = sig.core.Pubkey.initRandom(random);

    var success_account_data: [4 + 1]u8 = undefined;
    success_account_data[0] = @intFromEnum(instruction);
    success_account_data[1..][0..4].* = @splat(0); // 0 byte offset

    try expectProgramExecuteResult(
        allocator,
        zk_elgamal.ID,
        success_account_data,
        &.{
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 0 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = owner_key,
                    .lamports = 1_000_000_000,
                    .data = &success_proof_data.toBytes(),
                },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = compute_budget,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = owner_key,
                    .lamports = 1_000_000_000,
                    .data = &success_proof_data.toBytes(),
                },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = 0,
        },
        .{},
    );

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

    var fail_account_data: [4 + 1]u8 = undefined;
    fail_account_data[0] = @intFromEnum(instruction);
    fail_account_data[1..][0..4].* = @splat(0); // 0 byte offset

    try expectProgramExecuteError(
        error.InvalidInstructionData,
        allocator,
        zk_elgamal.ID,
        fail_account_data,
        &.{
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 0 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = owner_key,
                    .lamports = 1_000_000_000,
                    .data = &fail_proof_data.toBytes(),
                },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = compute_budget,
        },
        .{},
    );
}

fn testVerifyProofWithContext(
    comptime Proof: type,
    allocator: std.mem.Allocator,
    instruction: zk_elgamal.ProofInstruction,
    compute_budget: u64,
    success_proof_data: Proof,
    fail_proof_data: Proof,
) !void {
    var success_data: [Proof.BYTE_LEN + 1]u8 = undefined;
    success_data[0] = @intFromEnum(instruction);
    @memcpy(success_data[1..], &success_proof_data.toBytes());

    var fail_data: [Proof.BYTE_LEN + 1]u8 = undefined;
    fail_data[0] = @intFromEnum(instruction);
    @memcpy(fail_data[1..], &fail_proof_data.toBytes());

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const context_state_key = sig.core.Pubkey.initRandom(random);
    const context_authority_key = sig.core.Pubkey.initRandom(random);

    var expected_contents: [33 + Proof.Context.BYTE_LEN]u8 = undefined;
    expected_contents[0..32].* = @bitCast(context_authority_key);
    expected_contents[32] = @intFromEnum(instruction);
    @memcpy(expected_contents[33..], &success_proof_data.context.toBytes());

    // try to create proof context state with an invalid proof
    try expectProgramExecuteError(
        error.InvalidInstructionData,
        allocator,
        zk_elgamal.ID,
        fail_data,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = context_state_key,
                    .owner = zk_elgamal.ID,
                    .data = &(.{0} ** (Proof.Context.BYTE_LEN + 33)),
                    .lamports = 500_000,
                },
                .{ .pubkey = context_authority_key },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = compute_budget,
        },
        .{},
    );

    // try to create proof context state with incorrect account data length
    try expectProgramExecuteError(
        error.InvalidAccountData,
        allocator,
        zk_elgamal.ID,
        success_data,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = context_state_key,
                    .owner = zk_elgamal.ID,
                    .data = &(.{0} ** (Proof.Context.BYTE_LEN + 33 + 1)), // wrong length
                    .lamports = 500_000,
                },
                .{ .pubkey = context_authority_key },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = compute_budget,
        },
        .{},
    );

    try expectProgramExecuteResult(
        allocator,
        zk_elgamal.ID,
        success_data,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = context_state_key,
                    .owner = zk_elgamal.ID,
                    .data = &(.{0} ** (Proof.Context.BYTE_LEN + 33)),
                    .lamports = 500_000,
                },
                .{ .pubkey = context_authority_key },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = compute_budget,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = context_state_key,
                    .owner = zk_elgamal.ID,
                    .data = &expected_contents,
                    .lamports = 500_000,
                },
                .{ .pubkey = context_authority_key },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

fn testCloseState(
    comptime Proof: type,
    allocator: std.mem.Allocator,
    instruction: zk_elgamal.ProofInstruction,
    success_proof_data: Proof,
) !void {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const context_state_key = sig.core.Pubkey.initRandom(random);
    const context_authority_key = sig.core.Pubkey.initRandom(random);
    const destination_key = sig.core.Pubkey.initRandom(random);

    var initial_contents: [33 + Proof.Context.BYTE_LEN]u8 = undefined;
    initial_contents[0..32].* = @bitCast(context_authority_key);
    initial_contents[32] = @intFromEnum(instruction);
    @memcpy(initial_contents[33..], &success_proof_data.context.toBytes());

    try expectProgramExecuteResult(
        allocator,
        zk_elgamal.ID,
        zk_elgamal.ProofInstruction.close_context_state,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = context_state_key,
                    .owner = zk_elgamal.ID,
                    .data = &initial_contents,
                    .lamports = 12345,
                },
                .{
                    .pubkey = destination_key,
                    .lamports = 0,
                },
                .{ .pubkey = context_authority_key },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = zk_elgamal.CLOSE_CONTEXT_STATE_COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = context_state_key,
                    .owner = sig.runtime.program.system.ID,
                    .data = &.{},
                    .lamports = 0,
                },
                .{
                    .pubkey = destination_key,
                    .lamports = 12345,
                },
                .{ .pubkey = context_authority_key },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .accounts_resize_delta = -@as(i32, initial_contents.len),
            .compute_meter = 0,
        },
        .{},
    );
}
