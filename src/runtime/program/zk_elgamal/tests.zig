const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../../sig.zig");

const zksdk = sig.zksdk;
const zk_elgamal = sig.runtime.program.zk_elgamal;
const Pubkey = sig.core.Pubkey;
const ZeroCiphertextData = zksdk.ZeroCiphertextProofData;
const program = sig.runtime.program;

const expectProgramExecuteResult = program.testing.expectProgramExecuteResult;

// test "zero balance" {
//     const allocator = std.testing.allocator;

//     const kp = zksdk.ElGamalKeypair.random();
//     const zero_ciphertext = zksdk.el_gamal.encrypt(u64, 0, &kp.public);

//     const success_proof_data = ZeroCiphertextData.init(
//         &kp,
//         &zero_ciphertext,
//     );

//     const incorrect_keypair: zksdk.ElGamalKeypair = .{
//         .public = kp.public,
//         .secret = zksdk.ElGamalKeypair.Secret.random(),
//     };

//     const fail_proof_data = ZeroCiphertextData.init(
//         &incorrect_keypair,
//         &zero_ciphertext,
//     );

//     try testVerifyProofWithoutContext(
//         ZeroCiphertextData,
//         allocator,
//         .verify_zero_ciphertext,
//         &success_proof_data,
//         &fail_proof_data,
//     );
// }

fn testVerifyProofWithoutContext(
    comptime Proof: type,
    allocator: std.mem.Allocator,
    instruction: zk_elgamal.ProofInstruction,
    success_proof_data: *const Proof,
    fail_proof_data: *const Proof,
) !void {
    if (!builtin.is_test) @compileError("only use in tests");

    _ = fail_proof_data;

    var prng = std.Random.DefaultPrng.init(5083);
    const account_0_key = Pubkey.initRandom(prng.random());

    try expectProgramExecuteResult(
        allocator,
        zk_elgamal.ID,
        instruction,
        &.{
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 0 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = zk_elgamal.ID,
                    .data = &success_proof_data.toBytes(),
                },
                .{
                    .pubkey = zk_elgamal.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            // most expensive proof is the transfer-with-fee proof with 407_000 CUs
            .compute_meter = 500_000,
        },
        .{},
        .{ .print_logs = true },
    );
}
