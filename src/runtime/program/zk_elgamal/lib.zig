const sig = @import("../../../sig.zig");

/// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/zk_elgamal_proof_program/proof_data/mod.rs#L48
pub const ProofType = enum(u8) {
    /// Empty proof type used to distinguish if a proof context account is initialized
    uninitialized,
    zero_ciphertext,
    ciphertext_ciphertext_equality,
    ciphertext_commitment_equality,
    pubkey_validity,
    percentage_with_cap,
    batched_range_proof_u64,
    batched_range_proof_u128,
    batched_range_proof_u256,
    grouped_ciphertext2_handles_validity,
    batched_grouped_ciphertext2_handles_validity,
    grouped_ciphertext3_handles_validity,
    batched_grouped_ciphertext3_handles_validity,
    _,

    pub const BincodeSize = u8;
};

pub const ProofContextStateMeta = extern struct {
    context_state_authority: sig.core.Pubkey,
    proof_type: ProofType,
};

pub fn ProofContextState(C: type) type {
    return extern struct {
        context_state_authority: sig.core.Pubkey,
        proof_type: ProofType,
        context: [C.BYTE_LEN]u8,
    };
}

pub const ID: sig.core.Pubkey = .parse("ZkE1Gama1Proof11111111111111111111111111111");

// [agave] https://github.com/anza-xyz/agave/blob/master/programs/zk-elgamal-proof/src/lib.rs#L19-L31
pub const CLOSE_CONTEXT_STATE_COMPUTE_UNITS: u64 = 3_300;
pub const VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS: u64 = 6_000;
pub const VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS: u64 = 8_000;
pub const VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS: u64 = 6_400;
pub const VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS: u64 = 2_600;
pub const VERIFY_PERCENTAGE_WITH_CAP_COMPUTE_UNITS: u64 = 6_500;
pub const VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS: u64 = 111_000;
pub const VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS: u64 = 200_000;
pub const VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS: u64 = 368_000;
pub const VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS: u64 = 6_400;
pub const VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS: u64 = 13_000;
pub const VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS: u64 = 8_100;
pub const VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS: u64 = 16_400;

pub const tests = @import("tests.zig");
pub const ProofInstruction = @import("instruction.zig").ProofInstruction;
pub const execute = @import("execute.zig").execute;
