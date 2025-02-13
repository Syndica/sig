// This file exists for convenience and to provide access to IDs that do not
// have an appropriate place to live yet. It is not intended to be a permanent

// TODO: move IDs to programs as they are implemented, or to a more appropriate location for non-program IDs

const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const NATIVE_LOADER_ID =
    Pubkey.parseBase58String("NativeLoader1111111111111111111111111111111") catch unreachable;

pub const SYSVAR_INSTRUCTIONS_ID =
    Pubkey.parseBase58String("Sysvar1nstructions1111111111111111111111111") catch unreachable;

// Deprecated - UNUSED
pub const SYSVAR_REWARDS_ID =
    Pubkey.parseBase58String("SysvarRewards111111111111111111111111111111") catch unreachable;

pub const ADDRESS_LOOKUP_TABLE_PROGRAM_ID =
    Pubkey.parseBase58String("AddressLookupTab1e1111111111111111111111111") catch unreachable;
pub const COMPUTE_BUDGET_PROGRAM_ID =
    Pubkey.parseBase58String("ComputeBudget111111111111111111111111111111") catch unreachable;
pub const CONFIG_PROGRAM_ID =
    Pubkey.parseBase58String("Config1111111111111111111111111111111111111") catch unreachable;
pub const CONFIG_PROGRAM_STAKE_CONFIG_ID =
    Pubkey.parseBase58String("StakeConfig11111111111111111111111111111111") catch unreachable;
// Proposed - SIMD0072
pub const FEATURE_PROGRAM_ID =
    Pubkey.parseBase58String("Feature111111111111111111111111111111111111") catch unreachable;
pub const LOADER_V4_PROGRAM_ID =
    Pubkey.parseBase58String("LoaderV411111111111111111111111111111111111") catch unreachable;
pub const PRECOMPILE_ED25519_PROGRAM_ID =
    Pubkey.parseBase58String("Ed25519SigVerify111111111111111111111111111") catch unreachable;
pub const PRECOMPILE_SECP256K1_PROGRAM_ID =
    Pubkey.parseBase58String("KeccakSecp256k11111111111111111111111111111") catch unreachable;
pub const PRECOMPILE_SECP256R1_PROGRAM_ID =
    Pubkey.parseBase58String("Secp256r1SigVerify1111111111111111111111111") catch unreachable;
pub const STAKE_PROGRAM_ID =
    Pubkey.parseBase58String("Stake11111111111111111111111111111111111111") catch unreachable;

pub const VOTE_PROGRAM_ID =
    Pubkey.parseBase58String("Vote111111111111111111111111111111111111111") catch unreachable;
pub const ZK_ELGAMAL_PROOF_PROGRAM_ID =
    Pubkey.parseBase58String("ZkE1Gama1Proof11111111111111111111111111111") catch unreachable;
pub const ZK_TOKEN_PROOF_PROGRAM_ID =
    Pubkey.parseBase58String("ZkTokenProof1111111111111111111111111111111") catch unreachable;
