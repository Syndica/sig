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

pub const CONFIG_PROGRAM_STAKE_CONFIG_ID =
    Pubkey.parseBase58String("StakeConfig11111111111111111111111111111111") catch unreachable;
// Proposed - SIMD0072
pub const FEATURE_PROGRAM_ID =
    Pubkey.parseBase58String("Feature111111111111111111111111111111111111") catch unreachable;

pub const ZK_ELGAMAL_PROOF_PROGRAM_ID =
    Pubkey.parseBase58String("ZkE1Gama1Proof11111111111111111111111111111") catch unreachable;
pub const ZK_TOKEN_PROOF_PROGRAM_ID =
    Pubkey.parseBase58String("ZkTokenProof1111111111111111111111111111111") catch unreachable;

pub const Incinerator =
    Pubkey.parseBase58String("1nc1nerator11111111111111111111111111111111") catch unreachable;
