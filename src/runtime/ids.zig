// This file exists for convenience and to provide access to IDs that do not
// have an appropriate place to live yet. It is not intended to be a permanent

// TODO: move IDs to programs as they are implemented, or to a more appropriate location for non-program IDs

const sig = @import("../sig.zig");
const Pubkey = sig.core.Pubkey;

pub const NATIVE_LOADER_ID: Pubkey = .parse("NativeLoader1111111111111111111111111111111");

pub const SYSVAR_INSTRUCTIONS_ID: Pubkey = .parse("Sysvar1nstructions1111111111111111111111111");

// Deprecated - UNUSED
pub const SYSVAR_REWARDS_ID: Pubkey = .parse("SysvarRewards111111111111111111111111111111");

pub const CONFIG_PROGRAM_STAKE_CONFIG_ID: Pubkey =
    .parse("StakeConfig11111111111111111111111111111111");

// Proposed - SIMD0072
pub const FEATURE_PROGRAM_ID: Pubkey = .parse("Feature111111111111111111111111111111111111");
pub const FEATURE_PROGRAM_SOURCE_ID: Pubkey =
    .parse("3D3ydPWvmEszrSjrickCtnyRSJm1rzbbSsZog8Ub6vLh");

pub const ZK_TOKEN_PROOF_PROGRAM_ID: Pubkey = .parse("ZkTokenProof1111111111111111111111111111111");

pub const INCINERATOR: Pubkey = .parse("1nc1nerator11111111111111111111111111111111");
