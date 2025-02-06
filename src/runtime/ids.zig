const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const SYSVAR_OWNER_ID =
    Pubkey.parseBase58String("Sysvar1111111111111111111111111111111111111") catch unreachable;
pub const SYSVAR_CLOCK_ID =
    Pubkey.parseBase58String("SysvarC1ock11111111111111111111111111111111") catch unreachable;
pub const SYSVAR_EPOCH_REWARDS_ID =
    Pubkey.parseBase58String("SysvarEpochRewards1111111111111111111111111") catch unreachable;
pub const SYSVAR_EPOCH_SCHEDULE_ID =
    Pubkey.parseBase58String("SysvarEpochSchedu1e111111111111111111111111") catch unreachable;
// Deprecated
pub const SYSVAR_FEES_ID =
    Pubkey.parseBase58String("SysvarFees111111111111111111111111111111111") catch unreachable;
pub const SYSVAR_INSTRUCTIONS_ID =
    Pubkey.parseBase58String("Sysvar1nstructions1111111111111111111111111") catch unreachable;
pub const SYSVAR_LAST_RESTART_SLOT_ID =
    Pubkey.parseBase58String("SysvarLastRestartS1ot1111111111111111111111") catch unreachable;
// Deprecated
pub const SYSVAR_RECENT_BLOCKHASHES_ID =
    Pubkey.parseBase58String("SysvarRecentB1ockHashes11111111111111111111") catch unreachable;
pub const SYSVAR_RENT_ID =
    Pubkey.parseBase58String("SysvarRent111111111111111111111111111111111") catch unreachable;
pub const SYSVAR_SLOT_HISTORY_ID =
    Pubkey.parseBase58String("SysvarS1otHistory11111111111111111111111111") catch unreachable;
pub const SYSVAR_SLOT_HASHES_ID =
    Pubkey.parseBase58String("SysvarS1otHashes111111111111111111111111111") catch unreachable;
pub const SYSVAR_STAKE_HISTORY_ID =
    Pubkey.parseBase58String("SysvarStakeHistory1111111111111111111111111") catch unreachable;
// Deprecated - UNUSED
pub const SYSVAR_REWARDS_ID =
    Pubkey.parseBase58String("SysvarRewards111111111111111111111111111111") catch unreachable;

pub const ADDRESS_LOOKUP_TABLE_PROGRAM_ID =
    Pubkey.parseBase58String("AddressLookupTab1e1111111111111111111111111") catch unreachable;
// Deprecated
pub const BPF_LOADER_V1_PROGRAM_ID =
    Pubkey.parseBase58String("BPFLoader1111111111111111111111111111111111") catch unreachable;
pub const BPF_LOADER_V2_PROGRAM_ID =
    Pubkey.parseBase58String("BPFLoader2111111111111111111111111111111111") catch unreachable;
pub const BPF_LOADER_V3_PROGRAM_ID =
    Pubkey.parseBase58String("BPFLoaderUpgradeab1e11111111111111111111111") catch unreachable;
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
pub const SYSTEM_PROGRAM_ID =
    Pubkey.parseBase58String("11111111111111111111111111111111") catch unreachable;
pub const VOTE_PROGRAM_ID =
    Pubkey.parseBase58String("Vote111111111111111111111111111111111111111") catch unreachable;
pub const ZK_ELGAMAL_PROOF_PROGRAM_ID =
    Pubkey.parseBase58String("ZkE1Gama1Proof11111111111111111111111111111") catch unreachable;
pub const ZK_TOKEN_PROOF_PROGRAM_ID =
    Pubkey.parseBase58String("ZkTokenProof1111111111111111111111111111111") catch unreachable;
