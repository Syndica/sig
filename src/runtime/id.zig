const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const SYSVAR_OWNER_ID = Pubkey.fromString("Sysvar1111111111111111111111111111111111111") catch unreachable;
pub const SYSVAR_CLOCK_ID = Pubkey.fromString("SysvarC1ock11111111111111111111111111111111") catch unreachable;
pub const SYSVAR_EPOCH_REWARDS_ID = Pubkey.fromString("SysvarEpochRewards1111111111111111111111111") catch unreachable;
pub const SYSVAR_EPOCH_SCHEDULE_ID = Pubkey.fromString("SysvarEpochSchedu1e111111111111111111111111") catch unreachable;
pub const SYSVAR_FEES_ID = Pubkey.fromString("SysvarFees111111111111111111111111111111111") catch unreachable; // Deprecated
pub const SYSVAR_INSTRUCTIONS_ID = Pubkey.fromString("Sysvar1nstructions1111111111111111111111111") catch unreachable;
pub const SYSVAR_LAST_RESTART_SLOT_ID = Pubkey.fromString("SysvarLastRestartS1ot1111111111111111111111") catch unreachable;
pub const SYSVAR_RECENT_BLOCKHASHES_ID = Pubkey.fromString("SysvarRecentB1ockHashes11111111111111111111") catch unreachable; // Deprecated
pub const SYSVAR_RENT_ID = Pubkey.fromString("SysvarRent111111111111111111111111111111111") catch unreachable;
pub const SYSVAR_SLOT_HISTORY_ID = Pubkey.fromString("SysvarS1otHistory11111111111111111111111111") catch unreachable;
pub const SYSVAR_SLOT_HASHES_ID = Pubkey.fromString("SysvarS1otHashes111111111111111111111111111") catch unreachable;
pub const SYSVAR_STAKE_HISTORY_ID = Pubkey.fromString("SysvarStakeHistory1111111111111111111111111") catch unreachable;
pub const SYSVAR_REWARDS_ID = Pubkey.fromString("SysvarRewards111111111111111111111111111111") catch unreachable; // Deprecated - UNUSED

pub const ADDRESS_LOOKUP_TABLE_PROGRAM_ID = Pubkey.fromString("AddressLookupTab1e1111111111111111111111111") catch unreachable;
pub const BPF_LOADER_V1_PROGRAM_ID = Pubkey.fromString("BPFLoader1111111111111111111111111111111111") catch unreachable; // Deprecated
pub const BPF_LOADER_V2_PROGRAM_ID = Pubkey.fromString("BPFLoader2111111111111111111111111111111111") catch unreachable;
pub const BPF_LOADER_V3_PROGRAM_ID = Pubkey.fromString("BPFLoaderUpgradeab1e11111111111111111111111") catch unreachable;
pub const COMPUTE_BUDGET_PROGRAM_ID = Pubkey.fromString("ComputeBudget111111111111111111111111111111") catch unreachable;
pub const CONFIG_PROGRAM_ID = Pubkey.fromString("Config1111111111111111111111111111111111111") catch unreachable;
pub const CONFIG_PROGRAM_STAKE_CONFIG_ID = Pubkey.fromString("StakeConfig11111111111111111111111111111111") catch unreachable;
pub const FEATURE_PROGRAM_ID = Pubkey.fromString("Feature111111111111111111111111111111111111") catch unreachable; // Proposed - SIMD0072
pub const LOADER_V4_PROGRAM_ID = Pubkey.fromString("LoaderV411111111111111111111111111111111111") catch unreachable;
pub const PRECOMPILE_ED25519_PROGRAM_ID = Pubkey.fromString("Ed25519SigVerify111111111111111111111111111") catch unreachable;
pub const PRECOMPILE_SECP256K1_PROGRAM_ID = Pubkey.fromString("KeccakSecp256k11111111111111111111111111111") catch unreachable;
pub const PRECOMPILE_SECP256R1_PROGRAM_ID = Pubkey.fromString("Secp256r1SigVerify1111111111111111111111111") catch unreachable;
pub const STAKE_PROGRAM_ID = Pubkey.fromString("Stake11111111111111111111111111111111111111") catch unreachable;
pub const SYSTEM_PROGRAM_ID = Pubkey.fromString("11111111111111111111111111111111") catch unreachable;
pub const VOTE_PROGRAM_ID = Pubkey.fromString("Vote111111111111111111111111111111111111111") catch unreachable;
pub const ZK_ELGAMAL_PROOF_PROGRAM_ID = Pubkey.fromString("ZkE1Gama1Proof11111111111111111111111111111") catch unreachable;
pub const ZK_TOKEN_PROOF_PROGRAM_ID = Pubkey.fromString("ZkTokenProof1111111111111111111111111111111") catch unreachable;
