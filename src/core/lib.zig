const shared = @import("shared");

pub const account = @import("account.zig");
pub const ancestors = @import("ancestors.zig");
pub const bank = @import("bank.zig");
pub const blockhash_queue = shared.core.blockhash_queue;
pub const entry = @import("entry.zig");
pub const epoch_schedule = shared.core.epoch_schedule;
pub const epoch_stakes = @import("epoch_stakes.zig");
pub const features = shared.core.features;
pub const genesis_config = @import("genesis_config.zig");
pub const genesis_download = @import("genesis_download.zig");
pub const hard_forks = @import("hard_forks.zig");
pub const hash = shared.core.hash;
pub const instruction = shared.core.instruction;
pub const leader_schedule = @import("leader_schedule.zig");
pub const poh = @import("poh.zig");
pub const pubkey = shared.core.pubkey;
pub const rent_collector = shared.runtime.rent_collector;
pub const ReservedAccounts = @import("ReservedAccounts.zig");
pub const shred = @import("shred.zig");
pub const signature = shared.core.signature;
pub const stakes = @import("stakes.zig");
pub const status_cache = @import("status_cache.zig");
pub const time = shared.core.time;
pub const transaction = shared.core.transaction;
pub const transaction_error = shared.core.transaction_error;
pub const epoch_tracker = @import("epoch_tracker.zig");

/// TODO: Change EpochStakes to use EpochStakes(.stake) everywhere except in the `epoch_stakes` field
/// of `BankFields` for serialization purposes. When initialising an epoch stakes for production we
/// will need to load the accounts from accounts db to convert from `EpochStakes(.delegation)` to
/// `EpochStakes(.stake)`. Because we need to load the `credits_observed` value which is contained in
/// the stake account data which is a serialized `StakesStateV2`. This process also validates that
/// the stake accounts are valid.
/// NOTE: In the short term we may be able to get away with using `EpochStakes(.delegation)` if
/// we are not yet using the `credits_observed` value in the epoch stakes anywhere.
pub const EpochStakes = epoch_stakes.EpochStakesGeneric(.delegation);
pub const EpochStakesMap = epoch_stakes.EpochStakesMapGeneric(.delegation);
/// TODO: Move to serialization module, it is not required elsewhere.
pub const VersionedEpochStakes = epoch_stakes.VersionedEpochStakes;

/// TODO: The `StakesCache` should ultimately be either a `.stake` or `.account` variant. This
/// change requires populating the `StakesCache` loading accounts from the accounts db, deserializing
/// the account state, and creating either a `Stake` or `StakeAccount`. For now we will use the
/// `.delegation` variant for simplicity.
pub const StakesCache = stakes.StakesCacheGeneric(.stake);
pub const StakesType = stakes.StakesType;
pub const Stakes = stakes.Stakes;

pub const Account = account.Account;
pub const Ancestors = ancestors.Ancestors;
pub const BankFields = bank.BankFields;
pub const BlockhashQueue = shared.core.BlockhashQueue;
pub const ClusterType = genesis_config.ClusterType;
pub const Entry = entry.Entry;
pub const EpochSchedule = shared.core.EpochSchedule;
pub const EpochTracker = epoch_tracker.EpochTracker;
pub const EpochInfo = epoch_tracker.EpochInfo;
pub const FeeRateGovernor = genesis_config.FeeRateGovernor;
pub const FeatureSet = shared.core.FeatureSet;
pub const GenesisConfig = genesis_config.GenesisConfig;
pub const HardFork = HardForks.HardFork;
pub const Inflation = genesis_config.Inflation;
pub const PohConfig = genesis_config.PohConfig;
pub const HardForks = hard_forks.HardForks;
pub const Hash = shared.core.Hash;
pub const Instruction = shared.core.Instruction;
pub const LtHash = shared.core.LtHash;
pub const Nonce = shred.Nonce;
pub const Pubkey = shared.core.Pubkey;
pub const RentCollector = shared.runtime.RentCollector;
pub const ShredVersion = shred.ShredVersion;
pub const Signature = shared.core.Signature;
pub const SlotConstants = bank.SlotConstants;
pub const SlotState = bank.SlotState;
pub const StatusCache = status_cache.StatusCache;
pub const Transaction = shared.core.Transaction;
pub const TransactionError = shared.core.TransactionError;

pub const Epoch = shared.core.Epoch;
pub const Slot = shared.core.Slot;
pub const UnixTimestamp = shared.core.UnixTimestamp;
