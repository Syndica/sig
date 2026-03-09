//! Module that contains the RPC hook definitions.
pub const LedgerHookContext = @import("Ledger.zig");
pub const AccountHookContext = @import("Account.zig");
pub const ConsensusHookContext = @import("Consensus.zig");
pub const StaticHookContext = @import("Static.zig");
const prioritization_fee = @import("prioritization_fee.zig");

pub const PrioritizationFeeCache = prioritization_fee.PrioritizationFeeCache;
pub const PrioritizationFeeHookContext = prioritization_fee.PrioritizationFeeHookContext;
