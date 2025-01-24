const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Fees = sig.runtime.sysvar.Fees;

pub const RecentBlockhashes = struct {
    /// A list of entries ordered by descending block height. The first
    /// entry holds the most recent blockhash.
    entries: []const Entry,

    pub const Entry = struct {
        blockhash: Hash,
        fee_calculator: Fees.FeeCalculator,
    };
};
