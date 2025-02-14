const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Fees = sig.runtime.sysvar.Fees;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/recent_blockhashes.rs#L99
pub const RecentBlockhashes = struct {
    /// A list of entries ordered by descending block height. The first
    /// entry holds the most recent blockhash.
    entries: []const Entry,

    pub const ID =
        Pubkey.parseBase58String("SysvarRecentB1ockHashes11111111111111111111") catch unreachable;

    pub const Entry = struct {
        blockhash: Hash,
        fee_calculator: Fees.FeeCalculator,
    };

    pub fn isEmpty(self: RecentBlockhashes) bool {
        return self.entries.len == 0;
    }
};
