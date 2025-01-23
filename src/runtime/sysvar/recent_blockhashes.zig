// [Deprecated]
// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/recent_blockhashes.rs
// https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/sysvar/fd_sysvar_recent_hashes.h

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
