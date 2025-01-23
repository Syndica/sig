// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/rent/src/lib.rs#L1
// https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/sysvar/fd_sysvar_rent.h#L1

const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const Rent = struct {
    /// Rental rate in lamports/byte-year.
    lamports_per_byte_year: u64,

    /// Amount of time (in years) a balance must include rent for the account to
    /// be rent exempt.
    exemption_threshold: f64,

    /// The percentage of collected rent that is burned.
    ///
    /// Valid values are in the range [0, 100]. The remaining percentage is
    /// distributed to validators.
    burn_percent: u8,
};
