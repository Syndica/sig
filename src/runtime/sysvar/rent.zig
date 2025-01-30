const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

/// Account storage overhead for calculation of base rent.
///
/// This is the number of bytes required to store an account with no data. It is
/// added to an accounts data length when calculating [`Rent::minimumBalance`].
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/rent.rs#L51-L52
pub const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;

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

    pub fn mimimumBalance(self: Rent, data_len: usize) u64 {
        const bytes: u64 = @intCast(data_len);
        const lamports_per_year: f64 = @floatFromInt(
            (ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte_year,
        );
        return @intFromFloat(self.exemption_threshold * lamports_per_year);
    }
};
