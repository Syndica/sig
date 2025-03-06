const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/rent.rs#L35
pub const DEFAULT_LAMPORTS_PER_BYTE_YEAR: u64 = 1_000_000_000 / 100 * 365 / (1024 * 1024);

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/rent.rs#L39
pub const DEFAULT_EXEMPTION_THRESHOLD: f64 = 2.0;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/rent.rs#L45
pub const DEFAULT_BURN_PERCENT: u8 = 50;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/rent.rs#L51-L52
pub const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/rent.rs#L13
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

    pub const ID =
        Pubkey.parseBase58String("SysvarRent111111111111111111111111111111111") catch unreachable;

    pub const DEFAULT: Rent = .{
        .lamports_per_byte_year = DEFAULT_LAMPORTS_PER_BYTE_YEAR,
        .exemption_threshold = DEFAULT_EXEMPTION_THRESHOLD,
        .burn_percent = DEFAULT_BURN_PERCENT,
    };

    pub fn minimumBalance(self: Rent, data_len: usize) u64 {
        const bytes: u64 = @intCast(data_len);
        const lamports_per_year: f64 = @floatFromInt(
            (ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte_year,
        );
        return @intFromFloat(self.exemption_threshold * lamports_per_year);
    }

    pub fn isExempt(self: Rent, lamports: u64, data_len: usize) bool {
        return lamports >= self.minimumBalance(data_len);
    }
};
