const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/fees.rs#L43
pub const Fees = struct {
    fee_calculator: FeeCalculator,

    pub const FeeCalculator = struct {
        lamports_per_signature: u64,
    };

    pub const ID =
        Pubkey.parseBase58String("SysvarFees111111111111111111111111111111111") catch unreachable;
};
