const sig = @import("../../sig.zig");

pub const Fees = struct {
    fee_calculator: FeeCalculator,

    pub const FeeCalculator = struct {
        lamports_per_signature: u64,
    };
};
