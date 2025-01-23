// [Deprecated]
// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/fees.rs
// https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/sysvar/fd_sysvar_fees.h

const sig = @import("../../sig.zig");

pub const Fees = struct {
    fee_calculator: FeeCalculator,

    pub const FeeCalculator = struct {
        lamports_per_signature: u64,
    };
};
