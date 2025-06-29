const std = @import("std");

/// NOTE: Do we need this struct to exist? It is just a wrapper for lamports_per_signature
/// and agave has no methods defined on it. Why not just use a u64 directly?
pub const FeeCalculator = struct {
    /// The current cost of a signature.
    ///
    /// This amount may increase/decrease over time based on cluster processing
    /// load.
    lamports_per_signature: u64,

    pub fn initRandom(random: std.Random) FeeCalculator {
        return .{ .lamports_per_signature = random.int(u64) };
    }
};
