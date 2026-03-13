/// Analogous to [ClusterType](https://github.com/anza-xyz/solana-sdk/blob/a467058aabc453c7d749a4993c56df293d1d75c3/cluster-type/src/lib.rs#L19)
/// Explicit numbers are added to ensure we don't mess up the order of the fields and break bincode reading.
pub const ClusterType = enum(u8) {
    testnet = 0,
    mainnet = 1,
    devnet = 2,
    development = 3,

    /// Returns entrypoints for public clusters, null for development.
    /// For development this returns an empty list, because the caller
    /// must provide entrypoints manually.
    pub fn getEntrypoints(self: ClusterType) []const []const u8 {
        return switch (self) {
            .mainnet => &.{
                "entrypoint.mainnet-beta.solana.com:8001",
                "entrypoint2.mainnet-beta.solana.com:8001",
                "entrypoint3.mainnet-beta.solana.com:8001",
                "entrypoint4.mainnet-beta.solana.com:8001",
                "entrypoint5.mainnet-beta.solana.com:8001",
            },
            .testnet => &.{
                "entrypoint.testnet.solana.com:8001",
                "entrypoint2.testnet.solana.com:8001",
                "entrypoint3.testnet.solana.com:8001",
            },
            .devnet => &.{
                "entrypoint.devnet.solana.com:8001",
                "entrypoint2.devnet.solana.com:8001",
                "entrypoint3.devnet.solana.com:8001",
                "entrypoint4.devnet.solana.com:8001",
                "entrypoint5.devnet.solana.com:8001",
            },
            .development => &.{},
        };
    }

    /// Returns the RPC URL for this cluster.
    pub fn getRpcUrl(self: ClusterType) ?[]const u8 {
        return switch (self) {
            .mainnet => "https://api.mainnet-beta.solana.com",
            .testnet => "https://api.testnet.solana.com",
            .devnet => "https://api.devnet.solana.com",
            .development => null,
        };
    }
};
