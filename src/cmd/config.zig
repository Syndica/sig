const std = @import("std");
const sig = @import("../sig.zig");

const ACCOUNT_INDEX_SHARDS = sig.accounts_db.db.ACCOUNT_INDEX_SHARDS;
const ShredCollectorConfig = sig.shred_network.ShredCollectorConfig;
const IpAddr = sig.net.IpAddr;
const LogLevel = sig.trace.Level;
const Cluster = sig.core.Cluster;
const SocketAddr = sig.net.SocketAddr;

const resolveSocketAddr = sig.net.net.resolveSocketAddr;
const getAccountPerFileEstimateFromCluster =
    sig.accounts_db.db.getAccountPerFileEstimateFromCluster;

pub const Config = struct {
    identity: IdentityConfig = .{},
    gossip: GossipConfig = .{},
    shred_network: ShredCollectorConfig = shred_network_defaults,
    accounts_db: AccountsDBConfig = .{},
    geyser: GeyserConfig = .{},
    turbine: TurbineConfig = .{},

    test_transaction_sender: TestTransactionSenderConfig = .{},

    max_shreds: u64 = 1_000,
    leader_schedule_path: ?[]const u8 = null,
    genesis_file_path: ?[]const u8 = null,
    // general config
    log_level: LogLevel = .debug,
    metrics_port: u16 = 12345,
    shred_version: ?u16 = null,

    pub fn genesisFilePath(self: Config) error{UnknownCluster}!?[]const u8 {
        return if (self.genesis_file_path) |provided_path|
            provided_path
        else if (try self.gossip.getCluster()) |n| switch (n) {
            .mainnet => "data/genesis-files/mainnet_genesis.bin",
            .devnet => "data/genesis-files/devnet_genesis.bin",
            .testnet => "data/genesis-files/testnet_genesis.bin",
            .localnet => null, // no default genesis file for localhost
        } else null;
    }
};

pub const current: *Config = &default_validator_config;
var default_validator_config: Config = .{};

pub const IdentityConfig = struct {};

pub const GossipConfig = struct {
    host: ?[]const u8 = null,
    port: u16 = 8001,
    entrypoints: [][]const u8 = &.{},
    network: ?[]const u8 = null,
    spy_node: bool = false,
    dump: bool = false,
    trusted_validators: [][]const u8 = &.{},

    pub fn getHost(config: GossipConfig) sig.net.IpAddr.ParseIpError!?IpAddr {
        const host_str = config.host orelse return null;
        const socket = try sig.net.IpAddr.parse(host_str);
        return switch (socket) {
            .ipv4 => |v4| .{ .ipv4 = v4 },
            .ipv6 => |v6| .{ .ipv6 = v6 },
        };
    }

    pub fn getPortFromHost(config: GossipConfig) ?sig.net.SocketAddr.ParseIpError!u16 {
        const host_str = config.host orelse return null;
        const socket = try sig.net.SocketAddr.parse(host_str);
        return switch (socket) {
            .V4 => |v4| v4.port,
            .V6 => |v6| v6.port,
        };
    }

    pub fn getCluster(self: GossipConfig) error{UnknownCluster}!?Cluster {
        return if (self.network) |network_str|
            std.meta.stringToEnum(Cluster, network_str) orelse
                error.UnknownCluster
        else
            null;
    }

    pub fn getEntrypointAddrs(
        self: GossipConfig,
        allocator: std.mem.Allocator,
    ) ![]SocketAddr {
        var entrypoint_set = std.AutoArrayHashMap(SocketAddr, void).init(allocator);
        defer entrypoint_set.deinit();

        // add cluster entrypoints
        if (try self.getCluster()) |cluster| {
            for (sig.gossip.getClusterEntrypoints(cluster)) |entrypoint| {
                const socket_addr = try resolveSocketAddr(allocator, entrypoint);
                try entrypoint_set.put(socket_addr, {});
            }
        }

        // add config entrypoints
        for (self.entrypoints) |entrypoint| {
            const socket_addr = SocketAddr.parse(entrypoint) catch brk: {
                break :brk try resolveSocketAddr(allocator, entrypoint);
            };
            try entrypoint_set.put(socket_addr, {});
        }

        const entrypoints = try allocator.dupe(SocketAddr, entrypoint_set.keys());
        return entrypoints;
    }
};

pub const shred_network_defaults = ShredCollectorConfig{
    .turbine_recv_port = 8002,
    .repair_port = 8003,
    .start_slot = null,
};

/// Analogous to [AccountsDbConfig](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L597)
pub const AccountsDBConfig = struct {
    /// where to load/save snapshots from - also where disk indexes and account files are stored
    snapshot_dir: []const u8 = sig.VALIDATOR_DIR ++ "accounts_db",
    /// number of threads to load snapshot
    num_threads_snapshot_load: u32 = 0,
    /// number of threads to unpack snapshot from .tar.zstd
    num_threads_snapshot_unpack: u16 = 0,
    /// number of shards to use across the index
    number_of_index_shards: u64 = ACCOUNT_INDEX_SHARDS,
    /// use disk based index for accounts index
    use_disk_index: bool = false,
    /// force unpacking a fresh snapshot even if an accounts/ dir exists
    force_unpack_snapshot: bool = false,
    /// minmum download speed in megabytes per second to download a snapshot from
    min_snapshot_download_speed_mbs: u64 = 20,
    /// force download of new snapshot, even if one exists (usually to get a more up-to-date snapshot
    force_new_snapshot_download: bool = false,
    /// estimate of the number of accounts per file (used for preallocation)
    accounts_per_file_estimate: u64 = getAccountPerFileEstimateFromCluster(.testnet) catch {
        @panic("account_per_file_estimate missing for default cluster");
    },
    /// loads accounts-db from pre-existing state which has been saved with the `save_index` option
    fastload: bool = false,
    /// saves the accounts index to disk after loading to support fastloading
    save_index: bool = false,
    /// only load snapshot metadata when starting up
    snapshot_metadata_only: bool = false,
    /// maximum number of snapshot download attempts before failing
    max_number_of_snapshot_download_attempts: u64 = 1_000,
};

pub const GeyserConfig = struct {
    enable: bool = false,
    pipe_path: []const u8 = sig.VALIDATOR_DIR ++ "geyser.pipe",
    writer_fba_bytes: usize = 1 << 32, // 4gb
};

const LogConfig = struct {};

const TestTransactionSenderConfig = struct {
    n_transactions: u64 = 3,
    n_lamports_per_transaction: u64 = 1e7,
};

pub const TurbineConfig = struct {
    num_retransmit_threads: ?usize = null, // Default to number of CPUs
    // TODO: remove when no longer needed
    overwrite_stake_for_testing: bool = false,
};
