const std = @import("std");
const sig = @import("sig.zig");

const ShredNetworkConfig = sig.shred_network.ShredNetworkConfig;
const resolveSocketAddr = sig.net.net.resolveSocketAddr;
const getAccountPerFileEstimateFromCluster =
    sig.accounts_db.db.getAccountPerFileEstimateFromCluster;

pub const Cmd = struct {
    gossip: Gossip = .{},
    shred_network: ShredNetwork = .{},
    accounts_db: AccountsDB = .{},
    geyser: Geyser = .{},
    turbine: Turbine = .{},

    test_transaction_sender: TestTransactionSender = .{},

    validator_dir: []const u8 = sig.VALIDATOR_DIR,
    max_shreds: u64 = 5_000_000,
    leader_schedule_path: ?[]const u8 = null,
    genesis_file_path: ?[]const u8 = null,
    // general config
    log_filters: sig.trace.Filters = .debug,
    log_file: ?[]const u8 = null,
    tee_logs: bool = false,
    metrics_port: u16 = 12345,
    shred_version: ?u16 = null,
    replay_threads: u16 = 4,
    disable_consensus: bool = false,
    voting_enabled: bool = false,
    rpc_port: ?u16 = null,
    vote_account: ?[]const u8 = null,
    stop_at_slot: ?sig.core.Slot = null,

    pub fn genesisFilePath(self: Cmd) error{UnknownCluster}!?[]const u8 {
        if (self.genesis_file_path) |provided_path|
            return provided_path;

        const local_path = if (try self.gossip.getCluster()) |n| switch (n) {
            .mainnet => "data/genesis-files/mainnet_genesis.bin",
            .devnet => "data/genesis-files/devnet_genesis.bin",
            .testnet => "data/genesis-files/testnet_genesis.bin",
            .localnet => return error.MustProvideGenesisFileForLocalHost,
        } else return null;

        std.fs.cwd().access(local_path, .{ .read = true }) catch {
            return null;
        };
    }

    /// Derives a path relative to validator_dir if the param equals the default value.
    /// This is used to allow paths like snapshot_dir and geyser.pipe_path to be relative
    /// to validator_dir when using their default values, while still allowing explicit
    /// overrides.
    pub fn derivePathFromValidatorDir(
        self: Cmd,
        allocator: std.mem.Allocator,
        param_value: []const u8,
        comptime default_suffix: []const u8,
    ) ![]const u8 {
        if (std.mem.eql(u8, param_value, sig.VALIDATOR_DIR ++ default_suffix)) {
            return try std.fs.path.join(allocator, &.{ self.validator_dir, default_suffix });
        }
        return param_value;
    }
};

pub const TestTransactionSender = struct {
    n_transactions: u64 = 3,
    n_lamports_per_transaction: u64 = 1e7,
};

pub const Turbine = struct {
    num_retransmit_threads: ?usize = null, // Default to number of CPUs
    // TODO: remove when no longer needed
    overwrite_stake_for_testing: bool = false,
};

pub const Geyser = struct {
    enable: bool = false,
    pipe_path: []const u8 = sig.VALIDATOR_DIR ++ "geyser.pipe",
    writer_fba_bytes: usize = 1 << 32, // 4gb
};

/// The command-line arguments that are used to configure the shred network. The
/// CLI args are slightly different from the `shred_network.start` inputs, so it
/// gets its own struct. `ShredNetworkConfig` represents the inputs to the start
/// function.
pub const ShredNetwork = struct {
    root_slot: ?sig.core.Slot = null,
    repair_port: u16 = 8003,
    turbine_recv_port: u16 = 8002,
    no_retransmit: bool = true,
    dump_shred_tracker: bool = false,
    log_finished_slots: bool = false,

    /// Converts from the CLI args into the `shred_network.start` parameters
    pub fn toConfig(self: ShredNetwork, fallback_slot: sig.core.Slot) ShredNetworkConfig {
        return .{
            .root_slot = self.root_slot orelse fallback_slot,
            .repair_port = self.repair_port,
            .turbine_recv_port = self.turbine_recv_port,
            .retransmit = !self.no_retransmit,
            .dump_shred_tracker = self.dump_shred_tracker,
            .log_finished_slots = self.log_finished_slots,
        };
    }
};

/// Analogous to [AccountsDbConfig](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L597)
pub const AccountsDB = struct {
    /// where to load/save snapshots from - also where disk indexes and account files are stored
    snapshot_dir: []const u8 = sig.VALIDATOR_DIR ++ "accounts_db",
    /// number of threads to load snapshot
    num_threads_snapshot_load: u32 = 0,
    /// number of threads to unpack snapshot from .tar.zstd
    num_threads_snapshot_unpack: u16 = 0,
    /// number of shards to use across the index
    number_of_index_shards: u64 = sig.accounts_db.db.ACCOUNT_INDEX_SHARDS,
    /// use disk based index for accounts index
    use_disk_index: bool = false,
    /// force unpacking a fresh snapshot even if an accounts/ dir exists
    force_unpack_snapshot: bool = false,
    /// minmum download speed in megabytes per second to download a snapshot from
    min_snapshot_download_speed_mbs: u64 = 20,
    /// force download of new snapshot, even if one exists (usually to get a more up-to-date snapshot
    force_new_snapshot_download: bool = false,
    /// estimate of the number of accounts per file (used for preallocation)
    accounts_per_file_estimate: u64 = getAccountPerFileEstimateFromCluster(.testnet) catch
        @compileError("account_per_file_estimate missing for default cluster"),
    /// only load snapshot metadata when starting up
    snapshot_metadata_only: bool = false,
    /// maximum number of snapshot download attempts before failing
    max_number_of_snapshot_download_attempts: u64 = 1_000,
    /// skip the validation of the snapshot
    skip_snapshot_validation: bool = false,
};

pub const Gossip = struct {
    host: ?[]const u8 = null,
    port: u16 = 8001,
    entrypoints: []const []const u8 = &.{},
    cluster: ?[]const u8 = null,
    spy_node: bool = false,
    dump: bool = false,
    trusted_validators: []const []const u8 = &.{},

    pub fn getHost(config: Gossip) sig.net.IpAddr.ParseIpError!?sig.net.IpAddr {
        const host_str = config.host orelse return null;
        const socket = try sig.net.IpAddr.parse(host_str);
        return switch (socket) {
            .ipv4 => |v4| .{ .ipv4 = v4 },
            .ipv6 => |v6| .{ .ipv6 = v6 },
        };
    }

    pub fn getPortFromHost(config: Gossip) ?sig.net.SocketAddr.ParseIpError!u16 {
        const host_str = config.host orelse return null;
        const socket = try sig.net.SocketAddr.parse(host_str);
        return switch (socket) {
            .V4 => |v4| v4.port,
            .V6 => |v6| v6.port,
        };
    }

    pub fn getCluster(self: Gossip) error{UnknownCluster}!?sig.core.Cluster {
        return if (self.cluster) |cluster_str|
            std.meta.stringToEnum(sig.core.Cluster, cluster_str) orelse
                error.UnknownCluster
        else
            null;
    }

    pub fn getEntrypointAddrs(
        self: Gossip,
        allocator: std.mem.Allocator,
    ) ![]sig.net.SocketAddr {
        var entrypoint_set = std.AutoArrayHashMap(sig.net.SocketAddr, void).init(allocator);
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
            const socket_addr = sig.net.SocketAddr.parse(entrypoint) catch brk: {
                break :brk try resolveSocketAddr(allocator, entrypoint);
            };
            try entrypoint_set.put(socket_addr, {});
        }

        const entrypoints = try allocator.dupe(sig.net.SocketAddr, entrypoint_set.keys());
        return entrypoints;
    }
};
