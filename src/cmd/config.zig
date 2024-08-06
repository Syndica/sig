const sig = @import("../lib.zig");
const ACCOUNT_INDEX_BINS = sig.accounts_db.db.ACCOUNT_INDEX_BINS;
const ShredCollectorConfig = sig.shred_collector.ShredCollectorConfig;
const IpAddr = sig.net.IpAddr;
const LogLevel = sig.trace.Level;

pub const Config = struct {
    identity: IdentityConfig = .{},
    gossip: GossipConfig = .{},
    shred_collector: ShredCollectorConfig = shred_collector_defaults,

    accounts_db: AccountsDBConfig = .{},

    leader_schedule_path: ?[]const u8 = null,
    genesis_file_path: ?[]const u8 = null,
    // general config
    log_level: LogLevel = .debug,
    metrics_port: u16 = 12345,
};

pub const current: *Config = &default_validator_config;
var default_validator_config: Config = .{};

const IdentityConfig = struct {};

const GossipConfig = struct {
    host: ?[]const u8 = null,
    port: u16 = 8001,
    entrypoints: [][]const u8 = &.{},
    spy_node: bool = false,
    dump: bool = false,
    trusted_validators: [][]const u8 = &.{},

    pub fn getHost(config: GossipConfig) ?sig.net.SocketAddr.ParseIpError!IpAddr {
        const host_str = config.host orelse return null;
        const socket = try sig.net.SocketAddr.parse(host_str);
        return switch (socket) {
            .V4 => |v4| .{ .ipv4 = v4.ip },
            .V6 => |v6| .{ .ipv6 = v6.ip },
        };
    }
};

const shred_collector_defaults = ShredCollectorConfig{
    .turbine_recv_port = 8002,
    .repair_port = 8003,
    .start_slot = null,
};

/// Analogous to [AccountsDbConfig](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L597)
pub const AccountsDBConfig = struct {
    /// where to load/save snapshots from - also where disk indexes and account files are stored
    snapshot_dir: []const u8 = "ledger/accounts_db",
    /// number of threads to load snapshot
    num_threads_snapshot_load: u32 = 0,
    /// number of threads to unpack snapshot from .tar.zstd
    num_threads_snapshot_unpack: u16 = 0,
    /// number of shards to use across the index
    number_of_index_bins: usize = ACCOUNT_INDEX_BINS,
    /// use disk based index for accounts index
    use_disk_index: bool = false,
    /// force unpacking a fresh snapshot even if an accounts/ dir exists
    force_unpack_snapshot: bool = false,
    /// minmum download speed in megabytes per second to download a snapshot from
    min_snapshot_download_speed_mbs: usize = 20,
    /// force download of new snapshot, even if one exists (usually to get a more up-to-date snapshot
    force_new_snapshot_download: bool = false,
};

const LogConfig = struct {};
