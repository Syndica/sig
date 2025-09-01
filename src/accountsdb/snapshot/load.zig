const std = @import("std");
const sig = @import("../../sig.zig");
const sig_config = @import("../../config.zig");
const tracy = @import("tracy");
const accountsdb = @import("../lib.zig");
const snapshot = @import("lib.zig");

const Allocator = std.mem.Allocator;

const AccountsDB = sig.accounts_db.AccountsDB;
const GenesisConfig = sig.core.GenesisConfig;
const GeyserWriter = sig.geyser.GeyserWriter;
const GossipService = sig.gossip.GossipService;
const StatusCache = sig.accounts_db.snapshot.StatusCache;

const Logger = sig.trace.Logger("accountsdb.snapshot.load");

pub const LoadedSnapshot = struct {
    allocator: Allocator,
    accounts_db: AccountsDB,
    combined_manifest: snapshot.FullAndIncrementalManifest,
    collapsed_manifest: snapshot.Manifest,
    genesis_config: GenesisConfig,
    status_cache: ?snapshot.StatusCache,

    pub fn deinit(self: *@This()) void {
        self.accounts_db.deinit();
        self.combined_manifest.deinit(self.allocator);
        self.collapsed_manifest.deinit(self.allocator);
        self.genesis_config.deinit(self.allocator);
        if (self.status_cache) |status_cache| {
            status_cache.deinit(self.allocator);
        }
    }
};

const LoadSnapshotOptions = struct {
    /// optional service to download a fresh snapshot from gossip. if null, will read from the snapshot_dir
    gossip_service: ?*GossipService,
    /// optional geyser to write snapshot data to
    geyser_writer: ?*GeyserWriter,
    /// whether to validate the snapshot account data against the metadata
    validate_snapshot: bool,
    /// whether to load only the metadata of the snapshot
    metadata_only: bool = false,
};

pub fn loadSnapshot(
    allocator: Allocator,
    config: sig_config.AccountsDB,
    genesis_file_path: []const u8,
    logger: Logger,
    options: LoadSnapshotOptions,
) !LoadedSnapshot {
    const zone = tracy.Zone.init(@src(), .{ .name = "loadSnapshot" });
    defer zone.deinit();

    var validator_dir = try std.fs.cwd().makeOpenPath(sig.VALIDATOR_DIR, .{});
    defer validator_dir.close();

    // const genesis_file_path = try cfg.genesisFilePath() orelse return error.GenesisPathNotProvided;

    const snapshot_dir_str = config.snapshot_dir;

    const combined_manifest, //
    const snapshot_files //
    = try sig.accounts_db.snapshot.download.getOrDownloadAndUnpackSnapshot(
        allocator,
        .from(logger),
        snapshot_dir_str,
        .{
            .gossip_service = options.gossip_service,
            .force_unpack_snapshot = config.force_unpack_snapshot,
            .force_new_snapshot_download = config.force_new_snapshot_download,
            .num_threads_snapshot_unpack = config.num_threads_snapshot_unpack,
            .max_number_of_download_attempts = config.max_number_of_snapshot_download_attempts,
            .min_snapshot_download_speed_mbs = config.min_snapshot_download_speed_mbs,
        },
    );

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{ .iterate = true });
    defer snapshot_dir.close();

    logger.info().logf("full snapshot: {s}", .{sig.utils.fmt.tryRealPath(
        snapshot_dir,
        snapshot_files.full.snapshotArchiveName().constSlice(),
    )});
    if (snapshot_files.incremental()) |inc_snap| {
        logger.info().logf("incremental snapshot: {s}", .{
            sig.utils.fmt.tryRealPath(snapshot_dir, inc_snap.snapshotArchiveName().constSlice()),
        });
    }

    // cli parsing
    const n_threads_snapshot_load: u32 = blk: {
        const cli_n_threads_snapshot_load: u32 =
            config.num_threads_snapshot_load;
        if (cli_n_threads_snapshot_load == 0) {
            // default value
            break :blk std.math.lossyCast(u32, try std.Thread.getCpuCount());
        } else {
            break :blk cli_n_threads_snapshot_load;
        }
    };

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        // where we read the snapshot from
        .snapshot_dir = snapshot_dir,
        .geyser_writer = options.geyser_writer,
        // gossip information for propogating snapshot info
        .gossip_view = if (options.gossip_service) |service|
            try AccountsDB.GossipView.fromService(service)
        else
            null,
        // to use disk or ram for the index
        .index_allocation = if (config.use_disk_index) .disk else .ram,
        // number of shards for the index
        .number_of_index_shards = config.number_of_index_shards,
    });
    errdefer accounts_db.deinit();

    const collapsed_manifest = if (options.metadata_only)
        try combined_manifest.collapse(allocator)
    else
        try accounts_db.loadWithDefaults(
            allocator,
            combined_manifest,
            n_threads_snapshot_load,
            options.validate_snapshot,
            config.accounts_per_file_estimate,
            config.fastload,
            config.save_index,
        );
    errdefer collapsed_manifest.deinit(allocator);

    // this should exist before we start to unpack
    logger.info().log("reading genesis...");

    const genesis_config = GenesisConfig.init(allocator, genesis_file_path) catch |err| {
        if (err == error.FileNotFound) {
            logger.err().logf(
                "genesis config not found - expecting {s} to exist",
                .{genesis_file_path},
            );
        }
        return err;
    };
    errdefer genesis_config.deinit(allocator);

    logger.info().log("validating bank...");

    try collapsed_manifest.bank_fields.validate(&genesis_config);

    if (options.metadata_only) {
        logger.info().log("accounts-db setup done...");
        return .{
            .allocator = allocator,
            .accounts_db = accounts_db,
            .combined_manifest = combined_manifest,
            .collapsed_manifest = collapsed_manifest,
            .genesis_config = genesis_config,
            .status_cache = null,
        };
    }

    // validate the status cache
    const status_cache = StatusCache.initFromDir(allocator, snapshot_dir) catch |err| {
        if (err == error.FileNotFound) {
            logger.err().logf(
                "status_cache not found - expecting {s}/snapshots/status_cache to exist",
                .{snapshot_dir_str},
            );
        }
        return err;
    };
    errdefer status_cache.deinit(allocator);

    const slot_history = try accounts_db.getSlotHistory(allocator);
    defer slot_history.deinit(allocator);

    try status_cache.validate(allocator, collapsed_manifest.bank_fields.slot, &slot_history);

    logger.info().log("accounts-db setup done...");

    return .{
        .allocator = allocator,
        .accounts_db = accounts_db,
        .combined_manifest = combined_manifest,
        .collapsed_manifest = collapsed_manifest,
        .genesis_config = genesis_config,
        .status_cache = status_cache,
    };
}
