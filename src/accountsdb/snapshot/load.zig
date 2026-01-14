const std = @import("std");
const sig = @import("../../sig.zig");
const sig_config = @import("../../config.zig");
const tracy = @import("tracy");
const accountsdb = @import("../lib.zig");
const snapshot = @import("lib.zig");
const zstd = @import("zstd");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const GenesisConfig = sig.core.GenesisConfig;

const ThreadPool = sig.sync.ThreadPool;

const GeyserWriter = sig.geyser.GeyserWriter;
const GossipService = sig.gossip.GossipService;

const Rooted = sig.accounts_db.Two.Rooted;
const AccountsDB = sig.accounts_db.AccountsDB;
const StatusCache = sig.accounts_db.snapshot.StatusCache;
const Manifest = sig.accounts_db.snapshot.Manifest;
const SnapshotFiles = sig.accounts_db.snapshot.SnapshotFiles;
const FullAndIncrementalManifest = sig.accounts_db.snapshot.FullAndIncrementalManifest;

const Logger = sig.trace.Logger("accountsdb.snapshot.load");

pub const LoadedSnapshot = struct {
    allocator: Allocator,
    accounts_db: AccountsDB,
    combined_manifest: snapshot.FullAndIncrementalManifest,
    collapsed_manifest: snapshot.Manifest,
    genesis_config: GenesisConfig,
    status_cache: ?snapshot.StatusCache,
    tmp_dir: ?std.testing.TmpDir = null,

    pub fn deinit(self: *LoadedSnapshot) void {
        self.accounts_db.deinit();
        self.combined_manifest.deinit(self.allocator);
        self.collapsed_manifest.deinit(self.allocator);
        self.genesis_config.deinit(self.allocator);
        if (self.status_cache) |status_cache| {
            status_cache.deinit(self.allocator);
        }
        if (self.tmp_dir) |*tmp_dir| tmp_dir.cleanup();
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

/// Similar to `loadSnapshot`, but avoids untar-ing the snapshot into files on disk.
/// If provided, populates a Rooted DB instance with the accounts if DB is empty.
pub fn loadSnapshot2(
    allocator: Allocator,
    rooted_db: *Rooted,
    db_config: sig_config.AccountsDB,
    genesis_file_path: []const u8,
    logger: Logger,
    load_options: LoadSnapshotOptions,
) !LoadedSnapshot {
    const zone = tracy.Zone.init(@src(), .{ .name = "loadSnapshot2" });
    defer zone.deinit();

    // For rooted.computeLtHash
    var pool: ThreadPool = .init(.{
        .max_threads = @intCast(@max(1, try std.Thread.getCpuCount())),
    });
    defer {
        pool.shutdown();
        pool.deinit();
    }

    const snapshot_dir_str = db_config.snapshot_dir;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{ .iterate = true });
    defer snapshot_dir.close();

    const maybe_snapshot_files =
        SnapshotFiles.find(allocator, snapshot_dir) catch |err| switch (err) {
            error.NoFullSnapshotFileInfoFound => null,
            else => |e| return e,
        };

    // Download snapshot if not present or forced to
    if (maybe_snapshot_files == null or db_config.force_new_snapshot_download) {
        var timer = try std.time.Timer.start();
        logger.info().log("downloading snapshot");
        defer logger.info().logf(
            "  downloaded snapshot in {}",
            .{std.fmt.fmtDuration(timer.read())},
        );

        const min_mb_per_sec = db_config.max_number_of_snapshot_download_attempts;
        const gossip_service = load_options.gossip_service orelse {
            return error.SnapshotsNotFoundAndNoGossipService;
        };

        const trusted_validators: ?[]const Pubkey = null;
        const download_timeout: ?sig.time.Duration = null;

        const full, const maybe_inc = try sig.accounts_db.snapshot.downloadSnapshotsFromGossip(
            allocator,
            .from(logger),
            trusted_validators,
            gossip_service,
            snapshot_dir,
            @intCast(min_mb_per_sec),
            db_config.max_number_of_snapshot_download_attempts,
            download_timeout,
        );
        defer full.close();
        defer if (maybe_inc) |inc| inc.close();
    }

    const snapshot_files: SnapshotFiles = maybe_snapshot_files orelse
        (try SnapshotFiles.find(allocator, snapshot_dir));

    // Unpack snapshots directly into Rooted.

    const db_populate = rooted_db.count() == 0;
    if (!db_populate) {
        logger.info().logf("db has entries, skipping load from snapshot", .{});
    } else {
        logger.info().logf("db is empty -  loading from snapshot!", .{});
    }

    const full_manifest: Manifest, //
    var full_status_cache: StatusCache = blk: {
        const full_zone = tracy.Zone.init(@src(), .{ .name = "insertFromSnapshot: full" });
        defer full_zone.deinit();

        const path = snapshot_files.full.snapshotArchiveName();
        break :blk try insertFromSnapshotArchive(
            allocator,
            logger,
            rooted_db,
            snapshot_dir,
            path.constSlice(),
            .{ .slot = snapshot_files.full.slot, .hash = snapshot_files.full.hash },
            .{ .snapshot_type = .full, .put_accounts = db_populate },
        );
    };
    errdefer full_manifest.deinit(allocator);
    errdefer full_status_cache.deinit(allocator);

    const verify_hashes = !load_options.metadata_only and load_options.validate_snapshot;
    if (verify_hashes) {
        var timer = try std.time.Timer.start();
        logger.info().logf(
            "verifying snapshot accounts_lt_hash: {}",
            .{full_manifest.bank_extra.accounts_lt_hash.checksum()},
        );
        defer logger.info().logf(
            "LtHash verified in {}",
            .{std.fmt.fmtDuration(timer.read())},
        );

        const lt_hash = try rooted_db.computeLtHash(allocator, &pool);
        if (!full_manifest.bank_extra.accounts_lt_hash.eql(lt_hash)) {
            logger.err().logf(
                "incorrect snapshot accounts hash: expected vs calculated: {} vs {}",
                .{
                    full_manifest.bank_extra.accounts_lt_hash.checksum(),
                    lt_hash.checksum(),
                },
            );
            return error.IncorrectAccountsDeltaHash;
        }
    }

    const maybe_incremental_manifest: ?Manifest, //
    var maybe_incremental_status_cache: ?StatusCache = blk: {
        const incr_zone =
            tracy.Zone.init(@src(), .{ .name = "Rooted.insertFromSnapshot: incremental" });
        defer incr_zone.deinit();

        const info = snapshot_files.incremental() orelse break :blk .{ null, null };
        const incremental_path = info.snapshotArchiveName();
        const manifest, const status_cache = try insertFromSnapshotArchive(
            allocator,
            logger,
            rooted_db,
            snapshot_dir,
            incremental_path.constSlice(),
            info.slotAndHash(),
            .{ .snapshot_type = .incremental, .put_accounts = db_populate },
        );
        break :blk .{ manifest, status_cache };
    };
    errdefer if (maybe_incremental_manifest) |manifest| manifest.deinit(allocator);
    errdefer if (maybe_incremental_status_cache) |status_cache| status_cache.deinit(allocator);

    if (maybe_incremental_manifest) |*inc_manifest| {
        // Due to layout of DB, can only verify incremental snapshot if we've just inserted it.
        if (verify_hashes and db_populate) {
            var timer = try std.time.Timer.start();
            logger.info().logf(
                "verifying incremental accounts_lt_hash: {}",
                .{inc_manifest.bank_extra.accounts_lt_hash.checksum()},
            );
            defer logger.info().logf(
                "LtHash verified in {}",
                .{std.fmt.fmtDuration(timer.read())},
            );

            const lt_hash = try rooted_db.computeLtHash(allocator, &pool);
            if (!inc_manifest.bank_extra.accounts_lt_hash.eql(lt_hash)) {
                logger.err().logf(
                    "incorrect incremental accounts hash: expected vs calculated: {} vs {}",
                    .{
                        inc_manifest.bank_extra.accounts_lt_hash.checksum(),
                        lt_hash.checksum(),
                    },
                );
                return error.IncorrectAccountsDeltaHash;
            }
        }
    }

    const combined_manifest: FullAndIncrementalManifest = .{
        .full = full_manifest,
        .incremental = maybe_incremental_manifest,
    };
    // NOTE: do not call combined_manifest.deinit() as Manifest deinits are already errdefer above
    // and its returned on success.

    // Clones the manifests
    const collapsed_manifest = try combined_manifest.collapse(allocator);
    errdefer collapsed_manifest.deinit(allocator);

    // Fake accounts_db as not used.
    var accounts_db, var tmp_dir = try AccountsDB.initForTest(allocator);
    errdefer {
        accounts_db.deinit();
        tmp_dir.cleanup();
    }

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

    if (load_options.metadata_only) {
        logger.info().log("accounts-db setup done...");

        // Cleanup status caches.
        full_status_cache.deinit(allocator);
        if (maybe_incremental_status_cache) |status_cache| status_cache.deinit(allocator);

        return .{
            .allocator = allocator,
            .accounts_db = accounts_db,
            .tmp_dir = tmp_dir,
            .combined_manifest = combined_manifest,
            .collapsed_manifest = collapsed_manifest,
            .genesis_config = genesis_config,
            .status_cache = null,
        };
    }

    // validate the status cache of the latest slot

    const status_cache = blk: {
        // Consume both.
        defer full_status_cache = .EMPTY;
        defer maybe_incremental_status_cache = null;

        // Incremental takes precedent.
        if (maybe_incremental_status_cache) |inc_status_cache| {
            full_status_cache.deinit(allocator);
            break :blk inc_status_cache;
        }

        break :blk full_status_cache;
    };
    errdefer status_cache.deinit(allocator);

    const slot_history = blk: {
        const account = (try rooted_db.get(allocator, sig.runtime.sysvar.SlotHistory.ID)) orelse
            return error.PubkeyNotInIndex;
        defer account.deinit(allocator);

        var fba = std.io.fixedBufferStream(account.data);
        break :blk try sig.bincode.read(
            allocator,
            sig.runtime.sysvar.SlotHistory,
            fba.reader(),
            .{},
        );
    };
    defer slot_history.deinit(allocator);

    try status_cache.validate(allocator, collapsed_manifest.bank_fields.slot, &slot_history);

    logger.info().log("accounts-db setup done...");

    return .{
        .allocator = allocator,
        .accounts_db = accounts_db,
        .tmp_dir = tmp_dir,
        .combined_manifest = combined_manifest,
        .collapsed_manifest = collapsed_manifest,
        .genesis_config = genesis_config,
        .status_cache = status_cache,
    };
}

fn insertFromSnapshotArchive(
    allocator: std.mem.Allocator,
    logger: Logger,
    rooted_db: *Rooted,
    snapshot_dir: std.fs.Dir,
    snapshot_path: []const u8,
    slot_and_hash: sig.core.hash.SlotAndHash,
    options: struct {
        snapshot_type: enum { full, incremental },
        put_accounts: bool,
    },
) !struct { Manifest, StatusCache } {
    const zone = tracy.Zone.init(@src(), .{ .name = "insertFromSnapshotArchive" });
    defer zone.deinit();

    var timer = try std.time.Timer.start();
    logger.info().logf("loading snapshot archive: {s}", .{snapshot_path});
    defer logger.info().logf(
        "loaded snapshot archive in {}",
        .{std.fmt.fmtDuration(timer.read())},
    );

    rooted_db.beginTransaction();
    defer rooted_db.commitTransaction();

    const file = try snapshot_dir.openFile(snapshot_path, .{ .mode = .read_only });
    defer file.close();

    // calling posix.mmap on a zero-sized file will cause illegal behaviour
    const file_size = (try file.stat()).size;
    if (file_size == 0) return error.ZeroSizedTarball;

    const memory = try std.posix.mmap(
        null,
        file_size,
        std.posix.PROT.READ,
        std.posix.MAP{ .TYPE = .PRIVATE },
        file.handle,
        0,
    );
    defer std.posix.munmap(memory);

    if (@import("builtin").os.tag != .macos) {
        try std.posix.madvise(
            memory.ptr,
            memory.len,
            std.posix.MADV.SEQUENTIAL | std.posix.MADV.WILLNEED,
        );
    }

    var archive_stream = try zstd.Reader.init(memory);
    defer archive_stream.deinit();

    var tar_file_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var tar_link_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var tar_iter = std.tar.iterator(archive_stream.reader(), .{
        .file_name_buffer = &tar_file_name_buf,
        .link_name_buffer = &tar_link_name_buf,
    });

    var maybe_version: ?[5]u8 = null;
    var maybe_manifest: ?Manifest = null;
    var maybe_status_cache: ?StatusCache = null;
    errdefer {
        if (maybe_manifest) |manifest| manifest.deinit(allocator);
        if (maybe_status_cache) |status_cache| status_cache.deinit(allocator);
    }

    const manifest_path = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{slot_and_hash.slot});

    var account_data_buf: std.ArrayListUnmanaged(u8) = .{};
    try account_data_buf.ensureTotalCapacity(allocator, 10 * 1024 * 1024);
    defer account_data_buf.deinit(allocator);

    while (try tar_iter.next()) |tar_file| {
        if (tar_file.kind != .file) continue;

        // Read /version
        if (std.mem.eql(u8, tar_file.name, "version")) {
            const tar_zone = tracy.Zone.init(@src(), .{ .name = "Snapshot.readVersion" });
            defer tar_zone.deinit();

            if (maybe_version) |_| return error.DuplicateVersion;
            maybe_version = @as([5]u8, undefined);

            if ((try tar_file.reader().readAll(&maybe_version.?)) != maybe_version.?.len)
                return error.InvalidVersion;
            if (!std.mem.eql(u8, &maybe_version.?, "1.2.0"))
                return error.InvalidVersion;

            // Read /snapshot/status_cache
        } else if (std.mem.eql(u8, tar_file.name, "snapshots/status_cache")) {
            const inner_zone = tracy.Zone.init(@src(), .{ .name = "Snapshot.readStatusCache" });
            defer inner_zone.deinit();

            if (maybe_status_cache) |_| return error.DuplicateStatusCache;
            maybe_status_cache = try StatusCache.decodeFromBincode(allocator, tar_file.reader());

            // Read /snapshot/{slot}/{slot}
        } else if (std.mem.eql(u8, tar_file.name, manifest_path.constSlice())) {
            const inner_zone = tracy.Zone.init(@src(), .{ .name = "Snapshot.readManifest" });
            defer inner_zone.deinit();

            if (maybe_manifest) |_| return error.DuplicateManifest;
            maybe_manifest = try Manifest.decodeFromBincode(allocator, tar_file.reader());

            // Read /accounts/{slot}.{id}
        } else if (std.mem.startsWith(u8, tar_file.name, "accounts/")) {
            const inner_zone = tracy.Zone.init(@src(), .{ .name = "Snapshot.readAccountFile" });
            defer inner_zone.deinit();

            const split = std.mem.indexOf(u8, tar_file.name, ".") orelse
                return error.InvalidAccountFile;
            if (tar_file.name.len - 1 == split) return error.InvalidAccountFile;
            const slot = std.fmt.parseInt(u64, tar_file.name["accounts/".len..split], 10) catch
                return error.InvalidAccountFile;
            const id = std.fmt.parseInt(u32, tar_file.name[split + 1 ..], 10) catch
                return error.InvalidAccountFile;

            if (maybe_version == null) return error.MissingVersion;
            if (maybe_manifest == null) return error.MissingManifest;
            if (maybe_status_cache == null) return error.MissingStatusCache;
            rooted_db.largest_rooted_slot = maybe_manifest.?.accounts_db_fields.slot;

            // Skip account files
            if (!options.put_accounts) {
                break;
            }

            const info = maybe_manifest.?.accounts_db_fields.file_map.get(slot) orelse
                return error.InvalidAccountFile;
            if (info.id.toInt() != id)
                continue; // TODO: error?
            if (info.length > tar_file.size)
                return error.InvalidAccountFile;

            // Insert accounts in AccountFile into Rooted db
            var account_file_stream = std.io.limitedReader(tar_file.reader(), info.length);
            while (account_file_stream.bytes_left > 0) {
                const r = account_file_stream.reader();

                const account_zone = tracy.Zone.init(@src(), .{ .name = "Snapshot.readAccount" });
                defer account_zone.deinit();

                const header = r.readStructEndian(
                    extern struct {
                        write_version: u64,
                        data_len: u64,
                        pubkey: Pubkey,
                        lamports: u64,
                        rent_epoch: sig.core.Epoch,
                        owner: Pubkey,
                        executable: u8,
                        _padding: [7]u8,
                        hash: Hash,
                    },
                    .little,
                ) catch return error.InvalidAccountFile;

                // Header's hash is obsolete and always zero:
                // https://github.com/anza-xyz/agave/blob/v3.0/accounts-db/src/append_vec.rs#L1335-L1339
                if (!header.hash.eql(Hash.ZEROES)) {
                    return error.InvalidAccount;
                }

                // skip header padding.
                const header_size = @sizeOf(@TypeOf(header));
                const header_padding = std.mem.alignForward(usize, header_size, 8) - header_size;
                r.skipBytes(header_padding, .{}) catch return error.InvalidAccountFile;

                if (header.data_len > sig.runtime.program.system.MAX_PERMITTED_DATA_LENGTH)
                    return error.InvalidAccount;
                try account_data_buf.resize(allocator, header.data_len);
                const actual_data_size = try r.readAll(account_data_buf.items);
                if (actual_data_size < header.data_len)
                    return error.InvalidAccountFile;

                // skip data padding.
                const data_padding = @min(
                    account_file_stream.bytes_left,
                    std.mem.alignForward(usize, header.data_len, 8) - header.data_len,
                );
                r.skipBytes(data_padding, .{}) catch return error.InvalidAccountFile;

                // TODO: batched sqlite statements.
                rooted_db.put(header.pubkey, slot, .{
                    .owner = header.owner,
                    .lamports = header.lamports,
                    .rent_epoch = header.rent_epoch,
                    .data = account_data_buf.items,
                    .executable = switch (header.executable) {
                        0 => false,
                        1 => true,
                        else => return error.InvalidAccount,
                    },
                });
            }

            // Read unknown tar file
        } else {
            logger.err().logf(
                "invalid file in snapshot tar:\"{s}\" len:{}",
                .{ tar_file.name, tar_file.size },
            );
            return error.InvalidTar;
        }
    }

    if (maybe_version == null) return error.MissingVersion;
    return .{
        maybe_manifest orelse return error.MissingManifest,
        maybe_status_cache orelse return error.MissingStatusCache,
    };
}

pub fn loadSnapshot(
    allocator: Allocator,
    db_config: sig_config.AccountsDB,
    genesis_file_path: []const u8,
    logger: Logger,
    load_options: LoadSnapshotOptions,
) !LoadedSnapshot {
    const zone = tracy.Zone.init(@src(), .{ .name = "loadSnapshot" });
    defer zone.deinit();

    var validator_dir = try std.fs.cwd().makeOpenPath(sig.VALIDATOR_DIR, .{});
    defer validator_dir.close();

    const snapshot_dir_str = db_config.snapshot_dir;

    const combined_manifest, //
    const snapshot_files //
    = try sig.accounts_db.snapshot.download.getOrDownloadAndUnpackSnapshot(
        allocator,
        .from(logger),
        snapshot_dir_str,
        .{
            .gossip_service = load_options.gossip_service,
            .force_unpack_snapshot = db_config.force_unpack_snapshot,
            .force_new_snapshot_download = db_config.force_new_snapshot_download,
            .num_threads_snapshot_unpack = db_config.num_threads_snapshot_unpack,
            .max_number_of_download_attempts = db_config.max_number_of_snapshot_download_attempts,
            .min_snapshot_download_speed_mbs = db_config.min_snapshot_download_speed_mbs,
        },
    );
    errdefer combined_manifest.deinit(allocator);

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{ .iterate = true });
    errdefer snapshot_dir.close();

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
    const n_threads_snapshot_load = if (db_config.num_threads_snapshot_load == 0)
        std.math.lossyCast(u32, std.Thread.getCpuCount() catch 1)
    else
        db_config.num_threads_snapshot_load;

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        // where we read the snapshot from
        .snapshot_dir = snapshot_dir,
        .geyser_writer = load_options.geyser_writer,
        // gossip information for propogating snapshot info
        .gossip_view = if (load_options.gossip_service) |s| try .fromService(s) else null,
        // to use disk or ram for the index
        .index_allocation = if (db_config.use_disk_index) .disk else .ram,
        // number of shards for the index
        .number_of_index_shards = db_config.number_of_index_shards,
    });
    errdefer accounts_db.deinit();

    const collapsed_manifest = if (load_options.metadata_only)
        try combined_manifest.collapse(allocator)
    else
        try accounts_db.loadWithDefaults(
            allocator,
            combined_manifest,
            n_threads_snapshot_load,
            load_options.validate_snapshot,
            db_config.accounts_per_file_estimate,
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

    if (load_options.metadata_only) {
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
        if (err == error.FileNotFound) logger.err().logf(
            "status_cache not found - expecting {s}/snapshots/status_cache to exist",
            .{snapshot_dir_str},
        );
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

test loadSnapshot {
    // This is a very slow test that's mostly redundant with the pre-existing
    // snapshot loading tests db.zig. This just exists to get code coverage for
    // the high-level helper code in here.
    if (!sig.build_options.long_tests) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    const src_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    const snapshot_files = try snapshot.data.SnapshotFiles.find(allocator, src_dir);
    const snapshot_filename = snapshot_files.full.snapshotArchiveName();
    const incremental_filename = snapshot_files.incremental().?.snapshotArchiveName();

    try std.testing.expectError(error.SnapshotsNotFoundAndNoGossipService, loadSnapshot(
        allocator,
        .{
            .snapshot_dir = path,
            .number_of_index_shards = 4,
            .num_threads_snapshot_unpack = 1,
            .num_threads_snapshot_load = 1,
            .accounts_per_file_estimate = 500,
        },
        sig.TEST_DATA_DIR ++ "/genesis.bin",
        .noop,
        .{
            .gossip_service = null,
            .geyser_writer = null,
            .validate_snapshot = true,
        },
    ));

    try src_dir.copyFile(snapshot_filename.slice(), tmp.dir, snapshot_filename.slice(), .{});
    try src_dir.copyFile(incremental_filename.slice(), tmp.dir, incremental_filename.slice(), .{});

    try std.testing.expectError(error.FileNotFound, loadSnapshot(
        allocator,
        .{
            .snapshot_dir = path,
            .number_of_index_shards = 4,
            .num_threads_snapshot_unpack = 1,
            .num_threads_snapshot_load = 1,
            .accounts_per_file_estimate = 500,
        },
        sig.TEST_DATA_DIR ++ "/WRONG-genesis.bin",
        .noop,
        .{
            .gossip_service = null,
            .geyser_writer = null,
            .validate_snapshot = true,
        },
    ));

    var metadata_only = try loadSnapshot(
        allocator,
        .{
            .snapshot_dir = path,
            .number_of_index_shards = 4,
            .num_threads_snapshot_unpack = 1,
            .num_threads_snapshot_load = 0,
            .accounts_per_file_estimate = 500,
        },
        sig.TEST_DATA_DIR ++ "/genesis.bin",
        .noop,
        .{
            .gossip_service = null,
            .geyser_writer = null,
            .validate_snapshot = true,
            .metadata_only = true,
        },
    );
    metadata_only.deinit();

    var loaded_snapshot = try loadSnapshot(
        allocator,
        .{
            .snapshot_dir = path,
            .number_of_index_shards = 4,
            .num_threads_snapshot_unpack = 1,
            .num_threads_snapshot_load = 1,
            .accounts_per_file_estimate = 500,
        },
        sig.TEST_DATA_DIR ++ "/genesis.bin",
        .FOR_TESTS,
        .{
            .gossip_service = null,
            .geyser_writer = null,
            .validate_snapshot = true,
        },
    );
    loaded_snapshot.deinit();

    {
        const rooted_path = try std.fs.path.joinZ(allocator, &.{ path, "accounts.db" });
        defer allocator.free(rooted_path);

        var rooted_db: Rooted = try .init(rooted_path);
        defer rooted_db.deinit();

        var loaded_snapshot2 = try loadSnapshot2(
            allocator,
            &rooted_db,
            .{
                .snapshot_dir = path,
                .number_of_index_shards = 4,
                .num_threads_snapshot_unpack = 1,
                .num_threads_snapshot_load = 1,
                .accounts_per_file_estimate = 500,
            },
            sig.TEST_DATA_DIR ++ "/genesis.bin",
            .FOR_TESTS,
            .{
                .gossip_service = null,
                .geyser_writer = null,
                .validate_snapshot = true,
            },
        );
        loaded_snapshot2.deinit();
    }
}
