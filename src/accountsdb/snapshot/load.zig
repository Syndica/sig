const std = @import("std");
const sig = @import("../../sig.zig");
const sig_config = @import("../../config.zig");
const tracy = @import("tracy");
const accountsdb = @import("../lib.zig");
const snapshot = @import("lib.zig");
const zstd = @import("zstd");

const Allocator = std.mem.Allocator;

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const GenesisConfig = sig.core.GenesisConfig;

const AccountSharedData = sig.runtime.AccountSharedData;
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

    const db_has_entries = !rooted_db.isEmpty();
    if (db_has_entries) {
        logger.info().logf("db has entries, skipping load from snapshot\n", .{});
    } else {
        logger.info().logf("db is empty -  loading from snapshot!\n", .{});
    }

    const full_manifest, const full_status_cache = blk: {
        const full_zone = tracy.Zone.init(@src(), .{ .name = "insertFromSnapshot: full" });
        defer full_zone.deinit();

        const path = snapshot_files.full.snapshotArchiveName();
        break :blk try insertFromSnapshotArchive(
            allocator,
            logger,
            rooted_db,
            path.constSlice(),
            .{ .slot = snapshot_files.full.slot, .hash = snapshot_files.full.hash },
            .{ .snapshot_type = .full, .put_accounts = !db_has_entries },
        );
    };
    errdefer {
        full_manifest.deinit(allocator);
        full_status_cache.deinit(allocator);
    }

    const maybe_incremental_manifest: ?Manifest, const maybe_incremental_status_cache: ?StatusCache = blk: {
        const incr_zone =
            tracy.Zone.init(@src(), .{ .name = "Rooted.insertFromSnapshot: incremental" });
        defer incr_zone.deinit();

        const info = snapshot_files.incremental() orelse break :blk .{ null, null };
        const incremental_path = info.snapshotArchiveName();
        const manifest, const status_cache = try insertFromSnapshotArchive(
            allocator,
            logger,
            rooted_db,
            incremental_path.constSlice(),
            info.slotAndHash(),
            .{ .snapshot_type = .incremental, .put_accounts = !db_has_entries },
        );
        break :blk .{ manifest, status_cache };
    };
    errdefer if (maybe_incremental_manifest) |manifest| manifest.deinit(allocator);
    errdefer if (maybe_incremental_status_cache) |status_cache| status_cache.deinit(allocator);

    const combined_manifest: FullAndIncrementalManifest = .{
        .full = full_manifest,
        .incremental = maybe_incremental_manifest,
    };

    const collapsed_manifest = if (load_options.metadata_only)
        try combined_manifest.collapse(allocator)
    else
        // TODO: validate snapshot: accounts_db.loadWithDefaults
        try combined_manifest.collapse(allocator);
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

    // validate the status cache

    const status_cache: StatusCache = .{
        // TODO: is this correct?
        .bank_slot_deltas = try std.mem.concat(
            allocator,
            sig.accounts_db.snapshot.data.BankSlotDelta,
            &.{
                full_status_cache.bank_slot_deltas,
                if (maybe_incremental_status_cache) |sc| sc.bank_slot_deltas else &.{},
            },
        ),
    };
    errdefer allocator.free(status_cache.bank_slot_deltas);

    const slot_history = blk: {
        const account = (try rooted_db.get(allocator, sig.runtime.sysvar.SlotHistory.ID)) orelse return error.PubkeyNotInIndex;
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
        "  loaded snapshot archive in {}",
        .{std.fmt.fmtDuration(timer.read())},
    );

    const file = try std.fs.cwd().openFile(snapshot_path, .{ .mode = .read_only });
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

    // read version file
    {
        const tar_file: @TypeOf(tar_iter).File = while (true) {
            const tar_file = (try tar_iter.next()) orelse return error.MissingFile;
            if (tar_file.kind == .file) break tar_file;
        };

        if (!std.mem.eql(u8, tar_file.name, "version"))
            return error.UnexpectedFile;

        const expected_version = "1.2.0";
        var version: [expected_version.len]u8 = undefined;
        if ((try tar_file.reader().readAll(&version)) != version.len)
            return error.InvalidVersion;
        if (!std.mem.eql(u8, &version, expected_version)) {
            return error.InvalidVersion;
        }
    }

    // read manifest file
    const manifest = blk: {
        const inner_zone = tracy.Zone.init(@src(), .{ .name = "Snapshot.readManifest" });
        defer inner_zone.deinit();

        const tar_file: @TypeOf(tar_iter).File = while (true) {
            const tar_file = (try tar_iter.next()) orelse return error.MissingFile;
            if (tar_file.kind == .file) break tar_file;
        };

        const manifest_path = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{slot_and_hash.slot});
        if (!std.mem.eql(u8, tar_file.name, manifest_path.constSlice()))
            return error.UnexpectedFile;

        break :blk try Manifest.decodeFromBincode(allocator, tar_file.reader());
    };
    errdefer manifest.deinit(allocator);

    // read status cache
    const status_cache = blk: {
        const inner_zone = tracy.Zone.init(@src(), .{ .name = "Snapshot.readStatusCache" });
        defer inner_zone.deinit();

        const tar_file: @TypeOf(tar_iter).File = while (true) {
            const tar_file = (try tar_iter.next()) orelse return error.MissingFile;
            if (tar_file.kind == .file) break tar_file;
        };

        if (!std.mem.eql(u8, tar_file.name, "snapshots/status_cache"))
            return error.UnexpectedFile;

        break :blk try StatusCache.decodeFromBincode(allocator, tar_file.reader());
    };
    errdefer status_cache.deinit(allocator);

    // read account files
    const expected_account_files = manifest.accounts_db_fields.file_map.count();
    if (expected_account_files > 0 and options.put_accounts) {
        const inner_zone = tracy.Zone.init(@src(), .{ .name = "Snapshot.readAccountFiles" });
        defer inner_zone.deinit();

        rooted_db.beginTransaction();
        defer rooted_db.commitTransaction();

        var account_data_buf: std.ArrayListUnmanaged(u8) = .{};
        defer account_data_buf.deinit(allocator);

        const progress = std.Progress.start(.{});
        defer progress.end();

        var progress_node = progress.start("loading account files", expected_account_files);
        defer progress_node.end();

        var found_account_files: usize = 0;
        while (true) : (found_account_files += 1) {
            defer progress_node.completeOne();

            const tar_file: @TypeOf(tar_iter).File = (while (true) {
                const tar_file = (try tar_iter.next()) orelse break null;
                if (tar_file.kind == .file) break tar_file;
            }) orelse break;

            // Validate account file name
            if (!std.mem.startsWith(u8, tar_file.name, "accounts/"))
                return error.InvalidAccountFile;
            const split = std.mem.indexOf(u8, tar_file.name, ".") orelse
                return error.InvalidAccountFile;
            if (tar_file.name.len - 1 == split) return error.InvalidAccountFile;
            const slot = std.fmt.parseInt(u64, tar_file.name["accounts/".len..split], 10) catch
                return error.InvalidAccountFile;
            const id = std.fmt.parseInt(u32, tar_file.name[split + 1 ..], 10) catch
                return error.InvalidAccountFile;

            const info = manifest.accounts_db_fields.file_map.get(slot) orelse
                return error.InvalidAccountFile;
            if (info.id.toInt() != id)
                continue; // TODO: error?
            if (info.length > tar_file.size)
                return error.InvalidAccountFile;

            // read accounts from file
            var account_file_stream = std.io.limitedReader(tar_file.reader(), info.length);
            while (account_file_stream.bytes_left > 0) {
                const r = account_file_stream.reader();

                const header = r.readStructEndian(
                    extern struct {
                        write_version: u64,
                        data_len: u64,
                        pubkey: Pubkey,
                        lamports: u64,
                        rent_epoch: sig.core.Epoch,
                        owner: Pubkey,
                        executable: u64,
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
        }

        // TODO: figure out how to verify incremental snapshot count (is it collapsed?)
        switch (options.snapshot_type) {
            .incremental => {},
            .full => {
                if (found_account_files < expected_account_files)
                    return error.MissingFiles;
                if (found_account_files > expected_account_files)
                    return error.TooManyAccountFiles;
            },
        }
    }

    return .{ manifest, status_cache };
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
}
