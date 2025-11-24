const std = @import("std");
const sig = @import("../../sig.zig");
const tracy = @import("tracy");
const accountsdb = @import("../lib.zig");
const snapshot = @import("lib.zig");
const zstd = @import("zstd");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const ThreadPool = sig.sync.ThreadPool;
const Rooted = sig.accounts_db.Two.Rooted;
const features = sig.core.features;
const GenesisConfig = sig.core.GenesisConfig;
const FeatureSet = sig.core.features.Set;
const StatusCache = sig.accounts_db.snapshot.StatusCache;
const Manifest = sig.accounts_db.snapshot.Manifest;
const SnapshotFiles = sig.accounts_db.snapshot.SnapshotFiles;
const FullAndIncrementalManifest = sig.accounts_db.snapshot.FullAndIncrementalManifest;

const Logger = sig.trace.Logger("accountsdb.snapshot.load");

pub const LoadedSnapshot = struct {
    allocator: Allocator,
    combined_manifest: snapshot.FullAndIncrementalManifest,
    collapsed_manifest: snapshot.Manifest,
    genesis_config: GenesisConfig,

    pub fn deinit(self: *LoadedSnapshot) void {
        self.combined_manifest.deinit(self.allocator);
        self.collapsed_manifest.deinit(self.allocator);
        self.genesis_config.deinit(self.allocator);
    }

    pub fn featureSet(
        self: *LoadedSnapshot,
        allocator: Allocator,
        accounts_db: *sig.accounts_db.Two,
    ) !FeatureSet {
        const ancestors = self.collapsed_manifest.bank_fields.ancestors;

        var feature_set = FeatureSet.ALL_DISABLED;
        var inactive_iterator = feature_set.iterator(
            self.collapsed_manifest.bank_fields.slot,
            .inactive,
        );
        while (inactive_iterator.next()) |feature| {
            const feature_id = features.map.get(feature).key;
            if (try accounts_db.get(
                allocator,
                feature_id,
                &ancestors,
            )) |feature_account| {
                defer feature_account.deinit(allocator);
                if (try features.activationSlotFromAccount(feature_account)) |activation_slot| {
                    feature_set.setSlot(feature, activation_slot);
                }
            }
        }

        return feature_set;
    }
};

/// Similar to `loadSnapshot`, but avoids untar-ing the snapshot into files on disk.
/// If provided, populates a Rooted DB instance with the accounts if DB is empty.
pub fn loadSnapshot(
    allocator: Allocator,
    logger: Logger,
    snapshot_dir: std.fs.Dir,
    snapshot_files: SnapshotFiles,
    options: struct {
        // Where the genesis path lives.
        genesis_file_path: []const u8,
        // How and what to load from the snapshot files
        extract: union(enum) {
            /// Extract only the snapshot metadata (not the accounts)
            metadata_only,
            /// Extract the entire snapshot & insert accounts into the provided Rooted Db.
            entire_snapshot: *Rooted,
            /// Extract the entire snapshot & insert accounts into the provided Rooted Db.
            /// Also validates the lt hash of all accounts against the metadata lt hash.
            entire_snapshot_and_validate: *Rooted,
        },
    },
) !LoadedSnapshot {
    const zone = tracy.Zone.init(@src(), .{ .name = "loadSnapshot" });
    defer zone.deinit();

    // Read genesis before trying to load the snapshot
    logger.info().log("reading genesis...");

    const genesis_file_path = options.genesis_file_path;
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

    // For rooted.computeLtHash
    var pool: ThreadPool = .init(.{
        .max_threads = @intCast(@max(1, try std.Thread.getCpuCount())),
    });
    defer {
        pool.shutdown();
        pool.deinit();
    }

    // Unpack snapshots directly into Rooted.

    const maybe_rooted_db: ?*Rooted, //
    const validate_snapshot =
        switch (options.extract) {
            .metadata_only => .{ null, false },
            .entire_snapshot => |rooted_db| .{ rooted_db, false },
            .entire_snapshot_and_validate => |rooted_db| .{ rooted_db, true },
        };

    // Check if we should populate rooted_db with accounts.
    var db_has_entries = false;
    if (maybe_rooted_db) |rooted_db| {
        db_has_entries = rooted_db.count() > 0;
        if (db_has_entries) {
            logger.info().logf("db has entries, skipping insert from snapshot", .{});
        } else {
            logger.info().logf("db is empty - inserting from snapshot!", .{});
        }
    }

    const full_manifest: Manifest, //
    const full_status_cache: StatusCache = blk: {
        const full_zone = tracy.Zone.init(@src(), .{ .name = "insertFromSnapshot: full" });
        defer full_zone.deinit();

        const path = snapshot_files.full.snapshotArchiveName();
        break :blk try insertFromSnapshotArchive(
            allocator,
            logger,
            snapshot_dir,
            path.constSlice(),
            if (db_has_entries) null else maybe_rooted_db,
            .{ .slot = snapshot_files.full.slot, .hash = snapshot_files.full.hash },
        );
    };
    errdefer full_manifest.deinit(allocator);
    defer full_status_cache.deinit(allocator);

    if (validate_snapshot) blk: {
        // Due to Rooted DB only storing latest accounts, the accounts lt hash can only be verified
        // if the incremental snapshot hasnt been inserted yet:
        if (snapshot_files.incremental() != null and !db_has_entries)
            break :blk; // incremental exists & db was already populated

        var timer = try std.time.Timer.start();
        logger.info().logf(
            "verifying snapshot accounts_lt_hash: {}",
            .{full_manifest.bank_extra.accounts_lt_hash.checksum()},
        );
        defer logger.info().logf(
            "LtHash verified in {}",
            .{std.fmt.fmtDuration(timer.read())},
        );

        const lt_hash = try maybe_rooted_db.?.computeLtHash(allocator, &pool);
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
    const maybe_incremental_status_cache: ?StatusCache = blk: {
        const incr_zone =
            tracy.Zone.init(@src(), .{ .name = "Rooted.insertFromSnapshot: incremental" });
        defer incr_zone.deinit();

        const info = snapshot_files.incremental() orelse break :blk .{ null, null };
        const incremental_path = info.snapshotArchiveName();
        break :blk try insertFromSnapshotArchive(
            allocator,
            logger,
            snapshot_dir,
            incremental_path.constSlice(),
            maybe_rooted_db, // incremental doesnt have too many accounts to overwrite
            info.slotAndHash(),
        );
    };
    errdefer if (maybe_incremental_manifest) |manifest| manifest.deinit(allocator);
    defer if (maybe_incremental_status_cache) |status_cache| status_cache.deinit(allocator);

    if (maybe_incremental_manifest) |*inc_manifest| {
        if (validate_snapshot) {
            var timer = try std.time.Timer.start();
            logger.info().logf(
                "verifying incremental accounts_lt_hash: {}",
                .{inc_manifest.bank_extra.accounts_lt_hash.checksum()},
            );
            defer logger.info().logf(
                "LtHash verified in {}",
                .{std.fmt.fmtDuration(timer.read())},
            );

            const lt_hash = try maybe_rooted_db.?.computeLtHash(allocator, &pool);
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

    logger.info().log("validating bank...");

    try collapsed_manifest.bank_fields.validate(&genesis_config);

    const rooted_db = maybe_rooted_db orelse {
        logger.info().log("metadata loading done...");

        return .{
            .allocator = allocator,
            .combined_manifest = combined_manifest,
            .collapsed_manifest = collapsed_manifest,
            .genesis_config = genesis_config,
        };
    };

    // validate the status cache of the latest slot

    // doesnt take ownership.
    const status_cache = maybe_incremental_status_cache orelse full_status_cache;

    const slot_history = blk: {
        const account = (try rooted_db.get(allocator, sig.runtime.sysvar.SlotHistory.ID)) orelse
            return error.PubkeyNotInIndex;
        defer account.deinit(allocator);

        var fbs = std.io.fixedBufferStream(account.data);
        break :blk try sig.bincode.read(
            allocator,
            sig.runtime.sysvar.SlotHistory,
            fbs.reader(),
            .{},
        );
    };
    defer slot_history.deinit(allocator);

    try status_cache.validate(allocator, collapsed_manifest.bank_fields.slot, &slot_history);

    logger.info().log("accounts-db setup done...");

    return .{
        .allocator = allocator,
        .combined_manifest = combined_manifest,
        .collapsed_manifest = collapsed_manifest,
        .genesis_config = genesis_config,
    };
}

fn insertFromSnapshotArchive(
    allocator: std.mem.Allocator,
    logger: Logger,
    snapshot_dir: std.fs.Dir,
    snapshot_path: []const u8,
    maybe_rooted_db: ?*Rooted,
    slot_and_hash: sig.core.hash.SlotAndHash,
) !struct { Manifest, StatusCache } {
    const zone = tracy.Zone.init(@src(), .{ .name = "insertFromSnapshotArchive" });
    defer zone.deinit();

    var timer = try std.time.Timer.start();
    logger.info().logf("loading snapshot archive: {s}", .{snapshot_path});
    defer logger.info().logf(
        "loaded snapshot archive in {}",
        .{std.fmt.fmtDuration(timer.read())},
    );

    if (maybe_rooted_db) |rooted_db| rooted_db.beginTransaction();
    defer if (maybe_rooted_db) |rooted_db| rooted_db.commitTransaction();

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

            if (maybe_manifest.?.accounts_db_fields.slot != slot_and_hash.slot)
                return error.MismatchingManifestSlot;
            if (!maybe_manifest.?.bank_extra.accounts_lt_hash.checksum().eql(slot_and_hash.hash))
                return error.MismatchingManifestAccountsLtHash;

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

            // No DB means no accounts should be inserted (skip processing account files).
            const rooted_db = maybe_rooted_db orelse break;
            rooted_db.largest_rooted_slot = maybe_manifest.?.accounts_db_fields.slot;

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

    var src_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer src_dir.close();

    var snapshot_files = try snapshot.data.SnapshotFiles.find(allocator, src_dir);
    const snapshot_filename = snapshot_files.full.snapshotArchiveName();
    const incremental_filename = snapshot_files.incremental().?.snapshotArchiveName();

    var snapshot_dir = try std.fs.cwd().makeOpenPath(path, .{ .iterate = true });
    defer snapshot_dir.close();

    try std.testing.expectError(
        error.SnapshotsNotFoundAndNoGossipService,
        sig.accounts_db.snapshot.download.getOrDownloadSnapshotFiles(
            allocator,
            .noop,
            snapshot_dir,
            .{ .max_number_of_download_attempts = 0 },
        ),
    );

    try src_dir.copyFile(snapshot_filename.slice(), tmp.dir, snapshot_filename.slice(), .{});
    try src_dir.copyFile(incremental_filename.slice(), tmp.dir, incremental_filename.slice(), .{});

    snapshot_files = try sig.accounts_db.snapshot.download.getOrDownloadSnapshotFiles(
        allocator,
        .noop,
        snapshot_dir,
        .{ .max_number_of_download_attempts = 0 },
    );

    try std.testing.expectError(error.FileNotFound, loadSnapshot(
        allocator,
        .noop,
        snapshot_dir,
        snapshot_files,
        .{
            .genesis_file_path = sig.TEST_DATA_DIR ++ "/WRONG-genesis.bin",
            .extract = .metadata_only,
        },
    ));

    var metadata_only = try loadSnapshot(
        allocator,
        .noop,
        snapshot_dir,
        snapshot_files,
        .{
            .genesis_file_path = sig.TEST_DATA_DIR ++ "/genesis.bin",
            .extract = .metadata_only,
        },
    );
    metadata_only.deinit();

    const rooted_path = try std.fs.path.joinZ(allocator, &.{ path, "accounts.db" });
    defer allocator.free(rooted_path);

    var rooted_db: Rooted = try .init(rooted_path);
    defer rooted_db.deinit();

    var loaded_snapshot = try loadSnapshot(
        allocator,
        .noop,
        snapshot_dir,
        snapshot_files,
        .{
            .genesis_file_path = sig.TEST_DATA_DIR ++ "/genesis.bin",
            .extract = .{ .entire_snapshot_and_validate = &rooted_db },
        },
    );
    loaded_snapshot.deinit();
}
