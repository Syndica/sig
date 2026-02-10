//! logic for downloading a snapshot

const std = @import("std");
const sig = @import("../../sig.zig");
const tracy = @import("tracy");

const GossipService = sig.gossip.GossipService;
const GossipTable = sig.gossip.GossipTable;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const SignedGossipData = sig.gossip.data.SignedGossipData;
const SlotAndHash = sig.core.hash.SlotAndHash;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;

const SnapshotFiles = sig.accounts_db.snapshot.SnapshotFiles;
const FullAndIncrementalManifest = sig.accounts_db.snapshot.FullAndIncrementalManifest;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshot.data.IncrementalSnapshotFileInfo;
const FullSnapshotFileInfo = sig.accounts_db.snapshot.data.FullSnapshotFileInfo;

const parallelUnpackZstdTarBall = sig.accounts_db.snapshot.parallelUnpackZstdTarBall;

// NOTE: this also represents the interval at which progress updates are issued
const DOWNLOAD_WARMUP_TIME = sig.time.Duration.fromSecs(20);

const BYTE_PER_KIB = 1024;
const BYTE_PER_MIB = 1024 * BYTE_PER_KIB;
const BYTE_PER_GIB = 1024 * BYTE_PER_MIB;

/// The scope for the logger used in this file.
const Logger = sig.trace.Logger("accountsdb.download");

/// Analogous to [PeerSnapshotHash](https://github.com/anza-xyz/agave/blob/f868aa38097094e4fb78a885b6fb27ce0e43f5c7/validator/src/bootstrap.rs#L342)
pub const PeerSnapshotHash = struct {
    contact_info: ThreadSafeContactInfo,
    full_snapshot: SlotAndHash,
    inc_snapshot: ?SlotAndHash,
};

pub const PeerSearchResult = struct {
    is_me_count: usize = 0,
    invalid_shred_version: usize = 0,
    no_rpc_count: usize = 0,
    no_snapshot_hashes_count: usize = 0,
    is_blacklist: usize = 0,
    is_valid: usize = 0,
    untrusted_full_snapshot_count: usize = 0,
    untrusted_inc_snapshot_count: usize = 0,

    pub fn format(
        self: PeerSearchResult,
        comptime fmt_str: []const u8,
        fmt_options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = fmt_str;
        _ = fmt_options;

        inline for (@typeInfo(PeerSearchResult).@"struct".fields) |field| {
            if (@field(self, field.name) != 0) {
                try writer.print("{s}: {d} ", .{ field.name, @field(self, field.name) });
            }
        }
    }
};

/// finds valid contact infos which we can download a snapshot from.
/// valid contact infos are:
/// - not me
/// - shred version matches
/// - rpc socket is enabled
/// - snapshot hash is available
/// result is populated inside valid_peers (which is cleared at the beginning)
fn findPeersToDownloadFrom(
    allocator: std.mem.Allocator,
    table: *const GossipTable,
    contact_infos: []const ThreadSafeContactInfo,
    my_shred_version: usize,
    my_pubkey: Pubkey,
    blacklist: []const Pubkey,
    trusted_validators: ?[]const Pubkey,
) !struct { []PeerSnapshotHash, PeerSearchResult } {
    var valid_peers: std.array_list.Managed(PeerSnapshotHash) = try .initCapacity(
        allocator,
        contact_infos.len,
    );
    errdefer valid_peers.deinit();

    const TrustedMapType = std.AutoHashMap(
        SlotAndHash, // full snapshot hash
        std.AutoHashMap(SlotAndHash, void), // set of incremental snapshots
    );
    var maybe_trusted_snapshot_hashes: ?TrustedMapType = if (trusted_validators != null)
        TrustedMapType.init(allocator)
    else
        null;
    defer {
        if (maybe_trusted_snapshot_hashes) |*ts| ts.deinit();
    }

    if (maybe_trusted_snapshot_hashes) |*trusted_snapshot_hashes| {
        // populate with the hashes of trusted validators
        var trusted_count: usize = 0;
        // SAFE: the perf is safe because maybe_ is non null only if trusted_validators is non-null
        for (trusted_validators.?) |trusted_validator| {
            const gossip_data = table.getData(.{
                .SnapshotHashes = trusted_validator,
            }) orelse continue;
            const trusted_hashes = gossip_data.SnapshotHashes;
            trusted_count += 1;

            // track the full and all incremental hashes
            const r = try trusted_snapshot_hashes.getOrPut(trusted_hashes.full);
            const inc_map_ptr = r.value_ptr;
            if (!r.found_existing) {
                inc_map_ptr.* = std.AutoHashMap(SlotAndHash, void).init(allocator);
            }
            for (trusted_hashes.incremental.getSlice()) |inc_hash| {
                try inc_map_ptr.put(inc_hash, {});
            }
        }
    }

    var result = PeerSearchResult{};
    search_loop: for (contact_infos) |peer_contact_info| {
        const is_me = peer_contact_info.pubkey.equals(&my_pubkey);
        if (is_me) {
            result.is_me_count += 1;
            continue;
        }

        const matching_shred_version =
            my_shred_version == peer_contact_info.shred_version or
            my_shred_version == 0;
        if (!matching_shred_version) {
            result.invalid_shred_version += 1;
            continue;
        }
        if (peer_contact_info.rpc_addr == null) {
            result.no_rpc_count += 1;
            continue;
        }
        const gossip_data = table.getData(.{ .SnapshotHashes = peer_contact_info.pubkey }) orelse {
            result.no_snapshot_hashes_count += 1;
            continue;
        };
        const snapshot_hashes = gossip_data.SnapshotHashes;

        var max_inc_hash: ?SlotAndHash = null;
        for (snapshot_hashes.incremental.getSlice()) |inc_hash| {
            if (max_inc_hash == null or inc_hash.slot > max_inc_hash.?.slot) {
                max_inc_hash = inc_hash;
            }
        }

        // dont try to download from a slow peer
        for (blacklist) |black_list_peers| {
            if (black_list_peers.equals(&peer_contact_info.pubkey)) {
                result.is_blacklist += 1;
                continue :search_loop;
            }
        }

        // check if we have a trusted snapshot
        if (maybe_trusted_snapshot_hashes) |trusted_snapshot_hashes| {
            // full snapshot must be trusted
            if (trusted_snapshot_hashes.getEntry(snapshot_hashes.full)) |entry| {
                // if we have an incremental snapshot
                if (max_inc_hash) |inc_snapshot| {
                    // it should be trusted too
                    if (!entry.value_ptr.contains(inc_snapshot)) {
                        result.untrusted_inc_snapshot_count += 1;
                        continue;
                    }
                }
                // no incremental snapshot, thats ok
            } else {
                result.untrusted_full_snapshot_count += 1;
                continue;
            }
        }

        valid_peers.appendAssumeCapacity(.{
            .contact_info = peer_contact_info,
            .full_snapshot = snapshot_hashes.full,
            .inc_snapshot = max_inc_hash,
        });
    }
    result.is_valid = valid_peers.items.len;

    return .{ try valid_peers.toOwnedSlice(), result };
}

const Mode = enum { incremental, full };

fn downloadInfo(
    allocator: std.mem.Allocator,
    comptime mode: Mode,
    peer: PeerSnapshotHash,
    full_snapshot_slot: switch (mode) {
        .incremental => Slot,
        .full => @TypeOf(null),
    },
) !?struct {
    std.Uri,
    switch (mode) {
        .incremental => IncrementalSnapshotFileInfo,
        .full => FullSnapshotFileInfo,
    }.SnapshotArchiveNameStr,
    []const u8,
} {
    const rpc_socket = peer.contact_info.rpc_addr orelse return null;
    const snapshot = switch (mode) {
        .incremental => peer.inc_snapshot orelse return null,
        .full => peer.full_snapshot,
    };

    const snapshot_file_name = switch (mode) {
        .incremental => IncrementalSnapshotFileInfo.snapshotArchiveName(.{
            .base_slot = full_snapshot_slot,
            .slot = snapshot.slot,
            .hash = snapshot.hash,
        }),
        .full => FullSnapshotFileInfo.snapshotArchiveName(.{
            .slot = snapshot.slot,
            .hash = snapshot.hash,
        }),
    };

    const url = try std.fmt.allocPrint(
        allocator,
        "http://{}/{s}",
        .{ rpc_socket, snapshot_file_name.constSlice() },
    );

    const uri = std.Uri.parse(url) catch unreachable; // we created this url from sanitised params

    return .{ uri, snapshot_file_name, url };
}

fn downloadSnapshotWithRetry(
    tmp_allocator: std.mem.Allocator,
    logger: Logger,
    comptime mode: Mode,
    gossip: *GossipService,
    output_dir: std.fs.Dir,
    full_snapshot_slot: switch (mode) {
        .incremental => Slot,
        .full => @TypeOf(null),
    },
    bad_peers: *std.array_list.Managed(Pubkey),
    maybe_trusted_validators: ?[]const Pubkey,
    min_mb_per_sec: usize,
    max_attempts: u64,
    maybe_max_time: ?sig.time.Duration,
) !struct { Slot, std.fs.File } {
    const zone = tracy.Zone.init(@src(), .{
        .name = std.fmt.comptimePrint("downloadSnapshotWithRetry ({})", .{mode}),
    });
    defer zone.deinit();

    const max_time = maybe_max_time orelse sig.time.Duration{ .ns = std.math.maxInt(u64) };

    const download_buffer = try tmp_allocator.alloc(u8, 1 * BYTE_PER_MIB);
    defer tmp_allocator.free(download_buffer);

    var arena = std.heap.ArenaAllocator.init(tmp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var timer = try std.time.Timer.start();
    var dl_attempts: u64 = 0;

    return get_peers: while (timer.read() < max_time.ns and dl_attempts < max_attempts) {
        defer _ = arena.reset(.retain_capacity);

        // query our gossip table for peers we can download from
        const peers = blk: {
            const gossip_table, var gossip_table_lg = gossip.gossip_table_rw.readWithLock();
            defer gossip_table_lg.unlock();

            // TODO: maybe make this bigger? or dynamic?
            var contact_info_buf: [1024]ThreadSafeContactInfo = undefined;
            const contacts = gossip_table.getThreadSafeContactInfos(&contact_info_buf, 0);

            const peers, const result = try findPeersToDownloadFrom(
                allocator,
                gossip_table,
                contacts,
                gossip.my_contact_info.shred_version,
                gossip.my_contact_info.pubkey,
                bad_peers.items,
                maybe_trusted_validators,
            );

            logger.info().logf("searched for snapshot peers: {}", .{result});

            break :blk peers;
        };

        // TODO: To download quickly, we should probably:
        // 1) try to rank peers, and try "best" first (e.g. order by latency)
        // 2) configure timeouts to be lower

        // try to download from all eligible peers
        downloads: for (peers) |peer| {
            const uri, const file_name, const url = try downloadInfo(
                allocator,
                mode,
                peer,
                full_snapshot_slot,
            ) orelse continue :downloads;
            defer allocator.free(url);
            defer dl_attempts += 1;

            logger.info().logf("Attempting snapshot download from {}", .{uri});
            const file = downloadFile(
                allocator,
                logger,
                uri,
                output_dir,
                file_name.constSlice(),
                min_mb_per_sec,
                download_buffer,
            ) catch |err| {
                logger.info().logf("failed to download snapshot: {}", .{err});
                switch (err) {
                    error.TooSlow,
                    error.BadStatus,
                    error.ConnectionRefused,
                    error.ConnectionTimedOut,
                    => try bad_peers.append(peer.contact_info.pubkey),
                    else => {},
                }
                continue :downloads;
            };

            break :get_peers .{ peer.full_snapshot.slot, file };
        } else {
            if (peers.len == 0) {
                // We don't have peers yet, wait for gossip table population
                std.Thread.sleep(1 * std.time.ns_per_s);
            }
            continue :get_peers; // Failed to download from all peers, getting new peers
        }
    } else error.UnableToDownloadSnapshot;
}

/// downloads full and incremental snapshots from peers found in gossip.
/// note: gossip_service must be running.
pub fn downloadSnapshotsFromGossip(
    allocator: std.mem.Allocator,
    logger: Logger,
    /// if null, then we trust any peer for snapshot download
    maybe_trusted_validators: ?[]const Pubkey,
    gossip: *GossipService,
    output_dir: std.fs.Dir,
    min_mb_per_sec: usize,
    max_number_of_download_attempts: u64,
    timeout: ?sig.time.Duration,
) !struct { std.fs.File, ?std.fs.File } {
    const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb downloadSnapshotsFromGossip" });
    defer zone.deinit();

    var bad_peers: std.array_list.Managed(Pubkey) = .init(allocator);
    defer bad_peers.deinit();

    const full_slot, const full_file = try downloadSnapshotWithRetry(
        allocator,
        logger,
        .full,
        gossip,
        output_dir,
        null,
        &bad_peers,
        maybe_trusted_validators,
        min_mb_per_sec,
        max_number_of_download_attempts,
        timeout,
    );

    _, const incr_file = downloadSnapshotWithRetry(
        allocator,
        logger,
        .incremental,
        gossip,
        output_dir,
        full_slot,
        &bad_peers,
        maybe_trusted_validators,
        min_mb_per_sec,
        max_number_of_download_attempts,
        timeout,
    ) catch |err| {
        logger.warn().logf("Failed to download incremental snapshot - {}", .{err});
        return .{ full_file, null };
    };

    return .{ full_file, incr_file };
}

/// downloads a file from a url into output_dir/filename
/// returns error if it fails.
/// the main errors include {HeaderRequestFailed, NoContentLength, TooSlow} or a curl-related error
fn downloadFile(
    allocator: std.mem.Allocator,
    logger: Logger,
    uri: std.Uri,
    output_dir: std.fs.Dir,
    filename: []const u8,
    maybe_min_mib_per_second: ?usize,
    /// Used as an intermediate buffer to read the response body before writing to disk.
    /// Recommended size is at least 1 MiB for payloads which are expected to occupy 1 GiB or more.
    download_buffer: []u8,
) !std.fs.File {
    const zone = tracy.Zone.init(@src(), .{ .name = "downloadFile" });
    defer zone.deinit();

    var http_client: std.http.Client = .{ .allocator = allocator };
    defer http_client.deinit();

    var server_header_buffer: [4096]u8 = undefined;
    var request = try http_client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
    });
    defer request.deinit();

    try request.send();
    try request.finish();
    try request.wait();

    if (request.response.status != .ok) return error.BadStatus;

    const download_size = request.response.content_length orelse
        return error.NoContentLength;

    if (download_buffer.len < 1 * BYTE_PER_MIB and
        download_size >= BYTE_PER_GIB)
    {
        logger.warn().logf("Downloading file of size {} using a buffer of size {};" ++
            " recommended buffer size for such a payload is at least 1 MiB.", .{
            std.fmt.fmtIntSizeBin(download_size),
            std.fmt.fmtIntSizeBin(download_buffer.len),
        });
    }

    const output_file: std.fs.File = output_dir.createFile(
        filename,
        .{ .exclusive = true },
    ) catch |err| switch (err) {
        error.PathAlreadyExists => {
            logger.info().logf("snapshot {s} already on disk, skipping download", .{filename});
            return try output_dir.openFile(filename, .{});
        },
        else => return err,
    };
    errdefer {
        output_file.close();
        output_dir.deleteFile(filename) catch logger.warn().logf(
            "failed to delete snapshot file {s}, which failed to download",
            .{filename},
        );
    }
    try output_file.setEndPos(download_size);
    var buffered_out = std.io.bufferedWriter(output_file.writer());

    var total_bytes_read: u64 = 0;
    var lap_timer = sig.time.Timer.start();
    var full_timer = sig.time.Timer.start();
    var checked_speed = false;

    while (true) {
        const max_bytes_to_read = @min(download_buffer.len, download_size - total_bytes_read);
        const bytes_read = try request.readAll(download_buffer[0..max_bytes_to_read]);
        total_bytes_read += bytes_read;

        try buffered_out.writer().writeAll(download_buffer[0..bytes_read]);
        if (total_bytes_read == download_size) break;
        std.debug.assert(total_bytes_read < download_size);

        const elapsed_since_start = full_timer.read();
        const elapsed_since_prev_lap = lap_timer.read();
        if (elapsed_since_prev_lap.asNanos() <= DOWNLOAD_WARMUP_TIME.asNanos()) continue;
        // reset at the end of the iteration, after the update, right before the next read & write.
        defer lap_timer.reset();

        const total_bytes_left = download_size - total_bytes_read;
        const time_left_ns = total_bytes_left * (elapsed_since_start.asNanos() / total_bytes_read);
        logger.info().logf(
            "[download progress]: {d}% done ({:.4}/s - {:.4}/{:.4}) (time left: {d})",
            .{
                total_bytes_read * 100 / download_size,
                std.fmt.fmtIntSizeBin(total_bytes_read / elapsed_since_start.asSecs()),
                std.fmt.fmtIntSizeBin(total_bytes_read),
                std.fmt.fmtIntSizeBin(download_size),
                std.fmt.fmtDuration(time_left_ns),
            },
        );

        if (checked_speed) continue;
        checked_speed = true;

        const min_bytes_per_second = BYTE_PER_MIB * (maybe_min_mib_per_second orelse continue);
        const actual_bytes_per_second = total_bytes_read / elapsed_since_start.asSecs();

        if (actual_bytes_per_second < min_bytes_per_second) {
            // not fast enough => abort
            logger.info().logf(
                "[download progress]: speed is too slow ({:.4}/s) -- disconnecting",
                .{std.fmt.fmtIntSizeBin(actual_bytes_per_second)},
            );
            return error.TooSlow;
        }

        logger.info().logf(
            "[download progress]: speed is ok ({:.4}/s) -- maintaining",
            .{std.fmt.fmtIntSizeBin(actual_bytes_per_second)},
        );
    }

    try buffered_out.flush();
    return output_file;
}

pub fn getOrDownloadSnapshotFiles(
    allocator: std.mem.Allocator,
    logger: Logger,
    snapshot_dir: std.fs.Dir,
    options: struct {
        gossip_service: ?*GossipService = null,
        force_new_snapshot_download: bool = false,
        min_snapshot_download_speed_mbs: usize = 20,
        trusted_validators: ?[]const Pubkey = null,
        max_number_of_download_attempts: u64,
        download_timeout: ?sig.time.Duration = null,
    },
) !SnapshotFiles {
    var maybe_snapshot_files =
        SnapshotFiles.find(allocator, snapshot_dir) catch |err| switch (err) {
            error.NoFullSnapshotFileInfoFound => null,
            else => |e| return e,
        };

    if (maybe_snapshot_files == null or options.force_new_snapshot_download) {
        var timer = try std.time.Timer.start();
        logger.info().log("downloading snapshot");
        defer logger.info().logf(
            "  downloaded snapshot in {}",
            .{std.fmt.fmtDuration(timer.read())},
        );

        const gossip_service = options.gossip_service orelse {
            return error.SnapshotsNotFoundAndNoGossipService;
        };

        const full, const maybe_inc = try downloadSnapshotsFromGossip(
            allocator,
            logger,
            options.trusted_validators,
            gossip_service,
            snapshot_dir,
            @intCast(options.min_snapshot_download_speed_mbs),
            options.max_number_of_download_attempts,
            options.download_timeout,
        );
        defer full.close();
        defer if (maybe_inc) |inc| inc.close();

        maybe_snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);
    }

    return maybe_snapshot_files.?;
}

pub fn getOrDownloadAndUnpackSnapshot(
    allocator: std.mem.Allocator,
    logger: Logger,
    /// dir which stores the snapshot files to unpack into {validator_dir}/accounts_db
    snapshot_path: []const u8,
    options: struct {
        /// gossip service is not needed when loading from an existing snapshot.
        /// but when we need to download a new snapshot (force_new_snapshot_download flag),
        /// we need the gossip service.
        gossip_service: ?*GossipService = null,
        force_new_snapshot_download: bool = false,
        force_unpack_snapshot: bool = false,
        num_threads_snapshot_unpack: u16 = 0,
        min_snapshot_download_speed_mbs: usize = 20,
        trusted_validators: ?[]const Pubkey = null,
        max_number_of_download_attempts: u64,
        download_timeout: ?sig.time.Duration = null,
    },
) !struct { FullAndIncrementalManifest, SnapshotFiles } {
    const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb getOrDownloadAndUnpackSnapshot" });
    defer zone.deinit();

    const force_unpack_snapshot = options.force_unpack_snapshot;
    const force_new_snapshot_download = options.force_new_snapshot_download;
    var n_threads_snapshot_unpack: u32 = options.num_threads_snapshot_unpack;
    if (n_threads_snapshot_unpack == 0) {
        const n_cpus = @as(u32, @truncate(try std.Thread.getCpuCount()));
        n_threads_snapshot_unpack = n_cpus / 2;
    }

    // check if we need to download a fresh snapshot
    var should_delete_dir = false;
    if (std.fs.cwd().openDir(snapshot_path, .{ .iterate = true })) |dir| {
        defer std.posix.close(dir.fd);
        if (force_new_snapshot_download) {
            // clear old snapshots, if we will download a new one
            should_delete_dir = true;
        }
    } else |_| {}

    if (should_delete_dir) {
        logger.info().log("deleting snapshot dir...");
        std.fs.cwd().deleteTree(snapshot_path) catch |err| {
            logger.warn().logf("failed to delete snapshot directory: {}", .{err});
        };
    }

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_path, .{
        .iterate = true,
    });
    defer snapshot_dir.close();

    // download a new snapshot if required
    const snapshot_exists = blk: {
        _ = SnapshotFiles.find(allocator, snapshot_dir) catch |err| switch (err) {
            error.NoFullSnapshotFileInfoFound => break :blk false,
            else => |e| return e,
        };
        break :blk true;
    };
    const should_download_snapshot = force_new_snapshot_download or !snapshot_exists;
    if (should_download_snapshot) {
        const min_mb_per_sec = options.min_snapshot_download_speed_mbs;
        const gossip_service = options.gossip_service orelse {
            return error.SnapshotsNotFoundAndNoGossipService;
        };

        const full, const maybe_inc = try downloadSnapshotsFromGossip(
            allocator,
            .from(logger),
            options.trusted_validators,
            gossip_service,
            snapshot_dir,
            @intCast(min_mb_per_sec),
            options.max_number_of_download_attempts,
            options.download_timeout,
        );
        defer full.close();
        defer if (maybe_inc) |inc| inc.close();
    }

    const valid_accounts_folder = blk: {
        // NOTE: we only need to check this if we are *not* unpacking a fresh snapshot
        if (force_unpack_snapshot or !snapshot_exists) break :blk false;

        // do a quick sanity check on the number of files in accounts/
        // NOTE: this is sometimes the case that you unpacked only a portion
        // of the snapshot
        var accounts_dir = snapshot_dir.openDir("accounts", .{}) catch |err| switch (err) {
            // accounts folder doesnt exist, so its invalid
            error.FileNotFound => break :blk false,
            else => return err,
        };
        defer accounts_dir.close();
        const n_account_files = (try accounts_dir.stat()).size;
        if (n_account_files <= 100) {
            // if the accounts/ directory is empty, then we should unpack
            // the snapshot to get correct state
            logger.info().log("empty accounts/ directory found, will unpack snapshot...");
            break :blk false;
        } else {
            logger.info().log("accounts/ directory found, will not unpack snapshot...");
            break :blk true;
        }
    };

    var timer = try std.time.Timer.start();
    const should_unpack_snapshot =
        force_unpack_snapshot or
        !snapshot_exists or
        !valid_accounts_folder;
    if (should_unpack_snapshot) {
        const snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);
        if (snapshot_files.incremental_info == null) {
            logger.info().log("no incremental snapshot found");
        }
        errdefer {
            // if something goes wrong while unpacking, delete the accounts/ directory
            // so we unpack the full snapshot the next time we run this method. its
            // hard to debug with partially unpacked snapshots.
            //
            // NOTE: if we didnt do this, we would try to startup with a incomplete
            // accounts/ directory the next time we ran the code - see `valid_acounts_folder`.
            snapshot_dir.deleteTree("accounts") catch |err| {
                std.debug.print("failed to delete accounts/ dir: {}\n", .{err});
            };
        }

        logger.info().log("unpacking snapshots...");

        timer.reset();
        logger.info().logf(
            "unpacking {s}...",
            .{snapshot_files.full.snapshotArchiveName().constSlice()},
        );
        {
            const archive_file = try snapshot_dir.openFile(
                snapshot_files.full.snapshotArchiveName().constSlice(),
                .{},
            );
            defer archive_file.close();
            try parallelUnpackZstdTarBall(
                allocator,
                .from(logger),
                archive_file,
                snapshot_dir,
                n_threads_snapshot_unpack,
                true,
            );
        }
        logger.info().logf("unpacked snapshot in {s}", .{std.fmt.fmtDuration(timer.read())});

        // TODO: can probs do this in parallel with full snapshot
        if (snapshot_files.incremental()) |incremental_snapshot| {
            timer.reset();
            logger.info().logf(
                "unpacking {s}...",
                .{incremental_snapshot.snapshotArchiveName().constSlice()},
            );

            const archive_file = try snapshot_dir.openFile(
                incremental_snapshot.snapshotArchiveName().constSlice(),
                .{},
            );
            defer archive_file.close();

            try parallelUnpackZstdTarBall(
                allocator,
                .from(logger),
                archive_file,
                snapshot_dir,
                n_threads_snapshot_unpack,
                false,
            );
            logger.info().logf("unpacked snapshot in {s}", .{std.fmt.fmtDuration(timer.read())});
        }
    } else {
        logger.info().log("not unpacking snapshot...");
    }

    timer.reset();
    logger.info().log("reading snapshot metadata...");
    const snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);
    const snapshot_fields = try FullAndIncrementalManifest.fromFiles(
        allocator,
        .from(logger),
        snapshot_dir,
        snapshot_files,
    );
    logger.info().logf("read snapshot metdata in {s}", .{std.fmt.fmtDuration(timer.read())});

    return .{ snapshot_fields, snapshot_files };
}

test "accounts_db.download: test remove untrusted peers" {
    const allocator = std.testing.allocator;
    var table = try GossipTable.init(allocator, allocator);
    defer table.deinit();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const my_shred_version: usize = 19;
    const my_pubkey = Pubkey.initRandom(random);

    const contact_infos: []ThreadSafeContactInfo = try allocator.alloc(ThreadSafeContactInfo, 10);
    defer allocator.free(contact_infos);

    for (contact_infos) |*ci| {
        var lci = LegacyContactInfo.default(Pubkey.initRandom(random));
        lci.rpc.setPort(19); // no long unspecified = valid
        ci.* = ThreadSafeContactInfo.fromLegacyContactInfo(lci);
        ci.shred_version = 19; // matching shred version
    }

    var trusted_validators = try std.array_list.Managed(Pubkey).initCapacity(allocator, 10);
    defer trusted_validators.deinit();

    for (contact_infos) |ci| {
        const kp = KeyPair.generate();
        var snapshot_hashes = sig.gossip.data.SnapshotHashes.initRandom(random);
        snapshot_hashes.from = ci.pubkey;
        const data = SignedGossipData.initSigned(&kp, .{ .SnapshotHashes = snapshot_hashes });
        try trusted_validators.append(ci.pubkey);
        _ = try table.insert(data, 0);
    }

    var peers, _ = try findPeersToDownloadFrom(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null, // no trusted validators
    );
    try std.testing.expectEqual(peers.len, 10);
    allocator.free(peers);

    peers, _ = try findPeersToDownloadFrom(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        trusted_validators.items,
    );
    try std.testing.expectEqual(peers.len, 10);
    allocator.free(peers);

    _ = trusted_validators.pop();
    _ = trusted_validators.pop();

    peers, _ = try findPeersToDownloadFrom(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        trusted_validators.items,
    );
    try std.testing.expectEqual(peers.len, 8);
    allocator.free(peers);
}

test "accounts_db.download: test finding peers" {
    const allocator = std.testing.allocator;
    var table = try GossipTable.init(allocator, allocator);
    defer table.deinit();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const my_shred_version: usize = 19;
    const my_pubkey = Pubkey.initRandom(random);

    const contact_infos: []ThreadSafeContactInfo = try allocator.alloc(ThreadSafeContactInfo, 10);
    defer allocator.free(contact_infos);

    for (contact_infos) |*ci| {
        var lci = LegacyContactInfo.default(Pubkey.initRandom(random));
        lci.rpc.setPort(19); // no long unspecified = valid
        ci.* = ThreadSafeContactInfo.fromLegacyContactInfo(lci);
        ci.shred_version = 19; // matching shred version
    }

    var peers, var result = try findPeersToDownloadFrom(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null,
    );
    allocator.free(peers);

    // no snapshot hashes
    try std.testing.expect(result.is_valid == 0);
    try std.testing.expect(result.invalid_shred_version == 0);
    try std.testing.expect(result.no_rpc_count == 0);
    try std.testing.expect(result.is_me_count == 0);
    try std.testing.expect(result.is_blacklist == 0);
    try std.testing.expect(result.no_snapshot_hashes_count == 10);

    for (contact_infos) |*ci| {
        const kp = KeyPair.generate();
        var snapshot_hashes = sig.gossip.data.SnapshotHashes.initRandom(random);
        snapshot_hashes.from = ci.pubkey;
        const data = SignedGossipData.initSigned(&kp, .{ .SnapshotHashes = snapshot_hashes });
        _ = try table.insert(data, 0);
    }

    peers, result = try findPeersToDownloadFrom(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null,
    );
    allocator.free(peers);
    // all valid
    try std.testing.expect(result.is_valid == 10);

    // blacklist one
    var blist = [_]Pubkey{contact_infos[0].pubkey};
    peers, result = try findPeersToDownloadFrom(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &blist,
        null,
    );
    allocator.free(peers);
    try std.testing.expect(result.is_valid == 9);
    try std.testing.expect(result.is_blacklist == 1);

    for (contact_infos) |*ci| {
        ci.shred_version = 21; // non-matching shred version
    }
    peers, result = try findPeersToDownloadFrom(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null,
    );
    allocator.free(peers);
    try std.testing.expect(result.invalid_shred_version == 10);

    for (contact_infos) |*ci| {
        ci.pubkey = my_pubkey; // is_me pubkey
    }
    peers, result = try findPeersToDownloadFrom(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null,
    );
    allocator.free(peers);
    try std.testing.expect(result.is_me_count == 10);
}

test "PeerSearchResult format" {
    const Case = struct { PeerSearchResult, []const u8 };

    const cases: []const Case = &.{
        .{ .{}, "" },
        .{ .{ .is_me_count = 2 }, "is_me_count: 2 " },
        .{ .{ .is_blacklist = 0 }, "" },
        .{ .{ .is_blacklist = 2 }, "is_blacklist: 2 " },
        .{ .{ .is_me_count = 2, .is_blacklist = 1 }, "is_me_count: 2 is_blacklist: 1 " },
    };

    for (cases) |case| {
        const result, const expected = case;
        try std.testing.expectFmt(expected, "{}", .{result});
    }
}

test "findpeers leak check" {
    const test_fn = struct {
        fn f(
            allocator: std.mem.Allocator,
            gossip_table: *GossipTable,
            contact_infos: []ThreadSafeContactInfo,
            my_shred_version: usize,
            my_pubkey: Pubkey,
            trusted_validators: ?[]const Pubkey,
        ) !void {
            const peers, _ = try findPeersToDownloadFrom(
                allocator,
                gossip_table,
                contact_infos,
                my_shred_version,
                my_pubkey,
                &.{},
                trusted_validators,
            );
            allocator.free(peers);
        }
    }.f;

    const allocator = std.testing.allocator;
    var table = try GossipTable.init(allocator, allocator);
    defer table.deinit();

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const my_shred_version: usize = 19;
    const my_pubkey = Pubkey.initRandom(random);

    const contact_infos: []ThreadSafeContactInfo = try allocator.alloc(ThreadSafeContactInfo, 10);
    defer allocator.free(contact_infos);

    for (contact_infos) |*ci| {
        var lci = LegacyContactInfo.default(Pubkey.initRandom(random));
        lci.rpc.setPort(19); // no long unspecified = valid
        ci.* = ThreadSafeContactInfo.fromLegacyContactInfo(lci);
        ci.shred_version = 19; // matching shred version
    }

    try std.testing.checkAllAllocationFailures(allocator, test_fn, .{
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        null,
    });

    try std.testing.checkAllAllocationFailures(allocator, test_fn, .{
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{Pubkey.ZEROES},
    });
}

test "downloadInfo Incremental" {
    const test_fn = struct {
        fn f(
            allocator: std.mem.Allocator,
            peer: PeerSnapshotHash,
            full_snapshot_slot: Slot,
            expected: ?[]const u8,
        ) !void {
            _, _, const url = (try downloadInfo(
                allocator,
                .incremental,
                peer,
                full_snapshot_slot,
            )) orelse return error.NoSnapshotForPeer;
            defer allocator.free(url);

            try std.testing.expectEqualStrings(expected.?, url);
        }
    }.f;

    const allocator = std.testing.allocator;

    const Case = struct { PeerSnapshotHash, error{NoSnapshotForPeer}![]const u8 };

    const cases: []const Case = &.{
        .{
            .{
                .contact_info = .{
                    .pubkey = .ZEROES,
                    .shred_version = 0,
                    .gossip_addr = null,
                    .rpc_addr = null,
                    .tpu_addr = null,
                    .tvu_addr = null,
                    .tpu_quic_addr = null,
                    .tpu_vote_addr = null,
                },
                .full_snapshot = .{ .slot = 100, .hash = .ZEROES },
                .inc_snapshot = .{ .slot = 101, .hash = .ZEROES },
            },
            error.NoSnapshotForPeer,
        },
        .{
            .{
                .contact_info = .{
                    .pubkey = .ZEROES,
                    .shred_version = 0,
                    .gossip_addr = null,
                    .rpc_addr = .UNSPECIFIED,
                    .tpu_addr = null,
                    .tvu_addr = null,
                    .tpu_quic_addr = null,
                    .tpu_vote_addr = null,
                },
                .full_snapshot = .{ .slot = 100, .hash = .ZEROES },
                .inc_snapshot = null,
            },
            error.NoSnapshotForPeer,
        },
        .{
            .{
                .contact_info = .{
                    .pubkey = .ZEROES,
                    .shred_version = 0,
                    .gossip_addr = null,
                    .rpc_addr = .UNSPECIFIED,
                    .tpu_addr = null,
                    .tvu_addr = null,
                    .tpu_quic_addr = null,
                    .tpu_vote_addr = null,
                },
                .full_snapshot = .{ .slot = 100, .hash = .ZEROES },
                .inc_snapshot = .{ .slot = 101, .hash = .ZEROES },
            },
            "http://0.0.0.0:0/incremental-snapshot-100-101-11111111111111111111111111111111.tar.zst",
        },
    };

    for (cases) |case| {
        const peer, const expected = case;

        if (expected) |expected_url| {
            try std.testing.checkAllAllocationFailures(allocator, test_fn, .{
                peer,
                100,
                expected_url,
            });
        } else |expected_error| {
            try std.testing.expectError(
                expected_error,
                std.testing.checkAllAllocationFailures(allocator, test_fn, .{
                    peer,
                    100,
                    null,
                }),
            );
        }
    }
}

test "downloadInfo Full" {
    const test_fn = struct {
        fn f(
            allocator: std.mem.Allocator,
            peer: PeerSnapshotHash,
            expected: ?[]const u8,
        ) !void {
            _, _, const url = (try downloadInfo(
                allocator,
                .full,
                peer,
                null,
            )) orelse return error.NoSnapshotForPeer;
            defer allocator.free(url);

            try std.testing.expectEqualStrings(expected.?, url);
        }
    }.f;

    const allocator = std.testing.allocator;

    const Case = struct { PeerSnapshotHash, error{NoSnapshotForPeer}![]const u8 };

    const cases: []const Case = &.{
        .{
            .{
                .contact_info = .{
                    .pubkey = .ZEROES,
                    .shred_version = 0,
                    .gossip_addr = null,
                    .rpc_addr = null,
                    .tpu_addr = null,
                    .tvu_addr = null,
                    .tpu_quic_addr = null,
                    .tpu_vote_addr = null,
                },
                .full_snapshot = .{ .slot = 100, .hash = .ZEROES },
                .inc_snapshot = .{ .slot = 101, .hash = .ZEROES },
            },
            error.NoSnapshotForPeer,
        },
        .{
            .{
                .contact_info = .{
                    .pubkey = .ZEROES,
                    .shred_version = 0,
                    .gossip_addr = null,
                    .rpc_addr = .UNSPECIFIED,
                    .tpu_addr = null,
                    .tvu_addr = null,
                    .tpu_quic_addr = null,
                    .tpu_vote_addr = null,
                },
                .full_snapshot = .{ .slot = 100, .hash = .ZEROES },
                .inc_snapshot = null,
            },
            "http://0.0.0.0:0/snapshot-100-11111111111111111111111111111111.tar.zst",
        },
    };

    for (cases) |case| {
        const peer, const expected = case;

        if (expected) |expected_url| {
            try std.testing.checkAllAllocationFailures(allocator, test_fn, .{
                peer,
                expected_url,
            });
        } else |expected_error| {
            try std.testing.expectError(
                expected_error,
                std.testing.checkAllAllocationFailures(allocator, test_fn, .{
                    peer,
                    null,
                }),
            );
        }
    }
}

test "can't download snapshot" {
    const allocator = std.testing.allocator;
    var table = try GossipTable.init(allocator, allocator);
    defer table.deinit();

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // const my_shred_version: usize = 19;
    const my_keypair = KeyPair.generate();
    const my_pubkey = Pubkey.initRandom(random);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var me = try sig.gossip.ContactInfo.initRandom(allocator, random, my_pubkey, 0, 0, 1);
    try me.setSocket(.gossip, .{ .V4 = .{ .ip = .{ .octets = .{ 127, 0, 0, 1 } }, .port = 0 } });

    var gossip_service = try GossipService.init(
        allocator,
        allocator,
        me,
        my_keypair,
        null,
        .noop,
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
    }

    try std.testing.expectError(error.UnableToDownloadSnapshot, downloadSnapshotsFromGossip(
        allocator,
        .noop,
        null,
        &gossip_service,
        tmp_dir.dir,
        1,
        1,
        sig.time.Duration.fromMillis(1),
    ));
}
