//! logic for downloading a snapshot

const std = @import("std");
const sig = @import("../../sig.zig");
const tracy = @import("tracy");

const GossipService = sig.gossip.GossipService;
const GossipTable = sig.gossip.GossipTable;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const Pubkey = sig.core.Pubkey;

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
};

/// finds valid contact infos which we can download a snapshot from.
/// valid contact infos are:
/// - not me
/// - shred version matches
/// - rpc socket is enabled
/// - snapshot hash is available
/// result is populated inside valid_peers (which is cleared at the beginning)
pub fn findPeersToDownloadFromAssumeCapacity(
    allocator: std.mem.Allocator,
    table: *const GossipTable,
    contact_infos: []const ThreadSafeContactInfo,
    my_shred_version: usize,
    my_pubkey: Pubkey,
    blacklist: []const Pubkey,
    trusted_validators: ?[]const Pubkey,
    /// `.capacity` must be >= `contact_infos.len`.
    /// The arraylist is first cleared, and then the outputs
    /// are appended to it.
    valid_peers: *std.array_list.Managed(PeerSnapshotHash),
) !PeerSearchResult {
    // clear the list
    valid_peers.clearRetainingCapacity();
    std.debug.assert(valid_peers.capacity >= contact_infos.len);

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

    return result;
}

/// downloads full and incremental snapshots from peers found in gossip.
/// note: gossip_service must be running.
pub fn downloadSnapshotsFromGossip(
    allocator: std.mem.Allocator,
    logger: Logger,
    /// if null, then we trust any peer for snapshot download
    maybe_trusted_validators: ?[]const Pubkey,
    gossip_service: *GossipService,
    output_dir: std.fs.Dir,
    min_mb_per_sec: usize,
    max_number_of_download_attempts: u64,
    timeout: ?sig.time.Duration,
) !struct { std.fs.File, ?std.fs.File } {
    const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb downloadSnapshotsFromGossip" });
    defer zone.deinit();

    logger
        .info()
        .logf("starting snapshot download with min download speed: {d} MB/s", .{min_mb_per_sec});

    // TODO: maybe make this bigger? or dynamic?
    var contact_info_buf: [1_000]ThreadSafeContactInfo = undefined;

    const my_contact_info = gossip_service.my_contact_info;

    var available_snapshot_peers = std.array_list.Managed(PeerSnapshotHash).init(allocator);
    defer available_snapshot_peers.deinit();

    var slow_peer_pubkeys = std.array_list.Managed(Pubkey).init(allocator);
    defer slow_peer_pubkeys.deinit();

    var function_duration = try std.time.Timer.start();
    var download_attempts: u64 = 0;
    while (true) {
        std.Thread.sleep(5 * std.time.ns_per_s); // wait while gossip table updates

        if (download_attempts > max_number_of_download_attempts) {
            logger.err().logf(
                "exceeded max download attempts: {d}",
                .{max_number_of_download_attempts},
            );
            return error.UnableToDownloadSnapshot;
        }

        if (timeout) |t| {
            if (function_duration.read() > t.asNanos()) {
                logger.err().logf("exceeded download timeout: {any}", .{t});
                return error.UnableToDownloadSnapshot;
            }
        }

        // only hold gossip table lock for this block
        {
            const gossip_table, var gossip_table_lg = gossip_service.gossip_table_rw.readWithLock();
            defer gossip_table_lg.unlock();

            const contacts = gossip_table.getThreadSafeContactInfos(&contact_info_buf, 0);

            try available_snapshot_peers.ensureTotalCapacity(contacts.len);
            const result = try findPeersToDownloadFromAssumeCapacity(
                allocator,
                gossip_table,
                contacts,
                my_contact_info.shred_version,
                my_contact_info.pubkey,
                slow_peer_pubkeys.items,
                maybe_trusted_validators,
                // this is cleared and populated
                &available_snapshot_peers,
            );

            var write_buf: [512]u8 = undefined;
            var i: usize = 0;
            inline for (@typeInfo(PeerSearchResult).@"struct".fields) |field| {
                if (@field(result, field.name) != 0) {
                    const r = try std.fmt.bufPrint(
                        write_buf[i..],
                        "{s}: {d} ",
                        .{ field.name, @field(result, field.name) },
                    );
                    i += r.len;
                }
            }
            logger
                .info()
                .logf("searched for snapshot peers: {s}", .{write_buf[0..i]});
        }

        const download_buffer = try allocator.alloc(u8, 1 * BYTE_PER_MIB);
        defer allocator.free(download_buffer);

        for (available_snapshot_peers.items) |peer| {
            const rpc_socket = peer.contact_info.rpc_addr.?;

            // TODO: collapse these
            const full_info: FullSnapshotFileInfo = .{
                .slot = peer.full_snapshot.slot,
                .hash = peer.full_snapshot.hash,
            };

            // download the full snapshot
            var snapshot_url_buffer: [2048]u8 = undefined;
            const snapshot_url = std.fmt.bufPrint(
                &snapshot_url_buffer,
                "http://{f}/{f}",
                .{ rpc_socket, full_info },
            ) catch unreachable;

            const snapshot_uri = std.Uri.parse(snapshot_url) catch {
                const url_str = snapshot_url;
                std.debug.panic("Failed to Upri.parse '{s}'", .{url_str});
            };

            logger.info().logf(
                "downloading full_snapshot from: {s}",
                .{snapshot_url},
            );

            const full_archive_file = try full_info.openFile(output_dir);

            defer download_attempts += 1;
            downloadFile(
                allocator,
                logger,
                snapshot_uri,
                full_archive_file,
                min_mb_per_sec,
                download_buffer,
            ) catch |err| {
                switch (err) {
                    error.TooSlow => try slow_peer_pubkeys.append(peer.contact_info.pubkey),
                    else => logger.info().logf(
                        "failed to download full_snapshot: {t}",
                        .{err},
                    ),
                }
                continue;
            };
            errdefer comptime unreachable;

            // download the incremental snapshot
            const inc_archive_file: ?std.fs.File = if (peer.inc_snapshot) |inc_snapshot| blk: {
                // PERF: maybe do this in another thread? while downloading the full snapshot

                var info: IncrementalSnapshotFileInfo = .{
                    .base_slot = peer.full_snapshot.slot,
                    .slot = inc_snapshot.slot,
                    .hash = inc_snapshot.hash,
                };

                var url_buffer: [2048]u8 = undefined;
                const url = std.fmt.bufPrint(&url_buffer, "http://{s}/{f}", .{
                    rpc_socket,
                    info,
                }) catch unreachable;

                const inc_snapshot_uri = std.Uri.parse(url) catch
                    std.debug.panic("Failed to Uri.parse '{s}'", .{url});

                const inc_file = info.openFile(output_dir) catch {
                    logger.err().logf("failed to open incremental snapshot output: {f}", .{info});
                    break :blk null;
                };

                logger.info().logf("downloading inc_snapshot from: {s}", .{url});
                downloadFile(
                    allocator,
                    logger,
                    inc_snapshot_uri,
                    inc_file,
                    // NOTE: no min limit (we already downloaded the full snapshot at a good speed so this should be ok)
                    null,
                    download_buffer,
                ) catch |err| {
                    // failure here is ok (for now?)
                    logger.warn().logf("failed to download inc_snapshot: {s}", .{@errorName(err)});
                    break :blk null;
                };

                break :blk inc_file;
            } else null;

            logger.info().logf("snapshot downloaded finished", .{});
            return .{ full_archive_file, inc_archive_file };
        }
    }
}

/// Downloads a file from the provided URI into the output file.
fn downloadFile(
    allocator: std.mem.Allocator,
    logger: Logger,
    uri: std.Uri,
    output_file: std.fs.File,
    maybe_min_mib_per_second: ?usize,
    /// Used as an intermediate buffer to read the response body before writing to disk.
    /// Recommended size is at least 1 MiB for payloads which are expected to occupy 1 GiB or more.
    download_buffer: []u8,
) !void {
    var http_client: std.http.Client = .{ .allocator = allocator };
    defer http_client.deinit();

    var request = try http_client.request(.GET, uri, .{});
    defer request.deinit();
    // try http_client.initDefaultProxies(allocator);

    try request.sendBodiless();

    var redirect_buffer: [1024]u8 = undefined;
    var response = try request.receiveHead(&redirect_buffer);

    if (response.head.status != .ok) {
        logger.err().logf(
            "bad HTTP response code: '{d} {s}'",
            .{ response.head.status, response.head.status.phrase() orelse "" },
        );
        return error.HeadRequestFailed;
    }

    const download_size = response.head.content_length orelse return error.NoContentLength;

    if (download_buffer.len < 1 * BYTE_PER_MIB and
        download_size >= BYTE_PER_GIB)
    {
        logger.warn().logf("Downloading file of size {Bi} using a buffer of size {Bi};" ++
            " recommended buffer size for such a payload is at least 1 MiB.", .{
            download_size,
            download_buffer.len,
        });
    }

    try output_file.setEndPos(download_size);

    // TODO: see if `stream` makes better use of writer or readers buffer.

    var file_writer = output_file.writer(download_buffer);
    const writer = &file_writer.interface;

    var response_buffer: [4096]u8 = undefined;
    const reader = response.reader(&response_buffer);

    if (response.head.content_type) |t| {
        _ = t;
        @panic("TODO: check here");

        // const content_type = response.head.content_type orelse
        //     return f.fail(f.location_tok, try eb.addString("missing 'Content-Type' header"));

        // // Extract the MIME type, ignoring charset and boundary directives
        // const mime_type_end = std.mem.indexOf(u8, content_type, ";") orelse content_type.len;
        // const mime_type = content_type[0..mime_type_end];
    }

    var total_bytes_written: u64 = 0;
    var lap_timer = sig.time.Timer.start();
    var full_timer = sig.time.Timer.start();
    var checked_speed = false;

    while (true) {
        const bytes_written = reader.stream(writer, .unlimited) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        total_bytes_written += bytes_written;

        const elapsed_since_start = full_timer.read();
        const elapsed_since_prev_lap = lap_timer.read();

        if (elapsed_since_prev_lap.asNanos() <= DOWNLOAD_WARMUP_TIME.asNanos()) continue;
        // reset at the end of the iteration, after the update, right before the next read & write.
        defer lap_timer.reset();

        const total_bytes_left = download_size - total_bytes_written;
        const time_left_ns = total_bytes_left * (elapsed_since_start.asNanos() / total_bytes_written);
        logger.info().logf(
            "[download progress]: {d}% done ({Bi:.4}/s - {Bi:.4}/{Bi:.4}) (time left: {D})",
            .{
                total_bytes_written * 100 / download_size,
                total_bytes_written / elapsed_since_start.asSecs(),
                total_bytes_written,
                download_size,
                time_left_ns,
            },
        );

        if (checked_speed) continue;
        checked_speed = true;

        const min_bytes_per_second = BYTE_PER_MIB * (maybe_min_mib_per_second orelse continue);
        const actual_bytes_per_second = total_bytes_written / elapsed_since_start.asSecs();

        if (actual_bytes_per_second < min_bytes_per_second) {
            // not fast enough => abort
            logger.info().logf(
                "[download progress]: speed is too slow ({Bi:.4}/s) -- disconnecting",
                .{actual_bytes_per_second},
            );
            return error.TooSlow;
        }

        logger.info().logf(
            "[download progress]: speed is ok ({Bi:.4}/s) -- maintaining",
            .{actual_bytes_per_second},
        );
    }

    try writer.flush();
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
            "unpacking {f}...",
            .{snapshot_files.full},
        );
        {
            const archive_file = try snapshot_files.full.openFile(snapshot_dir);
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
        logger.info().logf("unpacked snapshot in {D}", .{timer.read()});

        // TODO: can probs do this in parallel with full snapshot
        if (snapshot_files.incremental()) |incremental_snapshot| {
            timer.reset();
            logger.info().logf("unpacking {f}...", .{incremental_snapshot});

            const archive_file = try incremental_snapshot.openFile(snapshot_dir);
            defer archive_file.close();

            try parallelUnpackZstdTarBall(
                allocator,
                .from(logger),
                archive_file,
                snapshot_dir,
                n_threads_snapshot_unpack,
                false,
            );
            logger.info().logf("unpacked snapshot in {D}", .{timer.read()});
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
    logger.info().logf("read snapshot metdata in {D}", .{timer.read()});

    return .{ snapshot_fields, snapshot_files };
}

test "accounts_db.download: test remove untrusted peers" {
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

    var valid_peers = try std.array_list.Managed(PeerSnapshotHash).initCapacity(allocator, 10);
    defer valid_peers.deinit();

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

    _ = try findPeersToDownloadFromAssumeCapacity(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null, // no trusted validators
        &valid_peers,
    );
    try std.testing.expectEqual(valid_peers.items.len, 10);

    _ = try findPeersToDownloadFromAssumeCapacity(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        trusted_validators.items,
        &valid_peers,
    );
    try std.testing.expectEqual(valid_peers.items.len, 10);

    _ = trusted_validators.pop();
    _ = trusted_validators.pop();

    _ = try findPeersToDownloadFromAssumeCapacity(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        trusted_validators.items,
        &valid_peers,
    );
    try std.testing.expectEqual(valid_peers.items.len, 8);
}

test "accounts_db.download: test finding peers" {
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

    var valid_peers = try std.array_list.Managed(PeerSnapshotHash).initCapacity(allocator, 10);
    defer valid_peers.deinit();

    var result = try findPeersToDownloadFromAssumeCapacity(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null,
        &valid_peers,
    );

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

    result = try findPeersToDownloadFromAssumeCapacity(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null,
        &valid_peers,
    );
    // all valid
    try std.testing.expect(result.is_valid == 10);

    // blacklist one
    var blist = [_]Pubkey{contact_infos[0].pubkey};
    result = try findPeersToDownloadFromAssumeCapacity(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &blist,
        null,
        &valid_peers,
    );
    try std.testing.expect(result.is_valid == 9);
    try std.testing.expect(result.is_blacklist == 1);

    for (contact_infos) |*ci| {
        ci.shred_version = 21; // non-matching shred version
    }
    result = try findPeersToDownloadFromAssumeCapacity(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null,
        &valid_peers,
    );
    try std.testing.expect(result.invalid_shred_version == 10);

    for (contact_infos) |*ci| {
        ci.pubkey = my_pubkey; // is_me pubkey
    }
    result = try findPeersToDownloadFromAssumeCapacity(
        allocator,
        &table,
        contact_infos,
        my_shred_version,
        my_pubkey,
        &.{},
        null,
        &valid_peers,
    );
    try std.testing.expect(result.is_me_count == 10);
}
