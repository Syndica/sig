//! logic for downloading a snapshot

const std = @import("std");
const curl = @import("curl");
const sig = @import("../lib.zig");

const SlotAndHash = sig.accounts_db.snapshots.SlotAndHash;
const Pubkey = sig.core.Pubkey;
const GossipTable = sig.gossip.GossipTable;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const GossipService = sig.gossip.GossipService;
const Logger = sig.trace.Logger;

const DOWNLOAD_PROGRESS_UPDATES_NS = 30 * std.time.ns_per_s;

/// Analogous to [PeerSnapshotHash](https://github.com/anza-xyz/agave/blob/f868aa38097094e4fb78a885b6fb27ce0e43f5c7/validator/src/bootstrap.rs#L342)
const PeerSnapshotHash = struct {
    contact_info: ThreadSafeContactInfo,
    full_snapshot: SlotAndHash,
    inc_snapshot: ?SlotAndHash,
};

const PeerSearchResult = struct {
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
    valid_peers: *std.ArrayList(PeerSnapshotHash),
) !PeerSearchResult {
    // clear the list
    valid_peers.clearRetainingCapacity();
    std.debug.assert(valid_peers.capacity >= contact_infos.len);

    const TrustedMapType = std.AutoHashMap(
        SlotAndHash, // full snapshot hash
        std.AutoHashMap(SlotAndHash, void), // set of incremental snapshots
    );
    var maybe_trusted_snapshot_hashes: ?TrustedMapType = if (trusted_validators != null) TrustedMapType.init(allocator) else null;
    defer {
        if (maybe_trusted_snapshot_hashes) |*ts| ts.deinit();
    }

    if (maybe_trusted_snapshot_hashes) |*trusted_snapshot_hashes| {
        // populate with the hashes of trusted validators
        var trusted_count: usize = 0;
        // SAFE: the perf is safe because maybe_ is non null only if trusted_validators is non-null
        for (trusted_validators.?) |trusted_validator| {
            const gossip_data = table.get(.{ .SnapshotHashes = trusted_validator }) orelse continue;
            const trusted_hashes = gossip_data.value.data.SnapshotHashes;
            trusted_count += 1;

            // track the full and all incremental hashes
            const r = try trusted_snapshot_hashes.getOrPut(trusted_hashes.full);
            const inc_map_ptr = r.value_ptr;
            if (!r.found_existing) {
                inc_map_ptr.* = std.AutoHashMap(SlotAndHash, void).init(allocator);
            }
            for (trusted_hashes.incremental) |inc_hash| {
                try inc_map_ptr.put(inc_hash, {});
            }
        }
    }

    var result = PeerSearchResult{};
    search_loop: for (contact_infos) |*peer_contact_info| {
        const is_me = peer_contact_info.pubkey.equals(&my_pubkey);
        if (is_me) {
            result.is_me_count += 1;
            continue;
        }

        const matching_shred_version = my_shred_version == peer_contact_info.shred_version or my_shred_version == 0;
        if (!matching_shred_version) {
            result.invalid_shred_version += 1;
            continue;
        }
        if (peer_contact_info.rpc_addr == null) {
            result.no_rpc_count += 1;
            continue;
        }
        const gossip_data = table.get(.{ .SnapshotHashes = peer_contact_info.pubkey }) orelse {
            result.no_snapshot_hashes_count += 1;
            continue;
        };
        const snapshot_hashes = gossip_data.value.data.SnapshotHashes;

        var max_inc_hash: ?SlotAndHash = null;
        for (snapshot_hashes.incremental) |inc_hash| {
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
            .contact_info = peer_contact_info.*,
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
    // if null, then we trust any peer for snapshot download
    maybe_trusted_validators: ?[]const Pubkey,
    gossip_service: *GossipService,
    output_dir: std.fs.Dir,
    min_mb_per_sec: usize,
) !void {
    logger.infof("starting snapshot download with min download speed: {d} MB/s", .{min_mb_per_sec});

    // TODO: maybe make this bigger? or dynamic?
    var contact_info_buf: [1_000]ThreadSafeContactInfo = undefined;

    const my_contact_info = gossip_service.my_contact_info;

    var available_snapshot_peers = std.ArrayList(PeerSnapshotHash).init(allocator);
    defer available_snapshot_peers.deinit();

    var slow_peer_pubkeys = std.ArrayList(Pubkey).init(allocator);
    defer slow_peer_pubkeys.deinit();

    while (true) {
        std.time.sleep(std.time.ns_per_s * 5); // wait while gossip table updates

        // only hold gossip table lock for this block
        {
            var lg = gossip_service.gossip_table_rw.read();
            defer lg.unlock();
            const table: *const GossipTable = lg.get();

            const contacts = table.getThreadSafeContactInfos(&contact_info_buf, 0);

            try available_snapshot_peers.ensureTotalCapacity(contacts.len);
            const result = try findPeersToDownloadFromAssumeCapacity(
                allocator,
                table,
                contacts,
                my_contact_info.shred_version,
                my_contact_info.pubkey,
                slow_peer_pubkeys.items,
                maybe_trusted_validators,
                // this is cleared and populated
                &available_snapshot_peers,
            );

            logger.infof("searched for peers to downlod from: {any}", .{result});
        }

        for (available_snapshot_peers.items) |peer| {
            // download the full snapshot
            const snapshot_filename = try std.fmt.allocPrint(allocator, "snapshot-{d}-{s}.{s}", .{
                peer.full_snapshot.slot,
                peer.full_snapshot.hash,
                "tar.zst",
            });
            defer allocator.free(snapshot_filename);

            const rpc_socket = peer.contact_info.rpc_addr.?;
            const rpc_url_bounded = rpc_socket.toStringBounded();
            const rpc_url = rpc_url_bounded.constSlice();

            const snapshot_url = try std.fmt.allocPrintZ(allocator, "http://{s}/{s}", .{
                rpc_url,
                snapshot_filename,
            });
            defer allocator.free(snapshot_url);

            logger.infof("downloading full_snapshot from: {s}", .{snapshot_url});
            downloadFile(
                allocator,
                logger,
                snapshot_url,
                output_dir,
                snapshot_filename,
                min_mb_per_sec,
            ) catch |err| {
                logger.infof("failed to download full_snapshot: {s}", .{@errorName(err)});
                if (err == error.TooSlow) {
                    logger.infof("peer is too slow, skipping", .{});
                    try slow_peer_pubkeys.append(peer.contact_info.pubkey);
                }
                continue;
            };

            // download the incremental snapshot
            // PERF: maybe do this in another thread? while downloading the full snapshot
            if (peer.inc_snapshot) |inc_snapshot| {
                const inc_snapshot_filename = try std.fmt.allocPrint(allocator, "incremental-snapshot-{d}-{d}-{s}.{s}", .{
                    peer.full_snapshot.slot,
                    inc_snapshot.slot,
                    inc_snapshot.hash,
                    "tar.zst",
                });
                defer allocator.free(inc_snapshot_filename);

                const inc_snapshot_url = try std.fmt.allocPrintZ(allocator, "http://{s}/{s}", .{
                    rpc_url,
                    inc_snapshot_filename,
                });
                defer allocator.free(inc_snapshot_url);

                logger.infof("downloading inc_snapshot from: {s}", .{inc_snapshot_url});
                _ = downloadFile(
                    allocator,
                    logger,
                    inc_snapshot_url,
                    output_dir,
                    inc_snapshot_filename,
                    // NOTE: no min limit (we already downloaded the full snapshot at a good speed so this should be ok)
                    null,
                ) catch |err| {
                    // failure here is ok (for now?)
                    logger.warnf("failed to download inc_snapshot: {s}", .{@errorName(err)});
                    return;
                };
            }

            // success
            logger.infof("snapshot downloaded finished", .{});
            return;
        }
    }
}

const DownloadProgress = struct {
    mmap: []align(std.mem.page_size) u8,
    download_size: usize,
    min_mb_per_second: ?usize,
    logger: Logger,

    mb_timer: std.time.Timer,
    bytes_read: usize = 0,
    file_memory_index: usize = 0,
    has_checked_speed: bool = false,

    const Self = @This();

    pub fn init(
        logger: Logger,
        output_dir: std.fs.Dir,
        filename: []const u8,
        download_size: usize,
        min_mb_per_second: ?usize,
    ) !Self {
        const file = try output_dir.createFile(filename, .{ .read = true });
        defer file.close();

        // resize the file
        try file.seekTo(download_size - 1);
        _ = try file.write(&[_]u8{1});
        try file.seekTo(0);

        const file_memory = try std.posix.mmap(
            null,
            download_size,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            std.posix.MAP{ .TYPE = .SHARED },
            file.handle,
            0,
        );

        return .{
            .logger = logger,
            .mmap = file_memory,
            .download_size = download_size,
            .min_mb_per_second = min_mb_per_second,
            .mb_timer = try std.time.Timer.start(),
        };
    }

    pub fn deinit(self: *Self) void {
        std.posix.munmap(self.mmap);
    }

    pub fn bufferWriteCallback(ptr: [*c]c_char, size: c_uint, nmemb: c_uint, user_data: *anyopaque) callconv(.C) c_uint {
        const len = size * nmemb;
        var self: *Self = @alignCast(@ptrCast(user_data));
        var typed_data: [*]u8 = @ptrCast(ptr);
        const buf = typed_data[0..len];

        @memcpy(self.mmap[self.file_memory_index..][0..len], buf);
        self.file_memory_index += len;
        self.bytes_read += len;

        const elapsed_ns = self.mb_timer.read();
        if (elapsed_ns > DOWNLOAD_PROGRESS_UPDATES_NS) {
            // each MB
            const mb_read = self.bytes_read / 1024 / 1024;
            if (mb_read == 0) {
                self.logger.infof("download speed is too slow (<1MB/s) -- disconnecting", .{});
                return 0;
            }

            defer {
                self.bytes_read = 0;
                self.mb_timer.reset();
            }
            const elapsed_sec = elapsed_ns / std.time.ns_per_s;
            const ns_per_mb = elapsed_ns / mb_read;
            const mb_left = (self.download_size - self.file_memory_index) / 1024 / 1024;
            const time_left_ns = mb_left * ns_per_mb;
            const mb_per_second = mb_read / elapsed_sec;

            self.logger.infof("[download progress]: {d}% done ({d} MB/s - {d}/{d}) (time left: {d})", .{
                self.file_memory_index * 100 / self.download_size,
                mb_per_second,
                self.file_memory_index,
                self.download_size,
                std.fmt.fmtDuration(time_left_ns),
            });

            const should_check_speed = self.min_mb_per_second != null and !self.has_checked_speed;
            if (should_check_speed) {
                // dont check again
                self.has_checked_speed = true;
                if (mb_per_second < self.min_mb_per_second.?) {
                    // not fast enough => abort
                    self.logger.infof("download speed is too slow ({d} MB/s) -- disconnecting", .{mb_per_second});
                    return 0;
                } else {
                    self.logger.infof("download speed is ok ({d} MB/s) -- maintaining connection", .{mb_per_second});
                }
            }
        }

        return len;
    }
};

fn checkCode(code: curl.libcurl.CURLcode) !void {
    if (code == curl.libcurl.CURLE_OK) {
        return;
    }
    // https://curl.se/libcurl/c/libcurl-errors.html
    std.log.debug("curl err code:{d}, msg:{s}\n", .{ code, curl.libcurl.curl_easy_strerror(code) });
    return error.Unexpected;
}

pub fn setNoBody(self: curl.Easy, no_body: bool) !void {
    try checkCode(curl.libcurl.curl_easy_setopt(self.handle, curl.libcurl.CURLOPT_NOBODY, @as(c_long, @intFromBool(no_body))));
}

/// downloads a file from a url into output_dir/filename
/// returns error if it fails.
/// the main errors include {HeaderRequestFailed, NoContentLength, TooSlow} or a curl-related error
pub fn downloadFile(
    allocator: std.mem.Allocator,
    logger: Logger,
    url: [:0]const u8,
    output_dir: std.fs.Dir,
    filename: []const u8,
    min_mb_per_second: ?usize,
) !void {
    var easy = try curl.Easy.init(allocator, .{});
    defer easy.deinit();

    try easy.setUrl(url);
    try easy.setMethod(.HEAD);
    try setNoBody(easy, true);
    var head_resp = easy.perform() catch {
        return error.HeaderRequestFailed;
    };

    var download_size: usize = 0;
    if (try head_resp.getHeader("content-length")) |content_length| {
        download_size = try std.fmt.parseInt(usize, content_length.get(), 10);
    } else {
        logger.debugf("header request didnt have content-length...", .{});
        return error.NoContentLength;
    }

    // timeout will need to be larger
    easy.timeout_ms = std.time.ms_per_hour * 5; // 5 hours is probs too long but its ok
    var download_progress = try DownloadProgress.init(
        logger,
        output_dir,
        filename,
        download_size,
        min_mb_per_second,
    );
    errdefer output_dir.deleteFile(filename) catch {};
    defer download_progress.deinit();

    try setNoBody(easy, false); // full download
    try easy.setUrl(url);
    try easy.setMethod(.GET);
    try easy.setWritedata(&download_progress);
    try easy.setWritefunction(DownloadProgress.bufferWriteCallback);

    var resp = try easy.perform();
    defer resp.deinit();

    const full_download = download_progress.file_memory_index == download_size;
    // this if block should only be hit if the download was too slow
    if (!full_download) {
        return error.TooSlow;
    }
}

const ThreadPool = sig.sync.thread_pool.ThreadPool;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const SignedGossipData = sig.gossip.data.SignedGossipData;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;

test "accounts_db.download: test remove untrusted peers" {
    const allocator = std.testing.allocator;
    var thread_pool = ThreadPool.init(.{});
    var table = try GossipTable.init(allocator, &thread_pool);
    defer table.deinit();

    var random = std.rand.DefaultPrng.init(0);
    const rng = random.random();

    const my_shred_version: usize = 19;
    const my_pubkey = Pubkey.random(rng);

    const contact_infos: []ThreadSafeContactInfo = try allocator.alloc(ThreadSafeContactInfo, 10);
    defer allocator.free(contact_infos);

    for (contact_infos) |*ci| {
        var lci = LegacyContactInfo.default(Pubkey.random(rng));
        lci.rpc.setPort(19); // no long unspecified = valid
        ci.* = ThreadSafeContactInfo.fromLegacyContactInfo(lci);
        ci.shred_version = 19; // matching shred version
    }

    var valid_peers = try std.ArrayList(PeerSnapshotHash).initCapacity(allocator, 10);
    defer valid_peers.deinit();

    var trusted_validators = try std.ArrayList(Pubkey).initCapacity(allocator, 10);
    defer trusted_validators.deinit();

    for (contact_infos) |*ci| {
        var kp = try KeyPair.create(null);
        var data = try SignedGossipData.randomWithIndex(rng, &kp, 9);
        data.data.SnapshotHashes.from = ci.pubkey;
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
    var thread_pool = ThreadPool.init(.{});
    var table = try GossipTable.init(allocator, &thread_pool);
    defer table.deinit();

    var random = std.rand.DefaultPrng.init(0);
    const rng = random.random();

    const my_shred_version: usize = 19;
    const my_pubkey = Pubkey.random(rng);

    const contact_infos: []ThreadSafeContactInfo = try allocator.alloc(ThreadSafeContactInfo, 10);
    defer allocator.free(contact_infos);

    for (contact_infos) |*ci| {
        var lci = LegacyContactInfo.default(Pubkey.random(rng));
        lci.rpc.setPort(19); // no long unspecified = valid
        ci.* = ThreadSafeContactInfo.fromLegacyContactInfo(lci);
        ci.shred_version = 19; // matching shred version
    }

    var valid_peers = try std.ArrayList(PeerSnapshotHash).initCapacity(allocator, 10);
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
        var kp = try KeyPair.create(null);
        var data = try SignedGossipData.randomWithIndex(rng, &kp, 9);
        data.data.SnapshotHashes.from = ci.pubkey;
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
