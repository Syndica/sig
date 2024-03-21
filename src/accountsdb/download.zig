const std = @import("std");

const lib = @import("../lib.zig");
const Pubkey = lib.core.Pubkey;
const GossipService = lib.gossip.GossipService;
const ContactInfo = lib.gossip.ContactInfo;
const GossipTable = lib.gossip.GossipTable;
const SlotAndHash = lib.accounts_db.SlotAndHash;
const setReadTimeout = lib.net.setReadTimeout;

const SOCKET_TAG_RPC = lib.gossip.SOCKET_TAG_RPC;

// TODO: make cli flag
const MIN_MB_PER_SEC: usize = 10;

const PeerSnapshotHash = struct {
    contact_info: ContactInfo,
    full_snapshot: SlotAndHash,
    inc_snapshot: ?SlotAndHash,
};

/// downloads full and incremental snapshots from peers found in gossip.
/// note: gossip_service must be running.
pub fn downloadSnapshotsFromGossip(
    allocator: std.mem.Allocator,
    gossip_service: *GossipService,
) !void {
    const my_contact_info = gossip_service.my_contact_info;
    const my_pubkey = my_contact_info.pubkey;

    var contact_info_buf: [1_000]ContactInfo = undefined;
    var valid_contacts_buf: [1_000]u8 = undefined;
    @memset(&valid_contacts_buf, 0);

    var available_snapshot_peers = std.ArrayList(PeerSnapshotHash).init(allocator);
    defer available_snapshot_peers.deinit();

    var slow_peer_pubkeys = std.ArrayList(Pubkey).init(allocator);
    defer slow_peer_pubkeys.deinit();

    while (true) {
        std.debug.print("sleeping...\n", .{});
        std.time.sleep(std.time.ns_per_s * 5); // wait while gossip table updates

        // only hold gossip table lock for this block
        {
            var lg = gossip_service.gossip_table_rw.read();
            defer lg.unlock();
            const table: *const GossipTable = lg.get();

            // find valid contact infos:
            // - not me
            // - shred version matches
            // - rpc socket is enabled
            // - snapshot is available
            var contacts = table.getContactInfos(&contact_info_buf, 0);
            std.debug.print("found {d} contacts\n", .{contacts.len});

            for (contacts) |*ci| {
                const is_me = ci.pubkey.equals(&my_pubkey);
                if (is_me) {
                    continue;
                }

                const matching_shred_version = my_contact_info.shred_version == ci.shred_version or my_contact_info.shred_version == 0;
                if (!matching_shred_version) {
                    continue;
                }
                _ = ci.getSocket(SOCKET_TAG_RPC) orelse continue;
                const snapshot_hash = table.get(.{ .SnapshotHashes = ci.pubkey }) orelse continue;
                const hashes = snapshot_hash.value.data.SnapshotHashes;

                var max_inc_hash: ?SlotAndHash = null;
                for (hashes.incremental) |inc_hash| {
                    if (max_inc_hash == null or inc_hash.slot > max_inc_hash.?.slot) {
                        max_inc_hash = inc_hash;
                    }
                }

                try available_snapshot_peers.append(.{
                    // NOTE: maybe we need to deep clone here due to arraylist sockets?
                    .contact_info = ci.*,
                    .full_snapshot = hashes.full,
                    .inc_snapshot = max_inc_hash,
                });
            }
            std.debug.print("found {d} valid peers for snapshot download...\n", .{available_snapshot_peers.items.len});
        }

        for (available_snapshot_peers.items) |peer| {
            // dont try to download from a slow peer
            var is_slow_peer = false;
            for (slow_peer_pubkeys.items) |slow_peer| {
                if (slow_peer.equals(&peer.contact_info.pubkey)) {
                    is_slow_peer = true;
                }
            }
            if (is_slow_peer) continue;

            // download the full snapshot
            const snapshot_filename = try std.fmt.allocPrint(allocator, "snapshot-{d}-{s}.{s}", .{
                peer.full_snapshot.slot,
                peer.full_snapshot.hash,
                "tar.zst",
            });
            defer allocator.free(snapshot_filename);

            const rpc_socket = peer.contact_info.getSocket(SOCKET_TAG_RPC).?;
            const r = rpc_socket.toString();
            const snapshot_url = try std.fmt.allocPrint(allocator, "http://{s}/{s}", .{
                r[0][0..r[1]],
                snapshot_filename,
            });
            defer allocator.free(snapshot_url);

            std.debug.print("downloading full_snapshot from: {s}\n", .{snapshot_url});
            var success = try downloadFile(
                allocator,
                try std.Uri.parse(snapshot_url),
                snapshot_filename,
                true,
                MIN_MB_PER_SEC,
            );
            if (!success) {
                std.debug.print("peer is too slow, skipping\n", .{});
                try slow_peer_pubkeys.append(peer.contact_info.pubkey);
                continue;
            }

            // download the incremental snapshot
            // NOTE: PERF: maybe do this in another thread? while downloading the full snapshot
            if (peer.inc_snapshot) |inc_snapshot| {
                const inc_snapshot_filename = try std.fmt.allocPrint(allocator, "incremental-snapshot-{d}-{d}-{s}.{s}", .{
                    peer.full_snapshot.slot,
                    inc_snapshot.slot,
                    inc_snapshot.hash,
                    "tar.zst",
                });
                defer allocator.free(inc_snapshot_filename);

                const inc_snapshot_url = try std.fmt.allocPrint(allocator, "http://{s}/{s}", .{
                    r[0][0..r[1]],
                    inc_snapshot_filename,
                });
                defer allocator.free(inc_snapshot_url);

                std.debug.print("downloading inc_snapshot from: {s}\n", .{inc_snapshot_url});
                _ = try downloadFile(
                    allocator,
                    try std.Uri.parse(inc_snapshot_url),
                    inc_snapshot_filename,
                    true,
                    // NOTE: no min limit (we already downloaded the full snapshot at a good speed so this should be ok)
                    null,
                );
            }

            // success
            return;
        }

        // try again
        available_snapshot_peers.clearRetainingCapacity();
    }
}

pub fn downloadFile(
    allocator: std.mem.Allocator,
    uri: std.Uri,
    filename: []const u8,
    with_progress: bool,
    min_mb_per_second: ?usize,
) !bool {
    var client = std.http.Client{ .allocator = allocator };
    var headers = std.http.Headers{ .allocator = allocator };
    defer headers.deinit();

    var request = try client.request(.GET, uri, headers, .{});
    defer request.deinit();

    // TODO: this can stall the process if the peer never connects
    try request.start();
    try request.wait();

    var download_size: usize = 0;
    const response_headers = request.response.headers;
    for (response_headers.list.items) |header| {
        if (std.mem.eql(u8, header.name, "content-length")) {
            download_size = try std.fmt.parseInt(usize, header.value, 10);
        }
    }

    var file = try std.fs.cwd().createFile(filename, .{ .read = true });
    defer file.close();

    // resize the file
    try file.seekTo(download_size - 1);
    _ = try file.write(&[_]u8{1});
    try file.seekTo(0);

    var file_memory = try std.os.mmap(
        null,
        download_size,
        std.os.PROT.READ | std.os.PROT.WRITE,
        std.os.MAP.SHARED,
        file.handle,
        0,
    );
    var file_memory_index: usize = 0;

    var total_timer = try std.time.Timer.start();
    var local_buf: [1024 * 1024]u8 = undefined;
    var bytes_read: usize = 0;
    var timer = try std.time.Timer.start();
    while (true) {
        const len = try request.read(&local_buf);
        if (len == 0) break;

        @memcpy(file_memory[file_memory_index..][0..len], local_buf[0..len]);
        file_memory_index += len;
        bytes_read += len;

        if (with_progress and bytes_read > 1024 * 1024) { // each MB
            defer {
                bytes_read = 0;
                timer.reset();
            }

            const elapsed_ns = timer.read();
            const elapsed_sec = elapsed_ns / std.time.ns_per_s;
            if (elapsed_sec == 0) continue;

            const mb_read = bytes_read / 1024 / 1024;
            if (mb_read == 0) continue;

            const ns_per_mb = elapsed_ns / mb_read;
            const mb_left = (download_size - bytes_read) / 1024 / 1024;
            const time_left_ns = mb_left * ns_per_mb;
            const mb_per_second = mb_read / elapsed_sec;

            std.debug.print("{d}% done ({d} mb/s) (time left: {d})\r", .{
                bytes_read * 100 / download_size,
                mb_per_second,
                std.fmt.fmtDuration(time_left_ns),
            });

            const total_time_seconds = total_timer.read() / std.time.ns_per_s;
            if (min_mb_per_second != null and mb_per_second < min_mb_per_second.? and total_time_seconds > 15) {
                std.debug.print("\n", .{});
                return false;
            }
        }
    }
    // make sure we got the entire file
    std.debug.assert(file_memory_index == download_size);

    return true;
}
