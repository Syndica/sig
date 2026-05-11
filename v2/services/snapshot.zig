const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const tel = lib.telemetry;

const download = lib.snapshot.download;

const IoUring = std.os.linux.IoUring;

const Address = lib.gossip.Address;
const Slot = lib.solana.Slot;
const Hash = lib.solana.Hash;

const SnapshotSourceRing = lib.snapshot.SnapshotSourceRing;
const Metrics = download.Metrics;
const DownloadResult = download.DownloadResult;
const PeerState = download.PeerState;
const ProbeConn = download.ProbeConn;
const DownloadConn = download.DownloadConn;
const Downloader = download.Downloader;
const DownloadRace = download.DownloadRace;
const DedupeMap = download.DedupeMap;

var dedupe_map_buf: [512 * 1024]u8 = @splat(0);

comptime {
    _ = start;
}

// Note: matches services.zon name
pub const name = .snapshot;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {
    config: *const lib.snapshot.SnapshotConfig,
};

pub const ReadWrite = struct {
    tel: *tel.Region,
    gossip_to_snapshot: *SnapshotSourceRing,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "snapshot");
    const metrics = rw.tel.metricAppender().appendFields(Metrics, Metrics.fields_config);

    rw.tel.signalReady();

    const folder_path = ro.config.folder_buffer[0..ro.config.folder_len];
    const known_validators = ro.config.knownValidators();

    const result: DownloadResult = result: {
        std.fs.cwd().makeDir(folder_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => |e| return e,
        };

        logger.info().logf("snapshot path {s}", .{folder_path});

        if (try download.findExistingSnapshot(folder_path)) |existing| {
            break :result .{ .already_exists = existing };
        }

        var dedupe_fba = std.heap.FixedBufferAllocator.init(&dedupe_map_buf);
        var dedupe_map = DedupeMap{};
        var gossip_iter = rw.gossip_to_snapshot.get(.reader);

        // TODO: create a .init for Downloader and move all this crap into lib/snapshot/download.zig
        var downloader = Downloader{
            .ring = try IoUring.init(256, 0),
            .gossip_iter = &gossip_iter,
            .dedupe_map = &dedupe_map,
            .dedupe_alloc = dedupe_fba.allocator(),
            .known_validators = known_validators,
            .probe_conns = .{ProbeConn.empty()} ** download.MAX_CONCURRENT_PROBES,
            .active_probes = 0,
            .timeout_pending = false,
            .download_conns = .{DownloadConn.empty()} ** download.MAX_DOWNLOAD_RACERS,
            .active_downloads = 0,
            .download_race = DownloadRace.empty(),
            .snapshot_dir = folder_path,
            .run_result = null,
            .metrics = metrics,
            .logger = logger,
        };
        defer downloader.deinit();

        break :result try downloader.run();
    };

    switch (result) {
        .already_exists => |existing| {
            logger.info().logf("snapshot already exists, skipping download name={s}", .{
                existing.name(),
            });
        },
        .downloaded => |snapshot| {
            // TODO: would be better to return the final path that was downloaded. Or, add a method
            // on CompletedSnapshot that takes in a buffer and constructs the path to snapshot.
            // Likely will refactor this as part of the other TODOs around constructing paths
            // (temp paths included) just once.
            logger.info().logf("snapshot download completed slot={d} hash={f}", .{
                snapshot.slot,
                snapshot.hash,
            });
        },
        .failed => |reason| {
            logger.err().logf("snapshot download failed reason={s}", .{
                @tagName(reason),
            });
        },
    }

    while (true) std.atomic.spinLoopHint();
}
