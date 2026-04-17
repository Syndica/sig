//! Runs a node instance of the gossip protocol, passing around cluster information from the network
//! to other validator services.

const std = @import("std");
const start = @import("start");
const lib = @import("lib");

const tel = lib.telemetry;

const SlotAndHash = lib.solana.SlotAndHash;

comptime {
    _ = start;
}

pub const name = .accounts_db;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    snapshot_queue: *lib.accounts_db.SnapshotQueue,
    tel: *tel.Region,
};

pub const ReadOnly = struct {
    config: *const lib.accounts_db.Config,
};

var scratch_mem: [1 * 1024 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    const folder = ro.config.folder_path[0..ro.config.folder_path_len];
    logger.info().logf("AccountsDB started in {s}", .{folder});

    var snapshot_dir = try std.fs.cwd().openDir(folder, .{ .iterate = true });
    defer snapshot_dir.close();

    var snapshot_addr_reader = rw.snapshot_queue.incoming.get(.reader);
    const snapshot_file, const slot_hash = try findOrDownloadSnapshot(
        .from(logger),
        snapshot_dir,
        &snapshot_addr_reader,
        ro.config.snapshot_download,
    );
    defer snapshot_file.close();

    const Global = struct {
        var db: lib.accounts_db.snapshot.load.Db = undefined;
    };
    const db = &Global.db;
    try db.init(snapshot_dir, "accounts.db");
    defer db.deinit();

    var fba = std.heap.FixedBufferAllocator.init(&scratch_mem);
    _ = try lib.accounts_db.snapshot.loadSnapshot(
        .from(logger),
        &fba,
        slot_hash,
        snapshot_file,
        db,
    );
    try db.sync(.from(logger));
    logger.info().logf("finished loading snapshot", .{});

    while (true) std.atomic.spinLoopHint();
}

fn findOrDownloadSnapshot(
    logger: tel.Logger("findOrDownloadSnapshot"),
    snapshot_dir: std.fs.Dir,
    snapshot_addr_reader: *lib.accounts_db.SnapshotQueue.Incoming.Iterator(.reader),
    dl_config: lib.accounts_db.snapshot.DownloadConfig,
) !struct { std.fs.File, SlotAndHash } {
    if (try lib.accounts_db.snapshot.findExistingSnapshot(snapshot_dir)) |found| {
        const sh = &found.@"1";
        logger.info().logf(
            "Found existing snapshot: ./snapshot-{d}-{f}.tar.zst",
            .{ sh.slot, sh.hash },
        );
        return found;
    }

    logger.debug().logf("Waiting for snapshot from gossip...", .{});
    while (true) {
        const entry_ptr = snapshot_addr_reader.next() orelse continue;
        const e = entry_ptr.*;
        snapshot_addr_reader.markUsed();

        // TODO: downgrade to debug once per-service filtering is implemented
        logger.info().logf(
            "Downloading snapshot from http://{f}/snapshot-{d}-{f}.tar.zst",
            .{ e.rpc_address, e.slot_hash.slot, e.slot_hash.hash },
        );
        const snapshot_file = lib.accounts_db.snapshot.downloadSnapshot(
            .from(logger),
            snapshot_dir,
            e.slot_hash,
            e.rpc_address,
            dl_config,
        ) catch |err| {
            logger.err().logf("snapshot download from {f} failed: {}", .{ e.rpc_address, err });
            continue;
        };

        logger.info().logf(
            "Downloaded ./snapshot-{d}-{f}.tar.zst",
            .{ e.slot_hash.slot, e.slot_hash.hash },
        );
        return .{ snapshot_file, e.slot_hash };
    }
}
