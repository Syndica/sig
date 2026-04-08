//! Runs a node instance of the gossip protocol, passing around cluster information from the network
//! to other validator services.

const std = @import("std");
const start = @import("start");
const lib = @import("lib");

comptime {
    _ = start;
}

pub const name = .accounts_db;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    snapshot_queue: *lib.accounts_db.SnapshotQueue,
};

pub const ReadOnly = struct {
    config: *const lib.accounts_db.Config,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const folder = ro.config.folder_path[0..ro.config.folder_path_len];
    std.log.info("AccountsDB started in {s}", .{folder});

    var snapshot_dir = try std.fs.cwd().openDir(folder, .{ .iterate = true });
    defer snapshot_dir.close();

    var snapshot_addr_reader = rw.snapshot_queue.incoming.get(.reader);
    const snapshot_file = try findOrDownloadSnapshot(
        snapshot_dir,
        &snapshot_addr_reader,
        ro.config.snapshot_download,
    );
    defer snapshot_file.close();

    while (true) std.atomic.spinLoopHint();
}

fn findOrDownloadSnapshot(
    snapshot_dir: std.fs.Dir,
    snapshot_addr_reader: *lib.accounts_db.SnapshotQueue.Incoming.Iterator(.reader),
    dl_config: lib.accounts_db.snapshot.DownloadConfig,
) !std.fs.File {
    if (try lib.accounts_db.snapshot.findExistingSnapshot(snapshot_dir)) |found| {
        const snapshot_file, const sh = found;
        std.log.info("Found existing snapshot: ./snapshot-{d}-{f}.tar.zst", .{ sh.slot, sh.hash });
        return snapshot_file;
    }

    var path_buf: [512]u8 = undefined;
    std.log.debug("Waiting for snapshot from gossip...", .{});
    while (true) {
        const e = snapshot_addr_reader.next() orelse continue;
        const addr = e.rpc_address;
        const path = try std.fmt.bufPrint(
            &path_buf,
            "snapshot-{d}-{f}.tar.zst",
            .{ e.slot_hash.slot, e.slot_hash.hash },
        );
        snapshot_addr_reader.markUsed();

        std.log.info("Downloading snapshot from http://{f}/{s}", .{ addr, path });
        const snapshot_file = lib.accounts_db.snapshot.downloadSnapshot(
            snapshot_dir,
            path,
            addr,
            dl_config,
        ) catch |err| {
            std.log.err("snapshot download from {f} failed: {}", .{ addr, err });
            continue;
        };

        std.log.info("Downloaded {s}", .{path});
        return snapshot_file;
    }
}
