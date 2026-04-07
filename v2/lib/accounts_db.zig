const std = @import("std");
const snapshots = @import("accounts_db/snapshots.zig");

pub const SnapshotQueue = snapshots.Queue;

pub const Config = struct {
    folder_path: [std.fs.max_path_bytes]u8,
    folder_path_len: u8,

    min_snapshot_download_speed_mb: u64,
    min_snapshot_download_warmup_ms: u64,
};
