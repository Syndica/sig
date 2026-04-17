const std = @import("std");
pub const snapshot = @import("accounts_db/snapshot.zig");

pub const SnapshotQueue = snapshot.Queue;

pub const Config = struct {
    folder_path: [std.fs.max_path_bytes]u8,
    folder_path_len: u8,
    snapshot_download: snapshot.DownloadConfig,
};
