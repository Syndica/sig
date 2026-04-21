const std = @import("std");
const lib = @import("lib.zig");

pub const SnapshotConfig = extern struct {
    // TODO rename to "path"
    folder_buffer: [std.fs.max_path_bytes]u8,
    folder_len: u32,
    cluster: lib.solana.Cluster,
};
