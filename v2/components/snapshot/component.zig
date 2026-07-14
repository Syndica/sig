//! The `snapshot` component wraps the peer-selection + HTTP download
//! machinery around the public `api` surface (`SnapshotConfig`,
//! `SnapshotSourceRing`, `SnapshotDataRing`, `ReadySnapshot`) that other
//! services and main.zig use to allocate the shared-memory regions.

comptime {
    if (@import("builtin").is_test) {
        _ = @import("download.zig");
    }
}

pub const api = @import("api");

pub const download = @import("download.zig");
