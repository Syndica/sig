comptime {
    if (@import("builtin").is_test) {
        _ = @import("clock.zig");
        _ = @import("collections.zig");
        _ = @import("crypto.zig");
        _ = @import("gossip.zig");
        _ = @import("ipc.zig");
        _ = @import("linux.zig");
        _ = @import("net.zig");
        _ = @import("shred.zig");
        _ = @import("snapshot.zig");
        _ = @import("solana.zig");
        _ = @import("telemetry.zig");
        _ = @import("util.zig");
    }
}

pub const net = @import("net.zig");
pub const clock = @import("clock.zig");
pub const crypto = @import("crypto.zig");
pub const solana = @import("solana.zig");
pub const shred = @import("shred.zig");
pub const gossip = @import("gossip.zig");
pub const ipc = @import("ipc.zig");
pub const linux = @import("linux.zig");
pub const util = @import("util.zig");
pub const collections = @import("collections.zig");
pub const snapshot = @import("snapshot.zig");
pub const telemetry = @import("telemetry.zig");
pub const accounts_db = @import("accounts_db.zig");
pub const fio = @import("fio.zig");

comptime {
    _ = net;
    _ = clock;
    _ = crypto;
    _ = solana;
    _ = shred;
    _ = gossip;
    _ = ipc;
    _ = linux;
    _ = snapshot;
    _ = telemetry;
    _ = snapshot;
    _ = accounts_db;
}

pub const test_data_dir = "../data/test-data/";
