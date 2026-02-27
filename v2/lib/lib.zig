const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

pub const net = @import("net.zig");
pub const crypto = @import("crypto.zig");
pub const solana = @import("solana.zig");
pub const shred = @import("shred.zig");
pub const gossip = @import("gossip.zig");
pub const ipc = @import("ipc.zig");
pub const linux = @import("linux.zig");
pub const util = @import("util.zig");
pub const observability = @import("observability.zig");

comptime {
    _ = net;
    _ = crypto;
    _ = solana;
    _ = shred;
    _ = gossip;
    _ = ipc;
    _ = linux;
    _ = observability;
}

pub const test_data_dir = "../data/test-data/";
