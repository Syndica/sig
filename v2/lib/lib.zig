comptime {
    if (@import("builtin").is_test) {
        _ = @import("account_pool.zig");
        _ = @import("clock.zig");
        _ = @import("collections.zig");
        _ = @import("crypto.zig");
        _ = @import("fio.zig");
        _ = @import("ipc.zig");
        _ = @import("net.zig");
        _ = @import("runner.zig");
        _ = @import("solana.zig");
        _ = @import("telemetry.zig");
        _ = @import("time.zig");
        _ = @import("util.zig");
    }
}

pub const AccountPool = @import("account_pool.zig").AccountPool;
pub const net = @import("net.zig");
pub const clock = @import("clock.zig");
pub const crypto = @import("crypto.zig");
pub const solana = @import("solana.zig");
pub const ipc = @import("ipc.zig");
pub const time = @import("time.zig");
pub const util = @import("util.zig");
pub const collections = @import("collections.zig");
pub const runner = @import("runner.zig");
pub const telemetry = @import("telemetry.zig");
pub const fio = @import("fio.zig");

pub const test_data_dir = "data/test-data/";
