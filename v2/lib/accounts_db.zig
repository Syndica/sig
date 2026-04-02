const std = @import("std");
const lib = @import("lib.zig");

const Signature = lib.solana.Signature;
const Pubkey = lib.solana.Pubkey;
const Hash = lib.solana.Hash;
const Slot = lib.solana.Slot;

pub const Config = struct {
    folder_path: [std.fs.max_path_bytes]u8,
    folder_path_len: u8,

    min_snapshot_download_speed_mb: u64,
    min_snapshot_download_warmup_ns: u64,
};
