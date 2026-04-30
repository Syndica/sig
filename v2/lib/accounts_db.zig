const std = @import("std");
const lib = @import("lib.zig");

pub const io = @import("accounts_db/io.zig");
pub const Table = @import("accounts_db/table.zig").Table;

const tel = lib.telemetry;

pub const DbConfig = extern struct {
    file_path: [std.fs.max_path_bytes]u8,
    file_path_len: u32,
    memory_len: usize,
    memory: [0]u8, // VLA with memory_len allocated
};
