const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

pub const sector_size = 4096; // buffer alignment for O_DIRECT accesses

pub const FileWriter = @import("fio/writer.zig").FileWriter;
pub const FileReader = @import("fio/reader.zig").FileReader;

pub fn openDirect(dir: std.fs.Dir, path: []const u8, mode: enum { rw, read_only }) !std.fs.File {
    return .{ .handle = try std.posix.openat(
        dir.fd,
        path,
        .{
            .ACCMODE = if (mode == .rw) .RDWR else .RDONLY,
            .CREAT = mode == .rw,
            .NOATIME = true,
            .CLOEXEC = true,
            .DIRECT = true,
        },
        0o777,
    ) };
}
