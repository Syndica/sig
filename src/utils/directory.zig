const std = @import("std");

/// Reads all the files in a directory. Does not iterate into sub-directories.
///
/// The caller owns the memory returned and needs to free it.
pub fn readDirectory(
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
) ![]const []const u8 {
    var dir_iter = directory.iterate();

    var filenames = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (filenames.items) |name| allocator.free(name);
        filenames.deinit();
    }

    while (try dir_iter.next()) |entry| {
        if (entry.kind == .file) {
            const owned_name = try allocator.dupe(u8, entry.name);
            errdefer allocator.free(owned_name);
            try filenames.append(owned_name);
        }
    }

    return filenames.toOwnedSlice();
}
