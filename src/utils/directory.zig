const std = @import("std");
const ArrayList = std.ArrayList;

/// reads all the files in a directory.
/// returns a list of filenames and the underlying memory for the filenames.
/// note: we prealloc the full underlying memory for all the filenames to be fast.
pub fn readDirectory(
    allocator: std.mem.Allocator,
    directory_iter: std.fs.Dir.Iterator,
) !struct { filenames: ArrayList([]u8), filename_memory: []u8 } {
    var dir_iter = directory_iter;
    var total_name_size: usize = 0;
    var total_files: usize = 0;
    while (try dir_iter.next()) |entry| {
        total_name_size += entry.name.len;
        total_files += 1;
    }

    const filename_memory = try allocator.alloc(u8, total_name_size);
    errdefer allocator.free(filename_memory);

    dir_iter.reset(); // reset

    var filenames = try ArrayList([]u8).initCapacity(allocator, total_files);
    errdefer filenames.deinit();

    var index: usize = 0;
    while (try dir_iter.next()) |file_entry| {
        const file_name_len = file_entry.name.len;
        @memcpy(filename_memory[index..(index + file_name_len)], file_entry.name);
        filenames.appendAssumeCapacity(filename_memory[index..(index + file_name_len)]);
        index += file_name_len;
    }
    dir_iter.reset(); // reset

    return .{ .filenames = filenames, .filename_memory = filename_memory };
}
