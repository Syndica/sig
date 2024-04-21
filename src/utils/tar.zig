const std = @import("std");

const ThreadPoolTask = @import("../utils/thread.zig").ThreadPoolTask;
const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const printTimeEstimate = @import("../time/estimate.zig").printTimeEstimate;

const Options = std.tar.Options;
const Header = std.tar.Header;

fn stripComponents(path: []const u8, count: u32) ![]const u8 {
    var i: usize = 0;
    var c = count;
    while (c > 0) : (c -= 1) {
        if (std.mem.indexOfScalarPos(u8, path, i, '/')) |pos| {
            i = pos + 1;
        } else {
            return error.TarComponentsOutsideStrippedPrefix;
        }
    }
    return path[i..];
}

pub const UnTarEntry = struct {
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    file_name: []const u8,
    filename_buf: []u8,
    header_buf: []u8,
    contents: []u8,

    pub fn callback(self: *UnTarEntry) !void {
        defer {
            self.allocator.free(self.filename_buf);
            self.allocator.free(self.header_buf);
            self.allocator.free(self.contents);
        }

        var file = try self.dir.createFile(self.file_name, .{ .read = true });
        defer file.close();

        const file_size = self.contents.len;
        try file.seekTo(file_size - 1);
        _ = try file.write(&[_]u8{1});
        try file.seekTo(0);

        const memory = try std.posix.mmap(
            null,
            file_size,
            std.posix.PROT.WRITE,
            std.posix.MAP.SHARED,
            file.handle,
            0,
        );
        @memcpy(memory, self.contents);
    }
};

/// interface struct for queueing untar tasks
pub const UnTarTask = ThreadPoolTask(UnTarEntry);

pub fn parallelUntarToFileSystem(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    reader: anytype,
    n_threads: usize,
    n_files_estimate: ?usize,
) !void {
    var thread_pool = ThreadPool.init(.{
        .max_threads = @intCast(n_threads),
    });
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

    std.debug.print("using {d} threads to unpack snapshot\n", .{n_threads});
    const tasks = try UnTarTask.init(allocator, n_threads);
    defer allocator.free(tasks);

    var timer = try std.time.Timer.start();
    var file_count: usize = 0;
    const strip_components: u32 = 0;
    loop: while (true) {
        var header_buf = try allocator.alloc(u8, 512);
        _ = try reader.readAtLeast(header_buf, 512);

        const header: Header = .{ .bytes = header_buf[0..512] };

        const file_size = try header.fileSize();
        const rounded_file_size = std.mem.alignForward(u64, file_size, 512);
        const pad_len = rounded_file_size - file_size;

        var file_name_buf = try allocator.alloc(u8, 255);
        const unstripped_file_name = try header.fullFileName(file_name_buf[0..255]);

        switch (header.fileType()) {
            .directory => {
                const file_name = try stripComponents(unstripped_file_name, strip_components);
                if (file_name.len != 0) {
                    try dir.makePath(file_name);
                }
                allocator.free(header_buf);
                allocator.free(file_name_buf);
            },
            .normal => {
                if (file_size == 0 and unstripped_file_name.len == 0) {
                    allocator.free(header_buf);
                    allocator.free(file_name_buf);
                    break :loop; // tar EOF
                }

                const file_name = try stripComponents(unstripped_file_name, strip_components);
                if (std.fs.path.dirname(file_name)) |dir_name| {
                    try dir.makePath(dir_name);
                }

                if (n_files_estimate) |n_files| {
                    printTimeEstimate(&timer, n_files, file_count, "untar_files", null);
                }
                file_count += 1;

                const contents = try allocator.alloc(u8, file_size);
                _ = try reader.readAtLeast(contents, file_size);

                try reader.skipBytes(pad_len, .{});

                const entry = UnTarEntry{
                    .allocator = allocator,
                    .contents = contents,
                    .dir = dir,
                    .file_name = file_name,
                    .filename_buf = file_name_buf,
                    .header_buf = header_buf,
                };
                UnTarTask.queue(&thread_pool, tasks, entry);
            },
            .global_extended_header, .extended_header => {
                return error.TarUnsupportedFileType;
            },
            .hard_link => return error.TarUnsupportedFileType,
            .symbolic_link => return error.TarUnsupportedFileType,
            else => return error.TarUnsupportedFileType,
        }
    }

    // wait for all tasks
    for (tasks) |*task| {
        while (!task.done.load(std.atomic.Ordering.Acquire)) {
            // wait
        }
    }
}
