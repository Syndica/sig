const std = @import("std");

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

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

pub const TarEntry = struct {
    contents: []u8,
    file_name: []const u8,
    filename_buf: []u8,
    header_buf: []u8,
};

const TarTask = struct {
    entry: TarEntry,
    task: Task,
    dir: std.fs.Dir,
    has_run: bool = false,
    done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(true),

    pub fn callback(task: *Task) void {
        var self = @fieldParentPtr(@This(), "task", task);
        std.debug.assert(!self.done.load(std.atomic.Ordering.Acquire));
        defer self.has_run = true;
        defer self.done.store(true, std.atomic.Ordering.Release);

        // std.debug.print("filename: {s}\n", .{self.entry.file_name});
        var file = self.dir.createFile(self.entry.file_name, .{ .read = true }) catch |err| {
            std.debug.print("TarTask error: {}\n", .{err});
            return;
        };
        defer file.close();

        const aligned_file_size = std.mem.alignForward(u64, self.entry.contents.len, std.mem.page_size);
        file.seekTo(aligned_file_size - 1) catch |err| {
            std.debug.print("TarTask error: {}\n", .{err});
            return;
        };
        _ = file.write(&[_]u8{1}) catch |err| {
            std.debug.print("TarTask error: {}\n", .{err});
            return;
        };
        file.seekTo(0) catch |err| {
            std.debug.print("TarTask error: {}\n", .{err});
            return;
        };

        var memory = std.os.mmap(
            null,
            self.entry.contents.len,
            std.os.PROT.WRITE,
            std.os.MAP.SHARED,
            file.handle,
            0,
        ) catch |err| {
            std.debug.print("TarTask error: {}\n", .{err});
            return;
        };
        @memcpy(memory, self.entry.contents);
    }
};

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
    var tasks = try allocator.alloc(TarTask, n_threads);
    defer allocator.free(tasks);
    for (tasks) |*t| {
        t.* = .{ .entry = undefined, .dir = dir, .task = .{ .callback = TarTask.callback } };
    }

    var timer = try std.time.Timer.start();
    var file_count: usize = 0;
    var task_i: usize = 0;
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

                var contents = try allocator.alloc(u8, file_size);
                _ = try reader.readAtLeast(contents, file_size);

                try reader.skipBytes(pad_len, .{});

                const entry = TarEntry{
                    .contents = contents,
                    .file_name = file_name,
                    .filename_buf = file_name_buf,
                    .header_buf = header_buf,
                };

                // find a free task
                var task_ptr = &tasks[task_i];
                while (!task_ptr.done.load(std.atomic.Ordering.Acquire)) {
                    task_i = (task_i + 1) % n_threads;
                    task_ptr = &tasks[task_i];
                }
                if (task_ptr.has_run) {
                    allocator.free(task_ptr.entry.filename_buf);
                    allocator.free(task_ptr.entry.header_buf);
                    allocator.free(task_ptr.entry.contents);
                    task_ptr.has_run = false;
                }

                task_ptr.entry = entry;
                task_ptr.done.store(false, std.atomic.Ordering.Release);

                const batch = Batch.from(&task_ptr.task);
                thread_pool.schedule(batch);
            },
            .global_extended_header, .extended_header => {
                try reader.skipBytes(rounded_file_size, .{});
                allocator.free(header_buf);
                allocator.free(file_name_buf);
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
        if (task.has_run) {
            allocator.free(task.entry.filename_buf);
            allocator.free(task.entry.contents);
            allocator.free(task.entry.header_buf);
        }
    }
}
