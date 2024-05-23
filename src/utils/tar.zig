const std = @import("std");

const ThreadPoolTask = @import("../utils/thread.zig").ThreadPoolTask;
const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const printTimeEstimate = @import("../time/estimate.zig").printTimeEstimate;

/// Unpack tarball is related to accounts_db so we reuse it's progress bar
const TAR_PROGRESS_UPDATES_NS = @import("../accountsdb/db.zig").DB_PROGRESS_UPDATES_NS;

const Options = std.tar.Options;

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
            std.posix.MAP{ .TYPE = .SHARED },
            file.handle,
            0,
        );
        @memcpy(memory, self.contents);
    }
};

/// interface struct for queueing untar tasks
pub const UnTarTask = ThreadPoolTask(UnTarEntry);

const Logger = @import("../trace/log.zig").Logger;

pub fn parallelUntarToFileSystem(
    allocator: std.mem.Allocator,
    logger: Logger,
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

    logger.infof("using {d} threads to unpack snapshot\n", .{n_threads});
    const tasks = try UnTarTask.init(allocator, n_threads);
    defer allocator.free(tasks);

    var timer = try std.time.Timer.start();
    var progress_timer = try std.time.Timer.start();
    var file_count: usize = 0;
    const strip_components: u32 = 0;
    loop: while (true) {
        var header_buf = try allocator.alloc(u8, 512);
        _ = try reader.readAtLeast(header_buf, 512);

        const header: TarHeaderMinimal = .{ .bytes = header_buf[0..512] };

        const file_size = try header.size();
        const rounded_file_size = std.mem.alignForward(u64, file_size, 512);
        const pad_len = rounded_file_size - file_size;

        var file_name_buf = try allocator.alloc(u8, 255);
        const unstripped_file_name = try header.fullName(file_name_buf[0..255]);

        switch (header.kind()) {
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

                if (n_files_estimate) |total_n_files| {
                    if (progress_timer.read() > TAR_PROGRESS_UPDATES_NS) {
                        printTimeEstimate(
                            logger,
                            &timer,
                            total_n_files,
                            file_count,
                            "untar files to disk",
                            null,
                        );
                        progress_timer.reset();
                    }
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
        while (!task.done.load(.acquire)) {
            // wait
        }
    }
}

/// Minimal implemenation of `std.tar.Header` since it's no longer `pub`
const TarHeaderMinimal = struct {
    bytes: *const [SIZE]u8,

    const SIZE = 512;
    const MAX_NAME_SIZE = 100 + 1 + 155; // name(100) + separator(1) + prefix(155)
    const LINK_NAME_SIZE = 100;

    const This = @This();

    const Kind = enum(u8) {
        normal_alias = 0,
        normal = '0',
        hard_link = '1',
        symbolic_link = '2',
        character_special = '3',
        block_special = '4',
        directory = '5',
        fifo = '6',
        contiguous = '7',
        global_extended_header = 'g',
        extended_header = 'x',
        // Types 'L' and 'K' are used by the GNU format for a meta file
        // used to store the path or link name for the next file.
        gnu_long_name = 'L',
        gnu_long_link = 'K',
        gnu_sparse = 'S',
        solaris_extended_header = 'X',
        _,
    };

    pub fn fullName(header: TarHeaderMinimal, buffer: []u8) ![]const u8 {
        const n = name(header);
        const p = prefix(header);
        if (buffer.len < n.len + p.len + 1) return error.TarInsufficientBuffer;
        if (!is_ustar(header) or p.len == 0) {
            @memcpy(buffer[0..n.len], n);
            return buffer[0..n.len];
        }
        @memcpy(buffer[0..p.len], p);
        buffer[p.len] = '/';
        @memcpy(buffer[p.len + 1 ..][0..n.len], n);
        return buffer[0 .. p.len + 1 + n.len];
    }

    pub fn size(header: TarHeaderMinimal) !u64 {
        const start = 124;
        const len = 12;
        const raw = header.bytes[start..][0..len];
        //  If the leading byte is 0xff (255), all the bytes of the field
        //  (including the leading byte) are concatenated in big-endian order,
        //  with the result being a negative number expressed in two’s
        //  complement form.
        if (raw[0] == 0xff) return error.TarNumericValueNegative;
        // If the leading byte is 0x80 (128), the non-leading bytes of the
        // field are concatenated in big-endian order.
        if (raw[0] == 0x80) {
            if (raw[1] != 0 or raw[2] != 0 or raw[3] != 0) return error.TarNumericValueTooBig;
            return std.mem.readInt(u64, raw[4..12], .big);
        }
        return try header.octal(start, len);
    }

    pub fn kind(header: TarHeaderMinimal) Kind {
        const result: Kind = @enumFromInt(header.bytes[156]);
        if (result == .normal_alias) return .normal;
        return result;
    }

    pub fn is_ustar(header: TarHeaderMinimal) bool {
        const magic = header.bytes[257..][0..6];
        return std.mem.eql(u8, magic[0..5], "ustar") and (magic[5] == 0 or magic[5] == ' ');
    }

    pub fn name(header: TarHeaderMinimal) []const u8 {
        return header.str(0, 100);
    }

    pub fn prefix(header: TarHeaderMinimal) []const u8 {
        return header.str(345, 155);
    }

    fn str(header: TarHeaderMinimal, start: usize, len: usize) []const u8 {
        return nullStr(header.bytes[start .. start + len]);
    }

    fn octal(header: TarHeaderMinimal, start: usize, len: usize) !u64 {
        const raw = header.bytes[start..][0..len];
        // Zero-filled octal number in ASCII. Each numeric field of width w
        // contains w minus 1 digits, and a null
        const ltrimmed = std.mem.trimLeft(u8, raw, "0 ");
        const rtrimmed = std.mem.trimRight(u8, ltrimmed, " \x00");
        if (rtrimmed.len == 0) return 0;
        return std.fmt.parseInt(u64, rtrimmed, 8) catch return error.TarHeader;
    }
};

// Breaks string on first null character.
fn nullStr(str: []const u8) []const u8 {
    for (str, 0..) |c, i| {
        if (c == 0) return str[0..i];
    }
    return str;
}
