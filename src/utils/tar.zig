const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const ScopedThreadPool = sig.utils.thread.ScopedThreadPool;
const printTimeEstimate = sig.time.estimate.printTimeEstimate;

/// Unpack tarball is related to accounts_db so we reuse it's progress bar
const TAR_PROGRESS_UPDATES = @import("../accountsdb/db.zig").DB_LOG_RATE;

// The identifier for the scoped logger used in this file.
const Logger = sig.trace.Logger("utils.tar");

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

/// Two zeroed out blocks representing the end of an archive.
pub const sentinel_blocks: [512 * 2]u8 = .{0} ** (512 * 2);

fn writeToFile(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    file_name: []const u8,
    contents: []u8,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "writeToFile" });
    defer zone.deinit();

    defer {
        allocator.free(file_name);
        allocator.free(contents);
    }

    var file = try dir.createFile(file_name, .{ .read = true });
    defer file.close();

    const file_size = contents.len;
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
    @memcpy(memory, contents);
}

pub fn parallelUntarToFileSystem(
    allocator: std.mem.Allocator,
    logger: Logger,
    dir: std.fs.Dir,
    reader: anytype,
    n_threads: usize,
    n_files_estimate: ?usize,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "tar parallelUntarToFileSystem" });
    defer zone.deinit();

    logger.info().logf("using {d} threads to unpack snapshot", .{n_threads});

    const pool = try ScopedThreadPool(writeToFile).init(allocator, n_threads);
    defer pool.deinit(allocator);

    var timer = sig.time.Timer.start();
    var progress_timer = sig.time.Timer.start();
    var file_count: usize = 0;
    const strip_components: u32 = 0;
    loop: while (true) {
        var header_buf: [512]u8 = undefined;
        switch (try reader.readAtLeast(&header_buf, 512)) {
            0 => break,
            512 => {},
            else => |actual_size| std.debug.panic(
                "Actual file size ({d}) too small for header (< 512).",
                .{actual_size},
            ),
        }

        const header: TarHeaderMinimal = .{ .bytes = header_buf[0..512] };

        const file_size = try header.size();
        const rounded_file_size = std.mem.alignForward(u64, file_size, 512);
        const pad_len = rounded_file_size - file_size;

        var file_name_buffer: [255]u8 = undefined;
        const unstripped_file_name = try header.fullName(&file_name_buffer);

        switch (header.kind()) {
            .directory => {
                const file_name = try stripComponents(unstripped_file_name, strip_components);
                if (file_name.len != 0) {
                    try dir.makePath(file_name);
                }
            },
            .normal => {
                if (file_size == 0 and unstripped_file_name.len == 0) {
                    break :loop; // tar EOF
                }

                const file_name_stripped = try stripComponents(
                    unstripped_file_name,
                    strip_components,
                );
                if (std.fs.path.dirname(file_name_stripped)) |dir_name| {
                    try dir.makePath(dir_name);
                }

                if (n_files_estimate) |total_n_files| {
                    if (progress_timer.read().asNanos() > TAR_PROGRESS_UPDATES.asNanos()) {
                        printTimeEstimate(
                            logger,
                            &timer,
                            total_n_files,
                            file_count,
                            "untar",
                            null,
                        );
                        progress_timer.reset();
                    }
                }
                file_count += 1;

                const contents = try allocator.alloc(u8, file_size);
                errdefer allocator.free(contents);

                const actual_contents_len = try reader.readAtLeast(contents, file_size);
                if (actual_contents_len != file_size) {
                    std.debug.panic(
                        "Reported file ({d}) size does not match actual file size ({d})",
                        .{ contents.len, actual_contents_len },
                    );
                }

                try reader.skipBytes(pad_len, .{});

                const file_name = try allocator.dupe(u8, file_name_stripped);
                errdefer allocator.free(file_name);

                try pool.schedule(allocator, .{ allocator, dir, file_name, contents });
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
    pool.join() catch |err|
        logger.err().logf("UnTarTask encountered error: {s}", .{@errorName(err)});
}

/// A struct that is exactly 512 bytes and matches tar file format. This is
/// intended to be used for outputting tar files; for parsing there is
/// `std.tar.Header`.
///
/// TODO(0.15): Hopefully the change to expose this header from the stdlib
/// will have made it in, update it if so!
const TarOutputHeader = extern struct {
    // This struct was originally copied from
    // https://github.com/mattnite/tar/blob/main/src/main.zig which is MIT
    // licensed.
    //
    // The name, linkname, magic, uname, and gname are null-terminated character
    // strings. All other fields are zero-filled octal numbers in ASCII. Each
    // numeric field of width w contains w minus 1 digits, and a null.
    // Reference: https://www.gnu.org/software/tar/manual/html_node/Standard.html
    // POSIX header:                                  byte offset
    name: [100]u8 = [_]u8{0} ** 100, //                         0
    mode: [7:0]u8 = default_mode.file, //                     100
    uid: [7:0]u8 = [_:0]u8{0} ** 7, // unused                 108
    gid: [7:0]u8 = [_:0]u8{0} ** 7, // unused                 116
    size: [11:0]u8 = [_:0]u8{'0'} ** 11, //                   124
    mtime: [11:0]u8 = [_:0]u8{'0'} ** 11, //                  136
    checksum: [7:0]u8 = [_:0]u8{' '} ** 7, //                 148
    typeflag: FileType = .regular, //                         156
    linkname: [100]u8 = [_]u8{0} ** 100, //                   157
    magic: [6]u8 = [_]u8{ 'u', 's', 't', 'a', 'r', 0 }, //    257
    version: [2]u8 = [_]u8{ '0', '0' }, //                    263
    uname: [32]u8 = [_]u8{0} ** 32, // unused                 265
    gname: [32]u8 = [_]u8{0} ** 32, // unused                 297
    devmajor: [7:0]u8 = [_:0]u8{0} ** 7, // unused            329
    devminor: [7:0]u8 = [_:0]u8{0} ** 7, // unused            337
    prefix: [155]u8 = [_]u8{0} ** 155, //                     345
    pad: [12]u8 = [_]u8{0} ** 12, // unused                   500

    pub const FileType = enum(u8) {
        regular = '0',
        symbolic_link = '2',
        directory = '5',
        gnu_long_name = 'L',
        gnu_long_link = 'K',
    };

    const default_mode = struct {
        const file = [_:0]u8{ '0', '0', '0', '0', '6', '6', '4' }; // 0o664
        const dir = [_:0]u8{ '0', '0', '0', '0', '7', '7', '5' }; // 0o775
        const sym_link = [_:0]u8{ '0', '0', '0', '0', '7', '7', '7' }; // 0o777
        const other = [_:0]u8{ '0', '0', '0', '0', '0', '0', '0' }; // 0o000
    };

    pub fn init(typeflag: FileType) TarOutputHeader {
        return .{
            .typeflag = typeflag,
            .mode = switch (typeflag) {
                .directory => default_mode.dir,
                .symbolic_link => default_mode.sym_link,
                .regular => default_mode.file,
                else => default_mode.other,
            },
        };
    }

    pub fn setSize(self: *TarOutputHeader, size: u64) !void {
        try octal(&self.size, size);
    }

    fn octal(buf: []u8, value: u64) !void {
        var remainder: u64 = value;
        var pos: usize = buf.len;
        while (remainder > 0 and pos > 0) {
            pos -= 1;
            const c: u8 = @as(u8, @intCast(remainder % 8)) + '0';
            buf[pos] = c;
            remainder /= 8;
            if (pos == 0 and remainder > 0) return error.OctalOverflow;
        }
    }

    pub fn setMode(self: *TarOutputHeader, mode: u32) !void {
        try octal(&self.mode, mode);
    }

    // Integer number of seconds since January 1, 1970, 00:00 Coordinated Universal Time.
    // mtime == 0 will use current time
    pub fn setMtime(self: *TarOutputHeader, mtime: u64) !void {
        try octal(&self.mtime, mtime);
    }

    pub fn updateChecksum(self: *TarOutputHeader) !void {
        var checksum: usize = ' '; // other 7 self.checksum bytes are initialized to ' '
        for (std.mem.asBytes(self)) |val|
            checksum += val;
        try octal(&self.checksum, checksum);
    }

    pub fn write(self: *TarOutputHeader, output_writer: anytype) !void {
        try self.updateChecksum();
        try output_writer.writeAll(std.mem.asBytes(self));
    }

    pub fn setLinkname(self: *TarOutputHeader, link: []const u8) !void {
        if (link.len > self.linkname.len) return error.NameTooLong;
        @memcpy(self.linkname[0..link.len], link);
    }

    pub fn setPath(self: *TarOutputHeader, prefix: []const u8, sub_path: []const u8) !void {
        const max_prefix = self.prefix.len;
        const max_name = self.name.len;
        const sep = std.fs.path.sep_posix;

        if (prefix.len + sub_path.len > max_name + max_prefix or prefix.len > max_prefix)
            return error.NameTooLong;

        // both fit into name
        if (prefix.len > 0 and prefix.len + sub_path.len < max_name) {
            @memcpy(self.name[0..prefix.len], prefix);
            self.name[prefix.len] = sep;
            @memcpy(self.name[prefix.len + 1 ..][0..sub_path.len], sub_path);
            return;
        }

        // sub_path fits into name
        // there is no prefix or prefix fits into prefix
        if (sub_path.len <= max_name) {
            @memcpy(self.name[0..sub_path.len], sub_path);
            @memcpy(self.prefix[0..prefix.len], prefix);
            return;
        }

        if (prefix.len > 0) {
            @memcpy(self.prefix[0..prefix.len], prefix);
            self.prefix[prefix.len] = sep;
        }
        const prefix_pos = if (prefix.len > 0) prefix.len + 1 else 0;

        // add as much to prefix as you can, must split at /
        const prefix_remaining = max_prefix - prefix_pos;
        if (std.mem.lastIndexOfScalar(
            u8,
            sub_path[0..@min(prefix_remaining, sub_path.len)],
            '/',
        )) |sep_pos| {
            @memcpy(self.prefix[prefix_pos..][0..sep_pos], sub_path[0..sep_pos]);
            if ((sub_path.len - sep_pos - 1) > max_name) return error.NameTooLong;
            @memcpy(self.name[0..][0 .. sub_path.len - sep_pos - 1], sub_path[sep_pos + 1 ..]);
            return;
        }

        return error.NameTooLong;
    }
};

pub fn writeTarHeader(
    writer: anytype,
    typeflag: TarOutputHeader.FileType,
    path: []const u8,
    size: u64,
) !void {
    var header = TarOutputHeader.init(typeflag);
    _ = try std.fmt.bufPrint(&header.name, "{s}", .{path});
    try header.setSize(size);

    const mode: u21 = switch (typeflag) {
        // allow read & write, but not execution by anyone
        .regular => 0o666,
        // allow read, write, and traversal by anyone
        .directory => 0o777,
        // we don't really use anything else, so just set no permissions so that it's obvious something is wrong if this somehow occurs
        else => 0,
    };
    _ = std.fmt.bufPrint(&header.mode, "{o:0>7}", .{mode}) catch unreachable;

    try header.updateChecksum();
    try writer.writeAll(std.mem.asBytes(&header));
}

/// Returns the number of padding bytes that must be written in order to have a round 512 byte block.
/// The result is 0 if the number of bytes written already form a round 512 byte block, or if there
/// are 0 bytes written.
pub fn paddingBytes(
    /// The actual number of bytes written, or the number of bytes written modulo 512.
    bytes_written_maybe_modulo: u64,
) std.math.IntFittingRange(0, 512 - 1) {
    const modulo = bytes_written_maybe_modulo % 512;
    if (modulo == 0) return 0; // we don't want any padding if it's already a round 512 block
    return @intCast(512 - modulo);
}

/// Minimal implemenation of `std.tar.Header` since it's no longer `pub`
pub const TarHeaderMinimal = struct {
    bytes: *const [SIZE]u8,

    const SIZE = 512;
    pub const MAX_NAME_SIZE = 100 + 1 + 155; // name(100) + separator(1) + prefix(155)
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
