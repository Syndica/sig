const std = @import("std");
const sig = @import("sig");

const Radix = sig.accounts_db.CompressedAccountRadix;

const INDEX_MAGIC = "CHIMIDX1";
const INDEX_HEADER_LEN: usize = 64;
const INDEX_RECORD_LEN_V1: u32 = 64;
const INDEX_RECORD_LEN_V2: u32 = 44;
const INDEX_FORMAT_VERSION_V1: u32 = 1;
const INDEX_FORMAT_VERSION_V2: u32 = 2;
const DEFAULT_READ_MIB: usize = 32;
const PROGRESS_ROWS: u64 = 50_000_000;

const Args = struct {
    index_path: []u8,
    output_path: []u8,
    prefix_bits: u32 = Radix.DEFAULT_PREFIX_BITS,
    read_mib: usize = DEFAULT_READ_MIB,

    fn deinit(self: *Args, allocator: std.mem.Allocator) void {
        allocator.free(self.index_path);
        allocator.free(self.output_path);
        self.* = undefined;
    }
};

const IndexMetadata = struct {
    file_size: u64,
    row_count: u64,
    records_offset: u64,
    record_len: u32,
    shard_prefix_bits: u32,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = parseArgs(allocator) catch |err| {
        printHelp();
        return err;
    };
    defer args.deinit(allocator);

    var index_file = try std.fs.cwd().openFile(args.index_path, .{ .mode = .read_only });
    defer index_file.close();
    const metadata = try readIndexMetadata(&index_file);
    if (args.prefix_bits < metadata.shard_prefix_bits or args.prefix_bits > Radix.MAX_PREFIX_BITS)
        return error.InvalidPrefixBits;
    if (metadata.row_count > std.math.maxInt(u32))
        return error.RadixRowCountOverflow;

    const boundary_count = try Radix.boundaryCount(args.prefix_bits);
    const boundaries = try allocator.alloc(u32, boundary_count);
    defer allocator.free(boundaries);

    const read_bytes = std.math.mul(usize, args.read_mib, 1024 * 1024) catch
        return error.InvalidReadSize;
    const index_record_len: usize = @intCast(metadata.record_len);
    const rows_per_read = read_bytes / index_record_len;
    if (rows_per_read == 0) return error.InvalidReadSize;
    const scan_buffer = try allocator.alloc(u8, rows_per_read * index_record_len);
    defer allocator.free(scan_buffer);

    std.debug.print(
        "compressed_account_index_radix_start index={s} output={s} rows={} prefix_bits={} boundaries={} read_mib={}\n",
        .{
            args.index_path,
            args.output_path,
            metadata.row_count,
            args.prefix_bits,
            boundary_count,
            args.read_mib,
        },
    );

    var timer = try std.time.Timer.start();
    var row: u64 = 0;
    var next_boundary: usize = 0;
    var previous_prefix: u32 = 0;
    var have_previous_prefix = false;
    var next_progress: u64 = PROGRESS_ROWS;

    while (row < metadata.row_count) {
        const rows_remaining = metadata.row_count - row;
        const rows_this_read: usize = @intCast(@min(rows_remaining, rows_per_read));
        const bytes_this_read = rows_this_read * index_record_len;
        const offset = metadata.records_offset + row * @as(u64, metadata.record_len);
        if (try index_file.preadAll(scan_buffer[0..bytes_this_read], offset) != bytes_this_read)
            return error.InvalidCompressedAccountIndex;

        var local_row: usize = 0;
        while (local_row < rows_this_read) : (local_row += 1) {
            const record_offset = local_row * index_record_len;
            const prefix = prefixFromRecord(scan_buffer[record_offset..][0..3], args.prefix_bits);
            if (have_previous_prefix and prefix < previous_prefix)
                return error.UnsortedCompressedAccountIndex;
            previous_prefix = prefix;
            have_previous_prefix = true;

            const global_row: u32 = @intCast(row + local_row);
            while (next_boundary <= prefix) : (next_boundary += 1) {
                boundaries[next_boundary] = global_row;
            }
        }
        row += rows_this_read;

        if (row >= next_progress or row == metadata.row_count) {
            std.debug.print(
                "compressed_account_index_radix_progress rows={}/{} elapsed_s={d:.1}\n",
                .{ row, metadata.row_count, @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_s },
            );
            while (next_progress <= row) next_progress +%= PROGRESS_ROWS;
        }
    }

    while (next_boundary < boundaries.len) : (next_boundary += 1) {
        boundaries[next_boundary] = @intCast(metadata.row_count);
    }

    var max_bucket_rows: u32 = 0;
    var empty_buckets: u64 = 0;
    for (boundaries[0 .. boundaries.len - 1], boundaries[1..]) |lo, hi| {
        const bucket_rows = hi - lo;
        max_bucket_rows = @max(max_bucket_rows, bucket_rows);
        empty_buckets += @intFromBool(bucket_rows == 0);
    }

    const header = try Radix.encodeHeader(
        args.prefix_bits,
        metadata.record_len,
        metadata.row_count,
        metadata.file_size,
        metadata.records_offset,
    );
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{args.output_path});
    defer allocator.free(temp_path);
    std.fs.cwd().deleteFile(temp_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    errdefer std.fs.cwd().deleteFile(temp_path) catch {};

    var output_file = try std.fs.cwd().createFile(temp_path, .{ .truncate = true });
    var output_open = true;
    defer if (output_open) output_file.close();
    try output_file.writeAll(&header);
    for (boundaries) |*boundary| {
        boundary.* = std.mem.nativeToLittle(u32, boundary.*);
    }
    try output_file.writeAll(std.mem.sliceAsBytes(boundaries));
    try output_file.sync();
    output_file.close();
    output_open = false;
    try std.fs.cwd().rename(temp_path, args.output_path);

    const output_bytes = Radix.HEADER_LEN + boundaries.len * @sizeOf(u32);
    std.debug.print(
        "compressed_account_index_radix_complete output={s} bytes={} rows={} prefix_bits={} buckets={} empty_buckets={} max_bucket_rows={} elapsed_s={d:.1}\n",
        .{
            args.output_path,
            output_bytes,
            metadata.row_count,
            args.prefix_bits,
            boundaries.len - 1,
            empty_buckets,
            max_bucket_rows,
            @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_s,
        },
    );
}

fn readIndexMetadata(file: *std.fs.File) !IndexMetadata {
    var header: [INDEX_HEADER_LEN]u8 = undefined;
    if (try file.preadAll(&header, 0) != header.len)
        return error.InvalidCompressedAccountIndex;
    if (!std.mem.eql(u8, header[0..INDEX_MAGIC.len], INDEX_MAGIC))
        return error.InvalidCompressedAccountIndex;

    const version = readU32(&header, 8);
    const record_len = readU32(&header, 12);
    const shard_prefix_bits = readU32(&header, 16);
    const row_count = readU64(&header, 24);
    const records_offset = readU64(&header, 40);
    if (!isSupportedIndexFormat(version, record_len) or
        shard_prefix_bits == 0 or
        shard_prefix_bits > 16)
    {
        return error.InvalidCompressedAccountIndex;
    }

    const records_bytes = std.math.mul(u64, row_count, @as(u64, record_len)) catch
        return error.InvalidCompressedAccountIndex;
    const expected_file_size = std.math.add(u64, records_offset, records_bytes) catch
        return error.InvalidCompressedAccountIndex;
    const file_size = try file.getEndPos();
    if (file_size != expected_file_size)
        return error.InvalidCompressedAccountIndex;

    return .{
        .file_size = file_size,
        .row_count = row_count,
        .records_offset = records_offset,
        .record_len = record_len,
        .shard_prefix_bits = shard_prefix_bits,
    };
}

fn prefixFromRecord(bytes: *const [3]u8, bits: u32) u32 {
    const first_24 = (@as(u32, bytes[0]) << 16) |
        (@as(u32, bytes[1]) << 8) |
        bytes[2];
    return first_24 >> @intCast(24 - bits);
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    var index_path: ?[]u8 = null;
    errdefer if (index_path) |path| allocator.free(path);
    var output_path: ?[]u8 = null;
    errdefer if (output_path) |path| allocator.free(path);
    var prefix_bits = Radix.DEFAULT_PREFIX_BITS;
    var read_mib: usize = DEFAULT_READ_MIB;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--index") and i + 1 < argv.len) {
            i += 1;
            if (index_path) |path| allocator.free(path);
            index_path = try allocator.dupe(u8, argv[i]);
        } else if (std.mem.eql(u8, arg, "--output") and i + 1 < argv.len) {
            i += 1;
            if (output_path) |path| allocator.free(path);
            output_path = try allocator.dupe(u8, argv[i]);
        } else if (std.mem.eql(u8, arg, "--prefix-bits") and i + 1 < argv.len) {
            i += 1;
            prefix_bits = try std.fmt.parseInt(u32, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--read-mib") and i + 1 < argv.len) {
            i += 1;
            read_mib = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--help")) {
            printHelp();
            std.process.exit(0);
        } else {
            return error.InvalidArgument;
        }
    }

    return .{
        .index_path = index_path orelse return error.MissingIndexPath,
        .output_path = output_path orelse return error.MissingOutputPath,
        .prefix_bits = prefix_bits,
        .read_mib = read_mib,
    };
}

fn printHelp() void {
    std.debug.print(
        \\Usage:
        \\  zig build compressed_index_radix -- --index /path/account-index.bin --output /path/account-index.radix
        \\
        \\Options:
        \\  --prefix-bits N  Dense prefix width (default 24, maximum 24)
        \\  --read-mib N     Sequential scan buffer in MiB (default 32)
        \\
    , .{});
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn readU64(bytes: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, bytes[offset..][0..8], .little);
}

fn isSupportedIndexFormat(version: u32, record_len: u32) bool {
    return (version == INDEX_FORMAT_VERSION_V1 and record_len == INDEX_RECORD_LEN_V1) or
        (version == INDEX_FORMAT_VERSION_V2 and record_len == INDEX_RECORD_LEN_V2);
}
