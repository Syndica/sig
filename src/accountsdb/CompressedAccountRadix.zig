//! Dense pubkey-prefix boundaries for narrowing compressed account index reads.
const std = @import("std");

const CompressedAccountRadix = @This();

pub const MAGIC = "CHIMRDX1";
pub const HEADER_LEN: usize = 64;
pub const FORMAT_VERSION: u32 = 1;
pub const DEFAULT_PREFIX_BITS: u32 = 24;
pub const MAX_PREFIX_BITS: u32 = 24;

prefix_bits: u32,
boundaries: []u32,

pub const ExpectedIndex = struct {
    file_size: u64,
    row_count: u64,
    records_offset: u64,
    record_len: u32,
    min_prefix_bits: u32 = 1,
};

pub const Range = struct {
    lo: u64,
    hi: u64,
};

pub fn load(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: ExpectedIndex,
) !CompressedAccountRadix {
    var file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();
    return loadFile(allocator, &file, expected);
}

fn loadFile(
    allocator: std.mem.Allocator,
    file: *std.fs.File,
    expected: ExpectedIndex,
) !CompressedAccountRadix {
    var header: [HEADER_LEN]u8 = undefined;
    if (try file.preadAll(&header, 0) != header.len)
        return error.InvalidCompressedAccountRadix;
    if (!std.mem.eql(u8, header[0..MAGIC.len], MAGIC))
        return error.InvalidCompressedAccountRadix;

    const version = readU32(&header, 8);
    const prefix_bits = readU32(&header, 12);
    const index_record_len = readU32(&header, 16);
    const index_row_count = readU64(&header, 24);
    const index_file_size = readU64(&header, 32);
    const index_records_offset = readU64(&header, 40);
    const boundary_count = readU64(&header, 48);

    if (version != FORMAT_VERSION or
        prefix_bits < expected.min_prefix_bits or
        prefix_bits > MAX_PREFIX_BITS or
        index_record_len != expected.record_len or
        index_row_count != expected.row_count or
        index_file_size != expected.file_size or
        index_records_offset != expected.records_offset or
        expected.row_count > std.math.maxInt(u32))
    {
        return error.InvalidCompressedAccountRadix;
    }

    const expected_boundary_count = try boundaryCount(prefix_bits);
    if (boundary_count != expected_boundary_count)
        return error.InvalidCompressedAccountRadix;
    const payload_bytes = std.math.mul(u64, boundary_count, @sizeOf(u32)) catch
        return error.InvalidCompressedAccountRadix;
    const expected_file_size = std.math.add(u64, HEADER_LEN, payload_bytes) catch
        return error.InvalidCompressedAccountRadix;
    if (try file.getEndPos() != expected_file_size)
        return error.InvalidCompressedAccountRadix;

    const boundaries = try allocator.alloc(u32, expected_boundary_count);
    errdefer allocator.free(boundaries);
    const boundary_bytes = std.mem.sliceAsBytes(boundaries);
    if (try file.preadAll(boundary_bytes, HEADER_LEN) != boundary_bytes.len)
        return error.InvalidCompressedAccountRadix;
    for (boundaries) |*boundary| {
        boundary.* = std.mem.littleToNative(u32, boundary.*);
    }

    if (boundaries[0] != 0 or boundaries[boundaries.len - 1] != expected.row_count)
        return error.InvalidCompressedAccountRadix;
    var previous: u32 = 0;
    for (boundaries) |boundary| {
        if (boundary < previous or boundary > expected.row_count)
            return error.InvalidCompressedAccountRadix;
        previous = boundary;
    }

    return .{
        .prefix_bits = prefix_bits,
        .boundaries = boundaries,
    };
}

pub fn deinit(self: *CompressedAccountRadix, allocator: std.mem.Allocator) void {
    allocator.free(self.boundaries);
    self.* = undefined;
}

pub fn rangeForPubkey(self: *const CompressedAccountRadix, pubkey: *const [32]u8) Range {
    const prefix = prefixForBytes(pubkey, self.prefix_bits);
    return .{
        .lo = self.boundaries[prefix],
        .hi = self.boundaries[prefix + 1],
    };
}

pub fn boundaryCount(prefix_bits: u32) !usize {
    if (prefix_bits == 0 or prefix_bits > MAX_PREFIX_BITS)
        return error.InvalidCompressedAccountRadix;
    return (@as(usize, 1) << @intCast(prefix_bits)) + 1;
}

pub fn prefixForBytes(bytes: []const u8, bits: u32) u32 {
    std.debug.assert(bits > 0 and bits <= MAX_PREFIX_BITS);
    std.debug.assert(bytes.len * 8 >= bits);

    var value: u32 = 0;
    var remaining = bits;
    var offset: usize = 0;
    while (remaining > 0) {
        const take = @min(@as(u32, 8), remaining);
        const take_shift: u5 = @intCast(take);
        const right_shift: u5 = @intCast(8 - take);
        value = (value << take_shift) | (@as(u32, bytes[offset]) >> right_shift);
        remaining -= take;
        offset += 1;
    }
    return value;
}

pub fn encodeHeader(
    prefix_bits: u32,
    index_record_len: u32,
    index_row_count: u64,
    index_file_size: u64,
    index_records_offset: u64,
) ![HEADER_LEN]u8 {
    const boundary_count = try boundaryCount(prefix_bits);
    var header = [_]u8{0} ** HEADER_LEN;
    @memcpy(header[0..MAGIC.len], MAGIC);
    std.mem.writeInt(u32, header[8..12], FORMAT_VERSION, .little);
    std.mem.writeInt(u32, header[12..16], prefix_bits, .little);
    std.mem.writeInt(u32, header[16..20], index_record_len, .little);
    std.mem.writeInt(u64, header[24..32], index_row_count, .little);
    std.mem.writeInt(u64, header[32..40], index_file_size, .little);
    std.mem.writeInt(u64, header[40..48], index_records_offset, .little);
    std.mem.writeInt(u64, header[48..56], boundary_count, .little);
    return header;
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn readU64(bytes: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, bytes[offset..][0..8], .little);
}

test "radix prefix uses the high pubkey bits" {
    const bytes = [_]u8{ 0xab, 0xcd, 0xef, 0x12 };
    try std.testing.expectEqual(@as(u32, 0xa), prefixForBytes(&bytes, 4));
    try std.testing.expectEqual(@as(u32, 0xabc), prefixForBytes(&bytes, 12));
    try std.testing.expectEqual(@as(u32, 0xabcdef), prefixForBytes(&bytes, 24));
}

test "radix sidecar validates and returns row ranges" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("fixture.radix", .{ .read = true });
    defer file.close();

    const header = try encodeHeader(2, 64, 6, 1024, 128);
    try file.writeAll(&header);
    const boundaries = [_]u32{ 0, 2, 2, 5, 6 };
    var encoded: [boundaries.len * @sizeOf(u32)]u8 = undefined;
    for (boundaries, 0..) |boundary, i| {
        std.mem.writeInt(u32, encoded[i * 4 ..][0..4], boundary, .little);
    }
    try file.writeAll(&encoded);

    var radix = try loadFile(testing.allocator, &file, .{
        .file_size = 1024,
        .row_count = 6,
        .records_offset = 128,
        .record_len = 64,
    });
    defer radix.deinit(testing.allocator);

    var pubkey = [_]u8{0} ** 32;
    pubkey[0] = 0x40;
    try testing.expectEqual(Range{ .lo = 2, .hi = 2 }, radix.rangeForPubkey(&pubkey));
    pubkey[0] = 0x80;
    try testing.expectEqual(Range{ .lo = 2, .hi = 5 }, radix.rangeForPubkey(&pubkey));
}
