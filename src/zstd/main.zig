pub usingnamespace @import("compress.zig");
pub usingnamespace @import("decompress.zig");
pub usingnamespace @import("types.zig");
pub usingnamespace @import("error.zig");

const std = @import("std");
const c = @import("c.zig");
const comp = @import("compress.zig");
const types = @import("types.zig");
const decomp = @import("decompress.zig");
const testing = std.testing;

pub fn main() !void {
    // const filepath = "../snapshots/incremental-folder/incremental-snapshot-244068316-244090370-Dq47uVRdDA1hVKCNb7RcgUEJ9RrczagQqHzgor85GP48.tar.zst";
    const filepath = "../sig/test_data/incremental-snapshot-10-25-GXgKvm3NMAPgGdv2verVaNXmKTHQgfy2TAxLVEfAvdCS.tar.zst";
    var file = try std.fs.cwd().openFile(filepath, .{});
    defer file.close();

    const file_stat = try file.stat();
    const file_size: u64 = @intCast(file_stat.size);
    var memory = try std.os.mmap(
        null,
        file_size,
        std.os.PROT.READ,
        std.os.MAP.SHARED,
        file.handle,
        0,
    );

    var timer = try std.time.Timer.start();
    const allocator = std.heap.page_allocator;

    timer.reset();
    var zstd_stream = std.io.FixedBufferStream([]u8){ .buffer = memory, .pos = 0 };
    var tar_stream = std.compress.zstd.decompressStream(allocator, zstd_stream.reader());
    const result = try tar_stream.reader().readAllAlloc(allocator, 1024 * 1024 * 1024); // 10GB
    std.debug.print("time: {s}\n", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    var d = try decomp.Decompressor.init(.{});
    var result_memory = try allocator.alloc(u8, 1024 * 1024);

    const z_result = try d.decompress(result_memory, memory);
    std.debug.print("time: {s}\n", .{std.fmt.fmtDuration(timer.read())});

    const r = std.mem.eql(u8, result, z_result);
    std.debug.print("result: {}\n", .{r});
}

pub fn version() std.SemanticVersion {
    return .{
        .major = c.ZSTD_VERSION_MAJOR,
        .minor = c.ZSTD_VERSION_MINOR,
        .patch = c.ZSTD_VERSION_RELEASE,
    };
}

test "refernece decls" {
    testing.refAllDeclsRecursive(comp);
}

const test_str = @embedFile("types.zig");

test "compress/decompress" {
    var comp_out: [1024]u8 = undefined;
    var decomp_out: [1024]u8 = undefined;

    const compressed = try comp.compress(&comp_out, test_str, comp.minCompressionLevel());
    const decompressed = try decomp.decompress(&decomp_out, compressed);
    try testing.expectEqualStrings(test_str, decompressed);
}

test "compress with context" {
    var out: [1024]u8 = undefined;

    const compressor = try comp.Compressor.init(.{});
    defer compressor.deinit();

    _ = try compressor.compress(&out, test_str, comp.minCompressionLevel());
}

test "streaming compress" {
    var in_fbs = std.io.fixedBufferStream(test_str);

    var out: [test_str.len]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out);

    var in_buf = try testing.allocator.alloc(u8, comp.Compressor.recommInSize());
    var out_buf = try testing.allocator.alloc(u8, comp.Compressor.recommOutSize());
    defer testing.allocator.free(in_buf);
    defer testing.allocator.free(out_buf);

    const ctx = try comp.Compressor.init(.{
        .compression_level = 1,
        .checksum_flag = 1,
    });

    while (true) {
        const read = try in_fbs.read(in_buf);
        const is_last_chunk = (read < in_buf.len);

        var input = types.InBuffer{
            .src = in_buf.ptr,
            .size = read,
            .pos = 0,
        };

        while (true) {
            var output = types.OutBuffer{
                .dst = out_buf.ptr,
                .size = out_buf.len,
                .pos = 0,
            };
            const remaining = try ctx.compressStream(&input, &output, if (is_last_chunk) .end else .continue_);
            _ = try out_fbs.write(out_buf[0..output.pos]);

            if ((is_last_chunk and remaining == 0) or input.pos == read)
                break;
        }

        if (is_last_chunk)
            break;
    }

    var decomp_out: [test_str.len]u8 = undefined;
    const decompressed = try decomp.decompress(&decomp_out, out_fbs.getWritten());
    try std.testing.expectEqualStrings(test_str, decompressed);
}
