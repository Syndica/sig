//! Genesis file download and unpacking from the network.
//!
//! This module handles downloading genesis.tar.bz2 archives from RPC nodes
//! and unpacking them to the validator directory, similar to how Agave handles
//! genesis bootstrap.

const std = @import("std");
const sig = @import("../sig.zig");
const bzip2 = @import("bzip2");

const Allocator = std.mem.Allocator;

const Logger = sig.trace.Logger("core.genesis_download");

pub const DEFAULT_GENESIS_ARCHIVE = "genesis.tar.bz2";
pub const DEFAULT_GENESIS_FILE = "genesis.bin";

pub const DownloadError = error{
    HttpRequestFailed,
    Bz2DecompressError,
    TarExtractError,
    GenesisNotFoundInArchive,
    OutOfMemory,
    ConnectionRefused,
    ConnectionTimedOut,
    UnexpectedResponse,
} || std.fs.File.OpenError || std.posix.WriteError;

/// Downloads the genesis archive from the network, decompresses it,
/// and extracts genesis.bin to the specified output directory.
///
/// Returns the path to the extracted genesis.bin file.
pub fn downloadAndExtractGenesis(
    allocator: Allocator,
    cluster_url: []const u8,
    output_dir: []const u8,
    logger: Logger,
) DownloadError![]const u8 {
    var genesis_url_buf: [std.fs.max_path_bytes]u8 = @splat(0);
    const genesis_url = try std.fmt.bufPrint(
        &genesis_url_buf,
        "{s}/{s}",
        .{ cluster_url, DEFAULT_GENESIS_ARCHIVE },
    );

    logger.info().logf("Downloading genesis from {s}...", .{genesis_url});
    const archive_data = try downloadGenesisArchive(allocator, genesis_url, logger);
    defer allocator.free(archive_data);

    logger.info().logf("Downloaded {d} bytes, decompressing...", .{archive_data.len});
    const tar_data = try decompressBz2(allocator, archive_data);
    defer allocator.free(tar_data);

    logger.info().logf("Decompressed to {d} bytes, extracting...", .{tar_data.len});
    var output_dir_handle = std.fs.cwd().makeOpenPath(output_dir, .{}) catch |err| {
        logger.err().logf("Failed to open/create output directory: {}", .{err});
        return error.TarExtractError;
    };
    defer output_dir_handle.close();

    try extractGenesisFromTar(tar_data, output_dir_handle, logger);
    const genesis_path = std.fs.path.join(allocator, &.{ output_dir, DEFAULT_GENESIS_FILE }) catch
        return error.OutOfMemory;

    logger.info().logf("Genesis extracted to {s}", .{genesis_path});
    return genesis_path;
}

/// Downloads the genesis archive using std.http.Client
fn downloadGenesisArchive(
    allocator: Allocator,
    url: []const u8,
    logger: Logger,
) DownloadError![]u8 {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var response = std.Io.Writer.Allocating.init(allocator);
    errdefer response.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .response_writer = &response.writer,
        .headers = .{
            .accept_encoding = .{
                .override = "identity",
            },
            .user_agent = .{
                .override = "sig/0.1",
            },
        },
    }) catch |err| {
        logger.err().logf("Failed to fetch genesis archive: {}", .{err});
        return error.HttpRequestFailed;
    };

    if (result.status != .ok) {
        logger.err().logf("HTTP request failed with status: {}", .{result.status});
        return error.HttpRequestFailed;
    }

    return try response.toOwnedSlice();
}

/// Decompresses bz2 data using libbz2
fn decompressBz2(allocator: Allocator, compressed_data: []const u8) DownloadError![]u8 {
    // Start with an estimate of 10x compression ratio
    var dest_len: u32 = @intCast(compressed_data.len * 10);
    var decompressed = allocator.alloc(u8, dest_len) catch return error.OutOfMemory;
    errdefer allocator.free(decompressed);

    while (true) {
        const result = bzip2.BZ2_bzBuffToBuffDecompress(
            decompressed.ptr,
            &dest_len,
            @ptrCast(@constCast(compressed_data.ptr)),
            @intCast(compressed_data.len),
            0, // small: 0 = use normal algorithm
            0, // verbosity: 0 = quiet
        );

        switch (result) {
            bzip2.BZ_OK => {
                // Shrink to actual size
                if (dest_len < decompressed.len) {
                    decompressed = allocator.realloc(decompressed, dest_len) catch
                        return error.OutOfMemory;
                }
                return decompressed;
            },
            bzip2.BZ_OUTBUFF_FULL => {
                dest_len = dest_len * 2;
                if (dest_len > 1024 * 1024 * 1024) { // 1GB limit
                    return error.Bz2DecompressError;
                }
                decompressed = allocator.realloc(decompressed, dest_len) catch {
                    return error.OutOfMemory;
                };
            },
            else => return error.Bz2DecompressError,
        }
    }
}

/// Extracts genesis.bin from a tar archive
fn extractGenesisFromTar(
    tar_data: []const u8,
    output_dir: std.fs.Dir,
    logger: Logger,
) DownloadError!void {
    var fbs = std.io.Reader.fixed(tar_data);
    var file_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var tar_iter = std.tar.Iterator.init(&fbs, .{
        .file_name_buffer = &file_name_buf,
        .link_name_buffer = &link_name_buf,
    });

    while (tar_iter.next() catch {
        return error.TarExtractError;
    }) |file| {
        if (file.kind != .file) continue;

        const is_genesis = std.mem.eql(u8, file.name, DEFAULT_GENESIS_FILE) or
            std.mem.endsWith(u8, file.name, "/" ++ DEFAULT_GENESIS_FILE);

        if (!is_genesis) continue;

        var out_file = output_dir.createFile(DEFAULT_GENESIS_FILE, .{}) catch |err| {
            logger.err().logf("Failed to create genesis.bin: {}", .{err});
            return error.TarExtractError;
        };
        defer out_file.close();

        var buf: [8192]u8 = undefined;
        var writer = out_file.writer(&buf);
        const bytes_read = tar_iter.reader.stream(
            &writer.interface,
            .limited(file.size),
        ) catch |err| {
            logger.err().logf("Failed to write genesis.bin: {}", .{err});
            return error.TarExtractError;
        };
        writer.interface.flush() catch return error.TarExtractError;

        if (bytes_read != file.size) {
            logger.err().logf(
                "Incomplete genesis extraction: expected {d} bytes, got {d}",
                .{ file.size, bytes_read },
            );
            return error.TarExtractError;
        }

        return;
    }

    logger.err().log("genesis.bin not found in archive");
    return error.GenesisNotFoundInArchive;
}

fn buildTarWithFiles(
    allocator: Allocator,
    files: []const struct { path: []const u8, contents: []const u8 },
) ![]u8 {
    var tar = std.Io.Writer.Allocating.init(allocator);
    errdefer tar.deinit();

    for (files) |file| {
        try sig.utils.tar.writeTarHeader(&tar.writer, .regular, file.path, file.contents.len);
        try tar.writer.writeAll(file.contents);
        for (0..sig.utils.tar.paddingBytes(file.contents.len)) |_| try tar.writer.writeByte(0);
    }
    try tar.writer.writeAll(&sig.utils.tar.sentinel_blocks);

    return tar.toOwnedSlice();
}

test "extractGenesisFromTar writes exactly genesis.bin bytes" {
    const allocator = std.testing.allocator;
    const genesis_contents = "genesis-content";

    const tar_data = try buildTarWithFiles(allocator, &.{
        .{ .path = "bootstrap/genesis.bin", .contents = genesis_contents },
        .{ .path = "bootstrap/extra.bin", .contents = "extra-content" },
    });
    defer allocator.free(tar_data);

    var output_dir = std.testing.tmpDir(.{});
    defer output_dir.cleanup();

    try extractGenesisFromTar(tar_data, output_dir.dir, .noop);

    const extracted = try output_dir.dir.readFileAlloc(allocator, DEFAULT_GENESIS_FILE, 1024 * 1024);
    defer allocator.free(extracted);

    try std.testing.expectEqualSlices(u8, genesis_contents, extracted);
}

test "extractGenesisFromTar fails on incomplete genesis payload" {
    const allocator = std.testing.allocator;

    var tar = std.Io.Writer.Allocating.init(allocator);
    defer tar.deinit();

    try sig.utils.tar.writeTarHeader(&tar.writer, .regular, "genesis.bin", 10);
    try tar.writer.writeAll("abc");

    const tar_data = try tar.toOwnedSlice();
    defer allocator.free(tar_data);

    var output_dir = std.testing.tmpDir(.{});
    defer output_dir.cleanup();

    try std.testing.expectError(
        error.TarExtractError,
        extractGenesisFromTar(tar_data, output_dir.dir, .noop),
    );
}
