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
    const genesis_path = try extractGenesisFromTar(allocator, tar_data, output_dir, logger);

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

    var response_body = std.ArrayList(u8).init(allocator);
    errdefer response_body.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .response_storage = .{ .dynamic = &response_body },
        .max_append_size = 100 * 1024 * 1024, // 100MB max
    }) catch |err| {
        logger.err().logf("Failed to fetch genesis archive: {}", .{err});
        return error.HttpRequestFailed;
    };

    if (result.status != .ok) {
        logger.err().logf("HTTP request failed with status: {}", .{result.status});
        return error.HttpRequestFailed;
    }

    return response_body.toOwnedSlice() catch return error.OutOfMemory;
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
            @constCast(@ptrCast(compressed_data.ptr)),
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
    allocator: Allocator,
    tar_data: []const u8,
    output_dir: []const u8,
    logger: Logger,
) DownloadError![]const u8 {
    var dir = std.fs.cwd().makeOpenPath(output_dir, .{}) catch |err| {
        logger.err().logf("Failed to open/create output directory: {}", .{err});
        return error.TarExtractError;
    };
    defer dir.close();

    var fbs = std.io.fixedBufferStream(tar_data);
    var file_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var tar_iter = std.tar.iterator(fbs.reader(), .{
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

        var out_file = dir.createFile(DEFAULT_GENESIS_FILE, .{}) catch |err| {
            logger.err().logf("Failed to create genesis.bin: {}", .{err});
            return error.TarExtractError;
        };
        defer out_file.close();

        var buf: [8192]u8 = undefined;
        while (true) {
            const bytes_read = file.reader().read(&buf) catch {
                return error.TarExtractError;
            };
            if (bytes_read == 0) break;
            out_file.writeAll(buf[0..bytes_read]) catch |err| {
                logger.err().logf("Failed to write genesis.bin: {}", .{err});
                return error.TarExtractError;
            };
        }

        return std.fs.path.join(allocator, &.{ output_dir, DEFAULT_GENESIS_FILE }) catch
            return error.OutOfMemory;
    }

    logger.err().log("genesis.bin not found in archive");
    return error.GenesisNotFoundInArchive;
}
