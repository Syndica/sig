const std = @import("std");
const sig = @import("../sig.zig");
const ledger = @import("lib.zig");

const Allocator = std.mem.Allocator;

const Logger = sig.trace.Logger;

const TestState = ledger.insert_shred.TestState;
const Shred = ledger.shred.Shred;

const schema = ledger.schema.schema;

test "put/get data consistency for merkle root" {
    const logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    var rng = std.Random.DefaultPrng.init(100);
    const random = rng.random();

    var state = try TestState.init("bsdbMerkleRootDatabaseConsistency");
    defer state.deinit();
    var db = state.db;

    const id = sig.ledger.shred.ErasureSetId{
        .slot = 1234127498,
        .fec_set_index = 4932874234,
    };
    const root = sig.core.Hash.random(random);

    try db.put(
        schema.merkle_root_meta,
        id,
        sig.ledger.meta.MerkleRootMeta{
            .merkle_root = root,
            .first_received_shred_index = 100,
            .first_received_shred_type = .data,
        },
    );
    const output: sig.ledger.meta.MerkleRootMeta = (try db.get(schema.merkle_root_meta, id)).?;
    try std.testing.expectEqualSlices(u8, &root.data, &output.merkle_root.?.data);
}

/// ensures the path exists as an empty directory.
/// deletes anything else that might exist here.
pub fn freshDir(path: []const u8) !void {
    if (std.fs.cwd().access(path, .{})) |_| {
        try std.fs.cwd().deleteTree(path);
    } else |_| {}
    try std.fs.cwd().makePath(path);
}

pub fn loadShredsFromFile(allocator: Allocator, path: []const u8) ![]const Shred {
    const file = try std.fs.cwd().openFile(path, .{});
    const reader = file.reader();
    var shreds = std.ArrayList(Shred).init(allocator);
    while (try readChunk(allocator, reader)) |chunk| {
        defer allocator.free(chunk);
        try shreds.append(try Shred.fromPayload(allocator, chunk));
    }
    return shreds.toOwnedSlice();
}

fn readChunk(allocator: Allocator, reader: anytype) !?[]const u8 {
    var size_bytes: [8]u8 = undefined;
    const num_size_bytes_read = try reader.readAll(&size_bytes);
    if (num_size_bytes_read == 0) {
        return null;
    }
    if (num_size_bytes_read != 8) {
        return error.IncompleteSize;
    }
    const size = std.mem.readInt(u64, &size_bytes, .little);

    const chunk = try allocator.alloc(u8, @intCast(size));
    const num_bytes_read = try reader.readAll(chunk);
    if (num_bytes_read != size) {
        return error.IncompleteChunk;
    }

    return chunk;
}

fn writeChunk(writer: anytype, chunk: []const u8) !void {
    var chunk_size_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &chunk_size_bytes, @intCast(chunk.len), .little);
    try writer.writeAll(&chunk_size_bytes);
    try writer.writeAll(chunk);
}

pub fn deinitShreds(allocator: Allocator, shreds: []const Shred) void {
    for (shreds) |shred| shred.deinit();
    allocator.free(shreds);
}
