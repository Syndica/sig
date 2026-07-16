//! Fixture loading for replay tests. Loads a fixture from disk and returns it as a Fixture struct.
const std = @import("std");
const lib = @import("lib");

pub const FEC_SHRED_COUNT = 32;

const FIXTURE_DIR = "tests/replay/fixtures";
const FIXTURE_INDEX_PATH = FIXTURE_DIR ++ "/index.zon";

pub const Index = struct {
    schema_version: u32,
    slots: []const Slot,

    pub const Slot = struct {
        slot: lib.solana.Slot,
        fec_sets: []const FecSet,
    };

    pub const FecSet = struct {
        fec_set_index: u32,
        path: []const u8,
        entry_count: u32,
        transaction_count: u32,
    };
};

pub const Manifest = struct {
    schema_version: u32,
    slot: lib.solana.Slot,
    fec_set_index: u32,
    shreds: Shreds,
    entries: Entries,

    pub const Shreds = struct {
        shred_version: u16,
        parent_offset: u16,
        parent_slot: lib.solana.Slot,
        data_indices: []const u32,
        coding_indices: []const u32,
        first_data_index: u32,
        last_data_index: u32,
        has_data_complete: bool,
        has_slot_complete: bool,
        data_complete_indices: []const u32,
        slot_complete_indices: []const u32,
    };

    pub const Entries = struct {
        decoded: bool,
        component_kind: []const u8,
        decode_error: ?[]const u8,
        entry_payload_len: u32,
        entry_count: u32,
        transaction_count: u32,
        transactions_per_entry: []const u32,
    };
};

pub const Fixture = struct {
    manifest: Manifest,
    packets: [FEC_SHRED_COUNT]lib.net.Packet,

    pub fn load(slot: lib.solana.Slot, allocator: std.mem.Allocator) !Fixture {
        const index = try loadZon(Index, allocator, FIXTURE_INDEX_PATH);
        defer std.zon.parse.free(allocator, index);

        try std.testing.expectEqual(@as(u32, 1), index.schema_version);

        const index_slot, const index_fec_set = for (index.slots) |index_slot| {
            if (index_slot.slot != slot) continue;
            if (index_slot.fec_sets.len == 0) return error.FixtureSlotHasNoFecSets;
            break .{ index_slot, index_slot.fec_sets[0] };
        } else return error.FixtureSlotNotFound;

        const manifest_path = try std.fs.path.join(allocator, &.{
            FIXTURE_DIR,
            index_fec_set.path,
        });
        defer allocator.free(manifest_path);

        const manifest = try loadZon(Manifest, allocator, manifest_path);
        errdefer std.zon.parse.free(allocator, manifest);

        try std.testing.expectEqual(@as(u32, 1), manifest.schema_version);
        try std.testing.expectEqual(index_slot.slot, manifest.slot);
        try std.testing.expectEqual(index_fec_set.fec_set_index, manifest.fec_set_index);

        const manifest_dir = std.fs.path.dirname(index_fec_set.path) orelse {
            return error.InvalidFixtureManifestPath;
        };
        const shreds_path = try std.fs.path.join(allocator, &.{
            FIXTURE_DIR,
            manifest_dir,
            "shreds.bin",
        });
        defer allocator.free(shreds_path);

        const packets = try loadFecSetPackets(allocator, shreds_path, &manifest);

        return .{
            .manifest = manifest,
            .packets = packets,
        };
    }

    pub fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        std.zon.parse.free(allocator, self.manifest);
    }
};

fn loadZon(comptime T: type, allocator: std.mem.Allocator, path: []const u8) !T {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAllocOptions(
        allocator,
        1024 * 1024,
        null,
        .@"1",
        0,
    );
    defer allocator.free(contents);

    var diag: std.zon.parse.Diagnostics = .{};
    defer diag.deinit(allocator);

    return std.zon.parse.fromSlice(T, allocator, contents, &diag, .{
        .ignore_unknown_fields = true,
    }) catch |err| {
        std.log.err("failed to parse {s}: {f}", .{ path, diag });
        return err;
    };
}

fn loadFecSetPackets(
    allocator: std.mem.Allocator,
    path: []const u8,
    manifest: *const Manifest,
) ![FEC_SHRED_COUNT]lib.net.Packet {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var read_buf: [4096]u8 = undefined;
    var file_reader = file.reader(&read_buf);
    const reader = &file_reader.interface;

    var selected: [FEC_SHRED_COUNT]lib.net.Packet = undefined;
    var selected_count: usize = 0;
    var seen_data = std.StaticBitSet(FEC_SHRED_COUNT).initEmpty();
    var seen_coding = std.StaticBitSet(FEC_SHRED_COUNT).initEmpty();
    while (try readChunk(allocator, reader)) |chunk| {
        defer allocator.free(chunk);

        try std.testing.expect(chunk.len <= lib.net.Packet.capacity);
        var packet: lib.net.Packet = undefined;
        @memcpy(packet.data[0..chunk.len], chunk);
        packet.len = @intCast(chunk.len);
        packet.addr = .initIp4(.{ 127, 0, 0, 1 }, 0);

        const shred = try lib.shred.Shred.fromPacketChecked(&packet);
        try std.testing.expectEqual(manifest.slot, shred.slot);
        try std.testing.expectEqual(manifest.fec_set_index, shred.fec_set_idx);
        try std.testing.expectEqual(manifest.shreds.shred_version, shred.version);

        const shred_index = if (shred.variant.isData())
            shred.slot_idx - shred.fec_set_idx
        else
            shred.code_or_data.code.code_shred_idx;
        try std.testing.expect(shred_index < FEC_SHRED_COUNT);

        const expected_indices = if (shred.variant.isData())
            manifest.shreds.data_indices
        else
            manifest.shreds.coding_indices;
        try std.testing.expect(std.mem.indexOfScalar(u32, expected_indices, shred_index) != null);

        const seen = if (shred.variant.isData()) &seen_data else &seen_coding;
        const bit_index: usize = @intCast(shred_index);
        try std.testing.expect(!seen.isSet(bit_index));
        seen.set(bit_index);

        selected[selected_count] = packet;
        selected_count += 1;
        if (selected_count == selected.len) return selected;
    }

    return error.FecSetNotFound;
}

// NOTE: Transplanted from v1's src/ledger/tests.zig shred fixture loader.
inline fn readChunk(allocator: std.mem.Allocator, reader: *std.Io.Reader) !?[]const u8 {
    const size = reader.takeInt(u64, .little) catch |err| switch (err) {
        error.EndOfStream => return null,
        else => return err,
    };

    const chunk = try allocator.alloc(u8, @intCast(size));
    errdefer allocator.free(chunk);
    try reader.readSliceAll(chunk);

    return chunk;
}
