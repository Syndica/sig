const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const FORMAT = "chimera-replay-warm-manifest-v1";
const MAX_MANIFEST_BYTES = 64 * 1024 * 1024;

pub const Manifest = struct {
    root_slot: Slot,
    target_slot: Slot,
    pubkeys: []Pubkey,

    pub fn deinit(self: *Manifest, allocator: Allocator) void {
        allocator.free(self.pubkeys);
        self.* = undefined;
    }
};

pub const RecordResult = struct {
    root_slot: Slot,
    target_slot: Slot,
    pubkeys: u64,
};

pub const WarmResult = struct {
    root_slot: Slot,
    target_slot: Slot,
    pubkeys: u64,
    prefetch: sig.accounts_db.CompressedAccountStore.PrefetchResult,
    elapsed_ns: u64,
};

pub fn maybeRecordFromEnv(
    allocator: Allocator,
    slot: Slot,
    main_pubkeys: []const Pubkey,
    programdata_pubkeys: []const Pubkey,
) !?RecordResult {
    const path = try optionalEnvOwned(allocator, "SIG_REPLAY_WARM_MANIFEST_OUT") orelse
        return null;
    defer allocator.free(path);

    const root_slot = try requiredEnvSlot(
        allocator,
        "SIG_REPLAY_WARM_MANIFEST_ROOT_SLOT",
    );
    const target_slot = try requiredEnvSlot(
        allocator,
        "SIG_REPLAY_WARM_MANIFEST_TARGET_SLOT",
    );
    if (slot != target_slot) return null;
    if (target_slot <= root_slot) return error.InvalidReplayWarmManifestSlots;

    const pubkey_count = try write(
        allocator,
        path,
        root_slot,
        target_slot,
        main_pubkeys,
        programdata_pubkeys,
    );
    return .{
        .root_slot = root_slot,
        .target_slot = target_slot,
        .pubkeys = pubkey_count,
    };
}

pub fn maybeWarmFromEnv(
    allocator: Allocator,
    actual_root_slot: Slot,
    account_reader: sig.accounts_db.SlotAccountReader,
) !?WarmResult {
    const path = try optionalEnvOwned(allocator, "SIG_REPLAY_WARM_MANIFEST_IN") orelse
        return null;
    defer allocator.free(path);

    var manifest = try load(allocator, path);
    defer manifest.deinit(allocator);
    if (manifest.root_slot != actual_root_slot)
        return error.ReplayWarmManifestRootMismatch;
    if (manifest.target_slot <= manifest.root_slot)
        return error.InvalidReplayWarmManifestSlots;

    var timer = sig.time.Timer.start();
    const prefetch = try account_reader.prefetchCompressedChunks(
        allocator,
        manifest.pubkeys,
    );
    return .{
        .root_slot = manifest.root_slot,
        .target_slot = manifest.target_slot,
        .pubkeys = @intCast(manifest.pubkeys.len),
        .prefetch = prefetch,
        .elapsed_ns = timer.read().asNanos(),
    };
}

pub fn write(
    allocator: Allocator,
    path: []const u8,
    root_slot: Slot,
    target_slot: Slot,
    main_pubkeys: []const Pubkey,
    programdata_pubkeys: []const Pubkey,
) !u64 {
    if (target_slot <= root_slot) return error.InvalidReplayWarmManifestSlots;

    var seen: std.AutoHashMapUnmanaged(Pubkey, void) = .{};
    defer seen.deinit(allocator);
    const requested_capacity = std.math.add(
        usize,
        main_pubkeys.len,
        programdata_pubkeys.len,
    ) catch return error.OutOfMemory;
    if (requested_capacity > std.math.maxInt(u32)) return error.OutOfMemory;
    try seen.ensureTotalCapacity(allocator, @intCast(requested_capacity));
    for (main_pubkeys) |pubkey| seen.putAssumeCapacity(pubkey, {});
    for (programdata_pubkeys) |pubkey| seen.putAssumeCapacity(pubkey, {});

    const pubkeys = try allocator.alloc(Pubkey, seen.count());
    defer allocator.free(pubkeys);
    var key_it = seen.keyIterator();
    var key_index: usize = 0;
    while (key_it.next()) |pubkey| : (key_index += 1) {
        pubkeys[key_index] = pubkey.*;
    }
    std.mem.sort(Pubkey, pubkeys, {}, struct {
        fn lessThan(_: void, a: Pubkey, b: Pubkey) bool {
            return a.order(b) == .lt;
        }
    }.lessThan);

    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();

    var write_buf: [4096]u8 = undefined;
    var writer = file.writer(&write_buf);
    try writer.interface.print(
        "{s}\nroot_slot={}\ntarget_slot={}\n",
        .{ FORMAT, root_slot, target_slot },
    );
    for (pubkeys) |pubkey| {
        try writer.interface.print("pubkey={f}\n", .{pubkey});
    }
    try writer.end();
    return @intCast(pubkeys.len);
}

pub fn load(allocator: Allocator, path: []const u8) !Manifest {
    const file_data = try std.fs.cwd().readFileAlloc(
        allocator,
        path,
        MAX_MANIFEST_BYTES,
    );
    defer allocator.free(file_data);

    var root_slot: ?Slot = null;
    var target_slot: ?Slot = null;
    var saw_format = false;
    var pubkeys: std.ArrayListUnmanaged(Pubkey) = .{};
    errdefer pubkeys.deinit(allocator);
    var seen: std.AutoHashMapUnmanaged(Pubkey, void) = .{};
    defer seen.deinit(allocator);

    var lines = std.mem.splitScalar(u8, file_data, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        if (!saw_format) {
            if (!std.mem.eql(u8, line, FORMAT))
                return error.InvalidReplayWarmManifestFormat;
            saw_format = true;
            continue;
        }
        if (std.mem.startsWith(u8, line, "root_slot=")) {
            if (root_slot != null) return error.InvalidReplayWarmManifestFormat;
            root_slot = try parseSlot(line["root_slot=".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, line, "target_slot=")) {
            if (target_slot != null) return error.InvalidReplayWarmManifestFormat;
            target_slot = try parseSlot(line["target_slot=".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, line, "pubkey=")) {
            const pubkey = Pubkey.parseRuntime(line["pubkey=".len..]) catch
                return error.InvalidReplayWarmManifestPubkey;
            const gop = try seen.getOrPut(allocator, pubkey);
            if (!gop.found_existing) {
                gop.value_ptr.* = {};
                try pubkeys.append(allocator, pubkey);
            }
            continue;
        }
        return error.InvalidReplayWarmManifestFormat;
    }

    if (!saw_format or root_slot == null or target_slot == null or pubkeys.items.len == 0)
        return error.InvalidReplayWarmManifestFormat;
    if (target_slot.? <= root_slot.?) return error.InvalidReplayWarmManifestSlots;

    std.mem.sort(Pubkey, pubkeys.items, {}, struct {
        fn lessThan(_: void, a: Pubkey, b: Pubkey) bool {
            return a.order(b) == .lt;
        }
    }.lessThan);
    return .{
        .root_slot = root_slot.?,
        .target_slot = target_slot.?,
        .pubkeys = try pubkeys.toOwnedSlice(allocator),
    };
}

fn parseSlot(raw: []const u8) !Slot {
    if (raw.len == 0) return error.InvalidReplayWarmManifestSlot;
    return std.fmt.parseUnsigned(Slot, raw, 10) catch
        return error.InvalidReplayWarmManifestSlot;
}

fn requiredEnvSlot(allocator: Allocator, key: []const u8) !Slot {
    const raw = try optionalEnvOwned(allocator, key) orelse
        return error.MissingReplayWarmManifestEnv;
    defer allocator.free(raw);
    return parseSlot(std.mem.trim(u8, raw, " \t\r\n"));
}

fn optionalEnvOwned(allocator: Allocator, key: []const u8) !?[]u8 {
    return std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
}

test "warm manifest round trips sorted unique pubkeys" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const a = Pubkey.parse("11111111111111111111111111111111");
    const b = Pubkey.parse("Vote111111111111111111111111111111111111111");
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    const manifest_path = try std.fs.path.join(allocator, &.{ path, "warm.txt" });
    defer allocator.free(manifest_path);

    try std.testing.expectEqual(
        @as(u64, 2),
        try write(allocator, manifest_path, 100, 101, &.{ b, a }, &.{b}),
    );
    var manifest = try load(allocator, manifest_path);
    defer manifest.deinit(allocator);
    try std.testing.expectEqual(@as(Slot, 100), manifest.root_slot);
    try std.testing.expectEqual(@as(Slot, 101), manifest.target_slot);
    try std.testing.expectEqual(@as(usize, 2), manifest.pubkeys.len);
    try std.testing.expect(manifest.pubkeys[0].order(manifest.pubkeys[1]) == .lt);
}

test "warm manifest rejects a root-target inversion" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    const manifest_path = try std.fs.path.join(allocator, &.{ path, "bad.txt" });
    defer allocator.free(manifest_path);

    const pubkey = Pubkey.parse("11111111111111111111111111111111");
    try std.testing.expectError(
        error.InvalidReplayWarmManifestSlots,
        write(allocator, manifest_path, 101, 101, &.{pubkey}, &.{}),
    );
}
