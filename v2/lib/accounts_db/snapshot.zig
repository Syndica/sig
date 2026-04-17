const std = @import("std");
const lib = @import("../lib.zig");

const Ring = lib.ipc.Ring;

const Slot = lib.solana.Slot;
const Hash = lib.solana.Hash;
const SlotAndHash = lib.solana.SlotAndHash;

pub const Queue = extern struct {
    incoming: Incoming,
    outgoing: Outgoing,

    pub const Incoming = Ring(1024, Entry);
    pub const Outgoing = Ring(1, SlotAndHash);

    pub const Entry = extern struct {
        slot_hash: SlotAndHash,
        rpc_address: std.net.Address,
    };
};

pub fn findExistingSnapshot(snapshot_dir: std.fs.Dir) !?struct { std.fs.File, SlotAndHash } {
    var it = snapshot_dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, "snapshot-")) continue;
        if (!std.mem.endsWith(u8, entry.name, ".tar.zst")) continue;

        const path = entry.name["snapshot-".len .. entry.name.len - ".tar.zst".len];
        const split = std.mem.indexOfScalar(u8, path, '-') orelse continue;

        const slot = std.fmt.parseInt(Slot, path[0..split], 10) catch continue;
        const hash = Hash.parseRuntime(path[split + 1 ..]) catch continue;

        const file = try snapshot_dir.openFile(entry.name, .{ .mode = .read_only });
        return .{ file, .{ .slot = slot, .hash = hash } };
    }
    return null;
}

const download = @import("snapshot/download.zig");
pub const DownloadConfig = download.Config;
pub const downloadSnapshot = download.downloadSnapshot;

pub const load = @import("snapshot/load.zig");
pub const loadSnapshot = load.loadSnapshot;
