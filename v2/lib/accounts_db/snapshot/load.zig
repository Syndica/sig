const std = @import("std");
const lib = @import("../../lib.zig");
const zstd = @import("zstd");

const tel = lib.telemetry;
const bincode = lib.solana.bincode;

const SlotAndHash = lib.solana.SlotAndHash;
const Manifest = lib.solana.snapshot.Manifest;
const StatusCache = lib.solana.snapshot.StatusCache;

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;
const Epoch = lib.solana.Epoch;
const Hash = lib.solana.Hash;

/// A snapshot-{slot}-{hash}.tar.zst is a zstd compressed tar archive
/// starting with 3 (unordered) tar files as the header:
/// - "version": a string of the snapshot file
/// - "snapshots/status_cache": bincode serialized StatusCache
/// - "snapshots/{slot}/{slot}": bincode serialized Manifest
///
/// Followed by multiple account files named "/accounts/{modified_slot}.{file_id}":
/// - the true length of each account file is in `Manifest.accounts_db_fields.account_files.get(modified_slot)`
/// - each file consists of multiple Accounts, formatted as [header][data:pad(header.data_len, 8)]
pub fn loadSnapshot(
    logger: tel.Logger("loadSnapshot"),
    fba: *std.heap.FixedBufferAllocator,
    slot_hash: SlotAndHash,
    snapshot_file: std.fs.File,
) !void {
    const file_size = (try snapshot_file.stat()).size;
    if (file_size == 0) return error.ZeroSizedTarball;

    const file_mapping = try std.posix.mmap(
        null,
        file_size,
        std.posix.PROT.READ,
        std.posix.MAP{ .TYPE = .PRIVATE },
        snapshot_file.handle,
        0,
    );
    errdefer std.posix.munmap(file_mapping);
    try std.posix.madvise(
        file_mapping.ptr,
        file_mapping.len,
        std.posix.MADV.SEQUENTIAL | std.posix.MADV.WILLNEED,
    );

    var zstd_reader = try @import("zstd").Reader.init(file_mapping);
    errdefer zstd_reader.deinit();

    // TODO: port zstd's Reader to 0.15.2 std.Io.Reader instead of using the adapter.
    var zstd_reader_buf: [1]u8 = undefined;
    var generic_reader = zstd_reader.reader();
    var adapted_reader = generic_reader.adaptToNewApi(&zstd_reader_buf);

    var tar_file_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var tar_link_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var tar_iter = std.tar.Iterator.init(&adapted_reader.new_interface, .{
        .file_name_buffer = &tar_file_name_buf,
        .link_name_buffer = &tar_link_name_buf,
    });

    var manifest_path_buf: [512]u8 = undefined;
    const manifest_path = std.fmt.bufPrint(
        &manifest_path_buf,
        "snapshots/{0}/{0}",
        .{slot_hash.slot},
    ) catch unreachable;

    var maybe_version: ?[]u8 = null;
    var maybe_manifest: ?Manifest = null;
    var maybe_status_cache: ?StatusCache = null;

    while (try tar_iter.next()) |tar_file| {
        if (tar_file.kind != .file) continue;

        var tar_reader = std.Io.Reader.limited(
            tar_iter.reader,
            .limited64(tar_file.size),
            &tar_link_name_buf, // we dont use tar_file.link_name anyway
        );
        defer tar_iter.unread_file_bytes = tar_reader.remaining.toInt().?;

        if (std.mem.eql(u8, tar_file.name, "version")) {
            if (maybe_version != null) return error.MultipleVersionFiles;
            maybe_version = try fba.allocator().alloc(u8, tar_file.size);
            try tar_reader.interface.readSliceAll(maybe_version.?);
            continue; // TODO: verify the version
        } else if (std.mem.eql(u8, tar_file.name, "snapshots/status_cache")) {
            if (maybe_status_cache != null) return error.MultipleStatusCacheFiles;
            maybe_status_cache = try bincode.read(fba, &tar_reader.interface, StatusCache);
            continue; // TODO: verify the StatusCache
        } else if (std.mem.eql(u8, tar_file.name, manifest_path)) {
            if (maybe_manifest != null) return error.MultipleManifestFiles;
            maybe_manifest = try bincode.read(fba, &tar_reader.interface, Manifest);
            continue; // TODO: verify the Manifest
        }

        if (maybe_version == null) return error.MissingVersionFile;
        if (maybe_manifest == null) return error.MissingManifestFile;
        if (maybe_status_cache == null) return error.MissingStatusCacheFile;

        const bank_fields = &maybe_manifest.?.bank_fields;
        if (bank_fields.slot != slot_hash.slot) return error.InvalidBankSlot;
        if (!bank_fields.hash.eql(&slot_hash.hash)) return error.InvalidBankHash;

        // TODO: use bank_fields + loaded accounts_db to compute leader schedule
        //
        // v1.sig.accountsdb.snapshot.LoadedSnapshot.featureSet(
        //    f = FeatureSet.ALL_DISABLED
        //    for (f.inactive) |feature|:
        //      acc = rooted.get(features.map.get(feature).pubkey) orelse continue
        //      switch features.activationStateFromAccount(acc.data):
        //        .activated |slot| if (slot > bank_fields.slot) f.set(feature, slot)
        //        .pending => continue // skip
        //        .invalid => continue // skip
        //    return f
        // )
        // v1.sig.core.EpochTracker.initFromManifest(
        //   bank_fields,
        //   manifest.extra_fields,
        //   feature_set = ^,
        // )
        // v1.sig.core.LeaderSchedule.init(
        //   leader_schedule_epoch = bank_fields.stakes.epoch,
        //   vote_accounts = bank_fields.stakes.vote_accounts,
        //   epoch_schedule = bank_fields.epoch_schedule,
        //   feature_set = ^
        // )
        //
        _ = .{ bank_fields, logger };

        const accounts_db_fields = &maybe_manifest.?.accounts_db_fields;
        if (true) break; // TODO: enable when rooted db is passed in.

        var account_file_reader: std.Io.Reader.Limited, //
        const account_file_slot: Slot = blk: { // parse account file
            const split = std.mem.indexOf(u8, tar_file.name, ".") orelse
                return error.InvalidAccountFileName;
            if (split + 1 >= tar_file.name.len)
                return error.InvalidAccountFileName;

            const slot = std.fmt.parseInt(u64, tar_file.name["accounts/".len..split], 10) catch
                return error.InvalidAccountFileSlot;
            const id = std.fmt.parseInt(u32, tar_file.name[split + 1 ..], 10) catch
                return error.InvalidAccountFileId;
            if (slot > accounts_db_fields.slot)
                return error.InvalidAccountFileSlot;

            // TODO: accelerate this search
            const info = accounts_db_fields.account_file_map.getPtr(slot) orelse
                return error.InvalidAccountFileSlot;
            if (info.id != id)
                return error.InvalidAccountFileId;
            if (info.length > tar_file.size)
                return error.InvalidAccountFileLength;

            break :blk .{
                .init(&tar_reader.interface, .limited64(info.length), &.{}),
                slot,
            };
        };

        while (account_file_reader.remaining.nonzero()) {
            const reader = &account_file_reader.interface;

            // read account header.
            var header: extern struct { // little-endian
                _unused_write_version: u64,
                data_len: u64,
                pubkey: Pubkey,
                lamports: u64,
                rent_epoch: Epoch,
                owner: Pubkey,
                executable: u8,
                _padding: [7]u8,
                hash: Hash,
            } = undefined;
            reader.readSliceAll(std.mem.asBytes(&header)) catch {
                return error.InvalidAccountHeader;
            };

            // Header's hash is obsolete and always zero:
            // https://github.com/anza-xyz/agave/blob/v4.0/accounts-db/src/append_vec.rs#L1353-L1357
            if (!header.hash.eql(&Hash.ZEROES))
                return error.InvalidAccountHeader;
            if (header.executable > 1)
                return error.InvalidAccountHeader;
            if (header.data_len > lib.solana.MAX_ACCOUNT_SIZE)
                return error.InvalidAccountData;

            const remaining = account_file_reader.remaining.toInt().?;
            if (header.data_len > remaining)
                return error.InvalidAccountData;

            var data_reader =
                std.Io.Reader.limited(reader, .limited64(header.data_len), &.{});

            _ = account_file_slot;
            // TODO: write account (header + data_reader) into Rooted.

            const data_len_padded = @min(remaining, std.mem.alignForward(u64, header.data_len, 8));
            const data_len_consumed = header.data_len - data_reader.remaining.toInt().?;
            try reader.discardAll(data_len_padded -| data_len_consumed);
        }
    }
}
