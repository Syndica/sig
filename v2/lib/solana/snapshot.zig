const std = @import("std");
const tracy = @import("tracy");
const lib = @import("../lib.zig");

const tel = lib.telemetry;

const bincode = lib.snapshot.bincode;
const Manifest = bincode.Manifest;
const StatusCache = bincode.StatusCache;

const Slot = lib.solana.Slot;
const Account = lib.accounts_db.Account;

// lib.snapshot.tar.TarIterator
pub fn SnapshotReader(comptime TarIterator: type) type {
    return struct {
        manifest: Manifest,
        status_cache: StatusCache,
        tar_iter: *TarIterator,

        account_file_slot: Slot = 0,
        account_file_len: usize = 0,
        account_data_len: usize = 0,
        account_data_padding: usize = 0,

        const Self = @This();

        pub fn read(
            fba: *std.heap.FixedBufferAllocator,
            logger: tel.Logger("snapshot.reader"),
            tar_iter: *TarIterator,
        ) !Self {
            // read /version file
            {
                const tar_file = (try tar_iter.next()) orelse return error.MissingVersionFile;
                if (!std.mem.eql(u8, tar_file.name, "version")) return error.InvalidVersionFile;

                const expected_version = "1.2.0";
                var version: [expected_version.len]u8 = undefined;
                try tar_iter.readSliceAll(&version);
                if (!std.mem.eql(u8, &version, expected_version)) return error.InvalidVersion;
            }

            // read /snapshots/* (status_cache, {slot}/{slot}) files (they can appear out of order)
            var maybe_manifest: ?Manifest = null;
            var maybe_status_cache: ?StatusCache = null;
            while (true) {
                const tar_file = (try tar_iter.next()) orelse return error.MissingMetadataFile;

                const decode_start = std.time.Instant.now() catch unreachable;
                logger.info().logf(
                    "decoding {s} (size:{B:.2})",
                    .{ tar_file.name, tar_file.size },
                );
                defer {
                    const decode_end = std.time.Instant.now() catch unreachable;
                    logger.info().logf("decoded {s} in {D:.2}", .{
                        tar_file.name, decode_end.since(decode_start),
                    });
                }

                if (std.mem.eql(u8, tar_file.name, "snapshots/status_cache")) {
                    if (maybe_status_cache != null) return error.MultipleStatusCaches;
                    maybe_status_cache = try StatusCache.read(fba, tar_iter);
                } else {
                    if (maybe_manifest != null) return error.MultipleManifests;
                    maybe_manifest = try Manifest.read(fba, tar_iter);
                }

                return .{
                    .manifest = maybe_manifest orelse continue,
                    .status_cache = maybe_status_cache orelse continue,
                    .tar_iter = tar_iter,
                };
            }
        }

        pub fn next(self: *Self) !?Account {
            // Skip unread data & data padding of previous Accountentry
            const skip = self.account_data_len + self.account_data_padding;
            _ = try self.tar_iter.discardShort(skip);

            // read /accounts/{slot}/{id} (containing Accounts in AppendVecs)
            while (self.account_file_len == 0) {
                @branchHint(.unlikely);

                const tar_file = (try self.tar_iter.next()) orelse return null;
                const split = std.mem.indexOf(u8, tar_file.name, ".") orelse
                    return error.InvalidAccountFileName;
                if (split + 1 >= tar_file.name.len)
                    return error.InvalidAccountFileName;

                const slot = std.fmt.parseInt(u64, tar_file.name["accounts/".len..split], 10) catch
                    return error.InvalidAccountFileSlot;
                const id = std.fmt.parseInt(u32, tar_file.name[split + 1 ..], 10) catch
                    return error.InvalidAccountFileId;
                if (slot > self.manifest.accounts_db_fields.slot)
                    return error.InvalidAccountFileSlot;

                const info = self.manifest.accounts_db_fields.account_file_map.getPtr(slot) orelse
                    return error.InvalidAccountFileSlot;
                if (info.id != id)
                    return error.InvalidAccountFileId;
                if (info.length > tar_file.size)
                    return error.InvalidAccountFileLength;

                self.account_file_slot = slot;
                self.account_file_len = info.length;
            }

            var header: extern struct { // little-endian
                _unused_write_version: u64,
                data_len: u64,
                pubkey: lib.solana.Pubkey,
                lamports: u64,
                rent_epoch: lib.solana.Epoch,
                owner: lib.solana.Pubkey,
                executable: u8,
                _padding: [7]u8,
                hash: lib.solana.Hash,
            } = undefined;
            self.account_file_len -= @sizeOf(@TypeOf(header));
            self.tar_iter.readSliceAll(std.mem.asBytes(&header)) catch
                return error.InvalidAccountHeader;

            // Header's hash is obsolete and always zero:
            // https://github.com/anza-xyz/agave/blob/v4.0/accounts-db/src/append_vec.rs#L1353-L1357
            if (!header.hash.eql(&lib.solana.Hash.ZEROES))
                return error.InvalidAccountHeader;
            if (header.executable > 1)
                return error.InvalidAccountHeader;
            if (header.data_len > 10 * 1024 * 1024)
                return error.InvalidAccountData;

            self.account_file_len -|= std.mem.alignForward(u64, header.data_len, 8);
            self.account_data_len = header.data_len;
            self.account_data_padding =
                std.mem.alignForward(u64, header.data_len, 8) - self.account_data_len;

            return .init(
                &header.pubkey,
                &header.owner,
                header.lamports,
                self.account_file_slot,
                header.rent_epoch,
                header.data_len,
                header.executable > 0,
            );
        }

        pub fn readSliceAll(self: *Self, buf: []u8) !void {
            if (buf.len > self.account_data_len) return error.EndOfStream;
            self.account_data_len -= buf.len;
            try self.tar_iter.readSliceAll(buf);
        }
    };
}
