const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const tel = lib.telemetry;

const Slot = lib.solana.Slot;
const Pubkey = lib.solana.Pubkey;

const Table = lib.accounts_db.Table;

const Manifest = lib.snapshot.bincode.Manifest;
const StatusCache = lib.snapshot.bincode.StatusCache;

comptime {
    _ = start;
}

pub const name = .accounts_db;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {};
pub const ReadWrite = struct {
    config: *lib.accounts_db.DbConfig,
    snapshot_to_accounts_db: *lib.snapshot.SnapshotDecodeRing,
    tel: *tel.Region,
};

var global: struct {
    metadata_memory: [1 * 1024 * 1024 * 1024]u8,
    file_writer: lib.accounts_db.io.FileWriter(64 * 1024 * 1024),
} = undefined;

pub fn serviceMain(_: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    const db_path = rw.config.file_path[0..rw.config.file_path_len];
    logger.info().logf("accounts_db started on {s}", .{db_path});

    // create rooted store
    const db_writer = &global.file_writer;
    try db_writer.init(std.fs.cwd(), db_path);
    defer db_writer.deinit();

    const db_table_seed = 0; // TODO: random generate
    var db_table = Table.init(
        db_table_seed,
        rw.config.memory[0..].ptr[0..rw.config.memory_len],
    );

    // TODO: pre-load db_table from db_path file

    // read /version file
    var tar_iter = TarIterator{ .snapshot_decoded = rw.snapshot_to_accounts_db };
    {
        const tar_file = (try tar_iter.next()) orelse return error.MissingVersionFile;
        if (!std.mem.eql(u8, tar_file.name, "version")) return error.InvalidVersionFile;

        const expected_version = "1.2.0";
        var version: [expected_version.len]u8 = undefined;
        try tar_iter.readSliceAll(&version);
        if (!std.mem.eql(u8, &version, expected_version)) return error.InvalidVersion;
    }

    // read /snapshots/* (status_cache, {slot}/{slot}) files (they can appear out of order)
    var fba = std.heap.FixedBufferAllocator.init(&global.metadata_memory);
    const manifest: Manifest, _ = blk: {
        var maybe_manifest: ?Manifest = null;
        var maybe_status_cache: ?StatusCache = null;
        while (true) {
            const tar_file = (try tar_iter.next()) orelse return error.MissingMetadataFile;

            const decode_start = std.time.Instant.now() catch unreachable;
            logger.info().logf("decoding {s} (size:{B:.2})", .{ tar_file.name, tar_file.size });
            defer {
                const elapsed = (std.time.Instant.now() catch unreachable).since(decode_start);
                logger.info().logf("decoded {s} in {D:.2}", .{ tar_file.name, elapsed });
            }

            if (std.mem.eql(u8, tar_file.name, "snapshots/status_cache")) {
                if (maybe_status_cache != null) return error.MultipleStatusCaches;
                maybe_status_cache = try StatusCache.read(&fba, &tar_iter);
            } else {
                if (maybe_manifest != null) return error.MultipleManifests;
                maybe_manifest = try Manifest.read(&fba, &tar_iter);
            }

            break :blk .{
                maybe_manifest orelse continue,
                maybe_status_cache orelse continue,
            };
        }
    };

    var num_puts: usize = 0;
    var decoded: usize = 0;
    var timer = try std.time.Timer.start();
    var last_time: u64 = 0;

    // read /accounts/{slot}/{id} files (containing Accounts in AppendVecs)
    while (try tar_iter.next()) |tar_file| {
        const split = std.mem.indexOf(u8, tar_file.name, ".") orelse
            return error.InvalidAccountFileName;
        if (split + 1 >= tar_file.name.len)
            return error.InvalidAccountFileName;

        const slot = std.fmt.parseInt(u64, tar_file.name["accounts/".len..split], 10) catch
            return error.InvalidAccountFileSlot;
        const id = std.fmt.parseInt(u32, tar_file.name[split + 1 ..], 10) catch
            return error.InvalidAccountFileId;
        if (slot > manifest.accounts_db_fields.slot)
            return error.InvalidAccountFileSlot;

        const info = manifest.accounts_db_fields.account_file_map.getPtr(slot) orelse
            return error.InvalidAccountFileSlot;
        if (info.id != id)
            return error.InvalidAccountFileId;
        if (info.length > tar_file.size)
            return error.InvalidAccountFileLength;

        var account_file_len: u64 = info.length;
        while (account_file_len > 0) {
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
            tar_iter.readSliceAll(std.mem.asBytes(&header)) catch return error.InvalidAccountHeader;
            account_file_len -= @sizeOf(@TypeOf(header));

            // Header's hash is obsolete and always zero:
            // https://github.com/anza-xyz/agave/blob/v4.0/accounts-db/src/append_vec.rs#L1353-L1357
            if (!header.hash.eql(&lib.solana.Hash.ZEROES))
                return error.InvalidAccountHeader;
            if (header.executable > 1)
                return error.InvalidAccountHeader;
            if (header.data_len > 10 * 1024 * 1024)
                return error.InvalidAccountData;

            // The account read & written to disk (a more compact format)
            var disk_acc: extern struct {
                info: packed struct(u64) {
                    executable: bool,
                    data_len: u24,
                    rent_epoch: u39,
                },
                pubkey: Pubkey,
                owner: Pubkey,
                lamports: u64,
            } = .{
                .info = .{
                    .executable = header.executable > 0,
                    .data_len = @intCast(header.data_len),
                    .rent_epoch = std.math.lossyCast(u39, header.rent_epoch),
                },
                .pubkey = header.pubkey,
                .owner = header.owner,
                .lamports = header.lamports,
            };

            // write disk offset entry to db
            num_puts += 1;
            db_table.put(&header.pubkey, slot, .{
                .len = @intCast(@sizeOf(@TypeOf(disk_acc)) + header.data_len),
                .offset = @intCast(db_writer.tail),
            });

            // write disk_acc
            {
                var buf: []const u8 = std.mem.asBytes(&disk_acc);
                while (buf.len > 0) {
                    const write_buf = try db_writer.getSlice(.from(logger));
                    const n = @min(write_buf.len, buf.len);
                    @memcpy(write_buf[0..n], buf[0..n]);
                    try db_writer.advance(n);
                    buf = buf[n..];
                }
            }

            // write account data
            {
                var data_len = header.data_len;
                while (data_len > 0) {
                    const write_buf = try db_writer.getSlice(.from(logger));
                    const n = @min(write_buf.len, data_len);
                    try tar_iter.readSliceAll(write_buf[0..n]);
                    data_len -= n;
                    try db_writer.advance(n);
                }
            }

            // skip account data padding
            const data_len_padded = std.mem.alignForward(u64, header.data_len, 8);
            _ = try tar_iter.discardShort(data_len_padded - header.data_len);
            account_file_len -|= data_len_padded;
        }

        decoded += tar_file.size;
        const now = timer.read();
        if (now - last_time >= std.time.ns_per_s) {
            defer last_time = now;
            defer decoded = 0;
            defer num_puts = 0;
            logger.info().logf(
                "processed {B:.2} ({} accounts) in {D:.0}",
                .{ decoded, num_puts, now - last_time },
            );
        }
    }

    try db_writer.sync(.from(logger));
    logger.info().logf("accounts_db finished ({} accounts {B:.2} on disk)", .{
        db_table.count,
        db_writer.tail,
    });

    while (true) std.atomic.spinLoopHint();
}

const TarIterator = struct {
    snapshot_decoded: *lib.snapshot.SnapshotDecodeRing,
    tar_header: [512]u8 = undefined,
    tar_payload: usize = 0,
    tar_padding: usize = 0,

    pub const TarFile = struct {
        name: []const u8,
        size: usize,
    };

    fn read(self: *TarIterator, maybe_ptr: ?[*]u8, len: usize) usize {
        if (len == 0) return 0;

        var n: usize = 0;
        while (true) : (std.atomic.spinLoopHint()) {
            const buf = self.snapshot_decoded.getSlice(.reader) catch return n;
            if (buf.len == 0) continue;

            const take = @min(buf.len, len - n);
            if (maybe_ptr) |ptr| {
                @memcpy(ptr[n..][0..take], buf[0..take]);
            }

            self.snapshot_decoded.advance(.reader, take);
            n += take;
            if (n == len) return n;
        }
    }

    pub fn next(self: *TarIterator) !?TarFile {
        while (true) {
            // Skip unprocessed bytes from tar file body
            _ = self.read(null, self.tar_padding + self.tar_payload);

            // Read header
            const n = self.read(self.tar_header[0..].ptr, self.tar_header.len);
            if (n == 0) return null;
            if (n < self.tar_header.len) return error.EndOfStream;

            const is_file = self.tar_header[156] == '0' or self.tar_header[156] == 0;
            const file_name = std.mem.sliceTo(self.tar_header[0..100], 0);
            const file_size = blk: {
                const buf = self.tar_header[124..][0..12];
                if (buf[0] == 0xff) return error.InvalidTar; // negative size
                if (buf[0] == 0x80) {
                    if (std.mem.readInt(u32, buf[0..4], .little) != 0x80) return error.InvalidTar;
                    break :blk std.mem.readInt(u64, buf[4..12], .big);
                }
                const trimmed = std.mem.trimRight(u8, std.mem.trimLeft(u8, buf, "0 "), " \x00");
                if (trimmed.len == 0) break :blk 0;
                break :blk std.fmt.parseInt(u64, trimmed, 8) catch return error.InvalidTar;
            };

            self.tar_payload = file_size;
            self.tar_padding = std.mem.alignForward(usize, file_size, 512) - file_size;
            if (file_size == 0 and file_name.len == 0) return null; // empty name/size = tar EOF
            if (is_file) return .{ .name = file_name, .size = file_size }; // only return files
        }
    }

    pub fn readSliceAll(self: *TarIterator, buf: []u8) !void {
        if (buf.len > self.tar_payload) return error.EndOfStream;
        const n = self.read(buf.ptr, buf.len);
        self.tar_payload -= n;
        if (n < buf.len) return error.EndOfStream;
    }

    pub fn discardShort(self: *TarIterator, n: usize) !usize {
        const take = @min(self.tar_payload, n);
        self.tar_payload -= take;
        return self.read(null, take);
    }

    pub fn discardAll(self: *TarIterator, n: usize) !void {
        if ((try self.discardShort(n)) != n) return error.EndOfStream;
    }
};
