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
    maybe_db: ?*Db,
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
        } else if (std.mem.eql(u8, tar_file.name, "snapshots/status_cache")) {
            if (maybe_status_cache != null) return error.MultipleStatusCacheFiles;
            maybe_status_cache = try bincode.read(fba, &tar_reader.interface, StatusCache);
        } else if (std.mem.eql(u8, tar_file.name, manifest_path)) {
            if (maybe_manifest != null) return error.MultipleManifestFiles;
            maybe_manifest = try bincode.read(fba, &tar_reader.interface, Manifest);
        } else {
            logger.err().logf("unexpected tar file: {s} (size:{B:.2})", .{tar_file.name, tar_file.size});
            return error.UnexpectedFile;
        }

        if (maybe_version != null and maybe_manifest != null and maybe_status_cache != null) {
            break;
        }
    }

    if (maybe_version == null) return error.MissingVersionFile;
    if (maybe_manifest == null) return error.MissingManifestFile;
    if (maybe_status_cache == null) return error.MissingStatusCacheFile;

    const bank_fields = &maybe_manifest.?.bank_fields;
    if (bank_fields.slot != slot_hash.slot) return error.InvalidBankSlot;

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
    const db = maybe_db orelse return;

    while (try tar_iter.next()) |tar_file| {
        if (tar_file.kind != .file) continue;
        var tar_reader = std.Io.Reader.limited(
            tar_iter.reader,
            .limited64(tar_file.size),
            &tar_link_name_buf, // we dont use tar_file.link_name anyway
        );
        defer tar_iter.unread_file_bytes = tar_reader.remaining.toInt().?;

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

            const maybe_account: ?*Db.Account = db.put(
                .from(logger),
                account_file_slot,
                &header.pubkey,
                if (header.lamports > 0) @intCast(header.data_len) else null,
            ) catch |err| switch (err) {
                error.OldSlot => null,
                else => |e| return e,
            };

            if (maybe_account) |account| {
                account.pubkey = header.pubkey;
                account.owner = header.owner;
                account.lamports = header.lamports;
                account.slot = @intCast(account_file_slot);
                account.rent_epoch = @intCast(header.rent_epoch);
                account.data.executable = header.executable > 0;
                account.data.len = @intCast(header.data_len);

                try data_reader.interface.readSliceAll(account.getData());
            }

            const data_len_padded = @min(remaining, std.mem.alignForward(u64, header.data_len, 8));
            const data_len_consumed = header.data_len - data_reader.remaining.toInt().?;
            try reader.discardAll(data_len_padded -| data_len_consumed);
        }
    }
}

pub const Db = struct {
    timer: std.time.Timer,
    last_elapsed: u64,
    total_written: usize,
    fd: std.posix.fd_t,
    ring: std.os.linux.IoUring,
    map: IndexMap,
    offset: u64,
    written: u32,
    current: u32,
    pool: PagePool,

    const Account = extern struct {
        data: packed struct(u32) {
            valid: bool,
            executable: bool,
            len: u30,
        },
        pubkey: Pubkey,
        owner: Pubkey,
        lamports: u64,
        slot: Slot,
        rent_epoch: Epoch,

        fn getData(self: *Account) []u8 {
            const ptr: [*]u8 = @ptrCast(self);
            return (ptr + @sizeOf(Account))[0..self.data.len];
        }
    };

    const sector_size = 512;
    const sector_align = 4096;

    const page_size = 16 * 1024 * 1024;
    comptime {
        std.debug.assert(page_size >= std.mem.alignForward(
            usize,
            @sizeOf(Account) + lib.solana.MAX_ACCOUNT_SIZE,
            sector_size,
        ));
    }

    const PagePool = struct {
        used: u32,
        io_pending: u32,
        io: [32]extern struct{ offset: u64, len: u32, wrote: u32 },
        pages: *Pages,
        memory: []align(std.heap.page_size_min) u8,

        const Pages = [32]extern struct { bytes: [page_size]u8 align(sector_align) };

        fn init(self: *PagePool) !void {
            self.used = 0;
            self.io_pending = 0;

            self.memory = try std.posix.mmap(
                null,
                @sizeOf(Pages),
                std.posix.PROT.READ | std.posix.PROT.WRITE,
                .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
                -1,
                0,
            );
            errdefer std.posix.munmap(self.memory);
            self.pages = @alignCast(@ptrCast(self.memory[0..@sizeOf(Pages)]));
        }

        fn deinit(self: *PagePool) void {
            std.posix.munmap(self.memory);
        }

        fn acquire(self: *PagePool) ?u32 {
            if (self.used == std.math.maxInt(u32)) return null;
            const idx = @ctz(~self.used);
            self.used |= @as(u32, 1) << @intCast(idx);
            return idx;
        }

        fn release(self: *PagePool, idx: u32) void {
            const mask = @as(u32, 1) << @intCast(idx);
            std.debug.assert(self.used & mask > 0);
            self.used &= ~mask;
        }
    };

    const IndexMap = struct {
        entries: []align(std.heap.page_size_min) Entry,
        count: u64,

        const num_entries = 1 << 31;
        const Entry = extern struct {
            hash: u64,
            slot: u32,
            sector: u32,
        };

        fn init(self: *IndexMap) !void {
            const memory = try std.posix.mmap(
                null,
                @sizeOf(Entry) * num_entries,
                std.posix.PROT.READ | std.posix.PROT.WRITE,
                .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
                -1,
                0,
            );
            errdefer std.posix.munmap(memory);
            self.entries = @alignCast(@ptrCast(memory[0..@sizeOf(Entry) * num_entries]));
            self.count = 0;
        }

        fn deinit(self: *IndexMap) void {
            const memory: []align(std.heap.page_size_min) u8 = @alignCast(@ptrCast(self.entries));
            std.posix.munmap(memory);
        }

        fn getOrPut(self: *IndexMap, hash: u64) struct{ bool, *Entry } {
            var idx = (hash *% 0x9E3779B97F4A7C15) >> @intCast(@as(u7, 64) - @ctz(@as(usize, num_entries)));
            while (true) {
                const e = &self.entries[idx];
                idx = (idx +% 1) & (self.entries.len - 1);
                if (e.hash == hash) return .{ true, e };
                if (e.hash == 0) {
                    e.hash = hash;
                    self.count += 1;
                    return .{ false, e };
                }
            }
        }
    };

    pub fn init(self: *Db, dir: std.fs.Dir, path: []const u8) !void {
        self.timer = try .start();
        self.last_elapsed = self.timer.read();
        self.total_written = 0;

        self.fd = try std.posix.openat(
            dir.fd,
            path,
            .{ .ACCMODE = .RDWR, .CREAT = true, .NOATIME = true, .CLOEXEC = true, .DIRECT = true },
            0o777,
        );
        errdefer std.posix.close(self.fd);

        self.ring = try .init(256, std.os.linux.IORING_SETUP_SQPOLL);
        errdefer self.ring.deinit();

        try self.map.init();
        errdefer self.map.deinit();

        try self.pool.init();
        errdefer self.pool.deinit();

        self.current = self.pool.acquire().?;
        self.offset = 0;
        self.written = 0;
    }

    pub fn deinit(self: *Db) void {
        self.pool.deinit();
        self.map.deinit();
        self.ring.deinit();
        std.posix.close(self.fd);
    }

    pub fn sync(self: *Db, logger: tel.Logger("db.sync")) !void {
        while (self.pool.io_pending > 0) try self.poll(.from(logger), true);
    }

    pub fn put(self: *Db, logger: tel.Logger("db.put"), slot: Slot, pubkey: *const Pubkey, maybe_data_len: ?u32) !*Account {
        try self.poll(.from(logger), false);

        const hash = std.hash.Wyhash.hash(0, &pubkey.data);
        const found, const entry = self.map.getOrPut(hash);

        if (found) {
            if (entry.slot > slot) return error.OldSlot;
            if (maybe_data_len == null) {} // TODO: delete from map
            // TODO: delete from disk
        }

        const data_len = maybe_data_len orelse 0; // TODO delete from map
        const size = std.mem.alignForward(u32, @sizeOf(Account) + data_len, sector_size);
        if (self.written + size > page_size) {
            try self.flushWritten(.from(logger));
        }

        entry.slot = @intCast(slot);
        entry.sector = @intCast(@divExact(self.offset + self.written, sector_size));

        const page = &self.pool.pages[self.current];
        const buf = page.bytes[self.written..][0..@sizeOf(Account) + data_len];

        self.written += size;
        std.debug.assert(self.written <= page_size);
        return @alignCast(@ptrCast(buf[0..@sizeOf(Account)]));
    }

    fn flushWritten(self: *Db, logger: tel.Logger("db.flush")) !void {
        const last = self.written + 1;
        if (last < page_size) {
            self.pool.pages[self.current].bytes[last] = 0;
            self.written += 1;
        }

        self.written = @min(page_size, std.mem.alignForward(u32, self.written, sector_size));
        self.pool.io[self.current] = .{
            .offset = self.offset,
            .len = self.written,
            .wrote = 0,
        };

        const sqe = try self.getSqe();
        // logger.info().logf(" submit buf={} offset={} wrote={}", .{self.current, self.offset, self.written});
        sqe.prep_write(self.fd, self.pool.pages[self.current].bytes[0..self.written], self.offset);
        sqe.user_data = self.current;

        self.pool.io_pending += 1;
        _ = try self.ring.submit(); // SQPOLL start immediately

        self.current = while (true) break self.pool.acquire() orelse {
            try self.poll(.from(logger), true);
            continue;
        };
        self.offset += page_size;
        self.written = 0;
    }

    fn getSqe(self: *Db) !*std.os.linux.io_uring_sqe {
        while (true) return self.ring.get_sqe() catch |err| switch (err) {
            error.SubmissionQueueFull => {
                _ = try self.ring.submit();
                continue;
            },
        };
    }

    fn poll(self: *Db, logger: tel.Logger("db.poll"), block: bool) !void {
        var cqes: [32]std.os.linux.io_uring_cqe = undefined;
        _ = try self.ring.submit_and_wait(@intFromBool(block));
        const n = try self.ring.copy_cqes(&cqes, 0);

        var submitted: u32 = 0;
        for (cqes[0..n]) |cqe| {
            const idx: u32 = @intCast(cqe.user_data);
            const io = &self.pool.io[idx];
            switch (cqe.err()) {
                .SUCCESS => {
                    const wrote: u32 = @intCast(cqe.res);
                    self.total_written += wrote;
                    io.wrote += wrote;
                    std.debug.assert(io.wrote <= io.len);
                    if (io.wrote == io.len) {
                        // logger.info().logf(" complete buf={} offset={B:.2} wrote={}", .{idx, io.offset, io.wrote});
                        self.pool.io_pending -= 1;
                        self.pool.release(idx);
                    } else {
                        const sqe = try self.getSqe();
                        sqe.prep_write(self.fd, self.pool.pages[idx].bytes[io.wrote..io.len - io.wrote], io.offset + io.wrote);
                        sqe.user_data = idx;
                        submitted += 1;
                    }
                },
                else => |err| {
                    logger.err().logf("pwrite(buf:{}, off:{}, len:{}) = {}", .{
                        cqe.user_data, io.offset, io.len, err,
                    });
                    return error.WriteError;
                }
            }
        }

        const total_elapsed = self.timer.read();
        const current_elapsed = total_elapsed - self.last_elapsed;
        if (current_elapsed >= std.time.ns_per_s) {
            self.last_elapsed = total_elapsed;

            const total_elapsed_secs = @as(f64, @floatFromInt(total_elapsed)) / std.time.ns_per_s;
            const bytes_per_sec: u64 =
                @intFromFloat(@as(f64, @floatFromInt(self.total_written)) / total_elapsed_secs);

            logger.info().logf("tar.zst -> db.put() {B:.3}/s (total:{B:.2})", .{
                bytes_per_sec,
                self.total_written,
            });
        }

        // SQPOLL
        if (submitted > 0) {
            self.pool.io_pending  += submitted;
            _ = try self.ring.submit();
        }
    }
};
