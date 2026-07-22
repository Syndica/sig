const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const tel = lib.telemetry;

const FileWriter = lib.fio.FileWriter;
const FileReader = lib.fio.FileReader;

const Table = lib.accounts_db.Table;
const AccountPool = lib.accounts_db.AccountPool;
const AccountLookups = lib.accounts_db.AccountLookups;
const SnapshotMetadata = lib.accounts_db.SnapshotMetadata;

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;
const Epoch = lib.solana.Epoch;
const Hash = lib.solana.Hash;

/// The rooted database stores data on disk in the form of
/// [journal][manifest+status_cache+FBA blob][ring of account sectors].
/// TODO: The ring aspect is not implemented, so for now it grows indefinitely.
pub const Rooted = struct {
    table: Table,
    put_batch: Table.PutBatch,

    buffered_file: std.fs.File,
    ring: std.os.linux.IoUring,
    account_pool: *AccountPool,

    ready_lookups: LookupIndex,
    free_lookups: LookupIndex,
    lookup_nodes: [max_active_lookups]LookupNode,

    journal: Journal,
    io: union {
        reader: FileReader(.{ .buffer_size = buffer_size, .block_size = block_size }),
        writer: FileWriter(.{ .buffer_size = buffer_size, .block_size = block_size }),
    },

    const buffer_size = 64 * 1024 * 1024;
    const block_size = 1 * 1024 * 1024;

    const max_active_lookups = 256;

    // > max_active_lookups == null
    const LookupIndex = std.math.IntFittingRange(0, max_active_lookups + 1);
    const invalid_lookup_index = max_active_lookups;

    pub const LookupResult = AccountLookups.Result;
    const LookupNode = struct {
        next: LookupIndex,
        result: LookupResult,
        file_offset: u64,
        file_header: extern struct {
            sector: SectorHeader align(1),
            meta: AccountMeta align(1),
        },
    };

    // Put any static metadata in here
    const Journal = extern struct {
        magic: enum(u32) { valid = 0xAA_BB_CC_DD, _ } align(1),
        state: enum(u8) { empty, committed, writing, _ },
        writing_slot: u32 align(1),
        committed_slot: u32 align(1),
        committed_offset: u64 align(1),
        blockhash_max_age: u32 align(1),
        /// Padded on-disk size of the SnapshotMetadata blob. 0 means "no metadata yet".
        manifest_bytes: u32 align(1),

        const empty: Journal = .{
            .magic = .valid,
            .state = .empty,
            .writing_slot = 0,
            .committed_slot = 0,
            .committed_offset = 0,
            .blockhash_max_age = 300,
            .manifest_bytes = 0,
        };
    };
    comptime {
        // so that it can be written on its own outside the ring in beginTransaction()
        std.debug.assert(@sizeOf(Journal) <= block_size);
    }

    pub fn init(
        self: *Rooted,
        logger: tel.Logger("Rooted.init"),
        dir: std.fs.Dir,
        path: []const u8,
        table_memory: []u8,
        account_pool: *AccountPool,
        snapshot_metadata: *SnapshotMetadata,
    ) !void {
        const seed: u64 = 0; // TODO: maybe in RootedConfig?
        self.put_batch = .empty;
        self.table = .init(seed, table_memory);

        self.journal = .empty;
        open_existing: {
            const read_file = lib.fio.openDirect(dir, path, .read_only) catch |err| switch (err) {
                error.FileNotFound => break :open_existing,
                else => |e| return e,
            };
            defer read_file.close();

            logger.info().logf("loading from existing rooted db", .{});
            self.loadExisting(
                .from(logger),
                read_file,
                snapshot_metadata,
            ) catch |err| switch (err) {
                error.InvalidJournal => {
                    self.journal = .empty; // reset any modifications from loadExisting()
                    break :open_existing;
                },
                else => |e| return e,
            };
        }

        // Activate the writer union member so future accesses arent UB.
        // Do so without an expensive memset(0xaa) given the buffer_size.
        {
            @setRuntimeSafety(false);
            self.io = .{ .writer = undefined };
        }

        const write_file = try lib.fio.openDirect(dir, path, .rw);
        errdefer write_file.close();

        try self.io.writer.init(write_file);
        errdefer self.io.writer.deinit();

        // sync the journal:
        // - if empty: write first empty journal to offset 0, bumping it
        // - if recovered: undo any uncommitted found during loadExisting()
        {
            try self.writeJournal(.from(logger));
            self.io.writer.setOffset(self.journal.committed_offset);
        }

        // Open the file separately in buffered mode (not O_DIRECT).
        // This is to service AccountPool reads, since Account ptrs arent sector_size aligned.
        self.buffered_file = try dir.openFile(path, .{ .mode = .read_only });
        errdefer self.buffered_file.close();

        self.ring = try .init(max_active_lookups, std.os.linux.IORING_SETUP_SQPOLL);
        errdefer self.ring.deinit();

        self.account_pool = account_pool;

        self.ready_lookups = invalid_lookup_index; // empty
        self.free_lookups = 0; // linked-list of free_lookups
        for (&self.lookup_nodes, 0..) |*node, i| {
            node.next = @intCast(i + 1);
        }
    }

    pub fn deinit(self: *Rooted) void {
        self.ring.deinit();
        self.buffered_file.close();
        self.io.writer.file.close();
        self.io.writer.deinit();
    }

    const SectorHeader = packed struct(u64) {
        type: enum(u3) {
            /// padding data to get file aligned to block_size for writing
            padding,
            /// holds an actual account
            account,
            _, // TODO: add other types of sections
        },
        info: packed union {
            count: u61,
            account: packed struct(u61) {
                data_len: u24,
                executable: bool,
                // epoch never goes this high deliberately. convert max(Epoch) = max(u37)
                rent_epoch: SmallEpoch, // could be smaller to fit more stuff in .account
            },
        },

        const SmallEpoch = u36;
    };

    const AccountMeta = extern struct {
        slot: u32 align(1),
        pubkey: Pubkey align(1),
        owner: Pubkey align(1),
        lamports: u64 align(1),
        // checksum: u32, TODO: checksum this AccountMeta and its data
    };

    fn loadExisting(
        self: *Rooted,
        logger: tel.Logger("Rooted.loadExisting"),
        file: std.fs.File,
        snapshot_metadata: *SnapshotMetadata,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.loadExisting" });
        defer zone.deinit();

        // Activate the reader union member so future accesses arent UB.
        // Do so without an expensive memset(0xaa) given the buffer_size.
        {
            @setRuntimeSafety(false);
            self.io = .{ .reader = undefined };
        }

        try self.io.reader.init(file);
        defer self.io.reader.deinit();

        // read journal
        {
            const buf = try self.io.reader.getBuffer(.from(logger));
            if (buf.len < block_size) return error.InvalidJournal;
            @memcpy(std.mem.asBytes(&self.journal), buf[0..@sizeOf(Journal)]);
            try self.io.reader.advance(block_size);

            // validate journal
            if (self.journal.magic != .valid) {
                logger.err().logf("invalid journal magic - expected:{x}, found:{x}", .{
                    @intFromEnum(@TypeOf(self.journal.magic).valid),
                    @intFromEnum(self.journal.magic),
                });
                return error.InvalidJournal;
            }

            switch (self.journal.state) {
                .empty => return error.InvalidJournal,
                .committed => {
                    if (self.journal.committed_offset < block_size) return error.InvalidJournal;
                },
                .writing => {
                    logger.err().logf("discarding journal written data at slot {}", .{
                        self.journal.writing_slot,
                    });
                    if (self.journal.committed_offset < block_size) return error.InvalidJournal;
                    self.journal.state = .committed;
                },
                _ => {
                    logger.err().logf("invalid journal state: 0x{x}", .{
                        @intFromEnum(self.journal.state),
                    });
                    return error.InvalidJournal;
                },
            }

            logger.info().logf("read journal: {any}", .{self.journal});
        }

        // read the persisted Manifest + StatusCache + FBA blob back into place.
        // Layout on disk: [Journal (block_size)][manifest+status_cache+memory (manifest_bytes)][account sectors...]
        {
            const disk_bytes = self.journal.manifest_bytes;
            const hdr_size = @sizeOf(lib.solana.snapshot.Manifest) +
                @sizeOf(lib.solana.snapshot.StatusCache);
            const total_capacity = hdr_size + snapshot_metadata.memory_len;
            if (disk_bytes == 0 or disk_bytes > total_capacity) {
                logger.err().logf("invalid manifest_bytes: disk={}, capacity={}", .{
                    disk_bytes, total_capacity,
                });
                return error.InvalidJournal;
            }

            const dst: [*]u8 = @ptrCast(&snapshot_metadata.manifest);
            try self.readExisting(.from(logger), dst, disk_bytes);
        }

        var timer = try std.time.Timer.start();
        var n_puts: usize = 0;
        var n_bytes_read: usize = 0;

        // read account sectors until EOF
        while ((try self.io.reader.getBuffer(.from(logger))).len > 0) {
            const file_offset = self.io.reader.getOffset();
            if (file_offset >= self.journal.committed_offset) break; // ignore overrun file data

            // read section header
            var header: SectorHeader = undefined;
            try self.readExisting(.from(logger), @ptrCast(&header), @sizeOf(SectorHeader));
            switch (header.type) {
                .padding => {
                    const pad_len = header.info.count;
                    if (pad_len > self.journal.committed_offset) return error.InvalidPadding;

                    // skip padding bytes
                    try self.readExisting(.from(logger), null, pad_len);
                },
                .account => {
                    const acc_info = header.info.account;
                    if (acc_info.data_len > 10 * 1024 * 1024) return error.InvalidAccount;

                    const data_offset = file_offset + @sizeOf(SectorHeader) + @sizeOf(AccountMeta);
                    if (data_offset + acc_info.data_len > self.journal.committed_offset) {
                        return error.InvalidAccount;
                    }

                    // read AccountMeta
                    var acc: AccountMeta = undefined;
                    try self.readExisting(.from(logger), @ptrCast(&acc), @sizeOf(AccountMeta));

                    // skip the account data
                    try self.readExisting(.from(logger), null, acc_info.data_len);
                    n_bytes_read += @sizeOf(AccountMeta) + acc_info.data_len;

                    // put() into rooted
                    self.journal.committed_slot = @max(self.journal.committed_slot, acc.slot);
                    self.table.put(&self.put_batch, &acc.pubkey, acc.slot, .{
                        .offset = @intCast(file_offset),
                        .len = @intCast(acc_info.data_len),
                    });
                    n_puts += 1;
                },
                _ => return error.InvalidSector,
            }

            const elapsed_ns = timer.read();
            if (elapsed_ns >= std.time.ns_per_s) {
                timer.reset();
                logger.info().logf(
                    "({:.2}%) read {} accounts ({B:.2}) in {D:.0} (io-stalled:{D:.0})",
                    .{
                        (@as(f64, @floatFromInt(self.io.reader.getOffset())) * 100.0) /
                            @as(f64, @floatFromInt(self.journal.committed_offset)),
                        n_puts,
                        n_bytes_read,
                        elapsed_ns,
                        self.io.reader.io_stalled,
                    },
                );
                n_puts = 0;
                n_bytes_read = 0;
                self.io.reader.io_stalled = 0;
            }
        }

        // release the readiness barrier now that Manifest + accounts are loaded.
        snapshot_metadata.populateSlot(self.journal.committed_slot);

        self.table.flushPuts(&self.put_batch);
        logger.info().logf("loaded rooted db: {} accounts", .{self.table.count()});
    }

    fn readExisting(
        self: *Rooted,
        logger: tel.Logger("Rooted.readExisting"),
        maybe_buf: ?[*]u8,
        len: usize,
    ) !void {
        var n: usize = 0;
        while (n < len) {
            const buf = try self.io.reader.getBuffer(.from(logger));
            if (buf.len == 0) return error.EndOfStream;

            const take = @min(buf.len, len - n);
            if (maybe_buf) |b| @memcpy(b[n..][0..take], buf[0..take]);

            try self.io.reader.advance(take);
            n += take;
        }
    }

    pub fn loadSnapshot(
        self: *Rooted,
        logger: tel.Logger("Rooted.loadSnapshot"),
        runner: lib.runner.Connection,
        snapshot_metadata: *SnapshotMetadata,
        buf_reader: anytype,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "loadSnapshot" });
        defer zone.deinit();

        _ = runner; // reserved for future backpressure hooks

        const snapshot = lib.solana.snapshot;
        const Manifest = snapshot.Manifest;
        const StatusCache = snapshot.StatusCache;
        const BufReader = @TypeOf(buf_reader);

        // Build the FBA over snapshot_metadata.memory. Reserve offset 0 as a
        // null sentinel for RelativeOffset(T) so no real allocation lands there.
        var fba = std.heap.FixedBufferAllocator.init(
            snapshot_metadata.memory[0..].ptr[0..snapshot_metadata.memory_len],
        );
        _ = try fba.allocator().alloc(u8, 1);

        var snapshot_iter = try snapshot.SnapshotIter(BufReader).init(
            &fba,
            snapshot_metadata,
            buf_reader,
        );

        const slot = snapshot_metadata.manifest.bank_fields.slot;
        try self.beginTransaction(.from(logger), slot);

        // Persist the Manifest + StatusCache + used-FBA-bytes as a single
        // contiguous blob right after the journal block. Padded to block_size
        // so account sectors start block-aligned.
        {
            const hdr_size = @sizeOf(Manifest) + @sizeOf(StatusCache);
            const unpadded: u64 = hdr_size + fba.end_index;
            const padded: u64 = std.mem.alignForward(u64, unpadded, block_size);
            if (padded > std.math.maxInt(u32)) return error.ManifestTooLarge;
            self.journal.manifest_bytes = @intCast(padded);

            const base: [*]const u8 = @ptrCast(&snapshot_metadata.manifest);
            var r = std.Io.Reader.fixed(base[0..unpadded]);
            try self.queueWrite(.from(logger), unpadded, &r);

            const pad_len = padded - unpadded;
            if (pad_len > 0) try self.queueWrite(.from(logger), pad_len, struct {
                pub fn readSliceAll(_: @This(), b: []u8) !void {
                    @memset(b, 0);
                }
            }{});
        }

        logger.info().logf("reading snapshot accounts", .{});

        var timer = try std.time.Timer.start();
        var n_puts: usize = 0;
        var n_transfer: usize = 0;
        while (try snapshot_iter.next()) |acc| {
            n_puts += 1;
            n_transfer += @sizeOf(AccountMeta) + @sizeOf(SectorHeader) + acc.data.len;
            try self.put(
                .from(logger),
                &snapshot_iter, // data reader
                .{
                    .slot = acc.slot,
                    .pubkey = acc.pubkey,
                    .owner = acc.owner,
                    .lamports = acc.lamports,
                    .rent_epoch = acc.rent_epoch,
                    .executable = acc.data.executable,
                    .data_len = acc.data.len,
                },
            );

            const elapsed_ns = timer.read();
            if (elapsed_ns >= std.time.ns_per_s) {
                timer.reset();
                logger.info().logf(
                    "({:.2}%) wrote {} accounts (queued:{B:.4}, flushed:{B:.4}) (io-stall:{D:.0})",
                    .{
                        snapshot_iter.tar_iter.buf_reader.percentCompleted(),
                        n_puts,
                        n_transfer,
                        self.io.writer.io_transferred,
                        self.io.writer.io_stalled,
                    },
                );
                n_puts = 0;
                n_transfer = 0;
                self.io.writer.io_transferred = 0;
                self.io.writer.io_stalled = 0;
            }
        }

        // release the readiness barrier now that Manifest + accounts are loaded.
        snapshot_metadata.populateSlot(slot);

        try self.commitTransaction(.from(logger));
        logger.info().logf("populated from snapshot: {} accounts", .{self.table.count()});
    }

    pub fn beginTransaction(
        self: *Rooted,
        logger: tel.Logger("Rooted.beginTransacation"),
        slot: Slot,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.beginTransaction" });
        defer zone.deinit();

        std.debug.assert(self.journal.state != .writing);

        self.journal.state = .writing;
        self.journal.writing_slot = @intCast(slot);
        try self.writeJournal(.from(logger));
    }

    fn writeJournal(self: *Rooted, logger: tel.Logger("Rooted.writeJournal")) !void {
        logger.info().logf("writing journal: {}", .{self.journal});

        const buf = try self.io.writer.getBuffer(.from(logger));
        std.debug.assert(buf.len == block_size); // must be at start of new block
        std.debug.assert(self.io.writer.io_inflight == 0); // must be flushed already

        // change the offset just for this journal write
        const old_offset = self.io.writer.getOffset();
        self.io.writer.setOffset(0);
        defer {
            // the first writeJournal() call should consume the 0 offset, not restore it.
            if (old_offset > 0) self.io.writer.setOffset(old_offset);
        }

        // Write the journal
        @memcpy(buf[0..@sizeOf(Journal)], std.mem.asBytes(&self.journal));
        try self.io.writer.advance(block_size);

        // Make sure the writes make it do disk
        try self.io.writer.sync(.from(logger));
        {
            const fsync_zone = tracy.Zone.init(@src(), .{ .name = "Rooted.fsync" });
            defer fsync_zone.deinit();

            try std.posix.fsync(self.io.writer.file.handle);
        }
    }

    pub fn put(
        self: *Rooted,
        logger: tel.Logger("Rooted.put"),
        /// std.Io.Reader
        data_reader: anytype, // readSliceAll()
        account_meta: struct {
            slot: Slot,
            pubkey: Pubkey,
            owner: Pubkey,
            lamports: u64,
            rent_epoch: Epoch,
            executable: bool,
            data_len: usize,
        },
    ) !void {
        std.debug.assert(self.journal.state == .writing);
        std.debug.assert(account_meta.data_len <= 10 * 1024 * 1024);
        std.debug.assert(account_meta.rent_epoch != std.math.maxInt(SectorHeader.SmallEpoch));

        self.table.put(&self.put_batch, &account_meta.pubkey, account_meta.slot, .{
            .offset = @intCast(self.io.writer.getOffset()),
            .len = @intCast(account_meta.data_len),
        });

        self.journal.writing_slot = @max(
            self.journal.writing_slot,
            @as(u32, @intCast(account_meta.slot)),
        );

        { // write SectorHeader + AccountMeta
            const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.writeAccountHeader" });
            defer zone.deinit();

            var header: extern struct {
                sector: SectorHeader align(1),
                meta: AccountMeta align(1),
            } = .{
                .sector = .{
                    .type = .account,
                    .info = .{ .account = .{
                        .data_len = @intCast(account_meta.data_len),
                        .executable = account_meta.executable,
                        .rent_epoch = std.math.lossyCast(
                            SectorHeader.SmallEpoch,
                            account_meta.rent_epoch,
                        ),
                    } },
                },
                .meta = .{
                    .slot = @intCast(account_meta.slot),
                    .pubkey = account_meta.pubkey,
                    .owner = account_meta.owner,
                    .lamports = account_meta.lamports,
                },
            };

            var r = std.Io.Reader.fixed(std.mem.asBytes(&header));
            try self.queueWrite(.from(logger), @sizeOf(@TypeOf(header)), &r);
        }

        if (account_meta.data_len > 0) { // write account data
            const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.writeAccountData" });
            defer zone.deinit();

            try self.queueWrite(.from(logger), account_meta.data_len, data_reader);
        }
    }

    fn queueWrite(
        self: *Rooted,
        logger: tel.Logger("Rooted.queueWrite"),
        len: usize,
        /// std.Io.Reader
        reader: anytype, // readSliceAll()
    ) !void {
        var n: usize = 0;
        while (n < len) {
            const buf = try self.io.writer.getBuffer(.from(logger));

            const take = @min(buf.len, len - n);
            try reader.readSliceAll(buf[0..take]);

            try self.io.writer.advance(take);
            n += take;
        }
    }

    pub fn commitTransaction(self: *Rooted, logger: tel.Logger("Rooted.commitTransaction")) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.commitTransaction" });
        defer zone.deinit();

        std.debug.assert(self.journal.state == .writing);

        // finish up writes made during the beginTransaction().
        try self.flushWrites(.from(logger));

        self.journal.committed_offset = self.io.writer.getOffset();
        self.journal.committed_slot = self.journal.writing_slot;
        self.journal.state = .committed;
        try self.writeJournal(.from(logger));
    }

    fn flushWrites(self: *Rooted, logger: tel.Logger("Rooted.flushWrites")) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.flushWrites" });
        defer zone.deinit();

        // flush the table
        self.table.flushPuts(&self.put_batch);

        // flush any current writes in the Writer by writing a padding sector to fill up the block
        var writable = (try self.io.writer.getBuffer(.from(logger))).len;
        std.debug.assert(writable <= block_size);
        if (writable != block_size) {
            // If under a SectionHeader, gotta fill up the next block too
            var pad_len = writable;
            if (writable < @sizeOf(SectorHeader)) pad_len += block_size;
            std.debug.assert(pad_len >= @sizeOf(SectorHeader));

            var header: SectorHeader = .{
                .type = .padding,
                .info = .{ .count = @intCast(pad_len - @sizeOf(SectorHeader)) },
            };
            logger.info().logf("writing pad sector: {B:.2}", .{header.info.count});

            // write padding header
            {
                var r = std.Io.Reader.fixed(std.mem.asBytes(&header));
                try self.queueWrite(.from(logger), @sizeOf(SectorHeader), &r);
            }

            // write padding data
            try self.queueWrite(.from(logger), header.info.count, struct {
                pub fn readSliceAll(_: @This(), buf: []u8) !void {
                    @memset(buf, 0);
                }
            }{});
        }

        // the writable block should be empty now
        writable = (try self.io.writer.getBuffer(.from(logger))).len;
        std.debug.assert(writable == block_size);

        // wait for all queued writes to complete.
        try self.io.writer.sync(.from(logger));
    }

    /// Queue a lookup into rooted to populate a new AccountPool index.
    /// Returns false if it cannot queue the lookup (call pollRead to check for completions).
    pub fn queueRead(
        self: *Rooted,
        logger: tel.Logger("Rooted.queueRead"),
        pubkey: *const Pubkey,
    ) !bool {
        const lookup_idx = self.free_lookups;
        if (lookup_idx == invalid_lookup_index) {
            return false; // no available lookups to use.
        }

        // pop from free list (add back on error)
        const node = &self.lookup_nodes[lookup_idx];
        self.free_lookups = node.next;
        errdefer {
            node.next = self.free_lookups;
            self.free_lookups = lookup_idx;
        }

        const entry = self.table.get(pubkey);
        if (entry.isEmpty()) { // not found. complete immediately.
            node.result = .{ .pubkey = pubkey.*, .account_index = .invalid };
            node.next = self.ready_lookups;
            self.ready_lookups = lookup_idx;
            return true;
        }

        const acc_idx = try self.account_pool.alloc(entry.len);
        node.result = .{ .pubkey = pubkey.*, .account_index = acc_idx };

        // prepare the account (these must be set before self.account_pool.free() on the same index)
        const account = self.account_pool.getAccount(acc_idx);
        account.ref_count = .init(0);
        account.data = .{ .executable = false, .len = @intCast(entry.len) };
        errdefer self.account_pool.free(acc_idx);

        node.file_offset = entry.offset;
        try self.submitRead(.from(logger), .{
            .lookup_idx = lookup_idx,
            .reading = .header,
            .read = 0,
        });

        return true;
    }

    // Consume
    pub fn pollRead(self: *Rooted, logger: tel.Logger("Rooted.pollReady")) !?LookupResult {
        // check if lookup in ready queue
        var lookup_idx = self.ready_lookups;
        if (lookup_idx >= self.lookup_nodes.len) {
            @branchHint(.unlikely);

            // try to fill up ready queue, then check again
            try self.pollCompletedReads(.from(logger));

            lookup_idx = self.ready_lookups;
            if (lookup_idx >= self.lookup_nodes.len) {
                return null;
            }
        }

        // pop from ready queue
        const node = &self.lookup_nodes[lookup_idx];
        self.ready_lookups = node.next;

        // consume result, then push to free list
        const result = node.result;
        node.next = self.free_lookups;
        self.free_lookups = lookup_idx;

        return result;
    }

    const RingUserData = packed struct(u64) {
        lookup_idx: LookupIndex,
        reading: enum(u1) { header, payload },
        read: std.meta.Int(.unsigned, 64 - @bitSizeOf(LookupIndex) - 1),
    };

    fn submitRead(
        self: *Rooted,
        logger: tel.Logger("Rooted.submitRead"),
        data: RingUserData,
    ) !void {
        const node = &self.lookup_nodes[data.lookup_idx];
        const account = self.account_pool.getAccount(node.result.account_index);
        const offset: u64, const buffer: []u8 = switch (data.reading) {
            .header => .{ 0, std.mem.asBytes(&node.file_header) },
            .payload => .{ @sizeOf(@TypeOf(node.file_header)), account.getData() },
        };

        std.debug.assert(data.read <= buffer.len);
        if (data.read == buffer.len) { // read is already complete
            return self.completeRead(.from(logger), data);
        }

        const sqe = while (true) break self.ring.get_sqe() catch |err| switch (err) {
            error.SubmissionQueueFull => {
                _ = try self.ring.submit();
                continue;
            },
        };
        sqe.prep_read(
            self.buffered_file.handle,
            buffer[data.read..],
            node.file_offset + offset + data.read,
        );
        sqe.user_data = @bitCast(data);
        _ = try self.ring.submit(); // SQPOLL makes this fast if done frequently enough
    }

    fn pollCompletedReads(self: *Rooted, logger: tel.Logger("Rooted.pollCompletedReads")) !void {
        var cqes: [max_active_lookups]std.os.linux.io_uring_cqe = undefined;
        const n = try self.ring.copy_cqes(&cqes, 0);

        for (cqes[0..n]) |*cqe| {
            var data: RingUserData = @bitCast(cqe.user_data);

            const node = &self.lookup_nodes[data.lookup_idx];
            errdefer { // on IO error, free the account pool value & the node
                self.account_pool.free(node.result.account_index);
                node.next = self.free_lookups;
                self.free_lookups = data.lookup_idx;
            }

            const account = self.account_pool.getAccount(node.result.account_index);
            const offset: u64, const buffer: []u8 = switch (data.reading) {
                .header => .{ 0, std.mem.asBytes(&node.file_header) },
                .payload => .{ @sizeOf(@TypeOf(node.file_header)), account.getData() },
            };

            const n_read: u32 = switch (cqe.err()) {
                .SUCCESS => @intCast(cqe.res),
                else => |err| {
                    logger.err().logf("pread(fd={}, buf={*}, len={}, offset={}) = {}", .{
                        self.buffered_file.handle,
                        buffer.ptr + data.read,
                        buffer[data.read..].len,
                        node.file_offset + offset + data.read,
                        err,
                    });
                    return error.ReadFailed;
                },
            };

            if (n_read == 0) {
                logger.err().logf("EOF when reading account {s} of {f}: {}/{}", .{
                    @tagName(data.reading),
                    node.result.pubkey,
                    data.read,
                    buffer.len,
                });
                return error.EndOfStream;
            }

            data.read += n_read;
            try self.submitRead(.from(logger), data); // continue the read process
        }
    }

    const ReadError =
        error{ ReadFailed, EndOfStream } || // I/O error
        error{InvalidRead} || // Corrupted data error
        @typeInfo( // io_uring.submit() error
            @typeInfo(@TypeOf(std.os.linux.IoUring.submit)).@"fn".return_type.?,
        ).error_union.error_set;

    fn completeRead(
        self: *Rooted,
        logger: tel.Logger("Rooted.completeRead"),
        data: RingUserData,
    ) ReadError!void {
        const node = &self.lookup_nodes[data.lookup_idx];
        const account = self.account_pool.getAccount(node.result.account_index);

        switch (data.reading) {
            .header => {
                std.debug.assert(data.read == std.mem.asBytes(&node.file_header).len);

                // validate the SectorHeader
                const header = node.file_header.sector;
                if (header.type != .account) {
                    logger.err().logf("account lookup {f} read invalid sector: {any}", .{
                        node.result.pubkey,
                        header,
                    });
                    return error.InvalidRead;
                }

                const acc_info = header.info.account;
                if (acc_info.data_len != account.data.len) {
                    logger.err().logf(
                        "account lookup {f} read mismatch sector size: expected {} found {}",
                        .{ node.result.pubkey, account.data.len, acc_info.data_len },
                    );
                    return error.InvalidRead;
                }

                // validate the AccountMeta
                const meta = node.file_header.meta;
                if (!meta.pubkey.equals(&node.result.pubkey)) {
                    logger.err().logf("account lookup {f} read invalid metadata: {any}", .{
                        node.result.pubkey,
                        meta,
                    });
                    return error.InvalidRead;
                }

                // start reading the account data body.
                return self.submitRead(.from(logger), .{
                    .lookup_idx = data.lookup_idx,
                    .reading = .payload,
                    .read = 0,
                });
            },
            .payload => {
                std.debug.assert(data.read == account.getData().len);

                // TODO: now with account.getData(), verify meta.checksum
                const sector = node.file_header.sector.info.account;
                const meta = &node.file_header.meta;

                // mark account as ready
                account.* = .{
                    .ref_count = .init(1),
                    .pubkey = meta.pubkey,
                    .owner = meta.owner,
                    .lamports = meta.lamports,
                    .rent_epoch = switch (sector.rent_epoch) {
                        std.math.maxInt(SectorHeader.SmallEpoch) => std.math.maxInt(Epoch),
                        else => |rent_epoch| rent_epoch,
                    },
                    .data = .{
                        .executable = sector.executable,
                        .len = @intCast(sector.data_len),
                    },
                };

                // push node to ready queue
                node.next = self.ready_lookups;
                self.ready_lookups = data.lookup_idx;
            },
        }
    }
};
