const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const tel = lib.telemetry;

const Table = lib.accounts_db.Table;
const FileWriter = lib.fio.FileWriter;
const FileReader = lib.fio.FileReader;

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;
const Epoch = lib.solana.Epoch;

/// The rooted database stores data on disk in the form of [journal][ring of sector data].
/// TODO: The ring aspect is not implemented, so for now it grows indefinitely.
pub const Rooted = struct {
    table: Table,
    journal: Journal,
    buffered_file: std.fs.File,
    put_batch: Table.PutBatch,
    io: union {
        reader: FileReader(.{ .buffer_size = buffer_size, .block_size = block_size }),
        writer: FileWriter(.{ .buffer_size = buffer_size, .block_size = block_size }),
    },

    const buffer_size = 16 * 1024 * 1024;
    const block_size = 64 * 1024;

    // Put any static metadata in here
    const Journal = extern struct {
        magic: enum(u32) { valid = 0xAA_BB_CC_DD, _ } align(1),
        state: enum(u8) { empty, committed, writing, _ },
        writing_slot: u32 align(1),
        committed_slot: u32 align(1),
        committed_offset: u64 align(1),

        const empty: Journal = .{
            .magic = .valid,
            .state = .empty,
            .writing_slot = 0,
            .committed_slot = 0,
            .committed_offset = 0,
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
    ) !void {
        const seed: u64 = 0; // TODO: maybe in RootedConfig?
        self.table = .init(seed, table_memory);
        self.put_batch = .empty;

        self.journal = .empty;
        open_existing: {
            const read_file = lib.fio.openDirect(dir, path, .read_only) catch |err| switch (err) {
                error.FileNotFound => break :open_existing,
                else => |e| return e,
            };
            defer read_file.close();

            logger.info().logf("loading from existing rooted db", .{});
            self.loadExisting(.from(logger), read_file) catch |err| switch (err) {
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
        errdefer self.buffered_file.deinit();
    }

    pub fn deinit(self: *Rooted) void {
        self.buffered_file.close();
        self.io.writer.file.close();
        self.io.writer.deinit();
    }

    const SectorHeader = packed struct(u64) {
        type: enum(u2) {
            padding, // padding data to get file aligned to block_size for writing
            account, // holds an actual account
            _, // TODO: add other types of sections
        },
        info: packed union {
            padding: u62,
            account: packed struct(u62) {
                data_len: u24,
                executable: bool,
                // epoch never goes this high deliberately. convert max(Epoch) = max(u37)
                rent_epoch: SmallEpoch, // could be smaller to fit more stuff in .account
            },
        },

        const SmallEpoch = u37;
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
                return;
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

        var timer = try std.time.Timer.start();
        var n_puts: usize = 0;
        var n_bytes_read: usize = 0;

        // read sectors until EOF
        while ((try self.io.reader.getBuffer(.from(logger))).len > 0) {
            const file_offset = self.io.reader.getOffset();
            if (file_offset >= self.journal.committed_offset) break; // ignore overrun file data

            // read section header
            var header: SectorHeader = undefined;
            try self.readExisting(.from(logger), @ptrCast(&header), @sizeOf(SectorHeader));
            switch (header.type) {
                .padding => {
                    const pad_len = header.info.padding;
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
                logger.info().logf("read {} accounts ({B:.2}) in {D:.0} (io-stalled:{D:.0})", .{
                    n_puts,
                    n_bytes_read,
                    elapsed_ns,
                    self.io.reader.io_stalled,
                });
                n_puts = 0;
                n_bytes_read = 0;
                self.io.reader.io_stalled = 0;
            }
        }

        self.table.flushPuts(&self.put_batch);
        logger.info().logf("loaded rooted db: {} accounts", .{self.table.count});
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
        snapshot_iter: *lib.solana.snapshot.SnapshotIter,
    ) !void {
        // TODO: pass in the slot from the snapshot_iter.manifest.bank_fields/accounts_db_fields
        try self.beginTransaction(.from(logger), 0);

        var timer = try std.time.Timer.start();
        var n_puts: usize = 0;
        var n_transfer: usize = 0;
        while (try snapshot_iter.next()) |acc| {
            n_puts += 1;
            n_transfer += @sizeOf(AccountMeta) + @sizeOf(SectorHeader) + acc.data.len;
            try self.put(
                .from(logger),
                acc.slot,
                acc.pubkey,
                acc.owner,
                acc.lamports,
                acc.rent_epoch,
                acc.data.executable,
                acc.data.len,
                snapshot_iter,
            );

            const elapsed_ns = timer.read();
            if (elapsed_ns >= std.time.ns_per_s) {
                timer.reset();
                logger.info().logf(
                    "wrote {} accounts (queued:{B:.4}, flushed:{B:.4}) in {D:.0} (io-stall:{D:.0})",
                    .{
                        n_puts,
                        n_transfer,
                        self.io.writer.io_transferred,
                        elapsed_ns,
                        self.io.writer.io_stalled,
                    },
                );
                n_puts = 0;
                n_transfer = 0;
                self.io.writer.io_transferred = 0;
                self.io.writer.io_stalled = 0;
            }
        }

        try self.commitTransaction(.from(logger));
        logger.info().logf("populated from snapshot: {} accounts", .{self.table.count});
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
        slot: Slot,
        pubkey: Pubkey,
        owner: Pubkey,
        lamports: u64,
        rent_epoch: Epoch,
        executable: bool,
        data_len: usize,
        data_reader: anytype, // anything with a std.Io.Reader.readSliceAll API
    ) !void {
        std.debug.assert(self.journal.state == .writing);
        std.debug.assert(data_len <= 10 * 1024 * 1024);
        std.debug.assert(rent_epoch != std.math.maxInt(SectorHeader.SmallEpoch));

        const offset = self.io.writer.getOffset();
        self.table.put(&self.put_batch, &pubkey, slot, .{
            .offset = @intCast(offset),
            .len = @intCast(data_len),
        });

        self.journal.writing_slot = @max(
            self.journal.writing_slot,
            @as(u32, @intCast(slot)),
        );

        { // write SectorHeader + AccountMeta
            const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.writeAccountHeader" });
            defer zone.deinit();

            {
                var header = SectorHeader{
                    .type = .account,
                    .info = .{ .account = .{
                        .data_len = @intCast(data_len),
                        .executable = executable,
                        .rent_epoch = std.math.lossyCast(SectorHeader.SmallEpoch, rent_epoch),
                    } },
                };

                var r = std.Io.Reader.fixed(std.mem.asBytes(&header));
                try self.queueWrite(.from(logger), @sizeOf(@TypeOf(header)), &r);
            }

            {
                var header = AccountMeta{
                    .slot = @intCast(slot),
                    .pubkey = pubkey,
                    .owner = owner,
                    .lamports = lamports,
                };

                var r = std.Io.Reader.fixed(std.mem.asBytes(&header));
                try self.queueWrite(.from(logger), @sizeOf(@TypeOf(header)), &r);
            }
        }

        if (data_len > 0) { // write account data
            const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.writeAccountData" });
            defer zone.deinit();

            try self.queueWrite(.from(logger), data_len, data_reader);
        }
    }

    fn queueWrite(
        self: *Rooted,
        logger: tel.Logger("Rooted.queueWrite"),
        len: usize,
        reader: anytype, // anything that impls an interface like std.Io.Reader
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
                .info = .{ .padding = @intCast(pad_len - @sizeOf(SectorHeader)) },
            };
            logger.info().logf("writing pad sector: {any}", .{header});

            // write padding header
            {
                var r = std.Io.Reader.fixed(std.mem.asBytes(&header));
                try self.queueWrite(.from(logger), @sizeOf(SectorHeader), &r);
            }

            // write padding data
            try self.queueWrite(.from(logger), header.info.padding, struct {
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
};
