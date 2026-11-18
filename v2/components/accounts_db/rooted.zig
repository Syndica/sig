const std = @import("std");
const lib = @import("lib");
const tracy = @import("tracy");
const api = @import("accounts_db_api");
const component = @import("component.zig");

const tel = lib.telemetry;

const FileWriter = lib.fio.FileWriter;
const FileReader = lib.fio.FileReader;

const Table = component.Table;
const AccountPool = lib.AccountPool;
const AccountLookups = api.AccountLookups;
const RuntimeMetadata = api.RuntimeMetadata;

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;
const Epoch = lib.solana.Epoch;
const Hash = lib.solana.Hash;
const LtHash = lib.solana.LtHash;

/// A reader that yields zeroes, used to fill padding sectors.
const ZeroReader = struct {
    pub fn readSliceAll(_: ZeroReader, buf: []u8) !void {
        @memset(buf, 0);
    }
};

/// Writes all of `bytes` at `offset`, retrying short writes.
fn pwriteAll(fd: std.posix.fd_t, bytes: []const u8, offset: u64) !void {
    var n: usize = 0;
    while (n < bytes.len) {
        const written = try std.posix.pwrite(fd, bytes[n..], offset + n);
        if (written == 0) return error.WriteFailed;
        n += written;
    }
}

/// The rooted database stores data on disk in the form of
/// [journal slots][ring of sector data]. The file has a fixed size; when the
/// data ring wraps, `compactIfNeeded` first drops stale sectors and relocates
/// live ones to the head, so old versions of accounts are reclaimed.
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
    /// Guards against re-entering compaction from `flushWrites`.
    compacting: bool,
    /// Last reported ring-usage bucket, so crossings are logged only once.
    usage_bucket: u8,
    io: union {
        reader: FileReader(.{ .buffer_size = buffer_size, .block_size = block_size }),
        writer: FileWriter(.{ .buffer_size = buffer_size, .block_size = block_size }),
    },

    const buffer_size = 64 * 1024 * 1024;
    const block_size = 1 * 1024 * 1024;

    /// Journal slots are written alternately: a torn write to one slot leaves
    /// the other slot (the previous commit) intact. Both live in the first
    /// block, which the data ring never touches.
    const journal_slot_size = 16 * 1024;
    const journal_slot_offsets = [2]u64{ 0, journal_slot_size };

    /// Sector data begins at the first block after the journal slots.
    const ring_start = block_size;
    /// A record may not extend past `ring_end - ring_wrap_gap`, so that a
    /// padding sector can always be written to wrap around to `ring_start`.
    const ring_wrap_gap = @sizeOf(SectorHeader);

    /// Start compacting when free space drops below this fraction of the ring.
    /// The effective threshold is at least one writer block (plus the wrap
    /// gap), so a transaction always has room to finish its current block.
    const compact_low_water_divisor = 16; // 1/16th == 6.25%
    /// Reclaim up to this fraction of the ring at a time while compacting.
    /// The effective target is at least two writer blocks (plus the wrap gap).
    const compact_high_water_divisor = 8; // 1/8th == 12.5%

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
        version: u8,
        state: enum(u8) { empty, committed, writing, _ },
        writing_slot: u32 align(1),
        committed_slot: u32 align(1),
        /// Offset of the next write into the data ring (the ring "head").
        committed_offset: u64 align(1),
        /// Offset of the oldest data in the ring (the ring "tail").
        tail_offset: u64 align(1),
        /// Fixed size of the file. The data ring is `[ring_start, ring_end)`.
        ring_end: u64 align(1),
        blockhash_max_age: u32 align(1),
        /// Offset of the live `block_metadata` sector, or 0 if there is none.
        /// It is relocated when compaction reaches it.
        metadata_offset: u64 align(1),
        block_id: Hash align(1),
        /// Incremented on every journal write; the highest valid seq wins.
        seq: u64 align(1),
        checksum: u32 align(1),

        const version_current = 1;

        fn init(capacity: u64) Journal {
            return .{
                .magic = .valid,
                .version = version_current,
                .state = .empty,
                .writing_slot = 0,
                .committed_slot = 0,
                .committed_offset = ring_start,
                .tail_offset = ring_start,
                .ring_end = capacity,
                .blockhash_max_age = 300,
                .metadata_offset = 0,
                .block_id = .ZEROES,
                .seq = 0,
                .checksum = 0,
            };
        }

        fn checksumOf(self: *const Journal) u32 {
            const bytes = std.mem.asBytes(self);
            return std.hash.Crc32.hash(bytes[0..@offsetOf(Journal, "checksum")]);
        }

        fn validate(self: *const Journal, capacity: u64) bool {
            if (self.magic != .valid) return false;
            if (self.version != version_current) return false;
            if (self.checksum != self.checksumOf()) return false;
            if (self.ring_end != capacity) return false;
            if (self.committed_offset < ring_start) return false;
            if (self.committed_offset >= capacity) return false;
            if (self.committed_offset % block_size != 0) return false;
            if (self.tail_offset < ring_start) return false;
            if (self.tail_offset >= capacity) return false;
            if (self.metadata_offset != 0) {
                if (self.metadata_offset < ring_start) return false;
                if (self.metadata_offset >= capacity) return false;
            }
            return switch (self.state) {
                .empty, .committed, .writing => self.usedBytes() < self.ringLen(),
                _ => false,
            };
        }

        fn ringLen(self: *const Journal) u64 {
            return self.ring_end - ring_start;
        }

        fn usedBytes(self: *const Journal) u64 {
            return ringDelta(self.committed_offset, self.tail_offset, self.ringLen());
        }
    };

    /// Forward distance from `tail` to `head` in a ring of `ring_len` bytes.
    /// Both offsets must be valid ring offsets (`>= ring_start` and
    /// `< ring_start + ring_len`).
    fn ringDelta(head: u64, tail: u64, ring_len: u64) u64 {
        if (head >= tail) return head - tail;
        return head + ring_len - tail;
    }

    comptime {
        // The journal is written on its own, outside the ring.
        std.debug.assert(@sizeOf(Journal) <= journal_slot_size);
        std.debug.assert(@sizeOf(Journal) == @offsetOf(Journal, "checksum") + 4);
        std.debug.assert(ring_start >= 2 * journal_slot_size);
        std.debug.assert(journal_slot_size % lib.fio.sector_size == 0);
    }

    pub fn init(
        self: *Rooted,
        logger: tel.Logger("Rooted.init"),
        runner: lib.runner.Connection,
        dir: std.fs.Dir,
        path: []const u8,
        capacity_in: u64,
        table_memory: []u8,
        account_pool: *AccountPool,
        runtime_metadata: *RuntimeMetadata,
    ) !void {
        const seed: u64 = 0; // TODO: maybe in RootedConfig?
        self.put_batch = .empty;
        self.table = .init(seed, table_memory);
        self.compacting = false;
        self.usage_bucket = 0;

        const capacity = std.mem.alignBackward(u64, capacity_in, block_size);
        if (capacity < ring_start + 4 * block_size) {
            logger.err().logf("rooted db capacity {B:.2} is too small", .{capacity_in});
            return error.InvalidCapacity;
        }
        if (capacity > std.math.maxInt(u40)) {
            // Table.Value.offset is a u40.
            logger.err().logf("rooted db capacity {B:.2} is too large", .{capacity_in});
            return error.InvalidCapacity;
        }
        self.journal = .init(capacity);

        const write_file = try lib.fio.openDirect(dir, path, .rw);
        errdefer write_file.close();

        // Open the file separately in buffered mode (not O_DIRECT).
        // This is to service AccountPool reads, since Account ptrs arent sector_size aligned,
        // and to read/write the journal without disturbing the O_DIRECT ring writer.
        self.buffered_file = try dir.openFile(path, .{ .mode = .read_only });
        errdefer self.buffered_file.close();

        const recovered = blk: {
            // A db written with a different capacity cannot be reused: its
            // tail/head offsets and wrap points are relative to the old file.
            if ((try write_file.getEndPos()) != capacity) break :blk false;

            logger.info().log("loading from existing rooted db");
            self.loadExisting(
                .from(logger),
                runner,
                write_file,
                runtime_metadata,
            ) catch |err| switch (err) {
                error.InvalidJournal => {
                    logger.err().log("invalid rooted db journal; starting fresh");
                    self.journal = .init(capacity); // reset any loadExisting() changes
                    self.put_batch = .empty;
                    self.table = .init(seed, table_memory);
                    break :blk false;
                },
                else => |e| return e,
            };
            break :blk true;
        };

        // Activate the writer union member so future accesses arent UB.
        // Do so without an expensive memset(0xaa) given the buffer_size.
        {
            @setRuntimeSafety(false);
            self.io = .{ .writer = undefined };
        }

        try self.io.writer.init(write_file);
        errdefer self.io.writer.deinit();

        if (!recovered) try write_file.setEndPos(capacity);
        self.io.writer.setRing(ring_start, capacity);

        // sync the journal:
        // - if fresh: write the first empty journal
        // - if recovered: undo any uncommitted found during loadExisting()
        try self.writeJournal(.from(logger));
        self.io.writer.setOffset(self.journal.committed_offset);

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
            /// holds the block_id followed by a serialized addition to the blockhash queue.
            /// body layout: `{ block_id: Hash, [info.count]Hash }`
            block_metadata,
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

    /// The on-disk prefix of an account sector. The account data follows
    /// immediately after these bytes, i.e. at `file_offset + @sizeOf(AccountHeader)`.
    const AccountHeader = extern struct {
        sector: SectorHeader align(1),
        meta: AccountMeta align(1),
    };

    comptime {
        std.debug.assert(@sizeOf(AccountHeader) ==
            @sizeOf(SectorHeader) + @sizeOf(AccountMeta));
    }

    fn loadExisting(
        self: *Rooted,
        logger: tel.Logger("Rooted.loadExisting"),
        runner: lib.runner.Connection,
        file: std.fs.File,
        runtime_metadata: *RuntimeMetadata,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.loadExisting" });
        defer zone.deinit();

        // Pick the newest journal slot. The slots are written alternately, so
        // a torn write to one leaves the previous commit intact in the other.
        var best: ?Journal = null;
        for (journal_slot_offsets) |slot_offset| {
            var slot: [journal_slot_size]u8 = undefined;
            try self.readAt(&slot, slot_offset);
            var journal: Journal = undefined;
            @memcpy(std.mem.asBytes(&journal), slot[0..@sizeOf(Journal)]);
            if (!journal.validate(self.journal.ring_end)) continue;
            if (best == null or journal.seq > best.?.seq) best = journal;
        }
        self.journal = best orelse {
            logger.err().log("no valid journal found");
            return error.InvalidJournal;
        };

        switch (self.journal.state) {
            .empty => return error.InvalidJournal,
            .committed => {},
            .writing => {
                logger.err().logf("discarding journal written data at slot {}", .{
                    self.journal.writing_slot,
                });
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

        var blockhash_writer = runtime_metadata.blockhash_queue.hashes.getView(.writer);
        defer {
            runtime_metadata.blockhash_queue.max_age = self.journal.blockhash_max_age;
            blockhash_writer.close(); // close when done.
        }

        var state: RecoveryState = .{};

        // The committed data may be split in two ranges when the ring wrapped.
        const used = self.journal.usedBytes();
        if (used == 0) {
            // Nothing has ever been committed. Treat this as a fresh db so the
            // caller can populate it from a snapshot.
            logger.info().log("rooted db journal is empty");
            return error.InvalidJournal;
        }
        {
            const tail = self.journal.tail_offset;
            const head = self.journal.committed_offset;
            if (tail < head) {
                try self.recoverRange(
                    .from(logger),
                    runner,
                    file,
                    tail,
                    head,
                    &blockhash_writer,
                    &state,
                );
            } else {
                try self.recoverRange(
                    .from(logger),
                    runner,
                    file,
                    tail,
                    self.journal.ring_end,
                    &blockhash_writer,
                    &state,
                );
                if (head > ring_start) {
                    try self.recoverRange(
                        .from(logger),
                        runner,
                        file,
                        ring_start,
                        head,
                        &blockhash_writer,
                        &state,
                    );
                }
            }
        }

        runtime_metadata.block_id = state.last_block_id orelse return error.NoBlockIDs;
        self.journal.block_id = runtime_metadata.block_id;
        self.journal.metadata_offset = state.metadata_offset;
        self.journal.committed_slot = @max(self.journal.committed_slot, state.max_slot);

        // write the slot to commit the RuntimeMetadata stuff
        const slot = self.journal.committed_slot;
        runtime_metadata.populateSlot(slot);

        self.table.flushPuts(&self.put_batch);
        logger.info().logf("loaded rooted db: {} accounts", .{self.table.count()});
    }

    const RecoveryState = struct {
        max_slot: u32 = 0,
        last_block_id: ?Hash = null,
        metadata_offset: u64 = 0,
    };

    /// Reads and indexes one contiguous committed range `[start, end)` of the
    /// ring. Sectors never cross `ring_end` (see `put`), so the two ranges of a
    /// wrapped ring can be recovered independently.
    fn recoverRange(
        self: *Rooted,
        logger: tel.Logger("Rooted.recoverRange"),
        runner: lib.runner.Connection,
        file: std.fs.File,
        start: u64,
        end: u64,
        blockhash_writer: anytype,
        state: *RecoveryState,
    ) !void {
        std.debug.assert(start < end);
        std.debug.assert(end <= self.journal.ring_end);

        // Activate the reader union member so future accesses arent UB.
        // Do so without an expensive memset(0xaa) given the buffer_size.
        {
            @setRuntimeSafety(false);
            self.io = .{ .reader = undefined };
        }

        const aligned_start = std.mem.alignBackward(u64, start, block_size);
        try self.io.reader.initAt(file, aligned_start);
        defer self.io.reader.deinit();
        defer self.io.reader.sync(.from(logger)) catch {};
        try self.io.reader.skip(start - aligned_start, .from(logger));

        var timer = try std.time.Timer.start();
        var n_puts: usize = 0;
        var n_bytes_read: usize = 0;

        while (true) {
            const file_offset = self.io.reader.getOffset();
            if (file_offset >= end) break;

            // read section header
            var header: SectorHeader = undefined;
            try self.readExisting(.from(logger), @ptrCast(&header), @sizeOf(SectorHeader));
            const next_offset = self.io.reader.getOffset();

            switch (header.type) {
                .padding => {
                    const pad_len = header.info.count;
                    if (next_offset + pad_len > end) return error.InvalidPadding;

                    // skip padding bytes
                    try self.readExisting(.from(logger), null, pad_len);
                },
                .account => {
                    const acc_info = header.info.account;
                    if (acc_info.data_len > 10 * 1024 * 1024) return error.InvalidAccount;

                    const data_offset = file_offset + @sizeOf(AccountHeader);
                    if (data_offset + acc_info.data_len > end) {
                        return error.InvalidAccount;
                    }

                    // read AccountMeta
                    var acc: AccountMeta = undefined;
                    try self.readExisting(.from(logger), @ptrCast(&acc), @sizeOf(AccountMeta));

                    // skip the account data
                    try self.readExisting(.from(logger), null, acc_info.data_len);
                    n_bytes_read += @sizeOf(AccountMeta) + acc_info.data_len;

                    // put() into rooted
                    state.max_slot = @max(state.max_slot, acc.slot);
                    self.table.put(&self.put_batch, &acc.pubkey, acc.slot, .{
                        .offset = @intCast(file_offset),
                        .len = @intCast(acc_info.data_len),
                    });
                    n_puts += 1;
                },
                .block_metadata => {
                    const num_hashes: u64 = header.info.count;
                    const sector_len = @sizeOf(SectorHeader) +
                        @sizeOf(Hash) + num_hashes * @sizeOf(Hash);
                    if (file_offset + sector_len > end) return error.InvalidSector;

                    // read block_id
                    var block_id: Hash = undefined;
                    try self.readExisting(.from(logger), (&block_id.data).ptr, @sizeOf(Hash));
                    state.last_block_id = block_id;
                    state.metadata_offset = file_offset;

                    // read blockhashes
                    var hashes_remaining = num_hashes;
                    while (hashes_remaining > 0) {
                        // get a buffer to write hashes into
                        const hash_buf: []Hash = try blockhash_writer.getBufferBlocking(runner);
                        if (hash_buf.len == 0) {
                            // blockhash_reader closed their end. just skip the hashes then.
                            try self.readExisting(
                                .from(logger),
                                null,
                                @sizeOf(Hash) * hashes_remaining,
                            );
                            break;
                        }

                        // read hashes into blockhash_writer to send over
                        const take = @min(hashes_remaining, hash_buf.len);
                        try self.readExisting(
                            .from(logger),
                            @ptrCast(hash_buf.ptr),
                            @sizeOf(Hash) * take,
                        );
                        blockhash_writer.advance(take);
                        hashes_remaining -= take;
                    }
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
                            @as(f64, @floatFromInt(end)),
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
        SnapshotReader: type,
        logger: tel.Logger("Rooted.loadSnapshot"),
        runner: lib.runner.Connection,
        snapshot_iter: *lib.solana.snapshot.SnapshotIter(SnapshotReader),
        runtime_metadata: *RuntimeMetadata,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "loadSnapshot" });
        defer zone.deinit();

        std.debug.assert(self.table.count() == 0);
        // A fresh db writes into an empty ring. This also resets a db whose
        // previous snapshot load failed before committing.
        self.journal.committed_offset = ring_start;
        self.journal.tail_offset = ring_start;
        self.journal.metadata_offset = 0;
        self.journal.block_id = .ZEROES;
        self.io.writer.setOffset(ring_start);

        const slot = snapshot_iter.manifest.bank_fields.slot;
        try self.beginTransaction(.from(logger), slot);

        var timer = try std.time.Timer.start();
        var n_puts: usize = 0;
        var n_transfer: usize = 0;
        while (try snapshot_iter.next()) |acc| {
            n_puts += 1;
            n_transfer += @sizeOf(AccountMeta) + @sizeOf(SectorHeader) + acc.data.len;
            try self.put(
                .from(logger),
                snapshot_iter, // data reader
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

        { // write the block_id + current blockhash queue
            const blockhash_queue = &snapshot_iter.manifest.bank_fields.blockhash_queue;
            self.journal.blockhash_max_age = std.math.lossyCast(u32, blockhash_queue.max_age);

            const block_id = snapshot_iter.manifest.extra_fields.block_id;
            const num_hashes = blockhash_queue.hashes.count;
            const hashes = blockhash_queue.hashes.array[0..num_hashes];

            try self.reserveRecordSpace(
                .from(logger),
                @as(u64, @sizeOf(SectorHeader) + @sizeOf(Hash)) +
                    @as(u64, num_hashes) * @sizeOf(Hash),
            );
            const metadata_offset = self.io.writer.getOffset();

            // write block_metadata header
            const header: SectorHeader = .{
                .type = .block_metadata,
                .info = .{ .count = @intCast(num_hashes) },
            };

            var r = std.Io.Reader.fixed(std.mem.asBytes(&header));
            try self.queueWrite(.from(logger), @sizeOf(SectorHeader), &r);

            // write block_id
            r = std.Io.Reader.fixed(std.mem.asBytes(&block_id));
            try self.queueWrite(.from(logger), @sizeOf(Hash), &r);

            // write blockhashes
            r = std.Io.Reader.fixed(std.mem.sliceAsBytes(hashes));
            try self.queueWrite(.from(logger), num_hashes * @sizeOf(Hash), &r);

            self.journal.metadata_offset = metadata_offset;
            self.journal.block_id = block_id;
            runtime_metadata.block_id = block_id;

            // send blockhashes over as metadata
            var blockhash_writer = runtime_metadata.blockhash_queue.hashes.getView(.writer);
            defer {
                runtime_metadata.blockhash_queue.max_age = self.journal.blockhash_max_age;
                blockhash_writer.close(); // close when done.
            }

            var i: usize = 0;
            while (i < hashes.len) {
                const buf = try blockhash_writer.getBufferBlocking(runner);
                if (buf.len == 0) break; // reader closed somehow

                const take = @min(buf.len, hashes.len - i);
                @memcpy(buf[0..take], hashes[i..][0..take]);
                blockhash_writer.advance(take);
                i += take;
            }
        }

        // write the slot to commit the RuntimeMetadata stuff
        runtime_metadata.populateSlot(slot);

        // Flush everything to disk so the accounts can be read back to verify
        // the snapshot's lattice hash. This is not wasted work: commitTransaction
        // flushes anyway, and the second flush finds nothing left to write.
        try self.flushWrites(.from(logger));

        if (snapshot_iter.manifest.extra_fields.accounts_lt_hash) |expected| {
            // Verify *before* committing, so that a snapshot whose account data
            // does not match the manifest is never recorded as a valid db.
            try self.verifyAccountsLtHash(.from(logger), expected);
        } else {
            logger.info().log("snapshot has no accounts_lt_hash; skipping verification");
        }

        try self.commitTransaction(.from(logger));
        logger.info().logf("populated from snapshot: {} accounts", .{self.table.count()});
    }

    /// Recomputes the lattice hash over the live accounts and compares it with
    /// the value recorded in the snapshot manifest.
    ///
    /// Agave's `accounts_lt_hash` covers the live account set, i.e. the version
    /// of each pubkey with the highest slot, which is exactly what the table
    /// holds after `loadSnapshot`. Older versions of a pubkey are still present
    /// in the journal and are therefore deliberately not mixed in.
    pub fn verifyAccountsLtHash(
        self: *Rooted,
        logger: tel.Logger("Rooted.verifyAccountsLtHash"),
        expected: LtHash,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "verifyAccountsLtHash" });
        defer zone.deinit();

        // TODO(#1727): parallelize this scan. It re-reads all account data, so
        // it roughly doubles the IO of a snapshot load. Hashing on the writer
        // path would avoid that, but requires reading superseded versions back
        // from the journal to mix them out.
        var actual = LtHash.IDENTITY;
        var n_accounts: usize = 0;
        var n_bytes: usize = 0;

        var it = self.table.iterator();
        while (it.next()) |item| {
            actual.mixIn(try hashAccountAt(self, item));
            n_accounts += 1;
            n_bytes += item.value.len;
        }

        if (!actual.eql(expected)) {
            logger.err().logf(
                "accounts_lt_hash mismatch over {} accounts ({} bytes): " ++
                    "expected {f}, found {f}",
                .{ n_accounts, n_bytes, expected.checksum(), actual.checksum() },
            );
            return error.AccountsLtHashMismatch;
        }

        logger.info().logf(
            "verified accounts_lt_hash over {} accounts ({} bytes): {f}",
            .{ n_accounts, n_bytes, actual.checksum() },
        );
    }

    /// Reads exactly `buf.len` bytes at `offset` from the journal, using the
    /// buffered (non-O_DIRECT) fd so arbitrary offsets and lengths are allowed.
    ///
    /// Also acts as the reader for `hashAccountAt`, which lets tests drive the
    /// same logic from a byte slice.
    pub fn readAt(self: *const Rooted, buf: []u8, offset: u64) !void {
        var n: usize = 0;
        while (n < buf.len) {
            const n_read = try std.posix.pread(self.buffered_file.handle, buf[n..], offset + n);
            if (n_read == 0) return error.EndOfStream;
            n += n_read;
        }
    }

    /// Chunk size used to stream account data while hashing. Accounts can be up
    /// to 10MiB, so buffering a whole one per account is undesirable.
    const hash_chunk_size = 64 * 1024;

    /// Parses one account's on-disk header and data, and returns its lattice
    /// hash. `reader` must provide `readAt(self, buf, offset) !void`.
    fn hashAccountAt(reader: anytype, item: Table.Item) !LtHash {
        const offset: u64 = item.value.offset;

        var header: AccountHeader = undefined;
        try reader.readAt(std.mem.asBytes(&header), offset);

        if (header.sector.type != .account) return error.InvalidSector;
        const sector = header.sector.info.account;
        const meta = &header.meta;
        if (sector.data_len != item.value.len) return error.InvalidAccount;
        if (!meta.pubkey.equals(&item.key)) return error.InvalidAccount;

        var hasher = LtHash.AccountHasher.init(
            meta.lamports,
            &meta.owner,
            sector.executable,
            &meta.pubkey,
        );

        if (!hasher.identity) {
            var data_offset = offset + @sizeOf(AccountHeader);
            var remaining: usize = item.value.len;
            var buf: [hash_chunk_size]u8 = undefined;
            while (remaining > 0) {
                const take = @min(remaining, buf.len);
                try reader.readAt(buf[0..take], data_offset);
                hasher.update(buf[0..take]);
                data_offset += take;
                remaining -= take;
            }
        }

        return hasher.final();
    }

    pub fn beginTransaction(
        self: *Rooted,
        logger: tel.Logger("Rooted.beginTransacation"),
        slot: Slot,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.beginTransaction" });
        defer zone.deinit();

        std.debug.assert(self.journal.state != .writing);

        // Reclaim space *before* starting the transaction, so that a crash
        // during compaction leaves the previous journal (and therefore the
        // previous head/tail) intact. The new head/tail are only published by
        // the journal write below, after the relocated data is durable.
        try self.compactIfNeeded(.from(logger));
        try self.flushWrites(.from(logger));
        self.journal.committed_offset = self.io.writer.getOffset();

        self.journal.state = .writing;
        self.journal.writing_slot = @intCast(slot);
        try self.writeJournal(.from(logger));
    }

    fn writeJournal(self: *Rooted, logger: tel.Logger("Rooted.writeJournal")) !void {
        logger.info().logf("writing journal: {}", .{self.journal});

        // The journal slots are written alternately, so that a torn write to
        // one cannot destroy the last good commit in the other.
        self.journal.seq +%= 1;
        self.journal.checksum = 0;
        self.journal.checksum = self.journal.checksumOf();

        const slot_index: usize = @intCast(self.journal.seq % journal_slot_offsets.len);
        const slot_offset = journal_slot_offsets[slot_index];

        // O_DIRECT requires sector-aligned buffers and lengths.
        var buf: [journal_slot_size]u8 align(lib.fio.sector_size) = @splat(0);
        @memcpy(buf[0..@sizeOf(Journal)], std.mem.asBytes(&self.journal));

        try pwriteAll(self.io.writer.file.handle, &buf, slot_offset);

        // Make sure the data writes and the journal write make it to disk.
        {
            const fsync_zone = tracy.Zone.init(@src(), .{ .name = "Rooted.fsync" });
            defer fsync_zone.deinit();

            try std.posix.fsync(self.io.writer.file.handle);
        }
    }

    fn compactIfNeeded(self: *Rooted, logger: tel.Logger("Rooted.compactIfNeeded")) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.compactIfNeeded" });
        defer zone.deinit();

        if (self.compacting) return;

        // Compaction advances the tail so that the reclaimed range can be
        // reused. That is only safe while no transaction is in flight: the
        // last committed journal must keep pointing at readable data until the
        // next transaction publishes the compacted state in `beginTransaction`.
        if (self.journal.state == .writing) return;

        const ring_len = self.journal.ringLen();
        // The writer commits whole blocks, so we need at least one block of
        // free space to make progress regardless of how big the ring is.
        const low_free = @max(
            ring_len / compact_low_water_divisor,
            block_size + ring_wrap_gap,
        );
        const free = self.freeBytes();
        if (free >= low_free) return;

        self.compacting = true;
        defer self.compacting = false;

        // Make in-transaction puts visible to the liveness checks below.
        self.table.flushPuts(&self.put_batch);

        const target_free = @max(
            ring_len / compact_high_water_divisor,
            2 * block_size + ring_wrap_gap,
        );
        logger.info().logf("compacting rooted db ring: {B:.2} free of {B:.2}", .{
            free,
            ring_len,
        });

        // Everything in [tail, committed_offset) is committed data. Relocated
        // sectors are written at the head, i.e. outside that range, so scanning
        // stops once the tail reaches the last committed head. This only runs
        // between transactions, so the old range is never touched by writes
        // until its replacement has been published by the next journal write.
        const scan_end = self.journal.committed_offset;
        var n_relocated: usize = 0;
        var n_dropped: usize = 0;

        while (self.freeBytes() < target_free and self.journal.tail_offset != scan_end) {
            const result = self.compactSector(.from(logger)) catch |err| switch (err) {
                // No room to relocate this sector. Everything before it has
                // already been relocated/dropped; stop here. The caller will
                // fail with RingFull if it really needs more space.
                error.RingFull => break,
                else => |e| return e,
            };
            self.journal.tail_offset = result.next;
            if (result.relocated) {
                n_relocated += 1;
            } else {
                n_dropped += 1;
            }
        }

        // Pad the head to a block boundary so the range is well formed and let
        // the queued copies make progress before the caller continues.
        try self.flushWritesNoCompact(.from(logger));

        logger.info().logf(
            "compacted rooted db ring: relocated {}, dropped {}, {B:.2} free of {B:.2}",
            .{ n_relocated, n_dropped, self.freeBytes(), ring_len },
        );
    }

    const CompactResult = struct {
        next: u64,
        relocated: bool,
    };

    /// Processes the sector at the ring tail: drops it if it is stale, or
    /// copies it to the ring head if it is live. Returns the next tail offset.
    fn compactSector(self: *Rooted, logger: tel.Logger("Rooted.compactSector")) !CompactResult {
        const source = self.journal.tail_offset;
        const capacity = self.journal.ring_end;

        var header: SectorHeader = undefined;
        try self.readAt(std.mem.asBytes(&header), source);

        const sector_len: u64 = switch (header.type) {
            .padding => @as(u64, @sizeOf(SectorHeader)) + header.info.count,
            .account => @as(u64, @sizeOf(AccountHeader)) + header.info.account.data_len,
            .block_metadata => @as(u64, @sizeOf(SectorHeader)) +
                @sizeOf(Hash) + @as(u64, header.info.count) * @sizeOf(Hash),
            _ => return error.InvalidSector,
        };
        if (source + sector_len > capacity) return error.InvalidSector;

        const next = if (source + sector_len == capacity)
            ring_start
        else
            source + sector_len;

        switch (header.type) {
            .padding => return .{ .next = next, .relocated = false }, // always droppable
            .account => {
                var acc_header: AccountHeader = undefined;
                try self.readAt(std.mem.asBytes(&acc_header), source);

                const data_len = acc_header.sector.info.account.data_len;
                const live = blk: {
                    const value = self.table.get(&acc_header.meta.pubkey);
                    break :blk !value.isEmpty() and
                        value.offset == @as(u40, @intCast(source)) and
                        value.len == data_len;
                };
                if (!live) return .{ .next = next, .relocated = false };

                // Copy the exact on-disk bytes to the head and repoint the
                // table at the copy. The old copy is reclaimed when the tail
                // advances past it.
                try self.reserveRecordSpace(.from(logger), @sizeOf(AccountHeader) + data_len);

                const dest = self.io.writer.getOffset();
                var r = std.Io.Reader.fixed(std.mem.asBytes(&acc_header));
                try self.queueWrite(.from(logger), @sizeOf(AccountHeader), &r);
                try self.copySectorBody(
                    .from(logger),
                    data_len,
                    source + @sizeOf(AccountHeader),
                );

                self.table.put(&self.put_batch, &acc_header.meta.pubkey, acc_header.meta.slot, .{
                    .offset = @intCast(dest),
                    .len = data_len,
                });

                return .{ .next = next, .relocated = true };
            },
            .block_metadata => {
                if (source != self.journal.metadata_offset) {
                    return .{ .next = next, .relocated = false };
                }

                const body_len: u64 = @sizeOf(Hash) +
                    @as(u64, header.info.count) * @sizeOf(Hash);
                try self.reserveRecordSpace(.from(logger), @sizeOf(SectorHeader) + body_len);

                const dest = self.io.writer.getOffset();
                var r = std.Io.Reader.fixed(std.mem.asBytes(&header));
                try self.queueWrite(.from(logger), @sizeOf(SectorHeader), &r);
                try self.copySectorBody(
                    .from(logger),
                    body_len,
                    source + @sizeOf(SectorHeader),
                );

                self.journal.metadata_offset = dest;
                return .{ .next = next, .relocated = true };
            },
            else => return error.InvalidSector,
        }
    }

    /// Copies `len` bytes from `source_offset` to the ring head.
    fn copySectorBody(
        self: *Rooted,
        logger: tel.Logger("Rooted.copySectorBody"),
        len: u64,
        source_offset: u64,
    ) !void {
        const copy_chunk_size = 64 * 1024;
        var buf: [copy_chunk_size]u8 = undefined;
        var done: u64 = 0;
        while (done < len) {
            const take: usize = @intCast(@min(@as(u64, buf.len), len - done));
            try self.readAt(buf[0..take], source_offset + done);
            var r = std.Io.Reader.fixed(buf[0..take]);
            try self.queueWrite(.from(logger), take, &r);
            done += take;
        }
    }

    fn usedBytes(self: *const Rooted) u64 {
        return ringDelta(
            self.io.writer.getOffset(),
            self.journal.tail_offset,
            self.journal.ringLen(),
        );
    }

    fn freeBytes(self: *const Rooted) u64 {
        return self.journal.ringLen() - self.usedBytes();
    }

    /// A snapshot of ring occupancy, for telemetry and operator alerts.
    /// `used` grows until compaction reclaims stale sectors.
    pub const RingUsage = struct {
        capacity: u64,
        used: u64,
        free: u64,

        pub fn percentFull(self: RingUsage) f64 {
            return @as(f64, @floatFromInt(self.used)) * 100.0 /
                @as(f64, @floatFromInt(self.capacity));
        }
    };

    pub fn ringUsage(self: *const Rooted) RingUsage {
        const capacity = self.journal.ringLen();
        const used = self.usedBytes();
        return .{ .capacity = capacity, .used = used, .free = capacity - used };
    }

    /// 0 below 75% full, 1 at 75-90%, 2 at 90% or more.
    fn usageBucket(used: u64, capacity: u64) u8 {
        const permille = used * 1000 / capacity;
        return if (permille >= 900) 2 else if (permille >= 750) 1 else 0;
    }

    /// Log gauge for ring occupancy. Emits one entry per threshold crossing
    /// (up or down) rather than one per commit, so it does not spam the logs.
    fn reportRingUsage(self: *Rooted, logger: tel.Logger("Rooted.usage")) void {
        const usage = self.ringUsage();
        const bucket = usageBucket(usage.used, usage.capacity);
        if (bucket == self.usage_bucket) return;
        self.usage_bucket = bucket;

        switch (bucket) {
            0 => logger.info().logf(
                "rooted db ring usage fell to {d:.1}% ({B:.2} used of {B:.2})",
                .{ usage.percentFull(), usage.used, usage.capacity },
            ),
            1 => logger.warn().logf(
                "rooted db ring is {d:.1}% full ({B:.2} used of {B:.2})",
                .{ usage.percentFull(), usage.used, usage.capacity },
            ),
            2 => logger.err().logf(
                "rooted db ring is {d:.1}% full; compaction is losing headroom ({B:.2} used of {B:.2})",
                .{ usage.percentFull(), usage.used, usage.capacity },
            ),
            else => unreachable,
        }
    }

    /// Ensures that a sector of `record_len` bytes can be written at the head
    /// without overwriting live data. If the sector would cross the end of the
    /// ring, a padding sector is written to fill the remainder first.
    ///
    /// This deliberately does not compact: compaction may only run between
    /// transactions, because it advances the tail and the reclaimed range is
    /// then reused by the current transaction's writes. Doing that while a
    /// transaction is in flight would let a crash overwrite data that the last
    /// committed journal still points at.
    fn reserveRecordSpace(
        self: *Rooted,
        logger: tel.Logger("Rooted.reserveRecordSpace"),
        record_len: u64,
    ) !void {
        const ring_len = self.journal.ringLen();

        if (record_len + ring_wrap_gap > ring_len) {
            return error.RecordTooLarge;
        }

        const capacity = self.journal.ring_end;
        const head = self.io.writer.getOffset();

        // Where the record will be written, and how much contiguous space from
        // `head` the transaction needs to reserve for it.
        const wraps = head + record_len + ring_wrap_gap > capacity;

        // Only the record itself has to fit right now. The final block is
        // padded by `flushWrites`, which checks the padding against the tail
        // and fails the transaction rather than overwriting it.
        const needed = if (wraps)
            (capacity - head) + record_len
        else
            record_len;

        // Keep at least one gap's worth of bytes between head and tail so that
        // an empty ring can never be confused with a full one.
        if (needed + ring_wrap_gap > self.freeBytes()) {
            return error.RingFull;
        }

        if (wraps) {
            const pad_len = capacity - head;
            std.debug.assert(pad_len >= @sizeOf(SectorHeader));
            logger.info().logf("wrapping rooted db ring: padding {B:.2}", .{pad_len});

            const header: SectorHeader = .{
                .type = .padding,
                .info = .{ .count = @intCast(pad_len - @sizeOf(SectorHeader)) },
            };
            var r = std.Io.Reader.fixed(std.mem.asBytes(&header));
            try self.queueWrite(.from(logger), @sizeOf(SectorHeader), &r);
            try self.queueWrite(.from(logger), @intCast(pad_len - @sizeOf(SectorHeader)), ZeroReader{});
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

        // This may write a padding sector to wrap the ring, so it must happen
        // before the table entry (and the sector header) is written.
        try self.reserveRecordSpace(
            .from(logger),
            @sizeOf(AccountHeader) + account_meta.data_len,
        );

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

            var header: AccountHeader = .{
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

        self.reportRingUsage(.from(logger));
    }

    fn flushWrites(self: *Rooted, logger: tel.Logger("Rooted.flushWrites")) !void {
        // Reclaim space first, then complete the current block. Compact only
        // between transactions: this is a no-op while compacting or writing.
        try self.compactIfNeeded(.from(logger));
        try self.flushWritesNoCompact(.from(logger));
    }

    fn flushWritesNoCompact(
        self: *Rooted,
        logger: tel.Logger("Rooted.flushWrites"),
    ) !void {
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

            // The writer commits whole blocks, so the padding must not run
            // into the tail. Compaction at the start of the transaction should
            // normally have made room; if it did not, fail without overwriting.
            const head = self.io.writer.getOffset();
            const ring_len = self.journal.ringLen();
            const pad_end = head + pad_len;
            std.debug.assert(pad_end <= self.journal.ring_end);
            if (ringDelta(pad_end, self.journal.tail_offset, ring_len) + ring_wrap_gap > ring_len) {
                return error.RingFull;
            }

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

test "hashAccountAt matches the one-shot account hash" {
    const allocator = std.testing.allocator;

    // Exercises the on-disk layout (sector header bit packing, AccountMeta
    // fields) and the chunked data streaming.
    const SliceReader = struct {
        bytes: []const u8,

        fn readAt(self: @This(), buf: []u8, offset: u64) !void {
            const start: usize = @intCast(offset);
            if (start + buf.len > self.bytes.len) return error.EndOfStream;
            @memcpy(buf, self.bytes[start..][0..buf.len]);
        }
    };

    var owner: Pubkey = .ZEROES;
    var address: Pubkey = .ZEROES;
    for (&owner.data, 0..) |*byte, i| byte.* = @truncate(i + 1);
    for (&address.data, 0..) |*byte, i| byte.* = @truncate(i * 7 + 3);

    const data_len = 2 * Rooted.hash_chunk_size + 17;
    const bytes = try allocator.alloc(u8, @sizeOf(Rooted.AccountHeader) + data_len);
    defer allocator.free(bytes);
    for (bytes[@sizeOf(Rooted.AccountHeader)..], 0..) |*byte, i| {
        byte.* = @truncate(i * 31 + 11);
    }

    const header: Rooted.AccountHeader = .{
        .sector = .{
            .type = .account,
            .info = .{ .account = .{
                .data_len = @intCast(data_len),
                .executable = true,
                .rent_epoch = 42,
            } },
        },
        .meta = .{
            .slot = 5,
            .pubkey = address,
            .owner = owner,
            .lamports = 1_000_000,
        },
    };
    @memcpy(bytes[0..@sizeOf(Rooted.AccountHeader)], std.mem.asBytes(&header));

    const item: Table.Item = .{
        .key = address,
        .slot = 5,
        .value = .{ .len = @intCast(data_len), .offset = 0 },
    };
    const reader: SliceReader = .{ .bytes = bytes };

    const expected = LtHash.hashAccount(
        1_000_000,
        bytes[@sizeOf(Rooted.AccountHeader)..],
        &owner,
        true,
        &address,
    );
    try std.testing.expect((try Rooted.hashAccountAt(reader, item)).eql(expected));

    // A single corrupted data byte must change the resulting hash.
    bytes[bytes.len - 1] ^= 0xff;
    try std.testing.expect(!(try Rooted.hashAccountAt(reader, item)).eql(expected));

    // Zero-lamport accounts contribute the identity element and their data is
    // not hashed at all.
    var zero_header = header;
    zero_header.meta.lamports = 0;
    @memcpy(bytes[0..@sizeOf(Rooted.AccountHeader)], std.mem.asBytes(&zero_header));
    try std.testing.expect((try Rooted.hashAccountAt(reader, item)).eql(LtHash.IDENTITY));
}

test "rooted ring distance and journal validation" {
    // Forward distance from tail to head, wrapping at the end of the ring.
    try std.testing.expectEqual(@as(u64, 2), Rooted.ringDelta(5, 3, 10));
    try std.testing.expectEqual(@as(u64, 8), Rooted.ringDelta(3, 5, 10));
    try std.testing.expectEqual(@as(u64, 0), Rooted.ringDelta(3, 3, 10));
    try std.testing.expectEqual(@as(u64, 9), Rooted.ringDelta(2, 3, 10));

    // Ring-usage alert thresholds are inclusive at 75% and 90%.
    try std.testing.expectEqual(@as(u8, 0), Rooted.usageBucket(0, 1000));
    try std.testing.expectEqual(@as(u8, 0), Rooted.usageBucket(749, 1000));
    try std.testing.expectEqual(@as(u8, 1), Rooted.usageBucket(750, 1000));
    try std.testing.expectEqual(@as(u8, 1), Rooted.usageBucket(899, 1000));
    try std.testing.expectEqual(@as(u8, 2), Rooted.usageBucket(900, 1000));
    try std.testing.expectEqual(@as(u8, 2), Rooted.usageBucket(1000, 1000));

    const capacity = Rooted.ring_start + 16 * Rooted.block_size;
    var journal: Rooted.Journal = .init(capacity);

    // The freshly initialized journal has no checksum yet.
    journal.checksum = journal.checksumOf() ^ 1;
    try std.testing.expect(!journal.validate(capacity));

    journal.checksum = journal.checksumOf();
    try std.testing.expect(journal.validate(capacity));

    // A checksum-covered field mutated without updating the checksum is rejected.
    journal.committed_offset = Rooted.ring_start + Rooted.block_size;
    try std.testing.expect(!journal.validate(capacity));
    journal.checksum = journal.checksumOf();
    try std.testing.expect(journal.validate(capacity));

    // A db written with a different capacity is not reusable.
    try std.testing.expect(!journal.validate(capacity + Rooted.block_size));

    // Offsets must stay inside the ring and the head must be block aligned.
    journal.committed_offset = Rooted.ring_start + 1;
    journal.checksum = journal.checksumOf();
    try std.testing.expect(!journal.validate(capacity));
    journal.committed_offset = Rooted.ring_start;
    journal.checksum = journal.checksumOf();
    try std.testing.expect(journal.validate(capacity));

    // Invalid magic/version/state are rejected even with a valid checksum.
    journal.magic = @enumFromInt(0);
    journal.checksum = journal.checksumOf();
    try std.testing.expect(!journal.validate(capacity));

    journal = .init(capacity);
    journal.state = @enumFromInt(0xff);
    journal.checksum = journal.checksumOf();
    try std.testing.expect(!journal.validate(capacity));

    journal = .init(capacity);
    journal.version = Rooted.Journal.version_current + 1;
    journal.checksum = journal.checksumOf();
    try std.testing.expect(!journal.validate(capacity));
}

fn testPubkey(i: u32) Pubkey {
    var key: Pubkey = .ZEROES;
    key.data[0] = @truncate(i);
    key.data[1] = @truncate(i >> 8);
    key.data[2] = @truncate(i >> 16);
    key.data[3] = @truncate(i >> 24);
    key.data[31] = 0xA5; // keep the system-program (zero) pubkey out of the test
    return key;
}

fn testAccountData(buf: []u8, key_index: u32, slot: u32) void {
    var seed: u64 = (@as(u64, key_index) << 32) | slot;
    seed ^= 0x9e37_79b9_7f4a_7c15;
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(buf);
}

fn expectRootedAccount(
    rooted: *Rooted,
    pubkey: *const Pubkey,
    expected_data: []const u8,
) !void {
    const logger = tel.Logger("test").noop;
    try std.testing.expect(try rooted.queueRead(.from(logger), pubkey));
    while (true) {
        if (try rooted.pollRead(.from(logger))) |result| {
            try std.testing.expectEqualSlices(u8, &pubkey.data, &result.pubkey.data);
            try std.testing.expect(result.account_index != .invalid);

            const account = rooted.account_pool.getAccount(result.account_index);
            try std.testing.expectEqualSlices(u8, expected_data, account.getData());
            if (account.unref()) rooted.account_pool.free(result.account_index);
            return;
        }
    }
}

test "rooted ring wraps, compacts, recovers, and survives a torn journal" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    // io_uring with SQPOLL needs privileges, and O_DIRECT support depends on the
    // filesystem. Skip rather than fail when the environment cannot host a db.
    {
        var probe = std.os.linux.IoUring.init(4, std.os.linux.IORING_SETUP_SQPOLL) catch
            return error.SkipZigTest;
        probe.deinit();
    }

    const allocator = std.testing.allocator;
    const logger = tel.Logger("test").noop;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const probe = lib.fio.openDirect(tmp.dir, "probe", .rw) catch return error.SkipZigTest;
        probe.close();
        try tmp.dir.deleteFile("probe");
    }

    const path = "accounts.db";
    const capacity = 8 * 1024 * 1024;
    const n_accounts = 128;
    const data_len = 2048;
    const n_transactions = 48;

    var activity: lib.runner.Activity = .{};
    var activity_view = activity.serviceView();
    const runner: lib.runner.Connection = .{ .activity = &activity_view };

    const table_memory = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(table_memory);
    @memset(table_memory, 0);

    const pool_memory = try allocator.alignedAlloc(
        u8,
        std.mem.Alignment.of(AccountPool),
        @sizeOf(AccountPool) + 4 * 1024 * 1024,
    );
    defer allocator.free(pool_memory);
    @memset(pool_memory, 0);
    const pool: *AccountPool = @ptrCast(pool_memory.ptr);
    pool.init(pool_memory.len - @sizeOf(AccountPool));

    const rooted = try allocator.create(Rooted);
    defer allocator.destroy(rooted);

    var metadata: RuntimeMetadata = undefined;
    metadata.init();

    try rooted.init(
        .from(logger),
        runner,
        tmp.dir,
        path,
        capacity,
        table_memory,
        pool,
        &metadata,
    );

    const block_id = Hash.parse("ByzshhkRgXWnTkHjapkkqaKgEFnsg8ceY3bw4MWBzFE");
    var scratch: [data_len]u8 = undefined;
    var wrapped = false;

    for (0..n_transactions) |tx| {
        const slot: u32 = @intCast(tx + 1);
        const head_before = rooted.io.writer.getOffset();

        try rooted.beginTransaction(.from(logger), slot);

        if (tx == 0) {
            // The recovery path requires a block_metadata sector to recover the
            // block id from. Write one with no blockhashes.
            const header: Rooted.SectorHeader = .{
                .type = .block_metadata,
                .info = .{ .count = 0 },
            };
            try rooted.reserveRecordSpace(.from(logger), @sizeOf(Rooted.SectorHeader) + @sizeOf(Hash));
            const offset = rooted.io.writer.getOffset();

            var r = std.Io.Reader.fixed(std.mem.asBytes(&header));
            try rooted.queueWrite(.from(logger), @sizeOf(Rooted.SectorHeader), &r);
            r = std.Io.Reader.fixed(std.mem.asBytes(&block_id));
            try rooted.queueWrite(.from(logger), @sizeOf(Hash), &r);

            rooted.journal.metadata_offset = offset;
            rooted.journal.block_id = block_id;
        }

        // Overwrite every account on every transaction so that all but the
        // newest sector for each key become stale and reclaimable.
        for (0..n_accounts) |i| {
            const key = testPubkey(@intCast(i));
            testAccountData(&scratch, @intCast(i), slot);

            var r = std.Io.Reader.fixed(&scratch);
            try rooted.put(.from(logger), &r, .{
                .slot = slot,
                .pubkey = key,
                .owner = testPubkey(0xffff_ffff),
                .lamports = 1_000 + i,
                .rent_epoch = 0,
                .executable = false,
                .data_len = scratch.len,
            });
        }

        try rooted.commitTransaction(.from(logger));

        // Compaction writes forward from the head, so the only way the head can
        // move backwards is by wrapping around the end of the ring.
        if (rooted.io.writer.getOffset() < head_before) wrapped = true;
    }

    try std.testing.expect(wrapped);
    try std.testing.expectEqual(@as(u64, n_accounts), rooted.table.count());

    const usage = rooted.ringUsage();
    try std.testing.expectEqual(rooted.journal.ringLen(), usage.capacity);
    try std.testing.expectEqual(usage.capacity - usage.used, usage.free);
    try std.testing.expect(usage.free > 0);
    try std.testing.expect(usage.used > 0);

    // Every live account must be reachable after wrapping and compaction.
    for (0..n_accounts) |i| {
        const key = testPubkey(@intCast(i));
        testAccountData(&scratch, @intCast(i), n_transactions);
        try expectRootedAccount(rooted, &key, &scratch);
    }

    const seq_before_torn_write = rooted.journal.seq;
    rooted.deinit();

    // Keep an intact copy: Rooted.init() rewrites the journal, which would
    // overwrite the slot the torn db needs to fall back to.
    const clean_path = "accounts-clean.db";
    try std.fs.Dir.copyFile(tmp.dir, path, tmp.dir, clean_path, .{});

    // Tear the newest journal slot. Recovery must fall back to the previous
    // slot, which describes the state just before the last transaction.
    {
        const file = try tmp.dir.openFile(path, .{ .mode = .read_write });
        defer file.close();
        const newest_slot = Rooted.journal_slot_offsets[seq_before_torn_write % 2];
        var garbage: [lib.fio.sector_size]u8 align(lib.fio.sector_size) = @splat(0xff);
        try pwriteAll(file.handle, &garbage, newest_slot);
        try std.posix.fsync(file.handle);
    }

    // Table.init relies on zeroed memory (as mmap provides), so clear it
    // before each reopen.
    @memset(table_memory, 0);

    var torn_metadata: RuntimeMetadata = undefined;
    torn_metadata.init();
    try rooted.init(
        .from(logger),
        runner,
        tmp.dir,
        path,
        capacity,
        table_memory,
        pool,
        &torn_metadata,
    );

    try std.testing.expectEqualSlices(u8, &block_id.data, &torn_metadata.block_id.data);
    try std.testing.expectEqual(@as(u64, n_accounts), rooted.table.count());
    for (0..n_accounts) |i| {
        const key = testPubkey(@intCast(i));
        testAccountData(&scratch, @intCast(i), n_transactions - 1);
        try expectRootedAccount(rooted, &key, &scratch);
    }
    rooted.deinit();

    // The intact copy must recover the full last transaction.
    @memset(table_memory, 0);

    var recovered_metadata: RuntimeMetadata = undefined;
    recovered_metadata.init();
    try rooted.init(
        .from(logger),
        runner,
        tmp.dir,
        clean_path,
        capacity,
        table_memory,
        pool,
        &recovered_metadata,
    );
    defer rooted.deinit();

    try std.testing.expectEqualSlices(u8, &block_id.data, &recovered_metadata.block_id.data);
    try std.testing.expectEqual(@as(u64, n_accounts), rooted.table.count());
    for (0..n_accounts) |i| {
        const key = testPubkey(@intCast(i));
        testAccountData(&scratch, @intCast(i), n_transactions);
        try expectRootedAccount(rooted, &key, &scratch);
    }
}

test "rooted loads a real agave snapshot and recovers it" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    {
        var probe = std.os.linux.IoUring.init(4, std.os.linux.IORING_SETUP_SQPOLL) catch
            return error.SkipZigTest;
        probe.deinit();
    }

    const allocator = std.testing.allocator;
    const logger = tel.Logger("test").noop;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const probe = lib.fio.openDirect(tmp.dir, "probe", .rw) catch return error.SkipZigTest;
        probe.close();
        try tmp.dir.deleteFile("probe");
    }

    const snapshot_path = lib.test_data_dir ++ "test-snapshot-v4.2.0-beta.1.tar.zst";
    const path = "accounts.db";
    // The fixture's accounts occupy about 129 KiB, well inside this ring.
    const capacity = 8 * 1024 * 1024;

    var activity: lib.runner.Activity = .{};
    var activity_view = activity.serviceView();
    const runner: lib.runner.Connection = .{ .activity = &activity_view };

    const table_memory = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(table_memory);
    @memset(table_memory, 0);

    const pool_memory = try allocator.alignedAlloc(
        u8,
        std.mem.Alignment.of(AccountPool),
        @sizeOf(AccountPool) + 4 * 1024 * 1024,
    );
    defer allocator.free(pool_memory);
    @memset(pool_memory, 0);
    const pool: *AccountPool = @ptrCast(pool_memory.ptr);
    pool.init(pool_memory.len - @sizeOf(AccountPool));

    const rooted = try allocator.create(Rooted);
    defer allocator.destroy(rooted);

    var metadata: RuntimeMetadata = undefined;
    metadata.init();

    try rooted.init(
        .from(logger),
        runner,
        tmp.dir,
        path,
        capacity,
        table_memory,
        pool,
        &metadata,
    );

    const zst_reader = try allocator.create(lib.solana.snapshot.ZstReader);
    defer allocator.destroy(zst_reader);
    try zst_reader.init(std.fs.cwd(), snapshot_path);
    defer zst_reader.deinit();

    const SnapshotBufReader = struct {
        zst_reader: *lib.solana.snapshot.ZstReader,
        buf: [128 * 1024]u8 = undefined,
        pos: usize = 0,
        end: usize = 0,

        pub fn percentCompleted(_: @This()) f64 {
            return 0.0;
        }

        pub fn getBuffer(self: *@This()) []const u8 {
            if (self.pos == self.end) {
                self.pos = 0;
                self.end = self.zst_reader.read(.noop, &self.buf) catch |e|
                    std.debug.panic("ZstReader.read failed: {t}", .{e});
            }
            return self.buf[self.pos..self.end];
        }

        pub fn advance(self: *@This(), n: usize) void {
            self.pos += n;
        }
    };

    var snapshot_reader: SnapshotBufReader = .{ .zst_reader = zst_reader };
    const fba_buf = try allocator.alloc(u8, 8 * 1024 * 1024);
    defer allocator.free(fba_buf);
    var fba: std.heap.FixedBufferAllocator = .init(fba_buf);
    var snapshot_iter =
        try lib.solana.snapshot.SnapshotIter(*SnapshotBufReader).init(&fba, &snapshot_reader);

    try rooted.loadSnapshot(
        *SnapshotBufReader,
        .from(logger),
        runner,
        &snapshot_iter,
        &metadata,
    );

    const expected_block_id = Hash.parse("4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4");

    // The fixture stores 9 versions of 8 distinct accounts.
    try std.testing.expectEqual(@as(u32, 100), rooted.journal.committed_slot);
    try std.testing.expectEqual(@as(u64, 8), rooted.table.count());
    try std.testing.expectEqualSlices(u8, &expected_block_id.data, &metadata.block_id.data);
    try std.testing.expectEqual(@as(u64, 300), metadata.blockhash_queue.max_age);

    rooted.deinit();

    // Table.init relies on zeroed memory (as mmap provides).
    @memset(table_memory, 0);

    var recovered_metadata: RuntimeMetadata = undefined;
    recovered_metadata.init();
    try rooted.init(
        .from(logger),
        runner,
        tmp.dir,
        path,
        capacity,
        table_memory,
        pool,
        &recovered_metadata,
    );
    defer rooted.deinit();

    try std.testing.expectEqual(@as(u32, 100), rooted.journal.committed_slot);
    try std.testing.expectEqual(@as(u64, 8), rooted.table.count());
    try std.testing.expectEqualSlices(
        u8,
        &expected_block_id.data,
        &recovered_metadata.block_id.data,
    );
    try std.testing.expectEqual(@as(u64, 300), recovered_metadata.blockhash_queue.max_age);
}
