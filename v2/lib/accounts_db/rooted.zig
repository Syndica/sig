const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const tel = lib.telemetry;

const Table = lib.accounts_db.Table;
const Account = lib.accounts_db.Account;

const FileReader = lib.accounts_db.io.FileReader;
const FileWriter = lib.accounts_db.io.FileWriter;

pub const Rooted = struct {
    file: std.fs.File,
    table: Table,
    file_reader: FileReader(16 * 1024 * 1024), // TODO: will be used for ringed compaction
    file_writer: FileWriter(16 * 1024 * 1024), // will be used for ringed rooting

    pub fn init(
        self: *Rooted,
        logger: tel.Logger("Rooted"),
        db_dir: std.fs.Dir,
        db_path: []const u8,
        table_memory: []u8,
    ) !void {
        const seed: u64 = 0; // TODO
        self.table = .init(seed, table_memory);

        self.file = try lib.accounts_db.io.openDirect(db_dir, db_path, .rw);
        errdefer self.file.close();

        try self.file_writer.init(self.file);
        errdefer self.file_writer.deinit();

        const db_size = (try self.file.stat()).size;
        if (db_size > 0) {
            logger.info().logf("loading existing db file: {B:.2}", .{db_size});
            try self.loadExisting(.from(logger), db_size);
        }
    }

    pub fn deinit(self: *Rooted) void {
        self.file_writer.deinit();
        self.file.close();
    }

    pub fn loadExisting(
        self: *Rooted,
        logger: tel.Logger("Rooted.loadExisting"),
        db_size: u64,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.loadExisting" });
        defer zone.deinit();

        try self.file_reader.init(self.file);
        defer self.file_reader.deinit();

        var last_now: u64 = 0;
        var last_head: u64 = 0;
        var num_accounts: usize = 0;
        var timer = std.time.Timer.start() catch unreachable;

        var account: Account = undefined;
        var put_batch: Table.PutBatch = .empty;
        loop: while (true) {
            // read account header
            var acc_buf: []u8 = std.mem.asBytes(&account);
            while (acc_buf.len > 0) {
                const buf = try self.file_reader.getSlice(.from(logger));
                if (buf.len == 0) {
                    if (acc_buf.len != @sizeOf(Account)) return error.EndOfStream;
                    break :loop;
                }
                const n = @min(acc_buf.len, buf.len);
                @memcpy(acc_buf[0..n], buf[0..n]);
                try self.file_reader.advance(n);
                acc_buf = acc_buf[n..];
            }

            // insert account if valid
            if (account.info.valid) {
                @branchHint(.likely);
                const data_len = account.info.data_len;
                if (data_len > 10 * 1024 * 1024) return error.InvalidAccount;

                num_accounts += 1;
                self.table.put(&put_batch, &account.pubkey, account.slot, .{
                    .len = @intCast(data_len),
                    .offset = @intCast(self.file_reader.head),
                });
            }

            // skip the account data
            var len = account.info.data_len;
            while (len > 0) {
                const buf = try self.file_reader.getSlice(.from(logger));
                if (buf.len == 0) return error.EndOfStream;
                const n = @min(buf.len, len);
                try self.file_reader.advance(n);
                len -= n;
            }

            const now = timer.read();
            if (now - last_now >= std.time.ns_per_s) {
                const head = self.file_reader.head;
                defer last_now = now;
                defer last_head = head;
                defer num_accounts = 0;

                logger.info().logf("processed {} accounts ({B:.2}) in {D:.1} ({:.2}%)", .{
                    num_accounts,
                    head - last_head,
                    now - last_now,
                    (@as(f64, @floatFromInt(head)) * 100) / @as(f64, @floatFromInt(db_size)),
                });
            }
        }

        // flush any remaining in the batch.
        self.table.flushPuts(&put_batch);
    }

    pub fn loadSnapshot(
        self: *Rooted,
        logger: tel.Logger("Rooted.loadSnapshot"),
        snapshot_reader: anytype, // *lib.solana.SnapshotReader
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.loadSnapshot" });
        defer zone.deinit();

        var last_now: u64 = 0;
        var num_bytes: usize = 0;
        var num_accounts: usize = 0;
        var timer = std.time.Timer.start() catch unreachable;

        var put_batch: Table.PutBatch = .empty;
        while (try snapshot_reader.next()) |account| {
            self.table.put(&put_batch, &account.pubkey, account.slot, .{
                .len = @intCast(account.getDataLength()),
                .offset = @intCast(self.file_writer.tail),
            });

            try self.writeAccount(
                .from(logger),
                &account,
                snapshot_reader,
            );

            num_bytes += @sizeOf(Account) + account.info.data_len;
            num_accounts += 1;

            const now = timer.read();
            if (now - last_now >= std.time.ns_per_s) {
                defer last_now = now;
                defer num_bytes = 0;
                defer num_accounts = 0;
                logger.info().logf("processed {} accounts ({B:.2}) in {D:.1}", .{
                    num_accounts,
                    num_bytes,
                    now - last_now,
                });
            }
        }

        // padding account to align disk size for O_DIRECT
        {
            // If current write buf goes over an Account, zero out the next buf as well.
            const padding_account = Account.initInvalid(@intCast(blk: {
                const buf = try self.file_writer.getSlice(.from(logger));
                break :blk if (buf.len < @sizeOf(Account))
                    (lib.accounts_db.io.page_size + buf.len) - @sizeOf(Account)
                else
                    buf.len - @sizeOf(Account);
            }));

            try self.writeAccount(.from(logger), &padding_account, struct {
                pub fn readSliceAll(_: @This(), buf: []u8) !void {
                    @memset(buf, 0);
                }
            }{});
        }

        // flush all pending puts/writes
        self.table.flushPuts(&put_batch);
        try self.file_writer.sync(.from(logger));
    }

    fn writeAccount(
        self: *Rooted,
        logger: tel.Logger("Rooted.writeAccount"),
        account: *const Account,
        account_data: anytype,
    ) !void {
        // write account
        var acc_bytes: []const u8 = std.mem.asBytes(account);
        while (acc_bytes.len > 0) {
            const buf = try self.file_writer.getSlice(.from(logger));
            const n = @min(buf.len, acc_bytes.len);
            @memcpy(buf[0..n], acc_bytes[0..n]);
            try self.file_writer.advance(n);
            acc_bytes = acc_bytes[n..];
        }

        // write account_data
        var len: usize = account.info.data_len;
        while (len > 0) {
            const buf = try self.file_writer.getSlice(.from(logger));
            const n = @min(buf.len, len);
            try account_data.readSliceAll(buf[0..n]);
            try self.file_writer.advance(n);
            len -= n;
        }
    }
};
