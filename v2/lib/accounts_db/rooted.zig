const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const tel = lib.telemetry;

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;

const Table = @import("table.zig").Table;
const FileWriter = @import("writer.zig").FileWriter;

pub const Rooted = struct {
    table: Table,
    writer: FileWriter,

    const Account = extern struct {
        info: packed struct(u64) {
            valid: bool,
            executable: bool,
            data_len: u24,
            rent_epoch: u38, // can be encoded smaller
        } align(1),
        lamports: u64 align(1),
        slot: u32 align(1), // u32 is enough for *another* 50yrs on mainnet with 400ms slot times
        pubkey: Pubkey align(1),
        owner: Pubkey align(1),
    };

    pub fn init(
        self: *Rooted,
        logger: tel.Logger("Rooted.init"),
        db_dir: std.fs.Dir,
        db_path: []const u8,
        db_memory: []u8,
    ) !void {
        self.table = .init(db_memory);

        try self.writer.init(db_dir, db_path);
        errdefer self.writer.deinit();

        const file_size = (try self.writer.file.stat()).size;
        if (file_size > 0) {
            try self.loadExisting(.from(logger), file_size);
        }
    }

    pub fn deinit(self: *Rooted) void {
        self.writer.deinit();
    }

    fn loadExisting(
        self: *Rooted,
        logger: tel.Logger("Rooted.loadExisting"),
        file_size: u64,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.loadExisting" });
        defer zone.deinit();

        const mapped = try std.posix.mmap(
            null,
            file_size,
            std.posix.PROT.READ,
            .{ .TYPE = .SHARED },
            self.writer.file.handle,
            0,
        );
        defer std.posix.munmap(mapped);
        try std.posix.madvise(
            mapped.ptr,
            mapped.len,
            std.posix.MADV.WILLNEED | std.posix.MADV.SEQUENTIAL,
        );

        var n_read: usize = 0;
        var n_puts: usize = 0;
        var last_now: u64 = 0;
        var timer = try std.time.Timer.start();

        var offset: u64 = 0;
        var acc: Account = undefined;
        while (offset < file_size) {
            const _zone = tracy.Zone.init(@src(), .{ .name = "Rooted.readExistingAccount" });
            defer _zone.deinit();

            // read account header.
            std.debug.assert(file_size - offset >= @sizeOf(Account));
            @memcpy(std.mem.asBytes(&acc), mapped[offset..][0..@sizeOf(Account)]);
            if (acc.info.valid) {
                n_puts += 1;
                self.table.put(&acc.pubkey, acc.slot, .{
                    .offset = @intCast(offset),
                    .len = @sizeOf(Account) + acc.info.data_len,
                });
            }

            // skip Account data
            offset += @sizeOf(Account) + acc.info.data_len;
            n_read += @sizeOf(Account) + acc.info.data_len;

            const now = timer.read();
            if (now - last_now >= std.time.ns_per_s) {
                defer last_now = now;
                defer n_read = 0;
                defer n_puts = 0;
                logger.info().logf(
                    "read:{B:.2} ({} accounts) in {D:.1}",
                    .{ n_read, n_puts, now - last_now },
                );
            }
        }

        // flush queued table puts to the table
        self.table.flushPuts();
    }

    pub fn loadSnapshot(
        self: *Rooted,
        logger: tel.Logger("Rooted.loadSnapshot"),
        snapshot_reader: *lib.solana.snapshot.SnapshotReader,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.loadSnapshot" });
        defer zone.deinit();

        var n_wrote: usize = 0;
        var n_puts: usize = 0;
        var last_now: u64 = 0;
        var timer = try std.time.Timer.start();

        while (try snapshot_reader.next()) |sol_acc| {
            n_puts += 1;
            self.table.put(&sol_acc.pubkey, sol_acc.slot, .{
                .offset = @intCast(self.writer.offset),
                .len = @intCast(@sizeOf(Account) + sol_acc.data.len),
            });

            const acc: Account = .{
                .info = .{
                    .valid = true,
                    .executable = sol_acc.data.executable,
                    .data_len = @intCast(sol_acc.data.len),
                    .rent_epoch = std.math.lossyCast(u38, sol_acc.rent_epoch),
                },
                .slot = @intCast(sol_acc.slot),
                .lamports = sol_acc.lamports,
                .pubkey = sol_acc.pubkey,
                .owner = sol_acc.owner,
            };
            try self.writeAccount(&acc, snapshot_reader);
            n_wrote += @sizeOf(Account) + acc.info.data_len;

            const now = timer.read();
            if (now - last_now >= std.time.ns_per_s) {
                defer last_now = now;
                defer n_wrote = 0;
                defer n_puts = 0;
                logger.info().logf(
                    "wrote:{B:.2} ({} accounts) in {D:.1}",
                    .{ n_wrote, n_puts, now - last_now },
                );
            }
        }

        // flush all table.puts() and writeAccount()s
        self.table.flushPuts();
        try self.flushWrites();
    }

    fn writeAccount(self: *Rooted, acc: *const Account, r: anytype) !void {
        {
            const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.writeAccountHeader" });
            defer zone.deinit();

            var reader = std.Io.Reader.fixed(std.mem.asBytes(acc));
            try self.queueWrite(@sizeOf(Account), &reader);
        }

        {
            const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.writeAccountData" });
            defer zone.deinit();

            try self.queueWrite(acc.info.data_len, r);
        }
    }

    fn queueWrite(self: *Rooted, len: usize, r: anytype) !void {
        var n = len;
        while (n > 0) {
            const buf = try self.writer.writableSlice();
            const take = @min(n, buf.len);
            try r.readSliceAll(buf[0..take]);
            try self.writer.advance(take);
            n -= take;
        }
    }

    fn flushWrites(self: *Rooted) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.flush" });
        defer zone.deinit();

        // align the writer to a page boundary using an invalid account
        const page_boundary = FileWriter.page_size;
        const writable = (try self.writer.writableSlice()).len;
        std.debug.assert(writable <= page_boundary);

        if (writable != page_boundary) {
            var pad_len = writable;
            if (pad_len < @sizeOf(Account)) pad_len += page_boundary; // fill next page

            var pad_acc = std.mem.zeroes(Account);
            pad_acc.info.valid = false;
            pad_acc.info.data_len = @intCast(pad_len - @sizeOf(Account));
            try self.writeAccount(&pad_acc, struct {
                pub fn readSliceAll(_: @This(), buf: []u8) !void {
                    @memset(buf, 0);
                }
            }{});
        }

        // finally, flush all writes to disk
        try self.writer.flush();
    }
};
