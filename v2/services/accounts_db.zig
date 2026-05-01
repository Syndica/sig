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
    rooted: lib.accounts_db.Rooted,
    snapshot_fba_buf: [256 * 1024 * 1024]u8,
} = undefined;

pub fn serviceMain(_: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    const db_path = rw.config.file_path[0..rw.config.file_path_len];
    logger.info().logf("accounts_db started on {s}", .{db_path});

    const rooted = &global.rooted;
    try rooted.init(
        .from(logger),
        std.fs.cwd(),
        db_path,
        rw.config.memory[0..].ptr[0..rw.config.memory_len],
    );
    defer rooted.deinit();

    // Handle the snapshot_to_accounts_db, if the rooted db isnt already loaded.
    {
        defer rw.snapshot_to_accounts_db.close(.reader);
        if (rooted.table.count == 0) {
            const TarReaderEffect = struct {
                snapshot_decoder: *lib.snapshot.SnapshotDecodeRing,

                pub fn getSlice(self: @This()) error{EndOfStream}![]u8 {
                    return self.snapshot_decoder.getSlice(.reader) catch return error.EndOfStream;
                }

                pub fn advance(self: @This(), n: usize) void {
                    self.snapshot_decoder.advance(.reader, n);
                }
            };
            var tar_iter = lib.snapshot.tar.TarIterator(TarReaderEffect).init(.{
                .snapshot_decoder = rw.snapshot_to_accounts_db,
            });

            var fba = std.heap.FixedBufferAllocator.init(&global.snapshot_fba_buf);
            var snapshot_reader = try lib.solana.SnapshotReader(@TypeOf(tar_iter)).read(
                &fba,
                .from(logger),
                &tar_iter,
            );

            // TODO: publish manifest stuff here.
            try rooted.loadSnapshot(.from(logger), &snapshot_reader);
        }
    }

    logger.info().logf("accounts_db finished", .{});
    while (true) std.atomic.spinLoopHint();
}
