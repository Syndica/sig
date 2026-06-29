const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");

const tel = lib.telemetry;

const SnapshotIter = lib.solana.snapshot.SnapshotIter;

const Rooted = lib.accounts_db.Rooted;
const AccountPool = lib.accounts_db.AccountPool;
const AccountLookups = lib.accounts_db.AccountLookups;
const RuntimeMetadata = lib.accounts_db.RuntimeMetadata;

comptime {
    _ = start;
}

pub const name = .accounts_db;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.accounts_db.ReadOnly;
pub const ReadWrite = services.accounts_db.ReadWrite;

pub fn serviceMain(runner: lib.runner.Connection, _: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    const file_path = rw.config.file_path[0..rw.config.file_len];
    logger.info().logf("accounts_db started into file: {s}", .{file_path});

    const Global = struct {
        var fba_memory: [32 * 1024 * 1024]u8 = undefined;
        var rooted: Rooted = undefined;
    };

    const rooted = &Global.rooted;
    try rooted.init(
        .from(logger),
        runner,
        std.fs.cwd(),
        file_path,
        rw.config.memory[0..].ptr[0..rw.config.memory_len],
        rw.account_pool,
        rw.snapshot_metadata_out,
    );
    defer rooted.deinit();

    var in = rw.ready_snapshot_in.getView(.reader);
    defer in.close();

    if (rooted.table.count() == 0) {
        logger.info().logf("no existing rooted db. reading from snapshot", .{});

        const ReadySnapshotReader = @TypeOf(in);
        const SnapshotBufReader = struct {
            in_: *ReadySnapshotReader,
            runner_: lib.runner.Connection,

            pub fn getBuffer(self: @This()) []const u8 {
                return self.in_.getBufferBlocking(self.runner_) catch |err| switch (err) {
                    error.Canceled => return &.{}, // cancel -> EOF
                };
            }

            pub fn advance(self: @This(), n: usize) void {
                self.in_.advance(n);
            }
        };

        var fba = std.heap.FixedBufferAllocator.init(&Global.fba_memory);
        var snapshot_iter = try SnapshotIter(SnapshotBufReader).init(&fba, .{
            .in_ = &in,
            .runner_ = runner,
        });

        logger.info().logf("reading snapshot accounts", .{});
        try rooted.loadSnapshot(
            .from(logger),
            runner,
            &snapshot_iter,
            rw.snapshot_metadata_out,
        );
    }

    { // Load feature accounts (TODO: use this to then load leader schedule & stake/vote data)
        const account_reader: struct {
            r: *Rooted,
            l: @TypeOf(logger),

            pub const AccountRef = AccountPool.Index;

            pub fn load(self: @This(), pubkey: *const lib.solana.Pubkey) ?AccountRef {
                errdefer |err| std.debug.panic("AccountReader: {}", .{err});

                if (!(try self.r.queueRead(.from(self.l), pubkey)))
                    return error.RootedQueueFull;
                const result: Rooted.LookupResult = while (true) : (std.atomic.spinLoopHint())
                    break (try self.r.pollRead(.from(self.l))) orelse continue;

                if (result.account_index == AccountPool.invalid_index) return null;
                return result.account_index;
            }

            pub fn free(self: @This(), account: AccountRef) void {
                if (self.r.account_pool.getAccount(account).unref())
                    self.r.account_pool.free(account);
            }

            pub fn getOwner(self: @This(), account: AccountRef) lib.solana.Pubkey {
                return self.r.account_pool.getAccount(account).owner;
            }

            pub fn getData(self: @This(), account: AccountRef) []const u8 {
                return self.r.account_pool.getAccount(account).getData();
            }
        } = .{ .r = rooted, .l = logger };

        logger.info().logf("fetching feature accounts", .{});

        const slot = rooted.journal.committed_slot;
        var feature_set = lib.solana.features.Set.ALL_DISABLED;
        var pending_set =
            try lib.solana.features.computeInactiveFeatureSet(&feature_set, slot, account_reader);

        var it = feature_set.iterator(slot, .active);
        while (it.next()) |feature| logger.info().logf("Feature(active) {}", .{feature});

        it = pending_set.iterator(slot, .active);
        while (it.next()) |feature| logger.info().logf("Feature(pending) {}", .{feature});
    }

    logger.info().logf("accounts_db loaded - servicing replay requests", .{});

    var replay_in = rw.replay_lookups.in.get(.reader);
    var replay_out = rw.replay_lookups.out.get(.writer);
    while (true) : (std.atomic.spinLoopHint()) {
        if (replay_in.peek()) |pubkey| {
            if (try rooted.queueRead(.from(logger), pubkey)) {
                _ = replay_in.next();
                replay_in.markUsed();
            }
        }
        if (replay_out.peek()) |result| {
            if (try rooted.pollRead(.from(logger))) |res| {
                result.* = res;
                _ = replay_out.next();
                replay_out.markUsed();
            }
        }
    }
}
