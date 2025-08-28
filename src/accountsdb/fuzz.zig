const std = @import("std");
const sig = @import("../sig.zig");
const cli = @import("cli");

const Account = sig.runtime.AccountSharedData;
const ChannelPrintLogger = sig.trace.ChannelPrintLogger;
const Pubkey = sig.core.pubkey.Pubkey;
const Slot = sig.core.time.Slot;

const AccountsDB = sig.accounts_db.AccountsDB;
const FullSnapshotFileInfo = sig.accounts_db.snapshots.FullSnapshotFileInfo;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo;

const N_RANDOM_THREADS = 8;

const TrackedAccountsMap = std.AutoArrayHashMapUnmanaged(Pubkey, TrackedAccount);

pub const TrackedAccount = struct {
    pubkey: Pubkey,
    slot: u64,
    data: [32]u8,

    pub fn initRandom(random: std.Random, slot: Slot) TrackedAccount {
        var data: [32]u8 = undefined;
        random.bytes(&data);
        return .{
            .pubkey = .initRandom(random),
            .slot = slot,
            .data = data,
        };
    }

    pub fn toAccount(self: *const TrackedAccount, allocator: std.mem.Allocator) !Account {
        return .{
            .lamports = 19,
            .data = try allocator.dupe(u8, &self.data),
            .owner = Pubkey.ZEROES,
            .executable = false,
            .rent_epoch = 0,
        };
    }
};

pub const RunCmd = struct {
    max_slots: ?Slot,

    pub const parser = cli.Parser(RunCmd, .{
        .help = .{
            .short = "Fuzz accountsdb.",
            .long = null,
        },
        .sub = .{
            .max_slots = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = null,
                .config = {},
                .help = "The number of slots number which, when surpassed, will exit the fuzzer.",
            },
        },
    });
};

pub fn run(seed: u64, args: *std.process.ArgIterator) !void {
    var prng_state: std.Random.DefaultPrng = .init(seed);
    const random = prng_state.random();

    // NOTE: we don't necessarily want to grow the db indefinitely -- so when we reach
    // the max, we only update existing accounts
    const N_ACCOUNTS_MAX: u64 = 100_000;
    const N_ACCOUNTS_PER_SLOT = 10;

    var gpa_state: std.heap.DebugAllocator(.{
        .safety = true,
    }) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const std_logger: *ChannelPrintLogger = try .init(.{
        .allocator = allocator,
        .max_level = .debug,
        .max_buffer = 1 << 20,
    }, null);
    defer std_logger.deinit();
    const logger = std_logger.logger("accountsdb.fuzz");

    const run_cmd: RunCmd = cmd: {
        var argv_list: std.ArrayListUnmanaged([]const u8) = .empty;
        defer argv_list.deinit(allocator);
        while (args.next()) |arg| try argv_list.append(allocator, arg);

        const stderr = std.io.getStdErr();
        const stderr_tty = std.io.tty.detectConfig(stderr);
        break :cmd try RunCmd.parser.parse(
            allocator,
            "fuzz accountsdb",
            stderr_tty,
            stderr.writer(),
            argv_list.items,
        ) orelse return;
    };

    const maybe_max_slots = run_cmd.max_slots;

    var fuzz_data_dir = try std.fs.cwd().makeOpenPath(sig.FUZZ_DATA_DIR, .{});
    defer fuzz_data_dir.close();

    const main_dir_name = "main";
    var main_accountsdb_dir = try fuzz_data_dir.makeOpenPath(main_dir_name, .{});
    defer main_accountsdb_dir.close();

    const alt_dir_name = "alt";
    var alt_accountsdb_dir = try fuzz_data_dir.makeOpenPath(alt_dir_name, .{});
    defer alt_accountsdb_dir.close();

    defer for ([_][]const u8{ main_dir_name, alt_dir_name }) |dir_name| {
        // NOTE: sometimes this can take a long time so we print when we start and finish
        logger.info().logf("deleting dir: {s}...", .{dir_name});
        defer logger.info().logf("deleted dir: {s}", .{dir_name});
        fuzz_data_dir.deleteTreeMinStackSize(dir_name) catch |err| {
            logger.err().logf(
                "failed to delete accountsdb dir ('{s}'): {}",
                .{ dir_name, err },
            );
        };
    };

    var last_full_snapshot_validated_slot: Slot = 0;
    var last_inc_snapshot_validated_slot: Slot = 0;

    const use_disk = random.boolean();
    logger.info().logf("use disk: {}", .{use_disk});
    var accounts_db: AccountsDB = try .init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .snapshot_dir = main_accountsdb_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = if (use_disk) .disk else .ram,
        .number_of_index_shards = sig.accounts_db.db.ACCOUNT_INDEX_SHARDS,
    });
    defer accounts_db.deinit();

    // prealloc some references to use throught the fuzz
    try accounts_db.account_index.expandRefCapacity(1_000_000);

    var manager_exit: std.atomic.Value(bool) = .init(false);
    const manager_handle: std.Thread = try .spawn(.{}, sig.accounts_db.manager.runLoop, .{
        &accounts_db, sig.accounts_db.manager.ManagerLoopConfig{
            .exit = &manager_exit,
            .slots_per_full_snapshot = 50_000,
            .slots_per_incremental_snapshot = 5_000,
            .zstd_nb_workers = @intCast(std.Thread.getCpuCount() catch 0),
        },
    });
    defer {
        manager_exit.store(true, .release);
        manager_handle.join();
    }

    var tracked_accounts_rw: sig.sync.RwMux(TrackedAccountsMap) = .init(.empty);
    defer {
        const tracked_accounts, var tracked_accounts_lg = tracked_accounts_rw.writeWithLock();
        defer tracked_accounts_lg.unlock();
        tracked_accounts.deinit(allocator);
    }

    {
        const tracked_accounts, var lg = tracked_accounts_rw.writeWithLock();
        defer lg.unlock();
        try tracked_accounts.ensureTotalCapacity(allocator, 10_000);
    }

    var reader_exit: std.atomic.Value(bool) = .init(true);
    var threads: std.BoundedArray(std.Thread, N_RANDOM_THREADS) = .{};
    defer {
        reader_exit.store(true, .seq_cst);
        for (threads.constSlice()) |thread| thread.join();
    }

    // spawn the random reader threads
    for (0..N_RANDOM_THREADS) |thread_i| {
        // NOTE: these threads just access accounts and do not perform
        // any validation (in the .get block of the main fuzzer
        // loop, we perform validation)
        threads.appendAssumeCapacity(try .spawn(.{}, readRandomAccounts, .{
            &accounts_db,
            &tracked_accounts_rw,
            seed + thread_i,
            &reader_exit,
            thread_i,
        }));
        logger.debug().logf("started readRandomAccounts thread: {}", .{thread_i});
    }

    var largest_rooted_slot: Slot = 0;
    var slot: Slot = 0;

    // get/put a bunch of accounts
    while (true) {
        if (maybe_max_slots) |max_slots| if (slot >= max_slots) {
            logger.info().logf("reached max slots: {}", .{max_slots});
            break;
        };
        defer switch (random.int(u2)) {
            0 => slot += random.intRangeAtMost(Slot, 1, 2),
            1, 2, 3 => {},
        };

        const action = random.enumValue(enum { put, get });
        switch (action) {
            .put => {
                const tracked_accounts, var tracked_accounts_lg =
                    tracked_accounts_rw.writeWithLock();
                defer tracked_accounts_lg.unlock();

                var pubkeys_this_slot: std.AutoHashMapUnmanaged(Pubkey, void) = .empty;
                defer pubkeys_this_slot.deinit(allocator);
                for (0..N_ACCOUNTS_PER_SLOT) |_| {
                    var tracked_account = TrackedAccount.initRandom(random, slot);

                    const update_all_existing =
                        tracked_accounts.count() > N_ACCOUNTS_MAX;
                    const overwrite_existing =
                        tracked_accounts.count() > 0 and
                        random.boolean();
                    const pubkey: Pubkey = blk: {
                        if (overwrite_existing or update_all_existing) {
                            const index = random.uintLessThan(usize, tracked_accounts.count());
                            const key = tracked_accounts.keys()[index];
                            // only if the pubkey is not already in this slot
                            if (!pubkeys_this_slot.contains(key)) {
                                tracked_account.pubkey = key;
                            }
                        }
                        break :blk tracked_account.pubkey;
                    };

                    const account_shared_data = try tracked_account.toAccount(allocator);
                    defer account_shared_data.deinit(allocator);
                    try accounts_db.putAccount(slot, pubkey, account_shared_data);

                    // always overwrite the old slot
                    try tracked_accounts.put(allocator, pubkey, tracked_account);
                    try pubkeys_this_slot.put(allocator, pubkey, {});
                }
            },
            .get => {
                const pubkey, const tracked_account = blk: {
                    const tracked_accounts, var tracked_accounts_lg =
                        tracked_accounts_rw.readWithLock();
                    defer tracked_accounts_lg.unlock();

                    const n_keys = tracked_accounts.count();
                    if (n_keys == 0) {
                        continue;
                    }
                    const index = random.intRangeAtMost(usize, 0, tracked_accounts.count() - 1);
                    const key = tracked_accounts.keys()[index];

                    break :blk .{ key, tracked_accounts.get(key).? };
                };
                const account, const ref =
                    try accounts_db.getAccountAndReference(&tracked_account.pubkey);
                defer account.deinit(allocator);

                if (!account.data.eqlSlice(&tracked_account.data)) {
                    std.debug.panic(
                        "found account {} with different data: " ++
                            "tracked: {any} vs found: {any} ({})\n",
                        .{ pubkey, tracked_account.data, account.data, ref },
                    );
                }
            },
        }

        const create_new_root = random.boolean();
        if (create_new_root) {
            largest_rooted_slot = @min(slot, largest_rooted_slot + 2);
            accounts_db.largest_rooted_slot.store(largest_rooted_slot, .monotonic);
        }

        snapshot_validation: {
            // holding the lock here means that the snapshot archive(s) wont be deleted
            // since deletion requires a write lock
            const maybe_latest_snapshot_info, //
            var snapshot_info_lg //
            = accounts_db.latest_snapshot_gen_info.readWithLock();
            defer snapshot_info_lg.unlock();

            const snapshot_info = maybe_latest_snapshot_info.* orelse
                break :snapshot_validation; // no snapshot yet
            const full_snapshot_info = snapshot_info.full;

            // copy the archive to the alternative snapshot dir
            const full_snapshot_file_info: FullSnapshotFileInfo = full: {
                if (full_snapshot_info.slot <= last_full_snapshot_validated_slot) {
                    const inc_snapshot_info = snapshot_info.inc orelse break :snapshot_validation;
                    if (inc_snapshot_info.slot <= last_inc_snapshot_validated_slot) {
                        break :snapshot_validation;
                    }
                } else {
                    last_full_snapshot_validated_slot = full_snapshot_info.slot;
                }

                const full_snapshot_file_info: FullSnapshotFileInfo = .{
                    .slot = full_snapshot_info.slot,
                    .hash = full_snapshot_info.hash,
                };
                const full_archive_name_bounded = full_snapshot_file_info.snapshotArchiveName();
                const full_archive_name = full_archive_name_bounded.constSlice();

                const full_archive_file =
                    try main_accountsdb_dir.openFile(full_archive_name, .{ .mode = .read_only });
                defer full_archive_file.close();

                try sig.accounts_db.snapshots.parallelUnpackZstdTarBall(
                    allocator,
                    .noop,
                    full_archive_file,
                    alt_accountsdb_dir,
                    5,
                    true,
                );
                logger.info().logf(
                    "fuzz[validate]: unpacked full snapshot '{s}'",
                    .{full_archive_name},
                );

                break :full full_snapshot_file_info;
            };

            // maybe copy the archive to the alternative snapshot dir
            const maybe_incremental_file_info: ?IncrementalSnapshotFileInfo = inc: {
                const inc_snapshot_info = snapshot_info.inc orelse break :inc null;

                // already validated
                if (inc_snapshot_info.slot <= last_inc_snapshot_validated_slot) break :inc null;
                last_inc_snapshot_validated_slot = inc_snapshot_info.slot;

                const inc_snapshot_file_info: IncrementalSnapshotFileInfo = .{
                    .base_slot = full_snapshot_info.slot,
                    .hash = inc_snapshot_info.hash,
                    .slot = inc_snapshot_info.slot,
                };
                const inc_archive_name_bounded = inc_snapshot_file_info.snapshotArchiveName();
                const inc_archive_name = inc_archive_name_bounded.constSlice();

                try main_accountsdb_dir.copyFile(
                    inc_archive_name,
                    alt_accountsdb_dir,
                    inc_archive_name,
                    .{},
                );

                const inc_archive_file =
                    try alt_accountsdb_dir.openFile(inc_archive_name, .{});
                defer inc_archive_file.close();

                try sig.accounts_db.snapshots.parallelUnpackZstdTarBall(
                    allocator,
                    .noop,
                    inc_archive_file,
                    alt_accountsdb_dir,
                    5,
                    true,
                );
                logger.info().logf(
                    "fuzz[validate]: unpacked inc snapshot '{s}'",
                    .{inc_archive_name},
                );

                break :inc inc_snapshot_file_info;
            };

            const snapshot_files = sig.accounts_db.SnapshotFiles.fromFileInfos(
                full_snapshot_file_info,
                maybe_incremental_file_info,
            );

            const combined_manifest = try sig.accounts_db.FullAndIncrementalManifest.fromFiles(
                allocator,
                .from(logger),
                alt_accountsdb_dir,
                snapshot_files,
            );
            defer combined_manifest.deinit(allocator);

            const index_type: AccountsDB.InitParams.Index =
                switch (accounts_db.account_index.reference_allocator) {
                    .disk => .disk,
                    .ram => .ram,
                    .parent => @panic("invalid argument"),
                };

            var alt_accounts_db = try AccountsDB.init(.{
                .allocator = allocator,
                .logger = .noop,
                .snapshot_dir = alt_accountsdb_dir,
                .geyser_writer = null,
                .gossip_view = null,
                .index_allocation = index_type,
                .number_of_index_shards = accounts_db.number_of_index_shards,
            });
            defer alt_accounts_db.deinit();

            (try alt_accounts_db.loadWithDefaults(
                allocator,
                combined_manifest,
                1,
                true,
                N_ACCOUNTS_PER_SLOT,
                false,
                false,
            )).deinit(allocator);

            const maybe_inc_slot = if (snapshot_info.inc) |inc| inc.slot else null;
            logger.info().logf(
                "loaded and validated snapshot at slot: {} (and inc snapshot @ slot {any})",
                .{ full_snapshot_info.slot, maybe_inc_slot },
            );
        }
    }

    logger.info().logf("fuzzing complete", .{});
}

fn readRandomAccounts(
    db: *AccountsDB,
    tracked_accounts_rw: *sig.sync.RwMux(TrackedAccountsMap),
    seed: u64,
    exit: *std.atomic.Value(bool),
    thread_id: usize,
) void {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    while (true) {
        if (exit.load(.seq_cst)) {
            std.debug.print("finishing readRandomAccounts thread: {}\n", .{thread_id});
            return;
        }

        var pubkeys: [50]Pubkey = undefined;
        {
            const tracked_accounts, var tracked_accounts_lg = tracked_accounts_rw.readWithLock();
            defer tracked_accounts_lg.unlock();

            const tracked_pubkeys = tracked_accounts.keys();
            if (tracked_pubkeys.len == 0) {
                // wait for some accounts to exist
                std.time.sleep(std.time.ns_per_s);
                continue;
            }

            for (&pubkeys) |*pubkey| pubkey.* = blk: {
                const index = random.intRangeLessThan(usize, 0, tracked_pubkeys.len);
                break :blk tracked_pubkeys[index];
            };
        }

        for (pubkeys) |pubkey| {
            const account = db.getAccountLatest(&pubkey) catch |e|
                std.debug.panic("getAccount failed with error: {}", .{e}) orelse
                continue;
            defer account.deinit(db.allocator);
        }
    }
}
