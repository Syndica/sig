//! includes the main database struct `AccountsDB`

const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const zstd = @import("zstd");
const bincode = sig.bincode;
const sysvars = sig.accounts_db.sysvars;
const snapgen = sig.accounts_db.snapshots.generate;

const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Blake3 = std.crypto.hash.Blake3;

const Account = sig.core.Account;
const Hash = sig.core.hash.Hash;
const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;

const AccountsDbFields = sig.accounts_db.snapshots.AccountsDbFields;
const AccountFileInfo = sig.accounts_db.snapshots.AccountFileInfo;
const AccountFile = sig.accounts_db.accounts_file.AccountFile;
const FileId = sig.accounts_db.accounts_file.FileId;
const AccountInFile = sig.accounts_db.accounts_file.AccountInFile;
const SnapshotFields = sig.accounts_db.snapshots.SnapshotFields;
const BankIncrementalSnapshotPersistence = sig.accounts_db.snapshots.BankIncrementalSnapshotPersistence;
const AllSnapshotFields = sig.accounts_db.snapshots.AllSnapshotFields;
const SnapshotFiles = sig.accounts_db.snapshots.SnapshotFiles;
const AccountIndex = sig.accounts_db.index.AccountIndex;
const AccountRef = sig.accounts_db.index.AccountRef;
const RwMux = sig.sync.RwMux;
const Logger = sig.trace.log.Logger;
const StandardErrLogger = sig.trace.log.ChannelPrintLogger;
const Level = sig.trace.level.Level;
const NestedHashTree = sig.common.merkle_tree.NestedHashTree;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const Counter = sig.prometheus.counter.Counter;
const Gauge = sig.prometheus.Gauge;
const Histogram = sig.prometheus.histogram.Histogram;
const StatusCache = sig.accounts_db.StatusCache;
const BankFields = sig.accounts_db.snapshots.BankFields;
const BankHashStats = sig.accounts_db.snapshots.BankHashStats;
const AccountsCache = sig.accounts_db.cache.AccountsCache;
const PubkeyShardCalculator = sig.accounts_db.index.PubkeyShardCalculator;
const ShardedPubkeyRefMap = sig.accounts_db.index.ShardedPubkeyRefMap;
const GeyserWriter = sig.geyser.GeyserWriter;

const parallelUnpackZstdTarBall = sig.accounts_db.snapshots.parallelUnpackZstdTarBall;
const spawnThreadTasks = sig.utils.thread.spawnThreadTasks;
const printTimeEstimate = sig.time.estimate.printTimeEstimate;
const globalRegistry = sig.prometheus.registry.globalRegistry;

pub const DB_LOG_RATE = sig.time.Duration.fromSecs(5);
pub const DB_MANAGER_LOOP_MIN = sig.time.Duration.fromSecs(5);

pub const MERKLE_FANOUT: usize = 16;
pub const ACCOUNT_INDEX_SHARDS: usize = 8192;
pub const ACCOUNT_FILE_SHRINK_THRESHOLD = 70; // shrink account files with more than X% dead bytes
pub const DELETE_ACCOUNT_FILES_MIN = 100;

/// database for accounts
///
/// Analogous to [AccountsDb](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L1363)
pub const AccountsDB = struct {
    allocator: std.mem.Allocator,

    /// maps pubkeys to account locations
    account_index: AccountIndex,

    /// per-slot map containing a list of pubkeys and accounts.
    /// This is tracked per-slot for purge/flush
    unrooted_accounts: RwMux(SlotPubkeyAccounts),

    // pubkey->account LRU maps
    accounts_cache: RwMux(AccountsCache),

    /// NOTE: see accountsdb/readme.md for more details on how these are used
    file_map: RwMux(FileMap) = RwMux(FileMap).init(.{}),
    /// `file_map_fd_rw` is used to ensure files in the file_map are not closed while its held as a read-lock.
    /// NOTE: see accountsdb/readme.md for more details on how these are used
    file_map_fd_rw: std.Thread.RwLock = .{},

    geyser_writer: ?*GeyserWriter,

    /// Tracks how many accounts (which we have stored) are dead for a specific slot.
    /// Used during clean to queue an AccountFile for shrink if it contains
    /// a large percentage of dead accounts, or deletion if the file contains only
    /// dead accounts.
    ///
    /// When a given counter reaches 0, it is to be removed (ie, if a slot does not exist
    /// in this map, then its safe to assume it has 0 dead accounts).
    /// When a counter is first added, it must be initialized to 0.
    dead_accounts_counter: RwMux(DeadAccountsCounter),

    /// Used for filenames when flushing accounts to disk.
    // TODO: do we need this? since flushed slots will be unique
    largest_file_id: FileId = FileId.fromInt(0),

    // TODO: integrate these values into consensus
    /// Used for flushing/cleaning/purging/shrinking.
    largest_rooted_slot: std.atomic.Value(Slot) = std.atomic.Value(Slot).init(0),
    /// Represents the largest slot for which all account data has been flushed to disk.
    /// Always `<= largest_rooted_slot`.
    largest_flushed_slot: std.atomic.Value(Slot) = std.atomic.Value(Slot).init(0),
    /// Represents the largest slot info used to generate a full snapshot, and optionally an incremental snapshot relative to it, which currently exists.
    latest_snapshot_info: RwMux(?SnapshotGenerationInfo) = RwMux(?SnapshotGenerationInfo).init(null),
    /// The snapshot info from which this instance was loaded from and validated against (null if that didn't happen).
    /// Used to potentially skip the first `computeAccountHashesAndLamports`.
    first_snapshot_load_info: RwMux(?SnapshotGenerationInfo) = RwMux(?SnapshotGenerationInfo).init(null),

    /// Not closed by the `AccountsDB`, but must live at least as long as it.
    snapshot_dir: std.fs.Dir,

    // TODO: populate this during snapshot load
    // TODO: move to Bank struct
    bank_hash_stats: RwMux(BankHashStatsMap) = RwMux(BankHashStatsMap).init(.{}),

    metrics: AccountsDBMetrics,
    logger: Logger,
    config: InitConfig,

    const Self = @This();

    pub const PubkeysAndAccounts = struct { []const Pubkey, []const Account };
    pub const SlotPubkeyAccounts = std.AutoHashMap(Slot, PubkeysAndAccounts);
    pub const DeadAccountsCounter = std.AutoArrayHashMap(Slot, u64);
    pub const BankHashStatsMap = std.AutoArrayHashMapUnmanaged(Slot, BankHashStats);
    pub const FileMap = std.AutoArrayHashMapUnmanaged(FileId, AccountFile);

    pub const InitConfig = struct {
        number_of_index_shards: usize,
        use_disk_index: bool,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        logger: Logger,
        snapshot_dir: std.fs.Dir,
        config: InitConfig,
        geyser_writer: ?*GeyserWriter,
    ) !Self {
        // init index
        const index_config: AccountIndex.AllocatorConfig = if (config.use_disk_index)
            .{ .Disk = .{ .accountsdb_dir = snapshot_dir } }
        else
            .{ .Ram = .{ .allocator = allocator } };
        var account_index = try AccountIndex.init(
            allocator,
            logger,
            index_config,
            config.number_of_index_shards,
            0,
        );
        errdefer account_index.deinit(true);

        // init cache
        var accounts_cache = try AccountsCache.init(allocator, 1_000); // TODO: make configurable
        errdefer accounts_cache.deinit();

        const metrics = try AccountsDBMetrics.init();

        // NOTE: we need the accounts directory to exist to create new account files correctly
        snapshot_dir.makePath("accounts") catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => |e| return e,
        };

        return .{
            .allocator = allocator,
            .account_index = account_index,
            .logger = logger,
            .config = config,
            .unrooted_accounts = RwMux(SlotPubkeyAccounts).init(SlotPubkeyAccounts.init(allocator)),
            .accounts_cache = RwMux(AccountsCache).init(accounts_cache),
            .snapshot_dir = snapshot_dir,
            .dead_accounts_counter = RwMux(DeadAccountsCounter).init(DeadAccountsCounter.init(allocator)),
            .metrics = metrics,
            .geyser_writer = geyser_writer,
        };
    }

    pub fn deinit(self: *Self) void {
        self.account_index.deinit(true);

        {
            const accounts_cache, var accounts_cache_lg = self.accounts_cache.writeWithLock();
            defer accounts_cache_lg.unlock();
            accounts_cache.deinit();
        }

        {
            const unrooted_accounts, var unrooted_accounts_lg = self.unrooted_accounts.writeWithLock();
            defer unrooted_accounts_lg.unlock();
            var iter = unrooted_accounts.valueIterator();
            while (iter.next()) |pubkeys_and_accounts| {
                const pubkeys, const accounts = pubkeys_and_accounts.*;
                for (accounts) |account| account.deinit(self.allocator);
                self.allocator.free(pubkeys);
                self.allocator.free(accounts);
            }
            unrooted_accounts.deinit();
        }
        {
            const file_map, var file_map_lg = self.file_map.writeWithLock();
            defer file_map_lg.unlock();
            file_map.deinit(self.allocator);
        }
        {
            const dead_accounts_counter, var dead_accounts_counter_lg = self.dead_accounts_counter.writeWithLock();
            defer dead_accounts_counter_lg.unlock();
            dead_accounts_counter.deinit();
        }

        {
            const bank_hash_stats, var bank_hash_stats_lg = self.bank_hash_stats.writeWithLock();
            defer bank_hash_stats_lg.unlock();
            bank_hash_stats.deinit(self.allocator);
        }
    }

    /// easier to use load function
    pub fn loadWithDefaults(
        self: *Self,
        /// needs to be a thread-safe allocator
        allocator: std.mem.Allocator,
        snapshot_fields_and_paths: *AllSnapshotFields,
        n_threads: u32,
        validate: bool,
        accounts_per_file_estimate: u64,
    ) !SnapshotFields {
        const snapshot_fields = try snapshot_fields_and_paths.collapse();

        const load_duration = try self.loadFromSnapshot(
            snapshot_fields.accounts_db_fields,
            n_threads,
            allocator,
            accounts_per_file_estimate,
        );
        self.logger.info().logf("loaded from snapshot in {s}", .{load_duration});

        if (validate) {
            const full_snapshot = snapshot_fields_and_paths.full;
            var validate_timer = try sig.time.Timer.start();
            try self.validateLoadFromSnapshot(.{
                .full_slot = full_snapshot.bank_fields.slot,
                .expected_full = .{
                    .accounts_hash = snapshot_fields.accounts_db_fields.bank_hash_info.accounts_hash,
                    .capitalization = full_snapshot.bank_fields.capitalization,
                },
                .expected_incremental = if (snapshot_fields.bank_fields_inc.snapshot_persistence) |inc_persistence| .{
                    .accounts_hash = inc_persistence.incremental_hash,
                    .capitalization = inc_persistence.incremental_capitalization,
                } else null,
            });
            self.logger.info().logf("validated from snapshot in {s}", .{validate_timer.read()});
        }

        return snapshot_fields;
    }

    /// loads the account files and gernates the account index from a snapshot
    pub fn loadFromSnapshot(
        self: *Self,
        /// Account file info map from the snapshot manifest.
        snapshot_manifest: AccountsDbFields,
        n_threads: u32,
        /// needs to be a thread-safe allocator
        per_thread_allocator: std.mem.Allocator,
        accounts_per_file_estimate: u64,
    ) !sig.time.Duration {
        self.logger.info().log("loading from snapshot...");

        // used to read account files
        const n_parse_threads = n_threads;
        // used to merge thread results
        const n_combine_threads = n_threads;

        var accounts_dir = try self.snapshot_dir.openDir("accounts", .{});
        defer accounts_dir.close();

        const n_account_files = snapshot_manifest.file_map.count();
        self.logger.info().logf("found {d} account files", .{n_account_files});
        std.debug.assert(n_account_files > 0);

        {
            const bhs, var bhs_lg = try self.getOrInitBankHashStats(snapshot_manifest.slot);
            defer bhs_lg.unlock();
            bhs.accumulate(snapshot_manifest.bank_hash_info.stats);
        }

        var timer = try sig.time.Timer.start();
        // short path
        if (n_threads == 1) {
            try self.loadAndVerifyAccountsFiles(
                accounts_dir,
                accounts_per_file_estimate,
                snapshot_manifest.file_map,
                0,
                n_account_files,
                true,
            );

            // if geyser, send end of data signal
            if (self.geyser_writer) |geyser_writer| {
                const end_of_snapshot: sig.geyser.core.VersionedAccountPayload = .EndOfSnapshotLoading;
                try geyser_writer.writePayloadToPipe(end_of_snapshot);
            }

            return timer.read();
        }

        // setup the parallel indexing
        const use_disk_index = self.config.use_disk_index;
        var loading_threads = try ArrayList(AccountsDB).initCapacity(
            self.allocator,
            n_parse_threads,
        );
        for (0..n_parse_threads) |_| {
            var thread_db = loading_threads.addOneAssumeCapacity();
            thread_db.* = try AccountsDB.init(
                per_thread_allocator,
                .noop, // dont spam the logs with init information (we set it after)
                self.snapshot_dir,
                self.config,
                self.geyser_writer,
            );
            thread_db.logger = self.logger;

            // set the disk allocator after init() doesnt create a new one
            if (use_disk_index) {
                thread_db.account_index.reference_allocator = self.account_index.reference_allocator;
            }
        }
        defer {
            // at this defer point, there are three memory components we care about
            // 1) the account references (AccountRef)
            // 2) the hashmap of refs (Map(Pubkey, *AccountRef))
            // and 3) the file maps Map(FileId, AccountFile)
            // each loading thread will have its own copy of these
            // what happens:
            // 2) and 3) will be copied into the main index thread and so we can deinit them
            // 1) will continue to exist on the heap and its ownership is given
            // the the main accounts-db index
            for (loading_threads.items) |*loading_thread| {
                // NOTE: deinit hashmap, dont close the files
                const file_map, var file_map_lg = loading_thread.file_map.writeWithLock();
                defer file_map_lg.unlock();
                file_map.deinit(per_thread_allocator);

                // NOTE: important `false` (ie, 1)
                loading_thread.account_index.reference_allocator = .{ .ram = per_thread_allocator }; // dont destory the **disk** allocator (since its shared)
                loading_thread.account_index.deinit(false);

                const accounts_cache, var accounts_cache_lg = loading_thread.accounts_cache.writeWithLock();
                defer accounts_cache_lg.unlock();
                accounts_cache.deinit();
            }
            loading_threads.deinit();
        }

        self.logger.info().logf("[{d} threads]: reading and indexing accounts...", .{n_parse_threads});
        {
            var wg: std.Thread.WaitGroup = .{};
            defer wg.wait();
            try spawnThreadTasks(loadAndVerifyAccountsFilesMultiThread, .{
                .wg = &wg,
                .data_len = n_account_files,
                .max_threads = n_parse_threads,
                .params = .{
                    loading_threads.items,
                    accounts_dir,
                    snapshot_manifest.file_map,
                    accounts_per_file_estimate,
                },
            });
        }

        // if geyser, send end of data signal
        if (self.geyser_writer) |geyser_writer| {
            const end_of_snapshot: sig.geyser.core.VersionedAccountPayload = .EndOfSnapshotLoading;
            try geyser_writer.writePayloadToPipe(end_of_snapshot);
        }

        self.logger.info().logf("[{d} threads]: combining thread accounts...", .{n_combine_threads});
        var merge_timer = try sig.time.Timer.start();
        try self.mergeMultipleDBs(loading_threads.items, n_combine_threads);
        self.logger.debug().logf("combining thread indexes took: {s}", .{merge_timer.read()});

        return timer.read();
    }

    /// multithread entrypoint into loadAndVerifyAccountsFiles.
    pub fn loadAndVerifyAccountsFilesMultiThread(
        loading_threads: []AccountsDB,
        accounts_dir: std.fs.Dir,
        file_info_map: AccountsDbFields.FileMap,
        accounts_per_file_estimate: u64,
        task: sig.utils.thread.TaskParams,
    ) !void {
        const thread_db = &loading_threads[task.thread_id];
        try thread_db.loadAndVerifyAccountsFiles(
            accounts_dir,
            accounts_per_file_estimate,
            file_info_map,
            task.start_index,
            task.end_index,
            task.thread_id == 0,
        );
    }

    /// loads and verifies the account files into the threads file map
    /// and stores the accounts into the threads index
    pub fn loadAndVerifyAccountsFiles(
        self: *Self,
        accounts_dir: std.fs.Dir,
        accounts_per_file_est: usize,
        file_info_map: AccountsDbFields.FileMap,
        file_map_start_index: usize,
        file_map_end_index: usize,
        // when we multithread this function we only want to print on the first thread
        print_progress: bool,
    ) !void {
        // NOTE: we can hold this lock for the entire function
        // because nothing else should be access the filemap
        // while loading from a snapshot
        const file_map, var file_map_lg = self.file_map.writeWithLock();
        defer file_map_lg.unlock();

        const n_account_files = file_map_end_index - file_map_start_index;
        try file_map.ensureTotalCapacity(self.allocator, n_account_files);

        const n_shards = self.account_index.pubkey_ref_map.numberOfShards();
        const shard_counts = try self.allocator.alloc(usize, n_shards);
        defer self.allocator.free(shard_counts);
        @memset(shard_counts, 0);

        // allocate all the references in one shot with a wrapper allocator
        // without this large allocation, snapshot loading is very slow
        const n_accounts_estimate = n_account_files * accounts_per_file_est;
        var references = try ArrayList(AccountRef).initCapacity(
            self.account_index.reference_allocator.get(),
            n_accounts_estimate,
        );

        const references_ptr = references.items.ptr;

        const counting_alloc = try FreeCounterAllocator.init(self.allocator, references);
        defer counting_alloc.deinitIfSafe();

        var timer = try sig.time.Timer.start();
        var progress_timer = try sig.time.Timer.start();

        if (n_account_files > std.math.maxInt(AccountIndex.SlotRefMap.Size)) {
            return error.FileMapTooBig;
        }
        // its ok to hold this lock for the entire function because nothing else
        // should be accessing the account index while loading from a snapshot
        const slot_reference_map, var slot_reference_map_lg = self.account_index.slot_reference_map.writeWithLock();
        defer slot_reference_map_lg.unlock();
        try slot_reference_map.ensureTotalCapacity(@intCast(n_account_files));

        // init storage which holds temporary account data per slot
        // which is eventually written to geyser
        var geyser_slot_storage: ?*GeyserTmpStorage = null;
        const geyser_is_enabled = self.geyser_writer != null;
        if (geyser_is_enabled) {
            geyser_slot_storage = try self.allocator.create(GeyserTmpStorage);
            geyser_slot_storage.?.* = try GeyserTmpStorage.init(self.allocator, n_accounts_estimate);
        }
        defer {
            if (geyser_slot_storage) |storage| {
                storage.deinit();
                self.allocator.destroy(storage);
            }
        }

        var total_n_accounts: u64 = 0;
        for (
            file_info_map.keys()[file_map_start_index..file_map_end_index],
            file_info_map.values()[file_map_start_index..file_map_end_index],
            1..,
        ) |slot, file_info, file_count| {
            // read accounts file
            var accounts_file = blk: {
                const file_name_bounded = sig.utils.fmt.boundedFmt("{d}.{d}", .{ slot, file_info.id.toInt() });

                const accounts_file_file = accounts_dir.openFile(file_name_bounded.constSlice(), .{ .mode = .read_write }) catch |err| {
                    self.logger.err().logf("Failed to open accounts/{s}: {s}", .{ file_name_bounded.constSlice(), @errorName(err) });
                    return err;
                };
                errdefer accounts_file_file.close();

                break :blk AccountFile.init(accounts_file_file, file_info, slot) catch |err| {
                    self.logger.err().logf("failed to *open* AccountsFile {s}: {s}\n", .{ file_name_bounded.constSlice(), @errorName(err) });
                    return err;
                };
            };
            errdefer accounts_file.deinit();

            indexAndValidateAccountFile(
                &accounts_file,
                self.account_index.pubkey_ref_map.shard_calculator,
                shard_counts,
                &references,
                geyser_slot_storage,
            ) catch |err| {
                self.logger.err().logf("failed to *validate/index* AccountsFile: {d}.{d}: {s}\n", .{
                    accounts_file.slot,
                    accounts_file.id.toInt(),
                    @errorName(err),
                });
                return err;
            };

            // NOTE: rn we dont support resizing because it invalidates pointers
            // - something went wrong if we resized
            if (references.items.ptr != references_ptr) {
                std.debug.panic("accounts-per-file-estimate too small ({d}), increase (using flag '-a') and try again...", .{accounts_per_file_est});
            }

            if (geyser_is_enabled) {
                var geyser_storage = geyser_slot_storage.?; // SAFE: will always be set if geyser_is_enabled
                const geyser_writer = self.geyser_writer.?; // SAFE: will always be set if geyser_is_enabled

                // ! reset memory for the next slot
                defer geyser_storage.reset();

                const data_versioned = sig.geyser.core.VersionedAccountPayload{
                    .AccountPayloadV1 = .{
                        .accounts = geyser_storage.accounts.items,
                        .pubkeys = geyser_storage.pubkeys.items,
                        .slot = slot,
                    },
                };
                try geyser_writer.writePayloadToPipe(data_versioned);
            }

            if (accounts_file.number_of_accounts > 0) {
                // the last `number_of_accounts` is associated with this file
                const start_index = references.items.len - accounts_file.number_of_accounts;
                const end_index = references.items.len;
                const ref_slice = references.items[start_index..end_index];
                const ref_list = ArrayList(AccountRef).fromOwnedSlice(
                    // deinit allocator uses the counting allocator
                    counting_alloc.allocator(),
                    ref_slice,
                );
                counting_alloc.count += 1;
                slot_reference_map.putAssumeCapacityNoClobber(slot, ref_list);
            }
            total_n_accounts += accounts_file.number_of_accounts;

            const file_id = file_info.id;

            file_map.putAssumeCapacityNoClobber(file_id, accounts_file);
            self.largest_file_id = FileId.max(self.largest_file_id, file_id);
            _ = self.largest_rooted_slot.fetchMax(slot, .release);
            self.largest_flushed_slot.store(self.largest_rooted_slot.load(.acquire), .release);

            if (print_progress and progress_timer.read().asNanos() > DB_LOG_RATE.asNanos()) {
                printTimeEstimate(
                    self.logger,
                    &timer,
                    n_account_files,
                    file_count,
                    "loading account files",
                    "thread0",
                );
                progress_timer.reset();
            }
        }

        // NOTE: this is good for debugging what to set `accounts_per_file_est` to
        if (print_progress) {
            self.logger.info().logf("accounts_per_file: actual vs estimated: {d} vs {d}", .{
                total_n_accounts / n_account_files,
                accounts_per_file_est,
            });
        }

        // allocate enough memory
        try self.account_index.pubkey_ref_map.ensureTotalCapacity(shard_counts);

        // PERF: can probs be faster if you sort the pubkeys first, and then you know
        // it will always be a search for a free spot, and not search for a match
        timer.reset();
        var ref_count: usize = 0;
        var slot_iter = slot_reference_map.keyIterator();
        while (slot_iter.next()) |slot| {
            const refs = slot_reference_map.get(slot.*).?;
            for (refs.items) |*ref| {
                _ = self.account_index.indexRefIfNotDuplicateSlotAssumeCapacity(ref);
                ref_count += 1;
            }

            if (print_progress and progress_timer.read().asNanos() > DB_LOG_RATE.asNanos()) {
                printTimeEstimate(
                    self.logger,
                    &timer,
                    total_n_accounts,
                    ref_count,
                    "building index",
                    "thread0",
                );
                progress_timer.reset();
            }
        }
    }

    /// merges multiple thread accounts-dbs into self.
    /// index merging happens in parallel using `n_threads`.
    pub fn mergeMultipleDBs(
        self: *Self,
        thread_dbs: []AccountsDB,
        n_threads: usize,
    ) !void {
        var combine_indexes_wg: std.Thread.WaitGroup = .{};
        defer combine_indexes_wg.wait();
        try spawnThreadTasks(combineThreadIndexesMultiThread, .{
            .wg = &combine_indexes_wg,
            .data_len = self.account_index.pubkey_ref_map.numberOfShards(),
            .max_threads = n_threads,
            .params = .{
                self.logger,
                &self.account_index,
                thread_dbs,
            },
        });

        // ensure enough capacity
        var ref_mem_capacity: u32 = 0;
        for (thread_dbs) |*thread_db| {
            const thread_ref_memory, var thread_ref_memory_lg = thread_db.account_index.slot_reference_map.readWithLock();
            defer thread_ref_memory_lg.unlock();
            ref_mem_capacity += thread_ref_memory.count();
        }

        // NOTE: its ok to hold this lock while we merge because
        // nothing else should be accessing the account index while loading from a snapshot
        const slot_reference_map, var slot_reference_map_lg = self.account_index.slot_reference_map.writeWithLock();
        defer slot_reference_map_lg.unlock();
        try slot_reference_map.ensureTotalCapacity(ref_mem_capacity);

        // NOTE: nothing else should try to access the file_map
        // while we are merging so this long hold is ok.
        const file_map, var file_map_lg = self.file_map.writeWithLock();
        defer file_map_lg.unlock();

        for (thread_dbs) |*thread_db| {
            // combine file maps
            {
                thread_db.file_map_fd_rw.lockShared();
                defer thread_db.file_map_fd_rw.unlockShared();

                const thread_file_map, var thread_file_map_lg = thread_db.file_map.readWithLock();
                defer thread_file_map_lg.unlock();

                try file_map.ensureUnusedCapacity(self.allocator, thread_file_map.count());
                for (
                    thread_file_map.keys(),
                    thread_file_map.values(),
                ) |file_id, account_file| {
                    file_map.putAssumeCapacityNoClobber(file_id, account_file);
                }
            }
            self.largest_file_id = FileId.max(self.largest_file_id, thread_db.largest_file_id);
            _ = self.largest_rooted_slot.fetchMax(thread_db.largest_rooted_slot.load(.acquire), .monotonic);
            self.largest_flushed_slot.store(self.largest_rooted_slot.load(.monotonic), .monotonic);

            // combine underlying memory
            const thread_slot_reference_map, var thread_slot_reference_map_lg = thread_db.account_index.slot_reference_map.readWithLock();
            defer thread_slot_reference_map_lg.unlock();

            var thread_ref_iter = thread_slot_reference_map.iterator();
            while (thread_ref_iter.next()) |thread_entry| {
                slot_reference_map.putAssumeCapacityNoClobber(
                    thread_entry.key_ptr.*,
                    thread_entry.value_ptr.*,
                );
            }
        }
    }

    /// combines multiple thread indexes into the given index.
    /// each bin is also sorted by pubkey.
    pub fn combineThreadIndexesMultiThread(
        logger: Logger,
        index: *AccountIndex,
        thread_dbs: []const AccountsDB,
        task: sig.utils.thread.TaskParams,
    ) !void {
        const shard_start_index = task.start_index;
        const shard_end_index = task.end_index;

        const total_shards = shard_end_index - shard_start_index;
        var timer = try sig.time.Timer.start();
        var progress_timer = try std.time.Timer.start();
        const print_progress = task.thread_id == 0;

        for (shard_start_index..shard_end_index, 1..) |shard_index, iteration_count| {
            // sum size across threads
            var shard_n_accounts: usize = 0;
            for (thread_dbs) |*thread_db| {
                shard_n_accounts += thread_db.account_index.pubkey_ref_map.getShardCount(shard_index);
            }

            // prealloc
            if (shard_n_accounts > 0) {
                const shard_map, var lock = index.pubkey_ref_map.getShardFromIndex(shard_index).writeWithLock();
                defer lock.unlock();
                try shard_map.ensureTotalCapacity(shard_n_accounts);
            }

            for (thread_dbs) |*thread_db| {
                const shard_map, var lock = thread_db.account_index.pubkey_ref_map.getShardFromIndex(shard_index).readWithLock();
                defer lock.unlock();

                // insert all of the thread entries into the main index
                var iter = shard_map.iterator();
                while (iter.next()) |thread_entry| {
                    const thread_head_ref = thread_entry.value_ptr.*;

                    // NOTE: we dont have to check for duplicates because the duplicate
                    // slots have already been handled in the prev step
                    index.indexRefAssumeCapacity(thread_head_ref.ref_ptr);
                }
            }

            if (print_progress and progress_timer.read() > DB_LOG_RATE.asNanos()) {
                printTimeEstimate(
                    logger,
                    &timer,
                    total_shards,
                    iteration_count,
                    "combining thread indexes",
                    "thread0",
                );
                progress_timer.reset();
            }
        }
    }

    pub const AccountHashesConfig = union(enum) {
        /// compute hash from `(min_slot?, max_slot]`
        FullAccountHash: struct {
            min_slot: ?Slot = null,
            max_slot: Slot,
        },
        /// compute hash from `(min_slot, max_slot?]`
        IncrementalAccountHash: struct {
            min_slot: Slot,
            max_slot: ?Slot = null,
        },
    };

    pub const ComputeAccountHashesAndLamportsError =
        std.mem.Allocator.Error ||
        std.time.Timer.Error ||
        std.Thread.CpuCountError ||
        std.Thread.SpawnError ||
        error{DivisionByZero} ||
        error{EmptyHashList};

    /// Computes a hash across all accounts in the db, and total lamports of those accounts
    /// using index data. depending on the config, this can compute either full or incremental
    /// snapshot values.
    /// Returns `.{ accounts_hash, total_lamports }`.
    /// NOTE: acquires a shared/read lock on `file_map_fd_rw` and `file_map` - those fields
    /// must not be under exclusive/write locks before calling this function on the same
    /// thread, or else this will dead lock.
    pub fn computeAccountHashesAndLamports(
        self: *Self,
        config: AccountHashesConfig,
    ) !struct { Hash, u64 } {
        var timer = try std.time.Timer.start();
        // TODO: make cli arg
        const n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;
        // const n_threads = 1;

        // alloc the result
        const hashes = try self.allocator.alloc(ArrayListUnmanaged(Hash), n_threads);
        defer {
            for (hashes) |*h| h.deinit(self.allocator);
            self.allocator.free(hashes);
        }
        @memset(hashes, .{});

        const lamports = try self.allocator.alloc(u64, n_threads);
        defer self.allocator.free(lamports);
        @memset(lamports, 0);

        // split processing the bins over muliple threads
        self.logger.info().logf("collecting hashes from accounts...", .{});
        if (n_threads == 1) {
            try getHashesFromIndex(
                self,
                config,
                self.account_index.pubkey_ref_map.shards,
                self.allocator,
                &hashes[0],
                &lamports[0],
                true,
            );
        } else {
            var wg: std.Thread.WaitGroup = .{};
            defer wg.wait();
            try spawnThreadTasks(getHashesFromIndexMultiThread, .{
                .wg = &wg,
                .data_len = self.account_index.pubkey_ref_map.numberOfShards(),
                .max_threads = n_threads,
                .params = .{
                    self,
                    config,
                    self.allocator,
                    hashes,
                    lamports,
                },
            });
        }

        self.logger.debug().logf("took: {s}", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        self.logger.info().logf("computing the merkle root over accounts...", .{});
        var hash_tree = NestedHashTree{ .hashes = hashes };
        const accounts_hash = try hash_tree.computeMerkleRoot(MERKLE_FANOUT);
        self.logger.debug().logf("took {s}", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        var total_lamports: u64 = 0;
        for (lamports) |lamport| {
            total_lamports += lamport;
        }

        return .{
            accounts_hash.*,
            total_lamports,
        };
    }

    pub const ValidateLoadFromSnapshotParams = struct {
        /// used to verify the full snapshot.
        full_slot: Slot,
        /// The expected full snapshot values to verify against.
        expected_full: ExpectedSnapInfo,
        /// The optionally expected incremental snapshot values to verify against.
        expected_incremental: ?ExpectedSnapInfo,

        pub const ExpectedSnapInfo = struct {
            accounts_hash: Hash,
            capitalization: u64,
        };
    };

    pub const ValidateLoadFromSnapshotError = error{
        IncorrectAccountsHash,
        IncorrectTotalLamports,
        IncorrectIncrementalLamports,
        IncorrectAccountsDeltaHash,
    };

    /// Validates accountsdb against some snapshot info - if used, it must
    /// be after loading the snapshot(s) whose information is supplied.
    pub fn validateLoadFromSnapshot(
        self: *Self,
        params: ValidateLoadFromSnapshotParams,
    ) !void {
        const p_maybe_first: *?SnapshotGenerationInfo, var first_lg = self.first_snapshot_load_info.writeWithLock();
        defer first_lg.unlock();

        if (p_maybe_first.*) |first| {
            std.debug.assert(first.full.slot == params.full_slot); // already validated against a different set of snapshot info
        }

        // validate the full snapshot
        self.logger.info().logf("validating the full snapshot", .{});
        const accounts_hash, const total_lamports = try self.computeAccountHashesAndLamports(.{
            .FullAccountHash = .{
                .max_slot = params.full_slot,
            },
        });

        if (params.expected_full.accounts_hash.order(&accounts_hash) != .eq) {
            self.logger.err().logf(
                \\ incorrect accounts hash
                \\ expected vs calculated: {d} vs {d}
            , .{ params.expected_full.accounts_hash, accounts_hash });
            return error.IncorrectAccountsHash;
        }

        if (params.expected_full.capitalization != total_lamports) {
            self.logger.err().logf(
                \\ incorrect total lamports
                \\ expected vs calculated: {d} vs {d}
            , .{ params.expected_full.capitalization, total_lamports });
            return error.IncorrectTotalLamports;
        }

        p_maybe_first.* = .{
            .full = .{
                .slot = params.full_slot,
                .hash = accounts_hash,
                .capitalization = total_lamports,
            },
            .inc = null,
        };
        const p_maybe_first_inc = &p_maybe_first.*.?.inc;

        // validate the incremental snapshot
        if (params.expected_incremental) |expected_incremental| {
            self.logger.info().logf("validating the incremental snapshot", .{});

            const inc_slot = self.largest_rooted_slot.load(.acquire);

            const accounts_delta_hash, const incremental_lamports = try self.computeAccountHashesAndLamports(.{
                .IncrementalAccountHash = .{
                    .min_slot = params.full_slot,
                    .max_slot = inc_slot,
                },
            });

            if (expected_incremental.capitalization != incremental_lamports) {
                self.logger.err().logf(
                    \\ incorrect incremental lamports
                    \\ expected vs calculated: {d} vs {d}
                , .{ expected_incremental.capitalization, incremental_lamports });
                return error.IncorrectIncrementalLamports;
            }

            if (expected_incremental.accounts_hash.order(&accounts_delta_hash) != .eq) {
                self.logger.err().logf(
                    \\ incorrect accounts delta hash
                    \\ expected vs calculated: {d} vs {d}
                , .{ expected_incremental.accounts_hash, accounts_delta_hash });
                return error.IncorrectAccountsDeltaHash;
            }

            p_maybe_first_inc.* = .{
                .slot = inc_slot,
                .hash = accounts_delta_hash,
                .capitalization = incremental_lamports,
            };
        }
    }

    /// multithread entrypoint for getHashesFromIndex
    pub fn getHashesFromIndexMultiThread(
        self: *AccountsDB,
        config: AccountsDB.AccountHashesConfig,
        /// Allocator shared by all the arraylists in `hashes`.
        hashes_allocator: std.mem.Allocator,
        hashes: []ArrayListUnmanaged(Hash),
        total_lamports: []u64,
        task: sig.utils.thread.TaskParams,
    ) !void {
        try getHashesFromIndex(
            self,
            config,
            self.account_index.pubkey_ref_map.shards[task.start_index..task.end_index],
            hashes_allocator,
            &hashes[task.thread_id],
            &total_lamports[task.thread_id],
            task.thread_id == 0,
        );
    }

    /// populates the account hashes and total lamports across a given shard slice
    pub fn getHashesFromIndex(
        self: *AccountsDB,
        config: AccountsDB.AccountHashesConfig,
        shards: []ShardedPubkeyRefMap.RwPubkeyRefMap,
        hashes_allocator: std.mem.Allocator,
        hashes: *ArrayListUnmanaged(Hash),
        total_lamports: *u64,
        // when we multithread this function we only want to print on the first thread
        print_progress: bool,
    ) !void {
        var total_n_pubkeys: usize = 0;
        for (shards) |*shard_rw| {
            const shard, var shard_lg = shard_rw.readWithLock();
            defer shard_lg.unlock();

            total_n_pubkeys += shard.count();
        }
        try hashes.ensureTotalCapacity(hashes_allocator, total_n_pubkeys);

        var keys_buf = try std.ArrayList(Pubkey).initCapacity(self.allocator, 1000);
        defer keys_buf.deinit();

        var local_total_lamports: u64 = 0;
        var timer = try sig.time.Timer.start();
        var progress_timer = try std.time.Timer.start();
        for (shards, 1..) |*shard_rw, count| {
            // get and sort pubkeys inshardn
            // PERF: may be holding this lock for too long
            const shard, var shard_lg = shard_rw.readWithLock();
            defer shard_lg.unlock();

            const n_pubkeys_in_shard = shard.count();
            if (n_pubkeys_in_shard == 0) continue;

            try keys_buf.ensureTotalCapacity(n_pubkeys_in_shard);
            keys_buf.clearRetainingCapacity();

            const shard_pubkeys: []Pubkey = blk: {
                var key_iter = shard.iterator();
                while (key_iter.next()) |entry| {
                    keys_buf.appendAssumeCapacity(entry.key_ptr.*);
                }
                break :blk keys_buf.items;
            };

            std.mem.sort(Pubkey, shard_pubkeys, {}, struct {
                fn lessThan(_: void, lhs: Pubkey, rhs: Pubkey) bool {
                    return std.mem.lessThan(u8, &lhs.data, &rhs.data);
                }
            }.lessThan);

            // get the hashes
            for (shard_pubkeys) |key| {
                const ref_head = shard.getPtr(key).?;

                // get the most recent state of the account
                const ref_ptr = ref_head.ref_ptr;
                const max_slot_ref = switch (config) {
                    .FullAccountHash => |full_config| slotListMaxWithinBounds(ref_ptr, full_config.min_slot, full_config.max_slot),
                    .IncrementalAccountHash => |inc_config| slotListMaxWithinBounds(ref_ptr, inc_config.min_slot, inc_config.max_slot),
                } orelse continue;

                // read the account state
                var account_hash, const lamports = try self.getAccountHashAndLamportsFromRef(max_slot_ref.location);

                // modify its hash, if needed
                if (lamports == 0) {
                    switch (config) {
                        // for full snapshots, only include non-zero lamport accounts
                        .FullAccountHash => continue,
                        // zero-lamport accounts for incrementals = hash(pubkey)
                        .IncrementalAccountHash => Blake3.hash(&key.data, &account_hash.data, .{}),
                    }
                } else {
                    // hashes arent always stored correctly in snapshots
                    if (account_hash.eql(Hash.ZEROES)) {
                        const account, var lock = try self.getAccountFromRefWithReadLock(max_slot_ref);
                        defer lock.unlock();

                        account_hash = switch (account) {
                            .file => |in_file_account| sig.core.account.hashAccount(
                                in_file_account.lamports().*,
                                in_file_account.data,
                                &in_file_account.owner().data,
                                in_file_account.executable().*,
                                in_file_account.rent_epoch().*,
                                &in_file_account.pubkey().data,
                            ),
                            .unrooted_map => |unrooted_account| unrooted_account.hash(&key),
                        };
                    }
                }

                hashes.appendAssumeCapacity(account_hash);
                local_total_lamports += lamports;
            }

            if (print_progress and progress_timer.read() > DB_LOG_RATE.asNanos()) {
                printTimeEstimate(
                    self.logger,
                    &timer,
                    shards.len,
                    count,
                    "gathering account hashes",
                    "thread0",
                );
                progress_timer.reset();
            }
        }
        total_lamports.* = local_total_lamports;
    }

    /// creates a unique accounts file associated with a slot. uses the
    /// largest_file_id field to ensure its a unique file
    pub fn createAccountFile(self: *Self, size: usize, slot: Slot) !struct {
        std.fs.File,
        FileId,
        []u8,
    } {
        self.largest_file_id = self.largest_file_id.increment();
        const file_id = self.largest_file_id;

        const file_path_bounded = sig.utils.fmt.boundedFmt("accounts/{d}.{d}", .{ slot, file_id.toInt() });
        const file = try self.snapshot_dir.createFile(file_path_bounded.constSlice(), .{ .read = true });
        errdefer file.close();

        // resize the file
        const file_size = (try file.stat()).size;
        if (file_size < size) {
            try file.seekTo(size - 1);
            _ = try file.write(&[_]u8{1});
            try file.seekTo(0);
        }

        const memory = try std.posix.mmap(
            null,
            size,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            std.posix.MAP{ .TYPE = .SHARED },
            file.handle,
            0,
        );

        return .{ file, file_id, memory };
    }

    pub const ManagerLoopConfig = struct {
        exit: *std.atomic.Value(bool),
        slots_per_full_snapshot: u64,
        slots_per_incremental_snapshot: u64,
        zstd_nb_workers: u31 = 0,
    };

    /// periodically runs flush/clean/shrink, and generates snapshots.
    pub fn runManagerLoop(
        self: *Self,
        config: ManagerLoopConfig,
    ) !void {
        const exit = config.exit;
        const slots_per_full_snapshot = config.slots_per_full_snapshot;
        const slots_per_incremental_snapshot = config.slots_per_incremental_snapshot;

        var timer = try std.time.Timer.start();

        var flush_slots = ArrayList(Slot).init(self.allocator);
        defer flush_slots.deinit();

        // files which have been flushed but not cleaned yet (old-state or zero-lamport accounts)
        var unclean_account_files = std.ArrayList(FileId).init(self.allocator);
        defer unclean_account_files.deinit();

        // files which have a small number of accounts alive and should be shrunk
        var shrink_account_files = std.AutoArrayHashMap(FileId, void).init(self.allocator);
        defer shrink_account_files.deinit();

        // files which have zero accounts and should be deleted
        var delete_account_files = std.AutoArrayHashMap(FileId, void).init(self.allocator);
        defer delete_account_files.deinit();

        const zstd_compressor = try zstd.Compressor.init(.{
            .nb_workers = config.zstd_nb_workers,
        });
        defer zstd_compressor.deinit();

        var zstd_sfba_state = std.heap.stackFallback(4096 * 4, self.allocator);
        const zstd_sfba = zstd_sfba_state.get();

        const zstd_buffer = try zstd_sfba.alloc(u8, zstd.Compressor.recommOutSize());
        defer zstd_sfba.free(zstd_buffer);

        // TODO: get rid of this once `generateFullSnapshot` can actually
        // derive this data correctly by itself.
        var prng = std.Random.DefaultPrng.init(1234);
        var tmp_bank_fields = try BankFields.initRandom(self.allocator, prng.random(), 128);
        defer tmp_bank_fields.deinit(self.allocator);

        while (!exit.load(.acquire)) {
            defer {
                const elapsed = timer.lap();
                if (elapsed < DB_MANAGER_LOOP_MIN.asNanos()) {
                    const delay = DB_MANAGER_LOOP_MIN.asNanos() - elapsed;
                    std.time.sleep(delay);
                }
            }

            {
                const unrooted_accounts, var unrooted_accounts_lg = self.unrooted_accounts.readWithLock();
                defer unrooted_accounts_lg.unlock();

                // we're careful to load this value only after acquiring a read lock on the
                // account cache, such as to avoid the edge case where:
                // * we load the largest rooted slot value.
                // * the account cache lock is acquired by a different thread.
                // * another thread increments the largest rooted slot value while
                //   we're waiting on the account cache lock.
                // * we eventually acquire the lock, but have already read a now-stale
                //   largest rooted slot value.
                const root_slot = self.largest_rooted_slot.load(.monotonic);

                // flush slots <= root slot
                // TODO: account for forks when consensus is implemented
                var unrooted_slot_iter = unrooted_accounts.keyIterator();
                while (unrooted_slot_iter.next()) |unrooted_slot| {
                    if (unrooted_slot.* <= root_slot) {
                        // NOTE: need to flush all references <= root_slot before we call clean
                        // or things break by trying to clean unrooted references
                        // NOTE: this might be too much in production, not sure
                        try flush_slots.append(unrooted_slot.*);
                    }
                }
            }

            const must_flush_slots = flush_slots.items.len > 0;
            defer if (must_flush_slots) {
                flush_slots.clearRetainingCapacity();
                unclean_account_files.clearRetainingCapacity();
                shrink_account_files.clearRetainingCapacity();
            };

            if (must_flush_slots) {
                self.logger.debug().logf("flushing slots: min: {}...{}", std.mem.minMax(Slot, flush_slots.items));

                // flush the slots
                try unclean_account_files.ensureTotalCapacityPrecise(flush_slots.items.len);

                var largest_flushed_slot: Slot = 0;
                for (flush_slots.items) |flush_slot| {
                    const unclean_file_id = self.flushSlot(flush_slot) catch |err| {
                        // flush fail = loss of account data on slot -- should never happen
                        self.logger.err().logf("flushing slot {d} error: {s}", .{ flush_slot, @errorName(err) });
                        continue;
                    };
                    unclean_account_files.appendAssumeCapacity(unclean_file_id);
                    largest_flushed_slot = @max(largest_flushed_slot, flush_slot);
                }
                _ = self.largest_flushed_slot.fetchMax(largest_flushed_slot, .seq_cst);
            }

            const largest_flushed_slot = self.largest_flushed_slot.load(.seq_cst);

            const latest_full_snapshot_slot_before_generation = blk: {
                const p_maybe_latest_info, var latest_info_lg = self.latest_snapshot_info.readWithLock();
                defer latest_info_lg.unlock();
                const latest_info = p_maybe_latest_info.* orelse break :blk 0;
                break :blk latest_info.full.slot;
            };
            if (largest_flushed_slot - latest_full_snapshot_slot_before_generation >= slots_per_full_snapshot) {
                self.logger.info().logf("accountsdb[manager]: generating full snapshot for slot {d}", .{largest_flushed_slot});
                _ = try self.generateFullSnapshotWithCompressor(zstd_compressor, zstd_buffer, .{
                    .target_slot = largest_flushed_slot,
                    .bank_fields = &tmp_bank_fields,
                    .lamports_per_signature = prng.random().int(u64),
                    .old_snapshot_action = .delete_old,
                });
            }

            const latest_full_snapshot_slot, // we may have just generated a full snapshot, so we re-read the latest full snapshot slot
            const latest_inc_snapshot_slot //
            = blk: {
                const p_maybe_latest_info, var latest_info_lg = self.latest_snapshot_info.readWithLock();
                defer latest_info_lg.unlock();
                const latest_info = p_maybe_latest_info.* orelse break :blk .{largest_flushed_slot} ** 2;
                const latest_info_inc = latest_info.inc orelse break :blk .{ latest_info.full.slot, largest_flushed_slot };
                break :blk .{
                    latest_info.full.slot,
                    latest_info_inc.slot,
                };
            };

            if (largest_flushed_slot - latest_inc_snapshot_slot >= slots_per_incremental_snapshot and
                largest_flushed_slot - latest_full_snapshot_slot >= slots_per_incremental_snapshot //
            ) {
                self.logger.info().logf(
                    "accountsdb[manager]: generating incremental snapshot from {d} to {d}",
                    .{ latest_full_snapshot_slot, largest_flushed_slot },
                );
                _ = try self.generateIncrementalSnapshotWithCompressor(zstd_compressor, zstd_buffer, .{
                    .target_slot = largest_flushed_slot,
                    .bank_fields = &tmp_bank_fields,
                    .lamports_per_signature = prng.random().int(u64),
                    .old_snapshot_action = .delete_old,
                });
            }

            if (must_flush_slots) {
                // clean the flushed slots account files
                const clean_result = try self.cleanAccountFiles(
                    latest_full_snapshot_slot,
                    unclean_account_files.items,
                    &shrink_account_files,
                    &delete_account_files,
                );
                _ = clean_result;
                // self.logger.debug().logf("clean_result: {any}", .{clean_result});

                // shrink any account files which have been cleaned
                const shrink_result = try self.shrinkAccountFiles(
                    shrink_account_files.keys(),
                    &delete_account_files,
                );
                _ = shrink_result;
                // self.logger.debug().logf("shrink_results: {any}", .{shrink_results});

                // delete any empty account files
                if (delete_account_files.count() > DELETE_ACCOUNT_FILES_MIN) {
                    defer delete_account_files.clearRetainingCapacity();
                    try self.deleteAccountFiles(delete_account_files.keys());
                }
            }
        }
    }

    /// flushes a slot account data from the cache onto disk, and updates the index
    /// note: this deallocates the []account and []pubkey data from the cache, as well
    /// as the data field ([]u8) for each account.
    /// Returns the unclean file id.
    pub fn flushSlot(self: *Self, slot: Slot) !FileId {
        var timer = try sig.time.Timer.start();

        defer self.metrics.number_files_flushed.inc();

        const pubkeys, const accounts: []const Account = blk: {
            // NOTE: flush should be the only function to delete/free cache slices of a flushed slot
            // -- purgeSlot removes slices but we should never purge rooted slots
            const unrooted_accounts, var unrooted_accounts_lg = self.unrooted_accounts.readWithLock();
            defer unrooted_accounts_lg.unlock();

            const pubkeys, const accounts = unrooted_accounts.get(slot) orelse return error.SlotNotFound;
            break :blk .{ pubkeys, accounts };
        };
        std.debug.assert(accounts.len == pubkeys.len);

        // create account file which is big enough
        var size: usize = 0;
        for (accounts) |*account| {
            const account_size_in_file = account.getSizeInFile();
            size += account_size_in_file;
            self.metrics.flush_account_file_size.observe(account_size_in_file);
        }

        const file, const file_id, const memory = try self.createAccountFile(size, slot);

        const offsets = try self.allocator.alloc(u64, accounts.len);
        defer self.allocator.free(offsets);

        var current_offset: u64 = 0;
        for (offsets, accounts, pubkeys) |*offset, account, pubkey| {
            offset.* = current_offset;
            // write the account to the file
            current_offset += account.writeToBuf(&pubkey, memory[current_offset..]);
        }

        var account_file = try AccountFile.init(file, .{
            .id = file_id,
            .length = current_offset,
        }, slot);
        account_file.number_of_accounts = accounts.len;

        // update the file map
        {
            const file_map, var file_map_lg = self.file_map.writeWithLock();
            defer file_map_lg.unlock();
            try file_map.putNoClobber(self.allocator, file_id, account_file);
        }

        self.metrics.flush_accounts_written.add(account_file.number_of_accounts);

        // update the reference AFTER the data exists
        for (pubkeys, offsets) |pubkey, offset| {
            const head_ref, var head_reference_lg = self.account_index.pubkey_ref_map.getWrite(&pubkey) orelse {
                return error.PubkeyNotFound;
            };
            defer head_reference_lg.unlock();

            // find the slot in the reference list
            var curr_ref: ?*AccountRef = head_ref.ref_ptr;
            const did_update = while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
                if (ref.slot == slot) {
                    ref.location = .{ .File = .{ .file_id = file_id, .offset = offset } };
                    // NOTE: we break here because we dont allow multiple account states per slot
                    // NOTE: if there are multiple states, then it will likely break during clean
                    // trying to access a .File location which is actually still .UnrootedMap (bc it
                    // was never updated)
                    break true;
                }
            } else false;
            std.debug.assert(did_update);
        }

        // TODO: prom metrics
        // self.logger.debug().logf("flushed {} accounts, totalling size {}", .{ account_file.number_of_accounts, size });

        // remove old references
        {
            const unrooted_accounts, var unrooted_accounts_lg = self.unrooted_accounts.writeWithLock();
            defer unrooted_accounts_lg.unlock();

            // remove from cache map
            const did_remove = unrooted_accounts.remove(slot);
            std.debug.assert(did_remove);

            // free slices
            for (accounts) |account| {
                self.allocator.free(account.data);
            }
            self.allocator.free(accounts);
            self.allocator.free(pubkeys);
        }

        self.metrics.time_flush.observe(timer.read().asNanos());

        // return to queue for cleaning
        return file_id;
    }

    /// removes stale accounts and zero-lamport accounts from disk
    /// including removing the account from the index and updating the account files
    /// dead bytes. this also queues accounts for shrink or deletion if they contain
    /// a small number of 'alive' accounts.
    ///
    /// note: this method should not be called in parallel to shrink or delete.
    pub fn cleanAccountFiles(
        self: *Self,
        rooted_slot_max: Slot,
        unclean_account_files: []const FileId,
        shrink_account_files: *std.AutoArrayHashMap(FileId, void),
        delete_account_files: *std.AutoArrayHashMap(FileId, void),
    ) !struct {
        num_zero_lamports: usize,
        num_old_states: usize,
    } {
        var timer = try sig.time.Timer.start();

        const number_of_files = unclean_account_files.len;
        defer self.metrics.number_files_cleaned.add(number_of_files);

        var num_zero_lamports: usize = 0;
        var num_old_states: usize = 0;

        // TODO: move this out into a CleanState struct to reduce allocations
        // track then delete all to avoid deleting while iterating
        var references_to_delete = std.ArrayList(struct { pubkey: Pubkey, slot: Slot }).init(self.allocator);
        defer references_to_delete.deinit();

        // track so we dont double delete
        var cleaned_pubkeys = std.AutoArrayHashMap(Pubkey, void).init(self.allocator);
        defer cleaned_pubkeys.deinit();

        for (unclean_account_files) |file_id| {
            // NOTE: this read-lock is held for a while but
            // is not expensive since writes only happen
            // during delete, which doesn't happen in parallel
            // to this function.
            self.file_map_fd_rw.lockShared();
            defer self.file_map_fd_rw.unlockShared();

            const account_file = blk: {
                const file_map, var file_map_lg = self.file_map.readWithLock();
                defer file_map_lg.unlock();
                break :blk file_map.get(file_id).?;
            };

            var account_iter = account_file.iterator();
            while (account_iter.next()) |account| {
                const pubkey = account.pubkey().*;

                // check if already cleaned
                if (try cleaned_pubkeys.fetchPut(pubkey, {}) != null) continue;

                const head_ref, var head_ref_lg = self.account_index.pubkey_ref_map.getRead(&pubkey).?; // SAFE: this should always succeed or something is wrong
                defer head_ref_lg.unlock();

                // get the highest slot <= highest_rooted_slot
                const rooted_ref_count, const ref_slot_max = head_ref.highestRootedSlot(rooted_slot_max);

                // short exit because nothing else to do
                if (rooted_ref_count == 0) continue;
                // if there are extra references, remove them

                var curr: ?*AccountRef = head_ref.ref_ptr;
                while (curr) |ref| : (curr = ref.next_ptr) {
                    const is_not_rooted = ref.slot > rooted_slot_max;
                    if (is_not_rooted) continue;

                    const is_old_state = ref.slot < ref_slot_max;

                    // the only reason to delete the highest ref is if it is zero-lamports
                    var is_largest_root_zero_lamports = false;
                    if (ref.slot == ref_slot_max) {
                        // check if account is zero-lamports
                        _, const lamports = try self.getAccountHashAndLamportsFromRef(ref.location);
                        is_largest_root_zero_lamports = lamports == 0;
                    }

                    if (is_old_state) num_old_states += 1;
                    if (is_largest_root_zero_lamports) num_zero_lamports += 1;

                    const should_delete_ref = is_largest_root_zero_lamports or is_old_state;
                    if (should_delete_ref) {
                        // queue for deletion
                        try references_to_delete.append(.{
                            .pubkey = ref.pubkey,
                            .slot = ref.slot,
                        });

                        // NOTE: we should never clean non-rooted references (ie, should always be in a file)
                        const ref_file_id = ref.location.File.file_id;
                        const ref_slot = ref.slot;

                        const accounts_total_count, const accounts_dead_count = blk: {
                            const dead_accounts_counter, var dead_accounts_counter_lg = self.dead_accounts_counter.writeWithLock();
                            defer dead_accounts_counter_lg.unlock();

                            // NOTE: if there is no counter for this slot, it may have been removed after reaching 0 dead accounts
                            // previously. it is added back as needed.
                            const number_dead_accounts_ptr = (try dead_accounts_counter.getOrPutValue(ref_slot, 0)).value_ptr;
                            number_dead_accounts_ptr.* += 1;
                            const accounts_dead_count = number_dead_accounts_ptr.*;

                            if (ref_file_id == file_id) {
                                // read from the currently locked file
                                break :blk .{ account_file.number_of_accounts, accounts_dead_count };
                            } else {
                                // read number of accounts from another file
                                const ref_account_file = ref_blk: {
                                    const file_map, var file_map_lg = self.file_map.readWithLock();
                                    defer file_map_lg.unlock();
                                    break :ref_blk file_map.get(ref_file_id).?; // we are holding a lock on `file_map_fd_rw`.
                                };
                                break :blk .{ ref_account_file.number_of_accounts, accounts_dead_count };
                            }
                        };
                        std.debug.assert(accounts_dead_count <= accounts_total_count);

                        const dead_percentage = 100 * accounts_dead_count / accounts_total_count;
                        if (dead_percentage == 100) {
                            // if its queued for shrink, remove it and queue it for deletion
                            _ = shrink_account_files.swapRemove(ref_file_id);
                            try delete_account_files.put(ref_file_id, {});
                        } else if (dead_percentage >= ACCOUNT_FILE_SHRINK_THRESHOLD) {
                            // queue for shrink
                            try shrink_account_files.put(ref_file_id, {});
                        }
                    }
                }
            }

            // remove from index
            for (references_to_delete.items) |ref| {
                try self.account_index.removeReference(&ref.pubkey, ref.slot);
                // sanity check
                if (builtin.mode == .Debug) {
                    std.debug.assert(!self.account_index.exists(&ref.pubkey, ref.slot));
                }
            }
            references_to_delete.clearRetainingCapacity();
            self.metrics.clean_references_deleted.set(references_to_delete.items.len);
        }

        if (number_of_files > 0) {
            self.logger.debug().logf(
                "cleaned {} slots - old_state: {}, zero_lamports: {}",
                .{ number_of_files, num_old_states, num_zero_lamports },
            );
        }

        self.metrics.clean_files_queued_deletion.set(delete_account_files.count());
        self.metrics.clean_files_queued_shrink.set(delete_account_files.count());
        self.metrics.clean_slot_old_state.set(num_old_states);
        self.metrics.clean_slot_zero_lamports.set(num_zero_lamports);

        self.metrics.time_clean.observe(timer.read().asNanos());
        return .{
            .num_zero_lamports = num_zero_lamports,
            .num_old_states = num_old_states,
        };
    }

    /// should only be called when all the accounts are dead (ie, no longer
    /// exist in the index).
    pub fn deleteAccountFiles(
        self: *Self,
        delete_account_files: []const FileId,
    ) !void {
        const number_of_files = delete_account_files.len;
        defer {
            self.metrics.number_files_deleted.add(number_of_files);
        }

        var delete_queue = try std.ArrayList(AccountFile).initCapacity(
            self.allocator,
            number_of_files,
        );
        defer delete_queue.deinit();

        {
            // we acquire this lock to ensure no account files are being accessed
            self.file_map_fd_rw.lock();
            defer self.file_map_fd_rw.unlock();

            // we acquire this lock to saftely remove file_id's from the file_map
            const file_map, var file_map_lg = self.file_map.writeWithLock();
            defer file_map_lg.unlock();

            for (delete_account_files) |file_id| {
                const account_file = file_map.get(file_id).?;

                // remove from file map
                const did_remove = file_map.swapRemove(file_id);
                std.debug.assert(did_remove);

                // NOTE: we can queue the actual removal of the account file without the lock because
                // because we know 1) no account files are being accessed and 2) no files are reading
                // from the file_map, so its no possible to access the file after this block returns.
                delete_queue.appendAssumeCapacity(account_file);
            }
        }

        for (delete_queue.items) |account_file| {
            const slot = account_file.slot;
            self.logger.info().logf("deleting slot: {}...", .{slot});
            account_file.deinit();

            // delete file from disk
            self.deleteAccountFile(slot, account_file.id) catch |err| {
                // NOTE: this should always succeed or something is wrong
                self.logger.err().logf(
                    "failed to delete account file slot.file_id: {d}.{d}: {s}",
                    .{ slot, account_file.id, @errorName(err) },
                );
            };
        }

        {
            const dead_accounts_counter, var dead_accounts_counter_lg = self.dead_accounts_counter.writeWithLock();
            defer dead_accounts_counter_lg.unlock();

            for (delete_queue.items) |account_file| {
                const slot = account_file.slot;
                // there are two cases for an account file being queued for deletion from cleaning:
                // 1) it was queued for shrink, and this is the *old* accountFile: dead_count == 0 and the slot DNE in the map (shrink removed it)
                // 2) it contains 100% dead accounts (in which dead_count > 0 and we can remove it from the map)
                _ = dead_accounts_counter.swapRemove(slot);
            }
        }
    }

    pub fn deleteAccountFile(
        self: *const Self,
        slot: Slot,
        file_id: FileId,
    ) !void {
        const file_path_bounded = sig.utils.fmt.boundedFmt("accounts/{d}.{d}", .{ slot, file_id.toInt() });
        self.snapshot_dir.deleteFile(file_path_bounded.constSlice()) catch |err| switch (err) {
            error.FileNotFound => {
                self.logger.warn().logf("trying to delete accounts file which does not exist: {s}", .{sig.utils.fmt.tryRealPath(self.snapshot_dir, file_path_bounded.constSlice())});
                return error.InvalidAccountFile;
            },
            else => |e| return e,
        };
    }

    /// resizes account files to reduce disk usage and remove dead accounts.
    pub fn shrinkAccountFiles(
        self: *Self,
        shrink_account_files: []const FileId,
        delete_account_files: *std.AutoArrayHashMap(FileId, void),
    ) !struct { num_accounts_deleted: usize } {
        var timer = try sig.time.Timer.start();

        const number_of_files = shrink_account_files.len;
        defer self.metrics.number_files_shrunk.add(number_of_files);

        var alive_pubkeys = std.AutoArrayHashMap(Pubkey, void).init(self.allocator);
        defer alive_pubkeys.deinit();

        try delete_account_files.ensureUnusedCapacity(shrink_account_files.len);

        var total_accounts_deleted_size: u64 = 0;
        var total_accounts_deleted: u64 = 0;
        for (shrink_account_files) |shrink_file_id| {
            self.file_map_fd_rw.lockShared();
            defer self.file_map_fd_rw.unlockShared();

            const shrink_account_file = blk: {
                const file_map, var file_map_lg = self.file_map.readWithLock();
                defer file_map_lg.unlock();
                break :blk file_map.get(shrink_file_id).?;
            };

            const slot = shrink_account_file.slot;

            // compute size of alive accounts (read)
            var is_alive_flags = try std.ArrayList(bool).initCapacity(
                self.allocator,
                shrink_account_file.number_of_accounts,
            );
            defer is_alive_flags.deinit();

            var accounts_dead_count: u64 = 0;
            var accounts_alive_count: u64 = 0;

            alive_pubkeys.clearRetainingCapacity();
            try alive_pubkeys.ensureTotalCapacity(shrink_account_file.number_of_accounts);

            var accounts_alive_size: u64 = 0;
            var accounts_dead_size: u64 = 0;
            var account_iter = shrink_account_file.iterator();
            while (account_iter.next()) |*account_in_file| {
                const pubkey = account_in_file.pubkey();
                // account is dead if it is not in the index; dead accounts
                // are removed from the index during cleaning
                const is_alive = self.account_index.exists(pubkey, shrink_account_file.slot);
                // NOTE: there may be duplicate state in account files which we must account for
                const is_not_duplicate = !alive_pubkeys.contains(pubkey.*);
                if (is_alive and is_not_duplicate) {
                    accounts_alive_size += account_in_file.getSizeInFile();
                    accounts_alive_count += 1;
                    is_alive_flags.appendAssumeCapacity(true);
                    alive_pubkeys.putAssumeCapacity(pubkey.*, {});
                } else {
                    accounts_dead_size += account_in_file.getSizeInFile();
                    accounts_dead_count += 1;
                    is_alive_flags.appendAssumeCapacity(false);
                }
            }
            // if there are no alive accounts, it should have been queued for deletion
            std.debug.assert(accounts_alive_count > 0);
            // if there are no dead accounts, it should have not been queued for shrink
            std.debug.assert(accounts_dead_count > 0);
            total_accounts_deleted += accounts_dead_count;
            total_accounts_deleted_size += accounts_dead_size;

            self.metrics.shrink_alive_accounts.observe(accounts_alive_count);
            self.metrics.shrink_dead_accounts.observe(accounts_dead_count);
            self.metrics.shrink_file_shrunk_by.observe(accounts_dead_size);

            // alloc account file for accounts
            const new_file, const new_file_id, const new_memory = try self.createAccountFile(
                accounts_alive_size,
                slot,
            );

            // write the alive accounts
            var offsets = try std.ArrayList(u64).initCapacity(self.allocator, accounts_alive_count);
            defer offsets.deinit();

            account_iter.reset();
            var offset: usize = 0;
            for (is_alive_flags.items) |is_alive| {
                // SAFE: we know is_alive_flags is the same length as the account_iter
                const account = account_iter.next().?;
                if (is_alive) {
                    offsets.appendAssumeCapacity(offset);
                    offset += account.writeToBuf(new_memory[offset..]);
                }
            }

            {
                // add file to map
                const file_map, var file_map_lg = self.file_map.writeWithLock();
                defer file_map_lg.unlock();
                try file_map.ensureUnusedCapacity(self.allocator, 1);

                var new_account_file = try AccountFile.init(
                    new_file,
                    .{ .id = new_file_id, .length = offset },
                    slot,
                );
                new_account_file.number_of_accounts = accounts_alive_count;

                file_map.putAssumeCapacityNoClobber(new_file_id, new_account_file);
            }

            // update the references
            var new_reference_block = try ArrayList(AccountRef).initCapacity(
                self.account_index.reference_allocator.get(),
                accounts_alive_count,
            );

            account_iter.reset();
            var offset_index: u64 = 0;
            for (is_alive_flags.items) |is_alive| {
                // SAFE: we know is_alive_flags is the same length as the account_iter
                const account = account_iter.next().?;
                if (is_alive) {
                    // find the slot in the reference list
                    const pubkey = account.pubkey();

                    const ref_parent, var ref_lg = self.account_index.getReferenceParent(pubkey, slot) catch |err| switch (err) {
                        // SAFE: we know the pubkey exists in the index because its alive
                        error.SlotNotFound, error.PubkeyNotFound => unreachable,
                    };
                    defer ref_lg.unlock();
                    const ptr_to_ref_field = switch (ref_parent) {
                        .head => |head| &head.ref_ptr,
                        .parent => |parent| &parent.next_ptr.?,
                    };

                    // copy + update the values
                    const new_ref_ptr = new_reference_block.addOneAssumeCapacity();
                    new_ref_ptr.* = ptr_to_ref_field.*.*;
                    new_ref_ptr.location.File = .{
                        .offset = offsets.items[offset_index],
                        .file_id = new_file_id,
                    };
                    offset_index += 1;
                    ptr_to_ref_field.* = new_ref_ptr;
                }
            }

            // update slot's reference memory
            {
                const slot_reference_map, var slot_reference_map_lg = self.account_index.slot_reference_map.writeWithLock();
                defer slot_reference_map_lg.unlock();

                const slot_reference_map_entry = slot_reference_map.getEntry(slot) orelse {
                    std.debug.panic("missing corresponding reference memory for slot {d}\n", .{slot});
                };
                // NOTE: this is ok because nothing points to this old reference memory
                // deinit old block of reference memory
                slot_reference_map_entry.value_ptr.deinit();
                // point to new block
                slot_reference_map_entry.value_ptr.* = new_reference_block;
            }

            // queue the old account_file for deletion
            delete_account_files.putAssumeCapacityNoClobber(shrink_file_id, {});

            {
                // remove the dead accounts counter entry, since there
                // are no longer any dead accounts at this slot for now.
                // there has to be a counter for it at this point, since
                // cleanAccounts would only have added this file_id to
                // the queue if it deleted any accounts refs.
                const dead_accounts_counter, var dead_accounts_counter_lg = self.dead_accounts_counter.writeWithLock();
                defer dead_accounts_counter_lg.unlock();
                const removed = dead_accounts_counter.fetchSwapRemove(slot) orelse unreachable;
                std.debug.assert(removed.value == accounts_dead_count);
            }
        }

        if (number_of_files > 0) {
            self.logger.info().logf("shrinked {} account files, total accounts deleted: {} ({} bytes)", .{ number_of_files, total_accounts_deleted, total_accounts_deleted_size });
        }
        self.metrics.time_shrink.observe(timer.read().asNanos());

        return .{
            .num_accounts_deleted = total_accounts_deleted,
        };
    }

    /// remove all accounts and associated reference memory.
    /// note: should only be called on non-rooted slots (ie, slots which
    /// only exist in the cache, and not on disk). this is mainly used for dropping
    /// forks.
    pub fn purgeSlot(self: *Self, slot: Slot) void {
        var timer = sig.time.Timer.start() catch @panic("Timer unsupported");

        const pubkeys: []const Pubkey, //
        const accounts: []const Account //
        = blk: {
            const unrooted_accounts, var unrooted_accounts_lg = self.unrooted_accounts.writeWithLock();
            defer unrooted_accounts_lg.unlock();

            const removed_entry = unrooted_accounts.fetchRemove(slot) orelse {
                // the way it works right now, account files only exist for rooted slots
                // rooted slots should never need to be purged so we should never get here
                @panic("purging an account file not supported");
            };
            break :blk removed_entry.value;
        };

        // remove the references
        for (pubkeys) |*pubkey| {
            self.account_index.removeReference(pubkey, slot) catch |err| switch (err) {
                error.PubkeyNotFound => std.debug.panic("pubkey not found in index while purging: {any}", .{pubkey}),
                error.SlotNotFound => std.debug.panic("pubkey @ slot not found in index while purging: {any} @ {d}", .{ pubkey, slot }),
            };
        }

        // free the reference memory
        self.account_index.freeReferenceBlock(slot) catch |err| switch (err) {
            error.MemoryNotFound => std.debug.panic("memory block @ slot not found: {d}", .{slot}),
        };

        // free the account memory
        for (accounts) |account| {
            account.deinit(self.allocator);
        }
        self.allocator.free(accounts);
        self.allocator.free(pubkeys);

        self.metrics.time_purge.observe(timer.read().asNanos());
    }

    // NOTE: we need to acquire locks which requires `self: *Self` but we never modify any data
    pub fn getAccountFromRef(self: *Self, account_ref: *const AccountRef) !Account {
        switch (account_ref.location) {
            .File => |ref_info| {
                const maybe_cached_account = blk: {
                    const accounts_cache, var accounts_cache_lg = self.accounts_cache.writeWithLock();
                    defer accounts_cache_lg.unlock();

                    const cached_account = accounts_cache.get(account_ref.pubkey, account_ref.slot) orelse break :blk null;
                    break :blk cached_account;
                };

                if (maybe_cached_account) |cached_account| {
                    const account = try cached_account.account.clone(self.allocator);
                    cached_account.releaseOrDestroy(self.allocator);
                    return account;
                } else {
                    const account = try self.getAccountInFile(
                        self.allocator,
                        ref_info.file_id,
                        ref_info.offset,
                    );

                    const accounts_cache, var accounts_cache_lg = self.accounts_cache.writeWithLock();
                    defer accounts_cache_lg.unlock();
                    try accounts_cache.put(account_ref.pubkey, account_ref.slot, account);

                    return account;
                }
            },
            .UnrootedMap => |ref_info| {
                const unrooted_accounts, var unrooted_accounts_lg = self.unrooted_accounts.readWithLock();
                defer unrooted_accounts_lg.unlock();

                _, const accounts = unrooted_accounts.get(account_ref.slot) orelse return error.SlotNotFound;
                const account = accounts[ref_info.index];

                return account.clone(self.allocator);
            },
        }
    }

    pub const AccountInCacheOrFileTag = enum { file, unrooted_map };
    pub const AccountInCacheOrFile = union(AccountInCacheOrFileTag) { file: AccountInFile, unrooted_map: Account };
    pub const AccountInCacheOrFileLock = union(AccountInCacheOrFileTag) {
        file: *std.Thread.RwLock,
        unrooted_map: RwMux(SlotPubkeyAccounts).RLockGuard,

        pub fn unlock(lock: *AccountInCacheOrFileLock) void {
            switch (lock.*) {
                .file => |rwlock| rwlock.unlockShared(),
                .unrooted_map => |*lg| lg.unlock(),
            }
        }
    };

    pub const GetAccountFromRefError = GetAccountInFileError || error{SlotNotFound};
    pub fn getAccountFromRefWithReadLock(
        self: *Self,
        account_ref: *const AccountRef,
    ) GetAccountFromRefError!struct { AccountInCacheOrFile, AccountInCacheOrFileLock } {
        switch (account_ref.location) {
            .File => |ref_info| {
                const account = try self.getAccountInFileAndLock(
                    ref_info.file_id,
                    ref_info.offset,
                );
                return .{
                    .{ .file = account },
                    .{ .file = &self.file_map_fd_rw },
                };
            },
            .UnrootedMap => |ref_info| {
                const unrooted_accounts, var unrooted_accounts_lg = self.unrooted_accounts.readWithLock();
                errdefer unrooted_accounts_lg.unlock();

                _, const accounts = unrooted_accounts.get(account_ref.slot) orelse return error.SlotNotFound;
                return .{
                    .{ .unrooted_map = accounts[ref_info.index] },
                    .{ .unrooted_map = unrooted_accounts_lg },
                };
            },
        }
    }

    pub const GetAccountInFileError = error{ FileIdNotFound, InvalidOffset };

    /// Gets an account given an file_id and offset value.
    /// Locks the account file entries, and then unlocks
    /// them, after returning the clone of the account.
    pub fn getAccountInFile(
        self: *Self,
        account_allocator: std.mem.Allocator,
        file_id: FileId,
        offset: usize,
    ) (GetAccountInFileError || std.mem.Allocator.Error)!Account {
        const account_in_file = try self.getAccountInFileAndLock(file_id, offset);
        defer self.file_map_fd_rw.unlockShared();
        return try account_in_file.toOwnedAccount(account_allocator);
    }

    /// Gets an account given an file_id and offset value.
    /// Locks the account file entries, and returns the account.
    /// Must call `self.file_map_fd_rw.unlockShared()`
    /// when done with the account.
    pub fn getAccountInFileAndLock(
        self: *Self,
        file_id: FileId,
        offset: usize,
    ) GetAccountInFileError!AccountInFile {
        self.file_map_fd_rw.lockShared();
        errdefer self.file_map_fd_rw.unlockShared();
        return try self.getAccountInFileAssumeLock(file_id, offset);
    }

    /// Gets an account given a file_id and an offset value.
    /// Assumes `self.file_map_fd_rw` is at least
    /// locked for reading (shared).
    pub fn getAccountInFileAssumeLock(
        self: *Self,
        file_id: FileId,
        offset: usize,
    ) GetAccountInFileError!AccountInFile {
        const account_file: AccountFile = blk: {
            const file_map, var file_map_lg = self.file_map.readWithLock();
            defer file_map_lg.unlock();
            break :blk file_map.get(file_id) orelse return error.FileIdNotFound;
        };
        return account_file.readAccount(offset) catch error.InvalidOffset;
    }

    pub fn getAccountHashAndLamportsFromRef(
        self: *Self,
        location: AccountRef.AccountLocation,
    ) (GetAccountInFileError)!struct { Hash, u64 } {
        switch (location) {
            .File => |ref_info| {
                self.file_map_fd_rw.lockShared();
                defer self.file_map_fd_rw.unlockShared();

                const account_file = blk: {
                    const file_map, var file_map_lg = self.file_map.readWithLock();
                    defer file_map_lg.unlock();
                    break :blk file_map.get(ref_info.file_id) orelse return error.FileIdNotFound;
                };

                const result = account_file.getAccountHashAndLamports(
                    ref_info.offset,
                ) catch return error.InvalidOffset;

                return .{
                    result.hash.*,
                    result.lamports.*,
                };
            },
            // we dont use this method for cache
            .UnrootedMap => @panic("getAccountHashAndLamportsFromRef is not implemented on UnrootedMap references"),
        }
    }

    /// gets an account given an associated pubkey. mut ref is required for locks.
    pub fn getAccount(self: *Self, pubkey: *const Pubkey) !Account {
        const head_ref, var lock = self.account_index.pubkey_ref_map.getRead(pubkey) orelse return error.PubkeyNotInIndex;
        defer lock.unlock();

        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, null, null).?;
        const account = try self.getAccountFromRef(max_ref);

        return account;
    }

    pub fn getAccountAndReference(self: *Self, pubkey: *const Pubkey) !struct { Account, AccountRef } {
        const head_ref, var lock = self.account_index.pubkey_ref_map.getRead(pubkey) orelse return error.PubkeyNotInIndex;
        defer lock.unlock();

        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, null, null).?;
        const account = try self.getAccountFromRef(max_ref);

        return .{ account, max_ref.* };
    }

    pub const GetAccountError = GetAccountFromRefError || error{PubkeyNotInIndex};
    pub fn getAccountWithReadLock(
        self: *Self,
        pubkey: *const Pubkey,
    ) GetAccountError!struct { AccountInCacheOrFile, AccountInCacheOrFileLock } {
        const head_ref, var lock = self.account_index.pubkey_ref_map.getRead(pubkey) orelse return error.PubkeyNotInIndex;
        defer lock.unlock();

        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, null, null).?;
        return try self.getAccountFromRefWithReadLock(max_ref);
    }

    pub const GetTypeFromAccountError = GetAccountError || error{DeserializationError};
    pub fn getTypeFromAccount(
        self: *Self,
        comptime T: type,
        pubkey: *const Pubkey,
    ) GetTypeFromAccountError!T {
        const account, var lock_guard = try self.getAccountWithReadLock(pubkey);
        // NOTE: bincode will copy heap memory so its safe to unlock at the end of the function
        defer lock_guard.unlock();

        const file_data: []const u8 = switch (account) {
            .file => |in_file_account| in_file_account.data,
            .unrooted_map => |unrooted_map_account| unrooted_map_account.data,
        };
        const t = bincode.readFromSlice(self.allocator, T, file_data, .{}) catch {
            return error.DeserializationError;
        };
        return t;
    }

    pub fn getSlotHistory(self: *Self) !sysvars.SlotHistory {
        return try self.getTypeFromAccount(
            sysvars.SlotHistory,
            &sysvars.IDS.slot_history,
        );
    }

    /// index and validate an account file.
    /// NOTE: should only be called in tests/benchmarks
    pub fn putAccountFile(
        self: *Self,
        account_file: *AccountFile,
        n_accounts: usize,
    ) !void {
        const shard_counts = try self.allocator.alloc(usize, self.account_index.pubkey_ref_map.numberOfShards());
        defer self.allocator.free(shard_counts);
        @memset(shard_counts, 0);

        var references = try ArrayList(AccountRef).initCapacity(
            self.account_index.reference_allocator.get(),
            n_accounts,
        );

        try indexAndValidateAccountFile(
            account_file,
            self.account_index.pubkey_ref_map.shard_calculator,
            shard_counts,
            &references,
            // NOTE: this method should only be called in tests/benchmarks so we dont need
            // to support geyser
            null,
        );
        try self.account_index.putReferenceBlock(account_file.slot, references);

        {
            const file_map, var file_map_lg = self.file_map.writeWithLock();
            defer file_map_lg.unlock();

            try file_map.put(self.allocator, account_file.id, account_file.*);

            // we update the bank hash stats while locking the file map to avoid
            // reading accounts from the file map and getting inaccurate/stale
            // bank hash stats.
            var account_iter = account_file.iterator();
            while (account_iter.next()) |account_in_file| {
                const bhs, var bhs_lg = try self.getOrInitBankHashStats(account_file.slot);
                defer bhs_lg.unlock();
                bhs.update(.{
                    .lamports = account_in_file.lamports().*,
                    .data_len = account_in_file.data.len,
                    .executable = account_in_file.executable().*,
                });
            }
        }

        // allocate enough memory here
        try self.account_index.pubkey_ref_map.ensureTotalAdditionalCapacity(shard_counts);

        // compute how many account_references for each pubkey
        var accounts_dead_count: u64 = 0;
        for (references.items) |*ref| {
            const was_inserted = self.account_index.indexRefIfNotDuplicateSlotAssumeCapacity(ref);
            if (!was_inserted) {
                accounts_dead_count += 1;
                self.logger.warn().logf(
                    "account was not referenced because its slot was a duplicate: {any}",
                    .{.{
                        .slot = ref.slot,
                        .pubkey = ref.pubkey,
                    }},
                );
            }
        }

        if (accounts_dead_count != 0) {
            const dead_accounts, var dead_accounts_lg = self.dead_accounts_counter.writeWithLock();
            defer dead_accounts_lg.unlock();
            try dead_accounts.putNoClobber(account_file.slot, accounts_dead_count);
        }
    }

    /// writes a batch of accounts to storage and updates the index
    /// NOTE: only currently used in benchmarks and tests
    pub fn putAccountSlice(
        self: *Self,
        accounts: []const Account,
        pubkeys: []const Pubkey,
        slot: Slot,
    ) !void {
        std.debug.assert(accounts.len == pubkeys.len);
        if (accounts.len == 0) return;

        if (self.geyser_writer) |geyser_writer| {
            const data_versioned = sig.geyser.core.VersionedAccountPayload{
                .AccountPayloadV1 = .{
                    .accounts = accounts,
                    .pubkeys = pubkeys,
                    .slot = slot,
                },
            };
            try geyser_writer.writePayloadToPipe(data_versioned);
        }

        {
            const accounts_duped = try self.allocator.alloc(Account, accounts.len);
            errdefer self.allocator.free(accounts_duped);

            for (accounts_duped, accounts, 0..) |*account, original, i| {
                errdefer for (accounts_duped[0..i]) |prev| prev.deinit(self.allocator);
                account.* = try original.clone(self.allocator);

                const bhs, var bhs_lg = try self.getOrInitBankHashStats(slot);
                defer bhs_lg.unlock();
                bhs.update(.{
                    .lamports = account.lamports,
                    .data_len = account.data.len,
                    .executable = account.executable,
                });
            }

            const pubkeys_duped = try self.allocator.dupe(Pubkey, pubkeys);
            errdefer self.allocator.free(pubkeys_duped);

            const unrooted_accounts, var unrooted_accounts_lg = self.unrooted_accounts.writeWithLock();
            defer unrooted_accounts_lg.unlock();
            // NOTE: there should only be a single state per slot
            try unrooted_accounts.putNoClobber(slot, .{ pubkeys_duped, accounts_duped });
        }

        // prealloc the ref map space
        var shard_counts = try self.allocator.alloc(usize, self.account_index.pubkey_ref_map.numberOfShards());
        defer self.allocator.free(shard_counts);
        @memset(shard_counts, 0);

        const index_shard_calc = self.account_index.pubkey_ref_map.shard_calculator;
        for (pubkeys) |*pubkey| {
            shard_counts[index_shard_calc.index(pubkey)] += 1;
        }
        try self.account_index.pubkey_ref_map.ensureTotalAdditionalCapacity(shard_counts);

        // update index
        var accounts_dead_count: u64 = 0;
        var references = try ArrayList(AccountRef).initCapacity(
            self.account_index.reference_allocator.get(),
            accounts.len,
        );
        for (0..accounts.len) |i| {
            const ref_ptr = references.addOneAssumeCapacity();
            ref_ptr.* = AccountRef{
                .pubkey = pubkeys[i],
                .slot = slot,
                .location = .{ .UnrootedMap = .{ .index = i } },
            };

            const was_inserted = self.account_index.indexRefIfNotDuplicateSlotAssumeCapacity(ref_ptr);
            if (!was_inserted) {
                self.logger.warn().logf(
                    "duplicate reference not inserted: slot: {d} pubkey: {s}",
                    .{ ref_ptr.slot, ref_ptr.pubkey },
                );
                accounts_dead_count += 1;
            }

            std.debug.assert(self.account_index.exists(&pubkeys[i], slot));
        }

        if (accounts_dead_count != 0) {
            const dead_accounts, var dead_accounts_lg = self.dead_accounts_counter.writeWithLock();
            defer dead_accounts_lg.unlock();
            try dead_accounts.putNoClobber(slot, accounts_dead_count);
        }
        try self.account_index.putReferenceBlock(slot, references);
    }

    /// Returns a pointer to the bank hash stats for the given slot, and a lock guard on the
    /// bank hash stats map, which should be unlocked after mutating the bank hash stats.
    fn getOrInitBankHashStats(self: *Self, slot: Slot) !struct { *BankHashStats, RwMux(BankHashStatsMap).WLockGuard } {
        const bank_hash_stats, var bank_hash_stats_lg = self.bank_hash_stats.writeWithLock();
        errdefer bank_hash_stats_lg.unlock();

        const gop = try bank_hash_stats.getOrPut(self.allocator, slot);
        if (!gop.found_existing) gop.value_ptr.* = BankHashStats.zero_init;
        return .{ gop.value_ptr, bank_hash_stats_lg };
    }

    pub inline fn slotListMaxWithinBounds(
        ref_ptr: *AccountRef,
        min_slot: ?Slot,
        max_slot: ?Slot,
    ) ?*AccountRef {
        var biggest: ?*AccountRef = null;
        if (inBoundsIf(ref_ptr.slot, min_slot, max_slot)) {
            biggest = ref_ptr;
        }

        var curr = ref_ptr;
        while (curr.next_ptr) |ref| {
            if (inBoundsIf(ref.slot, min_slot, max_slot) and (biggest == null or ref.slot > biggest.?.slot)) {
                biggest = ref;
            }
            curr = ref;
        }
        return biggest;
    }

    pub const OldSnapshotAction = enum {
        /// Ignore the previous snapshot.
        ignore_old,
        /// Delete the previous snapshot.
        delete_old,
    };

    pub const SnapshotGenerationInfo = struct {
        full: Full,
        inc: ?Incremental,

        pub const Full = struct {
            slot: Slot,
            hash: Hash,
            capitalization: u64,
        };

        pub const Incremental = struct {
            slot: Slot,
            hash: Hash,
            capitalization: u64,
        };
    };

    pub const FullSnapshotGenParams = struct {
        /// The slot to generate a snapshot for.
        /// Must be a flushed slot (`<= self.largest_flushed_slot.load(...)`).
        /// Must be greater than the most recently generated full snapshot.
        /// Must exist explicitly in the database.
        target_slot: Slot,
        /// Mutated (without re-allocation) to be valid for the target slot.
        bank_fields: *BankFields,
        lamports_per_signature: u64,
        old_snapshot_action: OldSnapshotAction,

        /// For tests against older snapshots. Should just be 0 during normal operation.
        deprecated_stored_meta_write_version: u64 = 0,
    };

    pub const GenerateFullSnapshotResult = struct {
        hash: Hash,
        capitalization: u64,
    };

    pub fn generateFullSnapshot(
        self: *Self,
        params: FullSnapshotGenParams,
    ) !GenerateFullSnapshotResult {
        const zstd_compressor = try zstd.Compressor.init(.{});
        defer zstd_compressor.deinit();

        var zstd_sfba_state = std.heap.stackFallback(4096 * 4, self.allocator);
        const zstd_sfba = zstd_sfba_state.get();
        const zstd_buffer = try zstd_sfba.alloc(u8, zstd.Compressor.recommOutSize());
        defer zstd_sfba.free(zstd_buffer);

        return self.generateFullSnapshotWithCompressor(zstd_compressor, zstd_buffer, params);
    }

    pub fn generateFullSnapshotWithCompressor(
        self: *Self,
        zstd_compressor: zstd.Compressor,
        zstd_buffer: []u8,
        params: FullSnapshotGenParams,
    ) !GenerateFullSnapshotResult {
        // NOTE: we hold the lock for the rest of the duration of the procedure to ensure
        // flush and clean do not create files while generating a snapshot.
        self.file_map_fd_rw.lockShared();
        defer self.file_map_fd_rw.unlockShared();

        const file_map, var file_map_lg = self.file_map.readWithLock();
        defer file_map_lg.unlock();

        // lock this now such that, if under any circumstance this method was invoked twice in parallel
        // on separate threads, there wouldn't be any overlapping work being done.
        const p_maybe_latest_snapshot_info: *?SnapshotGenerationInfo, var latest_snapshot_info_lg = self.latest_snapshot_info.writeWithLock();
        defer latest_snapshot_info_lg.unlock();

        std.debug.assert(zstd_buffer.len != 0);
        std.debug.assert(params.target_slot <= self.largest_flushed_slot.load(.monotonic));

        const full_hash, const full_capitalization = compute: {
            check_first: {
                const p_maybe_first, var first_lg = self.first_snapshot_load_info.readWithLock();
                defer first_lg.unlock();

                const first = p_maybe_first.* orelse break :check_first;
                if (first.full.slot != params.target_slot) break :check_first;

                break :compute .{ first.full.hash, first.full.capitalization };
            }

            break :compute try self.computeAccountHashesAndLamports(.{
                .FullAccountHash = .{
                    .max_slot = params.target_slot,
                },
            });
        };

        // TODO: this is a temporary value
        const delta_hash = Hash.ZEROES;

        const archive_file = blk: {
            const archive_file_name_bounded = sig.accounts_db.snapshots.FullSnapshotFileInfo.snapshotNameStr(.{
                .slot = params.target_slot,
                .hash = full_hash,
                .compression = .zstd,
            });
            const archive_file_name = archive_file_name_bounded.constSlice();
            self.logger.info().logf("Generating full snapshot '{s}' (full path: {s}).", .{
                archive_file_name, sig.utils.fmt.tryRealPath(self.snapshot_dir, archive_file_name),
            });
            break :blk try self.snapshot_dir.createFile(archive_file_name, .{ .read = true });
        };
        defer archive_file.close();

        const SerializableFileMap = std.AutoArrayHashMap(Slot, AccountFileInfo);

        var serializable_file_map = SerializableFileMap.init(self.allocator);
        defer serializable_file_map.deinit();
        var bank_hash_stats = BankHashStats.zero_init;

        // collect account files into serializable_file_map and compute bank_hash_stats
        try serializable_file_map.ensureTotalCapacity(file_map.count());
        for (file_map.values()) |account_file| {
            if (account_file.slot > params.target_slot) continue;

            const bank_hash_stats_map, var bank_hash_stats_map_lg = self.bank_hash_stats.readWithLock();
            defer bank_hash_stats_map_lg.unlock();

            if (bank_hash_stats_map.get(account_file.slot)) |other_stats| {
                bank_hash_stats.accumulate(other_stats);
            } else {
                self.logger.warn().logf("No bank hash stats for slot {}.", .{account_file.slot});
            }

            serializable_file_map.putAssumeCapacityNoClobber(account_file.slot, .{
                .id = account_file.id,
                .length = account_file.length,
            });
        }

        params.bank_fields.slot = params.target_slot; // !
        params.bank_fields.capitalization = full_capitalization; // !

        const snapshot_fields: SnapshotFields = .{
            .bank_fields = params.bank_fields.*,
            .accounts_db_fields = .{
                .file_map = serializable_file_map,
                .stored_meta_write_version = params.deprecated_stored_meta_write_version,
                .slot = params.target_slot,
                .bank_hash_info = .{
                    .accounts_delta_hash = delta_hash,
                    .accounts_hash = full_hash,
                    .stats = bank_hash_stats,
                },
                .rooted_slots = .{},
                .rooted_slot_hashes = .{},
            },
            .lamports_per_signature = params.lamports_per_signature,
            .bank_fields_inc = .{}, // default to null for full snapshot,
        };

        // main snapshot writing logic
        // writer() data flow: tar -> zstd -> archive_file
        const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, zstd_buffer);
        try writeSnapshotTarWithFields(
            zstd_write_ctx.writer(),
            sig.version.CURRENT_CLIENT_VERSION,
            StatusCache.default(),
            &snapshot_fields,
            file_map,
        );
        try zstd_write_ctx.finish();

        // update tracking for new snapshot

        if (p_maybe_latest_snapshot_info.*) |old_snapshot_info| {
            std.debug.assert(old_snapshot_info.full.slot <= params.target_slot);

            switch (params.old_snapshot_action) {
                .ignore_old => {},
                .delete_old => {
                    const full = old_snapshot_info.full;
                    try self.deleteOldSnapshotFile(.full, .{
                        .slot = full.slot,
                        .hash = full.hash,
                    });
                    if (old_snapshot_info.inc) |inc| {
                        try self.deleteOldSnapshotFile(.incremental, .{
                            .base_slot = old_snapshot_info.full.slot,
                            .slot = inc.slot,
                            .hash = inc.hash,
                        });
                    }
                },
            }
        }

        p_maybe_latest_snapshot_info.* = .{
            .full = .{
                .slot = params.target_slot,
                .hash = full_hash,
                .capitalization = full_capitalization,
            },
            .inc = null,
        };

        return .{
            .hash = full_hash,
            .capitalization = full_capitalization,
        };
    }

    pub const IncSnapshotGenParams = struct {
        /// The slot to generate a snapshot for.
        /// Must be a flushed slot (`<= self.largest_flushed_slot.load(...)`).
        /// Must be greater than the most recently generated full snapshot.
        /// Must exist explicitly in the database.
        target_slot: Slot,
        /// Mutated (without re-allocation) to be valid for the target slot.
        bank_fields: *BankFields,
        lamports_per_signature: u64,
        old_snapshot_action: OldSnapshotAction,

        /// For tests against older snapshots. Should just be 0 during normal operation.
        deprecated_stored_meta_write_version: u64 = 0,
    };

    pub const GenerateIncSnapshotResult = BankIncrementalSnapshotPersistence;

    pub fn generateIncrementalSnapshot(
        self: *Self,
        params: IncSnapshotGenParams,
    ) !GenerateIncSnapshotResult {
        const zstd_compressor = try zstd.Compressor.init(.{});
        defer zstd_compressor.deinit();

        var zstd_sfba_state = std.heap.stackFallback(4096 * 4, self.allocator);
        const zstd_sfba = zstd_sfba_state.get();
        const zstd_buffer = try zstd_sfba.alloc(u8, zstd.Compressor.recommOutSize());
        defer zstd_sfba.free(zstd_buffer);

        return self.generateIncrementalSnapshotWithCompressor(zstd_compressor, zstd_buffer, params);
    }

    pub fn generateIncrementalSnapshotWithCompressor(
        self: *Self,
        zstd_compressor: zstd.Compressor,
        zstd_buffer: []u8,
        params: IncSnapshotGenParams,
    ) !GenerateIncSnapshotResult {
        // NOTE: we hold the lock for the rest of the duration of the procedure to ensure
        // flush and clean do not create files while generating a snapshot.
        self.file_map_fd_rw.lockShared();
        defer self.file_map_fd_rw.unlockShared();

        const file_map, var file_map_lg = self.file_map.readWithLock();
        defer file_map_lg.unlock();

        // we need to hold a lock on the full & incremental snapshot for the duration of the function
        // to ensure we could never race if this method was invoked in parallel on different threads.
        const latest_snapshot_info, var latest_snapshot_info_lg = blk: {
            const p_maybe_latest_snapshot_info, var latest_snapshot_info_lg = self.latest_snapshot_info.writeWithLock();
            errdefer latest_snapshot_info_lg.unlock();
            break :blk .{
                &(p_maybe_latest_snapshot_info.* orelse return error.NoFullSnapshotExists),
                latest_snapshot_info_lg,
            };
        };
        defer latest_snapshot_info_lg.unlock();

        const full_snapshot_info = latest_snapshot_info.full;

        const incremental_hash, //
        const incremental_capitalization //
        = compute: {
            check_first: {
                const p_maybe_first, var first_lg = self.first_snapshot_load_info.readWithLock();
                defer first_lg.unlock();

                const first = p_maybe_first.* orelse break :check_first;
                const first_inc = first.inc orelse break :check_first;
                if (first.full.slot != full_snapshot_info.slot) break :check_first;
                if (first_inc.slot != params.target_slot) break :check_first;

                break :compute .{ first_inc.hash, first_inc.capitalization };
            }

            break :compute try self.computeAccountHashesAndLamports(.{
                .IncrementalAccountHash = .{
                    .min_slot = full_snapshot_info.slot,
                    .max_slot = params.target_slot,
                },
            });
        };

        // TODO: compute the correct value during account writes
        const delta_hash = Hash.ZEROES;

        const archive_file = blk: {
            const archive_file_name_bounded = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo.snapshotNameStr(.{
                .base_slot = full_snapshot_info.slot,
                .slot = params.target_slot,
                .hash = incremental_hash,
                .compression = .zstd,
            });
            const archive_file_name = archive_file_name_bounded.constSlice();
            self.logger.info().logf("Generating incremental snapshot '{s}' (full path: {s}).", .{
                archive_file_name, sig.utils.fmt.tryRealPath(self.snapshot_dir, archive_file_name),
            });
            break :blk try self.snapshot_dir.createFile(archive_file_name, .{ .read = true });
        };
        defer archive_file.close();

        const SerializableFileMap = std.AutoArrayHashMap(Slot, AccountFileInfo);

        var serializable_file_map: SerializableFileMap, //
        const bank_hash_stats: BankHashStats //
        = blk: {
            var serializable_file_map = SerializableFileMap.init(self.allocator);
            errdefer serializable_file_map.deinit();
            try serializable_file_map.ensureTotalCapacity(file_map.count());

            var bank_hash_stats = BankHashStats.zero_init;
            for (file_map.values()) |account_file| {
                if (account_file.slot <= full_snapshot_info.slot) continue;
                if (account_file.slot > params.target_slot) continue;

                const bank_hash_stats_map, var bank_hash_stats_map_lg = self.bank_hash_stats.readWithLock();
                defer bank_hash_stats_map_lg.unlock();

                if (bank_hash_stats_map.get(account_file.slot)) |other_stats| {
                    bank_hash_stats.accumulate(other_stats);
                } else {
                    self.logger.warn().logf("No bank hash stats for slot {}.", .{account_file.slot});
                }

                serializable_file_map.putAssumeCapacityNoClobber(account_file.slot, .{
                    .id = account_file.id,
                    .length = account_file.length,
                });
            }

            break :blk .{ serializable_file_map, bank_hash_stats };
        };
        defer serializable_file_map.deinit();

        const snap_persistence: BankIncrementalSnapshotPersistence = .{
            .full_slot = full_snapshot_info.slot,
            .full_hash = full_snapshot_info.hash,
            .full_capitalization = full_snapshot_info.capitalization,
            .incremental_hash = incremental_hash,
            .incremental_capitalization = incremental_capitalization,
        };

        params.bank_fields.slot = params.target_slot; // !

        const snapshot_fields: SnapshotFields = .{
            .bank_fields = params.bank_fields.*,
            .accounts_db_fields = .{
                .file_map = serializable_file_map,
                .stored_meta_write_version = params.deprecated_stored_meta_write_version,
                .slot = params.target_slot,
                .bank_hash_info = .{
                    .accounts_delta_hash = delta_hash,
                    .accounts_hash = Hash.ZEROES,
                    .stats = bank_hash_stats,
                },
                .rooted_slots = .{},
                .rooted_slot_hashes = .{},
            },
            .lamports_per_signature = params.lamports_per_signature,
            .bank_fields_inc = .{
                .snapshot_persistence = snap_persistence,
                // TODO: the other fields default to null, but this may not always be correct.
            },
        };

        // main snapshot writing logic
        // writer() data flow: tar -> zstd -> archive_file
        const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, zstd_buffer);
        try writeSnapshotTarWithFields(
            zstd_write_ctx.writer(),
            sig.version.CURRENT_CLIENT_VERSION,
            StatusCache.default(),
            &snapshot_fields,
            file_map,
        );
        try zstd_write_ctx.finish();

        // update tracking for new snapshot

        if (latest_snapshot_info.inc) |old_inc_snapshot_info| {
            std.debug.assert(old_inc_snapshot_info.slot <= params.target_slot);

            switch (params.old_snapshot_action) {
                .ignore_old => {},
                .delete_old => try self.deleteOldSnapshotFile(.incremental, .{
                    .base_slot = full_snapshot_info.slot,
                    .slot = old_inc_snapshot_info.slot,
                    .hash = old_inc_snapshot_info.hash,
                }),
            }
        }

        latest_snapshot_info.inc = .{
            .slot = params.target_slot,
            .hash = incremental_hash,
            .capitalization = incremental_capitalization,
        };

        return snap_persistence;
    }

    /// If this is being called using the `latest_snapshot_info`, it is assumed the caller
    /// has a write lock in order to do so.
    fn deleteOldSnapshotFile(
        self: *Self,
        comptime kind: enum { full, incremental },
        snapshot_name_info: switch (kind) {
            .full => sig.accounts_db.snapshots.FullSnapshotFileInfo,
            .incremental => sig.accounts_db.snapshots.IncrementalSnapshotFileInfo,
        },
    ) std.fs.Dir.DeleteFileError!void {
        const file_name_bounded = snapshot_name_info.snapshotNameStr();
        const file_name = file_name_bounded.constSlice();
        self.logger.info().logf("deleting old " ++ @tagName(kind) ++ " snapshot archive: {s}", .{file_name});
        try self.snapshot_dir.deleteFile(file_name);
    }

    inline fn lessThanIf(
        slot: Slot,
        max_slot: ?Slot,
    ) bool {
        if (max_slot) |max| {
            if (slot <= max) {
                return true;
            } else {
                return false;
            }
        } else {
            return true;
        }
    }

    inline fn greaterThanIf(
        slot: Slot,
        min_slot: ?Slot,
    ) bool {
        if (min_slot) |min| {
            if (slot > min) {
                return true;
            } else {
                return false;
            }
        } else {
            return true;
        }
    }

    inline fn inBoundsIf(
        slot: Slot,
        min_slot: ?Slot,
        max_slot: ?Slot,
    ) bool {
        return lessThanIf(slot, max_slot) and greaterThanIf(slot, min_slot);
    }
};

pub const AccountsDBMetrics = struct {
    number_files_flushed: *Counter,
    number_files_cleaned: *Counter,
    number_files_shrunk: *Counter,
    number_files_deleted: *Counter,

    time_flush: *Histogram,
    time_clean: *Histogram,
    time_shrink: *Histogram,
    time_purge: *Histogram,

    flush_account_file_size: *Histogram,
    flush_accounts_written: *Counter,

    clean_references_deleted: *Gauge(u64),
    clean_files_queued_deletion: *Gauge(u64),
    clean_files_queued_shrink: *Gauge(u64),
    clean_slot_old_state: *Gauge(u64),
    clean_slot_zero_lamports: *Gauge(u64),

    shrink_file_shrunk_by: *Histogram,
    shrink_alive_accounts: *Histogram,
    shrink_dead_accounts: *Histogram,

    const Self = @This();

    pub fn init() GetMetricError!Self {
        return globalRegistry().initStruct(Self);
    }

    pub fn histogramBucketsForField(comptime field_name: []const u8) []const f64 {
        const HistogramKind = enum {
            flush_account_file_size,
            shrink_file_shrunk_by,
            shrink_alive_accounts,
            shrink_dead_accounts,
            time_flush,
            time_clean,
            time_shrink,
            time_purge,
        };

        const account_size_buckets = &.{
            // 10 bytes -> 10MB (solana max account size)
            10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000,
        };
        const account_count_buckets = &.{ 1, 5, 10, 50, 100, 500, 1_000, 10_000 };
        const nanosecond_buckets = &.{
            // 0.01ms -> 10ms
            1_000,      10_000,      100_000,     1_000_000,   10_000_000,
            // 50ms -> 1000ms
            50_000_000, 100_000_000, 200_000_000, 400_000_000, 1_000_000_000,
        };

        return switch (@field(HistogramKind, field_name)) {
            .flush_account_file_size, .shrink_file_shrunk_by => account_size_buckets,
            .shrink_alive_accounts, .shrink_dead_accounts => account_count_buckets,
            .time_flush, .time_clean, .time_shrink, .time_purge => nanosecond_buckets,
        };
    }
};

/// this is used when loading from a snapshot. it uses a fixed buffer allocator
/// to allocate memory which is used to clone account data slices of account files.
/// the memory is serialized into bincode and sent through the pipe.
/// after this, the memory is freed and re-used for the next account file/slot's data.
pub const GeyserTmpStorage = struct {
    accounts: ArrayList(Account),
    pubkeys: ArrayList(Pubkey),

    const Self = @This();

    pub const Error = error{
        OutOfGeyserFBAMemory,
        OutOfGeyserArrayMemory,
    };

    pub fn init(allocator: std.mem.Allocator, n_accounts_estimate: usize) !Self {
        return .{
            .accounts = try ArrayList(Account).initCapacity(allocator, n_accounts_estimate),
            .pubkeys = try ArrayList(Pubkey).initCapacity(allocator, n_accounts_estimate),
        };
    }

    pub fn deinit(self: *Self) void {
        self.accounts.deinit();
        self.pubkeys.deinit();
    }

    pub fn reset(self: *Self) void {
        self.accounts.clearRetainingCapacity();
        self.pubkeys.clearRetainingCapacity();
    }

    pub fn cloneAndTrack(self: *Self, account_in_file: AccountInFile) Error!void {
        // NOTE: this works because we mmap the account files - this will not work once we remove mmaps
        const account = account_in_file.toAccount();

        self.accounts.append(account) catch return Error.OutOfGeyserArrayMemory;
        self.pubkeys.append(account_in_file.pubkey().*) catch return Error.OutOfGeyserArrayMemory;
    }
};

pub const ValidateAccountFileError = error{
    ShardCountMismatch,
    InvalidAccountFileLength,
    OutOfMemory,
} || AccountInFile.ValidateError || GeyserTmpStorage.Error;

pub fn indexAndValidateAccountFile(
    accounts_file: *AccountFile,
    shard_calculator: PubkeyShardCalculator,
    shard_counts: []usize,
    account_refs: *ArrayList(AccountRef),
    geyser_storage: ?*GeyserTmpStorage,
) ValidateAccountFileError!void {
    var offset: usize = 0;
    var number_of_accounts: usize = 0;

    if (shard_counts.len != shard_calculator.n_shards) {
        return error.ShardCountMismatch;
    }

    while (true) {
        const account = accounts_file.readAccount(offset) catch break;
        try account.validate();

        if (geyser_storage) |storage| {
            try storage.cloneAndTrack(account);
        }

        try account_refs.append(.{
            .pubkey = account.store_info.pubkey,
            .slot = accounts_file.slot,
            .location = .{
                .File = .{
                    .file_id = accounts_file.id,
                    .offset = offset,
                },
            },
        });

        const pubkey = &account.store_info.pubkey;
        shard_counts[shard_calculator.index(pubkey)] += 1;
        offset = offset + account.len;
        number_of_accounts += 1;
    }

    const aligned_length = std.mem.alignForward(usize, accounts_file.length, @sizeOf(u64));
    if (offset != aligned_length) {
        return error.InvalidAccountFileLength;
    }

    accounts_file.number_of_accounts = number_of_accounts;
}

/// allocator which counts the number of times free is called. when count
/// reaches 0, it will deinit the full arraylist. useful for when you want
/// to allocate a large Arraylist and split it across multiple different
/// ArrayLists -- alloc and resize are not implemented.
///
/// see `loadAndVerifyAccountsFiles` for an example of how to use this allocator
const FreeCounterAllocator = struct {
    /// optional heap allocator to deinit the ptr on deinit
    self_allocator: std.mem.Allocator,
    references: ArrayList(AccountRef),
    count: usize,

    const Self = @This();

    pub fn init(self_allocator: std.mem.Allocator, references: ArrayList(AccountRef)) !*Self {
        const self = try self_allocator.create(Self);
        self.* = .{
            .self_allocator = self_allocator,
            .references = references,
            .count = 0,
        };
        return self;
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return std.mem.Allocator{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    pub fn deinitIfSafe(self: *Self) void {
        if (self.count == 0) {
            self.deinit();
        }
    }

    pub fn deinit(self: *Self) void {
        // this shouldnt happen often but just in case
        if (self.count != 0) {
            std.debug.print(
                "Reference Counting Allocator deinit with count = {} (!= 0)\n",
                .{self.count},
            );
        }
        self.references.deinit();
        // free pointer
        self.self_allocator.destroy(self);
    }

    pub fn alloc(ctx: *anyopaque, n: usize, log2_align: u8, return_address: usize) ?[*]u8 {
        _ = ctx;
        _ = n;
        _ = log2_align;
        _ = return_address;
        @panic("not implemented");
    }

    pub fn resize(ctx: *anyopaque, buf: []u8, log2_align: u8, new_len: usize, return_address: usize) bool {
        _ = ctx;
        _ = buf;
        _ = log2_align;
        _ = new_len;
        _ = return_address;
        @panic("not implemented");
    }

    pub fn free(ctx: *anyopaque, buf: []u8, log2_align: u8, return_address: usize) void {
        _ = buf;
        _ = log2_align;
        _ = return_address;

        const self: *Self = @ptrCast(@alignCast(ctx));
        self.count -|= 1;
        self.deinitIfSafe();
    }
};

/// All entries in `snapshot_fields.accounts_db_fields.file_map` must correspond to an entry in `file_map`,
/// with the association defined by the file id (a field of the value of the former, the key of the latter).
pub fn writeSnapshotTarWithFields(
    archive_writer: anytype,
    version: sig.version.ClientVersion,
    status_cache: StatusCache,
    manifest: *const SnapshotFields,
    file_map: *const AccountsDB.FileMap,
) !void {
    try snapgen.writeMetadataFiles(archive_writer, version, status_cache, manifest);

    try snapgen.writeAccountsDirHeader(archive_writer);
    const file_info_map = manifest.accounts_db_fields.file_map;
    for (file_info_map.keys(), file_info_map.values()) |file_slot, file_info| {
        const account_file = file_map.getPtr(file_info.id) orelse unreachable;
        std.debug.assert(account_file.id == file_info.id);

        try snapgen.writeAccountFileHeader(archive_writer, file_slot, file_info);
        try archive_writer.writeAll(account_file.memory);
        try snapgen.writeAccountFilePadding(archive_writer, file_info.length);
    }

    try archive_writer.writeAll(&sig.utils.tar.sentinel_blocks);
}

fn testWriteSnapshotFull(
    allocator: std.mem.Allocator,
    accounts_db: *AccountsDB,
    slot: Slot,
    maybe_expected_hash: ?Hash,
) !void {
    const snapshot_dir = accounts_db.snapshot_dir;

    const manifest_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{slot});
    const manifest_file = try snapshot_dir.openFile(manifest_path_bounded.constSlice(), .{});
    defer manifest_file.close();

    var snap_fields = try SnapshotFields.decodeFromBincode(allocator, manifest_file.reader());
    defer snap_fields.deinit(allocator);

    _ = try accounts_db.loadFromSnapshot(snap_fields.accounts_db_fields, 1, allocator, 1_500);

    const snapshot_gen_info = try accounts_db.generateFullSnapshot(.{
        .target_slot = slot,
        .bank_fields = &snap_fields.bank_fields,
        .lamports_per_signature = snap_fields.lamports_per_signature,
        .old_snapshot_action = .ignore_old,
        .deprecated_stored_meta_write_version = snap_fields.accounts_db_fields.stored_meta_write_version,
    });

    if (maybe_expected_hash) |expected_hash| {
        try std.testing.expectEqual(expected_hash, snapshot_gen_info.hash);
    }

    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = slot,
        .expected_full = .{
            .capitalization = snapshot_gen_info.capitalization,
            .accounts_hash = snapshot_gen_info.hash,
        },
        .expected_incremental = null,
    });
}

fn testWriteSnapshotIncremental(
    allocator: std.mem.Allocator,
    accounts_db: *AccountsDB,
    slot: Slot,
    maybe_expected_incremental_hash: ?Hash,
) !void {
    const snapshot_dir = accounts_db.snapshot_dir;

    const manifest_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{slot});
    const manifest_file = try snapshot_dir.openFile(manifest_path_bounded.constSlice(), .{});
    defer manifest_file.close();

    var snap_fields = try SnapshotFields.decodeFromBincode(allocator, manifest_file.reader());
    defer snap_fields.deinit(allocator);

    _ = try accounts_db.loadFromSnapshot(snap_fields.accounts_db_fields, 1, allocator, 1_500);

    const snapshot_gen_info = try accounts_db.generateIncrementalSnapshot(.{
        .target_slot = slot,
        .bank_fields = &snap_fields.bank_fields,
        .lamports_per_signature = snap_fields.lamports_per_signature,
        .old_snapshot_action = .delete_old,
        .deprecated_stored_meta_write_version = snap_fields.accounts_db_fields.stored_meta_write_version,
    });

    if (maybe_expected_incremental_hash) |expected_hash| {
        try std.testing.expectEqual(expected_hash, snapshot_gen_info.incremental_hash);
    }

    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = snapshot_gen_info.full_slot,
        .expected_full = .{
            .capitalization = snapshot_gen_info.full_capitalization,
            .accounts_hash = snapshot_gen_info.full_hash,
        },
        .expected_incremental = .{
            .accounts_hash = snapshot_gen_info.incremental_hash,
            .capitalization = snapshot_gen_info.incremental_capitalization,
        },
    });
}

test "testWriteSnapshot" {
    const allocator = std.testing.allocator;
    var test_data_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer test_data_dir.close();

    const snap_files = try SnapshotFiles.find(allocator, test_data_dir);

    var tmp_snap_dir_root = std.testing.tmpDir(.{});
    defer tmp_snap_dir_root.cleanup();
    const tmp_snap_dir = tmp_snap_dir_root.dir;

    {
        const archive_file = try test_data_dir.openFile(snap_files.full_snapshot.snapshotNameStr().constSlice(), .{});
        defer archive_file.close();
        try parallelUnpackZstdTarBall(allocator, .noop, archive_file, tmp_snap_dir, 4, true);
    }

    if (snap_files.incremental_snapshot) |inc_snap| {
        const archive_file = try test_data_dir.openFile(inc_snap.snapshotNameStr().constSlice(), .{});
        defer archive_file.close();
        try parallelUnpackZstdTarBall(allocator, .noop, archive_file, tmp_snap_dir, 4, false);
    }

    var accounts_db = try AccountsDB.init(allocator, .noop, tmp_snap_dir, .{
        .number_of_index_shards = ACCOUNT_INDEX_SHARDS,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit();

    try testWriteSnapshotFull(
        allocator,
        &accounts_db,
        snap_files.full_snapshot.slot,
        snap_files.full_snapshot.hash,
    );
    try testWriteSnapshotIncremental(
        allocator,
        &accounts_db,
        snap_files.incremental_snapshot.?.slot,
        snap_files.incremental_snapshot.?.hash,
    );
}

fn unpackTestSnapshot(allocator: std.mem.Allocator, n_threads: usize) !void {
    std.debug.assert(builtin.is_test); // should only be used in tests

    var dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer dir.close();

    { // unpack both snapshots to get the acccount files
        const full_archive = try dir.openFile("snapshot-10-6ExseAZAVJsAZjhimxHTR7N8p6VGXiDNdsajYh1ipjAD.tar.zst", .{});
        defer full_archive.close();

        const inc_archive = try dir.openFile("incremental-snapshot-10-25-GXgKvm3NMAPgGdv2verVaNXmKTHQgfy2TAxLVEfAvdCS.tar.zst", .{});
        defer inc_archive.close();

        try parallelUnpackZstdTarBall(
            allocator,
            .noop,
            full_archive,
            dir,
            n_threads,
            true,
        );
        try parallelUnpackZstdTarBall(
            allocator,
            .noop,
            inc_archive,
            dir,
            n_threads,
            true,
        );
    }
}

fn loadTestAccountsDB(allocator: std.mem.Allocator, use_disk: bool, n_threads: u32) !struct { AccountsDB, AllSnapshotFields } {
    std.debug.assert(builtin.is_test); // should only be used in tests

    var dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer dir.close();

    try unpackTestSnapshot(allocator, n_threads);

    const snapshot_files = try SnapshotFiles.find(allocator, dir);

    const logger = .noop;

    var snapshots = try AllSnapshotFields.fromFiles(allocator, logger, dir, snapshot_files);
    errdefer snapshots.deinit(allocator);

    const snapshot = try snapshots.collapse();
    var accounts_db = try AccountsDB.init(allocator, logger, dir, .{
        .number_of_index_shards = 4,
        .use_disk_index = use_disk,
    }, null);
    errdefer accounts_db.deinit();

    _ = try accounts_db.loadFromSnapshot(snapshot.accounts_db_fields, n_threads, allocator, 500);

    return .{ accounts_db, snapshots };
}

// NOTE: this is a memory leak test - geyser correctness is tested in the geyser tests
test "geyser stream on load" {
    const allocator = std.testing.allocator;

    var dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer dir.close();
    try unpackTestSnapshot(allocator, 2);

    const snapshot_files = try SnapshotFiles.find(allocator, dir);

    const logger = .noop;

    var snapshots = try AllSnapshotFields.fromFiles(allocator, logger, dir, snapshot_files);
    errdefer snapshots.deinit(allocator);

    const geyser_pipe_path = sig.TEST_DATA_DIR ++ "geyser.pipe";
    var geyser_writer: ?*GeyserWriter = null;

    const geyser_exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(geyser_exit);
    geyser_exit.* = std.atomic.Value(bool).init(false);

    geyser_writer = try allocator.create(GeyserWriter);
    geyser_writer.?.* = try GeyserWriter.init(
        allocator,
        geyser_pipe_path,
        geyser_exit,
        1 << 20,
    );
    defer {
        if (geyser_writer) |writer| {
            writer.deinit();
            allocator.destroy(writer);
        }
    }

    // start the geyser writer
    try geyser_writer.?.spawnIOLoop();

    const reader_handle = try std.Thread.spawn(.{}, sig.geyser.core.streamReader, .{
        allocator,
        geyser_exit,
        geyser_pipe_path,
        null,
        null,
    });
    defer {
        geyser_exit.store(true, .release);
        _ = reader_handle.join();
    }

    const snapshot = try snapshots.collapse();
    var accounts_db = try AccountsDB.init(
        allocator,
        logger,
        dir,
        .{
            .number_of_index_shards = 4,
            .use_disk_index = false,
        },
        geyser_writer,
    );
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    _ = try accounts_db.loadFromSnapshot(
        snapshot.accounts_db_fields,
        1,
        allocator,
        1_500,
    );
}

test "write and read an account" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(allocator, false, 1);
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    var prng = std.rand.DefaultPrng.init(0);
    const pubkey = Pubkey.initRandom(prng.random());
    var data = [_]u8{ 1, 2, 3 };
    const test_account = Account{
        .data = &data,
        .executable = false,
        .lamports = 100,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    };

    // initial account
    var accounts = [_]Account{test_account};
    var pubkeys = [_]Pubkey{pubkey};
    try accounts_db.putAccountSlice(&accounts, &pubkeys, 19);

    var account = try accounts_db.getAccount(&pubkey);
    defer account.deinit(allocator);
    try std.testing.expect(test_account.equals(&account));

    // new account
    accounts[0].lamports = 20;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, 28);
    var account_2 = try accounts_db.getAccount(&pubkey);
    defer account_2.deinit(allocator);
    try std.testing.expect(accounts[0].equals(&account_2));
}

test "load and validate from test snapshot" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(allocator, false, 1);
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = snapshots.full.bank_fields.slot,
        .expected_full = .{
            .accounts_hash = snapshots.full.accounts_db_fields.bank_hash_info.accounts_hash,
            .capitalization = snapshots.full.bank_fields.capitalization,
        },
        .expected_incremental = if (snapshots.incremental.?.bank_fields_inc.snapshot_persistence) |inc_persistence| .{
            .accounts_hash = inc_persistence.incremental_hash,
            .capitalization = inc_persistence.incremental_capitalization,
        } else null,
    });
}

test "load and validate from test snapshot using disk index" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(allocator, false, 1);
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = snapshots.full.bank_fields.slot,
        .expected_full = .{
            .accounts_hash = snapshots.full.accounts_db_fields.bank_hash_info.accounts_hash,
            .capitalization = snapshots.full.bank_fields.capitalization,
        },
        .expected_incremental = if (snapshots.incremental.?.bank_fields_inc.snapshot_persistence) |inc_persistence| .{
            .accounts_hash = inc_persistence.incremental_hash,
            .capitalization = inc_persistence.incremental_capitalization,
        } else null,
    });
}

test "load and validate from test snapshot parallel" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(allocator, false, 2);
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = snapshots.full.bank_fields.slot,
        .expected_full = .{
            .accounts_hash = snapshots.full.accounts_db_fields.bank_hash_info.accounts_hash,
            .capitalization = snapshots.full.bank_fields.capitalization,
        },
        .expected_incremental = if (snapshots.incremental.?.bank_fields_inc.snapshot_persistence) |inc_persistence| .{
            .accounts_hash = inc_persistence.incremental_hash,
            .capitalization = inc_persistence.incremental_capitalization,
        } else null,
    });
}

test "load clock sysvar" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(allocator, false, 1);
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    const clock = try accounts_db.getTypeFromAccount(sysvars.Clock, &sysvars.IDS.clock);
    const expected_clock = sysvars.Clock{
        .slot = 25,
        .epoch_start_timestamp = 1702587901,
        .epoch = 0,
        .leader_schedule_epoch = 1,
        .unix_timestamp = 1702587915,
    };
    try std.testing.expectEqual(clock, expected_clock);
}

test "load other sysvars" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(allocator, false, 1);
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    const SlotAndHash = @import("./snapshots.zig").SlotAndHash;
    _ = try accounts_db.getTypeFromAccount(sysvars.EpochSchedule, &sysvars.IDS.epoch_schedule);
    _ = try accounts_db.getTypeFromAccount(sysvars.Rent, &sysvars.IDS.rent);
    _ = try accounts_db.getTypeFromAccount(SlotAndHash, &sysvars.IDS.slot_hashes);
    _ = try accounts_db.getTypeFromAccount(sysvars.StakeHistory, &sysvars.IDS.stake_history);

    const slot_history = try accounts_db.getTypeFromAccount(sysvars.SlotHistory, &sysvars.IDS.slot_history);
    defer bincode.free(allocator, slot_history);

    // // not always included in local snapshot
    // _ = try accounts_db.getTypeFromAccount(sysvars.LastRestartSlot, &sysvars.IDS.last_restart_slot);
    // _ = try accounts_db.getTypeFromAccount(sysvars.EpochRewards, &sysvars.IDS.epoch_rewards);
}

test "flushing slots works" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_shards = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit();

    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();
    const n_accounts = 3;

    // we dont defer deinit to make sure that they are cleared on purge
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts) |account| account.deinit(allocator);

    // this gets written to cache
    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // this writes to disk
    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();
    try unclean_account_files.append(try accounts_db.flushSlot(slot));

    accounts_db.file_map_fd_rw.lock();
    defer accounts_db.file_map_fd_rw.unlock();

    // try the validation
    const file_map, var file_map_lg = accounts_db.file_map.readWithLock();
    defer file_map_lg.unlock();

    const file_id = file_map.keys()[0];

    const account_file = file_map.getPtr(file_id).?;
    account_file.number_of_accounts = try account_file.validate();

    try std.testing.expect(account_file.number_of_accounts == n_accounts);
    try std.testing.expect(unclean_account_files.items.len == 1);
    try std.testing.expect(unclean_account_files.items[0] == file_id);
}

test "purge accounts in cache works" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_shards = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit();

    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();
    const n_accounts = 3;

    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;

    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const pubkey_copy: [n_accounts]Pubkey = pubkeys;

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    for (0..n_accounts) |i| {
        _, var lg = accounts_db.account_index.pubkey_ref_map.getRead(&pubkeys[i]) orelse return error.TestUnexpectedNull;
        lg.unlock();
    }

    accounts_db.purgeSlot(slot);

    // ref backing memory is cleared
    {
        const slot_reference_map, var slot_reference_map_lg = accounts_db.account_index.slot_reference_map.readWithLock();
        defer slot_reference_map_lg.unlock();

        try std.testing.expect(slot_reference_map.count() == 0);
    }
    // account cache is cleared
    {
        var lg = accounts_db.unrooted_accounts.read();
        defer lg.unlock();
        try std.testing.expect(lg.get().count() == 0);
    }

    // ref hashmap is cleared
    for (0..n_accounts) |i| {
        try std.testing.expect(accounts_db.account_index.pubkey_ref_map.getRead(&pubkey_copy[i]) == null);
    }
}

test "clean to shrink account file works with zero-lamports" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_shards = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit();

    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();
    const n_accounts = 10;

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, 100);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // test to make sure we can still read it
    const pubkey_remain = pubkeys[pubkeys.len - 1];

    // duplicate some before the flush/deinit
    const new_len = n_accounts - 1; // one new root with zero lamports
    var pubkeys2: [new_len]Pubkey = undefined;
    var accounts2: [new_len]Account = undefined;
    @memcpy(&pubkeys2, pubkeys[0..new_len]);
    for (&accounts2, 0..) |*account, i| {
        errdefer for (accounts2[0..i]) |prev_account| prev_account.deinit(allocator);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
        account.lamports = 0; // !
    }
    defer for (accounts2) |account| account.deinit(allocator);

    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();

    try unclean_account_files.append(try accounts_db.flushSlot(slot));

    // write new state
    const new_slot: u64 = 500;
    try accounts_db.putAccountSlice(&accounts2, &pubkeys2, new_slot);
    try unclean_account_files.append(try accounts_db.flushSlot(new_slot));

    var shrink_account_files = std.AutoArrayHashMap(FileId, void).init(allocator);
    defer shrink_account_files.deinit();

    var delete_account_files = std.AutoArrayHashMap(FileId, void).init(allocator);
    defer delete_account_files.deinit();

    const r = try accounts_db.cleanAccountFiles(
        new_slot + 100,
        unclean_account_files.items,
        &shrink_account_files,
        &delete_account_files,
    );
    try std.testing.expect(r.num_old_states == new_len);
    try std.testing.expect(r.num_zero_lamports == new_len);
    // shrink
    try std.testing.expectEqual(1, shrink_account_files.count());
    // slot 500 will be fully dead because its all zero lamports
    try std.testing.expectEqual(1, delete_account_files.count());

    var account = try accounts_db.getAccount(&pubkey_remain);
    defer account.deinit(allocator);
}

test "clean to shrink account file works" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_shards = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit();

    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();
    const n_accounts = 10;

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, 100);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // duplicate HALF before the flush/deinit
    const new_len = n_accounts - 1; // 90% delete = shrink
    var pubkeys2: [new_len]Pubkey = undefined;
    var accounts2: [new_len]Account = undefined;
    @memcpy(&pubkeys2, pubkeys[0..new_len]);
    for (&accounts2, 0..) |*account, i| {
        errdefer for (accounts2[0..i]) |prev_account| prev_account.deinit(allocator);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts2) |account| account.deinit(allocator);

    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();

    var shrink_account_files = std.AutoArrayHashMap(FileId, void).init(allocator);
    defer shrink_account_files.deinit();

    var delete_account_files = std.AutoArrayHashMap(FileId, void).init(allocator);
    defer delete_account_files.deinit();

    try unclean_account_files.append(try accounts_db.flushSlot(slot));

    // write new state
    const new_slot: u64 = 500;
    try accounts_db.putAccountSlice(&accounts2, &pubkeys2, new_slot);
    try unclean_account_files.append(try accounts_db.flushSlot(new_slot));

    const r = try accounts_db.cleanAccountFiles(
        new_slot + 100,
        unclean_account_files.items,
        &shrink_account_files,
        &delete_account_files,
    );
    try std.testing.expect(r.num_old_states == new_len);
    try std.testing.expect(r.num_zero_lamports == 0);
    // shrink
    try std.testing.expect(shrink_account_files.count() == 1);
    try std.testing.expect(delete_account_files.count() == 0);
}

test "full clean account file works" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_shards = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit();

    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();
    const n_accounts = 3;

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // duplicate before the flush/deinit
    var pubkeys2: [n_accounts]Pubkey = undefined;
    var accounts2: [n_accounts]Account = undefined;
    @memcpy(&pubkeys2, &pubkeys);
    for (&accounts2, 0..) |*account, i| {
        errdefer for (accounts2[0..i]) |prev_account| prev_account.deinit(allocator);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (&accounts2) |account| account.deinit(allocator);

    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();

    var shrink_account_files = std.AutoArrayHashMap(FileId, void).init(allocator);
    defer shrink_account_files.deinit();

    var delete_account_files = std.AutoArrayHashMap(FileId, void).init(allocator);
    defer delete_account_files.deinit();

    try unclean_account_files.append(try accounts_db.flushSlot(slot));

    var r = try accounts_db.cleanAccountFiles(0, unclean_account_files.items, &shrink_account_files, &delete_account_files); // zero is rooted so no files should be cleaned
    try std.testing.expect(r.num_old_states == 0);
    try std.testing.expect(r.num_zero_lamports == 0);

    r = try accounts_db.cleanAccountFiles(1, unclean_account_files.items, &shrink_account_files, &delete_account_files); // zero has no old state so no files should be cleaned
    try std.testing.expect(r.num_old_states == 0);
    try std.testing.expect(r.num_zero_lamports == 0);

    // write new state
    const new_slot: u64 = 500;
    try accounts_db.putAccountSlice(&accounts2, &pubkeys2, new_slot);
    try unclean_account_files.append(try accounts_db.flushSlot(new_slot));

    r = try accounts_db.cleanAccountFiles(new_slot + 100, unclean_account_files.items, &shrink_account_files, &delete_account_files);
    try std.testing.expect(r.num_old_states == n_accounts);
    try std.testing.expect(r.num_zero_lamports == 0);
    // full delete
    try std.testing.expect(delete_account_files.count() == 1);
    const delete_file_id = delete_account_files.keys()[0];

    // test delete
    {
        const file_map, var file_map_lg = accounts_db.file_map.readWithLock();
        defer file_map_lg.unlock();
        try std.testing.expect(file_map.get(delete_file_id) != null);
    }

    try accounts_db.deleteAccountFiles(delete_account_files.keys());

    {
        const file_map, var file_map_lg = accounts_db.file_map.readWithLock();
        defer file_map_lg.unlock();
        try std.testing.expectEqual(null, file_map.get(delete_file_id));
    }
}

test "shrink account file works" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_shards = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit();

    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    const n_accounts = 10;

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;

    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, 100);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // test to make sure we can still read it
    const pubkey_remain = pubkeys[pubkeys.len - 1];

    // duplicate some before the flush/deinit
    const new_len = n_accounts - 1; // 90% delete = shrink
    var pubkeys2: [new_len]Pubkey = undefined;
    var accounts2: [new_len]Account = undefined;
    @memcpy(&pubkeys2, pubkeys[0..new_len]);
    for (&accounts2, 0..new_len) |*account, i| {
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts2) |account| account.deinit(allocator);

    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();
    var shrink_account_files = std.AutoArrayHashMap(FileId, void).init(allocator);
    defer shrink_account_files.deinit();
    var delete_account_files = std.AutoArrayHashMap(FileId, void).init(allocator);
    defer delete_account_files.deinit();

    try unclean_account_files.append(try accounts_db.flushSlot(slot));

    // write new state
    const new_slot = @as(u64, @intCast(500));
    try accounts_db.putAccountSlice(
        &accounts2,
        &pubkeys2,
        new_slot,
    );
    try unclean_account_files.append(try accounts_db.flushSlot(new_slot));

    // clean the account files - slot is queued for shrink
    const clean_result = try accounts_db.cleanAccountFiles(
        new_slot + 100,
        unclean_account_files.items,
        &shrink_account_files,
        &delete_account_files,
    );
    try std.testing.expect(shrink_account_files.count() == 1);
    try std.testing.expectEqual(9, clean_result.num_old_states);

    const pre_shrink_size = blk: {
        accounts_db.file_map_fd_rw.lockShared();
        defer accounts_db.file_map_fd_rw.unlockShared();

        const file_map, var file_map_lg = accounts_db.file_map.readWithLock();
        defer file_map_lg.unlock();

        const slot_file_id: FileId = for (file_map.keys()) |file_id| {
            const account_file = file_map.get(file_id).?;
            if (account_file.slot == slot) break file_id;
        } else return error.NoSlotFile;
        break :blk file_map.get(slot_file_id).?.file_size;
    };

    // full memory block
    {
        const slot_reference_map, var slot_reference_map_lg = accounts_db.account_index.slot_reference_map.readWithLock();
        defer slot_reference_map_lg.unlock();

        const slot_mem = slot_reference_map.get(new_slot).?;
        try std.testing.expect(slot_mem.items.len == accounts2.len);
    }

    // test: files were shrunk
    const r = try accounts_db.shrinkAccountFiles(
        shrink_account_files.keys(),
        &delete_account_files,
    );
    try std.testing.expectEqual(9, r.num_accounts_deleted);

    // test: new account file is shrunk
    {
        accounts_db.file_map_fd_rw.lockShared();
        defer accounts_db.file_map_fd_rw.unlockShared();

        const file_map2, var file_map_lg2 = accounts_db.file_map.readWithLock();
        defer file_map_lg2.unlock();

        const new_slot_file_id: FileId = blk: {
            var maybe_max_file_id: ?FileId = null;
            for (file_map2.keys(), file_map2.values()) |file_id, account_file| {
                const max_file_id = maybe_max_file_id orelse {
                    if (account_file.slot == slot) {
                        maybe_max_file_id = file_id;
                    }
                    continue;
                };
                if (max_file_id.toInt() > file_id.toInt()) continue;
                if (account_file.slot != slot) continue;
                maybe_max_file_id = file_id;
            }
            break :blk maybe_max_file_id orelse return error.NoSlotFile;
        };

        const new_account_file = file_map2.get(new_slot_file_id).?;
        const post_shrink_size = new_account_file.file_size;
        try std.testing.expect(post_shrink_size < pre_shrink_size);
    }

    // test: memory block is shrunk too
    {
        const slot_reference_map, var slot_reference_map_lg = accounts_db.account_index.slot_reference_map.readWithLock();
        defer slot_reference_map_lg.unlock();

        const slot_mem = slot_reference_map.get(slot).?;
        try std.testing.expectEqual(1, slot_mem.items.len);
    }

    // last account ref should still be accessible
    const account = try accounts_db.getAccount(&pubkey_remain);
    account.deinit(allocator);
}

pub const BenchmarkAccountsDBSnapshotLoad = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 1;

    pub const BenchArgs = struct {
        use_disk: bool,
        n_threads: u32,
        name: []const u8,
    };

    pub const args = [_]BenchArgs{
        BenchArgs{
            .name = "RAM index",
            .use_disk = false,
            .n_threads = 10,
        },
        // BenchArgs{
        //     .use_disk = true,
        //     .n_threads = 2,
        //     .name = "DISK (2 threads)",
        // },
    };

    pub fn loadSnapshot(bench_args: BenchArgs) !sig.time.Duration {
        const allocator = std.heap.c_allocator;

        var std_logger = try StandardErrLogger.init(.{
            .allocator = allocator,
            .max_level = Level.debug,
            .max_buffer = 1 << 20,
        });
        defer std_logger.deinit();

        const logger = std_logger.logger();

        // unpack the snapshot
        // NOTE: usually this will be an incremental snapshot
        // renamed as a full snapshot (mv {inc-snap-fmt}.tar.zstd {full-snap-fmt}.tar.zstd)
        // (because test snapshots are too small and full snapshots are too big)
        const dir_path = sig.TEST_DATA_DIR ++ "bench_snapshot/";
        var snapshot_dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch {
            std.debug.print("need to setup a snapshot in {s} for this benchmark...\n", .{dir_path});
            return sig.time.Duration.fromNanos(0);
        };
        defer snapshot_dir.close();

        const snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);

        var accounts_dir = inline for (0..2) |attempt| {
            if (snapshot_dir.openDir("accounts", .{ .iterate = true })) |accounts_dir|
                break accounts_dir
            else |err| switch (err) {
                else => |e| return e,
                error.FileNotFound => if (attempt == 0) {
                    const archive_file = try snapshot_dir.openFile(snapshot_files.full_snapshot.snapshotNameStr().constSlice(), .{});
                    defer archive_file.close();
                    try parallelUnpackZstdTarBall(
                        allocator,
                        logger,
                        archive_file,
                        snapshot_dir,
                        try std.Thread.getCpuCount() / 2,
                        true,
                    );
                },
            }
        } else return error.SnapshotMissingAccountsDir;
        defer accounts_dir.close();

        var snapshots = try AllSnapshotFields.fromFiles(allocator, logger, snapshot_dir, snapshot_files);
        defer snapshots.deinit(allocator);
        const snapshot = try snapshots.collapse();

        var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
            .number_of_index_shards = 32,
            .use_disk_index = bench_args.use_disk,
        }, null);
        defer accounts_db.deinit();

        const duration = try accounts_db.loadFromSnapshot(
            snapshot.accounts_db_fields,
            bench_args.n_threads,
            allocator,
            1_500,
        );

        // sanity check
        const accounts_hash, const total_lamports = try accounts_db.computeAccountHashesAndLamports(.{
            .FullAccountHash = .{
                .max_slot = accounts_db.largest_rooted_slot.load(.monotonic),
            },
        });
        std.debug.print("r: hash: {}, lamports: {}\n", .{ accounts_hash, total_lamports });

        return duration;
    }
};

pub const BenchmarkAccountsDB = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 1;

    pub const MemoryType = enum {
        ram,
        disk,
    };

    pub const BenchArgs = struct {
        /// the number of accounts to store in the database (for each slot)
        n_accounts: usize,
        /// the number of slots to store (each slot is one batch write)
        slot_list_len: usize,
        /// the accounts memory type (ram (as a ArrayList) or disk (as a file))
        accounts: MemoryType,
        /// the index memory type (ram or disk (disk-memory allocator))
        index: MemoryType,
        /// the number of accounts to prepopulate the index with as a multiple of n_accounts
        /// ie, if n_accounts = 100 and n_accounts_multiple = 10, then the index will have 10x100=1000 accounts prepopulated
        n_accounts_multiple: usize = 0,
        /// the name of the benchmark
        name: []const u8 = "",
    };

    pub const args = [_]BenchArgs{
        BenchArgs{
            .n_accounts = 100_000,
            .slot_list_len = 1,
            .accounts = .ram,
            .index = .ram,
            .name = "100k accounts (1_slot - ram index - ram accounts)",
        },
        BenchArgs{
            .n_accounts = 100_000,
            .slot_list_len = 1,
            .accounts = .ram,
            .index = .disk,
            .name = "100k accounts (1_slot - disk index - ram accounts)",
        },
        BenchArgs{
            .n_accounts = 100_000,
            .slot_list_len = 1,
            .accounts = .disk,
            .index = .ram,
            .name = "100k accounts (1_slot - ram index - disk accounts)",
        },
        BenchArgs{
            .n_accounts = 100_000,
            .slot_list_len = 1,
            .accounts = .disk,
            .index = .disk,
            .name = "100k accounts (1_slot - disk index - disk accounts)",
        },

        // // test accounts in ram
        // BenchArgs{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .ram,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - ram accounts)",
        // },
        // BenchArgs{
        //     .n_accounts = 10_000,
        //     .slot_list_len = 10,
        //     .accounts = .ram,
        //     .index = .ram,
        //     .name = "10k accounts (10_slots - ram index - ram accounts)",
        // },

        // // tests large number of accounts on disk
        // BenchArgs{
        //     .n_accounts = 10_000,
        //     .slot_list_len = 10,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "10k accounts (10_slots - ram index - disk accounts)",
        // },
        // BenchArgs{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "500k accounts (1_slot - ram index - disk accounts)",
        // },
        // BenchArgs{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 3,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "500k accounts (3_slot - ram index - disk accounts)",
        // },
        // BenchArgs{
        //     .n_accounts = 3_000_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "3M accounts (1_slot - ram index - disk accounts)",
        // },
        // BenchArgs{
        //     .n_accounts = 3_000_000,
        //     .slot_list_len = 3,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "3M accounts (3_slot - ram index - disk accounts)",
        // },
        // BenchArgs{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .n_accounts_multiple = 2, // 1 mill accounts init
        //     .index = .ram,
        //     .name = "3M accounts (3_slot - ram index - disk accounts)",
        // },

        // // testing disk indexes
        // BenchArgs{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .name = "500k accounts (1_slot - disk index - disk accounts)",
        // },
        // BenchArgs{
        //     .n_accounts = 3_000_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .name = "3m accounts (1_slot - disk index - disk accounts)",
        // },
        // BenchArgs{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .n_accounts_multiple = 2,
        //     .name = "500k accounts (1_slot - disk index - disk accounts)",
        // },
    };

    pub fn readWriteAccounts(bench_args: BenchArgs) !sig.time.Duration {
        const n_accounts = bench_args.n_accounts;
        const slot_list_len = bench_args.slot_list_len;
        const total_n_accounts = n_accounts * slot_list_len;

        var allocator = std.heap.c_allocator;

        const disk_path = sig.TEST_DATA_DIR ++ "tmp/";
        std.fs.cwd().makeDir(disk_path) catch {};

        var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.VALIDATOR_DIR ++ "accounts_db", .{});
        defer snapshot_dir.close();

        const logger = .noop;
        var accounts_db: AccountsDB = try AccountsDB.init(allocator, logger, snapshot_dir, .{
            .number_of_index_shards = ACCOUNT_INDEX_SHARDS,
            .use_disk_index = bench_args.index == .disk,
        }, null);
        defer accounts_db.deinit();

        var prng = std.Random.DefaultPrng.init(19);
        const random = prng.random();

        var pubkeys = try allocator.alloc(Pubkey, n_accounts);
        defer allocator.free(pubkeys);
        for (0..n_accounts) |i| {
            pubkeys[i] = Pubkey.initRandom(random);
        }

        var all_filenames = try ArrayList([]const u8).initCapacity(allocator, slot_list_len + bench_args.n_accounts_multiple);
        defer all_filenames.deinit();
        defer {
            for (all_filenames.items) |filepath| {
                std.fs.cwd().deleteFile(filepath) catch {
                    std.debug.print("failed to delete file: {s}\n", .{filepath});
                };
            }
        }

        if (bench_args.accounts == .ram) {
            const n_accounts_init = bench_args.n_accounts_multiple * bench_args.n_accounts;
            const accounts = try allocator.alloc(Account, (total_n_accounts + n_accounts_init));
            for (0..(total_n_accounts + n_accounts_init)) |i| {
                accounts[i] = try Account.initRandom(allocator, random, i % 1_000);
            }

            if (n_accounts_init > 0) {
                try accounts_db.putAccountSlice(
                    accounts[total_n_accounts..(total_n_accounts + n_accounts_init)],
                    pubkeys,
                    @as(u64, @intCast(0)),
                );
            }

            var timer = try std.time.Timer.start();
            for (0..slot_list_len) |i| {
                const start_index = i * n_accounts;
                const end_index = start_index + n_accounts;
                try accounts_db.putAccountSlice(
                    accounts[start_index..end_index],
                    pubkeys,
                    @as(u64, @intCast(i)),
                );
            }
            const elapsed = timer.read();
            std.debug.print("WRITE: {d}\n", .{elapsed});
        } else {
            var account_files = try ArrayList(AccountFile).initCapacity(allocator, slot_list_len);
            defer account_files.deinit();

            for (0..(slot_list_len + bench_args.n_accounts_multiple)) |s| {
                var size: usize = 0;
                for (0..total_n_accounts) |i| {
                    const data_len = i % 1_000;
                    size += std.mem.alignForward(
                        usize,
                        AccountInFile.STATIC_SIZE + data_len,
                        @sizeOf(u64),
                    );
                }
                const aligned_size = std.mem.alignForward(usize, size, std.mem.page_size);
                const filepath_bounded = sig.utils.fmt.boundedFmt(disk_path ++ "slot{d}.bin", .{s});
                const filepath = filepath_bounded.constSlice();

                const length = blk: {
                    var file = try std.fs.cwd().createFile(filepath, .{ .read = true });
                    defer file.close();

                    // resize the file
                    const file_size = (try file.stat()).size;
                    if (file_size < aligned_size) {
                        try file.seekTo(aligned_size - 1);
                        _ = try file.write(&[_]u8{1});
                        try file.seekTo(0);
                    }

                    var memory = try std.posix.mmap(
                        null,
                        aligned_size,
                        std.posix.PROT.READ | std.posix.PROT.WRITE,
                        std.posix.MAP{ .TYPE = .SHARED }, // need it written to the file before it can be used
                        file.handle,
                        0,
                    );

                    var offset: usize = 0;
                    for (0..n_accounts) |i| {
                        const account = try Account.initRandom(allocator, random, i % 1_000);
                        defer allocator.free(account.data);
                        var pubkey = pubkeys[i % n_accounts];
                        offset += account.writeToBuf(&pubkey, memory[offset..]);
                    }
                    break :blk offset;
                };

                var account_file = blk: {
                    const file = try std.fs.cwd().openFile(filepath, .{ .mode = .read_write });
                    errdefer file.close();
                    break :blk try AccountFile.init(file, .{ .id = FileId.fromInt(@intCast(s)), .length = length }, s);
                };
                errdefer account_file.deinit();

                if (s < bench_args.n_accounts_multiple) {
                    try accounts_db.putAccountFile(&account_file, n_accounts);
                } else {
                    // to be indexed later (and timed)
                    account_files.appendAssumeCapacity(account_file);
                }
                all_filenames.appendAssumeCapacity(filepath);
            }

            var timer = try std.time.Timer.start();
            for (account_files.items) |*account_file| {
                try accounts_db.putAccountFile(account_file, n_accounts);
            }
            const elapsed = timer.read();

            std.debug.print("WRITE: {d}\n", .{elapsed});
        }

        var timer = try sig.time.Timer.start();
        for (0..n_accounts) |i| {
            const pubkey = &pubkeys[i];
            const account = try accounts_db.getAccount(pubkey);
            if (account.data.len != (i % 1_000)) {
                std.debug.panic("account data len dnm {}: {} != {}", .{ i, account.data.len, (i % 1_000) });
            }
        }
        const elapsed = timer.read();
        return elapsed;
    }
};
