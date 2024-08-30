//! includes the main database struct `AccountsDB`

const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const zstd = @import("zstd");
const bincode = sig.bincode;
const sysvars = sig.accounts_db.sysvars;

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
const DiskMemoryAllocator = sig.utils.allocators.DiskMemoryAllocator;
const RwMux = sig.sync.RwMux;
const Logger = sig.trace.log.Logger;
const NestedHashTree = sig.common.merkle_tree.NestedHashTree;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const Counter = sig.prometheus.counter.Counter;
const Histogram = sig.prometheus.histogram.Histogram;
const ClientVersion = sig.version.ClientVersion;
const StatusCache = sig.accounts_db.StatusCache;
const BankFields = sig.accounts_db.snapshots.BankFields;
const BankHashInfo = sig.accounts_db.snapshots.BankHashInfo;
const BankHashStats = sig.accounts_db.snapshots.BankHashStats;
const PubkeyBinCalculator = sig.accounts_db.index.PubkeyBinCalculator;
const GeyserWriter = sig.geyser.GeyserWriter;

const parallelUnpackZstdTarBall = sig.accounts_db.snapshots.parallelUnpackZstdTarBall;
const spawnThreadTasks = sig.utils.thread.spawnThreadTasks;
const printTimeEstimate = sig.time.estimate.printTimeEstimate;
const globalRegistry = sig.prometheus.registry.globalRegistry;

pub const DB_LOG_RATE = sig.time.Duration.fromSecs(5);
pub const DB_MANAGER_LOOP_MIN = sig.time.Duration.fromSecs(5);

pub const MERKLE_FANOUT: usize = 16;
pub const ACCOUNT_INDEX_BINS: usize = 8192;
pub const ACCOUNT_FILE_SHRINK_THRESHOLD = 70; // shrink account files with more than X% dead bytes
pub const DELETE_ACCOUNT_FILES_MIN = 100;

pub const AccountsDBStats = struct {
    const HistogramKind = enum {
        flush_account_file_size,
        shrink_file_shrunk_by,
        shrink_alive_accounts,
        shrink_dead_accounts,
        time_flush,
        time_clean,
        time_shrink,
        time_purge,

        fn buckets(self: HistogramKind) []const f64 {
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

            return switch (self) {
                .flush_account_file_size, .shrink_file_shrunk_by => account_size_buckets,
                .shrink_alive_accounts, .shrink_dead_accounts => account_count_buckets,
                .time_flush, .time_clean, .time_shrink, .time_purge => nanosecond_buckets,
            };
        }
    };

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

    clean_references_deleted: *Counter,
    clean_files_queued_deletion: *Counter,
    clean_files_queued_shrink: *Counter,
    clean_slot_old_state: *Counter,
    clean_slot_zero_lamports: *Counter,

    shrink_file_shrunk_by: *Histogram,
    shrink_alive_accounts: *Histogram,
    shrink_dead_accounts: *Histogram,

    const Self = @This();

    pub fn init() GetMetricError!Self {
        var self: Self = undefined;
        const registry = globalRegistry();
        const stats_struct_info = @typeInfo(Self).Struct;
        inline for (stats_struct_info.fields) |field| {
            @field(self, field.name) = switch (field.type) {
                *Counter => try registry.getOrCreateCounter(field.name),
                *Histogram => blk: {
                    @setEvalBranchQuota(2000); // stringToEnum requires a little more than default
                    const histogram_kind = comptime std.meta.stringToEnum(
                        HistogramKind,
                        field.name,
                    ) orelse @compileError("no matching HistogramKind for AccountsDBStats *Histogram field");

                    break :blk try registry.getOrCreateHistogram(field.name, histogram_kind.buckets());
                },
                else => @compileError("Unsupported field type"),
            };
        }
        return self;
    }
};

/// database for accounts
///
/// Analogous to [AccountsDb](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L1363)
pub const AccountsDB = struct {
    allocator: std.mem.Allocator,

    /// maps a pubkey to the account location
    account_index: AccountIndex,
    disk_allocator_ptr: ?*DiskMemoryAllocator = null,

    /// track per-slot for purge/flush
    account_cache: RwMux(AccountCache),

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
    /// Represents the largest slot info used to generate a full snapshot, which currently exists.
    /// Always `.slot <= largest_flushed_slot`.
    latest_full_snapshot_info: RwMux(?FullSnapshotGenerationInfo) = RwMux(?FullSnapshotGenerationInfo).init(null),
    latest_incremental_snapshot_info: RwMux(?IncSnapshotGenerationInfo) = RwMux(?IncSnapshotGenerationInfo).init(null),

    /// Not closed by the `AccountsDB`, but must live at least as long as it.
    snapshot_dir: std.fs.Dir,

    // TODO: populate this during snapshot load
    // TODO: move to Bank struct
    bank_hash_stats: RwMux(BankHashStatsMap) = RwMux(BankHashStatsMap).init(.{}),

    stats: AccountsDBStats,
    logger: Logger,
    config: InitConfig,

    const Self = @This();

    pub const PubkeysAndAccounts = struct { []const Pubkey, []const Account };
    pub const AccountCache = std.AutoHashMap(Slot, PubkeysAndAccounts);
    pub const DeadAccountsCounter = std.AutoArrayHashMap(Slot, u64);
    pub const BankHashStatsMap = std.AutoArrayHashMapUnmanaged(Slot, BankHashStats);
    pub const FileMap = std.AutoArrayHashMapUnmanaged(FileId, AccountFile);

    pub const InitConfig = struct {
        number_of_index_bins: usize,
        use_disk_index: bool,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        logger: Logger,
        snapshot_dir: std.fs.Dir,
        config: InitConfig,
        geyser_writer: ?*GeyserWriter,
    ) !Self {
        const maybe_disk_allocator_ptr: ?*DiskMemoryAllocator, //
        const reference_allocator: std.mem.Allocator //
        = blk: {
            if (config.use_disk_index) {
                var index_bin_dir = try snapshot_dir.makeOpenPath("index/bin", .{});
                defer index_bin_dir.close();

                const disk_file_suffix = try index_bin_dir.realpathAlloc(allocator, ".");
                errdefer allocator.free(disk_file_suffix);
                logger.infof("using disk index in {s}", .{disk_file_suffix});

                const ptr = try allocator.create(DiskMemoryAllocator);
                ptr.* = DiskMemoryAllocator.init(disk_file_suffix);

                break :blk .{ ptr, ptr.allocator() };
            } else {
                logger.infof("using ram index", .{});
                break :blk .{ null, std.heap.page_allocator };
            }
        };
        errdefer if (maybe_disk_allocator_ptr) |ptr| {
            ptr.deinit(allocator);
            allocator.destroy(ptr);
        };

        // ensure accounts/ exists
        snapshot_dir.makePath("accounts") catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => |e| return e,
        };

        var account_index = try AccountIndex.init(
            allocator,
            reference_allocator,
            config.number_of_index_bins,
        );
        errdefer account_index.deinit(true);

        const stats = try AccountsDBStats.init();

        return .{
            .allocator = allocator,
            .disk_allocator_ptr = maybe_disk_allocator_ptr,
            .account_index = account_index,
            .logger = logger,
            .config = config,
            .account_cache = RwMux(AccountCache).init(AccountCache.init(allocator)),
            .snapshot_dir = snapshot_dir,
            .dead_accounts_counter = RwMux(DeadAccountsCounter).init(DeadAccountsCounter.init(allocator)),
            .stats = stats,
            .geyser_writer = geyser_writer,
        };
    }

    pub fn deinit(
        self: *Self,
        delete_index_files: bool,
    ) void {
        self.account_index.deinit(true);
        if (self.disk_allocator_ptr) |ptr| {
            // note: we dont always deinit the allocator so we keep the index files
            // because they are expensive to generate
            if (delete_index_files) {
                ptr.deinit(self.allocator);
            } else {
                self.allocator.free(ptr.filepath);
            }
            self.allocator.destroy(ptr);
        }

        {
            const account_cache, var account_cache_lg = self.account_cache.writeWithLock();
            defer account_cache_lg.unlock();
            var iter = account_cache.valueIterator();
            while (iter.next()) |pubkeys_and_accounts| {
                const pubkeys, const accounts = pubkeys_and_accounts.*;
                for (accounts) |account| account.deinit(self.allocator);
                self.allocator.free(pubkeys);
                self.allocator.free(accounts);
            }
            account_cache.deinit();
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
        snapshot_fields_and_paths: *AllSnapshotFields,
        n_threads: u32,
        validate: bool,
        accounts_per_file_estimate: u64,
    ) !SnapshotFields {
        const snapshot_fields = try snapshot_fields_and_paths.collapse();

        const load_duration = try self.loadFromSnapshot(
            snapshot_fields.accounts_db_fields,
            n_threads,
            std.heap.page_allocator,
            accounts_per_file_estimate,
        );
        self.logger.infof("loaded from snapshot in {s}", .{load_duration});

        if (validate) {
            const full_snapshot = snapshot_fields_and_paths.full;
            const validate_duration = try self.validateLoadFromSnapshot(
                snapshot_fields.bank_fields_inc.snapshot_persistence,
                full_snapshot.bank_fields.slot,
                full_snapshot.bank_fields.capitalization,
                snapshot_fields.accounts_db_fields.bank_hash_info.accounts_hash,
            );
            self.logger.infof("validated from snapshot in {s}", .{validate_duration});
        }

        return snapshot_fields;
    }

    /// loads the account files and gernates the account index from a snapshot
    pub fn loadFromSnapshot(
        self: *Self,
        /// Account file info map from the snapshot manifest.
        snapshot_manifest: AccountsDbFields,
        n_threads: u32,
        per_thread_allocator: std.mem.Allocator,
        accounts_per_file_estimate: u64,
    ) !sig.time.Duration {
        self.logger.infof("loading from snapshot...", .{});

        // used to read account files
        const n_parse_threads = n_threads;
        // used to merge thread results
        const n_combine_threads = n_threads;

        var accounts_dir = try self.snapshot_dir.openDir("accounts", .{});
        defer accounts_dir.close();

        var timer = try sig.time.Timer.start();

        const n_account_files = snapshot_manifest.file_map.count();
        self.logger.infof("found {d} account files", .{n_account_files});

        std.debug.assert(n_account_files > 0);

        {
            const bhs, var bhs_lg = try self.getOrInitBankHashStats(snapshot_manifest.slot);
            defer bhs_lg.unlock();
            bhs.accumulate(snapshot_manifest.bank_hash_info.stats);
        }

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
                thread_db.disk_allocator_ptr = self.disk_allocator_ptr;
                thread_db.account_index.reference_allocator = thread_db.disk_allocator_ptr.?.allocator();
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
                loading_thread.account_index.deinit(false);
            }
            loading_threads.deinit();
        }

        self.logger.infof("reading and indexing accounts...", .{});
        {
            var handles = std.ArrayList(std.Thread).init(self.allocator);
            defer {
                for (handles.items) |*h| h.join();
                handles.deinit();
            }

            try spawnThreadTasks(
                &handles,
                loadAndVerifyAccountsFilesMultiThread,
                .{
                    loading_threads.items,
                    accounts_dir,
                    snapshot_manifest.file_map,
                    accounts_per_file_estimate,
                },
                n_account_files,
                n_parse_threads,
            );
        }
        self.logger.infof("total time: {s}", .{timer.read()});

        self.logger.infof("combining thread accounts...", .{});
        var merge_timer = try sig.time.Timer.start();
        try self.mergeMultipleDBs(loading_threads.items, n_combine_threads);
        self.logger.debugf("combining thread indexes took: {s}", .{merge_timer.read()});

        return timer.read();
    }

    /// multithread entrypoint into loadAndVerifyAccountsFiles.
    pub fn loadAndVerifyAccountsFilesMultiThread(
        loading_threads: []AccountsDB,
        accounts_dir: std.fs.Dir,
        file_info_map: AccountsDbFields.FileMap,
        accounts_per_file_estimate: u64,
        // task specific
        start_index: usize,
        end_index: usize,
        thread_id: usize,
    ) !void {
        const thread_db = &loading_threads[thread_id];

        try thread_db.loadAndVerifyAccountsFiles(
            accounts_dir,
            accounts_per_file_estimate,
            file_info_map,
            start_index,
            end_index,
            thread_id == 0,
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

        const bin_counts = try self.allocator.alloc(usize, self.account_index.numberOfBins());
        defer self.allocator.free(bin_counts);
        @memset(bin_counts, 0);

        // allocate all the references in one shot with a wrapper allocator
        // without this large allocation, snapshot loading is very slow
        const n_accounts_estimate = n_account_files * accounts_per_file_est;
        var references = try ArrayList(AccountRef).initCapacity(
            self.account_index.reference_allocator,
            n_accounts_estimate,
        );

        const references_ptr = references.items.ptr;

        const counting_alloc = try FreeCounterAllocator.init(self.allocator, references);
        defer counting_alloc.deinitIfSafe();

        var timer = try sig.time.Timer.start();
        var progress_timer = try sig.time.Timer.start();

        if (n_account_files > std.math.maxInt(AccountIndex.ReferenceMemory.Size)) {
            return error.FileMapTooBig;
        }
        // its ok to hold this lock for the entire function because nothing else
        // should be accessing the account index while loading from a snapshot
        const reference_memory, var reference_memory_lg = self.account_index.reference_memory.writeWithLock();
        defer reference_memory_lg.unlock();
        try reference_memory.ensureTotalCapacity(@intCast(n_account_files));

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

        for (
            file_info_map.keys()[file_map_start_index..file_map_end_index],
            file_info_map.values()[file_map_start_index..file_map_end_index],
            1..,
        ) |slot, file_info, file_count| {
            // read accounts file
            var accounts_file = blk: {
                const file_name_bounded = sig.utils.fmt.boundedFmt("{d}.{d}", .{ slot, file_info.id.toInt() });
                errdefer std.debug.print("failed to open file: {s}\n", .{file_name_bounded.constSlice()});

                const accounts_file_file = accounts_dir.openFile(file_name_bounded.constSlice(), .{ .mode = .read_write }) catch |err| {
                    self.logger.errf("Failed to open accounts/{s}", .{file_name_bounded.constSlice()});
                    return err;
                };
                errdefer accounts_file_file.close();

                break :blk AccountFile.init(accounts_file_file, file_info, slot) catch |err| {
                    self.logger.errf("failed to *open* AccountsFile {s}: {s}\n", .{ file_name_bounded.constSlice(), @errorName(err) });
                    return err;
                };
            };
            errdefer accounts_file.deinit();

            indexAndValidateAccountFile(
                &accounts_file,
                self.account_index.pubkey_bin_calculator,
                bin_counts,
                &references,
                geyser_slot_storage,
            ) catch |err| {
                self.logger.errf("failed to *validate/index* AccountsFile: {d}.{d}: {s}\n", .{
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
                reference_memory.putAssumeCapacityNoClobber(slot, ref_list);
            }

            const file_id = file_info.id;

            file_map.putAssumeCapacityNoClobber(file_id, accounts_file);
            self.largest_file_id = FileId.max(self.largest_file_id, file_id);
            _ = self.largest_rooted_slot.fetchMax(slot, .monotonic);
            self.largest_flushed_slot.store(self.largest_rooted_slot.load(.monotonic), .monotonic);

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

        // allocate enough memory for the bins
        var total_accounts: usize = 0;
        for (bin_counts, 0..) |count, bin_index| {
            if (count > 0) {
                const bin_rw = self.account_index.getBin(bin_index);
                const bin, var bin_lg = bin_rw.writeWithLock();
                defer bin_lg.unlock();

                try bin.ensureTotalCapacity(count);
                total_accounts += count;
            }
        }

        // NOTE: this is good for debugging what to set `accounts_per_file_est` to
        if (print_progress) {
            self.logger.infof("accounts_per_file: actual vs estimated: {d} vs {d}", .{
                total_accounts / n_account_files,
                accounts_per_file_est,
            });
        }

        // PERF: can probs be faster if you sort the pubkeys first, and then you know
        // it will always be a search for a free spot, and not search for a match
        var ref_count: usize = 0;
        timer.reset();

        var slot_iter = reference_memory.keyIterator();
        while (slot_iter.next()) |slot| {
            const refs = reference_memory.get(slot.*).?;
            for (refs.items) |*ref| {
                _ = self.account_index.indexRefIfNotDuplicateSlot(ref);
                ref_count += 1;
            }

            if (print_progress and progress_timer.read().asNanos() > DB_LOG_RATE.asNanos()) {
                printTimeEstimate(
                    self.logger,
                    &timer,
                    total_accounts,
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
        var handles = std.ArrayList(std.Thread).init(self.allocator);
        defer {
            for (handles.items) |*h| h.join();
            handles.deinit();
        }
        try spawnThreadTasks(
            &handles,
            combineThreadIndexesMultiThread,
            .{
                self.logger,
                &self.account_index,
                thread_dbs,
            },
            self.account_index.numberOfBins(),
            n_threads,
        );

        // ensure enough capacity
        var ref_mem_capacity: u32 = 0;
        for (thread_dbs) |*thread_db| {
            const thread_ref_memory, var thread_ref_memory_lg = thread_db.account_index.reference_memory.readWithLock();
            defer thread_ref_memory_lg.unlock();
            ref_mem_capacity += thread_ref_memory.count();
        }

        // NOTE: its ok to hold this lock while we merge because
        // nothing else should be accessing the account index while loading from a snapshot
        const reference_memory, var reference_memory_lg = self.account_index.reference_memory.writeWithLock();
        defer reference_memory_lg.unlock();
        try reference_memory.ensureTotalCapacity(ref_mem_capacity);

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
            _ = self.largest_rooted_slot.fetchMax(thread_db.largest_rooted_slot.load(.unordered), .monotonic);
            self.largest_flushed_slot.store(self.largest_rooted_slot.load(.monotonic), .monotonic);

            // combine underlying memory
            const thread_reference_memory, var thread_reference_memory_lg = thread_db.account_index.reference_memory.readWithLock();
            defer thread_reference_memory_lg.unlock();

            var thread_ref_iter = thread_reference_memory.iterator();
            while (thread_ref_iter.next()) |thread_entry| {
                reference_memory.putAssumeCapacityNoClobber(
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
        thread_dbs: []AccountsDB,
        // task specific
        bin_start_index: usize,
        bin_end_index: usize,
        thread_id: usize,
    ) !void {
        const total_bins = bin_end_index - bin_start_index;
        var timer = try sig.time.Timer.start();
        var progress_timer = try std.time.Timer.start();
        const print_progress = thread_id == 0;

        for (bin_start_index..bin_end_index, 1..) |bin_index, iteration_count| {
            const index_bin_rw = index.getBin(bin_index);

            // sum size across threads
            var bin_n_accounts: usize = 0;
            for (thread_dbs) |*thread_db| {
                var bin_rw = thread_db.account_index.getBin(bin_index);
                const bin, var bin_lg = bin_rw.readWithLock();
                defer bin_lg.unlock();

                bin_n_accounts += bin.count();
            }
            // prealloc
            if (bin_n_accounts > 0) {
                const index_bin, var index_bin_lg = index_bin_rw.writeWithLock();
                defer index_bin_lg.unlock();

                try index_bin.ensureTotalCapacity(bin_n_accounts);
            }

            for (thread_dbs) |*thread_db| {
                const bin_rw = thread_db.account_index.getBin(bin_index);
                const bin, var bin_lg = bin_rw.readWithLock();
                defer bin_lg.unlock();

                // insert all of the thread entries into the main index
                var iter = bin.iterator();
                while (iter.next()) |thread_entry| {
                    var thread_head_ref_rw = thread_entry.value_ptr.*;
                    const thread_head_ref, var thread_head_ref_lg = thread_head_ref_rw.readWithLock();
                    defer thread_head_ref_lg.unlock();

                    // NOTE: we dont have to check for duplicates because the duplicate
                    // slots have already been handled in the prev step
                    index.indexRef(thread_head_ref.ref_ptr);
                }
            }

            if (print_progress and progress_timer.read() > DB_LOG_RATE.asNanos()) {
                printTimeEstimate(
                    logger,
                    &timer,
                    total_bins,
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
    pub fn computeAccountHashesAndLamports(
        self: *Self,
        config: AccountHashesConfig,
    ) ComputeAccountHashesAndLamportsError!struct { Hash, u64 } {
        var timer = try std.time.Timer.start();
        const n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;

        // alloc the result
        const hashes = try self.allocator.alloc(ArrayListUnmanaged(Hash), n_threads);
        defer self.allocator.free(hashes);

        @memset(hashes, .{});
        defer for (hashes) |*h| h.deinit(self.allocator);

        const lamports = try self.allocator.alloc(u64, n_threads);
        defer self.allocator.free(lamports);
        @memset(lamports, 0);

        // split processing the bins over muliple threads
        self.logger.infof("collecting hashes from accounts...", .{});

        {
            var handles = std.ArrayList(std.Thread).init(self.allocator);
            defer {
                for (handles.items) |*h| h.join();
                handles.deinit();
            }
            try spawnThreadTasks(
                &handles,
                getHashesFromIndexMultiThread,
                .{
                    self,
                    config,
                    self.allocator,
                    hashes,
                    lamports,
                },
                self.account_index.numberOfBins(),
                n_threads,
            );
        }

        self.logger.debugf("took: {s}", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        self.logger.infof("computing the merkle root over accounts...", .{});
        var hash_tree = NestedHashTree{ .hashes = hashes };
        const accounts_hash = try hash_tree.computeMerkleRoot(MERKLE_FANOUT);
        self.logger.debugf("took {s}", .{std.fmt.fmtDuration(timer.read())});
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

    /// validates the accounts_db which was loaded from a snapshot (
    /// including the accounts hash and total lamports matches the expected values)
    pub fn validateLoadFromSnapshot(
        self: *Self,
        // used to verify the incremental snapshot
        incremental_snapshot_persistence: ?BankIncrementalSnapshotPersistence,
        // used to verify the full snapshot
        full_snapshot_slot: Slot,
        expected_full_lamports: u64,
        expected_accounts_hash: Hash,
    ) !sig.time.Duration {
        var timer = try sig.time.Timer.start();

        // validate the full snapshot
        self.logger.infof("validating the full snapshot", .{});
        const accounts_hash, const total_lamports = try self.computeAccountHashesAndLamports(.{
            .FullAccountHash = .{
                .max_slot = full_snapshot_slot,
            },
        });

        if (expected_accounts_hash.order(&accounts_hash) != .eq) {
            self.logger.errf(
                \\ incorrect accounts hash
                \\ expected vs calculated: {d} vs {d}
            , .{ expected_accounts_hash, accounts_hash });
            return error.IncorrectAccountsHash;
        }
        if (expected_full_lamports != total_lamports) {
            self.logger.errf(
                \\ incorrect total lamports
                \\ expected vs calculated: {d} vs {d}
            , .{ expected_full_lamports, total_lamports });
            return error.IncorrectTotalLamports;
        }

        // validate the incremental snapshot
        if (incremental_snapshot_persistence == null) {
            return timer.read();
        }

        self.logger.infof("validating the incremental snapshot", .{});
        const expected_accounts_delta_hash = incremental_snapshot_persistence.?.incremental_hash;
        const expected_incremental_lamports = incremental_snapshot_persistence.?.incremental_capitalization;

        const accounts_delta_hash, const incremental_lamports = try self.computeAccountHashesAndLamports(.{
            .IncrementalAccountHash = .{
                .min_slot = full_snapshot_slot,
            },
        });

        if (expected_incremental_lamports != incremental_lamports) {
            self.logger.errf(
                \\ incorrect incremental lamports
                \\ expected vs calculated: {d} vs {d}
            , .{ expected_incremental_lamports, incremental_lamports });
            return error.IncorrectIncrementalLamports;
        }

        if (expected_accounts_delta_hash.order(&accounts_delta_hash) != .eq) {
            self.logger.errf(
                \\ incorrect accounts delta hash
                \\ expected vs calculated: {d} vs {d}
            , .{ expected_accounts_delta_hash, accounts_delta_hash });
            return error.IncorrectAccountsDeltaHash;
        }

        return timer.read();
    }

    /// multithread entrypoint for getHashesFromIndex
    pub fn getHashesFromIndexMultiThread(
        self: *AccountsDB,
        config: AccountsDB.AccountHashesConfig,
        /// Allocator shared by all the arraylists in `hashes`.
        hashes_allocator: std.mem.Allocator,
        hashes: []ArrayListUnmanaged(Hash),
        total_lamports: []u64,
        // spawing thread specific params
        bin_start_index: usize,
        bin_end_index: usize,
        thread_index: usize,
    ) !void {
        try getHashesFromIndex(
            self,
            config,
            self.account_index.bins[bin_start_index..bin_end_index],
            hashes_allocator,
            &hashes[thread_index],
            &total_lamports[thread_index],
            thread_index == 0,
        );
    }

    /// populates the account hashes and total lamports for a given bin range
    /// from bin_start_index to bin_end_index.
    pub fn getHashesFromIndex(
        self: *AccountsDB,
        config: AccountsDB.AccountHashesConfig,
        thread_bins: []RwMux(AccountIndex.RefMap),
        hashes_allocator: std.mem.Allocator,
        hashes: *ArrayListUnmanaged(Hash),
        total_lamports: *u64,
        // when we multithread this function we only want to print on the first thread
        print_progress: bool,
    ) !void {
        var total_n_pubkeys: usize = 0;
        for (thread_bins) |*bin_rw| {
            const bin, var bin_lg = bin_rw.readWithLock();
            defer bin_lg.unlock();

            total_n_pubkeys += bin.count();
        }
        try hashes.ensureTotalCapacity(hashes_allocator, total_n_pubkeys);

        // well reuse this over time so this is ok (even if 1k is an under estimate)
        var keys = try self.allocator.alloc(Pubkey, 1_000);
        defer self.allocator.free(keys);

        var local_total_lamports: u64 = 0;
        var timer = try sig.time.Timer.start();
        var progress_timer = try std.time.Timer.start();
        for (thread_bins, 1..) |*bin_rw, count| {
            // get and sort pubkeys in bin
            // PERF: may be holding this lock for too long
            const bin, var bin_lg = bin_rw.readWithLock();
            defer bin_lg.unlock();

            const n_pubkeys_in_bin = bin.count();
            if (n_pubkeys_in_bin == 0) {
                continue;
            }
            if (n_pubkeys_in_bin > keys.len) {
                if (!self.allocator.resize(keys, n_pubkeys_in_bin)) {
                    self.allocator.free(keys);
                    const new_keys = try self.allocator.alloc(Pubkey, n_pubkeys_in_bin);
                    keys.ptr = new_keys.ptr;
                    keys.len = new_keys.len;
                } else {
                    keys.len = n_pubkeys_in_bin;
                }
            }

            var i: usize = 0;
            var key_iter = bin.iterator();
            while (key_iter.next()) |entry| {
                keys[i] = entry.key_ptr.*;
                i += 1;
            }
            const bin_pubkeys = keys[0..n_pubkeys_in_bin];

            std.mem.sort(Pubkey, bin_pubkeys, {}, struct {
                fn lessThan(_: void, lhs: Pubkey, rhs: Pubkey) bool {
                    return std.mem.lessThan(u8, &lhs.data, &rhs.data);
                }
            }.lessThan);

            // get the hashes
            for (bin_pubkeys) |key| {
                const ref_head_rw = bin.getPtr(key).?;
                const ref_head, var ref_head_lg = ref_head_rw.readWithLock();
                defer ref_head_lg.unlock();

                // get the most recent state of the account
                const ref_ptr = ref_head.ref_ptr;
                const max_slot_ref = switch (config) {
                    .FullAccountHash => |full_config| slotListMaxWithinBounds(ref_ptr, full_config.min_slot, full_config.max_slot),
                    .IncrementalAccountHash => |inc_config| slotListMaxWithinBounds(ref_ptr, inc_config.min_slot, inc_config.max_slot),
                } orelse continue;
                var account_hash, const lamports = try self.getAccountHashAndLamportsFromRef(max_slot_ref.location);
                if (lamports == 0) {
                    switch (config) {
                        // for full snapshots, only include non-zero lamport accounts
                        .FullAccountHash => continue,
                        // zero-lamport accounts for incrementals = hash(pubkey)
                        .IncrementalAccountHash => Blake3.hash(&key.data, &account_hash.data, .{}),
                    }
                } else {
                    // hashes arent always stored correctly in snapshots
                    if (account_hash.order(&Hash.default()) == .eq) {
                        const account, var lock_guard = try self.getAccountFromRefWithReadLock(max_slot_ref);
                        defer lock_guard.unlock();

                        account_hash = switch (account) {
                            .file => |in_file| sig.core.account.hashAccount(
                                in_file.lamports().*,
                                in_file.data,
                                &in_file.owner().data,
                                in_file.executable().*,
                                in_file.rent_epoch().*,
                                &in_file.pubkey().data,
                            ),
                            .cache => |cached| cached.hash(&key),
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
                    thread_bins.len,
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

        const zstd_compressor = try zstd.Compressor.init(.{});
        defer zstd_compressor.deinit();

        var zstd_sfba_state = std.heap.stackFallback(4096 * 4, self.allocator);
        const zstd_sfba = zstd_sfba_state.get();

        const zstd_buffer = try zstd_sfba.alloc(u8, zstd.Compressor.recommOutSize());
        defer zstd_sfba.free(zstd_buffer);

        // TODO: get rid of this once `makeFullSnapshotGenerationPackage` can actually
        // derive this data correctly by itself.
        var rand = std.Random.DefaultPrng.init(1234);
        var tmp_bank_fields = try BankFields.random(self.allocator, rand.random(), 128);
        defer tmp_bank_fields.deinit(self.allocator);

        while (!exit.load(.monotonic)) {
            defer {
                const elapsed = timer.lap();
                if (elapsed < DB_MANAGER_LOOP_MIN.asNanos()) {
                    const delay = DB_MANAGER_LOOP_MIN.asNanos() - elapsed;
                    std.time.sleep(delay);
                }
            }

            {
                const account_cache, var account_cache_lg = self.account_cache.readWithLock();
                defer account_cache_lg.unlock();

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
                var cache_slot_iter = account_cache.keyIterator();
                while (cache_slot_iter.next()) |cache_slot| {
                    if (cache_slot.* <= root_slot) {
                        // NOTE: need to flush all references <= root_slot before we call clean
                        // or things break by trying to clean cache references
                        // NOTE: this might be too much in production, not sure
                        try flush_slots.append(cache_slot.*);
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
                self.logger.debugf("flushing slots: min: {}...{}", std.mem.minMax(Slot, flush_slots.items));

                // flush the slots
                try unclean_account_files.ensureTotalCapacityPrecise(flush_slots.items.len);

                var largest_flushed_slot: Slot = 0;
                for (flush_slots.items) |flush_slot| {
                    const unclean_file_id = self.flushSlot(flush_slot) catch |err| {
                        // flush fail = loss of account data on slot -- should never happen
                        self.logger.errf("flushing slot {d} error: {s}", .{ flush_slot, @errorName(err) });
                        continue;
                    };
                    unclean_account_files.appendAssumeCapacity(unclean_file_id);
                    largest_flushed_slot = @max(largest_flushed_slot, flush_slot);
                }
                _ = self.largest_flushed_slot.fetchMax(largest_flushed_slot, .seq_cst);
            }

            const largest_flushed_slot = self.largest_flushed_slot.load(.seq_cst);

            const latest_full_snapshot_slot = blk: {
                const latest_full_snapshot_info, var latest_full_snapshot_info_lg = self.latest_full_snapshot_info.readWithLock();
                defer latest_full_snapshot_info_lg.unlock();
                break :blk if (latest_full_snapshot_info.*) |info| info.slot else 0;
            };
            if (largest_flushed_slot - latest_full_snapshot_slot >= slots_per_full_snapshot) {
                self.logger.infof("accountsdb[manager]: generating full snapshot for slot {d}", .{largest_flushed_slot});

                var snapshot_gen_pkg, const snapshot_gen_info = try self.makeFullSnapshotGenerationPackage(
                    largest_flushed_slot,
                    &tmp_bank_fields,
                    rand.random().int(u64),
                    0,
                );
                defer snapshot_gen_pkg.deinit();

                const archive_file_name_bounded = sig.accounts_db.snapshots.FullSnapshotFileInfo.snapshotNameStr(.{
                    .slot = snapshot_gen_info.slot,
                    .hash = snapshot_gen_info.hash,
                    .compression = .zstd,
                });
                const archive_file_name = archive_file_name_bounded.constSlice();
                const archive_file = try self.snapshot_dir.createFile(archive_file_name, .{ .read = true });
                defer archive_file.close();

                const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, zstd_buffer);

                try snapshot_gen_pkg.write(zstd_write_ctx.writer(), StatusCache.default());
                try zstd_write_ctx.finish();

                try self.commitFullSnapshotInfo(snapshot_gen_info, .delete_old);
            }

            const latest_incremental_snapshot_slot = blk: {
                const latest_incremental_snapshot_info, var latest_incremental_snapshot_info_lg = self.latest_incremental_snapshot_info.readWithLock();
                defer latest_incremental_snapshot_info_lg.unlock();
                break :blk if (latest_incremental_snapshot_info.*) |info| info.slot else 0;
            };
            if (largest_flushed_slot - latest_incremental_snapshot_slot >= slots_per_incremental_snapshot) inc_blk: {
                {
                    const latest_full_snapshot_info, var latest_full_snapshot_info_lg = self.latest_full_snapshot_info.readWithLock();
                    defer latest_full_snapshot_info_lg.unlock();
                    // no full snapshot, nothing to do
                    if (latest_full_snapshot_info.* == null) break :inc_blk;
                    // not enough new slots since last full snapshot, nothing to do
                    if (largest_flushed_slot < latest_full_snapshot_info.*.?.slot + slots_per_incremental_snapshot) break :inc_blk;
                }

                self.logger.infof("accountsdb[manager]: generating incremental snapshot from {d} to {d}", .{
                    latest_full_snapshot_slot,
                    largest_flushed_slot,
                });

                var inc_snapshot_pkg, const snapshot_gen_info = try self.makeIncrementalSnapshotGenerationPackage(
                    largest_flushed_slot,
                    &tmp_bank_fields,
                    rand.random().int(u64),
                    0,
                );
                defer inc_snapshot_pkg.deinit();

                const archive_file_name_bounded = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo.snapshotNameStr(.{
                    .base_slot = snapshot_gen_info.base_slot,
                    .slot = snapshot_gen_info.slot,
                    .hash = snapshot_gen_info.hash,
                    .compression = .zstd,
                });
                const archive_file_name = archive_file_name_bounded.constSlice();
                const archive_file = try self.snapshot_dir.createFile(archive_file_name, .{ .read = true });
                errdefer archive_file.close();

                const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, zstd_buffer);

                try inc_snapshot_pkg.write(zstd_write_ctx.writer());
                try zstd_write_ctx.finish();

                try self.commitIncrementalSnapshotInfo(snapshot_gen_info, .delete_old);
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
                // self.logger.debugf("clean_result: {any}", .{clean_result});

                // shrink any account files which have been cleaned
                const shrink_result = try self.shrinkAccountFiles(
                    shrink_account_files.keys(),
                    &delete_account_files,
                );
                _ = shrink_result;
                // self.logger.debugf("shrink_results: {any}", .{shrink_results});

                // delete any empty account files
                if (delete_account_files.count() > DELETE_ACCOUNT_FILES_MIN) {
                    defer delete_account_files.clearRetainingCapacity();
                    try self.deleteAccountFiles(delete_account_files.keys());
                }
            }
        }
    }

    pub fn buildFullSnapshot(
        self: *Self,
        slot: Slot,
        archive_dir: std.fs.Dir,
        bank_fields: *sig.accounts_db.snapshots.BankFields,
        status_cache: StatusCache,
    ) !void {
        var rand = std.Random.DefaultPrng.init(1234);

        // setup zstd
        const zstd_compressor = try zstd.Compressor.init(.{});
        defer zstd_compressor.deinit();
        var zstd_sfba_state = std.heap.stackFallback(4096 * 4, self.allocator);
        const zstd_sfba = zstd_sfba_state.get();
        const zstd_buffer = try zstd_sfba.alloc(u8, zstd.Compressor.recommOutSize());
        defer zstd_sfba.free(zstd_buffer);

        // generate the snapshot package
        var snapshot_gen_pkg, const snapshot_gen_info = try self.makeFullSnapshotGenerationPackage(
            slot,
            bank_fields,
            rand.random().int(u64),
            0,
        );
        defer snapshot_gen_pkg.deinit();

        // create the snapshot filename
        const archive_file_name_bounded = sig.accounts_db.snapshots.FullSnapshotFileInfo.snapshotNameStr(.{
            .slot = snapshot_gen_info.slot,
            .hash = snapshot_gen_info.hash,
            .compression = .zstd,
        });
        const archive_file_name = archive_file_name_bounded.constSlice();
        const archive_file = try archive_dir.createFile(archive_file_name, .{ .read = true });
        defer archive_file.close();

        const full_path = try archive_dir.realpathAlloc(self.allocator, archive_file_name);
        defer self.allocator.free(full_path);
        self.logger.infof("writing full snapshot to {s}", .{full_path});

        // write the snapshot to disk, compressed
        var timer = try sig.time.Timer.start();
        const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, zstd_buffer);
        try snapshot_gen_pkg.write(zstd_write_ctx.writer(), status_cache);
        try zstd_write_ctx.finish();
        self.logger.infof("writing full snapshot took {any}", .{timer.read()});

        // track new snapshot
        try self.commitFullSnapshotInfo(snapshot_gen_info, .ignore_old);
    }

    /// flushes a slot account data from the cache onto disk, and updates the index
    /// note: this deallocates the []account and []pubkey data from the cache, as well
    /// as the data field ([]u8) for each account.
    /// Returns the unclean file id.
    pub fn flushSlot(self: *Self, slot: Slot) !FileId {
        var timer = try sig.time.Timer.start();

        defer self.stats.number_files_flushed.inc();

        const pubkeys, const accounts: []const Account = blk: {
            // NOTE: flush should be the only function to delete/free cache slices of a flushed slot
            // -- purgeSlot removes slices but we should never purge rooted slots
            const account_cache, var account_cache_lg = self.account_cache.readWithLock();
            defer account_cache_lg.unlock();

            const pubkeys, const accounts = account_cache.get(slot) orelse return error.SlotNotFound;
            break :blk .{ pubkeys, accounts };
        };
        std.debug.assert(accounts.len == pubkeys.len);

        // create account file which is big enough
        var size: usize = 0;
        for (accounts) |*account| {
            const account_size_in_file = account.getSizeInFile();
            size += account_size_in_file;
            self.stats.flush_account_file_size.observe(@floatFromInt(account_size_in_file));
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

        self.stats.flush_accounts_written.add(account_file.number_of_accounts);

        // update the reference AFTER the data exists
        for (pubkeys, offsets) |pubkey, offset| {
            var head_reference_rw = self.account_index.getReference(&pubkey) orelse return error.PubkeyNotFound;
            const head_ref, var head_reference_lg = head_reference_rw.writeWithLock();
            defer head_reference_lg.unlock();

            // find the slot in the reference list
            var did_update = false;
            var curr_ref: ?*AccountRef = head_ref.ref_ptr;
            while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
                if (ref.slot == slot) {
                    ref.location = .{ .File = .{ .file_id = file_id, .offset = offset } };
                    did_update = true;
                    // NOTE: we break here because we dont allow multiple account states per slot
                    // NOTE: if there are multiple states, then it will likely break during clean
                    // trying to access a .File location which is actually still .Cache (bc it
                    // was never updated)
                    break;
                }
            }
            std.debug.assert(did_update);
        }

        self.logger.debugf("flushed {} accounts, totalling size {}", .{ account_file.number_of_accounts, size });

        // remove old references
        {
            const account_cache, var account_cache_lg = self.account_cache.writeWithLock();
            defer account_cache_lg.unlock();

            // remove from cache map
            const did_remove = account_cache.remove(slot);
            std.debug.assert(did_remove);

            // free slices
            for (accounts) |account| {
                self.allocator.free(account.data);
            }
            self.allocator.free(accounts);
            self.allocator.free(pubkeys);
        }

        self.stats.time_flush.observe(@floatFromInt(timer.read().asNanos()));

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

        defer {
            const number_of_files = unclean_account_files.len;
            self.stats.number_files_cleaned.add(number_of_files);
        }

        var num_zero_lamports: usize = 0;
        var num_old_states: usize = 0;

        // TODO: move this out into a CleanState struct to reduce allocations
        // track then delete all to avoid deleting while iterating
        var references_to_delete = std.ArrayList(*AccountRef).init(self.allocator);
        defer references_to_delete.deinit();

        // track so we dont double delete
        var cleaned_pubkeys = std.AutoArrayHashMap(Pubkey, void).init(self.allocator);
        defer cleaned_pubkeys.deinit();

        for (unclean_account_files) |file_id| {
            // NOTE: this read-lock is held for a while but
            // is not expensive since writes only happen
            // during shrink/delete (which dont happen in parallel to this fcn)
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

                // SAFE: this should always succeed or something is wrong
                var head_reference_rw = self.account_index.getReference(&pubkey).?;
                const head_ref, var head_ref_lg = head_reference_rw.readWithLock();
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
                        try references_to_delete.append(ref);

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
                                    break :ref_blk file_map.get(ref_file_id).?; // we are holding a lock on `disk_accounts.file_rw`.
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
            self.stats.clean_references_deleted.set(references_to_delete.items.len);
            self.logger.debugf(
                "cleaned slot {} - old_state: {}, zero_lamports: {}",
                .{ account_file.slot, num_old_states, num_zero_lamports },
            );
        }

        self.stats.clean_files_queued_deletion.set(delete_account_files.count());
        self.stats.clean_files_queued_shrink.set(delete_account_files.count());
        self.stats.clean_slot_old_state.set(num_old_states);
        self.stats.clean_slot_zero_lamports.set(num_zero_lamports);

        self.stats.time_clean.observe(@floatFromInt(timer.read().asNanos()));
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
            self.stats.number_files_deleted.add(number_of_files);
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
            self.logger.infof("deleting slot: {}...", .{slot});
            account_file.deinit();

            // delete file from disk
            self.deleteAccountFile(slot, account_file.id) catch |err| {
                // NOTE: this should always succeed or something is wrong
                self.logger.errf(
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
                self.logger.warnf("trying to delete accounts file which does not exist: {s}", .{sig.utils.fmt.tryRealPath(self.snapshot_dir, file_path_bounded.constSlice())});
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

        defer {
            const number_of_files = shrink_account_files.len;
            self.stats.number_files_shrunk.add(number_of_files);
        }

        var alive_pubkeys = std.AutoArrayHashMap(Pubkey, void).init(self.allocator);
        defer alive_pubkeys.deinit();

        try delete_account_files.ensureUnusedCapacity(shrink_account_files.len);

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
            self.logger.debugf("shrinking slot: {}...", .{slot});

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

            self.stats.shrink_alive_accounts.observe(@floatFromInt(accounts_alive_count));
            self.stats.shrink_dead_accounts.observe(@floatFromInt(accounts_dead_count));
            self.stats.shrink_file_shrunk_by.observe(@floatFromInt(accounts_dead_size));

            self.logger.debugf("n alive accounts: {}", .{accounts_alive_count});
            self.logger.debugf("n dead accounts: {}", .{accounts_dead_count});
            self.logger.debugf("shrunk by: {}", .{accounts_dead_size});

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
                self.account_index.reference_allocator,
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
                    // SAFE: we know the pubkey exists in the index because its alive
                    const old_ref = self.account_index.getReferenceSlot(pubkey, slot).?;

                    // copy + update the values
                    var new_ref = old_ref;
                    new_ref.location.File.offset = offsets.items[offset_index];
                    new_ref.location.File.file_id = new_file_id;
                    offset_index += 1;

                    const new_ref_ptr = new_reference_block.addOneAssumeCapacity();
                    new_ref_ptr.* = new_ref;

                    // remove + re-add new reference
                    try self.account_index.updateReference(pubkey, slot, new_ref_ptr);

                    if (builtin.mode == .Debug) {
                        std.debug.assert(self.account_index.exists(pubkey, slot));
                    }
                }
            }

            // update slot's reference memory
            {
                const reference_memory, var reference_memory_lg = self.account_index.reference_memory.writeWithLock();
                defer reference_memory_lg.unlock();

                const reference_memory_entry = reference_memory.getEntry(slot) orelse {
                    std.debug.panic("missing corresponding reference memory for slot {d}\n", .{slot});
                };
                // NOTE: this is ok because nothing points to this old reference memory
                // deinit old block of reference memory
                reference_memory_entry.value_ptr.deinit();
                // point to new block
                reference_memory_entry.value_ptr.* = new_reference_block;
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

        self.stats.time_shrink.observe(@floatFromInt(timer.read().asNanos()));

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

        const pubkeys, const accounts = blk: {
            const account_cache, var account_cache_lg = self.account_cache.readWithLock();
            defer account_cache_lg.unlock();

            const pubkeys, const accounts = account_cache.get(slot) orelse {
                // the way it works right now, account files only exist for rooted slots
                // rooted slots should never need to be purged so we should never get here
                @panic("purging an account file not supported");
            };
            break :blk .{ pubkeys, accounts };
        };

        // remove the references
        for (pubkeys) |*pubkey| {
            self.account_index.removeReference(pubkey, slot) catch |err| {
                switch (err) {
                    error.PubkeyNotFound => {
                        std.debug.panic("pubkey not found in index while purging: {any}", .{pubkey});
                    },
                    error.SlotNotFound => {
                        std.debug.panic(
                            "pubkey @ slot not found in index while purging: {any} @ {d}",
                            .{ pubkey, slot },
                        );
                    },
                }
            };
        }

        // free the reference memory
        self.account_index.freeReferenceBlock(slot) catch |err| {
            switch (err) {
                error.MemoryNotFound => {
                    std.debug.panic("memory block @ slot not found: {d}", .{slot});
                },
            }
        };

        // remove the slot from the cache
        const account_cache, var account_cache_lg = self.account_cache.writeWithLock();
        defer account_cache_lg.unlock();
        _ = account_cache.remove(slot);

        // free the account memory
        for (accounts) |account| {
            account.deinit(self.allocator);
        }
        self.allocator.free(accounts);
        self.allocator.free(pubkeys);

        self.stats.time_purge.observe(@floatFromInt(timer.read().asNanos()));
    }

    // NOTE: we need to acquire locks which requires `self: *Self` but we never modify any data
    pub fn getAccountFromRef(self: *Self, account_ref: *const AccountRef) !Account {
        switch (account_ref.location) {
            .File => |ref_info| {
                return try self.getAccountInFile(
                    self.allocator,
                    ref_info.file_id,
                    ref_info.offset,
                );
            },
            .Cache => |ref_info| {
                const account_cache, var account_cache_lg = self.account_cache.readWithLock();
                defer account_cache_lg.unlock();

                _, const accounts = account_cache.get(account_ref.slot) orelse return error.SlotNotFound;
                const account = accounts[ref_info.index];

                return account.clone(self.allocator);
            },
        }
    }

    pub const AccountInCacheOrFileTag = enum { file, cache };
    pub const AccountInCacheOrFile = union(AccountInCacheOrFileTag) {
        file: AccountInFile,
        cache: Account,
    };
    pub const AccountInCacheOrFileLock = union(AccountInCacheOrFileTag) {
        file: *std.Thread.RwLock,
        cache: RwMux(AccountCache).RLockGuard,

        pub fn unlock(lock: *AccountInCacheOrFileLock) void {
            switch (lock.*) {
                .file => |rwlock| rwlock.unlockShared(),
                .cache => |*lg| lg.unlock(),
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
            .Cache => |ref_info| {
                const account_cache, var account_cache_lg = self.account_cache.readWithLock();
                errdefer account_cache_lg.unlock();

                _, const accounts = account_cache.get(account_ref.slot) orelse return error.SlotNotFound;
                return .{
                    .{ .cache = accounts[ref_info.index] },
                    .{ .cache = account_cache_lg },
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
    /// Must call `self.disk_accounts.file_map_fd_rw.unlockShared()`
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
    /// Assumes `self.disk_accounts.file_map_fd_rw` is at least
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
            .Cache => @panic("getAccountHashAndLamportsFromRef is not implemented on cache references"),
        }
    }

    /// gets an account given an associated pubkey. mut ref is required for locks.
    pub fn getAccount(self: *Self, pubkey: *const Pubkey) !Account {
        var head_ref_rw = self.account_index.getReference(pubkey) orelse return error.PubkeyNotInIndex;

        const head_ref, var head_ref_lg = head_ref_rw.readWithLock();
        defer head_ref_lg.unlock();

        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, null, null).?;
        const account = try self.getAccountFromRef(max_ref);

        return account;
    }

    pub const GetAccountError = GetAccountFromRefError || error{PubkeyNotInIndex};
    pub fn getAccountWithReadLock(
        self: *Self,
        pubkey: *const Pubkey,
    ) GetAccountError!struct { AccountInCacheOrFile, AccountInCacheOrFileLock } {
        var head_ref_rw = self.account_index.getReference(pubkey) orelse return error.PubkeyNotInIndex;
        const head_ref, var head_ref_lg = head_ref_rw.readWithLock();
        defer head_ref_lg.unlock();

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
            .file => |in_file| in_file.data,
            .cache => |cached| cached.data,
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
        const bin_counts = try self.allocator.alloc(usize, self.account_index.numberOfBins());
        defer self.allocator.free(bin_counts);
        @memset(bin_counts, 0);

        var references = try ArrayList(AccountRef).initCapacity(
            self.account_index.reference_allocator,
            n_accounts,
        );

        try indexAndValidateAccountFile(
            account_file,
            self.account_index.pubkey_bin_calculator,
            bin_counts,
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
        var total_accounts: usize = 0;
        for (bin_counts, 0..) |count, bin_index| {
            if (count > 0) {
                const bin_rw = self.account_index.getBin(bin_index);
                const bin, var bin_lg = bin_rw.writeWithLock();
                defer bin_lg.unlock();

                try bin.ensureTotalCapacity(bin.count() + count);
                total_accounts += count;
            }
        }

        // compute how many account_references for each pubkey
        var accounts_dead_count: u64 = 0;
        for (references.items) |*ref| {
            const was_inserted = self.account_index.indexRefIfNotDuplicateSlot(ref);
            if (!was_inserted) {
                accounts_dead_count += 1;
                self.logger.warnf(
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

            const account_cache, var account_cache_lg = self.account_cache.writeWithLock();
            defer account_cache_lg.unlock();
            // NOTE: there should only be a single state per slot
            try account_cache.putNoClobber(slot, .{ pubkeys_duped, accounts_duped });
        }

        // prealloc the bins
        const n_bins = self.account_index.numberOfBins();
        var bin_counts = try self.allocator.alloc(usize, n_bins);
        defer self.allocator.free(bin_counts);
        @memset(bin_counts, 0);

        for (pubkeys) |*pubkey| {
            const bin_index = self.account_index.getBinIndex(pubkey);
            bin_counts[bin_index] += 1;
        }

        for (0..n_bins) |bin_index| {
            const bin_rw = self.account_index.getBin(bin_index);
            const bin, var bin_lg = bin_rw.writeWithLock();
            defer bin_lg.unlock();

            const new_len = bin_counts[bin_index] + bin.count();
            if (new_len > 0) {
                try bin.ensureTotalCapacity(new_len);
            }
        }

        // update index
        var accounts_dead_count: u64 = 0;
        var references = try ArrayList(AccountRef).initCapacity(
            self.account_index.reference_allocator,
            accounts.len,
        );
        for (0..accounts.len) |i| {
            const ref_ptr = references.addOneAssumeCapacity();
            ref_ptr.* = AccountRef{
                .pubkey = pubkeys[i],
                .slot = slot,
                .location = .{ .Cache = .{ .index = i } },
            };

            const was_inserted = self.account_index.indexRefIfNotDuplicateSlot(ref_ptr);
            if (!was_inserted) {
                self.logger.warnf(
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

    pub const FullSnapshotGenerationInfo = struct {
        slot: Slot,
        hash: Hash,
        capitalization: u64,
    };

    pub const FullSnapshotGenerationPackage = struct {
        slot: Slot,
        lamports_per_signature: u64,
        bank_hash_info: BankHashInfo,
        bank_fields: BankFields,
        /// This is no longer a meaningful field, but it is useful for testing where you load a snapshot,
        /// write it back, and test that the generated output is equivalent to the original data.
        deprecated_stored_meta_write_version: u64,

        file_infos_map: std.AutoArrayHashMap(Slot, AccountFileInfo),
        file_map_rw: RwMux(FileMap).RLockGuard,

        /// Writes the snapshot in tar archive format to `archive_writer`.
        pub fn write(package: *const FullSnapshotGenerationPackage, archive_writer: anytype, status_cache: StatusCache) !void {
            const snapshot_fields: SnapshotFields = .{
                .bank_fields = package.bank_fields,
                .accounts_db_fields = .{
                    .file_map = package.file_infos_map,

                    .stored_meta_write_version = package.deprecated_stored_meta_write_version,

                    .slot = package.slot,
                    .bank_hash_info = package.bank_hash_info,

                    .rooted_slots = .{},
                    .rooted_slot_hashes = .{},
                },
                .lamports_per_signature = package.lamports_per_signature,
                .bank_fields_inc = .{}, // default to null for full snapshot,
            };

            try writeSnapshotTarWithFields(
                archive_writer,
                sig.version.CURRENT_CLIENT_VERSION,
                status_cache,
                snapshot_fields,
                package.file_map_rw.get(),
            );
        }

        /// Should be called after the snapshot archive has been written. Unlocks the file map.
        pub fn deinit(self: *FullSnapshotGenerationPackage) void {
            self.file_infos_map.deinit();
            self.file_map_rw.unlock();
        }
    };

    /// Locks the file map, generates the rest of the data required to write the archive, as
    /// well as the snapshot generation info (which can be used to generate the name).
    /// The file map will remain locked until the snapshot generation package `deinit`s.
    pub fn makeFullSnapshotGenerationPackage(
        /// Although this is a mutable pointer, this method performs no mutations;
        /// the mutable reference is simply needed in order to obtain a lock on some
        /// fields.
        self: *Self,
        /// The slot to generate a snapshot for.
        /// Must be a flushed slot (`<= self.largest_flushed_slot.load(...)`).
        /// Must be greater than the most recently generated full snapshot.
        /// Must exist explicitly in the database.
        target_slot: Slot,
        /// Temporary: See above TODO
        bank_fields: *BankFields,
        lamports_per_signature: u64,
        /// For tests against older snapshots. Should just be 0 during normal operation.
        deprecated_stored_meta_write_version: u64,
    ) !struct { FullSnapshotGenerationPackage, FullSnapshotGenerationInfo } {
        // NOTE: we hold the lock for the entire duration of the procedure to ensure
        // flush and clean do not create files while generating a snapshot.
        self.file_map_fd_rw.lockShared();
        defer self.file_map_fd_rw.unlockShared();

        var file_map_rw = self.file_map.read();
        errdefer file_map_rw.unlock();
        const file_map = file_map_rw.get();

        std.debug.assert(target_slot <= self.largest_flushed_slot.load(.monotonic));

        var serializable_file_map = std.AutoArrayHashMap(Slot, AccountFileInfo).init(self.allocator);
        errdefer serializable_file_map.deinit();
        try serializable_file_map.ensureTotalCapacity(file_map.count());

        var bank_hash_stats = BankHashStats.zero_init;

        for (file_map.values()) |account_file| {
            if (account_file.slot > target_slot) continue;

            const bank_hash_stats_map, var bank_hash_stats_map_lg = self.bank_hash_stats.readWithLock();
            defer bank_hash_stats_map_lg.unlock();

            if (bank_hash_stats_map.get(account_file.slot)) |other_stats| {
                bank_hash_stats.accumulate(other_stats);
            } else {
                self.logger.warnf("No bank hash stats for slot {}.", .{account_file.slot});
            }

            serializable_file_map.putAssumeCapacityNoClobber(account_file.slot, .{
                .id = account_file.id,
                .length = account_file.length,
            });
        }

        const full_hash, const full_capitalization = try self.computeAccountHashesAndLamports(.{
            .FullAccountHash = .{
                .max_slot = target_slot,
            },
        });

        // TODO: this is a temporary value
        const delta_hash = Hash.default();

        bank_fields.slot = target_slot; // !
        bank_fields.capitalization = full_capitalization; // !

        const package: FullSnapshotGenerationPackage = .{
            .slot = target_slot,

            .lamports_per_signature = lamports_per_signature,
            .bank_hash_info = .{
                .accounts_delta_hash = delta_hash,
                .accounts_hash = full_hash,
                .stats = bank_hash_stats,
            },
            .bank_fields = bank_fields.*,
            .deprecated_stored_meta_write_version = deprecated_stored_meta_write_version,

            .file_infos_map = serializable_file_map,
            .file_map_rw = file_map_rw,
        };
        const info: FullSnapshotGenerationInfo = .{
            .slot = target_slot,
            .hash = full_hash,
            .capitalization = full_capitalization,
        };

        return .{ package, info };
    }

    /// Should be called after writing the snapshot archive from a `makeFullSnapshotGenerationPackage`
    /// on its associated `SnapshotGenerationInfo`.
    pub fn commitFullSnapshotInfo(
        self: *Self,
        snapshot_gen_info: FullSnapshotGenerationInfo,
        old_snapshot_action: enum {
            /// Ignore the previous snapshot.
            ignore_old,
            /// Delete the previous snapshot.
            delete_old,
        },
    ) std.fs.Dir.DeleteFileError!void {
        const latest_full_snapshot_info, var latest_full_snapshot_info_lg = self.latest_full_snapshot_info.writeWithLock();
        defer latest_full_snapshot_info_lg.unlock();

        const maybe_old_snapshot_info: ?FullSnapshotGenerationInfo = latest_full_snapshot_info.*;
        latest_full_snapshot_info.* = snapshot_gen_info;
        if (maybe_old_snapshot_info) |old_snapshot_info| {
            std.debug.assert(old_snapshot_info.slot <= snapshot_gen_info.slot);
        }

        switch (old_snapshot_action) {
            .ignore_old => {},
            .delete_old => if (maybe_old_snapshot_info) |old_snapshot_info| {
                const old_name_bounded = sig.accounts_db.snapshots.FullSnapshotFileInfo.snapshotNameStr(.{
                    .slot = old_snapshot_info.slot,
                    .hash = old_snapshot_info.hash,
                    .compression = .zstd,
                });
                const old_name = old_name_bounded.constSlice();

                self.logger.infof("deleting old full snapshot archive: {s}", .{old_name});
                try self.snapshot_dir.deleteFile(old_name);
            },
        }
    }

    pub const IncSnapshotGenerationInfo = struct {
        base_slot: Slot,
        slot: Slot,
        hash: Hash,
        capitalization: u64,
    };

    pub const IncSnapshotGenerationPackage = struct {
        slot: Slot,
        lamports_per_signature: u64,
        bank_hash_info: BankHashInfo,
        bank_fields: BankFields,
        snapshot_persistence: BankIncrementalSnapshotPersistence,
        /// This is no longer a meaningful field, but it is useful for testing where you load a snapshot,
        /// write it back, and test that the generated output is equivalent to the original data.
        deprecated_stored_meta_write_version: u64,

        file_infos_map: std.AutoArrayHashMap(Slot, AccountFileInfo),
        file_map_rw: RwMux(FileMap).RLockGuard,

        /// Writes the snapshot in tar archive format to `archive_writer`.
        pub fn write(package: *const IncSnapshotGenerationPackage, archive_writer: anytype) !void {
            const snapshot_fields: SnapshotFields = .{
                .bank_fields = package.bank_fields,
                .accounts_db_fields = .{
                    .file_map = package.file_infos_map,

                    .stored_meta_write_version = package.deprecated_stored_meta_write_version,

                    .slot = package.slot,
                    .bank_hash_info = package.bank_hash_info,

                    .rooted_slots = .{},
                    .rooted_slot_hashes = .{},
                },
                .lamports_per_signature = package.lamports_per_signature,
                .bank_fields_inc = .{
                    .snapshot_persistence = package.snapshot_persistence,
                    // TODO: the other fields default to null, but this may not always be correct.
                },
            };

            try writeSnapshotTarWithFields(
                archive_writer,
                sig.version.CURRENT_CLIENT_VERSION,
                .{ .bank_slot_deltas = &.{} },
                snapshot_fields,
                package.file_map_rw.get(),
            );
        }

        /// Should be called after the snapshot archive has been written. Unlocks the file map.
        pub fn deinit(self: *IncSnapshotGenerationPackage) void {
            self.file_infos_map.deinit();
            self.file_map_rw.unlock();
        }
    };

    pub const MakeIncSnapshotPackgeError = error{NoFullSnapshotExists} || ComputeAccountHashesAndLamportsError || std.mem.Allocator.Error;

    /// Locks the file map, generates the rest of the data required to write the archive, as
    /// well as the snapshot generation info (which can be used to generate the name).
    /// The file map will remain locked until the snapshot generation package `deinit`s.
    /// There must have been at least one full snapshot generated before calling this,
    /// otherwise it will return `error.NoFullSnapshotExists`.
    pub fn makeIncrementalSnapshotGenerationPackage(
        /// Although this is a mutable pointer, this method performs no mutations;
        /// the mutable reference is simply needed in order to obtain a lock on some
        /// fields.
        self: *Self,
        /// The slot to generate a snapshot for.
        /// Must be a flushed slot (`<= self.largest_flushed_slot.load(...)`).
        /// Must be greater than the most recently generated full snapshot.
        /// Must exist explicitly in the database.
        target_slot: Slot,
        /// Temporary: See above TODO
        bank_fields: *BankFields,
        lamports_per_signature: u64,
        /// For tests against older snapshots. Should just be 0 during normal operation.
        deprecated_stored_meta_write_version: u64,
    ) MakeIncSnapshotPackgeError!struct { IncSnapshotGenerationPackage, IncSnapshotGenerationInfo } {
        // NOTE: we hold the lock for the entire duration of the procedure to ensure
        // flush and clean do not create files while generating a snapshot.
        self.file_map_fd_rw.lockShared();
        defer self.file_map_fd_rw.unlockShared();

        var file_map_rw = self.file_map.read();
        errdefer file_map_rw.unlock();
        const file_map = file_map_rw.get();

        const p_maybe_full_snapshot_info, var full_snapshot_info_lg = self.latest_full_snapshot_info.readWithLock();
        defer full_snapshot_info_lg.unlock();
        const full_snapshot_info = p_maybe_full_snapshot_info.* orelse return error.NoFullSnapshotExists;

        var serializable_file_map = std.AutoArrayHashMap(Slot, AccountFileInfo).init(self.allocator);
        errdefer serializable_file_map.deinit();
        try serializable_file_map.ensureTotalCapacity(file_map.count());

        var bank_hash_stats = BankHashStats.zero_init;

        for (file_map.values()) |account_file| {
            if (account_file.slot <= full_snapshot_info.slot) continue;
            if (account_file.slot > target_slot) continue;

            const bank_hash_stats_map, var bank_hash_stats_map_lg = self.bank_hash_stats.readWithLock();
            defer bank_hash_stats_map_lg.unlock();

            if (bank_hash_stats_map.get(account_file.slot)) |other_stats| {
                bank_hash_stats.accumulate(other_stats);
            } else {
                self.logger.warnf("No bank hash stats for slot {}.", .{account_file.slot});
            }

            serializable_file_map.putAssumeCapacityNoClobber(account_file.slot, .{
                .id = account_file.id,
                .length = account_file.length,
            });
        }

        const incremental_hash, //
        const incremental_capitalization //
        = try self.computeAccountHashesAndLamports(.{
            .IncrementalAccountHash = .{
                .min_slot = full_snapshot_info.slot,
                .max_slot = target_slot,
            },
        });

        // TODO: compute the correct value during account writes
        const delta_hash = Hash.default();

        bank_fields.slot = target_slot; // !

        const package: IncSnapshotGenerationPackage = .{
            .slot = target_slot,

            .lamports_per_signature = lamports_per_signature,
            .bank_hash_info = .{
                .accounts_delta_hash = delta_hash,
                .accounts_hash = Hash.default(),
                .stats = bank_hash_stats,
            },
            .bank_fields = bank_fields.*,
            .snapshot_persistence = .{
                .full_slot = full_snapshot_info.slot,
                .full_hash = full_snapshot_info.hash,
                .full_capitalization = full_snapshot_info.capitalization,
                .incremental_hash = incremental_hash,
                .incremental_capitalization = incremental_capitalization,
            },
            .deprecated_stored_meta_write_version = deprecated_stored_meta_write_version,

            .file_infos_map = serializable_file_map,
            .file_map_rw = file_map_rw,
        };
        const info: IncSnapshotGenerationInfo = .{
            .base_slot = full_snapshot_info.slot,
            .slot = target_slot,
            .hash = incremental_hash,
            .capitalization = incremental_capitalization,
        };

        return .{ package, info };
    }

    pub fn commitIncrementalSnapshotInfo(
        self: *Self,
        snapshot_gen_info: IncSnapshotGenerationInfo,
        old_snapshot_action: enum {
            /// Ignore the previous snapshot.
            ignore_old,
            /// Delete the previous snapshot.
            delete_old,
        },
    ) std.fs.Dir.DeleteFileError!void {
        const latest_incremental_snapshot_info, var latest_incremental_snapshot_info_lg = self.latest_incremental_snapshot_info.writeWithLock();
        defer latest_incremental_snapshot_info_lg.unlock();

        const maybe_old_snapshot_info: ?IncSnapshotGenerationInfo = latest_incremental_snapshot_info.*;
        latest_incremental_snapshot_info.* = snapshot_gen_info;
        if (maybe_old_snapshot_info) |old_snapshot_info| {
            std.debug.assert(old_snapshot_info.slot <= snapshot_gen_info.slot);
        }

        switch (old_snapshot_action) {
            .ignore_old => {},
            .delete_old => if (maybe_old_snapshot_info) |old_snapshot_info| {
                const old_name_bounded = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo.snapshotNameStr(.{
                    .base_slot = old_snapshot_info.base_slot,
                    .slot = old_snapshot_info.slot,
                    .hash = old_snapshot_info.hash,
                    .compression = .zstd,
                });
                const old_name = old_name_bounded.constSlice();

                self.logger.infof("deleting old incremental snapshot archive: {s}", .{old_name});
                try self.snapshot_dir.deleteFile(old_name);
            },
        }
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
    BinCountMismatch,
    InvalidAccountFileLength,
    OutOfMemory,
} || AccountInFile.ValidateError || GeyserTmpStorage.Error;

pub fn indexAndValidateAccountFile(
    accounts_file: *AccountFile,
    pubkey_bin_calculator: PubkeyBinCalculator,
    bin_counts: []usize,
    account_refs: *ArrayList(AccountRef),
    geyser_storage: ?*GeyserTmpStorage,
) ValidateAccountFileError!void {
    var offset: usize = 0;
    var number_of_accounts: usize = 0;

    if (bin_counts.len != pubkey_bin_calculator.n_bins) {
        return error.BinCountMismatch;
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
        const bin_index = pubkey_bin_calculator.binIndex(pubkey);
        bin_counts[bin_index] += 1;

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
    version: ClientVersion,
    status_cache: StatusCache,
    snapshot_fields: SnapshotFields,
    file_map: *const AccountsDB.FileMap,
) !void {
    const slot: Slot = snapshot_fields.bank_fields.slot;

    var counting_writer_state = std.io.countingWriter(archive_writer);
    const writer = counting_writer_state.writer();

    // write the version file
    const version_str_bounded = sig.utils.fmt.boundedFmt("{d}.{d}.{d}", .{ version.major, version.minor, version.patch });
    const version_str = version_str_bounded.constSlice();
    try sig.utils.tar.writeTarHeader(writer, .regular, "version", version_str.len);
    try writer.writeAll(version_str);
    try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(counting_writer_state.bytes_written));

    // create the snapshots dir
    try sig.utils.tar.writeTarHeader(writer, .directory, "snapshots/", 0);

    // write the status cache
    try sig.utils.tar.writeTarHeader(writer, .regular, "snapshots/status_cache", bincode.sizeOf(status_cache, .{}));
    try bincode.write(writer, status_cache, .{});
    try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(counting_writer_state.bytes_written));

    // write the manifest
    const manifest = snapshot_fields;
    const manifest_encoded_size = bincode.sizeOf(manifest, .{});

    const dir_name_bounded = sig.utils.fmt.boundedFmt("snapshots/{d}/", .{slot});
    try sig.utils.tar.writeTarHeader(writer, .directory, dir_name_bounded.constSlice(), 0);

    const file_name_bounded = sig.utils.fmt.boundedFmt("snapshots/{0d}/{0d}", .{slot});
    try sig.utils.tar.writeTarHeader(writer, .regular, file_name_bounded.constSlice(), manifest_encoded_size);
    try bincode.write(writer, manifest, .{});
    try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(counting_writer_state.bytes_written));

    // create the accounts dir
    try sig.utils.tar.writeTarHeader(writer, .directory, "accounts/", 0);

    const file_info_map = &snapshot_fields.accounts_db_fields.file_map;
    for (file_info_map.keys(), file_info_map.values()) |account_slot, account_file_info| {
        const account_file = file_map.getPtr(account_file_info.id) orelse unreachable;
        std.debug.assert(account_file.id == account_file_info.id);

        const name_bounded = sig.utils.fmt.boundedFmt("accounts/{d}.{d}", .{ account_slot, account_file_info.id.toInt() });
        try sig.utils.tar.writeTarHeader(writer, .regular, name_bounded.constSlice(), account_file.memory.len);
        try writer.writeAll(account_file.memory);
        try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(counting_writer_state.bytes_written));
        counting_writer_state.bytes_written %= 512;
        std.debug.assert(counting_writer_state.bytes_written == 0);
    }

    // write the sentinel blocks
    try writer.writeByteNTimes(0, 512 * 2);
}

fn testWriteSnapshotFull(
    accounts_db: *AccountsDB,
    slot: Slot,
    maybe_expected_hash: ?Hash,
) !void {
    const allocator = std.testing.allocator;
    const snapshot_dir = accounts_db.snapshot_dir;

    const manifest_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{slot});
    const manifest_file = try snapshot_dir.openFile(manifest_path_bounded.constSlice(), .{});
    defer manifest_file.close();

    var snap_fields = try SnapshotFields.decodeFromBincode(allocator, manifest_file.reader());
    defer snap_fields.deinit(allocator);

    _ = try accounts_db.loadFromSnapshot(snap_fields.accounts_db_fields, 1, allocator, 1_500);

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    const snapshot_gen_info = blk: {
        var snapshot_gen_pkg, const snapshot_gen_info = try accounts_db.makeFullSnapshotGenerationPackage(
            slot,
            &snap_fields.bank_fields,
            snap_fields.lamports_per_signature,
            snap_fields.accounts_db_fields.stored_meta_write_version,
        );
        defer snapshot_gen_pkg.deinit();

        const archive_file_name_bounded = sig.accounts_db.snapshots.FullSnapshotFileInfo.snapshotNameStr(.{
            .slot = snapshot_gen_info.slot,
            .hash = snapshot_gen_info.hash,
            .compression = .zstd,
        });
        const archive_file_name = archive_file_name_bounded.constSlice();
        const archive_file = try tmp_dir.createFile(archive_file_name, .{ .read = true });
        errdefer archive_file.close();

        var buffered_state = std.io.bufferedWriter(archive_file.writer());
        try snapshot_gen_pkg.write(buffered_state.writer(), StatusCache.default());
        try buffered_state.flush();

        try accounts_db.commitFullSnapshotInfo(snapshot_gen_info, .ignore_old);

        break :blk snapshot_gen_info;
    };
    try std.testing.expectEqual(slot, snapshot_gen_info.slot);
    if (maybe_expected_hash) |expected_hash| {
        try std.testing.expectEqual(expected_hash, snapshot_gen_info.hash);
    }

    _ = try accounts_db.validateLoadFromSnapshot(
        null,
        slot,
        snapshot_gen_info.capitalization,
        snapshot_gen_info.hash,
    );
}

fn testWriteSnapshotIncremental(
    accounts_db: *AccountsDB,
    slot: Slot,
    maybe_expected_incremental_hash: ?Hash,
) !void {
    const allocator = std.testing.allocator;
    const snapshot_dir = accounts_db.snapshot_dir;

    const manifest_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{slot});
    const manifest_file = try snapshot_dir.openFile(manifest_path_bounded.constSlice(), .{});
    defer manifest_file.close();

    var snap_fields = try SnapshotFields.decodeFromBincode(allocator, manifest_file.reader());
    defer snap_fields.deinit(allocator);

    _ = try accounts_db.loadFromSnapshot(snap_fields.accounts_db_fields, 1, allocator, 1_500);

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    const snapshot_gen_info, const incremental_persistence: BankIncrementalSnapshotPersistence = blk: {
        var snapshot_gen_pkg, const snapshot_gen_info = try accounts_db.makeIncrementalSnapshotGenerationPackage(
            slot,
            &snap_fields.bank_fields,
            snap_fields.lamports_per_signature,
            snap_fields.accounts_db_fields.stored_meta_write_version,
        );
        defer snapshot_gen_pkg.deinit();

        const archive_file_name_bounded = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo.snapshotNameStr(.{
            .base_slot = snapshot_gen_info.base_slot,
            .slot = snapshot_gen_info.slot,
            .hash = snapshot_gen_info.hash,
            .compression = .zstd,
        });
        const archive_file_name = archive_file_name_bounded.constSlice();
        const archive_file = try tmp_dir.createFile(archive_file_name, .{ .read = true });
        errdefer archive_file.close();

        var buffered_state = std.io.bufferedWriter(archive_file.writer());
        try snapshot_gen_pkg.write(buffered_state.writer());
        try buffered_state.flush();

        break :blk .{ snapshot_gen_info, snapshot_gen_pkg.snapshot_persistence };
    };

    try std.testing.expectEqual(slot, snapshot_gen_info.slot);
    if (maybe_expected_incremental_hash) |expected_hash| {
        try std.testing.expectEqual(expected_hash, snapshot_gen_info.hash);
    }
    try std.testing.expectEqual(incremental_persistence.incremental_hash, snapshot_gen_info.hash);

    _ = try accounts_db.validateLoadFromSnapshot(
        incremental_persistence,
        incremental_persistence.full_slot,
        incremental_persistence.full_capitalization,
        incremental_persistence.full_hash,
    );
}

test "testWriteSnapshot" {
    var test_data_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer test_data_dir.close();

    const snap_files = try SnapshotFiles.find(std.testing.allocator, test_data_dir);

    var tmp_snap_dir_root = std.testing.tmpDir(.{});
    defer tmp_snap_dir_root.cleanup();
    const tmp_snap_dir = tmp_snap_dir_root.dir;

    {
        const archive_file = try test_data_dir.openFile(snap_files.full_snapshot.snapshotNameStr().constSlice(), .{});
        defer archive_file.close();
        try parallelUnpackZstdTarBall(std.testing.allocator, .noop, archive_file, tmp_snap_dir, 4, true);
    }

    if (snap_files.incremental_snapshot) |inc_snap| {
        const archive_file = try test_data_dir.openFile(inc_snap.snapshotNameStr().constSlice(), .{});
        defer archive_file.close();
        try parallelUnpackZstdTarBall(std.testing.allocator, .noop, archive_file, tmp_snap_dir, 4, false);
    }

    var accounts_db = try AccountsDB.init(std.testing.allocator, .noop, tmp_snap_dir, .{
        .number_of_index_bins = ACCOUNT_INDEX_BINS,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit(true);

    try testWriteSnapshotFull(&accounts_db, snap_files.full_snapshot.slot, snap_files.full_snapshot.hash);
    try testWriteSnapshotIncremental(&accounts_db, snap_files.incremental_snapshot.?.slot, snap_files.incremental_snapshot.?.hash);
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

    const logger = Logger{ .noop = {} };
    // var logger = Logger.init(std.heap.page_allocator, .debug);

    var snapshots = try AllSnapshotFields.fromFiles(allocator, logger, dir, snapshot_files);
    errdefer snapshots.deinit(allocator);

    const snapshot = try snapshots.collapse();
    var accounts_db = try AccountsDB.init(allocator, logger, dir, .{
        .number_of_index_bins = 4,
        .use_disk_index = use_disk,
    }, null);
    errdefer accounts_db.deinit(true);

    _ = try accounts_db.loadFromSnapshot(snapshot.accounts_db_fields, n_threads, allocator, 1_500);

    return .{ accounts_db, snapshots };
}

// NOTE: this is a memory leak test - geyser correctness is tested in the geyser tests
test "geyser stream on load" {
    const allocator = std.testing.allocator;

    var dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer dir.close();
    try unpackTestSnapshot(allocator, 2);

    const snapshot_files = try SnapshotFiles.find(allocator, dir);

    const logger = Logger{ .noop = {} };
    // var logger = Logger.init(std.heap.page_allocator, .debug);

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
        geyser_exit,
        geyser_pipe_path,
        null,
        null,
    });
    defer {
        geyser_exit.store(true, .unordered);
        _ = reader_handle.join();
    }

    const snapshot = try snapshots.collapse();
    var accounts_db = try AccountsDB.init(
        allocator,
        logger,
        dir,
        .{
            .number_of_index_bins = 4,
            .use_disk_index = false,
        },
        geyser_writer,
    );
    defer {
        accounts_db.deinit(true);
        snapshots.deinit(allocator);
    }

    var accounts_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR ++ "accounts", .{});
    defer accounts_dir.close();

    _ = try accounts_db.loadFromSnapshot(
        snapshot.accounts_db_fields,
        1,
        allocator,
        1_500,
    );
}

test "write and read an account" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(std.testing.allocator, false, 1);
    defer {
        accounts_db.deinit(true);
        snapshots.deinit(allocator);
    }

    var rng = std.rand.DefaultPrng.init(0);
    const pubkey = Pubkey.random(rng.random());
    var data = [_]u8{ 1, 2, 3 };
    const test_account = Account{
        .data = &data,
        .executable = false,
        .lamports = 100,
        .owner = Pubkey.default(),
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

test "load and validate from test snapshot using disk index" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(std.testing.allocator, false, 1);
    defer {
        accounts_db.deinit(true);
        snapshots.deinit(allocator);
    }

    _ = try accounts_db.validateLoadFromSnapshot(
        snapshots.incremental.?.bank_fields_inc.snapshot_persistence,
        snapshots.full.bank_fields.slot,
        snapshots.full.bank_fields.capitalization,
        snapshots.full.accounts_db_fields.bank_hash_info.accounts_hash,
    );
}

test "load and validate from test snapshot parallel" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(std.testing.allocator, false, 2);
    defer {
        accounts_db.deinit(true);
        snapshots.deinit(allocator);
    }

    _ = try accounts_db.validateLoadFromSnapshot(
        snapshots.incremental.?.bank_fields_inc.snapshot_persistence,
        snapshots.full.bank_fields.slot,
        snapshots.full.bank_fields.capitalization,
        snapshots.full.accounts_db_fields.bank_hash_info.accounts_hash,
    );
}

test "load and validate from test snapshot" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(std.testing.allocator, false, 1);
    defer {
        accounts_db.deinit(true);
        snapshots.deinit(allocator);
    }

    _ = try accounts_db.validateLoadFromSnapshot(
        snapshots.incremental.?.bank_fields_inc.snapshot_persistence,
        snapshots.full.bank_fields.slot,
        snapshots.full.bank_fields.capitalization,
        snapshots.full.accounts_db_fields.bank_hash_info.accounts_hash,
    );
}

test "load clock sysvar" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(std.testing.allocator, false, 1);
    defer {
        accounts_db.deinit(true);
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

    var accounts_db, var snapshots = try loadTestAccountsDB(std.testing.allocator, false, 1);
    defer {
        accounts_db.deinit(true);
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
    const logger = Logger{ .noop = {} };
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_bins = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit(true);

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();
    const n_accounts = 3;

    // we dont defer deinit to make sure that they are cleared on purge
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.random(rng);
        account.* = try Account.random(allocator, rng, i % 1_000);
    }
    defer for (accounts) |account| account.deinit(allocator);

    // this gets written to cache
    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // this writes to disk
    var unclean_account_files = ArrayList(FileId).init(std.testing.allocator);
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
    const logger = Logger{ .noop = {} };
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_bins = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit(true);

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();
    const n_accounts = 3;

    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;

    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.random(rng);
        account.* = try Account.random(allocator, rng, i % 1_000);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const pubkey_copy: [n_accounts]Pubkey = pubkeys;

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    for (0..n_accounts) |i| {
        try std.testing.expect(
            accounts_db.account_index.getReference(&pubkeys[i]) != null,
        );
    }

    accounts_db.purgeSlot(slot);

    // ref backing memory is cleared
    {
        const reference_memory, var reference_memory_lg = accounts_db.account_index.reference_memory.readWithLock();
        defer reference_memory_lg.unlock();

        try std.testing.expect(reference_memory.count() == 0);
    }
    // account cache is cleared
    {
        var lg = accounts_db.account_cache.read();
        defer lg.unlock();
        try std.testing.expect(lg.get().count() == 0);
    }

    // ref hashmap is cleared
    for (0..n_accounts) |i| {
        try std.testing.expect(accounts_db.account_index.getReference(&pubkey_copy[i]) == null);
    }
}

test "clean to shrink account file works with zero-lamports" {
    const allocator = std.testing.allocator;
    const logger = Logger{ .noop = {} };
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_bins = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit(true);

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();
    const n_accounts = 10;

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.random(rng);
        account.* = try Account.random(allocator, rng, 100);
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
        account.* = try Account.random(allocator, rng, i % 1_000);
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
    const logger = Logger{ .noop = {} };
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_bins = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit(true);

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();
    const n_accounts = 10;

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.random(rng);
        account.* = try Account.random(allocator, rng, 100);
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
        account.* = try Account.random(allocator, rng, i % 1_000);
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
    const logger = Logger{ .noop = {} };
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_bins = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit(true);

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();
    const n_accounts = 3;

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.random(rng);
        account.* = try Account.random(allocator, rng, i % 1_000);
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
        account.* = try Account.random(allocator, rng, i % 1_000);
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
    const logger = Logger{ .noop = {} };
    var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.TEST_DATA_DIR, .{});
    defer snapshot_dir.close();
    var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
        .number_of_index_bins = 4,
        .use_disk_index = false,
    }, null);
    defer accounts_db.deinit(true);

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    const n_accounts = 10;

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;

    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.random(rng);
        account.* = try Account.random(allocator, rng, 100);
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
        account.* = try Account.random(allocator, rng, i % 1_000);
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
        const reference_memory, var reference_memory_lg = accounts_db.account_index.reference_memory.readWithLock();
        defer reference_memory_lg.unlock();

        const slot_mem = reference_memory.get(new_slot).?;
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
        const reference_memory, var reference_memory_lg = accounts_db.account_index.reference_memory.readWithLock();
        defer reference_memory_lg.unlock();

        const slot_mem = reference_memory.get(slot).?;
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

    pub fn loadSnapshot(bench_args: BenchArgs) !u64 {
        const allocator = std.heap.page_allocator;

        // unpack the snapshot
        // NOTE: usually this will be an incremental snapshot
        // renamed as a full snapshot (mv {inc-snap-fmt}.tar.zstd {full-snap-fmt}.tar.zstd)
        // (because test snapshots are too small and full snapshots are too big)
        const dir_path = sig.TEST_DATA_DIR ++ "bench_snapshot/";
        const accounts_path = dir_path ++ "accounts";

        // const logger = Logger{ .noop = {} };
        const logger = Logger.init(allocator, .debug);
        defer logger.deinit();
        logger.spawn();

        const snapshot_dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch {
            std.debug.print("need to setup a snapshot in {s} for this benchmark...\n", .{dir_path});
            return 0;
        };

        const snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);

        std.fs.cwd().access(accounts_path, .{}) catch {
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
        };

        var snapshots = try AllSnapshotFields.fromFiles(allocator, logger, snapshot_dir, snapshot_files);
        defer snapshots.deinit(allocator);
        const snapshot = try snapshots.collapse();

        var accounts_db = try AccountsDB.init(allocator, logger, snapshot_dir, .{
            .number_of_index_bins = 32,
            .use_disk_index = bench_args.use_disk,
        }, null);
        defer accounts_db.deinit(false);

        var accounts_dir = try std.fs.cwd().openDir(accounts_path, .{ .iterate = true });
        defer accounts_dir.close();

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

        return duration.asNanos();
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

    pub fn readWriteAccounts(bench_args: BenchArgs) !u64 {
        const n_accounts = bench_args.n_accounts;
        const slot_list_len = bench_args.slot_list_len;
        const total_n_accounts = n_accounts * slot_list_len;

        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        var allocator = gpa.allocator();

        const disk_path = sig.TEST_DATA_DIR ++ "tmp/";
        std.fs.cwd().makeDir(disk_path) catch {};

        var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.VALIDATOR_DIR ++ "accounts_db", .{});
        defer snapshot_dir.close();

        const logger = Logger{ .noop = {} };
        var accounts_db: AccountsDB = try AccountsDB.init(allocator, logger, snapshot_dir, .{
            .number_of_index_bins = ACCOUNT_INDEX_BINS,
            .use_disk_index = bench_args.index == .disk,
        }, null);
        defer accounts_db.deinit(true);

        var random = std.Random.DefaultPrng.init(19);
        const rng = random.random();

        var pubkeys = try allocator.alloc(Pubkey, n_accounts);
        defer allocator.free(pubkeys);
        for (0..n_accounts) |i| {
            pubkeys[i] = Pubkey.random(rng);
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
                accounts[i] = try Account.random(allocator, rng, i % 1_000);
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
                const filepath = try std.fmt.allocPrint(allocator, disk_path ++ "slot{d}.bin", .{s});

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
                        const account = try Account.random(allocator, rng, i % 1_000);
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

        var timer = try std.time.Timer.start();
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
