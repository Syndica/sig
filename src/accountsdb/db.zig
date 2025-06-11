//! includes the main database struct `AccountsDB`

const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const zstd = @import("zstd");
const tracy = @import("tracy");

const sysvar = sig.runtime.sysvar;
const snapgen = sig.accounts_db.snapshots.generate;

const BenchTimeUnit = @import("../benchmarks.zig").BenchTimeUnit;

const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Blake3 = std.crypto.hash.Blake3;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const BankFields = sig.core.BankFields;

const AccountFile = sig.accounts_db.accounts_file.AccountFile;
const AccountInFile = sig.accounts_db.accounts_file.AccountInFile;
const FileId = sig.accounts_db.accounts_file.FileId;
const StatusCache = sig.accounts_db.StatusCache;

const AccountsDbFields = sig.accounts_db.snapshots.AccountsDbFields;
const BankHashStats = sig.accounts_db.snapshots.BankHashStats;
const BankIncrementalSnapshotPersistence =
    sig.accounts_db.snapshots.BankIncrementalSnapshotPersistence;
const FullAndIncrementalManifest = sig.accounts_db.snapshots.FullAndIncrementalManifest;
const FullSnapshotFileInfo = sig.accounts_db.snapshots.FullSnapshotFileInfo;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo;
const SnapshotFiles = sig.accounts_db.snapshots.SnapshotFiles;
const SnapshotManifest = sig.accounts_db.snapshots.Manifest;

const AccountDataHandle = sig.accounts_db.buffer_pool.AccountDataHandle;
const AccountIndex = sig.accounts_db.index.AccountIndex;
const AccountRef = sig.accounts_db.index.AccountRef;
const BufferPool = sig.accounts_db.buffer_pool.BufferPool;
const PubkeyShardCalculator = sig.accounts_db.index.PubkeyShardCalculator;
const ShardedPubkeyRefMap = sig.accounts_db.index.ShardedPubkeyRefMap;

const Account = sig.core.Account;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const NestedHashTree = sig.utils.merkle_tree.NestedHashTree;
const Logger = sig.trace.log.Logger;
const GeyserWriter = sig.geyser.GeyserWriter;

const Counter = sig.prometheus.counter.Counter;
const Gauge = sig.prometheus.Gauge;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const Histogram = sig.prometheus.histogram.Histogram;

const WeightedAliasSampler = sig.rand.WeightedAliasSampler;

const RwMux = sig.sync.RwMux;

const parallelUnpackZstdTarBall = sig.accounts_db.snapshots.parallelUnpackZstdTarBall;
const spawnThreadTasks = sig.utils.thread.spawnThreadTasks;
const printTimeEstimate = sig.time.estimate.printTimeEstimate;
const globalRegistry = sig.prometheus.registry.globalRegistry;

const LOG_SCOPE = "accounts_db";
const ScopedLogger = sig.trace.log.ScopedLogger(LOG_SCOPE);

pub const DB_LOG_RATE = sig.time.Duration.fromSecs(5);

pub const MERKLE_FANOUT: usize = 16;
pub const ACCOUNT_INDEX_SHARDS: usize = 8192;
pub const DELETE_ACCOUNT_FILES_MIN = 100;

/// database for accounts
///
/// Analogous to [AccountsDb](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L1363)
pub const AccountsDB = struct {

    // injected dependencies
    allocator: std.mem.Allocator,
    metrics: AccountsDBMetrics,
    logger: ScopedLogger,

    /// Not closed by the `AccountsDB`, but must live at least as long as it.
    snapshot_dir: std.fs.Dir,
    geyser_writer: ?*GeyserWriter,
    gossip_view: ?GossipView,

    // some static data
    number_of_index_shards: usize,

    // internal structures & data

    /// maps pubkeys to account locations
    account_index: AccountIndex,

    /// per-slot map containing a list of pubkeys and accounts.
    /// This is tracked per-slot for purge/flush
    unrooted_accounts: RwMux(SlotPubkeyAccounts),

    /// NOTE: see accountsdb/readme.md for more details on how these are used
    file_map: RwMux(FileMap),
    /// `file_map_fd_rw` is used to ensure files in the file_map are not closed while its held as a read-lock.
    /// NOTE: see accountsdb/readme.md for more details on how these are used
    file_map_fd_rw: std.Thread.RwLock,

    buffer_pool: BufferPool,

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
    largest_file_id: FileId,
    // TODO: integrate these values into consensus
    /// Used for flushing/cleaning/purging/shrinking.
    largest_rooted_slot: std.atomic.Value(Slot),
    /// Represents the largest slot for which all account data has been flushed to disk.
    /// Always `<= largest_rooted_slot`.
    largest_flushed_slot: std.atomic.Value(Slot),

    /// The snapshot info from which this instance was loaded from and validated against (null if that didn't happen).
    /// Used to potentially skip the first `computeAccountHashesAndLamports`.
    first_snapshot_load_info: RwMux(?SnapshotGenerationInfo),
    /// Represents the largest slot info used to generate a full snapshot, and optionally an incremental snapshot relative to it, which currently exists.
    /// It also protects access to the snapshot archive files it refers to - as in, the caller who has a lock on this has a lock on the snapshot archives.
    latest_snapshot_gen_info: RwMux(?SnapshotGenerationInfo),

    // TODO: populate this during snapshot load
    // TODO: move to Bank struct
    bank_hash_stats: RwMux(BankHashStatsMap),

    pub const PubkeysAndAccounts = struct { []const Pubkey, []const Account };
    pub const SlotPubkeyAccounts = std.AutoHashMap(Slot, PubkeysAndAccounts);
    pub const DeadAccountsCounter = std.AutoArrayHashMap(Slot, u64);
    pub const BankHashStatsMap = std.AutoArrayHashMapUnmanaged(Slot, BankHashStats);
    pub const FileMap = std.AutoArrayHashMapUnmanaged(FileId, AccountFile);

    pub const GossipView = struct {
        /// Used to initialize snapshot hashes to be sent to gossip.
        my_pubkey: Pubkey,
        /// Reference to the gossip service's message push queue, used to push updates to snapshot info.
        push_msg_queue: *sig.gossip.GossipService.PushMessageQueue,

        // TODO/NOTE: this will be more useful/nicer to use as a decl literal
        pub fn fromService(gossip_service: *sig.gossip.GossipService) !GossipView {
            return .{
                .my_pubkey = gossip_service.my_pubkey,
                .push_msg_queue = &gossip_service.push_msg_queue_mux,
            };
        }
    };

    pub const InitParams = struct {
        pub const Index = union(AccountIndex.AllocatorConfig.Tag) {
            ram,
            disk,
            parent: *sig.accounts_db.index.ReferenceAllocator,
        };
        allocator: std.mem.Allocator,
        logger: Logger,
        snapshot_dir: std.fs.Dir,
        geyser_writer: ?*GeyserWriter,
        gossip_view: ?GossipView,
        index_allocation: Index,
        number_of_index_shards: usize,
        /// Amount of BufferPool frames, used for cached reads. Default = 1GiB.
        buffer_pool_frames: u32 = 2 * 1024 * 1024,
    };

    pub fn init(params: InitParams) !AccountsDB {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb init" });
        defer zone.deinit();

        // init index
        const index_config: AccountIndex.AllocatorConfig = switch (params.index_allocation) {
            .disk => .{ .disk = .{ .accountsdb_dir = params.snapshot_dir } },
            .ram => .{ .ram = .{ .allocator = params.allocator } },
            .parent => |parent| .{ .parent = parent },
        };

        var account_index = try AccountIndex.init(
            params.allocator,
            params.logger,
            index_config,
            params.number_of_index_shards,
        );
        errdefer account_index.deinit();

        const metrics = try AccountsDBMetrics.init();

        // NOTE: we need the accounts directory to exist to create new account files correctly
        params.snapshot_dir.makePath("accounts") catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => |e| return e,
        };

        const buffer_pool = try BufferPool.init(params.allocator, params.buffer_pool_frames);
        errdefer buffer_pool.deinit(params.allocator);

        const unrooted_accounts = SlotPubkeyAccounts.init(params.allocator);
        const dead_accounts_counter = DeadAccountsCounter.init(params.allocator);

        return .{
            .allocator = params.allocator,
            .metrics = metrics,
            .logger = params.logger.withScope(LOG_SCOPE),
            .snapshot_dir = params.snapshot_dir,
            .geyser_writer = params.geyser_writer,
            .gossip_view = params.gossip_view,

            .number_of_index_shards = params.number_of_index_shards,

            .account_index = account_index,
            .unrooted_accounts = RwMux(SlotPubkeyAccounts).init(unrooted_accounts),
            .file_map = RwMux(FileMap).init(.{}),
            .file_map_fd_rw = .{},
            .buffer_pool = buffer_pool,
            .dead_accounts_counter = RwMux(DeadAccountsCounter).init(dead_accounts_counter),

            .largest_file_id = FileId.fromInt(0),
            .largest_rooted_slot = std.atomic.Value(Slot).init(0),
            .largest_flushed_slot = std.atomic.Value(Slot).init(0),

            .first_snapshot_load_info = RwMux(?SnapshotGenerationInfo).init(null),
            .latest_snapshot_gen_info = RwMux(?SnapshotGenerationInfo).init(null),

            .bank_hash_stats = RwMux(BankHashStatsMap).init(.{}),
        };
    }

    pub fn deinit(self: *AccountsDB) void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb deinit" });
        defer zone.deinit();

        self.account_index.deinit();
        self.buffer_pool.deinit(self.allocator);

        {
            const unrooted_accounts, var unrooted_accounts_lg =
                self.unrooted_accounts.writeWithLock();
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
            for (file_map.values()) |v| v.deinit();
            file_map.deinit(self.allocator);
        }
        {
            const dead_accounts_counter, var dead_accounts_counter_lg =
                self.dead_accounts_counter.writeWithLock();
            defer dead_accounts_counter_lg.unlock();
            dead_accounts_counter.deinit();
        }

        {
            const bank_hash_stats, var bank_hash_stats_lg =
                self.bank_hash_stats.writeWithLock();
            defer bank_hash_stats_lg.unlock();
            bank_hash_stats.deinit(self.allocator);
        }
    }

    /// easier to use load function
    pub fn loadWithDefaults(
        self: *AccountsDB,
        /// needs to be a thread-safe allocator
        allocator: std.mem.Allocator,
        /// Must have been allocated with `self.allocator`.
        full_inc_manifest: FullAndIncrementalManifest,
        n_threads: u32,
        validate: bool,
        accounts_per_file_estimate: u64,
        should_fastload: bool,
        save_index: bool,
    ) !SnapshotManifest {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb loadWithDefaults" });
        defer zone.deinit();

        const collapsed_manifest = try full_inc_manifest.collapse(self.allocator);
        errdefer collapsed_manifest.deinit(self.allocator);

        if (should_fastload) {
            var timer = try sig.time.Timer.start();
            var fastload_dir = try self.snapshot_dir.makeOpenPath("fastload_state", .{});
            defer fastload_dir.close();
            try self.fastload(fastload_dir, collapsed_manifest.accounts_db_fields);
            self.logger.info().logf("fastload: total time: {s}", .{timer.read()});
        } else {
            var load_timer = try sig.time.Timer.start();
            try self.loadFromSnapshot(
                collapsed_manifest.accounts_db_fields,
                n_threads,
                allocator,
                accounts_per_file_estimate,
            );
            self.logger.info().logf("loadFromSnapshot: total time: {s}", .{load_timer.read()});
        }

        // no need to re-save if we just loaded from a fastload
        if (save_index and !should_fastload) {
            var timer = try sig.time.Timer.start();
            _ = try self.saveStateForFastload();
            self.logger.info().logf("saveStateForFastload: total time: {s}", .{timer.read()});
        }

        if (validate) {
            const full_man = full_inc_manifest.full;
            const maybe_inc_persistence = if (full_inc_manifest.incremental) |inc|
                inc.bank_extra.snapshot_persistence
            else
                null;

            var validate_timer = try sig.time.Timer.start();
            try self.validateLoadFromSnapshot(.{
                .full_slot = full_man.bank_fields.slot,
                .expected_full = .{
                    .accounts_hash = full_man.accounts_db_fields.bank_hash_info.accounts_hash,
                    .capitalization = full_man.bank_fields.capitalization,
                },
                .expected_incremental = if (maybe_inc_persistence) |inc_persistence| .{
                    .accounts_hash = inc_persistence.incremental_hash,
                    .capitalization = inc_persistence.incremental_capitalization,
                } else null,
            });
            self.logger.info().logf(
                "validateLoadFromSnapshot: total time: {s}",
                .{validate_timer.read()},
            );
        }

        return collapsed_manifest;
    }

    /// easier to use load function
    pub fn loadFromSnapshotAndValidate(
        self: *AccountsDB,
        params: struct {
            /// needs to be a thread-safe allocator
            allocator: std.mem.Allocator,
            /// Must have been allocated with `self.allocator`.
            full_inc_manifest: FullAndIncrementalManifest,
            n_threads: u32,
            accounts_per_file_estimate: u64,
        },
    ) !SnapshotManifest {
        const allocator = params.allocator;
        const full_inc_manifest = params.full_inc_manifest;
        const n_threads = params.n_threads;
        const accounts_per_file_estimate = params.accounts_per_file_estimate;

        const collapsed_manifest = try full_inc_manifest.collapse(self.allocator);
        errdefer collapsed_manifest.deinit(self.allocator);

        {
            var load_timer = try sig.time.Timer.start();
            try self.loadFromSnapshot(
                collapsed_manifest.accounts_db_fields,
                n_threads,
                allocator,
                accounts_per_file_estimate,
            );
            self.logger.info().logf("loadFromSnapshot: total time: {s}", .{load_timer.read()});
        }

        {
            const full_man = full_inc_manifest.full;
            const maybe_inc_persistence = if (full_inc_manifest.incremental) |inc|
                inc.bank_extra.snapshot_persistence
            else
                null;

            var validate_timer = try sig.time.Timer.start();
            try self.validateLoadFromSnapshot(.{
                .full_slot = full_man.bank_fields.slot,
                .expected_full = .{
                    .accounts_hash = full_man.accounts_db_fields.bank_hash_info.accounts_hash,
                    .capitalization = full_man.bank_fields.capitalization,
                },
                .expected_incremental = if (maybe_inc_persistence) |inc_persistence| .{
                    .accounts_hash = inc_persistence.incremental_hash,
                    .capitalization = inc_persistence.incremental_capitalization,
                } else null,
            });
            self.logger.info().logf(
                "validateLoadFromSnapshot: total time: {s}",
                .{validate_timer.read()},
            );
        }

        return collapsed_manifest;
    }

    pub fn saveStateForFastload(
        self: *AccountsDB,
    ) !void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb fastsaveStateForFastloadload" });
        defer zone.deinit();

        self.logger.info().log("running saveStateForFastload...");
        var fastload_dir = try self.snapshot_dir.makeOpenPath("fastload_state", .{});
        defer fastload_dir.close();
        try self.account_index.saveToDisk(fastload_dir);
    }

    pub fn fastload(
        self: *AccountsDB,
        dir: std.fs.Dir,
        snapshot_manifest: AccountsDbFields,
    ) !void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb fastload" });
        defer zone.deinit();

        self.logger.info().log("running fastload...");

        var accounts_dir = try self.snapshot_dir.openDir("accounts", .{});
        defer accounts_dir.close();

        const n_account_files = snapshot_manifest.file_map.count();
        self.logger.info().logf("found {d} account files", .{n_account_files});
        std.debug.assert(n_account_files > 0);

        const file_map, var file_map_lg = self.file_map.writeWithLock();
        defer file_map_lg.unlock();
        try file_map.ensureTotalCapacity(self.allocator, n_account_files);

        self.logger.info().log("loading account files");
        const file_info_map = snapshot_manifest.file_map;
        for (file_info_map.keys(), file_info_map.values()) |slot, file_info| {
            // read accounts file
            var accounts_file = blk: {
                const file_name_bounded = sig.utils.fmt.boundedFmt(
                    "{d}.{d}",
                    .{ slot, file_info.id.toInt() },
                );
                const file_name = file_name_bounded.constSlice();
                const accounts_file = accounts_dir.openFile(file_name, .{
                    .mode = .read_write,
                }) catch |err| {
                    self.logger.err().logf(
                        "Failed to open accounts/{s}: {s}",
                        .{ file_name, @errorName(err) },
                    );
                    return err;
                };
                errdefer accounts_file.close();

                break :blk AccountFile.init(accounts_file, file_info, slot) catch |err| {
                    self.logger.err().logf(
                        "failed to *open* AccountsFile {s}: {s}\n",
                        .{ file_name, @errorName(err) },
                    );
                    return err;
                };
            };
            errdefer accounts_file.deinit();

            // NOTE: no need to validate since we are fast loading

            // track file
            const file_id = file_info.id;
            file_map.putAssumeCapacityNoClobber(file_id, accounts_file);
            self.largest_file_id = FileId.max(self.largest_file_id, file_id);
            _ = self.largest_rooted_slot.fetchMax(slot, .release);
            self.largest_flushed_slot.store(self.largest_rooted_slot.load(.acquire), .release);
        }

        // NOTE: index loading was the most expensive part which we fastload here
        try self.account_index.loadFromDisk(dir);
    }

    /// loads the account files and generates the account index from a snapshot
    pub fn loadFromSnapshot(
        self: *AccountsDB,
        /// Account file info map from the snapshot manifest.
        snapshot_manifest: AccountsDbFields,
        n_threads: u32,
        /// needs to be a thread-safe allocator
        per_thread_allocator: std.mem.Allocator,
        accounts_per_file_estimate: u64,
    ) !void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb loadFromSnapshot" });
        defer zone.deinit();

        self.logger.info().log("running loadFromSnapshot...");

        // used to read account files
        const n_parse_threads = n_threads;
        // used to merge thread results
        const n_combine_threads = n_threads;

        var accounts_dir = try self.snapshot_dir.openDir("accounts", .{});
        defer accounts_dir.close();

        const n_account_files = snapshot_manifest.file_map.count();
        self.logger.info().logf("found {d} account files", .{n_account_files});
        std.debug.assert(n_account_files > 0);

        // prealloc the references
        const n_accounts_estimate = n_account_files * accounts_per_file_estimate;
        try self.account_index.expandRefCapacity(n_accounts_estimate);

        {
            const bhs, var bhs_lg = try self.getOrInitBankHashStats(snapshot_manifest.slot);
            defer bhs_lg.unlock();
            bhs.accumulate(snapshot_manifest.bank_hash_info.stats);
        }

        // setup the parallel indexing
        const loading_threads = try self.allocator.alloc(AccountsDB, n_parse_threads);
        defer self.allocator.free(loading_threads);

        try initLoadingThreads(per_thread_allocator, loading_threads, self);
        defer deinitLoadingThreads(per_thread_allocator, loading_threads);

        self.logger.info().logf(
            "[{d} threads]: running loadAndVerifyAccountsFiles...",
            .{n_parse_threads},
        );
        try spawnThreadTasks(
            self.allocator,
            loadAndVerifyAccountsFilesMultiThread,
            .{
                .data_len = n_account_files,
                .max_threads = n_parse_threads,
                .params = .{
                    loading_threads,
                    accounts_dir,
                    snapshot_manifest.file_map,
                    accounts_per_file_estimate,
                },
            },
        );

        // if geyser, send end of data signal
        if (self.geyser_writer) |geyser_writer| {
            const end_of_snapshot: sig.geyser.core.VersionedAccountPayload = .EndOfSnapshotLoading;
            try geyser_writer.writePayloadToPipe(end_of_snapshot);
        }

        var merge_timer = try sig.time.Timer.start();
        try self.mergeMultipleDBs(loading_threads, n_combine_threads);
        self.logger.debug().logf("mergeMultipleDBs: total time: {}", .{merge_timer.read()});
    }

    /// Initializes a slice of children `AccountsDB`s, used to divide the work of loading from a snapshot.
    ///
    /// If successful, the caller is responsible for calling `deinitLoadingThreads(per_thread_allocator, loading_threads)`.
    ///
    /// On error, all resources which were allocated before encountering the error are freed, and the caller
    /// is to assume `loaoding_threads` points to undefined memory.
    fn initLoadingThreads(
        per_thread_allocator: std.mem.Allocator,
        /// Entirely overwritten, the caller should not assume retention of any information.
        loading_threads: []AccountsDB,
        parent: *AccountsDB,
    ) !void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb initLoadingThreads" });
        defer zone.deinit();

        @memset(loading_threads, undefined);

        for (loading_threads, 0..) |*loading_thread, init_count| {
            errdefer deinitLoadingThreads(per_thread_allocator, loading_threads[0..init_count]);
            loading_thread.* = try AccountsDB.init(.{
                .allocator = per_thread_allocator,
                .snapshot_dir = parent.snapshot_dir,
                .geyser_writer = parent.geyser_writer,
                .number_of_index_shards = parent.number_of_index_shards,

                // dont spam the logs with init information (we set it after)
                .logger = .noop,
                // loading threads would never need to generate a snapshot, therefore it doesn't need a view into gossip.
                .gossip_view = null,
                // we set this to use the disk reference allocator if we already have one (ram allocator doesn't allocate on init)
                .index_allocation = .{ .parent = &parent.account_index.reference_allocator },
            });

            loading_thread.logger = parent.logger;
            // 1) delete the old ptr so we dont leak
            per_thread_allocator.destroy(loading_thread.account_index.reference_manager);
            // 2) set the new ptr to the main index
            loading_thread.account_index.reference_manager = parent.account_index.reference_manager;
        }
    }

    /// At this point, there will be three groups of resources we care about per loading thread:
    /// 1) The `AccountRef`s themselves.
    /// 2) The ref hashmaps (`Map(Pubkey, *AccountRef)`).
    /// 3) The account file maps (`Map(FileId, AccountFile)`).
    ///
    /// What happens:
    /// 2) and 3) will be copied into the main index so we can deinit them, while 1) will
    /// continue to exist on the heap and its ownership is given to the main index
    fn deinitLoadingThreads(
        per_thread_allocator: std.mem.Allocator,
        loading_threads: []AccountsDB,
    ) void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb deinitLoadingThreads" });
        defer zone.deinit();

        for (loading_threads) |*loading_thread| {
            // NOTE: deinit hashmap, dont close the files
            const file_map, var file_map_lg = loading_thread.file_map.writeWithLock();
            defer file_map_lg.unlock();
            file_map.deinit(per_thread_allocator);

            loading_thread.account_index.deinitLoadingThread();
            loading_thread.buffer_pool.deinit(per_thread_allocator);
        }
    }

    /// multithread entrypoint into loadAndVerifyAccountsFiles.
    pub fn loadAndVerifyAccountsFilesMultiThread(
        loading_threads: []AccountsDB,
        accounts_dir: std.fs.Dir,
        file_info_map: AccountsDbFields.FileMap,
        accounts_per_file_estimate: u64,
        task: sig.utils.thread.TaskParams,
    ) !void {
        const zone = tracy.initZone(@src(), .{
            .name = "accountsdb loadAndVerifyAccountsFilesMultiThread",
        });
        defer zone.deinit();

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
        self: *AccountsDB,
        accounts_dir: std.fs.Dir,
        accounts_per_file_est: usize,
        file_info_map: AccountsDbFields.FileMap,
        file_map_start_index: usize,
        file_map_end_index: usize,
        // when we multithread this function we only want to print on the first thread
        print_progress: bool,
    ) !void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb loadAndVerifyAccountsFiles" });
        defer zone.deinit();

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
        const reference_manager = self.account_index.reference_manager;
        const references_buf, const ref_global_index =
            try reference_manager.alloc(n_accounts_estimate);

        var timer = try sig.time.Timer.start();
        var progress_timer = try sig.time.Timer.start();

        if (n_account_files > std.math.maxInt(AccountIndex.SlotRefMap.Size)) {
            return error.FileMapTooBig;
        }
        // its ok to hold this lock for the entire function because nothing else
        // should be accessing the account index while loading from a snapshot
        const slot_reference_map, var slot_reference_map_lg =
            self.account_index.slot_reference_map.writeWithLock();
        defer slot_reference_map_lg.unlock();
        try slot_reference_map.ensureTotalCapacity(@intCast(n_account_files));

        // init storage which holds temporary account data per slot
        // which is eventually written to geyser
        var geyser_slot_storage: ?*GeyserTmpStorage = null;
        const geyser_is_enabled = self.geyser_writer != null;
        if (geyser_is_enabled) {
            geyser_slot_storage =
                try self.allocator.create(GeyserTmpStorage);
            geyser_slot_storage.?.* =
                try GeyserTmpStorage.init(self.allocator, n_accounts_estimate);
        }
        defer {
            if (geyser_slot_storage) |storage| {
                storage.deinit(self.allocator);
                self.allocator.destroy(storage);
            }
        }

        var n_accounts_total: u64 = 0;
        for (
            file_info_map.keys()[file_map_start_index..file_map_end_index],
            file_info_map.values()[file_map_start_index..file_map_end_index],
            1..,
        ) |slot, file_info, file_count| {
            // read accounts file
            var accounts_file = blk: {
                const file_name_bounded = sig.utils.fmt.boundedFmt(
                    "{d}.{d}",
                    .{ slot, file_info.id.toInt() },
                );
                const file_name = file_name_bounded.constSlice();

                const accounts_file = accounts_dir.openFile(file_name, .{
                    .mode = .read_write,
                }) catch |err| {
                    self.logger.err().logf("Failed to open {s}: {s}", .{
                        try accounts_dir.realpathAlloc(self.allocator, file_name),
                        @errorName(err),
                    });
                    return err;
                };
                errdefer accounts_file.close();

                break :blk AccountFile.init(accounts_file, file_info, slot) catch |err| {
                    self.logger.err().logf("failed to *open* AccountsFile {s}: {s}\n", .{
                        file_name,
                        @errorName(err),
                    });
                    return err;
                };
            };
            var accounts_file_moved_to_filemap = false;
            defer if (!accounts_file_moved_to_filemap) accounts_file.deinit();

            // index the account file
            var slot_references = std.ArrayListUnmanaged(AccountRef).initBuffer(
                references_buf[n_accounts_total..],
            );
            indexAndValidateAccountFile(
                self.allocator,
                &self.buffer_pool,
                &accounts_file,
                self.account_index.pubkey_ref_map.shard_calculator,
                shard_counts,
                &slot_references,
                // ! we collect the accounts and pubkeys into geyser storage here
                geyser_slot_storage,
            ) catch |err| {
                if (err == ValidateAccountFileError.OutOfReferenceMemory) {
                    std.debug.panic(
                        "accounts-per-file-estimate too small ({d}), " ++
                            "increase (using flag '-a') and try again...",
                        .{accounts_per_file_est},
                    );
                } else {
                    self.logger.err().logf(
                        "failed to *validate/index* AccountsFile: {d}.{d}: {s}\n",
                        .{ accounts_file.slot, accounts_file.id.toInt(), @errorName(err) },
                    );
                }
            };

            const n_accounts_this_slot = accounts_file.number_of_accounts;
            if (n_accounts_this_slot == 0) {
                continue;
            }
            const file_id = file_info.id;
            file_map.putAssumeCapacityNoClobber(file_id, accounts_file);
            accounts_file_moved_to_filemap = true;

            // track slice of references per slot
            n_accounts_total += n_accounts_this_slot;
            slot_reference_map.putAssumeCapacityNoClobber(
                slot,
                slot_references.items[0..n_accounts_this_slot],
            );

            // write to geyser
            if (geyser_is_enabled) {
                // SAFE: will always be set if geyser_is_enabled
                var geyser_storage = geyser_slot_storage.?;

                // SAFE: will always be set if geyser_is_enabled
                const geyser_writer = self.geyser_writer.?;

                // ! reset memory for the next slot
                defer geyser_storage.reset(self.allocator);

                const data_versioned: sig.geyser.core.VersionedAccountPayload = .{
                    .AccountPayloadV1 = .{
                        .accounts = geyser_storage.accounts.items,
                        .pubkeys = geyser_storage.pubkeys.items,
                        .slot = slot,
                    },
                };
                try geyser_writer.writePayloadToPipe(data_versioned);
            }

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

        // free extra memory, if we overallocated (very likely)
        if (n_accounts_total != references_buf.len) {
            _ = reference_manager.tryRecycleUnusedSpace(references_buf.ptr, n_accounts_total);
        }

        // NOTE: this is good for debugging what to set `accounts_per_file_est` to
        if (print_progress) {
            self.logger.info().logf("accounts_per_file: actual vs estimated: {d} vs {d}", .{
                n_accounts_total / n_account_files,
                accounts_per_file_est,
            });
        }

        {
            const pubkey_ref_map_zone = tracy.initZone(@src(), .{
                .name = "accountsdb loadAndVerifyAccountsFiles pubkey_ref_map.ensureTotalCapacity",
            });
            defer pubkey_ref_map_zone.deinit();

            // allocate enough memory
            try self.account_index.pubkey_ref_map.ensureTotalCapacity(shard_counts);
        }

        // PERF: can probs be faster if you sort the pubkeys first, and then you know
        // it will always be a search for a free spot, and not search for a match

        {
            const index_build_zone = tracy.initZone(@src(), .{
                .name = "accountsdb loadAndVerifyAccountsFiles building index",
            });
            defer index_build_zone.deinit();

            timer.reset();
            for (references_buf[0..n_accounts_total], 0..) |*ref, ref_count| {
                _ = self.account_index.indexRefIfNotDuplicateSlotAssumeCapacity(
                    ref,
                    ref_global_index + ref_count,
                );

                if (print_progress and progress_timer.read().asNanos() > DB_LOG_RATE.asNanos()) {
                    printTimeEstimate(
                        self.logger,
                        &timer,
                        n_accounts_total,
                        ref_count,
                        "building index",
                        "thread0",
                    );
                    progress_timer.reset();
                }
            }
        }
    }

    /// merges multiple thread accounts-dbs into self.
    /// index merging happens in parallel using `n_threads`.
    pub fn mergeMultipleDBs(
        self: *AccountsDB,
        thread_dbs: []AccountsDB,
        n_threads: usize,
    ) !void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb mergeMultipleDBs" });
        defer zone.deinit();

        self.logger.info().logf("[{d} threads]: running mergeMultipleDBs...", .{n_threads});

        try spawnThreadTasks(self.allocator, mergeThreadIndexesMultiThread, .{
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
            const thread_ref_memory, var thread_ref_memory_lg =
                thread_db.account_index.slot_reference_map.readWithLock();
            defer thread_ref_memory_lg.unlock();
            ref_mem_capacity += thread_ref_memory.count();
        }

        // NOTE: its ok to hold this lock while we merge because
        // nothing else should be accessing the account index while loading from a snapshot
        const slot_reference_map, var slot_reference_map_lg =
            self.account_index.slot_reference_map.writeWithLock();
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
            _ = self.largest_rooted_slot.fetchMax(
                thread_db.largest_rooted_slot.load(.acquire),
                .monotonic,
            );
            self.largest_flushed_slot.store(self.largest_rooted_slot.load(.monotonic), .monotonic);

            // combine underlying memory
            const thread_slot_reference_map, var thread_slot_reference_map_lg =
                thread_db.account_index.slot_reference_map.readWithLock();
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
    pub fn mergeThreadIndexesMultiThread(
        logger: ScopedLogger,
        index: *AccountIndex,
        thread_dbs: []const AccountsDB,
        task: sig.utils.thread.TaskParams,
    ) !void {
        const zone = tracy.initZone(@src(), .{
            .name = "accountsdb mergeThreadIndexesMultiThread",
        });
        defer zone.deinit();

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
                const pubkey_ref_map = &thread_db.account_index.pubkey_ref_map;
                shard_n_accounts += pubkey_ref_map.getShardCount(shard_index);
            }

            // prealloc
            if (shard_n_accounts > 0) {
                const shard_map, var shard_map_lg =
                    index.pubkey_ref_map.getShardFromIndex(shard_index).writeWithLock();
                defer shard_map_lg.unlock();
                try shard_map.ensureTotalCapacity(shard_n_accounts);
            }

            for (thread_dbs) |*thread_db| {
                const pubkey_ref_map = &thread_db.account_index.pubkey_ref_map;

                const shard_map, var shard_map_lg =
                    pubkey_ref_map.getShardFromIndex(shard_index).readWithLock();
                defer shard_map_lg.unlock();

                // insert all of the thread entries into the main index
                var iter = shard_map.iterator();
                while (iter.next()) |thread_entry| {
                    const thread_head_ref = thread_entry.value_ptr.*;

                    // NOTE: we dont have to check for duplicates because the duplicate
                    // slots have already been handled in the prev step
                    index.indexRefAssumeCapacity(
                        thread_head_ref.ref_ptr,
                        thread_head_ref.ref_index,
                    );
                }
            }

            if (print_progress and progress_timer.read() > DB_LOG_RATE.asNanos()) {
                printTimeEstimate(
                    logger,
                    &timer,
                    total_shards,
                    iteration_count,
                    "merging thread indexes",
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
        self: *AccountsDB,
        config: AccountHashesConfig,
    ) !struct { Hash, u64 } {
        const zone = tracy.initZone(@src(), .{
            .name = "accountsdb computeAccountHashesAndLamports",
        });
        defer zone.deinit();

        var timer = try sig.time.Timer.start();
        // TODO: make cli arg
        const n_threads = @as(u32, @truncate(try std.Thread.getCpuCount()));
        // const n_threads = 4;

        // alloc the result
        const hashes = try self.allocator.alloc(std.ArrayListUnmanaged(Hash), n_threads);
        defer {
            for (hashes) |*h| h.deinit(self.allocator);
            self.allocator.free(hashes);
        }
        @memset(hashes, .{});

        const lamports = try self.allocator.alloc(u64, n_threads);
        defer self.allocator.free(lamports);
        @memset(lamports, 0);

        // split processing the bins over muliple threads
        self.logger.info().logf(
            "[{} threads] collecting hashes from accounts",
            .{n_threads},
        );
        try spawnThreadTasks(self.allocator, getHashesFromIndexMultiThread, .{
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
        self.logger.debug().logf("collecting hashes from accounts took: {s}", .{timer.read()});
        timer.reset();

        self.logger.info().logf("computing the merkle root over accounts...", .{});
        const nested_hashes = try self.allocator.alloc([]Hash, n_threads);
        defer self.allocator.free(nested_hashes);
        for (nested_hashes, 0..) |*h, i| {
            h.* = hashes[i].items;
        }
        const hash_tree = NestedHashTree{ .items = nested_hashes };
        const accounts_hash =
            try sig.utils.merkle_tree.computeMerkleRoot(&hash_tree, MERKLE_FANOUT);
        self.logger.debug().logf(
            "computing the merkle root over accounts took {s}",
            .{timer.read()},
        );
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
    /// be after loading the snapshot(s) whose information is supplied,
    /// and before mutating accountsdb.
    pub fn validateLoadFromSnapshot(
        self: *AccountsDB,
        params: ValidateLoadFromSnapshotParams,
    ) !void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb validateLoadFromSnapshot" });
        defer zone.deinit();

        const maybe_latest_snapshot_info: *?SnapshotGenerationInfo, //
        var latest_snapshot_info_lg //
        = self.latest_snapshot_gen_info.writeWithLock();
        defer latest_snapshot_info_lg.unlock();

        const maybe_first_snapshot_info: *?SnapshotGenerationInfo, //
        var first_snapshot_info_lg //
        = self.first_snapshot_load_info.writeWithLock();
        defer first_snapshot_info_lg.unlock();

        if (maybe_first_snapshot_info.*) |first| {
            std.debug.assert( // already validated against a different set of snapshot info
                first.full.slot == params.full_slot);
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
                "incorrect accounts hash: expected vs calculated: {d} vs {d}",
                .{ params.expected_full.accounts_hash, accounts_hash },
            );
            return error.IncorrectAccountsHash;
        }

        if (params.expected_full.capitalization != total_lamports) {
            self.logger.err().logf(
                "incorrect total lamports: expected vs calculated: {d} vs {d}",
                .{ params.expected_full.capitalization, total_lamports },
            );
            return error.IncorrectTotalLamports;
        }

        if (maybe_latest_snapshot_info.*) |latest_snapshot_info| {
            // ASSERTION: nothing has changed if we previously successfully
            // verified a load from the snapshot; ie, calling this function
            // after calling it once should not produce any mutations.
            // The assertion may also trip if any mutations to accountsdb
            // have occurred since the first call to this function.
            std.debug.assert(latest_snapshot_info.full.slot == params.full_slot);
            std.debug.assert(latest_snapshot_info.full.hash.eql(accounts_hash));
            std.debug.assert(latest_snapshot_info.full.capitalization == total_lamports);
        }
        maybe_first_snapshot_info.* = .{
            .full = .{
                .slot = params.full_slot,
                .hash = accounts_hash,
                .capitalization = total_lamports,
            },
            .inc = null,
        };
        const p_maybe_first_inc = &maybe_first_snapshot_info.*.?.inc;

        // validate the incremental snapshot
        if (params.expected_incremental) |expected_incremental| {
            self.logger.info().logf("validating the incremental snapshot", .{});

            const inc_slot = self.largest_rooted_slot.load(.acquire);

            const accounts_delta_hash, //
            const incremental_lamports //
            = try self.computeAccountHashesAndLamports(.{
                .IncrementalAccountHash = .{
                    .min_slot = params.full_slot,
                    .max_slot = inc_slot,
                },
            });

            if (expected_incremental.capitalization != incremental_lamports) {
                self.logger.err().logf(
                    "incorrect incremental lamports: expected vs calculated: {d} vs {d}",
                    .{ expected_incremental.capitalization, incremental_lamports },
                );
                return error.IncorrectIncrementalLamports;
            }

            if (expected_incremental.accounts_hash.order(&accounts_delta_hash) != .eq) {
                self.logger.err().logf(
                    "incorrect accounts delta hash: expected vs calculated: {d} vs {d}",
                    .{ expected_incremental.accounts_hash, accounts_delta_hash },
                );
                return error.IncorrectAccountsDeltaHash;
            }

            // ASSERTION: same idea as the previous assertion, but applied to
            // the incremental snapshot info.
            if (p_maybe_first_inc.*) |first_inc| {
                std.debug.assert(first_inc.slot == inc_slot);
                std.debug.assert(first_inc.hash.eql(accounts_delta_hash));
                std.debug.assert(first_inc.capitalization == incremental_lamports);
            }
            p_maybe_first_inc.* = .{
                .slot = inc_slot,
                .hash = accounts_delta_hash,
                .capitalization = incremental_lamports,
            };
        }

        maybe_latest_snapshot_info.* = maybe_first_snapshot_info.*;
    }

    /// multithread entrypoint for getHashesFromIndex
    pub fn getHashesFromIndexMultiThread(
        self: *AccountsDB,
        config: AccountsDB.AccountHashesConfig,
        /// Allocator shared by all the arraylists in `hashes`.
        hashes_allocator: std.mem.Allocator,
        hashes: []std.ArrayListUnmanaged(Hash),
        total_lamports: []u64,
        task: sig.utils.thread.TaskParams,
    ) !void {
        const zone = tracy.initZone(@src(), .{
            .name = "accountsdb getHashesFromIndexMultiThread",
        });
        defer zone.deinit();

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
        hashes: *std.ArrayListUnmanaged(Hash),
        total_lamports: *u64,
        // when we multithread this function we only want to print on the first thread
        print_progress: bool,
    ) !void {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb getHashesFromIndex" });
        defer zone.deinit();

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
                    inline //
                    .FullAccountHash,
                    .IncrementalAccountHash,
                    => |config_pl| slotListMaxWithinBounds(
                        ref_ptr,
                        config_pl.min_slot,
                        config_pl.max_slot,
                    ),
                } orelse continue;

                // read the account state
                var account_hash, const lamports =
                    try self.getAccountHashAndLamportsFromRef(max_slot_ref.location);

                // modify its hash, if needed
                if (lamports == 0) {
                    switch (config) {
                        // for full snapshots, only include non-zero lamport accounts
                        .FullAccountHash => continue,
                        // zero-lamport accounts for incrementals = hash(pubkey)
                        .IncrementalAccountHash => Blake3.hash(&key.data, &account_hash.data, .{}),
                    }
                } else {
                    // hashes aren't always stored correctly in snapshots
                    if (account_hash.eql(Hash.ZEROES)) {
                        const account, var account_lg =
                            try self.getAccountFromRefWithReadLock(max_slot_ref);
                        defer {
                            account_lg.unlock();
                            switch (account) {
                                .file => |in_file_account| in_file_account.deinit(self.allocator),
                                .unrooted_map => {},
                            }
                        }

                        account_hash = switch (account) {
                            .file => |in_file_account| blk: {
                                var iter = in_file_account.data.iterator();
                                break :blk sig.core.account.hashAccount(
                                    in_file_account.lamports().*,
                                    &iter,
                                    &in_file_account.owner().data,
                                    in_file_account.executable().*,
                                    in_file_account.rent_epoch().*,
                                    &in_file_account.pubkey().data,
                                );
                            },
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
    pub fn createAccountFile(self: *AccountsDB, size: usize, slot: Slot) !struct {
        std.fs.File,
        FileId,
    } {
        self.largest_file_id = self.largest_file_id.increment();
        const file_id = self.largest_file_id;

        const file_path_bounded = sig.utils.fmt.boundedFmt(
            "accounts/{d}.{d}",
            .{ slot, file_id.toInt() },
        );
        const file = try self.snapshot_dir.createFile(file_path_bounded.constSlice(), .{
            .read = true,
        });
        errdefer file.close();

        // resize the file
        const file_size = (try file.stat()).size;
        if (file_size < size) {
            try file.seekTo(size - 1);
            _ = try file.write(&[_]u8{1});
            try file.seekTo(0);
        }

        return .{ file, file_id };
    }

    const GetFileFromRefError = GetAccountInFileError ||
        std.mem.Allocator.Error ||
        error{SlotNotFound};

    // NOTE: we need to acquire locks which requires `self: *Self` but we never modify any data
    pub fn getAccountFromRef(
        self: *AccountsDB,
        account_ref: *const AccountRef,
    ) GetFileFromRefError!Account {
        switch (account_ref.location) {
            .File => |ref_info| {
                const account = try self.getAccountInFile(
                    self.allocator,
                    ref_info.file_id,
                    ref_info.offset,
                );
                errdefer account.deinit(self.allocator);

                return account;
            },
            .UnrootedMap => |ref_info| {
                const unrooted_accounts, var unrooted_accounts_lg =
                    self.unrooted_accounts.readWithLock();
                defer unrooted_accounts_lg.unlock();

                _, const accounts = unrooted_accounts.get(account_ref.slot) orelse
                    return error.SlotNotFound;
                const account = accounts[ref_info.index];

                return try account.cloneOwned(self.allocator);
            },
        }
    }

    pub const AccountInCacheOrFileTag = enum {
        file,
        unrooted_map,
    };
    pub const AccountInCacheOrFile = union(AccountInCacheOrFileTag) {
        file: AccountInFile,
        unrooted_map: Account,
    };
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
        self: *AccountsDB,
        account_ref: *const AccountRef,
    ) GetAccountFromRefError!struct { AccountInCacheOrFile, AccountInCacheOrFileLock } {
        switch (account_ref.location) {
            .File => |ref_info| {
                const account = try self.getAccountInFileAndLock(
                    self.allocator,
                    &self.buffer_pool,
                    ref_info.file_id,
                    ref_info.offset,
                );
                return .{
                    .{ .file = account },
                    .{ .file = &self.file_map_fd_rw },
                };
            },
            .UnrootedMap => |ref_info| {
                const unrooted_accounts, var unrooted_accounts_lg =
                    self.unrooted_accounts.readWithLock();
                errdefer unrooted_accounts_lg.unlock();

                _, const accounts = unrooted_accounts.get(account_ref.slot) orelse
                    return error.SlotNotFound;
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
        self: *AccountsDB,
        account_allocator: std.mem.Allocator,
        file_id: FileId,
        offset: usize,
    ) (GetAccountInFileError || std.mem.Allocator.Error)!Account {
        const account_in_file = try self.getAccountInFileAndLock(
            self.allocator,
            &self.buffer_pool,
            file_id,
            offset,
        );
        defer account_in_file.deinit(account_allocator);
        defer self.file_map_fd_rw.unlockShared();
        return try account_in_file.dupeCachedAccount(account_allocator);
    }

    /// Gets an account given an file_id and offset value.
    /// Locks the account file entries, and returns the account.
    /// Must call `self.file_map_fd_rw.unlockShared()`
    /// when done with the account.
    pub fn getAccountInFileAndLock(
        self: *AccountsDB,
        metadata_allocator: std.mem.Allocator,
        buffer_pool: *BufferPool,
        file_id: FileId,
        offset: usize,
    ) GetAccountInFileError!AccountInFile {
        self.file_map_fd_rw.lockShared();
        errdefer self.file_map_fd_rw.unlockShared();
        return try self.getAccountInFileAssumeLock(
            metadata_allocator,
            buffer_pool,
            file_id,
            offset,
        );
    }

    /// Gets an account given a file_id and an offset value.
    /// Assumes `self.file_map_fd_rw` is at least
    /// locked for reading (shared).
    pub fn getAccountInFileAssumeLock(
        self: *AccountsDB,
        metadata_allocator: std.mem.Allocator,
        buffer_pool: *BufferPool,
        file_id: FileId,
        offset: usize,
    ) GetAccountInFileError!AccountInFile {
        const account_file: AccountFile = blk: {
            const file_map, var file_map_lg = self.file_map.readWithLock();
            defer file_map_lg.unlock();
            break :blk file_map.get(file_id) orelse return error.FileIdNotFound;
        };
        return account_file.readAccount(
            metadata_allocator,
            buffer_pool,
            offset,
        ) catch error.InvalidOffset;
    }

    pub fn getAccountHashAndLamportsFromRef(
        self: *AccountsDB,
        location: AccountRef.AccountLocation,
    ) GetAccountInFileError!struct { Hash, u64 } {
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
                    self.allocator,
                    &self.buffer_pool,
                    ref_info.offset,
                ) catch return error.InvalidOffset;

                return .{
                    result.hash,
                    result.lamports,
                };
            },
            // we dont use this method for cache
            .UnrootedMap => @panic(
                "getAccountHashAndLamportsFromRef is not implemented on UnrootedMap references",
            ),
        }
    }

    pub const GetAccountError = GetFileFromRefError || error{PubkeyNotInIndex};
    /// gets an account given an associated pubkey. mut ref is required for locks.
    pub fn getAccount(
        self: *AccountsDB,
        pubkey: *const Pubkey,
    ) GetAccountError!Account {
        const head_ref, var lock = self.account_index.pubkey_ref_map.getRead(pubkey) orelse
            return error.PubkeyNotInIndex;
        defer lock.unlock();

        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, null, null).?;
        const account = try self.getAccountFromRef(max_ref);

        return account;
    }

    pub fn getAccountAndReference(
        self: *AccountsDB,
        pubkey: *const Pubkey,
    ) !struct { Account, AccountRef } {
        const head_ref, var head_ref_lg =
            self.account_index.pubkey_ref_map.getRead(pubkey) orelse return error.PubkeyNotInIndex;
        defer head_ref_lg.unlock();

        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, null, null).?;
        const account = try self.getAccountFromRef(max_ref);

        return .{ account, max_ref.* };
    }

    pub const GetAccountWithReadLockError = GetAccountFromRefError || error{PubkeyNotInIndex};
    pub fn getAccountWithReadLock(
        self: *AccountsDB,
        pubkey: *const Pubkey,
    ) GetAccountWithReadLockError!struct { AccountInCacheOrFile, AccountInCacheOrFileLock } {
        const head_ref, var head_ref_lg =
            self.account_index.pubkey_ref_map.getRead(pubkey) orelse return error.PubkeyNotInIndex;
        defer head_ref_lg.unlock();

        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, null, null).?;
        return try self.getAccountFromRefWithReadLock(max_ref);
    }

    pub fn getSlotAndAccountInSlotRangeWithReadLock(
        self: *AccountsDB,
        pubkey: *const Pubkey,
        min_slot: ?Slot,
        max_slot: ?Slot,
    ) GetAccountWithReadLockError!?struct { AccountInCacheOrFile, Slot, AccountInCacheOrFileLock } {
        const head_ref, var lock = self.account_index.pubkey_ref_map.getRead(pubkey) orelse
            return error.PubkeyNotInIndex;
        defer lock.unlock();

        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, min_slot, max_slot) orelse
            return null;
        const account, const account_lg = try self.getAccountFromRefWithReadLock(max_ref);
        return .{ account, max_ref.slot, account_lg };
    }

    pub const GetTypeFromAccountError = GetAccountWithReadLockError || error{DeserializationError};
    pub fn getTypeFromAccount(
        self: *AccountsDB,
        allocator: std.mem.Allocator,
        comptime T: type,
        pubkey: *const Pubkey,
    ) GetTypeFromAccountError!T {
        const account, var lock_guard = try self.getAccountWithReadLock(pubkey);
        // NOTE: bincode will copy heap memory so its safe to unlock at the end of the function
        defer {
            switch (account) {
                .file => |file| file.deinit(allocator),
                .unrooted_map => {},
            }
            lock_guard.unlock();
        }

        const file_data: AccountDataHandle = switch (account) {
            .file => |in_file_account| in_file_account.data,
            .unrooted_map => |unrooted_map_account| unrooted_map_account.data,
        };

        var iter = file_data.iterator();
        const t = sig.bincode.read(allocator, T, iter.reader(), .{}) catch {
            return error.DeserializationError;
        };
        return t;
    }

    pub fn getSlotHistory(self: *AccountsDB, allocator: std.mem.Allocator) !sysvar.SlotHistory {
        return try self.getTypeFromAccount(
            allocator,
            sysvar.SlotHistory,
            &sysvar.SlotHistory.ID,
        );
    }

    /// index and validate an account file.
    /// NOTE: should only be called in tests/benchmarks
    pub fn putAccountFile(
        self: *AccountsDB,
        account_file: *AccountFile,
        n_accounts: usize,
    ) !void {
        const shard_counts =
            try self.allocator.alloc(usize, self.account_index.pubkey_ref_map.numberOfShards());
        defer self.allocator.free(shard_counts);
        @memset(shard_counts, 0);

        const reference_buf, const ref_global_index = try self.account_index
            .reference_manager.allocOrExpand(n_accounts);
        var references = std.ArrayListUnmanaged(AccountRef).initBuffer(reference_buf);

        try indexAndValidateAccountFile(
            self.allocator,
            &self.buffer_pool,
            account_file,
            self.account_index.pubkey_ref_map.shard_calculator,
            shard_counts,
            &references,
            // NOTE: this method should only be called in tests/benchmarks so we dont need
            // to support geyser
            null,
        );

        // track the slot's references
        {
            const slot_ref_map, var lock = self.account_index.slot_reference_map.writeWithLock();
            defer lock.unlock();
            try slot_ref_map.putNoClobber(account_file.slot, reference_buf);
        }

        {
            const file_map, var file_map_lg = self.file_map.writeWithLock();
            defer file_map_lg.unlock();

            try file_map.put(self.allocator, account_file.id, account_file.*);

            var buffer_pool_frame_buf: [BufferPool.MAX_READ_BYTES_ALLOCATED]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&buffer_pool_frame_buf);
            const frame_allocator = fba.allocator();

            // we update the bank hash stats while locking the file map to avoid
            // reading accounts from the file map and getting inaccurate/stale
            // bank hash stats.
            var account_iter = account_file.iterator(
                frame_allocator,
                &self.buffer_pool,
            );
            while (try account_iter.next()) |account_in_file| {
                defer {
                    account_in_file.deinit(frame_allocator);
                    fba.reset();
                }

                const bhs, var bhs_lg = try self.getOrInitBankHashStats(account_file.slot);
                defer bhs_lg.unlock();
                bhs.update(.{
                    .lamports = account_in_file.lamports().*,
                    .data_len = account_in_file.data.len(),
                    .executable = account_in_file.executable().*,
                });
            }
        }

        // allocate enough memory here
        try self.account_index.pubkey_ref_map.ensureTotalAdditionalCapacity(shard_counts);

        // compute how many account_references for each pubkey
        var accounts_dead_count: u64 = 0;
        for (references.items, 0..) |*ref, ref_count| {
            const was_inserted = self.account_index.indexRefIfNotDuplicateSlotAssumeCapacity(
                ref,
                ref_global_index + ref_count,
            );
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
        self: *AccountsDB,
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
                account.* = try original.cloneOwned(self.allocator);

                const bhs, var bhs_lg = try self.getOrInitBankHashStats(slot);
                defer bhs_lg.unlock();
                bhs.update(.{
                    .lamports = account.lamports,
                    .data_len = account.data.len(),
                    .executable = account.executable,
                });
            }

            const pubkeys_duped = try self.allocator.dupe(Pubkey, pubkeys);
            errdefer self.allocator.free(pubkeys_duped);

            const unrooted_accounts, var unrooted_accounts_lg =
                self.unrooted_accounts.writeWithLock();
            defer unrooted_accounts_lg.unlock();
            // NOTE: there should only be a single state per slot
            try unrooted_accounts.putNoClobber(slot, .{ pubkeys_duped, accounts_duped });
        }

        // prealloc the ref map space
        const shard_counts =
            try self.allocator.alloc(usize, self.account_index.pubkey_ref_map.numberOfShards());
        defer self.allocator.free(shard_counts);
        @memset(shard_counts, 0);

        const index_shard_calc = self.account_index.pubkey_ref_map.shard_calculator;
        for (pubkeys) |*pubkey| {
            shard_counts[index_shard_calc.index(pubkey)] += 1;
        }
        try self.account_index.pubkey_ref_map.ensureTotalAdditionalCapacity(shard_counts);

        // update index
        var accounts_dead_count: u64 = 0;
        const reference_buf, const global_ref_index = try self.account_index
            .reference_manager.allocOrExpand(accounts.len);

        for (0..accounts.len) |i| {
            reference_buf[i] = AccountRef{
                .pubkey = pubkeys[i],
                .slot = slot,
                .location = .{ .UnrootedMap = .{ .index = i } },
            };

            const was_inserted = self.account_index
                .indexRefIfNotDuplicateSlotAssumeCapacity(
                &reference_buf[i],
                global_ref_index + i,
            );
            if (!was_inserted) {
                self.logger.warn().logf(
                    "duplicate reference not inserted: slot: {d} pubkey: {s}",
                    .{ slot, pubkeys[i] },
                );
                accounts_dead_count += 1;
            }

            std.debug.assert(self.account_index.exists(&pubkeys[i], slot));
        }

        // track the slot's references
        {
            const slot_ref_map, var lock = self.account_index.slot_reference_map.writeWithLock();
            defer lock.unlock();
            try slot_ref_map.putNoClobber(slot, reference_buf);
        }

        if (accounts_dead_count != 0) {
            const dead_accounts, var dead_accounts_lg = self.dead_accounts_counter.writeWithLock();
            defer dead_accounts_lg.unlock();
            try dead_accounts.putNoClobber(slot, accounts_dead_count);
        }
    }

    /// Returns a pointer to the bank hash stats for the given slot, and a lock guard on the
    /// bank hash stats map, which should be unlocked after mutating the bank hash stats.
    fn getOrInitBankHashStats(
        self: *AccountsDB,
        slot: Slot,
    ) !struct { *BankHashStats, RwMux(BankHashStatsMap).WLockGuard } {
        const zone = tracy.initZone(@src(), .{ .name = "accountsdb getOrInitBankHashStats" });
        defer zone.deinit();

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
            if (inBoundsIf(ref.slot, min_slot, max_slot) and
                (biggest == null or ref.slot > biggest.?.slot) //
            ) biggest = ref;
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
            /// The full slot.
            slot: Slot,
            /// The full accounts hash.
            hash: Hash,
            /// The total lamports at the full slot.
            capitalization: u64,
        };

        pub const Incremental = struct {
            /// The incremental slot relative to the base slot (.full.slot).
            slot: Slot,
            /// The incremental accounts delta hash, including zero-lamport accounts.
            hash: Hash,
            /// The capitalization from the base slot to the incremental slot.
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
        self: *AccountsDB,
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
        self: *AccountsDB,
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
        const maybe_latest_snapshot_info: *?SnapshotGenerationInfo, //
        var latest_snapshot_info_lg //
        = self.latest_snapshot_gen_info.writeWithLock();
        defer latest_snapshot_info_lg.unlock();

        std.debug.assert(zstd_buffer.len != 0);
        std.debug.assert(params.target_slot <= self.largest_flushed_slot.load(.monotonic));

        const full_hash, const full_capitalization = compute: {
            check_first: {
                const maybe_first_snapshot_info, var first_snapshot_info_lg =
                    self.first_snapshot_load_info.readWithLock();
                defer first_snapshot_info_lg.unlock();

                const first = maybe_first_snapshot_info.* orelse break :check_first;
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
            const archive_info: FullSnapshotFileInfo = .{
                .slot = params.target_slot,
                .hash = full_hash,
            };
            const archive_file_name_bounded = archive_info.snapshotArchiveName();
            const archive_file_name = archive_file_name_bounded.constSlice();
            self.logger.info().logf("Generating full snapshot '{s}' (full path: {1s}/{0s}).", .{
                archive_file_name, sig.utils.fmt.tryRealPath(self.snapshot_dir, "."),
            });
            break :blk try self.snapshot_dir.createFile(archive_file_name, .{ .read = true });
        };
        defer archive_file.close();

        const SerializableFileMap = AccountsDbFields.FileMap;

        var serializable_file_map: SerializableFileMap = .{};
        defer serializable_file_map.deinit(self.allocator);
        var bank_hash_stats = BankHashStats.zero_init;

        // collect account files into serializable_file_map and compute bank_hash_stats
        try serializable_file_map.ensureTotalCapacity(self.allocator, file_map.count());
        for (file_map.values()) |account_file| {
            if (account_file.slot > params.target_slot) continue;

            const bank_hash_stats_map, var bank_hash_stats_map_lg =
                self.bank_hash_stats.readWithLock();
            defer bank_hash_stats_map_lg.unlock();

            if (bank_hash_stats_map.get(account_file.slot)) |other_stats| {
                bank_hash_stats.accumulate(other_stats);
            }

            serializable_file_map.putAssumeCapacityNoClobber(account_file.slot, .{
                .id = account_file.id,
                .length = account_file.length,
            });
        }

        params.bank_fields.slot = params.target_slot; // !
        params.bank_fields.capitalization = full_capitalization; // !

        const manifest: SnapshotManifest = .{
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
                .rooted_slots = &.{},
                .rooted_slot_hashes = &.{},
            },
            .bank_extra = .{
                .lamports_per_signature = params.lamports_per_signature,
                // default to null for full snapshot,
                .snapshot_persistence = null,
                .epoch_accounts_hash = null,
                .versioned_epoch_stakes = .{},
                .accounts_lt_hash = null,
            },
        };

        // main snapshot writing logic
        // writer() data flow: tar -> zstd -> archive_file
        const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, zstd_buffer);
        try writeSnapshotTarWithFields(
            zstd_write_ctx.writer(),
            sig.version.CURRENT_CLIENT_VERSION,
            StatusCache.EMPTY,
            &manifest,
            file_map,
        );
        try zstd_write_ctx.finish();

        if (self.gossip_view) |gossip_view| { // advertise new snapshot via gossip
            const push_msg_queue, var push_msg_queue_lg =
                gossip_view.push_msg_queue.writeWithLock();
            defer push_msg_queue_lg.unlock();

            try push_msg_queue.queue.append(.{
                .SnapshotHashes = .{
                    .from = gossip_view.my_pubkey,
                    .full = .{ .slot = params.target_slot, .hash = full_hash },
                    .incremental = sig.gossip.data.SnapshotHashes.IncrementalSnapshotsList.EMPTY,
                    .wallclock = 0, // the wallclock will be set when it's processed in the queue
                },
            });
        }

        // update tracking for new snapshot

        if (maybe_latest_snapshot_info.*) |old_snapshot_info| {
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

        maybe_latest_snapshot_info.* = .{
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
        self: *AccountsDB,
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
        self: *AccountsDB,
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
        const latest_snapshot_info: *SnapshotGenerationInfo, //
        var latest_snapshot_info_lg //
        = blk: {
            const maybe_latest_snapshot_info, var latest_snapshot_info_lg =
                self.latest_snapshot_gen_info.writeWithLock();
            errdefer latest_snapshot_info_lg.unlock();
            const latest_snapshot_info: *SnapshotGenerationInfo =
                &(maybe_latest_snapshot_info.* orelse return error.NoFullSnapshotExists);
            break :blk .{ latest_snapshot_info, latest_snapshot_info_lg };
        };
        defer latest_snapshot_info_lg.unlock();

        const full_snapshot_info: SnapshotGenerationInfo.Full = latest_snapshot_info.full;

        const incremental_hash, //
        const incremental_capitalization //
        = compute: {
            check_first: {
                const maybe_first_snapshot_info, var first_snapshot_info_lg =
                    self.first_snapshot_load_info.readWithLock();
                defer first_snapshot_info_lg.unlock();

                const first = maybe_first_snapshot_info.* orelse break :check_first;
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
            const archive_info: IncrementalSnapshotFileInfo = .{
                .base_slot = full_snapshot_info.slot,
                .slot = params.target_slot,
                .hash = incremental_hash,
            };
            const archive_file_name_bounded = archive_info.snapshotArchiveName();
            const archive_file_name = archive_file_name_bounded.constSlice();
            self.logger.info().logf(
                "Generating incremental snapshot '{0s}' (full path: {1s}/{0s}).",
                .{
                    archive_file_name,
                    sig.utils.fmt.tryRealPath(self.snapshot_dir, "."),
                },
            );
            break :blk try self.snapshot_dir.createFile(archive_file_name, .{ .read = true });
        };
        defer archive_file.close();

        const SerializableFileMap = AccountsDbFields.FileMap;

        var serializable_file_map: SerializableFileMap, //
        const bank_hash_stats: BankHashStats //
        = blk: {
            var serializable_file_map: SerializableFileMap = .{};
            errdefer serializable_file_map.deinit(self.allocator);
            try serializable_file_map.ensureTotalCapacity(self.allocator, file_map.count());

            var bank_hash_stats = BankHashStats.zero_init;
            for (file_map.values()) |account_file| {
                if (account_file.slot <= full_snapshot_info.slot) continue;
                if (account_file.slot > params.target_slot) continue;

                const bank_hash_stats_map, var bank_hash_stats_map_lg =
                    self.bank_hash_stats.readWithLock();
                defer bank_hash_stats_map_lg.unlock();

                if (bank_hash_stats_map.get(account_file.slot)) |other_stats| {
                    bank_hash_stats.accumulate(other_stats);
                }

                serializable_file_map.putAssumeCapacityNoClobber(account_file.slot, .{
                    .id = account_file.id,
                    .length = account_file.length,
                });
            }

            break :blk .{ serializable_file_map, bank_hash_stats };
        };
        defer serializable_file_map.deinit(self.allocator);

        const snap_persistence: BankIncrementalSnapshotPersistence = .{
            .full_slot = full_snapshot_info.slot,
            .full_hash = full_snapshot_info.hash,
            .full_capitalization = full_snapshot_info.capitalization,
            .incremental_hash = incremental_hash,
            .incremental_capitalization = incremental_capitalization,
        };

        params.bank_fields.slot = params.target_slot; // !

        const manifest: SnapshotManifest = .{
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
                .rooted_slots = &.{},
                .rooted_slot_hashes = &.{},
            },
            .bank_extra = .{
                .lamports_per_signature = params.lamports_per_signature,
                .snapshot_persistence = snap_persistence,
                // TODO: the other fields default to empty/null, but this may not always be correct.
                .epoch_accounts_hash = null,
                .versioned_epoch_stakes = .{},
                .accounts_lt_hash = null,
            },
        };

        // main snapshot writing logic
        // writer() data flow: tar -> zstd -> archive_file
        const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, zstd_buffer);
        try writeSnapshotTarWithFields(
            zstd_write_ctx.writer(),
            sig.version.CURRENT_CLIENT_VERSION,
            StatusCache.EMPTY,
            &manifest,
            file_map,
        );
        try zstd_write_ctx.finish();

        if (self.gossip_view) |gossip_view| { // advertise new snapshot via gossip
            const push_msg_queue, var push_msg_queue_lg =
                gossip_view.push_msg_queue.writeWithLock();
            defer push_msg_queue_lg.unlock();

            const IncrementalSnapshotsList =
                sig.gossip.data.SnapshotHashes.IncrementalSnapshotsList;
            const incremental = IncrementalSnapshotsList.initSingle(.{
                .slot = params.target_slot,
                .hash = incremental_hash,
            });
            try push_msg_queue.queue.append(.{
                .SnapshotHashes = .{
                    .from = gossip_view.my_pubkey,
                    .full = .{ .slot = full_snapshot_info.slot, .hash = full_snapshot_info.hash },
                    .incremental = incremental,
                    .wallclock = 0, // the wallclock will be set when it's processed in the queue
                },
            });
        }

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
        self: *AccountsDB,
        comptime kind: enum { full, incremental },
        snapshot_name_info: switch (kind) {
            .full => sig.accounts_db.snapshots.FullSnapshotFileInfo,
            .incremental => sig.accounts_db.snapshots.IncrementalSnapshotFileInfo,
        },
    ) std.fs.Dir.DeleteFileError!void {
        const file_name_bounded = snapshot_name_info.snapshotArchiveName();
        const file_name = file_name_bounded.constSlice();
        self.logger.info().logf(
            "deleting old {s} snapshot archive: {s}",
            .{ @tagName(kind), file_name },
        );
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
        OutOfMemory, // feels odd adding this, but unfamiliar with geyser - sebastian
    };

    pub fn init(allocator: std.mem.Allocator, n_accounts_estimate: usize) !Self {
        return .{
            .accounts = try ArrayList(Account).initCapacity(allocator, n_accounts_estimate),
            .pubkeys = try ArrayList(Pubkey).initCapacity(allocator, n_accounts_estimate),
        };
    }

    pub fn deinit(
        self: *Self,
        allocator: std.mem.Allocator,
    ) void {
        for (self.accounts.items) |account| account.deinit(allocator);
        self.accounts.deinit();
        self.pubkeys.deinit();
    }

    pub fn reset(
        self: *Self,
        allocator: std.mem.Allocator,
    ) void {
        for (self.accounts.items) |account| account.deinit(allocator);
        self.accounts.clearRetainingCapacity();
        self.pubkeys.clearRetainingCapacity();
    }

    pub fn cloneAndTrack(
        self: *Self,
        allocator: std.mem.Allocator,
        account_in_file: AccountInFile,
    ) Error!void {
        const account = try account_in_file.dupeCachedAccount(allocator);
        errdefer account.deinit(allocator);
        self.accounts.append(account) catch return Error.OutOfGeyserArrayMemory;
        errdefer _ = self.accounts.pop();
        self.pubkeys.append(account_in_file.pubkey().*) catch return Error.OutOfGeyserArrayMemory;
    }
};

pub const ValidateAccountFileError = error{
    ShardCountMismatch,
    InvalidAccountFileLength,
    OutOfMemory,
    OutOfReferenceMemory,
} || AccountInFile.ValidateError || GeyserTmpStorage.Error || BufferPool.ReadError;

pub fn indexAndValidateAccountFile(
    allocator: std.mem.Allocator,
    buffer_pool: *BufferPool,
    accounts_file: *AccountFile,
    shard_calculator: PubkeyShardCalculator,
    shard_counts: []usize,
    account_refs: *ArrayListUnmanaged(AccountRef),
    geyser_storage: ?*GeyserTmpStorage,
) ValidateAccountFileError!void {
    const zone = tracy.initZone(@src(), .{
        .name = "accountsdb AccountIndex.indexAndValidateAccountFile",
    });
    defer zone.deinit();

    var offset: usize = 0;
    var number_of_accounts: usize = 0;

    if (shard_counts.len != shard_calculator.n_shards) {
        return error.ShardCountMismatch;
    }

    var buffer_pool_frame_buf: [BufferPool.MAX_READ_BYTES_ALLOCATED]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer_pool_frame_buf);
    const frame_allocator = fba.allocator();

    while (true) {
        const account = accounts_file.readAccount(
            frame_allocator,
            buffer_pool,
            offset,
        ) catch |err| switch (err) {
            error.EOF => break,
            else => |e| return e,
        };

        defer {
            account.deinit(frame_allocator);
            fba.reset();
        }

        try account.validate();

        if (geyser_storage) |storage| {
            try storage.cloneAndTrack(allocator, account);
        }

        if (account_refs.capacity == account_refs.items.len) {
            return error.OutOfReferenceMemory;
        }
        account_refs.appendAssumeCapacity(.{
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

pub fn getAccountPerFileEstimateFromCluster(
    cluster: sig.core.Cluster,
) error{NotImplementedYet}!u64 {
    return switch (cluster) {
        .testnet => 500,
        else => error.NotImplementedYet,
    };
}

/// All entries in `manifest.accounts_db_fields.file_map` must correspond to an entry in `file_map`,
/// with the association defined by the file id (a field of the value of the former, the key of the latter).
pub fn writeSnapshotTarWithFields(
    archive_writer: anytype,
    version: sig.version.ClientVersion,
    status_cache: StatusCache,
    manifest: *const SnapshotManifest,
    file_map: *const AccountsDB.FileMap,
) !void {
    var counting_state = if (std.debug.runtime_safety) std.io.countingWriter(archive_writer);
    const archive_writer_counted = if (std.debug.runtime_safety)
        counting_state.writer()
    else
        archive_writer;

    try snapgen.writeMetadataFiles(archive_writer_counted, version, status_cache, manifest);

    try snapgen.writeAccountsDirHeader(archive_writer_counted);
    const file_info_map = manifest.accounts_db_fields.file_map;
    for (file_info_map.keys(), file_info_map.values()) |file_slot, file_info| {
        const account_file = file_map.getPtr(file_info.id).?;
        std.debug.assert(account_file.id == file_info.id);
        std.debug.assert(account_file.length == file_info.length);

        try snapgen.writeAccountFileHeader(archive_writer_counted, file_slot, file_info);

        try account_file.file.seekTo(0);
        var fifo = std.fifo.LinearFifo(u8, .{ .Static = std.heap.page_size_min }).init();
        try fifo.pump(account_file.file.reader(), archive_writer_counted);

        try snapgen.writeAccountFilePadding(archive_writer_counted, account_file.file_size);
    }

    try archive_writer_counted.writeAll(&sig.utils.tar.sentinel_blocks);
    if (std.debug.runtime_safety) {
        std.debug.assert(counting_state.bytes_written % 512 == 0);
    }
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

    var snap_fields = try SnapshotManifest.decodeFromBincode(allocator, manifest_file.reader());
    defer snap_fields.deinit(allocator);

    try accounts_db.loadFromSnapshot(snap_fields.accounts_db_fields, 1, allocator, 500);

    const deprecated_stored_meta_write_version =
        snap_fields.accounts_db_fields.stored_meta_write_version;
    const snapshot_gen_info = try accounts_db.generateFullSnapshot(.{
        .target_slot = slot,
        .bank_fields = &snap_fields.bank_fields,
        .lamports_per_signature = snap_fields.bank_extra.lamports_per_signature,
        .old_snapshot_action = .ignore_old,
        .deprecated_stored_meta_write_version = deprecated_stored_meta_write_version,
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

    var snap_fields = try SnapshotManifest.decodeFromBincode(allocator, manifest_file.reader());
    defer snap_fields.deinit(allocator);

    try accounts_db.loadFromSnapshot(snap_fields.accounts_db_fields, 1, allocator, 500);
    const deprecated_stored_meta_write_version =
        snap_fields.accounts_db_fields.stored_meta_write_version;
    const snapshot_gen_info = try accounts_db.generateIncrementalSnapshot(.{
        .target_slot = slot,
        .bank_fields = &snap_fields.bank_fields,
        .lamports_per_signature = snap_fields.bank_extra.lamports_per_signature,
        .old_snapshot_action = .delete_old,
        .deprecated_stored_meta_write_version = deprecated_stored_meta_write_version,
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
    // TODO: loading once from the full snapshot, and then a second time from the incremental snapshot,
    // as is done in this test, isn't properly accounted for in the snapshot loading logic, since the
    // way loading actually is handled in the validator is collapsing the full and incremental snapshots
    // before loading.
    // Either this test must be updated to test using the conventional loading method, or we must add
    // a way to load from a full and then an incremental snapshot separately.
    if (true) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var test_data_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer test_data_dir.close();

    const snap_files = try SnapshotFiles.find(allocator, test_data_dir);

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    {
        const archive_file_path_bounded = snap_files.full.snapshotArchiveName();
        const archive_file_path = archive_file_path_bounded.constSlice();
        const archive_file = try test_data_dir.openFile(archive_file_path, .{});
        defer archive_file.close();
        try parallelUnpackZstdTarBall(allocator, .noop, archive_file, snapshot_dir, 4, true);
    }

    if (snap_files.incremental()) |inc_snap| {
        const archive_file_path_bounded = inc_snap.snapshotArchiveName();
        const archive_file_path = archive_file_path_bounded.constSlice();
        const archive_file = try test_data_dir.openFile(archive_file_path, .{});
        defer archive_file.close();
        try parallelUnpackZstdTarBall(allocator, .noop, archive_file, snapshot_dir, 4, false);
    }

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .noop,
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = ACCOUNT_INDEX_SHARDS,
    });
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
        snap_files.incremental_info.?.slot,
        snap_files.incremental_info.?.hash,
    );
}

/// Unpacks the snapshots from `sig.TEST_DATA_DIR`.
pub fn findAndUnpackTestSnapshots(
    n_threads: usize,
    /// The directory into which the snapshots are unpacked.
    /// Useful in tandem with the returned `SnapshotFiles` for loading
    /// from a different directory to where the source snapshot archives
    /// are located.
    output_dir: std.fs.Dir,
) !SnapshotFiles {
    comptime std.debug.assert(builtin.is_test); // should only be used in tests
    const allocator = std.testing.allocator;
    var test_data_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer test_data_dir.close();
    return try findAndUnpackSnapshotFilePair(allocator, n_threads, output_dir, test_data_dir);
}

pub fn findAndUnpackSnapshotFilePair(
    allocator: std.mem.Allocator,
    n_threads: usize,
    dst_dir: std.fs.Dir,
    /// Must be iterable.
    src_dir: std.fs.Dir,
) !SnapshotFiles {
    const snapshot_files = try SnapshotFiles.find(allocator, src_dir);
    try unpackSnapshotFilePair(allocator, n_threads, dst_dir, src_dir, snapshot_files);
    return snapshot_files;
}

/// Unpacks the identified snapshot files in `src_dir` into `dst_dir`.
pub fn unpackSnapshotFilePair(
    allocator: std.mem.Allocator,
    n_threads: usize,
    dst_dir: std.fs.Dir,
    src_dir: std.fs.Dir,
    /// `= try SnapshotFiles.find(allocator, src_dir)`
    snapshot_files: SnapshotFiles,
) !void {
    {
        const full = snapshot_files.full;
        const full_name_bounded = full.snapshotArchiveName();
        const full_name = full_name_bounded.constSlice();
        const full_archive_file = try src_dir.openFile(full_name, .{});
        defer full_archive_file.close();
        try parallelUnpackZstdTarBall(
            allocator,
            .noop,
            full_archive_file,
            dst_dir,
            n_threads,
            true,
        );
    }

    if (snapshot_files.incremental()) |inc| {
        const inc_name_bounded = inc.snapshotArchiveName();
        const inc_name = inc_name_bounded.constSlice();
        const inc_archive_file = try src_dir.openFile(inc_name, .{});
        defer inc_archive_file.close();
        try parallelUnpackZstdTarBall(
            allocator,
            .noop,
            inc_archive_file,
            dst_dir,
            n_threads,
            false,
        );
    }
}

fn loadTestAccountsDB(
    allocator: std.mem.Allocator,
    use_disk: bool,
    n_threads: u32,
    logger: Logger,
    /// The directory into which the snapshots are unpacked, and
    /// the `snapshots_dir` for the returned `AccountsDB`.
    snapshot_dir: std.fs.Dir,
) !struct { AccountsDB, FullAndIncrementalManifest } {
    comptime std.debug.assert(builtin.is_test); // should only be used in tests

    var dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
    defer dir.close();

    const snapshot_files = try findAndUnpackTestSnapshots(n_threads, snapshot_dir);

    const full_inc_manifest =
        try FullAndIncrementalManifest.fromFiles(allocator, logger, snapshot_dir, snapshot_files);
    errdefer full_inc_manifest.deinit(allocator);

    const manifest = try full_inc_manifest.collapse(allocator);
    defer manifest.deinit(allocator);

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = logger,
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = if (use_disk) .disk else .ram,
        .number_of_index_shards = 4,
    });
    errdefer accounts_db.deinit();

    try accounts_db.loadFromSnapshot(
        manifest.accounts_db_fields,
        n_threads,
        allocator,
        500,
    );

    return .{ accounts_db, full_inc_manifest };
}

// NOTE: this is a memory leak test - geyser correctness is tested in the geyser tests
test "geyser stream on load" {
    const allocator = std.testing.allocator;
    const logger: Logger = .noop;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    const snapshot_files = try findAndUnpackTestSnapshots(2, snapshot_dir);

    const full_inc_manifest =
        try FullAndIncrementalManifest.fromFiles(allocator, logger, snapshot_dir, snapshot_files);
    defer full_inc_manifest.deinit(allocator);

    var geyser_exit = std.atomic.Value(bool).init(false);

    const geyser_writer: *GeyserWriter = try allocator.create(GeyserWriter);
    defer allocator.destroy(geyser_writer);

    const geyser_pipe_path = sig.TEST_DATA_DIR ++ "geyser.pipe";
    geyser_writer.* = try GeyserWriter.init(
        allocator,
        geyser_pipe_path,
        &geyser_exit,
        1 << 21,
    );
    defer geyser_writer.deinit();

    // start the geyser writer
    try geyser_writer.spawnIOLoop();

    var reader = try sig.geyser.GeyserReader.init(
        allocator,
        geyser_pipe_path,
        &geyser_exit,
        .{},
    );
    defer reader.deinit();

    const reader_handle = try std.Thread.spawn(.{}, sig.geyser.core.streamReader, .{
        &reader,
        .noop,
        &geyser_exit,
        null,
    });
    defer reader_handle.join();

    defer geyser_exit.store(true, .release);

    const snapshot = try full_inc_manifest.collapse(allocator);
    defer snapshot.deinit(allocator);

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = logger,
        .snapshot_dir = snapshot_dir,
        .geyser_writer = geyser_writer,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 4,
    });
    defer accounts_db.deinit();

    try accounts_db.loadFromSnapshot(
        snapshot.accounts_db_fields,
        1,
        allocator,
        500,
    );
}

test "write and read an account" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDB(allocator, false, 1, .noop, snapshot_dir);
    defer accounts_db.deinit();
    defer full_inc_manifest.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(0);
    const pubkey = Pubkey.initRandom(prng.random());
    var data = [_]u8{ 1, 2, 3 };
    const test_account = Account{
        .data = AccountDataHandle.initAllocated(&data),
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

test "load and validate BankFields from test snapshot" {
    const allocator = std.testing.allocator;

    var test_data_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{});
    defer test_data_dir.close();

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapdir = tmp_dir_root.dir;

    const snapshot_files = try sig.accounts_db.db.findAndUnpackTestSnapshots(1, snapdir);

    const boundedFmt = sig.utils.fmt.boundedFmt;
    const full_manifest_path = boundedFmt("snapshots/{0}/{0}", .{snapshot_files.full.slot});
    const full_manifest_file = try snapdir.openFile(full_manifest_path.constSlice(), .{});
    defer full_manifest_file.close();

    const full_manifest = try SnapshotManifest.readFromFile(allocator, full_manifest_file);
    defer full_manifest.deinit(allocator);

    // use the genesis to verify loading
    const genesis_path = sig.TEST_DATA_DIR ++ "genesis.bin";
    const genesis_config = try sig.core.GenesisConfig.init(allocator, genesis_path);
    defer genesis_config.deinit(allocator);

    try full_manifest.bank_fields.validate(&genesis_config);
}

test "load and validate from test snapshot" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDB(allocator, false, 1, .noop, snapshot_dir);
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    const maybe_inc_persistence = full_inc_manifest.incremental.?.bank_extra.snapshot_persistence;
    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = full_inc_manifest.full.bank_fields.slot,
        .expected_full = .{
            .accounts_hash = full_inc_manifest.full.accounts_db_fields.bank_hash_info.accounts_hash,
            .capitalization = full_inc_manifest.full.bank_fields.capitalization,
        },
        .expected_incremental = if (maybe_inc_persistence) |inc_persistence| .{
            .accounts_hash = inc_persistence.incremental_hash,
            .capitalization = inc_persistence.incremental_capitalization,
        } else null,
    });
}

test "load and validate from test snapshot using disk index" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDB(allocator, false, 1, .noop, snapshot_dir);
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    const maybe_inc_persistence = full_inc_manifest.incremental.?.bank_extra.snapshot_persistence;
    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = full_inc_manifest.full.bank_fields.slot,
        .expected_full = .{
            .accounts_hash = full_inc_manifest.full.accounts_db_fields.bank_hash_info.accounts_hash,
            .capitalization = full_inc_manifest.full.bank_fields.capitalization,
        },
        .expected_incremental = if (maybe_inc_persistence) |inc_persistence| .{
            .accounts_hash = inc_persistence.incremental_hash,
            .capitalization = inc_persistence.incremental_capitalization,
        } else null,
    });
}

test "load and validate from test snapshot parallel" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDB(allocator, false, 2, .noop, snapshot_dir);
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    const maybe_inc_persistence = full_inc_manifest.incremental.?.bank_extra.snapshot_persistence;
    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = full_inc_manifest.full.bank_fields.slot,
        .expected_full = .{
            .accounts_hash = full_inc_manifest.full.accounts_db_fields.bank_hash_info.accounts_hash,
            .capitalization = full_inc_manifest.full.bank_fields.capitalization,
        },
        .expected_incremental = if (maybe_inc_persistence) |inc_persistence| .{
            .accounts_hash = inc_persistence.incremental_hash,
            .capitalization = inc_persistence.incremental_capitalization,
        } else null,
    });
}

test "load clock sysvar" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDB(allocator, false, 1, .noop, snapshot_dir);
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    const full = full_inc_manifest.full;
    const inc = full_inc_manifest.incremental;
    const expected_clock: sysvar.Clock = .{
        .slot = (inc orelse full).bank_fields.slot,
        .epoch_start_timestamp = 1733349736,
        .epoch = (inc orelse full).bank_fields.epoch,
        .leader_schedule_epoch = 1,
        .unix_timestamp = 1733350255,
    };
    try std.testing.expectEqual(
        expected_clock,
        try accounts_db.getTypeFromAccount(allocator, sysvar.Clock, &sysvar.Clock.ID),
    );
}

test "load other sysvars" {
    var gpa_state: std.heap.DebugAllocator(.{ .stack_trace_frames = 64 }) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDB(allocator, false, 1, .noop, snapshot_dir);
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    const SlotAndHash = sig.core.hash.SlotAndHash;
    _ = try accounts_db.getTypeFromAccount(
        allocator,
        sig.core.EpochSchedule,
        &sig.core.EpochSchedule.ID,
    );
    _ = try accounts_db.getTypeFromAccount(
        allocator,
        sysvar.Rent,
        &sysvar.Rent.ID,
    );
    _ = try accounts_db.getTypeFromAccount(
        allocator,
        SlotAndHash,
        &sysvar.SlotHashes.ID,
    );

    const stake_history = try accounts_db.getTypeFromAccount(
        allocator,
        sysvar.StakeHistory,
        &sysvar.StakeHistory.ID,
    );
    defer sig.bincode.free(allocator, stake_history);

    const slot_history = try accounts_db.getTypeFromAccount(
        allocator,
        sysvar.SlotHistory,
        &sysvar.SlotHistory.ID,
    );
    defer sig.bincode.free(allocator, slot_history);

    // // not always included in local snapshot
    // _ = try accounts_db.getTypeFromAccount(allocator, sysvars.LastRestartSlot, &sysvars.LastRestartSlot.ID);
    // _ = try accounts_db.getTypeFromAccount(allocator, sysvars.EpochRewards, &sysvars.EpochRewards.ID);
}

test "generate snapshot & update gossip snapshot hashes" {
    const GossipDataTag = sig.gossip.data.GossipDataTag;
    const SnapshotHashes = sig.gossip.data.SnapshotHashes;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(123); // TODO: use `std.testing.random_seed` when we update
    const random = prng.random();

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    const snap_files = try findAndUnpackTestSnapshots(1, snapshot_dir);

    const full_inc_manifest =
        try FullAndIncrementalManifest.fromFiles(allocator, .noop, snapshot_dir, snap_files);
    defer full_inc_manifest.deinit(allocator);

    // mock gossip service
    var push_msg_queue_mux = sig.gossip.GossipService.PushMessageQueue.init(.{
        .queue = std.ArrayList(sig.gossip.data.GossipData).init(allocator),
        .data_allocator = allocator,
    });
    defer push_msg_queue_mux.private.v.queue.deinit();
    const my_keypair = KeyPair.generate();

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .noop,
        .snapshot_dir = snapshot_dir,
        .gossip_view = .{
            .my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key),
            .push_msg_queue = &push_msg_queue_mux,
        },
        .geyser_writer = null,
        .index_allocation = .ram,
        .number_of_index_shards = ACCOUNT_INDEX_SHARDS,
    });
    defer accounts_db.deinit();

    (try accounts_db.loadWithDefaults(
        allocator,
        full_inc_manifest,
        1,
        true,
        300,
        false,
        false,
    )).deinit(allocator);

    var bank_fields = try BankFields.initRandom(allocator, random, 128);
    defer bank_fields.deinit(allocator);

    const full_slot = full_inc_manifest.full.accounts_db_fields.slot;
    const full_gen_result = try accounts_db.generateFullSnapshot(.{
        .target_slot = full_slot,
        .bank_fields = &bank_fields,
        .lamports_per_signature = random.int(u64),
        // make sure we don't delete anything in `sig.TEST_DATA_DIR`
        .old_snapshot_action = .ignore_old,
        .deprecated_stored_meta_write_version = blk: {
            const accounts_db_fields = full_inc_manifest.full.accounts_db_fields;
            break :blk accounts_db_fields.stored_meta_write_version;
        },
    });
    const full_hash = full_gen_result.hash;

    try std.testing.expectEqual(
        full_inc_manifest.full.accounts_db_fields.bank_hash_info.accounts_hash,
        full_gen_result.hash,
    );
    try std.testing.expectEqual(
        full_inc_manifest.full.bank_fields.capitalization,
        full_gen_result.capitalization,
    );

    {
        const queue, var queue_lg = push_msg_queue_mux.readWithLock();
        defer queue_lg.unlock();

        try std.testing.expectEqual(1, queue.queue.items.len);
        const queue_item_0 = queue.queue.items[0]; // should be from the full generation
        try std.testing.expectEqual(.SnapshotHashes, @as(GossipDataTag, queue_item_0));

        try std.testing.expectEqualDeep(
            SnapshotHashes{
                .from = Pubkey.fromPublicKey(&my_keypair.public_key),
                .full = .{ .slot = full_slot, .hash = full_hash },
                .incremental = SnapshotHashes.IncrementalSnapshotsList.EMPTY,
                // set to zero when pushed to the queue, because it would be set in `drainPushQueueToGossipTable`.
                .wallclock = 0,
            },
            queue_item_0.SnapshotHashes,
        );
    }

    if (full_inc_manifest.incremental) |inc_manifest| {
        const inc_slot = inc_manifest.accounts_db_fields.slot;
        const inc_gen_result = try accounts_db.generateIncrementalSnapshot(.{
            .target_slot = inc_slot,
            .bank_fields = &bank_fields,
            .lamports_per_signature = random.int(u64),
            // make sure we don't delete anything in `sig.TEST_DATA_DIR`
            .old_snapshot_action = .ignore_old,
            .deprecated_stored_meta_write_version = inc_manifest
                .accounts_db_fields.stored_meta_write_version,
        });
        const inc_hash = inc_gen_result.incremental_hash;

        try std.testing.expectEqual(
            inc_manifest.bank_extra.snapshot_persistence,
            inc_gen_result,
        );
        try std.testing.expectEqual(
            full_slot,
            inc_gen_result.full_slot,
        );
        try std.testing.expectEqual(
            full_gen_result.hash,
            inc_gen_result.full_hash,
        );
        try std.testing.expectEqual(
            full_gen_result.capitalization,
            inc_gen_result.full_capitalization,
        );

        {
            const queue, var queue_lg = push_msg_queue_mux.readWithLock();
            defer queue_lg.unlock();

            try std.testing.expectEqual(2, queue.queue.items.len);
            const queue_item_1 = queue.queue.items[1]; // should be from the incremental generation
            try std.testing.expectEqual(.SnapshotHashes, @as(GossipDataTag, queue_item_1));

            try std.testing.expectEqualDeep(
                SnapshotHashes{
                    .from = Pubkey.fromPublicKey(&my_keypair.public_key),
                    .full = .{ .slot = full_slot, .hash = full_hash },
                    .incremental = SnapshotHashes.IncrementalSnapshotsList.initSingle(.{
                        .slot = inc_slot,
                        .hash = inc_hash,
                    }),
                    // set to zero when pushed to the queue, because it would be set in `drainPushQueueToGossipTable`.
                    .wallclock = 0,
                },
                queue_item_1.SnapshotHashes,
            );
        }
    }
}

pub const BenchmarkAccountsDBSnapshotLoad = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 1;

    pub const SNAPSHOT_DIR_PATH = sig.TEST_DATA_DIR ++ "bench_snapshot/";

    pub const BenchArgs = struct {
        use_disk: bool,
        n_threads: u32,
        name: []const u8,
        cluster: sig.core.Cluster,
        // TODO: support fastloading checks
    };

    pub const args = [_]BenchArgs{
        BenchArgs{
            .name = "testnet - ram index - 4 threads",
            .use_disk = false,
            .n_threads = 4,
            .cluster = .testnet,
        },
    };

    pub fn loadAndVerifySnapshot(units: BenchTimeUnit, bench_args: BenchArgs) !struct {
        load_time: u64,
        validate_time: u64,
        fastload_save_time: u64,
        fastload_time: u64,
    } {
        const allocator = std.heap.c_allocator;
        var print_logger = sig.trace.DirectPrintLogger.init(allocator, .debug);
        const logger = print_logger.logger();

        // unpack the snapshot
        var snapshot_dir = std.fs.cwd().openDir(
            SNAPSHOT_DIR_PATH,
            .{ .iterate = true },
        ) catch {
            // not snapshot -> early exit
            std.debug.print(
                "need to setup a snapshot in {s} for this benchmark...\n",
                .{SNAPSHOT_DIR_PATH},
            );
            const zero_duration = sig.time.Duration.fromNanos(0);
            return .{
                .load_time = zero_duration.asNanos(),
                .validate_time = zero_duration.asNanos(),
                .fastload_save_time = zero_duration.asNanos(),
                .fastload_time = zero_duration.asNanos(),
            };
        };
        defer snapshot_dir.close();

        const snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);
        const full_inc_manifest = try FullAndIncrementalManifest.fromFiles(
            allocator,
            logger,
            snapshot_dir,
            snapshot_files,
        );
        defer full_inc_manifest.deinit(allocator);
        const collapsed_manifest = try full_inc_manifest.collapse(allocator);

        const loading_duration, //
        const fastload_save_duration, //
        const validate_duration //
        = duration_blk: {
            var accounts_db = try AccountsDB.init(.{
                .allocator = allocator,
                .logger = logger,
                .snapshot_dir = snapshot_dir,
                .geyser_writer = null,
                .gossip_view = null,
                .index_allocation = if (bench_args.use_disk) .disk else .ram,
                .number_of_index_shards = 32,
            });
            defer accounts_db.deinit();

            var load_timer = try sig.time.Timer.start();
            try accounts_db.loadFromSnapshot(
                collapsed_manifest.accounts_db_fields,
                bench_args.n_threads,
                allocator,
                try getAccountPerFileEstimateFromCluster(bench_args.cluster),
            );
            const loading_duration = load_timer.read();

            const fastload_save_duration = blk: {
                var timer = try sig.time.Timer.start();
                try accounts_db.saveStateForFastload();
                break :blk timer.read();
            };

            const full_manifest = full_inc_manifest.full;
            const maybe_inc_persistence = if (full_inc_manifest.incremental) |inc|
                inc.bank_extra.snapshot_persistence
            else
                null;

            var validate_timer = try sig.time.Timer.start();
            try accounts_db.validateLoadFromSnapshot(.{
                .full_slot = full_manifest.bank_fields.slot,
                .expected_full = .{
                    .accounts_hash = full_manifest.accounts_db_fields.bank_hash_info.accounts_hash,
                    .capitalization = full_manifest.bank_fields.capitalization,
                },
                .expected_incremental = if (maybe_inc_persistence) |inc_persistence| .{
                    .accounts_hash = inc_persistence.incremental_hash,
                    .capitalization = inc_persistence.incremental_capitalization,
                } else null,
            });
            const validate_duration = validate_timer.read();

            break :duration_blk .{ loading_duration, fastload_save_duration, validate_duration };
        };

        const fastload_duration = blk: {
            var fastload_accounts_db = try AccountsDB.init(.{
                .allocator = allocator,
                .logger = logger,
                .snapshot_dir = snapshot_dir,
                .geyser_writer = null,
                .gossip_view = null,
                .index_allocation = if (bench_args.use_disk) .disk else .ram,
                .number_of_index_shards = 32,
            });
            defer fastload_accounts_db.deinit();

            var fastload_dir = try snapshot_dir.makeOpenPath("fastload_state", .{});
            defer fastload_dir.close();

            var fastload_timer = try sig.time.Timer.start();
            try fastload_accounts_db.fastload(fastload_dir, collapsed_manifest.accounts_db_fields);
            break :blk fastload_timer.read();
        };

        return .{
            .load_time = units.convertDuration(loading_duration),
            .validate_time = units.convertDuration(validate_duration),
            .fastload_save_time = units.convertDuration(fastload_save_duration),
            .fastload_time = units.convertDuration(fastload_duration),
        };
    }
};

pub const BenchmarkAccountsDB = struct {
    pub const min_iterations = 3;
    pub const max_iterations = 10;

    pub const MemoryType = AccountIndex.AllocatorConfig.Tag;

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
        // BenchArgs{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .ram,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - ram accounts - lru disabled)",
        // },
        // BenchArgs{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .ram,
        //     .index = .disk,
        //     .name = "100k accounts (1_slot - disk index - ram accounts - lru disabled)",
        // },
        // BenchArgs{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .name = "100k accounts (1_slot - disk index - disk accounts - lru disabled)",
        // },

        // BenchArgs{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - disk accounts - lru disabled)",
        // },

        // BenchArgs{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - disk accounts)",
        // },
        // BenchArgs{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - disk accounts)",
        // },

        // BenchArgs{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - disk accounts)",
        // },

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

        // tests large number of accounts on disk
        // NOTE: the other tests are useful for understanding performance for but CI,
        // these are the most useful as they are the most similar to production
        BenchArgs{
            .n_accounts = 10_000,
            .slot_list_len = 10,
            .accounts = .disk,
            .index = .ram,
            .name = "10k accounts (10_slots - ram index - disk accounts)",
        },
        BenchArgs{
            .n_accounts = 500_000,
            .slot_list_len = 1,
            .accounts = .disk,
            .index = .ram,
            .name = "500k accounts (1_slot - ram index - disk accounts)",
        },

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
        //     .name = "3M accounts (3_slot - ram index - disk accounts - 1million init)",
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

    pub fn readWriteAccounts(
        units: BenchTimeUnit,
        bench_args: BenchArgs,
    ) !struct { read_time: u64, write_time: u64 } {
        const n_accounts = bench_args.n_accounts;
        const slot_list_len = bench_args.slot_list_len;
        const total_n_accounts = n_accounts * slot_list_len;

        // make sure theres no leaks
        const allocator = if (builtin.is_test) std.testing.allocator else std.heap.c_allocator;
        var disk_dir = std.testing.tmpDir(.{});
        defer disk_dir.cleanup();

        var snapshot_dir = try std.fs.cwd().makeOpenPath(sig.VALIDATOR_DIR ++ "accounts_db", .{});
        defer snapshot_dir.close();

        const index_type: AccountsDB.InitParams.Index = switch (bench_args.index) {
            .disk => .disk,
            .ram => .ram,
            .parent => @panic("invalid benchmark argument"),
        };

        const logger = .noop;
        var accounts_db: AccountsDB = try AccountsDB.init(.{
            .allocator = allocator,
            .logger = logger,
            .snapshot_dir = snapshot_dir,
            .geyser_writer = null,
            .gossip_view = null,
            .index_allocation = index_type,
            .number_of_index_shards = 32,
        });
        defer accounts_db.deinit();

        try accounts_db.account_index.expandRefCapacity(total_n_accounts);

        var prng = std.Random.DefaultPrng.init(19);
        const random = prng.random();

        var pubkeys = try allocator.alloc(Pubkey, n_accounts);
        defer allocator.free(pubkeys);
        for (0..n_accounts) |i| {
            pubkeys[i] = Pubkey.initRandom(random);
        }

        var all_filenames: ArrayListUnmanaged([]const u8) = .{};
        defer all_filenames.deinit(allocator);
        defer for (all_filenames.items) |filepath| {
            disk_dir.dir.deleteFile(filepath) catch {
                std.debug.print("failed to delete file: {s}\n", .{filepath});
            };
            allocator.free(filepath);
        };
        try all_filenames.ensureTotalCapacityPrecise(
            allocator,
            slot_list_len + bench_args.n_accounts_multiple,
        );

        const write_time = timer_blk: {
            switch (bench_args.accounts) {
                .parent => @panic("invalid bench arg"),
                .ram => {
                    const n_accounts_init = bench_args.n_accounts_multiple * bench_args.n_accounts;
                    const accounts =
                        try allocator.alloc(Account, (total_n_accounts + n_accounts_init));
                    defer {
                        for (accounts[0..total_n_accounts]) |account| account.deinit(allocator);
                        allocator.free(accounts);
                    }
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

                    var timer = try sig.time.Timer.start();
                    for (0..slot_list_len) |i| {
                        const start_index = i * n_accounts;
                        const end_index = start_index + n_accounts;
                        try accounts_db.putAccountSlice(
                            accounts[start_index..end_index],
                            pubkeys,
                            @as(u64, @intCast(i)),
                        );
                    }
                    break :timer_blk timer.read();
                },
                .disk => {
                    var account_files: ArrayListUnmanaged(AccountFile) = .{};
                    defer {
                        // don't deinit each account_file here - they are taken by putAccountFile
                        account_files.deinit(allocator);
                    }
                    try account_files.ensureTotalCapacityPrecise(
                        allocator,
                        slot_list_len,
                    );

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
                        const aligned_size =
                            std.mem.alignForward(usize, size, std.heap.page_size_min);

                        const filepath_bounded = sig.utils.fmt.boundedFmt("slot{d}.bin", .{s});
                        const filepath = filepath_bounded.constSlice();

                        var account_file = blk: {
                            var file = try disk_dir.dir.createFile(filepath, .{ .read = true });
                            errdefer file.close();

                            // resize the file
                            const file_size = (try file.stat()).size;
                            if (file_size < aligned_size) {
                                try file.seekTo(aligned_size - 1);
                                _ = try file.write(&[_]u8{1});
                                try file.seekTo(0);
                            }

                            const buf = try allocator.alloc(u8, aligned_size);
                            defer allocator.free(buf);

                            var offset: usize = 0;
                            for (0..n_accounts) |i| {
                                const account =
                                    try Account.initRandom(allocator, random, i % 1_000);
                                defer account.deinit(allocator);
                                var pubkey = pubkeys[i % n_accounts];
                                offset += account.writeToBuf(&pubkey, buf[offset..]);
                            }

                            try file.writeAll(buf);

                            break :blk try AccountFile.init(file, .{
                                .id = FileId.fromInt(@intCast(s)),
                                .length = offset,
                            }, s);
                        };

                        if (s < bench_args.n_accounts_multiple) {
                            try accounts_db.putAccountFile(&account_file, n_accounts);
                        } else {
                            // to be indexed later (and timed)
                            account_files.appendAssumeCapacity(account_file);
                        }
                        all_filenames.appendAssumeCapacity(try allocator.dupe(u8, filepath));
                    }

                    var timer = try sig.time.Timer.start();
                    for (account_files.items) |*account_file| {
                        try accounts_db.putAccountFile(account_file, n_accounts);
                    }
                    break :timer_blk timer.read();
                },
            }
        };

        // set up a WeightedAliasSampler to give our accounts normally distributed access probabilities.
        // this models how some accounts are far more commonly read than others.
        // TODO: is this distribution accurate? Probably not, but I don't have the data.
        const pubkeys_read_weighting = try allocator.alloc(f32, n_accounts);
        defer allocator.free(pubkeys_read_weighting);
        for (pubkeys_read_weighting) |*read_probability| read_probability.* = random.floatNorm(f32);
        var indexer = try WeightedAliasSampler.init(allocator, random, pubkeys_read_weighting);
        defer indexer.deinit(allocator);

        // "warm up" accounts cache
        {
            var i: usize = 0;
            while (i < n_accounts) : (i += 1) {
                const pubkey_idx = indexer.sample();
                const account = try accounts_db.getAccount(&pubkeys[pubkey_idx]);
                account.deinit(allocator);
            }
        }

        var timer = try sig.time.Timer.start();

        const do_read_count = n_accounts;
        var i: usize = 0;
        while (i < do_read_count) : (i += 1) {
            const pubkey_idx = indexer.sample();
            const account = try accounts_db.getAccount(&pubkeys[pubkey_idx]);
            defer account.deinit(allocator);
            if (account.data.len() != (pubkey_idx % 1_000)) std.debug.panic(
                "account data len dnm {}: {} != {}",
                .{ pubkey_idx, account.data.len(), pubkey_idx % 1_000 },
            );
        }
        const read_time = timer.read();

        return .{
            .read_time = units.convertDuration(read_time),
            .write_time = units.convertDuration(write_time),
        };
    }
};

test "read/write benchmark ram" {
    _ = try BenchmarkAccountsDB.readWriteAccounts(.nanos, .{
        .n_accounts = 10,
        .slot_list_len = 1,
        .accounts = .ram,
        .index = .ram,
    });
}

test "read/write benchmark disk" {
    _ = try BenchmarkAccountsDB.readWriteAccounts(.nanos, .{
        .n_accounts = 10,
        .slot_list_len = 1,
        .accounts = .disk,
        .index = .disk,
    });
}
