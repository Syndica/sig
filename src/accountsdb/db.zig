//! includes the main database struct `AccountsDB`

const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const zstd = @import("zstd");
const tracy = @import("tracy");

const sysvar = sig.runtime.sysvar;
const snapgen = sig.accounts_db.snapshot.data.generate;

const Resolution = @import("../benchmarks.zig").Resolution;

const ArrayList = std.array_list.Managed;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const BankFields = sig.core.BankFields;

const AccountFile = sig.accounts_db.accounts_file.AccountFile;
const AccountInFile = sig.accounts_db.accounts_file.AccountInFile;
const FileId = sig.accounts_db.accounts_file.FileId;
const StatusCache = sig.accounts_db.snapshot.StatusCache;

const AccountsDbFields = sig.accounts_db.snapshot.data.AccountsDbFields;
const BankHashStats = sig.accounts_db.snapshot.data.BankHashStats;
const ObsoleteIncrementalSnapshotPersistence =
    sig.accounts_db.snapshot.data.ObsoleteIncrementalSnapshotPersistence;
const FullAndIncrementalManifest = sig.accounts_db.snapshot.data.FullAndIncrementalManifest;
const FullSnapshotFileInfo = sig.accounts_db.snapshot.data.FullSnapshotFileInfo;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshot.data.IncrementalSnapshotFileInfo;
const SnapshotFiles = sig.accounts_db.snapshot.data.SnapshotFiles;
const SnapshotManifest = sig.accounts_db.snapshot.data.Manifest;

const AccountDataHandle = sig.accounts_db.buffer_pool.AccountDataHandle;
const AccountIndex = sig.accounts_db.index.AccountIndex;
const AccountRef = sig.accounts_db.index.AccountRef;
const BufferPool = sig.accounts_db.buffer_pool.BufferPool;
const PubkeyShardCalculator = sig.accounts_db.index.PubkeyShardCalculator;
const ShardedPubkeyRefMap = sig.accounts_db.index.ShardedPubkeyRefMap;

const Account = sig.core.Account;
const Ancestors = sig.core.Ancestors;
const Hash = sig.core.Hash;
const LtHash = sig.core.LtHash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const AccountSharedData = sig.runtime.AccountSharedData;

const GeyserWriter = sig.geyser.GeyserWriter;

const Counter = sig.prometheus.counter.Counter;
const Gauge = sig.prometheus.Gauge;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const Histogram = sig.prometheus.histogram.Histogram;

const WeightedAliasSampler = sig.rand.WeightedAliasSampler;

const RwMux = sig.sync.RwMux;

const assert = std.debug.assert;

const parallelUnpackZstdTarBall = sig.accounts_db.snapshot.data.parallelUnpackZstdTarBall;
const spawnThreadTasks = sig.utils.thread.spawnThreadTasks;
const printTimeEstimate = sig.time.estimate.printTimeEstimate;
const globalRegistry = sig.prometheus.registry.globalRegistry;

const Logger = sig.trace.log.Logger("accounts_db");

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
    logger: Logger,

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

    max_slots: RwMux(struct {
        // TODO: integrate these values into consensus
        /// Used for flushing/cleaning/purging/shrinking.
        rooted: ?Slot,
        /// Represents the largest slot for which all account data has been flushed to disk.
        /// Always `<= rooted`, or `null` if `rooted` is null.
        flushed: ?Slot,

        pub const INIT: @This() = .{
            .rooted = null,
            .flushed = null,
        };
    }),

    /// The snapshot info from which this instance was loaded from and validated against (null if that didn't happen).
    /// Used to potentially skip the first `computeAccountHashesAndLamports`.
    first_snapshot_load_info: RwMux(?SnapshotGenerationInfo),
    /// Represents the largest slot info used to generate a full snapshot, and optionally an incremental snapshot relative to it, which currently exists.
    /// It also protects access to the snapshot archive files it refers to - as in, the caller who has a lock on this has a lock on the snapshot archives.
    latest_snapshot_gen_info: RwMux(?SnapshotGenerationInfo),

    // TODO: populate this during snapshot load
    // TODO: move to Bank struct
    bank_hash_stats: RwMux(BankHashStatsMap),

    on_root_config: sig.accounts_db.manager.Config,

    const PubkeyAndAccount = struct { pubkey: Pubkey, account: Account };

    pub const PubkeysAndAccounts = std.MultiArrayList(PubkeyAndAccount);
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
        allocator: std.mem.Allocator,
        logger: Logger,
        snapshot_dir: std.fs.Dir,
        geyser_writer: ?*GeyserWriter,
        gossip_view: ?GossipView,
        index_allocation: Index,
        number_of_index_shards: usize,
        on_root_config: sig.accounts_db.manager.Config = .{},
        /// Amount of BufferPool frames, used for cached reads. Deprecated - defaulted to 20MiB.
        buffer_pool_frames: u32 = 40 * 1024,

        pub const Index = union(AccountIndex.AllocatorConfig.Tag) {
            ram,
            disk,
            parent: *sig.accounts_db.index.ReferenceAllocator,
        };

        /// Minimal configuration, mainly for tests.
        /// Uses ram for index allocation, one index shard, no gossip view, no geyser writer, and 2 buffer pool frames.
        pub fn minimal(
            allocator: std.mem.Allocator,
            logger: Logger,
            snapshot_dir: std.fs.Dir,
            buffer_pool_frames: ?u32,
        ) InitParams {
            return .{
                .allocator = allocator,
                .logger = logger,
                .snapshot_dir = snapshot_dir,
                .index_allocation = .ram,
                .number_of_index_shards = 1,
                .geyser_writer = null,
                .gossip_view = null,
                .buffer_pool_frames = buffer_pool_frames orelse 128 * 1024,
            };
        }
    };

    pub fn init(params: InitParams) !AccountsDB {
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb init" });
        defer zone.deinit();

        // init index
        const index_config: AccountIndex.AllocatorConfig = switch (params.index_allocation) {
            .disk => .{ .disk = .{ .accountsdb_dir = params.snapshot_dir } },
            .ram => .{ .ram = .{ .allocator = params.allocator } },
            .parent => |parent| .{ .parent = parent },
        };

        var account_index = try AccountIndex.init(
            params.allocator,
            .from(params.logger),
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

        return .{
            .allocator = params.allocator,
            .metrics = metrics,
            .logger = params.logger,
            .snapshot_dir = params.snapshot_dir,
            .geyser_writer = params.geyser_writer,
            .gossip_view = params.gossip_view,

            .number_of_index_shards = params.number_of_index_shards,

            .account_index = account_index,
            .unrooted_accounts = .init(.init(params.allocator)),
            .file_map = .init(.{}),
            .file_map_fd_rw = .{},
            .buffer_pool = buffer_pool,
            .dead_accounts_counter = .init(.init(params.allocator)),

            .largest_file_id = .fromInt(0),
            .max_slots = .init(.INIT),

            .first_snapshot_load_info = .init(null),
            .latest_snapshot_gen_info = .init(null),

            .bank_hash_stats = .init(.{}),
            .on_root_config = params.on_root_config,
        };
    }

    /// Returns a lean version of AccountsDB that can be initialized in under
    /// 1 ms during tests and you can put + get accounts in it.
    ///
    /// May be lacking some functionality for more advanced test cases like
    /// loading a snapshot.
    ///
    /// Returns a tmpdir that you should cleanup alongside AccountsDB
    pub fn initForTest(allocator: std.mem.Allocator) !struct { AccountsDB, std.testing.TmpDir } {
        const zone = tracy.Zone.init(@src(), .{ .name = "AccountsDB.initForTest" });
        defer zone.deinit();

        var tmp_dir = std.testing.tmpDir(.{});
        errdefer tmp_dir.cleanup();
        return .{
            try .init(.{
                .allocator = allocator,
                .logger = .FOR_TESTS,
                .snapshot_dir = tmp_dir.dir,
                .index_allocation = .ram,
                .number_of_index_shards = 1,
                .geyser_writer = null,
                .gossip_view = null,
                .buffer_pool_frames = 2,
            }),
            tmp_dir,
        };
    }

    pub fn deinit(self: *AccountsDB) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb deinit" });
        defer zone.deinit();

        self.account_index.deinit();
        self.buffer_pool.deinit(self.allocator);

        {
            const unrooted_accounts, var unrooted_accounts_lg =
                self.unrooted_accounts.writeWithLock();
            defer unrooted_accounts_lg.unlock();
            var iter = unrooted_accounts.valueIterator();
            while (iter.next()) |pubkeys_and_accounts| {
                for (pubkeys_and_accounts.items(.account)) |account| account.deinit(self.allocator);
                pubkeys_and_accounts.deinit(self.allocator);
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

    pub fn accountReader(self: *AccountsDB) sig.accounts_db.AccountReader {
        return .{ .accounts_db = self };
    }

    pub fn accountStore(self: *AccountsDB) sig.accounts_db.AccountStore {
        return .{ .accounts_db = self };
    }

    pub fn getAllPubkeysSorted(self: *AccountsDB, allocator: std.mem.Allocator) ![]const Pubkey {
        var pubkeys = std.ArrayListUnmanaged(Pubkey){};
        errdefer pubkeys.deinit(allocator);

        for (self.account_index.pubkey_ref_map.shards) |*shard| {
            const shard_map, var shard_lg = shard.readWithLock();
            defer shard_lg.unlock();
            var shard_map_iter = shard_map.iterator();
            while (shard_map_iter.next()) |entry| {
                // NOTE: we use the pubkey from the entry key, not the value
                // because the value is a reference head, which is not a pubkey.
                try pubkeys.append(allocator, entry.key_ptr.*);
            }
        }

        std.sort.heap(Pubkey, pubkeys.items, {}, struct {
            pub fn sortCmp(_: void, lhs: Pubkey, rhs: Pubkey) bool {
                return std.mem.order(u8, &lhs.data, &rhs.data) != .gt;
            }
        }.sortCmp);

        return pubkeys.toOwnedSlice(allocator);
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
    ) !SnapshotManifest {
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb loadWithDefaults" });
        defer zone.deinit();

        const collapsed_manifest = try full_inc_manifest.collapse(self.allocator);
        errdefer collapsed_manifest.deinit(self.allocator);

        {
            var load_timer = sig.time.Timer.start();
            try self.loadFromSnapshot(
                collapsed_manifest.accounts_db_fields,
                n_threads,
                allocator,
                accounts_per_file_estimate,
            );
            self.logger.info().logf("loadFromSnapshot: total time: {s}", .{load_timer.read()});
        }

        if (validate) {
            const full_man = full_inc_manifest.full;
            const maybe_inc_persistence = if (full_inc_manifest.incremental) |inc|
                inc.bank_extra.snapshot_persistence
            else
                null;

            var validate_timer = sig.time.Timer.start();
            try self.validateLoadFromSnapshot(.{
                .full_slot = full_man.bank_fields.slot,
                .expected_full = .{
                    .accounts_hash = full_man.bank_extra.accounts_lt_hash,
                },
                .expected_incremental = if (maybe_inc_persistence) |_| .{
                    .accounts_hash = full_inc_manifest.incremental.?.bank_extra.accounts_lt_hash,
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
            var load_timer = sig.time.Timer.start();
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

            var validate_timer = sig.time.Timer.start();
            try self.validateLoadFromSnapshot(.{
                .full_slot = full_man.bank_fields.slot,
                .expected_full = .{
                    .accounts_hash = full_man.bank_extra.accounts_lt_hash,
                },
                .expected_incremental = if (full_inc_manifest.incremental) |inc| .{
                    .accounts_hash = inc.bank_extra.accounts_lt_hash,
                } else null,
            });
            self.logger.info().logf(
                "validateLoadFromSnapshot: total time: {s}",
                .{validate_timer.read()},
            );
        }

        return collapsed_manifest;
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
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb loadFromSnapshot" });
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

        var merge_timer = sig.time.Timer.start();
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
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb initLoadingThreads" });
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
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb deinitLoadingThreads" });
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
    fn loadAndVerifyAccountsFilesMultiThread(
        loading_threads: []AccountsDB,
        accounts_dir: std.fs.Dir,
        file_info_map: AccountsDbFields.FileMap,
        accounts_per_file_estimate: u64,
        task: sig.utils.thread.TaskParams,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{
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
    fn loadAndVerifyAccountsFiles(
        self: *AccountsDB,
        accounts_dir: std.fs.Dir,
        accounts_per_file_est: usize,
        file_info_map: AccountsDbFields.FileMap,
        file_map_start_index: usize,
        file_map_end_index: usize,
        // when we multithread this function we only want to print on the first thread
        print_progress: bool,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb loadAndVerifyAccountsFiles" });
        defer zone.deinit();

        // NOTE: we can hold this lock for the entire function
        // because nothing else should be access the filemap
        // while loading from a snapshot
        const file_map, var file_map_lg = self.file_map.writeWithLock();
        defer file_map_lg.unlock();

        const n_account_files = file_map_end_index - file_map_start_index;
        try file_map.ensureTotalCapacity(self.allocator, n_account_files);

        // allocate all the references in one shot with a wrapper allocator
        // without this large allocation, snapshot loading is very slow
        const n_accounts_estimate = n_account_files * accounts_per_file_est;
        const reference_manager = self.account_index.reference_manager;

        var reference_bufs = try ArrayList([]AccountRef).initCapacity(
            self.allocator,
            n_account_files,
        );
        defer reference_bufs.deinit();

        try reference_manager.expandCapacity(n_accounts_estimate);

        var timer = sig.time.Timer.start();
        var progress_timer = sig.time.Timer.start();

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

        const shard_counts = try self.allocator.alloc(
            usize,
            self.account_index.pubkey_ref_map.numberOfShards(),
        );
        defer self.allocator.free(shard_counts);
        @memset(shard_counts, 0);

        self.logger.info().log("reading accounts files");

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

            const n_accounts_this_slot = blk: {
                var n_accounts: usize = 0;

                var iter = accounts_file.iterator(&self.buffer_pool);
                while (try iter.nextNoData()) |account| {
                    n_accounts += 1;
                    const shred_calculator = self.account_index.pubkey_ref_map.shard_calculator;
                    shard_counts[shred_calculator.index(&account.store_info.pubkey)] += 1;
                }
                break :blk n_accounts;
            };

            if (n_accounts_this_slot == 0) continue;

            const references_buf = reference_manager.alloc(
                n_accounts_this_slot,
            ) catch |err| switch (err) {
                error.AllocFailed, error.AllocTooBig => blk: {
                    self.logger.warn().log(
                        "ref manager AllocFailed: n_accounts_estimate too low? Expanding by 50%",
                    );
                    try reference_manager.expandCapacity(
                        @max(n_accounts_estimate / 2, n_accounts_this_slot),
                    );
                    break :blk try reference_manager.alloc(n_accounts_this_slot);
                },
                else => return err,
            };

            try reference_bufs.append(references_buf);

            // index the account file
            var slot_references: AccountIndex.SlotRefMapValue = .{
                .refs = .initBuffer(references_buf),
            };

            indexAndValidateAccountFile(
                self.allocator,
                &self.buffer_pool,
                &accounts_file,
                self.account_index.pubkey_ref_map.shard_calculator,
                null, // shard counts calculated earlier
                &slot_references.refs,
                // ! we collect the accounts and pubkeys into geyser storage here
                geyser_slot_storage,
            ) catch |err| {
                if (err == ValidateAccountFileError.OutOfReferenceMemory) {
                    // NOTE: is this even possible now?
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

            std.debug.assert(accounts_file.number_of_accounts <= n_accounts_this_slot);

            const file_id = file_info.id;
            file_map.putAssumeCapacityNoClobber(file_id, accounts_file);
            accounts_file_moved_to_filemap = true;

            // track slice of references per slot
            n_accounts_total += n_accounts_this_slot;
            slot_reference_map.putAssumeCapacityNoClobber(
                slot,
                slot_references,
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

            self.largest_file_id = .max(self.largest_file_id, file_id);
            {
                const max_slots, var max_slots_lg = self.max_slots.writeWithLock();
                defer max_slots_lg.unlock();
                max_slots.rooted = @max(max_slots.rooted orelse 0, slot);
                max_slots.flushed = max_slots.rooted;
            }

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
                n_accounts_total / n_account_files,
                accounts_per_file_est,
            });
        }

        {
            const pubkey_ref_map_zone = tracy.Zone.init(@src(), .{
                .name = "accountsdb loadAndVerifyAccountsFiles pubkey_ref_map.ensureTotalCapacity",
            });
            defer pubkey_ref_map_zone.deinit();

            // allocate enough memory
            try self.account_index.pubkey_ref_map.ensureTotalCapacity(shard_counts);
        }

        // PERF: can probs be faster if you sort the pubkeys first, and then you know
        // it will always be a search for a free spot, and not search for a match

        {
            const index_build_zone = tracy.Zone.init(@src(), .{
                .name = "accountsdb loadAndVerifyAccountsFiles building index",
            });
            defer index_build_zone.deinit();

            timer.reset();

            for (reference_bufs.items, 0..) |reference_buf, ref_buf_i| {
                for (reference_buf) |*ref| {
                    _ = try self.account_index.indexRefIfNotDuplicateSlot(ref);

                    if (print_progress and
                        progress_timer.read().asNanos() > DB_LOG_RATE.asNanos())
                    {
                        printTimeEstimate(
                            self.logger,
                            &timer,
                            reference_bufs.items.len,
                            ref_buf_i,
                            "building index",
                            "thread0",
                        );
                        progress_timer.reset();
                    }
                }
            }
        }
    }

    /// merges multiple thread accounts-dbs into self.
    /// index merging happens in parallel using `n_threads`.
    fn mergeMultipleDBs(
        self: *AccountsDB,
        thread_dbs: []AccountsDB,
        n_threads: usize,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb mergeMultipleDBs" });
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
            self.largest_file_id = .max(self.largest_file_id, thread_db.largest_file_id);
            {
                const max_slots, var max_slots_lg = self.max_slots.writeWithLock();
                defer max_slots_lg.unlock();
                if (thread_db.getLargestRootedSlot()) |thread_db_rooted| {
                    max_slots.rooted = @max(max_slots.rooted orelse 0, thread_db_rooted);
                }
                max_slots.flushed = max_slots.rooted;
            }

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
    fn mergeThreadIndexesMultiThread(
        logger: Logger,
        index: *AccountIndex,
        thread_dbs: []const AccountsDB,
        task: sig.utils.thread.TaskParams,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{
            .name = "accountsdb mergeThreadIndexesMultiThread",
        });
        defer zone.deinit();

        const shard_start_index = task.start_index;
        const shard_end_index = task.end_index;

        const total_shards = shard_end_index - shard_start_index;
        var timer = sig.time.Timer.start();
        var progress_timer = sig.time.Timer.start();
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
                    index.indexRefAssumeCapacity(thread_head_ref.ref_ptr);
                }
            }

            if (print_progress and progress_timer.read().gt(DB_LOG_RATE)) {
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
        /// compute hash from `(null, max_slot]`
        FullAccountHash: struct {
            max_slot: Slot,
        },
        /// compute hash from `(min_slot, max_slot?]`
        IncrementalAccountHash: struct {
            min_slot: Slot,
            max_slot: ?Slot = null,
        },

        fn minSlot(self: AccountHashesConfig) ?Slot {
            return switch (self) {
                .FullAccountHash => null,
                .IncrementalAccountHash => |iac| iac.min_slot,
            };
        }

        fn maxSlot(self: AccountHashesConfig) ?Slot {
            return switch (self) {
                .FullAccountHash => |fah| fah.max_slot,
                .IncrementalAccountHash => |iac| iac.max_slot,
            };
        }
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
    fn computeAccountHashesAndLamports(
        self: *AccountsDB,
        config: AccountHashesConfig,
    ) !struct { LtHash, u64 } {
        const zone = tracy.Zone.init(@src(), .{
            .name = "accountsdb computeAccountHashesAndLamports",
        });
        defer zone.deinit();

        var timer = sig.time.Timer.start();

        // going higher will only lead to more contention in the buffer pool reads
        const n_threads = @min(6, @as(u32, @truncate(try std.Thread.getCpuCount())));

        // split processing the bins over muliple threads
        self.logger.info().logf(
            "[{} threads] collecting hashes from accounts",
            .{n_threads},
        );

        const task_results: []HashedShard = try self.allocator.alloc(
            HashedShard,
            self.account_index.pubkey_ref_map.numberOfShards(),
        );
        defer self.allocator.free(task_results);

        try spawnThreadTasks(
            self.allocator,
            getHashesFromIndexMultiThread,
            .{
                .data_len = self.account_index.pubkey_ref_map.numberOfShards(),
                .max_threads = n_threads,
                .params = .{
                    self,
                    self.allocator,
                    config,
                    task_results,
                },
            },
        );

        const total_lamports, const accounts_hash = blk: {
            var lamports_sum: u64 = 0;
            var hash: LtHash = .IDENTITY;
            for (task_results) |result| {
                lamports_sum += result.lamports;
                hash.mixIn(result.hash);
            }
            // do subtraction after, to avoid potential overflows when
            // .subtract > .lamports for a shard.
            for (task_results) |result| {
                lamports_sum -|= result.subtract;
            }
            break :blk .{ lamports_sum, hash };
        };

        self.logger.debug().logf("collecting hashes from accounts took: {s}", .{timer.read()});
        timer.reset();

        return .{
            accounts_hash,
            total_lamports,
        };
    }

    /// Returns an iterator that iterates over every account that was modified
    /// in the slot.
    ///
    /// Holds the read lock on the index, so unlock it when done, and be careful
    /// how long you hold this.
    pub fn slotModifiedIterator(self: *AccountsDB, slot: Slot) ?SlotModifiedIterator {
        var slot_ref_map = self.account_index.slot_reference_map.read();

        const slot_references = slot_ref_map.get().getPtr(slot) orelse {
            slot_ref_map.unlock();
            return null;
        };

        return .{
            .db = self,
            .lock = slot_ref_map,
            .slot_index = slot_references,
            .cursor = 0,
        };
    }

    pub const SlotModifiedIterator = struct {
        db: *AccountsDB,
        lock: RwMux(AccountIndex.SlotRefMap).RLockGuard,
        slot_index: *AccountIndex.SlotRefMapValue,
        cursor: usize,

        pub fn unlock(self: *SlotModifiedIterator) void {
            self.cursor = std.math.maxInt(usize);
            self.lock.unlock();
        }

        pub fn len(self: *SlotModifiedIterator) usize {
            return self.slot_index.refs.items.len;
        }

        pub fn next(
            self: *SlotModifiedIterator,
            allocator: std.mem.Allocator,
        ) !?struct { Pubkey, Account } {
            assert(self.cursor != std.math.maxInt(usize));
            defer self.cursor += 1;
            if (self.cursor >= self.slot_index.refs.items.len) return null;
            const account_ref = self.slot_index.refs.items[self.cursor];
            const account = try self.db.getAccountFromRef(allocator, &account_ref);
            return .{ account_ref.pubkey, account };
        }
    };

    pub const ValidateLoadFromSnapshotParams = struct {
        /// used to verify the full snapshot.
        full_slot: Slot,
        /// The expected full snapshot values to verify against.
        expected_full: ExpectedSnapInfo,
        /// The optionally expected incremental snapshot values to verify against.
        expected_incremental: ?ExpectedSnapInfo,

        pub const ExpectedSnapInfo = struct {
            accounts_hash: LtHash,
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
    fn validateLoadFromSnapshot(
        self: *AccountsDB,
        params: ValidateLoadFromSnapshotParams,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb validateLoadFromSnapshot" });
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

        if (!params.expected_full.accounts_hash.eql(accounts_hash)) {
            self.logger.err().logf(
                "incorrect accounts hash: expected vs calculated: {d} vs {d}",
                .{ params.expected_full.accounts_hash, accounts_hash },
            );
            return error.IncorrectAccountsHash;
        }

        if (maybe_latest_snapshot_info.*) |latest_snapshot_info| {
            // ASSERTION: nothing has changed if we previously successfully
            // verified a load from the snapshot; ie, calling this function
            // after calling it once should not produce any mutations.
            // The assertion may also trip if any mutations to accountsdb
            // have occurred since the first call to this function.
            std.debug.assert(latest_snapshot_info.full.slot == params.full_slot);
            std.debug.assert(latest_snapshot_info.full.hash.eql(accounts_hash));
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

            const inc_slot = self.getLargestRootedSlot() orelse 0;

            var accounts_delta_hash = accounts_hash;

            const incr_hash, //
            const incremental_lamports //
            = try self.computeAccountHashesAndLamports(.{
                .IncrementalAccountHash = .{
                    .min_slot = params.full_slot,
                    .max_slot = inc_slot,
                },
            });
            _ = incremental_lamports;
            accounts_delta_hash.mixIn(incr_hash);

            if (!expected_incremental.accounts_hash.eql(accounts_delta_hash)) {
                self.logger.err().logf(
                    "incorrect accounts delta hash: expected vs calculated: {} vs {}",
                    .{
                        expected_incremental.accounts_hash.checksum(),
                        accounts_delta_hash.checksum(),
                    },
                );
                return error.IncorrectAccountsDeltaHash;
            }

            // ASSERTION: same idea as the previous assertion, but applied to
            // the incremental snapshot info.
            if (p_maybe_first_inc.*) |first_inc| {
                std.debug.assert(first_inc.slot == inc_slot);
                std.debug.assert(first_inc.hash.eql(accounts_delta_hash));
            }

            p_maybe_first_inc.* = .{
                .slot = inc_slot,
                .hash = accounts_delta_hash,
            };
        }

        maybe_latest_snapshot_info.* = maybe_first_snapshot_info.*;
    }

    const HashedShard = struct {
        lamports: u64,
        subtract: u64,

        hash: LtHash,
    };

    /// multithread entrypoint for getHashesFromIndex
    pub fn getHashesFromIndexMultiThread(
        self: *AccountsDB,
        tmp_allocator: std.mem.Allocator,
        config: AccountsDB.AccountHashesConfig,
        results: []HashedShard,
        task: sig.utils.thread.TaskParams,
    ) !void {
        return try getHashesFromIndex(
            self,
            tmp_allocator,
            config,
            self.account_index.pubkey_ref_map.shards[task.start_index..task.end_index],
            results[task.start_index..task.end_index],
            task.thread_id == 0,
        );
    }

    /// populates the account hashes and total lamports across a given shard slice
    fn getHashesFromIndex(
        self: *AccountsDB,
        tmp_allocator: std.mem.Allocator,
        config: AccountsDB.AccountHashesConfig,
        shards: []ShardedPubkeyRefMap.RwPubkeyRefMap,
        results: []HashedShard,
        print_progress: bool,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb getHashesFromIndex" });
        defer zone.deinit();

        var timer = sig.time.Timer.start();
        var progress_timer = sig.time.Timer.start();

        var arena = std.heap.ArenaAllocator.init(tmp_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        for (shards, results, 0..) |*shard_rw, *result, i| {
            // get and sort pubkeys inshardn
            // PERF: may be holding this lock for too long
            const shard, var shard_lg = shard_rw.readWithLock();
            defer shard_lg.unlock();

            var total_lamports: u64 = 0;
            var lt_hash: LtHash = .IDENTITY;

            var total_subtracted: u64 = 0;

            var iter = shard.iterator();
            while (iter.next()) |key| {
                defer std.debug.assert(arena.reset(.retain_capacity));

                const ref_head = key.value_ptr;

                // "mix in" latest version of account into hash
                {
                    const max_slot_ref = slotListMaxWithinBounds(
                        ref_head.ref_ptr,
                        config.minSlot(),
                        config.maxSlot(),
                    ) orelse continue;
                    const latest_account = try self.getAccountFromRef(allocator, max_slot_ref);
                    defer latest_account.deinit(allocator);
                    lt_hash.mixIn(latest_account.ltHash(max_slot_ref.pubkey));
                    total_lamports += latest_account.lamports;
                }

                // "mix out" previous latest version of account from hash (if applicable)
                if (config.minSlot()) |min_slot| {
                    // we are calculating the incremental hash
                    std.debug.assert(config == .IncrementalAccountHash);

                    // We've just mixed in the latest entry within our range, i.e. the latest
                    // account modification in our incremental snapshot. We should mix out the
                    // latest account found *before* our incremental snapshot (i.e. in the full
                    // snapshot), so that we can combine our result with the previously calculated
                    // full snapshot hash in order to produce the new full accounts hash.

                    const previous_slot_ref = slotListMaxWithinBounds(
                        ref_head.ref_ptr,
                        null,
                        min_slot,
                    ) orelse continue;

                    const prev_latest = try self.getAccountFromRef(allocator, previous_slot_ref);
                    defer prev_latest.deinit(allocator);

                    lt_hash.mixOut(prev_latest.ltHash(previous_slot_ref.pubkey));
                    total_subtracted += prev_latest.lamports;
                }
            }

            result.* = .{
                .hash = lt_hash,
                .lamports = total_lamports,
                .subtract = total_subtracted,
            };

            if (print_progress and progress_timer.read().gt(DB_LOG_RATE)) {
                printTimeEstimate(
                    self.logger,
                    &timer,
                    shards.len,
                    i + 1,
                    "gathering account hashes",
                    "thread0",
                );
                progress_timer.reset();
            }
        }
    }

    /// creates a unique accounts file associated with a slot. uses the
    /// largest_file_id field to ensure its a unique file
    pub fn createAccountFile(self: *AccountsDB, size: usize, slot: Slot) !struct {
        std.fs.File,
        FileId,
    } {
        const zone = tracy.Zone.init(@src(), .{ .name = "createAccountFile" });
        defer zone.deinit();

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
    fn getAccountFromRef(
        self: *AccountsDB,
        allocator: std.mem.Allocator,
        account_ref: *const AccountRef,
    ) GetFileFromRefError!Account {
        switch (account_ref.location) {
            .file => |ref_info| {
                const account = try self.getAccountInFile(
                    allocator,
                    ref_info.file_id,
                    ref_info.offset,
                );
                errdefer account.deinit(allocator);

                return account;
            },
            .unrooted_map => |ref_info| {
                const unrooted_accounts, var unrooted_accounts_lg =
                    self.unrooted_accounts.readWithLock();
                defer unrooted_accounts_lg.unlock();

                const slots_and_accounts = unrooted_accounts.get(account_ref.slot) orelse
                    return error.SlotNotFound;
                const accounts: []Account = slots_and_accounts.items(.account);
                const account = accounts[ref_info.index];

                return try account.cloneOwned(allocator);
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
    fn getAccountFromRefWithReadLock(
        self: *AccountsDB,
        account_ref: *const AccountRef,
    ) GetAccountFromRefError!struct { AccountInCacheOrFile, AccountInCacheOrFileLock } {
        switch (account_ref.location) {
            .file => |ref_info| {
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
            .unrooted_map => |ref_info| {
                const unrooted_accounts, var unrooted_accounts_lg =
                    self.unrooted_accounts.readWithLock();
                errdefer unrooted_accounts_lg.unlock();

                const accounts = (unrooted_accounts.get(account_ref.slot) orelse
                    return error.SlotNotFound).items(.account);
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
    fn getAccountInFile(
        self: *AccountsDB,
        allocator: std.mem.Allocator,
        file_id: FileId,
        offset: usize,
    ) (GetAccountInFileError || std.mem.Allocator.Error)!Account {
        const account_in_file = try self.getAccountInFileAndLock(
            allocator,
            &self.buffer_pool,
            file_id,
            offset,
        );
        defer account_in_file.deinit(allocator);
        defer self.file_map_fd_rw.unlockShared();
        return try account_in_file.dupeCachedAccount(allocator);
    }

    /// Gets an account given an file_id and offset value.
    /// Locks the account file entries, and returns the account.
    /// Must call `self.file_map_fd_rw.unlockShared()`
    /// when done with the account.
    fn getAccountInFileAndLock(
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
    fn getAccountInFileAssumeLock(
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
            .file => |ref_info| {
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
            .unrooted_map => @panic(
                "getAccountHashAndLamportsFromRef is not implemented on unrooted_map references",
            ),
        }
    }

    /// gets the latest version of an account at the provided address.
    ///
    /// This function is not fork aware. It only gets the account from the
    /// highest numeric slot when the account was updated. Typically, this is
    /// the wrong function to use, and you should use the fork-aware function
    /// getAccountWithAncestors, unless you really know what you're doing.
    ///
    /// mut ref is required for locks.
    pub fn getAccountLatest(
        self: *AccountsDB,
        allocator: std.mem.Allocator,
        pubkey: *const Pubkey,
    ) GetAccountError!?Account {
        const head_ref, var lock = self.account_index.pubkey_ref_map.getRead(pubkey) orelse
            return null;
        defer lock.unlock();

        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, null, null).?;
        const account = try self.getAccountFromRef(allocator, max_ref);

        return account;
    }

    pub const GetAccountError = GetFileFromRefError || error{PubkeyNotInIndex};

    pub fn getSlotAndAccount(
        self: *AccountsDB,
        allocator: std.mem.Allocator,
        pubkey: *const Pubkey,
    ) GetAccountError!struct { Slot, Account } {
        const head_ref, var lock = self.account_index.pubkey_ref_map.getRead(pubkey) orelse
            return error.PubkeyNotInIndex;
        defer lock.unlock();

        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(head_ref.ref_ptr, null, null).?;
        const account = try self.getAccountFromRef(allocator, max_ref);

        return .{ max_ref.slot, account };
    }

    /// gets an account given an associated pubkey. mut ref is required for locks.
    /// Will only find rooted accounts, or unrooted accounts from a slot in ancestors.
    pub fn getAccountWithAncestors(
        self: *AccountsDB,
        allocator: std.mem.Allocator,
        pubkey: *const Pubkey,
        ancestors: *const sig.core.Ancestors,
    ) GetFileFromRefError!?Account {
        // NOTE: take note of the ordering here between the two locks(!) reversal could cause a deadlock.
        _, var ref_map_lg = self.account_index.slot_reference_map.readWithLock();
        defer ref_map_lg.unlock();

        const head_ref, var lock = self.account_index.pubkey_ref_map.getRead(pubkey) orelse
            return null;
        defer lock.unlock();

        const max_ref = greatestInAncestors(
            head_ref.ref_ptr,
            ancestors,
            self.getLargestRootedSlot(),
        ) orelse return null;

        return try self.getAccountFromRef(allocator, max_ref);
    }

    pub const GetAccountWithReadLockError = GetAccountFromRefError || error{PubkeyNotInIndex};

    fn getAccountWithReadLock(
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

    fn getTypeFromAccount(
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
    fn putAccountFile(
        self: *AccountsDB,
        account_file: *AccountFile,
        n_accounts: usize,
    ) !void {
        const shard_counts =
            try self.allocator.alloc(usize, self.account_index.pubkey_ref_map.numberOfShards());
        defer self.allocator.free(shard_counts);
        @memset(shard_counts, 0);

        const reference_buf = try self.account_index.reference_manager.allocOrExpand(n_accounts);
        var references: std.ArrayListUnmanaged(AccountRef) = .initBuffer(reference_buf);

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
            try slot_ref_map.putNoClobber(account_file.slot, .{ .refs = references });
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
            var account_iter = account_file.iterator(&self.buffer_pool);
            while (try account_iter.next(frame_allocator)) |account_in_file| {
                defer {
                    account_in_file.deinit(frame_allocator);
                    fba.reset();
                }

                const info = account_in_file.account_info;
                const bhs, var bhs_lg = try self.getOrInitBankHashStats(account_file.slot);
                defer bhs_lg.unlock();
                bhs.update(.{
                    .lamports = info.lamports,
                    .data_len = account_in_file.data.len(),
                    .executable = info.executable,
                });
            }
        }

        // allocate enough memory here
        try self.account_index.pubkey_ref_map.ensureTotalAdditionalCapacity(shard_counts);

        // compute how many account_references for each pubkey
        var accounts_dead_count: u64 = 0;
        for (references.items) |*ref| {
            const was_inserted = try self.account_index.indexRefIfNotDuplicateSlot(ref);
            if (!was_inserted) {
                accounts_dead_count += 1;
                self.logger.warn().logf(
                    "account was not referenced because its slot was a duplicate: {any}",
                    .{.{ .slot = ref.slot, .pubkey = ref.pubkey }},
                );
            }
        }

        if (accounts_dead_count != 0) {
            const dead_accounts, var dead_accounts_lg = self.dead_accounts_counter.writeWithLock();
            defer dead_accounts_lg.unlock();
            try dead_accounts.putNoClobber(account_file.slot, accounts_dead_count);
        }
    }

    pub const PutAccountError = error{
        CannotWriteRootedSlot,
        GeyserWriteError,
        CorruptAccountIndex,
        InsertIndexFailed,
    } || std.mem.Allocator.Error;

    /// writes one account to storage
    /// intended for use from runtime
    pub fn putAccount(
        self: *AccountsDB,
        slot: Slot,
        pubkey: Pubkey,
        account: AccountSharedData,
    ) PutAccountError!void {
        if (self.getLargestRootedSlot()) |largest_rooted_slot| {
            if (slot <= largest_rooted_slot) {
                return error.CannotWriteRootedSlot;
            }
        }

        const duplicated: Account = .{
            .data = .{ .owned_allocation = try self.allocator.dupe(u8, account.data) },
            .executable = account.executable,
            .lamports = account.lamports,
            .owner = account.owner,
            .rent_epoch = account.rent_epoch,
        };
        var inserted_duplicate: bool = false;
        defer if (!inserted_duplicate) duplicated.deinit(self.allocator);

        if (self.geyser_writer) |geyser_writer| {
            geyser_writer.writePayloadToPipe(.{
                .AccountPayloadV1 = .{
                    .accounts = &.{duplicated},
                    .pubkeys = &.{pubkey},
                    .slot = slot,
                },
            }) catch |e| {
                self.logger.err().logf("{s}", .{@errorName(e)});
                return error.GeyserWriteError;
            };
        }

        {
            const bhs, var bhs_lg = try self.getOrInitBankHashStats(slot);
            defer bhs_lg.unlock();
            bhs.update(.{
                .lamports = account.lamports,
                .data_len = account.data.len,
                .executable = account.executable,
            });
        }

        // NOTE: take note of the ordering here between the two locks(!) reversal could cause a deadlock.
        const slot_ref_map, var slot_ref_map_lg =
            self.account_index.slot_reference_map.writeWithLock();
        defer slot_ref_map_lg.unlock();

        // look for existing account at this slot and overwrite in-place if present.
        search_and_overwrite: {
            const head_ref, var head_ref_lg =
                self.account_index.pubkey_ref_map.getWrite(&pubkey) orelse
                break :search_and_overwrite;
            defer head_ref_lg.unlock();

            const min_slot = if (slot == 0) null else slot - 1;
            const ref = slotListMaxWithinBounds(head_ref.ref_ptr, min_slot, slot) orelse
                break :search_and_overwrite;

            const index = switch (ref.location) {
                .unrooted_map => |location| location.index,
                .file => return error.CannotWriteRootedSlot,
            };

            const unrooted_accounts, var unrooted_accounts_lg =
                self.unrooted_accounts.writeWithLock();
            defer unrooted_accounts_lg.unlock();

            const slot_list = unrooted_accounts.get(ref.slot) orelse {
                // the index is telling us it contains a reference to an unrooted slot which doesn't exist.
                return error.CorruptAccountIndex;
            };
            const slot_accounts: []Account = slot_list.items(.account);

            const old_account = slot_accounts[index];
            slot_accounts[index] = duplicated;
            inserted_duplicate = true;
            old_account.deinit(self.allocator);

            // no need to insert/reindex if we were able to overwrite an existing account
            return;
        }

        {
            const unrooted_accounts, var unrooted_accounts_lg =
                self.unrooted_accounts.writeWithLock();
            defer unrooted_accounts_lg.unlock();

            const entry = try unrooted_accounts.getOrPut(slot);
            if (!entry.found_existing) entry.value_ptr.* = .empty;
            errdefer if (!entry.found_existing) {
                entry.value_ptr.deinit(self.allocator);
                unrooted_accounts.removeByPtr(entry.key_ptr);
            };
            try entry.value_ptr.append(
                self.allocator,
                .{ .account = duplicated, .pubkey = pubkey },
            );
            inserted_duplicate = true;
        }

        // update index
        self.expandSlotRefsAndInsertWithSlotMapLocked(
            slot,
            &.{pubkey},
            slot_ref_map,
        ) catch |err| switch (err) {
            error.OutOfMemory,
            error.AllocTooBig,
            error.AllocFailed,
            error.CollapseFailed,
            => |e| {
                self.logger.err().logf("expandSlotRefsAndInsert: {s}", .{@errorName(e)});
                return error.OutOfMemory;
            },
            error.InsertIndexFailed,
            => |e| return e,
        };
    }

    fn expandSlotRefsAndInsert(
        self: *AccountsDB,
        slot: Slot,
        pubkeys: []const Pubkey,
    ) !void {
        // NOTE: take note of the ordering here between the two locks(!) reversal could cause a deadlock.
        const slot_ref_map, var lock = self.account_index.slot_reference_map.writeWithLock();
        defer lock.unlock();
        try self.expandSlotRefsAndInsertWithSlotMapLocked(slot, pubkeys, slot_ref_map);
    }

    fn expandSlotRefsAndInsertWithSlotMapLocked(
        self: *AccountsDB,
        slot: Slot,
        pubkeys: []const Pubkey,
        slot_ref_map: *AccountIndex.SlotRefMap,
    ) !void {
        std.debug.assert(pubkeys.len > 0);
        const reference_manager = self.account_index.reference_manager;

        const slot_gop = try slot_ref_map.getOrPut(slot);
        const slot_ref_val = slot_gop.value_ptr;
        if (!slot_gop.found_existing) {
            slot_ref_val.* = .{ .refs = .empty };
        }
        // if we tried to create a new entry and failed, remove it before unlocking
        errdefer if (!slot_gop.found_existing) {
            slot_ref_map.removeByPtr(slot_gop.key_ptr);
        };

        // no entry => realloc always needed
        const realloc_needed =
            !slot_gop.found_existing or
            slot_ref_val.refs.unusedCapacitySlice().len < pubkeys.len;

        const old_refs = if (!slot_gop.found_existing) &.{} else slot_ref_val.refs.items;
        const new_len = old_refs.len + pubkeys.len;

        if (realloc_needed) {
            // not enough space, need to realloc

            // round up the size a little, so we don't realloc every time
            const new_capacity = std.math.ceilPowerOfTwo(usize, new_len) catch new_len;

            const new_ref_buf = try reference_manager.allocOrExpand(new_capacity);
            @memset(new_ref_buf, .ZEROES);
            for (new_ref_buf[0..new_len], 0..) |*new_ref, i| {
                if (i < old_refs.len) {
                    new_ref.* = old_refs[i];

                    // go back to prev & rewrite its next to make it valid again (we're moving these accountrefs)
                    if (new_ref.prev_ptr) |prev| {
                        prev.next_ptr = new_ref;
                    }

                    if (new_ref.next_ptr) |next| {
                        next.prev_ptr = new_ref;
                    }
                } else {
                    // new ref
                    new_ref.* = .{
                        .pubkey = pubkeys[i - old_refs.len],
                        .slot = slot,
                        .location = .{ .unrooted_map = .{ .index = i } },
                        .next_ptr = null,
                        .prev_ptr = null,
                    };
                }
            }

            // fix up any copied references' heads
            for (new_ref_buf[0..old_refs.len]) |*new_ref| {
                const shard_map: *ShardedPubkeyRefMap.PubkeyRefMap, var shard_map_lg =
                    self.account_index.pubkey_ref_map.getShard(&new_ref.pubkey).writeWithLock();
                defer shard_map_lg.unlock();

                // if we just moved an accountref which is the head, fix up the head
                const head = shard_map.getPtr(new_ref.pubkey) orelse continue;
                if (head.ref_ptr.slot == new_ref.slot and
                    head.ref_ptr.pubkey.equals(&new_ref.pubkey))
                {
                    head.ref_ptr = new_ref;
                }
            }

            // insert + check if inserted
            for (new_ref_buf[old_refs.len..new_len], pubkeys) |*new_ref, pubkey| {
                const was_inserted = try self.account_index.indexRefIfNotDuplicateSlot(new_ref);
                if (!was_inserted) {
                    self.logger.warn().logf(
                        "account was not referenced because its slot was a duplicate: {any}",
                        .{.{ .slot = new_ref.slot, .pubkey = new_ref.pubkey }},
                    );
                    // TODO: Make this error actually impossible to reach.
                    // Hitting this error means the account was added to
                    // accountsdb but not indexed, which is a big problem and
                    // will likely break consensus immediately. Ideally this
                    // would be unreachable, but technically a race is possible
                    // if multiple threads call putAccount for the same pubkey
                    // in the same slot. Replay won't do this, but we still want
                    // accountsdb to be safe without relying on that assumption.
                    // This may require significant changes to how accountsdb's
                    // internal data structures are locked.
                    return error.InsertIndexFailed;
                }

                std.debug.assert(self.account_index.exists(&pubkey, slot));
            }

            // replace + free old ref
            const old_ref_buf = slot_ref_val.refs.items;
            slot_ref_val.* = .{
                .refs = .{
                    .capacity = new_capacity,
                    .items = new_ref_buf[0..new_len],
                },
            };
            if (slot_gop.found_existing) {
                reference_manager.free(old_ref_buf.ptr);
                @memset(old_ref_buf, undefined);
            }
        } else {
            // no realloc necessary
            std.debug.assert(slot_ref_val.refs.capacity >= new_len);
            slot_ref_val.refs.items.len = new_len;
            for (0.., slot_ref_val.refs.items) |i, *ref| {
                if (i < old_refs.len) continue;
                // new ref
                ref.* = .{
                    .pubkey = pubkeys[i - old_refs.len],
                    .slot = slot,
                    .location = .{ .unrooted_map = .{ .index = i } },
                    .next_ptr = null,
                    .prev_ptr = null,
                };
            }

            // insert + check if inserted
            for (
                slot_ref_val.refs.items[old_refs.len..],
                pubkeys,
            ) |*ref, pubkey| {
                const was_inserted = try self.account_index.indexRefIfNotDuplicateSlot(ref);
                if (!was_inserted) {
                    self.logger.warn().logf(
                        "account was not referenced because its slot was a duplicate: {any}",
                        .{.{ .slot = ref.slot, .pubkey = ref.pubkey }},
                    );
                    // TODO: ideally this should be unreachable. see comment
                    // above for more context about this error.
                    return error.InsertIndexFailed;
                }

                std.debug.assert(self.account_index.exists(&pubkey, slot));
            }
        }
    }

    pub fn getLargestRootedSlot(self: *AccountsDB) ?Slot {
        return self.max_slots.readCopy().rooted;
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
            defer self.allocator.free(accounts_duped);

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

            const unrooted_accounts, var unrooted_accounts_lg =
                self.unrooted_accounts.writeWithLock();
            defer unrooted_accounts_lg.unlock();

            const entry = try unrooted_accounts.getOrPut(slot);
            if (!entry.found_existing) entry.value_ptr.* = .empty;
            try entry.value_ptr.ensureUnusedCapacity(self.allocator, pubkeys.len);
            for (pubkeys, accounts_duped) |pubkey, account| {
                entry.value_ptr.appendAssumeCapacity(.{ .account = account, .pubkey = pubkey });
            }
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

        try self.expandSlotRefsAndInsert(slot, pubkeys);
    }

    /// Returns a pointer to the bank hash stats for the given slot, and a lock guard on the
    /// bank hash stats map, which should be unlocked after mutating the bank hash stats.
    fn getOrInitBankHashStats(
        self: *AccountsDB,
        slot: Slot,
    ) !struct { *BankHashStats, RwMux(BankHashStatsMap).WLockGuard } {
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb getOrInitBankHashStats" });
        defer zone.deinit();

        const bank_hash_stats, var bank_hash_stats_lg = self.bank_hash_stats.writeWithLock();
        errdefer bank_hash_stats_lg.unlock();

        const gop = try bank_hash_stats.getOrPut(self.allocator, slot);
        if (!gop.found_existing) gop.value_ptr.* = BankHashStats.zero_init;
        return .{ gop.value_ptr, bank_hash_stats_lg };
    }

    /// first searches for the highest slot in ancestors. if none are found,
    /// then searches for the highest rooted slot that has been flushed.
    ///
    /// we need to filter by flushed slots here because if you just filter by
    /// rooted, you might catch some accounts from another branch before
    /// flushing should remove items from the cache.
    fn greatestInAncestors(
        ref_ptr: *AccountRef,
        ancestors: *const sig.core.Ancestors,
        maybe_largest_flushed_slot: ?Slot,
    ) ?*AccountRef {
        var biggest: ?*AccountRef = null;

        var curr: ?*AccountRef = ref_ptr;
        while (curr) |ref| : (curr = ref.next_ptr) {
            if (ancestors.containsSlot(ref.slot)) {
                const new_biggest = if (biggest) |big| ref.slot > big.slot else true;
                if (new_biggest) biggest = ref;
            }
        }

        if (biggest == null) if (maybe_largest_flushed_slot) |largest_flushed_slot| {
            curr = ref_ptr;
            while (curr) |ref| : (curr = ref.next_ptr) {
                if (ref.slot <= largest_flushed_slot) {
                    const new_biggest = if (biggest) |big| ref.slot > big.slot else true;
                    if (new_biggest) biggest = ref;
                }
            }
        };

        return biggest;
    }

    inline fn slotListMaxWithinBounds(
        ref_ptr: *AccountRef,
        min_slot: ?Slot,
        max_slot: ?Slot,
    ) ?*AccountRef {
        var biggest: ?*AccountRef = null;
        if (slotInRange(ref_ptr.slot, min_slot, max_slot)) {
            biggest = ref_ptr;
        }

        var curr = ref_ptr;
        while (curr.next_ptr) |ref| {
            if (slotInRange(ref.slot, min_slot, max_slot) and
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
            hash: LtHash,
            /// The total lamports at the full slot.
            capitalization: u64,
        };

        pub const Incremental = struct {
            /// The incremental slot relative to the base slot (.full.slot).
            slot: Slot,
            /// The incremental accounts delta hash, including zero-lamport accounts.
            hash: LtHash,
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
        hash: LtHash,
        capitalization: u64,
    };

    // NOTE: we don't store the information needed to create snapshots currently
    // pub fn generateFullSnapshot(
    //     self: *AccountsDB,
    //     params: FullSnapshotGenParams,
    // ) !GenerateFullSnapshotResult {
    //     const zstd_compressor = try zstd.Compressor.init(.{});
    //     defer zstd_compressor.deinit();

    //     var zstd_sfba_state = std.heap.stackFallback(4096 * 4, self.allocator);
    //     const zstd_sfba = zstd_sfba_state.get();
    //     const zstd_buffer = try zstd_sfba.alloc(u8, zstd.Compressor.recommOutSize());
    //     defer zstd_sfba.free(zstd_buffer);

    //     return self.generateFullSnapshotWithCompressor(zstd_compressor, zstd_buffer, params);
    // }

    // pub fn generateFullSnapshotWithCompressor(
    //     self: *AccountsDB,
    //     zstd_compressor: zstd.Compressor,
    //     zstd_buffer: []u8,
    //     params: FullSnapshotGenParams,
    // ) !GenerateFullSnapshotResult {
    //     const zone = tracy.Zone.init(@src(), .{ .name = "generateFullSnapshotWithCompressor" });
    //     defer zone.deinit();

    //     // NOTE: we hold the lock for the rest of the duration of the procedure to ensure
    //     // flush and clean do not create files while generating a snapshot.
    //     self.file_map_fd_rw.lockShared();
    //     defer self.file_map_fd_rw.unlockShared();

    //     const file_map, var file_map_lg = self.file_map.readWithLock();
    //     defer file_map_lg.unlock();

    //     // lock this now such that, if under any circumstance this method was invoked twice in parallel
    //     // on separate threads, there wouldn't be any overlapping work being done.
    //     const maybe_latest_snapshot_info: *?SnapshotGenerationInfo, //
    //     var latest_snapshot_info_lg //
    //     = self.latest_snapshot_gen_info.writeWithLock();
    //     defer latest_snapshot_info_lg.unlock();

    //     std.debug.assert(zstd_buffer.len != 0);
    //     std.debug.assert(params.target_slot <= self.getLargestRootedSlot() orelse 0);

    //     const full_lt_hash, const full_capitalization = compute: {
    //         check_first: {
    //             const maybe_first_snapshot_info, var first_snapshot_info_lg =
    //                 self.first_snapshot_load_info.readWithLock();
    //             defer first_snapshot_info_lg.unlock();

    //             const first = maybe_first_snapshot_info.* orelse break :check_first;
    //             if (first.full.slot != params.target_slot) break :check_first;

    //             break :compute .{ first.full.hash, first.full.capitalization };
    //         }

    //         break :compute try self.computeAccountHashesAndLamports(.{
    //             .FullAccountHash = .{
    //                 .max_slot = params.target_slot,
    //             },
    //         });
    //     };

    //     const full_hash = full_lt_hash.checksum();

    //     const archive_file = blk: {
    //         const archive_info: FullSnapshotFileInfo = .{
    //             .slot = params.target_slot,
    //             .hash = full_hash,
    //         };
    //         const archive_file_name_bounded = archive_info.snapshotArchiveName();
    //         const archive_file_name = archive_file_name_bounded.constSlice();
    //         self.logger.info().logf("Generating full snapshot '{s}' (full path: {1s}/{0s}).", .{
    //             archive_file_name, sig.utils.fmt.tryRealPath(self.snapshot_dir, "."),
    //         });
    //         break :blk try self.snapshot_dir.createFile(archive_file_name, .{ .read = true });
    //     };
    //     defer archive_file.close();

    //     const SerializableFileMap = AccountsDbFields.FileMap;

    //     var serializable_file_map: SerializableFileMap = .{};
    //     defer serializable_file_map.deinit(self.allocator);
    //     var bank_hash_stats = BankHashStats.zero_init;

    //     // collect account files into serializable_file_map and compute bank_hash_stats
    //     try serializable_file_map.ensureTotalCapacity(self.allocator, file_map.count());
    //     for (file_map.values()) |account_file| {
    //         if (account_file.slot > params.target_slot) continue;

    //         const bank_hash_stats_map, var bank_hash_stats_map_lg =
    //             self.bank_hash_stats.readWithLock();
    //         defer bank_hash_stats_map_lg.unlock();

    //         if (bank_hash_stats_map.get(account_file.slot)) |other_stats| {
    //             bank_hash_stats.accumulate(other_stats);
    //         }

    //         serializable_file_map.putAssumeCapacityNoClobber(account_file.slot, .{
    //             .id = account_file.id,
    //             .length = account_file.length,
    //         });
    //     }

    //     params.bank_fields.slot = params.target_slot; // !
    //     params.bank_fields.capitalization = full_capitalization; // !

    //     const manifest: SnapshotManifest = .{
    //         .bank_fields = params.bank_fields.*,
    //         .accounts_db_fields = .{
    //             .file_map = serializable_file_map,
    //             .stored_meta_write_version = params.deprecated_stored_meta_write_version,
    //             .slot = params.target_slot,
    //             .bank_hash_info = .{
    //                 .stats = bank_hash_stats,
    //             },
    //             .rooted_slots = &.{},
    //             .rooted_slot_hashes = &.{},
    //         },
    //         .bank_extra = .{
    //             .lamports_per_signature = params.lamports_per_signature,
    //             // default to null for full snapshot,
    //             .snapshot_persistence = null,
    //             .epoch_accounts_hash = null,
    //             .versioned_epoch_stakes = .{},
    //             .accounts_lt_hash = full_lt_hash,
    //         },
    //     };

    //     // main snapshot writing logic
    //     // writer() data flow: tar -> zstd -> archive_file
    //     const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, zstd_buffer);
    //     try writeSnapshotTarWithFields(
    //         zstd_write_ctx.writer(),
    //         .CURRENT,
    //         StatusCache.EMPTY,
    //         &manifest,
    //         file_map,
    //     );
    //     try zstd_write_ctx.finish();

    //     if (self.gossip_view) |gossip_view| { // advertise new snapshot via gossip
    //         const push_msg_queue, var push_msg_queue_lg =
    //             gossip_view.push_msg_queue.writeWithLock();
    //         defer push_msg_queue_lg.unlock();

    //         try push_msg_queue.queue.append(.{
    //             .SnapshotHashes = .{
    //                 .from = gossip_view.my_pubkey,
    //                 .full = .{ .slot = params.target_slot, .hash = full_hash },
    //                 .incremental = sig.gossip.data.SnapshotHashes.IncrementalSnapshotsList.EMPTY,
    //                 .wallclock = 0, // the wallclock will be set when it's processed in the queue
    //             },
    //         });
    //     }

    //     // update tracking for new snapshot

    //     if (maybe_latest_snapshot_info.*) |old_snapshot_info| {
    //         std.debug.assert(old_snapshot_info.full.slot <= params.target_slot);

    //         switch (params.old_snapshot_action) {
    //             .ignore_old => {},
    //             .delete_old => {
    //                 const full = old_snapshot_info.full;
    //                 try self.deleteOldSnapshotFile(.full, .{
    //                     .slot = full.slot,
    //                     .hash = full.hash.checksum(),
    //                 });
    //                 if (old_snapshot_info.inc) |inc| {
    //                     try self.deleteOldSnapshotFile(.incremental, .{
    //                         .base_slot = old_snapshot_info.full.slot,
    //                         .slot = inc.slot,
    //                         .hash = inc.hash.checksum(),
    //                     });
    //                 }
    //             },
    //         }
    //     }

    //     maybe_latest_snapshot_info.* = .{
    //         .full = .{
    //             .slot = params.target_slot,
    //             .hash = full_lt_hash,
    //             .capitalization = full_capitalization,
    //         },
    //         .inc = null,
    //     };

    //     return .{
    //         .hash = full_lt_hash,
    //         .capitalization = full_capitalization,
    //     };
    // }

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

    pub const GenerateIncSnapshotResult = struct {
        full_slot: Slot,
        full_hash: LtHash,
        full_capitalization: u64,
        incremental_hash: LtHash,

        fn intoSnapshotPersistence(
            self: GenerateIncSnapshotResult,
        ) ObsoleteIncrementalSnapshotPersistence {
            return .{
                .full_slot = self.full_slot,
                .full_hash = self.full_hash.checksum(),
                .full_capitalization = self.full_capitalization,
                .incremental_hash = self.incremental_hash.checksum(),
                .incremental_capitalization = 0,
            };
        }
    };

    // pub fn generateIncrementalSnapshot(
    //     self: *AccountsDB,
    //     params: IncSnapshotGenParams,
    // ) !GenerateIncSnapshotResult {
    //     const zstd_compressor = try zstd.Compressor.init(.{});
    //     defer zstd_compressor.deinit();

    //     var zstd_sfba_state = std.heap.stackFallback(4096 * 4, self.allocator);
    //     const zstd_sfba = zstd_sfba_state.get();
    //     const zstd_buffer = try zstd_sfba.alloc(u8, zstd.Compressor.recommOutSize());
    //     defer zstd_sfba.free(zstd_buffer);

    //     return self.generateIncrementalSnapshotWithCompressor(zstd_compressor, zstd_buffer, params);
    // }

    // pub fn generateIncrementalSnapshotWithCompressor(
    //     self: *AccountsDB,
    //     zstd_compressor: zstd.Compressor,
    //     zstd_buffer: []u8,
    //     params: IncSnapshotGenParams,
    // ) !GenerateIncSnapshotResult {
    //     // NOTE: we hold the lock for the rest of the duration of the procedure to ensure
    //     // flush and clean do not create files while generating a snapshot.
    //     self.file_map_fd_rw.lockShared();
    //     defer self.file_map_fd_rw.unlockShared();

    //     const file_map, var file_map_lg = self.file_map.readWithLock();
    //     defer file_map_lg.unlock();

    //     // we need to hold a lock on the full & incremental snapshot for the duration of the function
    //     // to ensure we could never race if this method was invoked in parallel on different threads.
    //     const latest_snapshot_info: *SnapshotGenerationInfo, //
    //     var latest_snapshot_info_lg //
    //     = blk: {
    //         const maybe_latest_snapshot_info, var latest_snapshot_info_lg =
    //             self.latest_snapshot_gen_info.writeWithLock();
    //         errdefer latest_snapshot_info_lg.unlock();
    //         const latest_snapshot_info: *SnapshotGenerationInfo =
    //             &(maybe_latest_snapshot_info.* orelse return error.NoFullSnapshotExists);
    //         break :blk .{ latest_snapshot_info, latest_snapshot_info_lg };
    //     };
    //     defer latest_snapshot_info_lg.unlock();

    //     const full_snapshot_info: SnapshotGenerationInfo.Full = latest_snapshot_info.full;

    //     const incremental_hash = compute: {
    //         check_first: {
    //             const maybe_first_snapshot_info, var first_snapshot_info_lg =
    //                 self.first_snapshot_load_info.readWithLock();
    //             defer first_snapshot_info_lg.unlock();

    //             const first = maybe_first_snapshot_info.* orelse break :check_first;
    //             const first_inc = first.inc orelse break :check_first;
    //             if (first.full.slot != full_snapshot_info.slot) break :check_first;
    //             if (first_inc.slot != params.target_slot) break :check_first;

    //             break :compute first_inc.hash;
    //         }

    //         var hash = full_snapshot_info.hash;
    //         const incremental = (try self.computeAccountHashesAndLamports(.{
    //             .IncrementalAccountHash = .{
    //                 .min_slot = full_snapshot_info.slot,
    //                 .max_slot = params.target_slot,
    //             },
    //         }))[0];
    //         hash.mixIn(incremental);

    //         break :compute hash;
    //     };

    //     const archive_file = blk: {
    //         const archive_info: IncrementalSnapshotFileInfo = .{
    //             .base_slot = full_snapshot_info.slot,
    //             .slot = params.target_slot,
    //             .hash = incremental_hash.checksum(),
    //         };
    //         const archive_file_name_bounded = archive_info.snapshotArchiveName();
    //         const archive_file_name = archive_file_name_bounded.constSlice();
    //         self.logger.info().logf(
    //             "Generating incremental snapshot '{0s}' (full path: {1s}/{0s}).",
    //             .{
    //                 archive_file_name,
    //                 sig.utils.fmt.tryRealPath(self.snapshot_dir, "."),
    //             },
    //         );
    //         break :blk try self.snapshot_dir.createFile(archive_file_name, .{ .read = true });
    //     };
    //     defer archive_file.close();

    //     const SerializableFileMap = AccountsDbFields.FileMap;

    //     var serializable_file_map: SerializableFileMap, //
    //     const bank_hash_stats: BankHashStats //
    //     = blk: {
    //         var serializable_file_map: SerializableFileMap = .{};
    //         errdefer serializable_file_map.deinit(self.allocator);
    //         try serializable_file_map.ensureTotalCapacity(self.allocator, file_map.count());

    //         var bank_hash_stats = BankHashStats.zero_init;
    //         for (file_map.values()) |account_file| {
    //             if (account_file.slot <= full_snapshot_info.slot) continue;
    //             if (account_file.slot > params.target_slot) continue;

    //             const bank_hash_stats_map, var bank_hash_stats_map_lg =
    //                 self.bank_hash_stats.readWithLock();
    //             defer bank_hash_stats_map_lg.unlock();

    //             if (bank_hash_stats_map.get(account_file.slot)) |other_stats| {
    //                 bank_hash_stats.accumulate(other_stats);
    //             }

    //             serializable_file_map.putAssumeCapacityNoClobber(account_file.slot, .{
    //                 .id = account_file.id,
    //                 .length = account_file.length,
    //             });
    //         }

    //         break :blk .{ serializable_file_map, bank_hash_stats };
    //     };
    //     defer serializable_file_map.deinit(self.allocator);

    //     const snap_persistence: GenerateIncSnapshotResult = .{
    //         .full_slot = full_snapshot_info.slot,
    //         .full_hash = full_snapshot_info.hash,
    //         .full_capitalization = full_snapshot_info.capitalization,
    //         .incremental_hash = incremental_hash,
    //     };

    //     params.bank_fields.slot = params.target_slot; // !

    //     const manifest: SnapshotManifest = .{
    //         .bank_fields = params.bank_fields.*,
    //         .accounts_db_fields = .{
    //             .file_map = serializable_file_map,
    //             .stored_meta_write_version = params.deprecated_stored_meta_write_version,
    //             .slot = params.target_slot,
    //             .bank_hash_info = .{
    //                 .stats = bank_hash_stats,
    //             },
    //             .rooted_slots = &.{},
    //             .rooted_slot_hashes = &.{},
    //         },
    //         .bank_extra = .{
    //             .lamports_per_signature = params.lamports_per_signature,
    //             .snapshot_persistence = snap_persistence.intoSnapshotPersistence(),
    //             // TODO: the other fields default to empty/null, but this may not always be correct.
    //             .epoch_accounts_hash = null,
    //             .versioned_epoch_stakes = .{},
    //             .accounts_lt_hash = latest_snapshot_info.full.hash,
    //         },
    //     };

    //     // main snapshot writing logic
    //     // writer() data flow: tar -> zstd -> archive_file
    //     const zstd_write_ctx = zstd.writerCtx(archive_file.writer(), &zstd_compressor, zstd_buffer);
    //     try writeSnapshotTarWithFields(
    //         zstd_write_ctx.writer(),
    //         .CURRENT,
    //         StatusCache.EMPTY,
    //         &manifest,
    //         file_map,
    //     );
    //     try zstd_write_ctx.finish();

    //     if (self.gossip_view) |gossip_view| { // advertise new snapshot via gossip
    //         const push_msg_queue, var push_msg_queue_lg =
    //             gossip_view.push_msg_queue.writeWithLock();
    //         defer push_msg_queue_lg.unlock();

    //         const IncrementalSnapshotsList =
    //             sig.gossip.data.SnapshotHashes.IncrementalSnapshotsList;
    //         const incremental = IncrementalSnapshotsList.initSingle(.{
    //             .slot = params.target_slot,
    //             .hash = incremental_hash.checksum(),
    //         });
    //         try push_msg_queue.queue.append(.{
    //             .SnapshotHashes = .{
    //                 .from = gossip_view.my_pubkey,
    //                 .full = .{
    //                     .slot = full_snapshot_info.slot,
    //                     .hash = full_snapshot_info.hash.checksum(),
    //                 },
    //                 .incremental = incremental,
    //                 .wallclock = 0, // the wallclock will be set when it's processed in the queue
    //             },
    //         });
    //     }

    //     // update tracking for new snapshot

    //     if (latest_snapshot_info.inc) |old_inc_snapshot_info| {
    //         std.debug.assert(old_inc_snapshot_info.slot <= params.target_slot);

    //         switch (params.old_snapshot_action) {
    //             .ignore_old => {},
    //             .delete_old => try self.deleteOldSnapshotFile(.incremental, .{
    //                 .base_slot = full_snapshot_info.slot,
    //                 .slot = old_inc_snapshot_info.slot,
    //                 .hash = old_inc_snapshot_info.hash.checksum(),
    //             }),
    //         }
    //     }

    //     latest_snapshot_info.inc = .{
    //         .slot = params.target_slot,
    //         .hash = incremental_hash,
    //     };

    //     return snap_persistence;
    // }

    /// If this is being called using the `latest_snapshot_info`, it is assumed the caller
    /// has a write lock in order to do so.
    fn deleteOldSnapshotFile(
        self: *AccountsDB,
        comptime kind: enum { full, incremental },
        snapshot_name_info: switch (kind) {
            .full => sig.accounts_db.snapshot.data.FullSnapshotFileInfo,
            .incremental => sig.accounts_db.snapshot.data.IncrementalSnapshotFileInfo,
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

    /// inclusive bound
    inline fn slotSatisfiesMax(slot: Slot, max_slot: ?Slot) bool {
        if (max_slot) |max| return slot <= max;
        return true;
    }

    /// exclusive bound
    inline fn slotSatisfiesMin(slot: Slot, min_slot: ?Slot) bool {
        if (min_slot) |min| return slot > min;
        return true;
    }

    /// Checks if slot is in range (min, max]
    ///
    /// This is exclusive of the min and inclusive of the max
    inline fn slotInRange(slot: Slot, min_slot: ?Slot, max_slot: ?Slot) bool {
        return slotSatisfiesMax(slot, max_slot) and slotSatisfiesMin(slot, min_slot);
    }

    pub fn registerRPCHooks(self: *AccountsDB, rpc_hooks: *sig.rpc.Hooks) !void {
        try rpc_hooks.set(self.allocator, struct {
            accountsdb: *AccountsDB,

            pub fn getAccountInfo(
                this: @This(),
                allocator: std.mem.Allocator,
                params: sig.rpc.methods.GetAccountInfo,
            ) !sig.rpc.methods.GetAccountInfo.Response {
                const config: sig.rpc.methods.GetAccountInfo.Config = params.config orelse .{};
                const encoding = config.encoding orelse .base64;
                if (config.commitment) |commitment| {
                    std.debug.panic("TODO: handle commitment={s}", .{@tagName(commitment)});
                }

                const account: sig.accounts_db.AccountsDB.AccountInCacheOrFile, //
                const account_slot: sig.core.Slot, //
                var account_lg: sig.accounts_db.AccountsDB.AccountInCacheOrFileLock //
                = (this.accountsdb.getSlotAndAccountInSlotRangeWithReadLock(
                    &params.pubkey,
                    // if it's null, it's null, there's no floor to the query.
                    config.minContextSlot orelse null,
                    null,
                ) catch return error.AccountsDbError) orelse {
                    return error.InvalidSlotSlot;
                };
                defer account_lg.unlock();

                const Facts = struct {
                    executable: bool,
                    lamports: u64,
                    owner: sig.core.Pubkey,
                    rent_epoch: u64,
                    space: u64,
                };

                const data_handle: AccountDataHandle, //
                const facts: Facts //
                = switch (account) {
                    .file => |aif| .{ aif.data, .{
                        .executable = aif.account_info.executable,
                        .lamports = aif.account_info.lamports,
                        .owner = aif.account_info.owner,
                        .rent_epoch = aif.account_info.rent_epoch,
                        .space = aif.data.len(),
                    } },
                    .unrooted_map => |um| .{ um.data, .{
                        .executable = um.executable,
                        .lamports = um.lamports,
                        .owner = um.owner,
                        .rent_epoch = um.rent_epoch,
                        .space = um.data.len(),
                    } },
                };

                const account_data_base64 = blk: {
                    var account_data_base64: std.ArrayListUnmanaged(u8) = .{};
                    defer account_data_base64.deinit(allocator);

                    const acc_writer = account_data_base64.writer(allocator);
                    const acc_data_handle = if (config.dataSlice) |ds|
                        // TODO: handle potental integer overflow properly here
                        data_handle.slice(
                            @intCast(ds.offset),
                            @intCast(ds.offset + ds.length),
                        )
                    else
                        data_handle;

                    var b64_enc_stream =
                        sig.utils.base64.EncodingStream.init(std.base64.standard.Encoder);
                    const b64_enc_writer_ctx = b64_enc_stream.writerCtx(acc_writer);
                    const b64_enc_writer = b64_enc_writer_ctx.writer();

                    var frame_iter = acc_data_handle.iterator();
                    while (frame_iter.nextFrame()) |frame_bytes| {
                        try b64_enc_writer.writeAll(frame_bytes);
                    }
                    try b64_enc_writer_ctx.flush();
                    break :blk try account_data_base64.toOwnedSlice(allocator);
                };
                errdefer allocator.free(account_data_base64);

                return .{
                    .context = .{
                        .slot = account_slot,
                        .apiVersion = "2.0.15",
                    },
                    .value = .{
                        .data = .{ .encoded = .{
                            account_data_base64,
                            encoding,
                        } },
                        .executable = facts.executable,
                        .lamports = facts.lamports,
                        .owner = facts.owner,
                        .rentEpoch = facts.rent_epoch,
                        .space = facts.space,
                    },
                };
            }

            pub fn getSnapshot(
                this: @This(),
                _: std.mem.Allocator,
                params: sig.rpc.methods.GetSnapshot,
            ) !sig.rpc.methods.GetSnapshot.Response {
                const snapshot_target = getSnapshotTarget(
                    this.accountsdb,
                    params.path,
                ) orelse return error.NoSnapshotForPathAvaialable;

                switch (snapshot_target) {
                    inline else => |pair| {
                        const snap_info, var full_info_lg = pair;
                        defer full_info_lg.unlock();

                        const archive_name_bounded = snap_info.snapshotArchiveName();
                        const archive_name = archive_name_bounded.constSlice();

                        switch (params.get) {
                            .size => {
                                const stat = try this.accountsdb.snapshot_dir.statFile(archive_name);
                                return .{ .size = stat.size };
                            },
                            .file => {
                                const archive_file = this.accountsdb.snapshot_dir.openFile(
                                    archive_name,
                                    .{},
                                ) catch |err| {
                                    switch (err) {
                                        error.FileNotFound => {
                                            this.accountsdb.logger.err().logf(
                                                "not found: {s}\n",
                                                .{sig.utils.fmt.tryRealPath(
                                                    this.accountsdb.snapshot_dir,
                                                    archive_name,
                                                )},
                                            );
                                        },
                                        else => {},
                                    }
                                    return error.SystemIoError;
                                };
                                errdefer archive_file.close();
                                return .{ .file = archive_file };
                            },
                        }
                    },
                }
            }

            fn getSnapshotTarget(
                accounts_db: *AccountsDB,
                target: []const u8,
            ) ?union(enum) {
                const SnapshotReadLock = sig.sync.RwMux(?SnapshotGenerationInfo).RLockGuard;
                full_snapshot: struct { FullSnapshotFileInfo, SnapshotReadLock },
                inc_snapshot: struct { IncrementalSnapshotFileInfo, SnapshotReadLock },
            } {
                const latest_snapshot_gen_info_rw = &accounts_db.latest_snapshot_gen_info;
                const is_snapshot_archive_like =
                    !std.meta.isError(FullSnapshotFileInfo.parseFileNameTarZst(target)) or
                    !std.meta.isError(IncrementalSnapshotFileInfo.parseFileNameTarZst(target));

                if (is_snapshot_archive_like) check_snapshots: {
                    const maybe_latest_snapshot_gen_info, //
                    var latest_snapshot_info_lg //
                    = latest_snapshot_gen_info_rw.readWithLock();
                    defer latest_snapshot_info_lg.unlock();

                    const full_info: FullSnapshotFileInfo, //
                    const inc_info: ?IncrementalSnapshotFileInfo //
                    = blk: {
                        const latest_snapshot_gen_info = maybe_latest_snapshot_gen_info.* orelse
                            break :check_snapshots;
                        const latest_full = latest_snapshot_gen_info.full;
                        const full_info: FullSnapshotFileInfo = .{
                            .slot = latest_full.slot,
                            .hash = latest_full.hash.checksum(),
                        };
                        const latest_incremental = latest_snapshot_gen_info.inc orelse
                            break :blk .{ full_info, null };
                        const inc_info: IncrementalSnapshotFileInfo = .{
                            .base_slot = latest_full.slot,
                            .slot = latest_incremental.slot,
                            .hash = latest_incremental.hash.checksum(),
                        };
                        break :blk .{ full_info, inc_info };
                    };

                    accounts_db.logger.debug().logf("Available full: {?s}", .{
                        full_info.snapshotArchiveName().constSlice(),
                    });
                    accounts_db.logger.debug().logf("Available inc: {?s}", .{
                        if (inc_info) |info| info.snapshotArchiveName().constSlice() else null,
                    });

                    const full_archive_name_bounded = full_info.snapshotArchiveName();
                    const full_archive_name = full_archive_name_bounded.constSlice();
                    if (std.mem.eql(u8, target, full_archive_name)) {
                        // acquire another lock on the rwmux, since the first one we got is going to unlock after we return.
                        const latest_snapshot_info_lg_again = latest_snapshot_gen_info_rw.read();
                        return .{
                            .full_snapshot = .{
                                full_info,
                                latest_snapshot_info_lg_again,
                            },
                        };
                    }

                    if (inc_info) |inc| {
                        const inc_archive_name_bounded = inc.snapshotArchiveName();
                        const inc_archive_name = inc_archive_name_bounded.constSlice();

                        if (std.mem.eql(u8, target, inc_archive_name)) {
                            // acquire another lock on the rwmux, since the first one we got is going to unlock after we return.
                            const latest_snapshot_info_lg_again = latest_snapshot_gen_info_rw.read();
                            return .{ .inc_snapshot = .{ inc, latest_snapshot_info_lg_again } };
                        }
                    }
                }

                return null;
            }
        }{ .accountsdb = self });
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

    pub fn reset(self: *Self, allocator: std.mem.Allocator) void {
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

        const store_info = account_in_file.store_info;
        self.pubkeys.append(store_info.pubkey) catch return Error.OutOfGeyserArrayMemory;
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
    shard_counts: ?[]usize,
    account_refs: *ArrayListUnmanaged(AccountRef),
    geyser_storage: ?*GeyserTmpStorage,
) ValidateAccountFileError!void {
    const zone = tracy.Zone.init(@src(), .{
        .name = "accountsdb AccountIndex.indexAndValidateAccountFile",
    });
    defer zone.deinit();

    var offset: usize = 0;
    var number_of_accounts: usize = 0;

    if (shard_counts) |s_c| {
        if (s_c.len != shard_calculator.n_shards) {
            return error.ShardCountMismatch;
        }
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
            .location = .{ .file = .{
                .file_id = accounts_file.id,
                .offset = offset,
            } },
            .next_ptr = null,
            .prev_ptr = null,
        });

        if (shard_counts) |s_c| {
            const pubkey = &account.store_info.pubkey;
            s_c[shard_calculator.index(pubkey)] += 1;
        }

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
        var buf: [std.heap.page_size_min]u8 = undefined;
        const file_reader = account_file.file.reader();
        while (true) {
            const bytes_read = try file_reader.read(&buf);
            if (bytes_read == 0) break;
            try archive_writer_counted.writeAll(buf[0..bytes_read]);
        }

        try snapgen.writeAccountFilePadding(archive_writer_counted, account_file.file_size);
    }

    try archive_writer_counted.writeAll(&sig.utils.tar.sentinel_blocks);
    if (std.debug.runtime_safety) {
        std.debug.assert(counting_state.bytes_written % 512 == 0);
    }
}

// fn testWriteSnapshotFull(
//     allocator: std.mem.Allocator,
//     accounts_db: *AccountsDB,
//     slot: Slot,
//     maybe_expected_hash: ?Hash,
// ) !void {
//     const snapshot_dir = accounts_db.snapshot_dir;

//     const manifest_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{slot});
//     const manifest_file = try snapshot_dir.openFile(manifest_path_bounded.constSlice(), .{});
//     defer manifest_file.close();

//     var snap_fields = try SnapshotManifest.decodeFromBincode(allocator, manifest_file.reader());
//     defer snap_fields.deinit(allocator);

//     try accounts_db.loadFromSnapshot(snap_fields.accounts_db_fields, 1, allocator, 500);

//     const deprecated_stored_meta_write_version =
//         snap_fields.accounts_db_fields.stored_meta_write_version;
//     const snapshot_gen_info = try accounts_db.generateFullSnapshot(.{
//         .target_slot = slot,
//         .bank_fields = &snap_fields.bank_fields,
//         .lamports_per_signature = snap_fields.bank_extra.lamports_per_signature,
//         .old_snapshot_action = .ignore_old,
//         .deprecated_stored_meta_write_version = deprecated_stored_meta_write_version,
//     });

//     if (maybe_expected_hash) |expected_hash| {
//         try std.testing.expectEqual(expected_hash, snapshot_gen_info.hash);
//     }

//     try accounts_db.validateLoadFromSnapshot(.{
//         .full_slot = slot,
//         .expected_full = .{
//             .capitalization = snapshot_gen_info.capitalization,
//             .accounts_hash = snapshot_gen_info.hash,
//         },
//         .expected_incremental = null,
//     });
// }

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

// test "testWriteSnapshot" {
//     // TODO: loading once from the full snapshot, and then a second time from the incremental snapshot,
//     // as is done in this test, isn't properly accounted for in the snapshot loading logic, since the
//     // way loading actually is handled in the validator is collapsing the full and incremental snapshots
//     // before loading.
//     // Either this test must be updated to test using the conventional loading method, or we must add
//     // a way to load from a full and then an incremental snapshot separately.
//     if (true) return error.SkipZigTest;

//     const allocator = std.testing.allocator;
//     var test_data_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
//     defer test_data_dir.close();

//     const snap_files = try SnapshotFiles.find(allocator, test_data_dir);

//     var tmp_dir_root = std.testing.tmpDir(.{});
//     defer tmp_dir_root.cleanup();
//     const snapshot_dir = tmp_dir_root.dir;

//     {
//         const archive_file_path_bounded = snap_files.full.snapshotArchiveName();
//         const archive_file_path = archive_file_path_bounded.constSlice();
//         const archive_file = try test_data_dir.openFile(archive_file_path, .{});
//         defer archive_file.close();
//         try parallelUnpackZstdTarBall(allocator, .noop, archive_file, snapshot_dir, 4, true);
//     }

//     if (snap_files.incremental()) |inc_snap| {
//         const archive_file_path_bounded = inc_snap.snapshotArchiveName();
//         const archive_file_path = archive_file_path_bounded.constSlice();
//         const archive_file = try test_data_dir.openFile(archive_file_path, .{});
//         defer archive_file.close();
//         try parallelUnpackZstdTarBall(allocator, .noop, archive_file, snapshot_dir, 4, false);
//     }

//     var accounts_db = try AccountsDB.init(.{
//         .allocator = allocator,
//         .logger = .noop,
//         .snapshot_dir = snapshot_dir,
//         .geyser_writer = null,
//         .gossip_view = null,
//         .index_allocation = .ram,
//         .number_of_index_shards = ACCOUNT_INDEX_SHARDS,
//     });
//     defer accounts_db.deinit();

//     try testWriteSnapshotFull(
//         allocator,
//         &accounts_db,
//         snap_files.full_snapshot.slot,
//         snap_files.full_snapshot.hash,
//     );
//     try testWriteSnapshotIncremental(
//         allocator,
//         &accounts_db,
//         snap_files.incremental_info.?.slot,
//         snap_files.incremental_info.?.hash,
//     );
// }

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

/// Loads from a snapshot, which takes time. For leaner accountsdb, use initForTest
fn loadTestAccountsDBFromSnapshot(
    allocator: std.mem.Allocator,
    use_disk: bool,
    n_threads: u32,
    logger: Logger,
    /// The directory into which the snapshots are unpacked, and
    /// the `snapshots_dir` for the returned `AccountsDB`.
    snapshot_dir: std.fs.Dir,
    accounts_per_file_estimate: u64,
) !struct { AccountsDB, FullAndIncrementalManifest } {
    comptime std.debug.assert(builtin.is_test); // should only be used in tests

    const snapshot_files = try findAndUnpackTestSnapshots(n_threads, snapshot_dir);

    const full_inc_manifest = try FullAndIncrementalManifest
        .fromFiles(allocator, .from(logger), snapshot_dir, snapshot_files);
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
        accounts_per_file_estimate,
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

    const full_inc_manifest = try FullAndIncrementalManifest
        .fromFiles(allocator, .from(logger), snapshot_dir, snapshot_files);
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
        sig.trace.Logger("geyser").noop,
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
        .number_of_index_shards = 1,
        .buffer_pool_frames = 2,
    });
    defer accounts_db.deinit();

    try accounts_db.loadFromSnapshot(
        snapshot.accounts_db_fields,
        1,
        allocator,
        100,
    );
}

test "write and read an account - basic" {
    const allocator = std.testing.allocator;

    var accounts_db, var dir = try AccountsDB.initForTest(allocator);
    defer accounts_db.deinit();
    defer dir.cleanup();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    var account = try accounts_db.getAccountLatest(allocator, &pubkey) orelse unreachable;
    defer account.deinit(allocator);
    try std.testing.expect(test_account.equals(&account));

    // new account
    accounts[0].lamports = 20;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, 28);
    var account_2 = try accounts_db.getAccountLatest(allocator, &pubkey) orelse unreachable;
    defer account_2.deinit(allocator);
    try std.testing.expect(accounts[0].equals(&account_2));
}

test "write and read an account (write single + read with ancestors)" {
    const allocator = std.testing.allocator;

    var accounts_db, var dir = try AccountsDB.initForTest(allocator);
    defer accounts_db.deinit();
    defer dir.cleanup();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const pubkey = Pubkey.initRandom(prng.random());

    var data = [_]u8{ 1, 2, 3 };

    const test_account: Account = .{
        .data = .initAllocated(&data),
        .executable = false,
        .lamports = 100,
        .owner = .ZEROES,
        .rent_epoch = 0,
    };
    const test_account_shared: AccountSharedData = .{
        .data = &data,
        .executable = false,
        .lamports = 100,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    };

    try accounts_db.putAccount(5083, pubkey, test_account_shared);

    // normal get
    {
        var account = (try accounts_db.getAccountLatest(allocator, &pubkey)).?;
        defer account.deinit(allocator);
        try std.testing.expect(test_account.equals(&account));
    }

    // assume we've progessed past the need for ancestors
    {
        accounts_db.max_slots.set(.{ .rooted = 10_000, .flushed = 10_000 });
        var account = (try accounts_db.getAccountWithAncestors(allocator, &pubkey, &.{})).?;
        defer account.deinit(allocator);
        accounts_db.max_slots.set(.{ .rooted = null, .flushed = null });
        try account.expectEquals(test_account);
    }

    // slot is in ancestors
    {
        var ancestors: sig.core.Ancestors = .EMPTY;
        defer ancestors.deinit(allocator);
        try ancestors.ancestors.put(allocator, 5083, {});

        var account = (try accounts_db.getAccountWithAncestors(allocator, &pubkey, &ancestors)).?;
        defer account.deinit(allocator);
        try account.expectEquals(test_account);
    }

    // slot is not in ancestors
    try std.testing.expectEqual(null, accounts_db.getAccountWithAncestors(allocator, &pubkey, &.{}));

    // write account to the same pubkey in the next slot (!)
    {
        var data_2 = [_]u8{ 0, 1, 0, 1 };

        const test_account_2: Account = .{
            .data = .initAllocated(&data_2),
            .executable = true,
            .lamports = 1000,
            .owner = Pubkey.ZEROES,
            .rent_epoch = 1,
        };

        const test_account_2_shared: AccountSharedData = .{
            .data = &data_2,
            .executable = true,
            .lamports = 1000,
            .owner = Pubkey.ZEROES,
            .rent_epoch = 1,
        };

        try accounts_db.putAccount(5084, pubkey, test_account_2_shared);

        // prev slot, get prev account
        {
            var ancestors = sig.core.Ancestors{};
            defer ancestors.deinit(allocator);
            try ancestors.ancestors.put(allocator, 5083, {});

            var account = (try accounts_db.getAccountWithAncestors(
                allocator,
                &pubkey,
                &ancestors,
            )).?;
            defer account.deinit(allocator);
            try std.testing.expect(test_account.equals(&account));
        }

        // new slot, get new account
        {
            var ancestors = sig.core.Ancestors{};
            defer ancestors.deinit(allocator);
            try ancestors.ancestors.put(allocator, 5084, {});

            var account = (try accounts_db.getAccountWithAncestors(
                allocator,
                &pubkey,
                &ancestors,
            )).?;
            defer account.deinit(allocator);
            try std.testing.expect(test_account_2.equals(&account));
        }
    }
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

test "load and validate from test snapshot - single threaded" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDBFromSnapshot(allocator, false, 1, .noop, snapshot_dir, 500);
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    const maybe_inc_persistence = if (full_inc_manifest.incremental) |inc|
        inc.bank_extra.snapshot_persistence
    else
        null;

    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = full_inc_manifest.full.bank_fields.slot,
        .expected_full = .{
            .accounts_hash = full_inc_manifest.full.bank_extra.accounts_lt_hash,
        },
        .expected_incremental = if (maybe_inc_persistence) |_| .{
            .accounts_hash = full_inc_manifest.incremental.?.bank_extra.accounts_lt_hash,
        } else null,
    });

    // use the genesis to verify loading
    const genesis_path = sig.TEST_DATA_DIR ++ "genesis.bin";
    const genesis_config = try sig.core.GenesisConfig.init(allocator, genesis_path);
    defer genesis_config.deinit(allocator);

    try full_inc_manifest.full.bank_fields.validate(&genesis_config);
}

test "load and validate from test snapshot - disk index" {
    // slow, and doesn't add a lot on top of the single threaded test
    if (!sig.build_options.long_tests) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDBFromSnapshot(allocator, true, 1, .noop, snapshot_dir, 500);
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = full_inc_manifest.full.bank_fields.slot,
        .expected_full = .{
            .accounts_hash = full_inc_manifest.full.bank_extra.accounts_lt_hash,
        },
        .expected_incremental = if (full_inc_manifest.incremental) |inc| .{
            .accounts_hash = inc.bank_extra.accounts_lt_hash,
        } else null,
    });
}

test "load and validate from test snapshot - parallel" {
    // slow, and doesn't add a lot on top of the single threaded test
    if (!sig.build_options.long_tests) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDBFromSnapshot(allocator, false, 2, .noop, snapshot_dir, 500);
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    try accounts_db.validateLoadFromSnapshot(.{
        .full_slot = full_inc_manifest.full.bank_fields.slot,
        .expected_full = .{
            .accounts_hash = full_inc_manifest.full.bank_extra.accounts_lt_hash,
        },
        .expected_incremental = if (full_inc_manifest.incremental) |inc| .{
            .accounts_hash = inc.bank_extra.accounts_lt_hash,
        } else null,
    });
}

test "load sysvars" {
    var gpa_state: std.heap.DebugAllocator(.{ .stack_trace_frames = 64 }) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db, const full_inc_manifest =
        try loadTestAccountsDBFromSnapshot(allocator, false, 1, .noop, snapshot_dir, 500);
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    { // load clock sysvar
        const full = full_inc_manifest.full;
        const inc = full_inc_manifest.incremental;
        const expected_clock: sysvar.Clock = .{
            .slot = (inc orelse full).bank_fields.slot,
            .epoch_start_timestamp = 1761088804,
            .epoch = (inc orelse full).bank_fields.epoch,
            .leader_schedule_epoch = 1,
            .unix_timestamp = 1761088804,
        };
        try std.testing.expectEqual(
            expected_clock,
            try accounts_db.getTypeFromAccount(allocator, sysvar.Clock, &sysvar.Clock.ID),
        );
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

// test "generate snapshot & update gossip snapshot hashes" {
//     const GossipDataTag = sig.gossip.data.GossipDataTag;
//     const SnapshotHashes = sig.gossip.data.SnapshotHashes;

//     const allocator = std.testing.allocator;

// var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
// const random = prng.random();

//     var tmp_dir_root = std.testing.tmpDir(.{});
//     defer tmp_dir_root.cleanup();
//     const snapshot_dir = tmp_dir_root.dir;

//     const snap_files = try findAndUnpackTestSnapshots(1, snapshot_dir);

//     const full_inc_manifest =
//         try FullAndIncrementalManifest.fromFiles(allocator, .noop, snapshot_dir, snap_files);
//     defer full_inc_manifest.deinit(allocator);

//     // mock gossip service
//     var push_msg_queue_mux = sig.gossip.GossipService.PushMessageQueue.init(.{
//         .queue = std.array_list.Managed(sig.gossip.data.GossipData).init(allocator),
//         .data_allocator = allocator,
//     });
//     defer push_msg_queue_mux.private.v.queue.deinit();
//     const my_keypair = KeyPair.generate();

//     var accounts_db = try AccountsDB.init(.{
//         .allocator = allocator,
//         .logger = .noop,
//         .snapshot_dir = snapshot_dir,
//         .gossip_view = .{
//             .my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key),
//             .push_msg_queue = &push_msg_queue_mux,
//         },
//         .geyser_writer = null,
//         .index_allocation = .ram,
//         .number_of_index_shards = ACCOUNT_INDEX_SHARDS,
//     });
//     defer accounts_db.deinit();

//     {
//         const loaded = try accounts_db.loadWithDefaults(
//             allocator,
//             full_inc_manifest,
//             1,
//             true,
//             300,
//         );
//         defer loaded.deinit(allocator);
//     }

//     var bank_fields: BankFields = try .initRandom(allocator, random, 128);
//     defer bank_fields.deinit(allocator);

//     const full_slot = full_inc_manifest.full.accounts_db_fields.slot;
//     const full_gen_result = try accounts_db.generateFullSnapshot(.{
//         .target_slot = full_slot,
//         .bank_fields = &bank_fields,
//         .lamports_per_signature = random.int(u64),
//         // make sure we don't delete anything in `sig.TEST_DATA_DIR`
//         .old_snapshot_action = .ignore_old,
//         .deprecated_stored_meta_write_version = blk: {
//             const accounts_db_fields = full_inc_manifest.full.accounts_db_fields;
//             break :blk accounts_db_fields.stored_meta_write_version;
//         },
//     });
//     const full_hash = full_gen_result.hash;

// try std.testing.expectEqual(
//     full_inc_manifest.full.bank_extra.accounts_lt_hash.checksum(),
//     full_gen_result.hash.checksum(),
// );
// try std.testing.expectEqual(
//     full_inc_manifest.full.bank_fields.capitalization,
//     full_gen_result.capitalization,
// );

//     {
//         const queue, var queue_lg = push_msg_queue_mux.readWithLock();
//         defer queue_lg.unlock();

// try std.testing.expectEqual(1, queue.queue.items.len);
// const queue_item_0 = queue.queue.items[0]; // should be from the full generation
// try std.testing.expectEqual(.SnapshotHashes, @as(GossipDataTag, queue_item_0));

//     try std.testing.expectEqualDeep(
//         SnapshotHashes{
//             .from = Pubkey.fromPublicKey(&my_keypair.public_key),
//             .full = .{ .slot = full_slot, .hash = full_hash.checksum() },
//             .incremental = SnapshotHashes.IncrementalSnapshotsList.EMPTY,
//             // set to zero when pushed to the queue, because it would be set in `drainPushQueueToGossipTable`.
//             .wallclock = 0,
//         },
//         queue_item_0.SnapshotHashes,
//     );
// }

//     if (full_inc_manifest.incremental) |inc_manifest| {
//         const inc_slot = inc_manifest.accounts_db_fields.slot;
//         const inc_gen_result = try accounts_db.generateIncrementalSnapshot(.{
//             .target_slot = inc_slot,
//             .bank_fields = &bank_fields,
//             .lamports_per_signature = random.int(u64),
//             // make sure we don't delete anything in `sig.TEST_DATA_DIR`
//             .old_snapshot_action = .ignore_old,
//             .deprecated_stored_meta_write_version = inc_manifest
//                 .accounts_db_fields.stored_meta_write_version,
//         });
//         const inc_hash = inc_gen_result.incremental_hash;

// try std.testing.expectEqual(
//     full_slot,
//     inc_gen_result.full_slot,
// );
// try std.testing.expectEqual(
//     full_gen_result.hash,
//     inc_gen_result.full_hash,
// );
// try std.testing.expectEqual(
//     full_gen_result.capitalization,
//     inc_gen_result.full_capitalization,
// );

//         {
//             const queue, var queue_lg = push_msg_queue_mux.readWithLock();
//             defer queue_lg.unlock();

// try std.testing.expectEqual(2, queue.queue.items.len);
// const queue_item_1 = queue.queue.items[1]; // should be from the incremental generation
// try std.testing.expectEqual(.SnapshotHashes, @as(GossipDataTag, queue_item_1));

//         try std.testing.expectEqualDeep(
//             SnapshotHashes{
//                 .from = Pubkey.fromPublicKey(&my_keypair.public_key),
//                 .full = .{ .slot = full_slot, .hash = full_hash.checksum() },
//                 .incremental = SnapshotHashes.IncrementalSnapshotsList.initSingle(.{
//                     .slot = inc_slot,
//                     .hash = inc_hash.checksum(),
//                 }),
//                 // set to zero when pushed to the queue, because it would be set in `drainPushQueueToGossipTable`.
//                 .wallclock = 0,
//             },
//             queue_item_1.SnapshotHashes,
//         );
//     }
// }
// }

pub const BenchmarkAccountsDBSnapshotLoad = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 1;
    pub const name = "AccountsDBSnapshotLoad";

    pub const SNAPSHOT_DIR_PATH = sig.TEST_DATA_DIR ++ "bench_snapshot/";

    pub const BenchInputs = struct {
        use_disk: bool,
        n_threads: u32,
        name: []const u8,
        cluster: sig.core.Cluster,
    };

    pub const inputs = [_]BenchInputs{.{
        .name = "testnet - ram index - 4 threads",
        .use_disk = false,
        .n_threads = 4,
        .cluster = .testnet,
    }};

    pub fn loadAndVerifySnapshot(
        units: Resolution,
        bench_inputs: BenchInputs,
    ) !struct {
        load_time: u64,
        validate_time: u64,
    } {
        const allocator = std.heap.c_allocator;
        const logger = sig.trace.direct_print.logger("accountsdb.benchmark", .debug);

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
            const zero_duration: sig.time.Duration = .fromNanos(0);
            return .{
                .load_time = zero_duration.asNanos(),
                .validate_time = zero_duration.asNanos(),
            };
        };
        defer snapshot_dir.close();

        const snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);
        const full_inc_manifest = try FullAndIncrementalManifest.fromFiles(
            allocator,
            .from(logger),
            snapshot_dir,
            snapshot_files,
        );
        defer full_inc_manifest.deinit(allocator);
        const collapsed_manifest = try full_inc_manifest.collapse(allocator);

        const loading_duration, //
        const validate_duration //
        = duration_blk: {
            var accounts_db = try AccountsDB.init(.{
                .allocator = allocator,
                .logger = .from(logger),
                .snapshot_dir = snapshot_dir,
                .geyser_writer = null,
                .gossip_view = null,
                .index_allocation = if (bench_inputs.use_disk) .disk else .ram,
                .number_of_index_shards = 32,
            });
            defer accounts_db.deinit();

            var load_timer = sig.time.Timer.start();
            try accounts_db.loadFromSnapshot(
                collapsed_manifest.accounts_db_fields,
                bench_inputs.n_threads,
                allocator,
                try getAccountPerFileEstimateFromCluster(bench_inputs.cluster),
            );
            const loading_duration = load_timer.read();

            const full_manifest = full_inc_manifest.full;
            const maybe_inc_persistence = if (full_inc_manifest.incremental) |inc|
                inc.bank_extra.snapshot_persistence
            else
                null;

            var validate_timer = sig.time.Timer.start();
            try accounts_db.validateLoadFromSnapshot(.{
                .full_slot = full_manifest.bank_fields.slot,
                .expected_full = .{
                    .accounts_hash = full_manifest.bank_extra.accounts_lt_hash,
                },
                .expected_incremental = if (maybe_inc_persistence) |_| .{
                    .accounts_hash = full_inc_manifest.incremental.?.bank_extra.accounts_lt_hash,
                } else null,
            });
            const validate_duration = validate_timer.read();

            break :duration_blk .{ loading_duration, validate_duration };
        };

        // TODO: re-add fastload benchmarks here

        return .{
            .load_time = units.convertDuration(loading_duration),
            .validate_time = units.convertDuration(validate_duration),
        };
    }
};

pub const BenchmarkAccountsDB = struct {
    pub const min_iterations = 3;
    pub const max_iterations = 10;
    pub const name = "AccountsDB";

    pub const MemoryType = AccountIndex.AllocatorConfig.Tag;

    pub const BenchInputs = struct {
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

    pub const inputs = [_]BenchInputs{
        // .{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .ram,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - ram accounts - lru disabled)",
        // },
        // .{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .ram,
        //     .index = .disk,
        //     .name = "100k accounts (1_slot - disk index - ram accounts - lru disabled)",
        // },
        // .{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .name = "100k accounts (1_slot - disk index - disk accounts - lru disabled)",
        // },

        // .{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - disk accounts - lru disabled)",
        // },

        // .{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - disk accounts)",
        // },
        // .{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - disk accounts)",
        // },

        // .{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - disk accounts)",
        // },

        // // test accounts in ram
        // .{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .ram,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index - ram accounts)",
        // },
        // .{
        //     .n_accounts = 10_000,
        //     .slot_list_len = 10,
        //     .accounts = .ram,
        //     .index = .ram,
        //     .name = "10k accounts (10_slots - ram index - ram accounts)",
        // },

        // tests large number of accounts on disk
        // NOTE: the other tests are useful for understanding performance for but CI,
        // these are the most useful as they are the most similar to production
        .{
            .n_accounts = 10_000,
            .slot_list_len = 10,
            .accounts = .disk,
            .index = .ram,
            .name = "10k accounts (10_slots - ram index - disk accounts)",
        },
        .{
            .n_accounts = 500_000,
            .slot_list_len = 1,
            .accounts = .disk,
            .index = .ram,
            .name = "500k accounts (1_slot - ram index - disk accounts)",
        },

        // .{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 3,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "500k accounts (3_slot - ram index - disk accounts)",
        // },
        // .{
        //     .n_accounts = 3_000_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "3M accounts (1_slot - ram index - disk accounts)",
        // },
        // .{
        //     .n_accounts = 3_000_000,
        //     .slot_list_len = 3,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "3M accounts (3_slot - ram index - disk accounts)",
        // },
        // .{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .n_accounts_multiple = 2, // 1 mill accounts init
        //     .index = .ram,
        //     .name = "3M accounts (3_slot - ram index - disk accounts - 1million init)",
        // },

        // // testing disk indexes
        // .{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .name = "500k accounts (1_slot - disk index - disk accounts)",
        // },
        // .{
        //     .n_accounts = 3_000_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .name = "3m accounts (1_slot - disk index - disk accounts)",
        // },
        // .{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .n_accounts_multiple = 2,
        //     .name = "500k accounts (1_slot - disk index - disk accounts)",
        // },
    };

    pub fn readWriteAccounts(
        units: Resolution,
        bench_args: BenchInputs,
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

        var accounts_db: AccountsDB = try AccountsDB.init(.{
            .allocator = allocator,
            .logger = .noop,
            .snapshot_dir = snapshot_dir,
            .geyser_writer = null,
            .gossip_view = null,
            .index_allocation = index_type,
            .number_of_index_shards = 32,
        });
        defer accounts_db.deinit();

        try accounts_db.account_index.expandRefCapacity(
            std.math.ceilPowerOfTwo(usize, total_n_accounts) catch total_n_accounts,
        );

        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

                    var timer = sig.time.Timer.start();
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
                                offset += account.serialize(&pubkey, buf[offset..]);
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

                    var timer = sig.time.Timer.start();
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
                const account = try accounts_db.getAccountLatest(
                    allocator,
                    &pubkeys[pubkey_idx],
                ) orelse unreachable;
                account.deinit(allocator);
            }
        }

        var timer = sig.time.Timer.start();

        const do_read_count = n_accounts;
        var i: usize = 0;
        while (i < do_read_count) : (i += 1) {
            const pubkey_idx = indexer.sample();
            const account = try accounts_db.getAccountLatest(allocator, &pubkeys[pubkey_idx]) orelse
                unreachable;
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

test "insert multiple accounts on same slot" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    // Initialize empty accounts db
    var accounts_db, var tmp_dir = try AccountsDB.initForTest(allocator);
    defer tmp_dir.cleanup();
    defer accounts_db.deinit();

    // Set initial slot
    const slot: Slot = 10;

    // Create ancestors with initial slot
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    // Insert 50 random accounts on current slot and reload them immediately
    for (0..50) |i| {
        const pubkey = Pubkey.initRandom(random);

        const expected = try createRandomAccount(allocator, random);
        defer allocator.free(expected.data);

        try accounts_db.putAccount(slot, pubkey, expected);

        const maybe_actual = try accounts_db.getAccountWithAncestors(
            allocator,
            &pubkey,
            &ancestors,
        );
        defer if (maybe_actual) |actual| actual.deinit(allocator);

        if (maybe_actual) |actual| {
            try expectedAccountSharedDataEqualsAccount(expected, actual, false);
        } else {
            std.debug.print("Account {} not found after insertion.\n", .{i});
            return error.AccountNotFound;
        }
    }
}

fn createRandomAccount(
    allocator: std.mem.Allocator,
    random: std.Random,
) !AccountSharedData {
    if (!builtin.is_test) @compileError("only for testing");

    const data_size = random.uintAtMost(u64, 1_024);
    const data = try allocator.alloc(u8, data_size);
    random.bytes(data);

    return .{
        .lamports = random.uintAtMost(u64, 1_000_000),
        .data = data,
        .owner = Pubkey.initRandom(random),
        .executable = random.boolean(),
        .rent_epoch = random.uintAtMost(u64, 1_000_000),
    };
}

fn expectedAccountSharedDataEqualsAccount(
    expected: AccountSharedData,
    account: Account,
    print_instead_of_expect: bool,
) !void {
    if (!builtin.is_test)
        @compileError("expectedAccountSharedDataEqualsAccount is only for testing");

    if (print_instead_of_expect) {
        std.debug.print("expected: {any}\n", .{expected});
        std.debug.print("actual:   {any}\n\n", .{account});
    } else {
        // we know where this data came from (not from the disk), so we can take its slice directly
        std.debug.assert(account.data == .owned_allocation);

        try std.testing.expectEqual(expected.lamports, account.lamports);
        try std.testing.expectEqualSlices(u8, expected.data, account.data.owned_allocation);
        try std.testing.expectEqualSlices(u8, &expected.owner.data, &account.owner.data);
        try std.testing.expectEqual(expected.executable, account.executable);
        try std.testing.expectEqual(expected.rent_epoch, account.rent_epoch);
    }
}

test "insert multiple accounts on multiple slots" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var accounts_db, var tmp_dir = try AccountsDB.initForTest(allocator);
    defer tmp_dir.cleanup();
    defer accounts_db.deinit();

    const slots = [_]Slot{ 5, 9, 10, 11, 12 };

    for (0..50) |i| {
        const slot = slots[random.uintLessThan(u64, slots.len)];

        var ancestors = Ancestors{};
        defer ancestors.deinit(allocator);
        try ancestors.ancestors.put(allocator, slot, {});

        const pubkey = Pubkey.initRandom(random);
        errdefer std.log.err(
            "Failed to insert and load account: i={}, slot={}, ancestors={any} pubkey={}\n",
            .{ i, slot, ancestors.ancestors.keys(), pubkey },
        );

        const expected = try createRandomAccount(allocator, random);
        defer allocator.free(expected.data);

        try accounts_db.putAccount(slot, pubkey, expected);

        const maybe_actual = try accounts_db.getAccountWithAncestors(
            allocator,
            &pubkey,
            &ancestors,
        );
        defer if (maybe_actual) |actual| actual.deinit(allocator);

        if (maybe_actual) |actual|
            try expectedAccountSharedDataEqualsAccount(expected, actual, false)
        else
            return error.AccountNotFound;
    }
}

test "insert account on multiple slots" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var accounts_db, var tmp_dir = try AccountsDB.initForTest(allocator);
    defer tmp_dir.cleanup();
    defer accounts_db.deinit();

    const slots = [_]Slot{ 5, 9, 10, 11, 12 };

    for (0..50) |i| {
        const pubkey = Pubkey.initRandom(random);
        const num_slots_to_insert = random.uintAtMost(usize, slots.len);

        for (0..num_slots_to_insert) |j| {
            const slot = slots[random.uintLessThan(u64, slots.len)];

            var ancestors = Ancestors{};
            defer ancestors.deinit(allocator);
            try ancestors.ancestors.put(allocator, slot, {});

            errdefer std.log.err(
                \\Failed to insert and load account: i={}
                \\    j:         {}/{}
                \\    slot:      {}
                \\    ancestors: {any}
                \\    pubkey:    {}
                \\
            ,
                .{ i, j, num_slots_to_insert, slot, ancestors.ancestors.keys(), pubkey },
            );

            const expected = try createRandomAccount(allocator, random);
            defer allocator.free(expected.data);

            try accounts_db.putAccount(slot, pubkey, expected);

            const maybe_actual = try accounts_db.getAccountWithAncestors(
                allocator,
                &pubkey,
                &ancestors,
            );
            defer if (maybe_actual) |actual| actual.deinit(allocator);

            if (maybe_actual) |actual|
                try expectedAccountSharedDataEqualsAccount(expected, actual, false)
            else
                return error.AccountNotFound;
        }
    }
}

test "missing ancestor returns null" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var accounts_db, var tmp_dir = try AccountsDB.initForTest(allocator);
    defer tmp_dir.cleanup();
    defer accounts_db.deinit();

    const slot: Slot = 15;
    const pubkey = Pubkey.initRandom(random);

    const account = try createRandomAccount(allocator, random);
    defer allocator.free(account.data);
    try accounts_db.putAccount(slot, pubkey, account);

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);

    try std.testing.expectEqual(
        null,
        try accounts_db.getAccountWithAncestors(allocator, &pubkey, &ancestors),
    );
}

test "overwrite account in same slot" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var accounts_db, var tmp_dir = try AccountsDB.initForTest(allocator);
    defer tmp_dir.cleanup();
    defer accounts_db.deinit();

    const slot: Slot = 15;
    const pubkey = Pubkey.initRandom(random);

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    const first = try createRandomAccount(allocator, random);
    defer allocator.free(first.data);
    try accounts_db.putAccount(slot, pubkey, first);

    const second = try createRandomAccount(allocator, random);
    defer allocator.free(second.data);
    try accounts_db.putAccount(slot, pubkey, second);

    const maybe_actual = try accounts_db.getAccountWithAncestors(allocator, &pubkey, &ancestors);
    defer if (maybe_actual) |actual| actual.deinit(allocator);

    if (maybe_actual) |actual|
        try expectedAccountSharedDataEqualsAccount(second, actual, false)
    else
        return error.AccountNotFound;
}

test "insert many duplicate individual accounts, get latest with ancestors" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var accounts_db, var tmp_dir = try AccountsDB.initForTest(allocator);
    defer tmp_dir.cleanup();
    defer accounts_db.deinit();

    const pubkey_count = 50;
    const max_versions_per_key = 50;

    var pubkeys: [pubkey_count]Pubkey = undefined;
    for (&pubkeys) |*p| p.* = Pubkey.initRandom(random);

    var allocated_accounts: ArrayList(AccountSharedData) = .init(allocator);
    defer {
        for (allocated_accounts.items) |account| allocator.free(account.data);
        allocated_accounts.deinit();
    }

    var expected_latest: [pubkey_count]?struct {
        slot: Slot,
        account: AccountSharedData,
    } = @splat(null);

    for (0..pubkey_count) |i| {
        const pubkey = pubkeys[i];

        const num_versions = 1 + random.uintLessThan(u32, max_versions_per_key);

        for (0..num_versions) |_| {
            // we cannot go backwards in slots
            const max_slot_so_far = if (expected_latest[i]) |expected| expected.slot else 0;
            const slot = @min(random.uintLessThan(u64, 20), max_slot_so_far);

            const account = try createRandomAccount(allocator, random);
            try allocated_accounts.append(account);

            try accounts_db.putAccount(slot, pubkey, account);

            std.debug.assert(slot >= max_slot_so_far);

            expected_latest[i] = .{ .slot = slot, .account = account };
        }
    }

    for (pubkeys, expected_latest) |pubkey, maybe_expected| {
        const expected = maybe_expected orelse return error.ExpectedMissing;

        var ancestors = Ancestors{};
        defer ancestors.deinit(allocator);
        try ancestors.ancestors.put(allocator, expected.slot, {});

        const maybe_actual = try accounts_db.getAccountWithAncestors(
            allocator,
            &pubkey,
            &ancestors,
        );
        defer if (maybe_actual) |actual| actual.deinit(allocator);

        if (maybe_actual) |actual| {
            try expectedAccountSharedDataEqualsAccount(
                expected.account,
                actual,
                false,
            );
        } else {
            return error.AccountNotFound;
        }
    }
}

test "expandSlotRefsAndInsert alloc failure" {
    const test_fn = struct {
        fn f(allocator: std.mem.Allocator) !void {
            var accounts_db, var tmp_dir = try AccountsDB.initForTest(allocator);
            defer tmp_dir.cleanup();
            defer accounts_db.deinit();

            try accounts_db.expandSlotRefsAndInsert(1, &.{Pubkey.ZEROES});
            try accounts_db.expandSlotRefsAndInsert(2, &.{Pubkey.ZEROES});
        }
    }.f;

    try std.testing.checkAllAllocationFailures(std.testing.allocator, test_fn, .{});
}

test "expandSlotRefsAndInsert double insert failure" {
    const allocator = std.testing.allocator;

    var accounts_db, var tmp_dir = try AccountsDB.initForTest(allocator);
    defer tmp_dir.cleanup();
    defer accounts_db.deinit();

    try accounts_db.expandSlotRefsAndInsert(1, &.{Pubkey.ZEROES});

    accounts_db.logger = .noop;
    try std.testing.expectError(
        error.InsertIndexFailed,
        accounts_db.expandSlotRefsAndInsert(1, &.{Pubkey.ZEROES}),
    );
}

test "loadAndVerifyAccountsFiles ref manager expand" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    const accounts_per_file_estimate = 3; // deliberate under-estimate

    var accounts_db, const full_inc_manifest = try loadTestAccountsDBFromSnapshot(
        allocator,
        false,
        1,
        .noop,
        snapshot_dir,
        accounts_per_file_estimate,
    );
    defer {
        accounts_db.deinit();
        full_inc_manifest.deinit(allocator);
    }

    const n_slots = blk: {
        const slot_reference_map, var slot_reference_map_lg =
            accounts_db.account_index.slot_reference_map.readWithLock();
        defer slot_reference_map_lg.unlock();

        break :blk slot_reference_map.count();
    };

    const ref_capacity = accounts_db.account_index.reference_manager.capacity;

    // For this test, accounts per file == accounts per slot.
    // If we've made more account ref capacity per slot than we've estimated, we have expanded our
    // reference manager.
    try std.testing.expect(ref_capacity / n_slots > accounts_per_file_estimate);
}
