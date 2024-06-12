const std = @import("std");
const builtin = @import("builtin");
const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const spawnThreadTasks = @import("../utils/thread.zig").spawnThreadTasks;
const Account = @import("../core/account.zig").Account;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/time.zig").Slot;
const Epoch = @import("../core/time.zig").Epoch;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");
const sysvars = @import("../accountsdb/sysvars.zig");
const AccountsDbFields = @import("../accountsdb/snapshots.zig").AccountsDbFields;
const AccountFileInfo = @import("../accountsdb/snapshots.zig").AccountFileInfo;
const AccountFile = @import("../accountsdb/accounts_file.zig").AccountFile;
const FileId = @import("../accountsdb/accounts_file.zig").FileId;
const AccountInFile = @import("../accountsdb/accounts_file.zig").AccountInFile;
const Blake3 = std.crypto.hash.Blake3;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;

const NestedHashTree = @import("../common/merkle_tree.zig").NestedHashTree;
const SnapshotFields = @import("../accountsdb/snapshots.zig").SnapshotFields;
const BankIncrementalSnapshotPersistence = @import("../accountsdb/snapshots.zig").BankIncrementalSnapshotPersistence;
const Bank = @import("bank.zig").Bank;
const readDirectory = @import("../utils/directory.zig").readDirectory;
const SnapshotFiles = @import("../accountsdb/snapshots.zig").SnapshotFiles;
const AllSnapshotFields = @import("../accountsdb/snapshots.zig").AllSnapshotFields;
const SnapshotFieldsAndPaths = @import("../accountsdb/snapshots.zig").SnapshotFieldsAndPaths;
const parallelUnpackZstdTarBall = @import("snapshots.zig").parallelUnpackZstdTarBall;
const Logger = @import("../trace/log.zig").Logger;
const printTimeEstimate = @import("../time/estimate.zig").printTimeEstimate;

const _accounts_index = @import("index.zig");
const AccountIndex = _accounts_index.AccountIndex;
const RefMemoryLinkedList = _accounts_index.RefMemoryLinkedList;
const AccountRef = _accounts_index.AccountRef;
const DiskMemoryAllocator = _accounts_index.DiskMemoryAllocator;

pub const DB_PROGRESS_UPDATES_NS = 5 * std.time.ns_per_s;
pub const MERKLE_FANOUT: usize = 16;
pub const ACCOUNT_INDEX_BINS: usize = 8192;
// NOTE: this constant has a large impact on performance due to allocations (best to overestimate)
pub const ACCOUNTS_PER_FILE_EST: usize = 1500;

pub const AccountsDBConfig = struct {
    // number of Accounts to preallocate for cache
    storage_cache_size: usize = 0,
    // number of bins to shard the index pubkeys across -- must be power of two
    number_of_index_bins: usize = ACCOUNT_INDEX_BINS,
    // how many RAM references to preallocate for each bin
    index_ram_capacity: usize = 0,
    // where to create disk indexes files (if null, will not use disk indexes)
    disk_index_path: ?[]const u8 = null,
    // how many DISK references to preallocate for each bin
    index_disk_capacity: usize = 0,
};

/// database for accounts
pub const AccountsDB = struct {
    allocator: std.mem.Allocator,

    // holds the account data
    storage: AccountStorage,
    // maps a pubkey to the account location
    account_index: AccountIndex,
    disk_allocator_ptr: ?*DiskMemoryAllocator = null,

    logger: Logger,
    config: AccountsDBConfig,
    fields: ?AccountsDbFields = null,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        logger: Logger,
        config: AccountsDBConfig,
    ) !Self {
        const storage = try AccountStorage.init(
            allocator,
            config.storage_cache_size,
        );

        const maybe_disk_allocator_ptr: ?*DiskMemoryAllocator, //
        const reference_allocator: std.mem.Allocator //
        = blk: {
            if (config.disk_index_path) |disk_index_path| {
                const ptr = try allocator.create(DiskMemoryAllocator);
                errdefer allocator.destroy(ptr);
                ptr.* = try DiskMemoryAllocator.init(disk_index_path);
                break :blk .{ ptr, ptr.allocator() };
            } else {
                break :blk .{ null, std.heap.page_allocator };
            }
        };

        const account_index = try AccountIndex.init(
            allocator,
            reference_allocator,
            config.number_of_index_bins,
        );

        return .{
            .allocator = allocator,
            .disk_allocator_ptr = maybe_disk_allocator_ptr,
            .storage = storage,
            .account_index = account_index,
            .logger = logger,
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        self.storage.deinit();
        self.account_index.deinit(true);
        if (self.disk_allocator_ptr) |ptr| {
            self.allocator.destroy(ptr);
        }
    }

    /// easier to use load function
    pub fn loadWithDefaults(
        self: *Self,
        snapshot_fields_and_paths: *SnapshotFieldsAndPaths,
        snapshot_dir: []const u8,
        n_threads: u32,
        validate: bool,
    ) !SnapshotFields {
        const snapshot_fields = try snapshot_fields_and_paths.all_fields.collapse();
        const accounts_path = try std.fmt.allocPrint(self.allocator, "{s}/accounts/", .{snapshot_dir});
        defer self.allocator.free(accounts_path);

        var timer = try std.time.Timer.start();
        self.logger.infof("loading from snapshot...", .{});
        try self.loadFromSnapshot(
            snapshot_fields.accounts_db_fields,
            accounts_path,
            n_threads,
            std.heap.page_allocator,
        );
        self.logger.infof("loaded from snapshot in {s}", .{std.fmt.fmtDuration(timer.read())});

        if (validate) {
            timer.reset();
            const full_snapshot = snapshot_fields_and_paths.all_fields.full;
            try self.validateLoadFromSnapshot(
                snapshot_fields.bank_fields.incremental_snapshot_persistence,
                full_snapshot.bank_fields.slot,
                full_snapshot.bank_fields.capitalization,
            );
            self.logger.infof("validated from snapshot in {s}", .{std.fmt.fmtDuration(timer.read())});
        }

        return snapshot_fields;
    }

    /// loads the account files and gernates the account index from a snapshot
    pub fn loadFromSnapshot(
        self: *Self,
        // fields from the snapshot
        fields: AccountsDbFields,
        // where the account files are
        accounts_path: []const u8,
        n_threads: u32,
        per_thread_allocator: std.mem.Allocator,
    ) !void {
        self.fields = fields;

        // used to read account files
        const n_parse_threads = n_threads;
        // used to merge thread results
        const n_combine_threads = n_threads;

        var timer = std.time.Timer.start() catch unreachable;
        timer.reset();

        // read the account files
        var accounts_dir = try std.fs.cwd().openDir(accounts_path, .{ .iterate = true });
        defer accounts_dir.close();

        const accounts_dir_iter = accounts_dir.iterate();

        var files = try readDirectory(self.allocator, accounts_dir_iter);
        const filenames = files.filenames;
        defer {
            files.filenames.deinit();
            self.allocator.free(files.filename_memory);
        }

        var n_account_files: usize = 0;
        for (filenames.items) |filename| {
            var fiter = std.mem.tokenizeSequence(u8, filename, ".");
            const slot = std.fmt.parseInt(Slot, fiter.next().?, 10) catch continue;
            if (fields.file_map.contains(slot)) {
                n_account_files += 1;
            }
        }
        self.logger.infof("found {d} account files", .{n_account_files});
        std.debug.assert(n_account_files > 0);

        const use_disk_index = self.config.disk_index_path != null;
        if (use_disk_index) {
            self.logger.info("using disk index");
        } else {
            self.logger.info("using ram index");
        }

        // short path
        if (n_threads == 1) {
            try self.loadAndVerifyAccountsFiles(
                accounts_path,
                filenames.items,
                ACCOUNTS_PER_FILE_EST,
                true,
            );
            return;
        }

        // setup the parallel indexing
        var loading_threads = try ArrayList(AccountsDB).initCapacity(
            self.allocator,
            n_parse_threads,
        );
        for (0..n_parse_threads) |_| {
            var thread_db = try AccountsDB.init(
                per_thread_allocator,
                self.logger,
                .{ .number_of_index_bins = self.config.number_of_index_bins },
            );

            thread_db.fields = self.fields;
            if (use_disk_index) {
                thread_db.disk_allocator_ptr = self.disk_allocator_ptr;
            }
            loading_threads.appendAssumeCapacity(thread_db);
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
                loading_thread.storage.file_map.deinit();
                loading_thread.storage.cache.deinit();
                // NOTE: important `false` (ie, 1))
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
                    filenames.items,
                    accounts_path,
                },
                filenames.items.len,
                n_parse_threads,
            );
        }

        self.logger.infof("total time: {s}", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        self.logger.infof("combining thread accounts...", .{});
        try self.mergeMultipleDBs(loading_threads.items, n_combine_threads);
        self.logger.debugf("combining thread indexes took: {s}", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();
    }

    /// multithread entrypoint into parseAndBinAccountFiles.
    /// Assumes that `loading_threads[thread_id].fields != null`.
    pub fn loadAndVerifyAccountsFilesMultiThread(
        loading_threads: []AccountsDB,
        filenames: [][]const u8,
        accounts_dir_path: []const u8,
        // task specific
        start_index: usize,
        end_index: usize,
        thread_id: usize,
    ) !void {
        const thread_db = &loading_threads[thread_id];
        const thread_filenames = filenames[start_index..end_index];

        try thread_db.loadAndVerifyAccountsFiles(
            accounts_dir_path,
            thread_filenames,
            ACCOUNTS_PER_FILE_EST,
            thread_id == 0,
        );
    }

    /// loads and verifies the account files into the threads file map
    /// and stores the accounts into the threads index
    /// Assumes `self.fields != null`.
    pub fn loadAndVerifyAccountsFiles(
        self: *Self,
        accounts_dir_path: []const u8,
        file_names: [][]const u8,
        accounts_per_file_est: usize,
        // when we multithread this function we only want to print on the first thread
        print_progress: bool,
    ) !void {
        std.debug.assert(self.fields != null);

        var file_map = &self.storage.file_map;
        try file_map.ensureTotalCapacity(file_names.len);

        const bin_counts = try self.allocator.alloc(usize, self.account_index.numberOfBins());
        defer self.allocator.free(bin_counts);
        @memset(bin_counts, 0);

        const n_accounts_est = file_names.len * accounts_per_file_est;
        const refs_ptr = blk: {
            var memory = try ArrayList(AccountRef).initCapacity(self.account_index.reference_allocator, n_accounts_est);
            errdefer memory.deinit();
            break :blk try self.account_index.addMemoryBlock(memory);
        };

        // NOTE: might need to be longer depending on abs path length
        var buf: [1024]u8 = undefined;
        var timer = try std.time.Timer.start();
        var progress_timer = try std.time.Timer.start();

        for (file_names, 1..) |file_name, file_count| {
            // parse "{slot}.{id}" from the file_name
            var fiter = std.mem.tokenizeSequence(u8, file_name, ".");
            const slot = std.fmt.parseInt(Slot, fiter.next().?, 10) catch |err| {
                self.logger.warnf("failed to parse slot from {s}", .{file_name});
                return err;
            };
            const accounts_file_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

            // read metadata
            const file_infos: ArrayList(AccountFileInfo) = self.fields.?.file_map.get(slot) orelse {
                // dont read account files which are not in the file_map
                // note: this can happen when we load from a snapshot and there are extra account files
                // in the directory which dont correspond to the snapshot were loading
                self.logger.warnf("failed to read metadata for slot {d}", .{slot});
                continue;
            };
            // if this is hit, its likely an old snapshot
            if (file_infos.items.len != 1) {
                std.debug.panic("incorrect file_info count for slot {d}, likley trying to load from an unsupported snapshot\n", .{slot});
            }
            const file_info = file_infos.items[0];
            if (file_info.id != accounts_file_id) {
                std.debug.panic("file_info.id ({d}) != accounts_file_id ({d})\n", .{ file_info.id, accounts_file_id });
            }

            // read accounts file
            const abs_path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ accounts_dir_path, file_name });
            const accounts_file_file = try std.fs.cwd().openFile(abs_path, .{ .mode = .read_write });
            var accounts_file = AccountFile.init(accounts_file_file, file_info, slot) catch |err| {
                std.debug.panic("failed to *open* AccountsFile {s}: {s}\n", .{ file_name, @errorName(err) });
            };

            // validate and count here for prealloc
            self.account_index.validateAccountFile(&accounts_file, bin_counts, refs_ptr) catch |err| {
                std.debug.panic("failed to *sanitize* AccountsFile: {d}.{d}: {s}\n", .{ accounts_file.slot, accounts_file.id, @errorName(err) });
            };

            const file_id = FileId.fromInt(@intCast(accounts_file_id));
            file_map.putAssumeCapacityNoClobber(file_id, accounts_file);

            if (print_progress and progress_timer.read() > DB_PROGRESS_UPDATES_NS) {
                printTimeEstimate(
                    self.logger,
                    &timer,
                    file_names.len,
                    file_count,
                    "loading account files",
                    "thread0",
                );
                progress_timer.reset();
            }
        }

        // free extra memory
        refs_ptr.shrinkAndFree(refs_ptr.items.len);

        // allocate enough memory for the bins
        var total_accounts: usize = 0;
        for (bin_counts, 0..) |count, bin_index| {
            if (count > 0) {
                try self.account_index.getBin(bin_index).ensureTotalCapacity(@intCast(count));
                total_accounts += count;
            }
        }

        // // NOTE: this is good for debugging what to set `accounts_per_file_est` to
        // std.debug.print("n_accounts vs estimated: {d} vs {d}", .{ total_accounts, n_accounts_est });

        // TODO: PERF: can probs be faster if you sort the pubkeys first, and then you know
        // it will always be a search for a free spot, and not search for a match

        timer.reset();
        // compute how many account_references for each pubkey
        for (refs_ptr.items, 1..) |*ref, ref_count| {
            _ = self.account_index.indexRefIfNotDuplicateSlot(ref);

            if (print_progress and progress_timer.read() > DB_PROGRESS_UPDATES_NS) {
                printTimeEstimate(
                    self.logger,
                    &timer,
                    refs_ptr.items.len,
                    ref_count,
                    "building index",
                    null,
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

        // push underlying memory to index
        const index_allocator = self.account_index.allocator;
        const head = try index_allocator.create(RefMemoryLinkedList);
        head.* = .{
            .memory = thread_dbs[0].account_index.memory_linked_list.?.memory,
        };
        var curr = head;
        for (1..thread_dbs.len) |i| {
            // sometimes not all threads are spawned
            if (thread_dbs[i].account_index.memory_linked_list) |memory_linked_list| {
                const ref = try index_allocator.create(RefMemoryLinkedList);
                ref.* = .{ .memory = memory_linked_list.memory };
                curr.next_ptr = ref;
                curr = ref;
            } else {
                break;
            }
        }
        self.account_index.memory_linked_list = head;

        // combine file maps
        for (thread_dbs) |*task| {
            var iter = task.storage.file_map.iterator();
            while (iter.next()) |entry| {
                try self.storage.file_map.putNoClobber(entry.key_ptr.*, entry.value_ptr.*);
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
        var timer = try std.time.Timer.start();
        var progress_timer = try std.time.Timer.start();
        const print_progress = thread_id == 0;

        for (bin_start_index..bin_end_index, 1..) |bin_index, iteration_count| {
            const index_bin = index.getBin(bin_index);

            // sum size across threads
            var bin_n_accounts: usize = 0;
            for (thread_dbs) |*thread_db| {
                bin_n_accounts += thread_db.account_index.getBin(bin_index).count();
            }
            // prealloc
            if (bin_n_accounts > 0) {
                try index_bin.ensureTotalCapacity(@intCast(bin_n_accounts));
            }

            for (thread_dbs) |*thread_db| {
                const thread_refs = thread_db.account_index.getBin(bin_index);
                // insert all of the thread entries into the main index
                var iter = thread_refs.iterator();
                while (iter.next()) |thread_entry| {
                    const thread_ref_ptr = thread_entry.value_ptr.*;
                    // NOTE: we dont have to check for duplicates because the duplicate
                    // slots have already been handled in the prev step
                    index.indexRef(thread_ref_ptr);
                }
            }

            if (print_progress and progress_timer.read() > DB_PROGRESS_UPDATES_NS) {
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
        // compute hash from (..., max_slot]
        FullAccountHash: struct {
            max_slot: Slot,
        },
        // compute hash from (min_slot, ...)
        IncrementalAccountHash: struct {
            min_slot: Slot,
        },
    };

    /// computes a hash across all accounts in the db, and total lamports of those accounts
    /// using index data. depending on the config, this can compute
    /// either full or incremental snapshot values.
    pub fn computeAccountHashesAndLamports(self: *Self, config: AccountHashesConfig) !struct { accounts_hash: Hash, total_lamports: u64 } {
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
            .accounts_hash = accounts_hash.*,
            .total_lamports = total_lamports,
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
    ) !void {
        const expected_accounts_hash = self.fields.?.bank_hash_info.accounts_hash;

        // validate the full snapshot
        self.logger.infof("validating the full snapshot", .{});
        const full_result = try self.computeAccountHashesAndLamports(AccountHashesConfig{
            .FullAccountHash = .{
                .max_slot = full_snapshot_slot,
            },
        });

        const total_lamports = full_result.total_lamports;
        const accounts_hash = full_result.accounts_hash;

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
        if (incremental_snapshot_persistence == null) return;
        self.logger.infof("validating the incremental snapshot", .{});
        const expected_accounts_delta_hash = incremental_snapshot_persistence.?.incremental_hash;
        const expected_incremental_lamports = incremental_snapshot_persistence.?.incremental_capitalization;

        const incremental_result = try self.computeAccountHashesAndLamports(AccountHashesConfig{
            .IncrementalAccountHash = .{
                .min_slot = full_snapshot_slot,
            },
        });
        const incremental_lamports = incremental_result.total_lamports;
        const accounts_delta_hash = incremental_result.accounts_hash;

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
        thread_bins: []const AccountIndex.RefMap,
        hashes_allocator: std.mem.Allocator,
        hashes: *ArrayListUnmanaged(Hash),
        total_lamports: *u64,
        // when we multithread this function we only want to print on the first thread
        print_progress: bool,
    ) !void {
        var total_n_pubkeys: usize = 0;
        for (thread_bins) |*bin| {
            total_n_pubkeys += bin.count();
        }
        try hashes.ensureTotalCapacity(hashes_allocator, total_n_pubkeys);

        // well reuse this over time so this is ok (even if 1k is an under estimate)
        var keys = try self.allocator.alloc(Pubkey, 1_000);
        defer self.allocator.free(keys);

        var local_total_lamports: u64 = 0;
        var timer = try std.time.Timer.start();
        var progress_timer = try std.time.Timer.start();
        for (thread_bins, 1..) |*bin_ptr, count| {
            // get and sort pubkeys in bin
            const bin_refs = bin_ptr;
            const n_pubkeys_in_bin = bin_refs.count();
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
            var key_iter = bin_refs.iterator();
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
                const ref_ptr = bin_refs.get(key).?;

                // get the most recent state of the account
                const max_slot_ref = switch (config) {
                    .FullAccountHash => |full_config| slotListMaxWithinBounds(ref_ptr, null, full_config.max_slot),
                    .IncrementalAccountHash => |inc_config| slotListMaxWithinBounds(ref_ptr, inc_config.min_slot, null),
                } orelse continue;
                const result = try self.getAccountHashAndLamportsFromRef(max_slot_ref);

                const lamports = result.lamports;
                var account_hash = result.hash;
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
                        const account = try self.getAccountFromRef(max_slot_ref);
                        account_hash = account.hash(&key);
                    }
                }

                hashes.appendAssumeCapacity(account_hash);
                local_total_lamports += lamports;
            }

            if (print_progress and progress_timer.read() > DB_PROGRESS_UPDATES_NS) {
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

    /// writes a batch of accounts to storage and updates the index
    pub fn putAccountBatch(
        self: *Self,
        accounts: []Account,
        pubkeys: []Pubkey,
        slot: Slot,
    ) !void {
        std.debug.assert(accounts.len == pubkeys.len);

        // store account
        const cache_index_start = self.storage.cache.items.len;
        try self.storage.cache.appendSlice(accounts);

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
            const bin = self.account_index.getBin(bin_index);
            const new_len = bin_counts[bin_index] + bin.count();
            if (new_len > 0) {
                try bin.ensureTotalCapacity(@intCast(new_len));
            }
        }

        // update index
        const reference_allocator = self.account_index.reference_allocator;
        var refs = try ArrayList(AccountRef).initCapacity(reference_allocator, accounts.len);
        for (0..accounts.len) |i| {
            const account_ref = AccountRef{
                .pubkey = pubkeys[i],
                .slot = slot,
                .location = .{
                    .Cache = .{ .index = cache_index_start + i },
                },
            };
            refs.appendAssumeCapacity(account_ref);
            self.account_index.indexRef(&refs.items[i]);
        }
        _ = try self.account_index.addMemoryBlock(refs);
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

    pub fn getAccountFromRef(self: *const Self, account_ref: *const AccountRef) !Account {
        switch (account_ref.location) {
            .File => |ref_info| {
                const account_in_file = try self.storage.getAccountInFile(
                    ref_info.file_id,
                    ref_info.offset,
                );
                const account = Account{
                    .data = account_in_file.data,
                    .executable = account_in_file.executable().*,
                    .lamports = account_in_file.lamports().*,
                    .owner = account_in_file.owner().*,
                    .rent_epoch = account_in_file.rent_epoch().*,
                };
                return account;
            },
            .Cache => |ref_info| {
                const account = self.storage.cache.items[ref_info.index];
                return account;
            },
        }
    }

    pub fn getAccountHashAndLamportsFromRef(
        self: *const Self,
        account_ref: *const AccountRef,
    ) !struct { hash: Hash, lamports: u64 } {
        switch (account_ref.location) {
            .File => |ref_info| {
                const account_file = self.storage.getAccountFile(
                    ref_info.file_id,
                ) orelse return error.FileNotFound;

                const result = account_file.getAccountHashAndLamports(
                    ref_info.offset,
                ) catch return error.InvalidOffset;

                return .{
                    .hash = result.hash.*,
                    .lamports = result.lamports.*,
                };
            },
            .Cache => |_| {
                return error.NotImplemented;
            },
        }
    }

    /// gets an account given an associated pubkey
    pub fn getAccount(self: *const Self, pubkey: *const Pubkey) !Account {
        const bin = self.account_index.getBinFromPubkey(pubkey);
        const ref = bin.get(pubkey.*) orelse return error.PubkeyNotInIndex;
        // NOTE: this will always be a safe unwrap since both bounds are null
        const max_ref = slotListMaxWithinBounds(ref, null, null).?;
        const account = try self.getAccountFromRef(max_ref);
        return account;
    }

    pub fn getTypeFromAccount(self: *const Self, comptime T: type, pubkey: *const Pubkey) !T {
        const account = try self.getAccount(pubkey);
        const t = bincode.readFromSlice(self.allocator, T, account.data, .{}) catch {
            return error.DeserializationError;
        };
        return t;
    }

    pub fn getSlotHistory(self: *const Self) !sysvars.SlotHistory {
        return try self.getTypeFromAccount(
            sysvars.SlotHistory,
            &sysvars.IDS.slot_history,
        );
    }

    pub fn putAccountFile(
        self: *Self,
        account_file: *AccountFile,
        n_accounts: usize,
    ) !void {
        const bin_counts = try self.allocator.alloc(usize, self.account_index.numberOfBins());
        defer self.allocator.free(bin_counts);
        @memset(bin_counts, 0);

        const reference_allocator = self.account_index.reference_allocator;
        var refs = try ArrayList(AccountRef).initCapacity(reference_allocator, n_accounts);

        try self.account_index.validateAccountFile(account_file, bin_counts, &refs);
        try self.storage.file_map.put(FileId.fromInt(@intCast(account_file.id)), account_file.*);
        const refs_ptr = try self.account_index.addMemoryBlock(refs);

        // allocate enough memory here
        var total_accounts: usize = 0;
        for (bin_counts, 0..) |count, bin_index| {
            if (count > 0) {
                const bin = self.account_index.getBin(bin_index);
                try bin.ensureTotalCapacity(bin.count() + count);
                total_accounts += count;
            }
        }

        // compute how many account_references for each pubkey
        for (refs_ptr.items) |*ref| {
            self.account_index.indexRef(ref);
        }
    }
};

/// where accounts are stored
pub const AccountStorage = struct {
    file_map: std.AutoArrayHashMap(FileId, AccountFile),
    cache: std.ArrayList(Account),

    pub fn init(allocator: std.mem.Allocator, cache_size: usize) !AccountStorage {
        return AccountStorage{
            .file_map = std.AutoArrayHashMap(FileId, AccountFile).init(allocator),
            .cache = try std.ArrayList(Account).initCapacity(allocator, cache_size),
        };
    }

    pub fn deinit(self: *AccountStorage) void {
        for (self.file_map.values()) |*af| {
            af.deinit();
        }
        self.file_map.deinit();
        self.cache.deinit();
    }

    pub fn getAccountFile(self: *const AccountStorage, file_id: FileId) ?AccountFile {
        return self.file_map.get(file_id);
    }

    /// gets an account given an file_id and offset value
    pub fn getAccountInFile(
        self: *const AccountStorage,
        file_id: FileId,
        offset: usize,
    ) !AccountInFile {
        const accounts_file: AccountFile = self.getAccountFile(file_id) orelse {
            return error.FileIdNotFound;
        };
        const account = accounts_file.readAccount(offset) catch {
            return error.InvalidOffset;
        };
        return account;
    }
};

fn loadTestAccountsDB(use_disk: bool) !struct { AccountsDB, AllSnapshotFields } {
    std.debug.assert(builtin.is_test); // should only be used in tests
    var allocator = std.testing.allocator;

    const dir_path = "test_data";
    const dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });

    // unpack both snapshots to get the acccount files
    try parallelUnpackZstdTarBall(
        allocator,
        .noop,
        "test_data/snapshot-10-6ExseAZAVJsAZjhimxHTR7N8p6VGXiDNdsajYh1ipjAD.tar.zst",
        dir,
        1,
        true,
    );
    try parallelUnpackZstdTarBall(
        allocator,
        .noop,
        "test_data/incremental-snapshot-10-25-GXgKvm3NMAPgGdv2verVaNXmKTHQgfy2TAxLVEfAvdCS.tar.zst",
        dir,
        1,
        true,
    );

    var snapshot_files = try SnapshotFiles.find(allocator, dir_path);
    defer snapshot_files.deinit(allocator);

    var snapshots = try AllSnapshotFields.fromFiles(allocator, dir_path, snapshot_files);
    defer {
        allocator.free(snapshots.full_path);
        if (snapshots.incremental_path) |inc_path| {
            allocator.free(inc_path);
        }
    }

    var disk_dir: ?[]const u8 = null;
    var disk_capacity: usize = 0;
    if (use_disk) {
        disk_dir = "test_data/tmp";
        try std.fs.cwd().makePath(disk_dir.?);
        disk_capacity = 1000;
    }

    const snapshot = try snapshots.all_fields.collapse();
    const logger = Logger{ .noop = {} };
    // var logger = Logger.init(std.heap.page_allocator, .debug);
    // logger.spawn();

    var accounts_db = try AccountsDB.init(allocator, logger, .{
        .number_of_index_bins = 4,
        .storage_cache_size = 10,
        .disk_index_path = disk_dir,
        .index_disk_capacity = disk_capacity,
    });

    const accounts_path = "test_data/accounts";
    try accounts_db.loadFromSnapshot(
        snapshot.accounts_db_fields,
        accounts_path,
        1,
        allocator,
    );

    return .{
        accounts_db,
        snapshots.all_fields,
    };
}

test "accounts_db.db: write and read an account" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(false);
    defer {
        accounts_db.deinit();
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
    try accounts_db.putAccountBatch(&accounts, &pubkeys, 19);
    const account = try accounts_db.getAccount(&pubkey);
    try std.testing.expect(std.meta.eql(test_account, account));

    // new account
    accounts[0].lamports = 20;
    try accounts_db.putAccountBatch(&accounts, &pubkeys, 28);
    const account_2 = try accounts_db.getAccount(&pubkey);
    try std.testing.expect(std.meta.eql(accounts[0], account_2));
}

test "accounts_db.db: load and validate from test snapshot using disk index" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(true);
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    try accounts_db.validateLoadFromSnapshot(
        snapshots.incremental.?.bank_fields.incremental_snapshot_persistence,
        snapshots.full.bank_fields.slot,
        snapshots.full.bank_fields.capitalization,
    );
}

test "accounts_db.db: load and validate from test snapshot" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(false);
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    try accounts_db.validateLoadFromSnapshot(
        snapshots.incremental.?.bank_fields.incremental_snapshot_persistence,
        snapshots.full.bank_fields.slot,
        snapshots.full.bank_fields.capitalization,
    );
}

test "accounts_db.db: load clock sysvar" {
    const allocator = std.testing.allocator;

    var accounts_db, var snapshots = try loadTestAccountsDB(false);
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

test "accounts_db.db: load other sysvars" {
    const allocator = std.testing.allocator;

    var accounts_db: AccountsDB, var snapshots: AllSnapshotFields = try loadTestAccountsDB(false);
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

pub const BenchmarkAccountsDB = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 2;

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

    pub fn readAccounts(bench_args: BenchArgs) !u64 {
        const n_accounts = bench_args.n_accounts;
        const slot_list_len = bench_args.slot_list_len;
        const total_n_accounts = n_accounts * slot_list_len;

        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        var allocator = gpa.allocator();

        const disk_path = "test_data/tmp/";
        std.fs.cwd().makeDir(disk_path) catch {};

        const logger = Logger{ .noop = {} };
        var accounts_db: AccountsDB = undefined;
        if (bench_args.index == .disk) {
            // std.debug.print("using disk index\n", .{});
            accounts_db = try AccountsDB.init(allocator, logger, .{
                .disk_index_path = disk_path ++ "tmp",
            });
        } else {
            // std.debug.print("using ram index\n", .{});
            accounts_db = try AccountsDB.init(allocator, logger, .{});
        }
        defer accounts_db.deinit();

        var random = std.rand.DefaultPrng.init(19);
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
            var accounts = try allocator.alloc(Account, (total_n_accounts + n_accounts_init));
            for (0..(total_n_accounts + n_accounts_init)) |i| {
                accounts[i] = try Account.random(allocator, rng, i % 1_000);
            }

            if (n_accounts_init > 0) {
                try accounts_db.putAccountBatch(
                    accounts[total_n_accounts..(total_n_accounts + n_accounts_init)],
                    pubkeys,
                    @as(u64, @intCast(0)),
                );
            }

            var timer = try std.time.Timer.start();
            try accounts_db.storage.cache.ensureTotalCapacity(total_n_accounts);
            for (0..slot_list_len) |i| {
                const start_index = i * n_accounts;
                const end_index = start_index + n_accounts;
                try accounts_db.putAccountBatch(
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
                        offset += try account.writeToBuf(&pubkey, memory[offset..]);
                    }
                    break :blk offset;
                };

                var account_file = blk: {
                    const file = try std.fs.cwd().openFile(filepath, .{ .mode = .read_write });
                    errdefer file.close();
                    break :blk try AccountFile.init(file, .{ .id = s, .length = length }, s);
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
