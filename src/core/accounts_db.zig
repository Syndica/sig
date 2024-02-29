const std = @import("std");
const builtin = @import("builtin");
const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;

const Account = @import("../core/account.zig").Account;
const hashAccount = @import("../core/account.zig").hashAccount;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/time.zig").Slot;
const Epoch = @import("../core/time.zig").Epoch;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");

const sysvars = @import("../core/sysvars.zig");

const AccountsDbFields = @import("../core/snapshots.zig").AccountsDbFields;
const AccountFileInfo = @import("../core/snapshots.zig").AccountFileInfo;

const AccountFile = @import("../core/accounts_file.zig").AccountFile;
const FileId = @import("../core/accounts_file.zig").FileId;
const AccountInFile = @import("../core/accounts_file.zig").AccountInFile;
const computeSizeInFile = @import("../core/accounts_file.zig").computeSizeInFile;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

const NestedHashTree = @import("../common/merkle_tree.zig").NestedHashTree;

const GenesisConfig = @import("../core/genesis_config.zig").GenesisConfig;
const StatusCache = @import("../core/snapshots.zig").StatusCache;

const SnapshotFields = @import("../core/snapshots.zig").SnapshotFields;
const BankIncrementalSnapshotPersistence = @import("../core/snapshots.zig").BankIncrementalSnapshotPersistence;

const Bank = @import("./bank.zig").Bank;
const readDirectory = @import("../utils/directory.zig").readDirectory;

const SnapshotPaths = @import("./snapshots.zig").SnapshotPaths;
const AllSnapshotFields = @import("./snapshots.zig").AllSnapshotFields;

const Logger = @import("../trace/log.zig").Logger;
const Level = @import("../trace/level.zig").Level;

const printTimeEstimate = @import("../time/estimate.zig").printTimeEstimate;
const parallelUnpackZstdTarBall = @import("./snapshots.zig").parallelUnpackZstdTarBall;

pub const MERKLE_FANOUT: usize = 16;
pub const ACCOUNT_INDEX_BINS: usize = 8192;

pub const AccountRef = struct {
    pubkey: Pubkey,
    slot: Slot,
    location: AccountLocation,

    pub const AccountLocation = union(enum(u8)) {
        File: struct {
            file_id: u32,
            offset: usize,
        },
        Cache: struct {
            index: usize,
        },
    };

    pub fn default() AccountRef {
        return AccountRef{
            .pubkey = Pubkey.default(),
            .slot = 0,
            .location = .{
                .Cache = .{ .index = 0 },
            },
        };
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

    pub fn deinit(self: *AccountStorage) void {
        for (self.file_map.values()) |*af| {
            af.deinit();
        }
        self.file_map.deinit();
        self.cache.deinit();
    }
};

pub const AccountsDBConfig = struct {
    // number of Accounts to preallocate for cache
    storage_cache_size: usize = 10_000,
    // number of bins to shard the index pubkeys across -- must be power of two
    n_index_bins: usize = ACCOUNT_INDEX_BINS,
    // how many RAM references to preallocate for each bin
    index_ram_capacity: usize = 0,
    // where to create disk indexes files (if null, will not use disk indexes)
    disk_index_dir: ?[]const u8 = null,
    // how many DISK references to preallocate for each bin
    index_disk_capacity: usize = 0,
};

const PubkeyCountMap = FastMap(Pubkey, usize, pubkey_hash, pubkey_eql);

pub const AccountsDB = struct {
    allocator: std.mem.Allocator,

    // holds the account data
    storage: AccountStorage,
    // maps a pubkey to the account location
    index: AccountIndex,
    fields: AccountsDbFields = undefined,
    logger: Logger,
    config: AccountsDBConfig,

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

        var disk_index_config: ?DiskMemoryConfig = null;
        if (config.disk_index_dir != null) {
            disk_index_config = DiskMemoryConfig{
                .dir_path = config.disk_index_dir.?,
                .capacity = config.index_disk_capacity,
            };
        }

        const index = try AccountIndex.init(
            allocator,
            config.n_index_bins,
            RamMemoryConfig{
                .capacity = config.index_ram_capacity,
            },
            disk_index_config,
        );

        return Self{
            .storage = storage,
            .index = index,
            .allocator = allocator,
            .logger = logger,
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        self.storage.deinit();
        self.index.deinit();
        self.logger.deinit();
    }

    /// used to build AccountsDB from a snapshot in parallel
    pub const LoadingThreadAccountsDB = struct {
        index: AccountIndex,
        file_map: std.AutoArrayHashMap(FileId, AccountFile),
        pubkey_counts: PubkeyCountMap = undefined,
        account_refs_memory: []u8 = undefined,
        n_accounts: usize = 0,

        pub fn init(
            allocator: std.mem.Allocator,
            n_bins: usize,
            ram_config: RamMemoryConfig,
            disk_config: ?DiskMemoryConfig,
        ) !@This() {
            var self = @This(){
                .index = try AccountIndex.init(allocator, n_bins, ram_config, disk_config),
                .file_map = std.AutoArrayHashMap(FileId, AccountFile).init(allocator),
            };
            return self;
        }

        pub fn deinit(self: *@This()) void {
            std.heap.page_allocator.free(self.account_refs_memory);
            self.index.allocator.free(self.pubkey_counts);
            self.file_map.deinit();
            self.index.deinit();
            self.pubkey_counts.deinit();
        }
    };

    /// loads the account files and indexes the accounts from a snapshot
    pub fn loadFromSnapshot(
        self: *Self,
        // fields from the snapshot
        fields: AccountsDbFields,
        // where the account files are
        accounts_path: []const u8,
    ) !void {
        self.fields = fields;

        // start the indexing
        var timer = std.time.Timer.start() catch unreachable;
        timer.reset();

        var accounts_dir = try std.fs.cwd().openIterableDir(accounts_path, .{});
        defer accounts_dir.close();

        // read account files
        var files = try readDirectory(self.allocator, accounts_dir);
        var filenames = files.filenames;
        defer {
            filenames.deinit();
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
        self.logger.infof("found {d} account files\n", .{n_account_files});
        std.debug.assert(n_account_files > 0);

        const use_disk_index = self.index.use_disk;

        // TODO: THESE LEAK -- TMP SOLN FOR THE TESTS
        const page_allocator = std.heap.page_allocator;

        const n_bins = self.index.bins.len;
        const n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;
        var thread_dbs = try ArrayList(LoadingThreadAccountsDB).initCapacity(
            page_allocator, // TODO: LEAK
            n_threads,
        );
        var thread_disk_dirs = ArrayList([]const u8).init(self.allocator);
        for (0..n_threads) |thread_i| {
            if (!use_disk_index) {
                const t_index = try LoadingThreadAccountsDB.init(
                    page_allocator, // TODO: LEAK
                    n_bins,
                    // pre-alloc happens in the thread
                    RamMemoryConfig{ .capacity = 0 },
                    null,
                );
                thread_dbs.appendAssumeCapacity(t_index);
            } else {
                const thread_disk_dir = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}/thread_{d}",
                    .{ self.config.disk_index_dir.?, thread_i },
                );
                try thread_disk_dirs.append(thread_disk_dir);

                // pre-alloc happens in the thread
                const t_index = try LoadingThreadAccountsDB.init(
                    page_allocator, // TODO: LEAK
                    n_bins,
                    .{},
                    DiskMemoryConfig{ .dir_path = thread_disk_dir, .capacity = 0 },
                );
                thread_dbs.appendAssumeCapacity(t_index);
            }
        }
        defer {
            // all thread specific values will be copied to the main allocator
            // so we can deinit them here
            // for (thread_dbs.items) |*ti| {
            //     ti.deinit();
            // }
            // thread_dbs.deinit();

            if (use_disk_index) {
                for (thread_disk_dirs.items) |thread_disk_dir| {
                    std.fs.cwd().deleteTree(thread_disk_dir) catch |err| {
                        self.logger.errf("failed to delete disk mem {s}: {s}\n", .{ thread_disk_dir, @errorName(err) });
                    };
                    self.allocator.free(thread_disk_dir);
                }
                thread_disk_dirs.deinit();
            }
        }

        self.logger.infof("reading and binning accounts...", .{});
        var handles = try spawnThreadTasks(
            self.allocator,
            parseAndBinAccountFiles,
            .{
                &fields,
                accounts_path,
                thread_dbs.items,
                filenames.items,
            },
            filenames.items.len,
            n_threads,
        );

        for (handles.items) |handle| {
            handle.join();
        }
        handles.deinit();

        self.logger.infof("\n", .{});
        self.logger.infof("total time: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        var total_accounts: usize = 0;
        for (0..n_bins) |i| {
            // sum size across threads
            var bin_n_accounts: usize = 0;
            for (thread_dbs.items) |*t_db| {
                bin_n_accounts += t_db.index.bins[i].getRefs().count();
            }
            // prealloc
            if (bin_n_accounts > 0) {
                try self.index.bins[i].getRefs().ensureTotalCapacity(@intCast(bin_n_accounts));
            }
            total_accounts += bin_n_accounts;
        }
        self.logger.infof("found {d} accounts\n", .{total_accounts});
        timer.reset();

        self.logger.infof("combining thread accounts...\n", .{});
        handles = try spawnThreadTasks(
            self.allocator,
            combineThreadIndexes,
            .{
                &self.index,
                &thread_dbs,
            },
            n_bins,
            n_threads,
        );

        for (thread_dbs.items) |*task| {
            var iter = task.file_map.iterator();
            while (iter.next()) |entry| {
                try self.storage.file_map.putNoClobber(entry.key_ptr.*, entry.value_ptr.*);
            }
        }

        for (handles.items) |handle| {
            handle.join();
        }
        handles.deinit();

        self.logger.debugf("\n", .{});
        self.logger.debugf("combining thread indexes took: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();
    }

    /// loads and verifies the account files
    /// and stores the accounts into the thread-specific index
    /// (ie, thread_indexes[thread_id])
    pub fn parseAndBinAccountFiles(
        fields: *const AccountsDbFields,
        accounts_dir_path: []const u8,
        thread_dbs: []LoadingThreadAccountsDB,
        file_names: [][]const u8,
        // task specific
        start_index: usize,
        end_index: usize,
        thread_id: usize,
    ) !void {
        const thread_db = &thread_dbs[thread_id];
        const thread_index = &thread_db.index;
        const file_map = &thread_db.file_map;
        const thread_filenames = file_names[start_index..end_index];

        try file_map.ensureTotalCapacity(thread_filenames.len);

        var files = try ArrayList(AccountFile).initCapacity(
            file_map.allocator,
            thread_filenames.len,
        );

        var bin_counts = try file_map.allocator.alloc(usize, thread_index.numberOfBins());
        defer file_map.allocator.free(bin_counts);
        @memset(bin_counts, 0);

        var timer = try std.time.Timer.start();
        // NOTE: might need to be longer depending on abs path length
        var buf: [1024]u8 = undefined;
        for (thread_filenames, 1..) |file_name, file_count| {
            // parse "{slot}.{id}" from the file_name
            var fiter = std.mem.tokenizeSequence(u8, file_name, ".");
            const slot = std.fmt.parseInt(Slot, fiter.next().?, 10) catch |err| {
                std.debug.print("failed to parse slot from {s}\n", .{file_name});
                return err;
            };
            const accounts_file_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

            // read metadata
            const file_infos: ArrayList(AccountFileInfo) = fields.file_map.get(slot) orelse {
                // dont read account files which are not in the file_map
                std.debug.print("failed to read metadata for slot {d}\n", .{slot});
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
            thread_index.validateAccountFile(&accounts_file, bin_counts) catch |err| {
                std.debug.panic("failed to *sanitize* AccountsFile: {d}.{d}: {s}\n", .{ accounts_file.slot, accounts_file.id, @errorName(err) });
            };
            files.appendAssumeCapacity(accounts_file);

            const file_id_u32: u32 = @intCast(accounts_file_id);
            file_map.putAssumeCapacityNoClobber(file_id_u32, accounts_file);

            if (file_count % 100 == 0 or (thread_filenames.len - file_count) < 100) {
                printTimeEstimate(&timer, thread_filenames.len, file_count, "reading account files", null);
            }
        }

        var page_allocator = std.heap.page_allocator;

        // allocate enough memory here
        var total_accounts: usize = 0;
        for (bin_counts, 0..) |count, bin_index| {
            if (count > 0) {
                try thread_index.getBin(bin_index).getRefs().ensureTotalCapacity(@intCast(count));
                total_accounts += count;
            }
        }
        thread_db.pubkey_counts = try PubkeyCountMap.initCapacity(page_allocator, total_accounts);
        thread_db.n_accounts = total_accounts;

        const account_references_size = total_accounts * @sizeOf(AccountRef);
        var account_refs_memory = try page_allocator.alloc(u8, account_references_size);
        var fba = std.heap.FixedBufferAllocator.init(account_refs_memory);
        const allocator = fba.allocator();

        thread_db.account_refs_memory = account_refs_memory;

        // compute how many account_references for each pubkey
        // NOTE: need this cound because of the way fixed buffer allocator works with resizing
        for (files.items, 0..) |*accounts_file, file_count| {
            var offset: usize = 0;
            while (true) {
                var result = accounts_file.getAccountPubkey(offset) catch break;
                const pubkey = result.pubkey;

                const map_result = thread_db.pubkey_counts.getOrPutAssumeCapacity(pubkey.*);
                if (map_result.found_existing) {
                    map_result.value_ptr.* += 1;
                } else {
                    map_result.value_ptr.* = 1;
                }
                offset = offset + result.account_len;
            }
            if (file_count % 100 == 0 or (thread_filenames.len - file_count) < 100) {
                printTimeEstimate(&timer, thread_filenames.len, file_count, "allocating reference lists", null);
            }
        }

        timer.reset();
        for (files.items, 0..) |*accounts_file, file_count| {
            var offset: usize = 0;
            while (true) {
                var account = accounts_file.readAccount(offset) catch break;
                const pubkey = account.store_info.pubkey;

                const hash_is_missing = std.mem.eql(u8, &account.hash().data, &Hash.default().data);
                if (hash_is_missing) {
                    const hash = hashAccount(
                        account.account_info.lamports,
                        account.data,
                        &account.account_info.owner.data,
                        account.account_info.executable,
                        account.account_info.rent_epoch,
                        &pubkey.data,
                    );
                    account.hash_ptr.* = hash;
                }

                const account_ref = AccountRef{
                    .pubkey = pubkey,
                    .slot = accounts_file.slot,
                    .location = .{
                        .File = .{
                            .file_id = @as(u32, @intCast(accounts_file.id)),
                            .offset = offset,
                        },
                    },
                };

                try thread_index.putWithCounts(
                    allocator,
                    pubkey,
                    account_ref,
                    &thread_db.pubkey_counts,
                );
                offset = offset + account.len;
            }

            if (file_count % 100 == 0 or (thread_filenames.len - file_count) < 100) {
                printTimeEstimate(&timer, thread_filenames.len, file_count, "indexing account files", null);
            }
        }
    }

    /// combines multiple thread indexes into the given index.
    /// each bin is also sorted by pubkey.
    pub fn combineThreadIndexes(
        index: *AccountIndex,
        thread_dbs: *ArrayList(LoadingThreadAccountsDB),
        //
        bin_start_index: usize,
        bin_end_index: usize,
        thread_id: usize,
    ) !void {
        _ = thread_id;
        const total_bins = bin_end_index - bin_start_index;
        var timer = try std.time.Timer.start();

        var total_accounts: usize = 0;
        for (thread_dbs.items) |*t_db| {
            total_accounts += t_db.n_accounts;
        }

        // TODO: this doubles our memory usage (can we figure out a way to reuse)
        // - may need to rewrite the architechture for this
        const account_references_size = total_accounts * @sizeOf(AccountRef);
        var account_refs_memory = try std.heap.page_allocator.alloc(u8, account_references_size);
        var fba = std.heap.FixedBufferAllocator.init(account_refs_memory);
        const allocator = fba.allocator();
        var pubkey_counts = try PubkeyCountMap.initCapacity(
            std.heap.page_allocator,
            total_accounts,
        );

        for (bin_start_index..bin_end_index, 1..) |bin_index, count| {
            const index_bin = index.getBin(bin_index);
            const index_bin_refs = index_bin.getRefs();

            // re-count everything
            for (thread_dbs.items) |*t_db| {
                const thread_refs = t_db.index.getBin(bin_index).getRefs();
                var iter = thread_refs.iterator();
                while (iter.next()) |entry| {
                    const pubkey = entry.key_ptr.*;
                    const n_refs = t_db.pubkey_counts.get(pubkey).?;
                    const map_result = pubkey_counts.getOrPutAssumeCapacity(pubkey);
                    if (map_result.found_existing) {
                        map_result.value_ptr.* += n_refs;
                    } else {
                        map_result.value_ptr.* = n_refs;
                    }
                }
            }

            // insert it into main index
            for (thread_dbs.items) |*t_db| {
                const thread_bin = t_db.index.getBin(bin_index);
                const thread_refs = thread_bin.getRefs();
                var iter = thread_refs.iterator();

                while (iter.next()) |entry| {
                    const pubkey = entry.key_ptr.*;
                    const get_result = index_bin_refs.getOrPutAssumeCapacity(pubkey);
                    if (!get_result.found_existing) {
                        const ref_count = pubkey_counts.getOrPutAssumeCapacity(pubkey).value_ptr.*;
                        get_result.value_ptr.* = try SlotList.initCapacity(allocator, ref_count);
                    }
                    get_result.value_ptr.appendSliceAssumeCapacity(entry.value_ptr.items);
                }
            }
            printTimeEstimate(&timer, total_bins, count, "combining thread indexes", null);
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
        var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;

        // alloc the result
        var hashes = try self.allocator.alloc(ArrayList(Hash), n_threads);
        for (hashes) |*h| {
            h.* = ArrayList(Hash).init(self.allocator);
        }
        var lamports = try self.allocator.alloc(u64, n_threads);
        @memset(lamports, 0);
        defer {
            for (hashes) |*h| h.deinit();
            self.allocator.free(hashes);
            self.allocator.free(lamports);
        }

        // split processing the bins over muliple threads
        self.logger.infof("collecting hashes from accounts...", .{});
        var handles = try spawnThreadTasks(
            self.allocator,
            getHashesFromIndex,
            .{
                self,
                config,
                hashes,
                lamports,
            },
            self.index.numberOfBins(),
            n_threads,
        );

        for (handles.items) |handle| {
            handle.join();
        }
        handles.deinit();

        self.logger.debugf("\n", .{});
        self.logger.debugf("took: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        self.logger.infof("computing the merkle root over accounts...\n", .{});
        var hash_tree = NestedHashTree{ .hashes = hashes };
        const accounts_hash = try hash_tree.computeMerkleRoot(MERKLE_FANOUT);

        self.logger.debugf("took {s}\n", .{std.fmt.fmtDuration(timer.read())});
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
        const expected_accounts_hash = self.fields.bank_hash_info.accounts_hash;

        // validate the full snapshot
        self.logger.infof("validating the full snapshot\n", .{});
        const full_result = try self.computeAccountHashesAndLamports(AccountHashesConfig{
            .FullAccountHash = .{
                .max_slot = full_snapshot_slot,
            },
        });

        // std.mem.doNotOptimizeAway(full_result);
        // _ = expected_full_lamports;
        // _ = expected_accounts_hash;

        const total_lamports = full_result.total_lamports;
        const accounts_hash = full_result.accounts_hash;

        if (expected_accounts_hash.cmp(&accounts_hash) != .eq) {
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
        self.logger.infof("validating the incremental snapshot\n", .{});
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

        if (expected_accounts_delta_hash.cmp(&accounts_delta_hash) != .eq) {
            self.logger.errf(
                \\ incorrect accounts delta hash
                \\ expected vs calculated: {d} vs {d}
            , .{ expected_accounts_delta_hash, accounts_delta_hash });
            return error.IncorrectAccountsDeltaHash;
        }
    }

    /// populates the account hashes and total lamports for a given bin range
    /// from bin_start_index to bin_end_index.
    pub fn getHashesFromIndex(
        self: *AccountsDB,
        config: AccountsDB.AccountHashesConfig,
        hashes: []ArrayList(Hash),
        total_lamports: []u64,
        // spawing thread specific params
        bin_start_index: usize,
        bin_end_index: usize,
        thread_index: usize,
    ) !void {
        const thread_bins = self.index.bins[bin_start_index..bin_end_index];
        const thread_hashes = &hashes[thread_index];

        var total_len: usize = 0;
        for (thread_bins) |*bin| {
            total_len += bin.getRefs().count();
        }
        try thread_hashes.ensureTotalCapacity(total_len);

        var keys = try self.allocator.alloc(Pubkey, 1_000);
        defer self.allocator.free(keys);

        var local_total_lamports: u64 = 0;
        var timer = try std.time.Timer.start();
        for (thread_bins, 1..) |*bin_ptr, count| {
            const bin_refs = bin_ptr.getRefs();

            const n_keys = bin_refs.count();
            if (n_keys == 0) {
                continue;
            }
            if (n_keys > keys.len) {
                if (!self.allocator.resize(keys, n_keys)) {
                    self.allocator.free(keys);
                    keys = try self.allocator.alloc(Pubkey, n_keys);
                }
            }

            var i: usize = 0;
            var key_iter = bin_refs.iterator();
            while (key_iter.next()) |entry| {
                keys[i] = entry.key_ptr.*;
                i += 1;
            }

            std.mem.sort(Pubkey, keys[0..n_keys], {}, struct {
                fn lessThan(_: void, lhs: Pubkey, rhs: Pubkey) bool {
                    return std.mem.lessThan(u8, &lhs.data, &rhs.data);
                }
            }.lessThan);

            for (keys[0..n_keys]) |key| {
                const slot_list = bin_refs.get(key).?;
                std.debug.assert(slot_list.items.len > 0);

                // get the most recent state of the account
                const max_slot_index = switch (config) {
                    .FullAccountHash => |full_config| AccountsDB.slotListArgmaxWithMax(slot_list, full_config.max_slot),
                    .IncrementalAccountHash => |inc_config| AccountsDB.slotListArgmaxWithMin(slot_list, inc_config.min_slot),
                } orelse continue;

                const result = try self.getAccountHashAndLamportsFromRef(&slot_list.items[max_slot_index]);

                // only include non-zero lamport accounts (for full snapshots)
                const lamports = result.lamports;
                if (config == .FullAccountHash and lamports == 0) continue;

                thread_hashes.appendAssumeCapacity(result.hash);
                local_total_lamports += lamports;
            }
            printTimeEstimate(&timer, thread_bins.len, count, "gathering account hashes", null);
        }

        total_lamports[thread_index] = local_total_lamports;
    }

    pub fn indexAccountFile(
        self: *Self,
        account_file: *AccountFile,
    ) !void {
        var bin_counts = try self.allocator.alloc(usize, self.index.numberOfBins());
        defer self.allocator.free(bin_counts);
        @memset(bin_counts, 0);

        try self.index.validateAccountFile(account_file, bin_counts);
        try self.storage.file_map.put(@as(u32, @intCast(account_file.id)), account_file.*);

        // allocate enough memory here
        var timer = try std.time.Timer.start();

        var total_accounts: usize = 0;
        for (bin_counts, 0..) |count, bin_index| {
            if (count > 0) {
                const bin = self.index.getBin(bin_index);
                try bin.getRefs().ensureTotalCapacity(bin.getRefs().count() + count);
                total_accounts += count;
            }
        }
        std.debug.print("bin counting: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        var pubkey_counts = try PubkeyCountMap.initCapacity(self.allocator, total_accounts);
        defer pubkey_counts.deinit();

        var offset: usize = 0;
        while (true) {
            var result = account_file.getAccountPubkey(offset) catch break;
            const pubkey = result.pubkey;
            const map_result = pubkey_counts.getOrPutAssumeCapacity(pubkey.*);
            if (map_result.found_existing) {
                map_result.value_ptr.* += 1;
            } else {
                // in case of resize we need to move all of the existing references + new ones
                if (self.index.getBinFromPubkey(pubkey).getRefs().get(pubkey.*)) |references| {
                    const n_refs = references.items.len + 1;
                    map_result.value_ptr.* = n_refs;
                    total_accounts += n_refs;
                } else {
                    map_result.value_ptr.* = 1;
                }
            }
            offset = offset + result.account_len;
        }
        std.debug.print("pubkey counting: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        const account_references_size = total_accounts * @sizeOf(AccountRef);
        var account_refs_memory = try self.allocator.alloc(u8, account_references_size);
        var fba = std.heap.FixedBufferAllocator.init(account_refs_memory);
        const allocator = fba.allocator();

        offset = 0;
        while (true) {
            var account = account_file.readAccount(offset) catch break;
            const pubkey = account.store_info.pubkey;

            const hash_is_missing = std.mem.eql(u8, &account.hash().data, &Hash.default().data);
            if (hash_is_missing) {
                const hash = hashAccount(
                    account.account_info.lamports,
                    account.data,
                    &account.account_info.owner.data,
                    account.account_info.executable,
                    account.account_info.rent_epoch,
                    &pubkey.data,
                );
                account.hash_ptr.* = hash;
            }

            const account_ref = AccountRef{
                .pubkey = pubkey,
                .slot = account_file.slot,
                .location = .{
                    .File = .{
                        .file_id = @as(u32, @intCast(account_file.id)),
                        .offset = offset,
                    },
                },
            };

            try self.index.putWithCounts(
                allocator,
                pubkey,
                account_ref,
                &pubkey_counts,
            );
            offset = offset + account.len;
        }
        std.debug.print("putting: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();
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

        // prealloc
        const n_bins = self.index.numberOfBins();
        var bin_counts = try self.allocator.alloc(usize, n_bins);
        defer self.allocator.free(bin_counts);
        @memset(bin_counts, 0);

        var total_accounts = accounts.len;
        var pubkey_counts = try PubkeyCountMap.initCapacity(self.allocator, total_accounts);
        defer pubkey_counts.deinit();

        for (pubkeys) |*pubkey| {
            const bin_index = self.index.getBinIndex(pubkey);
            bin_counts[bin_index] += 1;

            const map_result = pubkey_counts.getOrPutAssumeCapacity(pubkey.*);
            if (map_result.found_existing) {
                map_result.value_ptr.* += 1;
            } else {
                // in case of resize we need to move all of the existing references + new ones
                if (self.index.getBin(bin_index).getRefs().get(pubkey.*)) |references| {
                    map_result.value_ptr.* = references.items.len + 1;
                    total_accounts += references.items.len + 1;
                } else {
                    map_result.value_ptr.* = 1;
                }
            }
        }

        for (0..n_bins) |bin_index| {
            const bin = self.index.getBin(bin_index);
            const new_len = bin_counts[bin_index] + bin.getRefs().count();
            if (new_len > 0) {
                try bin.getRefs().ensureTotalCapacity(@intCast(new_len));
            }
        }

        const account_references_size = total_accounts * @sizeOf(AccountRef);
        // TODO: FIX THIS LEAK
        var account_refs_memory = try std.heap.page_allocator.alloc(u8, account_references_size);
        var fba = std.heap.FixedBufferAllocator.init(account_refs_memory);
        const allocator = fba.allocator();

        // update index
        for (0..accounts.len) |i| {
            const account_ref = AccountRef{
                .pubkey = pubkeys[i],
                .slot = slot,
                .location = .{
                    .Cache = .{ .index = cache_index_start + i },
                },
            };
            try self.index.putWithCounts(allocator, pubkeys[i], account_ref, &pubkey_counts);
        }
    }

    pub fn getSlotHistory(self: *const Self) !sysvars.SlotHistory {
        return try self.getTypeFromAccount(
            sysvars.SlotHistory,
            &sysvars.IDS.slot_history,
        );
    }

    /// gets the index of the biggest pubkey in the list that is > min_slot
    /// (mainly used when computing accounts hash for an **incremental** snapshot)
    pub inline fn slotListArgmaxWithMin(
        slot_list: SlotList,
        min_slot: Slot,
    ) ?usize {
        if (slot_list.items.len == 0) {
            return null;
        }

        var biggest: AccountRef = undefined;
        var biggest_index: ?usize = null;
        for (slot_list.items, 0..) |item, i| {
            if (item.slot > min_slot and (biggest_index == null or item.slot > biggest.slot)) {
                biggest = item;
                biggest_index = i;
            }
        }
        return biggest_index;
    }

    /// gets the index of the biggest pubkey in the list that is <= max_slot
    /// (mainly used when computing accounts hash for a **full** snapshot)
    pub inline fn slotListArgmaxWithMax(
        slot_list: SlotList,
        max_slot: Slot,
    ) ?usize {
        if (slot_list.items.len == 0) {
            return null;
        }

        var biggest: AccountRef = undefined;
        var biggest_index: ?usize = null;
        for (slot_list.items, 0..) |item, i| {
            if (item.slot <= max_slot and (biggest_index == null or item.slot > biggest.slot)) {
                biggest = item;
                biggest_index = i;
            }
        }
        return biggest_index;
    }

    pub inline fn slotListArgmax(
        slot_list: SlotList,
    ) ?usize {
        return std.sort.argMax(
            AccountRef,
            slot_list.items,
            {},
            struct {
                fn lessThan(_: void, a: AccountRef, b: AccountRef) bool {
                    return a.slot < b.slot;
                }
            }.lessThan,
        );
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
        const bin = self.index.getBinFromPubkey(pubkey);
        // check ram
        var refs = AccountIndexBin.getSlotList(bin.getInMemRefs(), pubkey);
        if (refs == null) {
            // check disk
            if (bin.getDiskRefs()) |disk_refs| {
                refs = AccountIndexBin.getSlotList(disk_refs, pubkey);
                if (refs == null) {
                    return error.PubkeyNotInIndex;
                }
            } else {
                return error.PubkeyNotInIndex;
            }
        }

        const max_account_index = slotListArgmax(refs.?).?;
        const account = try self.getAccountFromRef(&refs.?.items[max_account_index]);
        return account;
    }

    pub fn getTypeFromAccount(self: *const Self, comptime T: type, pubkey: *const Pubkey) !T {
        const account = try self.getAccount(pubkey);
        const t = bincode.readFromSlice(self.allocator, T, account.data, .{}) catch {
            return error.DeserializationError;
        };
        return t;
    }
};

/// Spawns tasks and returns a list of threads
/// task function should take {params} ++ {start_index, end_index, thread_id}
pub fn spawnThreadTasks(
    allocator: std.mem.Allocator,
    f: anytype,
    params: anytype,
    data_len: usize,
    max_n_threads: usize,
) !std.ArrayList(std.Thread) {
    var chunk_size = data_len / max_n_threads;
    var n_threads = max_n_threads;
    if (chunk_size == 0) {
        n_threads = 1;
        chunk_size = data_len;
    }

    var handles = try std.ArrayList(std.Thread).initCapacity(allocator, n_threads);

    var start_index: usize = 0;
    var end_index: usize = 0;
    for (0..n_threads) |thread_id| {
        if (thread_id == (n_threads - 1)) {
            end_index = data_len;
        } else {
            end_index = start_index + chunk_size;
        }
        const handle = try std.Thread.spawn(.{}, f, params ++ .{ start_index, end_index, thread_id });
        handles.appendAssumeCapacity(handle);

        start_index = end_index;
    }

    return handles;
}

pub const PubkeyBinCalculator = struct {
    shift_bits: u6,

    pub fn init(n_bins: usize) PubkeyBinCalculator {
        // u8 * 3 (ie, we consider on the first 3 bytes of a pubkey)
        const MAX_BITS: u32 = 24;
        // within bounds
        std.debug.assert(n_bins > 0);
        std.debug.assert(n_bins <= (1 << MAX_BITS));
        // power of two
        std.debug.assert((n_bins & (n_bins - 1)) == 0);
        // eg,
        // 8 bins
        // => leading zeros = 28
        // => shift_bits = (24 - (32 - 28 - 1)) = 21
        // ie,
        // if we have the first 24 bits set (u8 << 16, 8 + 16 = 24)
        // want to consider the first 3 bits of those 24
        // 0000 ... [100]0 0000 0000 0000 0000 0000
        // then we want to shift right by 21
        // 0000 ... 0000 0000 0000 0000 0000 0[100]
        // those 3 bits can represent 2^3 (= 8) bins
        const shift_bits = @as(u6, @intCast(MAX_BITS - (32 - @clz(@as(u32, @intCast(n_bins))) - 1)));

        return PubkeyBinCalculator{
            .shift_bits = shift_bits,
        };
    }

    pub fn binIndex(self: *const PubkeyBinCalculator, pubkey: *const Pubkey) usize {
        const data = &pubkey.data;
        return (@as(usize, data[0]) << 16 |
            @as(usize, data[1]) << 8 |
            @as(usize, data[2])) >> self.shift_bits;
    }
};

pub const DiskMemoryAllocator = struct {
    filepath: []const u8,
    count: usize = 0,

    const Self = @This();

    pub fn init(filepath: []const u8) !Self {
        return Self{
            .filepath = filepath,
        };
    }

    /// deletes all allocated files + optionally frees the filepath
    pub fn deinit(self: *Self, str_allocator: ?std.mem.Allocator) void {
        // delete all files
        var buf: [1024]u8 = undefined;
        for (0..self.count) |i| {
            // this should never fail since we know the file exists in alloc()
            const filepath = std.fmt.bufPrint(&buf, "{s}_{d}", .{ self.filepath, i }) catch unreachable;
            std.fs.cwd().deleteFile(filepath) catch |err| {
                std.debug.print("Disk Memory Allocator deinit: error: {}\n", .{err});
            };
        }
        if (str_allocator) |a| {
            a.free(self.filepath);
        }
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

    /// creates a new file with size aligned to page_size and returns a pointer to it
    pub fn alloc(ctx: *anyopaque, n: usize, log2_align: u8, return_address: usize) ?[*]u8 {
        _ = log2_align;
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));

        var buf: [1024]u8 = undefined;
        const filepath = std.fmt.bufPrint(&buf, "{s}_{d}", .{ self.filepath, self.count }) catch |err| {
            std.debug.print("Disk Memory Allocator error: {}\n", .{err});
            return null;
        };

        var file = std.fs.cwd().createFile(filepath, .{ .read = true }) catch |err| {
            std.debug.print("Disk Memory Allocator error: {}\n", .{err});
            return null;
        };
        defer file.close();
        self.count += 1;

        const aligned_size = std.mem.alignForward(usize, n, std.mem.page_size);
        const file_size = (file.stat() catch |err| {
            std.debug.print("Disk Memory Allocator error: {}\n", .{err});
            return null;
        }).size;

        if (file_size < aligned_size) {
            // resize the file
            file.seekTo(aligned_size - 1) catch |err| {
                std.debug.print("Disk Memory Allocator error: {}\n", .{err});
                return null;
            };
            _ = file.write(&[_]u8{1}) catch |err| {
                std.debug.print("Disk Memory Allocator error: {}\n", .{err});
                return null;
            };
            file.seekTo(0) catch |err| {
                std.debug.print("Disk Memory Allocator error: {}\n", .{err});
                return null;
            };
        }

        var memory = std.os.mmap(
            null,
            aligned_size,
            std.os.PROT.READ | std.os.PROT.WRITE,
            std.os.MAP.SHARED,
            file.handle,
            0,
        ) catch |err| {
            std.debug.print("Disk Memory Allocator error: {}\n", .{err});
            return null;
        };

        return memory.ptr;
    }

    /// unmaps the memory (file still exists and is removed on deinit())
    pub fn free(_: *anyopaque, buf: []u8, log2_align: u8, return_address: usize) void {
        _ = log2_align;
        _ = return_address;
        const buf_aligned_len = std.mem.alignForward(usize, buf.len, std.mem.page_size);
        std.os.munmap(@alignCast(buf.ptr[0..buf_aligned_len]));
    }

    /// not supported rn
    fn resize(
        _: *anyopaque,
        buf_unaligned: []u8,
        log2_buf_align: u8,
        new_size: usize,
        return_address: usize,
    ) bool {
        // not supported
        _ = buf_unaligned;
        _ = log2_buf_align;
        _ = new_size;
        _ = return_address;
        return false;
    }
};

pub const DiskMemoryConfig = struct {
    // path to where disk files will be stored
    dir_path: []const u8,
    // size of each bins' reference arraylist to preallocate
    capacity: usize,
};

pub const RamMemoryConfig = struct {
    // size of each bins' reference arraylist to preallocate
    capacity: usize = 0,
    // we found this leads to better 'append' performance vs GPA
    allocator: std.mem.Allocator = std.heap.page_allocator,
};

// TODO: AccountRefs
const SlotList = std.ArrayListUnmanaged(AccountRef);

pub inline fn pubkey_hash(key: Pubkey) u64 {
    return std.mem.readIntLittle(u64, key.data[0..8]);
}

pub inline fn pubkey_eql(key1: Pubkey, key2: Pubkey) bool {
    return key1.equals(&key2);
}

const IndexMap = FastMap(Pubkey, SlotList, pubkey_hash, pubkey_eql);

pub fn FastMap(
    comptime Key: type,
    comptime Value: type,
    comptime hash_fn: fn (Key) callconv(.Inline) u64,
    comptime eq_fn: fn (Key, Key) callconv(.Inline) bool,
) type {
    return struct {
        groups: [][GROUP_SIZE]KeyValue,
        // states: [][GROUP_SIZE]State,
        states: []@Vector(GROUP_SIZE, u8),
        bit_mask: usize,
        // underlying memory
        memory: []u8,
        allocator: std.mem.Allocator,
        _count: usize = 0,
        _capacity: usize = 0,

        const GROUP_SIZE = 16;

        pub const Self = @This();

        pub const State = packed struct(u8) {
            state: enum(u1) { empty, occupied },
            control_bytes: u7,
        };

        pub const KeyValue = struct {
            key: Key,
            value: Value,
        };

        pub const KeyValuePtr = struct {
            key_ptr: *Key,
            value_ptr: *Value,
        };

        pub fn init(allocator: std.mem.Allocator) @This() {
            return @This(){
                .allocator = allocator,
                .groups = undefined,
                .states = undefined,
                .memory = undefined,
                .bit_mask = 0,
            };
        }

        pub fn initCapacity(allocator: std.mem.Allocator, n: usize) !Self {
            var self = init(allocator);
            try self.ensureTotalCapacity(n);
            return self;
        }

        pub fn ensureTotalCapacity(self: *@This(), n: usize) !void {
            if (n == 0) {
                // something is wrong
                return error.ZeroCapacityNotSupported;
            }
            if (n <= self._capacity) {
                return;
            }

            if (self._capacity == 0) {
                const n_groups = @max(std.math.pow(u64, 2, std.math.log2(n) + 1) / GROUP_SIZE, 1);
                const group_size = n_groups * @sizeOf([GROUP_SIZE]KeyValue);
                const ctrl_size = n_groups * @sizeOf([GROUP_SIZE]State);
                const size = group_size + ctrl_size;

                const memory = try self.allocator.alloc(u8, size);
                @memset(memory, 0);

                const group_ptr: [*][GROUP_SIZE]KeyValue = @alignCast(@ptrCast(memory.ptr));
                const groups = group_ptr[0..n_groups];
                // const states_ptr: [*][GROUP_SIZE]State = @alignCast(@ptrCast(memory.ptr + group_size));
                const states_ptr: [*]@Vector(GROUP_SIZE, u8) = @alignCast(@ptrCast(memory.ptr + group_size));
                const states = states_ptr[0..n_groups];

                self._capacity = n_groups * GROUP_SIZE;
                std.debug.assert(self._capacity >= n);
                self.groups = groups;
                self.states = states;
                self.memory = memory;
                self.bit_mask = n_groups - 1;
            } else {
                // recompute the size
                const n_groups = @max(std.math.pow(u64, 2, std.math.log2(n) + 1) / GROUP_SIZE, 1);

                const group_size = n_groups * @sizeOf([GROUP_SIZE]KeyValue);
                const ctrl_size = n_groups * @sizeOf([GROUP_SIZE]State);
                const size = group_size + ctrl_size;

                const memory = try self.allocator.alloc(u8, size);
                @memset(memory, 0);

                const group_ptr: [*][GROUP_SIZE]KeyValue = @alignCast(@ptrCast(memory.ptr));
                const groups = group_ptr[0..n_groups];
                const states_ptr: [*]@Vector(GROUP_SIZE, u8) = @alignCast(@ptrCast(memory.ptr + group_size));
                // const states_ptr: [*][GROUP_SIZE]State = @alignCast(@ptrCast(memory.ptr + group_size));
                const states = states_ptr[0..n_groups];

                var new_self = Self{
                    .allocator = self.allocator,
                    .groups = groups,
                    .states = states,
                    .memory = memory,
                    .bit_mask = n_groups - 1,
                    ._capacity = n_groups * GROUP_SIZE,
                };

                var iter = self.iterator();
                while (iter.next()) |kv| {
                    new_self.putAssumeCapacity(kv.key_ptr.*, kv.value_ptr.*);
                }

                self.deinit(); // release old memory

                self._capacity = new_self._capacity;
                self._count = new_self._count;
                self.groups = new_self.groups;
                self.states = new_self.states;
                self.memory = new_self.memory;
                self.bit_mask = new_self.bit_mask;
            }
        }

        pub fn deinit(self: *@This()) void {
            if (self._capacity > 0)
                self.allocator.free(self.memory);
        }

        pub const Iterator = struct {
            hm: *const Self,
            group_index: usize = 0,
            position: usize = 0,

            pub fn next(it: *Iterator) ?KeyValuePtr {
                const self = it.hm;
                const free_state: @Vector(GROUP_SIZE, u8) = @splat(0);

                if (self.capacity() == 0) return null;

                while (true) {
                    if (it.group_index == self.groups.len) {
                        return null;
                    }

                    // const states: @Vector(GROUP_SIZE, u8) = @bitCast(self.states[it.group_index]);
                    const states = self.states[it.group_index];
                    const occupied_states = free_state != states;

                    if (@reduce(.Or, occupied_states)) {
                        for (it.position..GROUP_SIZE) |j| {
                            defer it.position += 1;
                            if (occupied_states[j]) {
                                return .{
                                    .key_ptr = &self.groups[it.group_index][j].key,
                                    .value_ptr = &self.groups[it.group_index][j].value,
                                };
                            }
                        }
                    }
                    it.position = 0;
                    it.group_index += 1;
                }
            }
        };

        pub fn iterator(self: *const @This()) Iterator {
            return .{ .hm = self };
        }

        pub inline fn count(self: *const @This()) usize {
            return self._count;
        }

        pub inline fn capacity(self: *const @This()) usize {
            return self._capacity;
        }

        pub const GetOrPutResult = struct {
            found_existing: bool,
            value_ptr: *Value,
        };

        pub fn get(self: *const @This(), key: Key) ?Value {
            if (self._capacity == 0) return null;

            var hash = hash_fn(key);
            var group_index = hash & self.bit_mask;

            // what we are searching for (get)
            const control_bytes: u7 = @intCast(hash >> (64 - 7));
            // PERF: this struct is represented by a u8
            const key_state = State{
                .state = .occupied,
                .control_bytes = control_bytes,
            };
            const search_state: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(key_state));
            const free_state: @Vector(GROUP_SIZE, u8) = @splat(0);

            for (0..self.groups.len) |_| {
                // const states: @Vector(GROUP_SIZE, u8) = @bitCast(self.states[group_index]);
                const states = self.states[group_index];

                // PERF: SIMD eq check: search for a match
                var match_vec = search_state == states;
                if (@reduce(.Or, match_vec)) {
                    inline for (0..GROUP_SIZE) |j| {
                        // PERF: SIMD eq check across pubkeys
                        if (match_vec[j] and eq_fn(self.groups[group_index][j].key, key)) {
                            return self.groups[group_index][j].value;
                        }
                    }
                }

                // PERF: SIMD eq check: if theres a free state, then the key DNE
                const free_vec = free_state == states;
                if (@reduce(.Or, free_vec)) {
                    return null;
                }

                // otherwise try the next group
                group_index = (group_index + 1) & self.bit_mask;
            }
            return null;
        }

        pub fn putAssumeCapacity(self: *@This(), key: Key, value: Value) void {
            var hash = hash_fn(key);
            var group_index = hash & self.bit_mask;
            std.debug.assert(self._capacity > self._count);

            // what we are searching for (get)
            const control_bytes: u7 = @intCast(hash >> (64 - 7));
            // PERF: this struct is represented by a u8
            const key_state = State{
                .state = .occupied,
                .control_bytes = control_bytes,
            };
            const free_state: @Vector(GROUP_SIZE, u8) = @splat(0);

            for (0..self.groups.len) |_| {
                // const states: @Vector(GROUP_SIZE, u8) = @bitCast(self.states[group_index]);
                const states = self.states[group_index];

                // if theres an free then insert
                const free_vec = free_state == states;
                if (@reduce(.Or, free_vec)) {
                    const invalid_state: @Vector(GROUP_SIZE, u8) = @splat(16);
                    const indices = @select(u8, free_vec, std.simd.iota(u8, GROUP_SIZE), invalid_state);
                    const free_index = @reduce(.Min, indices);

                    // occupy it
                    self.groups[group_index][free_index] = .{
                        .key = key,
                        .value = value,
                    };
                    self.states[group_index][free_index] = @bitCast(key_state);
                    self._count += 1;
                    return;
                }

                // otherwise try the next group
                group_index = (group_index + 1) & self.bit_mask;
            }
            unreachable;
        }

        pub fn getOrPutAssumeCapacity(self: *@This(), key: Key) GetOrPutResult {
            var hash = hash_fn(key);
            var group_index = hash & self.bit_mask;

            std.debug.assert(self._capacity > self._count);

            // what we are searching for (get)
            const control_bytes: u7 = @intCast(hash >> (64 - 7));
            const key_state = State{
                .state = .occupied,
                .control_bytes = control_bytes,
            };
            const search_state: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(key_state));
            // or looking for an empty space (ie, put)
            const free_state: @Vector(GROUP_SIZE, u8) = @splat(0);

            for (0..self.groups.len) |_| {
                // const states: @Vector(GROUP_SIZE, u8) = @bitCast(self.states[group_index]); // 1)
                const states = self.states[group_index];

                // SIMD eq search for a match (get)
                var match_vec = search_state == states;
                if (@reduce(.Or, match_vec)) {
                    inline for (0..GROUP_SIZE) |j| {
                        if (match_vec[j] and eq_fn(self.groups[group_index][j].key, key)) {
                            return .{
                                .found_existing = true,
                                .value_ptr = &self.groups[group_index][j].value,
                            };
                        }
                    }
                }

                // if theres an free then insert (put)
                const free_vec = free_state == states;
                if (@reduce(.Or, free_vec)) {
                    const invalid_state: @Vector(GROUP_SIZE, u8) = @splat(16);
                    const indices = @select(u8, free_vec, std.simd.iota(u8, GROUP_SIZE), invalid_state);
                    const free_index = @reduce(.Min, indices);

                    // occupy it
                    self.groups[group_index][free_index].key = key; // 2)
                    self.states[group_index][free_index] = @bitCast(key_state);
                    self._count += 1;
                    return .{
                        .found_existing = false,
                        .value_ptr = &self.groups[group_index][free_index].value,
                    };
                }

                // otherwise try the next group
                group_index = (group_index + 1) & self.bit_mask;
            }
            unreachable;
        }
    };
}

pub const AccountIndexBin = struct {
    account_refs: RefMap,
    disk_memory: ?DiskMemory,
    allocator: std.mem.Allocator,

    pub const DiskMemory = struct {
        account_refs: RefMap,
        allocator: *DiskMemoryAllocator,
    };

    const RefMap = IndexMap;
    // const RefMap = std.HashMap(Pubkey, SlotList, struct {
    //     pub fn hash(self: @This(), key: Pubkey) u64 {
    //         _ = self;
    //         return std.mem.readIntLittle(u64, key.data[0..8]);
    //     }
    //     pub fn eql(self: @This(), key1: Pubkey, key2: Pubkey) bool {
    //         _ = self;
    //         return key1.equals(&key2);
    //     }
    // }, std.hash_map.default_max_load_percentage);

    pub fn initCapacity(
        allocator: std.mem.Allocator,
        ram_memory_config: RamMemoryConfig,
        maybe_disk_config: ?DiskMemoryConfig,
        bin_index: usize,
    ) !AccountIndexBin {
        // // setup in-mem references
        // const account_refs = try ArrayList(AccountRef).initCapacity(
        //     ram_memory_config.allocator,
        //     ram_memory_config.capacity,
        // );

        var account_refs = RefMap.init(ram_memory_config.allocator);
        // try account_refs.ensureTotalCapacity(@intCast(ram_memory_config.capacity));

        // setup disk references
        var disk_memory: ?DiskMemory = null;
        if (maybe_disk_config) |*disk_config| {
            std.fs.cwd().access(disk_config.dir_path, .{}) catch {
                try std.fs.cwd().makeDir(disk_config.dir_path);
            };

            const disk_filepath = try std.fmt.allocPrint(
                allocator,
                "{s}/bin{d}_index_data",
                .{ disk_config.dir_path, bin_index },
            );

            // need to store on heap so `ptr.allocator()` is always correct
            var ptr = try allocator.create(DiskMemoryAllocator);
            ptr.* = try DiskMemoryAllocator.init(disk_filepath);

            // const disk_account_refs = try ArrayList(AccountRef).initCapacity(
            //     ptr.allocator(),
            //     disk_config.capacity,
            // );

            var disk_account_refs = RefMap.init(ptr.allocator());
            // try disk_account_refs.ensureTotalCapacity(@intCast(disk_config.capacity));

            disk_memory = .{
                .account_refs = disk_account_refs,
                .allocator = ptr,
            };
        }

        return AccountIndexBin{
            .account_refs = account_refs,
            .disk_memory = disk_memory,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AccountIndexBin) void {
        self.account_refs.deinit();
        if (self.disk_memory) |*disk_memory| {
            disk_memory.account_refs.deinit();
            disk_memory.allocator.deinit(self.allocator);
            self.allocator.destroy(disk_memory.allocator);
        }
    }

    pub inline fn getInMemRefs(self: *AccountIndexBin) *RefMap {
        return &self.account_refs;
    }

    pub inline fn getDiskRefs(self: *AccountIndexBin) ?*RefMap {
        if (self.disk_memory) |*disk_memory| {
            return &disk_memory.account_refs;
        } else {
            return null;
        }
    }

    pub inline fn getRefs(self: *AccountIndexBin) *RefMap {
        if (self.disk_memory) |*disk_memory| {
            return &disk_memory.account_refs;
        } else {
            return &self.account_refs;
        }
    }

    // ** useful account reference functions

    pub fn put(refs: *RefMap, allocator: std.mem.Allocator, account_ref: AccountRef) !void {
        const result = refs.getOrPutAssumeCapacity(account_ref.pubkey);
        if (result.found_existing) {
            const ptr = try result.value_ptr.addOne(allocator);
            ptr.* = account_ref;
        } else {
            result.value_ptr.* = try std.ArrayListUnmanaged(AccountRef).initCapacity(allocator, 1);
            result.value_ptr.appendAssumeCapacity(account_ref);
        }
    }

    pub fn getSlotList(
        account_refs: *const RefMap,
        pubkey: *const Pubkey,
    ) ?SlotList {
        var v = account_refs.get(pubkey.*);
        return v;
    }
};

/// stores the mapping from Pubkey to the account location (AccountRef)
pub const AccountIndex = struct {
    bins: []AccountIndexBin,
    calculator: PubkeyBinCalculator,
    allocator: std.mem.Allocator,
    use_disk: bool,

    const Self = @This();

    pub fn init(
        // used to allocate the bin slice and other bin metadata
        allocator: std.mem.Allocator,
        // number of bins to shard pubkeys across
        n_bins: usize,
        ram_config: RamMemoryConfig,
        disk_config: ?DiskMemoryConfig,
    ) !Self {
        const calculator = PubkeyBinCalculator.init(n_bins);

        var bins = try allocator.alloc(AccountIndexBin, n_bins);
        for (bins, 0..) |*bin, bin_i| {
            bin.* = try AccountIndexBin.initCapacity(
                allocator,
                ram_config,
                disk_config,
                bin_i,
            );
        }
        const use_disk = disk_config != null;

        return Self{
            .bins = bins,
            .calculator = calculator,
            .allocator = allocator,
            .use_disk = use_disk,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.bins) |*bin| {
            bin.deinit();
        }
        self.allocator.free(self.bins);
    }

    pub inline fn getBinIndex(self: *const Self, pubkey: *const Pubkey) usize {
        return self.calculator.binIndex(pubkey);
    }

    pub inline fn getBin(self: *const Self, index: usize) *AccountIndexBin {
        return &self.bins[index];
    }

    pub inline fn getBinFromPubkey(
        self: *const Self,
        pubkey: *const Pubkey,
    ) *AccountIndexBin {
        const bin_index = self.calculator.binIndex(pubkey);
        return &self.bins[bin_index];
    }

    pub inline fn numberOfBins(self: *const Self) usize {
        return self.bins.len;
    }

    pub fn putWithCounts(
        self: *Self,
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
        account_ref: AccountRef,
        counts: *const PubkeyCountMap,
    ) !void {
        const bin = self.getBinFromPubkey(&pubkey);
        const result = bin.getRefs().getOrPutAssumeCapacity(pubkey);
        const count = counts.get(pubkey) orelse return error.PubkeyNotFoundInCounts;
        if (!result.found_existing) {
            result.value_ptr.* = try SlotList.initCapacity(allocator, count);
        } else {
            const capacity = result.value_ptr.capacity;
            // note: count should include the current len
            if (capacity < count) {
                // need to realloc the list
                // dont bother freeing (fixbuffer doesnt handle frees well)
                var new_list = try SlotList.initCapacity(allocator, count);
                new_list.appendSliceAssumeCapacity(result.value_ptr.items);
                result.value_ptr.* = new_list;
            }
        }
        result.value_ptr.appendAssumeCapacity(account_ref);
    }

    /// indexes and accounts file by parsing out the accounts.
    pub fn indexAccountFile(self: *Self, allocator: std.mem.Allocator, accounts_file: *AccountFile) !void {
        var offset: usize = 0;

        while (true) {
            var account = accounts_file.readAccount(offset) catch break;
            const pubkey = account.store_info.pubkey;

            const hash_is_missing = std.mem.eql(u8, &account.hash().data, &Hash.default().data);
            if (hash_is_missing) {
                const hash = hashAccount(
                    account.account_info.lamports,
                    account.data,
                    &account.account_info.owner.data,
                    account.account_info.executable,
                    account.account_info.rent_epoch,
                    &pubkey.data,
                );
                account.hash_ptr.* = hash;
            }

            const account_ref = AccountRef{
                .pubkey = pubkey,
                .slot = accounts_file.slot,
                .location = .{
                    .File = .{
                        .file_id = @as(u32, @intCast(accounts_file.id)),
                        .offset = offset,
                    },
                },
            };

            // put this in a per bin vector []Vec(AccountRef)
            const index_bin = self.getBinFromPubkey(&pubkey);
            const refs = index_bin.getRefs();
            try AccountIndexBin.put(refs, allocator, account_ref);

            offset = offset + account.len;
        }
    }

    pub fn validateAccountFile(
        self: *Self,
        accounts_file: *AccountFile,
        bin_counts: []usize,
    ) !void {
        var offset: usize = 0;
        var n_accounts: usize = 0;

        if (bin_counts.len != self.numberOfBins()) {
            return error.BinCountMismatch;
        }

        while (true) {
            const account = accounts_file.readAccount(offset) catch break;
            try account.validate();

            const pubkey = &account.store_info.pubkey;
            const bin_index = self.getBinIndex(pubkey);
            bin_counts[bin_index] += 1;

            offset = offset + account.len;
            n_accounts += 1;
        }

        if (offset != std.mem.alignForward(usize, accounts_file.length, @sizeOf(u64))) {
            return error.InvalidAccountFileLength;
        }

        accounts_file.n_accounts = n_accounts;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    var benchmark_timer = try std.time.Timer.start();

    // NOTE: running with `zig build run` or similar will not work due to fd limits
    // you need to build and then run ./zig-out/bin/accounts_db to get around these

    const n_threads_snapshot_unpack = 20;
    const disk_index_dir: ?[]const u8 = "test_data/tmp";
    // const disk_index_dir: ?[]const u8 = null;
    const index_ram_capacity = 100_000;
    const force_unpack_snapshot = false;
    // const snapshot_dir = "../snapshots/";
    const snapshot_dir = "test_data/";

    var logger = Logger.init(allocator, Level.debug);
    logger.spawn();

    // this should exist before we start to unpack
    const genesis_path = try std.fmt.allocPrint(
        allocator,
        "{s}/genesis.bin",
        .{snapshot_dir},
    );
    defer allocator.free(genesis_path);

    std.fs.cwd().access(genesis_path, .{}) catch {
        std.debug.print("genesis.bin not found: {s}\n", .{genesis_path});
        return error.GenesisNotFound;
    };

    // if this exists, we wont look for a .tar.zstd
    const accounts_path = try std.fmt.allocPrint(
        allocator,
        "{s}/accounts/",
        .{snapshot_dir},
    );
    defer allocator.free(accounts_path);

    var accounts_path_exists = true;
    std.fs.cwd().access(accounts_path, .{}) catch {
        accounts_path_exists = false;
    };
    const should_unpack_snapshot = !accounts_path_exists or force_unpack_snapshot;

    var snapshot_paths = try SnapshotPaths.find(allocator, snapshot_dir);
    if (snapshot_paths.incremental_snapshot == null) {
        std.debug.print("no incremental snapshot found\n", .{});
    }

    if (should_unpack_snapshot) {
        std.debug.print("unpacking snapshots...\n", .{});
        // if accounts/ doesnt exist then we unpack the found snapshots
        var snapshot_dir_iter = try std.fs.cwd().openIterableDir(snapshot_dir, .{});
        defer snapshot_dir_iter.close();

        try parallelUnpackZstdTarBall(
            allocator,
            snapshot_paths.full_snapshot.path,
            snapshot_dir_iter.dir,
            n_threads_snapshot_unpack,
            true,
        );

        // TODO: can probs do this in parallel with full snapshot
        if (snapshot_paths.incremental_snapshot) |incremental_snapshot| {
            try parallelUnpackZstdTarBall(
                allocator,
                incremental_snapshot.path,
                snapshot_dir_iter.dir,
                n_threads_snapshot_unpack,
                false,
            );
        }
    }

    var full_timer = try std.time.Timer.start();
    var timer = try std.time.Timer.start();

    std.debug.print("reading snapshots...\n", .{});
    var snapshots = try AllSnapshotFields.fromPaths(allocator, snapshot_dir, snapshot_paths);
    defer snapshots.deinit(allocator);
    std.debug.print("read snapshots in {s}\n", .{std.fmt.fmtDuration(timer.read())});
    const full_snapshot = snapshots.full;

    // load and validate
    std.debug.print("initializing accounts-db...\n", .{});
    var accounts_db = try AccountsDB.init(allocator, logger, AccountsDBConfig{
        .index_ram_capacity = index_ram_capacity,
        .disk_index_dir = disk_index_dir,
    });
    defer accounts_db.deinit();
    std.debug.print("initialized in {s}\n", .{std.fmt.fmtDuration(timer.read())});
    timer.reset();

    const snapshot = try snapshots.collapse();
    timer.reset();

    std.debug.print("loading from snapshot...\n", .{});
    try accounts_db.loadFromSnapshot(
        snapshot.accounts_db_fields,
        accounts_path,
    );
    std.debug.print("loaded from snapshot in {s}\n", .{std.fmt.fmtDuration(timer.read())});

    try accounts_db.validateLoadFromSnapshot(
        snapshot.bank_fields.incremental_snapshot_persistence,
        full_snapshot.bank_fields.slot,
        full_snapshot.bank_fields.capitalization,
    );
    std.debug.print("validated from snapshot in {s}\n", .{std.fmt.fmtDuration(timer.read())});
    std.debug.print("full timer: {s}\n", .{std.fmt.fmtDuration(full_timer.read())});
    std.debug.print("benchmark timer: {d}seconds\n", .{benchmark_timer.read() / std.time.ns_per_s});

    // use the genesis to validate the bank
    const genesis_config = try GenesisConfig.init(allocator, genesis_path);
    defer genesis_config.deinit(allocator);

    std.debug.print("validating bank...\n", .{});
    const bank = Bank.init(&accounts_db, &snapshot.bank_fields);
    try Bank.validateBankFields(bank.bank_fields, &genesis_config);

    // validate the status cache
    std.debug.print("validating status cache...\n", .{});
    const status_cache_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "snapshots/status_cache" },
    );
    defer allocator.free(status_cache_path);

    var status_cache = try StatusCache.init(allocator, status_cache_path);
    defer status_cache.deinit();

    var slot_history = try accounts_db.getSlotHistory();
    defer slot_history.deinit(accounts_db.allocator);

    const bank_slot = snapshot.bank_fields.slot;
    try status_cache.validate(allocator, bank_slot, &slot_history);

    std.debug.print("done!\n", .{});
}

fn loadTestAccountsDB(use_disk: bool) !struct { AccountsDB, AllSnapshotFields } {
    std.debug.assert(builtin.is_test); // should only be used in tests

    var allocator = std.testing.allocator;

    const dir_path = "test_data";
    const dir = try std.fs.cwd().openDir(dir_path, .{});
    dir.access("accounts", .{}) catch {
        // unpack both snapshots to get the acccount files
        try parallelUnpackZstdTarBall(
            allocator,
            "snapshot-10-6ExseAZAVJsAZjhimxHTR7N8p6VGXiDNdsajYh1ipjAD.tar.zst",
            dir,
            1,
            true,
        );
        try parallelUnpackZstdTarBall(
            allocator,
            "incremental-snapshot-10-25-GXgKvm3NMAPgGdv2verVaNXmKTHQgfy2TAxLVEfAvdCS.tar.zst",
            dir,
            1,
            true,
        );
    };

    var snapshot_paths = try SnapshotPaths.find(allocator, dir_path);
    var snapshots = try AllSnapshotFields.fromPaths(allocator, dir_path, snapshot_paths);

    var disk_dir: ?[]const u8 = null;
    var disk_capacity: usize = 0;
    if (use_disk) {
        disk_dir = "test_data/tmp";
        disk_capacity = 1000;
    }

    const snapshot = try snapshots.collapse();
    var logger = Logger{ .noop = {} };
    // var logger = Logger.init(std.heap.page_allocator, .debug);
    var accounts_db = try AccountsDB.init(allocator, logger, .{
        .n_index_bins = 4,
        .storage_cache_size = 10,
        .disk_index_dir = disk_dir,
        .index_disk_capacity = disk_capacity,
    });

    const accounts_path = "test_data/accounts";
    try accounts_db.loadFromSnapshot(
        snapshot.accounts_db_fields,
        accounts_path,
    );

    return .{
        accounts_db,
        snapshots,
    };
}

test "core.accounts_db: write and read an account" {
    var allocator = std.testing.allocator;

    var result = try loadTestAccountsDB(false);
    var accounts_db: AccountsDB = result[0];
    var snapshots: AllSnapshotFields = result[1];
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    var rng = std.rand.DefaultPrng.init(0);
    const pubkey = Pubkey.random(rng.random());
    var data = [_]u8{ 1, 2, 3 };
    var test_account = Account{
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
    var account = try accounts_db.getAccount(&pubkey);
    try std.testing.expectEqualDeep(test_account, account);

    // new account
    accounts[0].lamports = 20;
    try accounts_db.putAccountBatch(&accounts, &pubkeys, 28);
    var account_2 = try accounts_db.getAccount(&pubkey);
    try std.testing.expectEqualDeep(accounts[0], account_2);
}

test "core.accounts_db: tests disk allocator on hashmaps" {
    var allocator = try DiskMemoryAllocator.init("test_data/tmp/tests");
    var refs = std.AutoHashMap(Pubkey, AccountRef).init(allocator.allocator());
    try refs.ensureTotalCapacity(100);

    const ref = AccountRef{
        .pubkey = Pubkey.default(),
        .location = .{
            .Cache = .{ .index = 2 },
        },
        .slot = 144,
    };

    try refs.put(Pubkey.default(), ref);

    const r = refs.get(Pubkey.default()) orelse return error.MissingAccount;
    try std.testing.expectEqualDeep(r, ref);
}

test "core.accounts_db: tests disk allocator" {
    var allocator = try DiskMemoryAllocator.init("test_data/tmp/tests");
    var disk_account_refs = try ArrayList(AccountRef).initCapacity(
        allocator.allocator(),
        1,
    );
    defer disk_account_refs.deinit();

    const ref = AccountRef{
        .pubkey = Pubkey.default(),
        .location = .{
            .Cache = .{ .index = 2 },
        },
        .slot = 10,
    };
    disk_account_refs.appendAssumeCapacity(ref);

    try std.testing.expectEqualDeep(disk_account_refs.items[0], ref);

    const ref2 = AccountRef{
        .pubkey = Pubkey.default(),
        .location = .{
            .Cache = .{ .index = 4 },
        },
        .slot = 14,
    };
    // this will lead to another allocation
    try disk_account_refs.append(ref2);

    try std.testing.expectEqualDeep(disk_account_refs.items[0], ref);
    try std.testing.expectEqualDeep(disk_account_refs.items[1], ref2);

    // these should exist
    try std.fs.cwd().access("test_data/tmp/tests_0", .{});
    try std.fs.cwd().access("test_data/tmp/tests_1", .{});

    // this should delete them
    allocator.deinit(null);

    // these should no longer exist
    var did_error = false;
    std.fs.cwd().access("test_data/tmp/tests_0", .{}) catch {
        did_error = true;
    };
    try std.testing.expect(did_error);
    did_error = false;
    std.fs.cwd().access("test_data/tmp/tests_1", .{}) catch {
        did_error = true;
    };
    try std.testing.expect(did_error);
}

test "core.accounts_db: load and validate from test snapshot using disk index" {
    var allocator = std.testing.allocator;

    var result = try loadTestAccountsDB(true);
    var accounts_db: AccountsDB = result[0];
    var snapshots: AllSnapshotFields = result[1];
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

test "core.accounts_db: load and validate from test snapshot" {
    var allocator = std.testing.allocator;

    var result = try loadTestAccountsDB(false);
    var accounts_db: AccountsDB = result[0];
    var snapshots: AllSnapshotFields = result[1];
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

test "core.accounts_db: load clock sysvar" {
    var allocator = std.testing.allocator;

    var result = try loadTestAccountsDB(false);
    var accounts_db: AccountsDB = result[0];
    var snapshots: AllSnapshotFields = result[1];
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
    std.debug.print("clock: {}\n", .{clock});
    try std.testing.expectEqual(clock, expected_clock);
}

test "core.accounts_db: load other sysvars" {
    var allocator = std.testing.allocator;

    var result = try loadTestAccountsDB(false);
    var accounts_db: AccountsDB = result[0];
    var snapshots: AllSnapshotFields = result[1];
    defer {
        accounts_db.deinit();
        snapshots.deinit(allocator);
    }

    _ = try accounts_db.getTypeFromAccount(sysvars.EpochSchedule, &sysvars.IDS.epoch_schedule);
    _ = try accounts_db.getTypeFromAccount(sysvars.Rent, &sysvars.IDS.rent);
    _ = try accounts_db.getTypeFromAccount(sysvars.SlotHash, &sysvars.IDS.slot_hashes);
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
        n_accounts: usize,
        slot_list_len: usize,
        accounts: MemoryType,
        index: MemoryType,
        n_accounts_multiple: usize = 0,
        name: []const u8 = "",
    };

    pub const args = [_]BenchArgs{
        // // test accounts in ram
        // BenchArgs{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .n_accounts_multiple = 2, // 1M
        //     .name = "10k accounts (10_slots - ram index)",
        // },
        // BenchArgs{
        //     .n_accounts = 100_000,
        //     .slot_list_len = 1,
        //     .accounts = .ram,
        //     .index = .ram,
        //     .name = "100k accounts (1_slot - ram index)",
        // },
        // tests large number of accounts on disk
        BenchArgs{
            // .n_accounts = 500_000,
            .n_accounts = 1_000_000,
            .slot_list_len = 1,
            .accounts = .disk,
            .index = .ram,
            .name = "500k accounts (1_slot - ram index)",
        },
        // BenchArgs{
        //     .n_accounts = 1_000_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .ram,
        //     .name = "1m accounts (1_slot - ram index)",
        // },

        // // testing disk indexes
        // BenchArgs{
        //     .n_accounts = 500_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .name = "500k accounts (1_slot - disk index)",
        // },
        // BenchArgs{
        //     .n_accounts = 3_000_000,
        //     .slot_list_len = 1,
        //     .accounts = .disk,
        //     .index = .disk,
        //     .name = "3m accounts (1_slot - disk index)",
        // },
    };

    pub fn readAccounts(bench_args: BenchArgs) !u64 {
        const n_accounts = bench_args.n_accounts;
        const slot_list_len = bench_args.slot_list_len;
        const total_n_accounts = n_accounts * slot_list_len;

        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        var allocator = gpa.allocator();

        var logger = Logger{ .noop = {} };
        var accounts_db: AccountsDB = undefined;
        if (bench_args.index == .disk) {
            // std.debug.print("using disk index\n", .{});
            accounts_db = try AccountsDB.init(allocator, logger, .{
                .disk_index_dir = "test_data/tmp",
                .index_disk_capacity = 0,
                .n_index_bins = 16,
            });
        } else {
            // std.debug.print("using ram index\n", .{});
            accounts_db = try AccountsDB.init(allocator, logger, .{
                .index_ram_capacity = 16,
            });
        }
        defer accounts_db.deinit();

        var random = std.rand.DefaultPrng.init(19);
        var rng = random.random();

        var pubkeys = try allocator.alloc(Pubkey, n_accounts);
        defer allocator.free(pubkeys);
        for (0..n_accounts) |i| {
            pubkeys[i] = Pubkey.random(rng);
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
            var slot_list_filenames = try ArrayList([]const u8).initCapacity(allocator, slot_list_len);
            defer slot_list_filenames.deinit();

            var account_files = try ArrayList(AccountFile).initCapacity(allocator, slot_list_len);
            defer account_files.deinit();

            // defer {
            //     for (slot_list_filenames.items) |filepath| {
            //         std.fs.cwd().deleteFile(filepath) catch {
            //             std.debug.print("failed to delete file: {s}\n", .{filepath});
            //         };
            //     }
            // }

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
                const filepath = try std.fmt.allocPrint(allocator, "test_data/tmp/slot{d}.bin", .{s});

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

                    var memory = try std.os.mmap(
                        null,
                        aligned_size,
                        std.os.PROT.READ | std.os.PROT.WRITE,
                        std.os.MAP.SHARED, // need it written to the file before it can be used
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

                var file = try std.fs.cwd().openFile(filepath, .{ .mode = .read_write });
                var account_file = try AccountFile.init(file, .{ .id = s, .length = length }, s);
                if (s < bench_args.n_accounts_multiple) {
                    try accounts_db.indexAccountFile(&account_file);
                } else {
                    slot_list_filenames.appendAssumeCapacity(filepath);
                    account_files.appendAssumeCapacity(account_file);
                }
            }

            var timer = try std.time.Timer.start();
            for (account_files.items) |*account_file| {
                try accounts_db.indexAccountFile(account_file);
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
