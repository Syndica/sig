const std = @import("std");
const builtin = @import("builtin");
const ArrayList = std.ArrayList;

const Account = @import("../core/account.zig").Account;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/time.zig").Slot;
const Epoch = @import("../core/time.zig").Epoch;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");

const sysvars = @import("../core/sysvars.zig");

const AccountsDbFields = @import("../core/snapshot_fields.zig").AccountsDbFields;
const AccountFileInfo = @import("../core/snapshot_fields.zig").AccountFileInfo;

const AccountFile = @import("../core/accounts_file.zig").AccountFile;
const FileId = @import("../core/accounts_file.zig").FileId;
const AccountFileAccountInfo = @import("../core/accounts_file.zig").AccountFileAccountInfo;
const PubkeyAccountRef = @import("../core/accounts_file.zig").PubkeyAccountRef;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;
const Channel = @import("../sync/channel.zig").Channel;

const merkleTreeHash = @import("../common/merkle_tree.zig").merkleTreeHash;
const GenesisConfig = @import("../core/genesis_config.zig").GenesisConfig;
const StatusCache = @import("../core/snapshot_fields.zig").StatusCache;

const SnapshotFields = @import("../core/snapshot_fields.zig").SnapshotFields;
const BankIncrementalSnapshotPersistence = @import("../core/snapshot_fields.zig").BankIncrementalSnapshotPersistence;

const Bank = @import("./bank.zig").Bank;

pub const MERKLE_FANOUT: usize = 16;
pub const ACCOUNT_INDEX_BINS: usize = 8192;

pub const AccountRef = packed struct {
    slot: Slot,
    file_id: FileId,
    offset: u32,
};
const AccountFileChannel = Channel(struct { AccountFile, ArrayList(PubkeyAccountRef) });

pub const AccountsDB = struct {
    allocator: std.mem.Allocator,
    account_file_map: std.AutoArrayHashMap(FileId, AccountFile),

    index: std.AutoArrayHashMap(Pubkey, ArrayList(AccountRef)),
    index_bins: AccountIndexBins,

    accounts_db_fields: AccountsDbFields = undefined,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .account_file_map = std.AutoArrayHashMap(FileId, AccountFile).init(allocator),
            .index = std.AutoArrayHashMap(Pubkey, ArrayList(AccountRef)).init(allocator),
            .index_bins = try AccountIndexBins.init(allocator, ACCOUNT_INDEX_BINS),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.account_file_map.values()) |*af| {
            af.deinit();
        }
        self.account_file_map.deinit();

        for (self.index.values()) |*refs| {
            refs.deinit();
        }
        self.index.deinit();
    }

    pub const IndexTask = struct {
        thread_bins: []ArrayList(*PubkeyAccountRef),
        file_map: std.AutoArrayHashMap(FileId, AccountFile),

        pub fn init(allocator: std.mem.Allocator, n_bins: usize) !@This() {
            var thread_bins = try allocator.alloc(ArrayList(*PubkeyAccountRef), n_bins);
            return @This(){
                .thread_bins = thread_bins,
                .file_map = std.AutoArrayHashMap(FileId, AccountFile).init(allocator),
            };
        }
    };

    /// loads the account files and create the pubkey indexes
    pub fn loadFromSnapshot(
        self: *Self,
        accounts_db_fields: AccountsDbFields,
        accounts_path: []const u8,
    ) !void {
        self.accounts_db_fields = accounts_db_fields;

        // start the indexing
        var timer = std.time.Timer.start() catch unreachable;
        std.debug.print("starting indexing...\n", .{});
        timer.reset();

        var accounts_dir = try std.fs.cwd().openIterableDir(accounts_path, .{});
        defer accounts_dir.close();

        var files = try readDirectory(self.allocator, accounts_dir);
        var filenames = files.filenames;
        defer {
            filenames.deinit();
            self.allocator.free(files.mem);
        }

        var n_account_files: usize = 0;
        for (filenames.items) |filename| {
            var fiter = std.mem.tokenizeSequence(u8, filename, ".");
            const slot = std.fmt.parseInt(Slot, fiter.next().?, 10) catch continue;
            if (accounts_db_fields.file_map.contains(slot)) {
                n_account_files += 1;
            }
        }
        std.debug.print("found {d} account files\n", .{n_account_files});
        std.debug.assert(n_account_files > 0);

        var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;
        var chunk_size = n_account_files / n_threads;
        if (chunk_size == 0) {
            n_threads = 1;
            chunk_size = n_account_files;
        }
        std.debug.print("using {d} threads with {d} account_files per thread\n", .{ n_threads, chunk_size });

        var handles = try ArrayList(std.Thread).initCapacity(self.allocator, n_threads);
        defer handles.deinit();

        var tasks = try ArrayList(IndexTask).initCapacity(self.allocator, n_threads);
        // defer tasks.deinit();

        const n_bins = self.index_bins.bins.len;

        var start_index: usize = 0;
        var end_index: usize = 0;
        for (0..n_threads) |i| {
            if (i == (n_threads - 1)) {
                end_index = filenames.items.len;
            } else {
                end_index = start_index + chunk_size;
            }

            var index_task = try IndexTask.init(self.allocator, n_bins);
            tasks.appendAssumeCapacity(index_task);

            const handle = try std.Thread.spawn(.{}, binAccountFiles, .{
                accounts_path,
                &accounts_db_fields,
                &self.index_bins,
                // per task files
                filenames.items[start_index..end_index],
                tasks.items[i].thread_bins,
                &tasks.items[i].file_map,
            });

            handles.appendAssumeCapacity(handle);
            start_index = end_index;
        }
        std.debug.assert(end_index == filenames.items.len);

        for (handles.items) |handle| {
            handle.join();
        }
        std.debug.print("\n", .{});
        std.debug.print("total time: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        // preallocate per bin
        std.debug.print("preallocating size for full bins\n", .{});
        var total_accounts: usize = 0;
        for (0..n_bins) |i| {
            var bin_total_accounts: usize = 0;
            for (tasks.items) |*task| {
                bin_total_accounts += task.thread_bins[i].items.len;
            }
            total_accounts += bin_total_accounts;
            // allocate all the keys and values (pubkeys and ptr to arraylists)
            try self.index_bins.bins[i].pubkey_map.ensureTotalCapacity(bin_total_accounts);
        }
        // preallocate the memory for the arraylists
        var account_ref_memory = try self.allocator.alloc(AccountRef, total_accounts);
        std.debug.print("total time: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        chunk_size = n_bins / n_threads;
        if (chunk_size == 0) {
            n_threads = 1;
            chunk_size = n_bins;
        }
        std.debug.print("using {d} threads with {d} bins per thread\n", .{ n_threads, chunk_size });

        handles.clearRetainingCapacity();

        start_index = 0;
        end_index = 0;
        for (0..n_threads) |i| {
            if (i == (n_threads - 1)) {
                end_index = n_bins;
            } else {
                end_index = start_index + chunk_size;
            }

            const handle = try std.Thread.spawn(.{}, indexFromBins, .{
                &self.index_bins,
                // per task files
                &tasks,
                account_ref_memory,
                start_index,
                end_index,
            });

            handles.appendAssumeCapacity(handle);
            start_index = end_index;
        }

        for (tasks.items) |*task| {
            var iter = task.file_map.iterator();
            while (iter.next()) |entry| {
                try self.account_file_map.putNoClobber(entry.key_ptr.*, entry.value_ptr.*);
            }
        }

        for (handles.items) |handle| {
            handle.join();
        }
        std.debug.print("\n", .{});
        std.debug.print("total time: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();
    }

    pub fn binAccountFiles(
        accounts_dir_path: []const u8,
        accounts_db_fields: *const AccountsDbFields,
        index_bins: *AccountIndexBins,
        // task specific
        file_names: [][]const u8,
        thread_bins: []ArrayList(*PubkeyAccountRef),
        file_map: *std.AutoArrayHashMap(FileId, AccountFile),
    ) !void {
        var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = false }){};
        var allocator = gpa.allocator();

        // preallocate some things
        const accounts_per_file_estimate = 900; // TODO: tune?
        const n_refs_estimate = accounts_per_file_estimate * file_names.len;
        var refs = try ArrayList(PubkeyAccountRef).initCapacity(allocator, n_refs_estimate);
        try file_map.ensureTotalCapacity(file_names.len);

        var timer = try std.time.Timer.start();
        var str_buf: [1024]u8 = undefined;
        // NOTE: might need to be longer depending on abs path length
        var abs_path_buf: [1024]u8 = undefined;

        for (file_names, 1..) |file_name, file_count| {
            // parse "{slot}.{id}" from the file_name
            var fiter = std.mem.tokenizeSequence(u8, file_name, ".");
            const slot = std.fmt.parseInt(Slot, fiter.next().?, 10) catch |err| {
                std.debug.print("failed to parse slot from {s}\n", .{file_name});
                return err;
            };
            const accounts_file_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

            // read metadata
            const slot_metas: ArrayList(AccountFileInfo) = accounts_db_fields.file_map.get(slot) orelse {
                // dont read account files which are not in the file_map
                std.debug.print("failed to read metadata for slot {d}\n", .{slot});
                continue;
            };
            std.debug.assert(slot_metas.items.len == 1);
            const slot_meta = slot_metas.items[0];
            if (slot_meta.id != accounts_file_id) {
                std.debug.panic("slot_meta.id ({d}) != accounts_file_id ({d})\n", .{ slot_meta.id, accounts_file_id });
            }

            // read appendVec from file
            const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir_path, file_name });
            const accounts_file_file = try std.fs.cwd().openFile(abs_path, .{ .mode = .read_write });
            var accounts_file = AccountFile.init(accounts_file_file, slot_meta, slot) catch |err| {
                std.debug.panic("failed to *open* appendVec {s}: {s}\n", .{ file_name, @errorName(err) });
            };

            accounts_file.sanitizeAndGetAccountsRefs(&refs) catch |err| {
                std.debug.panic("failed to *sanitize* appendVec {s}: {s}\n", .{ file_name, @errorName(err) });
            };

            const file_id_u32: u32 = @intCast(accounts_file_id);
            file_map.putAssumeCapacityNoClobber(file_id_u32, accounts_file);

            if (file_count % 1000 == 0 or (file_names.len - file_count) < 1000) {
                const n_accounts_str = try std.fmt.bufPrint(
                    &str_buf,
                    "n_accounts: {d}",
                    .{refs.items.len},
                );
                printTimeEstimate(&timer, file_names.len, file_count, "read and index accounts", n_accounts_str);
            }
        }

        // bin it all
        const n_bins = index_bins.bins.len;
        const n_refs_per_bin = refs.items.len / n_bins;
        for (thread_bins) |*bin| {
            bin.* = try ArrayList(*PubkeyAccountRef).initCapacity(allocator, n_refs_per_bin);
        }

        timer.reset();
        for (refs.items, 0..) |*ref, i | {
            const bin = &thread_bins[index_bins.getBinIndex(&ref.pubkey)];
            try bin.append(ref);

            if (i % 1000 == 0 or (refs.items.len - i) < 1000) {
                printTimeEstimate(&timer, refs.items.len, i, "binning accounts", null);
            }
        }
    }

    pub fn indexFromBins(
        index_bin: *AccountIndexBins,
        tasks: *ArrayList(IndexTask),
        account_ref_memory: []AccountRef,
        bin_start_index: usize,
        bin_end_index: usize,
    ) !void {
        // NOTE: this is ok to leave hanging because we wont ever dealloc this memory
        // we use a different one per thread so we dont need to lock it on allocs
        var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = false }){};
        var allocator = gpa.allocator();

        const total_bins = bin_end_index - bin_start_index;
        var timer = try std.time.Timer.start();

        // compute where this thread should start to write to
        var mem_index: usize = 0;
        for (0..bin_start_index) |bin_index| {
            for (tasks.items) |*task| {
                mem_index += task.thread_bins[bin_index].items.len;
            }
        }

        for (bin_start_index..bin_end_index, 1..) |bin_index, count| {
            for (tasks.items) |*task| {
                var thread_bin = &task.thread_bins[bin_index];
                for (thread_bin.items) |ref| {
                    var entry = index_bin.bins[bin_index].pubkey_map.getOrPutAssumeCapacity(ref.pubkey);

                    const account_ref_ptr = &account_ref_memory[mem_index];
                    account_ref_ptr.* = AccountRef{
                        .slot = ref.slot,
                        .file_id = @as(u32, @intCast(ref.file_id)),
                        .offset = @as(u32, @intCast(ref.offset)),
                    };
                    defer mem_index += 1;

                    if (!entry.found_existing) {
                        var slice = try allocator.alloc(*AccountRef, 1);
                        slice[0] = account_ref_ptr;
                        var slot_list = std.ArrayList(*AccountRef).fromOwnedSlice(allocator, slice);

                        entry.value_ptr.* = slot_list;
                    } else {
                        var ptr = try entry.value_ptr.addOne();
                        ptr.* = account_ref_ptr;
                    }
                }
            }

            printTimeEstimate(&timer, total_bins, count, "combining bins", null);
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

    /// computes the full accounts hash, accounts-delta-hash, and total lamports
    /// using index data (not account file data)
    pub fn computeAccountHashesAndLamports(self: *Self, config: AccountHashesConfig) !struct { accounts_hash: Hash, total_lamports: u64 } {
        std.debug.print("computing account hashes\n", .{});

        // logic for computing the hashes
        var n_bins: usize = PUBKEY_BINS_FOR_CALCULATING_HASHES;
        // NOTE: because we preallocate sizes per bin, this can be expensive
        // for a large number of bins
        if (builtin.is_test or self.index.count() < 100_000) {
            n_bins = 256;
        }
        var bins = try PubkeyBins.initAndPreAlloc(self.allocator, n_bins, 1_000);
        defer bins.deinit();

        // populate the bins
        for (self.index_bins.bins) |*bin| {
            for (bin.pubkey_map.keys()) |*pubkey| {
                try bins.insert(pubkey);
            }
        }

        std.debug.print("sorting {d} bins\n", .{n_bins});
        var timer = try std.time.Timer.start();
        var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount()));
        var chunk_size = n_bins / n_threads;
        if (chunk_size == 0) {
            n_threads = 1;
            chunk_size = n_bins;
        }

        var handles = try std.ArrayList(std.Thread).initCapacity(self.allocator, n_threads);
        defer handles.deinit();

        var start_index: usize = 0;
        var end_index: usize = 0;
        for (0..n_threads) |i| {
            if (i == (n_threads - 1)) {
                end_index = n_bins;
            } else {
                end_index = start_index + chunk_size;
            }
            var handle = try std.Thread.spawn(.{}, sortBins, .{
                bins.bins,
                start_index,
                end_index,
            });
            handles.appendAssumeCapacity(handle);
            start_index = end_index;
        }
        std.debug.assert(end_index == n_bins);

        for (handles.items) |handle| {
            handle.join();
        }
        std.debug.print("\n", .{});
        std.debug.print("sorting took: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        // compute merkle tree over the slices
        std.debug.print("gathering account hashes\n", .{});
        var total_accounts: usize = 0;
        for (bins.bins) |*bin| {
            total_accounts += bin.items.len;
        }

        // used for full hashes
        var hashes = try ArrayList(Hash).initCapacity(self.allocator, total_accounts);
        defer hashes.deinit();

        var total_lamports: u64 = 0;
        for (bins.bins) |*bin| {
            for (bin.items) |pubkey| {
                const bin_ptr = try self.index_bins.getBin(pubkey);
                const slot_list: ArrayList(*AccountRef) = bin_ptr.pubkey_map.get(pubkey.*).?;
                std.debug.assert(slot_list.items.len > 0);

                // get the most recent state of the account
                const max_slot_index = switch (config) {
                    .FullAccountHash => |full_config| slotListArgmaxWithMax(slot_list, full_config.max_slot),
                    .IncrementalAccountHash => |inc_config| slotListArgmaxWithMin(slot_list, inc_config.min_slot),
                } orelse continue;

                const max_account_loc = slot_list.items[max_slot_index];
                const account = try self.getAccountInner(
                    max_account_loc.file_id,
                    @as(usize, @intCast(max_account_loc.offset)),
                );

                // only include non-zero lamport accounts (for full snapshots)
                const lamports = account.lamports();
                if (config == .FullAccountHash and lamports == 0) continue;

                hashes.appendAssumeCapacity(account.hash.*);
                total_lamports += lamports;
            }
        }
        std.debug.print("took {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        std.debug.print("computing the full account merkle root over {d} accounts\n", .{hashes.items.len});
        const accounts_hash = try merkleTreeHash(hashes.items, MERKLE_FANOUT);
        std.debug.print("took {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        return .{
            .accounts_hash = accounts_hash.*,
            .total_lamports = total_lamports,
        };
    }

    /// validates the accounts_db which was loaded from a snapshot
    pub fn validateLoadFromSnapshot(
        self: *Self,
        // used to verify the incremental snapshot
        incremental_snapshot_persistence: ?BankIncrementalSnapshotPersistence,
        // used to verify the full snapshot
        full_snapshot_slot: Slot,
        expected_full_lamports: u64,
    ) !void {
        const expected_accounts_hash = self.accounts_db_fields.bank_hash_info.accounts_hash;

        // validate the full snapshot
        const full_result = try self.computeAccountHashesAndLamports(AccountHashesConfig{
            .FullAccountHash = .{
                .max_slot = full_snapshot_slot,
            },
        });
        const total_lamports = full_result.total_lamports;
        const accounts_hash = full_result.accounts_hash;

        if (expected_full_lamports != total_lamports) {
            std.debug.print("incorrect total lamports\n", .{});
            std.debug.print("expected vs calculated: {d} vs {d}\n", .{ expected_full_lamports, total_lamports });
            return error.IncorrectTotalLamports;
        }
        if (expected_accounts_hash.cmp(&accounts_hash) != .eq) {
            std.debug.print("incorrect accounts hash\n", .{});
            std.debug.print("expected vs calculated: {s} vs {s}\n", .{ expected_accounts_hash, accounts_hash });
            return error.IncorrectAccountsHash;
        }

        // validate the incremental snapshot
        if (incremental_snapshot_persistence == null) return;
        std.debug.print("validating the incremental snapshot\n", .{});
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
            std.debug.print("incorrect incremental lamports\n", .{});
            std.debug.print("expected vs calculated: {d} vs {d}\n", .{ expected_incremental_lamports, incremental_lamports });
            return error.IncorrectIncrementalLamports;
        }

        if (expected_accounts_delta_hash.cmp(&accounts_delta_hash) != .eq) {
            std.debug.print("incorrect accounts delta hash\n", .{});
            std.debug.print("expected vs calculated: {s} vs {s}\n", .{ expected_accounts_delta_hash, accounts_delta_hash });
            return error.IncorrectAccountsDeltaHash;
        }
    }

    pub fn getSlotHistory(self: *const Self) !sysvars.SlotHistory {
        return try self.getTypeFromAccount(
            sysvars.SlotHistory,
            &sysvars.IDS.slot_history,
        );
    }

    pub inline fn slotListArgmaxWithMin(
        slot_list: ArrayList(*AccountRef),
        min_slot: Slot,
    ) ?usize {
        if (slot_list.items.len == 0) {
            return null;
        }

        var biggest: *AccountRef = undefined;
        var biggest_index: ?usize = null;
        for (slot_list.items, 0..) |item, i| {
            if (item.slot > min_slot and (biggest_index == null or item.slot > biggest.slot)) {
                biggest = item;
                biggest_index = i;
            }
        }

        return biggest_index;
    }

    pub inline fn slotListArgmaxWithMax(
        slot_list: ArrayList(*AccountRef),
        max_slot: Slot,
    ) ?usize {
        if (slot_list.items.len == 0) {
            return null;
        }

        var biggest: *AccountRef = undefined;
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
        slot_list: ArrayList(*AccountRef),
    ) ?usize {
        return std.sort.argMax(
            *AccountRef,
            slot_list.items,
            {},
            struct {
                fn lessThan(_: void, a: *AccountRef, b: *AccountRef) bool {
                    return a.slot < b.slot;
                }
            }.lessThan,
        );
    }

    /// gets an account given an associated pubkey
    pub fn getAccount(self: *const Self, pubkey: *const Pubkey) !AccountFileAccountInfo {
        const bin = try self.index_bins.getBin(pubkey);
        const refs = bin.pubkey_map.get(pubkey.*) orelse {
            return error.PubkeyNotInIndex;
        };
        std.debug.assert(refs.items.len > 0);

        // this is a safe unwrap because we know refs.len > 0
        const max_account_index = slotListArgmax(refs).?;
        const max_account_loc = refs.items[max_account_index];
        const account = try self.getAccountInner(
            max_account_loc.file_id,
            @as(usize, @intCast(max_account_loc.offset)),
        );
        return account;
    }

    /// gets an account given an file_id and offset value
    pub fn getAccountInner(self: *const Self, file_id: FileId, offset: usize) !AccountFileAccountInfo {
        const accounts_file: AccountFile = self.account_file_map.get(file_id) orelse return error.FileIdNotFound;
        const account = accounts_file.getAccount(offset) catch {
            return error.InvalidOffset;
        };
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

pub fn printTimeEstimate(
    // timer should be started at the beginning
    timer: *std.time.Timer,
    total: usize,
    i: usize,
    comptime name: []const u8,
    other_info: ?[]const u8,
) void {
    if (i == 0 or total == 0) return;

    const p_done = i * 100 / total;
    const left = total - i;

    const elapsed = timer.read();
    const ns_per_vec = elapsed / i;
    const ns_left = ns_per_vec * left;

    if (other_info) |info| {
        std.debug.print("{s}: {d}/{d} ({d}%) {s} (time left: {s})\r", .{
            name,
            i,
            total,
            p_done,
            info,
            std.fmt.fmtDuration(ns_left),
        });
    } else {
        std.debug.print("{s}: {d}/{d} ({d}%) (time left: {s})\r", .{
            name,
            i,
            total,
            p_done,
            std.fmt.fmtDuration(ns_left),
        });
    }
}

pub fn readDirectory(
    allocator: std.mem.Allocator,
    directory: std.fs.IterableDir,
) !struct { filenames: ArrayList([]u8), mem: []u8 } {
    var dir_iter = directory.iterate();
    var total_name_size: usize = 0;
    var total_files: usize = 0;
    while (try dir_iter.next()) |entry| {
        total_name_size += entry.name.len;
        total_files += 1;
    }
    var mem = try allocator.alloc(u8, total_name_size);
    errdefer allocator.free(mem);

    dir_iter = directory.iterate(); // reset

    var filenames = try ArrayList([]u8).initCapacity(allocator, total_files);
    errdefer filenames.deinit();

    var index: usize = 0;
    while (try dir_iter.next()) |file_entry| {
        const file_name_len = file_entry.name.len;
        @memcpy(mem[index..(index + file_name_len)], file_entry.name);
        filenames.appendAssumeCapacity(mem[index..(index + file_name_len)]);
        index += file_name_len;
    }
    dir_iter = directory.iterate(); // reset

    return .{ .filenames = filenames, .mem = mem };
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

pub const PUBKEY_BINS_FOR_CALCULATING_HASHES: usize = 65_536;

pub const AccountIndex = struct {
    pubkey_map: std.AutoArrayHashMap(Pubkey, ArrayList(*AccountRef)),
    mux: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) !AccountIndex {
        return AccountIndex{ .pubkey_map = std.AutoArrayHashMap(Pubkey, ArrayList(*AccountRef)).init(allocator) };
    }

    pub fn deinit(self: *AccountIndex) void {
        var iter = self.pubkey_map.iterator();
        while (iter.next()) |*entry| {
            entry.value_ptr.deinit();
        }
        self.pubkey_map.deinit();
    }
};

pub const AccountIndexBins = struct {
    bins: []AccountIndex,
    calculator: PubkeyBinCalculator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, n_bins: usize) !Self {
        const calculator = PubkeyBinCalculator.init(n_bins);

        var bins = try allocator.alloc(AccountIndex, n_bins);
        for (bins) |*bin| {
            bin.* = try AccountIndex.init(allocator);
        }

        return Self{
            .bins = bins,
            .calculator = calculator,
        };
    }

    pub fn deinit(self: *Self) void {
        const allocator = self.bins[0].allocator;
        for (self.bins) |*bin| {
            bin.deinit();
        }
        allocator.free(self.bins);
    }

    pub fn getBinIndex(self: *Self, pubkey: *const Pubkey) usize {
        return self.calculator.binIndex(pubkey);
    }

    pub fn getBin(self: *const Self, pubkey: *const Pubkey) !*AccountIndex {
        const bin_index = self.calculator.binIndex(pubkey);
        return &self.bins[bin_index];
    }
};

pub const PubkeyBins = struct {
    bins: []BinType,
    calculator: PubkeyBinCalculator,

    const Self = @This();
    const BinType = ArrayList(*const Pubkey);

    pub fn init(allocator: std.mem.Allocator, n_bins: usize) Self {
        return Self.initAndPreAlloc(allocator, n_bins, null);
    }

    pub fn initAndPreAlloc(allocator: std.mem.Allocator, n_bins: usize, preallocate_len: usize) !Self {
        const calculator = PubkeyBinCalculator.init(n_bins);

        var bins = try allocator.alloc(BinType, n_bins);
        for (bins) |*bin| {
            bin.* = try BinType.initCapacity(allocator, preallocate_len);
        }

        return Self{
            .bins = bins,
            .calculator = calculator,
        };
    }

    pub fn deinit(self: *Self) void {
        const allocator = self.bins[0].allocator;
        for (self.bins) |*bin| {
            bin.deinit();
        }
        allocator.free(self.bins);
    }

    pub fn insert(self: *Self, pubkey: *const Pubkey) !void {
        const bin_index = self.calculator.binIndex(pubkey);
        try self.bins[bin_index].append(pubkey);
    }
};

pub fn sortBins(
    bins: []ArrayList(*const Pubkey),
    bin_start_index: usize,
    bin_end_index: usize,
) !void {
    const total_bins = bin_end_index - bin_start_index;
    var timer = try std.time.Timer.start();

    for (bin_start_index..bin_end_index, 1..) |bin_i, count| {
        var bin = bins[bin_i];

        std.mem.sort(*const Pubkey, bin.items, {}, struct {
            fn lessThan(_: void, lhs: *const Pubkey, rhs: *const Pubkey) bool {
                return std.mem.lessThan(u8, &lhs.data, &rhs.data);
            }
        }.lessThan);

        if (count % 1000 == 0) {
            printTimeEstimate(&timer, total_bins, count, "sortBins", null);
        }
    }
}

pub const FullSnapshotPath = struct {
    path: []const u8,
    slot: Slot,
    hash: []const u8,

    /// matches with the regex: r"^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$";
    pub fn fromPath(path: []const u8) !FullSnapshotPath {
        var ext_parts = std.mem.splitSequence(u8, path, ".");
        const stem = ext_parts.next() orelse return error.InvalidSnapshotPath;

        var extn = ext_parts.rest();
        // only support tar.zst
        if (!std.mem.eql(u8, extn, "tar.zst"))
            return error.InvalidSnapshotPath;

        var parts = std.mem.splitSequence(u8, stem, "-");
        const header = parts.next() orelse return error.InvalidSnapshotPath;
        if (!std.mem.eql(u8, header, "snapshot"))
            return error.InvalidSnapshotPath;

        const slot_str = parts.next() orelse return error.InvalidSnapshotPath;
        const slot = std.fmt.parseInt(Slot, slot_str, 10) catch return error.InvalidSnapshotPath;

        var hash = parts.next() orelse return error.InvalidSnapshotPath;

        return FullSnapshotPath{ .path = path, .slot = slot, .hash = hash };
    }
};

pub const IncrementalSnapshotPath = struct {
    path: []const u8,
    // this references the full snapshot slot
    base_slot: Slot,
    slot: Slot,
    hash: []const u8,

    /// matches against regex: r"^incremental-snapshot-(?P<base>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$";
    pub fn fromPath(path: []const u8) !IncrementalSnapshotPath {
        var ext_parts = std.mem.splitSequence(u8, path, ".");
        const stem = ext_parts.next() orelse return error.InvalidSnapshotPath;

        var extn = ext_parts.rest();
        // only support tar.zst
        if (!std.mem.eql(u8, extn, "tar.zst"))
            return error.InvalidSnapshotPath;

        var parts = std.mem.splitSequence(u8, stem, "-");
        var header = parts.next() orelse return error.InvalidSnapshotPath;
        if (!std.mem.eql(u8, header, "incremental"))
            return error.InvalidSnapshotPath;

        header = parts.next() orelse return error.InvalidSnapshotPath;
        if (!std.mem.eql(u8, header, "snapshot"))
            return error.InvalidSnapshotPath;

        const base_slot_str = parts.next() orelse return error.InvalidSnapshotPath;
        const base_slot = std.fmt.parseInt(Slot, base_slot_str, 10) catch return error.InvalidSnapshotPath;

        const slot_str = parts.next() orelse return error.InvalidSnapshotPath;
        const slot = std.fmt.parseInt(Slot, slot_str, 10) catch return error.InvalidSnapshotPath;

        var hash = parts.next() orelse return error.InvalidSnapshotPath;

        return IncrementalSnapshotPath{
            .path = path,
            .slot = slot,
            .base_slot = base_slot,
            .hash = hash,
        };
    }
};

pub const SnapshotPaths = struct {
    full_snapshot: FullSnapshotPath,
    incremental_snapshot: ?IncrementalSnapshotPath,

    /// finds existing snapshots (full and matching incremental) by looking for .tar.zstd files
    pub fn find(allocator: std.mem.Allocator, snapshot_dir: []const u8) !SnapshotPaths {
        var snapshot_dir_iter = try std.fs.cwd().openIterableDir(snapshot_dir, .{});
        defer snapshot_dir_iter.close();

        var files = try readDirectory(allocator, snapshot_dir_iter);
        var filenames = files.filenames;
        defer {
            filenames.deinit();
            allocator.free(files.mem);
        }

        // find the snapshots
        var maybe_latest_full_snapshot: ?FullSnapshotPath = null;
        var count: usize = 0;
        for (filenames.items) |filename| {
            const snap_path = FullSnapshotPath.fromPath(filename) catch continue;
            if (count == 0 or snap_path.slot > maybe_latest_full_snapshot.?.slot) {
                maybe_latest_full_snapshot = snap_path;
            }
            count += 1;
        }
        var latest_full_snapshot = maybe_latest_full_snapshot orelse return error.NoFullSnapshotFound;
        // clone the name so we can deinit the full array
        latest_full_snapshot.path = try allocator.dupe(u8, latest_full_snapshot.path);

        count = 0;
        var maybe_latest_incremental_snapshot: ?IncrementalSnapshotPath = null;
        for (filenames.items) |filename| {
            const snap_path = IncrementalSnapshotPath.fromPath(filename) catch continue;
            // need to match the base slot
            if (snap_path.base_slot == latest_full_snapshot.slot and (count == 0 or
                // this unwrap is safe because count > 0
                snap_path.slot > maybe_latest_incremental_snapshot.?.slot))
            {
                maybe_latest_incremental_snapshot = snap_path;
            }
            count += 1;
        }

        return .{
            .full_snapshot = latest_full_snapshot,
            .incremental_snapshot = maybe_latest_incremental_snapshot,
        };
    }
};

pub const Snapshots = struct {
    full: SnapshotFields,
    incremental: ?SnapshotFields,

    pub fn readFromPaths(allocator: std.mem.Allocator, snapshot_dir: []const u8, paths: *const SnapshotPaths) !Snapshots {
        // unpack
        const full_metadata_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/{d}/{d}",
            .{ snapshot_dir, "snapshots", paths.full_snapshot.slot, paths.full_snapshot.slot },
        );
        defer allocator.free(full_metadata_path);

        var full = try SnapshotFields.readFromFilePath(
            allocator,
            full_metadata_path,
        );

        var incremental: ?SnapshotFields = null;
        if (paths.incremental_snapshot) |incremental_snapshot_path| {
            const incremental_metadata_path = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}/{d}/{d}",
                .{ snapshot_dir, "snapshots", incremental_snapshot_path.slot, incremental_snapshot_path.slot },
            );
            defer allocator.free(incremental_metadata_path);

            incremental = try SnapshotFields.readFromFilePath(
                allocator,
                incremental_metadata_path,
            );
        }

        return Snapshots{
            .full = full,
            .incremental = incremental,
        };
    }

    /// collapse all full and incremental snapshots into one.
    /// note: this works by stack copying the full snapshot and combining
    /// the accounts-db account file map.
    /// this will 1) modify the incremental snapshot account map
    /// and 2) the returned snapshot heap fields will still point to the incremental snapshot
    /// (so be sure not to deinit it while still using the returned snapshot)
    pub fn collapse(self: *Snapshots) !SnapshotFields {
        // nothing to collapse
        if (self.incremental == null)
            return self.full;

        // collapse bank fields into the
        var snapshot = self.incremental.?; // stack copy
        const full_slot = self.full.bank_fields.slot;

        // collapse accounts-db fields
        var storages_map = &self.incremental.?.accounts_db_fields.file_map;
        // make sure theres no overlap in slots between full and incremental and combine
        var storages_entry_iter = storages_map.iterator();
        while (storages_entry_iter.next()) |*incremental_entry| {
            const slot = incremental_entry.key_ptr.*;

            // only keep slots > full snapshot slot
            if (!(slot > full_slot)) {
                _ = storages_map.remove(slot);
                continue;
            }

            var slot_entry = try self.full.accounts_db_fields.file_map.getOrPut(slot);
            if (slot_entry.found_existing) {
                std.debug.panic("invalid incremental snapshot: slot {d} is in both full and incremental snapshots\n", .{slot});
            } else {
                slot_entry.value_ptr.* = incremental_entry.value_ptr.*;
            }
        }
        snapshot.accounts_db_fields = self.full.accounts_db_fields;

        return snapshot;
    }
};

/// unpacks a .tar.zstd file into the given directory
pub fn unpackZstdTarBall(allocator: std.mem.Allocator, path: []const u8, output_dir: std.fs.Dir) !void {
    const file = try output_dir.openFile(path, .{});
    defer file.close();

    var timer = try std.time.Timer.start();
    var stream = std.compress.zstd.decompressStream(allocator, file.reader());
    try std.tar.pipeToFileSystem(output_dir, stream.reader(), .{ .mode_mode = .ignore });
    std.debug.print("unpacked {s} in {s}\n", .{ path, std.fmt.fmtDuration(timer.read()) });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    // const snapshot_dir = "test_data/";
    const snapshot_dir = "../snapshots/";

    // this should exist before we start to unpack
    const genesis_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "genesis.bin" },
    );
    defer allocator.free(genesis_path);

    std.fs.cwd().access(genesis_path, .{}) catch {
        std.debug.print("genesis.bin not found: {s}\n", .{genesis_path});
        return error.GenesisNotFound;
    };

    // if this exists, we wont look for a .tar.zstd
    const accounts_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "accounts" },
    );
    defer allocator.free(accounts_path);

    var snapshot_paths = try SnapshotPaths.find(allocator, snapshot_dir);

    // TMP: remove later
    if (std.mem.eql(u8, snapshot_dir, "../snapshots/")) {
        snapshot_paths.incremental_snapshot = null;
    }

    if (snapshot_paths.incremental_snapshot == null) {
        std.debug.print("no incremental snapshot found\n", .{});
    }

    std.fs.cwd().access(accounts_path, .{}) catch {
        std.debug.print("accounts/ not found ... unpacking snapshots...\n", .{});
        // if accounts/ doesnt exist then we unpack the found snapshots
        var snapshot_dir_iter = try std.fs.cwd().openIterableDir(snapshot_dir, .{});
        defer snapshot_dir_iter.close();

        try unpackZstdTarBall(allocator, snapshot_paths.full_snapshot.path, snapshot_dir_iter.dir);
        if (snapshot_paths.incremental_snapshot) |incremental_snapshot| {
            try unpackZstdTarBall(allocator, incremental_snapshot.path, snapshot_dir_iter.dir);
        }
    };

    var timer = try std.time.Timer.start();
    std.debug.print("reading snapshots...\n", .{});
    var snapshots = try Snapshots.readFromPaths(allocator, snapshot_dir, &snapshot_paths);
    std.debug.print("read snapshots in {s}\n", .{std.fmt.fmtDuration(timer.read())});
    const full_snapshot = snapshots.full;

    // load and validate
    var accounts_db = try AccountsDB.init(allocator);
    defer accounts_db.deinit();

    const snapshot = try snapshots.collapse();

    timer.reset();
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

    // use the genesis to validate the bank
    const genesis_config = try GenesisConfig.init(allocator, genesis_path);
    defer genesis_config.deinit(allocator);

    std.debug.print("validating bank...\n", .{});
    var bank = Bank.init(&accounts_db, &snapshot.bank_fields);
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

test "core.accounts_db: test full snapshot path parsing" {
    const full_snapshot_path = "snapshot-269-EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn.tar.zst";
    const snapshot_info = try FullSnapshotPath.fromPath(full_snapshot_path);

    try std.testing.expect(snapshot_info.slot == 269);
    try std.testing.expect(std.mem.eql(u8, snapshot_info.hash, "EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn"));
    try std.testing.expect(std.mem.eql(u8, snapshot_info.path, full_snapshot_path));
}

test "core.accounts_db: test incremental snapshot path parsing" {
    const path = "incremental-snapshot-269-307-4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB.tar.zst";
    const snapshot_info = try IncrementalSnapshotPath.fromPath(path);

    try std.testing.expect(snapshot_info.base_slot == 269);
    try std.testing.expect(snapshot_info.slot == 307);
    try std.testing.expect(std.mem.eql(u8, snapshot_info.hash, "4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB"));
    try std.testing.expect(std.mem.eql(u8, snapshot_info.path, path));
}

fn loadTestAccountsDB() !struct { AccountsDB, SnapshotFields } {
    std.debug.assert(builtin.is_test); // should only be used in tests

    var allocator = std.testing.allocator;

    const full_metadata_path = "test_data/10";
    var full_snapshot_fields = try SnapshotFields.readFromFilePath(
        allocator,
        full_metadata_path,
    );

    var accounts_db = try AccountsDB.init(allocator);

    const accounts_path = "test_data/accounts";
    const dir = try std.fs.cwd().openDir("test_data", .{});

    dir.access("accounts", .{}) catch {
        // unpack both snapshots to get the acccount files
        try unpackZstdTarBall(allocator, "snapshot-10-6ExseAZAVJsAZjhimxHTR7N8p6VGXiDNdsajYh1ipjAD.tar.zst", dir);
        try unpackZstdTarBall(allocator, "incremental-snapshot-10-25-GXgKvm3NMAPgGdv2verVaNXmKTHQgfy2TAxLVEfAvdCS.tar.zst", dir);
    };

    try accounts_db.loadFromSnapshot(full_snapshot_fields.accounts_db_fields, accounts_path);

    return .{
        accounts_db,
        full_snapshot_fields,
    };
}

test "core.accounts_db: load and validate from test snapshot" {
    var allocator = std.testing.allocator;

    var result = try loadTestAccountsDB();
    var accounts_db = result[0];
    defer accounts_db.deinit();
    var full_snapshot_fields = result[1];
    defer full_snapshot_fields.deinit(allocator);

    try accounts_db.validateLoadFromSnapshot(
        null,
        full_snapshot_fields.bank_fields.slot,
        full_snapshot_fields.bank_fields.capitalization,
    );
}

test "core.accounts_db: load clock sysvar" {
    var allocator = std.testing.allocator;

    var result = try loadTestAccountsDB();
    var accounts_db = result[0];
    defer accounts_db.deinit();
    var full_snapshot_fields = result[1];
    defer full_snapshot_fields.deinit(allocator);

    const clock = try accounts_db.getTypeFromAccount(sysvars.Clock, &sysvars.IDS.clock);
    const expected_clock = sysvars.Clock{
        .slot = 10,
        .epoch_start_timestamp = 1702587901,
        .epoch = 0,
        .leader_schedule_epoch = 1,
        .unix_timestamp = 1702587908,
    };
    std.debug.print("clock: {}\n", .{clock});
    try std.testing.expectEqual(clock, expected_clock);
}

test "core.accounts_db: load other sysvars" {
    var allocator = std.testing.allocator;

    var result = try loadTestAccountsDB();
    var accounts_db = result[0];
    defer accounts_db.deinit();
    var full_snapshot_fields = result[1];
    defer full_snapshot_fields.deinit(allocator);

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
