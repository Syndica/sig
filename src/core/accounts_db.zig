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

const NestedHashTree = @import("../common/merkle_tree.zig").NestedHashTree;

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

    index: AccountIndexBins,
    accounts_db_fields: AccountsDbFields = undefined,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .account_file_map = std.AutoArrayHashMap(FileId, AccountFile).init(allocator),
            .index = try AccountIndexBins.init(allocator, ACCOUNT_INDEX_BINS),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.account_file_map.values()) |*af| {
            af.deinit();
        }
        self.account_file_map.deinit();
    }

    /// used to build AccountsDB from a snapshot in parallel
    pub const ThreadAccountsDB = struct {
        index: AccountIndexBins,
        file_map: std.AutoArrayHashMap(FileId, AccountFile),

        pub fn init(allocator: std.mem.Allocator, n_bins: usize) !@This() {
            return @This(){
                .index = try AccountIndexBins.init(allocator, n_bins),
                .file_map = std.AutoArrayHashMap(FileId, AccountFile).init(allocator),
            };
        }
    };

    /// loads the account files and indexes the accounts
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

        const n_bins = self.index.bins.len;
        const n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;
        var thread_indexes = try ArrayList(ThreadAccountsDB).initCapacity(self.allocator, n_threads);
        for (0..n_threads) |_| {
            const thread_index = try ThreadAccountsDB.init(self.allocator, n_bins);
            thread_indexes.appendAssumeCapacity(thread_index);
        }

        var handles = try spawnThreadTasks(
            self.allocator,
            binAccountFiles,
            .{
                &accounts_db_fields,
                accounts_path,
                thread_indexes.items,
                filenames.items,
            },
            filenames.items.len,
            n_threads,
        );

        for (handles.items) |handle| {
            handle.join();
        }
        handles.deinit();

        std.debug.print("\n", .{});
        std.debug.print("total time: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        // preallocate per bin
        std.debug.print("preallocating size for full bins\n", .{});
        var total_accounts: usize = 0;
        for (0..n_bins) |i| {
            for (thread_indexes.items) |*t_index| {
                total_accounts += @as(u32, @intCast(t_index.index.bins[i].flat_map.items.len));
            }
        }
        var account_ref_memory = try self.allocator.alloc(*PubkeyAccountRef, total_accounts);
        std.debug.print("total time: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        handles = try spawnThreadTasks(
            self.allocator,
            indexFromBins,
            .{
                &self.index,
                &thread_indexes,
                account_ref_memory,
            },
            n_bins,
            n_threads,
        );

        for (thread_indexes.items) |*task| {
            var iter = task.file_map.iterator();
            while (iter.next()) |entry| {
                try self.account_file_map.putNoClobber(entry.key_ptr.*, entry.value_ptr.*);
            }
        }

        for (handles.items) |handle| {
            handle.join();
        }
        handles.deinit();

        std.debug.print("\n", .{});
        std.debug.print("total time: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();
    }

    pub fn binAccountFiles(
        accounts_db_fields: *const AccountsDbFields,
        accounts_dir_path: []const u8,
        thread_indexes: []ThreadAccountsDB,
        file_names: [][]const u8,
        // task specific
        start_index: usize,
        end_index: usize,
        thread_id: usize,
    ) !void {
        var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = false }){};
        var allocator = gpa.allocator();

        // preallocate some things
        const thread_filenames = file_names[start_index..end_index];
        const accounts_per_file_estimate = 900; // TODO: tune?
        const n_refs_estimate = accounts_per_file_estimate * thread_filenames.len;
        var refs = try ArrayList(PubkeyAccountRef).initCapacity(allocator, n_refs_estimate);

        const thread_bins = &thread_indexes[thread_id].index;

        const file_map = &thread_indexes[thread_id].file_map;
        try file_map.ensureTotalCapacity(thread_filenames.len);

        var timer = try std.time.Timer.start();
        var str_buf: [1024]u8 = undefined;
        // NOTE: might need to be longer depending on abs path length
        var abs_path_buf: [1024]u8 = undefined;

        for (thread_filenames, 1..) |file_name, file_count| {
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

            if (file_count % 1000 == 0 or (thread_filenames.len - file_count) < 1000) {
                const n_accounts_str = try std.fmt.bufPrint(
                    &str_buf,
                    "n_accounts: {d}",
                    .{refs.items.len},
                );
                printTimeEstimate(&timer, thread_filenames.len, file_count, "read and index accounts", n_accounts_str);
            }
        }

        // bin it all
        const n_refs_per_bin = refs.items.len / thread_bins.numberOfBins();
        for (thread_bins.bins) |*index| {
            index.* = AccountIndex{ .flat_map = try std.ArrayListUnmanaged(*PubkeyAccountRef).initCapacity(allocator, n_refs_per_bin) };
        }

        timer.reset();
        for (refs.items, 0..) |*ref, i| {
            const index = thread_bins.getPubkeyBin(&ref.pubkey);
            try index.flat_map.append(allocator, ref);

            if (i % 1000 == 0 or (refs.items.len - i) < 1000) {
                printTimeEstimate(&timer, refs.items.len, i, "binning accounts", null);
            }
        }
    }

    pub fn indexFromBins(
        index: *AccountIndexBins,
        thread_indexes: *ArrayList(ThreadAccountsDB),
        mem: []*PubkeyAccountRef,
        //
        bin_start_index: usize,
        bin_end_index: usize,
        thread_id: usize,
    ) !void {
        _ = thread_id;
        const total_bins = bin_end_index - bin_start_index;
        var timer = try std.time.Timer.start();

        var mem_index: usize = 0;
        for (0..bin_start_index) |bin_index| {
            for (thread_indexes.items) |*t_index| {
                mem_index += t_index.index.getBin(bin_index).len();
            }
        }

        for (bin_start_index..bin_end_index, 1..) |bin_index, count| {
            var start_index = mem_index;
            for (thread_indexes.items) |*t_index| {
                const thread_bin = t_index.index.getBin(bin_index);
                const n_thread_refs = thread_bin.len();

                @memcpy(mem[mem_index..(mem_index + n_thread_refs)], thread_bin.flat_map.items);
                mem_index += n_thread_refs;
            }
            const bin_slice = mem[start_index..mem_index];

            std.mem.sort(*PubkeyAccountRef, bin_slice, {}, struct {
                fn lessThan(_: void, lhs: *PubkeyAccountRef, rhs: *PubkeyAccountRef) bool {
                    return std.mem.lessThan(u8, &lhs.pubkey.data, &rhs.pubkey.data);
                }
            }.lessThan);

            index.getBin(bin_index).flat_map = std.ArrayListUnmanaged(*PubkeyAccountRef).fromOwnedSlice(bin_slice);
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

    /// computes a hash across all accounts in the db, and total lamports of those accounts
    /// using index data. depending on the config, this can compute
    /// either full or incremental snapshot values.
    pub fn computeAccountHashesAndLamports(self: *Self, config: AccountHashesConfig) !struct { accounts_hash: Hash, total_lamports: u64 } {
        var timer = try std.time.Timer.start();
        var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;

        // alloc the result
        var hashes = try self.allocator.alloc(ArrayList(Hash), n_threads);
        var lamports = try self.allocator.alloc(u64, n_threads);
        @memset(lamports, 0);
        defer {
            for (hashes) |*h| h.deinit();
            self.allocator.free(hashes);
            self.allocator.free(lamports);
        }

        // split processing the bins over muliple threads
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
        std.debug.print("\n", .{});
        std.debug.print("sorting took: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        var hash_tree = NestedHashTree{ .hashes = hashes };
        std.debug.print("computing the full account merkle root over {d} accounts\n", .{hash_tree.len()});
        const accounts_hash = try hash_tree.computeMerkleRoot(MERKLE_FANOUT);
        std.debug.print("took {s}\n", .{std.fmt.fmtDuration(timer.read())});
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

        if (expected_accounts_hash.cmp(&accounts_hash) != .eq) {
            std.debug.print("incorrect accounts hash\n", .{});
            std.debug.print("expected vs calculated: {s} vs {s}\n", .{ expected_accounts_hash, accounts_hash });
            return error.IncorrectAccountsHash;
        }
        if (expected_full_lamports != total_lamports) {
            std.debug.print("incorrect total lamports\n", .{});
            std.debug.print("expected vs calculated: {d} vs {d}\n", .{ expected_full_lamports, total_lamports });
            return error.IncorrectTotalLamports;
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
            total_len += bin.flat_map.items.len;
        }
        thread_hashes.* = try ArrayList(Hash).initCapacity(self.allocator, total_len);

        var local_total_lamports: u64 = 0;

        var timer = try std.time.Timer.start();
        for (thread_bins, 1..) |bin_ptr, count| {
            var start_index: usize = 0;

            while (start_index < bin_ptr.flat_map.items.len) {
                var slot_start_index: usize = start_index;
                var slot_end_index: usize = start_index;
                var current_pubkey = &bin_ptr.flat_map.items[start_index].pubkey;

                for (bin_ptr.flat_map.items[start_index..]) |ref| {
                    if (ref.pubkey.equals(current_pubkey)) {
                        slot_end_index += 1;
                    } else break;
                }
                start_index = slot_end_index;

                const slot_list = bin_ptr.flat_map.items[slot_start_index..slot_end_index];
                std.debug.assert(slot_list.len > 0);

                // get the most recent state of the account
                const max_slot_index = switch (config) {
                    .FullAccountHash => |full_config| AccountsDB.slotListArgmaxWithMax(slot_list, full_config.max_slot),
                    .IncrementalAccountHash => |inc_config| AccountsDB.slotListArgmaxWithMin(slot_list, inc_config.min_slot),
                } orelse continue;

                const max_account_loc = slot_list[max_slot_index];
                const account = try self.getAccountInnerFast(
                    @as(u32, @intCast(max_account_loc.file_id)),
                    @as(usize, @intCast(max_account_loc.offset)),
                );

                // only include non-zero lamport accounts (for full snapshots)
                const lamports = account.lamports();
                if (config == .FullAccountHash and lamports == 0) continue;

                thread_hashes.appendAssumeCapacity(account.hash.*);
                local_total_lamports += lamports;
            }
            printTimeEstimate(&timer, thread_bins.len, count, "gathering account hashes", null);
        }

        total_lamports[thread_index] = local_total_lamports;
    }

    pub fn getSlotHistory(self: *const Self) !sysvars.SlotHistory {
        return try self.getTypeFromAccount(
            sysvars.SlotHistory,
            &sysvars.IDS.slot_history,
        );
    }

    pub inline fn slotListArgmaxWithMin(
        slot_list: []*PubkeyAccountRef,
        min_slot: Slot,
    ) ?usize {
        if (slot_list.len == 0) {
            return null;
        }

        var biggest: *PubkeyAccountRef = undefined;
        var biggest_index: ?usize = null;
        for (slot_list, 0..) |item, i| {
            if (item.slot > min_slot and (biggest_index == null or item.slot > biggest.slot)) {
                biggest = item;
                biggest_index = i;
            }
        }

        return biggest_index;
    }

    pub inline fn slotListArgmaxWithMax(
        slot_list: []*PubkeyAccountRef,
        max_slot: Slot,
    ) ?usize {
        if (slot_list.len == 0) {
            return null;
        }

        var biggest: *PubkeyAccountRef = undefined;
        var biggest_index: ?usize = null;
        for (slot_list, 0..) |item, i| {
            if (item.slot <= max_slot and (biggest_index == null or item.slot > biggest.slot)) {
                biggest = item;
                biggest_index = i;
            }
        }

        return biggest_index;
    }

    pub inline fn slotListArgmax(
        slot_list: []*PubkeyAccountRef,
    ) ?usize {
        return std.sort.argMax(
            *PubkeyAccountRef,
            slot_list,
            {},
            struct {
                fn lessThan(_: void, a: *PubkeyAccountRef, b: *PubkeyAccountRef) bool {
                    return a.slot < b.slot;
                }
            }.lessThan,
        );
    }

    /// gets an account given an associated pubkey
    pub fn getAccount(self: *const Self, pubkey: *const Pubkey) !AccountFileAccountInfo {
        const pubkey_index = self.index.getPubkeyBin(pubkey);
        const refs = pubkey_index.getSlotList(pubkey);
        if (refs.len == 0) {
            return error.PubkeyNotInIndex;
        }

        // this is a safe unwrap because we know refs.len > 0
        const max_account_index = slotListArgmax(refs).?;
        const max_account_loc = refs[max_account_index];
        const account = try self.getAccountInner(
            @as(u32, @intCast(max_account_loc.file_id)),
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

    /// gets an account given an file_id and offset value
    /// used when reading all the account hashes from the index
    pub fn getAccountInnerFast(self: *const Self, file_id: FileId, offset: usize) !AccountFileAccountInfo {
        const accounts_file: AccountFile = self.account_file_map.get(file_id) orelse return error.FileIdNotFound;
        const account = accounts_file.getAccountFast(offset) catch {
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
    for (0..n_threads) |i| {
        if (i == (n_threads - 1)) {
            end_index = data_len;
        } else {
            end_index = start_index + chunk_size;
        }
        const handle = try std.Thread.spawn(.{}, f, params ++ .{ start_index, end_index, i });
        handles.appendAssumeCapacity(handle);

        start_index = end_index;
    }

    return handles;
}

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

pub fn PubkeyPtrMap(comptime Value: type) type {
    return std.HashMap(*const Pubkey, Value, struct {
        pub fn hash(ctx: @This(), x: *const Pubkey) u64 {
            _ = ctx;
            return @as(u64, x.data[0]) |
                @as(u64, x.data[1]) << 8 |
                @as(u64, x.data[2]) << 16 |
                @as(u64, x.data[3]) << 24;
        }

        pub fn eql(_: @This(), a: *const Pubkey, b: *const Pubkey) bool {
            return a.equals(b);
        }
    }, 80);
}

pub const AccountIndex = struct {
    flat_map: std.ArrayListUnmanaged(*PubkeyAccountRef) = .{},

    pub fn len(self: *const AccountIndex) usize {
        return self.flat_map.items.len;
    }

    pub fn getSlotList(self: *const AccountIndex, pubkey: *const Pubkey) []*PubkeyAccountRef {
        var slot_start_index: usize = 0;
        var slot_end_index: usize = 0;
        var found = false;

        for (self.flat_map.items, 0..) |ref, index| {
            if (ref.pubkey.equals(pubkey)) {
                if (!found) {
                    slot_start_index = index;
                    slot_end_index = index;
                    found = true;
                }
                slot_end_index += 1;
            } else if (found) {
                break;
            }
        }

        return self.flat_map.items[slot_start_index..slot_end_index];
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
            bin.* = AccountIndex{};
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

    pub fn getBin(self: *const Self, index: usize) *AccountIndex {
        return &self.bins[index];
    }

    pub fn getPubkeyBin(self: *const Self, pubkey: *const Pubkey) *AccountIndex {
        const bin_index = self.calculator.binIndex(pubkey);
        return &self.bins[bin_index];
    }

    pub fn numberOfBins(self: *const Self) usize {
        return self.bins.len;
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
        if (maybe_latest_incremental_snapshot) |*latest_incremental_snapshot| {
            latest_incremental_snapshot.path = try allocator.dupe(u8, latest_incremental_snapshot.path);
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

        std.debug.print("reading full snapshot from {s}\n", .{full_metadata_path});

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

            std.debug.print("reading incremental snapshot from {s}\n", .{incremental_metadata_path});

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
    const snapshot_dir = "../../snapshots/";

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
        // "{s}/accounts/run",
        .{snapshot_dir},
    );
    defer allocator.free(accounts_path);

    var snapshot_paths = try SnapshotPaths.find(allocator, snapshot_dir);

    // TMP: remove later
    if (!std.mem.eql(u8, snapshot_dir, "test_data/")) {
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

    var full_timer = try std.time.Timer.start();
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
    std.debug.print("validated from snapshot in {s}\n", .{std.fmt.fmtDuration(timer.read())});
    std.debug.print("full timer: {s}\n", .{std.fmt.fmtDuration(full_timer.read())});

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
