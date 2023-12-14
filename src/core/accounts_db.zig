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
const findSnapshotMetadataPath = @import("../cmd/snapshot_utils.zig").findSnapshotMetadataPath;
const GenesisConfig = @import("../core/genesis_config.zig").GenesisConfig;
const StatusCache = @import("../core/snapshot_fields.zig").StatusCache;
const MAX_CACHE_ENTRIES = @import("../core/snapshot_fields.zig").MAX_CACHE_ENTRIES;
const HashSet = @import("../core/snapshot_fields.zig").HashSet;

const SnapshotFields = @import("../core/snapshot_fields.zig").SnapshotFields;

pub const MERKLE_FANOUT: usize = 16;

pub const AccountRef = struct {
    slot: Slot,
    file_id: FileId,
    offset: usize,
};
const AccountFileChannel = Channel(struct { AccountFile, ArrayList(PubkeyAccountRef) });

pub const AccountsDB = struct {
    allocator: std.mem.Allocator,
    account_files: std.AutoArrayHashMap(FileId, AccountFile),
    index: std.AutoArrayHashMap(Pubkey, ArrayList(AccountRef)),

    // TODO: remove later (only need accounts-db fields)
    snapshot_fields: SnapshotFields = undefined,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .account_files = std.AutoArrayHashMap(FileId, AccountFile).init(allocator),
            .index = std.AutoArrayHashMap(Pubkey, ArrayList(AccountRef)).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.account_files.values()) |*af| {
            af.deinit();
        }
        self.account_files.deinit();

        for (self.index.values()) |*refs| {
            refs.deinit();
        }
        self.index.deinit();

        bincode.free(self.allocator, self.snapshot_fields);
    }

    /// loads the account files and create the pubkey indexes
    pub fn loadFromSnapshot(
        self: *Self,
        snapshot_fields: SnapshotFields,
        accounts_path: []const u8,
    ) !void {
        self.snapshot_fields = snapshot_fields;

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
        var n_account_files: usize = filenames.items.len;
        std.debug.print("found {d} account files\n", .{n_account_files});

        var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;
        var chunk_size = n_account_files / n_threads;
        if (chunk_size == 0) {
            n_threads = 1;
            chunk_size = n_account_files;
        }
        std.debug.print("using {d} threads with {d} account_files per thread\n", .{ n_threads, chunk_size });

        var channel = AccountFileChannel.init(self.allocator, 10_000);
        defer channel.deinit();

        var handles = try ArrayList(std.Thread).initCapacity(self.allocator, n_threads);
        defer handles.deinit();

        var start_index: usize = 0;
        var end_index: usize = 0;
        for (0..n_threads) |i| {
            if (i == (n_threads - 1)) {
                end_index = n_account_files;
            } else {
                end_index = start_index + chunk_size;
            }
            const handle = try std.Thread.spawn(.{}, openAndParseAccountFiles, .{
                self.allocator,
                accounts_path,
                &self.snapshot_fields.accounts_db_fields,
                channel,
                // per task files
                filenames.items[start_index..end_index],
            });

            handles.appendAssumeCapacity(handle);
            start_index = end_index;
        }
        std.debug.assert(end_index == n_account_files);

        try self.recvAndIndexAccounts(channel, n_account_files);

        for (handles.items) |handle| {
            handle.join();
        }
        std.debug.print("\n", .{});
        std.debug.print("total time: {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();
    }

    pub fn openAndParseAccountFiles(
        allocator: std.mem.Allocator,
        accounts_dir_path: []const u8,
        accounts_db_fields: *const AccountsDbFields,
        channel: *AccountFileChannel,
        // task specific
        file_names: [][]const u8,
    ) !void {
        // estimate of how many accounts per accounts file
        const ACCOUNTS_PER_FILE_EST = 20_000; // TODO: tune?
        var refs = try ArrayList(PubkeyAccountRef).initCapacity(allocator, ACCOUNTS_PER_FILE_EST);

        // NOTE: might need to be longer depending on abs path length
        var abs_path_buf: [1024]u8 = undefined;
        for (file_names) |file_name| {
            // parse "{slot}.{id}" from the file_name
            var fiter = std.mem.tokenizeSequence(u8, file_name, ".");
            const slot = std.fmt.parseInt(Slot, fiter.next().?, 10) catch |err| {
                std.debug.print("failed to parse slot from {s}\n", .{file_name});
                return err;
            };
            const accounts_file_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

            // read metadata
            const slot_metas: ArrayList(AccountFileInfo) = accounts_db_fields.file_map.get(slot).?;
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

            try channel.send(.{ accounts_file, refs });

            // re-allocate
            refs = try ArrayList(PubkeyAccountRef).initCapacity(allocator, ACCOUNTS_PER_FILE_EST);
        }
        refs.deinit();
    }

    pub fn recvAndIndexAccounts(
        self: *Self,
        channel: *AccountFileChannel,
        total_files: usize,
    ) !void {
        var timer = try std.time.Timer.start();
        var file_count: usize = 0;
        var max_file_id: usize = 0;

        while (file_count != total_files) {
            const maybe_task_outputs = channel.try_drain() catch unreachable;
            var task_outputs = maybe_task_outputs orelse continue;
            defer channel.allocator.free(task_outputs);

            for (task_outputs) |task_output| {
                const account_file: AccountFile = task_output[0];
                const refs: ArrayList(PubkeyAccountRef) = task_output[1];
                defer refs.deinit();

                // track the file
                max_file_id = @max(account_file.id, max_file_id);
                const u32_id: u32 = @intCast(account_file.id);
                try self.account_files.putNoClobber(u32_id, account_file);

                // populate index
                for (refs.items) |account_ref| {
                    var entry = try self.index.getOrPut(account_ref.pubkey);
                    if (!entry.found_existing) {
                        entry.value_ptr.* = ArrayList(AccountRef).init(self.allocator);
                    }

                    try entry.value_ptr.append(AccountRef{
                        .file_id = u32_id,
                        .offset = account_ref.offset,
                        .slot = account_ref.slot,
                    });
                }

                file_count += 1;
                if (file_count % 1000 == 0 or file_count < 1000) {
                    printTimeEstimate(&timer, total_files, file_count, "recvAndIndexAccounts");
                }
            }
        }

        std.debug.assert(max_file_id <= std.math.maxInt(u32) / 2);
    }

    /// computes the full accounts hash, accounts-delta-hash, and total lamports
    pub fn computeAccountHashesAndLamports(self: *Self, max_slot: Slot) !struct { accounts_hash: Hash, total_lamports: u64 } {
        std.debug.print("computing account hashes\n", .{});

        // logic for computing the hashes
        var n_bins: usize = undefined;
        if (builtin.is_test or self.index.count() < 100_000) {
            n_bins = 256;
        } else {
            n_bins = PUBKEY_BINS_FOR_CALCULATING_HASHES;
        }

        var bins = try PubkeyBins.init(self.allocator, n_bins);
        defer bins.deinit();

        // populate the bins
        for (self.index.keys()) |*pubkey| {
            try bins.insert(pubkey);
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

        // used for account-delta-hash
        var slot_hashes = try ArrayList(Hash).initCapacity(self.allocator, 1000);
        defer slot_hashes.deinit();

        // used for full hashes
        var hashes = try ArrayList(Hash).initCapacity(self.allocator, total_accounts);
        defer hashes.deinit();

        var total_lamports: u64 = 0;
        for (bins.bins) |*bin| {
            for (bin.items) |pubkey| {
                const slot_list: ArrayList(AccountRef) = self.index.get(pubkey.*).?;
                std.debug.assert(slot_list.items.len > 0);

                // get the most recent state of the account
                const max_slot_index = slotListArgmaxWithMax(slot_list, max_slot) orelse continue;
                const max_account_loc = slot_list.items[max_slot_index];
                const account = try self.getAccountInner(
                    max_account_loc.file_id,
                    max_account_loc.offset,
                );

                // only include non-zero lamport accounts (for full snapshots)
                const lamports = account.lamports();
                if (lamports == 0) continue;

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

        // std.debug.print("computing the delta-account merkle root over {d} accounts\n", .{slot_hashes.items.len});
        // const accounts_delta_hash = try merkleTreeHash(slot_hashes.items, MERKLE_FANOUT);
        // std.debug.print("took {s}\n", .{std.fmt.fmtDuration(timer.read())});
        // timer.reset();

        return .{
            .accounts_hash = accounts_hash.*,
            .total_lamports = total_lamports,
        };
    }

    /// validates the loaded accounts_db which is loaded from a snapshot
    /// this verifies:
    /// - the full account hash is correct
    /// - the total number of lamports is correct
    /// - the delta account hash is correct
    /// - the bankfields metadata matches the genesis config metadata
    /// - the bankfields are correct
    /// - the status cache is correct
    pub fn validateLoadFromSnapshot(
        self: *Self,
        genesis_config: *const GenesisConfig,
        status_cache: *StatusCache,
        full_snapshot_slot: Slot,
        full_snapshot_total_lamports: u64,
    ) !void {
        const bank_fields = self.snapshot_fields.bank_fields;
        if (bank_fields.max_tick_height != (bank_fields.slot + 1) * bank_fields.ticks_per_slot) {
            return error.InvalidBankFields;
        }
        if (bank_fields.epoch_schedule.getEpoch(bank_fields.slot) != bank_fields.epoch) {
            return error.InvalidBankFields;
        }

        // the bankfields metadata matches the genesis config metadata
        if (genesis_config.creation_time != bank_fields.genesis_creation_time) {
            return error.BankAndGenesisMismatch;
        }
        if (genesis_config.ticks_per_slot != bank_fields.ticks_per_slot) {
            return error.BankAndGenesisMismatch;
        }
        const genesis_ns_per_slot = genesis_config.poh_config.target_tick_duration.nanos * @as(u128, genesis_config.ticks_per_slot);
        if (bank_fields.ns_per_slot != genesis_ns_per_slot) {
            return error.BankAndGenesisMismatch;
        }

        const genesis_slots_per_year = yearsAsSlots(1, genesis_config.poh_config.target_tick_duration.nanos, bank_fields.ticks_per_slot);
        if (genesis_slots_per_year != bank_fields.slots_per_year) {
            return error.BankAndGenesisMismatch;
        }
        if (!std.meta.eql(bank_fields.epoch_schedule, genesis_config.epoch_schedule)) {
            return error.BankAndGenesisMismatch;
        }

        // const bank_slot = self.snapshot_fields.bank_fields.slot;

        const result = try self.computeAccountHashesAndLamports(full_snapshot_slot);
        const total_lamports = result.total_lamports;
        const accounts_hash = result.accounts_hash;

        // const expected_total_lamports = self.snapshot_fields.bank_fields.capitalization;
        if (full_snapshot_total_lamports != total_lamports) {
            std.debug.print("incorrect total lamports\n", .{});
            std.debug.print("expected vs calculated: {d} vs {d}\n", .{ full_snapshot_total_lamports, total_lamports });
            return error.IncorrectTotalLamports;
        }

        const bank_hash_info = self.snapshot_fields.accounts_db_fields.bank_hash_info;
        const expected_accounts_hash = bank_hash_info.accounts_hash;
        if (expected_accounts_hash.cmp(&accounts_hash) != .eq) {
            std.debug.print("incorrect accounts hash\n", .{});
            std.debug.print("expected vs calculated: {s} vs {s}\n", .{ expected_accounts_hash, accounts_hash });
            return error.IncorrectAccountsHash;
        }

        // const expected_accounts_delta_hash = bank_hash_info.accounts_delta_hash;
        // if (expected_accounts_delta_hash.cmp(&accounts_delta_hash) != .eq) {
        //     std.debug.print("incorrect accounts delta hash\n", .{});
        //     std.debug.print("expected vs calculated: {s} vs {s}\n", .{ expected_accounts_delta_hash, accounts_delta_hash });
        //     return error.IncorrectAccountsDeltaHash;
        // }

        _ = status_cache;
        // // validate the status cache
        // std.debug.print("validating status cache\n", .{});
        // // TODO: probs wana store this on the bank?
        // const slot_history = try self.getTypeFromAccount(
        //     sysvars.SlotHistory,
        //     &sysvars.IDS.slot_history,
        // );
        // defer bincode.free(self.allocator, slot_history);

        // try AccountsDB.validateStatusCache(
        //     self.allocator,
        //     bank_slot,
        //     status_cache,
        //     &slot_history,
        // );
    }

    pub inline fn slotListArgmaxWithMax(
        slot_list: ArrayList(AccountRef),
        max_slot: Slot,
    ) ?usize {
        if (slot_list.items.len == 0) {
            return null;
        }

        var biggest: *AccountRef = undefined;
        var biggest_index: ?usize = null;
        for (slot_list.items, 0..) |*item, i| {
            if (item.slot <= max_slot and (biggest_index == null or item.slot > biggest.slot)) {
                biggest = item;
                biggest_index = i;
            }
        }

        return biggest_index;
    }

    pub inline fn slotListArgmax(
        slot_list: ArrayList(AccountRef),
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

    /// gets an account given an associated pubkey
    pub fn getAccount(self: *const Self, pubkey: *const Pubkey) !AccountFileAccountInfo {
        const refs = self.index.get(pubkey.*) orelse {
            return error.PubkeyNotInIndex;
        };
        std.debug.assert(refs.items.len > 0);

        const max_account_index = slotListArgmax(refs) orelse return error.EmptySlotList;
        const max_account_loc = refs.items[max_account_index];
        const account = try self.getAccountInner(
            max_account_loc.file_id,
            max_account_loc.offset,
        );
        return account;
    }

    /// gets an account given an file_id and offset value
    pub fn getAccountInner(self: *const Self, file_id: FileId, offset: usize) !AccountFileAccountInfo {
        const accounts_file: AccountFile = self.account_files.get(file_id) orelse return error.FileIdNotFound;
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

    pub fn validateStatusCache(
        allocator: std.mem.Allocator,
        bank_slot: Slot,
        status_cache: *const StatusCache,
        slot_history: *const sysvars.SlotHistory,
    ) !void {
        // status cache validation
        const len = status_cache.items.len;
        if (len > MAX_CACHE_ENTRIES) {
            return error.TooManyCacheEntries;
        }
        var slots_seen = std.AutoArrayHashMap(Slot, void).init(allocator);
        defer slots_seen.deinit();

        for (status_cache.items) |slot_delta| {
            if (!slot_delta.is_root) {
                return error.NonRootSlot;
            }
            const slot = slot_delta.slot;
            if (slot > bank_slot) {
                return error.SlotTooHigh;
            }
            const entry = try slots_seen.getOrPut(slot);
            if (entry.found_existing) {
                return error.MultipleSlotEntries;
            }
        }

        // validate bank matches the status cache
        if (slot_history.newest() != bank_slot) {
            return error.SlotHistoryMismatch;
        }
        for (slots_seen.keys()) |slot| {
            if (slot_history.check(slot) != sysvars.SlotCheckResult.Found) {
                return error.SlotNotFoundInHistory;
            }
        }

        for (slot_history.oldest()..slot_history.newest()) |slot| {
            if (!slots_seen.contains(slot)) {
                return error.SlotNotFoundInStatusCache;
            }
        }
    }
};

pub const SECONDS_PER_YEAR: f64 = 365.242_199 * 24.0 * 60.0 * 60.0;

pub fn yearsAsSlots(years: f64, tick_duration_ns: u32, ticks_per_slot: u64) f64 {
    return years * SECONDS_PER_YEAR * (1_000_000_000.0 / @as(f64, @floatFromInt(tick_duration_ns))) / @as(f64, @floatFromInt(ticks_per_slot));
}

pub fn printTimeEstimate(
    // timer should be started at the beginning
    timer: *std.time.Timer,
    total: usize,
    i: usize,
    comptime name: []const u8,
) void {
    if (i == 0 or total == 0) return;

    const p_done = i * 100 / total;
    const left = total - i;

    const elapsed = timer.read();
    const ns_per_vec = elapsed / i;
    const time_left = ns_per_vec * left;

    const min_left = time_left / std.time.ns_per_min;
    const sec_left = (time_left / std.time.ns_per_s) - (min_left * std.time.s_per_min);

    if (sec_left < 10) {
        std.debug.print("{s}: {d}/{d} ({d}%) (time left: {d}:0{d})\r", .{
            name,
            i,
            total,
            p_done,
            min_left,
            sec_left,
        });
    } else {
        std.debug.print("{s}: {d}/{d} ({d}%) (time left: {d}:{d})\r", .{
            name,
            i,
            total,
            p_done,
            min_left,
            sec_left,
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

pub const PubkeyBins = struct {
    bins: []BinType,
    calculator: PubkeyBinCalculator,

    const BinType = ArrayList(*const Pubkey);

    pub fn init(allocator: std.mem.Allocator, n_bins: usize) !PubkeyBins {
        const calculator = PubkeyBinCalculator.init(n_bins);

        var bins = try allocator.alloc(BinType, n_bins);
        for (bins) |*bin| {
            const INIT_BUCKET_LENGTH = 1_000;
            bin.* = try BinType.initCapacity(allocator, INIT_BUCKET_LENGTH);
        }

        return PubkeyBins{
            .bins = bins,
            .calculator = calculator,
        };
    }

    pub fn deinit(self: *PubkeyBins) void {
        const allocator = self.bins[0].allocator;
        for (self.bins) |*bin| {
            bin.deinit();
        }
        allocator.free(self.bins);
    }

    pub fn insert(self: *PubkeyBins, pubkey: *const Pubkey) !void {
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
            printTimeEstimate(&timer, total_bins, count, "sortBins");
        }
    }
}

pub const FullSnapshotPath = struct {
    path: []const u8,
    slot: Slot,
    hash: []const u8,
};

pub const IncrementalSnapshotPath = struct {
    path: []const u8,
    // this references the full snapshot slot
    base_slot: Slot,
    slot: Slot,
    hash: []const u8,
};

/// matches with the regex: r"^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$";
pub fn parseFullSnapshotPath(path: []const u8) !FullSnapshotPath {
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

/// matches against regex: r"^incremental-snapshot-(?P<base>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$";
pub fn parseIncrementalSnapshotPath(path: []const u8) !IncrementalSnapshotPath {
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

pub fn unpackZstdTarBall(allocator: std.mem.Allocator, path: []const u8, output_dir: std.fs.Dir) !void {
    const file = try output_dir.openFile(path, .{});
    defer file.close();

    var stream = std.compress.zstd.decompressStream(allocator, file.reader());
    try std.tar.pipeToFileSystem(output_dir, stream.reader(), .{ .mode_mode = .ignore });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    const snapshot_dir = "./test_data/";
    var snapshot_dir_iter = try std.fs.cwd().openIterableDir(snapshot_dir, .{});
    defer snapshot_dir_iter.close();

    var files = try readDirectory(allocator, snapshot_dir_iter);
    var filenames = files.filenames;
    defer {
        filenames.deinit();
        allocator.free(files.mem);
    }

    // find the snapshots
    var maybe_largest_full_snapshot: ?FullSnapshotPath = null;
    var count: usize = 0;
    for (filenames.items) |filename| {
        const snap_path = parseFullSnapshotPath(filename) catch continue;
        if (count == 0 or snap_path.slot > maybe_largest_full_snapshot.?.slot) {
            maybe_largest_full_snapshot = snap_path;
        }
        count += 1;
    }
    var largest_full_snapshot = maybe_largest_full_snapshot.?;
    std.debug.print("full snapshot: {s}\n", .{largest_full_snapshot.path});

    count = 0;
    var maybe_largest_incremental_snapshot: ?IncrementalSnapshotPath = null;
    for (filenames.items) |filename| {
        const snap_path = parseIncrementalSnapshotPath(filename) catch continue;
        // need to match the base slot
        if (snap_path.base_slot == largest_full_snapshot.slot and (count == 0 or
            // this unwrap is safe because count > 0
            snap_path.slot > maybe_largest_incremental_snapshot.?.slot))
        {
            maybe_largest_incremental_snapshot = snap_path;
        }
        count += 1;
    }

    // unpack
    try unpackZstdTarBall(allocator, largest_full_snapshot.path, snapshot_dir_iter.dir);
    const full_metadata_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/{d}/{d}",
        .{ snapshot_dir, "snapshots", largest_full_snapshot.slot, largest_full_snapshot.slot },
    );
    defer allocator.free(full_metadata_path);

    var full_snapshot_fields = try SnapshotFields.readFromFilePath(
        allocator,
        full_metadata_path,
    );

    const full_snapshot_lamports = full_snapshot_fields.bank_fields.capitalization;
    const full_snapshot_slot = full_snapshot_fields.bank_fields.slot;
    std.debug.print("full snapshot capitalization: {}\n", .{full_snapshot_lamports});
    std.debug.print("full snapshot slot: {}\n", .{full_snapshot_slot});

    if (maybe_largest_incremental_snapshot) |largest_incremental_snapshot| {
        std.debug.print("incremental snapshot: {s}\n", .{largest_incremental_snapshot.path});
        try unpackZstdTarBall(allocator, largest_incremental_snapshot.path, snapshot_dir_iter.dir);

        const incremental_metadata_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/{d}/{d}",
            .{ snapshot_dir, "snapshots", largest_incremental_snapshot.slot, largest_incremental_snapshot.slot },
        );
        defer allocator.free(incremental_metadata_path);

        // NOTE: dont deinit because is used in 1) bankfields + 2) accounts-db maps
        var incremental_snapshot_fields = try SnapshotFields.readFromFilePath(
            allocator,
            incremental_metadata_path,
        );

        // collapse bank fields
        full_snapshot_fields.bank_fields = incremental_snapshot_fields.bank_fields;

        // collapse accounts-db fields
        // const full_snapshot_slot = full_snapshot_fields.accounts_db_fields.slot;
        var storages_map = &incremental_snapshot_fields.accounts_db_fields.file_map;
        // make sure theres no overlap in slots between full and incremental and combine
        var storages_entry_iter = storages_map.iterator();
        while (storages_entry_iter.next()) |*incremental_entry| {
            const slot = incremental_entry.key_ptr.*;

            // only keep slots > full snapshot slot
            if (slot <= full_snapshot_slot) {
                _ = storages_map.remove(slot);
                continue;
            }

            var full_snapshot_entry = try full_snapshot_fields.accounts_db_fields.file_map.getOrPut(slot);
            if (full_snapshot_entry.found_existing) {
                std.debug.panic("invalid incremental snapshot: slot {d} is in both full and incremental snapshots\n", .{slot});
            } else {
                full_snapshot_entry.value_ptr.* = incremental_entry.value_ptr.*;
            }
        }
    } else {
        std.debug.print("no incremental snapshot found\n", .{});
    }

    const accounts_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "accounts" },
    );
    defer allocator.free(accounts_path);

    const genesis_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "genesis.bin" },
    );
    defer allocator.free(genesis_path);

    // use the genesis to verify loading
    const gen_config = try GenesisConfig.init(allocator, genesis_path);
    defer gen_config.deinit(allocator);

    const status_cache_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "snapshots/status_cache" },
    );
    defer allocator.free(status_cache_path);

    var status_cache_file = try std.fs.cwd().openFile(status_cache_path, .{});
    defer status_cache_file.close();

    var status_cache = try bincode.read(
        allocator,
        StatusCache,
        status_cache_file.reader(),
        .{},
    );
    defer bincode.free(allocator, status_cache);

    var accounts_db = AccountsDB.init(allocator);
    defer accounts_db.deinit();

    try accounts_db.loadFromSnapshot(full_snapshot_fields, accounts_path);
    try accounts_db.validateLoadFromSnapshot(
        &gen_config,
        &status_cache,
        full_snapshot_slot,
        full_snapshot_lamports,
    );

    std.debug.print("done!\n", .{});
}

test "core.accounts_db: test full snapshot path parsing" {
    const full_snapshot_path = "snapshot-269-EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn.tar.zst";
    const snapshot_info = try parseFullSnapshotPath(full_snapshot_path);

    try std.testing.expect(snapshot_info.slot == 269);
    try std.testing.expect(std.mem.eql(u8, snapshot_info.hash, "EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn"));
    try std.testing.expect(std.mem.eql(u8, snapshot_info.path, full_snapshot_path));
}

test "core.accounts_db: test incremental snapshot path parsing" {
    const path = "incremental-snapshot-269-307-4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB.tar.zst";
    const snapshot_info = try parseIncrementalSnapshotPath(path);

    try std.testing.expect(snapshot_info.base_slot == 269);
    try std.testing.expect(snapshot_info.slot == 307);
    try std.testing.expect(std.mem.eql(u8, snapshot_info.hash, "4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB"));
    try std.testing.expect(std.mem.eql(u8, snapshot_info.path, path));
}

test "core.accounts_db: load and validate from test snapshot" {
    var allocator = std.testing.allocator;

    const snapshot_path = "test_data/";
    var accounts_db = AccountsDB.init(allocator);
    defer accounts_db.deinit();
    try accounts_db.loadFromSnapshot(snapshot_path);

    // use the genesis to verify loading
    const genesis_path = "test_data/genesis.bin";
    const gen_config = try GenesisConfig.init(allocator, genesis_path);
    defer gen_config.deinit(allocator);

    try accounts_db.validateLoadFromSnapshot(&gen_config);
}

test "core.accounts_db: load clock sysvar" {
    var allocator = std.testing.allocator;

    const snapshot_path = "test_data/";
    var accounts_db = AccountsDB.init(allocator);
    defer accounts_db.deinit();
    try accounts_db.loadFromSnapshot(snapshot_path);

    const clock = try accounts_db.getTypeFromAccount(sysvars.Clock, &sysvars.IDS.clock);
    const expected_clock = sysvars.Clock{
        .slot = 269,
        .epoch_start_timestamp = 1701807364,
        .epoch = 0,
        .leader_schedule_epoch = 1,
        .unix_timestamp = 1701807490,
    };
    try std.testing.expect(std.meta.eql(clock, expected_clock));
}

test "core.accounts_db: load other sysvars" {
    var allocator = std.testing.allocator;

    const snapshot_path = "test_data/";
    var accounts_db = AccountsDB.init(allocator);
    defer accounts_db.deinit();

    try accounts_db.loadFromSnapshot(snapshot_path);

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
