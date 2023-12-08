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
    snapshot_metadata: SnapshotFields = undefined,

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

        bincode.free(self.allocator, self.snapshot_metadata);
    }

    /// loads the account files and create the pubkey indexes
    pub fn loadFromSnapshot(
        self: *Self,
        snapshot_path: []const u8,
    ) !void {
        std.debug.print("loading from snapshot: {s}\n", .{snapshot_path});

        // check if accounts dir path exists
        const accounts_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ snapshot_path, "accounts" },
        );
        defer self.allocator.free(accounts_path);

        // no accounts/ directory OR no snapshots/{slot}/{slot} file
        // => search for .zst tarball
        const search_for_zstd = blk: {
            std.fs.cwd().access(accounts_path, .{}) catch |e| {
                if (e == error.FileNotFound) {
                    break :blk true;
                }
            };

            var path = findSnapshotMetadataPath(self.allocator, snapshot_path) catch {
                break :blk true;
            };
            self.allocator.free(path);

            break :blk false;
        };

        var snapshot_dir = try std.fs.cwd().openIterableDir(snapshot_path, .{});
        defer snapshot_dir.close();

        if (search_for_zstd) {
            var snapshot_iter = snapshot_dir.iterate();
            while (try snapshot_iter.next()) |entry| {
                if (std.mem.containsAtLeast(u8, entry.name, 1, ".tar.zst")) {
                    std.debug.print("loading from zstd tarball: {s} ...", .{entry.name});

                    // unpack
                    var timer = try std.time.Timer.start();
                    const zstd_tarball_path = try std.fmt.allocPrint(
                        self.allocator,
                        "{s}/{s}",
                        .{ snapshot_path, entry.name },
                    );
                    const file = try std.fs.cwd().openFile(zstd_tarball_path, .{});
                    defer file.close();

                    var stream = std.compress.zstd.decompressStream(self.allocator, file.reader());
                    try std.tar.pipeToFileSystem(snapshot_dir.dir, stream.reader(), .{ .mode_mode = .ignore });
                    std.debug.print(" took {s}\n", .{std.fmt.fmtDuration(timer.read())});
                    break;
                }
            }
        } else {
            std.debug.print("loading from directory...\n", .{});
        }

        // load the snapshot metadata
        std.debug.print("reading snapshot metadata...", .{});
        var timer = try std.time.Timer.start();
        const snapshot_metadata_path = try findSnapshotMetadataPath(
            self.allocator,
            snapshot_path,
        );
        defer self.allocator.free(snapshot_metadata_path);

        var snapshot_fields = try SnapshotFields.readFromFilePath(
            self.allocator,
            snapshot_metadata_path,
        );
        self.snapshot_metadata = snapshot_fields;
        std.debug.print(" took {s}\n", .{std.fmt.fmtDuration(timer.read())});

        // start the indexing
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
                &self.snapshot_metadata.accounts_db_fields,
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
            const slot_metas: ArrayList(AccountFileInfo) = accounts_db_fields.map.get(slot).?;
            std.debug.assert(slot_metas.items.len == 1);
            const slot_meta = slot_metas.items[0];
            std.debug.assert(slot_meta.id == accounts_file_id);

            // read appendVec from file
            const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir_path, file_name });
            const accounts_file_file = try std.fs.cwd().openFile(abs_path, .{ .mode = .read_write });
            var accounts_file = AccountFile.init(accounts_file_file, slot_meta, slot) catch |err| {
                var buf: [1024]u8 = undefined;
                var stream = std.io.fixedBufferStream(&buf);
                var writer = stream.writer();
                try std.fmt.format(writer, "failed to *open* appendVec {s}: {s}", .{ file_name, @errorName(err) });
                @panic(stream.getWritten());
            };

            accounts_file.sanitizeAndGetAccountsRefs(&refs) catch |err| {
                var buf: [1024]u8 = undefined;
                var stream = std.io.fixedBufferStream(&buf);
                var writer = stream.writer();
                try std.fmt.format(writer, "failed to *sanitize* appendVec {s}: {s}", .{ file_name, @errorName(err) });
                @panic(stream.getWritten());
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

    /// validates the loaded accounts_db which is loaded from a snapshot
    /// this verifies:
    /// - the full account hash is correct
    /// - the total number of lamports is correct
    /// - the delta account hash is correct
    /// - the bankfields metadata matches the genesis config metadata
    /// - the bankfields are correct
    pub fn validateLoadFromSnapshot(
        self: *Self,
        genesis_config: *const GenesisConfig,
    ) !void {
        const bank_fields = self.snapshot_metadata.bank_fields;
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

        // logic for computing the hashes
        var n_bins: usize = undefined;
        if (builtin.is_test) {
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

        std.debug.print("sorting bins\n", .{});
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
        const snapshot_slot = self.snapshot_metadata.bank_fields.slot;
        var slot_hashes = try ArrayList(Hash).initCapacity(self.allocator, 1000);
        defer slot_hashes.deinit();

        var hashes = try ArrayList(Hash).initCapacity(self.allocator, total_accounts);
        defer hashes.deinit();

        var total_lamports: u64 = 0;
        for (bins.bins) |*bin| {
            for (bin.items) |pubkey| {
                const slot_list = self.index.get(pubkey.*).?;
                std.debug.assert(slot_list.items.len > 0);

                // get the most recent state of the account
                const max_slot_index = slotListArgmax(slot_list).?;
                const max_account_loc = slot_list.items[max_slot_index];
                const account = try self.getAccountInner(
                    max_account_loc.file_id,
                    max_account_loc.offset,
                );

                if (max_account_loc.slot == snapshot_slot) {
                    try slot_hashes.append(account.hash.*);
                }

                // only include non-zero lamport accounts (for full snapshots)
                const lamports = account.lamports();
                if (lamports == 0) continue;

                hashes.appendAssumeCapacity(account.hash.*);
                total_lamports += lamports;
            }
        }
        std.debug.print("took {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        const expected_total_lamports = self.snapshot_metadata.bank_fields.capitalization;
        if (expected_total_lamports != total_lamports) {
            std.debug.print("incorrect total lamports\n", .{});
            std.debug.print("expected vs calculated: {d} vs {d}\n", .{ expected_total_lamports, total_lamports });
            return error.IncorrectTotalLamports;
        }

        std.debug.print("computing the merkle root\n", .{});
        const accounts_hash = try merkleTreeHash(hashes.items, MERKLE_FANOUT);
        std.debug.print("took {s}\n", .{std.fmt.fmtDuration(timer.read())});
        timer.reset();

        const bank_hash_info = self.snapshot_metadata.accounts_db_fields.bank_hash_info;
        const expected_accounts_hash = bank_hash_info.accounts_hash;
        if (expected_accounts_hash.cmp(accounts_hash) != .eq) {
            std.debug.print("incorrect accounts hash\n", .{});
            std.debug.print("expected vs calculated: {s} vs {s}\n", .{ expected_accounts_hash, accounts_hash });
            return error.IncorrectAccountsHash;
        }

        const expected_accounts_delta_hash = bank_hash_info.accounts_delta_hash;
        const accounts_delta_hash = try merkleTreeHash(slot_hashes.items, MERKLE_FANOUT);
        if (expected_accounts_delta_hash.cmp(accounts_delta_hash) != .eq) {
            std.debug.print("incorrect accounts delta hash\n", .{});
            std.debug.print("expected vs calculated: {s} vs {s}\n", .{ expected_accounts_delta_hash, accounts_delta_hash });
            return error.IncorrectAccountsDeltaHash;
        }
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

test "core.accounts_db: load from test snapshot" {
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
    // _ = try accounts_db.getTypeFromAccount(sysvars.EpochRewards, &sysvars.IDS.epoch_rewards);
    _ = try accounts_db.getTypeFromAccount(sysvars.Rent, &sysvars.IDS.rent);
    _ = try accounts_db.getTypeFromAccount(sysvars.SlotHash, &sysvars.IDS.slot_hashes);
    _ = try accounts_db.getTypeFromAccount(sysvars.StakeHistory, &sysvars.IDS.stake_history);
    _ = try accounts_db.getTypeFromAccount(sysvars.LastRestartSlot, &sysvars.IDS.last_restart_slot);
}
