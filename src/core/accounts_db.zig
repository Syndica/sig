const std = @import("std");
const ArrayList = std.ArrayList;

const Account = @import("../core/account.zig").Account;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/clock.zig").Slot;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");

const AccountsDbFields = @import("../core/snapshot_fields.zig").AccountsDbFields;
const AccountFileInfo = @import("../core/snapshot_fields.zig").AccountFileInfo;

const AccountFile = @import("../core/accounts_file.zig").AccountFile;
const alignToU64 = @import("../core/accounts_file.zig").alignToU64;
const PubkeyAccountRef = @import("../core/accounts_file.zig").PubkeyAccountRef;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;
const Channel = @import("../sync/channel.zig").Channel;

const hashAccount = @import("../core/account.zig").hashAccount;
const merkleTreeHash = @import("../common/merkle_tree.zig").merkleTreeHash;
const findSnapshotMetadataPath = @import("../cmd/snapshot_utils.zig").findSnapshotMetadataPath;

const SnapshotFields = @import("../core/snapshot_fields.zig").SnapshotFields;

pub const MERKLE_FANOUT: usize = 16;

pub const FileId = usize;
pub const AccountRef = struct {
    slot: Slot,
    file_id: FileId,
    offset: usize,
};
const AccountFileChannel = Channel(struct { AccountFile, ArrayList(PubkeyAccountRef) });

pub const AccountsDB = struct {
    account_files: std.AutoArrayHashMap(FileId, AccountFile),
    index: std.AutoArrayHashMap(Pubkey, ArrayList(AccountRef)),
    allocator: std.mem.Allocator,

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
    }

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
        defer snapshot_fields.deinit(self.allocator);

        var snapshot_metadata = snapshot_fields.getFieldRefs();
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

        //
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
                snapshot_metadata.accounts_db_fields,
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

        while (true) {
            const maybe_task_outputs = channel.try_drain() catch unreachable;
            var task_outputs = maybe_task_outputs orelse continue;
            defer channel.allocator.free(task_outputs);

            for (task_outputs) |task_output| {
                const account_file: AccountFile = task_output[0];
                const refs: ArrayList(PubkeyAccountRef) = task_output[1];
                defer refs.deinit();

                // track the file
                try self.account_files.putNoClobber(account_file.id, account_file);

                // populate index
                for (refs.items) |account_ref| {
                    var entry = try self.index.getOrPut(account_ref.pubkey);
                    if (!entry.found_existing) {
                        entry.value_ptr.* = ArrayList(AccountRef).init(self.allocator);
                    }

                    try entry.value_ptr.append(AccountRef{
                        .file_id = account_file.id,
                        .offset = account_ref.offset,
                        .slot = account_ref.slot,
                    });
                }

                file_count += 1;
                if (file_count % 1000 == 0 or file_count < 1000) {
                    printTimeEstimate(&timer, total_files, file_count, "recvAndIndexAccounts");
                    if (file_count == total_files) return;
                }
            }
        }
    }
};

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

const PubkeyBinCalculator = @import("../cmd/snapshot_verify.zig").PubkeyBinCalculator;
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

    // init db -- will first load from the .zstd file
    var accounts_db = AccountsDB.init(allocator);
    defer accounts_db.deinit();

    try accounts_db.loadFromSnapshot(snapshot_path);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    const snapshot_path = "../local-net";

    // init db
    var accounts_db = AccountsDB.init(allocator);
    try accounts_db.loadFromSnapshot(snapshot_path);

    // // // verification logic
    // // sort the pubkeys
    // std.debug.print("initializing pubkey bins\n", .{});
    // const n_bins = 128;
    // var bins = try PubkeyBins.init(allocator, n_bins);
    // for (accounts_db.index.keys()) |*pubkey| {
    //     try bins.insert(pubkey);
    // }

    // n_threads = @as(u32, @truncate(try std.Thread.getCpuCount()));
    // chunk_size = n_bins / n_threads;
    // if (chunk_size == 0) {
    //     n_threads = 1;
    // }
    // handles.clearRetainingCapacity();
    // std.debug.print("starting {d} threads with {d} bins per thread\n", .{ n_threads, chunk_size });

    // start_index = 0;
    // end_index = 0;

    // for (0..n_threads) |i| {
    //     if (i == (n_threads - 1)) {
    //         end_index = n_bins;
    //     } else {
    //         end_index = start_index + chunk_size;
    //     }

    //     var handle = try std.Thread.spawn(.{}, sortBins, .{
    //         bins.bins,
    //         start_index,
    //         end_index,
    //     });

    //     handles.appendAssumeCapacity(handle);
    //     start_index = end_index;
    // }
    // std.debug.assert(end_index == n_bins);

    // for (handles.items) |handle| {
    //     handle.join();
    // }
    // std.debug.print("\n", .{});
    // std.debug.print("done in {d}ms\n", .{timer.read() / std.time.ns_per_ms});
    // timer.reset();

    // // compute merkle tree over the slices
    // std.debug.print("computing merkle tree\n", .{});
    // var total_count: usize = 0;
    // for (bins.bins) |*bin| {
    //     total_count += bin.items.len;
    // }

    // var total_lamports: u64 = 0;
    // var hashes = try ArrayList(Hash).initCapacity(allocator, total_count);
    // for (bins.bins) |*bin| {
    //     for (bin.items) |pubkey| {
    //         const account_states = accounts_db.index.get(pubkey.*).?;
    //         var max_slot_index: ?usize = null;
    //         var max_slot: usize = 0;
    //         for (account_states.items, 0..) |account_info, i| {
    //             if (max_slot_index == null or max_slot < account_info.slot) {
    //                 max_slot = account_info.slot;
    //                 max_slot_index = i;
    //             }
    //         }
    //         const newest_account_loc = account_states.items[max_slot_index.?];
    //         const accounts_file: AccountFile = accounts_db.account_files.get(newest_account_loc.file_id).?;
    //         const account = try accounts_file.getAccount(newest_account_loc.offset);
    //         const lamports = account.account_info.lamports;

    //         if (account.account_info.lamports == 0) continue;
    //         // std.debug.print("pubkey: {s} slot: {d} lamports: {d} bin: {d}\n", .{account_info.pubkey.toStringWithBuf(dest[0..44]), account_info.slot, account_info.lamports, bin_i});
    //         hashes.appendAssumeCapacity(account.hash.*);
    //         total_lamports += lamports;
    //     }
    // }
    // std.debug.print("total lamports: {d}\n", .{total_lamports});

    // const root_hash = try merkleTreeHash(hashes.items, MERKLE_FANOUT);
    // std.debug.print("merkle root: {any}\n", .{root_hash.*});

    // std.debug.print("\n", .{});
    // std.debug.print("done in {d}ms\n", .{full_timer.read() / std.time.ns_per_ms});
    // timer.reset();
}
