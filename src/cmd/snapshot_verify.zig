const std = @import("std");
const ArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const Account = @import("../core/account.zig").Account;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/clock.zig").Slot;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");

const AccountsDbFields = @import("../core/snapshot_fields.zig").AccountsDbFields;
const AccountFileInfo = @import("../core/snapshot_fields.zig").AccountFileInfo;

const AccountFile = @import("../core/accounts_file.zig").AccountFile;
const alignToU64 = @import("../core/accounts_file.zig").alignToU64;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

const hashAccount = @import("../core/account.zig").hashAccount;
const merkleTreeHash = @import("../common/merkle_tree.zig").merkleTreeHash;

pub const MERKLE_FANOUT: usize = 16;

const AccountHashData = struct {
    pubkey: Pubkey,
    hash: Hash,
    slot: Slot,
    lamports: u64,
    id: usize,
    offset: usize,
};

pub fn indexAndBinFiles(
    accounts_db_fields: *const AccountsDbFields,
    accounts_dir_path: []const u8,
    // task specific
    file_names: [][]const u8,
    bins: *PubkeyBins,
) !void {
    const total_append_vec_count = file_names.len;

    var timer = try std.time.Timer.start();
    // TODO: might need to be longer depending on abs path length
    var abs_path_buf: [1024]u8 = undefined;
    for (file_names, 1..) |file_name, append_vec_count| {
        // parse "{slot}.{id}" from the file_name
        var fiter = std.mem.tokenizeSequence(u8, file_name, ".");
        const slot = try std.fmt.parseInt(Slot, fiter.next().?, 10);
        const append_vec_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

        // read metadata
        const slot_metas: ArrayList(AccountFileInfo) = accounts_db_fields.map.get(slot).?;
        std.debug.assert(slot_metas.items.len == 1);
        const slot_meta = slot_metas.items[0];
        std.debug.assert(slot_meta.id == append_vec_id);

        // read appendVec from file
        const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir_path, file_name });
        const append_vec_file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });
        var append_vec = AccountFile.init(append_vec_file, slot_meta, slot) catch |err| {
            var buf: [1024]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buf);
            var writer = stream.writer();
            try std.fmt.format(writer, "failed to *open* appendVec {s}: {s}", .{ file_name, @errorName(err) });
            @panic(stream.getWritten());
        };
        // close after
        defer append_vec.deinit();

        sanitizeAndBin(
            &append_vec,
            bins,
        ) catch |err| {
            var buf: [1024]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buf);
            var writer = stream.writer();
            try std.fmt.format(writer, "failed to *sanitize* appendVec {s}: {s}", .{ file_name, @errorName(err) });
            @panic(stream.getWritten());
        };

        if (append_vec_count % 1_000 == 0) {
            // estimate how long left
            printTimeEstimate(
                &timer,
                total_append_vec_count,
                append_vec_count,
                "parsing append vecs",
            );
        }
    }
}

/// used for initial loading
/// we want to sanitize and index and bin (for hash verification) in one go
pub fn sanitizeAndBin(append_vec: *AccountFile, bins: *PubkeyBins) !void {
    var offset: usize = 0;
    var n_accounts: usize = 0;

    while (true) {
        var account = append_vec.getAccount(offset) catch break;
        try account.sanitize();

        const pubkey = account.store_info.pubkey;
        const hash_is_missing = std.mem.eql(u8, &account.hash.data, &Hash.default().data);
        const hash = hashAccount(
            account.account_info.lamports,
            account.data,
            &account.account_info.owner.data,
            account.account_info.executable,
            account.account_info.rent_epoch,
            &pubkey.data,
        );

        if (hash_is_missing) {
            account.hash.* = hash;
        } else {
            const hash_matches = std.mem.eql(u8, &account.hash.data, &hash.data);
            if (!hash_matches) {
                std.debug.print("account hash mismatch: {s} != {s}\n", .{ account.hash, hash });
            }
        }

        try bins.insert(AccountHashData{
            .id = append_vec.id,
            .pubkey = pubkey,
            .hash = hash,
            .lamports = account.account_info.lamports,
            .slot = append_vec.slot,
            .offset = offset,
        });

        offset = offset + account.len;
        n_accounts += 1;
    }

    if (offset != alignToU64(append_vec.length)) {
        return error.InvalidAccountFileLength;
    }

    append_vec.n_accounts = n_accounts;
}

pub fn sortThreadBins(
    allocator: std.mem.Allocator,
    thread_bins: []PubkeyBins,
    bin_start_index: usize,
    bin_end_index: usize,
) !void {
    const SlotAndIndex = struct { slot: Slot, index: usize };
    var hashmap = HashMap(Pubkey, SlotAndIndex).init(allocator);
    defer hashmap.deinit();

    var timer = try std.time.Timer.start();
    const n_threads = thread_bins.len;

    for (bin_start_index..bin_end_index, 1..) |bin_i, count| {

        // compute total capacity required
        var total_len_required: usize = 0;
        for (0..n_threads) |i| {
            total_len_required += thread_bins[i].bins[bin_i].items.len;
        }
        var main_bin = try allocator.alloc(AccountHashData, total_len_required);

        // fill the main bin
        var main_bin_index: usize = 0;
        for (0..n_threads) |thread_i| {
            var thread_bin = &thread_bins[thread_i].bins[bin_i];
            defer thread_bin.deinit();

            for (thread_bin.items) |account_hash_data| {
                if (hashmap.getEntry(account_hash_data.pubkey)) |*entry| {
                    // only track the most recent slot
                    if (account_hash_data.slot > entry.value_ptr.slot) {
                        const index = entry.value_ptr.index;
                        main_bin[index] = account_hash_data;
                        entry.value_ptr.slot = account_hash_data.slot;
                    }
                } else {
                    main_bin[main_bin_index] = account_hash_data;

                    try hashmap.putNoClobber(account_hash_data.pubkey, .{
                        .slot = account_hash_data.slot,
                        .index = main_bin_index,
                    });
                    main_bin_index += 1;
                }
            }
        }

        // sort main_bin
        std.mem.sort(AccountHashData, main_bin[0..main_bin_index], {}, struct {
            fn lessThan(_: void, lhs: AccountHashData, rhs: AccountHashData) bool {
                return std.mem.lessThan(u8, &lhs.pubkey.data, &rhs.pubkey.data);
            }
        }.lessThan);

        // update
        var main_bin_array = ArrayList(AccountHashData).fromOwnedSlice(allocator, main_bin);
        main_bin_array.items.len = main_bin_index;

        thread_bins[0].bins[bin_i] = main_bin_array;

        // clear mem for next iteration
        hashmap.clearRetainingCapacity();

        if (count % 1000 == 0) {
            printTimeEstimate(
                &timer,
                bin_end_index - bin_start_index,
                count,
                "sorting pubkey bins",
            );
        }
    }
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

pub const PUBKEY_BINS_FOR_CALCULATING_HASHES: usize = 65_536;

pub const PubkeyBins = struct {
    bins: []ArrayList(AccountHashData),
    calculator: PubkeyBinCalculator,

    pub fn init(allocator: std.mem.Allocator, n_bins: usize) !PubkeyBins {
        const calculator = PubkeyBinCalculator.init(n_bins);

        var bins = try allocator.alloc(ArrayList(AccountHashData), n_bins);
        for (bins) |*bin| {
            const INIT_BUCKET_LENGTH = 1_000;
            bin.* = try ArrayList(AccountHashData).initCapacity(allocator, INIT_BUCKET_LENGTH);
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

    pub fn insert(self: *PubkeyBins, account: AccountHashData) !void {
        const bin_index = self.calculator.binIndex(&account.pubkey);
        try self.bins[bin_index].append(account);
    }
};

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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    const snapshot_path = "/Users/tmp/Documents/zig-solana/snapshots";

    const accounts_dir_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_path, "accounts" },
    );
    const accounts_db_fields_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_path, "accounts_db.bincode" },
    );

    var accounts_dir = try std.fs.openIterableDirAbsolute(accounts_dir_path, .{});
    var accounts_dir_iter = accounts_dir.iterate();

    // compute the total size (to compute time left)
    var total_append_vec_count: usize = 0;
    while (try accounts_dir_iter.next()) |_| {
        total_append_vec_count += 1;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset
    std.debug.print("total_append_vec_count: {d}\n", .{total_append_vec_count});

    // time it
    var full_timer = try std.time.Timer.start();
    var timer = try std.time.Timer.start();

    // allocate all the filenames
    var total_name_size: usize = 0;
    while (try accounts_dir_iter.next()) |entry| {
        total_name_size += entry.name.len;
    }
    var filename_mem = try allocator.alloc(u8, total_name_size);
    defer allocator.free(filename_mem);
    accounts_dir_iter = accounts_dir.iterate(); // reset

    var filename_slices = try ArrayList([]u8).initCapacity(allocator, total_append_vec_count);
    defer filename_slices.deinit();

    var index: usize = 0;
    while (try accounts_dir_iter.next()) |file_entry| {
        const file_name_len = file_entry.name.len;
        @memcpy(filename_mem[index..(index + file_name_len)], file_entry.name);
        filename_slices.appendAssumeCapacity(filename_mem[index..(index + file_name_len)]);
        index += file_name_len;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset
    std.debug.assert(filename_slices.items.len == total_append_vec_count);

    // read accounts_db.bincode
    const accounts_db_fields_file = std.fs.openFileAbsolute(accounts_db_fields_path, .{}) catch |err| {
        std.debug.print("failed to open accounts-db fields file: {s} ... skipping test\n", .{@errorName(err)});
        return;
    };
    var accounts_db_fields = try bincode.read(allocator, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(allocator, accounts_db_fields);

    const accounts_hash_exp = accounts_db_fields.bank_hash_info.accounts_hash;
    const total_lamports_exp = accounts_db_fields.bank_hash_info.stats.num_lamports_stored;
    std.debug.print("expected hash: {s}\n", .{accounts_hash_exp});
    std.debug.print("expected total lamports: {d}\n", .{total_lamports_exp});

    // setup the threads
    // double the number of CPUs bc of the high I/O from mmap (and cache misses)
    timer.reset();

    var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;
    var handles = try ArrayList(std.Thread).initCapacity(allocator, n_threads);
    var chunk_size = total_append_vec_count / n_threads;
    if (chunk_size == 0) {
        n_threads = 1;
    }
    std.debug.print("starting {d} threads with {d} files per thread\n", .{ n_threads, chunk_size });

    var start_index: usize = 0;
    var end_index: usize = 0;

    // !!
    // const n_bins = PUBKEY_BINS_FOR_CALCULATING_HASHES;
    const n_bins = 128;
    var thread_bins = try allocator.alloc(PubkeyBins, n_threads);
    for (thread_bins) |*thread_bin| {
        thread_bin.* = try PubkeyBins.init(allocator, n_bins);
    }

    for (0..n_threads) |i| {
        if (i == (n_threads - 1)) {
            end_index = total_append_vec_count;
        } else {
            end_index = start_index + chunk_size;
        }

        const handle = try std.Thread.spawn(.{}, indexAndBinFiles, .{
            &accounts_db_fields,
            accounts_dir_path,
            filename_slices.items[start_index..end_index],
            &thread_bins[i],
        });
        handles.appendAssumeCapacity(handle);
        start_index = end_index;
    }
    std.debug.assert(end_index == total_append_vec_count);

    for (handles.items) |handle| {
        handle.join();
    }
    std.debug.print("\n", .{});
    std.debug.print("done in {d}ms\n", .{timer.read() / std.time.ns_per_ms});
    timer.reset();

    // process per bin
    // no I/O so we use cpu count exact
    n_threads = @as(u32, @truncate(try std.Thread.getCpuCount()));
    chunk_size = n_bins / n_threads;
    if (chunk_size == 0) {
        n_threads = 1;
    }
    std.debug.print("starting {d} threads with {d} bins per thread\n", .{ n_threads, chunk_size });

    start_index = 0;
    end_index = 0;

    handles.clearRetainingCapacity();
    try handles.ensureTotalCapacity(n_threads);

    for (0..n_threads) |i| {
        if (i == (n_threads - 1)) {
            end_index = n_bins;
        } else {
            end_index = start_index + chunk_size;
        }

        const handle = try std.Thread.spawn(.{}, sortThreadBins, .{
            allocator,
            thread_bins,
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
    std.debug.print("done in {d}ms\n", .{timer.read() / std.time.ns_per_ms});
    timer.reset();

    // compute merkle tree over the slices
    std.debug.print("computing merkle tree\n", .{});
    var total_count: usize = 0;
    for (thread_bins[0].bins) |bin| {
        total_count += bin.items.len;
    }

    // var dest: [44]u8 = undefined;
    var total_lamports: u64 = 0;
    var hashes = try ArrayList(Hash).initCapacity(allocator, total_count);
    for (thread_bins[0].bins) |bin| {
        for (bin.items) |account_info| {
            if (account_info.lamports == 0) continue;
            // std.debug.print("pubkey: {s} slot: {d} lamports: {d} bin: {d}\n", .{account_info.pubkey.toStringWithBuf(dest[0..44]), account_info.slot, account_info.lamports, bin_i});
            hashes.appendAssumeCapacity(account_info.hash);
            total_lamports += account_info.lamports;
        }
    }
    std.debug.print("total lamports: {d}\n", .{total_lamports});

    const root_hash = try merkleTreeHash(hashes.items, MERKLE_FANOUT);
    std.debug.print("merkle root: {any}\n", .{root_hash.*});

    std.debug.print("done in {d}ms\n", .{full_timer.read() / std.time.ns_per_ms});
}
