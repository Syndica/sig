const std = @import("std");
const ArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const Account = @import("../core/account.zig").Account;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/clock.zig").Slot;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");

const AccountsDbFields = @import("../core/snapshot_fields.zig").AccountsDbFields;
const AppendVecInfo = @import("../core/snapshot_fields.zig").AppendVecInfo;

const AppendVec = @import("../core/append_vec.zig").AppendVec;
const TmpPubkey = @import("../core/append_vec.zig").TmpPubkey;
const alignToU64 = @import("../core/append_vec.zig").alignToU64;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;
const Channel = @import("../sync/channel.zig").Channel;

const hashAccount = @import("../core/account.zig").hashAccount;
const merkleTreeHash = @import("../common/merkle_tree.zig").merkleTreeHash;

pub const MERKLE_FANOUT: usize = 16;

pub const FileId = usize;
pub const AccountRef = struct {
    slot: Slot,
    file_id: FileId,
    offset: usize,
};

pub const AccountsDB = struct {
    account_files: HashMap(FileId, AppendVec),
    index: HashMap(TmpPubkey, ArrayList(AccountRef)),

    pub fn init(alloc: std.mem.Allocator) AccountsDB {
        return AccountsDB{
            .account_files = HashMap(FileId, AppendVec).init(alloc),
            .index = HashMap(TmpPubkey, ArrayList(AccountRef)).init(alloc),
        };
    }
};

// accounts-db {
// 	accounts-files: hashmap<file_id, account_file>
// 	index: hashmap<pubkey, (slot, file_id, offset)>
// }

// read account files
// thread1:
// open append_vec
// generate vec<account_hash_data>
// send vec<account_hash_data> to channel

// thread2:
// index vec<account_hash_data>

// once all index
// compute_accounts_hash(max_slot)
// iterate over the index and get accounts
// bin the pubkeys
// run sorting algo across bins
// get the full hash across bins
// compute the merkle tree

// dump_to_csv(max_slot)
// iterate over the index and get accounts
// look up the full accounts in the accounts-db
// dump to csv

// iterate over the index and get accounts
// get their hash
// compute the merkle tree

// dump_to_csv(max_slot)
// iterate over the index and get accounts
// look up the full accounts in the accounts-db
// dump to csv

const PubkeyAccountRef = struct {
    pubkey: TmpPubkey,
    offset: usize,
    slot: Slot,
};

const AccountFileChannel = Channel(struct { AppendVec, ArrayList(PubkeyAccountRef) });

pub fn openFiles(
    allocator: std.mem.Allocator,
    accounts_db_fields: *const AccountsDbFields,
    accounts_dir_path: []const u8,
    // task specific
    file_names: [][]const u8,
    channel: *AccountFileChannel,
) !void {
    // estimate of how many accounts per append vec
    const ACCOUNTS_PER_FILE_EST = 20_000;
    var refs = try ArrayList(PubkeyAccountRef).initCapacity(allocator, ACCOUNTS_PER_FILE_EST);

    // NOTE: might need to be longer depending on abs path length
    var abs_path_buf: [1024]u8 = undefined;
    for (file_names) |file_name| {
        // parse "{slot}.{id}" from the file_name
        var fiter = std.mem.tokenizeSequence(u8, file_name, ".");
        const slot = try std.fmt.parseInt(Slot, fiter.next().?, 10);
        const append_vec_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

        // read metadata
        const slot_metas: ArrayList(AppendVecInfo) = accounts_db_fields.map.get(slot).?;
        std.debug.assert(slot_metas.items.len == 1);
        const slot_meta = slot_metas.items[0];
        std.debug.assert(slot_meta.id == append_vec_id);

        // read appendVec from file
        const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir_path, file_name });
        const append_vec_file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });
        var append_vec = AppendVec.init(append_vec_file, slot_meta, slot) catch |err| {
            var buf: [1024]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buf);
            var writer = stream.writer();
            try std.fmt.format(writer, "failed to *open* appendVec {s}: {s}", .{ file_name, @errorName(err) });
            @panic(stream.getWritten());
        };

        sanitizeAndParseAccounts(&append_vec, &refs) catch |err| {
            var buf: [1024]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buf);
            var writer = stream.writer();
            try std.fmt.format(writer, "failed to *sanitize* appendVec {s}: {s}", .{ file_name, @errorName(err) });
            @panic(stream.getWritten());
        };

        try channel.send(.{ append_vec, refs });

        // re-allocate
        refs = try ArrayList(PubkeyAccountRef).initCapacity(allocator, ACCOUNTS_PER_FILE_EST);
    }
}

pub fn sanitizeAndParseAccounts(append_vec: *AppendVec, refs: *ArrayList(PubkeyAccountRef)) !void {
    var offset: usize = 0;
    var n_accounts: usize = 0;

    while (true) {
        var account = append_vec.getAccount(offset) catch break;
        try account.sanitize();

        const pubkey = account.store_info.pubkey;

        const hash_is_missing = std.mem.eql(u8, &account.hash.data, &Hash.default().data);
        if (hash_is_missing) {
            const hash = hashAccount(
                account.account_info.lamports,
                account.data,
                &account.account_info.owner.data,
                account.account_info.executable,
                account.account_info.rent_epoch,
                &pubkey.data,
            );
            account.hash.* = hash;
        }

        try refs.append(PubkeyAccountRef{
            .pubkey = pubkey,
            .offset = offset,
            .slot = append_vec.slot,
        });

        offset = offset + account.len;
        n_accounts += 1;
    }

    if (offset != alignToU64(append_vec.length)) {
        return error.InvalidAppendVecLength;
    }

    append_vec.n_accounts = n_accounts;
}

pub fn recvFilesAndIndex(
    allocator: std.mem.Allocator,
    channel: *AccountFileChannel,
    accounts_db: *AccountsDB,
    total_files: usize,
) !void {
    var timer = try std.time.Timer.start();
    var file_count: usize = 0;

    while (true) {
        const maybe_task_outputs = channel.try_drain() catch unreachable;
        var task_outputs = maybe_task_outputs orelse continue;
        defer channel.allocator.free(task_outputs);

        for (task_outputs) |task_output| {
            const account_file: AppendVec = task_output[0];
            const refs: ArrayList(PubkeyAccountRef) = task_output[1];
            defer refs.deinit();

            // track the file
            try accounts_db.account_files.putNoClobber(account_file.id, account_file);

            // populate index
            for (refs.items) |account_ref| {
                var entry = try accounts_db.index.getOrPut(account_ref.pubkey);
                if (!entry.found_existing) {
                    entry.value_ptr.* = ArrayList(AccountRef).init(allocator);
                }

                try entry.value_ptr.append(AccountRef{
                    .file_id = account_file.id,
                    .offset = account_ref.offset,
                    .slot = account_ref.slot,
                });
            }

            file_count += 1;
            if (file_count % 1000 == 0 or file_count < 1000) {
                printTimeEstimate(&timer, total_files, file_count, "recvFilesAndIndex");
                if (file_count == total_files) return;
            }
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

    // start processing
    var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;
    var handles = try ArrayList(std.Thread).initCapacity(allocator, n_threads);
    var chunk_size = total_append_vec_count / n_threads;
    if (chunk_size == 0) {
        n_threads = 1;
    }
    std.debug.print("starting {d} threads with {d} files per thread\n", .{ n_threads, chunk_size });

    var channel = AccountFileChannel.init(allocator, 10_000);
    defer channel.deinit();

    var start_index: usize = 0;
    var end_index: usize = 0;

    //
    for (0..n_threads) |i| {
        if (i == (n_threads - 1)) {
            end_index = total_append_vec_count;
        } else {
            end_index = start_index + chunk_size;
        }

        const handle = try std.Thread.spawn(.{}, openFiles, .{
            allocator,
            &accounts_db_fields,
            accounts_dir_path,
            filename_slices.items[start_index..end_index],
            channel,
        });
        handles.appendAssumeCapacity(handle);
        start_index = end_index;
    }
    std.debug.assert(end_index == total_append_vec_count);

    //
    var accounts_db = AccountsDB.init(allocator);
    try recvFilesAndIndex(allocator, channel, &accounts_db, total_append_vec_count);

    for (handles.items) |handle| {
        handle.join();
    }
    std.debug.print("\n", .{});
    std.debug.print("done in {d}ms\n", .{timer.read() / std.time.ns_per_ms});
    timer.reset();
}
