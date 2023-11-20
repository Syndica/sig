const std = @import("std");
const ArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const Account = @import("../core/account.zig").Account;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/clock.zig").Slot;
const Epoch = @import("../core/clock.zig").Epoch;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");

const SnapshotFields = @import("../core/snapshot_fields.zig").SnapshotFields;
const AccountsDbFields = @import("../core/snapshot_fields.zig").AccountsDbFields;
const AppendVecInfo = @import("../core/snapshot_fields.zig").AppendVecInfo;

const base58 = @import("base58-zig");

const AppendVec = @import("../core/append_vec.zig").AppendVec;
const AccountsIndex = @import("../core/append_vec.zig").AccountsIndex;
const TmpPubkey = @import("../core/append_vec.zig").TmpPubkey;
const alignToU64 = @import("../core/append_vec.zig").alignToU64;
const PubkeyAndAccountInAppendVecRef = @import("../core/append_vec.zig").PubkeyAndAccountInAppendVecRef;

const Channel = @import("../sync/channel.zig").Channel;
const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

const hashAccount = @import("../core/account.zig").hashAccount;

const merkleTreeHash = @import("../common/merkle_tree.zig").merkleTreeHash;

pub const MERKLE_FANOUT: usize = 16;

const Release = std.atomic.Ordering.Release;
const Acquire = std.atomic.Ordering.Acquire;

// const LoadedAccounts = struct { append_vecs: ArrayList(AppendVec), refs: ArrayList(PubkeyAndAccountInAppendVecRef) };
const PubkeyAndHash = struct { pubkey: TmpPubkey, hash: Hash };
const TaskOutput = struct { size: usize, items: ArrayList(PubkeyAndHash) };
const AccountLoadChannel = Channel(TaskOutput);
const CHUNK_SIZE = 20;

pub fn sanitizeWithRefs(append_vec: *AppendVec, refs: *ArrayList(PubkeyAndHash)) !void {
    var offset: usize = 0;
    var n_accounts: usize = 0;

    // if sanitization fails revert the refs
    const init_len = refs.items.len;
    errdefer refs.shrinkRetainingCapacity(init_len);

    while (true) {
        const account = append_vec.getAccount(offset) catch break;
        try account.sanitize();

        const pubkey = account.store_info.pubkey;
        const hash = hashAccount(
            account.account_info.lamports,
            account.data,
            &account.account_info.owner.data,
            account.account_info.executable,
            account.account_info.rent_epoch,
            &pubkey.data,
        );

        const pubkey_account_ref = PubkeyAndHash{
            .pubkey = pubkey,
            .hash = hash,
        };

        // NOTE: the refs array should mostly be pre-allocated
        // so this shouldnt be expensive
        try refs.append(pubkey_account_ref);

        offset = offset + account.len;
        n_accounts += 1;
    }

    if (offset != alignToU64(append_vec.length)) {
        return error.InvalidAppendVecLength;
    }

    append_vec.n_accounts = n_accounts;
}

pub fn parseAccounts(
    allocator: std.mem.Allocator,
    channel: *AccountLoadChannel,
    accounts_db_fields: *const AccountsDbFields,
    accounts_dir_path: []const u8,
    // task specific
    file_names: [][]const u8,
) !void {
    const ALLOC_SIZE_MULT = 1_500;
    // (32 * 8) * 2 = 512 bytes per pubkey hash
    var pubkey_hashes = try ArrayList(PubkeyAndHash).initCapacity(
        allocator,
        ALLOC_SIZE_MULT * file_names.len,
    );
    errdefer pubkey_hashes.deinit();

    // TODO: might need to be longer depending on abs path length
    var abs_path_buf: [1024]u8 = undefined;
    var last_capacity = pubkey_hashes.capacity;
    var count: usize = 0;

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
            try std.fmt.format(writer, "failed to open appendVec {s}: {s}", .{file_name, @errorName(err)});
            @panic(stream.getWritten());
        };
        defer append_vec.deinit();

        // each appendVec will have the n_accounts tracked so we can use just a single refs arraylist
        sanitizeWithRefs(&append_vec, &pubkey_hashes) catch {
            var buf: [1024]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buf);
            var writer = stream.writer();
            try std.fmt.format(writer, "appendVec failed sanitize: {s}", .{file_name});
            @panic(stream.getWritten());
        };
        count += 1;

        // if we ever go over capacity - send em
        if (last_capacity != pubkey_hashes.capacity) {
            try channel.send(.{
                .size = count,
                .items = pubkey_hashes,
            });

            pubkey_hashes = try ArrayList(PubkeyAndHash).initCapacity(
                allocator,
                ALLOC_SIZE_MULT * file_names.len,
            );
            count = 0;
        }
    }

    if (count > 0) {
        try channel.send(.{
            .size = count,
            .items = pubkey_hashes,
        });
    }
}

pub const AccountsDB = struct {
    storage: HashMap(Slot, AppendVec),
    index: AccountsIndex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .storage = HashMap(Slot, AppendVec).init(allocator),
            .index = AccountsIndex.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        // deinit the appendVecs
        var iter = self.storage.iterator();
        while (iter.next()) |*entry| entry.value_ptr.deinit();
        self.storage.deinit();

        self.index.deinit();
    }
};

pub fn recvAndLoadAccounts(
    allocator: std.mem.Allocator,
    incoming_channel: *AccountLoadChannel,
    accounts_db: *AccountsDB,
    total_append_vec_count: usize,
) !void {
    _ = accounts_db;

    var append_vec_count: usize = 0;
    var timer = try std.time.Timer.start();
    const start_time = timer.read();

    var pubkeys = try ArrayList(TmpPubkey).initCapacity(
        allocator,
        369_000_000,
    );
    var hashes = try ArrayList(Hash).initCapacity(
        allocator,
        369_000_000,
    );

    var n_pubkeys: usize = 0;
    blk: {
        while (true) {
            const maybe_pubkey_hashes = incoming_channel.drain();
            var slice_array_pubkey_hashes = maybe_pubkey_hashes orelse continue;
            defer incoming_channel.allocator.free(slice_array_pubkey_hashes);

            for (slice_array_pubkey_hashes) |n_vecs_array_pubkey_hashes| {
                const array_pubkey_hashes = n_vecs_array_pubkey_hashes.items;
                // free the arraylist
                defer array_pubkey_hashes.deinit();

                for (array_pubkey_hashes.items) |*pubkey_hash| {
                    try pubkeys.append(pubkey_hash.pubkey);
                    try hashes.append(pubkey_hash.hash);
                }
                n_pubkeys += array_pubkey_hashes.items.len;

                // print progress every so often
                const n_append_vecs_parsed = n_vecs_array_pubkey_hashes.size;
                append_vec_count += n_append_vecs_parsed;

                const vecs_left = total_append_vec_count - append_vec_count;
                if (append_vec_count % 300 == 0 or n_append_vecs_parsed > 300 or vecs_left < 300) {
                    // estimate how long left
                    const now: u64 = timer.read();
                    const elapsed = now - start_time;
                    const ns_per_vec = elapsed / append_vec_count;
                    const time_left = ns_per_vec * vecs_left;

                    const min_left = time_left / std.time.ns_per_min;
                    const sec_left = (time_left / std.time.ns_per_s) - (min_left * std.time.s_per_min);

                    const p_done = append_vec_count * 100 / total_append_vec_count;

                    if (sec_left < 10) {
                        std.debug.print("dumped {d}/{d} appendvecs - ({d}%) (time left: {d}:0{d})\r", .{
                            append_vec_count,
                            total_append_vec_count,
                            p_done,
                            min_left,
                            sec_left,
                        });
                    } else {
                        std.debug.print("dumped {d}/{d} appendvecs - ({d}%) (time left: {d}:{d})\r", .{
                            append_vec_count,
                            total_append_vec_count,
                            p_done,
                            min_left,
                            sec_left,
                        });
                    }

                    if (vecs_left == 0) {
                        std.debug.print("\n", .{});
                        break :blk;
                    }
                }
            }
        }
    }
    std.debug.print("-> parsed all accounts in {}s\n", .{timer.read() / std.time.ns_per_s});
    std.debug.print("found {} pubkeys\n", .{n_pubkeys});
    timer.reset();

    // sort based on pubkeys
    std.debug.print("sorting pubkeys and hashes\n", .{});
    const SortContext = struct {
        pubkeys: ArrayList(TmpPubkey),
        hashes: ArrayList(Hash),

        pub fn lessThan(context: @This(), lhs: usize, rhs: usize) bool {
            const lhs_pubkey = context.pubkeys.items[lhs];
            const rhs_pubkey = context.pubkeys.items[rhs];
            return std.mem.lessThan(u8, &lhs_pubkey.data, &rhs_pubkey.data);
        }
    };

    var indexes = try ArrayList(usize).initCapacity(allocator, pubkeys.items.len);
    defer indexes.deinit();
    for (0..pubkeys.items.len) |i| {
        indexes.appendAssumeCapacity(i);
    }

    std.mem.sort(
        usize,
        indexes.items,
        SortContext{ .pubkeys = pubkeys, .hashes = hashes },
        SortContext.lessThan,
    );

    // reorg the hashes
    var hashes_sorted = try allocator.alloc(Hash, hashes.items.len);
    defer allocator.free(hashes_sorted);

    var increasing_index: usize = 0;
    for (indexes.items) |sorted_index| {
        hashes_sorted[increasing_index] = hashes.items[sorted_index];
        increasing_index += 1;
    }
    std.debug.print("-> sorting done in {}s\n", .{timer.read() / std.time.ns_per_s});
    timer.reset();

    // compute the merkle tree
    std.debug.print("computing merkle tree\n", .{});
    const final_hash = try merkleTreeHash(
        hashes_sorted,
        MERKLE_FANOUT,
    );
    std.debug.print("final hash: {s}\n", .{final_hash.*});
    std.debug.print("-> merkle tree done in {}s\n", .{timer.read() / std.time.ns_per_s});
    timer.reset();

    std.debug.print("recver done!\n", .{});
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
        // compute the size
        total_append_vec_count += 1;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset

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
    var index: usize = 0;

    // track the slices
    var filename_slices = try ArrayList([]u8).initCapacity(allocator, total_append_vec_count);
    defer filename_slices.deinit();

    while (try accounts_dir_iter.next()) |file_entry| {
        const file_name_len = file_entry.name.len;
        @memcpy(filename_mem[index..(index + file_name_len)], file_entry.name);
        filename_slices.appendAssumeCapacity(filename_mem[index..(index + file_name_len)]);
        index += file_name_len;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset
    const filename_elapsed = timer.read();
    std.debug.print("parsed filenames in {d}ms\n", .{filename_elapsed / std.time.ns_per_ms});
    std.debug.assert(filename_slices.items.len == total_append_vec_count);

    const accounts_db_fields_file = std.fs.openFileAbsolute(accounts_db_fields_path, .{}) catch |err| {
        std.debug.print("failed to open accounts-db fields file: {s} ... skipping test\n", .{@errorName(err)});
        return;
    };
    var accounts_db_fields = try bincode.read(allocator, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(allocator, accounts_db_fields);

    const accounts_hash_exp = accounts_db_fields.bank_hash_info.accounts_hash;
    std.debug.print("expected hash: {s}\n", .{accounts_hash_exp});

    var accounts_db = AccountsDB.init(allocator);
    defer accounts_db.deinit();

    // channel for thread output
    var channel = AccountLoadChannel.init(allocator, 100_000);
    defer channel.deinit();

    // setup the threads
    // double the number of CPUs bc of the high I/O from mmap (and cache misses)
    var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;
    var handles = try ArrayList(std.Thread).initCapacity(allocator, n_threads);
    var chunk_size = total_append_vec_count / n_threads;

    var start_index: usize = 0;
    var end_index: usize = chunk_size;

    for (0..n_threads) |i| {
        if (end_index == total_append_vec_count) break;

        if (i == (n_threads - 1)) {
            end_index = total_append_vec_count;
        } else {
            end_index = start_index + chunk_size;
            end_index = @min(end_index, total_append_vec_count);
        }

        const handle = try std.Thread.spawn(.{}, parseAccounts, .{
            allocator,
            channel,
            &accounts_db_fields,
            accounts_dir_path,
            filename_slices.items[start_index..end_index],
        });
        handles.appendAssumeCapacity(handle);
        start_index = end_index;

        // account for jitter
        if (end_index == total_append_vec_count) break;
    }
    std.debug.assert(end_index == total_append_vec_count);
    std.debug.print(
        "parsing accounts across {d} threads with each {d} accounts\n",
        .{ n_threads, chunk_size },
    );

    // recv task output fcn
    try recvAndLoadAccounts(
        allocator,
        channel,
        &accounts_db,
        total_append_vec_count,
    );

    for (handles.items) |handle| {
        handle.join();
    }

    // 8min total rn 
    // ~138331351292 = 138seconds (likely IO bound watching htop + more threads
    // than cores = faster)
    const elapsed = timer.read();
    std.debug.print("ns elapsed: {d}\n", .{elapsed});
}
