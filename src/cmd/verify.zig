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
    var pubkey_hashes = try ArrayList(PubkeyAndHash).initCapacity(
        allocator,
        1_500 * file_names.len,
    );
    errdefer pubkey_hashes.deinit();

    // TODO: might need to be longer depending on abs path length
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
        var append_vec = AppendVec.init(append_vec_file, slot_meta, slot) catch continue;
        defer append_vec.deinit();

        // each appendVec will have the n_accounts tracked so we can use just a single refs arraylist
        sanitizeWithRefs(&append_vec, &pubkey_hashes) catch {
            var buf: [1024]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buf);
            var writer = stream.writer();
            try std.fmt.format(writer, "appendVec failed sanitize: {s}", .{file_name});

            @panic(stream.getWritten());
        };

        // if we ever get to capacity - double it 
        if (pubkey_hashes.items.len == pubkey_hashes.capacity) { 
            try pubkey_hashes.ensureTotalCapacity(pubkey_hashes.capacity * 2);
        }
    }

    try channel.send(.{
        .size = file_names.len,
        .items = pubkey_hashes,
    });
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
    _ = allocator;

    var append_vec_count: usize = 0;
    const start_time: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);

    // var pubkeys = try ArrayList(TmpPubkey).initCapacity(
    //     allocator,
    //     361_934_929,
    // );
    // var hashes = try ArrayList(Hash).initCapacity(
    //     allocator,
    //     361_934_929,
    // );

    var n_pubkeys: usize = 0;
    defer {
        std.debug.print("found {} pubkeys\n", .{n_pubkeys});
        std.debug.assert(361_934_929 == n_pubkeys);
    }

    blk: {
        while (true) {
            const maybe_pubkey_hashes = incoming_channel.drain();
            var slice_array_pubkey_hashes = maybe_pubkey_hashes orelse continue;
            defer incoming_channel.allocator.free(slice_array_pubkey_hashes);

            for (slice_array_pubkey_hashes) |n_vecs_array_pubkey_hashes| {
                const array_pubkey_hashes = n_vecs_array_pubkey_hashes.items;
                // free the arraylist
                defer array_pubkey_hashes.deinit();

                // for (array_pubkey_hashes.items) |*pubkey_hash| {
                //     try pubkeys.append(pubkey_hash.pubkey);
                //     try hashes.append(pubkey_hash.hash);
                // }

                n_pubkeys += array_pubkey_hashes.items.len;

                // print progress every so often
                const n_append_vecs_parsed = n_vecs_array_pubkey_hashes.size;
                append_vec_count += n_append_vecs_parsed;
                const vecs_left = total_append_vec_count - append_vec_count;
                if (append_vec_count % 300 == 0 or n_append_vecs_parsed > 300 or vecs_left < 300) {
                    // estimate how long left
                    const now: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);
                    const elapsed = now - start_time;
                    const ns_per_vec = elapsed / append_vec_count;
                    const time_left = ns_per_vec * vecs_left;

                    const min_left = time_left / std.time.ns_per_min;
                    const sec_left = (time_left / std.time.ns_per_s) - (min_left * std.time.s_per_min);

                    const p_done = append_vec_count * 100 / total_append_vec_count;

                    std.debug.print("dumped {d}/{d} appendvecs - ({d}%) (time left: {d}:{d})\r", .{
                        append_vec_count,
                        total_append_vec_count,
                        p_done,
                        min_left,
                        sec_left,
                    });

                    if (vecs_left == 0) {
                        std.debug.print("\n", .{});
                        break :blk;
                    }
                }
            }
        }
    }

    std.debug.print("recver done!\n", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    const accounts_dir_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts";
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
    var file_names = try ArrayList([]const u8).initCapacity(allocator, total_append_vec_count);
    defer {
        for (file_names.items) |file_name| allocator.free(file_name);
        file_names.deinit();
    }

    // TODO: might need to be longer depending on abs path length
    // var abs_path_buf: [1024]u8 = undefined;
    while (try accounts_dir_iter.next()) |entry| {
        const file_name = entry.name;
        var heap_filename = allocator.alloc(u8, file_name.len) catch unreachable;
        @memcpy(heap_filename, file_name);
        file_names.appendAssumeCapacity(heap_filename);
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset

    const accounts_db_fields_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts_db.bincode";
    const accounts_db_fields_file = std.fs.openFileAbsolute(accounts_db_fields_path, .{}) catch |err| {
        std.debug.print("failed to open accounts-db fields file: {s} ... skipping test\n", .{@errorName(err)});
        return;
    };
    var accounts_db_fields = try bincode.read(allocator, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(allocator, accounts_db_fields);

    var accounts_db = AccountsDB.init(allocator);
    defer accounts_db.deinit();

    // channel for thread output
    var channel = AccountLoadChannel.init(allocator, total_append_vec_count / CHUNK_SIZE);
    defer channel.deinit();

    // setup the threads
    var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount())) * 2;
    var handles = try ArrayList(std.Thread).initCapacity(allocator, n_threads);
    var chunk_size = total_append_vec_count / n_threads;
    std.debug.print("chunk size {d} across {d} threads\n", .{chunk_size, n_threads});

    var start_index: usize = 0;
    var end_index: usize = chunk_size;
    var rng = std.rand.DefaultPrng.init(19);
    const random = rng.random();

    for (0..n_threads) |i| {
        if (end_index == total_append_vec_count) break;

        if (i == (n_threads - 1)) {
            end_index = total_append_vec_count;
        } else {
            end_index = start_index + chunk_size;
            // add jitter so not all threads end at the same time
            end_index += random.intRangeAtMost(usize, 100, 500);
            end_index = @min(end_index, total_append_vec_count);
        }

        const handle = try std.Thread.spawn(.{}, parseAccounts, .{
            allocator,
            channel,
            &accounts_db_fields,
            accounts_dir_path,
            file_names.items[start_index..end_index],
        });
        handles.appendAssumeCapacity(handle);
        start_index = end_index;
    }

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

    const elapsed = timer.read();
    std.debug.print("ns elapsed: {d}\n", .{elapsed});
}
