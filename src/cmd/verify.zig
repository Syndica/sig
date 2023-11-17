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

// what all the tasks will need
const LoadAccountsTask = struct {
    allocator: std.mem.Allocator,
    channel: *AccountLoadChannel,
    accounts_db_fields: *const AccountsDbFields,
    accounts_dir_path: []const u8,

    // task specific
    file_names: [][]const u8,

    task: Task,
    done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),

    // callback must be void so push errors in run()
    pub fn callback(task: *Task) void {
        var self = @fieldParentPtr(@This(), "task", task);
        defer self.done.store(true, Release);

        self.run() catch {};
    }

    pub fn run(self: *@This()) !void {
        var pubkey_hashes = try ArrayList(PubkeyAndHash).initCapacity(
            self.allocator,
            32_768,
        );
        errdefer pubkey_hashes.deinit();

        // TODO: might need to be longer depending on abs path length
        var abs_path_buf: [1024]u8 = undefined;

        for (self.file_names) |file_name| {
            // parse "{slot}.{id}" from the file_name
            var fiter = std.mem.tokenizeSequence(u8, file_name, ".");
            const slot = try std.fmt.parseInt(Slot, fiter.next().?, 10);
            const append_vec_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

            // read metadata
            const slot_metas: ArrayList(AppendVecInfo) = self.accounts_db_fields.map.get(slot).?;
            std.debug.assert(slot_metas.items.len == 1);
            const slot_meta = slot_metas.items[0];
            std.debug.assert(slot_meta.id == append_vec_id);

            // read appendVec from file
            const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ self.accounts_dir_path, file_name });
            const append_vec_file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });
            var append_vec = AppendVec.init(append_vec_file, slot_meta, slot) catch continue;
            defer append_vec.deinit();

            if (append_vec.file_size > 10_000_000) { // > 10MB
                std.debug.print("parsing large appendVec: {s} with size {d}MB\n", .{ file_name, append_vec.file_size / 1_000_000 });
            }

            // each appendVec will have the n_accounts tracked so we can use just a single refs arraylist
            sanitizeWithRefs(&append_vec, &pubkey_hashes) catch {
                continue;
            };
        }

        try self.channel.send(.{
            .size = self.file_names.len,
            .items = pubkey_hashes,
        });
    }

    pub fn reset(self: *@This()) void {
        self.done.store(false, Release);
        self.allocator.free(self.file_names);
    }
};

pub fn runTaskScheduler(
    allocator: std.mem.Allocator,
    thread_pool: *ThreadPool,
    file_names: [][]const u8,
    file_order: []usize,
    tasks_slice: anytype, // []SomeAccountFileTask
    comptime chunk_size: usize,
) void {
    const n_tasks = tasks_slice.len;

    var ready_indexes = std.ArrayList(usize).initCapacity(allocator, n_tasks) catch unreachable;
    defer ready_indexes.deinit();
    var running_indexes = std.ArrayList(usize).initCapacity(allocator, n_tasks) catch unreachable;
    defer running_indexes.deinit();

    // at the start = all ready to schedule
    for (0..n_tasks) |i| ready_indexes.appendAssumeCapacity(i);

    var index: usize = 0;
    var account_name_buf: [chunk_size][]const u8 = undefined;
    var has_sent_all_accounts = false;
    while (!has_sent_all_accounts) {
        // queue the ready tasks
        var batch = Batch{};
        const n_ready = ready_indexes.items.len;
        for (0..n_ready) |_| {
            var i: usize = 0;
            while (i < chunk_size) : (i += 1) {
                if (index == file_order.len) {
                    has_sent_all_accounts = true;
                    break;
                }

                const file_index = file_order[index];
                const file_name = file_names[file_index];
                account_name_buf[i] = file_name;

                index += 1;
            }
            if (i == 0) break;

            // populate the task
            const task_index = ready_indexes.pop();
            const task = &tasks_slice[task_index];

            // fill out the filename
            var task_file_names = allocator.alloc([]const u8, i) catch unreachable;
            for (0..i) |idx| {
                var filename: []const u8 = account_name_buf[idx];
                task_file_names[idx] = filename;
            }
            task.file_names = task_file_names;

            const task_batch = Batch.from(&task.task);
            batch.push(task_batch);

            running_indexes.appendAssumeCapacity(task_index);

            if (has_sent_all_accounts) break;
        }

        if (batch.len != 0) {
            ThreadPool.schedule(thread_pool, batch);
        }

        if (has_sent_all_accounts) {
            std.debug.print("sent all account files!\n", .{});
        }

        var current_index: usize = 0;
        const n_running = running_indexes.items.len;
        for (0..n_running) |_| {
            const task_index = running_indexes.items[current_index];
            const task = &tasks_slice[task_index];

            if (!task.done.load(std.atomic.Ordering.Acquire)) {
                if (has_sent_all_accounts) {
                    // these are the last tasks so we wait for them until they are done
                    while (!task.done.load(std.atomic.Ordering.Acquire)) {}
                }
                // check the next task
                current_index += 1;
            } else {
                ready_indexes.appendAssumeCapacity(task_index);
                // removing so next task can be checked without changing current_index
                _ = running_indexes.orderedRemove(current_index);
                task.reset();
            }
        }
    }

    std.debug.print("scheduler done!\n", .{});
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
    //     2_000_000_000,
    // );
    // var hashes = try ArrayList(Hash).initCapacity(
    //     allocator,
    //     2_000_000_000,
    // );

    blk: {
        while (true) {
            const maybe_pubkey_hashes = try incoming_channel.try_drain();
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

                    std.debug.print("dumped {d}/{d} appendvecs - (vecs left: {d}) (time left: {d}:{d})\r", .{
                        append_vec_count,
                        total_append_vec_count,
                        vecs_left,
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

    // track the file names (larger files should be scheduled first)
    std.debug.print("ordering files...\n", .{});
    var file_names = try ArrayList([]const u8).initCapacity(allocator, total_append_vec_count);
    defer {
        for (file_names.items) |file_name| allocator.free(file_name);
        file_names.deinit();
    }

    var large_files = try ArrayList(usize).initCapacity(allocator, 100);
    defer large_files.deinit();
    var other_files = try ArrayList(usize).initCapacity(allocator, total_append_vec_count - 100);
    defer other_files.deinit();

    // this will be the final order
    var file_order = try allocator.alloc(usize, total_append_vec_count);
    defer allocator.free(file_order);

    // TODO: might need to be longer depending on abs path length
    var abs_path_buf: [1024]u8 = undefined;
    var index: usize = 0;
    const start_time: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);

    while (try accounts_dir_iter.next()) |entry| {
        const file_name = entry.name;
        var heap_filename = allocator.alloc(u8, file_name.len) catch unreachable;
        @memcpy(heap_filename, file_name);

        const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir_path, file_name });
        const file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });
        defer file.close();

        const file_stat = try file.stat();
        const file_size: u64 = @intCast(file_stat.size);

        if (file_size > 10_000_000) { // >10MB
            try large_files.append(index);
        } else {
            try other_files.append(index);
        }
        index += 1;

        file_names.appendAssumeCapacity(heap_filename);

        const append_vec_count = index;
        const vecs_left = total_append_vec_count - append_vec_count;
        if (append_vec_count % 10_000 == 0 or vecs_left < 10_000) {
            // estimate how long left
            const now: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);
            const elapsed = now - start_time;
            const ns_per_vec = elapsed / append_vec_count;
            const time_left = ns_per_vec * vecs_left;

            const min_left = time_left / std.time.ns_per_min;
            const sec_left = (time_left / std.time.ns_per_s) - (min_left * std.time.s_per_min);

            if (sec_left < 10) {
                std.debug.print("time left: {d}:0{d}\r", .{
                    min_left,
                    sec_left,
                });
            } else {
                std.debug.print("time left: {d}:{d}\r", .{
                    min_left,
                    sec_left,
                });
            }
        }
    }
    std.debug.print("\n", .{});
    std.debug.assert(index == total_append_vec_count);
    accounts_dir_iter = accounts_dir.iterate(); // reset

    // transfer to single slice
    const n_large_files = large_files.items.len;
    @memcpy(file_order[0..n_large_files], large_files.items[0..n_large_files]);
    const n_other_files = other_files.items.len;
    @memcpy(file_order[n_large_files..(n_large_files + n_other_files)], other_files.items[0..n_other_files]);

    std.debug.print("done ordering files...\n", .{});

    const accounts_db_fields_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts_db.bincode";
    const accounts_db_fields_file = std.fs.openFileAbsolute(accounts_db_fields_path, .{}) catch |err| {
        std.debug.print("failed to open accounts-db fields file: {s} ... skipping test\n", .{@errorName(err)});
        return;
    };

    var accounts_db_fields = try bincode.read(allocator, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(allocator, accounts_db_fields);

    // time it
    var timer = try std.time.Timer.start();

    var accounts_db = AccountsDB.init(allocator);
    defer accounts_db.deinit();

    // channel for thread output
    var channel = AccountLoadChannel.init(allocator, 1000);
    defer channel.deinit();

    // setup the threadpool
    var n_threads = @as(u32, @truncate(try std.Thread.getCpuCount()));
    var thread_pool = ThreadPool.init(.{
        .max_threads = n_threads * 2, // two threads per core
        .stack_size = 2 * 1024 * 1024,
    });
    defer thread_pool.shutdown();

    // pre-allocate the tasks
    const n_tasks = thread_pool.max_threads * 2;
    var tasks = try allocator.alloc(LoadAccountsTask, n_tasks);
    defer allocator.free(tasks);

    for (tasks) |*task| {
        task.* = LoadAccountsTask{
            .task = .{ .callback = LoadAccountsTask.callback },
            .allocator = allocator,
            .accounts_db_fields = &accounts_db_fields,
            .accounts_dir_path = accounts_dir_path,
            .channel = channel,
            // to be filled
            .file_names = undefined,
        };
    }

    // schedule the iter to tasks
    var handle = std.Thread.spawn(.{}, runTaskScheduler, .{
        allocator,
        &thread_pool,
        file_names.items,
        file_order,
        tasks,
        CHUNK_SIZE,
    }) catch unreachable;

    // recv task output fcn
    try recvAndLoadAccounts(
        allocator,
        channel,
        &accounts_db,
        total_append_vec_count,
    );

    handle.join();

    // 2.08 mintues
    const elapsed = timer.read();
    std.debug.print("elapsed: {d}seconds\n", .{elapsed / std.time.ns_per_s});
}
