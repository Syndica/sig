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
const PubkeyAndAccountInAppendVecRef = @import("../core/append_vec.zig").PubkeyAndAccountInAppendVecRef;

const Channel = @import("../sync/channel.zig").Channel;
const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

const runTaskScheduler = @import("../cmd/snapshot_utils.zig").runTaskScheduler;

const Release = std.atomic.Ordering.Release;
const Acquire = std.atomic.Ordering.Acquire;

const LoadedAccounts = struct { append_vecs: ArrayList(AppendVec), refs: ArrayList(PubkeyAndAccountInAppendVecRef) };
const AccountLoadChannel = Channel(LoadedAccounts);
const CHUNK_SIZE = 20;

// const Scheduler = getScheduler(LoadAccountsTask, std.fs.IterableDir.Iterator);

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
        var account_files = try ArrayList(AppendVec).initCapacity(
            self.allocator,
            self.file_names.len,
        );
        errdefer account_files.deinit();

        var refs_array = try ArrayList(PubkeyAndAccountInAppendVecRef).initCapacity(
            self.allocator,
            self.file_names.len * 100, // estimate 100 accounts per appendVec (??)
        );
        errdefer refs_array.deinit();

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

            // each appendVec will have the n_accounts tracked so we can use just a single refs arraylist
            append_vec.sanitizeWithRefs(&refs_array) catch {
                append_vec.deinit();
                continue;
            };

            // sanitize passes - were good
            account_files.appendAssumeCapacity(append_vec);
        }

        try self.channel.send(LoadedAccounts{
            .append_vecs = account_files,
            .refs = refs_array,
        });
    }

    pub fn reset(self: *@This()) void {
        self.done.store(false, Release);
        for (self.file_names) |file_name| {
            self.allocator.free(file_name);
        }
        self.allocator.free(self.file_names);
    }
};

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
    is_done: *std.atomic.Atomic(bool),
) !void {
    var append_vec_count: usize = 0;
    const start_time: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);

    var pubkeys = try ArrayList(TmpPubkey).initCapacity(allocator, 2_000_000);
    var hashes = try ArrayList(Hash).initCapacity(allocator, 2_000_000);

    while (true) {
        const maybe_loaded_accounts = try incoming_channel.try_drain();

        var loaded_accounts = maybe_loaded_accounts orelse {
            // check if were done
            if (is_done.load(std.atomic.Ordering.Acquire)) return;
            continue;
        };
        defer incoming_channel.allocator.free(loaded_accounts);

        for (loaded_accounts) |*loaded_account| {
            const append_vecs: *ArrayList(AppendVec) = &loaded_account.append_vecs;
            const refs: *ArrayList(PubkeyAndAccountInAppendVecRef) = &loaded_account.refs;

            defer {
                refs.deinit();
                append_vecs.deinit();
            }

            var ref_index: usize = 0;
            for (append_vecs.items) |append_vec| {
                try accounts_db.storage.put(append_vec.slot, append_vec);

                // index the accounts
                for (0..append_vec.n_accounts) |_| {
                    const ref = &refs.items[ref_index];
                    try accounts_db.index.insertNewAccountRef(ref.pubkey, ref.account_ref);
                    ref_index += 1;

                    try pubkeys.append(ref.pubkey);
                    try hashes.append(ref.hash);
                }

                // print progress every so often
                append_vec_count += 1;
                const vecs_left = total_append_vec_count - append_vec_count;
                if (append_vec_count % 100 == 0 or vecs_left < 100) {
                    // estimate how long left
                    const now: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);
                    const elapsed = now - start_time;
                    const ns_per_vec = elapsed / append_vec_count;
                    const time_left = ns_per_vec * vecs_left / std.time.ns_per_min;

                    std.debug.print("dumped {d}/{d} appendvecs - (mins left: {d})\r", .{
                        append_vec_count,
                        total_append_vec_count,
                        time_left,
                    });
                }
            }
            std.debug.assert(ref_index == refs.items.len);
        }
    }
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
        total_append_vec_count += 1;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset

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
        .max_threads = n_threads,
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
    var is_done = std.atomic.Atomic(bool).init(false);
    var handle = std.Thread.spawn(.{}, runTaskScheduler, .{
        allocator,
        &thread_pool,
        &accounts_dir_iter,
        tasks,
        &is_done,
        CHUNK_SIZE,
    }) catch unreachable;

    // recv task output fcn
    try recvAndLoadAccounts(
        allocator,
        channel,
        &accounts_db,
        total_append_vec_count,
        &is_done,
    );

    handle.join();

    const elapsed = timer.read();
    std.debug.print("elapsed: {d}\n", .{elapsed / std.time.ns_per_s});
}
