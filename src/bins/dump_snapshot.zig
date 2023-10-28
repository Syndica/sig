const std = @import("std");
const bincode = @import("../bincode/bincode.zig");
const AccountsDbFields = @import("../core/snapshot_fields.zig").AccountsDbFields;
const AppendVecInfo = @import("../core/snapshot_fields.zig").AppendVecInfo;
const AppendVec = @import("../core/append_vec.zig").AppendVec;
const TmpPubkey = @import("../core/append_vec.zig").TmpPubkey;
const Account = @import("../core/account.zig").Account;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const Slot = @import("../core/clock.zig").Slot;
const ArrayList = std.ArrayList;
const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

const Channel = @import("../sync/channel.zig").Channel;

pub const AccountAndPubkey = struct {
    pubkey: TmpPubkey,
    account: Account,
};

pub const CsvRows = ArrayList([]u8);
pub const CsvChannel = Channel(CsvRows);

pub fn parseAccounts(
    filename: []const u8,
    accounts_db_fields: *AccountsDbFields,
    alloc: std.mem.Allocator,
    accounts_dir_path: []const u8,
    channel: *CsvChannel,
) !void {
    // parse "{slot}.{id}" from the filename
    var fiter = std.mem.tokenizeSequence(u8, filename, ".");
    const slot = std.fmt.parseInt(Slot, fiter.next() orelse { std.debug.print("{s} is not valid", .{ filename }); unreachable; }, 10) catch |err| { 
        std.debug.print("{s} is not valid", .{ filename });
        return err;
    };
    const append_vec_id = std.fmt.parseInt(usize, fiter.next() orelse { std.debug.print("{s} is not valid", .{ filename }); unreachable; }, 10) catch |err| { 
        std.debug.print("{s} is not valid", .{ filename });
        return err;
    };

    // read metadata
    const slot_metas: ArrayList(AppendVecInfo) = accounts_db_fields.map.get(slot).?;
    std.debug.assert(slot_metas.items.len == 1);
    const slot_meta = slot_metas.items[0];
    std.debug.assert(slot_meta.id == append_vec_id);

    // read appendVec from file
    var abs_path_buf: [1024]u8 = undefined;
    const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir_path, filename });
    const append_vec_file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });

    var append_vec = AppendVec.init(append_vec_file, slot_meta, slot) catch return;

    // verify its valid
    append_vec.sanitize() catch {
        append_vec.deinit();
        return;
    };

    const pubkey_and_refs = try append_vec.getAccountsRefs(alloc);
    defer pubkey_and_refs.deinit();

    var result = try ArrayList([]u8).initCapacity(alloc, pubkey_and_refs.items.len);
    errdefer result.deinit();

    for (pubkey_and_refs.items) |*pubkey_and_ref| {
        const pubkey = pubkey_and_ref.pubkey;
        const account_ref = pubkey_and_ref.account_ref;

        const account = try append_vec.getAccount(account_ref.offset);
        const owner_pk = try Pubkey.fromBytes(&account.account_info.owner.data, .{});

        const to_dump = AccountAndPubkey{ .pubkey = pubkey, .account = Account{
            .owner = owner_pk,
            .data = account.data,
            .lamports = account.account_info.lamports,
            .executable = account.account_info.executable,
            .rent_epoch = account.account_info.rent_epoch,
        } };

        const csv_row = try std.fmt.allocPrint(alloc, "{s};{s};{any};{d};{any};{d}", .{
            try to_dump.pubkey.toString(),
            try account.account_info.owner.toString(),
            to_dump.account.data,
            to_dump.account.lamports,
            to_dump.account.executable,
            to_dump.account.rent_epoch,
        });
        result.appendAssumeCapacity(csv_row);
    }
    _ = channel.send(result) catch unreachable;
}

const CsvTask = struct {
    allocator: std.mem.Allocator,
    channel: *CsvChannel,
    accounts_db_fields: *AccountsDbFields,
    accounts_dir_path: []const u8,

    filename: []const u8, // !

    task: Task,
    done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),

    pub fn callback(task: *Task) void {
        var self = @fieldParentPtr(@This(), "task", task);
        defer self.done.store(true, std.atomic.Ordering.Release);

        parseAccounts(
            self.filename,
            self.accounts_db_fields,
            self.allocator,
            self.accounts_dir_path,
            self.channel,
        ) catch unreachable;
    }
};

pub fn recvAndWriteCsv(total_append_vec_count: usize, csv_file: std.fs.File, channel: *CsvChannel) void {
    var account_count: usize = 0;
    var append_vec_count: usize = 0;
    var writer = csv_file.writer();
    var maybe_last_time: ?u64 = null;

    while (true) {
        const maybe_csv_rows_slice = channel.try_drain() catch break;

        if (maybe_csv_rows_slice == null) continue;
        var csv_rows_slice = maybe_csv_rows_slice.?;

        defer channel.allocator.free(csv_rows_slice);

        for (csv_rows_slice) |csv_rows| {
            for (csv_rows.items) |csv_row| {
                writer.print("{s}\n", .{csv_row}) catch unreachable;
                account_count += 1;
            }
            append_vec_count += 1;

            if (append_vec_count % 100 == 0) {
                // estimate how long left
                const now: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);
                const time_left_mins = blk: {
                    if (maybe_last_time) |last_time| {
                        const elapsed = now - last_time;
                        const ns_per_vec = elapsed / 100;
                        const vecs_left = total_append_vec_count - append_vec_count;
                        const time_left = ns_per_vec * vecs_left;
                        break :blk time_left / std.time.ns_per_min;
                    } else {
                        break :blk 0;
                    }
                };

                std.debug.print("dumped {d} accounts across {d}/{d} appendvecs (mins left: {d})\r", .{
                    account_count,
                    append_vec_count,
                    total_append_vec_count,
                    time_left_mins,
                });
                maybe_last_time = now;
            }
        }
    }
}

pub fn spawnParsingTasks(
    alloc: std.mem.Allocator,
    channel: *CsvChannel,
    accounts_db_fields: *AccountsDbFields,
    accounts_dir_path: []const u8,
    thread_pool: *ThreadPool,
    accounts_dir_iter: *std.fs.IterableDir.Iterator,
) void {
    const n_tasks = 100;
    var tasks: [n_tasks]*CsvTask = undefined;

    // pre-allocate all the tasks
    for (0..tasks.len) |i| {
        var csv_task = alloc.create(CsvTask) catch unreachable;
        csv_task.* = CsvTask{
            .task = .{ .callback = CsvTask.callback },
            .allocator = alloc,
            .channel = channel,
            .accounts_db_fields = accounts_db_fields,
            .accounts_dir_path = accounts_dir_path,
            .filename = "",
        };
        tasks[i] = csv_task;
    }
    defer {
        for (tasks) |task| alloc.destroy(task);
    }

    var is_done = false;
    while (!is_done) {
        var task_count: usize = 0;
        for (0..n_tasks) |i| {
            const entry = accounts_dir_iter.next() catch {
                is_done = true;
                break;
            } orelse { 
                is_done = true;
                break;
            };
            var filename: []const u8 = entry.name;

            var heap_filename = alloc.alloc(u8, filename.len) catch unreachable;
            @memcpy(heap_filename, filename);

            // populate the task 
            var task = tasks[i];
            task.filename = heap_filename;

            task_count += 1;

            const batch = Batch.from(&task.task);
            ThreadPool.schedule(thread_pool, batch);
        }

        for (tasks[0..task_count]) |task| {
            while (!task.done.load(std.atomic.Ordering.Acquire)) {
                // wait
            }
            task.done.store(false, std.atomic.Ordering.Release);
            alloc.free(task.filename);
        }
    }

    // done parsing all files
    channel.close();
}

pub fn main() !void {
    const accounts_db_fields_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts_db.bincode";
    const accounts_dir_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts";
    const dump_file_csv_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts.csv";

    const alloc = std.heap.c_allocator;

    const csv_file = try std.fs.createFileAbsolute(dump_file_csv_path, .{});
    defer csv_file.close();

    const accounts_db_fields_file = try std.fs.openFileAbsolute(accounts_db_fields_path, .{});
    var accounts_db_fields = try bincode.read(alloc, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(alloc, accounts_db_fields);

    var accounts_dir = try std.fs.openIterableDirAbsolute(accounts_dir_path, .{});
    var accounts_dir_iter = accounts_dir.iterate();

    // compute the total size (to compute time left)
    var total_append_vec_count: usize = 0;
    while (try accounts_dir_iter.next()) |_| {
        total_append_vec_count += 1;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset

    var n_threads = @as(u32, @truncate(std.Thread.getCpuCount() catch unreachable));
    var thread_pool = ThreadPool.init(.{
        .max_threads = n_threads,
        .stack_size = 2 * 1024 * 1024,
    });
    std.debug.print("starting with {d} threads\n", .{n_threads});

    var channel = CsvChannel.init(alloc, 1000);
    defer channel.deinit();

    var handle = std.Thread.spawn(.{}, spawnParsingTasks, .{
        alloc,
        channel,
        &accounts_db_fields,
        accounts_dir_path,
        &thread_pool,
        &accounts_dir_iter,
    }) catch unreachable;

    recvAndWriteCsv(
        total_append_vec_count,
        csv_file,
        channel,
    );

    handle.join();

    std.debug.print("done!\n", .{});
}
