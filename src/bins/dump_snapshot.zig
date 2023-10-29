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

pub const CsvRows = []u8;
pub const CsvChannel = Channel(CsvRows);

pub fn parseAccounts(
    alloc: std.mem.Allocator,
    filename: []const u8,
    accounts_db_fields: *AccountsDbFields,
    accounts_dir_path: []const u8,
    channel: *CsvChannel,
) !void {
    // parse "{slot}.{id}" from the filename
    var fiter = std.mem.tokenizeSequence(u8, filename, ".");
    const slot = try std.fmt.parseInt(Slot, fiter.next().?, 10);
    const append_vec_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

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
    defer append_vec.deinit();

    // verify its valid
    append_vec.sanitize() catch {
        append_vec.deinit();
        return;
    };

    const pubkey_and_refs = try append_vec.getAccountsRefs(alloc);
    defer pubkey_and_refs.deinit();

    var total_fmt_size: u64 = 0;
    for (pubkey_and_refs.items) |*pubkey_and_ref| {
        const pubkey = pubkey_and_ref.pubkey;
        const account = try append_vec.getAccount(pubkey_and_ref.account_ref.offset);
        const owner_pk = try Pubkey.fromBytes(&account.account_info.owner.data, .{});

        const fmt_count = std.fmt.count("{s};{s};{any};{d};{any};{d}\n", .{
            try pubkey.toString(),
            owner_pk.string(),
            account.data,
            account.account_info.lamports,
            account.account_info.executable,
            account.account_info.rent_epoch,
        });
        total_fmt_size += fmt_count;
    }

    const csv_string = alloc.alloc(u8, total_fmt_size) catch unreachable;
    var csv_string_offset: usize = 0;

    for (pubkey_and_refs.items) |*pubkey_and_ref| {
        const pubkey = pubkey_and_ref.pubkey;
        const account = try append_vec.getAccount(pubkey_and_ref.account_ref.offset);
        const owner_pk = try Pubkey.fromBytes(&account.account_info.owner.data, .{});

        const fmt_slice_len = (std.fmt.bufPrint(csv_string[csv_string_offset..], "{s};{s};{any};{d};{any};{d}\n", .{
            try pubkey.toString(),
            owner_pk.string(),
            account.data,
            account.account_info.lamports,
            account.account_info.executable,
            account.account_info.rent_epoch,
        }) catch unreachable).len;

        csv_string_offset += fmt_slice_len;
    }

    _ = channel.send(csv_string) catch unreachable;
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
            self.allocator,
            self.filename,
            self.accounts_db_fields,
            self.accounts_dir_path,
            self.channel,
        ) catch {};
    }
};

pub fn recvAndWriteCsv(total_append_vec_count: usize, csv_file: std.fs.File, channel: *CsvChannel) void {
    var append_vec_count: usize = 0;
    var writer = csv_file.writer();
    const start_time: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);

    while (true) {
        const maybe_csv_rows = channel.try_drain() catch { 
            std.debug.print("recv csv files channel closed\n", .{});
            break;
        };

        var csv_rows = maybe_csv_rows orelse continue;
        defer channel.allocator.free(csv_rows);

        for (csv_rows) |csv_row| {
            writer.writeAll(csv_row) catch unreachable;
            channel.allocator.free(csv_row);
            append_vec_count += 1;

            const vecs_left = total_append_vec_count - append_vec_count;
            if (append_vec_count % 100 == 0) {
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
            } else if (vecs_left < 100) { 
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
    const n_tasks = 200;
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

    var ready_to_schedule_tasks = std.ArrayList(usize).initCapacity(alloc, n_tasks) catch unreachable;
    defer ready_to_schedule_tasks.deinit();
    // at the start = all ready to schedule
    for (0..n_tasks) |i| ready_to_schedule_tasks.appendAssumeCapacity(i);

    var scheduled_tasks = std.ArrayList(usize).initCapacity(alloc, n_tasks) catch unreachable;
    defer scheduled_tasks.deinit();

    var has_sent_all_accounts = false;
    while (!has_sent_all_accounts) {
        const n_free_tasks = ready_to_schedule_tasks.items.len;
        for (0..n_free_tasks) |_| {
            const entry = accounts_dir_iter.next() catch {
                has_sent_all_accounts = true;
                break;
            } orelse { 
                has_sent_all_accounts = true;
                break;
            };
            var filename: []const u8 = entry.name;

            var heap_filename = alloc.alloc(u8, filename.len) catch unreachable;
            @memcpy(heap_filename, filename);

            // populate the task 
            const task_i = ready_to_schedule_tasks.pop();
            scheduled_tasks.appendAssumeCapacity(task_i);
            var task = tasks[task_i];
            task.filename = heap_filename;

            const batch = Batch.from(&task.task);
            ThreadPool.schedule(thread_pool, batch);
        }

        const n_tasks_running = scheduled_tasks.items.len;
        var count_with_removes: usize = 0;
        for (0..n_tasks_running) |_| { 
            var task_i = scheduled_tasks.items[count_with_removes];
            var task = tasks[task_i];

            if (!task.done.load(std.atomic.Ordering.Acquire)) {
                // these are the last tasks so we wait for them until they are done
                if (has_sent_all_accounts) { 
                    while (!task.done.load(std.atomic.Ordering.Acquire)) { }
                    
                    // mark out done 
                    task.done.store(false, std.atomic.Ordering.Release);
                    alloc.free(task.filename);
                    ready_to_schedule_tasks.appendAssumeCapacity(task_i);
                    _ = scheduled_tasks.orderedRemove(count_with_removes);
                } else { 
                    // check the next task
                    count_with_removes += 1;
                }
            } else { 
                task.done.store(false, std.atomic.Ordering.Release);
                alloc.free(task.filename);
                ready_to_schedule_tasks.appendAssumeCapacity(task_i);
                _ = scheduled_tasks.orderedRemove(count_with_removes);
                // removing this task count_with_removes will index the next task
            }
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
