const std = @import("std");
const cli = @import("zig-cli");
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
const SnapshotFields = @import("../core/snapshot_fields.zig").SnapshotFields;

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

    pub fn reset(self: *@This()) void {
        self.done.store(false, std.atomic.Ordering.Release);
        self.allocator.free(self.filename);
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
    const n_tasks = thread_pool.max_threads * 2;

    // pre-allocate all the tasks
    var tasks = try alloc.alloc(CsvTask, n_tasks);
    defer alloc.free(tasks);
    for (0..tasks.len) |i| {
        tasks[i].* = CsvTask{
            .task = .{ .callback = CsvTask.callback },
            .allocator = alloc,
            .channel = channel,
            .accounts_db_fields = accounts_db_fields,
            .accounts_dir_path = accounts_dir_path,
            .filename = "",
        };
    }

    var ready_indexes = std.ArrayList(usize).initCapacity(alloc, n_tasks) catch unreachable;
    defer ready_indexes.deinit();
    var running_indexes = std.ArrayList(usize).initCapacity(alloc, n_tasks) catch unreachable;
    defer running_indexes.deinit();

    // at the start = all ready to schedule
    for (0..n_tasks) |i| ready_indexes.appendAssumeCapacity(i);

    var has_sent_all_accounts = false;
    while (!has_sent_all_accounts) {

        // queue the ready tasks
        const n_ready = ready_indexes.items.len;
        for (0..n_ready) |_| {
            const account_path = accounts_dir_iter.next() catch {
                has_sent_all_accounts = true;
                break;
            } orelse {
                has_sent_all_accounts = true;
                break;
            };

            var filename: []const u8 = account_path.name;
            var heap_filename = alloc.alloc(u8, filename.len) catch unreachable;
            @memcpy(heap_filename, filename);

            // populate the task
            const task_idx = ready_indexes.pop();

            const task = &tasks[task_idx];
            task.filename = heap_filename;

            const batch = Batch.from(&task.task);
            ThreadPool.schedule(thread_pool, batch);

            running_indexes.appendAssumeCapacity(task_idx);
        }

        var current_index: usize = 0;
        const n_running = running_indexes.items.len;
        for (0..n_running) |_| {
            var task_i = running_indexes.items[current_index];
            const task = &tasks[task_i];

            if (!task.done.load(std.atomic.Ordering.Acquire)) {
                if (has_sent_all_accounts) {
                    // these are the last tasks so we wait for them until they are done
                    while (!task.done.load(std.atomic.Ordering.Acquire)) {}

                    // TODO: do we need this?
                    task.reset();
                    ready_indexes.appendAssumeCapacity(task_i);
                    _ = running_indexes.orderedRemove(current_index);
                } else {
                    // check the next task
                    current_index += 1;
                }
            } else {
                ready_indexes.appendAssumeCapacity(task_i);
                _ = running_indexes.orderedRemove(current_index);
                // removing this task count_with_removes will index the next task
                task.reset();
            }
        }
    }

    // done parsing all files
    channel.close();
}

var snapshot_dir_option = cli.Option{
    .long_name = "snapshot-dir",
    .short_alias = 's',
    .help = "absolute path to the snapshot directory",
    .required = true,
    .value = .{ .string = null },
};

var metadata_path_option = cli.Option{
    .long_name = "metadata-path",
    .short_alias = 'm',
    .help = "absolute path to the snapshot metadata file (snapshots/{SLOT}/{SLOT})",
    .required = true,
    .value = .{ .string = null },
};

var app = &cli.App{
    .name = "dump_snapshot",
    .description = "utils for snapshot dumping",
    .author = "Syndica & Contributors",
    .subcommands = &.{
        // requires: dump_account_fields to be run first
        &cli.Command{
            .name = "dump_snapshot",
            .help = "Dump snapshot accounts to a csv file",
            .action = dumpSnapshot,
            .options = &.{
                &snapshot_dir_option,
            },
        },
        &cli.Command{
            .name = "dump_account_fields",
            .help = "dumps account db fields for faster loading (should run first)",
            .options = &.{
                &snapshot_dir_option,
                &metadata_path_option,
            },
            .action = dumpAccountFields,
        },
    },
};

pub fn main() !void {
    // eg,
    // zig build snapshot_utils -Doptimize=ReleaseSafe
    // ./zig-out/bin/snapshot_utils dump_account_fields -s /Users/tmp/snapshots -m /Users/tmp/snapshots/snapshots/225552163/225552163
    // ./zig-out/bin/snapshot_utils dump_snapshot -s /Users/tmp/Documents/zig-solana/snapshots

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    try cli.run(app, allocator);
}

/// we do this bc the bank_fields in the snapshot metadata is very large
pub fn dumpAccountFields(_: []const []const u8) !void {
    const allocator = std.heap.c_allocator;

    const snapshot_dir = snapshot_dir_option.value.string.?;
    const metadata_path = metadata_path_option.value.string.?;

    const output_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "accounts_db.bincode" },
    );

    var snapshot_fields = try SnapshotFields.readFromFilePath(allocator, metadata_path);
    const fields = snapshot_fields.getFieldRefs();

    // rewrite the accounts_db_fields seperate
    const db_file = try std.fs.createFileAbsolute(output_path, .{});
    defer db_file.close();

    var db_buf = try bincode.writeToArray(allocator, fields.accounts_db_fields.*, .{});
    defer db_buf.deinit();

    _ = try db_file.write(db_buf.items);
}

pub fn dumpSnapshot(_: []const []const u8) !void {
    const allocator = std.heap.c_allocator;

    const snapshot_dir = snapshot_dir_option.value.string.?;
    const accounts_db_fields_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "accounts_db.bincode" },
    );
    const accounts_dir_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "accounts" },
    );
    const dump_csv_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "accounts.csv" },
    );
    defer {
        allocator.free(accounts_db_fields_path);
        allocator.free(accounts_dir_path);
        allocator.free(dump_csv_path);
    }

    const csv_file = try std.fs.createFileAbsolute(dump_csv_path, .{});
    defer csv_file.close();

    const accounts_db_fields_file = std.fs.openFileAbsolute(accounts_db_fields_path, .{}) catch {
        std.debug.print("could not open accounts_db.bincode - run `prepare` first\n", .{});
        return;
    };
    var accounts_db_fields = try bincode.read(allocator, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(allocator, accounts_db_fields);

    var accounts_dir = try std.fs.openIterableDirAbsolute(accounts_dir_path, .{});
    var accounts_dir_iter = accounts_dir.iterate();

    var n_threads = @as(u32, @truncate(std.Thread.getCpuCount() catch unreachable));
    var thread_pool = ThreadPool.init(.{
        .max_threads = n_threads,
        .stack_size = 2 * 1024 * 1024,
    });
    std.debug.print("starting with {d} threads\n", .{n_threads});

    // compute the total size (to compute time left)
    var total_append_vec_count: usize = 0;
    while (try accounts_dir_iter.next()) |_| {
        total_append_vec_count += 1;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset

    var channel = CsvChannel.init(allocator, 1000);
    defer channel.deinit();

    var handle = std.Thread.spawn(.{}, spawnParsingTasks, .{
        allocator,
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
