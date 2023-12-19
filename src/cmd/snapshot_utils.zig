const std = @import("std");
const cli = @import("zig-cli");
const AccountsDbFields = @import("../core/snapshot_fields.zig").AccountsDbFields;
const AccountFileInfo = @import("../core/snapshot_fields.zig").AccountFileInfo;
const AccountFile = @import("../core/accounts_file.zig").AccountFile;
const PubkeyAccountRef = @import("../core/accounts_file.zig").PubkeyAccountRef;

const Account = @import("../core/account.zig").Account;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const Slot = @import("../core/time.zig").Slot;
const ArrayList = std.ArrayList;
const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

const Channel = @import("../sync/channel.zig").Channel;
const SnapshotFields = @import("../core/snapshot_fields.zig").SnapshotFields;
const SnapshotPaths = @import("../core/accounts_db.zig").SnapshotPaths;

pub const AccountAndPubkey = struct {
    pubkey: Pubkey,
    account: Account,
};

pub const CsvRows = []u8;
pub const CsvChannel = Channel(CsvRows);

pub fn findSnapshotMetadataPath(
    allocator: std.mem.Allocator,
    snapshot_dir: []const u8,
) ![]const u8 {
    const metadata_sub_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_dir, "snapshots" },
    );
    defer allocator.free(metadata_sub_path);

    var metadata_dir = try std.fs.cwd().openIterableDir(metadata_sub_path, .{});
    defer metadata_dir.close();

    var maybe_snapshot_slot: ?usize = null;
    var metadata_dir_iter = metadata_dir.iterate();
    while (try metadata_dir_iter.next()) |entry| {
        if (entry.kind == std.fs.File.Kind.directory) {
            maybe_snapshot_slot = try std.fmt.parseInt(usize, entry.name, 10);
            break;
        }
    }
    var snapshot_slot = maybe_snapshot_slot orelse return error.MetadataNotFound;

    const metadata_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{d}/{d}",
        .{ metadata_sub_path, snapshot_slot, snapshot_slot },
    );

    return metadata_path;
}

pub fn accountsToCsvRowAndSend(
    alloc: std.mem.Allocator,
    accounts_db_fields: *AccountsDbFields,
    accounts_dir_path: []const u8,
    channel: *CsvChannel,
    owner_filter: ?Pubkey,
    // !
    filename: []const u8,
) !void {
    // parse "{slot}.{id}" from the filename
    var fiter = std.mem.tokenizeSequence(u8, filename, ".");
    const slot = try std.fmt.parseInt(Slot, fiter.next().?, 10);
    const accounts_file_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

    // read metadata
    const slot_metas: ArrayList(AccountFileInfo) = accounts_db_fields.file_map.get(slot).?;
    std.debug.assert(slot_metas.items.len == 1);
    const slot_meta = slot_metas.items[0];
    std.debug.assert(slot_meta.id == accounts_file_id);

    // read appendVec from file
    var file_buf: [1024]u8 = undefined;
    const file_path = try std.fmt.bufPrint(&file_buf, "{s}/{s}", .{ accounts_dir_path, filename });
    const accounts_file_file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });

    var accounts_file = AccountFile.init(accounts_file_file, slot_meta, slot) catch return;
    defer accounts_file.deinit();

    // verify its valid
    var refs = try ArrayList(PubkeyAccountRef).initCapacity(alloc, 20_000);
    defer refs.deinit();

    accounts_file.sanitizeAndGetAccountsRefs(&refs) catch {
        std.debug.panic("failed to *sanitize* appendVec {s} ... snapshot likely faulty ... aborting\n", .{filename});
    };

    // compute the full size to allocate at once
    var total_fmt_size: u64 = 0;
    for (refs.items) |*ref| {
        const account = try accounts_file.getAccount(ref.offset);
        if (owner_filter) |owner| {
            if (!account.account_info.owner.equals(&owner)) continue;
        }

        // TODO: can probs compute it with a (N + data.len * M)
        const fmt_count = std.fmt.count(
            "{s};{s};{any};{d};{any};{d}\n",
            .{
                account.store_info.pubkey.string(),
                account.account_info.owner.string(),
                account.data,
                account.account_info.lamports,
                account.account_info.executable,
                account.account_info.rent_epoch,
            },
        );
        total_fmt_size += fmt_count;
    }

    const csv_string = alloc.alloc(u8, total_fmt_size) catch unreachable;
    var csv_string_offset: usize = 0;

    for (refs.items) |*ref| {
        const account = try accounts_file.getAccount(ref.offset);
        if (owner_filter) |owner| {
            if (!account.account_info.owner.equals(&owner)) continue;
        }

        const fmt_slice_len = (std.fmt.bufPrint(
            csv_string[csv_string_offset..],
            "{s};{s};{any};{d};{any};{d}\n",
            .{
                account.store_info.pubkey.string(),
                account.account_info.owner.string(),
                account.data,
                account.account_info.lamports,
                account.account_info.executable,
                account.account_info.rent_epoch,
            },
        ) catch unreachable).len;

        csv_string_offset += fmt_slice_len;
    }

    _ = channel.send(csv_string) catch unreachable;
}

// what all the tasks will need
const CsvTask = struct {
    allocator: std.mem.Allocator,
    accounts_db_fields: *AccountsDbFields,
    accounts_dir_path: []const u8,
    channel: *CsvChannel,
    owner_filter: ?Pubkey,

    file_names: [][]const u8,

    task: Task,
    done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),

    pub fn callback(task: *Task) void {
        var self = @fieldParentPtr(@This(), "task", task);
        defer self.done.store(true, std.atomic.Ordering.Release);

        for (self.file_names) |file_name| {
            accountsToCsvRowAndSend(
                self.allocator,
                self.accounts_db_fields,
                self.accounts_dir_path,
                self.channel,
                self.owner_filter,
                file_name,
            ) catch {};
        }
    }

    pub fn reset(self: *@This()) void {
        self.done.store(false, std.atomic.Ordering.Release);
        for (self.file_names) |file_name| {
            self.allocator.free(file_name);
        }
        self.allocator.free(self.file_names);
    }
};

pub fn runTaskScheduler(
    allocator: std.mem.Allocator,
    thread_pool: *ThreadPool,
    iter: *std.fs.IterableDir.Iterator,
    tasks_slice: anytype, // []SomeAccountFileTask
    is_done: *std.atomic.Atomic(bool),
    comptime chunk_size: usize,
) void {
    const n_tasks = tasks_slice.len;

    var ready_indexes = std.ArrayList(usize).initCapacity(allocator, n_tasks) catch unreachable;
    defer ready_indexes.deinit();
    var running_indexes = std.ArrayList(usize).initCapacity(allocator, n_tasks) catch unreachable;
    defer running_indexes.deinit();

    // at the start = all ready to schedule
    for (0..n_tasks) |i| ready_indexes.appendAssumeCapacity(i);

    var account_name_buf: [chunk_size][]const u8 = undefined;
    var has_sent_all_accounts = false;
    while (!has_sent_all_accounts) {
        // queue the ready tasks
        var batch = Batch{};
        const n_ready = ready_indexes.items.len;
        for (0..n_ready) |_| {
            var i: usize = 0;
            while (i < chunk_size) : (i += 1) {
                const file = iter.next() catch {
                    has_sent_all_accounts = true;
                    break;
                } orelse {
                    has_sent_all_accounts = true;
                    break;
                };
                account_name_buf[i] = file.name;
            }
            if (i == 0) break;

            // populate the task
            const task_index = ready_indexes.pop();
            const task = &tasks_slice[task_index];

            // fill out the filename
            var file_names = allocator.alloc([]const u8, i) catch unreachable;
            for (0..i) |idx| {
                var filename: []const u8 = account_name_buf[idx];
                var heap_filename = allocator.alloc(u8, filename.len) catch unreachable;
                @memcpy(heap_filename, filename);
                file_names[idx] = heap_filename;
            }
            task.file_names = file_names[0..i];

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

    is_done.store(true, std.atomic.Ordering.Release);
}

pub fn recvAndWriteCsv(
    total_accounts_file_count: usize,
    csv_file: std.fs.File,
    channel: *CsvChannel,
    is_done: *std.atomic.Atomic(bool),
) void {
    var accounts_file_count: usize = 0;
    var writer = csv_file.writer();
    const start_time: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);

    while (true) {
        const maybe_csv_rows = channel.try_drain() catch unreachable;

        var csv_rows = maybe_csv_rows orelse {
            // check if all tasks are done
            if (is_done.load(std.atomic.Ordering.Acquire)) break;
            continue;
        };
        defer channel.allocator.free(csv_rows);

        for (csv_rows) |csv_row| {
            writer.writeAll(csv_row) catch unreachable;
            channel.allocator.free(csv_row);
            accounts_file_count += 1;

            const vecs_left = total_accounts_file_count - accounts_file_count;
            if (accounts_file_count % 100 == 0 or vecs_left < 100) {
                // estimate how long left
                const now: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);
                const elapsed = now - start_time;
                const ns_per_vec = elapsed / accounts_file_count;
                const time_left = ns_per_vec * vecs_left / std.time.ns_per_min;

                std.debug.print("dumped {d}/{d} accountsfiles - (mins left: {d})\r", .{
                    accounts_file_count,
                    total_accounts_file_count,
                    time_left,
                });
            }
        }
    }
}

var owner_filter_option = cli.Option{
    .long_name = "owner-filter",
    .short_alias = 's',
    .help = "owner pubkey to filter what accounts to dump",
    .required = false,
    .value = .{ .string = null },
};

var snapshot_dir_option = cli.Option{
    .long_name = "snapshot-dir",
    .short_alias = 's',
    .help = "absolute path to the snapshot directory",
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
                &owner_filter_option,
            },
        },
    },
};

pub fn main() !void {
    // eg,
    // zig build -Doptimize=ReleaseSafe
    // ./zig-out/bin/snapshot_utils dump_snapshot -s /Users/tmp/snapshots

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    try cli.run(app, allocator);
}

pub fn dumpSnapshot(_: []const []const u8) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    const owner_filter_str = owner_filter_option.value.string;
    var owner_filter: ?Pubkey = null;
    if (owner_filter_str) |str| {
        owner_filter = try Pubkey.fromString(str);
    }

    const cwd = std.fs.cwd();
    const snapshot_dir = snapshot_dir_option.value.string.?;
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
        allocator.free(accounts_dir_path);
        allocator.free(dump_csv_path);
    }

    const csv_file = try cwd.createFile(dump_csv_path, .{});
    defer csv_file.close();

    var paths = try SnapshotPaths.find(allocator, snapshot_dir);
    paths.incremental_snapshot = null; // not supported rn

    // unpack
    const full_metadata_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/{d}/{d}",
        .{ snapshot_dir, "snapshots", paths.full_snapshot.slot, paths.full_snapshot.slot },
    );
    defer allocator.free(full_metadata_path);

    var snapshot_fields = try SnapshotFields.readFromFilePath(
        allocator,
        full_metadata_path,
    );
    defer snapshot_fields.deinit(allocator);

    var accounts_dir = try cwd.openIterableDir(accounts_dir_path, .{});
    var accounts_dir_iter = accounts_dir.iterate();

    var n_threads = @as(u32, @truncate(std.Thread.getCpuCount() catch unreachable));
    var thread_pool = ThreadPool.init(.{
        .max_threads = n_threads,
        .stack_size = 2 * 1024 * 1024,
    });
    // clean up threadpool once done
    defer thread_pool.shutdown();

    std.debug.print("starting with {d} threads\n", .{n_threads});

    // compute the total size (to compute time left)
    var total_accounts_file_count: usize = 0;
    while (try accounts_dir_iter.next()) |_| {
        total_accounts_file_count += 1;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset

    var channel = CsvChannel.init(allocator, 1000);
    defer channel.deinit();

    // setup the tasks
    const n_tasks = thread_pool.max_threads * 2;
    // pre-allocate all the tasks
    var tasks = allocator.alloc(CsvTask, n_tasks) catch unreachable;
    defer allocator.free(tasks);

    for (0..tasks.len) |i| {
        tasks[i] = CsvTask{
            .task = .{ .callback = CsvTask.callback },
            .accounts_db_fields = &snapshot_fields.accounts_db_fields,
            .accounts_dir_path = accounts_dir_path,
            .allocator = allocator,
            .channel = channel,
            .owner_filter = owner_filter,
            // to be filled
            .file_names = undefined,
        };
    }

    var is_done = std.atomic.Atomic(bool).init(false);

    var handle = std.Thread.spawn(.{}, runTaskScheduler, .{
        allocator,
        &thread_pool,
        &accounts_dir_iter,
        tasks,
        &is_done,
        20,
    }) catch unreachable;

    recvAndWriteCsv(
        total_accounts_file_count,
        csv_file,
        channel,
        &is_done,
    );

    handle.join();

    std.debug.print("done!\n", .{});
}
