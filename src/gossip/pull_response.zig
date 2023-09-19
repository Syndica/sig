const std = @import("std");
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const ContactInfo = @import("node.zig").ContactInfo;
const ArrayList = std.ArrayList;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const exp = std.math.exp;

const RwMux = @import("../sync/mux.zig").RwMux;
const CrdsTable = @import("crds_table.zig").CrdsTable;
const crds = @import("crds.zig");
const CrdsValue = crds.CrdsValue;

const crds_pull_req = @import("./pull_request.zig");
const CrdsFilter = crds_pull_req.CrdsFilter;

pub const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;

// TODO: make it batch
pub fn filterCrdsValues(
    alloc: std.mem.Allocator,
    crds_table: *const CrdsTable,
    filter: *const CrdsFilter,
    caller_wallclock: u64,
    max_number_values: usize,
) error{OutOfMemory}!ArrayList(CrdsValue) {
    if (max_number_values == 0) {
        return ArrayList(CrdsValue).init(alloc);
    }

    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    const jitter = rng.intRangeAtMost(u64, 0, CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 4);
    const caller_wallclock_with_jitter = caller_wallclock + jitter;

    var bloom = filter.filter;

    var match_indexs = try crds_table.getBitmaskMatches(alloc, filter.mask, filter.mask_bits);
    defer match_indexs.deinit();

    var output = try ArrayList(CrdsValue).initCapacity(alloc, match_indexs.items.len);
    errdefer output.deinit();

    for (match_indexs.items) |entry_index| {
        var entry = crds_table.store.iterator().values[entry_index];

        // entry is too new
        if (entry.value.wallclock() > caller_wallclock_with_jitter) {
            continue;
        }
        // entry is already contained in the bloom
        if (bloom.contains(&entry.value_hash.data)) {
            continue;
        }
        // exclude contact info (? not sure why - labs does it)
        if (entry.value.data == crds.CrdsData.ContactInfo) {
            continue;
        }

        // good
        try output.append(entry.value);
        if (output.items.len == max_number_values) {
            break;
        }
    }

    return output;
}

test "gossip.pull: test filter_crds_values batch" {
    const N_FILTERS = 100;
    const N_VALUES_IN_TABLE = 10_000;

    var crds_table = try CrdsTable.init(std.testing.allocator);
    var crds_table_rw = RwMux(CrdsTable).init(crds_table);
    defer {
        var lg = crds_table_rw.write();
        lg.mut().deinit();
    }
    var seed: u64 = 18;
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    // insert a some values
    const keypair = try KeyPair.create([_]u8{1} ** 32);
    var lg = crds_table_rw.write();
    for (0..N_VALUES_IN_TABLE) |_| {
        var crds_value = try crds.CrdsValue.random(rng, &keypair);
        try lg.mut().insert(crds_value, 0);
    }
    lg.unlock();

    const fuzz = @import("fuzz.zig");
    const SocketAddr = @import("../net/net.zig").SocketAddr;
    const bincode = @import("../bincode/bincode.zig");
    const Protocol = @import("protocol.zig").Protocol;

    // create a pull request 
    // const allocator = std.testing.allocator;
    const allocator = std.heap.c_allocator;
    const to_addr = SocketAddr.random(rng).toEndpoint();

    var filters = try std.ArrayList(CrdsFilter).initCapacity(allocator, N_FILTERS);
    defer {
        for (filters.items) |*filter| {
            filter.deinit(); 
        }
        filters.deinit();
    }
    for (0..N_FILTERS) |_| {
        const packet = try fuzz.randomPullRequest(allocator, rng, &keypair, to_addr);
        var msg = try bincode.readFromSlice(allocator, Protocol, packet.data[0..packet.size], bincode.Params{});
        var filter: CrdsFilter = msg.PullRequest[0];
        filters.appendAssumeCapacity(filter);
    }

    // process them sequentially 
    var resp_values = std.ArrayList(CrdsValue).init(allocator);
    defer resp_values.deinit();
    var read_lg = crds_table_rw.read();
    var crds_table_read: *const CrdsTable = read_lg.get();

    var seq_timer = try std.time.Timer.start();
    for (filters.items) |*filter| {
        const resp = try filterCrdsValues(
            allocator, 
            crds_table_read, 
            filter, 
            crds.getWallclockMs(),
            100
        );
        defer resp.deinit();

        try resp_values.appendSlice(resp.items);
    }
    read_lg.unlock();
    std.debug.assert(resp_values.items.len > 0);
    const seq_elapsed = seq_timer.read();
    std.debug.print("SEQ: elapsed = {}\n", .{seq_elapsed});

    // process them in parallel
    const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
    const Task = ThreadPool.Task;

    var pool = ThreadPool.init(.{
        .max_threads = @max(@as(u32, @truncate(std.Thread.getCpuCount() catch 0)), 2),
        .stack_size = 2 * 1024 * 1024,
    });

    const PullRequestContext = struct { 
        filter: *const CrdsFilter,
        crds_table: *const CrdsTable,
        output: ArrayList(CrdsValue), 
        done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),
    };
    
    const PullRequestTask = struct { 
        task: Task,
        context: *PullRequestContext, 
        allocator: std.mem.Allocator, 

        pub fn callback(task: *Task) void {
            var self = @fieldParentPtr(@This(), "task", task);
            const response_crds_values = filterCrdsValues(
                self.allocator, 
                self.context.crds_table, 
                self.context.filter, 
                crds.getWallclockMs(),
                100,
            ) catch { 
                // std.debug.print("filterCrdsValues failed\n", .{});
                return;
            }; 
            self.context.output.appendSlice(response_crds_values.items) catch {
                // std.debug.print("append slice failed\n", .{});
                return;
            };
            // std.debug.print("success: len = {}\n", .{ response_crds_values.items.len });
            self.context.done.store(true, std.atomic.Ordering.Release);
        }
    };

    // read lock crds table
    read_lg = crds_table_rw.read();
    crds_table_read = read_lg.get();
    var batch: ThreadPool.Batch = undefined;
    var parallel_timer = try std.time.Timer.start();

    var tasks = try std.ArrayList(*PullRequestTask).initCapacity(allocator, filters.items.len);
    for (filters.items, 0..) |*filter_i, i| { 
        var output = ArrayList(CrdsValue).init(allocator);
        var context = PullRequestContext {
            .filter = filter_i,
            .crds_table = crds_table_read,
            .output = output,
        };
        var context_heap = try allocator.create(PullRequestContext);
        context_heap.* = context;

        var pull_task = PullRequestTask { 
            .task = .{ .callback = PullRequestTask.callback },
            .context = context_heap, 
            .allocator = allocator,
        };

        // alloc on heap 
        var pull_task_heap = try allocator.create(PullRequestTask);
        pull_task_heap.* = pull_task;
        tasks.appendAssumeCapacity(pull_task_heap);

        if (i == 0) { 
            batch = ThreadPool.Batch.from(&pull_task_heap.task);
        } else { 
            var tmp_batch = ThreadPool.Batch.from(&pull_task_heap.task);
            batch.push(tmp_batch);
        }
    }
    // schedule the threadpool
    ThreadPool.schedule(&pool, batch);

    for (tasks.items) |task| { 
        while (!task.context.done.load(std.atomic.Ordering.Acquire)) {
            // wait
        }
    }
    // unlock crds table
    read_lg.unlock();
    const parallel_elapsed = parallel_timer.read();
    std.debug.print("PARALLEL: elapsed: {}\n", .{parallel_elapsed});

    var total_len: usize = 0;
    for (tasks.items) |task| { 
        total_len += task.context.output.items.len;
    }
    try std.testing.expect(total_len == resp_values.items.len);

   const time_diff: i128 = @as(i128, @intCast(parallel_elapsed)) - @as(i128, @intCast(seq_elapsed)); 
   std.debug.print("TIME DIFF: {}(ns)\n", .{time_diff});
   if (time_diff > 0) { 
       std.debug.print("sequential fast\n", .{});
   } else { 
       std.debug.print("parallel fast\n", .{});
   }
}

test "gossip.pull: test filter_crds_values" {
    var crds_table = try CrdsTable.init(std.testing.allocator);
    var crds_table_rw = RwMux(CrdsTable).init(crds_table);
    defer {
        var lg = crds_table_rw.write();
        lg.mut().deinit();
    }

    // insert a some value
    const kp = try KeyPair.create([_]u8{1} ** 32);

    var seed: u64 = 18;
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var lg = crds_table_rw.write();
    for (0..100) |_| {
        var crds_value = try crds.CrdsValue.random(rng, &kp);
        try lg.mut().insert(crds_value, 0);
    }
    lg.unlock();

    const max_bytes = 10;

    // recver
    const failed_pull_hashes = std.ArrayList(Hash).init(std.testing.allocator);
    var filters = try crds_pull_req.buildCrdsFilters(
        std.testing.allocator,
        &crds_table_rw,
        &failed_pull_hashes,
        max_bytes,
        100,
    );
    defer crds_pull_req.deinitCrdsFilters(&filters);
    var filter = filters.items[0];

    // corresponding value
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk, true);
    var legacy_contact_info = crds.LegacyContactInfo.default(id);
    legacy_contact_info.id = id;
    legacy_contact_info.wallclock = @intCast(std.time.milliTimestamp());
    var crds_value = try CrdsValue.initSigned(crds.CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    }, &kp);

    // insert more values which the filters should be missing
    lg = crds_table_rw.write();
    for (0..64) |_| {
        var v2 = try crds.CrdsValue.random(rng, &kp);
        try lg.mut().insert(v2, 0);
    }

    var values = try filterCrdsValues(
        std.testing.allocator,
        lg.get(),
        &filter,
        crds_value.wallclock(),
        100,
    );
    defer values.deinit();
    lg.unlock();

    try std.testing.expect(values.items.len > 0);
}
