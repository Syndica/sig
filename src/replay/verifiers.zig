const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Entry = sig.core.Entry;
const Hash = sig.core.Hash;
const Transaction = sig.core.Transaction;

const verifyPoh = sig.core.entry.verifyPoh;

/// Verifies entries asynchronously in a thread pool by reproducing the poh
/// chain in parallel and aggregating the results.
///
/// TODO: use SIMDs or GPU to increase parallelism
pub const EntryVerifier = struct {
    allocator: Allocator,
    thread_pool: sig.utils.thread.HomogeneousThreadPool(Task),
    preallocated_nodes: []const std.ArrayListUnmanaged(Hash),
    max_tasks: usize,
    running: bool,

    const Task = struct {
        allocator: Allocator,
        preallocated_nodes: *std.ArrayListUnmanaged(Hash),
        initial_hash: Hash,
        entries: []const Entry,

        pub fn run(self: *Task) bool {
            return verifyPoh(self.allocator, self.preallocated_nodes, self.initial_hash, self.entries);
        }
    };

    pub fn init(
        allocator: Allocator,
        thread_pool: *ThreadPool,
        max_tasks: u32,
    ) Allocator.Error!EntryVerifier {
        const preallocated_nodes = try allocator.alloc(std.ArrayListUnmanaged(Hash), max_tasks);
        for (preallocated_nodes) |*pn| pn.* = .{};
        return .{
            .allocator = allocator,
            .thread_pool = try sig.utils.thread.HomogeneousThreadPool(Task)
                .initBorrowed(allocator, thread_pool, max_tasks),
            .preallocated_nodes = preallocated_nodes,
            .max_tasks = max_tasks,
            .running = false,
        };
    }

    pub fn deinit(self: EntryVerifier) void {
        self.thread_pool.deinit();
        self.allocator.free(self.preallocated_nodes);
    }

    /// Schedule verification tasks into the thread pool.
    /// Call `finish` to get the result.
    pub fn start(self: *EntryVerifier, initial_hash: Hash, entries: []const Entry) void {
        std.debug.assert(!self.running);
        self.running = true;
        if (entries.len == 0) return true;
        const num_tasks = @min(self.max_tasks, entries.len);
        const entries_per_task = entries.len / num_tasks;
        var batch_initial_hash = initial_hash;
        for (0..num_tasks) |i| {
            const end = if (i == num_tasks + 1) entries.len else i * entries_per_task;
            self.thread_pool.schedule(.{
                .allocator = self.allocator,
                .preallocated_nodes = &self.preallocated_nodes[i],
                .initial_hash = batch_initial_hash,
                .entries = entries[i..end],
            });
            batch_initial_hash = entries[end - 1];
        }
    }

    /// Block until all verification tasks are complete, and return the result.
    pub fn finish(self: *EntryVerifier) Allocator.Error!bool {
        defer self.running = false;
        const results = try self.thread_pool.join();
        defer results.deinit();
        for (results.items) |result| {
            if (!try result) return false;
        }
        return true;
    }
};

/// Verifies transaction signatures and blake3 hashes their messages
/// asynchronously in a thread pool, producing RuntimeSanitizedTransactions
///
/// TODO: use SIMDs or GPU to increase parallelism
/// TODO: consolidate common pattern from this, AsyncEntryVerifier, and sig.utils.thread
pub const TransactionVerifyAndHasher = struct {
    allocator: Allocator,
    thread_pool: sig.utils.thread.HomogeneousThreadPool(Task),
    list_recycler: *ListRecycler(RuntimeSanitizedTransaction),
    max_tasks: usize,
    running: bool,

    const Task = struct {
        list_recycler: *ListRecycler(RuntimeSanitizedTransaction),
        input: []const Entry,
        output: []ReplayEntry,

        pub fn run(self: *Task) !void {
            for (self.input, 0..) |entry, i| {
                const replay_entry = &self.output[i];
                replay_entry.* = if (entry.transactions.len == 0)
                    .{ .tick = entry.hash }
                else
                    .{ .transactions = self.list_recycler.get() };

                const list_allocator = self.list_recycler.allocator;
                for (entry.transactions.items) |tx| {
                    const hash = try tx.verifyAndHashMessage();
                    try replay_entry.transactions.append(
                        list_allocator,
                        .{ .hash = hash, .transaction = tx },
                    );
                }
            }
            return;
        }
    };

    pub fn init(
        allocator: Allocator,
        thread_pool: *ThreadPool,
        list_recycler: *ListRecycler(RuntimeSanitizedTransaction),
        max_tasks: u32,
    ) Allocator.Error!TransactionVerifyAndHasher {
        const preallocated_results = try allocator
            .alloc(std.ArrayListUnmanaged(RuntimeSanitizedTransaction), max_tasks);
        for (preallocated_results) |*pn| pn.* = .{};
        return .{
            .allocator = allocator,
            .thread_pool = try sig.utils.thread.HomogeneousThreadPool(Task)
                .initBorrowed(allocator, thread_pool, max_tasks),
            .list_recycler = list_recycler,
            .max_tasks = max_tasks,
            .running = false,
        };
    }

    pub fn deinit(self: TransactionVerifyAndHasher) void {
        self.thread_pool.deinit();
        for (self.preallocated_results) |pr| pr.deinit(self.allocator);
        self.allocator.free(self.preallocated_results);
    }

    /// Schedule verification tasks into the thread pool.
    /// Call `finish` to get the result.
    pub fn start(
        self: *TransactionVerifyAndHasher,
        input: []const Entry,
        output: []ReplayEntry,
    ) void {
        std.debug.assert(!self.running);
        std.debug.assert(input.len == output.len);
        self.running = true;

        if (input.len == 0) return true;
        const num_tasks = @min(self.max_tasks, input.len);
        const entries_per_task = input.len / num_tasks;

        for (0..num_tasks) |i| {
            const end = if (i == num_tasks + 1) input.len else i * entries_per_task;

            self.thread_pool.schedule(.{
                .allocator = self.allocator,
                .list_recycler = self.list_recycler,
                .input = input[i..end],
                .output = output[i..end],
            });
        }
    }

    /// Block until all verification tasks are complete, and write the results
    /// to the passed in `results` parameter. Any existing items in that list
    /// will be erased.
    pub fn finish(self: *TransactionVerifyAndHasher) !void {
        std.debug.assert(!self.running);
        defer self.running = false;
        try self.thread_pool.joinFallible();
    }
};

pub const RuntimeSanitizedTransaction = struct {
    transaction: Transaction,
    hash: Hash,
    is_simple_vote_transaction: bool = false, // TODO
};

pub const ReplayEntry = union(enum) {
    transactions: std.ArrayListUnmanaged(RuntimeSanitizedTransaction),
    tick: Hash,
};

pub fn ListRecycler(T: type) type {
    return struct {
        /// Used for all lists and the ring buffer.
        allocator: Allocator,
        recycled_lists: sig.sync.RingBuffer(std.ArrayListUnmanaged(T)),

        pub fn init(allocator: Allocator, size: usize) Allocator.Error!ListRecycler(T) {
            return .{
                .allocator = allocator,
                .recycled_lists = try sig.sync.RingBuffer(std.ArrayListUnmanaged(T))
                    .init(allocator, size),
            };
        }

        pub fn deinit(self: *ListRecycler(T)) void {
            var count: usize = 0;
            while (self.recycled_lists.pop()) |const_item| {
                var item = const_item;
                item.deinit(self.allocator);
                count += 1;
                std.debug.assert(count < self.recycled_lists.slots.len);
            }
        }

        pub fn get(self: *ListRecycler(T)) T {
            return self.recycled_lists.pop() orelse .{};
        }

        pub fn recycle(self: *ListRecycler(T), list: std.ArrayListUnmanaged(T)) void {
            list.clearRetainingCapacity();
            self.recycled_lists.push(list) catch list.deinit(self.allocator);
        }
    };
}
