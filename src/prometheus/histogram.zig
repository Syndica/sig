const std = @import("std");
const prometheus = @import("lib.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.array_list.Managed;
const Atomic = std.atomic.Value;

const Metric = prometheus.metric.Metric;
const MetricType = prometheus.metric.MetricType;

pub const DEFAULT_BUCKETS: [11]f64 = .{
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
};

pub fn exponentialBuckets(base: i64, comptime start: i64, comptime end: i64) [end - start]f64 {
    std.debug.assert(end > start);
    const base_float = @as(f64, @floatFromInt(base));
    var buckets: [end - start]f64 = undefined;
    for (0..end - start) |i| {
        const exponent = @as(f64, @floatFromInt(start + @as(i64, @intCast(i))));
        buckets[i] = std.math.pow(f64, base_float, exponent);
    }
    return buckets;
}

/// Histogram optimized for fast concurrent writes.
/// Reads and writes are thread-safe if you use the public methods.
/// Writes are lock-free. Reads are locked with a mutex because they occupy a shard.
///
/// The histogram state is represented in a shard. There are two shards, hot and cold.
/// Writes incremenent the hot shard.
/// Reads flip a switch to change which shard is considered hot for writes,
/// then wait for the previous hot shard to cool down before reading it.
pub const Histogram = struct {
    allocator: Allocator,

    /// The highest value to include in each bucket.
    upper_bounds: ArrayList(f64),

    /// One hot shard for writing, one cold shard for reading.
    shards: [2]struct {
        /// Total of all observed values.
        sum: Atomic(f64) = Atomic(f64).init(0.0),
        /// Total number of observations that have finished being recorded to this shard.
        count: Atomic(u64) = Atomic(u64).init(0),
        /// Cumulative counts for each upper bound.
        buckets: ArrayList(Atomic(u64)),
    },

    /// Used to ensure reads and writes occur on separate shards.
    /// Atomic representation of `ShardSync`.
    shard_sync: Atomic(u64) = Atomic(u64).init(0),

    /// Prevents more than one reader at a time, since read operations actually
    /// execute an internal write by swapping the hot and cold shards.
    read_mutex: std.Thread.Mutex = .{},

    /// Used by registry to report the histogram
    metric: Metric = .{ .getResultFn = getResult },

    pub const metric_type: MetricType = .histogram;

    const ShardSync = packed struct {
        /// The total count of events that have started to be recorded (including those that finished).
        /// If this is larger than the shard count, it means a write is in progress.
        count: u63 = 0,
        /// Index of the shard currently being used for writes.
        shard: u1 = 0,
    };

    const Self = @This();

    pub fn init(allocator: Allocator, buckets: []const f64) !Self {
        var upper_bounds = try ArrayList(f64).initCapacity(allocator, buckets.len);
        upper_bounds.appendSliceAssumeCapacity(buckets);
        return Self{
            .allocator = allocator,
            .upper_bounds = upper_bounds,
            .shards = .{
                .{ .buckets = try shardBuckets(allocator, buckets.len) },
                .{ .buckets = try shardBuckets(allocator, buckets.len) },
            },
        };
    }

    pub fn deinit(self: *Self) void {
        self.shards[0].buckets.deinit();
        self.shards[1].buckets.deinit();
        self.upper_bounds.deinit();
    }

    pub fn reset(self: *Self) void {
        for (0..2) |shard_i| {
            var shard = &self.shards[shard_i];
            for (shard.buckets.items) |*bucket| {
                _ = bucket.store(0, .monotonic);
            }
            shard.sum.store(0.0, .monotonic);
            shard.count.store(0, .monotonic);
        }
    }

    fn shardBuckets(allocator: Allocator, size: usize) !ArrayList(Atomic(u64)) {
        const slice = try allocator.alloc(u64, size);
        @memset(slice, 0);
        return ArrayList(Atomic(u64)).fromOwnedSlice(allocator, @ptrCast(slice));
    }

    /// Writes a value into the histogram.
    pub fn observe(
        self: *Self,
        /// Must be f64 or int
        value: anytype,
    ) void {
        const float: f64 = if (@typeInfo(@TypeOf(value)) == .int) @floatFromInt(value) else value;
        const shard_sync = self.incrementCount(.acquire); // acquires lock. must be first step.
        const shard = &self.shards[shard_sync.shard];
        for (self.upper_bounds.items, 0..) |bound, i| {
            if (float <= bound) {
                _ = shard.buckets.items[i].fetchAdd(1, .monotonic);
                break;
            }
        }
        _ = shard.sum.fetchAdd(float, .monotonic);
        _ = shard.count.fetchAdd(1, .release); // releases lock. must be last step.
    }

    /// Reads the current state of the histogram.
    pub fn getSnapshot(self: *Self, allocator: ?Allocator) !HistogramSnapshot {
        var alloc = self.allocator;
        if (allocator) |a| alloc = a;

        // Acquire the lock so no one else executes this function at the same time.
        self.read_mutex.lock();
        defer self.read_mutex.unlock();

        // Make the hot shard cold. Some writers may still be writing to it,
        // but no more will start after this.
        const shard_sync = self.flipShard(.monotonic);
        const cold_shard = &self.shards[shard_sync.shard];
        const hot_shard = &self.shards[shard_sync.shard +% 1];

        // Wait until all writers are done writing to the cold shard
        // TODO: switch to a condvar. see: `std.Thread.Condition`
        while (cold_shard.count.cmpxchgStrong(shard_sync.count, 0, .acquire, .monotonic)) |_| {
            // Acquire on success: keeps shard usage after.
        }

        // Now the cold shard is totally cold and unused by other threads.
        // - read the cold shard's data
        // - zero out the cold shard.
        // - write the cold shard's data into the hot shard.
        const cold_shard_sum = cold_shard.sum.swap(0.0, .monotonic);
        var buckets = try ArrayList(Bucket).initCapacity(alloc, self.upper_bounds.items.len);
        var cumulative_count: u64 = 0;
        for (0.., self.upper_bounds.items) |i, upper_bound| {
            const count = cold_shard.buckets.items[i].swap(0, .monotonic);
            cumulative_count += count;
            buckets.appendAssumeCapacity(.{
                .cumulative_count = cumulative_count,
                .upper_bound = upper_bound,
            });
            _ = hot_shard.buckets.items[i].fetchAdd(count, .monotonic);
        }
        _ = hot_shard.sum.fetchAdd(cold_shard_sum, .monotonic);
        _ = hot_shard.count.fetchAdd(shard_sync.count, .monotonic);

        return HistogramSnapshot.init(cold_shard_sum, shard_sync.count, buckets);
    }

    fn getResult(metric: *Metric, allocator: Allocator) Metric.Error!Metric.Result {
        const self: *Self = @fieldParentPtr("metric", metric);
        const snapshot = try self.getSnapshot(allocator);
        return Metric.Result{ .histogram = snapshot };
    }

    /// Increases the global count (used for synchronization), not a count within a shard.
    /// Returns the state from before this operation, which was replaced by this operation.
    fn incrementCount(self: *@This(), comptime ordering: std.builtin.AtomicOrder) ShardSync {
        return @bitCast(self.shard_sync.fetchAdd(1, ordering));
    }

    /// Makes the hot shard cold and vice versa.
    /// Returns the state from before this operation, which was replaced by this operation.
    fn flipShard(self: *@This(), comptime ordering: std.builtin.AtomicOrder) ShardSync {
        const data = self.shard_sync.fetchAdd(@bitCast(ShardSync{ .shard = 1 }), ordering);
        return @bitCast(data);
    }
};

/// A snapshot of the histogram state from a point in time.
pub const HistogramSnapshot = struct {
    /// Sum of all values observed by the histogram.
    sum: f64,
    /// Total number of events observed by the histogram.
    count: u64,
    /// Cumulative histogram counts.
    ///
    /// The len *must* be the same as the amount of memory that was
    /// allocated for this slice, or else the memory will leak.
    buckets: []Bucket,
    /// Allocator that was used to allocate the buckets.
    allocator: Allocator,

    pub fn init(sum: f64, count: u64, buckets: ArrayList(Bucket)) @This() {
        std.debug.assert(buckets.capacity == buckets.items.len);
        return .{
            .sum = sum,
            .count = count,
            .buckets = buckets.items,
            .allocator = buckets.allocator,
        };
    }

    pub fn deinit(self: *const @This()) void {
        self.allocator.free(self.buckets);
    }
};

pub const Bucket = struct {
    cumulative_count: u64 = 0,
    upper_bound: f64 = 0,
};

test "prometheus.histogram: empty" {
    const allocator = std.testing.allocator;
    var hist = try Histogram.init(allocator, &DEFAULT_BUCKETS);
    defer hist.deinit();

    var snapshot = try hist.getSnapshot(null);
    defer snapshot.deinit();

    try expectSnapshot(0, &DEFAULT_BUCKETS, &(.{0} ** 11), snapshot);
}

test "prometheus.histogram: data goes in correct buckets" {
    const allocator = std.testing.allocator;
    var hist = try Histogram.init(allocator, &DEFAULT_BUCKETS);
    defer hist.deinit();

    const expected_buckets = observeVarious(&hist);

    var snapshot = try hist.getSnapshot(null);
    defer snapshot.deinit();

    try expectSnapshot(7, &DEFAULT_BUCKETS, &expected_buckets, snapshot);
}

test "prometheus.histogram: repeated snapshots measure the same thing" {
    const allocator = std.testing.allocator;
    var hist = try Histogram.init(allocator, &DEFAULT_BUCKETS);
    defer hist.deinit();

    const expected_buckets = observeVarious(&hist);

    var snapshot1 = try hist.getSnapshot(null);
    snapshot1.deinit();
    var snapshot = try hist.getSnapshot(null);
    defer snapshot.deinit();

    try expectSnapshot(7, &DEFAULT_BUCKETS, &expected_buckets, snapshot);
}

test "prometheus.histogram: values accumulate across snapshots" {
    const allocator = std.testing.allocator;
    var hist = try Histogram.init(allocator, &DEFAULT_BUCKETS);
    defer hist.deinit();

    _ = observeVarious(&hist);

    var snapshot1 = try hist.getSnapshot(null);
    snapshot1.deinit();

    hist.observe(1.0);

    var snapshot = try hist.getSnapshot(null);
    defer snapshot.deinit();

    const expected_buckets: [11]u64 = .{ 1, 1, 1, 1, 4, 4, 4, 6, 7, 7, 7 };
    try expectSnapshot(8, &DEFAULT_BUCKETS, &expected_buckets, snapshot);
}

test "prometheus.histogram: totals add up after concurrent reads and writes" {
    const allocator = std.testing.allocator;
    var hist = try Histogram.init(allocator, &DEFAULT_BUCKETS);
    defer hist.deinit();

    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(
            .{},
            struct {
                fn run(h: *Histogram) void {
                    for (0..1000) |i| {
                        _ = observeVarious(h);
                        if (i % 10 == 0) {
                            (h.getSnapshot(null) catch @panic("snapshot")).deinit();
                        }
                    }
                }
            }.run,
            .{&hist},
        );
    }
    for (&threads) |*thread| thread.join();

    const snapshot = try hist.getSnapshot(allocator);
    defer snapshot.deinit();

    var expected = ArrayList(u64).init(allocator);
    defer expected.deinit();
    for (result) |r| {
        try expected.append(4000 * r);
    }
    try expectSnapshot(28000, &DEFAULT_BUCKETS, expected.items, snapshot);
}

fn observeVarious(hist: *Histogram) [11]u64 {
    hist.observe(1.0);
    hist.observe(0.1);
    hist.observe(2.0);
    hist.observe(0.1);
    hist.observe(0.0000000001);
    hist.observe(0.1);
    hist.observe(100.0);
    return result;
}

const result: [11]u64 = .{ 1, 1, 1, 1, 4, 4, 4, 5, 6, 6, 6 };

fn expectSnapshot(
    expected_total: u64,
    expected_bounds: []const f64,
    expected_buckets: []const u64,
    snapshot: anytype,
) !void {
    try std.testing.expectEqual(expected_total, snapshot.count);
    try std.testing.expectEqual(DEFAULT_BUCKETS.len, snapshot.buckets.len);
    for (0.., snapshot.buckets) |i, bucket| {
        try expectEqual(
            expected_buckets[i],
            bucket.cumulative_count,
            "value in bucket {}\n",
            .{i},
        );
        try expectEqual(
            expected_bounds[i],
            bucket.upper_bound,
            "bound for bucket {}\n",
            .{i},
        );
    }
}

fn expectEqual(expected: anytype, actual: anytype, comptime fmt: anytype, args: anytype) !void {
    std.testing.expectEqual(expected, actual) catch |e| {
        std.debug.print(fmt, args);
        return e;
    };
    return;
}
