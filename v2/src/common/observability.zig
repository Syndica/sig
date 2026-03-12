const std = @import("std");
const builtin = @import("builtin");

pub const log = @import("observability/log.zig");

comptime {
    _ = log;
}

pub const ReadWrite = struct {
    /// NOTE: some of these actually represent floats, and `std.atomic.Value(T)`s.
    histogram_data: []u64,
    log_streams: []log.MessageStream,
};

pub const ReadOnly = struct {
    startup: *const Startup,
    id_mem: []const u8,
    /// NOTE: Some of these are actually `f64`s.
    gauges: []const std.atomic.Value(u64),
};

/// Data that's only relevant during startup.
pub const Startup = extern struct {
    /// The port to listen on for the prometheus client.
    /// Mutating this is after initialization illegal.
    port: u16,
    /// The maximum log level to emit.
    /// Mutating this is after initialization illegal.
    max_log_level: log.Level,
    /// Should start with a value equal to the number of other services that are going to
    /// be writing metrics to the trace service. The trace service will wait until this
    /// value is equal to zero before starting up, giving all other services a chance to
    /// set up their metrics.
    pending_services: std.atomic.Value(u32),
    /// Represents the end of `id_mem`. Can be incremented atomically by other services to
    /// claim space in `id_mem`.
    id_mem_end: std.atomic.Value(u32),
    /// Represents the end of `gauges`. Can be incremented atomically by other services to
    /// claim space in `gauges`.
    gauges_end: std.atomic.Value(u32),
    /// Represents the end of `histogram_data`. Can be incremented atomically by other services to
    /// claim space in `histogram_data`.
    histogram_data_end: std.atomic.Value(u32),
    /// Represents the end of `log_streams`. Can be incremented atomically by other services to
    /// claim elements in `log_streams`.
    log_streams: std.atomic.Value(u32),

    pub const InitParams = struct {
        /// The port to listen on for the prometheus client.
        port: u16,
        /// The maximum log level to emit.
        max_log_level: log.Level,
        /// Number of other services excluding the observability service (of which there is presumably only instance).
        service_count: u32,
    };

    pub fn init(
        self: *Startup,
        params: InitParams,
    ) void {
        self.* = .{
            .port = params.port,
            .max_log_level = params.max_log_level,
            .pending_services = .init(params.service_count),
            .id_mem_end = .init(0),
            .gauges_end = .init(0),
            .histogram_data_end = .init(0),
            .log_streams = .init(0),
        };
    }

    /// A service should call this when they want to signal to the observability service
    /// that it has acquired a logger stream, and has registered all desired metrics.
    pub fn signalReady(self: *Startup) void {
        std.debug.assert(self.pending_services.fetchSub(1, .release) != 0);
    }
};

pub const endian = builtin.target.cpu.arch.endian();

pub fn Logger(comptime scope_str: []const u8) type {
    return struct {
        sink: log.MessageSink,
        max_level: log.Level,
        const LoggerSelf = @This();

        pub const scope = scope_str;

        pub const noop: LoggerSelf = .{
            .ring = null,
            .max_level = .err,
        };

        pub fn from(logger: anytype) LoggerSelf {
            const LoggerOther = Logger(@TypeOf(logger).scope);
            return LoggerOther.withScope(logger, scope);
        }

        pub fn withScope(
            self: LoggerSelf,
            comptime new_scope: []const u8,
        ) Logger(new_scope) {
            return .{
                .ring = self.ring,
                .max_level = self.max_level,
            };
        }

        pub fn err(self: LoggerSelf) Entry(0) {
            return self.entry(.err);
        }

        pub fn warn(self: LoggerSelf) Entry(0) {
            return self.entry(.warn);
        }

        pub fn info(self: LoggerSelf) Entry(0) {
            return self.entry(.info);
        }

        pub fn debug(self: LoggerSelf) Entry(0) {
            return self.entry(.debug);
        }

        pub fn trace(self: LoggerSelf) Entry(0) {
            return self.entry(.trace);
        }

        pub fn entry(self: LoggerSelf, level: log.Level) Entry(0) {
            return .{
                .logger = self,
                .level = level,
                .entries = .{},
            };
        }

        pub fn Entry(comptime entry_count: usize) type {
            return struct {
                logger: LoggerSelf,
                level: log.Level,
                entries: [entry_count]log.EntryField,
                const EntrySelf = @This();

                pub fn field(
                    self: *const EntrySelf,
                    name: []const u8,
                    value: log.AnyFmt,
                ) Entry(entry_count + 1) {
                    return .{
                        .logger = self.logger,
                        .level = self.level,
                        .entries = self.entries ++ .{.{
                            .name = name,
                            .value = value,
                        }},
                    };
                }

                pub fn logf(
                    self: *const EntrySelf,
                    comptime fmt_str: []const u8,
                    args: anytype,
                ) void {
                    if (@intFromEnum(self.level) > @intFromEnum(self.logger.max_level)) return;
                    self.logger.sink.sendMessage(
                        @intCast(std.time.milliTimestamp()),
                        self.level,
                        scope,
                        &self.entries,
                        fmt_str,
                        args,
                    ) catch |e| switch (e) {
                        // TODO: maybe try to handle these in some way? Maybe panic?
                        error.Full => {},
                        error.WriteFailed => {},
                    };
                }
            };
        }
    };
}

pub const MetricKind = enum(u8) {
    gauge_int,
    gauge_float,
    histogram,
};

/// This represents the metric detail that appears before the metric value in memory.
pub const MetricDetail = struct {
    id: MetricId,
    kind: MetricKind,
    /// The index representing the location of the metric, with its meaning depending on `kind`:
    /// * `gauge_int` & `gauge_float`: index of element in the `gauges` region.
    /// * `histogram`: index of a `bucket_count` element in `histogram_data`, which will be
    /// followed by a number of elements corresponding to a `Histogram` with that bucket_count.
    index: u32,

    /// Returns the number of bytes that would be written by `self.binaryWrite(w)`.
    pub fn binaryLength(self: MetricDetail) usize {
        var trash_buffer: [128]u8 = undefined;
        var dw: std.Io.Writer.Discarding = .init(&trash_buffer);
        self.binaryWrite(&dw.writer) catch |err| switch (err) {
            error.WriteFailed => unreachable,
        };
        return dw.fullCount();
    }

    /// Write metric detail in binary format.
    pub fn binaryWrite(
        self: MetricDetail,
        w: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try self.id.writeBinary(w);
        try w.writeInt(u8, @intFromEnum(self.kind), endian);
        try w.writeInt(u32, self.index, endian);
    }

    /// Expects `r` to be a reader that contains the full serialized metric detail,
    /// such that calls to '`r.take`*' never invalidate previous calls to '`r.take`*'.
    /// This is most easily achieved when `r.* = .fixed(buffer)`.
    pub fn fromFixedReader(
        r: *std.Io.Reader,
    ) (std.Io.Reader.Error || std.Io.Reader.TakeEnumError)!MetricDetail {
        return .{
            .id = try .fromFixedReader(r),
            .kind = try r.takeEnum(MetricKind, endian),
            .index = try r.takeInt(u32, endian),
        };
    }
};

pub const MetricId = struct {
    name: []const u8,
    label_count: usize,
    /// Should be a list of comma-separated strings.
    /// It is asserted that:
    /// * `count(u8, labels, ',') + 1 == label_count`.
    labels: [:'}']const u8,

    pub fn eql(a: MetricId, b: MetricId) bool {
        if (a.label_count != b.label_count) return false;
        if (!std.mem.eql(u8, a.name, b.name)) return false;
        if (!std.mem.eql(u8, a.labels, b.labels)) return false;
        return true;
    }

    pub fn hash(self: MetricId) u64 {
        var hashing_ws_buf: [4096]u8 = undefined;
        var hashing_ws: std.Io.Writer.Hashing(std.hash.Wyhash) =
            .initHasher(.init(0), &hashing_ws_buf);
        const hashing_w = &hashing_ws.writer;
        self.writeBinary(hashing_w) catch unreachable;
        return hashing_ws.hasher.final();
    }

    /// Returns a formatter for the metric id using `writeText`.
    pub fn fmtText(self: MetricId) std.fmt.Alt(MetricId, writeText) {
        return .{ .data = self };
    }

    pub fn writeText(self: MetricId, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(self.name);
        try w.writeByte('{');
        try w.writeAll(self.labels);
        try w.writeByte('}');
    }

    pub fn writeBinary(self: MetricId, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeInt(usize, self.name.len, endian);
        try w.writeAll(self.name);

        try w.writeInt(usize, self.label_count, endian);
        try w.writeAll(self.labels);
        try w.writeByte('}');
    }

    /// Expects `r` to be a reader that contains the full serialized metric id,
    /// such that consecutive calls to '`r.take`*' never invalidate previous calls
    /// to '`r.take`*'.
    /// This is most easily achieved when `r.* = .fixed(buffer)`.
    ///
    /// This is bijective with `writeBinary`.
    pub fn fromFixedReader(
        r: *std.Io.Reader,
    ) std.Io.Reader.Error!MetricId {
        const name_len = try r.takeInt(usize, endian);
        const name = try r.take(name_len);

        const label_count = try r.takeInt(usize, endian);

        var index: usize = 0;
        for (0..label_count) |label_index| while (true) : (index += 1) {
            try r.fill(index + 1);
            switch (r.buffered()[index]) {
                ',' => {
                    std.debug.assert(label_index < label_count - 1);
                    break;
                },
                '}' => {
                    std.debug.assert(label_index == label_count - 1);
                    break;
                },
                else => {},
            }
            if (r.buffered()[index] == ',') break;
        };
        const labels = try r.take(index + 1);

        return .{
            .name = name,
            .label_count = label_count,
            .labels = labels[0 .. labels.len - 1 :'}'],
        };
    }
};

pub const MetricAppender = struct {
    id_mem: []u8,
    id_mem_end: *std.atomic.Value(u32),

    gauges: []std.atomic.Value(u64),
    gauges_end: *std.atomic.Value(u32),

    histogram_data: []u64,
    histogram_data_end: *std.atomic.Value(u32),

    pub const GaugeKind = enum {
        int,
        float,

        pub fn Type(comptime kind: GaugeKind) type {
            return switch (kind) {
                .int => u64,
                .float => f64,
            };
        }
    };

    pub fn appendGauge(
        self: MetricAppender,
        metric_id: MetricId,
        comptime kind: GaugeKind,
        init_value: kind.Type(),
    ) *std.atomic.Value(kind.Type()) {
        const gauge_index = self.gauges_end.fetchAdd(1, .acq_rel);
        self.appendMetricId(.{
            .id = metric_id,
            .kind = switch (kind) {
                .int => .gauge_int,
                .float => .gauge_float,
            },
            .index = gauge_index,
        });
        const gauge = &self.gauges[gauge_index];
        gauge.* = .init(init_value);
        return @ptrCast(gauge);
    }

    pub fn appendHistogram(
        self: MetricAppender,
        metric_id: MetricId,
        bucket_count: u32,
    ) Histogram.Raw {
        const elem_count = Histogram.elementsFromBucketCount(bucket_count);
        const elem_offs = self.histogram_data_end.fetchAdd(elem_count + 1, .acq_rel);
        self.appendMetricId(.{
            .id = metric_id,
            .kind = .histogram,
            .index = elem_offs,
        });
        self.histogram_data[elem_offs] = bucket_count;
        return .{ .elements = self.histogram_data[elem_offs + 1 ..][0..elem_count] };
    }

    fn appendMetricId(self: MetricAppender, metric_detail: MetricDetail) void {
        const id_mem_len = metric_detail.binaryLength();
        const id_mem_offset = self.id_mem_end.fetchAdd(@intCast(id_mem_len), .acq_rel);

        var id_mem_w: std.Io.Writer = .fixed(self.id_mem[id_mem_offset..][0..id_mem_len]);
        metric_detail.binaryWrite(&id_mem_w) catch |err| switch (err) {
            error.WriteFailed => unreachable,
        };
    }
};

/// This struct consists of pointers to a contiguous list of elements of size `@sizeOf(u64)`
/// and alignment `@alignOf(u64)`.
/// The order of the elements match the field order.
pub const Histogram = struct {
    /// The highest value to include in each bucket.
    upper_bounds: []const f64,
    /// Used to ensure reads and writes occur on separate shards.
    /// Atomic representation of `ShardSync`.
    shard_sync: *std.atomic.Value(u64),
    /// One hot shard for writing, one cold shard for reading.
    shards: [2]Shard,

    pub const DEFAULT_UPPER_BOUNDS: [11]f64 = .{
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    };

    /// Assumes `raw` is in a valid state. Passing an uninitialized or partially-initialized
    /// `raw` may cause illegal behavior.
    pub fn fromRaw(raw: Raw) Histogram {
        return .{
            .upper_bounds = raw.upperBounds(),
            .shard_sync = raw.shardSync(),
            .shards = raw.shards(),
        };
    }

    pub const Shard = struct {
        /// Total of all observed values.
        sum: *std.atomic.Value(f64),
        /// Total number of observations that have finished being recorded to this shard.
        count: *std.atomic.Value(u64),
        /// Cumulative counts for each upper bound.
        buckets: []std.atomic.Value(u64),

        /// For when `elems` does not already represent a valid shard, see `Shard.init`.
        /// Assumes `elems.len >= 2`.
        pub fn fromElements(elems: []u64) Shard {
            return .{
                .sum = @ptrCast(&elems[0]),
                .count = @ptrCast(&elems[1]),
                .buckets = @ptrCast(elems[2..]),
            };
        }

        /// XXX: Not an atomic operation. This method overwrites all pointed-to data directly
        /// Assumes `self.buckets.len == init_data.buckets.len`.
        /// Sets all pointed-to data to zero.
        pub fn initZeroes(self: Shard) void {
            self.sum.* = .init(0);
            self.count.* = .init(0);
            @memset(self.buckets, .init(0));
        }
    };

    /// Accessor for a raw view of the slice representing a histogram's pointed-to data.
    pub const Raw = struct {
        /// `elements.len` is assumed to always have a valid length
        /// according to `bucketFromElementsCount(elements.len)`.
        elements: []u64,

        /// XXX: Not an atomic operation. This method overwrites all pointed-to data directly.
        /// Assumes `self.bucketCount() == upper_bounds.len`.
        /// Assumes `self.bucketcount() == init_data.shards[n].buckets.len`.
        /// Assumes everything assumed by `Shard.init` about each element of `init_data.shards`.
        ///
        /// This method is used to ensure data is initialized exhaustively.
        pub fn init(self: Raw, upper_bounds: []const f64) void {
            @memcpy(self.upperBounds(), upper_bounds);
            self.shardSync().* = .init(0);
            for (&self.shards()) |shard| shard.initZeroes();
        }

        /// Assumes that `bucketFromElementsCount(self.elements.len)` returns a non-error value.
        pub fn bucketCount(self: Raw) u64 {
            return bucketFromElementsCount(self.elements.len) catch unreachable;
        }

        /// Should be treated as immutable after initialization.
        pub fn upperBounds(self: Raw) []f64 {
            return @ptrCast(self.elements[0..self.bucketCount()]);
        }

        pub fn shardSync(self: Raw) *std.atomic.Value(u64) {
            return @ptrCast(&self.elements[self.bucketCount()]);
        }

        pub fn shards(self: Raw) [2]Shard {
            const bucket_count = self.bucketCount();
            const all_elems = self.elements[bucket_count + 1 ..];
            const shard0: Shard = .fromElements(all_elems[0..@divExact(all_elems.len, 2)]);
            const shard1: Shard = .fromElements(all_elems[@divExact(all_elems.len, 2)..]);
            std.debug.assert(shard0.buckets.len == bucket_count);
            std.debug.assert(shard0.buckets.len == shard1.buckets.len);
            return .{ shard0, shard1 };
        }
    };

    /// Writes a value into the histogram.
    pub fn observe(
        self: *const Histogram,
        /// Must be f64 or int
        value: anytype,
    ) void {
        const float: f64 = if (@typeInfo(@TypeOf(value)) == .int) @floatFromInt(value) else value;
        const shard_sync = self.incrementCount(.acquire); // acquires lock. must be first step.
        const shard = &self.shards[shard_sync.shard];
        for (self.upper_bounds, 0..) |bound, i| {
            if (float <= bound) {
                _ = shard.buckets[i].fetchAdd(1, .monotonic);
                break;
            }
        }
        _ = shard.sum.fetchAdd(float, .monotonic);
        _ = shard.count.fetchAdd(1, .release); // releases lock. must be last step.
    }

    /// Swaps in the hot shard for the cold shard, such that it can be viewed as a snapshot of
    /// recent state.
    /// The returned struct is used to access this state iteratively, before resetting the cold
    /// shard's state, so it can be swapped out again in the future.
    pub fn swapOutSnapshot(self: *const Histogram) SnapshotReader {
        // Make the hot shard cold. Some writers may still be writing to it,
        // but no more will start after this.
        const shard_sync = self.flipShard(.monotonic);
        const cold_shard = &self.shards[shard_sync.shard];
        const hot_shard = &self.shards[shard_sync.shard +% 1];

        // Wait until all writers are done writing to the cold shard
        // TODO: maybe switch to a condvar? see: `std.Thread.Condition`
        while (cold_shard.count.cmpxchgStrong(shard_sync.count, 0, .acquire, .monotonic)) |_| {
            // Acquire on success: keeps shard usage after.
        }

        // Now the cold shard is totally cold and unused by other threads.
        // - read the cold shard's data
        // - zero out the cold shard.
        // - write the cold shard's data into the hot shard.
        const cold_shard_sum = cold_shard.sum.swap(0.0, .monotonic);

        return .{
            .count = shard_sync.count,
            .sum = cold_shard_sum,

            .upper_bounds = self.upper_bounds,
            .cold_shard_buckets = cold_shard.buckets,
            .hot_shard_buckets = hot_shard.buckets,
            .hot_shard = hot_shard,

            .current_cumulative_count = 0,
            .current_bucket_index = 0,
        };
    }

    pub const SnapshotReader = struct {
        /// Total number of events observed by the histogram.
        count: u63,
        /// Sum of all values observed by the histogram.
        sum: f64,

        // internal references
        upper_bounds: []const f64,
        cold_shard_buckets: []std.atomic.Value(u64),
        hot_shard_buckets: []std.atomic.Value(u64),
        hot_shard: *const Shard,

        // mutable state
        current_cumulative_count: u64,
        current_bucket_index: usize,

        pub const Bucket = struct {
            upper_bound: f64,
            cumulative_count: u64,
        };

        pub fn finished(self: *const SnapshotReader) bool {
            std.debug.assert(self.cold_shard_buckets.len == self.upper_bounds.len);
            std.debug.assert(self.cold_shard_buckets.len == self.hot_shard.buckets.len);
            return self.current_bucket_index == self.cold_shard_buckets.len;
        }

        /// Release the snapshot reader, ignoring any unobserved buckets.
        pub fn release(self: *SnapshotReader) void {
            if (self.finished()) return;
            while (self.nextBucket()) |_| {}
        }

        /// After this returns `null`, the cold shard will have been fully reset, and the hot shard
        /// will have everything that was pending in the cold bucket aggregated into it.
        pub fn nextBucket(self: *SnapshotReader) ?Bucket {
            if (self.finished()) {
                _ = self.hot_shard.sum.fetchAdd(self.sum, .monotonic);
                _ = self.hot_shard.count.fetchAdd(self.count, .monotonic);
                return null;
            }
            defer self.current_bucket_index += 1;

            const upper_bound = self.upper_bounds[self.current_bucket_index];
            const cold_bucket = &self.cold_shard_buckets[self.current_bucket_index];
            const hot_bucket = &self.hot_shard_buckets[self.current_bucket_index];

            const count = cold_bucket.swap(0, .monotonic);
            _ = hot_bucket.fetchAdd(count, .monotonic);

            self.current_cumulative_count += count;
            return .{
                .cumulative_count = self.current_cumulative_count,
                .upper_bound = upper_bound,
            };
        }
    };

    pub fn elementsFromBucketCount(bucket_count: u32) u32 {
        const elements_per_shard =
            1 + // sum
            1 + // count
            bucket_count // buckets
        ;
        const backing_element_count =
            bucket_count + // upper_bounds
            1 + // shard_sync
            2 * elements_per_shard // shards
        ;
        return backing_element_count;
    }

    pub const BucketFromElementsCountError = error{ TooFewElements, InvalidFlexibleCount };
    pub fn bucketFromElementsCount(total_elements: u64) BucketFromElementsCountError!u64 {
        const min_fields =
            1 + // shard_sync
            2 * (0 + // shards[i]
                1 + // sum
                1 // count
            );
        if (total_elements < min_fields) {
            return error.TooFewElements;
        }
        const flexible_elements = total_elements - min_fields;
        if (flexible_elements % 3 != 0) {
            return error.InvalidFlexibleCount;
        }
        return @divExact(flexible_elements, 3);
    }

    const ShardSync = packed struct {
        /// The total count of events that have started to be recorded (including those that finished).
        /// If this is larger than the shard count, it means a write is in progress.
        count: u63 = 0,
        /// Index of the shard currently being used for writes.
        shard: u1 = 0,
    };

    /// Increases the global count (used for synchronization), not a count within a shard.
    /// Returns the state from before this operation, which was replaced by this operation.
    fn incrementCount(self: *const Histogram, comptime ordering: std.builtin.AtomicOrder) ShardSync {
        return @bitCast(self.shard_sync.fetchAdd(1, ordering));
    }

    /// Makes the hot shard cold and vice versa.
    /// Returns the state from before this operation, which was replaced by this operation.
    fn flipShard(self: *const Histogram, comptime ordering: std.builtin.AtomicOrder) ShardSync {
        const shard_sync: ShardSync = .{ .shard = 1 };
        const data = self.shard_sync.fetchAdd(@bitCast(shard_sync), ordering);
        return @bitCast(data);
    }

    /// Used to initialize a histogram in-place.
    pub fn initForTest(
        gpa: std.mem.Allocator,
        upper_bounds: []const f64,
    ) std.mem.Allocator.Error!Histogram {
        const element_count = elementsFromBucketCount(@intCast(upper_bounds.len));
        const raw: Raw = .{ .elements = try gpa.alloc(u64, element_count) };
        raw.init(upper_bounds);
        return .fromRaw(raw);
    }

    /// Only valid if `self` was initialized using `initForTest`.
    pub fn deinitForTest(self: Histogram, gpa: std.mem.Allocator) void {
        const element_count = elementsFromBucketCount(@intCast(self.upper_bounds.len));
        const elements: []const u64 = @ptrCast(self.upper_bounds.ptr[0..element_count]);
        gpa.free(elements);
    }

    pub fn testExpectBuckets(
        self: Histogram,
        expected_count: u63,
        expected_buckets: []const SnapshotReader.Bucket,
    ) !void {
        if (!builtin.is_test) @compileError("Not allowed in tests.");
        const gpa = std.testing.allocator;

        var snap = self.swapOutSnapshot();
        defer snap.release();

        var actual_buckets: std.ArrayList(SnapshotReader.Bucket) = .empty;
        defer actual_buckets.deinit(gpa);

        while (snap.nextBucket()) |bucket| {
            try actual_buckets.append(gpa, bucket);
        }

        try std.testing.expectEqualSlices(
            Histogram.SnapshotReader.Bucket,
            expected_buckets,
            actual_buckets.items,
        );
        try std.testing.expectEqual(expected_count, snap.count);
    }
};

fn initBuckets(
    comptime len: usize,
    upper_bounds: *const [len]f64,
    cumulative_counts: *const [len]u64,
) [len]Histogram.SnapshotReader.Bucket {
    var buckets: [len]Histogram.SnapshotReader.Bucket = undefined;
    for (
        &buckets,
        upper_bounds,
        cumulative_counts,
    ) |*bucket, upper_bound, cumulative_count| {
        bucket.* = .{
            .upper_bound = upper_bound,
            .cumulative_count = cumulative_count,
        };
    }
    return buckets;
}

const various_observation_results: [11]u64 = .{ 1, 1, 1, 1, 4, 4, 4, 5, 6, 6, 6 };
fn observeVarious(hist: Histogram) void {
    hist.observe(1.0);
    hist.observe(0.1);
    hist.observe(2.0);
    hist.observe(0.1);
    hist.observe(0.0000000001);
    hist.observe(0.1);
    hist.observe(100.0);
}

test "histogram: empty" {
    const gpa = std.testing.allocator;

    const histogram: Histogram = try .initForTest(gpa, &Histogram.DEFAULT_UPPER_BOUNDS);
    defer histogram.deinitForTest(gpa);

    try histogram.testExpectBuckets(0, &initBuckets(
        Histogram.DEFAULT_UPPER_BOUNDS.len,
        &Histogram.DEFAULT_UPPER_BOUNDS,
        &@splat(0),
    ));
}

test "histogram: data goes in correct buckets" {
    const gpa = std.testing.allocator;

    const histogram: Histogram = try .initForTest(gpa, &Histogram.DEFAULT_UPPER_BOUNDS);
    defer histogram.deinitForTest(gpa);

    observeVarious(histogram);

    try histogram.testExpectBuckets(7, &initBuckets(
        Histogram.DEFAULT_UPPER_BOUNDS.len,
        &Histogram.DEFAULT_UPPER_BOUNDS,
        &various_observation_results,
    ));
}

test "histogram: repeated snapshots measure the same thing" {
    const gpa = std.testing.allocator;

    const histogram: Histogram = try .initForTest(gpa, &Histogram.DEFAULT_UPPER_BOUNDS);
    defer histogram.deinitForTest(gpa);

    observeVarious(histogram);

    for (0..2) |_| try histogram.testExpectBuckets(7, &initBuckets(
        Histogram.DEFAULT_UPPER_BOUNDS.len,
        &Histogram.DEFAULT_UPPER_BOUNDS,
        &various_observation_results,
    ));
}

test "histogram: values accumulate across snapshots" {
    const gpa = std.testing.allocator;

    const histogram: Histogram = try .initForTest(gpa, &Histogram.DEFAULT_UPPER_BOUNDS);
    defer histogram.deinitForTest(gpa);

    observeVarious(histogram);
    try histogram.testExpectBuckets(7, &initBuckets(
        Histogram.DEFAULT_UPPER_BOUNDS.len,
        &Histogram.DEFAULT_UPPER_BOUNDS,
        &various_observation_results,
    ));

    histogram.observe(1.0);

    try histogram.testExpectBuckets(8, &initBuckets(
        Histogram.DEFAULT_UPPER_BOUNDS.len,
        &Histogram.DEFAULT_UPPER_BOUNDS,
        &.{ 1, 1, 1, 1, 4, 4, 4, 6, 7, 7, 7 },
    ));
}

test "histogram: totals add up after concurrent reads and writes" {
    const gpa = std.testing.allocator;

    const histogram: Histogram = try .initForTest(gpa, &Histogram.DEFAULT_UPPER_BOUNDS);
    defer histogram.deinitForTest(gpa);

    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*thread, thread_i| {
        const local = struct {
            fn run(h: Histogram, snapshotter: bool) void {
                for (0..1000) |i| {
                    observeVarious(h);
                    if (snapshotter and i % 10 == 0) {
                        var snap = h.swapOutSnapshot();
                        defer snap.release();
                    }
                }
            }
        };
        thread.* = try .spawn(.{}, local.run, .{ histogram, thread_i == 0 });
    }
    for (&threads) |*thread| thread.join();

    var expected = various_observation_results;
    for (&expected) |*r| r.* *= 4000;

    try histogram.testExpectBuckets(28000, &initBuckets(
        Histogram.DEFAULT_UPPER_BOUNDS.len,
        &Histogram.DEFAULT_UPPER_BOUNDS,
        &expected,
    ));
}
