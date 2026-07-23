const std = @import("std");
const builtin = @import("builtin");
const clock = @import("clock.zig");
const tracy = @import("tracy");

pub const metric = @import("telemetry/metric.zig");
pub const log = @import("telemetry/log.zig");
pub const prometheus = @import("telemetry/prometheus.zig");
pub const prometheus_proto = @import("telemetry/prometheus_proto.zig");
comptime {
    if (@import("builtin").is_test) {
        _ = @import("telemetry/log.zig");
        _ = @import("telemetry/metric.zig");
        _ = @import("telemetry/prometheus.zig");
        _ = @import("telemetry/prometheus_proto.zig");
    }
}

/// The native endian, which is what is used by telemetry for `std.Io.Writer` and `std.Io.Reader` IPC data.
pub const endian = builtin.target.cpu.arch.endian();

/// Data that's only relevant during startup.
pub const Region = extern struct {
    /// Mutating this is after initialization illegal.
    info: Info align(@alignOf(u64)),
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

    pub const Info = extern struct {
        /// The port to listen on for the prometheus client.
        port: u16,
        /// The length of the encoded log filters byte string.
        log_filters_len: u32,

        /// Number of other services excluding the telemetry service (of which there is presumably only instance).
        /// This is also the maximum number of log streams to support.
        service_count: u32,

        /// The maximum number of bytes to allow for storing metric ids.
        id_mem_len: u32,
        /// The maximum number of (`u64`-sized) elements to support.
        gauges_len: u32,
        /// The maximum number of histogram (`u64`-sized) elements to support.
        histogram_data_len: u32,

        /// NOTE: keep in sync with `Region.getSlices`.
        pub fn regionSize(self: Info) usize {
            var size: usize = 0;
            size += @sizeOf(Region);

            size = std.mem.alignForward(usize, size, @alignOf(u8));
            size += self.log_filters_len;

            size = std.mem.alignForward(usize, size, @alignOf(u64));
            size += self.gauges_len * @sizeOf(u64);

            size = std.mem.alignForward(usize, size, @alignOf(u64));
            size += self.histogram_data_len * @sizeOf(u64);

            size = std.mem.alignForward(usize, size, @alignOf(log.MessageStream));
            size += self.service_count * @sizeOf(log.MessageStream);

            size = std.mem.alignForward(usize, size, @alignOf(u8));
            size += self.id_mem_len;
            return size;
        }
    };

    pub const InitParams = struct {
        /// The port to listen on for the prometheus client.
        port: u16,
        log_filters_encoded: []const u8,

        /// Number of other services excluding the telemetry service (of which there is presumably only instance).
        /// This is also the maximum number of log streams to support.
        service_count: u32,

        /// The maximum number of bytes to allow for storing metric ids.
        id_mem_len: u32,
        /// The maximum number of (`u64`-sized) elements to support.
        gauges_len: u32,
        /// The maximum number of histogram (`u64`-sized) elements to support.
        histogram_data_len: u32,

        pub fn info(self: InitParams) Info {
            return .{
                .port = self.port,
                .log_filters_len = @intCast(self.log_filters_encoded.len),

                .service_count = self.service_count,

                .id_mem_len = self.id_mem_len,
                .gauges_len = self.gauges_len,
                .histogram_data_len = self.histogram_data_len,
            };
        }
    };

    pub fn init(
        self: *Region,
        params: InitParams,
    ) void {
        self.* = .{
            .info = params.info(),
            .pending_services = .init(params.service_count),
            .id_mem_end = .init(0),
            .gauges_end = .init(0),
            .histogram_data_end = .init(0),
            .log_streams = .init(0),
        };
        @memcpy(self.getSlices().log_filters_encoded, params.log_filters_encoded);
    }

    pub const Slices = struct {
        log_filters_encoded: []u8,
        id_mem: []u8,
        /// NOTE: Some of these are actually `f64`s.
        gauges: []std.atomic.Value(u64),
        /// NOTE: some of these actually represent floats, and `std.atomic.Value(T)`s.
        histogram_data: []u64,
        log_streams: []log.MessageStream,
    };

    /// NOTE: keep in sync with `Info.regionSize`.
    pub fn getSlices(self: *Region) Slices {
        const buf: []align(@alignOf(u64)) u8 = trailing: {
            const ptr: [*]align(@alignOf(u64)) u8 = @ptrCast(self);
            const full: []align(@alignOf(u64)) u8 = ptr[0..self.info.regionSize()];
            const header_padded_size = comptime Info.regionSize(.{
                .port = 0,
                .log_filters_len = 0,
                .service_count = 0,
                .id_mem_len = 0,
                .gauges_len = 0,
                .histogram_data_len = 0,
            });
            break :trailing full[header_padded_size..];
        };
        var seek: usize = 0;
        const log_filters =
            skipPaddingTakeElements(buf, &seek, self.info.log_filters_len, u8);
        const gauges =
            skipPaddingTakeElements(buf, &seek, self.info.gauges_len, std.atomic.Value(u64));
        const histogram_data =
            skipPaddingTakeElements(buf, &seek, self.info.histogram_data_len, u64);
        const log_streams =
            skipPaddingTakeElements(buf, &seek, self.info.service_count, log.MessageStream);
        const id_mem =
            skipPaddingTakeElements(buf, &seek, self.info.id_mem_len, u8);
        return .{
            .log_filters_encoded = log_filters,
            .id_mem = id_mem,
            .gauges = gauges,
            .histogram_data = histogram_data,
            .log_streams = log_streams,
        };
    }

    fn skipPaddingTakeElements(
        buffer: []align(@alignOf(u64)) u8,
        seek: *usize,
        n: usize,
        comptime T: type,
    ) []T {
        seek.* += paddingSize(seek.*, .of(T));
        const bytes = buffer[seek.*..][0 .. n * @sizeOf(T)];
        seek.* += n * @sizeOf(T);
        return @ptrCast(@alignCast(bytes));
    }

    fn paddingSize(seek: usize, alignment: std.mem.Alignment) usize {
        return std.mem.alignForward(usize, seek, alignment.toByteUnits()) - seek;
    }

    /// A service should call this when they want to signal to the telemetry service
    /// that it has acquired a logger stream, and has registered all desired metrics.
    pub fn signalReady(self: *Region) void {
        std.debug.assert(self.pending_services.fetchSub(1, .release) != 0);
    }

    pub fn acquireLogger(
        self: *Region,
        /// Asserts `str.len <= log.MessageStream.Name.MAX_LEN`.
        name: []const u8,
        comptime scope: []const u8,
    ) Logger(scope) {
        const slices = self.getSlices();

        const log_stream_index = self.log_streams.fetchAdd(1, .release);
        const stream = &slices.log_streams[log_stream_index];

        std.debug.assert(name.len <= log.MessageStream.Name.MAX_LEN); // see `stream.name.init`
        stream.name.init(name);
        return .{ .sink = .{ .swap_buffer = &stream.swap_buffer } };
    }

    /// Low-level helper for registering metrics.
    pub fn metricAppender(self: *Region) metric.Appender {
        const slices = self.getSlices();
        return .{
            .id_mem = slices.id_mem,
            .id_mem_end = &self.id_mem_end,

            .gauges = slices.gauges,
            .gauges_end = &self.gauges_end,

            .histogram_data = slices.histogram_data,
            .histogram_data_end = &self.histogram_data_end,
        };
    }
};

pub fn Logger(comptime scope_str: []const u8) type {
    return struct {
        sink: log.MessageSink,
        const LoggerSelf = @This();

        pub const scope = scope_str;

        pub const noop: LoggerSelf = .{ .sink = .noop };

        pub fn from(logger: anytype) LoggerSelf {
            const LoggerOther = Logger(@TypeOf(logger).scope);
            return LoggerOther.withScope(logger, scope);
        }

        pub fn withScope(
            self: LoggerSelf,
            comptime new_scope: []const u8,
        ) Logger(new_scope) {
            return .{ .sink = self.sink };
        }

        pub fn fatal(self: LoggerSelf) Entry(0) {
            return self.entry(.fatal);
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
            const log_zig = @import("telemetry/log.zig");
            return struct {
                logger: LoggerSelf,
                level: log_zig.Level,
                entries: [entry_count]log_zig.EntryField,
                const EntrySelf = @This();

                /// Add a field to the log message using the default formatter
                /// for the type, if it exists. To customize the format, use
                /// `fieldFmt`.
                pub fn field(
                    self: *const EntrySelf,
                    name: []const u8,
                    value_ptr: anytype,
                ) Entry(entry_count + 1) {
                    const new_entry: log_zig.EntryField = .{
                        .name = name,
                        .value = .fromValue(fieldFmtString(@TypeOf(value_ptr.*)), value_ptr),
                    };
                    return .{
                        .logger = self.logger,
                        .level = self.level,
                        .entries = self.entries ++ .{new_entry},
                    };
                }

                /// Returns the field format string for common types: strings,
                /// numbers, and types with `format` functions.
                ///
                /// For other types, rather than falling back to `{any}`, they
                /// are simply not supported. `{any}` formatting is still
                /// achievable, but it must be done explicitly using `fieldFmt`.
                /// This makes it so `{any}` formatting is never used by
                /// accident, which may lead to unsatisfying output.
                fn fieldFmtString(comptime Value: type) []const u8 {
                    return switch (@typeInfo(Value)) {
                        .int, .comptime_int, .float, .comptime_float => "{}",

                        .pointer => |ptr| if (ptr.size == .one)
                            fieldFmtString(ptr.child)
                        else if (ptr.child == u8)
                            "{s}"
                        else
                            @compileError("use fieldFmt"),

                        .array => |arr| if (arr.child == u8)
                            "{s}"
                        else
                            @compileError("use fieldFmt"),

                        else => if (@hasDecl(Value, "format"))
                            "{f}"
                        else
                            @compileError("use fieldFmt"),
                    };
                }

                /// Add a field to the log message with a custom formatter.
                pub fn fieldFmt(
                    self: *const EntrySelf,
                    name: []const u8,
                    value: log_zig.EntryValueFmt,
                ) Entry(entry_count + 1) {
                    const new_entry: log_zig.EntryField = .{
                        .name = name,
                        .value = value,
                    };
                    return .{
                        .logger = self.logger,
                        .level = self.level,
                        .entries = self.entries ++ .{new_entry},
                    };
                }

                pub fn log(self: *const EntrySelf, comptime fmt_str: []const u8) void {
                    self.logf(fmt_str, .{});
                }

                /// If `self.logger.sink == .noop`, this is guaranteed to succeed.
                ///
                /// If `self.logger.sink == .writer`, failure to write is ignored; ability to
                /// detect such a failure is defined by the writer implementation.
                ///
                /// If `self.logger.sink == .swap_buffer`, it is assumed there is another thread
                /// actively consuming the buffer, so this function will re-attempt transmission
                /// a number of times; when a retry threshold is reached, it will panic.
                pub fn logf(
                    self: *const EntrySelf,
                    comptime fmt_str: []const u8,
                    args: anytype,
                ) void {
                    switch (self.level) {
                        inline else => |ilevel| {
                            tracy.print(@tagName(ilevel) ++ ": " ++ fmt_str, args);
                        },
                    }

                    const message: log_zig.Message = .{
                        .epoch_millis = clock.wallclock(.ms),
                        .scope = scope,
                        .fields = &self.entries,
                        .msg = .fromFmt(fmt_str, &args),
                        .level = self.level,
                    };

                    switch (self.logger.sink) {
                        .noop => return,
                        .writer => |w| {
                            _ = message.write(w) catch |e| switch (e) {
                                error.WriteFailed => {},
                            };
                        },
                        .swap_buffer => |sb| {
                            const expected_header = message.computeHeader();
                            const encoded_len = expected_header.encodedLength();

                            // NOTE: although the retry path is highly unlikely assuming the swapbuffer is sufficiently large,
                            // there's an extremely slim but non-zero chance it could happen.
                            // If it does happen, but the reader is actually still responsive, it is unlikely to happen many
                            // times in a row, so we'll retry a handful of times before considering the channel to be dead,
                            // and subsequently panic.
                            const max_retries = 100;

                            const writable: log_zig.MessageStream.SwapBuffer.Writable =
                                for (0..max_retries) |_| {
                                    const writable = sb.getWritable();
                                    if (writable.slice.len >= encoded_len) break writable;
                                    writable.commit(0);
                                } else std.debug.panic(
                                    "Failed to log message after {d} retries.",
                                    .{max_retries},
                                );

                            var fbw: std.Io.Writer = .fixed(writable.slice);
                            const message_header = message.write(&fbw) catch |e| switch (e) {
                                // we already know there's enough space in the buffer for the message.
                                error.WriteFailed => unreachable,
                            };
                            std.debug.assert(message_header.encodedLength() == encoded_len);
                            std.debug.assert(std.meta.eql(message_header, expected_header));
                            writable.commit(encoded_len);
                        },
                    }
                }
            };
        }
    };
}

pub const Counter = struct {
    value: *std.atomic.Value(u64),

    pub fn reset(self: Counter) void {
        self.value.store(0, .monotonic);
    }

    pub fn increment(self: Counter, amount: u64) void {
        _ = self.value.fetchAdd(amount, .monotonic);
    }
};

pub const Gauge = struct {
    value: *std.atomic.Value(u64),

    pub fn set(self: Gauge, value: u64) void {
        self.value.store(value, .monotonic);
    }
};

/// Can be used as a counter or a gauge.
pub fn Variant(comptime V: type) type {
    return struct {
        counts: [Indexer.count]*std.atomic.Value(u64),
        const VariantCounterSelf = @This();

        pub const Value = V;
        pub const Enum = std.meta.FieldEnum(Value);
        pub const Tag = switch (@typeInfo(Value)) {
            .@"enum" => Value,
            .@"union" => |u_info| u_info.tag_type.?,
            .error_set => Value,
            else => @compileError("Unsupported: " ++ @typeName(Value)),
        };

        pub const Indexer = std.enums.EnumIndexer(Enum);

        pub fn set(self: *const VariantCounterSelf, tag: Tag, value: u64) void {
            _ = self.counts[indexFromTag(tag)].store(value, .monotonic);
        }

        pub fn increment(self: *const VariantCounterSelf, tag: Tag, amount: u64) void {
            _ = self.counts[indexFromTag(tag)].fetchAdd(amount, .monotonic);
        }

        /// Asserts `amount` to be less than the current value.
        pub fn decrement(self: *const VariantCounterSelf, tag: Tag, amount: u64) void {
            std.debug.assert(amount <= self.counts[indexFromTag(tag)].fetchSub(amount, .monotonic));
        }

        pub fn reset(self: *const VariantCounterSelf, tag: Tag) void {
            self.counts[indexFromTag(tag)].store(0, .monotonic);
        }

        pub fn resetAll(self: *const VariantCounterSelf) void {
            for (&self.counts) |*count| count.store(0, .monotonic);
        }

        fn indexFromTag(value: Tag) usize {
            return Indexer.indexOf(enumFromTag(value));
        }

        fn enumFromTag(value: Tag) Enum {
            return switch (@typeInfo(Value)) {
                .@"enum" => if (Enum == Value) value else switch (value) {
                    inline else => |itag| @field(Enum, @tagName(itag)),
                },
                .@"union" => |u_info| if (Enum == u_info.tag_type) value else switch (value) {
                    inline else => |_, itag| @field(Enum, @tagName(itag)),
                },
                .error_set => switch (value) {
                    inline else => |tag| @field(Enum, @errorName(tag)),
                },
                else => @compileError("Unsupported: " ++ @typeName(Value)),
            };
        }
    };
}

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
        const shard_sync: ShardSync = @bitCast(self.shard_sync.fetchAdd(1, .acquire)); // acquires lock. must be first step.
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

    /// Starts a span timer that records its elapsed nanoseconds into this histogram. Call
    /// `.observe()` on the result at the end of the span, usually with `defer`. `upper_bounds` must
    /// then be in nanoseconds; see the unit contract on `LatencyObserver`, and `IO_LATENCY_BOUNDS`
    /// in `snapshot/download.zig` for an example.
    pub fn observer(self: *const Histogram) LatencyObserver(.standard, null) {
        return .init(self);
    }

    /// Swaps in the hot shard for the cold shard, such that it can be viewed as a snapshot of
    /// recent state.
    /// The returned struct is used to access this state iteratively, before resetting the cold
    /// shard's state, so it can be swapped out again in the future.
    pub fn swapOutSnapshot(self: *const Histogram) SnapshotReader {
        // Make the hot shard cold. Some writers may still be writing to it,
        // but no more will start after this.
        const shard_sync = self.flipShard(.acq_rel);
        const cold_shard = &self.shards[shard_sync.shard];
        const hot_shard = &self.shards[shard_sync.shard +% 1];

        // Wait until all writers are done writing to the cold shard
        while (true) {
            const current_cold_count = cold_shard.count.load(.acquire);
            if (current_cold_count == shard_sync.count) {
                cold_shard.count.store(0, .monotonic);
                break;
            }
            std.debug.assert(current_cold_count < shard_sync.count);
        }

        // Now the cold shard is totally cold and unused by other threads.
        // - read the cold shard's data
        // - zero out the cold shard.
        // - write the cold shard's data into the hot shard.
        const cold_shard_sum = cold_shard.sum.load(.monotonic);
        cold_shard.sum.store(0.0, .monotonic);

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
        /// NOTE: it may seem strange to have references to the hot shard & its buckets
        /// inside the iterator for reading the cold state, however the results from each
        /// cold bucket have to be read and then added back to the current hot shard & its
        /// buckets in order to maintain consistency.
        hot_shard_buckets: []std.atomic.Value(u64),
        /// NOTE: see NOTE on `hot_shard_buckets`.
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

/// Prometheus native-histogram bucket boundaries within one mantissa octave for a given `schema`:
/// `bounds[k] = 0.5 * 2^(k / 2^schema)` for `k in 0..2^schema`. Used to bin the `frexp` fraction
/// (which lies in `[0.5, 1)`) into a sub-octave bucket.
fn nativeBoundsTable(comptime schema: u4) [@as(usize, 1) << schema]f64 {
    @setEvalBranchQuota(1_000_000); // comptime `exp2` per entry is branch-heavy
    var arr: [@as(usize, 1) << schema]f64 = undefined;
    const per_octave: f64 = @floatFromInt(@as(u64, 1) << schema);
    for (&arr, 0..) |*b, k| {
        b.* = 0.5 * std.math.exp2(@as(f64, @floatFromInt(k)) / per_octave);
    }
    return arr;
}

/// Smallest index `k` with `bounds[k] >= frac` (like Go's `sort.SearchFloat64s`), in `0..bounds.len`.
fn searchFloat(bounds: []const f64, frac: f64) i64 {
    var lo: usize = 0;
    var hi: usize = bounds.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (bounds[mid] < frac) lo = mid + 1 else hi = mid;
    }
    return @intCast(lo);
}

/// The global Prometheus native-histogram bucket index for `ns` at `schema`. Splits `ns` with
/// `frexp` and bins the fraction via a per-schema boundary table, so the result is exact at octave
/// boundaries (mirrors `prometheus/client_golang`) and avoids the off-by-one a naive
/// `ceil(2^schema * log2(ns))` suffers from floating-point error. Assumes `ns >= 1`.
fn nativeBucketIndex(schema: u4, ns: u64) i64 {
    const fv: f64 = @floatFromInt(ns);
    const r = std.math.frexp(fv);
    const per_octave: i64 = @as(i64, 1) << @as(u6, schema);
    const s: i64 = switch (schema) {
        inline 0...8 => |sc| blk: {
            const table = comptime nativeBoundsTable(sc);
            break :blk searchFloat(&table, r.significand);
        },
        else => unreachable,
    };
    return (@as(i64, r.exponent) - 1) * per_octave + s;
}

pub const LatencyHistogram = struct {
    layout: Layout,
    /// Used to ensure reads and writes occur on separate shards.
    /// Atomic representation of `ShardSync`.
    shard_sync: *std.atomic.Value(u64),
    /// One hot shard for writing, one cold shard for reading.
    shards: [2]Shard,

    /// A windowed Prometheus native histogram: geometric (log-exponential) buckets aligned 1:1 with a
    /// native-histogram `schema`. Bucket `i`'s upper bound is `2^((base_index + i) / 2^schema)` ns,
    /// where `base_index = baseIndex()`; there are `2^schema` buckets per power-of-two octave.
    ///
    /// `min_ns`/`octaves` bound the fixed storage window — native histograms are unbounded/sparse,
    /// but the IPC region is dense/fixed. Observations below the window clamp into bucket 0; those
    /// above it land in the implicit `+Inf` bucket (counted, but in no explicit bucket).
    pub const Layout = struct {
        /// Native histogram schema `n`; buckets per octave = `2^n`. Valid range 0..8.
        schema: u4,
        /// Lower window edge in ns; storage bucket 0 has global native index `baseIndex()`.
        min_ns: u64,
        /// Number of power-of-two octaves of range; `bucketCount = octaves << schema`.
        octaves: u64,

        /// Number of leading `u64` words (at `Detail.index`) encoding `layout` — `[schema, min_ns,
        /// octaves]` — before the `Raw` shard elements.
        pub const header_words: u32 = 3;

        pub fn initFromHeader(src: []const u64) Layout {
            std.debug.assert(src.len == header_words);
            return .{
                .schema = @intCast(src[0]),
                .min_ns = src[1],
                .octaves = src[2],
            };
        }

        /// Serialize `layout` into a `header_words`-length region header.
        pub fn writeHeader(self: Layout, dst: []u64) void {
            std.debug.assert(dst.len == header_words);
            dst[0] = self.schema;
            dst[1] = self.min_ns;
            dst[2] = self.octaves;
        }

        pub fn comptimeValidate(comptime self: Layout) void {
            if (self.octaves == 0) @compileError("Layout requires at least one octave");
            if (self.schema > 8) @compileError("Layout schema must be in 0..8");
            if (self.min_ns == 0) @compileError("Layout requires min_ns > 0");
            // The top bucket's bound is ~`min_ns << octaves` (one native octave == one power-of-two
            // octave); keep the shift in range and the bound within u64.
            if (self.octaves >= 64 or self.min_ns > std.math.maxInt(u64) >> self.octaves)
                @compileError("bucket bounds overflow u64: reduce octaves or min_ns");
        }

        pub fn bucketCount(self: Layout) u64 {
            return @intCast(self.octaves << @as(u6, self.schema));
        }

        pub fn elementsFromBucketCount(self: Layout) u32 {
            return @intCast(1 + 2 * (2 + self.bucketCount()));
        }

        /// Global native bucket index of storage bucket 0; storage bucket `i` has global index
        /// `baseIndex() + i`. This is the `sint32` `positive_span` offset in the native histogram.
        pub fn baseIndex(self: Layout) i64 {
            return nativeBucketIndex(self.schema, self.min_ns);
        }

        /// The inclusive `le` upper bound (in ns) for bucket `index`, rounded to an integer:
        /// `2^((base_index + index) / 2^schema)`. Used only by the classic (text) render path; the
        /// native protobuf path uses bucket indices directly via `baseIndex`.
        pub fn upperBoundNs(self: Layout, index: usize) u64 {
            const gi = self.baseIndex() + @as(i64, @intCast(index));
            const per_octave: f64 = @floatFromInt(@as(u64, 1) << @as(u6, self.schema));
            const bound = std.math.exp2(@as(f64, @floatFromInt(gi)) / per_octave);
            return @intFromFloat(@round(bound));
        }
    };

    const ShardSync = Histogram.ShardSync;

    pub const Shard = struct {
        /// Total of all observed values, in nanoseconds.
        sum: *std.atomic.Value(u64),
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

    /// A raw view of a latency histogram's shard storage: `[shard_sync][shard0][shard1]`.
    /// Unlike `Histogram.Raw`, no bounds are stored — they are derived from the `Layout`.
    pub const Raw = struct {
        elements: []u64,

        /// XXX: Not an atomic operation. Zeroes `shard_sync` and both shards.
        pub fn init(self: Raw) void {
            self.shardSync().* = .init(0);
            for (&self.shards()) |shard| shard.initZeroes();
        }

        pub fn shardSync(self: Raw) *std.atomic.Value(u64) {
            return @ptrCast(&self.elements[0]);
        }

        pub fn shards(self: Raw) [2]Shard {
            const rest = self.elements[1..]; // everything after shard_sync
            const half = @divExact(rest.len, 2);
            const shard0: Shard = .fromElements(rest[0..half]);
            const shard1: Shard = .fromElements(rest[half..]);
            std.debug.assert(shard0.buckets.len == shard1.buckets.len);
            return .{ shard0, shard1 };
        }
    };

    pub fn fromRaw(layout: Layout, raw: Raw) LatencyHistogram {
        return .{
            .layout = layout,
            .shard_sync = raw.shardSync(),
            .shards = raw.shards(),
        };
    }

    fn bucketIndex(self: *const LatencyHistogram, ns: u64) usize {
        // Global native index minus the window base; values below the window floor into bucket 0,
        // values above the top land in the implicit `+Inf` bucket via `observe`'s `index <
        // buckets.len` guard.
        if (ns == 0) return 0;
        const local = nativeBucketIndex(self.layout.schema, ns) - self.layout.baseIndex();
        return if (local < 0) 0 else @intCast(local);
    }

    /// Writes an observed latency (in nanoseconds) into the histogram.
    pub fn observe(self: *const LatencyHistogram, ns: u64) void {
        const shard_sync: ShardSync = @bitCast(self.shard_sync.fetchAdd(1, .acquire)); // acquires lock; must be first
        const shard = &self.shards[shard_sync.shard];
        const index = self.bucketIndex(ns);
        // A value above every bucket bound lands in the implicit `+Inf` bucket: it still
        // contributes to `sum`/`count` but to no explicit bucket (matches `Histogram.observe`).
        if (index < shard.buckets.len) {
            _ = shard.buckets[index].fetchAdd(1, .monotonic);
        }
        _ = shard.sum.fetchAdd(ns, .monotonic);
        _ = shard.count.fetchAdd(1, .release); // releases lock; must be last
    }

    /// Starts a span timer that records its elapsed nanoseconds into this histogram. Call
    /// `.observe()` on the result at the end of the span, usually with `defer` (see the `defer`
    /// caveat on `LatencyObserver` first). The bounds come from the `Layout` and are already in
    /// nanoseconds.
    pub fn observer(self: *const LatencyHistogram) LatencyObserver(.latency, null) {
        return .init(self);
    }

    /// Makes the hot shard cold and vice versa, returning the pre-swap `shard_sync`.
    fn flipShard(
        self: *const LatencyHistogram,
        comptime ordering: std.builtin.AtomicOrder,
    ) ShardSync {
        const shard_sync: ShardSync = .{ .shard = 1 };
        const data = self.shard_sync.fetchAdd(@bitCast(shard_sync), ordering);
        return @bitCast(data);
    }

    /// Swaps the hot and cold shards, then returns a reader over a consistent snapshot of the
    /// now-cold shard. Mirrors `LatencyHistogram.swapOutSnapshot`.
    pub fn swapOutSnapshot(self: *const LatencyHistogram) SnapshotReader {
        // Make the hot shard cold. Some writers may still be writing to it, but no new ones will.
        const shard_sync = self.flipShard(.acq_rel);
        const cold_shard = &self.shards[shard_sync.shard];
        const hot_shard = &self.shards[shard_sync.shard +% 1];

        // Wait until in-flight writers finish draining into the now-cold shard.
        while (true) {
            const current_cold_count = cold_shard.count.load(.acquire);
            if (current_cold_count == shard_sync.count) {
                cold_shard.count.store(0, .monotonic);
                break;
            }
            std.debug.assert(current_cold_count < shard_sync.count);
        }

        const cold_shard_sum = cold_shard.sum.load(.monotonic);
        cold_shard.sum.store(0, .monotonic);

        return .{
            .count = shard_sync.count,
            .sum = cold_shard_sum,

            .layout = self.layout,
            .cold_shard_buckets = cold_shard.buckets,
            .hot_shard_buckets = hot_shard.buckets,
            .hot_shard = hot_shard,

            .current_cumulative_count = 0,
            .current_bucket_index = 0,
        };
    }

    /// Iterates a cold-shard snapshot as cumulative prometheus buckets, folding each bucket back
    /// into the hot shard as it goes. Mirrors `LatencyHistogram.SnapshotReader`, except bucket
    /// bounds are derived from `layout` via `upperBoundNs` rather than a stored slice.
    pub const SnapshotReader = struct {
        /// Total number of events observed by the histogram.
        count: u63,
        /// Sum of all values observed by the histogram, in nanoseconds.
        sum: u64,

        // internal references
        layout: Layout,
        cold_shard_buckets: []std.atomic.Value(u64),
        /// See the NOTE on `LatencyHistogram.SnapshotReader.hot_shard_buckets`.
        hot_shard_buckets: []std.atomic.Value(u64),
        hot_shard: *const Shard,

        // mutable state
        current_cumulative_count: u64,
        current_bucket_index: usize,

        pub const Bucket = struct {
            upper_bound: u64,
            cumulative_count: u64,
        };

        pub fn finished(self: *const SnapshotReader) bool {
            std.debug.assert(self.cold_shard_buckets.len == self.hot_shard.buckets.len);
            return self.current_bucket_index == self.cold_shard_buckets.len;
        }

        /// Release the snapshot reader, ignoring any unobserved buckets.
        pub fn release(self: *SnapshotReader) void {
            if (self.finished()) return;
            while (self.nextBucket()) |_| {}
        }

        /// After this returns `null`, the cold shard is fully reset and everything pending in it
        /// has been aggregated back into the hot shard.
        pub fn nextBucket(self: *SnapshotReader) ?Bucket {
            if (self.finished()) {
                _ = self.hot_shard.sum.fetchAdd(self.sum, .monotonic);
                _ = self.hot_shard.count.fetchAdd(self.count, .monotonic);
                return null;
            }
            defer self.current_bucket_index += 1;

            const upper_bound = self.layout.upperBoundNs(self.current_bucket_index);
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

    /// Used to initialize a latency histogram in-place, backed by a heap allocation.
    pub fn initForTest(
        gpa: std.mem.Allocator,
        layout: Layout,
    ) std.mem.Allocator.Error!LatencyHistogram {
        const raw: Raw = .{ .elements = try gpa.alloc(u64, layout.elementsFromBucketCount()) };
        raw.init();
        return .fromRaw(layout, raw);
    }

    /// Only valid if `self` was initialized using `initForTest`.
    pub fn deinitForTest(self: LatencyHistogram, gpa: std.mem.Allocator) void {
        const element_count = self.layout.elementsFromBucketCount();
        const elements: []const u64 = @as(
            [*]const u64,
            @ptrCast(self.shard_sync),
        )[0..element_count];
        gpa.free(elements);
    }

    pub fn testExpectBuckets(
        self: LatencyHistogram,
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
            SnapshotReader.Bucket,
            expected_buckets,
            actual_buckets.items,
        );
        try std.testing.expectEqual(expected_count, snap.count);
    }
};

/// One `Hist` per variant of `V`, held in a fixed inline array indexed by `EnumIndexer`, so each
/// tag records into its own distribution through a direct index rather than a map lookup. `V` may
/// be an enum, a tagged union (its tag type is used), or an error set: `Tag` is what `observe`
/// takes, and `Enum` is the `FieldEnum` assigning each variant its array slot in declaration order.
///
/// The histogram analogue of `Variant`, and intended to be exposed the same way: one metric name
/// (e.g. `method_elapsed_seconds`) carrying a series per tag under a `variant="<tag>"` label, so
/// variants can be summed together or filtered apart in Prometheus/Grafana. `kind` selects the
/// backing histogram: `.latency` for ns-native `LatencyHistogram`, `.standard` for `Histogram`
/// with explicit bounds. Every variant shares one `Kind`, so the series aggregate cleanly; the
/// bucket layout itself is still supplied once by the appender.
pub fn VariantHistogram(comptime V: type, comptime kind: metric.HistogramKind) type {
    const Hist = kind.StructType();
    return struct {
        histograms: [Indexer.count]Hist,
        const VariantHistogramSelf = @This();

        pub const Value = V;
        pub const Enum = std.meta.FieldEnum(Value);
        pub const Tag = switch (@typeInfo(Value)) {
            .@"enum" => Value,
            .@"union" => |u_info| u_info.tag_type.?,
            .error_set => Value,
            else => @compileError("Unsupported: " ++ @typeName(Value)),
        };

        pub const Indexer = std.enums.EnumIndexer(Enum);

        /// Records an observed value into the histogram for `tag`. For a `LatencyHistogram` the
        /// value is a latency in nanoseconds; for a `Histogram` it is a raw observation.
        pub fn observe(self: *const VariantHistogramSelf, comptime tag: Tag, value: anytype) void {
            self.get(tag).observe(value);
        }

        /// Starts a span timer that records its elapsed nanoseconds into the histogram for whichever
        /// tag `.observe(tag)` is given at the end of the span, usually with `defer`. For
        /// `kind == .standard` the registered `upper_bounds` must be in nanoseconds; see the unit
        /// contract on `LatencyObserver`.
        pub fn observer(self: *const VariantHistogramSelf) LatencyObserver(kind, Value) {
            return .init(self);
        }

        /// Returns the individual `Hist` handle registered for `tag`, for operations beyond
        /// `observe` (e.g. snapshotting a single variant's distribution). `Hist` is a handle of
        /// pointers into the shared region, so the returned copy writes to the same counters.
        pub fn get(self: *const VariantHistogramSelf, comptime tag: Tag) Hist {
            const enum_tag = switch (@typeInfo(Value)) {
                .@"enum" => if (Enum == Value) tag else switch (tag) {
                    inline else => |itag| @field(Enum, @tagName(itag)),
                },
                .@"union" => |u_info| if (Enum == u_info.tag_type) tag else switch (tag) {
                    inline else => |_, itag| @field(Enum, @tagName(itag)),
                },
                .error_set => switch (tag) {
                    inline else => |t| @field(Enum, @errorName(t)),
                },
                else => @compileError("Unsupported: " ++ @typeName(Value)),
            };
            return self.histograms[Indexer.indexOf(enum_tag)];
        }
    };
}

/// A timer for one span. `init` reads the monotonic clock; `observe` reads it again and records the
/// elapsed nanoseconds into the histogram.
///
/// `V` selects the shape. `null` gives a plain `Histogram` or `LatencyHistogram` and an `observe()`
/// taking no argument. A `VariantHistogram`'s value type gives `observe(tag)`, which selects the
/// series at the end of the span, after an outcome such as an error tag is known. `tag` must be
/// comptime-known; dispatch a runtime one with
/// `switch (tag) { inline else => |t| obs.observe(t) }`.
///
/// The recorded value is always in nanoseconds, so the histogram's bounds must be in nanoseconds
/// too. A `LatencyHistogram` derives its bounds from a `Layout`, which already is. A
/// `kind == .standard` histogram uses whatever `upper_bounds` it was registered with. Nothing
/// checks the unit, and bounds in another unit mislabel every bucket.
///
/// Holds a pointer to the histogram handle, which the caller must keep alive. Call `observe` once
/// per observer: it does not stop or reset the timer, so a second call records a second span.
///
/// `defer obs.observe()` records on every exit from the enclosing scope, including `break`,
/// `continue`, and error returns — there is no way to disarm an observer. Only use it where every
/// exit ends a span worth recording. A scope that can leave without completing one, such as a drain
/// loop that breaks on `error.WouldBlock`, must instead call `observe` on the success path; a
/// `defer` there records the failed operation as if it had succeeded.
pub fn LatencyObserver(comptime kind: metric.HistogramKind, comptime V: ?type) type {
    // `V` is the variant histogram's value type, not its `Tag`. The two differ for a tagged union,
    // whose `Tag` is the union's tag type, so reconstructing from `Tag` would name a different
    // `VariantHistogram` instantiation than the caller holds.
    const Hist = if (V) |v| VariantHistogram(v, kind) else kind.StructType();
    return struct {
        hist: *const Hist,
        start_ns: u64,

        const LatencyObserverSelf = @This();

        pub fn init(hist: *const Hist) LatencyObserverSelf {
            return .{
                .hist = hist,
                .start_ns = clock.monotonic(.ns),
            };
        }

        /// Nanoseconds elapsed since construction. Reads the clock once;
        /// saturating so a non-monotonic clock can never underflow.
        pub fn elapsedNs(self: LatencyObserverSelf) u64 {
            return clock.monotonic(.ns) -| self.start_ns;
        }

        /// Records the elapsed span, in nanoseconds. Takes no argument for a plain histogram, and a
        /// tag for a variant histogram. Call it once per observer; see `LatencyObserver`.
        pub const observe = if (V != null) observeTagged else observePlain;

        fn observeTagged(self: LatencyObserverSelf, comptime tag: Hist.Tag) void {
            self.hist.observe(tag, self.elapsedNs());
        }

        fn observePlain(self: LatencyObserverSelf) void {
            self.hist.observe(self.elapsedNs());
        }
    };
}

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

test "latency histogram: layout header round-trips" {
    const Layout = LatencyHistogram.Layout;
    const cases = [_]Layout{
        .{ .schema = 2, .min_ns = 512, .octaves = 12 },
        .{ .schema = 0, .min_ns = 64, .octaves = 10 },
        .{ .schema = 8, .min_ns = 1_000, .octaves = 4 },
    };
    for (cases) |layout| {
        var header: [Layout.header_words]u64 = undefined;
        layout.writeHeader(&header);
        try std.testing.expectEqual(layout, Layout.initFromHeader(&header));
    }
}

test "latency histogram: comptimeValidate accepts well-formed layouts" {
    const Layout = LatencyHistogram.Layout;
    Layout.comptimeValidate(.{ .schema = 2, .min_ns = 512, .octaves = 12 });
    Layout.comptimeValidate(.{ .schema = 0, .min_ns = 1, .octaves = 8 });
    Layout.comptimeValidate(.{ .schema = 8, .min_ns = 1_000, .octaves = 4 });
}

test "latency histogram: geometric bounds and base index" {
    const Layout = LatencyHistogram.Layout;
    // schema 2 (4 buckets/octave), window anchored at 512ns == native index 36. Bounds are
    // `2^((36 + i) / 4)` rounded: 512, 609, 724, 861, 1024, 1218, 1448, 1722.
    const layout: Layout = .{ .schema = 2, .min_ns = 512, .octaves = 2 };
    const want = [_]u64{ 512, 609, 724, 861, 1024, 1218, 1448, 1722 };
    for (want, 0..) |bound, i| try std.testing.expectEqual(bound, layout.upperBoundNs(i));

    // Storage bucket 0 is native index 36 (== 2^schema * log2(512), exact since 512 is a power of 2);
    // this is the `positive_span` offset the protobuf encoder emits.
    try std.testing.expectEqual(@as(i64, 36), layout.baseIndex());
    try std.testing.expectEqual(@as(u64, 8), layout.bucketCount());
}

test "latency histogram: bins geometrically" {
    const gpa = std.testing.allocator;
    const Layout = LatencyHistogram.Layout;

    // schema 2, min_ns 512, 2 octaves -> 8 buckets. Octave boundaries (512, 1024) exercise the
    // fp-safe `frexp` binning; 513/700 are mid-octave; 2000 overflows into the implicit `+Inf`.
    const layout: Layout = .{ .schema = 2, .min_ns = 512, .octaves = 2 };
    const hist: LatencyHistogram = try .initForTest(gpa, layout);
    defer hist.deinitForTest(gpa);

    hist.observe(512); // bucket 0 (le=512, inclusive octave boundary)
    hist.observe(513); // bucket 1 (le=609)
    hist.observe(700); // bucket 2 (le=724)
    hist.observe(1024); // bucket 4 (le=1024, inclusive octave boundary)
    hist.observe(2000); // +Inf

    try hist.testExpectBuckets(5, &.{
        .{ .upper_bound = 512, .cumulative_count = 1 },
        .{ .upper_bound = 609, .cumulative_count = 2 },
        .{ .upper_bound = 724, .cumulative_count = 3 },
        .{ .upper_bound = 861, .cumulative_count = 3 },
        .{ .upper_bound = 1024, .cumulative_count = 4 },
        .{ .upper_bound = 1218, .cumulative_count = 4 },
        .{ .upper_bound = 1448, .cumulative_count = 4 },
        .{ .upper_bound = 1722, .cumulative_count = 4 },
    });
}

test "latency histogram: values accumulate across snapshots" {
    const gpa = std.testing.allocator;
    const Layout = LatencyHistogram.Layout;

    const layout: Layout = .{ .schema = 2, .min_ns = 512, .octaves = 2 };
    const hist: LatencyHistogram = try .initForTest(gpa, layout);
    defer hist.deinitForTest(gpa);

    hist.observe(512); // bucket 0
    hist.observe(513); // bucket 1
    try hist.testExpectBuckets(2, &.{
        .{ .upper_bound = 512, .cumulative_count = 1 },
        .{ .upper_bound = 609, .cumulative_count = 2 },
        .{ .upper_bound = 724, .cumulative_count = 2 },
        .{ .upper_bound = 861, .cumulative_count = 2 },
        .{ .upper_bound = 1024, .cumulative_count = 2 },
        .{ .upper_bound = 1218, .cumulative_count = 2 },
        .{ .upper_bound = 1448, .cumulative_count = 2 },
        .{ .upper_bound = 1722, .cumulative_count = 2 },
    });

    // The prior snapshot folds its counts back into the hot shard, so totals accumulate.
    hist.observe(512); // bucket 0
    try hist.testExpectBuckets(3, &.{
        .{ .upper_bound = 512, .cumulative_count = 2 },
        .{ .upper_bound = 609, .cumulative_count = 3 },
        .{ .upper_bound = 724, .cumulative_count = 3 },
        .{ .upper_bound = 861, .cumulative_count = 3 },
        .{ .upper_bound = 1024, .cumulative_count = 3 },
        .{ .upper_bound = 1218, .cumulative_count = 3 },
        .{ .upper_bound = 1448, .cumulative_count = 3 },
        .{ .upper_bound = 1722, .cumulative_count = 3 },
    });
}

test "latency histogram: values below the window floor into bucket 0" {
    const gpa = std.testing.allocator;
    const Layout = LatencyHistogram.Layout;

    const layout: Layout = .{ .schema = 2, .min_ns = 512, .octaves = 2 };
    const hist: LatencyHistogram = try .initForTest(gpa, layout);
    defer hist.deinitForTest(gpa);

    hist.observe(0); // clamps to bucket 0
    hist.observe(1); // below window -> bucket 0
    hist.observe(100); // below window -> bucket 0

    try hist.testExpectBuckets(3, &.{
        .{ .upper_bound = 512, .cumulative_count = 3 },
        .{ .upper_bound = 609, .cumulative_count = 3 },
        .{ .upper_bound = 724, .cumulative_count = 3 },
        .{ .upper_bound = 861, .cumulative_count = 3 },
        .{ .upper_bound = 1024, .cumulative_count = 3 },
        .{ .upper_bound = 1218, .cumulative_count = 3 },
        .{ .upper_bound = 1448, .cumulative_count = 3 },
        .{ .upper_bound = 1722, .cumulative_count = 3 },
    });
}

// A window of 512ns .. ~537ms. Wide enough that a measured span lands in an explicit bucket rather
// than the implicit `+Inf` one.
const observer_test_layout: LatencyHistogram.Layout = .{
    .schema = 2,
    .min_ns = 512,
    .octaves = 20,
};

// Bounds for the `.standard` observer tests, in nanoseconds per the contract on
// `VariantHistogram.observer`. The 1s top bound is above any span these tests measure.
const observer_test_bounds: []const f64 = &.{
    1 * std.time.ns_per_us,
    1 * std.time.ns_per_ms,
    1 * std.time.ns_per_s,
};

/// Builds a `VariantHistogram` without a metric region. The observer only needs the `Hist` handles,
/// and registration is covered by the `variant histogram` tests in `metric.zig`.
fn initVariantForTest(
    comptime V: type,
    comptime kind: metric.HistogramKind,
    gpa: std.mem.Allocator,
    config: kind.ConfigType(),
) std.mem.Allocator.Error!VariantHistogram(V, kind) {
    var vh: VariantHistogram(V, kind) = undefined;
    var initialized: usize = 0;
    errdefer for (vh.histograms[0..initialized]) |h| h.deinitForTest(gpa);
    for (&vh.histograms) |*h| {
        h.* = try .initForTest(gpa, config);
        initialized += 1;
    }
    return vh;
}

/// Frees a `VariantHistogram` built by `initVariantForTest`.
fn deinitVariantForTest(vh: anytype, gpa: std.mem.Allocator) void {
    for (vh.histograms) |h| h.deinitForTest(gpa);
}

test "latency observer: observe records the elapsed span" {
    const gpa = std.testing.allocator;

    const hist: LatencyHistogram = try .initForTest(gpa, observer_test_layout);
    defer hist.deinitForTest(gpa);

    const obs = hist.observer();

    // `elapsedNs` reads the clock but records nothing, so the histogram is still empty.
    const early = obs.elapsedNs();
    try std.testing.expect(obs.elapsedNs() >= early);
    {
        var empty = hist.swapOutSnapshot();
        defer empty.release();
        try std.testing.expectEqual(@as(u63, 0), empty.count);
    }

    // A second `observe` is not a no-op. It records a second span from the same start.
    obs.observe();
    obs.observe();

    var snap = hist.swapOutSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(u63, 2), snap.count);
    // Both spans were still running when `early` was read, so each is at least that long.
    try std.testing.expect(snap.sum >= 2 * early);
}

test "latency observer: tagged spans record into their own variant" {
    const gpa = std.testing.allocator;
    const Method = enum { get, put, delete };

    const vh = try initVariantForTest(Method, .latency, gpa, observer_test_layout);
    defer deinitVariantForTest(vh, gpa);

    vh.observer().observe(.get);
    vh.observer().observe(.get);
    vh.observer().observe(.put);

    inline for (.{ .{ Method.get, 2 }, .{ Method.put, 1 }, .{ Method.delete, 0 } }) |case| {
        var snap = vh.get(case[0]).swapOutSnapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(u63, case[1]), snap.count);
    }
}

test "latency observer: a runtime tag dispatches through an inline switch" {
    const gpa = std.testing.allocator;
    const Outcome = enum { ok, err };

    const vh = try initVariantForTest(Outcome, .latency, gpa, observer_test_layout);
    defer deinitVariantForTest(vh, gpa);

    // Start the timer before the outcome is known, then select the variant at the end. `observe`
    // takes a comptime tag, so a runtime one is dispatched with `inline else`.
    const obs = vh.observer();
    var outcome: Outcome = .err;
    _ = &outcome; // keep `outcome` runtime-known
    switch (outcome) {
        inline else => |tag| obs.observe(tag),
    }

    inline for (.{ .{ Outcome.ok, 0 }, .{ Outcome.err, 1 } }) |case| {
        var snap = vh.get(case[0]).swapOutSnapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(u63, case[1]), snap.count);
    }
}

test "latency observer: a tagged union selects the variant by its tag type" {
    const gpa = std.testing.allocator;
    // Covers the union case of the value-type rule noted on `LatencyObserver`.
    const Event = union(enum) { get: u32, put: []const u8, delete: void };
    const Tag = std.meta.Tag(Event);

    const vh = try initVariantForTest(Event, .latency, gpa, observer_test_layout);
    defer deinitVariantForTest(vh, gpa);

    vh.observer().observe(.get);
    vh.observer().observe(.delete);

    inline for (.{ .{ Tag.get, 1 }, .{ Tag.put, 0 }, .{ Tag.delete, 1 } }) |case| {
        var snap = vh.get(case[0]).swapOutSnapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(u63, case[1]), snap.count);
    }
}

test "latency observer: a standard-kind variant records ns into its explicit bounds" {
    const gpa = std.testing.allocator;
    const Outcome = enum { ok, err };

    const vh = try initVariantForTest(Outcome, .standard, gpa, observer_test_bounds);
    defer deinitVariantForTest(vh, gpa);

    // `Histogram` is unit-agnostic, but the span still arrives as a nanosecond count through
    // `observe`'s int to f64 conversion. Two `elapsedNs` reads bracket the recorded value.
    const obs = vh.observer();
    const before = obs.elapsedNs();
    obs.observe(.ok);
    const after = obs.elapsedNs();

    var snap = vh.get(.ok).swapOutSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(u63, 1), snap.count);
    try std.testing.expect(snap.sum >= @as(f64, @floatFromInt(before)));
    try std.testing.expect(snap.sum <= @as(f64, @floatFromInt(after)));

    // The bounds are in nanoseconds, so the span lands in an explicit bucket rather than the
    // implicit `+Inf` one, and the final cumulative count includes it.
    var last_cumulative: u64 = 0;
    while (snap.nextBucket()) |bucket| last_cumulative = bucket.cumulative_count;
    try std.testing.expectEqual(@as(u64, 1), last_cumulative);

    var untouched = vh.get(.err).swapOutSnapshot();
    defer untouched.release();
    try std.testing.expectEqual(@as(u63, 0), untouched.count);
}

test "latency observer: a plain histogram observes through the same ns contract" {
    const gpa = std.testing.allocator;

    const hist: Histogram = try .initForTest(gpa, observer_test_bounds);
    defer hist.deinitForTest(gpa);

    const obs = hist.observer();
    const before = obs.elapsedNs();
    obs.observe();
    const after = obs.elapsedNs();

    var snap = hist.swapOutSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(u63, 1), snap.count);
    try std.testing.expect(snap.sum >= @as(f64, @floatFromInt(before)));
    try std.testing.expect(snap.sum <= @as(f64, @floatFromInt(after)));
}
