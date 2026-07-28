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
    /// then be in nanoseconds; see the unit contract on `LatencyObserver`.
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

/// Largest `schema` the tables below are built for. `Layout.schema()` is `log2` of
/// `bounds_per_doubling`, which validation caps at 256, so no layout reaches past this.
const max_schema: u4 = 8;

/// Prometheus native-histogram bucket boundaries within one mantissa octave for a given `schema`:
/// `bounds[k] = 0.5 * 2^(k / 2^schema)` for `k in 0..2^schema`. Used to bin the `frexp` fraction
/// (which lies in `[0.5, 1)`) into a sub-octave bucket.
fn nativeBoundsTable(comptime schema: u4) [@as(usize, 1) << schema]f64 {
    // Two comptime backwards branches per entry: the loop iteration, and one inside `exp2`. The
    // count accumulates across a whole evaluation and the `inline` switches below build every
    // table in one, so budget for all of them: `sum(2^s for s in 0...max_schema)` entries, times
    // 2 branches, times 4 for slack.
    @setEvalBranchQuota(8 * ((@as(u32, 2) << max_schema) - 1));
    var arr: [@as(usize, 1) << schema]f64 = undefined;
    const per_octave: f64 = @floatFromInt(@as(u64, 1) << schema);
    inline for (&arr, 0..) |*b, k| {
        b.* = 0.5 * std.math.exp2(@as(f64, @floatFromInt(k)) / per_octave);
    }
    return arr;
}

/// Smallest index `k` with `bounds[k] >= frac` (like Go's `sort.SearchFloat64s`), in `0..len`.
///
/// `len` is always `2^schema`, so the range halves cleanly and the search unrolls to a fixed
/// `log2(len) + 1` compares — the same count the loop form needs — with each comparison folded into
/// `base` as an integer rather than a jump. That leaves no branches at all, not just no
/// data-dependent ones. Relies on `bounds` being sorted, which `nativeBoundsTable` builds it to be.
fn searchFloat(comptime len: usize, bounds: *const [len]f64, frac: f64) i64 {
    comptime std.debug.assert(std.math.isPowerOfTwo(len));
    var base: usize = 0;
    inline for (0..comptime std.math.log2_int(usize, len)) |i| {
        const half = len >> @intCast(1 + i);
        base += half * @intFromBool(bounds[base + half - 1] < frac);
    }
    // A NaN `frac` makes every compare false and lands on 0, matching the loop form.
    return @intCast(base + @intFromBool(bounds[base] < frac));
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
        inline 0...max_schema => |sc| blk: {
            const table = comptime nativeBoundsTable(sc);
            break :blk searchFloat(table.len, &table, r.significand);
        },
        else => unreachable,
    };
    return (@as(i64, r.exponent) - 1) * per_octave + s;
}

/// The inclusive upper bound of global native bucket `index` at `schema`: `2^(index / 2^schema)`.
/// Built by splitting `index` into an octave and a sub-octave remainder and reading the same table
/// `nativeBucketIndex` bins against, rather than by `exp2`-ing the quotient, which makes the two
/// exact inverses: `nativeBucketIndex(schema, nativeBound(schema, i)) == i`. A bound derived any
/// other way can land a ulp off and rounding it would name a value in the neighbouring bucket.
fn nativeBound(schema: u4, index: i64) f64 {
    const per_octave: i64 = @as(i64, 1) << @as(u6, schema);
    // Floor division, so a negative `index` (a bound below 1ns) splits the same way as a positive
    // one; `rem` is then always in `0..per_octave`.
    const octave = @divFloor(index, per_octave);
    const rem: usize = @intCast(index - octave * per_octave);
    const frac: f64 = switch (schema) {
        inline 0...max_schema => |sc| blk: {
            const table = comptime nativeBoundsTable(sc);
            break :blk table[rem];
        },
        else => unreachable,
    };
    // `table` holds `0.5 * 2^(rem / 2^schema)`, i.e. the bound already halved into `frexp`'s
    // `[0.5, 1)`, hence the `+ 1` on the exponent.
    return std.math.ldexp(frac, @intCast(octave + 1));
}

pub const LatencyHistogram = struct {
    layout: Layout,
    /// `layout.baseIndex()`, resolved once here rather than per observation. It is a pure function
    /// of `layout` and so never changes, but computing it is a full `nativeBucketIndex` — a `frexp`
    /// and a table search — which `bucketIndex` would otherwise repeat on every `observe`.
    base_index: i64,
    /// Used to ensure reads and writes occur on separate shards.
    /// Atomic representation of `ShardSync`.
    shard_sync: *std.atomic.Value(u64),
    /// One hot shard for writing, one cold shard for reading.
    shards: [2]Shard,

    /// A windowed histogram with geometric (log-exponential) bucket bounds. Bucket `i`'s upper
    /// bound is `2^((base_index + i) / bounds_per_doubling)` ns, where `base_index = baseIndex()`.
    ///
    /// Two expositions render the same storage, and the bounds being geometric is what lets one
    /// layout serve both:
    ///
    /// * **Protobuf** — a standard exponential *native* histogram. The bounds sit on a native
    ///   schema ladder by construction, so `schema()` names the ladder and each bucket crosses as
    ///   a span offset off `baseIndex()` rather than as a bound. This is what production reads:
    ///   a Prometheus server with `scrape_native_histograms` negotiates protobuf, and ours is
    ///   configured for it. See `telemetry/prometheus_proto.zig`.
    /// * **Text** — a classic histogram, one `le` line per resolved bound plus `+Inf`, for humans
    ///   `curl`ing the endpoint and for scrapers that do not negotiate protobuf. See
    ///   `telemetry/prometheus.zig`.
    ///
    /// The window is fixed, so something has to hold the tail above it. Classic has `le="+Inf"`
    /// for that, which Prometheus derives from `sample_count`; an exponential schema has no
    /// equivalent, because it derives every bound from a bucket index and so defines no open-ended
    /// bucket short of `MaxFloat64`. Rather than depend on a form only one encoding offers, the
    /// tail is held by a real bucket: `bucketCount` allocates one rung above `max_upper_bound_ns`
    /// and `observe` saturates into it. `count == Σ buckets` then holds by construction, which is
    /// the invariant a native scrape is rejected for breaking, and the tail is capped rather than
    /// dropped — see `max_upper_bound_ns` for what that costs.
    ///
    /// That cap is the native path's price, not a property of the data. The text path skips the
    /// saturating bucket and lets its own `+Inf` carry the tail uncapped — see
    /// `prometheus.writeLatencyHistogramBody`.
    ///
    /// One consequence worth respecting on the text path: Prometheus reads classic buckets by
    /// their `le` labels, so a bound that appeared only in the scrapes where something landed in
    /// it would look like a bucket layout that keeps changing. Every resolved bound is rendered
    /// every time, empty or not — see `prometheus.writeHistogramSnapshot`.
    ///
    /// Both endpoints are inclusive, so a `[512, 2048]` window at 4 bounds per doubling resolves
    /// `2 * 4 + 1` = 9 bounds, and stores a tenth to saturate into:
    ///
    ///     512, 608, 724, 861, 1024, 1217, 1448, 1722, 2048 | 2435
    pub const Layout = struct {
        /// The smallest upper bound in the histogram: bucket 0's. Every observation at or below it
        /// lands in bucket 0 — counted, but not resolved. That is exact rather than a clamp, and
        /// both expositions say so: a classic histogram's first bucket is `(-Inf, le]`, and on the
        /// native path bucket 0 crosses as the *zero bucket* `[-t, +t]` rather than as a ladder
        /// bucket with a lower edge (see `zeroThreshold`). A 1ns observation genuinely belongs to
        /// it either way. Rounds up to the nearest representable bound when it is not a power of
        /// two, taking `max_upper_bound_ns` up with it by the same factor; prefer a power of two
        /// so no rounding happens.
        min_upper_bound_ns: u64,
        /// The largest bound a value is resolved against. Must be `min_upper_bound_ns` times a
        /// power of two. Not a ceiling on what may be observed: larger values saturate into the
        /// bucket one rung above it, staying exact in `sum`/`count` but resolved no further than
        /// "above this". Set it where magnitude stops being worth knowing — every quantile past
        /// it reports the saturating bucket's bound, so crossing it is a signal, not a reading.
        max_upper_bound_ns: u64,
        /// How many upper bounds fall in each doubling — each `x` to `2x` range. Power of two in
        /// 1..256. Each bound is `2^(1 / bounds_per_doubling)` times the one below it: 4 leaves them
        /// 18.9% apart, 8 -> 9.1%, 16 -> 4.4%.
        bounds_per_doubling: u16 = 4,

        /// Backstop on the share of the fixed histogram region a single metric may claim. Not a
        /// budget — a layout anywhere near this is a typo, not a decision. At the ceiling one metric
        /// costs `header_words + 1 + 2 * (2 + 512)` = 1032 u64 words, ~8 KiB. It is also what bounds
        /// `bounds_per_doubling` against window width: the two trade directly, so at 256 bounds per
        /// doubling one doubling fits (257 buckets) and two do not (513).
        pub const max_bucket_count: u64 = 512;

        /// Hard ceiling on `max_upper_bound_ns`, and what keeps `upperBoundNs`'s `exp2` -> `u64`
        /// conversion in range, rounding included. 2^62 ns is ~146 years, so the limit binds on
        /// the arithmetic rather than on anything a latency metric could observe.
        const max_upper_bound_limit: u64 = 1 << 62;

        /// Number of leading `u64` words (at `Detail.index`) encoding `layout` —
        /// `[bounds_per_doubling, min_upper_bound_ns, max_upper_bound_ns]` — before the `Raw` shard
        /// elements.
        pub const header_words: u32 = 3;

        pub fn initFromHeader(src: []const u64) Layout {
            std.debug.assert(src.len == header_words);
            const layout: Layout = .{
                .bounds_per_doubling = @intCast(src[0]),
                .min_upper_bound_ns = src[1],
                .max_upper_bound_ns = src[2],
            };
            // Everything reaching here was written by `writeHeader` from a `comptimeValidate`-checked
            // layout, and `signalReady` orders that write ahead of any read. A torn or zeroed header
            // is the one bad layout no `comptime` can reach — these words cross a region boundary —
            // and it is worth catching here because a `bounds_per_doubling` that is not a power of
            // two fails silently: `@ctz` just reads it as a smaller schema. Every accessor below
            // assumes either these checks or `comptimeValidate` has run.
            std.debug.assert(layout.bounds_per_doubling != 0 and
                layout.bounds_per_doubling <= 256 and
                std.math.isPowerOfTwo(layout.bounds_per_doubling));
            std.debug.assert(layout.min_upper_bound_ns != 0);
            std.debug.assert(layout.max_upper_bound_ns > layout.min_upper_bound_ns);
            std.debug.assert(layout.max_upper_bound_ns <= max_upper_bound_limit);
            const ratio = layout.max_upper_bound_ns / layout.min_upper_bound_ns;
            std.debug.assert(ratio * layout.min_upper_bound_ns == layout.max_upper_bound_ns);
            std.debug.assert(std.math.isPowerOfTwo(ratio));
            return layout;
        }

        /// Serialize `layout` into a `header_words`-length region header.
        pub fn writeHeader(self: Layout, dst: []u64) void {
            std.debug.assert(dst.len == header_words);
            dst[0] = self.bounds_per_doubling;
            dst[1] = self.min_upper_bound_ns;
            dst[2] = self.max_upper_bound_ns;
        }

        /// Note the `@popCount`/`@clz` builtins throughout, and that the `Layout` helpers this leans
        /// on are `inline fn`: a plain call to a non-`inline` helper yields a runtime-known value
        /// even here, which would leave every `@compileError` branch live and fire them all
        /// unconditionally. The remaining `comptime` prefixes mark the calls into `std` and into
        /// `upperBoundNs`, which are not `inline`.
        pub fn comptimeValidate(comptime self: Layout) void {
            if (self.bounds_per_doubling == 0 or self.bounds_per_doubling > 256 or
                @popCount(self.bounds_per_doubling) != 1)
                @compileError(std.fmt.comptimePrint(
                    "Layout bounds_per_doubling must be a power of two in 1..256; got {d}.",
                    .{self.bounds_per_doubling},
                ));
            if (self.min_upper_bound_ns == 0)
                @compileError("Layout requires min_upper_bound_ns > 0");
            if (self.max_upper_bound_ns <= self.min_upper_bound_ns)
                @compileError(std.fmt.comptimePrint(
                    "Layout max_upper_bound_ns ({d}) must exceed min_upper_bound_ns ({d}).",
                    .{ self.max_upper_bound_ns, self.min_upper_bound_ns },
                ));
            if (self.max_upper_bound_ns > max_upper_bound_limit)
                @compileError(std.fmt.comptimePrint(
                    "Layout max_upper_bound_ns ({d}) must be <= {d}; see `max_upper_bound_limit`.",
                    .{ self.max_upper_bound_ns, max_upper_bound_limit },
                ));

            // A power-of-two ratio is what keeps every derived quantity in integer arithmetic, and
            // what makes it impossible to name a bound sitting a hair off a representable one.
            const ratio = self.max_upper_bound_ns / self.min_upper_bound_ns;
            if (ratio * self.min_upper_bound_ns != self.max_upper_bound_ns or
                @popCount(ratio) != 1)
            {
                // `ratio` floors to 1 for any `max` inside the first doubling, and `min` itself is
                // not a legal `max` — so the pair to name there is the first two rungs, not `min`.
                const lower: comptime_int = if (ratio < 2)
                    @as(comptime_int, self.min_upper_bound_ns) * 2
                else
                    @as(comptime_int, self.min_upper_bound_ns) << (63 - @clz(ratio));
                @compileError(std.fmt.comptimePrint(
                    "Layout max_upper_bound_ns must be min_upper_bound_ns ({d}) times a " ++
                        "power of two; {d} is not. Nearest legal values: {d} and {d}.",
                    .{ self.min_upper_bound_ns, self.max_upper_bound_ns, lower, lower * 2 },
                ));
            }

            const count = self.bucketCount();
            const words = header_words + self.elementsFromBucketCount();
            if (count > max_bucket_count) {
                // Spell out the product rather than just the total: the two factors are the two
                // knobs, and which one to turn is the whole question the error has to answer.
                const spans = self.doublings();
                // Widest ladder that still fits at this window width. `spans` is at most 62 and
                // the branch needs `spans * bounds_per_doubling >= 511`, so this never floors to 0.
                const fits = comptime std.math.floorPowerOfTwo(
                    u64,
                    (max_bucket_count - 2) / spans,
                );
                @compileError(std.fmt.comptimePrint(
                    "Layout resolves to {d} doublings x {d} bounds + 1, plus the saturating " ++
                        "bucket = {d} buckets ({d} u64 words), over the {d}-bucket ceiling. " ++
                        "Lower bounds_per_doubling to {d}, or narrow the window.",
                    .{ spans, self.bounds_per_doubling, count, words, max_bucket_count, fits },
                ));
            }

            // `upperBoundNs` rounds to an integer, so a ladder fine enough relative to its floor
            // rounds two adjacent bounds onto the same `le` — at `min = 1, bpd = 16` the first two
            // are 1 and 1.04, both emitted as `le="1"`. That would put two `_bucket` series with
            // the same `le` in one text-exposition histogram, which no consumer can read back as
            // two distinct buckets. Bounds are geometric so the gap only widens: checking the
            // first pair settles every pair.
            if (comptime self.upperBoundNs(1) <= self.upperBoundNs(0)) {
                // Smallest floor whose first gap survives rounding, at this resolution.
                const fits_min = comptime blk: {
                    var candidate: u64 = self.min_upper_bound_ns;
                    while (true) : (candidate *= 2) {
                        const probe: Layout = .{
                            .min_upper_bound_ns = candidate,
                            .max_upper_bound_ns = candidate * 2,
                            .bounds_per_doubling = self.bounds_per_doubling,
                        };
                        if (probe.upperBoundNs(1) > probe.upperBoundNs(0)) break :blk candidate;
                    }
                };
                @compileError(std.fmt.comptimePrint(
                    "Layout's first two bounds both round to {d}ns: {d} bounds per doubling is " ++
                        "finer than 1ns at a floor of {d}ns, so the `le` labels would collide. " ++
                        "Raise min_upper_bound_ns to {d}, or lower bounds_per_doubling.",
                    .{
                        self.upperBoundNs(0),    self.bounds_per_doubling,
                        self.min_upper_bound_ns, fits_min,
                    },
                ));
            }
        }

        /// The Prometheus native-histogram `schema` whose bucket ladder this layout's bounds sit
        /// on: `log2` of `bounds_per_doubling`. The protobuf exposition puts it on the wire as
        /// `Histogram.schema`; keeping the bounds schema-aligned is also what lets `bucketIndex`
        /// reuse `nativeBucketIndex`'s exact `frexp` binning instead of a `log2` that rounds badly.
        pub inline fn schema(self: Layout) u4 {
            return @intCast(@ctz(self.bounds_per_doubling));
        }

        /// Number of `x` -> `2x` ranges the window spans. Assumes an exact power-of-two ratio;
        /// `comptimeValidate` and `initFromHeader` are what prove it.
        inline fn doublings(self: Layout) u6 {
            return @intCast(@ctz(self.max_upper_bound_ns / self.min_upper_bound_ns));
        }

        /// Buckets that resolve a value, one per bound from `min_upper_bound_ns` to
        /// `max_upper_bound_ns`. Both endpoints are inclusive, hence the `+ 1`.
        pub inline fn resolvedBucketCount(self: Layout) u64 {
            return @as(u64, self.doublings()) * self.bounds_per_doubling + 1;
        }

        /// Every bucket in storage: the resolved ones plus the saturating bucket a rung above
        /// `max_upper_bound_ns`, which `observe` clamps larger values into. This is what sizes a
        /// shard, so it is also what `upperBoundNs` and the snapshot readers iterate over.
        pub inline fn bucketCount(self: Layout) u64 {
            return self.resolvedBucketCount() + 1;
        }

        pub inline fn elementsFromBucketCount(self: Layout) u32 {
            return @intCast(1 + 2 * (2 + self.bucketCount()));
        }

        /// Global native bucket index of storage bucket 0; storage bucket `i` has global index
        /// `baseIndex() + i`. Anchors both `bucketIndex` and `upperBoundNs` onto the `schema()`
        /// ladder, so a bound and the bin that value falls into are computed from the same table.
        pub fn baseIndex(self: Layout) i64 {
            return nativeBucketIndex(self.schema(), self.min_upper_bound_ns);
        }

        /// The native exposition's zero-bucket threshold: bucket 0's exact upper bound on the
        /// ladder, which is what makes the zero bucket `[-t, +t]` and the first positive bucket
        /// `(t, next]` tile with no gap or overlap.
        ///
        /// Neither of the two nearby values works here. `min_upper_bound_ns` is what the caller
        /// asked for, which `baseIndex` rounds *up* onto the ladder — a `min` of 1000 bins against
        /// 1024, so a threshold of 1000 would leave `(1000, 1024]` claimed by no bucket on the wire
        /// while `zero_count` holds those observations anyway. `upperBoundNs(0)` is that same bound
        /// floored to an integer `le` label, which leaves the sub-1ns remainder `(floor(b), b]`
        /// in the same position. The threshold is a `double` on the wire, so it can carry the
        /// boundary `bucketIndex` actually bins against, exactly.
        pub fn zeroThreshold(self: Layout) f64 {
            return nativeBound(self.schema(), self.baseIndex());
        }

        /// The inclusive `le` upper bound (in ns) for bucket `index`, rounded to an integer:
        /// `2^((base_index + index) / bounds_per_doubling)`. This is what the text exposition
        /// emits; the native path carries no bounds at all, deriving them from `schema` and the
        /// span offsets off `baseIndex`.
        ///
        /// `nativeBound` rather than `exp2(gi / bpd)` so the bound is the exact inverse of the
        /// `nativeBucketIndex` call in `bucketIndex`: a value landing on a boundary is binned into
        /// the bucket that names it, with no ulp-width disagreement between the two.
        ///
        /// Floored, not rounded, and that is load-bearing. Observations are whole nanoseconds, so
        /// for integer `v` and a real boundary `b`, `v <= b` exactly when `v <= floor(b)` — the
        /// floored bound is a faithful `le` label. Rounding up would put the label above the
        /// boundary it names, and an observation of exactly that value would bin one bucket higher
        /// than the label it was just promised. Both endpoints are powers of two, so they are
        /// exact either way; only interior bounds move (`2^(37/4)` is 608.87, so `le="608"`).
        fn upperBoundNs(self: Layout, index: usize) u64 {
            return self.upperBoundNsAt(self.baseIndex(), index);
        }

        /// `upperBoundNs` with `baseIndex()` supplied by the caller, so a reader walking every
        /// bucket resolves it once instead of once per bucket — see `LatencyHistogram.base_index`
        /// for what resolving it costs. `base` has to be `self.baseIndex()`: any other value shifts
        /// every bound by a constant and still yields plausible integers, so it is asserted rather
        /// than trusted.
        fn upperBoundNsAt(self: Layout, base: i64, index: usize) u64 {
            std.debug.assert(base == self.baseIndex());
            const gi = base + @as(i64, @intCast(index));
            return @intFromFloat(@floor(nativeBound(self.schema(), gi)));
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
        const shards = raw.shards();
        // `bucketIndex` bounds observations against `layout`, not against the slice, so a `raw`
        // sized from a different layout would index out of the buckets it was handed.
        std.debug.assert(shards[0].buckets.len == layout.bucketCount());
        return .{
            .layout = layout,
            .base_index = layout.baseIndex(),
            .shard_sync = raw.shardSync(),
            .shards = shards,
        };
    }

    fn bucketIndex(self: *const LatencyHistogram, ns: u64) usize {
        // Global native index minus the window base. Values below the window land in bucket 0,
        // which is correct rather than a clamp — bucket 0 runs from `-Inf` under both expositions
        // (see `Layout.min_upper_bound_ns`). Values above the window return an index past the last
        // bucket, which `observe` clamps into the saturating one.
        if (ns == 0) return 0;
        const local = nativeBucketIndex(self.layout.schema(), ns) - self.base_index;
        return if (local < 0) 0 else @intCast(local);
    }

    /// Writes an observed latency (in nanoseconds) into the histogram.
    pub fn observe(self: *const LatencyHistogram, ns: u64) void {
        const shard_sync: ShardSync = @bitCast(self.shard_sync.fetchAdd(1, .acquire)); // acquires lock; must be first
        const shard = &self.shards[shard_sync.shard];
        // Values past `max_upper_bound_ns` saturate into the final bucket rather than being
        // dropped, which is what keeps `count` equal to the sum of the buckets — the invariant a
        // native encoding is rejected for breaking. The bound they are filed under is one rung
        // too low for them, but its lower edge still holds: the value really did exceed
        // `max_upper_bound_ns`. See `Layout.bucketCount`.
        const index = @min(self.bucketIndex(ns), shard.buckets.len - 1);
        _ = shard.buckets[index].fetchAdd(1, .monotonic);
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
            .base_index = self.base_index,
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
        /// The histogram's `base_index`, carried along so the walk never resolves it — see
        /// `Layout.upperBoundNsAt`.
        base_index: i64,
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

            const upper_bound = self.layout.upperBoundNsAt(self.base_index, self.current_bucket_index);
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

test "latency histogram: both window endpoints are inclusive" {
    const Layout = LatencyHistogram.Layout;
    // The regression this API shape exists for: the old `bucketCount = octaves << schema` left the
    // final bound one rung short of the top anyone wrote down (60097 where 65536 was meant).
    const layout: Layout = .{
        .min_upper_bound_ns = 1_024,
        .max_upper_bound_ns = 65_536,
        .bounds_per_doubling = 8,
    };
    try std.testing.expectEqual(@as(u6, 6), layout.doublings());
    try std.testing.expectEqual(@as(u64, 49), layout.resolvedBucketCount());
    try std.testing.expectEqual(@as(u64, 50), layout.bucketCount());
    try std.testing.expectEqual(@as(u64, 1_024), layout.upperBoundNs(0));
    try std.testing.expectEqual(@as(u64, 65_536), layout.upperBoundNs(48));
    // The saturating bucket, one rung past `max_upper_bound_ns`.
    try std.testing.expectEqual(@as(u64, 71_467), layout.upperBoundNs(49));
}

test "latency histogram: bounds that are not powers of two round up together" {
    const Layout = LatencyHistogram.Layout;
    // 1000 sits between the representable bounds 964 and 1024, so the window opens at 1024 and the
    // top rises by the same factor.
    const layout: Layout = .{
        .min_upper_bound_ns = 1_000,
        .max_upper_bound_ns = 16_000,
        .bounds_per_doubling = 8,
    };
    // Rounding shifts the window without changing its span: still 4 doublings, 33 resolved.
    try std.testing.expectEqual(@as(u6, 4), layout.doublings());
    try std.testing.expectEqual(@as(u64, 33), layout.resolvedBucketCount());
    try std.testing.expectEqual(@as(u64, 34), layout.bucketCount());
    try std.testing.expectEqual(@as(u64, 1_024), layout.upperBoundNs(0));
    try std.testing.expectEqual(@as(u64, 16_384), layout.upperBoundNs(32));
    // The fields keep what the caller wrote.
    try std.testing.expectEqual(@as(u64, 1_000), layout.min_upper_bound_ns);
    try std.testing.expectEqual(@as(u64, 16_000), layout.max_upper_bound_ns);
}

test "latency histogram: the zero threshold is bucket 0's real bound, not the raw field" {
    const gpa = std.testing.allocator;
    const Layout = LatencyHistogram.Layout;

    // Powers of two are the uninteresting case: field, effective bound and threshold all agree.
    const aligned: Layout = .{
        .min_upper_bound_ns = 512,
        .max_upper_bound_ns = 2_048,
        .bounds_per_doubling = 4,
    };
    try std.testing.expectEqual(@as(f64, 512), aligned.zeroThreshold());

    // A floor that is not a power of two rounds up onto the ladder. Emitting the raw 1000 as the
    // native zero threshold would leave `(1000, 1024]` in no bucket on the wire, while bucket 0
    // holds those observations regardless.
    const rounded: Layout = .{
        .min_upper_bound_ns = 1_000,
        .max_upper_bound_ns = 16_000,
        .bounds_per_doubling = 8,
    };
    try std.testing.expectEqual(@as(f64, 1_024), rounded.zeroThreshold());

    // The threshold is the boundary `bucketIndex` bins against, so everything up to it is bucket 0
    // and the next integer starts the first positive bucket.
    const hist: LatencyHistogram = try .initForTest(gpa, rounded);
    defer hist.deinitForTest(gpa);
    try std.testing.expectEqual(@as(usize, 0), hist.bucketIndex(1_000));
    try std.testing.expectEqual(@as(usize, 0), hist.bucketIndex(1_024));
    try std.testing.expect(hist.bucketIndex(1_025) > 0);

    // A floor that rounds onto an interior rung lands on a bound that is not an integer, and the
    // threshold carries the exact one rather than the floored `le` label: `upperBoundNs(0)` would
    // drop the `(1116, 1116.68]` sliver that bucket 0 still bins.
    const interior: Layout = .{
        .min_upper_bound_ns = 1_050,
        .max_upper_bound_ns = 16_800,
        .bounds_per_doubling = 8,
    };
    try std.testing.expectEqual(@as(u64, 1_116), interior.upperBoundNs(0));
    try std.testing.expect(interior.zeroThreshold() > 1_116);
    try std.testing.expect(interior.zeroThreshold() < 1_117);
}

test "latency histogram: bounds_per_doubling maps onto the native schema" {
    const Layout = LatencyHistogram.Layout;
    const cases = [_]struct { u16, u4 }{
        .{ 1, 0 }, .{ 2, 1 }, .{ 4, 2 }, .{ 8, 3 }, .{ 16, 4 }, .{ 256, 8 },
    };
    for (cases) |case| {
        const bounds_per_doubling, const schema = case;
        const layout: Layout = .{
            .min_upper_bound_ns = 512,
            .max_upper_bound_ns = 1_024,
            .bounds_per_doubling = bounds_per_doubling,
        };
        try std.testing.expectEqual(schema, layout.schema());
    }
}

test "latency histogram: the pre-rename layout keeps its bounds" {
    const Layout = LatencyHistogram.Layout;
    // `{schema = 2, min_ns = 512, octaves = 12}` spelled in the current API. Its 48 bounds are
    // unchanged; the 49th is the top rung the old arithmetic dropped.
    const layout: Layout = .{
        .min_upper_bound_ns = 512,
        .max_upper_bound_ns = 2_097_152,
        .bounds_per_doubling = 4,
    };
    try std.testing.expectEqual(@as(i64, 36), layout.baseIndex());
    try std.testing.expectEqual(@as(u64, 49), layout.resolvedBucketCount());
    try std.testing.expectEqual(@as(u64, 50), layout.bucketCount());
    const head = [_]u64{ 512, 608, 724, 861, 1024, 1217, 1448, 1722, 2048 };
    for (head, 0..) |bound, i| try std.testing.expectEqual(bound, layout.upperBoundNs(i));
    try std.testing.expectEqual(@as(u64, 1_763_487), layout.upperBoundNs(47));
    try std.testing.expectEqual(@as(u64, 2_097_152), layout.upperBoundNs(48));
}

test "latency histogram: layout header round-trips" {
    const Layout = LatencyHistogram.Layout;
    const cases = [_]Layout{
        .{ .min_upper_bound_ns = 512, .max_upper_bound_ns = 512 << 12, .bounds_per_doubling = 4 },
        .{ .min_upper_bound_ns = 64, .max_upper_bound_ns = 64 << 10, .bounds_per_doubling = 1 },
        // 1_000 is not a power of two, so this case round-trips a layout whose bounds round up.
        .{ .min_upper_bound_ns = 1_000, .max_upper_bound_ns = 16_000, .bounds_per_doubling = 16 },
    };
    for (cases) |layout| {
        var header: [Layout.header_words]u64 = undefined;
        layout.writeHeader(&header);
        try std.testing.expectEqual(layout, Layout.initFromHeader(&header));
    }
}

test "latency histogram: comptimeValidate accepts well-formed layouts" {
    const Layout = LatencyHistogram.Layout;
    Layout.comptimeValidate(.{
        .min_upper_bound_ns = 512,
        .max_upper_bound_ns = 512 << 12,
        .bounds_per_doubling = 4,
    });
    Layout.comptimeValidate(.{
        .min_upper_bound_ns = 1,
        .max_upper_bound_ns = 1 << 8,
        .bounds_per_doubling = 1,
    });
    Layout.comptimeValidate(.{
        .min_upper_bound_ns = 1_000,
        .max_upper_bound_ns = 16_000,
        .bounds_per_doubling = 16,
    });
}

test "latency histogram: geometric bounds and base index" {
    const Layout = LatencyHistogram.Layout;
    // 4 bounds per doubling, window anchored at 512ns == native index 36. Bounds are
    // `2^((36 + i) / 4)` rounded, both endpoints inclusive.
    const layout: Layout = .{
        .min_upper_bound_ns = 512,
        .max_upper_bound_ns = 2048,
        .bounds_per_doubling = 4,
    };
    const want = [_]u64{ 512, 608, 724, 861, 1024, 1217, 1448, 1722, 2048 };
    for (want, 0..) |bound, i| try std.testing.expectEqual(bound, layout.upperBoundNs(i));

    // Storage bucket 0 is native index 36 (== bounds_per_doubling * log2(512), exact since 512 is a
    // power of 2); this is the `positive_span` offset the protobuf encoder emits.
    try std.testing.expectEqual(@as(i64, 36), layout.baseIndex());
    try std.testing.expectEqual(@as(u64, 2), layout.doublings());
    try std.testing.expectEqual(@as(u4, 2), layout.schema());
    // Two doublings at 4 bounds each, plus the closing bound.
    try std.testing.expectEqual(@as(u64, 9), layout.resolvedBucketCount());
    // Plus the saturating bucket.
    try std.testing.expectEqual(@as(u64, 10), layout.bucketCount());
}

test "latency histogram: bins geometrically" {
    const gpa = std.testing.allocator;
    const Layout = LatencyHistogram.Layout;

    // [512, 1024] at 4 bounds per doubling -> 5 buckets. Both endpoints are doubling boundaries and
    // both are observed, exercising the fp-safe `frexp` binning; 513/700 are mid-doubling; 861 stays
    // empty, so an interior bucket holds the running cumulative; 2000 is above the window and
    // saturates into the final bucket (le=1217, a rung past the 1024 top).
    const layout: Layout = .{
        .min_upper_bound_ns = 512,
        .max_upper_bound_ns = 1024,
        .bounds_per_doubling = 4,
    };
    const hist: LatencyHistogram = try .initForTest(gpa, layout);
    defer hist.deinitForTest(gpa);

    hist.observe(512); // bucket 0 (le=512, inclusive doubling boundary)
    hist.observe(513); // bucket 1 (le=608)
    hist.observe(700); // bucket 2 (le=724)
    hist.observe(1024); // bucket 4 (le=1024, inclusive doubling boundary)
    hist.observe(2000); // saturates into bucket 5 (le=1217)

    try hist.testExpectBuckets(5, &.{
        .{ .upper_bound = 512, .cumulative_count = 1 },
        .{ .upper_bound = 608, .cumulative_count = 2 },
        .{ .upper_bound = 724, .cumulative_count = 3 },
        .{ .upper_bound = 861, .cumulative_count = 3 },
        .{ .upper_bound = 1024, .cumulative_count = 4 },
        .{ .upper_bound = 1217, .cumulative_count = 5 },
    });
}

test "latency histogram: every bound is emitted on every snapshot" {
    const gpa = std.testing.allocator;
    const Layout = LatencyHistogram.Layout;

    // The text exposition identifies a classic bucket by its `le` label, so a bound that showed up
    // only in the scrapes where something landed in it would read as a bucket layout that keeps
    // changing — every range query spanning the change sees a series appear from nothing. The set
    // has to be the layout's, never the observed subset, including a snapshot where nothing was
    // observed at all.
    const layout: Layout = .{
        .min_upper_bound_ns = 512,
        .max_upper_bound_ns = 1024,
        .bounds_per_doubling = 4,
    };
    const hist: LatencyHistogram = try .initForTest(gpa, layout);
    defer hist.deinitForTest(gpa);

    // Asserted at the reader, which yields the saturating bucket like any other — the text
    // renderer is what stops short of it (`resolvedBucketCount`), and the native path needs it
    // present to keep `count == zero_count + Σ buckets`.
    const bounds = [_]u64{ 512, 608, 724, 861, 1024, 1217 };
    for ([_]?u64{ null, 700, null }) |maybe_ns| {
        if (maybe_ns) |ns| hist.observe(ns);

        var snap = hist.swapOutSnapshot();
        defer snap.release();

        var seen: usize = 0;
        while (snap.nextBucket()) |bucket| : (seen += 1) {
            try std.testing.expectEqual(bounds[seen], bucket.upper_bound);
        }
        try std.testing.expectEqual(bounds.len, seen);
    }
}

test "latency histogram: a bound bins into the bucket that names it" {
    const Layout = LatencyHistogram.Layout;

    // `upperBoundNs` and `bucketIndex` have to agree exactly, or a value sitting on a boundary is
    // reported under an `le` below itself. They do because both route through the same per-octave
    // table — `nativeBound` is the inverse of `nativeBucketIndex`, not an `exp2` that lands within
    // a ulp of it. Every bound of every shipped-shape layout, checked against the binning.
    //
    // Floors here are all coarse enough that no two bounds round together; `comptimeValidate`
    // rejects the ones that would (see its `le` collision check).
    for ([_]u16{ 1, 2, 4, 8, 16 }) |bpd| {
        for ([_]u64{ 512, 1024 }) |min| {
            const layout: Layout = .{
                .min_upper_bound_ns = min,
                .max_upper_bound_ns = min << 20,
                .bounds_per_doubling = bpd,
            };
            const hist: LatencyHistogram = try .initForTest(std.testing.allocator, layout);
            defer hist.deinitForTest(std.testing.allocator);

            var prev_bound: u64 = 0;
            for (0..layout.bucketCount()) |i| {
                const bound = layout.upperBoundNs(i);
                // Strictly ascending, which is what keeps two buckets off the same `le` label on
                // the text path.
                try std.testing.expect(bound > prev_bound);
                prev_bound = bound;
                // The rounded bound must land in bucket `i`, and the next integer must not.
                try std.testing.expectEqual(i, hist.bucketIndex(bound));
                if (bound + 1 <= layout.max_upper_bound_ns) {
                    try std.testing.expect(hist.bucketIndex(bound + 1) > i);
                }
            }
        }
    }
}

test "latency histogram: values accumulate across snapshots" {
    const gpa = std.testing.allocator;
    const Layout = LatencyHistogram.Layout;

    const layout: Layout = .{
        .min_upper_bound_ns = 512,
        .max_upper_bound_ns = 1024,
        .bounds_per_doubling = 4,
    };
    const hist: LatencyHistogram = try .initForTest(gpa, layout);
    defer hist.deinitForTest(gpa);

    hist.observe(512); // bucket 0
    hist.observe(513); // bucket 1
    try hist.testExpectBuckets(2, &.{
        .{ .upper_bound = 512, .cumulative_count = 1 },
        .{ .upper_bound = 608, .cumulative_count = 2 },
        .{ .upper_bound = 724, .cumulative_count = 2 },
        .{ .upper_bound = 861, .cumulative_count = 2 },
        .{ .upper_bound = 1024, .cumulative_count = 2 },
        .{ .upper_bound = 1217, .cumulative_count = 2 },
    });

    // The prior snapshot folds its counts back into the hot shard, so totals accumulate.
    hist.observe(512); // bucket 0
    try hist.testExpectBuckets(3, &.{
        .{ .upper_bound = 512, .cumulative_count = 2 },
        .{ .upper_bound = 608, .cumulative_count = 3 },
        .{ .upper_bound = 724, .cumulative_count = 3 },
        .{ .upper_bound = 861, .cumulative_count = 3 },
        .{ .upper_bound = 1024, .cumulative_count = 3 },
        .{ .upper_bound = 1217, .cumulative_count = 3 },
    });
}

test "latency histogram: values below the window floor into bucket 0" {
    const gpa = std.testing.allocator;
    const Layout = LatencyHistogram.Layout;

    const layout: Layout = .{
        .min_upper_bound_ns = 512,
        .max_upper_bound_ns = 1024,
        .bounds_per_doubling = 4,
    };
    const hist: LatencyHistogram = try .initForTest(gpa, layout);
    defer hist.deinitForTest(gpa);

    hist.observe(0); // clamps to bucket 0
    hist.observe(1); // below window -> bucket 0
    hist.observe(100); // below window -> bucket 0

    try hist.testExpectBuckets(3, &.{
        .{ .upper_bound = 512, .cumulative_count = 3 },
        .{ .upper_bound = 608, .cumulative_count = 3 },
        .{ .upper_bound = 724, .cumulative_count = 3 },
        .{ .upper_bound = 861, .cumulative_count = 3 },
        .{ .upper_bound = 1024, .cumulative_count = 3 },
        .{ .upper_bound = 1217, .cumulative_count = 3 },
    });
}

// A window of 512ns .. ~537ms. Wide enough that a measured span lands in an explicit bucket rather
// than the implicit `+Inf` one.
const observer_test_layout: LatencyHistogram.Layout = .{
    .min_upper_bound_ns = 512,
    .max_upper_bound_ns = 512 << 20,
    .bounds_per_doubling = 4,
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
