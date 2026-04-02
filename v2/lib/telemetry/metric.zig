const std = @import("std");
const tel = @import("../telemetry.zig");

pub const Kind = enum(u8) {
    gauge_int,
    gauge_float,
    histogram,
};

/// This represents the metric detail that appears before the metric value in memory.
pub const Detail = struct {
    id: Id,
    kind: Kind,
    /// The index representing the location of the metric, with its meaning depending on `kind`:
    /// * `gauge_int` & `gauge_float`: index of element in the `gauges` region.
    /// * `histogram`: index of a `bucket_count` element in `histogram_data`, which will be
    /// followed by a number of elements corresponding to a `Histogram` with that bucket_count.
    index: u32,

    /// Returns the number of bytes that would be written by `self.binaryWrite(w)`.
    pub fn binaryLength(self: Detail) usize {
        var trash_buffer: [128]u8 = undefined;
        var dw: std.Io.Writer.Discarding = .init(&trash_buffer);
        self.binaryWrite(&dw.writer) catch |err| switch (err) {
            error.WriteFailed => unreachable,
        };
        return dw.fullCount();
    }

    /// Write metric detail in binary format.
    pub fn binaryWrite(
        self: Detail,
        w: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try self.id.writeBinary(w);
        try w.writeInt(u8, @intFromEnum(self.kind), tel.endian);
        try w.writeInt(u32, self.index, tel.endian);
    }

    /// Expects `r` to be a reader that contains the full serialized metric detail,
    /// such that calls to '`r.take`*' never invalidate previous calls to '`r.take`*'.
    /// This is most easily achieved when `r.* = .fixed(buffer)`.
    pub fn fromFixedReader(
        r: *std.Io.Reader,
    ) (std.Io.Reader.Error || std.Io.Reader.TakeEnumError)!Detail {
        return .{
            .id = try .fromFixedReader(r),
            .kind = try r.takeEnum(Kind, tel.endian),
            .index = try r.takeInt(u32, tel.endian),
        };
    }
};

pub const Id = struct {
    name: []const u8,
    label_count: usize,
    /// Should be a list of comma-separated strings.
    /// It is asserted that:
    /// * `count(u8, labels, ',') + 1 == label_count`.
    labels: [:'}']const u8,

    pub fn eql(a: Id, b: Id) bool {
        if (a.label_count != b.label_count) return false;
        if (!std.mem.eql(u8, a.name, b.name)) return false;
        if (!std.mem.eql(u8, a.labels, b.labels)) return false;
        return true;
    }

    pub fn hash(self: Id) u64 {
        var hashing_ws_buf: [4096]u8 = undefined;
        var hashing_ws: std.Io.Writer.Hashing(std.hash.Wyhash) =
            .initHasher(.init(0), &hashing_ws_buf);
        const hashing_w = &hashing_ws.writer;
        self.writeBinary(hashing_w) catch unreachable;
        return hashing_ws.hasher.final();
    }

    /// Returns a formatter for the metric id using `writeText`.
    pub fn fmtText(self: Id) std.fmt.Alt(Id, writeText) {
        return .{ .data = self };
    }

    pub fn writeText(self: Id, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(self.name);
        try w.writeByte('{');
        try w.writeAll(self.labels);
        try w.writeByte('}');
    }

    pub fn writeBinary(self: Id, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeInt(usize, self.name.len, tel.endian);
        try w.writeAll(self.name);

        try w.writeInt(usize, self.label_count, tel.endian);
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
    ) std.Io.Reader.Error!Id {
        const name_len = try r.takeInt(usize, tel.endian);
        const name = try r.take(name_len);

        const label_count = try r.takeInt(usize, tel.endian);

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
        };
        const labels = try r.take(index + 1);

        return .{
            .name = name,
            .label_count = label_count,
            .labels = labels[0 .. labels.len - 1 :'}'],
        };
    }
};

pub const Appender = struct {
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

    pub fn appendGaugeRaw(
        self: Appender,
        id: Id,
        comptime kind: GaugeKind,
        init_value: kind.Type(),
    ) *std.atomic.Value(kind.Type()) {
        const gauge_index = self.gauges_end.fetchAdd(1, .monotonic);
        self.appendId(.{
            .id = id,
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

    pub fn appendHistogramRaw(
        self: Appender,
        id: Id,
        bucket_count: u32,
    ) tel.Histogram.Raw {
        const elem_count = tel.Histogram.elementsFromBucketCount(bucket_count);
        const elem_offs = self.histogram_data_end.fetchAdd(elem_count + 1, .acq_rel);
        self.appendId(.{
            .id = id,
            .kind = .histogram,
            .index = elem_offs,
        });
        self.histogram_data[elem_offs] = bucket_count;
        return .{ .elements = self.histogram_data[elem_offs + 1 ..][0..elem_count] };
    }

    fn appendId(self: Appender, detail: Detail) void {
        const id_mem_len = detail.binaryLength();
        const id_mem_offset = self.id_mem_end.fetchAdd(@intCast(id_mem_len), .acq_rel);

        var id_mem_w: std.Io.Writer = .fixed(self.id_mem[id_mem_offset..][0..id_mem_len]);
        detail.binaryWrite(&id_mem_w) catch |err| switch (err) {
            error.WriteFailed => unreachable,
        };
    }
};
