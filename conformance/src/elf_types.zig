const std = @import("std");

const Allocator = std.mem.Allocator;
const xxhash = std.hash.XxHash64.hash;
const writeInt = std.mem.writeInt;

/// Wrapper for the ELF binary and the features that the loader should use
/// Note that we currently hardcode the features to be used by the loader,
/// so features isn't actually used yet.
pub const ELFLoaderCtx = struct {
    elf: ?[]const u8 = null,
    features: ?FeatureSet = null,
    deploy_checks: bool = false,

    pub fn deinit(self: *const ELFLoaderCtx, allocator: Allocator) void {
        if (self.features) |features| features.deinit(allocator);
    }

    /// Decode a flatbuffer ELFLoaderCtx into the protobuf ELFLoaderCtx struct.
    /// The returned struct borrows elf.data directly from buf, so buf must
    /// outlive the result.
    pub fn decode(
        allocator: Allocator,
        buf: []const u8,
    ) error{ OutOfMemory, InsufficientData }!ELFLoaderCtx {
        const root_pos = try decodeInt(u32, buf[0..]);
        const vt: VTable = try .decode(buf, root_pos);

        return .{
            .elf = if (vt.field(0)) |offset|
                try decodeUbyteVec(buf, root_pos + offset)
            else
                null,
            .features = if (vt.field(1)) |offset|
                try .decode(allocator, buf, try deref(buf, root_pos + offset))
            else
                null,
            .deploy_checks = if (vt.field(2)) |offset| buf[root_pos + offset] != 0 else false,
        };
    }
};

/// Captures the results of a elf binary load.
/// Structurally similar to fd_sbpf_program_t
pub const ELFLoaderEffects = struct {
    rodata: []const u8 = &.{},
    rodata_sz: u64 = 0,
    text_cnt: u64 = 0,
    text_off: u64 = 0,
    entry_pc: u64 = 0,
    calldests: std.ArrayListUnmanaged(u64) = .empty,
    @"error": i32 = 0,

    pub fn deinit(self: *const ELFLoaderEffects, allocator: Allocator) void {
        allocator.free(self.rodata);
        var cd = self.calldests;
        cd.deinit(allocator);
    }

    pub const buf_size = 72;

    /// Encode an ELFLoaderEffects into a 72-byte FlatBuffer.
    pub fn encode(self: *const ELFLoaderEffects) [buf_size]u8 {
        const meta: EncodeMeta = .{
            .rodata_hash = self.rodata.len != 0,
            .calldests_hash = self.calldests.items.len != 0,
        };
        var buf: [buf_size]u8 = template(meta);

        buf[28] = @truncate(@as(u32, @bitCast(self.@"error")));
        if (meta.rodata_hash) {
            writeInt(u64, buf[32..40], xxhash(0, self.rodata), .little);
        }
        writeInt(u64, buf[40..48], self.text_cnt, .little);
        writeInt(u64, buf[48..56], self.text_off, .little);
        writeInt(u64, buf[56..64], self.entry_pc, .little);
        if (meta.calldests_hash) {
            const calldests_bytes = std.mem.sliceAsBytes(self.calldests.items);
            writeInt(u64, buf[64..72], xxhash(0, calldests_bytes), .little);
        }

        return buf;
    }

    const EncodeMeta = struct {
        rodata_hash: bool,
        calldests_hash: bool,
    };

    inline fn template(meta: EncodeMeta) [buf_size]u8 {
        var buf: [buf_size]u8 = @splat(0);
        // root offset: table at byte 24
        writeInt(u32, buf[0..4], 24, .little);
        // vtable (bytes 4..20): vt_size, table_size, 6 field offsets
        writeInt(u16, buf[4..6], 16, .little); // vt_size  (2+2+6*2 = 16)
        writeInt(u16, buf[6..8], 48, .little); // table inline size
        writeInt(u16, buf[8..10], 4, .little); // field 0: err_code
        writeInt(u16, buf[10..12], if (meta.rodata_hash) 8 else 0, .little); // field 1: rodata_hash
        writeInt(u16, buf[12..14], 16, .little); // field 2: text_cnt
        writeInt(u16, buf[14..16], 24, .little); // field 3: text_off
        writeInt(u16, buf[16..18], 32, .little); // field 4: entry_pc
        writeInt(u16, buf[18..20], if (meta.calldests_hash) 40 else 0, .little); // field 5: calldests_hash
        // bytes 20..24: padding (already zero)
        // soffset: table_pos(24) - vtable_pos(4) = 20
        writeInt(i32, buf[24..28], 20, .little);
        return buf;
    }
};

pub const FeatureSet = struct {
    features: std.ArrayListUnmanaged(u64) = .empty,

    pub fn deinit(self: *const FeatureSet, allocator: Allocator) void {
        var features = self.features;
        features.deinit(allocator);
    }

    pub fn decode(
        allocator: Allocator,
        buf: []const u8,
        pos: usize,
    ) error{ OutOfMemory, InsufficientData }!FeatureSet {
        const vt: VTable = try .decode(buf, pos);
        var result: FeatureSet = .{};
        if (vt.field(0)) |offset| {
            const vec_pos = try deref(buf, pos + offset);
            const len = try decodeInt(u32, buf[vec_pos..]);
            try result.features.ensureTotalCapacity(allocator, len);
            for (0..len) |i| {
                result.features.appendAssumeCapacity(
                    try decodeInt(u64, buf[vec_pos + 4 + i * 8 ..]),
                );
            }
        }
        return result;
    }
};

const VTable = struct {
    buf: []const u8,
    /// start of vtable in buf
    pos: usize,
    /// vtable size in bytes
    size: usize,

    fn decode(buf: []const u8, table_pos: usize) error{InsufficientData}!VTable {
        const soff = try decodeInt(i32, buf[table_pos..]);
        const vt_pos: usize = @intCast(@as(i64, @intCast(table_pos)) - soff);
        const vt_size = try decodeInt(u16, buf[vt_pos..]);
        return .{ .buf = buf, .pos = vt_pos, .size = vt_size };
    }

    /// Return the field offset (relative to table start) for field `index`, or null if absent.
    fn field(self: VTable, index: usize) ?usize {
        const entry = 4 + index * 2; // first field entry is at byte 4 in vtable
        if (entry + 2 > self.size) return null;
        const offset = std.mem.readInt(u16, self.buf[self.pos + entry ..][0..2], .little);
        if (offset == 0) return null;
        return offset;
    }
};

/// Follow a uoffset_t: return the position it points to.
fn deref(buf: []const u8, pos: usize) error{InsufficientData}!usize {
    if (pos + 4 > buf.len) return error.InsufficientData;
    return pos + try decodeInt(u32, buf[pos..]);
}

fn decodeUbyteVec(buf: []const u8, field_pos: usize) error{InsufficientData}![]const u8 {
    const vec_pos = try deref(buf, field_pos);
    const len = try decodeInt(u32, buf[vec_pos..]);
    const start = vec_pos + 4;
    if (start + len > buf.len) return error.InsufficientData;
    return buf[start .. start + len];
}

fn decodeInt(Int: type, buf: []const u8) error{InsufficientData}!Int {
    if (buf.len < @sizeOf(Int)) return error.InsufficientData;
    return std.mem.readInt(Int, buf[0..@sizeOf(Int)], .little);
}
