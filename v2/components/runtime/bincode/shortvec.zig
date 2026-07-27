const std = @import("std");
const bincode = @import("bincode.zig");

const MAX_ENCODING_LENGTH: usize = 3;

/// Strict `ShortU16` decoder matching `solana_short_vec::ShortU16`.
///
/// Unlike a generic LEB128 reader, this enforces:
///   * at most 3 bytes (sufficient to encode any `u16`),
///   * any non-first byte must be non-zero (rejects alias-encoded values like
///     `[0x80, 0x00]`, which would decode to `0` under permissive LEB128),
///   * the third byte must not have the continuation bit set,
///   * the decoded value must fit in `u16`.
///
/// [agave] https://github.com/anza-xyz/solana-sdk/blob/short-vec@v3.2.2/short-vec/src/lib.rs#L146-166
pub fn readShortU16(reader: anytype) !u16 {
    var value: u16 = 0;
    inline for (0..MAX_ENCODING_LENGTH) |nth_byte| {
        const elem: u8 = try reader.readByte();
        if (nth_byte != 0 and elem == 0) return error.ShortU16Alias;

        const elem_val: u16 = elem & 0x7f;
        const elem_done = (elem & 0x80) == 0;
        if (nth_byte == 2 and !elem_done) return error.ShortU16ByteThreeContinues;

        const shift: u4 = @intCast(nth_byte * 7);
        const shifted: u32 = @as(u32, elem_val) << shift;
        const new_val: u32 = @as(u32, value) | shifted;
        value = std.math.cast(u16, new_val) orelse return error.ShortU16Overflow;

        if (elem_done) return value;
    }
    return error.ShortU16ByteThreeContinues;
}

/// Strict varint decoder matching `solana_serde_varint`.
///
/// Like `readShortU16` but for arbitrary unsigned integer widths. Enforces
/// minimal encoding: the terminating byte cannot be zero unless it is also
/// the only byte, and the shift on the terminating byte cannot truncate any
/// of its set bits.
///
/// [agave] https://github.com/anza-xyz/solana-sdk/blob/serde-varint@v3.0.1/serde-varint/src/lib.rs#L69-96
pub fn readVarInt(comptime T: type, reader: anytype) !T {
    comptime std.debug.assert(@typeInfo(T) == .int and @typeInfo(T).int.signedness == .unsigned);
    const ShiftT = std.math.Log2Int(T);

    var out: T = 0;
    var shift: u32 = 0;
    while (shift < @bitSizeOf(T)) {
        const byte: u8 = try reader.readByte();
        const part: T = byte & 0x7F;
        const shift_amt: ShiftT = @intCast(shift);
        out |= part << shift_amt;

        if (byte & 0x80 == 0) {
            // The shift above must not have truncated any of `byte`'s bits.
            if (@as(u8, @truncate(out >> shift_amt)) != byte) {
                return error.VarIntLastByteTruncated;
            }
            // Trailing zero byte is only allowed when this is the sole byte and
            // the result is also zero.
            if (byte == 0 and (shift != 0 or out != 0)) {
                return error.VarIntInvalidTrailingZeros;
            }
            return out;
        }
        shift += 7;
    }
    return error.VarIntLeftShiftOverflows;
}

pub fn sliceConfig(comptime Slice: type) bincode.FieldConfig(Slice) {
    const Child = std.meta.Elem(Slice);
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            const len: u16 = std.math.cast(u16, data.len) orelse return error.DataTooLarge;
            try std.leb.writeUleb128(writer, len);
            for (data) |item| {
                try bincode.write(writer, item, params);
            }
        }

        pub fn deserialize(limit_allocator: *bincode.LimitAllocator, reader: anytype, params: bincode.Params) !Slice {
            const len = try readShortU16(reader);

            const allocator = limit_allocator.allocator();
            const elems = try allocator.alloc(Child, len);
            errdefer allocator.free(elems);

            for (elems, 0..) |*elem, i| {
                errdefer for (elems[0..i]) |prev| bincode.free(allocator, prev);
                elem.* = try bincode.readWithLimit(limit_allocator, Child, reader, params);
            }
            return elems;
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            for (data) |elem| bincode.free(allocator, elem);
            allocator.free(data);
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn arrayListConfig(comptime Child: type) bincode.FieldConfig(std.array_list.Managed(Child)) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            const list: std.array_list.Managed(Child) = data;
            const len = std.math.cast(u16, list.items.len) orelse return error.DataTooLarge;
            try std.leb.writeUleb128(writer, len);
            for (list.items) |item| {
                try bincode.write(writer, item, params);
            }
        }

        pub fn deserialize(limit_allocator: *bincode.LimitAllocator, reader: anytype, params: bincode.Params) !std.array_list.Managed(Child) {
            const len = try readShortU16(reader);

            var list =
                try std.array_list.Managed(Child).initCapacity(limit_allocator.allocator(), @as(usize, len));
            errdefer list.deinit();

            for (0..len) |_| {
                const item = try bincode.readWithLimit(limit_allocator, Child, reader, params);
                try list.append(item);
            }

            list.allocator = limit_allocator.backing_allocator; // patch with backing before return.
            return list;
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            _ = allocator;
            data.deinit();
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

// Tests mirrored from upstream agave:
//   * `solana_short_vec::tests::test_deserialize`
//     https://github.com/anza-xyz/solana-sdk/blob/short-vec@v3.2.2/short-vec/src/lib.rs
//   * `solana_serde_varint::tests::*`
//     https://github.com/anza-xyz/solana-sdk/blob/serde-varint@v3.0.1/serde-varint/src/lib.rs

test "readShortU16 accepts canonical encodings" {
    const Case = struct { value: u16, bytes: []const u8 };
    const cases = [_]Case{
        .{ .value = 0x0000, .bytes = &.{0x00} },
        .{ .value = 0x007f, .bytes = &.{0x7f} },
        .{ .value = 0x0080, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = 0x00ff, .bytes = &.{ 0xff, 0x01 } },
        .{ .value = 0x0100, .bytes = &.{ 0x80, 0x02 } },
        .{ .value = 0x07ff, .bytes = &.{ 0xff, 0x0f } },
        .{ .value = 0x3fff, .bytes = &.{ 0xff, 0x7f } },
        .{ .value = 0x4000, .bytes = &.{ 0x80, 0x80, 0x01 } },
        .{ .value = 0xffff, .bytes = &.{ 0xff, 0xff, 0x03 } },
    };
    for (cases) |case| {
        var stream = std.io.fixedBufferStream(case.bytes);
        try std.testing.expectEqual(case.value, try readShortU16(stream.reader()));
    }
}

test "readShortU16 rejects alias encodings" {
    const bad: []const []const u8 = &.{
        // aliases of 0x0000
        &.{ 0x80, 0x00 },
        &.{ 0x80, 0x80, 0x00 },
        // aliases of 0x007f
        &.{ 0xff, 0x00 },
        &.{ 0xff, 0x80, 0x00 },
        // alias of 0x0080
        &.{ 0x80, 0x81, 0x00 },
        // alias of 0x00ff
        &.{ 0xff, 0x81, 0x00 },
        // alias of 0x0100
        &.{ 0x80, 0x82, 0x00 },
        // alias of 0x07ff
        &.{ 0xff, 0x8f, 0x00 },
        // alias of 0x3fff
        &.{ 0xff, 0xff, 0x00 },
    };
    for (bad) |bytes| {
        var stream = std.io.fixedBufferStream(bytes);
        try std.testing.expectError(error.ShortU16Alias, readShortU16(stream.reader()));
    }
}

test "readShortU16 rejects values that overflow u16" {
    var s1 = std.io.fixedBufferStream(&[_]u8{ 0x80, 0x80, 0x04 });
    try std.testing.expectError(error.ShortU16Overflow, readShortU16(s1.reader()));
    var s2 = std.io.fixedBufferStream(&[_]u8{ 0x80, 0x80, 0x06 });
    try std.testing.expectError(error.ShortU16Overflow, readShortU16(s2.reader()));
}

test "readShortU16 rejects continuation bit on third byte" {
    var stream = std.io.fixedBufferStream(&[_]u8{ 0x80, 0x80, 0x80 });
    try std.testing.expectError(error.ShortU16ByteThreeContinues, readShortU16(stream.reader()));
}

test "readShortU16 rejects truncated buffer" {
    var s1 = std.io.fixedBufferStream(&[_]u8{});
    try std.testing.expectError(error.EndOfStream, readShortU16(s1.reader()));
    var s2 = std.io.fixedBufferStream(&[_]u8{0x80});
    try std.testing.expectError(error.EndOfStream, readShortU16(s2.reader()));
}

test "readVarInt accepts canonical encodings (u64)" {
    const Case = struct { value: u64, bytes: []const u8 };
    const cases = [_]Case{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 0x7f, .bytes = &.{0x7f} },
        .{ .value = 0x80, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = 0x3fff, .bytes = &.{ 0xff, 0x7f } },
        .{ .value = 0x4000, .bytes = &.{ 0x80, 0x80, 0x01 } },
        // u64::MAX (10-byte varint: nine 0xff continuation bytes then 0x01)
        .{
            .value = std.math.maxInt(u64),
            .bytes = &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 },
        },
    };
    for (cases) |case| {
        var stream = std.io.fixedBufferStream(case.bytes);
        try std.testing.expectEqual(case.value, try readVarInt(u64, stream.reader()));
    }
}

test "readVarInt rejects invalid trailing zero (multi-byte zero)" {
    // `[0x80, 0x00]` decodes to 0 under permissive LEB128 but is a non-canonical
    // alias of the single-byte `[0x00]`. agave's serde_varint rejects this as
    // "Invalid Trailing Zeros".
    var stream = std.io.fixedBufferStream(&[_]u8{ 0x80, 0x00 });
    try std.testing.expectError(error.VarIntInvalidTrailingZeros, readVarInt(u64, stream.reader()));
}

test "readVarInt rejects trailing zero on terminal byte (u32)" {
    // Five-byte u32 varint with terminal zero byte: agave test_serde_varint_trailing_zeros.
    var stream = std.io.fixedBufferStream(&[_]u8{ 0x93, 0xc2, 0xa9, 0x8d, 0x00 });
    try std.testing.expectError(error.VarIntInvalidTrailingZeros, readVarInt(u32, stream.reader()));
}

test "readVarInt rejects last-byte truncation (u32)" {
    // agave test_serde_varint_last_byte_truncated: terminal byte's high bits do
    // not fit in u32 after shifting by 28.
    var stream = std.io.fixedBufferStream(&[_]u8{ 0xe4, 0xd7, 0x88, 0xf6, 0x6f });
    try std.testing.expectError(error.VarIntLastByteTruncated, readVarInt(u32, stream.reader()));
}

test "readVarInt rejects left-shift overflow (u32)" {
    // agave test_serde_varint_shift_overflow: five continuation bytes for a u32
    // would require a 6th byte; we exit the loop with an overflow error.
    var stream = std.io.fixedBufferStream(&[_]u8{ 0x84, 0xdf, 0x96, 0xfa, 0xef });
    try std.testing.expectError(error.VarIntLeftShiftOverflows, readVarInt(u32, stream.reader()));
}

test "readVarInt rejects truncated buffer" {
    var stream = std.io.fixedBufferStream(&[_]u8{ 0x84, 0xdf, 0x96, 0xfa });
    try std.testing.expectError(error.EndOfStream, readVarInt(u32, stream.reader()));
}
