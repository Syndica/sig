pub fn serialize(writer: anytype, value: u16) !void {
    const val = @as(u32, value);
    const needs_byte_1 = val > 0x007F;
    const needs_byte_2 = val > 0x3FFF;
    const byte_0 = val & 0x7F;
    const byte_1 = (val >> 7) & 0x7F;
    const byte_2 = val >> 14;
    try writer.writeByte(@truncate(byte_0 | (@as(u32, @intFromBool(needs_byte_1)) << 7)));
    if (needs_byte_1) try writer.writeByte(@truncate(byte_1 | (@as(u32, @intFromBool(needs_byte_2)) << 7)));
    if (needs_byte_2) try writer.writeByte(@truncate(byte_2));
}

pub fn deserialize(reader: anytype) !u16 {
    const byte_0 = try reader.readByte();
    if ((byte_0 & 0x80) == 0) {
        return byte_0;
    }

    const byte_1 = try reader.readByte();
    if ((byte_1 & 0x80) == 0) {
        if (byte_1 != 0) {
            return @as(u16, @truncate(@as(u32, byte_0 & 0x7F) + (@as(u32, byte_1) << 7)));
        } else return error.InvalidCompactU16;
    }

    const byte_2 = try reader.readByte();
    if ((byte_2 & 0x80) == 0) {
        if (byte_2 != 0) {
            return @as(u16, @truncate(@as(u32, byte_0 & 0x7F) + (@as(u32, byte_1 & 0x7F) << 7) + (@as(u32, byte_2) << 14)));
        } else return error.InvalidCompactU16;
    }

    return error.InvalidCompactU16;
}

fn testRoundTrip(value: u16) !void {
    var write_result = [_]u8{0} ** 3;
    var writer = Writer.init(&write_result);
    try CompactU16.serialize(&writer, value);

    var reader = Reader.init(&write_result);
    const read_result = try CompactU16.deserialize(&reader);

    try std.testing.expectEqual(value, read_result);
}

test "compactU16RoundTrip" {
    try testRoundTrip(0);
    try testRoundTrip(128);
    try testRoundTrip(49152);
}

const CompactU16 = @This();

const std = @import("std");
const sig = @import("../sig.zig");

const Writer = sig.io.Writer;
const Reader = sig.io.Reader;
