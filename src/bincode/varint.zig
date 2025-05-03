const std = @import("std");
const sig = @import("../sig.zig");
const bincode = sig.bincode;

pub const var_int_config_u16 = VarIntConfig(u16);
pub const var_int_config_u64 = VarIntConfig(u64);

pub fn VarIntConfig(comptime VarInt: type) bincode.FieldConfig(VarInt) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            _ = params;
            var v = data;
            while (v >= 0x80) {
                const byte = @as(u8, @intCast(((v & 0x7F) | 0x80)));
                v >>= 7;
                try writer.writeByte(byte);
            }
            try writer.writeByte(@as(u8, @intCast(v)));
        }

        pub fn deserialize(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) !VarInt {
            _ = params;
            _ = allocator;

            var out: VarInt = 0;

            const t_bits: u8 = switch (VarInt) {
                u16 => 16,
                u32 => 32,
                u64 => 64,
                else => {
                    return error.InvalidType;
                },
            };

            const ShiftT: type = switch (VarInt) {
                u16 => u4,
                u32 => u5,
                u64 => u6,
                else => unreachable,
            };

            var shift: u32 = 0;
            while (shift < t_bits) {
                const byte: u8 = try reader.readByte();
                out |= @as(VarInt, @intCast((byte & 0x7F))) << @as(ShiftT, @intCast(shift));
                if (byte & 0x80 == 0) {
                    if (@as(u8, @intCast(out >> @as(ShiftT, @intCast(shift)))) != byte) {
                        return error.TruncatedLastByte;
                    }
                    if (byte == 0 and (shift != 0 or out != 0)) {
                        return error.NotValidTrailingZeros;
                    }
                    return out;
                }
                shift += 7;
            }
            return error.ShiftOverflows;
        }
    };

    return bincode.FieldConfig(VarInt){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
    };
}

pub fn serializeShortU16(writer: anytype, data: u16) error{WriterError}!void {
    var value = data;
    while (true) {
        const elem: u8 = @intCast(value & 0x7f);
        value >>= 7;
        if (value != 0) {
            writer.writeByte(elem | 0x80) catch return error.WriterError;
        } else {
            writer.writeByte(elem) catch return error.WriterError;
            break;
        }
    }
}

const MAX_ENCODING_LENGTH: u2 = 3;

pub const DeserializeShortU16Error =
    VisitByteError || error{
    ReaderError,
    EndOfStream,
};

pub fn deserializeShortU16(reader: anytype) DeserializeShortU16Error!struct { u16, u2 } {
    var current_value: u16 = 0;
    for (0..MAX_ENCODING_LENGTH) |byte_index| {
        const elem: u8 = reader.readByte() catch return error.ReaderError;
        switch (try visitByte(elem, current_value, byte_index)) {
            .more => |value| current_value = value,
            .done => |value| return .{ value, @intCast(byte_index + 1) },
        }
    }
    return error.ByteThreeContinues;
}

pub const VisitByteError = error{
    ZeroAfterStart,
    TooLong,
    ByteThreeContinues,
    Overflow,
};

pub const DoneOrMore = union(enum) {
    done: u16,
    more: u16,
};

pub fn visitByte(
    current_byte: u8,
    current_value: u16,
    byte_index: u64,
) VisitByteError!DoneOrMore {
    if (current_byte == 0 and byte_index != 0) {
        return error.ZeroAfterStart;
    }

    const elem_val: u32 = current_byte & 0x7f;
    const elem_done = (current_byte & 0x80) == 0;

    if (byte_index >= MAX_ENCODING_LENGTH) {
        return error.TooLong;
    }

    if (byte_index == @as(usize, MAX_ENCODING_LENGTH) -| 1 and !elem_done) {
        return error.ByteThreeContinues;
    }

    const shift: u32 = (std.math.cast(u32, byte_index) orelse std.math.maxInt(u32)) *| 7;
    const elem_val_shifted: u32 = elem_val <<| shift;

    const new_val = current_value | elem_val_shifted;
    // const shift = std.math.cast(
    //     u3,
    //     (std.math.cast(u32, nth_byte) orelse U32_MAX) *| 7,
    // ) orelse return error.ShiftOverflows;

    // const shift_res = @shlWithOverflow(elem_val, shift);
    // const result = shift_res.@"0";
    // const overflow_bit = shift_res.@"1";
    // if (overflow_bit == 1) {
    //     elem_val = U32_MAX;
    // } else {
    //     elem_val = result;
    // }

    // const new_val = value | elem_val;
    const out_val = std.math.cast(u16, new_val) orelse return error.Overflow;

    if (elem_done) {
        return .{ .done = out_val };
    } else {
        return .{ .more = out_val };
    }
}
