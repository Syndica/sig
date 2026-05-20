const std = @import("std");

pub fn read(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader, comptime T: type) !T {
    switch (@typeInfo(T)) {
        inline .int, .float, .array => |info| {
            if (@typeInfo(T) == .array)
                comptime std.debug.assert(@typeInfo(info.child) == .int);
            var val: T = undefined;
            try reader.readSliceAll(std.mem.asBytes(&val));
            return val;
        },
        .bool => {
            const b = try read(fba, reader, u8);
            if (b > 1) return error.InvalidBool;
            return b > 0;
        },
        .optional => |info| {
            const is_some = try read(fba, reader, bool);
            return if (is_some) try read(fba, reader, info.child) else null;
        },
        .@"enum" => |info| {
            const tag = try read(fba, reader, info.tag_type);
            return try std.meta.intToEnum(T, tag);
        },
        .@"union" => |info| {
            if (@hasDecl(T, "bincodeRead")) return @field(T, "bincodeRead")(fba, reader);

            switch (try read(fba, reader, info.tag_type.?)) {
                inline else => |tag| {
                    const Variant = @FieldType(T, @tagName(tag));
                    return @unionInit(T, @tagName(tag), try read(fba, reader, Variant));
                },
            }
        },
        .@"struct" => |info| {
            if (@hasDecl(T, "bincodeRead")) return @field(T, "bincodeRead")(fba, reader);
            var value: T = undefined;
            inline for (info.fields) |f| @field(value, f.name) = try read(fba, reader, f.type);
            return value;
        },
        .void => return {},
        else => @compileError("unsupported type: " ++ @typeName(T)),
    }
}

const ShortU16 = struct {
    value: u16,

    pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
        var val: u32 = 0;
        for (0..3) |nth_byte| {
            const b = try read(fba, reader, u8);
            if (b == 0 and nth_byte != 0) return error.AliasEncoding;
            val |= @as(u32, b & 0x7f) << @intCast(nth_byte * 7);
            if (b & 0x80 == 0) {
                return .{ .value = std.math.cast(u16, val) orelse return error.Overflow };
            }
            if (nth_byte == 2) return error.ByteThreeContinues;
        }
        unreachable;
    }
};

pub fn Vec(comptime T: type) type {
    return struct {
        items: []const T,
        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
            const n = try read(fba, reader, u64);
            const slice = try fba.allocator().alloc(T, n);
            for (slice) |*v| v.* = try read(fba, reader, T);
            return .{ .items = slice };
        }
    };
}

pub fn ShortVec(comptime T: type) type {
    return struct {
        items: []const T,
        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
            const n = (try read(fba, reader, ShortU16)).value;
            const slice = try fba.allocator().alloc(T, n);
            for (slice) |*v| v.* = try read(fba, reader, T);
            return .{ .items = slice };
        }
    };
}

pub fn NullOnEof(comptime T: type) type {
    return struct {
        value: ?T,
        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
            return .{ .value = read(fba, reader, T) catch |err| switch (err) {
                error.EndOfStream => null,
                else => |e| return e,
            } };
        }
    };
}
