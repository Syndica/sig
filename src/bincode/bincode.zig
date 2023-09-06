const std = @import("std");
pub const getty = @import("getty");
const bincode = @This();
const testing = std.testing;

pub const Params = struct {
    pub const legacy: Params = .{
        .endian = .Little,
        .int_encoding = .fixed,
        .include_fixed_array_length = true,
    };

    pub const standard: Params = .{
        .endian = .Little,
        .int_encoding = .fixed,
        .include_fixed_array_length = false,
    };

    endian: std.builtin.Endian = .Little,
    int_encoding: enum { variable, fixed } = .fixed,
    include_fixed_array_length: bool = false,
};

pub fn deserializer(r: anytype, params: Params) Deserializer(@TypeOf(r)) {
    return Deserializer(@TypeOf(r)).init(r, params);
}

pub fn Deserializer(comptime Reader: type) type {
    return struct {
        reader: Reader,
        params: Params,

        const Self = @This();
        const Error = getty.de.Error || error{
            IO,
        };

        const De = Self.@"getty.Deserializer";

        pub fn init(reader: Reader, params: Params) Self {
            std.debug.assert(params.int_encoding == .fixed);
            return Self{ .reader = reader, .params = params };
        }

        pub usingnamespace getty.Deserializer(
            *Self,
            Error,
            custom_dser,
            null,
            .{
                .deserializeBool = deserializeBool,
                .deserializeInt = deserializeInt,
                .deserializeEnum = deserializeEnum,
                .deserializeOptional = deserializeOptional,
                .deserializeVoid = deserializeVoid,
                .deserializeSeq = deserializeSeq,
            },
        );

        fn deserializeSeq(self: *Self, allocator: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            // var len = if (self.params.include_fixed_array_length) try self.deserializeInt(allocator, getty.de.blocks.Int.Visitor(u64)) else null;

            const tmp: @TypeOf(visitor).Value = undefined; // TODO: fix without stack alloc?
            const len = tmp.len;

            var s = SeqAccess(Self){ .d = self, .len = len };
            const result = try visitor.visitSeq(allocator.?, De, s.seqAccess());
            errdefer getty.de.free(allocator.?, De, result);

            return result;
        }

        pub fn deserializeVoid(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            _ = self;
            return try visitor.visitVoid(ally, De);
        }

        pub fn deserializeOptional(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            const byte = self.reader.readByte() catch {
                return Error.IO;
            };
            return switch (byte) {
                0 => try visitor.visitNull(ally, De),
                1 => try visitor.visitSome(ally, self.deserializer()),
                else => getty.de.Error.InvalidValue,
            };
        }

        pub fn deserializeEnum(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            const T = u32; // enum size
            const tag = switch (self.params.endian) {
                .Little => self.reader.readIntLittle(T),
                .Big => self.reader.readIntBig(T),
            } catch {
                return Error.IO;
            };
            return try visitor.visitInt(ally, De, tag);
        }

        pub fn deserializeInt(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            const T = @TypeOf(visitor).Value;

            const value = switch (self.params.endian) {
                .Little => self.reader.readIntLittle(T),
                .Big => self.reader.readIntBig(T),
            } catch {
                return Error.IO;
            };

            return try visitor.visitInt(ally, De, value);
        }

        pub fn deserializeBool(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            const byte = self.reader.readByte() catch {
                return Error.IO;
            };
            const value = switch (byte) {
                0 => false,
                1 => true,
                else => return getty.de.Error.InvalidValue,
            };

            return try visitor.visitBool(ally, De, value);
        }

        const custom_dser = struct {
            pub fn is(comptime T: type) bool {
                return switch (@typeInfo(T)) {
                    .Union => true,
                    .Struct => true,
                    .Pointer => |*info| {
                        // should never be called but compiler complains
                        if (info.size == .Many) {
                            return true;
                        }
                        return info.size == .Slice;
                    },
                    else => false,
                };
            }

            pub fn Visitor(comptime Value: type) type {
                return struct {
                    pub usingnamespace getty.de.Visitor(
                        @This(),
                        Value,
                        .{},
                    );
                };
            }

            pub fn free(
                allocator: std.mem.Allocator,
                comptime d: type,
                value: anytype,
            ) void {
                const T = @TypeOf(value);
                switch (@typeInfo(T)) {
                    .Union => |*info| {
                        inline for (info.fields) |field| {
                            if (value == @field(T, field.name)) {
                                return getty.de.free(allocator, d, @field(value, field.name));
                            }
                        }
                    },
                    .Struct => |*info| {
                        inline for (info.fields) |field| {
                            // std.debug.print("freeing {s} on {s}\n", .{ field.name, @typeName(T) });
                            if (get_field_config(T, field)) |config| {
                                if (config.free) |free_fcn| {
                                    // std.debug.print("found free fcn...\n", .{});
                                    var field_value = @field(value, field.name);
                                    switch (@typeInfo(field.type)) {
                                        .Pointer => |*field_info| {
                                            if (field_info.size == .Slice) {
                                                free_fcn(allocator, field_value);
                                                continue;
                                            }
                                        },
                                        else => {},
                                    }
                                    free_fcn(allocator, &field_value);
                                    continue;
                                }
                            }

                            if (!field.is_comptime) {
                                getty.de.free(allocator, d, @field(value, field.name));
                            }
                        }
                    },
                    .Pointer => |*info| {
                        if (info.size == .Many) {
                            unreachable;
                        }
                        std.debug.assert(info.size == .Slice);
                        for (value) |item| {
                            getty.de.free(allocator, d, item);
                        }
                        allocator.free(value);
                    },
                    else => {},
                }
            }

            pub fn deserialize(
                alloc: ?std.mem.Allocator,
                comptime T: type,
                dd: anytype,
                visitor: anytype,
            ) Error!@TypeOf(visitor).Value {
                switch (@typeInfo(T)) {
                    .Union => |*info| {
                        const tag_type = info.tag_type orelse @compileError("unions must have a tag type");
                        const raw_tag = try getty.deserialize(alloc, tag_type, dd);

                        inline for (info.fields) |field| {
                            if (raw_tag == @field(tag_type, field.name)) {
                                const payload = try getty.deserialize(alloc, field.type, dd);
                                return @unionInit(T, field.name, payload);
                            }
                        }
                        return getty.de.Error.InvalidValue;
                    },
                    .Struct => |*info| {
                        const reader = dd.context.reader;
                        const params = dd.context.params;
                        var data: T = undefined;

                        inline for (info.fields) |field| {
                            if (!field.is_comptime) {
                                if (get_field_config(T, field)) |config| {
                                    if (shouldUseDefaultValue(field, config)) |default_val| {
                                        @field(data, field.name) = @as(*const field.type, @ptrCast(@alignCast(default_val))).*;
                                        continue;
                                    }

                                    if (config.deserializer) |deser_fcn| {
                                        @field(data, field.name) = deser_fcn(alloc, reader, params) catch return getty.de.Error.InvalidValue;
                                        continue;
                                    }
                                }

                                @field(data, field.name) = try getty.deserialize(alloc, field.type, dd);
                            }
                        }
                        return data;
                    },
                    .Pointer => |*info| {
                        std.debug.assert(info.size == .Slice);

                        const len = try getty.deserialize(alloc, u64, dd);
                        const ally = alloc.?;

                        const entries = try ally.alloc(info.child, len);
                        errdefer ally.free(entries);

                        for (entries) |*entry| {
                            entry.* = try getty.deserialize(alloc, info.child, dd);
                        }

                        return entries;
                    },
                    else => unreachable,
                }
            }
        };

        fn SeqAccess(comptime D: type) type {
            return struct {
                d: *D,
                len: usize,
                idx: usize = 0,

                const Seq = @This();

                pub usingnamespace getty.de.SeqAccess(
                    *Seq,
                    Error,
                    .{ .nextElementSeed = nextElementSeed },
                );

                fn nextElementSeed(self: *Seq, ally: ?std.mem.Allocator, seed: anytype) Error!?@TypeOf(seed).Value {
                    if (self.idx == self.len) {
                        return null;
                    }
                    const element = try seed.deserialize(ally, self.d.deserializer());
                    self.idx += 1;

                    return element;
                }
            };
        }
    };
}

pub fn free(
    ally: std.mem.Allocator,
    v: anytype,
) void {
    const D = Deserializer(
        std.io.FixedBufferStream([]u8).Reader,
    );
    return getty.de.free(ally, D.De, v);
}

// for ref: https://github.com/getty-zig/json/blob/a5c4d9f996dc3f472267f6210c30f96c39da576b/src/ser/serializer.zig
pub fn serializer(w: anytype, params: Params) Serializer(@TypeOf(w)) {
    return Serializer(@TypeOf(w)).init(w, params);
}

pub fn Serializer(
    comptime Writer: type,
) type {
    return struct {
        writer: Writer,
        params: Params,

        const Self = @This();
        const Ok = void;
        const Error = getty.ser.Error || error{IO};

        pub fn init(w: Writer, params: Params) Self {
            std.debug.assert(params.int_encoding == .fixed);
            return .{ .writer = w, .params = params };
        }

        pub usingnamespace getty.Serializer(
            *Self,
            Ok,
            Error,
            custom_ser,
            null,
            null,
            Aggregate,
            null,
            .{
                .serializeBool = serializeBool,
                .serializeInt = serializeInt,
                .serializeEnum = serializeEnum,
                .serializeSome = serializeSome,
                .serializeNull = serializeNull,
                .serializeSeq = serializeSeq,
                .serializeVoid = serializeVoid,
            },
        );

        fn serializeSeq(self: *Self, len: ?usize) Error!Aggregate {
            if (self.params.include_fixed_array_length) {
                try self.serializeInt(@as(u64, len.?));
            }
            return try self.serializeMap(len);
        }

        fn serializeVoid(self: *Self) Error!Ok {
            _ = self;
        }

        fn serializeNull(self: *Self) Error!Ok {
            try (self.writer.writeByte(0) catch Error.IO);
        }

        fn serializeSome(self: *Self, value: anytype) Error!Ok {
            try (self.writer.writeByte(1) catch Error.IO);
            const ss = self.serializer();
            return try getty.serialize(null, value, ss);
        }

        fn serializeMap(self: *Self, len: ?usize) Error!Aggregate {
            _ = len;
            return Aggregate{ .ser = self };
        }

        fn serializeBool(self: *Self, value: bool) Error!Ok {
            try (self.writer.writeByte(@intFromBool(value)) catch Error.IO);
        }

        fn serializeInt(self: *Self, value: anytype) Error!Ok {
            const T = @TypeOf(value);
            switch (@typeInfo(T)) {
                .ComptimeInt => {
                    if (value < 0) {
                        @compileError("Signed comptime integers can not be serialized.");
                    }
                    try self.serializeInt(@as(u64, value));
                },
                .Int => |info| {
                    if ((info.bits & (info.bits - 1)) != 0 or info.bits < 8 or info.bits > 256) {
                        @compileError("Only i{8, 16, 32, 64, 128, 256}, u{8, 16, 32, 64, 128, 256} integers may be serialized, but attempted to serialize " ++ @typeName(T) ++ ".");
                    }

                    switch (self.params.int_encoding) {
                        .fixed => {
                            try (switch (self.params.endian) {
                                .Little => self.writer.writeIntLittle(T, value),
                                .Big => self.writer.writeIntBig(T, value),
                            } catch Error.IO);
                        },
                        else => unreachable,
                    }
                },
                else => {
                    unreachable;
                },
            }
        }

        fn serializeEnum(self: *Self, index: anytype, name: []const u8) Error!Ok {
            _ = name;
            switch (self.params.int_encoding) {
                .fixed => {
                    return try self.serializeInt(@as(u32, index));
                },
                .variable => {
                    unreachable;
                },
            }
        }

        const custom_ser = struct {
            pub fn is(comptime T: type) bool {
                return switch (@typeInfo(T)) {
                    .Union => true,
                    .Struct => true,
                    .Pointer => |*info| {
                        return info.size == .Slice;
                    },
                    else => false,
                };
            }

            pub fn serialize(alloc: ?std.mem.Allocator, value: anytype, ss: anytype) Error!Ok {
                const T = @TypeOf(value);
                switch (@typeInfo(T)) {
                    .Union => |*info| {
                        try getty.serialize(alloc, @as(u32, @intFromEnum(value)), ss);
                        inline for (info.fields) |field| {
                            if (value == @field(T, field.name)) {
                                return try getty.serialize(alloc, @field(value, field.name), ss);
                            }
                        }
                    },
                    .Struct => |*info| {
                        var params = ss.context.params;
                        var writer = ss.context.writer;

                        inline for (info.fields) |field| {
                            if (!field.is_comptime) {
                                if (get_field_config(T, field)) |config| {
                                    if (config.skip) {
                                        continue;
                                    }
                                    if (config.serializer) |ser_fcn| {
                                        ser_fcn(writer, @field(value, field.name), params) catch return Error.IO;
                                        continue;
                                    }
                                }

                                try getty.serialize(alloc, @field(value, field.name), ss);
                            }
                        }
                    },
                    .Pointer => |*info| {
                        std.debug.assert(info.size == .Slice);

                        try getty.serialize(alloc, @as(u64, value.len), ss);
                        for (value) |element| {
                            try getty.serialize(alloc, element, ss);
                        }
                    },
                    else => unreachable,
                }
            }
        };

        const Aggregate = struct {
            ser: *Self,

            const A = @This();

            pub usingnamespace getty.ser.Seq(
                *A,
                Ok,
                Error,
                .{
                    .serializeElement = serializeElement,
                    .end = end,
                },
            );

            fn serializeElement(self: *A, value: anytype) Error!Ok {
                const ss = self.ser.serializer();
                try getty.serialize(null, value, ss);
            }

            fn end(self: *A) Error!Ok {
                _ = self;
            }
        };
    };
}

// need this fn to define the return type T
pub fn DeserializeFunction(comptime T: type) type {
    return fn (alloc: ?std.mem.Allocator, reader: anytype, params: Params) anyerror!T;
}
pub const SerializeFunction = fn (writer: anytype, data: anytype, params: Params) anyerror!void;
pub const FreeFunction = fn (allocator: std.mem.Allocator, data: anytype) void;

// ** Field Functions ** //
pub fn FieldConfig(comptime T: type) type {
    return struct {
        deserializer: ?DeserializeFunction(T) = null,
        serializer: ?SerializeFunction = null,
        free: ?FreeFunction = null,
        skip: bool = false,
    };
}

pub fn get_field_config(comptime struct_type: type, comptime field: std.builtin.Type.StructField) ?FieldConfig(field.type) {
    const bincode_field = "!bincode-config:" ++ field.name;
    if (@hasDecl(struct_type, bincode_field)) {
        const config = @field(struct_type, bincode_field);
        return config;
    }
    return null;
}

pub inline fn shouldUseDefaultValue(comptime field: std.builtin.Type.StructField, comptime config: FieldConfig(field.type)) ?*const anyopaque {
    if (config.skip) {
        if (field.default_value == null) {
            const field_type_name = @typeName(field.type);
            @compileError("┓\n|\n|--> Invalid config: cannot skip field '" ++ field_type_name ++ "." ++ field.name ++ "' deserialization if no default value set\n\n");
        }
        return field.default_value;
    } else {
        return null;
    }
}

// ** Writer/Reader functions ** //
/// note: will fail if the slice is too small to hold the serialized data
pub fn writeToSlice(slice: []u8, data: anytype, params: Params) ![]u8 {
    var stream = std.io.fixedBufferStream(slice);
    var writer = stream.writer();

    var s = serializer(writer, params);
    const ss = s.serializer();

    try getty.serialize(null, data, ss);
    return stream.getWritten();
}

pub fn writeToArray(alloc: std.mem.Allocator, data: anytype, params: Params) !std.ArrayList(u8) {
    // var array_buf = try std.ArrayList(u8).initCapacity(alloc, @bitSizeOf(@TypeOf(data)));
    var array_buf = try std.ArrayList(u8).initCapacity(alloc, 2048);

    var s = serializer(array_buf.writer(), params);
    const ss = s.serializer();

    try getty.serialize(alloc, data, ss);

    return array_buf;
}

pub fn write(alloc: ?std.mem.Allocator, writer: anytype, data: anytype, params: Params) !void {
    var s = serializer(writer, params);
    const ss = s.serializer();
    try getty.serialize(alloc, data, ss);
}

pub fn get_serialized_size_with_slice(slice: []u8, data: anytype, params: Params) !usize {
    var ser_slice = try writeToSlice(slice, data, params);
    return ser_slice.len;
}

pub fn get_serialized_size(alloc: std.mem.Allocator, data: anytype, params: Params) !usize {
    var list = try writeToArray(alloc, data, params);
    defer list.deinit();

    return list.items.len;
}

// can call if dont require an allocator
pub fn readFromSlice(alloc: ?std.mem.Allocator, comptime T: type, slice: []const u8, params: Params) !T {
    var stream = std.io.fixedBufferStream(slice);
    var reader = stream.reader();
    var d = deserializer(reader, params);
    const dd = d.deserializer();
    const v = try getty.deserialize(alloc, T, dd);
    errdefer getty.de.free(alloc, @TypeOf(dd), v); // !

    return v;
}

pub fn read(alloc: ?std.mem.Allocator, comptime T: type, reader: anytype, params: Params) !T {
    var d = deserializer(reader, params);
    const dd = d.deserializer();
    const v = try getty.deserialize(alloc, T, dd);
    errdefer getty.de.free(alloc, @TypeOf(dd), v);

    return v;
}

// ** Tests **//
fn TestSliceConfig(comptime Child: type) FieldConfig([]Child) {
    const S = struct {
        fn deserialize_test_slice(allocator: ?std.mem.Allocator, reader: anytype, params: Params) ![]Child {
            var ally = allocator.?;
            var len = try bincode.read(ally, u16, reader, params);
            var elems = try ally.alloc(Child, len);
            for (0..len) |i| {
                elems[i] = try bincode.read(ally, Child, reader, params);
            }
            return elems;
        }

        pub fn serilaize_test_slice(writer: anytype, data: anytype, params: bincode.Params) !void {
            var len = std.math.cast(u16, data.len) orelse return error.DataTooLarge;
            try bincode.write(null, writer, len, params);
            for (data) |item| {
                try bincode.write(null, writer, item, params);
            }
            return;
        }
    };

    return FieldConfig([]Child){
        .serializer = S.serilaize_test_slice,
        .deserializer = S.deserialize_test_slice,
    };
}

test "bincode: custom field serialization" {
    const Foo = struct {
        accounts: []u8,
        txs: []u32,
        skip_me: u8 = 20,

        pub const @"!bincode-config:accounts" = TestSliceConfig(u8);
        pub const @"!bincode-config:txs" = TestSliceConfig(u32);
        pub const @"!bincode-config:skip_me" = FieldConfig(u8){
            .skip = true,
        };
    };

    var accounts = [_]u8{ 1, 2, 3 };
    var txs = [_]u32{ 1, 2, 3 };
    var foo = Foo{ .accounts = &accounts, .txs = &txs };

    var buf: [1000]u8 = undefined;
    var out = try writeToSlice(&buf, foo, Params{});
    std.debug.print("{any}", .{out});
    try std.testing.expect(out[out.len - 1] != 20); // skip worked

    var size = try get_serialized_size(std.testing.allocator, foo, Params{});
    try std.testing.expect(size > 0);

    var r = try readFromSlice(std.testing.allocator, Foo, out, Params{});
    defer free(std.testing.allocator, r);
    std.debug.print("{any}", .{r});

    try std.testing.expect(r.accounts.len == foo.accounts.len);
    try std.testing.expect(r.txs.len == foo.txs.len);
    try std.testing.expect(r.skip_me == 20);
}

test "bincode: test serialization" {
    var buf: [1]u8 = undefined;

    {
        var out = try writeToSlice(&buf, true, Params.standard);
        try std.testing.expect(out.len == 1);
        try std.testing.expect(out[0] == 1);
    }

    {
        var out = try readFromSlice(null, bool, &buf, Params{});
        try std.testing.expect(out == true);
    }

    {
        var out = try writeToSlice(&buf, false, Params.standard);
        try std.testing.expect(out.len == 1);
        try std.testing.expect(out[0] == 0);
    }

    var buf2: [8]u8 = undefined; // u64 default
    _ = try writeToSlice(&buf2, 300, Params.standard);

    var buf3: [4]u8 = undefined;
    var v: u32 = 200;
    _ = try writeToSlice(&buf3, v, Params.standard);

    {
        var out = try readFromSlice(null, u32, &buf3, Params{});
        try std.testing.expect(out == 200);
    }

    const Foo = enum { A, B };
    var out = try writeToSlice(&buf3, Foo.B, Params.standard);
    var e = [_]u8{ 1, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &e, out);

    var read_out = try readFromSlice(null, Foo, &buf3, Params{});
    try std.testing.expectEqual(read_out, Foo.B);

    const Foo2 = union(enum(u8)) { A: u32, B: u32, C: u32 };
    const expected = [_]u8{ 1, 0, 0, 0, 1, 1, 1, 1 };
    const value = Foo2{ .B = 16843009 };
    // Map keys
    // .A = 65 = 1000001 (7 bits)
    // .B = 66 = 1000010
    // .B = 67 = 1000011
    var out2 = try writeToSlice(&buf2, value, Params.standard);
    try std.testing.expectEqualSlices(u8, &expected, out2);

    var read_out2 = try readFromSlice(null, Foo2, &buf2, Params{});
    try std.testing.expectEqual(read_out2, value);

    const Bar = struct { a: u32, b: u32, c: Foo2 };
    const b = Bar{ .a = 65, .b = 66, .c = Foo2{ .B = 16843009 } };
    var buf4: [100]u8 = undefined;
    var out3 = try writeToSlice(&buf4, b, Params.standard);
    var expected2 = [_]u8{ 65, 0, 0, 0, 66, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1 };
    try std.testing.expectEqualSlices(u8, &expected2, out3);

    const s = struct {
        a: u32,
        b: ?u16,
        c: Bar,
    };
    const _s = s{
        .a = 65,
        .b = null,
        .c = Bar{ .a = 66, .b = 67, .c = Foo2{ .B = 16843009 } },
    };
    var buf6: [100]u8 = undefined;
    var out4 = try writeToSlice(&buf6, _s, Params.standard);
    var result = try readFromSlice(null, s, out4, Params{});
    try std.testing.expectEqual(result, _s);

    // ensure write to array works too
    var array_buf = try writeToArray(std.testing.allocator, _s, Params.standard);
    defer array_buf.deinit();
    try std.testing.expectEqualSlices(u8, out4, array_buf.items);
}

test "bincode: (legacy) serialize an array" {
    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    const Foo = struct {
        first: u8,
        second: u8,
    };

    try bincode.write(null, buffer.writer(), [_]Foo{
        .{ .first = 10, .second = 20 },
        .{ .first = 30, .second = 40 },
    }, bincode.Params.legacy);

    try testing.expectEqualSlices(u8, &[_]u8{
        2, 0, 0, 0, 0, 0, 0, 0, // Length of the array
        10, 20, // First Foo
        30, 40, // Second Foo
    }, buffer.items);
}

test "bincode: serialize and deserialize" {
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    inline for (.{bincode.Params.standard}) |params| {
        inline for (.{
            @as(i8, std.math.minInt(i8)),
            @as(i16, std.math.minInt(i16)),
            @as(i32, std.math.minInt(i32)),
            @as(i64, std.math.minInt(i64)),
            @as(usize, std.math.minInt(usize)),
            @as(isize, std.math.minInt(isize)),
            @as(i8, std.math.maxInt(i8)),
            @as(i16, std.math.maxInt(i16)),
            @as(i32, std.math.maxInt(i32)),
            @as(i64, std.math.maxInt(i64)),
            @as(u8, std.math.maxInt(u8)),
            @as(u16, std.math.maxInt(u16)),
            @as(u32, std.math.maxInt(u32)),
            @as(u64, std.math.maxInt(u64)),
            @as(usize, std.math.maxInt(usize)),
            @as(isize, std.math.maxInt(isize)),

            // @as(f32, std.math.floatMin(f32)),
            // @as(f64, std.math.floatMin(f64)),
            // @as(f32, std.math.floatMax(f32)),
            // @as(f64, std.math.floatMax(f64)),

            [_]u8{ 0, 1, 2, 3 },
        }) |expected| {
            try bincode.write(null, buffer.writer(), expected, params);

            const actual = try bincode.readFromSlice(testing.allocator, @TypeOf(expected), buffer.items, params);
            defer bincode.free(testing.allocator, actual);

            try testing.expectEqual(expected, actual);
            buffer.clearRetainingCapacity();
        }
    }

    inline for (.{bincode.Params.standard}) |params| {
        inline for (.{
            @as([]const u8, "hello world"),
        }) |expected| {
            try bincode.write(null, buffer.writer(), expected, params);

            const actual = try bincode.readFromSlice(testing.allocator, @TypeOf(expected), buffer.items, params);
            defer bincode.free(testing.allocator, actual);

            try testing.expectEqualSlices(std.meta.Elem(@TypeOf(expected)), expected, actual);
            buffer.clearRetainingCapacity();
        }
    }
}
