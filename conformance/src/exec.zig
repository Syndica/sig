const std = @import("std");

const Allocator = std.mem.Allocator;

pub const output_buffer_size: usize = 128 * 1024 * 1024;

pub const TestResult = enum { pass, mismatch, bad_status, missing_entrypoint };

pub const ExecError = @typeInfo(
    @typeInfo(@TypeOf(execFixture)).@"fn".return_type.?,
).error_union.error_set;

pub fn execFixture(
    allocator: Allocator,
    lib: *Library,
    input_path: []const u8,
    out_buf: []u8,
) !TestResult {
    const data = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(data);

    const fixture = try parseFixture(data);

    const entrypoint = try lib.get(allocator, fixture.entrypoint) orelse return .missing_entrypoint;

    var out_sz: u64 = @intCast(out_buf.len);
    const status = entrypoint(
        out_buf.ptr,
        &out_sz,
        fixture.input.ptr,
        @intCast(fixture.input.len),
    );
    if (status == 0) return .bad_status;
    if (out_sz > out_buf.len) return error.OutputBufferTooSmall;

    const actual = out_buf[0..@intCast(out_sz)];

    const expected = fixture.expected;
    return if (std.mem.eql(u8, actual, expected)) .pass else .mismatch;
}

pub const DirectoryRunStats = struct {
    fix_paths: []const []const u8,
    results: []const TestResult,
};

pub fn execDir(allocator: Allocator, lib: *Library, input_dir_path: []const u8) !DirectoryRunStats {
    var fix_paths: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (fix_paths.items) |input_path| allocator.free(input_path);
        fix_paths.deinit(allocator);
    }

    var dir = try std.fs.cwd().openDir(input_dir_path, .{ .iterate = true });
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".fix")) continue;
        const input_path = try std.fs.path.join(allocator, &.{ input_dir_path, entry.path });
        errdefer allocator.free(input_path);
        try fix_paths.append(allocator, input_path);
    }

    var rng = std.Random.DefaultPrng.init(0);
    rng.random().shuffle([]const u8, fix_paths.items); // distribute work more evenly

    if (fix_paths.items.len == 0) return error.NoFixtureFiles;

    const thread_count = @max(1, @min(fix_paths.items.len, try std.Thread.getCpuCount()));
    const threads = try allocator.alloc(std.Thread, thread_count);
    defer allocator.free(threads);

    const errors = try allocator.alloc(?ExecError, thread_count);
    defer allocator.free(errors);
    for (errors) |*slot| slot.* = null;

    const results = try allocator.alloc(TestResult, fix_paths.items.len);
    errdefer allocator.free(results);

    const base_chunk_size = fix_paths.items.len / thread_count;
    const remainder = fix_paths.items.len % thread_count;
    var start_index: usize = 0;

    for (threads, 0..) |*thread, i| {
        const end_index = start_index + base_chunk_size + @intFromBool(i < remainder);
        thread.* = try std.Thread.spawn(.{}, execMany, .{
            allocator,
            lib,
            fix_paths.items[start_index..end_index],
            results[start_index..end_index],
            &errors[i],
        });
        start_index = end_index;
    }

    for (threads) |thread| thread.join();
    for (errors) |err| if (err) |e| return e;

    return .{
        .fix_paths = try fix_paths.toOwnedSlice(allocator),
        .results = results,
    };
}

fn execMany(
    allocator: Allocator,
    lib: *Library,
    fix_paths: []const []const u8,
    results: []TestResult,
    err: *?ExecError,
) void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();

    const out_buf = allocator.alloc(u8, output_buffer_size) catch @panic("oom");
    defer allocator.free(out_buf);

    for (fix_paths, results) |input, *result_entry| {
        defer _ = arena.reset(.retain_capacity);
        result_entry.* = execFixture(arena.allocator(), lib, input, out_buf) catch |e| {
            err.* = e;
            return;
        };
    }
}

const EntryPoint = *const fn (
    out: [*]u8,
    out_sz: *u64,
    input: [*]const u8,
    in_sz: u64,
) callconv(.c) i32;

pub const Library = union(enum) {
    dyn: std.DynLib,
    map: *const std.StaticStringMap(EntryPoint),

    fn get(self: *Library, allocator: Allocator, name: []const u8) !?EntryPoint {
        return switch (self.*) {
            .dyn => |*lib| {
                const entrypoint_z = try allocator.dupeZ(u8, name);
                defer allocator.free(entrypoint_z);
                return lib.lookup(EntryPoint, entrypoint_z) orelse return null;
            },
            .map => |*map| map.*.get(name),
        };
    }
};

const Fixture = struct {
    input: []const u8,
    entrypoint: []const u8,
    expected: []const u8,
};

fn parseFixture(data: []const u8) !Fixture {
    const metadata = try extractProtobufField(data, 1) orelse return error.NoMetadata;
    return .{
        .input = try extractProtobufField(data, 2) orelse return error.NoInput,
        .expected = try extractProtobufField(data, 3) orelse return error.NoExpected,
        .entrypoint = try extractProtobufField(metadata, 1) orelse return error.NoEntrypoint,
    };
}

fn extractProtobufField(message: []const u8, wanted_field: u64) !?[]const u8 {
    var index: usize = 0;
    while (index < message.len) {
        const key = try readVarint(message, &index);
        const field_number = key >> 3;
        const wire_type = key & 0x07;

        switch (wire_type) {
            0 => _ = try readVarint(message, &index),
            1 => {
                if (message.len - index < 8) return error.TruncatedField;
                index += 8;
            },
            2 => {
                const len_u64 = try readVarint(message, &index);
                if (len_u64 > std.math.maxInt(usize)) return error.FieldTooLarge;
                const len: usize = @intCast(len_u64);
                if (len > message.len - index) return error.TruncatedField;
                if (field_number == wanted_field) return message[index .. index + len]; // found it
                index += len;
            },
            5 => {
                if (message.len - index < 4) return error.TruncatedField;
                index += 4;
            },
            else => return error.UnsupportedProtobufType,
        }
    }
    return null;
}

fn readVarint(message: []const u8, index: *usize) !u64 {
    var value: u64 = 0;
    var shift: u32 = 0;

    while (index.* < message.len and shift < 64) {
        const byte = message[index.*];
        index.* += 1;
        value |= @as(u64, byte & 0x7f) << @as(u6, @intCast(shift));
        if ((byte & 0x80) == 0) {
            return value;
        }
        shift += 7;
    }

    return error.InvalidVarint;
}
