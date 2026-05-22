const std = @import("std");

const Allocator = std.mem.Allocator;

pub const output_buffer_size: usize = 128 * 1024 * 1024;

pub const TestResult = enum { pass, mismatch, bad_status, missing_entrypoint };

pub const ExecError = @typeInfo(
    @typeInfo(@TypeOf(execFixture)).@"fn".return_type.?,
).error_union.error_set;

pub fn execFixture(
    allocator: Allocator,
    report_allocator: ?Allocator,
    lib: *Library,
    input_path: []const u8,
    out_buf: []u8,
    failure: ?*?ResultDetail,
) !TestResult {
    const data = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(data);

    const fixture = try parseFixture(data);

    const entrypoint = try lib.get(allocator, fixture.entrypoint) orelse {
        if (failure) |detail| detail.* = try toResultDetail(report_allocator.?, fixture, null);
        return .missing_entrypoint;
    };

    var out_sz: u64 = @intCast(out_buf.len);
    const status = entrypoint(
        out_buf.ptr,
        &out_sz,
        fixture.input.ptr,
        @intCast(fixture.input.len),
    );
    if (status == 0) {
        if (failure) |detail| detail.* = try toResultDetail(report_allocator.?, fixture, null);
        return .bad_status;
    }
    if (out_sz > out_buf.len) return error.OutputBufferTooSmall;

    const actual = out_buf[0..@intCast(out_sz)];

    const expected = fixture.expected;
    if (failure) |detail| detail.* = try toResultDetail(report_allocator.?, fixture, actual);
    if (std.mem.eql(u8, actual, expected)) return .pass;
    return .mismatch;
}

const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const protobuf = @import("protobuf");

pub const ResultDetail = union(enum) {
    elf_loader: Fields(pb.ELFLoaderEffects),
    instr: Fields(pb.InstrEffects),
    syscall: Fields(pb.SyscallEffects),
    txn: Fields(pb.TxnResult),
    unknown: Fields([]const u8),

    pub fn jsonStringify(self: *const @This(), jws: anytype) !void {
        return switch (self.*) {
            inline else => |value| writeJson(value, jws, null) catch error.WriteFailed,
        };
    }

    fn Fields(comptime Output: type) type {
        return struct {
            harness: []const u8,
            expected: Output,
            actual: ?Output,

            pub const _desc_table = .{
                .harness = protobuf.fd(1, .{ .scalar = .string }),
                .expected = protobuf.fd(1, .{ .scalar = .bytes }),
                .actual = protobuf.fd(2, .{ .scalar = .bytes }),
            };
        };
    }
};

fn toResultDetail(allocator: Allocator, fixture: Fixture, actual: ?[]const u8) !ResultDetail {
    return if (std.mem.eql(u8, "sol_compat_instr_execute_v1", fixture.entrypoint))
        toResultDetailTyped("instr", pb.InstrEffects, allocator, fixture, actual)
    else if (std.mem.eql(u8, "sol_compat_vm_interp_v1", fixture.entrypoint))
        toResultDetailTyped("syscall", pb.SyscallEffects, allocator, fixture, actual)
    else if (std.mem.eql(u8, "sol_compat_vm_cpi_syscall_v1", fixture.entrypoint))
        toResultDetailTyped("syscall", pb.SyscallEffects, allocator, fixture, actual)
    else if (std.mem.eql(u8, "sol_compat_vm_syscall_execute_v1", fixture.entrypoint))
        toResultDetailTyped("syscall", pb.SyscallEffects, allocator, fixture, actual)
    else if (std.mem.eql(u8, "sol_compat_elf_loader_v1", fixture.entrypoint))
        toResultDetailTyped("elf_loader", pb.ELFLoaderEffects, allocator, fixture, actual)
    else if (std.mem.eql(u8, "sol_compat_txn_execute_v1", fixture.entrypoint))
        toResultDetailTyped("txn", pb.TxnResult, allocator, fixture, actual)
    else
        .{ .unknown = .{
            .harness = try allocator.dupe(u8, fixture.entrypoint),
            .expected = try allocator.dupe(u8, fixture.expected),
            .actual = if (actual) |bytes| try allocator.dupe(u8, bytes) else null,
        } };
}

fn toResultDetailTyped(
    comptime tag: []const u8,
    comptime Output: type,
    allocator: Allocator,
    fixture: Fixture,
    actual: ?[]const u8,
) !ResultDetail {
    var expected_reader = std.Io.Reader.fixed(fixture.expected);

    var expected_typed = try Output.decode(&expected_reader, allocator);
    errdefer expected_typed.deinit(allocator);

    var actual_typed: ?Output = null;
    if (actual) |bytes| {
        var actual_reader = std.Io.Reader.fixed(bytes);
        actual_typed = try Output.decode(&actual_reader, allocator);
    }
    errdefer if (actual_typed) |*value| value.deinit(allocator);

    const harness_name = try allocator.dupe(u8, fixture.entrypoint);

    return @unionInit(ResultDetail, tag, .{
        .harness = harness_name,
        .expected = expected_typed,
        .actual = actual_typed,
    });
}

pub fn writeJson(v: anytype, jws: anytype, comptime ftype: ?protobuf.FieldType) !void {
    const T = @TypeOf(v);
    if (T == []const u8) {
        if (ftype.?.scalar == .string) {
            try jws.write(v);
        } else if (v.len <= 512) {
            try jws.beginWriteRaw();
            defer jws.endWriteRaw();
            try jws.writer.writeByte('"');
            try std.base64.standard.Encoder.encodeWriter(jws.writer, v);
            try jws.writer.writeByte('"');
        } else {
            var hash: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(v, &hash, .{});
            const hash_hex = std.fmt.bytesToHex(hash, .lower);
            var buf: [128]u8 = @splat(0);
            const s = try std.fmt.bufPrint(&buf, "len: {d}, sha256: {s}", .{ v.len, hash_hex });
            try jws.beginWriteRaw();
            defer jws.endWriteRaw();
            try std.json.Stringify.encodeJsonString(s, jws.options, jws.writer);
        }
    } else switch (@typeInfo(T)) {
        .optional => if (v) |value| try writeJson(value, jws, ftype) else try jws.write(v),
        .@"struct" => |s| {
            try jws.beginObject();
            inline for (s.fields) |field| {
                const value = @field(v, field.name);
                try jws.objectField(field.name);
                if (@typeInfo(field.type) == .@"struct" and
                    @hasField(field.type, "items") and @hasField(field.type, "capacity"))
                {
                    try jws.beginArray();
                    for (value.items) |*account| try writeJson(account.*, jws, null);
                    try jws.endArray();
                } else try writeJson(value, jws, @field(T._desc_table, field.name).ftype);
            }
            try jws.endObject();
        },

        else => try jws.write(v),
    }
}

pub const DirectoryRunStats = struct {
    fix_paths: []const []const u8,
    results: []const TestResult,
    details: ?[]?ResultDetail = null,

    pub fn deinit(self: *DirectoryRunStats, allocator: Allocator) void {
        for (self.fix_paths) |input_path| allocator.free(input_path);
        allocator.free(self.fix_paths);
        allocator.free(self.results);
    }
};

pub fn execDir(
    allocator: Allocator,
    report_allocator: ?Allocator,
    lib: *Library,
    input_dir_path: []const u8,
) !DirectoryRunStats {
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

    const details = if (report_allocator) |failure_allocator|
        try failure_allocator.alloc(?ResultDetail, fix_paths.items.len)
    else
        null;
    if (details) |failure_details| @memset(failure_details, null);

    const base_chunk_size = fix_paths.items.len / thread_count;
    const remainder = fix_paths.items.len % thread_count;
    var start_index: usize = 0;

    for (threads, 0..) |*thread, i| {
        const end_index = start_index + base_chunk_size + @intFromBool(i < remainder);
        thread.* = try std.Thread.spawn(.{}, execMany, .{
            allocator,
            report_allocator,
            lib,
            fix_paths.items[start_index..end_index],
            results[start_index..end_index],
            if (details) |failure_details| failure_details[start_index..end_index] else null,
            &errors[i],
        });
        start_index = end_index;
    }

    for (threads) |thread| thread.join();
    for (errors) |err| if (err) |e| return e;

    return .{
        .fix_paths = try fix_paths.toOwnedSlice(allocator),
        .results = results,
        .details = details,
    };
}

fn execMany(
    allocator: Allocator,
    report_allocator: ?Allocator,
    lib: *Library,
    fix_paths: []const []const u8,
    results: []TestResult,
    details: ?[]?ResultDetail,
    err: *?ExecError,
) void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();

    const out_buf = allocator.alloc(u8, output_buffer_size) catch @panic("oom");
    defer allocator.free(out_buf);

    for (fix_paths, results, 0..) |input, *result_entry, i| {
        defer _ = arena.reset(.retain_capacity);
        result_entry.* = execFixture(
            arena.allocator(),
            report_allocator,
            lib,
            input,
            out_buf,
            if (details) |failure_details| &failure_details[i] else null,
        ) catch |e| {
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
