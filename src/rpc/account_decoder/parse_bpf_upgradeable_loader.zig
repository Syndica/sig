/// Types for parsing BPF upgradeable loader accounts for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_bpf_loader.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const account_decoder = @import("lib.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const State = sig.runtime.program.bpf_loader.v3.State;
const ParseError = account_decoder.ParseError;

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_bpf_loader.rs#L13
pub fn parseBpfUpgradeableLoader(
    allocator: Allocator,
    // std.io.Reader
    reader: anytype,
    data_len: u32,
) ParseError!BpfUpgradeableLoaderAccountType {
    const discriminant = reader.readInt(u32, .little) catch return ParseError.InvalidAccountData;
    return switch (discriminant) {
        0 => .uninitialized,
        1 => blk: {
            // Buffer: Option<Pubkey> authority + bytecode
            const maybe_authority = readOptionPubkey(reader) catch return ParseError.InvalidAccountData;
            // Buffer size: enum tag (u32) + option tag (1 byte) + optionally pubkey (32 bytes)
            const metadata_size: u32 = @sizeOf(u32) + 1 + if (maybe_authority != null) @as(u32, Pubkey.SIZE) else 0;
            const bytecode = readRemainingBytes(
                allocator,
                reader,
                data_len,
                metadata_size,
            ) catch return ParseError.InvalidAccountData;
            break :blk .{
                .buffer = UiBuffer{
                    .maybe_authority = if (maybe_authority) |authority| authority.base58String() else null,
                    .bytecode = bytecode,
                },
            };
        },
        2 => blk: {
            // Program: Pubkey programdata_address
            const programdata_address = readPubkey(reader) catch return ParseError.InvalidAccountData;
            break :blk .{
                .program = UiProgram{
                    .programdata_address = programdata_address.base58String(),
                },
            };
        },
        3 => blk: {
            // ProgramData: u64 slot + Option<Pubkey> upgrade_authority + bytecode
            const slot = reader.readInt(u64, .little) catch return ParseError.InvalidAccountData;
            const maybe_upgrade_authority = readOptionPubkey(reader) catch return ParseError.InvalidAccountData;
            // ProgramData size: enum tag (u32) + slot (u64) + option tag (1 byte) + optionally pubkey (32 bytes)
            const metadata_size: u32 = @sizeOf(u32) + @sizeOf(u64) + 1 + if (maybe_upgrade_authority != null) @as(u32, Pubkey.SIZE) else 0;
            const bytecode = readRemainingBytes(
                allocator,
                reader,
                data_len,
                metadata_size,
            ) catch return ParseError.InvalidAccountData;
            break :blk .{
                .program_data = UiProgramData{
                    .slot = slot,
                    .maybe_upgrade_authority = if (maybe_upgrade_authority) |auth| auth.base58String() else null,
                    .bytecode = bytecode,
                },
            };
        },
        else => return ParseError.InvalidAccountData,
    };
}

// TODO: do we need this? does reader provide a typed read?
fn readPubkey(reader: anytype) !Pubkey {
    var bytes: [Pubkey.SIZE]u8 = undefined;
    const n = try reader.readAll(&bytes);
    if (n != Pubkey.SIZE) return error.EndOfStream;
    return Pubkey{ .data = bytes };
}

fn readOptionPubkey(reader: anytype) !?Pubkey {
    const tag = try reader.readByte();
    return switch (tag) {
        0 => null,
        1 => try readPubkey(reader),
        else => error.InvalidData,
    };
}

fn readRemainingBytes(
    allocator: Allocator,
    reader: anytype,
    data_len: u32,
    metadata_size: usize,
) ![]const u8 {
    if (data_len < metadata_size) return error.InvalidData;
    const bytecode_len = data_len - metadata_size;
    if (bytecode_len == 0) return &.{};
    const bytecode = allocator.alloc(u8, bytecode_len) catch return error.OutOfMemory;
    const n = reader.readAll(bytecode) catch return error.InvalidData;
    if (n != bytecode_len) return error.InvalidData;
    return bytecode;
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_bpf_loader.rs#L68-L73
pub const BpfUpgradeableLoaderAccountType = union(enum) {
    uninitialized,
    buffer: UiBuffer,
    program: UiProgram,
    program_data: UiProgramData,
    pub fn jsonStringify(self: BpfUpgradeableLoaderAccountType, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            .uninitialized => try jw.write("uninitialized"),
            .buffer => |buffer| {
                try jw.write("buffer");
                try jw.objectField("info");
                try buffer.jsonStringify(jw);
            },
            .program => |program| {
                try jw.write("program");
                try jw.objectField("info");
                try program.jsonStringify(jw);
            },
            .program_data => |program_data| {
                try jw.write("programData");
                try jw.objectField("info");
                try program_data.jsonStringify(jw);
            },
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_bpf_loader.rs#L77-L80
pub const UiBuffer = struct {
    maybe_authority: ?Pubkey.Base58String,
    bytecode: []const u8,
    pub fn jsonStringify(self: UiBuffer, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        // Skip authority if null (matches Agave's skip_serializing_if)
        if (self.maybe_authority) |authority| {
            try jw.objectField("authority");
            try jw.write(authority.slice());
        }
        try jw.objectField("data");
        try writeBase64DataTuple(jw, self.bytecode);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_bpf_loader.rs#L84-L86
pub const UiProgram = struct {
    programdata_address: Pubkey.Base58String,
    pub fn jsonStringify(self: UiProgram, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("programData");
        try jw.write(self.programdata_address.slice());
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_bpf_loader.rs#L90-L95
pub const UiProgramData = struct {
    slot: u64,
    maybe_upgrade_authority: ?Pubkey.Base58String,
    bytecode: []const u8,
    pub fn jsonStringify(self: UiProgramData, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("slot");
        try jw.write(self.slot);
        // Skip authority if null (matches Agave's skip_serializing_if)
        if (self.maybe_upgrade_authority) |authority| {
            try jw.objectField("authority");
            try jw.write(authority.slice());
        }
        try jw.objectField("data");
        try writeBase64DataTuple(jw, self.bytecode);
        try jw.endObject();
    }
};

/// Writes a ["<base64>", "base64"] tuple, streaming the base64 encoding directly to the JSON writer.
/// Weird, but to conform with Agave response format.
fn writeBase64DataTuple(jw: anytype, bytecode: []const u8) @TypeOf(jw.*).Error!void {
    try jw.beginArray();
    // Stream base64-encoded bytecode directly to underlying writer
    try jw.beginWriteRaw();
    try jw.stream.writeByte('"');
    var base64_stream = sig.utils.base64.EncodingStream.init(std.base64.standard.Encoder);
    const ctx = base64_stream.writerCtx(jw.stream);
    try ctx.writer().writeAll(bytecode);
    try ctx.flush();
    try jw.stream.writeByte('"');
    jw.endWriteRaw();
    // Second element: encoding type
    try jw.write("base64");
    try jw.endArray();
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_bpf_loader.rs#L97
test "rpc.account_decoder.parse_bpf_upgradeable_loader: parse accounts" {
    const allocator = std.testing.allocator;

    // Unitialized
    {
        const state = State.uninitialized;
        const serialized = try sig.bincode.writeAlloc(allocator, state, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseBpfUpgradeableLoader(
            allocator,
            &stream.reader(),
            @intCast(serialized.len),
        );

        try std.testing.expectEqual(
            BpfUpgradeableLoaderAccountType.uninitialized,
            result,
        );
    }

    // Buffer with authority and bytecode
    {
        const authority = Pubkey{ .data = [_]u8{1} ** 32 };
        const program_bytecode = [_]u8{7} ** 64;
        const state = State{ .buffer = .{ .authority_address = authority } };
        const metadata = try sig.bincode.writeAlloc(allocator, state, .{});
        defer allocator.free(metadata);

        // Combine metadata + bytecode
        const full_data = try allocator.alloc(u8, metadata.len + program_bytecode.len);
        defer allocator.free(full_data);

        @memcpy(full_data[0..metadata.len], metadata);
        @memcpy(full_data[metadata.len..], &program_bytecode);
        var stream = std.io.fixedBufferStream(full_data);
        const result = try parseBpfUpgradeableLoader(allocator, stream.reader(), @intCast(full_data.len));
        defer allocator.free(result.buffer.bytecode);

        try std.testing.expect(result == .buffer);
        try std.testing.expectEqualStrings(
            authority.base58String().slice(),
            result.buffer.maybe_authority.?.slice(),
        );
        try std.testing.expectEqualSlices(u8, &program_bytecode, result.buffer.bytecode);
    }

    // Buffer without authority
    {
        const program_bytecode = [_]u8{7} ** 64;
        const state = State{ .buffer = .{ .authority_address = null } };
        const metadata = try sig.bincode.writeAlloc(allocator, state, .{});
        defer allocator.free(metadata);

        const full_data = try allocator.alloc(u8, metadata.len + program_bytecode.len);
        defer allocator.free(full_data);

        @memcpy(full_data[0..metadata.len], metadata);
        @memcpy(full_data[metadata.len..], &program_bytecode);
        var stream = std.io.fixedBufferStream(full_data);
        const result = try parseBpfUpgradeableLoader(allocator, stream.reader(), @intCast(full_data.len));

        defer allocator.free(result.buffer.bytecode);
        try std.testing.expect(result == .buffer);
        try std.testing.expect(result.buffer.maybe_authority == null);
        try std.testing.expectEqualSlices(u8, &program_bytecode, result.buffer.bytecode);
    }

    // Program
    {
        const programdata_address = Pubkey{ .data = [_]u8{42} ** 32 };
        const state = State{ .program = .{ .programdata_address = programdata_address } };
        const serialized = try sig.bincode.writeAlloc(allocator, state, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseBpfUpgradeableLoader(allocator, stream.reader(), @intCast(serialized.len));

        try std.testing.expect(result == .program);
        try std.testing.expectEqualStrings(
            programdata_address.base58String().slice(),
            result.program.programdata_address.slice(),
        );
    }

    // ProgramData with authority
    {
        const authority = Pubkey{ .data = [_]u8{99} ** 32 };
        const slot: u64 = 42;
        const program_bytecode = [_]u8{7} ** 64;
        const state = State{ .program_data = .{
            .slot = slot,
            .upgrade_authority_address = authority,
        } };

        const metadata = try sig.bincode.writeAlloc(allocator, state, .{});
        defer allocator.free(metadata);

        const full_data = try allocator.alloc(u8, metadata.len + program_bytecode.len);
        defer allocator.free(full_data);

        @memcpy(full_data[0..metadata.len], metadata);
        @memcpy(full_data[metadata.len..], &program_bytecode);
        var stream = std.io.fixedBufferStream(full_data);
        const result = try parseBpfUpgradeableLoader(allocator, stream.reader(), @intCast(full_data.len));
        defer allocator.free(result.program_data.bytecode);

        try std.testing.expect(result == .program_data);
        try std.testing.expectEqual(slot, result.program_data.slot);
        try std.testing.expectEqualStrings(
            authority.base58String().slice(),
            result.program_data.maybe_upgrade_authority.?.slice(),
        );
        try std.testing.expectEqualSlices(u8, &program_bytecode, result.program_data.bytecode);
    }

    // ProgramData without authority
    {
        const slot: u64 = 42;
        const program_bytecode = [_]u8{7} ** 64;
        const state = State{ .program_data = .{
            .slot = slot,
            .upgrade_authority_address = null,
        } };

        const metadata = try sig.bincode.writeAlloc(allocator, state, .{});
        defer allocator.free(metadata);

        const full_data = try allocator.alloc(u8, metadata.len + program_bytecode.len);
        defer allocator.free(full_data);

        @memcpy(full_data[0..metadata.len], metadata);
        @memcpy(full_data[metadata.len..], &program_bytecode);
        var stream = std.io.fixedBufferStream(full_data);

        const result = try parseBpfUpgradeableLoader(allocator, stream.reader(), @intCast(full_data.len));
        defer allocator.free(result.program_data.bytecode);

        try std.testing.expect(result == .program_data);
        try std.testing.expectEqual(slot, result.program_data.slot);
        try std.testing.expect(result.program_data.maybe_upgrade_authority == null);
        try std.testing.expectEqualSlices(u8, &program_bytecode, result.program_data.bytecode);
    }
}
