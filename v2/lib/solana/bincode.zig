//! Types and encoders/decoders for protocol-defined data using bincode

const std = @import("std");
const bk = @import("binkode");
const lib = @import("../lib.zig");

const Pubkey = lib.solana.Pubkey;
const Signature = lib.solana.Signature;
const Hash = lib.solana.Hash;

pub const Entry = struct {
    num_hashes: u64,
    hash: Hash,
    transactions: []VersionedTransaction,

    pub const bk_config: bk.Codec(Entry) = .standard(.tuple(.{
        .num_hashes = .fixint,
        .hash = .from(hash_codec),
        .transactions = .sliceNonStd(VersionedTransaction.bk_config),
    }));
};

// For slices that have a compact_u16 length rather than a u64
pub fn shortVec(comptime Element: type, element: bk.Codec(Element)) bk.Codec([]Element) {
    return .standard(.sliceWithLenNonStd(u16, compact_u16, element));
}

test shortVec {
    const short_vec_u8 = shortVec(u8, bk.StdCodec(u8).fixint.codec);

    // 1-byte compact_u16 len (=3), followed by payload
    {
        const expected_bytes = &[_]u8{ 0x03, 0xAA, 0xBB, 0xCC };
        var reader = std.io.Reader.fixed(expected_bytes);
        const decoded = try short_vec_u8.decode(&reader, std.testing.allocator, .default, null);
        defer std.testing.allocator.free(decoded);
        try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB, 0xCC }, decoded);
    }

    // no data
    {
        const expected_bytes = &[_]u8{0x00};
        var reader = std.io.Reader.fixed(expected_bytes);
        const decoded = try short_vec_u8.decode(&reader, std.testing.allocator, .default, null);
        defer std.testing.allocator.free(decoded);
        try std.testing.expectEqual(@as(usize, 0), decoded.len);
    }

    // 128-len (2-byte length prefix)
    {
        const buf: [130]u8 = @as([2]u8, .{ 0x80, 0x01 }) ++ @as([128]u8, @splat(0x50));
        var reader = std.io.Reader.fixed(&buf);
        const decoded = try short_vec_u8.decode(&reader, std.testing.allocator, .default, null);
        defer std.testing.allocator.free(decoded);
        try std.testing.expectEqual(@as(usize, 128), decoded.len);
        try std.testing.expectEqualSlices(u8, &@as([128]u8, @splat(0x50)), decoded);
    }
}

const hash_codec: bk.Codec(Hash) = .standard(.tuple(.{
    .data = .array(.fixint),
}));

const pubkey_codec: bk.Codec(Pubkey) = .standard(.tuple(.{
    .data = .array(.fixint),
}));

const MessageHeader = struct {
    num_required_signatures: u8,
    num_readonly_signed_accounts: u8,
    num_readonly_unsigned_accounts: u8,

    const bk_config: bk.Codec(MessageHeader) = .standard(.tuple(.{
        .num_required_signatures = .fixint,
        .num_readonly_signed_accounts = .fixint,
        .num_readonly_unsigned_accounts = .fixint,
    }));
};

const CompiledInstruction = struct {
    program_id_index: u8,
    accounts: []u8,
    data: []u8,

    const bk_config: bk.Codec(CompiledInstruction) = .standard(.tuple(.{
        .program_id_index = .fixint,
        .accounts = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
        .data = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
    }));
};

const AddressLookup = struct {
    account_key: Pubkey,
    writable_indexes: []u8,
    readonly_indexes: []u8,

    const bk_config: bk.Codec(AddressLookup) = .standard(.tuple(.{
        .account_key = .from(pubkey_codec),
        .writable_indexes = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
        .readonly_indexes = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
    }));
};

const LegacyMessage = struct {
    header: MessageHeader,
    account_keys: []Pubkey,
    recent_blockhash: Hash,
    instructions: []CompiledInstruction,

    const bk_config: bk.Codec(LegacyMessage) = .standard(.tuple(.{
        .header = .from(MessageHeader.bk_config),
        .account_keys = .from(shortVec(Pubkey, pubkey_codec)),
        .recent_blockhash = .from(hash_codec),
        .instructions = .from(shortVec(CompiledInstruction, CompiledInstruction.bk_config)),
    }));
};

const V0Message = struct {
    header: MessageHeader,
    account_keys: []Pubkey,
    recent_blockhash: Hash,
    instructions: []CompiledInstruction,
    address_table_lookups: []AddressLookup,

    const bk_config: bk.Codec(V0Message) = .standard(.tuple(.{
        .header = .from(MessageHeader.bk_config),
        .account_keys = .from(shortVec(Pubkey, pubkey_codec)),
        .recent_blockhash = .from(hash_codec),
        .instructions = .from(shortVec(CompiledInstruction, CompiledInstruction.bk_config)),
        .address_table_lookups = .from(shortVec(AddressLookup, AddressLookup.bk_config)),
    }));
};

const VersionedMessage = union(enum) {
    // first byte & 0x80 == 0
    legacy: LegacyMessage,
    // first byte & 0x80 != 0
    v0: V0Message,

    const bk_config: bk.Codec(VersionedMessage) = .implement(void, void, struct {
        pub fn encode(
            writer: *std.Io.Writer,
            config: bk.Config,
            values: []const VersionedMessage,
            _: ?*[encode_stack_size]u64,
            limit: std.Io.Limit,
            _: void,
        ) bk.EncodeToWriterError!bk.EncodedCounts {
            const max_count = limit.max(values.len);
            var byte_count: usize = 0;
            for (values[0..max_count]) |value| {
                switch (value) {
                    .legacy => |msg| {
                        // Legacy: no version prefix byte; MessageHeader.num_required_signatures
                        // is the first byte on the wire (written by LegacyMessage codec).
                        const counts = LegacyMessage.bk_config.encodeOnePartialRaw(
                            writer,
                            config,
                            &msg,
                            null,
                            .unlimited,
                            {},
                        ) catch return error.EncodeFailed;
                        byte_count += counts.byte_count;
                    },
                    .v0 => |msg| {
                        // V0: write version prefix byte (0x80 | 0x00 = 0x80), then V0Message.
                        writer.writeByte(0x80) catch return error.EncodeFailed;
                        byte_count += 1;
                        const counts = V0Message.bk_config.encodeOnePartialRaw(
                            writer,
                            config,
                            &msg,
                            null,
                            .unlimited,
                            {},
                        ) catch return error.EncodeFailed;
                        byte_count += counts.byte_count;
                    },
                }
            }
            return .{ .value_count = max_count, .byte_count = byte_count };
        }

        pub const encode_min_size: usize = 1;
        pub const encode_stack_size: usize = 0;
        pub const decodeInit = null;

        pub fn decode(
            reader: *std.Io.Reader,
            config: bk.Config,
            gpa_opt: ?std.mem.Allocator,
            values: []VersionedMessage,
            decoded_count: *usize,
            _: void,
        ) bk.DecodeFromReaderError!void {
            for (values, 0..) |*value, i| {
                errdefer decoded_count.* = i;

                // Peek the first byte to determine version.
                const first_byte = try reader.takeByte();

                if (first_byte & 0x80 == 0) {
                    // Legacy message. The byte we just read is num_required_signatures.
                    // We need to "put it back" — reconstruct by reading the remaining
                    // MessageHeader fields (2 more bytes), then the rest of the message.
                    const num_readonly_signed = try reader.takeByte();
                    const num_readonly_unsigned = try reader.takeByte();
                    const header: MessageHeader = .{
                        .num_required_signatures = first_byte,
                        .num_readonly_signed_accounts = num_readonly_signed,
                        .num_readonly_unsigned_accounts = num_readonly_unsigned,
                    };

                    // Decode the remaining fields of LegacyMessage (account_keys, recent_blockhash, instructions)
                    const account_keys_codec = shortVec(Pubkey, pubkey_codec);
                    const account_keys = try account_keys_codec.decode(
                        reader,
                        gpa_opt,
                        config,
                        null,
                    );

                    var recent_blockhash: Hash = undefined;
                    try hash_codec.decodeIntoOne(reader, null, config, &recent_blockhash, null);

                    const instructions_codec = shortVec(CompiledInstruction, .bk_config);
                    const instructions = try instructions_codec.decode(
                        reader,
                        gpa_opt,
                        config,
                        null,
                    );

                    value.* = .{ .legacy = .{
                        .header = header,
                        .account_keys = account_keys,
                        .recent_blockhash = recent_blockhash,
                        .instructions = instructions,
                    } };
                } else {
                    // Versioned message. The byte was consumed. Check version.
                    const version = first_byte & 0x7F;
                    if (version != 0) {
                        return error.DecodeFailed; // unsupported version
                    }

                    // Decode V0Message
                    const msg = try V0Message.bk_config.decode(reader, gpa_opt, config, null);
                    value.* = .{ .v0 = msg };
                }
            }
            decoded_count.* = values.len;
        }

        pub fn decodeSkip(
            reader: *std.Io.Reader,
            config: bk.Config,
            value_count: usize,
            decoded_count: *usize,
            _: void,
        ) bk.DecodeSkipError!void {
            for (0..value_count) |i| {
                errdefer decoded_count.* = i;
                const first_byte = try reader.takeByte();

                if (first_byte & 0x80 == 0) {
                    // Legacy: skip remaining 2 header bytes + fields
                    try reader.discardAll(2);
                    // Skip account_keys (shortVec of 32-byte pubkeys)
                    const ak_len = try compact_u16.decode(reader, null, .default, null);
                    try reader.discardAll(ak_len * Pubkey.SIZE);
                    // Skip recent_blockhash
                    try reader.discardAll(Hash.SIZE);
                    // Skip instructions
                    const ix_len = try compact_u16.decode(reader, null, .default, null);
                    try CompiledInstruction.bk_config.decodeSkip(reader, config, ix_len, {});
                } else {
                    // V0: version byte already consumed. Skip V0Message.
                    try V0Message.bk_config.decodeSkip(reader, config, 1, {});
                }
            }
            decoded_count.* = value_count;
        }

        pub fn free(
            gpa_opt: ?std.mem.Allocator,
            values: []const VersionedMessage,
            _: void,
        ) void {
            for (values) |value| {
                switch (value) {
                    .legacy => |msg| LegacyMessage.bk_config.free(gpa_opt, &msg, null),
                    .v0 => |msg| V0Message.bk_config.free(gpa_opt, &msg, null),
                }
            }
        }
    });
};

const VersionedTransaction = struct {
    signatures: []Signature,
    message: VersionedMessage,

    const bk_config: bk.Codec(VersionedTransaction) = .standard(.tuple(.{
        .signatures = .from(shortVec(Signature, Signature.bk_config)),
        .message = .from(VersionedMessage.bk_config),
    }));
};

// This isn't quite a bincode fixed int, nor a varint. It's some custom Solana thing used in
// Agave's `short_vec`. I think it's supposed to be smaller than a fixed or varint for a u16.
// NOTE: compact_u16 encoding will be the same as bincode varint for integers 127 and lower, but
// differs otherwise.
// TODO: using ?void, ?void to get around a binkode compile error. This should be void, void.
const compact_u16: bk.Codec(u16) = .implement(?void, ?void, struct {
    pub fn encode(
        writer: *std.Io.Writer,
        _: bk.Config,
        values: []const u16,
        _: ?*[encode_stack_size]u64,
        limit: std.Io.Limit,
        _: ?void,
    ) bk.EncodeToWriterError!bk.EncodedCounts {
        _ = limit; // should we use this?

        var byte_count: usize = 0;
        for (values) |val| {
            var rem: u16 = val;
            while (true) {
                var elem: u8 = @truncate(rem & 0x7f);
                rem >>= 7;
                if (rem == 0) {
                    writer.writeByte(elem) catch return error.EncodeFailed;
                    byte_count += 1;
                    break;
                } else {
                    elem |= 0x80;
                    writer.writeByte(elem) catch return error.EncodeFailed;
                    byte_count += 1;
                }
            }
        }
        return .{ .value_count = values.len, .byte_count = byte_count };
    }

    pub const encode_min_size: usize = 1;
    pub const encode_stack_size: usize = 0;
    pub const decodeInit = null;

    pub fn decode(
        reader: *std.Io.Reader,
        _: bk.Config,
        _: ?std.mem.Allocator,
        values: []u16,
        decoded_count: *usize,
        _: ?void,
    ) bk.DecodeFromReaderError!void {
        for (values, 0..) |*value, i| {
            errdefer decoded_count.* = i;

            var result: u16 = 0;
            var shift: u5 = 0;
            for (0..3) |i_byte| {
                const byte = try reader.takeByte();

                const wide = @as(u32, byte & 0x7f) << shift;
                if (wide > std.math.maxInt(u16)) return error.DecodeFailed;
                result |= @truncate(wide);

                if (byte & 0x80 == 0) {
                    // Reject non-canonical
                    if (byte == 0 and i_byte != 0) return error.DecodeFailed;
                    break;
                }

                shift += 7;
            } else {
                // Fourth byte would be needed, always an overflow for u16
                return error.DecodeFailed;
            }
            value.* = result;
        }
        decoded_count.* = values.len;
    }

    pub fn decodeSkip(
        reader: *std.Io.Reader,
        _: bk.Config,
        value_count: usize,
        decoded_count: *usize,
        _: void,
    ) bk.DecodeSkipError!void {
        for (0..value_count) |i| {
            errdefer decoded_count.* = i;
            for (0..3) |_| {
                const byte = try reader.takeByte();
                if (byte & 0x80 == 0) break;
            } else {
                return error.DecodeFailed;
            }
        }
        decoded_count.* = value_count;
    }

    pub const free = null;
});

test compact_u16 {
    const Case = struct { value: u16, encoded: []const u8 };

    const good_cases: []const Case = &.{
        .{ .value = 0, .encoded = &.{0x00} },
        .{ .value = 127, .encoded = &.{0x7F} },
        .{ .value = 128, .encoded = &.{ 0x80, 0x01 } },
        .{ .value = 255, .encoded = &.{ 0xFF, 0x01 } },
        .{ .value = 16383, .encoded = &.{ 0xFF, 0x7F } },
        .{ .value = 16384, .encoded = &.{ 0x80, 0x80, 0x01 } },
        .{ .value = 65535, .encoded = &.{ 0xFF, 0xFF, 0x03 } },
    };

    const bad_cases: []const []const u8 = &.{
        // aliases of 0x0000
        &.{ 0x80, 0x00 },
        &.{ 0x80, 0x80, 0x00 },
        // aliases of 0x007F
        &.{ 0xFF, 0x00 },
        &.{ 0xFF, 0x80, 0x00 },
        // aliases of 0x0080
        &.{ 0x80, 0x81, 0x00 },
        // aliases of 0x00FF
        &.{ 0xFF, 0x81, 0x00 },
        // aliases of 0x0100
        &.{ 0x80, 0x82, 0x00 },
        // aliases of 0x07FF
        &.{ 0xFF, 0x8F, 0x00 },
        // aliases of 0x3FFF
        &.{ 0xFF, 0xFF, 0x00 },
        // too long (4 bytes)
        &.{ 0x80, 0x80, 0x80, 0x00 },
        // overflow u16
        &.{ 0x80, 0x80, 0x04 },
        &.{ 0x80, 0x80, 0x06 },
    };

    // decode
    for (good_cases) |case| {
        var reader = std.io.Reader.fixed(case.encoded);
        const value = try compact_u16.decode(&reader, null, .{ .endian = .big, .int = .fixint }, {});
        try std.testing.expectEqual(case.value, value);
    }
    for (bad_cases) |case| {
        errdefer std.debug.print("decoding `{X}` should have failed\n", .{case});
        var reader = std.io.Reader.fixed(case);
        const value = compact_u16.decode(&reader, null, .{ .endian = .big, .int = .fixint }, {});
        try std.testing.expectError(error.DecodeFailed, value);
    }

    // encode
    for (good_cases) |case| {
        var out_buf: [3]u8 = undefined;
        var writer = std.io.Writer.fixed(&out_buf);
        try compact_u16.encode(&writer, .{ .endian = .big, .int = .fixint }, &case.value, {});
        try std.testing.expectEqualSlices(u8, writer.buffered(), case.encoded);
    }
}
