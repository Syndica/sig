const std = @import("std");
const sig = @import("../lib.zig");

const bincode = sig.bincode;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const BitFlags = sig.utils.BitFlags;
const Hash = sig.core.Hash;
const Nonce = sig.core.Nonce;
const Packet = sig.net.Packet;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

const SIGNATURE_LENGTH = sig.core.SIGNATURE_LENGTH;

pub const MAX_DATA_SHREDS_PER_SLOT: usize = 32_768;
pub const MAX_CODE_SHREDS_PER_SLOT: usize = MAX_DATA_SHREDS_PER_SLOT;
pub const MAX_SHREDS_PER_SLOT: usize = MAX_CODE_SHREDS_PER_SLOT + MAX_DATA_SHREDS_PER_SLOT;

pub const Shred = struct {
    common_header: ShredCommonHeader,
    custom_header: CustomHeader,
    payload: ArrayList(u8),

    const CustomHeader = union(ShredType) {
        Code: CodingShredHeader,
        Data: DataShredHeader,
    };

    const Self = @This();

    pub fn fromPayload(allocator: Allocator, payload: []const u8) !Self {
        const variant = shred_layout.getShredVariant(payload) orelse return error.uygugj;
        const SIZE_OF_PAYLOAD = switch (variant.shred_type) {
            .Code => CodingShredHeader.SIZE_OF_PAYLOAD,
            .Data => DataShredHeader.SIZE_OF_PAYLOAD,
        };
        if (payload.len < SIZE_OF_PAYLOAD) {
            return error.InvalidPayloadSize;
        }
        const exact_payload = payload[0..SIZE_OF_PAYLOAD];
        var buf = std.io.fixedBufferStream(exact_payload);
        const common_header = try bincode.read(allocator, ShredCommonHeader, buf.reader(), .{});
        const custom_header: CustomHeader = switch (variant.shred_type) {
            .Code => .{ .Code = try bincode.read(allocator, CodingShredHeader, buf.reader(), .{}) },
            .Data => .{ .Data = try bincode.read(allocator, DataShredHeader, buf.reader(), .{}) },
        };
        var owned_payload = ArrayList(u8).init(allocator); // TODO: find a cheaper way to get the payload in here
        try owned_payload.appendSlice(exact_payload);
        var self = Self{
            .common_header = common_header,
            .custom_header = custom_header,
            .payload = owned_payload,
        };
        try self.sanitize();
        return self;
    }

    pub fn isLastInSlot(self: *const Self) bool {
        return switch (self.custom_header) {
            .Code => false,
            .Data => |data| data.flags.isSet(.last_shred_in_slot),
        };
    }

    fn sanitize(self: *const Self) !void {
        _ = self;
        // TODO
    }
};

pub const ShredCommonHeader = struct {
    signature: Signature,
    shred_variant: ShredVariant,
    slot: Slot,
    index: u32,
    version: u16,
    fec_set_index: u32,

    pub const @"!bincode-config:shred_variant" = ShredVariantConfig;
};

pub const DataShredHeader = struct {
    parent_offset: u16,
    flags: ShredFlags,
    size: u16, // common shred header + data shred header + data

    const SIZE_OF_PAYLOAD: usize = 1203; // TODO this can be calculated like solana
};

pub const CodingShredHeader = struct {
    num_data_shreds: u16,
    num_coding_shreds: u16,
    position: u16, // [0..num_coding_shreds)

    const SIZE_OF_PAYLOAD: usize = 1228; // TODO this can be calculated like solana
};

pub const ShredType = enum(u8) {
    Code = 0b0101_1010,
    Data = 0b1010_0101,
};

pub const ShredVariant = struct {
    shred_type: ShredType,
    proof_size: u8,
    chained: bool,
    resigned: bool,

    fn fromByte(byte: u8) error{ UnknownShredVariant, LegacyShredVariant }!@This() {
        return switch (byte & 0xF0) {
            0x40 => .{
                .shred_type = .Code,
                .proof_size = byte & 0x0F,
                .chained = false,
                .resigned = false,
            },
            0x60 => .{
                .shred_type = .Code,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = false,
            },
            0x70 => .{
                .shred_type = .Code,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = true,
            },
            0x80 => .{
                .shred_type = .Data,
                .proof_size = byte & 0x0F,
                .chained = false,
                .resigned = false,
            },
            0x90 => .{
                .shred_type = .Data,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = false,
            },
            0xb0 => .{
                .shred_type = .Data,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = true,
            },
            @intFromEnum(ShredType.Code) => error.LegacyShredVariant,
            @intFromEnum(ShredType.Data) => error.LegacyShredVariant,
            else => error.UnknownShredVariant,
        };
    }
};

pub const ShredVariantConfig = blk: {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            _ = writer;
            _ = params;
            _ = data;
            @panic("todo - not implemented"); // TODO
            // try writer.writeByte(0);
        }

        pub fn deserialize(_: ?std.mem.Allocator, reader: anytype, _: bincode.Params) !ShredVariant {
            return try ShredVariant.fromByte(try reader.readByte());
        }

        pub fn free(_: std.mem.Allocator, _: anytype) void {}
    };

    break :blk bincode.FieldConfig(ShredVariant){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
};

pub const ShredFlags = BitFlags(enum(u8) {
    shred_tick_reference_mask = 0b0011_1111,
    data_complete_shred = 0b0100_0000,
    last_shred_in_slot = 0b1100_0000,
});

pub const shred_layout = struct {
    const SIZE_OF_COMMON_SHRED_HEADER: usize = 83;
    const SIZE_OF_DATA_SHRED_HEADERS: usize = 88;
    const SIZE_OF_CODING_SHRED_HEADERS: usize = 89;
    const SIZE_OF_SIGNATURE: usize = sig.core.SIGNATURE_LENGTH;
    const SIZE_OF_SHRED_VARIANT: usize = 1;
    const SIZE_OF_SHRED_SLOT: usize = 8;

    const OFFSET_OF_SHRED_VARIANT: usize = SIZE_OF_SIGNATURE;
    const OFFSET_OF_SHRED_SLOT: usize = SIZE_OF_SIGNATURE + SIZE_OF_SHRED_VARIANT;
    const OFFSET_OF_SHRED_INDEX: usize = OFFSET_OF_SHRED_SLOT + SIZE_OF_SHRED_SLOT;

    pub fn getShred(packet: *const Packet) ?[]const u8 {
        if (getShredSize(packet) > packet.data.len) return null;
        return packet.data[0..getShredSize(packet)];
    }

    pub fn getShredSize(packet: *const Packet) usize {
        return if (packet.isSet(.repair))
            packet.size -| @sizeOf(Nonce)
        else
            packet.size;
    }

    pub fn getSlot(shred: []const u8) ?Slot {
        return getInt(Slot, shred, OFFSET_OF_SHRED_SLOT);
    }

    pub fn getVersion(shred: []const u8) ?u16 {
        return getInt(u16, shred, 77);
    }

    pub fn getShredVariant(shred: []const u8) ?ShredVariant {
        if (shred.len <= OFFSET_OF_SHRED_VARIANT) return null;
        const byte = shred[OFFSET_OF_SHRED_VARIANT];
        return ShredVariant.fromByte(byte) catch null;
    }

    pub fn getIndex(shred: []const u8) ?u32 {
        return getInt(u32, shred, OFFSET_OF_SHRED_INDEX);
    }

    pub fn getSignature(shred: []const u8) ?Signature {
        if (shred.len < SIGNATURE_LENGTH) {
            return null;
        }
        return Signature.init(shred[0..SIZE_OF_SIGNATURE].*);
    }

    pub fn getSignedData(shred: []const u8) ?Hash {
        const variant = getShredVariant(shred) orelse return null;
        _ = variant;
        // TODO implement this once the leader schedule is available to runShredSigVerify
        return Hash.default();
    }

    /// must be a data shred, otherwise the return value will be corrupted and meaningless
    pub fn getParentOffset(shred: []const u8) ?u16 {
        std.debug.assert(getShredVariant(shred).?.shred_type == .Data);
        return getInt(u16, shred, 83);
    }

    /// Extracts a little-endian integer from within the slice,
    /// starting at start_index.
    fn getInt(
        comptime Int: type,
        data: []const u8,
        start_index: usize,
    ) ?Int {
        const end_index = start_index + @sizeOf(Int);
        if (data.len < end_index) return null;
        const bytes: *const [@sizeOf(Int)]u8 = @ptrCast(data[start_index..end_index]);
        return std.mem.readInt(Int, bytes, .little);
    }
};
