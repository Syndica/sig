const std = @import("std");
const sig = @import("../sig.zig");
const base58 = @import("base58");
const BASE58_ENDEC = base58.Table.BITCOIN;

pub const Pubkey = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;

    pub const ZEROES: Pubkey = .{ .data = .{0} ** SIZE };

    pub fn fromPublicKey(public_key: *const std.crypto.sign.Ed25519.PublicKey) Pubkey {
        return .{ .data = public_key.bytes };
    }

    pub fn initRandom(random: std.Random) Pubkey {
        var bytes: [SIZE]u8 = undefined;
        random.bytes(&bytes);
        return .{ .data = bytes };
    }

    pub fn equals(self: *const Pubkey, other: *const Pubkey) bool {
        const xx: @Vector(SIZE, u8) = self.data;
        const yy: @Vector(SIZE, u8) = other.data;
        return @reduce(.And, xx == yy);
    }

    pub fn isZeroed(self: *const Pubkey) bool {
        return self.equals(&ZEROES);
    }

    pub fn parseBase58String(str: []const u8) error{InvalidPubkey}!Pubkey {
        if (str.len > BASE58_MAX_SIZE) return error.InvalidPubkey;
        var encoded: std.BoundedArray(u8, BASE58_MAX_SIZE) = .{};
        encoded.appendSliceAssumeCapacity(str);

        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        const decoded = BASE58_ENDEC.decodeBounded(BASE58_MAX_SIZE, encoded) catch {
            return error.InvalidPubkey;
        };

        if (decoded.len != SIZE) return error.InvalidPubkey;
        return .{ .data = decoded.constSlice()[0..SIZE].* };
    }

    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);
    pub const Base58String = std.BoundedArray(u8, BASE58_MAX_SIZE);
    pub fn base58String(self: Pubkey) Base58String {
        return BASE58_ENDEC.encodeArray(SIZE, self.data);
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const str = self.base58String();
        return writer.writeAll(str.constSlice());
    }

    pub fn jsonParse(
        _: std.mem.Allocator,
        source: anytype,
        _: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!Pubkey {
        return switch (try source.next()) {
            .string => |str| parseBase58String(str) catch error.UnexpectedToken,
            else => error.UnexpectedToken,
        };
    }
};

const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
