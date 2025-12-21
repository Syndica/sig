const std = @import("std");
const base58 = @import("base58");
const BASE58_ENDEC = base58.Table.BITCOIN;

const Edwards25519 = std.crypto.ecc.Edwards25519;

pub const Pubkey = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;

    pub const ZEROES: Pubkey = .{ .data = .{0} ** SIZE };

    pub fn fromBytes(data: [SIZE]u8) !Pubkey {
        try Edwards25519.rejectNonCanonical(data);
        return .{ .data = data };
    }

    pub fn fromPublicKey(public_key: *const std.crypto.sign.Ed25519.PublicKey) Pubkey {
        return .{ .data = public_key.bytes };
    }

    pub fn initRandom(random: std.Random) Pubkey {
        var bytes: [SIZE]u8 = undefined;
        random.bytes(&bytes);
        return .{ .data = bytes };
    }

    pub fn hash(self: Pubkey) u64 {
        // From Wyhash/RapidHash:
        // https://github.com/hoxxep/rapidhash/blob/ec78aed2815e76dfaa4bf700f474138c88e9453e/rapidhash-c/cpp/rapidhash_v3.hpp#L128-L136
        const sk = [_]u64{
            0x2d358dccaa6c78a5,
            0x8bb84b93962eacc9,
            0x4b33a62ed433d4a3,
            0x4d5a2da51de1aa47,
            0xa0761d6478bd642f,
            0xe7037ed1a0b428db,
        };

        const in: [4]u64 = @bitCast(self.data);
        const m1: [2]u64 = @bitCast(@as(u128, in[0] ^ sk[0]) * (in[1] ^ sk[1]));
        const m2: [2]u64 = @bitCast(@as(u128, in[2] ^ sk[2]) * (in[3] ^ sk[3]));
        const m3: [2]u64 = @bitCast(@as(u128, m1[0] ^ m1[1] ^ sk[3]) * (m2[0] ^ m2[1] ^ sk[4]));
        return m3[0] ^ m3[1];
    }

    pub fn order(self: Pubkey, other: Pubkey) std.math.Order {
        const xx: @Vector(SIZE, u8) = self.data;
        const yy: @Vector(SIZE, u8) = other.data;

        const diff_mask: std.meta.Int(.unsigned, SIZE) = @bitCast(xx != yy);
        const all_eq = diff_mask == 0;

        const first_diff = if (all_eq) 0 else @ctz(diff_mask);
        const lt_or_gt: std.math.Order =
            if (self.data[first_diff] < other.data[first_diff]) .lt else .gt;

        return if (all_eq) .eq else lt_or_gt;
    }

    pub fn equals(self: *const Pubkey, other: *const Pubkey) bool {
        const xx: @Vector(SIZE, u8) = self.data;
        const yy: @Vector(SIZE, u8) = other.data;
        return @reduce(.And, xx == yy);
    }

    pub fn isZeroed(self: *const Pubkey) bool {
        return self.equals(&ZEROES);
    }

    pub inline fn parse(comptime str: []const u8) Pubkey {
        comptime {
            return parseRuntime(str) catch @compileError("failed to parse pubkey");
        }
    }

    pub fn parseRuntime(str: []const u8) error{ InvalidLength, InvalidPubkey }!Pubkey {
        if (str.len > BASE58_MAX_SIZE) return error.InvalidLength;
        var encoded: std.BoundedArray(u8, BASE58_MAX_SIZE) = .{};
        encoded.appendSliceAssumeCapacity(str);

        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        const decoded = BASE58_ENDEC.decodeBounded(BASE58_MAX_SIZE, encoded) catch {
            return error.InvalidPubkey;
        };

        if (decoded.len != SIZE) return error.InvalidLength;
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

    pub fn jsonStringify(self: Pubkey, write_stream: anytype) !void {
        try write_stream.write(self.base58String().slice());
    }

    pub fn jsonParse(
        _: std.mem.Allocator,
        source: anytype,
        _: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!Pubkey {
        return switch (try source.next()) {
            .string => |str| parseRuntime(str) catch error.UnexpectedToken,
            else => error.UnexpectedToken,
        };
    }

    pub fn jsonParseFromValue(
        _: std.mem.Allocator,
        source: std.json.Value,
        _: std.json.ParseOptions,
    ) std.json.ParseFromValueError!Pubkey {
        return switch (source) {
            .string => |str| parseRuntime(str) catch |err| switch (err) {
                error.InvalidPubkey => error.InvalidCharacter,
                error.InvalidLength => error.LengthMismatch,
            },
            else => error.UnexpectedToken,
        };
    }

    pub fn indexIn(self: Pubkey, pubkeys: []const Pubkey) ?usize {
        return for (pubkeys, 0..) |candidate, index| {
            if (self.equals(&candidate)) break index;
        } else null;
    }
};

const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
