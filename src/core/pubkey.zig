const std = @import("std");
const sig = @import("../sig.zig");
const base58 = @import("base58");
const BASE58_TABLE = base58.Table.BITCOIN;

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

    pub fn order(self: Pubkey, other: Pubkey) std.math.Order {
        return for (self.data, other.data) |a_byte, b_byte| {
            if (a_byte > b_byte) break .gt;
            if (a_byte < b_byte) break .lt;
        } else .eq;
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

    const MAX_ENCODED_SIZE = base58.encodedMaxSize(SIZE);

    pub fn parseRuntime(str: []const u8) error{ InvalidLength, InvalidPubkey }!Pubkey {
        if (str.len > MAX_ENCODED_SIZE) return error.InvalidLength;
        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);

        var decoded: [MAX_ENCODED_SIZE]u8 = undefined;
        const len = BASE58_TABLE.decode(&decoded, str) catch return error.InvalidPubkey;
        if (len != SIZE) return error.InvalidLength;
        return .{ .data = decoded[0..SIZE].* };
    }

    pub fn format(self: Pubkey, writer: *std.Io.Writer) !void {
        var encoded: [MAX_ENCODED_SIZE]u8 = undefined;
        const len = BASE58_TABLE.encode(&encoded, &self.data);
        return try writer.writeAll(encoded[0..len]);
    }

    pub fn jsonStringify(self: Pubkey, writer: *std.io.Writer) !void {
        try writer.print("\"{f}\"", .{self});
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
