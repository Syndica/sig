const std = @import("std");
const sig = @import("../sig.zig");
const base58 = @import("base58");
const BASE58_ENDEC = base58.Table.BITCOIN;

const ed25519 = sig.crypto.ed25519;
const Pubkey = sig.core.Pubkey;

pub const Signature = extern struct {
    r: [32]u8,
    s: [32]u8,

    pub const SIZE: usize = 64;

    pub const ZEROES: Signature = .{ .r = @splat(0), .s = @splat(0) };

    pub fn fromBytes(data: [SIZE]u8) Signature {
        return .{
            .r = data[0..32].*,
            .s = data[32..64].*,
        };
    }

    pub fn toBytes(self: Signature) [SIZE]u8 {
        return self.r ++ self.s;
    }

    pub fn fromSignature(signature: std.crypto.sign.Ed25519.Signature) Signature {
        return .{ .r = signature.r, .s = signature.s };
    }

    pub fn verify(self: Signature, pubkey: Pubkey, message: []const u8) !void {
        try ed25519.verifySignature(self, pubkey, message, true);
    }

    pub fn eql(self: *const Signature, other: *const Signature) bool {
        const x: @Vector(SIZE, u8) = self.toBytes();
        const y: @Vector(SIZE, u8) = other.toBytes();
        return @reduce(.And, x == y);
    }

    pub inline fn parse(comptime str: []const u8) Signature {
        comptime {
            return parseRuntime(str) catch @compileError("failed to parse signature");
        }
    }

    pub fn parseRuntime(str: []const u8) error{InvalidSignature}!Signature {
        if (str.len > BASE58_MAX_SIZE) return error.InvalidSignature;
        var encoded: std.BoundedArray(u8, BASE58_MAX_SIZE) = .{};
        encoded.appendSliceAssumeCapacity(str);

        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        const decoded = BASE58_ENDEC.decodeBounded(BASE58_MAX_SIZE, encoded) catch {
            return error.InvalidSignature;
        };

        if (decoded.len != SIZE) return error.InvalidSignature;
        return .fromBytes(decoded.constSlice()[0..SIZE].*);
    }

    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);
    pub const Base58String = std.BoundedArray(u8, BASE58_MAX_SIZE);

    pub fn base58String(self: Signature) Base58String {
        return BASE58_ENDEC.encodeArray(SIZE, self.toBytes());
    }

    pub fn format(
        self: Signature,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const str = self.base58String();
        return writer.writeAll(str.constSlice());
    }

    pub fn jsonStringify(self: Signature, writer: anytype) @TypeOf(writer.*).Error!void {
        try writer.print("\"{s}\"", .{self.base58String().slice()});
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !Signature {
        const value = try std.json.Value.jsonParse(allocator, source, options);
        return if (value == .string)
            parseRuntime(value.string) catch return error.InvalidNumber
        else
            error.UnexpectedToken;
    }

    pub fn jsonParseFromValue(
        _: std.mem.Allocator,
        source: std.json.Value,
        _: std.json.ParseOptions,
    ) std.json.ParseFromValueError!Signature {
        return switch (source) {
            .string => |str| parseRuntime(str) catch error.InvalidCharacter,
            else => error.UnexpectedToken,
        };
    }
};
