const std = @import("std");

test {
    _ = std.testing.refAllDecls(@This());
}

const common = @import("../../common.zig");
const binkode = @import("binkode");

const base58 = @import("base58");
const BASE58_ENDEC = base58.Table.BITCOIN;

const ed25519 = common.crypto.ed25519;
const Pubkey = common.solana.Pubkey;

pub const Signature = extern struct {
    r: [32]u8,
    s: [32]u8,

    pub const SIZE: usize = 64;

    pub const ZEROES: Signature = .{ .r = @splat(0), .s = @splat(0) };

    pub const bk_config: binkode.Codec(Signature) = .standard(.tuple(.{
        .r = .array(.fixint),
        .s = .array(.fixint),
    }));

    pub fn fromBytes(data: *const [SIZE]u8) *const Signature {
        return @ptrCast(data);
    }

    pub fn toBytes(self: Signature) [SIZE]u8 {
        return self.r ++ self.s;
    }

    pub fn fromSignature(signature: std.crypto.sign.Ed25519.Signature) Signature {
        return .{ .r = signature.r, .s = signature.s };
    }

    pub fn verify(self: *const Signature, pubkey: *const Pubkey, message: []const u8) !void {
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

        var encoded: [BASE58_MAX_SIZE]u8 = undefined;
        var encoded_len: usize = 0;

        @memcpy(encoded[0..str.len], str);
        encoded_len += str.len;

        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);

        var decoded_buf: [SIZE + 2]u8 = undefined;
        const decoded_len = BASE58_ENDEC.decode(&decoded_buf, encoded[0..encoded_len]) catch {
            return error.InvalidSignature;
        };

        if (decoded_len != SIZE) return error.InvalidSignature;
        return Signature.fromBytes(decoded_buf[0..SIZE]).*;
    }

    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);
    pub fn base58String(self: *const Signature, buffer: *[BASE58_MAX_SIZE]u8) []const u8 {
        const len = BASE58_ENDEC.encode(buffer, &self.toBytes());
        return buffer[0..len];
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
};
