//! Public API for the sig-crypto library.
//!
//! This is the "header" module — what consumers import to use crypto types
//! and operations. Types are defined as extern structs with stable ABI layout.
//!
//! Only cryptographic operations (hashing, signature verification) are bridged
//! to the static library via @extern — these benefit from optimized compilation
//! (ReleaseFast, AVX-512/SHA-NI). Non-crypto helpers (eql, order, parse, base58,
//! indexIn) are implemented directly here.

const std = @import("std");
const base58 = @import("base58");
const binkode = @import("binkode");

// -- @extern declarations for cryptographic operations from sig-crypto -- //

// Hash (cryptographic)
const sig_crypto_hash_init = @extern(
    *const fn ([*]const u8, usize, *Hash) callconv(.c) void,
    .{ .name = "sig_crypto_hash_init" },
);
const sig_crypto_hash_init_many = @extern(
    *const fn ([*]const [*]const u8, [*]const usize, usize, *Hash) callconv(.c) void,
    .{ .name = "sig_crypto_hash_init_many" },
);
const sig_crypto_hash_extend = @extern(
    *const fn (*const Hash, [*]const u8, usize, *Hash) callconv(.c) void,
    .{ .name = "sig_crypto_hash_extend" },
);
const sig_crypto_hash_repeated = @extern(
    *const fn (*const Hash, *Hash, usize) callconv(.c) void,
    .{ .name = "sig_crypto_hash_repeated" },
);

// Signature (cryptographic)
const sig_crypto_sig_verify = @extern(
    *const fn (*const Signature, *const Pubkey, [*]const u8, usize) callconv(.c) bool,
    .{ .name = "sig_crypto_sig_verify" },
);

// -- Types -- //

pub const ed25519 = struct {
    // ed25519 functions are called internally by Signature.verify,
    // which lives in the static library. No direct @extern needed here.
};

pub const Hash = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;
    pub const ZEROES: Hash = .{ .data = @splat(0) };
    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);

    const BASE58_ENDEC = base58.Table.BITCOIN;

    // -- Cryptographic operations (bridged to static library) -- //

    pub fn init(data: []const u8) Hash {
        var out: Hash = undefined;
        sig_crypto_hash_init(data.ptr, data.len, &out);
        return out;
    }

    pub fn initMany(data: []const []const u8) Hash {
        var ptrs: [8][*]const u8 = undefined;
        var lens: [8]usize = undefined;
        const n = @min(data.len, 8);
        for (0..n) |i| {
            ptrs[i] = data[i].ptr;
            lens[i] = data[i].len;
        }
        var out: Hash = undefined;
        sig_crypto_hash_init_many(&ptrs, &lens, n, &out);
        return out;
    }

    pub fn extend(self: Hash, data: []const u8) Hash {
        var out: Hash = undefined;
        sig_crypto_hash_extend(&self, data.ptr, data.len, &out);
        return out;
    }

    pub fn hashRepeated(input: *const Hash, out: *Hash, count: usize) void {
        sig_crypto_hash_repeated(input, out, count);
    }

    // -- Non-crypto operations (implemented directly) -- //

    pub fn eql(self: *const Hash, other: *const Hash) bool {
        const x: @Vector(SIZE, u8) = self.data;
        const y: @Vector(SIZE, u8) = other.data;
        return @reduce(.And, x == y);
    }

    pub fn order(self: *const Hash, other: *const Hash) std.math.Order {
        return for (self.data, other.data) |a_byte, b_byte| {
            if (a_byte > b_byte) break .gt;
            if (a_byte < b_byte) break .lt;
        } else .eq;
    }

    pub fn parseRuntime(str: []const u8) error{InvalidHash}!Hash {
        if (str.len > BASE58_MAX_SIZE) return error.InvalidHash;
        var encoded: [BASE58_MAX_SIZE]u8 = undefined;
        @memcpy(encoded[0..str.len], str);
        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        var decoded_buf: [SIZE + 2]u8 = undefined;
        const decoded_len = BASE58_ENDEC.decode(&decoded_buf, encoded[0..str.len]) catch {
            return error.InvalidHash;
        };
        if (decoded_len != SIZE) return error.InvalidHash;
        return .{ .data = decoded_buf[0..SIZE].* };
    }

    pub inline fn parse(comptime str: []const u8) Hash {
        comptime {
            return parseRuntime(str) catch @compileError("failed to parse hash");
        }
    }

    pub fn base58String(self: *const Hash, buffer: *[BASE58_MAX_SIZE]u8) []const u8 {
        const len = BASE58_ENDEC.encode(buffer, &self.data);
        return buffer[0..len];
    }

    pub fn format(self: *const Hash, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [BASE58_MAX_SIZE]u8 = undefined;
        const str = self.base58String(&buf);
        return writer.writeAll(str);
    }

    pub fn initRandom(random: std.Random) Hash {
        var data: [SIZE]u8 = undefined;
        random.bytes(&data);
        return .{ .data = data };
    }
};

pub const Pubkey = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;
    pub const ZEROES: Pubkey = .{ .data = .{0} ** SIZE };
    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);

    const BASE58_ENDEC = base58.Table.BITCOIN;

    pub fn fromPublicKey(public_key: *const std.crypto.sign.Ed25519.PublicKey) Pubkey {
        return .{ .data = public_key.bytes };
    }

    pub fn equals(self: *const Pubkey, other: *const Pubkey) bool {
        const xx: @Vector(SIZE, u8) = self.data;
        const yy: @Vector(SIZE, u8) = other.data;
        return @reduce(.And, xx == yy);
    }

    pub fn isZeroed(self: *const Pubkey) bool {
        return self.equals(&ZEROES);
    }

    pub fn order(self: Pubkey, other: Pubkey) std.math.Order {
        return for (self.data, other.data) |a_byte, b_byte| {
            if (a_byte > b_byte) break .gt;
            if (a_byte < b_byte) break .lt;
        } else .eq;
    }

    pub fn parseRuntime(str: []const u8) error{ InvalidLength, InvalidPubkey }!Pubkey {
        if (str.len > BASE58_MAX_SIZE) return error.InvalidLength;
        var encoded: [BASE58_MAX_SIZE]u8 = undefined;
        @memcpy(encoded[0..str.len], str);
        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        var decoded_buf: [SIZE + 2]u8 = undefined;
        const decoded_len = BASE58_ENDEC.decode(&decoded_buf, encoded[0..str.len]) catch {
            return error.InvalidPubkey;
        };
        if (decoded_len != SIZE) return error.InvalidLength;
        return .{ .data = decoded_buf[0..SIZE].* };
    }

    pub inline fn parse(comptime str: []const u8) Pubkey {
        comptime {
            return parseRuntime(str) catch @compileError("failed to parse pubkey");
        }
    }

    pub fn base58String(self: *const Pubkey, buffer: *[BASE58_MAX_SIZE]u8) []const u8 {
        const len = BASE58_ENDEC.encode(buffer, &self.data);
        return buffer[0..len];
    }

    pub fn format(self: *const Pubkey, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [BASE58_MAX_SIZE]u8 = undefined;
        const str = self.base58String(&buf);
        return writer.writeAll(str);
    }

    pub fn indexIn(self: Pubkey, pubkeys: []const Pubkey) ?usize {
        return for (pubkeys, 0..) |candidate, index| {
            if (self.equals(&candidate)) break index;
        } else null;
    }

    pub fn initRandom(random: std.Random) Pubkey {
        const Edwards25519 = std.crypto.ecc.Edwards25519;
        var bytes: [SIZE]u8 = undefined;
        random.bytes(&bytes);
        return .{ .data = Edwards25519.fromUniform(bytes).toBytes() };
    }
};

pub const Signature = extern struct {
    r: [32]u8,
    s: [32]u8,

    pub const SIZE: usize = 64;
    pub const ZEROES: Signature = .{ .r = @splat(0), .s = @splat(0) };
    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);

    pub const bk_config: binkode.Codec(Signature) = .standard(.tuple(.{
        .r = .array(.fixint),
        .s = .array(.fixint),
    }));

    const BASE58_ENDEC = base58.Table.BITCOIN;

    pub fn fromBytes(data: *const [SIZE]u8) *const Signature {
        return @ptrCast(data);
    }

    pub fn toBytes(self: Signature) [SIZE]u8 {
        return self.r ++ self.s;
    }

    pub fn fromSignature(signature: std.crypto.sign.Ed25519.Signature) Signature {
        return .{ .r = signature.r, .s = signature.s };
    }

    // -- Cryptographic operation (bridged to static library) -- //

    pub fn verify(
        self: *const Signature,
        pubkey: *const Pubkey,
        message: []const u8,
    ) !void {
        if (!sig_crypto_sig_verify(
            self,
            pubkey,
            message.ptr,
            message.len,
        )) return error.InvalidSignature;
    }

    // -- Non-crypto operations (implemented directly) -- //

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
        @memcpy(encoded[0..str.len], str);
        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        var decoded_buf: [SIZE + 2]u8 = undefined;
        const decoded_len = BASE58_ENDEC.decode(&decoded_buf, encoded[0..str.len]) catch {
            return error.InvalidSignature;
        };
        if (decoded_len != SIZE) return error.InvalidSignature;
        const sig_ptr: *const Signature = @ptrCast(decoded_buf[0..SIZE]);
        return sig_ptr.*;
    }

    pub fn base58String(self: *const Signature, buffer: *[BASE58_MAX_SIZE]u8) []const u8 {
        const len = BASE58_ENDEC.encode(buffer, &self.toBytes());
        return buffer[0..len];
    }

    pub fn format(self: *const Signature, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [BASE58_MAX_SIZE]u8 = undefined;
        const str = self.base58String(&buf);
        return writer.writeAll(str);
    }
};
