const std = @import("std");
const std14 = @import("std14");
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

    // Port of https://github.com/ogxd/gxhash/
    // Since hashing [32]u8, this keeps the hashing in simd registers (vs mulx alternatives)
    pub fn hash(self: *const Pubkey, seed: u64) u64 {
        const AesBlock = std.crypto.core.aes.Block;
        const KEYS: [3]AesBlock = .{
            .fromBytes(std.mem.asBytes(&[_]u32{ 0xF2784542, 0xB09D3E21, 0x89C222E5, 0xFC3BC28E })),
            .fromBytes(std.mem.asBytes(&[_]u32{ 0x03FCE279, 0xCB6B2E9B, 0xB361DC58, 0x39132BD9 })),
            .fromBytes(std.mem.asBytes(&[_]u32{ 0xD0012E32, 0x689D2B7D, 0x5544B1B7, 0xC78B122B })),
        };

        // create_seed
        var state = AesBlock.fromBytes(std.mem.asBytes(&[_]u64{ seed, seed }));

        // write!
        state = AesBlock.fromBytes(self.data[0..16]).encryptLast(state.encrypt(KEYS[0]));
        state = AesBlock.fromBytes(self.data[16..32]).encryptLast(state.encrypt(KEYS[0]));

        // finalize
        state = state.encrypt(KEYS[0]).encrypt(KEYS[1]).encryptLast(KEYS[2]);

        // finish
        const h: u128 = @bitCast(state.toBytes());
        return @truncate(h);
    }

    pub fn order(self: *const Pubkey, other: Pubkey) std.math.Order {
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

        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        var decoded_buf: [base58.decodedMaxSize(BASE58_MAX_SIZE)]u8 = undefined;
        const decoded_len = BASE58_ENDEC.decode(&decoded_buf, str) catch {
            return error.InvalidPubkey;
        };

        if (decoded_len != SIZE) return error.InvalidLength;
        return .{ .data = decoded_buf[0..SIZE].* };
    }

    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);
    pub const Base58String = std14.BoundedArray(u8, BASE58_MAX_SIZE);

    pub fn base58String(self: Pubkey) Base58String {
        var result: Base58String = .{};
        const len = BASE58_ENDEC.encode(result.unusedCapacitySlice(), &self.data);
        result.len = len;
        return result;
    }

    pub fn format(
        self: @This(),
        writer: *std.io.Writer,
    ) std.io.Writer.Error!void {
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

    /// Returns the 32 bytes as a 64-character lowercase hex string.
    /// Intended for embedding in SQL literals like `X'<hex>'`.
    pub fn hexBytesLower(comptime self: Pubkey) [64]u8 {
        return std.fmt.bytesToHex(&self.data, .lower);
    }
};

const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
