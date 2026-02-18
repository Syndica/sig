const std = @import("std");
const builtin = @import("builtin");
const common = @import("../../common.zig");
const base58 = @import("base58");

const BASE58_ENDEC = base58.Table.BITCOIN;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Slot = common.solana.Slot;

pub const Hash = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;

    pub const ZEROES: Hash = .{ .data = @splat(0) };

    /// Returns a `Hash` that represents SHA256 applied over `data`.
    pub fn init(data: []const u8) Hash {
        var out: [32]u8 = undefined;
        Sha256.hash(data, &out, .{});
        return .{ .data = out };
    }

    /// Does the same thing as `init`, but updates the hash with each input from the `data` list.
    pub fn initMany(data: []const []const u8) Hash {
        var new = Sha256.init(.{});
        for (data) |d| new.update(d);
        return .{ .data = new.finalResult() };
    }

    /// re-hashes the current hash with the mixed-in byte slice(s).
    pub fn extend(self: Hash, data: []const u8) Hash {
        return .initMany(&.{ &self.data, data });
    }

    pub fn eql(self: Hash, other: Hash) bool {
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

    pub fn bytes(self: *Hash) []u8 {
        return &self.data;
    }

    pub inline fn parse(comptime str: []const u8) Hash {
        comptime {
            return parseRuntime(str) catch @compileError("failed to parse hash");
        }
    }

    pub fn parseRuntime(str: []const u8) error{InvalidHash}!Hash {
        if (str.len > BASE58_MAX_SIZE) return error.InvalidHash;
        var encoded: std.BoundedArray(u8, BASE58_MAX_SIZE) = .{};
        encoded.appendSliceAssumeCapacity(str);

        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        const decoded = BASE58_ENDEC.decodeBounded(BASE58_MAX_SIZE, encoded) catch {
            return error.InvalidHash;
        };

        if (decoded.len != SIZE) return error.InvalidHash;
        return .{ .data = decoded.constSlice()[0..SIZE].* };
    }

    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);
    pub const Base58String = std.BoundedArray(u8, BASE58_MAX_SIZE);
    pub fn base58String(self: Hash) Base58String {
        return BASE58_ENDEC.encodeArray(SIZE, self.data);
    }

    pub fn format(
        self: Hash,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        const str = self.base58String();
        return writer.writeAll(str.constSlice());
    }

    /// Intended to be used in tests.
    pub fn initRandom(random: std.Random) Hash {
        var data: [SIZE]u8 = undefined;
        random.bytes(&data);
        return .{ .data = data };
    }

    /// `input` and `out` arguments may alias.
    pub fn hashRepeated(input: *const Hash, out: *Hash, count: usize) void {
        if (comptime std.Target.x86.featureSetHasAll(builtin.cpu.features, &.{ .sha, .avx2 })) {
            const V = @Vector(4, u32);

            const iv = [8]u32{
                0x6A09E667,
                0xBB67AE85,
                0x3C6EF372,
                0xA54FF53A,
                0x510E527F,
                0x9B05688C,
                0x1F83D9AB,
                0x5BE0CD19,
            };

            const W = [64 / 4]@Vector(4, u32){
                .{ 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5 },
                .{ 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5 },
                .{ 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3 },
                .{ 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174 },
                .{ 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC },
                .{ 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA },
                .{ 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7 },
                .{ 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967 },
                .{ 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13 },
                .{ 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85 },
                .{ 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3 },
                .{ 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070 },
                .{ 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5 },
                .{ 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3 },
                .{ 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208 },
                .{ 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2 },
            };

            var first: [4]V = .{
                @byteSwap(@as(V, @bitCast(input.data[0..16].*))),
                @byteSwap(@as(V, @bitCast(input.data[16..32].*))),
                @bitCast(@as(@Vector(16, u8), .{
                    0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                })),
                // always indicate 32-byte seperator
                @bitCast(@as(@Vector(16, u8), .{
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                })),
            };
            const feba: V = comptime .{ iv[5], iv[4], iv[1], iv[0] };
            const hgdc: V = comptime .{ iv[7], iv[6], iv[3], iv[2] };

            for (0..count) |_| {
                var x = feba;
                var y = hgdc;

                var last: [12]V = undefined;
                inline for (0..16) |k| {
                    if (k < 12) {
                        var tmp = if (comptime k < 4) first[k] else last[k - 4];
                        last[k] = asm (
                            \\ sha256msg1 %[w4_7], %[tmp]
                            \\ vpalignr $0x4, %[w8_11], %[w12_15], %[result]
                            \\ paddd %[tmp], %[result]
                            \\ sha256msg2 %[w12_15], %[result]
                            : [tmp] "=&x" (tmp),
                              [result] "=&x" (-> V),
                            : [_] "0" (tmp),
                              [w4_7] "x" (if (k + 1 < 4) first[k + 1] else last[k + 1 - 4]),
                              [w8_11] "x" (if (k + 2 < 4) first[k + 2] else last[k + 2 - 4]),
                              [w12_15] "x" (if (k + 3 < 4) first[k + 3] else last[k + 3 - 4]),
                        );
                    }

                    const w: V = (if (k < 4) first[k] else last[k - 4]) +% comptime W[k];
                    y = asm ("sha256rnds2 %[x], %[y]"
                        : [y] "=x" (-> V),
                        : [_] "0" (y),
                          [x] "x" (x),
                          [_] "{xmm0}" (w),
                    );
                    x = asm ("sha256rnds2 %[y], %[x]"
                        : [x] "=x" (-> V),
                        : [_] "0" (x),
                          [y] "x" (y),
                          [_] "{xmm0}" (@shuffle(u32, w, undefined, @Vector(4, i32){ 2, 3, 0, 1 })),
                    );
                }

                x +%= feba;
                y +%= hgdc;

                first[0] = @shuffle(u32, x, y, @Vector(4, i32){ 3, 2, ~@as(i32, 3), ~@as(i32, 2) });
                first[1] = @shuffle(u32, x, y, @Vector(4, i32){ 1, 0, ~@as(i32, 1), ~@as(i32, 0) });
            }

            out.data[0..16].* = @bitCast(@byteSwap(first[0]));
            out.data[16..32].* = @bitCast(@byteSwap(first[1]));
        } else {
            out.* = input.*;
            for (0..count) |_| Sha256.hash(&out.data, &out.data, .{});
        }
    }
};
