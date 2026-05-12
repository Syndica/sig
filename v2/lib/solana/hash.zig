const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const builtin = @import("builtin");
const base58 = @import("base58");
const build_options = @import("build-options");

const BASE58_ENDEC = base58.Table.BITCOIN;
const Sha256 = std.crypto.hash.sha2.Sha256;

const has_sha_ni = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHasAll(builtin.cpu.features, &.{ .sha, .avx });
comptime {
    if (builtin.cpu.arch == .x86_64 and !has_sha_ni and !build_options.allow_no_sha) @compileError(
        "Target lacks the x86 SHA extension required for the fast hashRepeated path. " ++
            "Re-build with -Dallow-no-sha=true to opt in to the slower AVX software fallback.",
    );
}

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

    /// Makes a new hash by hashing the current hash's bytes with the provided data
    pub fn extend(self: Hash, data: []const u8) Hash {
        return .initMany(&.{ &self.data, data });
    }

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

        var encoded: [BASE58_MAX_SIZE]u8 = undefined;
        var encoded_len: usize = 0;

        @memcpy(encoded[0..str.len], str);
        encoded_len += str.len;

        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);

        var decoded_buf: [SIZE + 2]u8 = undefined;
        const decoded_len = BASE58_ENDEC.decode(&decoded_buf, encoded[0..encoded_len]) catch {
            return error.InvalidHash;
        };

        if (decoded_len != SIZE) return error.InvalidHash;
        return .{ .data = decoded_buf[0..SIZE].* };
    }

    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);
    pub fn base58String(self: *const Hash, buffer: *[BASE58_MAX_SIZE]u8) []const u8 {
        const len = BASE58_ENDEC.encode(buffer, &self.data);
        return buffer[0..len];
    }

    pub fn format(self: Hash, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [BASE58_MAX_SIZE]u8 = undefined;
        const str = self.base58String(&buf);
        return writer.writeAll(str);
    }

    /// Intended to be used in tests.
    pub fn initRandom(random: std.Random) Hash {
        var data: [SIZE]u8 = undefined;
        random.bytes(&data);
        return .{ .data = data };
    }

    /// `input` and `out` arguments may alias.
    pub fn hashRepeated(input: *const Hash, out: *Hash, count: usize) void {
        hashRepeatedImpl(has_sha_ni, input, out, count);
    }

    inline fn hashRepeatedImpl(
        comptime use_sha_ni: bool,
        input: *const Hash,
        out: *Hash,
        count: usize,
    ) void {
        const V = @Vector(4, u32);

        const iv = [8]u32{
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        };

        const W = [64 / 4]V{
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

        const pad_vec: [2]V = comptime .{
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

        // Rolling hash state as two big-endian-loaded u32 vectors. Each
        // iteration's output feeds directly into W[0]/W[1] of the next.
        var state: [2]V = .{
            @byteSwap(@as(V, @bitCast(input.data[0..16].*))),
            @byteSwap(@as(V, @bitCast(input.data[16..32].*))),
        };

        if (comptime use_sha_ni) {
            var first: [4]V = .{ state[0], state[1] } ++ pad_vec;
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

            state[0] = first[0];
            state[1] = first[1];
        } else {
            // AVX vector message schedule + scalar compression. Targets x86
            // hosts with AVX/AVX2 but no SHA-NI. The schedule's 4-word
            // recurrence vectorizes cleanly; compression is a sequential
            // dep chain so it stays scalar.
            //
            // Algorithm follows the standard SSSE3/AVX SHA-256
            // message-schedule technique used by OpenSSL/BoringSSL.

            // W[2]/W[3] are constant across iterations (SHA-256 padding for
            // a 32-byte message), so K + W for blocks 2 and 3 is comptime.
            const KW_pad: [2]V = comptime .{
                W[2] +% pad_vec[0],
                W[3] +% pad_vec[1],
            };

            const iv_v: [2]V = comptime .{
                .{ iv[0], iv[1], iv[2], iv[3] },
                .{ iv[4], iv[5], iv[6], iv[7] },
            };

            const VSigma = struct {
                inline fn s0(x: V) V {
                    return std.math.rotr(V, x, 7) ^
                        std.math.rotr(V, x, 18) ^
                        (x >> @as(@Vector(4, u5), @splat(3)));
                }
                inline fn s1(x: V) V {
                    return std.math.rotr(V, x, 17) ^
                        std.math.rotr(V, x, 19) ^
                        (x >> @as(@Vector(4, u5), @splat(10)));
                }

                // Compute W[i+16..i+19] from the 16-word window
                // [W0=W[i..i+3], W1=W[i+4..i+7], W2=W[i+8..i+11], W3=W[i+12..i+15]].
                // s1 of the last two new words depends on the first two, so
                // it runs in a second pass.
                inline fn nextBlock(W0: V, W1: V, W2: V, W3: V) V {
                    const w_1_4 = @shuffle(u32, W0, W1, [4]i32{ 1, 2, 3, ~@as(i32, 0) });
                    const w_9_12 = @shuffle(u32, W2, W3, [4]i32{ 1, 2, 3, ~@as(i32, 0) });

                    var T = W0 +% w_9_12 +% s0(w_1_4);

                    const w14_15 = @shuffle(u32, W3, W3, [4]i32{ 2, 3, 2, 3 });
                    const s1_lo = s1(w14_15);
                    T +%= @shuffle(
                        u32,
                        s1_lo,
                        @as(V, @splat(0)),
                        [4]i32{ 0, 1, ~@as(i32, 0), ~@as(i32, 0) },
                    );

                    const w16_17 = @shuffle(u32, T, T, [4]i32{ 0, 1, 0, 1 });
                    const s1_hi = s1(w16_17);
                    T +%= @shuffle(
                        u32,
                        s1_hi,
                        @as(V, @splat(0)),
                        [4]i32{ ~@as(i32, 0), ~@as(i32, 0), 0, 1 },
                    );

                    return T;
                }
            };

            const Sigma = struct {
                inline fn S0(x: u32) u32 {
                    return std.math.rotr(u32, x, 2) ^
                        std.math.rotr(u32, x, 13) ^
                        std.math.rotr(u32, x, 22);
                }
                inline fn S1(x: u32) u32 {
                    return std.math.rotr(u32, x, 6) ^
                        std.math.rotr(u32, x, 11) ^
                        std.math.rotr(u32, x, 25);
                }
            };

            // Hold the rolling hash as two vectors between iterations,
            // mirroring the SHA-NI path. The previous output's big-endian
            // u32s feed directly into W[0]/W[1] of the next compression.
            for (0..count) |_| {
                var Wm: [16]V = undefined;
                Wm[0] = state[0];
                Wm[1] = state[1];
                Wm[2] = pad_vec[0];
                Wm[3] = pad_vec[1];

                var h: [8]u32 = iv;

                inline for (0..16) |block| {
                    if (block >= 4) {
                        Wm[block] = VSigma.nextBlock(
                            Wm[block - 4],
                            Wm[block - 3],
                            Wm[block - 2],
                            Wm[block - 1],
                        );
                    }
                    const KW: V = switch (block) {
                        2 => KW_pad[0],
                        3 => KW_pad[1],
                        else => W[block] +% Wm[block],
                    };

                    inline for (0..4) |j| {
                        const w: u32 = KW[j];

                        const ep1 = Sigma.S1(h[4]);
                        const ch = h[6] ^ (h[4] & (h[5] ^ h[6]));
                        const t1 = h[7] +% ep1 +% ch +% w;

                        const ep0 = Sigma.S0(h[0]);
                        const maj = (h[0] & (h[1] | h[2])) | (h[1] & h[2]);
                        const t2 = ep0 +% maj;

                        h[7] = h[6];
                        h[6] = h[5];
                        h[5] = h[4];
                        h[4] = h[3] +% t1;
                        h[3] = h[2];
                        h[2] = h[1];
                        h[1] = h[0];
                        h[0] = t1 +% t2;
                    }
                }

                // Each iter restarts from IV, so state_out = IV + h.
                state[0] = @as(V, .{ h[0], h[1], h[2], h[3] }) +% iv_v[0];
                state[1] = @as(V, .{ h[4], h[5], h[6], h[7] }) +% iv_v[1];
            }
        }

        out.data[0..16].* = @bitCast(@byteSwap(state[0]));
        out.data[16..32].* = @bitCast(@byteSwap(state[1]));
    }
};
