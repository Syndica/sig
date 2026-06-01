//! Export wrappers for the sig-crypto static library.
//! Only cryptographic operations are exported here — those that benefit from
//! optimized compilation (ReleaseFast, AVX-512/SHA-NI, etc.).
//! Non-crypto helpers (eql, order, parse, base58, indexIn) are implemented
//! directly in the client-side header (lib/crypto.zig).
//!
//! Consumers access these via @extern in lib/crypto.zig.

const common = @import("common");

const Hash = common.Hash;
const Pubkey = common.Pubkey;
const Signature = common.Signature;

// -- Hash Exports (cryptographic) -- //

fn hashInit(data_ptr: [*]const u8, data_len: usize, out: *Hash) callconv(.c) void {
    out.* = Hash.init(data_ptr[0..data_len]);
}
comptime {
    @export(&hashInit, .{ .name = "sig_crypto_hash_init" });
}

fn hashInitMany(
    ptrs: [*]const [*]const u8,
    lens: [*]const usize,
    count: usize,
    out: *Hash,
) callconv(.c) void {
    var slices: [8][]const u8 = undefined;
    const n = @min(count, 8);
    for (0..n) |i| {
        slices[i] = ptrs[i][0..lens[i]];
    }
    out.* = Hash.initMany(slices[0..n]);
}
comptime {
    @export(&hashInitMany, .{ .name = "sig_crypto_hash_init_many" });
}

fn hashExtend(
    self: *const Hash,
    data_ptr: [*]const u8,
    data_len: usize,
    out: *Hash,
) callconv(.c) void {
    out.* = self.extend(data_ptr[0..data_len]);
}
comptime {
    @export(&hashExtend, .{ .name = "sig_crypto_hash_extend" });
}

fn hashRepeated(input: *const Hash, out: *Hash, count: usize) callconv(.c) void {
    Hash.hashRepeated(input, out, count);
}
comptime {
    @export(&hashRepeated, .{ .name = "sig_crypto_hash_repeated" });
}

// -- Signature Exports (cryptographic) -- //

fn sigVerify(
    self: *const Signature,
    pubkey: *const Pubkey,
    msg_ptr: [*]const u8,
    msg_len: usize,
) callconv(.c) bool {
    self.verify(pubkey, msg_ptr[0..msg_len]) catch return false;
    return true;
}
comptime {
    @export(&sigVerify, .{ .name = "sig_crypto_sig_verify" });
}
