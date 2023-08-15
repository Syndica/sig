const std = @import("std");
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const Hash = @import("../core/hash.zig").Hash;
const Signature = @import("../core/signature.zig").Signature;
const bincode = @import("../bincode/bincode.zig");
const Channel = @import("../sync/channel");
const SocketAddr = @import("net.zig").SocketAddr;

const crds = @import("crds.zig");
const CrdsValue = crds.CrdsValue;
const CrdsData = crds.CrdsData;
const Version = crds.Version;
const LegacyVersion2 = crds.LegacyVersion2;
const LegacyContactInfo = crds.LegacyContactInfo;

const pull_import = @import("pull_request.zig");
const CrdsFilter = pull_import.CrdsFilter;

const Option = @import("../option.zig").Option;
const DefaultPrng = std.rand.DefaultPrng;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const testing = std.testing;

const Protocol = @import("./protocol.zig").Protocol;

const PING_TOKEN_SIZE: usize = 32;
const PING_PONG_HASH_PREFIX: [16]u8 = .{
    'S', 'O', 'L', 'A', 'N', 'A', '_', 'P', 'I', 'N', 'G', '_', 'P', 'O', 'N', 'G',
};

pub const Ping = struct {
    from: Pubkey,
    token: [PING_TOKEN_SIZE]u8,
    signature: Signature,

    const Self = @This();

    pub fn init(token: [PING_TOKEN_SIZE]u8, keypair: KeyPair) !Self {
        const sig = try keypair.sign(&token, null);
        var self = Self{
            .from = Pubkey.fromPublicKey(&keypair.public_key, true),
            .token = token,
            .signature = Signature.init(sig.toBytes()),
        };
        return self;
    }

    pub fn random(keypair: KeyPair) Self {
        var token: [PING_TOKEN_SIZE]u8 = undefined;
        var rand = DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        rand.fill(&token);
        var sig = keypair.sign(&token, null) catch unreachable; // TODO: do we need noise?

        return Self{
            .from = Pubkey.fromPublicKey(&keypair.public_key, true),
            .token = token,
            .signature = Signature.init(sig.toBytes()),
        };
    }

    pub fn verify(self: *Self) !void {
        if (!self.signature.verify(self.from, &self.token)) {
            return error.InvalidSignature;
        }
    }
};

pub const Pong = struct {
    from: Pubkey,
    hash: Hash, // Hash of received ping token.
    signature: Signature,

    const Self = @This();

    pub fn init(ping: *Ping, keypair: *KeyPair) !Self {
        var token_with_prefix = PING_PONG_HASH_PREFIX ++ ping.token;
        var hash = Hash.generateSha256Hash(token_with_prefix[0..]);
        const sig = try keypair.sign(&hash.data, null);

        return Self{
            .from = Pubkey.fromPublicKey(&keypair.public_key, true),
            .hash = hash,
            .signature = Signature.init(sig.toBytes()),
        };
    }

    pub fn verify(self: *Self) !void {
        if (!self.signature.verify(self.from, &self.hash.data)) {
            return error.InvalidSignature;
        }
    }
};

test "gossip.protocol: ping signatures match rust" {
    var keypair = try KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes([_]u8{
        125, 52,  162, 97,  231, 139, 58,  13,  185, 212, 57,  142, 136, 12,  21,  127, 228, 71,
        115, 126, 138, 52,  102, 69,  103, 185, 45,  255, 132, 222, 243, 138, 25,  117, 21,  11,
        61,  170, 38,  18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230,
        121, 12,  227, 248, 199, 156, 253, 144, 175, 67,
    }));
    var ping = Ping.init([_]u8{0} ** PING_TOKEN_SIZE, keypair) catch unreachable;
    const sig = ping.signature.data;

    const rust_sig = [_]u8{ 52, 171, 91, 205, 183, 211, 38, 219, 53, 155, 163, 118, 202, 169, 15, 237, 147, 87, 209, 20, 6, 115, 24, 114, 196, 41, 217, 55, 123, 245, 35, 138, 126, 47, 233, 182, 90, 206, 13, 173, 212, 107, 94, 120, 167, 254, 14, 11, 253, 199, 158, 4, 203, 42, 173, 143, 214, 209, 132, 158, 223, 62, 214, 11 };
    try testing.expect(std.mem.eql(u8, &sig, &rust_sig));
    try ping.verify();
}
