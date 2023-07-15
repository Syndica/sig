const std = @import("std");
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const Hash = @import("../core/hash.zig").Hash;
const Signature = @import("../core/signature.zig").Signature;
const bincode = @import("bincode-zig");
const Channel = @import("../sync/channel");
const CrdsValue = @import("crds.zig").CrdsValue;
const CrdsData = @import("crds.zig").CrdsData;
const CrdsFilter = @import("crds.zig").CrdsFilter;
const Version = @import("crds.zig").Version;
const LegacyVersion2 = @import("crds.zig").LegacyVersion2;
const Option = @import("../option.zig").Option;
const DefaultPrng = std.rand.DefaultPrng;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const testing = std.testing;

const PING_TOKEN_SIZE: usize = 32;
const PING_PONG_HASH_PREFIX: [16]u8 = .{
    'S', 'O', 'L', 'A', 'N', 'A', '_', 'P', 'I', 'N', 'G', '_', 'P', 'O', 'N', 'G',
};

const PruneData = struct {
    /// Pubkey of the node that sent this prune data
    pubkey: Pubkey,
    /// Pubkeys of nodes that should be pruned
    prunes: []Pubkey,
    /// Signature of this Prune Message
    signature: Signature,
    /// The Pubkey of the intended node/destination for this message
    destination: Pubkey,
    /// Wallclock of the node that generated this message
    wallclock: u64,
};

/// Gossip protocol messages
pub const Protocol = union(enum(u32)) {
    PullRequest: struct { CrdsFilter, CrdsValue },
    PullResponse: struct { Pubkey, []CrdsValue },
    PushMessage: struct { Pubkey, []CrdsValue },
    PruneMessage: struct { Pubkey, PruneData },
    PingMessage: Ping,
    PongMessage: Pong,
};

pub const Ping = struct {
    from: Pubkey,
    token: [PING_TOKEN_SIZE]u8,
    signature: Signature,

    const Self = @This();

    pub fn init(token: [PING_TOKEN_SIZE]u8, keypair: KeyPair) !Self {
        var sig = try keypair.sign(&token, null);
        var self = Self{
            .from = Pubkey.fromPublicKey(keypair.public_key, true),
            .token = token,
            .signature = sig,
        };
        return self;
    }

    pub fn random(keypair: KeyPair) Self {
        var token: [PING_TOKEN_SIZE]u8 = undefined;
        var rand = DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        rand.fill(&token);
        var sig = keypair.sign(&token, null) catch unreachable; // TODO: do we need noise?
        var self = Self{
            .from = Pubkey.fromPublicKey(&keypair.public_key, true),
            .token = token,
            .signature = Signature.init(sig.toBytes()),
        };
        return self;
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
        var sig = try keypair.sign(hash, null);
        var self = Self{
            .from = Pubkey.fromPublicKey(keypair.public_key, true),
            .hash = hash,
            .signature = sig,
        };
        return self;
    }
};

const logger = std.log.scoped(.protocol);

test "gossip.protocol: ping message serializes and deserializes correctly" {
    var keypair = KeyPair.create(null) catch unreachable;

    var original = Protocol{ .PingMessage = Ping.random(keypair) };
    var buf = [_]u8{0} ** 1232;

    var serialized = try bincode.writeToSlice(buf[0..], original, bincode.Params.standard);

    var deserialized = try bincode.readFromSlice(testing.allocator, Protocol, serialized, bincode.Params.standard);

    try testing.expect(original.PingMessage.from.equals(&deserialized.PingMessage.from));
    try testing.expect(original.PingMessage.signature.eql(&deserialized.PingMessage.signature));
    try testing.expect(std.mem.eql(u8, original.PingMessage.token[0..], deserialized.PingMessage.token[0..]));
}

test "gossip.protocol: ping message matches rust bytes" {
    var keypair = KeyPair.create(null) catch unreachable;

    var original = Protocol{ .PingMessage = Ping.random(keypair) };
    var buf = [_]u8{0} ** 1232;

    var serialized = try bincode.writeToSlice(buf[0..], original, bincode.Params.standard);

    var deserialized = try bincode.readFromSlice(testing.allocator, Protocol, serialized, bincode.Params.standard);

    try testing.expect(original.PingMessage.from.equals(&deserialized.PingMessage.from));
    try testing.expect(original.PingMessage.signature.eql(&deserialized.PingMessage.signature));
    try testing.expect(std.mem.eql(u8, original.PingMessage.token[0..], deserialized.PingMessage.token[0..]));
}

test "gossip.protocol: ping message serializes and deserializes" {
    var rust_bytes = [_]u8{
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        255, 255, 255, 255, 255, 255, 255, 255, 0,   0,   0,   0,   220, 64,  225, 78,  22,  90,  232, 152, 207, 56,  205, 161, 228, 200, 208, 60,  94,
        182, 94,  193, 169, 20,  89,  77,  29,  57,  214, 252, 199, 219, 181, 196, 254, 186, 170, 233, 141, 65,  129, 66,  222, 199, 161, 219, 45,  64,
        65,  179, 236, 234, 226, 27,  41,  106, 134, 167, 159, 38,  162, 92,  15,  180, 135, 1,   7,   0,   0,   0,   25,  117, 21,  11,  61,  170, 38,
        18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230, 121, 12,  227, 248, 199, 156, 253, 144, 175, 67,  100, 0,   0,   0,
        0,   0,   0,   0,   1,   0,   2,   0,   3,   0,   0,   4,   0,   0,   0,
    };
    var keypair = try KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes([_]u8{
        125, 52,  162, 97,  231, 139, 58,  13,  185, 212, 57,  142, 136, 12,  21,  127, 228, 71,
        115, 126, 138, 52,  102, 69,  103, 185, 45,  255, 132, 222, 243, 138, 25,  117, 21,  11,
        61,  170, 38,  18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230,
        121, 12,  227, 248, 199, 156, 253, 144, 175, 67,
    }));

    var pubkey = Pubkey.fromPublicKey(&keypair.public_key, true);

    var crds_value = CrdsValue.init(CrdsData{
        .Version = Version.init(
            pubkey,
            100,
            LegacyVersion2.init(1, 2, 3, Option(u32).None(), 4),
        ),
    });

    try crds_value.sign(keypair);

    var original = Protocol{ .PullRequest = .{
        CrdsFilter.init(testing.allocator),
        crds_value,
    } };

    std.debug.print("original: {any}\n", .{original});

    var buf = [_]u8{0} ** 1232;

    var serialized = try bincode.writeToSlice(buf[0..], original, bincode.Params.standard);

    std.debug.print("serialized: {any}\n", .{serialized});

    var deserialized = try bincode.readFromSlice(testing.allocator, Protocol, serialized, bincode.Params.standard);

    std.debug.print("deserialized: {any}\n", .{deserialized});

    try testing.expect(std.mem.eql(u8, rust_bytes[0..], serialized));
    try testing.expect(std.meta.eql(original, deserialized));
    try testing.expect(try deserialized.PullRequest.@"1".verify(pubkey));
}
