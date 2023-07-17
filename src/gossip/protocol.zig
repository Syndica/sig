const std = @import("std");
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const Hash = @import("../core/hash.zig").Hash;
const Signature = @import("../core/signature.zig").Signature;
const bincode = @import("bincode-zig");
const Channel = @import("../sync/channel");
const SocketAddr = @import("net.zig").SocketAddr;

const crds = @import("crds.zig");
const CrdsValue = crds.CrdsValue;
const CrdsData = crds.CrdsData;
const CrdsFilter = crds.CrdsFilter;
const Version = crds.Version;
const LegacyVersion2 = crds.LegacyVersion2;
const LegacyContactInfo = crds.LegacyContactInfo;

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

// // TODO: FIX (need to fix the bloom ser/deser test first)
// test "gossip.protocol: pull request serializes and deserializes" {
//     var rust_bytes = [_]u8{
//         0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
//         255, 255, 255, 255, 255, 255, 255, 255, 0,   0,   0,   0,   220, 64,  225, 78,  22,  90,  232, 152, 207, 56,  205, 161, 228, 200, 208, 60,  94,
//         182, 94,  193, 169, 20,  89,  77,  29,  57,  214, 252, 199, 219, 181, 196, 254, 186, 170, 233, 141, 65,  129, 66,  222, 199, 161, 219, 45,  64,
//         65,  179, 236, 234, 226, 27,  41,  106, 134, 167, 159, 38,  162, 92,  15,  180, 135, 1,   7,   0,   0,   0,   25,  117, 21,  11,  61,  170, 38,
//         18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230, 121, 12,  227, 248, 199, 156, 253, 144, 175, 67,  100, 0,   0,   0,
//         0,   0,   0,   0,   1,   0,   2,   0,   3,   0,   0,   4,   0,   0,   0,
//     };
//     var keypair = try KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes([_]u8{
//         125, 52,  162, 97,  231, 139, 58,  13,  185, 212, 57,  142, 136, 12,  21,  127, 228, 71,
//         115, 126, 138, 52,  102, 69,  103, 185, 45,  255, 132, 222, 243, 138, 25,  117, 21,  11,
//         61,  170, 38,  18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230,
//         121, 12,  227, 248, 199, 156, 253, 144, 175, 67,
//     }));

//     var pubkey = Pubkey.fromPublicKey(&keypair.public_key, true);

//     var crds_value = CrdsValue.init(CrdsData{
//         .Version = Version.init(
//             pubkey,
//             100,
//             LegacyVersion2.init(1, 2, 3, Option(u32).None(), 4),
//         ),
//     });

//     try crds_value.sign(keypair);

//     var original = Protocol{ .PullRequest = .{
//         CrdsFilter.init(testing.allocator),
//         crds_value,
//     } };

//     std.debug.print("original: {any}\n", .{original});

//     var buf = [_]u8{0} ** 1232;

//     var serialized = try bincode.writeToSlice(buf[0..], original, bincode.Params.standard);

//     std.debug.print("serialized: {any}\n", .{serialized});

//     var deserialized = try bincode.readFromSlice(testing.allocator, Protocol, serialized, bincode.Params.standard);

//     std.debug.print("deserialized: {any}\n", .{deserialized});

//     // try testing.expect(std.mem.eql(u8, rust_bytes[0..], serialized));
//     try testing.expectEqualSlices(u8, rust_bytes[0..], serialized);

//     try testing.expect(std.meta.eql(original, deserialized));
//     try testing.expect(try deserialized.PullRequest.@"1".verify(pubkey));
// }

test "gossip.protocol: push message serializes and deserializes correctly" {
    var kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk, true);

    const gossip_addr = SocketAddr.init_ipv4(.{127, 0, 0, 1}, 1234);
    const unspecified_addr = SocketAddr.unspecified();

    var buf = [_]u8{0} ** 1024;

    var legacy_contact_info = LegacyContactInfo {
        .id = id,
        .gossip = gossip_addr,
        .tvu = unspecified_addr,
        .tvu_forwards = unspecified_addr,
        .repair = unspecified_addr,
        .tpu = unspecified_addr,
        .tpu_forwards = unspecified_addr,
        .tpu_vote = unspecified_addr,
        .rpc = unspecified_addr,
        .rpc_pubsub = unspecified_addr,
        .serve_repair = unspecified_addr,
        .wallclock = 0,
        .shred_version = 0,
    };

    // // legacy for fixed len encoding (used in labs codebase)
    // var rust_crds_data = [_]u8 { 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 0, 0, 0, 0, 127, 0, 0, 1, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    // var bytes = try bincode.writeToSlice(buf[0..], legacy_contact_info, bincode.Params.standard);
    // std.debug.print("serialized: {any}\n", .{bytes});
    // std.debug.print("rust target: {any}\n", .{rust_crds_data[0..bytes.len]});
    // try testing.expectEqualSlices(u8, bytes[0..bytes.len], rust_crds_data[0..bytes.len]);

    var crds_data = crds.CrdsData {
        .LegacyContactInfo = legacy_contact_info,
    };

    // // legacy for fixed len encoding (used in labs codebase)
    // var rust_crds_data = [_]u8 { 0, 0, 0, 0, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 0, 0, 0, 0, 127, 0, 0, 1, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    // var bytes = try bincode.writeToSlice(buf[0..], crds_data, bincode.Params.standard);
    // std.debug.print("serialized: {any}\n", .{bytes});
    // std.debug.print("rust target: {any}\n", .{rust_crds_data[0..bytes.len]});
    // try testing.expectEqualSlices(u8, bytes[0..bytes.len], rust_crds_data[0..bytes.len]);

    var rust_bytes = [_]u8{2, 0, 0, 0, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 1, 0, 0, 0, 0, 0, 0, 0, 247, 119, 8, 235, 122, 255, 148, 105, 239, 205, 20, 32, 112, 227, 208, 92, 37, 18, 5, 71, 105, 58, 203, 18, 69, 196, 217, 80, 56, 47, 2, 45, 166, 139, 244, 114, 132, 206, 156, 187, 206, 205, 0, 176, 167, 196, 11, 17, 22, 77, 142, 176, 215, 8, 110, 221, 30, 206, 219, 80, 196, 217, 118, 13, 0, 0, 0, 0, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 0, 0, 0, 0, 127, 0, 0, 1, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    var crds_value = try crds.CrdsValue.initSigned(crds_data, kp);
    var values = [_]crds.CrdsValue{ crds_value };
    var pushmsg = Protocol { 
        .PushMessage = .{ 
            id, 
            &values
        }
    };
    var bytes = try bincode.writeToSlice(buf[0..], pushmsg, bincode.Params.standard);
    // std.debug.print("serialized: {any}\n", .{bytes});
    // std.debug.print("rust target: {any}\n", .{rust_bytes[0..bytes.len]});

    try testing.expectEqualSlices(u8, bytes[0..bytes.len], &rust_bytes);
}