const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const DefaultPrng = std.Random.DefaultPrng;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const SecretKey = std.crypto.sign.Ed25519.SecretKey;

const PACKET_DATA_SIZE = sig.net.Packet.DATA_SIZE;
pub const PRUNE_DATA_PREFIX: []const u8 = "\xffSOLANA_PRUNE_DATA";

pub const PruneData = struct {
    /// Pubkey of the node that sent this prune data
    pubkey: Pubkey,
    /// Pubkeys of nodes that should be pruned
    prunes: []const Pubkey,
    /// Signature of this Prune Message
    signature: Signature,
    /// The Pubkey of the intended node/destination for this message
    destination: Pubkey,
    /// Wallclock of the node that generated this message
    wallclock: u64,

    pub fn init(pubkey: Pubkey, prunes: []const Pubkey, destination: Pubkey, now: u64) PruneData {
        return .{
            .pubkey = pubkey,
            .prunes = prunes,
            .destination = destination,
            .signature = Signature.ZEROES,
            .wallclock = now,
        };
    }

    pub fn deinit(self: PruneData, allocator: std.mem.Allocator) void {
        allocator.free(self.prunes);
    }

    const PruneSignableData = struct {
        pubkey: Pubkey,
        prunes: []const Pubkey,
        destination: Pubkey,
        wallclock: u64,
    };

    const PruneSignableDataWithPrefix = struct {
        prefix: []const u8 = PRUNE_DATA_PREFIX,
        pubkey: Pubkey,
        prunes: []const Pubkey,
        destination: Pubkey,
        wallclock: u64,
    };

    pub fn initRandom(random: std.Random, keypair: *const KeyPair) !PruneData {
        var self = PruneData{
            .pubkey = Pubkey.fromPublicKey(&keypair.public_key),
            .prunes = &[0]Pubkey{},
            .signature = Signature.ZEROES,
            .destination = Pubkey.initRandom(random),
            .wallclock = sig.time.clock.now(),
        };
        try self.sign(keypair);

        return self;
    }

    pub fn sign(self: *PruneData, keypair: *const KeyPair) !void {
        try self.signWithoutPrefix(keypair);
    }

    pub fn signWithoutPrefix(self: *PruneData, keypair: *const KeyPair) !void {
        const signable_data = PruneSignableData{
            .pubkey = self.pubkey,
            .prunes = self.prunes,
            .destination = self.destination,
            .wallclock = self.wallclock,
        };

        // serialize
        var d: [PACKET_DATA_SIZE]u8 = undefined;
        const data = try bincode.writeToSlice(&d, signable_data, .{});
        // sign
        var signature = try keypair.sign(data, null);
        self.signature.data = signature.toBytes();
    }

    pub fn signWithPrefix(self: *PruneData, keypair: *const KeyPair) !void {
        const signable_data = PruneSignableDataWithPrefix{
            .pubkey = self.pubkey,
            .prunes = self.prunes,
            .destination = self.destination,
            .wallclock = self.wallclock,
        };

        // serialize
        var d: [PACKET_DATA_SIZE]u8 = undefined;
        const data = try bincode.writeToSlice(&d, signable_data, .{});
        // sign
        var signature = try keypair.sign(data, null);
        self.signature.data = signature.toBytes();
    }

    pub fn verify(self: *const PruneData) !void {
        self.verifyWithoutPrefix() catch |err| switch (err) {
            error.InvalidSignature => try self.verifyWithPrefix(),
            else => return err,
        };
    }

    pub fn verifyWithoutPrefix(self: *const PruneData) !void {
        const signable_data = PruneSignableData{
            .pubkey = self.pubkey,
            .prunes = self.prunes,
            .destination = self.destination,
            .wallclock = self.wallclock,
        };

        // serialize
        var d: [PACKET_DATA_SIZE]u8 = undefined;
        const data = try bincode.writeToSlice(&d, signable_data, .{});
        // verify
        if (!try self.signature.verify(self.pubkey, data))
            return error.InvalidSignature;
    }

    pub fn verifyWithPrefix(self: *const PruneData) !void {
        const signable_data = PruneSignableDataWithPrefix{
            .pubkey = self.pubkey,
            .prunes = self.prunes,
            .destination = self.destination,
            .wallclock = self.wallclock,
        };

        // serialize
        var d: [PACKET_DATA_SIZE]u8 = undefined;
        const data = try bincode.writeToSlice(&d, signable_data, .{});
        // verify
        if (!try self.signature.verify(self.pubkey, data))
            return error.InvalidSignature;
    }
};

test "sign/verify PruneData with prefix" {
    // src: https://github.com/anza-xyz/agave/blob/82347779ffdad910ce1f4bb23949e0c46bdddd33/gossip/src/protocol.rs#L686
    const wallclock = 1736887210868;
    const keypair = try KeyPair.fromSecretKey(try SecretKey.fromBytes([_]u8{
        187, 129, 57,  32,  118, 252, 92,  64,  33,  91,  198, 4,  45,  142, 35,  144, 247,
        236, 207, 93,  140, 218, 133, 14,  145, 14,  121, 148, 86, 67,  243, 201, 74,  44,
        91,  45,  177, 37,  96,  182, 179, 147, 191, 143, 138, 47, 10,  56,  172, 249, 27,
        230, 102, 29,  182, 139, 6,   61,  35,  28,  233, 6,   63, 229,
    }));
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    const expected_pubkey = try Pubkey.parseBase58String(
        "5zYQ7PqYa81fw3rXAYUtmUcoL9TFwG67wcE9LW8hwtfE",
    );
    try std.testing.expectEqual(expected_pubkey.data, pubkey.data);

    const prune1 = try Pubkey.parseBase58String("1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM");
    const prune2 = try Pubkey.parseBase58String("1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh");
    const prune3 = try Pubkey.parseBase58String("11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3");
    const destination = try Pubkey.parseBase58String("11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP");

    const expected_signature = try Signature.parseBase58String(
        "XjXQxG6vhrfPPQtddCgkfmKsH69YoUvG6GTrQfvmB73GUTjXCL5VDBE3Na94e4uT2MWPTBP3cinVdpHdBb9zAxY",
    );

    var prune_data = PruneData{
        .pubkey = pubkey,
        .destination = destination,
        .prunes = &[_]Pubkey{ prune1, prune2, prune3 },
        .signature = expected_signature,
        .wallclock = wallclock,
    };

    // check if verification works (with expected signature)
    try prune_data.verify();

    // check if signing works
    try prune_data.signWithPrefix(&keypair);
    try std.testing.expectEqual(expected_signature.data, prune_data.signature.data);
}

test "PruneData sig verify" {
    var keypair = try KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes([_]u8{
        125, 52,  162, 97,  231, 139, 58,  13,  185, 212, 57,  142, 136, 12,  21,  127, 228, 71,
        115, 126, 138, 52,  102, 69,  103, 185, 45,  255, 132, 222, 243, 138, 25,  117, 21,  11,
        61,  170, 38,  18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230,
        121, 12,  227, 248, 199, 156, 253, 144, 175, 67,
    }));

    var prng = DefaultPrng.init(0);
    var prune = try PruneData.initRandom(prng.random(), &keypair);

    try prune.verify();

    const rust_bytes = [_]u8{
        80,  98,  7,   181, 129, 96,  249, 247, 34,  39,  251, 41, 125, 241, 31,  25,  122, 103,
        202, 48,  78,  160, 222, 65,  228, 81,  171, 237, 233, 87, 248, 29,  37,  0,   19,  66,
        83,  207, 78,  86,  232, 157, 184, 144, 71,  12,  223, 86, 144, 169, 160, 171, 139, 248,
        106, 63,  194, 178, 144, 119, 51,  60,  201, 7,
    };

    var prune_v2 = PruneData{
        .pubkey = Pubkey.fromPublicKey(&keypair.public_key),
        .prunes = &[0]Pubkey{},
        .signature = Signature.ZEROES,
        .destination = Pubkey.fromPublicKey(&keypair.public_key),
        .wallclock = 0,
    };
    try prune_v2.signWithoutPrefix(&keypair);

    var sig_bytes = prune_v2.signature.data;
    try std.testing.expectEqualSlices(u8, &rust_bytes, &sig_bytes);
}
