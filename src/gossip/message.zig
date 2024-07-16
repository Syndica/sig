const std = @import("std");
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const Signature = @import("../core/signature.zig").Signature;
const bincode = @import("../bincode/bincode.zig");
const SocketAddr = @import("../net/net.zig").SocketAddr;

const _gossip_data = @import("data.zig");
const SignedGossipData = _gossip_data.SignedGossipData;
const GossipData = _gossip_data.GossipData;
const LegacyContactInfo = _gossip_data.LegacyContactInfo;
const getWallclockMs = _gossip_data.getWallclockMs;

const GossipPullFilter = @import("pull_request.zig").GossipPullFilter;
const PACKET_DATA_SIZE = @import("../net/packet.zig").PACKET_DATA_SIZE;

const DefaultPrng = std.rand.DefaultPrng;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const testing = std.testing;

const Ping = @import("ping_pong.zig").Ping;
const Pong = @import("ping_pong.zig").Pong;

pub const MAX_WALLCLOCK: u64 = 1_000_000_000_000_000;

/// Analogous to [Protocol](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/cluster_info.rs#L268)
pub const GossipMessage = union(enum(u32)) {
    PullRequest: struct { GossipPullFilter, SignedGossipData },
    PullResponse: struct { Pubkey, []SignedGossipData },
    PushMessage: struct { Pubkey, []SignedGossipData },
    PruneMessage: struct { Pubkey, PruneData },
    PingMessage: Ping,
    PongMessage: Pong,

    const Self = @This();

    pub fn verifySignature(self: *Self) !void {
        switch (self.*) {
            .PullRequest => |*pull| {
                var value = pull[1];
                const is_verified = try value.verify(value.id());
                if (!is_verified) {
                    return error.InvalidPullRequest;
                }
            },
            .PullResponse => |*pull| {
                const values = pull[1];
                for (values) |*value| {
                    const is_verified = try value.verify(value.id());
                    if (!is_verified) {
                        return error.InvalidPullResponse;
                    }
                }
            },
            .PushMessage => |*push| {
                const values = push[1];
                for (values) |*value| {
                    const is_verified = try value.verify(value.id());
                    if (!is_verified) {
                        return error.InvalidPushMessage;
                    }
                }
            },
            .PruneMessage => |*prune| {
                var data: PruneData = prune[1];
                data.verify() catch return error.InvalidPruneMessage;
            },
            .PingMessage => |*ping| {
                ping.verify() catch return error.InvalidPingMessage;
            },
            .PongMessage => |*pong| {
                pong.verify() catch return error.InvalidPongMessage;
            },
        }
    }

    pub fn sanitize(self: *Self) !void {
        switch (self.*) {
            .PullRequest => {},
            .PullResponse => {},
            .PushMessage => |*msg| {
                const gossip_values = msg[1];
                for (gossip_values) |value| {
                    const data: GossipData = value.data;
                    try data.sanitize();
                }
            },
            .PruneMessage => |*msg| {
                const from = msg[0];
                const value = msg[1];
                if (!from.equals(&value.pubkey)) {
                    return error.InvalidValue;
                }
                try sanitizeWallclock(value.wallclock);
            },
            // do nothing
            .PingMessage => {},
            .PongMessage => {},
        }
    }

    /// Frees the ephemeral messaging data that is only needed
    /// for the initial processing of an incoming message.
    ///
    /// Does not free the contained gossip data that
    /// needs to be stored in the gossip table.
    pub fn shallowFree(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .PullRequest => |*msg| {
                msg[0].deinit();
            },
            .PullResponse => |*msg| {
                allocator.free(msg[1]);
            },
            .PushMessage => |*msg| {
                allocator.free(msg[1]);
            },
            .PruneMessage => |*msg| {
                allocator.free(msg[1].prunes);
            },
            .PingMessage => {},
            .PongMessage => {},
        }
    }
};

pub fn sanitizeWallclock(wallclock: u64) !void {
    if (wallclock >= MAX_WALLCLOCK) {
        return error.InvalidValue;
    }
}

pub const PruneData = struct {
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

    const Self = @This();

    pub fn init(pubkey: Pubkey, prunes: []Pubkey, destination: Pubkey, now: u64) Self {
        return Self{
            .pubkey = pubkey,
            .prunes = prunes,
            .destination = destination,
            .signature = Signature.init(.{0} ** 64),
            .wallclock = now,
        };
    }

    const PruneSignableData = struct {
        pubkey: Pubkey,
        prunes: []Pubkey,
        destination: Pubkey,
        wallclock: u64,
    };

    pub fn random(rng: std.rand.Random, keypair: *KeyPair) !PruneData {
        var self = PruneData{
            .pubkey = Pubkey.fromPublicKey(&keypair.public_key),
            .prunes = &[0]Pubkey{},
            .signature = Signature.init(.{0} ** 64),
            .destination = Pubkey.random(rng),
            .wallclock = getWallclockMs(),
        };
        try self.sign(keypair);

        return self;
    }

    pub fn sign(self: *PruneData, keypair: *const KeyPair) !void {
        // should always be enough space of is invalid msg
        var slice: [PACKET_DATA_SIZE]u8 = undefined;
        const signable_data = PruneSignableData{
            .pubkey = self.pubkey,
            .prunes = self.prunes,
            .destination = self.destination,
            .wallclock = self.wallclock,
        };
        const out = try bincode.writeToSlice(&slice, signable_data, bincode.Params{});
        var sig = try keypair.sign(out, null);
        self.signature.data = sig.toBytes();
    }

    pub fn verify(self: *const PruneData) !void {
        // should always be enough space of is invalid msg
        var slice: [PACKET_DATA_SIZE]u8 = undefined;
        const signable_data = PruneSignableData{
            .pubkey = self.pubkey,
            .prunes = self.prunes,
            .destination = self.destination,
            .wallclock = self.wallclock,
        };
        const out = try bincode.writeToSlice(&slice, signable_data, bincode.Params{});
        if (!self.signature.verify(self.pubkey, out)) {
            return error.InvalidSignature;
        }
    }
};

test "gossip.message: push message serialization is predictable" {
    var rng = DefaultPrng.init(_gossip_data.getWallclockMs());
    const pubkey = Pubkey.random(rng.random());
    var values = std.ArrayList(SignedGossipData).init(std.testing.allocator);
    defer values.deinit();

    const msg = GossipMessage{ .PushMessage = .{ pubkey, values.items } };
    const empty_size = bincode.sizeOf(msg, .{});

    const value = try SignedGossipData.random(rng.random(), &(try KeyPair.create(null)));
    const value_size = bincode.sizeOf(value, .{});
    try values.append(value);
    try std.testing.expect(values.items.len == 1);

    const msg_with_value = GossipMessage{ .PushMessage = .{ pubkey, values.items } };
    const msg_value_size = bincode.sizeOf(msg_with_value, .{});
    try std.testing.expectEqual(value_size + empty_size, msg_value_size);
}

test "gossip.message: test prune data sig verify" {
    var keypair = try KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes([_]u8{
        125, 52,  162, 97,  231, 139, 58,  13,  185, 212, 57,  142, 136, 12,  21,  127, 228, 71,
        115, 126, 138, 52,  102, 69,  103, 185, 45,  255, 132, 222, 243, 138, 25,  117, 21,  11,
        61,  170, 38,  18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230,
        121, 12,  227, 248, 199, 156, 253, 144, 175, 67,
    }));

    var rng = DefaultPrng.init(_gossip_data.getWallclockMs());
    var prune = try PruneData.random(rng.random(), &keypair);

    try prune.verify();

    const rust_bytes = [_]u8{ 80, 98, 7, 181, 129, 96, 249, 247, 34, 39, 251, 41, 125, 241, 31, 25, 122, 103, 202, 48, 78, 160, 222, 65, 228, 81, 171, 237, 233, 87, 248, 29, 37, 0, 19, 66, 83, 207, 78, 86, 232, 157, 184, 144, 71, 12, 223, 86, 144, 169, 160, 171, 139, 248, 106, 63, 194, 178, 144, 119, 51, 60, 201, 7 };

    var prune_v2 = PruneData{
        .pubkey = Pubkey.fromPublicKey(&keypair.public_key),
        .prunes = &[0]Pubkey{},
        .signature = Signature.init(.{0} ** 64),
        .destination = Pubkey.fromPublicKey(&keypair.public_key),
        .wallclock = 0,
    };
    try prune_v2.sign(&keypair);

    var sig_bytes = prune_v2.signature.data;
    try std.testing.expectEqualSlices(u8, &rust_bytes, &sig_bytes);
}

test "gossip.message: ping message serializes and deserializes correctly" {
    var keypair = KeyPair.create(null) catch unreachable;

    var rng = std.rand.DefaultPrng.init(0);

    var original = GossipMessage{ .PingMessage = try Ping.random(rng.random(), &keypair) };
    var buf = [_]u8{0} ** 1232;

    const serialized = try bincode.writeToSlice(buf[0..], original, bincode.Params.standard);

    var deserialized = try bincode.readFromSlice(testing.allocator, GossipMessage, serialized, bincode.Params.standard);

    try testing.expect(original.PingMessage.from.equals(&deserialized.PingMessage.from));
    try testing.expect(original.PingMessage.signature.eql(&deserialized.PingMessage.signature));
    try testing.expect(std.mem.eql(u8, original.PingMessage.token[0..], deserialized.PingMessage.token[0..]));
}

test "gossip.message: test ping pong sig verify" {
    var keypair = KeyPair.create(null) catch unreachable;

    var rng = std.rand.DefaultPrng.init(0);
    var ping = try Ping.random(rng.random(), &keypair);
    var msg = GossipMessage{ .PingMessage = ping };
    try msg.verifySignature();

    var pong = GossipMessage{ .PongMessage = try Pong.init(&ping, &keypair) };
    try pong.verifySignature();
}

test "gossip.message: pull request serializes and deserializes" {
    var rust_bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 190, 193, 13, 216, 175, 227, 117, 168, 246, 219, 213, 39, 67, 249, 88, 3, 238, 151, 144, 15, 23, 142, 153, 198, 47, 221, 117, 132, 218, 28, 29, 115, 248, 253, 211, 101, 137, 19, 174, 112, 43, 57, 251, 110, 173, 14, 71, 0, 186, 24, 36, 61, 75, 241, 119, 73, 86, 93, 136, 249, 167, 40, 134, 14, 0, 0, 0, 0, 25, 117, 21, 11, 61, 170, 38, 18, 67, 196, 242, 219, 50, 154, 4, 254, 79, 227, 253, 229, 188, 230, 121, 12, 227, 248, 199, 156, 253, 144, 175, 67, 0, 0, 0, 0, 127, 0, 0, 1, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var keypair = try KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes([_]u8{
        125, 52,  162, 97,  231, 139, 58,  13,  185, 212, 57,  142, 136, 12,  21,  127, 228, 71,
        115, 126, 138, 52,  102, 69,  103, 185, 45,  255, 132, 222, 243, 138, 25,  117, 21,  11,
        61,  170, 38,  18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230,
        121, 12,  227, 248, 199, 156, 253, 144, 175, 67,
    }));
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);

    // pull requests only use ContactInfo data
    const gossip_addr = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 1234);
    const unspecified_addr = SocketAddr.unspecified();
    const legacy_contact_info = LegacyContactInfo{
        .id = pubkey,
        .gossip = gossip_addr,
        .turbine_recv = unspecified_addr,
        .turbine_recv_quic = unspecified_addr,
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
    const data = GossipData{
        .LegacyContactInfo = legacy_contact_info,
    };
    const value = try SignedGossipData.initSigned(data, &keypair);

    var filter = GossipPullFilter.init(testing.allocator);
    defer filter.deinit();

    const pull = GossipMessage{ .PullRequest = .{
        filter,
        value,
    } };

    var buf = [_]u8{0} ** 1232;
    const serialized = try bincode.writeToSlice(buf[0..], pull, bincode.Params.standard);
    try testing.expectEqualSlices(u8, rust_bytes[0..], serialized);

    const deserialized = try bincode.readFromSlice(testing.allocator, GossipMessage, serialized, bincode.Params.standard);
    try testing.expect(std.meta.eql(pull, deserialized));
}

test "gossip.message: push message serializes and deserializes correctly" {
    const kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk);

    const gossip_addr = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 1234);
    const unspecified_addr = SocketAddr.unspecified();

    var buf = [_]u8{0} ** 1024;

    const legacy_contact_info = LegacyContactInfo{
        .id = id,
        .gossip = gossip_addr,
        .turbine_recv = unspecified_addr,
        .turbine_recv_quic = unspecified_addr,
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

    const data = GossipData{
        .LegacyContactInfo = legacy_contact_info,
    };

    var rust_bytes = [_]u8{ 2, 0, 0, 0, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 1, 0, 0, 0, 0, 0, 0, 0, 247, 119, 8, 235, 122, 255, 148, 105, 239, 205, 20, 32, 112, 227, 208, 92, 37, 18, 5, 71, 105, 58, 203, 18, 69, 196, 217, 80, 56, 47, 2, 45, 166, 139, 244, 114, 132, 206, 156, 187, 206, 205, 0, 176, 167, 196, 11, 17, 22, 77, 142, 176, 215, 8, 110, 221, 30, 206, 219, 80, 196, 217, 118, 13, 0, 0, 0, 0, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 0, 0, 0, 0, 127, 0, 0, 1, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const gossip_value = try SignedGossipData.initSigned(data, &kp);
    var values = [_]SignedGossipData{gossip_value};
    const pushmsg = GossipMessage{ .PushMessage = .{ id, &values } };
    var bytes = try bincode.writeToSlice(buf[0..], pushmsg, bincode.Params.standard);
    try testing.expectEqualSlices(u8, bytes[0..bytes.len], &rust_bytes);
}

test "gossip.message: Protocol.PullRequest.ContactInfo signature is valid" {
    var contact_info_pull_response_packet_from_mainnet = [_]u8{
        1,   0,   0,   0,   9,   116, 228, 64,  179, 73,  145, 220, 74,  55,  179, 56,  86,  218,
        47,  62,  172, 162, 127, 102, 37,  146, 103, 117, 255, 245, 248, 212, 101, 163, 188, 231,
        1,   0,   0,   0,   0,   0,   0,   0,   191, 176, 3,   19,  120, 201, 21,  227, 94,  146,
        60,  127, 111, 181, 147, 150, 68,  234, 8,   131, 192, 30,  108, 150, 121, 5,   134, 220,
        252, 71,  136, 63,  192, 193, 133, 15,  13,  156, 242, 62,  160, 222, 146, 240, 206, 85,
        123, 212, 13,  187, 138, 37,  135, 174, 74,  94,  36,  86,  43,  124, 18,  119, 152, 12,
        11,  0,   0,   0,   168, 36,  147, 159, 43,  110, 51,  177, 21,  191, 96,  206, 25,  12,
        133, 238, 147, 223, 2,   133, 105, 29,  83,  234, 44,  111, 123, 246, 244, 15,  167, 219,
        185, 175, 235, 255, 204, 49,  220, 224, 176, 3,   13,  13,  6,   0,   242, 150, 1,   17,
        9,   0,   0,   0,   0,   22,  194, 36,  85,  0,   1,   0,   0,   0,   0,   34,  221, 220,
        125, 12,  0,   0,   192, 62,  10,  0,   1,   11,  0,   1,   5,   0,   1,   6,   0,   1,
        9,   0,   1,   4,   0,   3,   8,   0,   1,   7,   0,   1,   1,   0,   1,   2,   0,   248,
        6,   3,   0,   1,   0,
    };

    var message = try bincode.readFromSlice(
        std.testing.allocator,
        GossipMessage,
        &contact_info_pull_response_packet_from_mainnet,
        bincode.Params.standard,
    );
    defer bincode.free(std.testing.allocator, message);

    try message.sanitize();
    try message.verifySignature();
}
