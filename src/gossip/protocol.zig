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

const Ping = @import("./ping_pong.zig").Ping;
const Pong = @import("./ping_pong.zig").Pong;

const logger = std.log.scoped(.protocol);

pub const MAX_WALLCLOCK: u64 = 1_000_000_000_000_000;

/// Gossip protocol messages
pub const Protocol = union(enum(u32)) {
    PullRequest: struct { CrdsFilter, CrdsValue },
    PullResponse: struct { Pubkey, []CrdsValue },
    PushMessage: struct { Pubkey, []CrdsValue },
    PruneMessage: struct { Pubkey, PruneData },
    PingMessage: Ping,
    PongMessage: Pong,

    pub fn verify_signature(self: *Protocol) !void {
        switch (self.*) {
            .PullRequest => |*pull| {
                var value = pull[1];
                const is_verified = try value.verify(value.id());
                if (!is_verified) {
                    return error.InvalidValue;
                }
            },
            .PullResponse => |*pull| {
                var values = pull[1];
                for (values) |*value| {
                    const is_verified = try value.verify(value.id());
                    if (!is_verified) {
                        return error.InvalidValue;
                    }
                }
            },
            .PushMessage => |*push| {
                var values = push[1];
                for (values) |*value| {
                    const is_verified = try value.verify(value.id());
                    if (!is_verified) {
                        return error.InvalidValue;
                    }
                }
            },
            .PruneMessage => |*prune| {
                var data = prune[1];
                try data.verify();
            },
            .PingMessage => |*ping| {
                try ping.verify();
            },
            .PongMessage => |*pong| {
                try pong.verify();
            },
        }
    }

    pub fn sanitize(self: *Protocol) !void {
        switch (self.*) {
            .PullRequest => {},
            .PullResponse => {},
            .PushMessage => |*msg| {
                const crds_values = msg[1];
                for (crds_values) |value| {
                    const data = value.data;
                    try data.sanitize();
                }
            },
            .PruneMessage => |*msg| {
                const from = msg[0];
                const value = msg[1];
                if (!from.equals(&value.pubkey)) {
                    return error.InvalidValue;
                }
                try sanitize_wallclock(value.wallclock);
            },
            // do nothing
            .PingMessage => {},
            .PongMessage => {},
        }
    }
};

pub fn sanitize_wallclock(wallclock: u64) !void {
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
            .pubkey = Pubkey.fromPublicKey(&keypair.public_key, true),
            .prunes = &[0]Pubkey{},
            .signature = Signature.init(.{0} ** 64),
            .destination = Pubkey.random(rng, .{}),
            .wallclock = crds.get_wallclock(),
        };
        try self.sign(keypair);

        return self;
    }

    pub fn sign(self: *PruneData, keypair: *KeyPair) !void {
        var slice: [1024]u8 = undefined; // TODO: fix sizing
        var signable_data = PruneSignableData{
            .pubkey = self.pubkey,
            .prunes = self.prunes,
            .destination = self.destination,
            .wallclock = self.wallclock,
        };
        var out = try bincode.writeToSlice(&slice, signable_data, bincode.Params{});
        var sig = try keypair.sign(out, null);
        self.signature.data = sig.toBytes();
    }

    pub fn verify(self: *const PruneData) !void {
        var slice: [1024]u8 = undefined; // TODO: fix sizing
        var signable_data = PruneSignableData{
            .pubkey = self.pubkey,
            .prunes = self.prunes,
            .destination = self.destination,
            .wallclock = self.wallclock,
        };
        var out = try bincode.writeToSlice(&slice, signable_data, bincode.Params{});
        if (!self.signature.verify(self.pubkey, out)) {
            return error.InvalidSignature;
        }
    }
};

test "gossip.protocol: push message serialization is predictable" {
    var rng = DefaultPrng.init(crds.get_wallclock());
    var pubkey = Pubkey.random(rng.random(), .{});
    var values = std.ArrayList(CrdsValue).init(std.testing.allocator);
    defer values.deinit();

    var msg = Protocol{ .PushMessage = .{ pubkey, values.items } };
    const empty_size = try bincode.get_serialized_size(
        std.testing.allocator,
        msg,
        bincode.Params{},
    );

    var value = try CrdsValue.random(rng.random(), try KeyPair.create(null));
    const value_size = try bincode.get_serialized_size(
        std.testing.allocator,
        value,
        bincode.Params{},
    );
    try values.append(value);
    try std.testing.expect(values.items.len == 1);

    var msg_with_value = Protocol{ .PushMessage = .{ pubkey, values.items } };
    const msg_value_size = try bincode.get_serialized_size(
        std.testing.allocator,
        msg_with_value,
        bincode.Params{},
    );
    std.debug.print("value_size, empty_size, msg_value_size: {d} {d} {d}\n", .{ value_size, empty_size, msg_value_size });
    try std.testing.expectEqual(value_size + empty_size, msg_value_size);
}

test "gossip.protocol: test prune data sig verify" {
    var keypair = try KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes([_]u8{
        125, 52,  162, 97,  231, 139, 58,  13,  185, 212, 57,  142, 136, 12,  21,  127, 228, 71,
        115, 126, 138, 52,  102, 69,  103, 185, 45,  255, 132, 222, 243, 138, 25,  117, 21,  11,
        61,  170, 38,  18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230,
        121, 12,  227, 248, 199, 156, 253, 144, 175, 67,
    }));

    var rng = DefaultPrng.init(crds.get_wallclock());
    var prune = try PruneData.random(rng.random(), &keypair);

    try prune.verify();

    const rust_bytes = [_]u8{ 80, 98, 7, 181, 129, 96, 249, 247, 34, 39, 251, 41, 125, 241, 31, 25, 122, 103, 202, 48, 78, 160, 222, 65, 228, 81, 171, 237, 233, 87, 248, 29, 37, 0, 19, 66, 83, 207, 78, 86, 232, 157, 184, 144, 71, 12, 223, 86, 144, 169, 160, 171, 139, 248, 106, 63, 194, 178, 144, 119, 51, 60, 201, 7 };

    var prune_v2 = PruneData{
        .pubkey = Pubkey.fromPublicKey(&keypair.public_key, true),
        .prunes = &[0]Pubkey{},
        .signature = Signature.init(.{0} ** 64),
        .destination = Pubkey.fromPublicKey(&keypair.public_key, true),
        .wallclock = 0,
    };
    try prune_v2.sign(&keypair);

    var sig_bytes = prune_v2.signature.data;
    try std.testing.expectEqualSlices(u8, &rust_bytes, &sig_bytes);
}

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

test "gossip.protocol: test ping pong sig verify" {
    var keypair = KeyPair.create(null) catch unreachable;

    var ping = Ping.random(keypair);
    var msg = Protocol{ .PingMessage = ping };
    try msg.verify_signature();

    var pong = Protocol{ .PongMessage = try Pong.init(&ping, &keypair) };
    try pong.verify_signature();
}

test "gossip.protocol: pull request serializes and deserializes" {
    var rust_bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 190, 193, 13, 216, 175, 227, 117, 168, 246, 219, 213, 39, 67, 249, 88, 3, 238, 151, 144, 15, 23, 142, 153, 198, 47, 221, 117, 132, 218, 28, 29, 115, 248, 253, 211, 101, 137, 19, 174, 112, 43, 57, 251, 110, 173, 14, 71, 0, 186, 24, 36, 61, 75, 241, 119, 73, 86, 93, 136, 249, 167, 40, 134, 14, 0, 0, 0, 0, 25, 117, 21, 11, 61, 170, 38, 18, 67, 196, 242, 219, 50, 154, 4, 254, 79, 227, 253, 229, 188, 230, 121, 12, 227, 248, 199, 156, 253, 144, 175, 67, 0, 0, 0, 0, 127, 0, 0, 1, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var keypair = try KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes([_]u8{
        125, 52,  162, 97,  231, 139, 58,  13,  185, 212, 57,  142, 136, 12,  21,  127, 228, 71,
        115, 126, 138, 52,  102, 69,  103, 185, 45,  255, 132, 222, 243, 138, 25,  117, 21,  11,
        61,  170, 38,  18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230,
        121, 12,  227, 248, 199, 156, 253, 144, 175, 67,
    }));
    var pubkey = Pubkey.fromPublicKey(&keypair.public_key, true);

    // pull requests only use ContactInfo CRDS data
    const gossip_addr = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 1234);
    const unspecified_addr = SocketAddr.unspecified();
    var legacy_contact_info = LegacyContactInfo{
        .id = pubkey,
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
    var crds_data = crds.CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    };
    var crds_value = try crds.CrdsValue.initSigned(crds_data, keypair);

    var filter = CrdsFilter.init(testing.allocator);
    defer filter.deinit();

    var pull = Protocol{ .PullRequest = .{
        filter,
        crds_value,
    } };

    var buf = [_]u8{0} ** 1232;
    var serialized = try bincode.writeToSlice(buf[0..], pull, bincode.Params.standard);
    try testing.expectEqualSlices(u8, rust_bytes[0..], serialized);

    var deserialized = try bincode.readFromSlice(testing.allocator, Protocol, serialized, bincode.Params.standard);
    try testing.expect(std.meta.eql(pull, deserialized));
}

test "gossip.protocol: push message serializes and deserializes correctly" {
    var kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk, true);

    const gossip_addr = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 1234);
    const unspecified_addr = SocketAddr.unspecified();

    var buf = [_]u8{0} ** 1024;

    var legacy_contact_info = LegacyContactInfo{
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

    var crds_data = crds.CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    };

    var rust_bytes = [_]u8{ 2, 0, 0, 0, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 1, 0, 0, 0, 0, 0, 0, 0, 247, 119, 8, 235, 122, 255, 148, 105, 239, 205, 20, 32, 112, 227, 208, 92, 37, 18, 5, 71, 105, 58, 203, 18, 69, 196, 217, 80, 56, 47, 2, 45, 166, 139, 244, 114, 132, 206, 156, 187, 206, 205, 0, 176, 167, 196, 11, 17, 22, 77, 142, 176, 215, 8, 110, 221, 30, 206, 219, 80, 196, 217, 118, 13, 0, 0, 0, 0, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 0, 0, 0, 0, 127, 0, 0, 1, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var crds_value = try crds.CrdsValue.initSigned(crds_data, kp);
    var values = [_]crds.CrdsValue{crds_value};
    var pushmsg = Protocol{ .PushMessage = .{ id, &values } };
    var bytes = try bincode.writeToSlice(buf[0..], pushmsg, bincode.Params.standard);
    try testing.expectEqualSlices(u8, bytes[0..bytes.len], &rust_bytes);
}
