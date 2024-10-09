const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Nonce = sig.core.Nonce;
const Pong = sig.gossip.Pong;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

/// Analogous to [SIGNED_REPAIR_TIME_WINDOW](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/core/src/repair/serve_repair.rs#L89)
const SIGNED_REPAIR_TIME_WINDOW_SECS: u64 = 600;

/// Internal representation of a repair request.
/// Does not contain any header or identification, only info about the desired shreds.
///
/// Analogous to [ShredRepairType](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/core/src/repair/serve_repair.rs#L95)
pub const RepairRequest = union(enum) {
    /// Requesting `MAX_ORPHAN_REPAIR_RESPONSES` parent shreds
    Orphan: Slot,
    /// Requesting any shred with index greater than or equal to the particular index
    HighestShred: struct { Slot, u64 },
    /// Requesting the missing shred at a particular index
    Shred: struct { Slot, u64 },

    const Self = @This();

    pub fn slot(self: *const Self) Slot {
        return switch (self.*) {
            .Orphan => |x| x,
            .HighestShred => |x| x[0],
            .Shred => |x| x[0],
        };
    }
};

/// Executes all three because they are tightly coupled:
/// - convert request to message
/// - serialize message
/// - sign message
///
/// Analogous to [ServeRepair::map_repair_request](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/core/src/repair/serve_repair.rs#L1141)
pub fn serializeRepairRequest(
    buf: []u8,
    request: RepairRequest,
    keypair: *const KeyPair,
    recipient: Pubkey,
    timestamp: u64,
    nonce: Nonce,
) ![]u8 {
    const header = RepairRequestHeader{
        .signature = Signature.init(undefined),
        .sender = try Pubkey.fromBytes(&keypair.public_key.bytes),
        .recipient = recipient,
        .timestamp = timestamp,
        .nonce = nonce,
    };
    const msg: RepairMessage = switch (request) {
        .Shred => |r| .{ .WindowIndex = .{
            .header = header,
            .slot = r[0],
            .shred_index = r[1],
        } },
        .HighestShred => |r| .{ .HighestWindowIndex = .{
            .header = header,
            .slot = r[0],
            .shred_index = r[1],
        } },
        .Orphan => |r| .{ .Orphan = .{
            .header = header,
            .slot = r,
        } },
    };
    var serialized = try bincode.writeToSlice(buf, msg, .{});

    var signer = try keypair.signer(null); // TODO noise
    signer.update(serialized[0..4]);
    signer.update(serialized[4 + Signature.size ..]);
    @memcpy(serialized[4 .. 4 + Signature.size], &signer.finalize().toBytes());

    return serialized;
}

/// Messaging data that is directly serialized and sent over repair sockets.
/// Contains any header/identification as needed.
///
/// Analogous to [RepairProtocol](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/core/src/repair/serve_repair.rs#L221)
pub const RepairMessage = union(enum(u8)) {
    Pong: Pong = 7,
    WindowIndex: struct {
        header: RepairRequestHeader,
        slot: Slot,
        shred_index: u64,
    },
    HighestWindowIndex: struct {
        header: RepairRequestHeader,
        slot: Slot,
        shred_index: u64,
    },
    Orphan: struct {
        header: RepairRequestHeader,
        slot: Slot,
    },
    AncestorHashes: struct {
        header: RepairRequestHeader,
        slot: Slot,
    },

    pub const Tag: type = @typeInfo(Self).Union.tag_type.?;
    const Self = @This();

    const MAX_SERIALIZED_SIZE: usize = 160;

    pub fn eql(self: *const Self, other: *const Self) bool {
        if (!std.mem.eql(u8, @tagName(self.*), @tagName(other.*))) {
            return false;
        }
        switch (self.*) {
            .Pong => |*s| return s.eql(&other.Pong),
            .WindowIndex => |*s| {
                const o = other.WindowIndex;
                return s.header.eql(&o.header) and s.slot == o.slot and s.shred_index == o.shred_index;
            },
            .HighestWindowIndex => |*s| {
                const o = other.HighestWindowIndex;
                return s.header.eql(&o.header) and s.slot == o.slot and s.shred_index == o.shred_index;
            },
            .Orphan => |*s| {
                return s.header.eql(&other.Orphan.header) and s.slot == other.Orphan.slot;
            },
            .AncestorHashes => |*s| {
                return s.header.eql(&other.AncestorHashes.header) and s.slot == other.AncestorHashes.slot;
            },
        }
    }

    /// Analogous to [ServeRepair::verify_signed_packet](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/core/src/repair/serve_repair.rs#L847)
    pub fn verify(
        self: *const Self,
        /// bincode serialized data, from which this struct was deserialized
        serialized: []u8,
        /// to compare to the header. typically is this validator's own pubkey
        expected_recipient: Pubkey,
        /// unix timestamp in milliseconds when this function is called
        current_timestamp_millis: u64,
    ) error{ IdMismatch, InvalidSignature, Malformed, TimeSkew }!void {
        switch (self.*) {
            .Pong => |pong| try pong.verify(),
            inline else => |msg| {
                // i am the intended recipient
                const header: RepairRequestHeader = msg.header;
                if (!header.recipient.equals(&expected_recipient)) {
                    return error.IdMismatch;
                }

                // message was generated recently
                const time_diff = @as(i128, current_timestamp_millis) - @as(i128, header.timestamp);
                const time_diff_abs = if (time_diff >= 0) time_diff else -time_diff;
                if (time_diff_abs > SIGNED_REPAIR_TIME_WINDOW_SECS) {
                    return error.TimeSkew;
                }

                // signature is valid
                if (serialized.len < 4 + Signature.size) {
                    return error.Malformed;
                }
                var verifier = header.signature.verifier(header.sender) catch {
                    return error.InvalidSignature;
                };
                verifier.update(serialized[0..4]);
                verifier.update(serialized[4 + Signature.size ..]);
                verifier.verify() catch {
                    return error.InvalidSignature;
                };
            },
        }
    }
};

pub const RepairRequestHeader = struct {
    signature: Signature,
    sender: Pubkey,
    recipient: Pubkey,
    timestamp: u64,
    nonce: Nonce,

    fn eql(self: *const @This(), other: *const @This()) bool {
        return self.signature.eql(&other.signature) and
            self.sender.equals(&other.sender) and
            self.recipient.equals(&other.recipient) and
            self.timestamp == other.timestamp and
            self.nonce == other.nonce;
    }
};

test "signed/serialized RepairRequest is valid" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(392138);
    const random = prng.random();

    inline for (.{
        RepairRequest{ .Orphan = random.int(Slot) },
        RepairRequest{ .Shred = .{ random.int(Slot), random.int(u64) } },
        RepairRequest{ .HighestShred = .{ random.int(Slot), random.int(u64) } },
    }) |request| {
        var kp_noise: [32]u8 = undefined;
        random.bytes(&kp_noise);
        const keypair = try KeyPair.create(kp_noise);
        const recipient = Pubkey.random(random);
        const timestamp = random.int(u64);
        const nonce = random.int(Nonce);

        var buf: [1232]u8 = undefined;
        var serialized = try serializeRepairRequest(
            &buf,
            request,
            &keypair,
            recipient,
            timestamp,
            nonce,
        );

        // TODO: `serializeRepairRequest` is currently non-deterministic because keypair.signer uses csprng.
        // figure out a way to make it deterministic!

        var deserialized = try bincode.readFromSlice(allocator, RepairMessage, serialized, .{});
        try deserialized.verify(serialized, recipient, timestamp);
        random.bytes(serialized[10..15]); // >99.99% chance that this invalidates the signature
        var bad = try bincode.readFromSlice(allocator, RepairMessage, serialized, .{});
        if (bad.verify(serialized, recipient, timestamp)) |_| @panic("should err") else |_| {}
    }
}

test "RepairRequestHeader serialization round trip" {
    var prng = std.rand.DefaultPrng.init(5224);
    var signature: [Signature.size]u8 = undefined;
    prng.fill(&signature);

    const header = RepairRequestHeader{
        .signature = Signature.init(signature),
        .sender = Pubkey.random(prng.random()),
        .recipient = Pubkey.random(prng.random()),
        .timestamp = 5924,
        .nonce = 123,
    };

    var buf: [RepairMessage.MAX_SERIALIZED_SIZE]u8 = undefined;
    const serialized = try bincode.writeToSlice(&buf, header, .{});

    const expected = [_]u8{
        39,  95,  42,  53,  95,  32,  120, 241, 244, 206, 142, 80,  233, 26,  232, 206, 241,
        24,  226, 101, 183, 172, 170, 201, 42,  127, 121, 127, 213, 234, 180, 0,   226, 0,
        128, 58,  176, 144, 99,  139, 220, 112, 10,  117, 212, 239, 129, 197, 170, 11,  92,
        151, 239, 163, 174, 85,  172, 227, 75,  115, 1,   143, 134, 9,   21,  189, 8,   17,
        240, 55,  159, 41,  45,  133, 143, 153, 57,  113, 39,  28,  86,  183, 182, 76,  41,
        19,  160, 55,  54,  41,  126, 184, 144, 195, 245, 38,  164, 157, 171, 233, 18,  178,
        15,  2,   196, 46,  124, 59,  178, 108, 95,  194, 39,  18,  119, 16,  226, 118, 112,
        26,  255, 82,  27,  175, 162, 144, 207, 151, 36,  23,  0,   0,   0,   0,   0,   0,
        123, 0,   0,   0,
    };

    try std.testing.expect(std.mem.eql(u8, &expected, serialized));

    const roundtripped = try bincode.readFromSlice(
        std.testing.allocator,
        RepairRequestHeader,
        serialized,
        .{},
    );
    try std.testing.expect(header.eql(&roundtripped));
}

test "RepairProtocolMessage.Pong serialization round trip" {
    try testHelpers.assertMessageSerializesCorrectly(57340, .Pong, &[_]u8{
        7,   0,   0,   0,   252, 143, 181, 36,  240, 87,  69,  104, 157, 159, 242, 94,  101,
        48,  187, 120, 173, 241, 68,  167, 217, 67,  141, 46,  105, 85,  179, 69,  249, 140,
        6,   145, 6,   201, 32,  10,  11,  24,  157, 240, 245, 65,  91,  80,  255, 89,  18,
        136, 27,  80,  101, 106, 118, 175, 154, 105, 205, 69,  2,   112, 61,  168, 217, 197,
        251, 212, 16,  137, 153, 40,  116, 229, 235, 90,  12,  54,  76,  123, 187, 108, 132,
        78,  151, 13,  47,  0,   127, 182, 158, 5,   19,  226, 204, 0,   120, 218, 175, 155,
        122, 155, 94,  44,  198, 119, 196, 127, 121, 242, 98,  87,  235, 233, 241, 57,  53,
        125, 88,  67,  4,   23,  164, 128, 221, 124, 139, 84,  106, 7,
    });
}

test "RepairProtocolMessage.WindowIndex serialization round trip" {
    try testHelpers.assertMessageSerializesCorrectly(4823794, .WindowIndex, &[_]u8{
        8,   0,   0,   0,   100, 7,   241, 74,  194, 88,  24,  128, 85,  15,  149, 108, 142,
        133, 234, 217, 3,   79,  124, 171, 68,  30,  189, 219, 173, 11,  184, 159, 208, 104,
        206, 31,  233, 86,  166, 102, 235, 97,  198, 145, 62,  149, 19,  202, 91,  237, 153,
        175, 64,  205, 96,  10,  66,  7,   66,  104, 119, 214, 232, 34,  168, 170, 191, 254,
        170, 237, 236, 185, 88,  155, 113, 136, 171, 26,  210, 220, 45,  195, 26,  211, 174,
        235, 79,  241, 31,  60,  134, 15,  207, 28,  50,  96,  253, 80,  191, 140, 108, 58,
        53,  196, 143, 167, 65,  56,  105, 42,  146, 49,  136, 194, 147, 74,  110, 247, 135,
        48,  92,  138, 71,  230, 204, 175, 17,  87,  167, 45,  210, 99,  50,  122, 47,  19,
        19,  197, 58,  51,  19,  223, 45,  162, 128, 200, 255, 158, 217, 0,   235, 83,  78,
        233, 7,   127, 119, 47,  7,   223,
    });
}

test "RepairProtocolMessage.HighestWindowIndex serialization round trip" {
    try testHelpers.assertMessageSerializesCorrectly(636345, .HighestWindowIndex, &[_]u8{
        9,   0,   0,   0,   44,  123, 16,  108, 173, 151, 229, 132, 4,  0,   5,   215, 25,
        179, 235, 166, 181, 42,  30,  231, 218, 43,  166, 238, 92,  80, 234, 87,  30,  123,
        140, 27,  65,  165, 32,  139, 235, 225, 146, 239, 107, 162, 4,  80,  215, 131, 42,
        94,  28,  153, 26,  191, 57,  87,  214, 211, 145, 158, 113, 53, 178, 178, 33,  217,
        204, 75,  59,  119, 212, 148, 21,  154, 19,  106, 222, 14,  10, 225, 243, 182, 32,
        149, 101, 1,   226, 133, 56,  84,  175, 53,  65,  157, 177, 34, 153, 171, 107, 230,
        177, 30,  169, 141, 24,  248, 39,  184, 152, 55,  108, 199, 61, 232, 189, 152, 129,
        249, 88,  86,  204, 12,  134, 9,   185, 8,   176, 163, 50,  51, 149, 144, 227, 124,
        63,  248, 112, 172, 251, 252, 42,  232, 95,  7,   74,  139, 26, 36,  163, 156, 135,
        113, 204, 230, 147, 29,  223, 167,
    });
}

test "RepairProtocolMessage.Orphan serialization round trip" {
    try testHelpers.assertMessageSerializesCorrectly(734566, .Orphan, &[_]u8{
        10,  0,   0,   0,   52,  54,  182, 49,  197, 238, 253, 118, 145, 61,  198, 235, 42,
        211, 229, 42,  2,   33,  5,   161, 179, 171, 26,  243, 51,  240, 82,  98,  121, 90,
        210, 244, 120, 168, 226, 131, 209, 42,  251, 16,  90,  129, 113, 90,  195, 130, 55,
        58,  97,  240, 114, 59,  154, 38,  7,   66,  209, 77,  18,  17,  22,  1,   65,  184,
        202, 21,  198, 105, 238, 24,  115, 147, 78,  249, 178, 229, 75,  189, 129, 104, 138,
        75,  78,  30,  54,  222, 175, 51,  218, 247, 211, 188, 142, 76,  64,  156, 21,  191,
        163, 86,  38,  244, 0,   213, 69,  78,  102, 190, 220, 19,  138, 92,  30,  149, 125,
        135, 239, 186, 78,  147, 83,  128, 23,  200, 81,  2,   102, 110, 226, 11,  217, 50,
        27,  76,  129, 55,  218, 236, 152, 27,  164, 106, 186, 169, 80,  103, 36,  153,
    });
}

test "RepairProtocolMessage.AncestorHashes serialization round trip" {
    try testHelpers.assertMessageSerializesCorrectly(6236757, .AncestorHashes, &[_]u8{
        11,  0,   0,   0,   192, 86,  218, 156, 168, 139, 216, 200, 30,  181, 244, 121, 90,
        41,  177, 117, 55,  40,  199, 207, 62,  118, 56,  134, 73,  88,  74,  2,   139, 189,
        201, 150, 22,  75,  239, 15,  35,  125, 154, 130, 165, 120, 24,  154, 159, 42,  222,
        92,  189, 252, 136, 151, 184, 96,  137, 169, 181, 62,  108, 82,  235, 143, 42,  93,
        212, 223, 9,   217, 201, 202, 143, 14,  99,  140, 33,  48,  241, 185, 240, 10,  146,
        127, 62,  122, 247, 66,  91,  169, 32,  251, 220, 5,   197, 184, 172, 190, 182, 248,
        69,  46,  30,  121, 156, 153, 238, 91,  192, 207, 163, 187, 60,  71,  60,  232, 71,
        228, 195, 225, 162, 193, 230, 37,  128, 114, 73,  252, 29,  20,  164, 63,  220, 2,
        32,  166, 102, 87,  214, 59,  20,  255, 18,  190, 186, 206, 159, 97,  45,  99,
    });
}

test "RepairProtocolMessage serializes to size <= MAX_SERIALIZED_SIZE" {
    var prng = std.rand.DefaultPrng.init(184837);
    for (0..10) |_| {
        inline for (@typeInfo(RepairMessage.Tag).Enum.fields) |enum_field| {
            const tag = @field(RepairMessage.Tag, enum_field.name);
            const msg = testHelpers.randomRepairProtocolMessage(prng.random(), tag);
            var buf: [RepairMessage.MAX_SERIALIZED_SIZE]u8 = undefined;
            _ = try bincode.writeToSlice(&buf, msg, .{});
        }
    }
}

const testHelpers = struct {
    fn assertMessageSerializesCorrectly(
        seed: u64,
        tag: RepairMessage.Tag,
        expected: []const u8,
    ) !void {
        var prng = std.rand.DefaultPrng.init(seed);
        const msg = testHelpers.randomRepairProtocolMessage(prng.random(), tag);
        debugMessage(&msg);

        var buf: [RepairMessage.MAX_SERIALIZED_SIZE]u8 = undefined;
        const serialized = try bincode.writeToSlice(&buf, msg, .{});
        try std.testing.expect(std.mem.eql(u8, expected, serialized));

        switch (msg) {
            .Pong => |_| try msg.verify(serialized, undefined, 0),
            inline else => |m| {
                const result = msg.verify(serialized, m.header.recipient, m.header.timestamp);
                if (result) |_| @panic("should fail due to signature") else |_| {}
            },
        }

        const roundtripped = try bincode.readFromSlice(
            std.testing.allocator,
            RepairMessage,
            serialized,
            .{},
        );
        try std.testing.expect(msg.eql(&roundtripped));

        // // rust template to generate expectation:
        // let header = RepairRequestHeader {
        //     signature: Signature::new(&[]),
        //     sender: Pubkey::from([]),
        //     recipient: Pubkey::from([]),
        //     timestamp: ,
        //     nonce: ,
        // };
        // let msg = RepairProtocol::AncestorHashes {
        //     header,
        //     slot: ,
        // };
        // let data = bincode::serialize(&msg).unwrap();
        // println!("{data:?}");
    }

    fn randomRepairRequestHeader(rand: std.rand.Random) RepairRequestHeader {
        var signature: [Signature.size]u8 = undefined;
        rand.bytes(&signature);

        return RepairRequestHeader{
            .signature = Signature.init(signature),
            .sender = Pubkey.random(rand),
            .recipient = Pubkey.random(rand),
            .timestamp = rand.int(u64),
            .nonce = rand.int(u32),
        };
    }

    fn randomRepairProtocolMessage(
        rand: std.rand.Random,
        message_type: RepairMessage.Tag,
    ) RepairMessage {
        return switch (message_type) {
            .Pong => x: {
                var buf: [32]u8 = undefined;
                rand.bytes(&buf);
                const kp = KeyPair.create(buf) catch unreachable;
                break :x .{ .Pong = Pong.random(rand, &(kp)) catch unreachable };
            },
            .WindowIndex => .{ .WindowIndex = .{
                .header = randomRepairRequestHeader(rand),
                .slot = rand.int(Slot),
                .shred_index = rand.int(u64),
            } },
            .HighestWindowIndex => .{ .HighestWindowIndex = .{
                .header = randomRepairRequestHeader(rand),
                .slot = rand.int(Slot),
                .shred_index = rand.int(u64),
            } },
            .Orphan => .{ .Orphan = .{
                .header = randomRepairRequestHeader(rand),
                .slot = rand.int(Slot),
            } },
            .AncestorHashes => .{ .AncestorHashes = .{
                .header = randomRepairRequestHeader(rand),
                .slot = rand.int(Slot),
            } },
        };
    }

    const DEBUG: bool = false;

    fn debugMessage(message: *const RepairMessage) void {
        if (!DEBUG) return;
        std.debug.print("_\n\n", .{});
        switch (message.*) {
            .Pong => |*msg| {
                std.debug.print("from: {any}\n\n", .{msg.from});
                std.debug.print("hash: {any}\n\n", .{msg.hash});
                std.debug.print("signature: {any}\n\n", .{msg.signature});
            },
            .WindowIndex => |*msg| {
                debugHeader(msg.header);
            },
            .HighestWindowIndex => |*msg| {
                debugHeader(msg.header);
            },
            .Orphan => |*msg| {
                debugHeader(msg.header);
            },
            .AncestorHashes => |*msg| {
                debugHeader(msg.header);
            },
        }
        std.debug.print("{any}", .{message});
    }

    fn debugHeader(header: RepairRequestHeader) void {
        if (!DEBUG) return;
        std.debug.print("nonce: {any}\n\n", .{header.nonce});
        std.debug.print("recipient: {any}\n\n", .{header.recipient.data});
        std.debug.print("sender: {any}\n\n", .{header.sender.data});
        std.debug.print("signature: {any}\n\n", .{header.signature.data});
        std.debug.print("timestamp: {any}\n\n", .{header.timestamp});
    }
};
