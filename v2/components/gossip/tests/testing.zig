const std = @import("std");
const lib = @import("lib");
const api = @import("gossip_api");

const Ed25519KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Packet = lib.net.Packet;
const Pubkey = lib.solana.Pubkey;

const bincode = lib.solana.bincode;
const GossipData = api.GossipData;
const GossipMessage = api.GossipMessage;
const GossipValue = api.GossipValue;
const KeyPair = lib.crypto.KeyPair;
const SocketMap = api.SocketMap;

pub fn deterministicKeyPair(seed: [Ed25519KeyPair.seed_length]u8) !KeyPair {
    const keypair = try Ed25519KeyPair.generateDeterministic(seed);
    return .fromKeyPair(keypair);
}

pub fn signedValue(
    keypair: *const KeyPair,
    data: GossipData,
) !GossipValue {
    var bytes: [Packet.capacity]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try bincode.write(&writer, data);
    return .{
        .signature = try keypair.sign(writer.buffered()),
        .data = data,
    };
}

pub fn signedContactInfo(
    keypair: *const KeyPair,
    wallclock_ms: u64,
    created_ms: u64,
    shred_version: u16,
    socket_map: SocketMap,
) !GossipValue {
    return signedValue(keypair, .{ .contact_info = .{
        .from = keypair.pubkey,
        .wallclock = .{ .value = wallclock_ms },
        .created = created_ms,
        .shred_version = shred_version,
        .major = .{ .value = 0 },
        .minor = .{ .value = 0 },
        .patch = .{ .value = 0 },
        .commit = 0,
        .feature_set = 0,
        .client_id = .{ .value = 0 },
        .socket_map = socket_map,
        .extensions = .{ .items = &.{} },
    } });
}

pub fn packetFromMessage(
    source: std.net.Address,
    message: GossipMessage,
) !Packet {
    var result: Packet = .{
        .data = undefined,
        .len = 0,
        .addr = source,
    };
    var writer: std.Io.Writer = .fixed(&result.data);
    try bincode.write(&writer, message);
    result.len = @intCast(writer.buffered().len);
    return result;
}

pub fn readMessage(
    alloc_buffer: []u8,
    packet_: *const Packet,
) !GossipMessage {
    var allocator: std.heap.FixedBufferAllocator = .init(alloc_buffer);
    var reader: std.Io.Reader = .fixed(packet_.data[0..packet_.len]);
    return bincode.read(&allocator, &reader, GossipMessage);
}

pub fn pingMessage(
    keypair: *const KeyPair,
    token: [32]u8,
) !GossipMessage {
    return .{ .ping_message = .{
        .from = keypair.pubkey,
        .token = token,
        .signature = try keypair.sign(&token),
    } };
}

pub fn pushMessage(from: Pubkey, values: []GossipValue) GossipMessage {
    return .{ .push_message = .{
        .from = from,
        .values = .{ .items = values },
    } };
}
