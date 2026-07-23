const std = @import("std");
const lib = @import("../../lib.zig");

pub fn deterministicKeyPair(seed_byte: u8) !lib.gossip.KeyPair {
    const keypair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(seed_byte));
    return .fromKeyPair(keypair);
}

pub fn signedValue(
    keypair: *const lib.gossip.KeyPair,
    data: lib.gossip.GossipData,
) !lib.gossip.GossipValue {
    var bytes: [lib.net.Packet.capacity]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try lib.gossip.bincode.write(&writer, data);
    return .{
        .signature = try keypair.sign(writer.buffered()),
        .data = data,
    };
}

pub fn signedContactInfo(
    keypair: *const lib.gossip.KeyPair,
    wallclock_ms: u64,
    created_ms: u64,
    shred_version: u16,
    socket_map: lib.gossip.SocketMap,
) !lib.gossip.GossipValue {
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

pub fn signedSnapshotHashes(
    keypair: *const lib.gossip.KeyPair,
    wallclock_ms: u64,
    slot: lib.solana.Slot,
    hash: lib.solana.Hash,
) !lib.gossip.GossipValue {
    return signedValue(keypair, .{ .snapshot_hashes = .{
        .from = keypair.pubkey,
        .full = .{ .slot = slot, .hash = hash },
        .incremental = .{ .items = &.{} },
        .wallclock = wallclock_ms,
    } });
}

pub fn packetFromMessage(
    source: std.net.Address,
    message: lib.gossip.GossipMessage,
) !lib.net.Packet {
    var result: lib.net.Packet = .{
        .data = undefined,
        .len = 0,
        .addr = source,
    };
    var writer: std.Io.Writer = .fixed(&result.data);
    try lib.gossip.bincode.write(&writer, message);
    result.len = @intCast(writer.buffered().len);
    return result;
}

pub fn readMessage(
    alloc_buffer: []u8,
    packet_: *const lib.net.Packet,
) !lib.gossip.GossipMessage {
    var allocator: std.heap.FixedBufferAllocator = .init(alloc_buffer);
    var reader: std.Io.Reader = .fixed(packet_.data[0..packet_.len]);
    return lib.gossip.bincode.read(&allocator, &reader, lib.gossip.GossipMessage);
}

pub fn pingMessage(
    keypair: *const lib.gossip.KeyPair,
    token: [32]u8,
) !lib.gossip.GossipMessage {
    return .{ .ping_message = .{
        .from = keypair.pubkey,
        .token = token,
        .signature = try keypair.sign(&token),
    } };
}

pub fn pushMessage(
    from: lib.solana.Pubkey,
    values: []lib.gossip.GossipValue,
) lib.gossip.GossipMessage {
    return .{ .push_message = .{
        .from = from,
        .values = .{ .items = values },
    } };
}
