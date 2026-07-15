const std = @import("std");
const TestNode = @import("TestNode.zig");
const lib = @import("../../lib.zig");
const testing = lib.gossip.testing;

const local_address: lib.gossip.Address = .fromNetAddress(.initIp4(.{ 127, 0, 0, 1 }, 8001));
const remote_address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001);
const start_ms = 1_000_000;

fn expectOutgoingPacketsDecodable(test_node: *const TestNode) !void {
    for (test_node.outgoingPackets()) |*packet| {
        var message_memory: [16 * 1024]u8 = undefined;
        _ = try testing.readMessage(&message_memory, packet);
    }
}

fn fuzzPacket(test_node: *TestNode, input: []const u8) !void {
    try test_node.reset(start_ms);

    var packet: lib.net.Packet = .{
        .data = @splat(0),
        .len = @intCast(@min(input.len, lib.net.Packet.capacity)),
        .addr = remote_address,
    };
    @memcpy(packet.data[0..packet.len], input[0..packet.len]);

    test_node.receivePacket(&packet);
    try expectOutgoingPacketsDecodable(test_node);
}

// Feeds arbitrary wire bytes into gossip and verifies state and emitted packets.
test "fuzz packet input" {
    const remote_keypair = try testing.deterministicKeyPair(2);
    const ping_packet = try testing.packetFromMessage(
        remote_address,
        try testing.pingMessage(&remote_keypair, @splat(12)),
    );
    const initial_corpus = [_][]const u8{ping_packet.data[0..ping_packet.len]};

    var test_node = try TestNode.init(
        std.heap.page_allocator,
        start_ms,
        1,
        local_address,
        &.{},
    );
    defer test_node.deinit();

    try std.testing.fuzz(&test_node, fuzzPacket, .{ .corpus = &initial_corpus });
}

const ScenarioContext = struct {
    test_node: *TestNode,
    remote_keypair: lib.gossip.KeyPair,
};

const ScenarioOperation = enum {
    advance_and_poll,
    valid_ping,
    random_packet,
    duplicate_ping,
    contact_info,
};

fn fuzzScenario(context: *ScenarioContext, input: []const u8) !void {
    var seed_bytes: [8]u8 = @splat(0);
    const seed_len = @min(seed_bytes.len, input.len);
    @memcpy(seed_bytes[0..seed_len], input[0..seed_len]);

    var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed_bytes, .little));
    const random = prng.random();
    try context.test_node.reset(start_ms);

    for (0..128) |_| {
        switch (random.enumValue(ScenarioOperation)) {
            .advance_and_poll => {
                context.test_node.advanceMs(random.uintLessThan(u64, 1_000));
                try context.test_node.poll();
            },
            .valid_ping => {
                var token: [32]u8 = undefined;
                random.bytes(&token);
                try context.test_node.receiveMessage(
                    remote_address,
                    try testing.pingMessage(&context.remote_keypair, token),
                );
            },
            .random_packet => {
                var packet: lib.net.Packet = .{
                    .data = undefined,
                    .len = random.uintLessThan(u16, lib.net.Packet.capacity + 1),
                    .addr = remote_address,
                };
                random.bytes(packet.data[0..packet.len]);
                context.test_node.receivePacket(&packet);
            },
            .duplicate_ping => {
                const message = try testing.pingMessage(&context.remote_keypair, @splat(12));
                try context.test_node.receiveMessage(remote_address, message);
                try context.test_node.receiveMessage(remote_address, message);
            },
            .contact_info => {
                var socket_builder: lib.gossip.SocketMap.Builder = .{};
                socket_builder.set(.gossip, .fromNetAddress(remote_address));
                var values = [_]lib.gossip.GossipValue{try testing.signedContactInfo(
                    &context.remote_keypair,
                    context.test_node.now_ms,
                    start_ms,
                    42,
                    socket_builder.asSocketMap(),
                )};
                try context.test_node.receiveMessage(
                    remote_address,
                    testing.pushMessage(context.remote_keypair.pubkey, &values),
                );
            },
        }
        try expectOutgoingPacketsDecodable(context.test_node);
        context.test_node.clearOutgoingPackets();
    }
}

// Uses fuzzed RNG seeds to explore deterministic message and timing sequences.
test "fuzz stateful scenario seed" {
    var test_node = try TestNode.init(
        std.heap.page_allocator,
        start_ms,
        1,
        local_address,
        &.{},
    );
    defer test_node.deinit();

    var context: ScenarioContext = .{
        .test_node = &test_node,
        .remote_keypair = try testing.deterministicKeyPair(2),
    };
    try std.testing.fuzz(&context, fuzzScenario, .{});
}
