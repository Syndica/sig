const std = @import("std");
const TestNode = @import("TestNode.zig");
const lib = @import("../../lib.zig");
const testing = lib.gossip.testing;

const local_address: lib.gossip.Address = .fromNetAddress(.initIp4(.{ 127, 0, 0, 1 }, 8001));
const remote_address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001);
const rpc_address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8899);
const entrypoint: lib.gossip.Address = .fromNetAddress(remote_address);

// Verifies that a valid ping/pong exchange moves a peer from tracked to verified.
test "valid ping handshake verifies peer" {
    const allocator = std.testing.allocator;
    const remote_keypair = try testing.deterministicKeyPair(2);

    var test_node = try TestNode.init(allocator, 1_000_000, 1, local_address, &.{});
    defer test_node.deinit();

    // Process the peer's ping and inspect the expected pong and verification ping.
    const token: [32]u8 = @splat(12);
    try test_node.receiveMessage(remote_address, try testing.pingMessage(&remote_keypair, token));

    try std.testing.expectEqual(2, test_node.outgoingPackets().len);
    var found_ping: ?lib.gossip.GossipMessage = null;
    var found_pong = false;
    for (test_node.outgoingPackets()) |*packet| {
        var message_memory: [16 * 1024]u8 = undefined;
        const message = try testing.readMessage(&message_memory, packet);
        switch (message) {
            .ping_message => |ping| {
                try std.testing.expectEqual(test_node.identity(), ping.from);
                try ping.signature.verify(&ping.from, &ping.token);
                found_ping = message;
            },
            .pong_message => |pong| {
                const expected_hash = lib.solana.Hash.initMany(&.{ "SOLANA_PING_PONG", &token });
                try std.testing.expectEqual(test_node.identity(), pong.from);
                try std.testing.expect(pong.hash.eql(&expected_hash));
                try pong.signature.verify(&pong.from, &pong.hash.data);
                found_pong = true;
            },
            // Without advancing time or polling, handling this ping can only emit a pong and a
            // ping to verify the new peer.
            else => unreachable,
        }
    }

    try std.testing.expect(found_pong);
    const ping = (found_ping orelse return error.ExpectedPing).ping_message;
    try std.testing.expectEqual(.tracked, test_node.node.peerStatus(remote_keypair.pubkey));

    // Answer the node's verification ping to complete peer verification.
    const ping_hash = lib.solana.Hash.initMany(&.{ "SOLANA_PING_PONG", &ping.token });
    const pong_message: lib.gossip.GossipMessage = .{ .pong_message = .{
        .from = remote_keypair.pubkey,
        .hash = ping_hash,
        .signature = try remote_keypair.sign(&ping_hash.data),
    } };
    try test_node.receiveMessage(remote_address, pong_message);

    try std.testing.expectEqual(.verified, test_node.node.peerStatus(remote_keypair.pubkey));
}

// Ensures an invalid ping has no effects or state changes and records the expected metric.
test "invalid ping is inert" {
    const allocator = std.testing.allocator;
    const remote_keypair = try testing.deterministicKeyPair(2);

    var test_node = try TestNode.init(allocator, 1_000_000, 1, local_address, &.{});
    defer test_node.deinit();

    // Submit a ping with an invalid signature.
    const message: lib.gossip.GossipMessage = .{ .ping_message = .{
        .from = remote_keypair.pubkey,
        .token = @splat(12),
        .signature = .ZEROES,
    } };
    try test_node.receiveMessage(remote_address, message);

    // Confirm rejection leaves peer and output state untouched while recording the failure.
    try std.testing.expectEqual(0, test_node.outgoingPackets().len);
    try std.testing.expectEqual(.missing, test_node.node.peerStatus(remote_keypair.pubkey));
    try std.testing.expectEqual(
        1,
        test_node.node.metrics.invalid_messages.get(error.InvalidSignature),
    );
}

// Verifies every payload-less deprecated gossip value can be received and rejected as invalid.
test "deprecated gossip messages are handled" {
    const allocator = std.testing.allocator;
    const now_ms = 1_000_000;
    const remote_keypair = try testing.deterministicKeyPair(2);

    var test_node = try TestNode.init(allocator, now_ms, 1, local_address, &.{});
    defer test_node.deinit();

    const deprecated_data = [_]lib.gossip.GossipData{
        .legacy_contact_info,
        .legacy_snapshot_hashes,
        .account_hashes,
        .legacy_version,
        .version,
        .node_instance,
    };
    for (deprecated_data) |data| {
        var values = [_]lib.gossip.GossipValue{try testing.signedValue(&remote_keypair, data)};
        try test_node.receiveMessage(
            remote_address,
            testing.pushMessage(remote_keypair.pubkey, &values),
        );
    }

    const expected_invalid_messages: u64 = deprecated_data.len;
    try std.testing.expectEqual(
        expected_invalid_messages,
        test_node.node.metrics.invalid_messages.get(error.InvalidTableValue),
    );
}

const SnapshotDiscoveryOrder = enum {
    contact_first,
    snapshot_first,
};

fn runSnapshotDiscoveryScenario(order: SnapshotDiscoveryOrder) !void {
    const allocator = std.testing.allocator;
    const now_ms = 1_000_000;
    const remote_keypair = try testing.deterministicKeyPair(2);
    const snapshot_hash = lib.solana.Hash.init("snapshot");

    var test_node = try TestNode.init(allocator, now_ms, 1, local_address, &.{});
    defer test_node.deinit();

    var socket_builder: lib.gossip.SocketMap.Builder = .{};
    socket_builder.set(.gossip, .fromNetAddress(remote_address));
    socket_builder.set(.rpc, .fromNetAddress(rpc_address));

    const contact = try testing.signedContactInfo(
        &remote_keypair,
        now_ms,
        now_ms,
        42,
        socket_builder.asSocketMap(),
    );
    const snapshot = try testing.signedSnapshotHashes(
        &remote_keypair,
        now_ms,
        123,
        snapshot_hash,
    );

    const first_value, const second_value = switch (order) {
        .contact_first => .{ contact, snapshot },
        .snapshot_first => .{ snapshot, contact },
    };

    // Submit one half of the source metadata and confirm discovery is still incomplete.
    var values = [_]lib.gossip.GossipValue{first_value};
    try test_node.receiveMessage(
        remote_address,
        testing.pushMessage(remote_keypair.pubkey, &values),
    );
    try std.testing.expectEqual(0, test_node.snapshotSources().len);

    // Submit the complementary value and inspect the reported snapshot source.
    values[0] = second_value;
    try test_node.receiveMessage(
        remote_address,
        testing.pushMessage(remote_keypair.pubkey, &values),
    );

    try std.testing.expectEqual(1, test_node.snapshotSources().len);
    const source = test_node.snapshotSources()[0];
    try std.testing.expectEqual(remote_keypair.pubkey, source.from);
    try std.testing.expect(std.meta.eql(
        lib.gossip.Address.fromNetAddress(rpc_address),
        source.rpc_addr,
    ));
    try std.testing.expectEqual(123, source.slot);
    try std.testing.expect(source.hash.eql(&snapshot_hash));
}

// Ensures contact and snapshot values produce the same source regardless of arrival order.
test "snapshot source discovery is arrival-order independent" {
    try runSnapshotDiscoveryScenario(.contact_first);
    try runSnapshotDiscoveryScenario(.snapshot_first);
}

// Ensures an older value cannot replace a newer value for the same table key.
test "older gossip value does not replace newer entry" {
    const allocator = std.testing.allocator;
    const now_ms = 1_000_000;
    const remote_keypair = try testing.deterministicKeyPair(2);

    var test_node = try TestNode.init(allocator, now_ms, 1, local_address, &.{});
    defer test_node.deinit();

    var socket_builder: lib.gossip.SocketMap.Builder = .{};
    socket_builder.set(.gossip, .fromNetAddress(remote_address));
    const socket_map = socket_builder.asSocketMap();

    const older = try testing.signedContactInfo(
        &remote_keypair,
        now_ms - 1_000,
        now_ms - 2_000,
        42,
        socket_map,
    );
    const newer = try testing.signedContactInfo(
        &remote_keypair,
        now_ms + 1_000,
        now_ms - 2_000,
        42,
        socket_map,
    );

    // Establish the newer table entry.
    var values = [_]lib.gossip.GossipValue{newer};
    try test_node.receiveMessage(
        remote_address,
        testing.pushMessage(remote_keypair.pubkey, &values),
    );
    try std.testing.expectEqual(
        now_ms + 1_000,
        test_node.node.getEntryWallclockMs(remote_keypair.pubkey, .contact_info, 0).?,
    );

    // Attempt an older update and confirm the stored wallclock does not regress.
    values[0] = older;
    try test_node.receiveMessage(
        remote_address,
        testing.pushMessage(remote_keypair.pubkey, &values),
    );
    try std.testing.expectEqual(
        now_ms + 1_000,
        test_node.node.getEntryWallclockMs(remote_keypair.pubkey, .contact_info, 0).?,
    );
}

// Verifies periodic push deadlines and contact timestamps using simulated time.
test "periodic push follows simulated wallclock" {
    const allocator = std.testing.allocator;
    const start_ms = 1_000_000;

    var test_node = try TestNode.init(allocator, start_ms, 1, local_address, &.{entrypoint});
    defer test_node.deinit();

    // Establish the initial deadlines and discard bootstrap output.
    try test_node.poll();
    test_node.clearOutgoingPackets();

    // Confirm no push is emitted before the five-second deadline.
    test_node.advanceMs(4_999);
    try test_node.poll();
    for (test_node.outgoingPackets()) |*packet| {
        var message_memory: [16 * 1024]u8 = undefined;
        const message = try testing.readMessage(&message_memory, packet);
        try std.testing.expect(message != .push_message);
    }
    test_node.clearOutgoingPackets();

    // Reach the deadline and verify the node publishes its refreshed contact info once.
    test_node.advanceMs(1);
    try test_node.poll();

    const packets = test_node.outgoingPackets();
    try std.testing.expectEqual(1, packets.len);

    var message_memory: [16 * 1024]u8 = undefined;
    const message = try testing.readMessage(&message_memory, &packets[0]);
    const push = switch (message) {
        .push_message => |push| push,
        else => unreachable,
    };

    try std.testing.expectEqual(1, push.values.items.len);
    const contact = switch (push.values.items[0].data) {
        .contact_info => |contact| contact,
        else => unreachable,
    };
    try std.testing.expectEqual(test_node.identity(), contact.from);
    try std.testing.expectEqual(start_ms + 5_000, contact.wallclock.value);
}
