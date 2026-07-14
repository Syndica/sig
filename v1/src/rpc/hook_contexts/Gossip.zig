//! The Gossip RPC hook context. These methods reflect gossip-derived state (cluster nodes, etc.)

const std = @import("std");
const sig = @import("../../sig.zig");

const common = sig.rpc.methods.common;

const Slot = sig.core.Slot;

const GetClusterNodes = sig.rpc.methods.GetClusterNodes;

const GossipHookContext = @This();

gossip_table_rw: ?*sig.sync.RwMux(sig.gossip.GossipTable) = null,
my_shred_version: ?*const std.atomic.Value(u16) = null,

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L3634-3695
pub fn getClusterNodes(
    self: GossipHookContext,
    arena: std.mem.Allocator,
    _: GetClusterNodes,
) !GetClusterNodes.Response {
    const gossip_table_rw = self.gossip_table_rw orelse
        return error.GossipTableNotAvailable;
    const my_shred_version_atomic = self.my_shred_version orelse
        return error.ShredVersionNotAvailable;

    const my_shred_version = my_shred_version_atomic.load(.monotonic);

    const gossip_table, var gossip_lock = gossip_table_rw.readWithLock();
    defer gossip_lock.unlock();

    var contact_info_iter = gossip_table.contactInfoIterator(0);
    var result_list: std.ArrayList(common.RpcContactInfo) = .empty;
    // Deduplicate by pubkey: the iterator may yield both a ContactInfo and a
    // converted LegacyContactInfo entry for the same node.
    // See: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L3637
    var seen_pubkeys: std.AutoArrayHashMapUnmanaged(sig.core.Pubkey, void) = .empty;

    while (contact_info_iter.next()) |contact_info| {
        const gop = try seen_pubkeys.getOrPut(arena, contact_info.pubkey);
        if (gop.found_existing) continue;
        if (try contactInfoToRpc(
            arena,
            contact_info,
            my_shred_version,
        )) |rpc_contact_info| {
            try result_list.append(arena, rpc_contact_info);
        }
    }

    return try result_list.toOwnedSlice(arena);
}

/// Converts a gossip ContactInfo into RpcContactInfo. Returns null if the contact
/// should be skipped (shred version mismatch or invalid gossip address).
fn contactInfoToRpc(
    arena: std.mem.Allocator,
    contact_info: *const sig.gossip.ContactInfo,
    my_shred_version: u16,
) !?common.RpcContactInfo {
    // Filter by matching shred version (exclude spy nodes with shred_version 0)
    // See: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L3643
    if (contact_info.shred_version != my_shred_version) return null;

    // Check that gossip address is valid (not unspecified)
    // See: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L3644-3647
    const gossip_addr = contact_info.getSocket(.gossip);
    if (gossip_addr == null or gossip_addr.?.isUnspecified()) return null;

    var b58_buf: [sig.core.Pubkey.BASE58_MAX_SIZE]u8 = undefined;
    return .{
        .pubkey = try std.fmt.allocPrint(
            arena,
            "{s}",
            .{contact_info.pubkey.base58String(&b58_buf)},
        ),
        .gossip = try formatSocketAddr(
            arena,
            gossip_addr,
        ),
        .tvu = try formatSocketAddrGlobal(
            arena,
            contact_info.getSocket(.turbine_recv),
        ),
        .tpu = try formatSocketAddrGlobal(
            arena,
            contact_info.getSocket(.tpu),
        ),
        .tpuQuic = try formatSocketAddrGlobal(
            arena,
            contact_info.getSocket(.tpu_quic),
        ),
        .tpuForwards = try formatSocketAddrGlobal(
            arena,
            contact_info.getSocket(.tpu_forwards),
        ),
        .tpuForwardsQuic = try formatSocketAddrGlobal(
            arena,
            contact_info.getSocket(.tpu_forwards_quic),
        ),
        .tpuVote = try formatSocketAddrGlobal(
            arena,
            contact_info.getSocket(.tpu_vote),
        ),
        .serveRepair = try formatSocketAddrGlobal(
            arena,
            contact_info.getSocket(.serve_repair),
        ),
        .rpc = try formatSocketAddrGlobal(
            arena,
            contact_info.getSocket(.rpc),
        ),
        .pubsub = try formatSocketAddrGlobal(
            arena,
            contact_info.getSocket(.rpc_pubsub),
        ),
        .version = try std.fmt.allocPrint(
            arena,
            "{f}",
            .{contact_info.version},
        ),
        .featureSet = contact_info.version.feature_set,
        .shredVersion = contact_info.shred_version,
    };
}

fn formatSocketAddr(arena: std.mem.Allocator, addr: ?sig.net.SocketAddr) !?[]const u8 {
    const socket_addr = addr orelse return null;
    if (socket_addr.isUnspecified()) return null;
    return try std.fmt.allocPrint(arena, "{f}", .{socket_addr.toAddress()});
}

/// Like formatSocketAddr but also returns null for non-globally-routable addresses
/// (private, loopback, link-local). Matches Agave's SocketAddrSpace::Global filter.
/// See: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L3659
fn formatSocketAddrGlobal(arena: std.mem.Allocator, addr: ?sig.net.SocketAddr) !?[]const u8 {
    const socket_addr = addr orelse return null;
    if (!socket_addr.isGloballyRoutable()) return null;
    return try std.fmt.allocPrint(arena, "{f}", .{socket_addr.toAddress()});
}

const testing = std.testing;

fn testDummySlotConstants(slot: Slot, block_height: u64) sig.core.SlotConstants {
    return .{
        .parent_slot = slot -| 1,
        .parent_hash = .ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = block_height,
        .collector_id = .ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = .DEFAULT,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .inflation = .DEFAULT,
        .rent_collector = .DEFAULT,
    };
}

fn testDummySlotState(transaction_count: u64) sig.core.SlotState {
    var state: sig.core.SlotState = .GENESIS;
    state.transaction_count = .init(transaction_count);
    return state;
}

fn testSetupSlotTracker(
    root_slot: Slot,
    root_block_height: u64,
    root_tx_count: u64,
) !sig.replay.trackers.SlotTracker {
    return .init(testing.allocator, root_slot, .{
        .constants = testDummySlotConstants(root_slot, root_block_height),
        .state = testDummySlotState(root_tx_count),
        .allocator = testing.allocator,
    });
}

fn testGossipHookContext(
    slot_tracker: *sig.replay.trackers.SlotTracker,
    commitments: *sig.replay.trackers.CommitmentTracker,
) GossipHookContext {
    return .{
        .slot_tracker = slot_tracker,
        .commitments = commitments,
        .gossip_table_rw = null,
        .my_shred_version = null,
        .epoch_tracker = undefined, // not used by getBlockHeight/getTransactionCount/getHighestSnapshotSlot
    };
}

fn testGossipHookContextWithEpochTracker(
    slot_tracker: *sig.replay.trackers.SlotTracker,
    commitments: *sig.replay.trackers.CommitmentTracker,
    epoch_tracker: *sig.core.EpochTracker,
) GossipHookContext {
    return .{
        .slot_tracker = slot_tracker,
        .commitments = commitments,
        .gossip_table_rw = null,
        .my_shred_version = null,
        .epoch_tracker = epoch_tracker,
    };
}

test "formatSocketAddrGlobal filters non-global addresses" {
    try testing.expectEqual(
        null,
        try formatSocketAddrGlobal(testing.allocator, null),
    );
    try testing.expectEqual(
        null,
        try formatSocketAddrGlobal(
            testing.allocator,
            .initIpv4(.{ 10, 1, 2, 3 }, 8000),
        ),
    );
    const addr = (try formatSocketAddrGlobal(
        testing.allocator,
        .initIpv4(.{ 8, 8, 8, 8 }, 8000),
    )).?;
    defer testing.allocator.free(addr);
    try testing.expectEqualStrings("8.8.8.8:8000", addr);
}

test "contactInfoToRpc filters and formats fields" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const id = sig.core.Pubkey.initRandom(prng.random());

    var contact_info = sig.gossip.ContactInfo.init(testing.allocator, id, 1, 42);
    defer contact_info.deinit();

    contact_info.version = .{
        .major = 1,
        .minor = 2,
        .patch = 0,
        .commit = 1234,
        .feature_set = 5678,
        .client = .sig,
        .prerelease = .{ .release_candidate = 5 },
    };

    try contact_info.setSocket(.gossip, sig.net.SocketAddr.initIpv4(.{ 8, 8, 8, 8 }, 8000));
    try contact_info.setSocket(.turbine_recv, sig.net.SocketAddr.initIpv4(.{ 10, 0, 0, 1 }, 8001));
    try contact_info.setSocket(.tpu, sig.net.SocketAddr.initIpv4(.{ 1, 1, 1, 1 }, 8002));

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rpc_contact = (try contactInfoToRpc(arena, &contact_info, 42)).?;
    try testing.expectEqualStrings("8.8.8.8:8000", rpc_contact.gossip.?);
    try testing.expectEqual(null, rpc_contact.tvu);
    try testing.expectEqualStrings("1.1.1.1:8002", rpc_contact.tpu.?);
    try testing.expectEqualStrings("1.2.0-rc.5", rpc_contact.version.?);
    try testing.expectEqual(5678, rpc_contact.featureSet);
    try testing.expectEqual(42, rpc_contact.shredVersion);
    try testing.expectEqual(
        null,
        try contactInfoToRpc(arena, &contact_info, 99),
    );

    var no_gossip = sig.gossip.ContactInfo.init(testing.allocator, id, 1, 42);
    defer no_gossip.deinit();
    try testing.expectEqual(
        null,
        try contactInfoToRpc(arena, &no_gossip, 42),
    );
}

test "GossipHookContext.getClusterNodes returns deduplicated entries" {
    const gossip_table = try sig.gossip.GossipTable.init(testing.allocator, testing.allocator);
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    const kp = try sig.identity.KeyPair.generateDeterministic(@splat(12));
    const id = sig.core.Pubkey.fromPublicKey(&kp.public_key);

    var contact_info = sig.gossip.ContactInfo.init(
        testing.allocator,
        id,
        sig.time.getWallclockMs(),
        88,
    );
    try contact_info.setSocket(.gossip, sig.net.SocketAddr.initIpv4(.{ 8, 8, 4, 4 }, 8001));

    var legacy = sig.gossip.data.LegacyContactInfo.default(id);
    legacy.gossip = sig.net.SocketAddr.initIpv4(.{ 8, 8, 4, 4 }, 8001);
    legacy.shred_version = 88;

    {
        const table, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try table.insert(
            sig.gossip.SignedGossipData.initSigned(&kp, .{ .ContactInfo = contact_info }),
            0,
        );
        _ = try table.insert(
            sig.gossip.SignedGossipData.initSigned(&kp, .{ .LegacyContactInfo = legacy }),
            0,
        );
    }

    var my_shred_version = std.atomic.Value(u16).init(88);
    const ctx: GossipHookContext = .{
        .gossip_table_rw = &gossip_table_rw,
        .my_shred_version = &my_shred_version,
    };

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const nodes = try ctx.getClusterNodes(arena_state.allocator(), .{});
    try testing.expectEqual(1, nodes.len);
}

test "GossipHookContext.getClusterNodes returns setup errors" {
    const missing_gossip_ctx: GossipHookContext = .{};
    try testing.expectError(
        error.GossipTableNotAvailable,
        missing_gossip_ctx.getClusterNodes(testing.allocator, .{}),
    );

    const gossip_table = try sig.gossip.GossipTable.init(testing.allocator, testing.allocator);
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    const missing_shred_ctx: GossipHookContext = .{
        .gossip_table_rw = &gossip_table_rw,
        .my_shred_version = null,
    };
    try testing.expectError(
        error.ShredVersionNotAvailable,
        missing_shred_ctx.getClusterNodes(testing.allocator, .{}),
    );
}
