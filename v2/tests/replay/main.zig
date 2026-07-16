const std = @import("std");
const lib = @import("lib");
const services = @import("services");

const tel = lib.telemetry;
const topology = lib.topology;
const fixture_loader = @import("fixtures/load.zig");

const Region = topology.Region;
const Fixture = fixture_loader.Fixture;

const fixture_for_test = 410010000;
const account_pool_memory = 0;

const Topology = struct {
    shred_receiver: topology.ServiceRegions(.from(services.shred_receiver)),
    replay: topology.ServiceRegions(.from(services.replay)),
    telemetry: topology.ServiceRegions(.from(services.telemetry)),
};

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const gpa = dba_state.allocator();

    var fixture: Fixture = try .load(fixture_for_test, gpa);
    defer fixture.deinit(gpa);

    var selected_packets = fixture.packets;

    const leader_kp: lib.gossip.KeyPair = .fromKeyPair(try .generateDeterministic(@splat(3)));
    try resignPackets(&selected_packets, &leader_kp);
    const first_shred = try lib.shred.Shred.fromPacketChecked(&selected_packets[0]);

    var shred_recv_config: Region(lib.shred.RecvConfig) = try .simple();
    shred_recv_config.ptr().leader_schedule.base_slot = fixture.manifest.slot;
    for (&shred_recv_config.ptr().leader_schedule.leaders) |*schedule_leader| {
        schedule_leader.* = leader_kp.pubkey;
    }
    shred_recv_config.ptr().shred_version = fixture.manifest.shreds.shred_version;

    const net_to_shred_params: lib.net.Pair.InitParams = .{ .port = 8002 };
    var net_to_shred: Region(lib.net.Pair) = try .sized(net_to_shred_params.size());
    net_to_shred_params.init(net_to_shred.ptr());

    var shreds_to_replay: Region(lib.shred.DeshredRing) = try .simple();
    shreds_to_replay.ptr().init();

    var transaction_pool: Region(lib.replay.TransactionPool) =
        try .sized(lib.replay.TransactionPool.size());
    transaction_pool.ptr().init();

    var block_pool: Region(lib.replay.BlockPool) = try .sized(lib.replay.BlockPool.size());
    block_pool.ptr().init();

    var exec_req_response_region: Region(lib.replay.ExecReqResponse) = try .simple();
    exec_req_response_region.ptr().init();

    var snapshot_metadata: Region(lib.accounts_db.RuntimeMetadata) = try .simple();
    snapshot_metadata.ptr().init();
    snapshot_metadata.ptr().block_id = first_shred.chainedMerkleRoot().*;
    {
        var writer = snapshot_metadata.ptr().blockhash_queue.hashes.getView(.writer);
        const blockhashes = writer.getBuffer().?;
        blockhashes[0] = lib.solana.Hash.ZEROES;
        writer.advance(1);
        writer.close();
    }
    snapshot_metadata.ptr().populateSlot(fixture.manifest.shreds.parent_slot);

    var replay_scratch: Region([lib.replay.scratch_buffer_size]u8) = try .simple();

    var account_pool: Region(lib.accounts_db.AccountPool) =
        try .sized(@sizeOf(lib.accounts_db.AccountPool) + account_pool_memory);
    account_pool.ptr().init(account_pool_memory);

    var account_lookups: Region(lib.accounts_db.AccountLookups) = try .simple();
    account_lookups.ptr().init();

    const telemetry_params: tel.Region.InitParams = .{
        .port = 12346,
        .log_filters_encoded = lib.telemetry.log.Filter.parseListStrLitIntoBinary(
            .fatal,
            "replay=info",
        ).?,
        .service_count = 2,
        .id_mem_len = 4096 * 16,
        .gauges_len = 4096 * 2,
        .histogram_data_len = 4096 * 3,
    };
    var telemetry_region: Region(tel.Region) = try .sized(telemetry_params.info().regionSize());
    telemetry_region.ptr().init(telemetry_params);

    const shred_recv_config_init = shred_recv_config.finish();
    const net_to_shred_init = net_to_shred.finish();
    const shreds_to_replay_init = shreds_to_replay.finish();
    const transaction_pool_init = transaction_pool.finish();
    const block_pool_init = block_pool.finish();
    const exec_req_response_init = exec_req_response_region.finish();
    const snapshot_metadata_init = snapshot_metadata.finish();
    const replay_scratch_init = replay_scratch.finish();
    const account_pool_init = account_pool.finish();
    const account_lookups_init = account_lookups.finish();
    const telemetry_init = telemetry_region.finish();

    const net_pair = try net_to_shred_init.memfd.mmapStaticSize(.rw, lib.net.Pair, .{});
    defer std.posix.munmap(@ptrCast(net_pair));

    const exec_req_response = try exec_req_response_init.memfd.mmapStaticSize(
        .rw,
        lib.replay.ExecReqResponse,
        .{},
    );
    defer std.posix.munmap(@ptrCast(exec_req_response));

    const account_lookup_pair = try account_lookups_init.memfd.mmapStaticSize(
        .rw,
        lib.accounts_db.AccountLookups,
        .{},
    );
    defer std.posix.munmap(@ptrCast(account_lookup_pair));

    var spawned: topology.Children(Topology) = undefined;
    try spawned.spawn(.sandboxed, .{
        .shred_receiver = .{
            .ro = .{ .config = shred_recv_config_init },
            .rw = .{
                .snapshot_metadata = snapshot_metadata_init,
                .tvu_socket = net_to_shred_init,
                .deshredded_out = shreds_to_replay_init,
                .tel = telemetry_init,
            },
        },
        .replay = .{
            .ro = .{},
            .rw = .{
                .scratch_memory = replay_scratch_init,
                .snapshot_metadata_in = snapshot_metadata_init,
                .deshredded_in = shreds_to_replay_init,
                .replay_transaction_pool = transaction_pool_init,
                .block_pool = block_pool_init,
                .exec_req_response = exec_req_response_init,
                .account_pool = account_pool_init,
                .account_lookups = account_lookups_init,
                .tel = telemetry_init,
            },
        },
        .telemetry = .{
            .ro = .{},
            .rw = .{ .region = telemetry_init },
        },
    });

    {
        var writer = net_pair.recv.get(.writer);
        for (&selected_packets) |*selected_packet| {
            const packet = writer.next() orelse return error.NetToShredRingFull;
            packet.* = selected_packet.*;
        }
        writer.markUsed();
    }

    try waitForReplayOutput(
        exec_req_response,
        account_lookup_pair,
        fixture.manifest.entries.transaction_count,
        5 * std.time.ns_per_s,
    );
    std.log.info(
        "replay emitted expected transaction requests: {}",
        .{fixture.manifest.entries.transaction_count},
    );

    spawned.cancel();
    try spawned.wait(2 * std.time.ns_per_s);
}

fn resignPackets(
    packets: *[fixture_loader.FEC_SHRED_COUNT]lib.net.Packet,
    keypair: *const lib.gossip.KeyPair,
) !void {
    for (packets) |*packet| {
        const shred = try lib.shred.Shred.fromPacketChecked(packet);
        var merkle_root: lib.solana.Hash = undefined;
        try shred.merkleRoot(&merkle_root);

        const mutable_shred = lib.shred.Shred.fromBufferUncheckedMut(&packet.data);
        mutable_shred.signature = try keypair.sign(&merkle_root.data);
    }
}

fn waitForReplayOutput(
    exec_req_response: *lib.replay.ExecReqResponse,
    account_lookups: *lib.accounts_db.AccountLookups,
    expected_transaction_count: u32,
    timeout_ns: u64,
) !void {
    const start = lib.clock.monotonic(.ns);
    var request_reader = exec_req_response.request_ring.get(.reader);
    var lookup_reader = account_lookups.in.get(.reader);
    var lookup_writer = account_lookups.out.get(.writer);

    var count: u32 = 0;
    while (lib.clock.monotonic(.ns) - start < timeout_ns) {
        var handled_lookup = false;
        while (lookup_reader.next()) |request| {
            const response = lookup_writer.next() orelse return error.AccountLookupResponseRingFull;
            response.* = .{
                .pubkey = request.*,
                .account_index = .invalid,
            };
            handled_lookup = true;
        }
        if (handled_lookup) {
            lookup_reader.markUsed();
            lookup_writer.markUsed();
        }

        var handled_request = false;
        while (request_reader.next()) |request| {
            try std.testing.expect(request.request_kind == .txn_exec);
            count += 1;
            try std.testing.expect(count <= expected_transaction_count);
            handled_request = true;
            if (count == expected_transaction_count) {
                request_reader.markUsed();
                return;
            }
        }
        if (handled_request) request_reader.markUsed();
        std.atomic.spinLoopHint();
    }

    try std.testing.expectEqual(expected_transaction_count, count);
}
