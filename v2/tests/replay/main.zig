const std = @import("std");
const lib = @import("lib");
const services = @import("services");
const topology = @import("topology");

const accounts_db = @import("accounts_db_api");
const shred = @import("shred_api");
const replay = @import("replay_api");

const tel = lib.telemetry;
const fixture_loader = @import("fixtures/load.zig");

const Region = topology.Region;
const Fixture = fixture_loader.Fixture;

const fixture_for_test = 410010000;
const account_pool_memory = 1024 * 1024;

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

    const leader_kp: lib.crypto.KeyPair = .fromKeyPair(try .generateDeterministic(@splat(3)));
    try resignPackets(&selected_packets, &leader_kp);
    const first_shred = try shred.Shred.fromPacketChecked(&selected_packets[0]);

    var shred_recv_config: Region(shred.RecvConfig) = try .simple();
    shred_recv_config.ptr().leader_schedule.base_slot = fixture.manifest.slot;
    for (&shred_recv_config.ptr().leader_schedule.leaders) |*schedule_leader| {
        schedule_leader.* = leader_kp.pubkey;
    }
    shred_recv_config.ptr().shred_version = fixture.manifest.shreds.shred_version;

    const net_to_shred_params: lib.net.Pair.InitParams = .{ .port = 8002 };
    var net_to_shred: Region(lib.net.Pair) = try .sized(net_to_shred_params.size());
    net_to_shred_params.init(net_to_shred.ptr());

    var shreds_to_replay: Region(shred.DeshredRing) = try .simple();
    shreds_to_replay.ptr().init();

    var transaction_pool: Region(replay.TransactionPool) =
        try .sized(replay.TransactionPool.size());
    transaction_pool.ptr().init();

    var block_pool: Region(replay.BlockPool) = try .sized(replay.BlockPool.size());
    block_pool.ptr().init();

    var exec_req_response_region: Region(replay.ExecReqResponse) = try .simple();
    exec_req_response_region.ptr().init();

    var snapshot_metadata: Region(accounts_db.RuntimeMetadata) = try .simple();
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

    var replay_scratch: Region([replay.scratch_buffer_size]u8) = try .simple();

    var account_pool: Region(accounts_db.AccountPool) =
        try .sized(@sizeOf(accounts_db.AccountPool) + account_pool_memory);
    account_pool.ptr().init(account_pool_memory);

    var account_lookups: Region(accounts_db.AccountLookups) = try .simple();
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

    const net_pair = try net_to_shred.finish().memfd.mmapStaticSize(.rw, lib.net.Pair, .{});
    defer std.posix.munmap(@ptrCast(net_pair));

    const exec_req_response = try exec_req_response_region.finish().memfd.mmapStaticSize(
        .rw,
        replay.ExecReqResponse,
        .{},
    );
    defer std.posix.munmap(@ptrCast(exec_req_response));

    const account_lookup_pair = try account_lookups.finish().memfd.mmapStaticSize(
        .rw,
        accounts_db.AccountLookups,
        .{},
    );
    defer std.posix.munmap(@ptrCast(account_lookup_pair));

    const account_pool_init = account_pool.finish();
    const account_pool_buf = try account_pool_init.memfd.mmapRaw(.rw, .{});
    defer std.posix.munmap(account_pool_buf);
    const account_pool_ptr: *accounts_db.AccountPool = @ptrCast(account_pool_buf.ptr);

    var spawned: topology.Children(Topology) = undefined;
    try spawned.spawn(.sandboxed, .{
        .shred_receiver = .{
            .ro = .{ .config = shred_recv_config.finish() },
            .rw = .{
                .snapshot_metadata = snapshot_metadata.finish(),
                .tvu_socket = net_to_shred.finish(),
                .deshredded_out = shreds_to_replay.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .replay = .{
            .ro = .{},
            .rw = .{
                .scratch_memory = replay_scratch.finish(),
                .snapshot_metadata_in = snapshot_metadata.finish(),
                .deshredded_in = shreds_to_replay.finish(),
                .replay_transaction_pool = transaction_pool.finish(),
                .block_pool = block_pool.finish(),
                .exec_req_response = exec_req_response_region.finish(),
                .account_pool = account_pool_init,
                .account_lookups = account_lookups.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .telemetry = .{
            .ro = .{},
            .rw = .{ .region = telemetry_region.finish() },
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
        &spawned,
        exec_req_response,
        account_lookup_pair,
        account_pool_ptr,
        fixture.manifest.entries.transaction_count,
        30 * std.time.ns_per_s,
        30 * std.time.ns_per_s,
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
    keypair: *const lib.crypto.KeyPair,
) !void {
    for (packets) |*packet| {
        const a_shred = try shred.Shred.fromPacketChecked(packet);
        var merkle_root: lib.solana.Hash = undefined;
        try a_shred.merkleRoot(&merkle_root);

        const mutable_shred = shred.Shred.fromBufferUncheckedMut(&packet.data);
        mutable_shred.signature = try keypair.sign(&merkle_root.data);
    }
}

fn waitForReplayOutput(
    spawned: *topology.Children(Topology),
    exec_req_response: *replay.ExecReqResponse,
    account_lookups: *accounts_db.AccountLookups,
    account_pool: *accounts_db.AccountPool,
    expected_transaction_count: u32,
    output_timeout_ns: u64,
    idle_timeout_ns: u64,
) !void {
    var request_reader = exec_req_response.request_ring.get(.reader);
    var lookup_reader = account_lookups.in.get(.reader);
    var lookup_writer = account_lookups.out.get(.writer);

    var count: u32 = 0;

    // Phase 1: wait for replay to emit the expected number of exec requests.
    const output_start = lib.clock.monotonic(.ns);
    while (count < expected_transaction_count) {
        if (lib.clock.monotonic(.ns) - output_start >= output_timeout_ns) {
            try std.testing.expectEqual(expected_transaction_count, count);
            return error.ReplayOutputTimeout;
        }
        try serviceAccountLookups(account_pool, &lookup_reader, &lookup_writer);
        try drainReplayRequests(&request_reader, &count, expected_transaction_count);
        std.atomic.spinLoopHint();
    }

    // Phase 2: wait for services to go idle.
    const idle_start = lib.clock.monotonic(.ns);
    while (spawned.isActive()) : (std.atomic.spinLoopHint()) {
        if (lib.clock.monotonic(.ns) - idle_start >= idle_timeout_ns) {
            return error.ServicesDidNotBecomeIdle;
        }
        try serviceAccountLookups(account_pool, &lookup_reader, &lookup_writer);
        try drainReplayRequests(&request_reader, &count, expected_transaction_count);
    }

    // Final drain after idle, then exact assert.
    try serviceAccountLookups(account_pool, &lookup_reader, &lookup_writer);
    try drainReplayRequests(&request_reader, &count, expected_transaction_count);
    try std.testing.expectEqual(expected_transaction_count, count);
}

fn serviceAccountLookups(
    account_pool: *accounts_db.AccountPool,
    lookup_reader: *@FieldType(accounts_db.AccountLookups, "in").Iterator(.reader),
    lookup_writer: *@FieldType(accounts_db.AccountLookups, "out").Iterator(.writer),
) !void {
    var handled_lookup = false;
    while (lookup_reader.next()) |request| {
        const response = lookup_writer.next() orelse return error.AccountLookupResponseRingFull;
        response.* = .{
            .pubkey = request.*,
            .account_index = try createMockAccount(account_pool, request),
        };
        handled_lookup = true;
    }
    if (handled_lookup) {
        lookup_reader.markUsed();
        lookup_writer.markUsed();
    }
}

fn createMockAccount(
    account_pool: *accounts_db.AccountPool,
    pubkey: *const lib.solana.Pubkey,
) !accounts_db.AccountPool.AccountRef {
    const account_ref = try account_pool.alloc(0);
    const account = account_pool.getAccount(account_ref);
    account.* = .{
        .ref_count = .init(1),
        .pubkey = pubkey.*,
        .owner = .ZEROES,
        .lamports = 0,
        .rent_epoch = 0,
        .data = .{ .executable = false, .len = 0 },
    };
    return account_ref;
}

fn drainReplayRequests(
    request_reader: *replay.ExecReqResponse.RequestRing.Iterator(.reader),
    count: *u32,
    expected_transaction_count: u32,
) !void {
    var handled_request = false;
    while (request_reader.next()) |request| {
        try std.testing.expect(request.request_kind == .txn_exec);
        count.* += 1;
        try std.testing.expect(count.* <= expected_transaction_count);
        handled_request = true;
    }
    if (handled_request) request_reader.markUsed();
}
