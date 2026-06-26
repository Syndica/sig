const std = @import("std");
const lib = @import("lib");

const tel = lib.telemetry;
const fixture_loader = @import("fixtures/load.zig");

const Fixture = fixture_loader.Fixture;

const fixture_for_test = 410010000;

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const gpa = dba_state.allocator();

    var fixture: Fixture = try .load(fixture_for_test, gpa);
    defer fixture.deinit(gpa);

    var selected_packets = fixture.packets;

    const leader_kp: lib.gossip.KeyPair = .fromKeyPair(try .generateDeterministic(@splat(3)));
    try resignPackets(&selected_packets, &leader_kp);

    const service_map = try topology.serviceMap(.{
        .shred_recv_config = .{
            .base_slot = fixture.manifest.slot,
            .leader = leader_kp.pubkey,
            .shred_version = fixture.manifest.shreds.shred_version,
        },
        .net_to_shred = .{ .port = 8002 },
        .shreds_to_replay = {},
        .transaction_pool = {},
        .block_pool = {},
        .exec_req_response = {},
        .telemetry = .{
            .port = 12346,
            .log_filters_encoded = lib.telemetry.log.Filter.parseListStrLitIntoBinary(
                .fatal,
                "replay=info",
            ).?,
            .service_count = @intCast(topology.countTotalBindingShares(.telemetry) - 1),

            .id_mem_len = 4096 * 16,
            .gauges_len = 4096 * 2,

            .histogram_data_len = 4096 * 3,
        },
    });

    const net_to_shred_memfd =
        service_map.entries.get(.shred_receiver).?.bindings.get(.net_to_shred).?;
    const exec_req_response_memfd =
        service_map.entries.get(.replay).?.bindings.get(.exec_req_response).?;

    const net_pair = try net_to_shred_memfd.memfd.mmapStaticSize(.rw, lib.net.Pair, .{});
    defer std.posix.munmap(@ptrCast(net_pair));

    const exec_req_response = try exec_req_response_memfd.memfd.mmapStaticSize(
        .rw,
        lib.replay.ExecReqResponse,
        .{},
    );
    defer std.posix.munmap(@ptrCast(exec_req_response));

    var spawned: topology.Children = undefined;
    try spawned.spawn(.sandboxed, &service_map);

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

        const mutable_shred: *lib.shred.Shred = @ptrCast(packet);
        mutable_shred.signature = try keypair.sign(&merkle_root.data);
    }
}

fn waitForReplayOutput(
    exec_req_response: *lib.replay.ExecReqResponse,
    expected_transaction_count: u32,
    timeout_ns: u64,
) !void {
    const start = lib.clock.monotonic(.ns);
    var request_reader = exec_req_response.request_ring.get(.reader);
    defer request_reader.markUsed();

    var count: u32 = 0;
    while (lib.clock.monotonic(.ns) - start < timeout_ns) {
        while (request_reader.next()) |request| {
            if (request.request_kind != .txn_exec) return error.UnexpectedReplayRequestKind;
            count += 1;
            if (count == expected_transaction_count) return;
            if (count > expected_transaction_count) return error.UnexpectedReplayRequestCount;
        }
        std.atomic.spinLoopHint();
    }

    return error.ReplayOutputTimeout;
}

const topology_schema: lib.topology.Schema = .{
    .services = @import("schema"),
};

pub const topology = lib.topology.Bind(topology_schema, Region, .init(.{
    .shred_recv_config = .initOne(.@"shred_receiver:config"),
    .net_to_shred = .initOne(.@"shred_receiver:from_net"),
    .shreds_to_replay = .initMany(&.{
        .@"shred_receiver:deshredded_out",
        .@"replay:deshredded_in",
    }),
    .transaction_pool = .initMany(&.{
        .@"replay:transaction_pool",
    }),
    .block_pool = .initMany(&.{
        .@"replay:block_pool",
    }),
    .exec_req_response = .initMany(&.{
        .@"replay:exec_req_response",
    }),
    .telemetry = .initMany(&.{
        .@"telemetry:main",
        .@"shred_receiver:telemetry",
        .@"replay:telemetry",
    }),
}));

pub const Region = union(enum) {
    shred_recv_config: struct {
        base_slot: lib.solana.Slot,
        leader: lib.solana.Pubkey,
        shred_version: u16,
    },
    net_to_shred: lib.net.Pair.InitParams,
    shreds_to_replay,
    transaction_pool,
    block_pool,
    exec_req_response,
    telemetry: tel.Region.InitParams,

    pub const Tag = @typeInfo(Region).@"union".tag_type.?;

    pub fn size(self: Region) usize {
        return switch (self) {
            .shred_recv_config => @sizeOf(lib.shred.RecvConfig),
            .net_to_shred => |cfg| cfg.size(),
            .shreds_to_replay => @sizeOf(lib.shred.DeshredRing),
            .transaction_pool => lib.replay.TransactionPool.size(),
            .block_pool => lib.replay.BlockPool.size(),
            .exec_req_response => @sizeOf(lib.replay.ExecReqResponse),
            .telemetry => |params| params.info().regionSize(),
        };
    }

    pub fn init(self: Region, buf: []align(std.heap.page_size_min) u8) !void {
        std.log.info("Initialising: {}", .{std.meta.activeTag(self)});

        return switch (self) {
            .shred_recv_config => |cfg| {
                std.debug.assert(buf.len == @sizeOf(lib.shred.RecvConfig));
                const data: *lib.shred.RecvConfig = @ptrCast(buf);
                data.leader_schedule.base_slot = cfg.base_slot;
                for (&data.leader_schedule.leaders) |*schedule_leader| {
                    schedule_leader.* = cfg.leader;
                }
                data.shred_version = cfg.shred_version;
            },
            .net_to_shred => |cfg| cfg.init(buf),
            .shreds_to_replay => {
                std.debug.assert(buf.len == @sizeOf(lib.shred.DeshredRing));
                const data: *lib.shred.DeshredRing = @ptrCast(buf);
                data.init();
            },
            .transaction_pool => {
                std.debug.assert(buf.len == lib.replay.TransactionPool.size());
                const data: *lib.replay.TransactionPool = @ptrCast(buf);
                data.init();
            },
            .block_pool => {
                std.debug.assert(buf.len == lib.replay.BlockPool.size());
                const data: *lib.replay.BlockPool = @ptrCast(buf);
                data.init();
            },
            .exec_req_response => {
                std.debug.assert(buf.len == @sizeOf(lib.replay.ExecReqResponse));
                const data: *lib.replay.ExecReqResponse = @ptrCast(buf);
                data.init();
            },
            .telemetry => |params| {
                std.debug.assert(buf.len == params.info().regionSize());
                const data: *tel.Region = @ptrCast(buf);
                data.init(params);
            },
        };
    }
};
