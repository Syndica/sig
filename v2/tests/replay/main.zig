const std = @import("std");
const lib = @import("lib");
const tel = lib.telemetry;

const fec_shred_count = 32;
const fixture_path = lib.test_data_dir ++ "shreds/agave.blockstore.bench_write_small.shreds.bin";

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const gpa = dba_state.allocator();

    var selected_packets = try loadFecSetPackets(gpa, fixture_path);

    const leader_kp: lib.gossip.KeyPair = .fromKeyPair(try .generateDeterministic(@splat(3)));
    try resignPackets(&selected_packets, &leader_kp);
    const first_shred = try lib.shred.Shred.fromPacketChecked(&selected_packets[0]);

    const service_map = try topology.serviceMap(.{
        .shred_recv_config = .{
            .base_slot = first_shred.slot,
            .leader = leader_kp.pubkey,
            .shred_version = first_shred.version,
        },
        .net_to_shred = .{ .port = 8002 },
        .shreds_to_replay = {},
        .telemetry = .{
            .port = 12346,
            .log_filters_encoded = lib.telemetry.log.Filter.parseListStrLitIntoBinary(.fatal, "").?,
            .service_count = @intCast(topology.countTotalBindingShares(.telemetry) - 1),

            .id_mem_len = 4096 * 16,
            .gauges_len = 4096 * 2,

            .histogram_data_len = 4096 * 3,
        },
    });

    const net_to_shred_memfd =
        service_map.entries.get(.shred_receiver).?.bindings.get(.net_to_shred).?;
    const shreds_to_replay_memfd =
        service_map.entries.get(.shred_receiver).?.bindings.get(.shreds_to_replay).?;

    const net_pair = try net_to_shred_memfd.memfd.mmapStaticSize(lib.net.Pair, null);
    defer std.posix.munmap(@ptrCast(net_pair));

    const shreds_to_replay = try shreds_to_replay_memfd.memfd.mmapStaticSize(
        lib.shred.DeshredRing,
        null,
    );
    defer std.posix.munmap(@ptrCast(shreds_to_replay));

    var spawned = try topology.spawnSandboxed(&service_map);
    const activities = spawned.activityViews();

    {
        var writer = net_pair.recv.get(.writer);
        for (&selected_packets) |*selected_packet| {
            const packet = writer.next() orelse return error.NetToShredRingFull;
            packet.* = selected_packet.*;
        }
        writer.markUsed();
    }

    const emitted_tail = try waitForTailAdvance(shreds_to_replay, 1 * std.time.ns_per_s);
    try waitForHeadToCatchTail(shreds_to_replay, emitted_tail, 1 * std.time.ns_per_s);

    for (activities) |*view| view.cancel();
    try spawned.wait(1 * std.time.ns_per_s);
}

fn loadFecSetPackets(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![fec_shred_count]lib.net.Packet {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var read_buf: [4096]u8 = undefined;
    var file_reader = file.reader(&read_buf);
    const reader = &file_reader.interface;

    var selected: [fec_shred_count]lib.net.Packet = undefined;
    var selected_count: usize = 0;
    var selected_id: ?lib.shred.FecSetId = null;
    while (try readChunk(allocator, reader)) |chunk| {
        defer allocator.free(chunk);

        if (chunk.len > lib.net.Packet.capacity) return error.ShredPayloadTooLarge;
        var packet: lib.net.Packet = undefined;
        @memcpy(packet.data[0..chunk.len], chunk);
        packet.len = @intCast(chunk.len);
        packet.addr = .initIp4(.{ 127, 0, 0, 1 }, 0);

        const shred = try lib.shred.Shred.fromPacketChecked(&packet);
        const id: lib.shred.FecSetId = .{
            .slot = shred.slot,
            .fec_set_idx = shred.fec_set_idx,
        };

        if (selected_id) |current_id| {
            if (!current_id.eql(&id)) continue;
        } else {
            selected_id = id;
        }

        selected[selected_count] = packet;
        selected_count += 1;
        if (selected_count == selected.len) return selected;
    }

    return error.FecSetNotFound;
}

// Transplanted from v1's src/ledger/tests.zig shred fixture loader
fn readChunk(allocator: std.mem.Allocator, reader: *std.Io.Reader) !?[]const u8 {
    var size_bytes: [8]u8 = undefined;
    reader.readSliceAll(&size_bytes) catch |err| switch (err) {
        error.EndOfStream => return null,
        else => return err,
    };
    const size = std.mem.readInt(u64, &size_bytes, .little);

    const chunk = try allocator.alloc(u8, @intCast(size));
    errdefer allocator.free(chunk);
    try reader.readSliceAll(chunk);

    return chunk;
}

fn waitForTailAdvance(ring: *const lib.shred.DeshredRing, timeout_ns: u64) !u32 {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ns) {
        const tail = ring.tail.value.load(.acquire);
        if (tail != 0) return tail;
        std.atomic.spinLoopHint();
    }
    return error.TailDidNotAdvance;
}

fn resignPackets(
    packets: *[fec_shred_count]lib.net.Packet,
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

fn waitForHeadToCatchTail(
    ring: *const lib.shred.DeshredRing,
    expected_tail: u32,
    timeout_ns: u64,
) !void {
    var timer = try std.time.Timer.start();
    while (timer.read() < timeout_ns) {
        const head = ring.head.value.load(.acquire);
        if (head == expected_tail) return;
        std.atomic.spinLoopHint();
    }
    return error.HeadDidNotCatchTail;
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
    .telemetry = .initMany(&.{ .@"telemetry:main", .@"shred_receiver:telemetry" }),
}));

pub const Region = union(enum) {
    shred_recv_config: struct {
        base_slot: lib.solana.Slot,
        leader: lib.solana.Pubkey,
        shred_version: u16,
    },
    net_to_shred: lib.net.Pair.InitParams,
    shreds_to_replay,
    telemetry: tel.Region.InitParams,

    pub const Tag = @typeInfo(Region).@"union".tag_type.?;

    pub fn size(self: Region) usize {
        return switch (self) {
            .shred_recv_config => @sizeOf(lib.shred.RecvConfig),
            .net_to_shred => |cfg| cfg.size(),
            .shreds_to_replay => @sizeOf(lib.shred.DeshredRing),
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
            .telemetry => |params| {
                std.debug.assert(buf.len == params.info().regionSize());
                const data: *tel.Region = @ptrCast(buf);
                data.init(params);
            },
        };
    }
};
