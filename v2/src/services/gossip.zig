//! This service participates in the gossip cluster, advertising our service addresses, collecting
//! the service addresses of other nodes, and generally getting status updates in and out of the
//! validator.

const std = @import("std");
const start = @import("start");
const common = @import("common");
const tracy = @import("tracy");

const Pair = common.net.Pair;
const Packet = common.net.Packet;
const Slot = common.solana.Slot;
const Hash = common.solana.Hash;

comptime {
    _ = start;
}

pub const name = .gossip;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    pair: *Pair,
    scratch_mem: *[common.gossip.scratch_memory_size]u8,
};

pub const ReadOnly = struct {
    gossip_config: *const common.gossip.GossipConfig,
};


pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    // Get cluster / entrypoint info.
    const ip, const shred_version, const entry_addr =
        getEchoInfo(ro.gossip_config.cluster.getEntrypoints()) catch |e| {
            std.log.err("failed to get entrypoint info: {}", .{e});
            return e;
        };

    const keypair = &ro.gossip_config.keypair;
    std.log.debug(
        "Gossip started on {any}:{} (shred_version:{} entrypoint:{f})",
        .{ip, rw.pair.port, shred_version, entry_addr},
    );

    var _fba = std.heap.FixedBufferAllocator.init(rw.scratch_mem);
    const allocator = _fba.allocator();

    var table: std.AutoArrayHashMapUnmanaged(
        struct {
            from: common.solana.Pubkey,
            tag: enum{}, // TODO
            index: u16,
        },
        struct {
            hash: common.solana.Hash,
            wallclock: u64,
            duplicates: u8,
            bytes: u16,
            value: [common.net.Packet.len]u8,
        },
    ) = .{};
    defer table.deinit(allocator);
    try table.ensureTotalCapacity(allocator, 8192);

    table.putAssumeCapacity(
        .{ .from = ro.gossip_config.keypair.pubkey, .tag = undefined, .index = 0 },
        undefined,
    );


    // WIP:
    {
        const ping_token: [32]u8 = @splat(0);
        const signature = try keypair.sign(&ping_token);

        var slice = try rw.pair.send.getWritable();
        const p = slice.one();
        var writer = std.Io.Writer.fixed(&p.data);
        try writeFixed(&writer, .{
            .tag = GossipMessageType.ping_message,
            .from = keypair.pubkey,
            .token = ping_token,
            .signature = signature,
        });
        p.size = @intCast(writer.buffered().len);
        p.addr = entry_addr;
        slice.markUsed(1);
    }

    while (true) {
        var slice = rw.pair.recv.getReadable() catch continue;
        const packet = slice.one();
        defer slice.markUsed(1);

        std.log.debug("Got packet: {f} (bytes:{})", .{packet.addr, packet.size});
    }
}

fn getEchoInfo(entrypoints: []const []const u8) !struct{ IpAddr, u16, std.net.Address } {
    for (entrypoints) |entrypoint| {
        const split = std.mem.indexOfScalar(u8, entrypoint, ':') orelse continue;
        const port = std.fmt.parseInt(u16, entrypoint[split + 1..], 10) catch continue;

        var scratch_buf: [8192]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch_buf);

        const addr_list =
            try std.net.getAddressList(fba.allocator(), entrypoint[0..split], port);
        defer addr_list.deinit();

        for (addr_list.addrs) |addr| {
            const socket = try std.posix.socket(
                addr.any.family,
                std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC,
                std.posix.IPPROTO.TCP,
            );
            defer std.posix.close(socket);

            // set timeout of 1s for connect, read, write.
            const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
            try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv);
            std.posix.connect(socket, &addr.any, addr.getOsSockLen()) catch continue;

            // TODO: buffer
            var writer = (std.net.Stream{ .handle = socket }).writer(&.{});
            writeFixed(&writer.interface, (struct {
                _hidden_header: [4]u8 = @splat(0),
                tcp_ports: [4]u16 = @splat(0),
                udp_ports: [4]u16 = @splat(0),
                _hidden_trailer: u8 = '\n',
            }){}) catch continue;

            // TODO: buffer
            var buf: [4]u8 = undefined;
            var reader = (std.net.Stream{ .handle = socket }).reader(&buf);
            const resp = readFixed(reader.interface(), struct {
                _hidden_header: u32,
                ip: IpAddr,
                shred_version: ?u16,
            }) catch continue;

            const shred_version = resp.shred_version orelse 0;
            return .{ resp.ip, shred_version, addr };
        }
    }
    return error.NoValidEntrypoint;
}

fn readFixed(reader: *std.Io.Reader, comptime T: type) !T {
    switch (@typeInfo(T)) {
        .int => return try reader.takeInt(T, .little),
        .optional => |info| switch (try reader.takeByte()) {
            0 => return null,
            1 => return try readFixed(reader, info.child),
            else => return error.InvalidOptional,
        },
        .array => |info| {
            comptime std.debug.assert(@typeInfo(info.child) == .int);
            return @bitCast((try reader.takeArray(@sizeOf(info.child) * info.len)).*);
        },
        .@"enum" => |info| return try std.meta.intToEnum(T, try readFixed(reader, info.tag_type)),
        .@"union" => |info| switch (try readFixed(reader, info.tag_type.?)) {
            inline else => |tag| {
                const Variant = @TypeOf(@field(@as(T, undefined), @tagName(tag)));
                return @unionInit(T, @tagName(tag), try readFixed(reader, Variant));
            },
        },
        .@"struct" => |info| {
            var value: T = undefined;
            inline for (info.fields) |f| @field(value, f.name) = try readFixed(reader, f.type);
            return value;
        },
        else => @compileError("unsupported type: " ++ @typeName(T)),
    }
}

fn writeFixed(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int => try writer.writeInt(T, value, .little),
        .optional => {
            try writer.writeByte(@intFromBool(value != null));
            if (value) |v| try writeFixed(writer, v);
        },
        .array => |info| {
            comptime std.debug.assert(@typeInfo(info.child) == .int);
            try writer.writeAll(std.mem.asBytes(&value));
        },
        .@"enum" => try writeFixed(writer, @intFromEnum(value)),
        .@"union" => switch (std.meta.activeTag(value)) {
            inline else => |tag| {
                try writeFixed(writer, tag);
                try writeFixed(writer, @field(value, @tagName(tag)));
            },
        },
        .@"struct" => |info| {
            inline for (info.fields) |f| try writeFixed(writer, @field(value, f.name));
        },
        else => @compileError("unsupported type: " ++ @typeName(T)),
    }
}

const IpAddr = union(enum(u32)) {
    v4: [4]u8,
    v6: [16]u8,
};

const GossipMessageType = enum(u32) {
    pull_request,
    pull_response,
    push_message,
    prune_message,
    ping_message,
    pong_message,
};