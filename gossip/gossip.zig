const std = @import("std");
const sig = @import("sig");

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const MTU = 1232;

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer std.debug.assert(gpa_state.deinit() == .ok);
    const gpa = gpa_state.allocator();

    const gossip_port = 8001;
    const keypair: KeyPair = .generate();
    const entrypoints: []const []const u8 = &.{
        "entrypoint.testnet.solana.com:8001",
        "entrypoint2.testnet.solana.com:8001",
        "entrypoint3.testnet.solana.com:8001",
    };

    const echo: EchoResponse, const entry_addr: std.net.Address = for (entrypoints) |entrypoint| {
        const split = std.mem.indexOfScalar(u8, entrypoint, ':') orelse continue;
        const port = std.fmt.parseInt(u16, entrypoint[split + 1..], 10) catch continue;

        const addr_list = std.net.getAddressList(gpa, entrypoint[0..split], port) catch continue;
        defer addr_list.deinit();

        break for (addr_list.addrs) |addr| {
            const socket = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, 0);
            defer std.posix.close(socket);

            const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
            try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv);
            std.posix.connect(socket, &addr.any, addr.getOsSockLen()) catch continue;

            const stream = std.net.Stream{ .handle = socket };
            try bincode.write(stream.writer(), EchoMessage{
                ._hidden_header = 0,
                .tcp_ports = @splat(0),
                .udp_ports = .{ gossip_port, 0, 0, 0 },
                ._hidden_trailer = '\n',
            });

            const echo = 
                try bincode.read(std.testing.failing_allocator, stream.reader(), EchoResponse);
            break .{ echo, addr };
        } else continue;
    } else return error.NoValidEntryPoints;

    const my_contact_info: ContactInfo = .{
        .from = .{ .data = keypair.public_key.bytes },
        .wallclock = undefined, // set during signing
        .created = realtime(),
        .shred_version = echo.shred_version orelse 0,
        .version = .{
            .major = 0,
            .minor = 0,
            .patch = 0,
            .commit = null,
        },
        .feature_set = 0,
        .client_id = @enumFromInt(0),
        .ips = &.{ echo.addr },
        .sockets = &.{ .{ .key = .gossip, .idx = 0, .port = gossip_port } },
        .extensions = &.{},
    };

    try runGossip(entry_addr, keypair, my_contact_info);
}

fn runGossip(entry_addr: std.net.Address, keypair: KeyPair, my_ci: ContactInfo) !void {
    var prng = std.Random.DefaultPrng.init(0);
    
    // Set addr ip to 0 for binding
    var my_addr = try getGossipAddr(.{ .contact_info = my_ci });
    my_addr = switch (my_addr.any.family) {
        std.posix.AF.INET => .initIp4(@splat(0), my_addr.getPort()),
        std.posix.AF.INET6 => .initIp6(@splat(0), my_addr.getPort(), 0, 0),
        else => unreachable,
    };

    const socket = try std.posix.socket(my_addr.any.family, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(socket);

    // Timeout on socket for recvfrom() to eventually run PullRequest/PushMessages
    const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
    try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv);
    
    try std.posix.bind(socket, &my_addr.any, my_addr.getOsSockLen());
    std.log.debug(
        "Started gossip on {any} shred_version:{} pubkey:{}",
        .{my_addr, my_ci.shred_version, Pubkey{ .data = keypair.public_key.bytes } },
    );

    // Start by sending out our contact Info
    try sendGossipMessage(socket, entry_addr, .{ .push_message = .{
        .from = my_ci.from,
        .values = &.{ try signData(keypair, .{
            .version = .{
                .from = my_ci.from,
                .wallclock = undefined, // set during signData
                .version = my_ci.version,
                .feature_set = my_ci.feature_set,
            } }),
        },
    }});
    try sendGossipMessage(socket, entry_addr, .{ .push_message = .{
        .from = my_ci.from,
        .values = &.{ try signData(keypair, .{
            .node_instance = .{
                .from = my_ci.from,
                .wallclock = undefined, // set during signData
                .created = my_ci.created,
                .token = prng.random().int(u64),
            } }), 
        },
    }});
    try sendGossipMessage(socket, entry_addr, .{ .pull_request = .{
        .filter = .{
            .keys = &.{ 0 },
            .has_words = 1,
            .words = &.{ 0 },
            .num_bits = 0,
        },
        .mask = 0,
        .mask_bits = 0,
        .contact_info = try signData(keypair, .{ .contact_info = my_ci }),
    }});

    // filter: struct {
    //     keys: []const u64,
    //     has_words: u8,
    //     words: []const u64,
    //     num_bits: u64,
    // },
    // mask: u64,
    // mask_bits: u32,


    while (true) {
        const now = realtime();
        std.log.debug("Waiting for gossip msg: {}", .{now});

        var buf: [MTU]u8 = undefined;
        var addr: std.net.Address = undefined;
        var addr_len: std.posix.socklen_t = undefined;
        const n = std.posix.recvfrom(socket, &buf, 0, &addr.any, &addr_len) catch |e| switch (e) {
            error.WouldBlock => continue,
            else => |err| return err,
        };
        
        var fbs = std.io.fixedBufferStream(buf[0..n]);
        var alloc_buf: [MTU] u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
        const msg = bincode.read(fba.allocator(), fbs.reader(), GossipMessage) catch |e| {
            std.log.err("Invalid gossip msg: {}", .{e});
            continue;
        };

        std.log.debug("msg: {}\n", .{std.meta.activeTag(msg)});
    }
}

fn sendGossipMessage(socket: std.posix.socket_t, addr: std.net.Address, msg: GossipMessage) !void {
    var buf: [MTU]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try bincode.write(fbs.writer(), msg);
    const sent = try std.posix.sendto(socket, fbs.getWritten(), 0, &addr.any, addr.getOsSockLen());
    std.debug.assert(sent == fbs.getWritten().len);
}

fn getGossipAddr(contact_info_data: CrdsData) !std.net.Address {
    switch (contact_info_data) {
        .legacy_contact_info => |ci| return switch (ci.gossip) {
            .v4 => |s| .initIp4(s.ip, s.port),
            .v6 => |s| .initIp6(s.ip, s.port, 0, 0),
        },
        .contact_info => |ci| for (ci.sockets) |s| {
            if (s.key != .gossip) continue;
            if (s.idx >= ci.ips.len) return error.InvalidContactInfo;
            return switch (ci.ips[s.idx]) {
                .v4 => |ip| .initIp4(ip, s.port),
                .v6 => |ip| .initIp6(ip, s.port, 0, 0),
            };
        } else return error.InvalidContactInfo,
        else => return error.InvalidContactInfo,
    }
}

fn signData(keypair: KeyPair, data_: CrdsData) !CrdsValue {
    var data = data_;
    switch (std.meta.activeTag(data)) {
        inline else => |tag| {
            @field(data, @tagName(tag)).from = .{ .data = keypair.public_key.bytes };
            @field(data, @tagName(tag)).wallclock = realtime();
        }
    }

    var buf: [MTU]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try bincode.write(fbs.writer(), data);
    return .{
        .signature = .fromBytes((try keypair.sign(fbs.getWritten(), null)).toBytes()),
        .data = data,
    };
}

fn realtime() u64 {
    return @intCast(std.time.milliTimestamp());
}

const bincode = struct {
    fn read(gpa: std.mem.Allocator, reader: anytype, comptime T: type) !T {
        switch (@typeInfo(T)) {
            .int => return reader.readInt(T, .little),
            .array => |info| {
                var v: T = undefined;
                for (0..info.len) |i| v[i] = try read(gpa, reader, info.child);
                return v;
            },
            .pointer => |info| {
                comptime std.debug.assert(info.size == .slice);
                const n = try reader.readInt(u64, .little);
                const slice = try gpa.alloc(info.child, n);
                for (0..n) |i| slice[i] = try read(gpa, reader, info.child);
                return slice;
            },
            .optional => |info| switch (try reader.readByte()) {
                0 => return null,
                1 => return try read(gpa, reader, info.child),
                else => return error.InvalidOptional,
            },
            .@"enum" => |info| {
                return try std.meta.intToEnum(T, try read(gpa, reader, info.tag_type));
            },
            .@"union" => |info| switch (try read(gpa, reader, info.tag_type.?)) {
                inline else => |tag| {
                    const Variant = @TypeOf(@field(@as(T, undefined), @tagName(tag)));
                    return @unionInit(T, @tagName(tag), try read(gpa, reader, Variant));
                },
            },
            .@"struct" => |info| {
                var v: T = undefined;
                inline for (info.fields) |f| @field(v, f.name) = try read(gpa, reader, f.type);
                return v;
            },
            else => @compileError("invalid bincode type"),
        }
    }

    fn write(writer: anytype, value: anytype) !void {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .int => try writer.writeInt(T, value, .little),
            .array => for (value) |v| try write(writer, v),
            .pointer => |info| {
                comptime std.debug.assert(info.size == .slice);
                try write(writer, @as(u64, value.len));
                for (value) |v| try write(writer, v);
            },
            .optional => {
                try writer.writeByte(@intFromBool(value != null));
                if (value) |v| try write(writer, v);
            },
            .@"enum" => try write(writer, @intFromEnum(value)),
            .@"union" => switch (value) {
                inline else => |v| {
                    try write(writer, std.meta.activeTag(value));
                    try write(writer, v);
                },
            },
            .@"struct" => |info| {
                inline for (info.fields) |f| try write(writer, @field(value, f.name));
            },
            else => @compileError("invalid bincode type"),
        }
    }
};

const Timestamp = u64;
const ShredVersion = u16;

const EchoMessage = struct {
    _hidden_header: u32,
    tcp_ports: [4]u16,
    udp_ports: [4]u16,
    _hidden_trailer: u8,
};

const EchoResponse = struct {
    _hidden_header: u32,
    addr: IpAddr,
    shred_version: ?ShredVersion,
};

const IpAddr = union(enum(u32)) {
    v4: [4]u8,
    v6: [16]u8,
};

const GossipMessage = union(enum(u32)) {
    pull_request: struct {
        filter: struct {
            keys: []const u64,
            has_words: u8,
            words: []const u64,
            num_bits: u64,
        },
        mask: u64,
        mask_bits: u32,
        contact_info: CrdsValue,
    },
    pull_response: struct {
        from: Pubkey,
        values: []const CrdsValue,
    },
    push_message: struct {
        from: Pubkey,
        values: []const CrdsValue,
    },
    prune_message: struct {
        from: Pubkey,
        data: struct {
            pubkey: Pubkey,
            prunes: []const Pubkey,
            signature: Signature,
            dest: Pubkey,
            wallclock: Timestamp,
        },
    },
    ping_message: struct {
        from: Pubkey,
        token: [32]u8,
        signature: Signature,
    },
    pong_message: struct {
        from: Pubkey,
        hash: Hash,
        signature: Signature,
    },
};

const CrdsValue = struct {
    signature: Signature,
    data: CrdsData,
};

const CrdsData = union(enum(u32)) {
    legacy_contact_info: struct {
        from: Pubkey,
        gossip: SocketAddr,
        tvu: SocketAddr,
        tvu_quic: SocketAddr,
        serve_repair_quic: SocketAddr,
        tpu: SocketAddr,
        tpu_forwards: SocketAddr,
        tpu_vote: SocketAddr,
        rpc: SocketAddr,
        rpc_pubsub: SocketAddr,
        serve_repair: SocketAddr,
        wallclock: Timestamp,
        shred_version: ShredVersion,
    },
    vote: struct {
        index: u8,
        from: Pubkey,
        transaction: struct {
            signatures: []const Signature,
            message: struct {
                num_signatures: u8,
                num_readonly_signed: u8,
                num_readonly_unsigned: u8,
                accounts: []const Pubkey,
                recent_blockhash: Hash,
                instructions: []const struct {
                    program_id: u8,
                    accounts: []const u8,
                    data: []const u8,
                },
            },
        },
        wallclock: Timestamp,
        slot: Slot,
    },
    lowest_slot: struct {
        index: u8,
        from: Pubkey,
        _root: Slot, // deprecated
        lowest: Slot,
        _slots: []const Slot, // deprecated
        _stashes: []const struct { // deprecated
            first_slot: Slot,
            compression: enum(u32) {
                uncompressed,
                gzip,
                bzip2,
            },
            bytes: []const u8,
        },
        wallclock: Timestamp,
    },
    legacy_snapshot_hashes: AccountHashes,
    account_hashes: AccountHashes,
    epoch_slots: struct {
        index: u8,
        from: Pubkey,
        slots: []const union(enum(u32)) {
            flate2: struct {
                first_slot: Slot,
                num_slots: u64,
                compressed: []const u8,
            },
            uncompressed: struct {
                first_slot: Slot,
                num_slots: u64,
                has_slots: u8,
                slots: []const u8,
            },
        },
        wallclock: Timestamp,
    },
    legacy_version: struct {
        from: Pubkey,
        wallclock: Timestamp,
        version: Version,
    },
    version: struct {
        from: Pubkey,
        wallclock: Timestamp,
        version: Version,
        feature_set: u32,
    },
    node_instance: struct {
        from: Pubkey,
        wallclock: Timestamp,
        created: Timestamp,
        token: u64,
    },
    duplicate_shred: struct {
        index: u16,
        from: Pubkey,
        wallclock: Timestamp,
        slot: Slot,
        _unused: u32,
        _shred_type: enum(u32) {
            data = 0b10100101,
            code = 0b01011010,
        },
        num_chunks: u8,
        chunk_idx: u8,
        chunk: []const u8,
    },
    snapshot_hashes: struct {
        from: Pubkey,
        full: SlotAndHash,
        incremental: []const SlotAndHash,
        wallclock: Timestamp,
    },
    contact_info: ContactInfo,
    restart_last_voted_fork_slots: struct {
        from: Pubkey,
        wallclock: Timestamp,
        offsets: []const union(enum(u32)) {
            rle: []const u16,
            raw: struct {
                has_items: u8,
                items: []const u8,
            },
        },
        last_voted: SlotAndHash,
        shred_version: ShredVersion,
    },
    restart_heaviest_fork: struct {
        from: Pubkey,
        wallclock: Timestamp,
    },
};

const ContactInfo = struct {
    from: Pubkey,
    wallclock: Timestamp,
    created: Timestamp,
    shred_version: ShredVersion,
    version: Version,
    feature_set: u32,
    client_id: enum(u16) { _ },
    ips: []const IpAddr,
    sockets: []const struct {
        key: enum(u8) {
            gossip,
            serve_repair_quic,
            rpc,
            rpc_pubsub,
            serve_repair,
            tpu,
            tpu_forwards,
            tpu_forwards_quic,
            tpu_quic,
            tpu_vote,
            tvu,
            tvu_quic,
            tpu_vote_quic,
        },
        idx: u8,
        port: u16,
    },
    extensions: []const struct{},
};

const SocketAddr = union(enum(u32)) {
    v4: struct {
        ip: [4]u8,
        port: u16,
    },
    v6: struct {
        ip: [16]u8,
        port: u16,
    },
};

const AccountHashes = struct {
    from: Pubkey,
    slot_hashes: []const SlotAndHash,
    wallclock: Timestamp,
};

const SlotAndHash = struct {
    slot: Slot,
    hash: Hash,
};

const Version = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: ?u16,
};

