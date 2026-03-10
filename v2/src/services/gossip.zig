//! This service participates in the gossip cluster, advertising our service addresses, collecting
//! the service addresses of other nodes, and generally getting status updates in and out of the
//! validator.

const std = @import("std");
const start = @import("start");
const common = @import("common");
const tracy = @import("tracy");

const assert = std.debug.assert;

const Pair = common.net.Pair;
const Packet = common.net.Packet;

const Signature = common.solana.Signature;
const Pubkey = common.solana.Pubkey;
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
    config: *const common.gossip.Config,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const cluster_info = &ro.config.cluster_info;
    std.log.debug(
        "Gossip started on :{} (shred_version:{} entrypoint:{f})",
        .{ rw.pair.port, cluster_info.shred_version, cluster_info.entry_addr },
    );

    var socket_entries: [2]GossipData.SocketEntry = .{
        .{ .key = .gossip, .ip_idx = 0, .port_offset = rw.pair.port },
        .{ .key = .tvu, .ip_idx = 0, .port_offset = ro.config.turbine_recv_port },
    };
    {
        // Sort by ports.
        std.mem.sort(GossipData.SocketEntry, &socket_entries, {}, struct {
            fn lessThan(_: void, a: GossipData.SocketEntry, b: GossipData.SocketEntry) bool {
                return a.port_offset < b.port_offset;
            }
        }.lessThan);

        // Convert ports into offsets of each other.
        var port: u16 = 0;
        for (socket_entries) |*e| {
            e.port_offset -= port;
            port += e.port_offset;
        }
    }

    var now: u64 = @intCast(std.time.milliTimestamp());
    const contact_info: GossipData = .{ .contact_info = .{
        .from = ro.config.keypair.pubkey,
        .wallclock = .{ .value = now },
        .created = now,
        .shred_version = cluster_info.shred_version,
        .major = .{ .value = 0 },
        .minor = .{ .value = 0 },
        .patch = .{ .value = 0 },
        .commit = 0,
        .feature_set = 0,
        .client_id = .{ .value = 0 },
        .ips = .{ .items = &.{
            switch (cluster_info.public_ip.any.family) {
                std.posix.AF.INET => .{ .v4 = @bitCast(cluster_info.public_ip.in.sa.addr) },
                std.posix.AF.INET6 => .{ .v6 = cluster_info.public_ip.in6.sa.addr },
                else => unreachable,
            },
        } },
        .sockets = .{ .items = &socket_entries },
        .extensions = .{ .items = &.{} },
    } };

    var fba = std.heap.FixedBufferAllocator.init(rw.scratch_mem);
    var gossip = try Gossip.init(&fba, .{
        .netpair = rw.pair,
        .keypair = &ro.config.keypair,
        .entry_addr = cluster_info.entry_addr,
        .contact_info = contact_info,
    });

    while (true) {
        now = @intCast(std.time.milliTimestamp());
        try gossip.poll(now);
    }
}

const Gossip = struct {
    table: Table,
    peers: Peers,
    expired: Expired,
    config: Config,
    prng: std.Random.DefaultPrng = .init(0),
    ping_token: [32]u8 = @splat(0xff),
    ping_timeout: u64 = 0,
    push_timeout: u64 = 0,
    pull_timeout: u64 = 0,

    const PULL_INTERVAL_MS = 500;
    const PUSH_INTERVAL_MS = 7500;
    const PING_INTERVAL_MS = 60 * 1000;

    const ACTIVE_CONTACT_THRESHOLD_MS = 30 * 1000;
    const ACTIVE_PONG_THRESHOLD_MS = 60 * 1000;
    const STALE_PUSH_THRESHOLD_MS = 15 * 1000;

    const PRUNE_PREFIX = "\xffSOLANA_PRUNE_DATA";
    const PING_PONG_PREFIX = "SOLANA_PING_PONG";

    const MAX_BLOOM_KEYS = 8;
    const MAX_BLOOM_BYTES = 928;

    const Key = struct {
        from: Pubkey,
        tag: std.meta.Tag(GossipValue),
        index: u16,
    };
    const Table = std.AutoArrayHashMapUnmanaged(Key, struct {
        hash: Hash,
        wallclock: u64,
        duplicates: u8,
        size: u16,
        value: [Packet.len]u8,
    });
    const Expired = std.ArrayListUnmanaged(struct {
        hash: Hash,
        wallclock: u64,
    });
    const Peers = std.AutoArrayHashMapUnmanaged(Pubkey, Peer);
    const Peer = struct {
        addr: std.net.Address,
        last_ping: u64,
        last_pong: ?u64,
        last_contact: ?u64,
        ignoring: BlockBloomFilter,
    };

    const BlockBloomFilter = struct {
        keys: [MAX_BLOOM_KEYS]u64,
        words: [MAX_BLOOM_BYTES / 8]u64,

        fn init(prng: std.Random) @This() {
            var keys: [MAX_BLOOM_KEYS]u64 = undefined;
            for (&keys) |k| k.* = prng.int(u64);
            return .{ .keys = keys, .words = @splat(0) };
        }

        fn asBloomFilter(self: *@This()) BloomFilter {
            var bits_set: u64 = 0;
            for (self.words) |w| bits_set += @popCount(w);
            return .{
                .keys = .{ .items = &self.keys },
                .bits = .{ .words = &self.words, .capacity = self.words.len * 64 },
                .bits_set = bits_set,
            };
        }
    };

    pub const Config = struct {
        netpair: *Pair,
        keypair: *const common.gossip.KeyPair,
        entry_addr: std.net.Address,
        contact_info: GossipData,
    };

    pub fn init(fba: *std.heap.FixedBufferAllocator, config: Config) !Gossip {
        assert(config.contact_info == .contact_info);

        var table: Table = .empty;
        try table.ensureTotalCapacity(fba.allocator(), 16384);

        var expired: Expired = .empty;
        try expired.ensureTotalCapacity(fba.allocator(), 8192);

        var peers: Peers = .empty;
        try peers.ensureTotalCapacity(fba.allocator(), 65535);

        return .{
            .table = table,
            .peers = peers,
            .expired = expired,
            .config = config,
        };
    }

    pub fn poll(self: *Gossip, now: u64) !void {
        if (self.pull_timeout <= now) {
            self.pull_timeout = now + PULL_INTERVAL_MS;
            try self.sendPullRequests(now);
        }

        if (self.push_timeout <= now) {
            self.push_timeout = now + PUSH_INTERVAL_MS;
            try self.sendPushMessages(now);
        }

        if (self.ping_timeout <= now) {
            self.ping_timeout = now + PING_INTERVAL_MS;
            try self.processPings(now);
        }

        var slice = self.config.netpair.recv.getReadable() catch return;
        defer slice.markUsed(1);
        const packet: *const Packet = slice.get(0);

        var msg_buf: [16 * 1024]u8 = undefined;
        var msg_fba = std.heap.FixedBufferAllocator.init(&msg_buf);
        var msg_reader: std.Io.Reader = .fixed(packet.data[0..packet.size]);
        const msg = bincode.read(&msg_fba, &msg_reader, GossipMessage) catch |e| {
            std.log.err("invalid msg from ({f}, size={}): {}", .{ packet.addr, packet.size, e });
            return;
        };

        self.processMessage(now, packet.addr, msg) catch |e| {
            std.log.err("failed to process msg ({f}, {s}) {}", .{ packet.addr, @tagName(msg), e });
            return;
        };
    }

    fn processMessage(self: *Gossip, now: u64, addr: std.net.Address, msg: GossipMessage) !void {
        std.log.debug("{s}", .{@tagName(msg)});

        switch (msg) {
            .pull_request => |pr| {
                const from = switch (pr.contact_info.data) {
                    inline .legacy_contact_info, .contact_info => |ci| ci.from,
                    else => return error.InvalidPullRequestContactInfo,
                };

                // Unverified peers must respond to a ping first.
                const peer = self.getOrTrackPeer(addr, from) orelse
                    return error.PullRequestFromUnverifiedPeer;
                const mask_bits = std.math.cast(u6, pr.mask_bits) catch
                    return error.InvalidPullRequestMaskBits;

                // Update the ContactInfo
                try self.insertValue(now, .pull, pr.contact_info);

                // Find a value that match the PullRequest mask + bloom filter
                for (self.table.values()) |v| {
                    const lsb_mask = (~@as(u64, 0)) >> mask_bits;
                    const h: u64 = std.mem.readInt(u64, v.hash[0..8], .little);
                    if ((h | lsb_mask) != (pr.mask | lsb_mask)) continue;
                    if (pr.ignoring.contains(&v.hash)) continue;

                    var found_buf: [16 * 1024]u8 = undefined;
                    var found_fba = std.heap.FixedBufferAllocator.init(&found_buf);
                    var found_reader: std.Io.Reader = .fixed(v.value[0..v.size]);
                    const value = try bincode.read(&found_fba, &found_reader, GossipValue);

                    // Only technically need to send one value back to be compliant.
                    // Other nodes do this to unstaked nodes too.
                    try self.sendMessage(peer.addr, .{ .pull_response = .{
                        .from = self.identity(),
                        .values = .{ .items = &.{value} },
                    } });
                    return;
                }
            },
            .pull_response => |pr| {
                @compileError("TODO");
            },
            .push_message => |push| {
                @compileError("TODO");
            },
            .prune_message => |prune| {
                if (!prune.from.equals(&prune.data.sender))
                    return error.InvalidPruneDataSender;
                if (!prune.data.receiver.equals(&self.identity()))
                    return error.InvalidPruneDataDestination;

                const peer = self.peers.get(prune.from) orelse
                    return error.PruneSentByUntrackedPeer;
                if ((peer.last_contact orelse 0) < (now -| ACTIVE_CONTACT_THRESHOLD_MS))
                    return error.PruneSentByInactivePeer;

                var sign_buf: [Packet.len]u8 = undefined;
                var sign_writer: std.Io.Writer = .fixed(&sign_buf);
                try bincode.write(&sign_writer, .{
                    .prefix = PRUNE_PREFIX.*,
                    .pubkey = prune.data.sender,
                    .prunes = prune.data.filter_out,
                    .dest = prune.data.receiver,
                    .wallclock = prune.data.wallclock,
                });

                // Prune can be signed with or without prefix...
                const sign_msg = sign_writer.buffered();
                prune.data.signature.verify(&prune.from, sign_msg) catch {
                    prune.data.signature.verify(&prune.from, sign_msg[PRUNE_PREFIX.len..]) catch {
                        return error.InvalidPruneSignature;
                    };
                };

                var bloom_filter = peer.ignoring.asBloomFilter();
                for (prune.data.filter_out.items) |*pubkey| {
                    bloom_filter.add(&pubkey.data);
                }
            },
            .ping_message => |ping| {
                ping.signature.verify(&ping.from, &ping.token) catch {
                    std.log.err("invalid Ping signature from {}:{}", .{ ping.from, addr });
                    return;
                };

                const hash = Hash.initMany(&.{ PING_PONG_PREFIX, &ping.token });
                try self.sendMessage(addr, .{ .pong_message = .{
                    .from = self.identity(),
                    .hash = hash,
                    .signature = try self.sign(&hash.data),
                } });
            },
            .pong_message => |pong| {
                pong.signature.verify(&pong.from, &pong.hash) catch {
                    std.log.err("invalid Pong signature from {}:{}", .{ pong.from, addr });
                    return;
                };

                const hash = Hash.initMany(&.{ PING_PONG_PREFIX, &self.ping_token });
                if (!pong.hash.eql(&hash)) {
                    std.log.err("invalid Pong hash from {}:{}", .{ pong.from, addr });
                    return;
                }

                const peer = self.peers.get(pong.from) orelse return;
                peer.last_pong = now;
            },
        }
    }

    fn processPings(self: *Gossip, now: u64) !void {
        @compileError("TODO");
    }

    fn sendPushMessages(self: *Gossip, now: u64) !void {
        @compileError("TODO");
    }

    fn sendPullRequests(self: *Gossip, now: u64) !void {
        @compileError("TODO");
    }

    fn insertValue(self: *Gossip, now: u64, caller: enum { pull, push }, value: GossipValue) !?u8 {
        const from: Pubkey, const wallclock: u64, const index: u16 = switch (value.data) {
            inline .vote, .lowest_slot, .epoch_slots, .duplicate_shred => |v| blk: {
                break :blk .{ v.from, v.wallclock, v.index };
            },
            inline .snapshot_hashes, .restart_last_voted_fork, .restart_heaviest_fork => |v| blk: {
                break :blk .{ v.from, v.wallclock, 0 };
            },
            .contact_info => |v| .{ v.from, v.wallclock.value, 0 },
            else => return null, // deprecated
        };

        // Serialize the value & validate its signature.
        var value_buf: [Packet.len]u8 = undefined;
        var value_writer: std.Io.Writer = .fixed(&value_buf);
        try bincode.write(&value_writer, value);

        const value_bytes = value_writer.buffered();
        try value.signature.verify(&from, value_bytes[64..]);
        const hash = Hash.init(value_bytes);

        // Check wallclock in general
        const update_last_contact = switch (caller) {
            .push => blk: {
                if (wallclock <= (now -| STALE_PUSH_THRESHOLD_MS)) return null;
                if (wallclock >= (now +| STALE_PUSH_THRESHOLD_MS)) return null;
                break :blk true;
            },
            .pull => blk: {
                const threshold: u64 = // TODO: 2 days for staked `from`
                    if (from.equals(&self.identity())) std.math.maxInt(u64) else 15 * 1000;
                if (now <= wallclock +| threshold) break :blk true;
                if (value.data == .contact_info) break :blk false;
                self.addExpired(now, hash);
                return null;
            },
        };

        const key: Key = .{ .from = from, .tag = std.meta.activeTag(value.data), .index = index };
        const exists, const v = blk: {
            if (self.table.count() == self.table.capacity()) {
                if (self.table.getPtr(key)) |v| break :blk .{ true, v };
                const i = findOldest(self.table.values());
                self.table.swapRemoveAt(i);
            }
            const gop = self.table.getOrPutAssumeCapacity(key);
            break :blk .{ gop.found_existing, gop.value_ptr };
        };

        if (exists) {
            // duplicate
            if (hash.eql(&v.hash)) {
                v.duplicates +|= 1;
                return v.duplicates;
            }
            // failed_push
            if (wallclock < v.wallclock or hash.order(&v.hash) == .lt) {
                self.addExpired(now, hash);
                return null;
            }
            // evicted
            self.addExpired(now, v.hash);
        }

        v.* = .{
            .hash = hash,
            .wallclock = wallclock,
            .duplicate = 0,
            .size = @intCast(value_bytes.len),
            .value = undefined,
        };
        @memcpy(v.value[0..v.size], value_bytes);

        // handle newly inserted value
        switch (value.data) {
            .vote => {}, // TODO: send to consensus service
            .lowest_slot => {}, // TODO: send to repair service
            .epoch_slots => {}, // TODO: send to consensus service
            .duplicate_shred => {}, // TODO: send to shred/consensus service
            .snapshot_hashes => {}, // TODO: send to snapshot service
            .contact_info => |ci| blk: {
                // validate & create socket map for ContactInfo
                var map: std.EnumMap(GossipData.SocketKey, std.net.Address) = .init(.{});
                var port: u16 = 0;
                for (ci.sockets.items) |s| {
                    if (s.ip_idx >= ci.ips.items.len) break :blk; // invalid ip_idx
                    port += s.port_offset;
                    if (map.fetchPut(s.key, switch (ci.ips.items[s.ip_idx]) {
                        .v4 => |ip| .initIp4(ip, port),
                        .v6 => |ip| .initIp6(ip, port, 0, 0),
                    })) |_| break :blk; // duplicate keys
                }

                if (map.get(.gossip)) |gossip_addr| b: {
                    const peer = self.getOrTrackPeer(now, gossip_addr, ci.from) orelse break :b;
                    if (update_last_contact) peer.last_contact = wallclock;
                }

                // TODO: if map.get(.serve_repair): send to repair service
                // TODO: if map.get(.tpu_vote): send to consensus service
                // TODO: if map.get(.rpc): send to snapshot service
            },
            .restart_last_voted_fork => {}, // TODO: implement wen-restart protocol (SIMD-0046).
            .restart_heaviest_fork => {}, // TODO: implement wen-restart protocol (SIMD-0046).
            else => {},
        }

        return 0;
    }

    fn addExpired(self: *Gossip, now: u64, hash: Hash) void {
        if (self.expired.items.len == self.expired.capacity) {
            const i = findOldest(self.expired.items);
            _ = self.expired.swapRemove(i);
        }
        self.expired.appendAssumeCapacity(.{ .hash = hash, .wallclock = now });
    }

    fn getOrTrackPeer(self: *Gossip, now: u64, addr: std.net.Address, from: Pubkey) ?*Peer {
        if (self.peers.count() == self.peers.capacity()) {
            if (self.peers.getPtr(from)) |peer|
                return peer;
            const i = findOldest(self.peers.values());
            self.peers.swapRemoveAt(i);
        }

        const gop = self.peers.getOrPutAssumeCapacity(from);
        if (!gop.found_existing) {
            const maybe_ci = self.table.getPtr(.{ .from = from, .tag = .contact_info, .index = 0 });
            gop.value_ptr.* = .{
                .addr = addr,
                .last_ping = now,
                .last_pong = null,
                .last_contact = if (maybe_ci) |v| v.wallclock else null,
                .ignoring = .init(self.prng.random()),
            };
            try self.sendPing(addr);
            return null;
        }

        return gop.value_ptr;
    }

    fn findOldest(slice: anytype) usize {
        var oldest: usize = 0;
        for (1..slice.len) |i| {
            if (slice[i].wallclock < slice[oldest].wallclock)
                oldest = i;
        }
        return oldest;
    }

    fn identity(self: *const Gossip) Pubkey {
        return self.config.keypair.pubkey;
    }

    fn sign(self: *Gossip, msg: []const u8) !Signature {
        return self.config.keypair.sign(msg);
    }

    fn signData(self: *const Gossip, now: u64, data_: GossipData) !GossipValue {
        var data = data_;
        switch (std.meta.activeTag(data)) {
            inline else => |tag| {
                @field(data, @tagName(tag)).wallclock = now;
            },
        }

        var buf: [Packet.len]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        try bincode.write(&writer, data);
        return .{
            .signature = try self.sign(writer.buffered()),
            .data = data,
        };
    }

    fn sendPing(self: *Gossip, addr: std.net.Address) !void {
        return self.sendMessage(addr, .{ .ping_message = .{
            .from = self.identity(),
            .token = self.ping_token,
            .signature = try self.sign(self.ping_token),
        } });
    }

    fn sendMessage(self: *Gossip, addr: std.net.Address, msg: GossipMessage) !void {
        var slice = while (true) break self.config.netpair.send.getWritable() catch continue;
        const packet: *Packet = slice.get(0);
        packet.addr = addr;
        var writer: std.Io.Writer = .fixed(&packet.data);
        try bincode.write(&writer, msg);
        packet.size = @intCast(writer.buffered().len);
        slice.markUsed(1);
    }
};

const bincode = struct {
    fn read(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader, comptime T: type) !T {
        if (@hasDecl(T, "bincodeRead")) return T.read(fba, reader);
        switch (@typeInfo(T)) {
            .int => return try reader.takeInt(T, .little),
            .optional => |info| switch (try reader.takeByte()) {
                0 => return null,
                1 => return try read(fba, reader, info.child),
                else => return error.InvalidOptional,
            },
            .array => |info| {
                comptime std.debug.assert(@typeInfo(info.child) == .int);
                return @bitCast((try reader.takeArray(@sizeOf(info.child) * info.len)).*);
            },
            .@"enum" => |info| {
                const tag = try reader.takeInt(info.tag_type, .little);
                return try std.meta.intToEnum(T, tag);
            },
            .@"union" => |info| switch (try read(reader, info.tag_type.?)) {
                inline else => |tag| {
                    const Variant = @TypeOf(@field(@as(T, undefined), @tagName(tag)));
                    return @unionInit(T, @tagName(tag), try read(fba, reader, Variant));
                },
            },
            .@"struct" => |info| {
                var value: T = undefined;
                inline for (info.fields) |f| @field(value, f.name) = try read(fba, reader, f.type);
                return value;
            },
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }

    fn write(writer: *std.Io.Writer, value: anytype) !void {
        const T = @TypeOf(value);
        if (@hasDecl(T, "bincodeWrite")) return value.bincodeWrite(writer);
        switch (@typeInfo(T)) {
            .int => try writer.writeInt(T, value, .little),
            .optional => {
                try writer.writeByte(@intFromBool(value != null));
                if (value) |v| try write(writer, v);
            },
            .array => |info| {
                comptime std.debug.assert(@typeInfo(info.child) == .int);
                try writer.writeAll(std.mem.asBytes(&value));
            },
            .@"enum" => try write(writer, @intFromEnum(value)),
            .@"union" => switch (std.meta.activeTag(value)) {
                inline else => |tag| {
                    try write(writer, tag);
                    try write(writer, @field(value, @tagName(tag)));
                },
            },
            .@"struct" => |info| {
                inline for (info.fields) |f| try write(writer, @field(value, f.name));
            },
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }
};

fn VarInt(comptime T: type) type {
    return struct {
        value: T,

        pub fn bincodeRead(_: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
            return .{ .value = try reader.takeLeb128(T) };
        }

        pub fn bincodeWrite(self: *const @This(), writer: *std.Io.Writer) !void {
            try writer.writeLeb128(self.value);
        }
    };
}

fn Vec(comptime T: type) type {
    return struct {
        items: []const T,

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
            const n = try reader.takeInt(u64, .little);
            const slice = try fba.allocator().alloc(T, n);
            if (@typeInfo(T) == .int) {
                try reader.readSliceAll(std.mem.sliceAsBytes(slice));
            } else {
                for (slice) |*v| v.* = try bincode.read(fba, reader, T);
            }
            return .{ .items = slice };
        }

        pub fn bincodeWrite(self: *const @This(), writer: *std.Io.Writer) !void {
            try writer.writeInt(u64, self.items.len, .little);
            if (@typeInfo(T) == .int) {
                try writer.writeAll(std.mem.sliceAsBytes(self.items));
            } else {
                for (self.items) |v| try bincode.write(writer, v);
            }
        }
    };
}

fn ShortVec(comptime T: type) type {
    return struct {
        items: []const T,

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
            const n = try bincode.read(fba, reader, VarInt(u16));
            const slice = try fba.allocator().alloc(T, n.value);
            if (@typeInfo(T) == .int) {
                try reader.readSliceAll(std.mem.sliceAsBytes(slice));
            } else {
                for (slice) |*v| v.* = try bincode.read(fba, reader, T);
            }
            return .{ .items = slice };
        }

        pub fn bincodeWrite(self: *const @This(), writer: *std.Io.Writer) !void {
            try bincode.write(writer, VarInt(u16){ .value = @intCast(self.items.len) });
            if (@typeInfo(T) == .int) {
                try writer.writeAll(std.mem.sliceAsBytes(self.items));
            } else {
                for (self.items) |v| try bincode.write(writer, v);
            }
        }
    };
}

fn BitVec(comptime T: type) type {
    return struct {
        words: []T,
        capacity: u64,

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
            const maybe_vec = try bincode.read(fba, reader, ?Vec(T));
            const capacity = try reader.takeInt(u64, .little);

            const words: []T = if (maybe_vec) |vec| @constCast(vec.items) else &.{};
            if (capacity > words.len * @sizeOf(T)) return error.InvalidBitCapacity;
            return .{ .words = words, .capacity = capacity };
        }

        pub fn bincodeWrite(self: *const @This(), writer: *std.Io.Writer) !void {
            const maybe_vec: ?Vec(T) =
                if (self.words.len > 0) Vec(T){ .items = self.words } else null;
            try bincode.write(writer, maybe_vec);
            try writer.writeInt(u64, self.capacity, .little);
        }

        pub fn get(self: *const @This(), bit: usize) u1 {
            const words = self.words orelse return 0;
            return @truncate(words.items[bit / @sizeOf(T)] >> @intCast(bit % @sizeOf(T)));
        }

        pub fn set(self: *@This(), bit: usize) u1 {
            const words = self.words orelse return 0;
            const mask = @as(T, 1) << @intCast(bit % @sizeOf(T));
            const word = &words.items[bit / @sizeOf(T)];
            defer word.* |= mask;
            return @intFromBool(word & mask > 0);
        }
    };
}

const BloomFilter = struct {
    keys: Vec(u64),
    bits: BitVec(u64),
    bits_set: u64,

    fn getBitPos(self: *const BloomFilter, key: u64, bytes: []const u8) u64 {
        var h = std.hash.Fnv1a_64{ .value = key };
        h.update(bytes);
        return h.final() % self.bits.capacity;
    }

    fn add(self: *BloomFilter, bytes: []const u8) void {
        for (self.keys.items) |key| {
            const pos = self.getBitPos(key, bytes);
            self.bits_set += self.bits.set(pos);
        }
    }

    fn contains(self: *const BloomFilter, bytes: []const u8) bool {
        for (self.keys.items) |key| {
            const pos = self.getBitPos(key, bytes);
            if (self.bits.get(pos) == 0) return false;
        }
        return true;
    }
};

const GossipMessage = union(enum(u32)) {
    pull_request: struct {
        ignoring: BloomFilter,
        mask: u64,
        mask_bits: u32,
        contact_info: GossipValue,
    },
    pull_response: struct {
        from: Pubkey,
        values: Vec(GossipValue),
    },
    push_message: struct {
        from: Pubkey,
        values: Vec(GossipValue),
    },
    prune_message: struct {
        from: Pubkey,
        data: struct {
            receiver: Pubkey,
            filter_out: Vec(Pubkey),
            signature: Signature,
            sender: Pubkey,
            wallclock: u64,
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

const GossipValue = struct {
    signature: Signature,
    data: GossipData,
};

const GossipData = union(enum(u32)) {
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
        wallclock: u64,
        shred_version: u16,
    },
    vote: struct {
        index: u8,
        from: Pubkey,
        transaction: struct {
            signatures: ShortVec(Signature),
            message: struct {
                num_signatures: u8,
                num_readonly_signed: u8,
                num_readonly_unsigned: u8,
                accounts: ShortVec(Pubkey),
                recent_blockhash: Hash,
                instructions: ShortVec(struct {
                    program_id: u8,
                    accounts: ShortVec(u8),
                    data: ShortVec(u8),
                }),
            },
        },
        wallclock: u64,
    },
    lowest_slot: struct {
        index: u8,
        from: Pubkey,
        _root: Slot, // deprecated
        lowest: Slot,
        _slots: Vec(Slot), // deprecated
        _stashes: Vec(struct { // deprecated
            first_slot: Slot,
            compression: enum(u32) {
                uncompressed,
                gzip,
                bzip2,
            },
            bytes: Vec(u8),
        }),
        wallclock: u64,
    },
    legacy_snapshot_hashes: AccountHashes,
    account_hashes: AccountHashes,
    epoch_slots: struct {
        index: u8,
        from: Pubkey,
        slots: Vec(union(enum(u32)) {
            flate2: struct {
                first_slot: Slot,
                num_slots: u64,
                compressed: Vec(u8),
            },
            uncompressed: struct {
                first_slot: Slot,
                num_slots: u64,
                slots: BitVec(u8),
            },
        }),
        wallclock: u64,
    },
    legacy_version: struct {
        from: Pubkey,
        wallclock: u64,
        version: Version,
    },
    version: struct {
        from: Pubkey,
        wallclock: u64,
        version: Version,
        feature_set: u32,
    },
    node_instance: struct {
        from: Pubkey,
        wallclock: u64,
        created: u64,
        token: u64,
    },
    duplicate_shred: struct {
        index: u16,
        from: Pubkey,
        wallclock: u64,
        slot: Slot,
        _unused: u32,
        _shred_type: enum(u8) {
            data = 0b10100101,
            code = 0b01011010,
        },
        num_chunks: u8,
        chunk_idx: u8,
        chunk: Vec(u8),
    },
    snapshot_hashes: struct {
        from: Pubkey,
        full: SlotAndHash,
        incremental: Vec(SlotAndHash),
        wallclock: u64,
    },
    contact_info: struct {
        from: Pubkey,
        wallclock: VarInt(u64),
        created: u64,
        shred_version: u16,
        major: VarInt(u16),
        minor: VarInt(u16),
        patch: VarInt(u16),
        commit: u32,
        feature_set: u32,
        client_id: VarInt(u16),
        ips: ShortVec(union(enum(u32)) {
            v4: [4]u8,
            v6: [16]u8,
        }),
        sockets: ShortVec(SocketEntry),
        extensions: ShortVec(struct {
            type: u8,
            bytes: ShortVec(u8),
        }),
    },
    restart_last_voted_fork: struct {
        from: Pubkey,
        wallclock: u64,
        offsets: Vec(union(enum(u32)) {
            rle: Vec(VarInt(u16)),
            raw: BitVec(u8),
        }),
        last_voted: SlotAndHash,
        shred_version: u16,
    },
    restart_heaviest_fork: struct {
        from: Pubkey,
        wallclock: u16,
        last_slot: SlotAndHash,
        observed_stake: u64,
        shred_version: u16,
    },

    const SocketKey = enum(u8) {
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
        alpenglow,
        _,
    };

    const SocketEntry = struct {
        key: SocketKey,
        ip_idx: u8,
        port_offset: VarInt(u16),
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
        slot_hashes: Vec(SlotAndHash),
        wallclock: u64,
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
};
