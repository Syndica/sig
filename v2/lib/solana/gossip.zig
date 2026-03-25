const std = @import("std");

const assert = std.debug.assert;

comptime {
    _ = std.testing.refAllDecls(@This());
}

const Packet = @import("../net.zig").Packet;

const Signature = @import("signature.zig").Signature;
const Pubkey = @import("pubkey.zig").Pubkey;
const Slot = @import("../solana.zig").Slot;
const Hash = @import("hash.zig").Hash;
const ClusterType = @import("cluster.zig").ClusterType;

pub const Config = extern struct {
    keypair: @import("keypair.zig").KeyPair,
    cluster_info: ClusterInfo,
    turbine_recv_port: u16,
};

pub fn Gossip(comptime EffectsType: type) type {
    if (!@hasDecl(EffectsType, "sendMessage")) {
        @compileError("effects must define sendMessage(self, addr, msg)");
    }
    if (!@hasDecl(EffectsType, "sign")) {
        @compileError("effects must define sign(self, msg)");
    }

    return struct {
        table: Table,
        peers: Peers,
        expired: Expired,

        push_buf: PushBuf,
        push_alloc_buf: PushAllocBuf,
        filter_set: *FilterSet,
        push_active_set: PushActiveSet,
        ping_token_window: [2][32]u8 = @splat(@splat(0xff)),

        effects: *EffectsType,
        config: EngineConfig,
        prng: std.Random.DefaultPrng = .init(0),

        ping_timeout: u64 = 0,
        push_timeout: u64 = 0,
        pull_timeout: u64 = 0,
        no_peers_timeout: u64 = 0,

        const Self = @This();
        const PULL_INTERVAL_MS = 500;
        const PUSH_INTERVAL_MS = 5 * 1000;
        const PING_INTERVAL_MS = ACTIVE_PONG_THRESHOLD_MS;

        const ACTIVE_VALUE_THRESHOLD_MS = 60 * 1000;
        const ACTIVE_PONG_THRESHOLD_MS = 60 * 1000;
        const STALE_PUSH_THRESHOLD_MS = 15 * 1000;
        const STALE_EXPIRED_THRESHOLD_MS = 20 * 1000;
        const STALE_TABLE_THRESHOLD_MS = 15 * 1000;
        const NO_PEERS_THRESHOLD_MS = 2 * 1000;

        const PUSH_PEER_FANOUT = 9;
        const PUSH_BUFFER_MAX = 64;
        const PINGS_BEFORE_STOP_TRACKING = 8;
        const DUPLICATE_THRESHOLD_UNTIL_PRUNE = 20;

        const PRUNE_PREFIX = "\xffSOLANA_PRUNE_DATA";
        const PING_PONG_PREFIX = "SOLANA_PING_PONG";

        const MAX_BLOOM_KEYS = 8;
        const MAX_BLOOM_BYTES = 928;
        const MAX_BLOOM_FALSE_RATE = 0.1;
        const MAX_PULL_REQUESTS = 256; // must be pow2

        const Key = struct {
            from: Pubkey,
            tag: std.meta.Tag(Data),
            index: u16,

            pub fn format(self: *const Key, writer: *std.Io.Writer) std.Io.Writer.Error!void {
                try writer.print(
                    "Key({s}:{}, from:{f})",
                    .{ @tagName(self.tag), self.index, self.from },
                );
            }
        };

        const Table = std.AutoArrayHashMapUnmanaged(Key, struct {
            hash: Hash,
            wallclock: u64,
            last_updated: u64,
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
            shred_version: ?u16,
            last_ping: struct { wallclock: u64, count_since_pong: u8 },
            last_pong: ?u64,
            ignoring: BlockBloomFilter,

            fn getExpiryWallclock(self: *const Peer) u64 {
                return self.last_pong orelse {
                    const since = @as(u64, self.last_ping.count_since_pong) * ACTIVE_PONG_THRESHOLD_MS;
                    return self.last_ping.wallclock -| since;
                };
            }
        };

        const BlockBloomFilter = struct {
            keys: [MAX_BLOOM_KEYS]u64,
            words: [MAX_BLOOM_BYTES / 8]u64,

            fn init(prng: std.Random) BlockBloomFilter {
                var keys: [MAX_BLOOM_KEYS]u64 = undefined;
                for (&keys) |*key| key.* = prng.int(u64);
                return .{ .keys = keys, .words = @splat(0) };
            }

            fn asBloomFilter(self: *BlockBloomFilter, num_keys: ?usize, num_bits: ?usize) BloomFilter {
                const n_keys = num_keys orelse self.keys.len;
                const n_bits = num_bits orelse self.words.len * 64;
                const num_words = std.math.divCeil(usize, n_bits, 64) catch unreachable;

                var bits_set: u64 = 0;
                for (self.words[0..num_words]) |w| bits_set += @popCount(w);

                return .{
                    .keys = .{ .items = self.keys[0..n_keys] },
                    .bits = .{ .words = self.words[0..num_words], .capacity = n_bits },
                    .bits_set = bits_set,
                };
            }
        };

        const PushAllocBuf = std.ArrayListUnmanaged(u8);
        const PushBuf = std.AutoArrayHashMapUnmanaged(Key, void);
        const PushActiveSet = std.ArrayListUnmanaged(Pubkey);

        const FilterSet = struct {
            blocks: [MAX_PULL_REQUESTS]BlockBloomFilter,

            const max_items: f64 = blk: {
                const max_bits: f64 = MAX_BLOOM_BYTES * 8;
                const max_keys: f64 = MAX_BLOOM_KEYS;
                const false_rate: f64 = MAX_BLOOM_FALSE_RATE;
                const x = @as(f64, 1.0) - @exp(@log(false_rate) / max_keys);
                break :blk @ceil(max_bits / (-max_keys / @log(x)));
            };
            const num_bits: usize = blk: {
                const false_rate: f64 = MAX_BLOOM_FALSE_RATE;
                const denom = @log(@as(f64, 1.0) / std.math.pow(f64, 2.0, std.math.ln2));
                break :blk @intFromFloat(@ceil((max_items * @log(false_rate)) / denom));
            };
            const num_keys: usize = blk: {
                assert(max_items != 0.0);
                const n_bits: f64 = @floatFromInt(num_bits);
                const n = @max(1.0, @round((n_bits / max_items) * std.math.ln2));
                break :blk @intFromFloat(n);
            };
        };

        const EngineConfig = struct {
            identity: Pubkey,
            entry_addr: std.net.Address,
            contact_info: Data,
        };

        pub fn init(fba: *std.heap.FixedBufferAllocator, effects: *EffectsType, config: EngineConfig) !Self {
            assert(config.contact_info == .contact_info);

            var table: Table = .empty;
            try table.ensureTotalCapacity(fba.allocator(), 16384);

            var expired: Expired = .empty;
            try expired.ensureTotalCapacity(fba.allocator(), 8192);

            var peers: Peers = .empty;
            try peers.ensureTotalCapacity(fba.allocator(), 65535);

            var push_buf: PushBuf = .empty;
            try push_buf.ensureTotalCapacity(fba.allocator(), PUSH_BUFFER_MAX);

            var push_alloc_buf: PushAllocBuf = .empty;
            try push_alloc_buf.ensureTotalCapacity(fba.allocator(), PUSH_BUFFER_MAX * (16 * 1024));

            var push_active_set: PushActiveSet = .empty;
            try push_active_set.ensureTotalCapacity(fba.allocator(), PUSH_PEER_FANOUT);

            const filter_set = try fba.allocator().create(FilterSet);

            return .{
                .table = table,
                .peers = peers,
                .expired = expired,
                .push_buf = push_buf,
                .push_alloc_buf = push_alloc_buf,
                .filter_set = filter_set,
                .push_active_set = push_active_set,
                .effects = effects,
                .config = config,
            };
        }

        pub fn poll(self: *Self, now: u64) !void {
            if (self.pull_timeout <= now) {
                self.pull_timeout = now + PULL_INTERVAL_MS;
                try self.sendPullRequests(now);
            }

            if (self.push_timeout <= now) {
                self.push_timeout = now + PUSH_INTERVAL_MS;
                try self.processPushMessages(now);
            }

            if (self.ping_timeout <= now) {
                self.ping_timeout = now + PING_INTERVAL_MS;
                try self.processPings(now);
            }
        }

        pub fn handlePacket(self: *Self, now: u64, packet: *const Packet) void {
            var msg_buf: [16 * 1024]u8 = undefined;
            var msg_fba = std.heap.FixedBufferAllocator.init(&msg_buf);
            var msg_reader: std.Io.Reader = .fixed(packet.data[0..packet.size]);
            const msg = bincode.read(&msg_fba, &msg_reader, Message) catch |e| {
                std.log.err("invalid msg from ({f}, size={}): {}", .{ packet.addr, packet.size, e });
                return;
            };

            self.processMessage(now, packet.addr, msg) catch |e| {
                std.log.err("failed to process msg ({f}, {s}) {}", .{ packet.addr, @tagName(msg), e });
                return;
            };
        }

        fn processMessage(self: *Self, now: u64, addr: std.net.Address, msg: Message) !void {
            switch (msg) {
                .pull_request => |pr| {
                    const from, const shred_version = switch (pr.contact_info.data) {
                        inline .legacy_contact_info, .contact_info => |v| .{ v.from, v.shred_version },
                        else => return error.InvalidPullRequestContactInfo,
                    };

                    std.log.debug("Received PullRequest(from:{f})", .{from});

                    // Unverified peers must respond to a ping first.
                    const peer = try self.getOrTrackPeer(now, shred_version, addr, from) orelse
                        return error.PullRequestFromUnverifiedPeer;

                    // Update the ContactInfo
                    _ = try self.insertValue(now, .pull, pr.contact_info);

                    const mask_bits = std.math.cast(u6, pr.mask_bits) orelse
                        return error.InvalidPullRequestMaskBits;

                    // Find a value that match the PullRequest mask + bloom filter
                    for (self.table.values()) |v| {
                        const lsb_mask = (~@as(u64, 0)) >> mask_bits;
                        const h: u64 = std.mem.readInt(u64, v.hash.data[0..8], .little);
                        if ((h | lsb_mask) != (pr.mask | lsb_mask)) continue;
                        if (pr.ignoring.contains(&v.hash.data)) continue;

                        var found_buf: [16 * 1024]u8 = undefined;
                        var found_fba = std.heap.FixedBufferAllocator.init(&found_buf);
                        var found_reader: std.Io.Reader = .fixed(v.value[0..v.size]);
                        const value = try bincode.read(&found_fba, &found_reader, Value);

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
                    std.log.debug(
                        "Received PullResponse(from:{f}, values:{})",
                        .{ pr.from, pr.values.items.len },
                    );

                    // PullResponse should only be returned from a peer that we couldve sent it to.
                    const peer = self.peers.getPtr(pr.from) orelse
                        return error.PullResponseFromUntrackedPeer;
                    const last_pong = peer.last_pong orelse
                        return error.PullResponseFromUnverifiedPeer;

                    // *1 for when selected during PullRequest. another *1 for recv window after that.
                    if (last_pong <= now -| (ACTIVE_PONG_THRESHOLD_MS * 2))
                        return error.PullResponseFromExpiredPeer;

                    for (pr.values.items) |value| {
                        _ = try self.insertValue(now, .pull, value);
                    }
                },
                .push_message => |push| {
                    std.log.debug(
                        "Received PushMessage(from:{f}, values:{})",
                        .{ push.from, push.values.items.len },
                    );

                    // missing std.BoundedArray :(
                    var prune_buf: [64]Pubkey = undefined;
                    var prune_len: usize = 0;

                    for (push.values.items) |value| {
                        const key, const duplicates =
                            (try self.insertValue(now, .push, value)) orelse continue;

                        // Add to prunes if enough duplicates.
                        if (duplicates >= DUPLICATE_THRESHOLD_UNTIL_PRUNE) {
                            if (prune_len < prune_buf.len) {
                                const exists = for (prune_buf[0..prune_len]) |pk| {
                                    if (pk.equals(&key.from)) break true;
                                } else false;
                                if (!exists) {
                                    prune_buf[prune_len] = key.from;
                                    prune_len += 1;
                                }
                            }
                        }
                    }

                    // Prune duplicates.
                    if (prune_len > 0) blk: {
                        const prunes: Vec(Pubkey) = .{ .items = prune_buf[0..prune_len] };

                        // Dont send back prunes from pushes that arent peers with a ContactInfo.
                        const peer = self.peers.getPtr(push.from) orelse break :blk;
                        const ci_key: Key = .{ .from = push.from, .tag = .contact_info, .index = 0 };
                        if (!self.table.contains(ci_key)) break :blk;

                        var sign_buf: [Packet.len]u8 = undefined;
                        var sign_writer: std.Io.Writer = .fixed(&sign_buf);
                        try bincode.write(&sign_writer, .{
                            .prefix = PRUNE_PREFIX.*,
                            .pubkey = self.identity(),
                            .prunes = prunes,
                            .destination = push.from,
                            .wallclock = now,
                        });

                        try self.sendMessage(peer.addr, .{ .prune_message = .{
                            .from = self.identity(),
                            .data = .{
                                .pubkey = self.identity(),
                                .prunes = prunes,
                                .signature = self.effects.sign(sign_writer.buffered()),
                                .destination = push.from,
                                .wallclock = now,
                            },
                        } });
                    }

                    // Push fanout.
                    try self.sendPushMessages();
                },
                .prune_message => |prune| {
                    std.log.debug(
                        "Received PruneMessage(from:{f}, prunes:{})",
                        .{ prune.from, prune.data.prunes.items.len },
                    );

                    if (!prune.from.equals(&prune.data.pubkey))
                        return error.InvalidPruneDataSender;
                    if (!prune.data.destination.equals(&self.identity()))
                        return error.InvalidPruneDataDestination;

                    const peer = self.peers.getPtr(prune.from) orelse
                        return error.PruneSentByUntrackedPeer;

                    // TODO: verify this with msg directly from the Packet
                    var sign_buf: [Packet.len]u8 = undefined;
                    var sign_writer: std.Io.Writer = .fixed(&sign_buf);
                    try bincode.write(&sign_writer, .{
                        .prefix = PRUNE_PREFIX.*,
                        .pubkey = prune.data.pubkey,
                        .prunes = prune.data.prunes,
                        .destination = prune.data.destination,
                        .wallclock = prune.data.wallclock,
                    });

                    // Prune can be signed with or without prefix...
                    const sign_msg = sign_writer.buffered();
                    prune.data.signature.verify(&prune.from, sign_msg) catch {
                        prune.data.signature.verify(&prune.from, sign_msg[PRUNE_PREFIX.len..]) catch {
                            return error.InvalidPruneSignature;
                        };
                    };

                    var bloom_filter = peer.ignoring.asBloomFilter(null, null);
                    for (prune.data.prunes.items) |*pubkey| {
                        bloom_filter.add(&pubkey.data);
                    }
                },
                .ping_message => |ping| {
                    std.log.debug("Received PingMessage(from:{f} @ {f})", .{ ping.from, addr });

                    ping.signature.verify(&ping.from, &ping.token) catch {
                        std.log.err("invalid Ping signature from {f}:{f}", .{ ping.from, addr });
                        return;
                    };

                    const hash = Hash.initMany(&.{ PING_PONG_PREFIX, &ping.token });
                    try self.sendMessage(addr, .{ .pong_message = .{
                        .from = self.identity(),
                        .hash = hash,
                        .signature = self.effects.sign(&hash.data),
                    } });

                    // NOTE: differs from agave.
                    //
                    // The flow is: send PullRequest to entrypoint. It starts tracking us & sends Ping.
                    // We respond back with Pong & future PullRequests to entrypoint get PullResponses.
                    //
                    // But PullResponses are rejected from untracked peers, so when the entrypoint Pings
                    // us, we need to start having a way to track it as well.
                    _ = try self.getOrTrackPeer(now, null, addr, ping.from);
                },
                .pong_message => |pong| {
                    std.log.debug("Received PongMessage(from:{f} @ {f})", .{ pong.from, addr });

                    // If not a hash in window (prev, current), not worth verifying the signature either
                    const h1 = Hash.initMany(&.{ PING_PONG_PREFIX, &self.ping_token_window[0] });
                    const h2 = Hash.initMany(&.{ PING_PONG_PREFIX, &self.ping_token_window[1] });
                    if (!pong.hash.eql(&h1) and !pong.hash.eql(&h2)) {
                        std.log.err("invalid Pong hash from {f}:{f}", .{ pong.from, addr });
                        return;
                    }

                    pong.signature.verify(&pong.from, &pong.hash.data) catch {
                        std.log.err("invalid Pong signature from {f}:{f}", .{ pong.from, addr });
                        return;
                    };

                    const peer = self.peers.getPtr(pong.from) orelse {
                        std.log.err("pong from untracked peer {f}:{f}", .{ pong.from, addr });
                        return;
                    };

                    peer.last_pong = now;
                    peer.last_ping.count_since_pong = 0;
                },
            }
        }

        fn processPings(self: *Self, now: u64) !void {
            // Update the ping tokens
            self.ping_token_window[0] = self.ping_token_window[1];
            self.prng.fill(&self.ping_token_window[1]);

            // Re-ping or purge unresponsive peers.
            var i: usize = 0;
            while (i < self.peers.count()) {
                const peer = &self.peers.values()[i];

                const wallclock = peer.getExpiryWallclock();
                if (wallclock <= now -| (ACTIVE_PONG_THRESHOLD_MS * PINGS_BEFORE_STOP_TRACKING)) {
                    self.peers.swapRemoveAt(i);
                    continue;
                }

                i += 1;
                if (peer.last_ping.wallclock <= now -| ACTIVE_PONG_THRESHOLD_MS) {
                    try self.sendPing(peer.addr);
                    peer.last_ping.wallclock = now;
                    peer.last_ping.count_since_pong += 1;
                }
            }
        }

        fn processPushMessages(self: *Self, now: u64) !void {
            // Refresh push active set
            self.push_active_set.clearRetainingCapacity();

            // TODO: stake-weighted random sampling
            const peer_keys = self.peers.keys();
            if (peer_keys.len > 0) {
                const peer_values = self.peers.values();
                const rng_start = self.prng.random().uintLessThan(usize, peer_keys.len);
                for (0..peer_keys.len) |i| {
                    const idx = (rng_start +% i) % peer_keys.len;
                    const from = peer_keys[idx];
                    const peer = &peer_values[idx];

                    // TODO: if staked & rng.change(1/16), then skip checks below

                    // Past the ping check
                    if (peer.last_pong == null)
                        continue;

                    // TODO: enable this? matching shred_version
                    // if (peer.shred_version != self.config.contact_info.contact_info.shred_version)
                    //     continue;

                    // TODO: enable this? active-enough ContactInfo
                    // const ci_key: Key = .{ .from = from, .tag = .contact_info, .index = 0 };
                    // const ci = self.table.getPtr(ci_key) orelse continue;
                    // if (ci.last_updated <= now -| ACTIVE_VALUE_THRESHOLD_MS)
                    //     continue;

                    self.push_active_set.appendAssumeCapacity(from);
                    if (self.push_active_set.items.len == self.push_active_set.capacity) break;
                }
            }

            // Add a new instance of our contact info.
            try self.insertOurOwnData(now, self.config.contact_info);

            // Send out push messages
            try self.sendPushMessages();
        }

        fn sendPushMessages(self: *Self) !void {
            // Consume pushed keys.
            const pushed_keys = self.push_buf.keys();
            if (pushed_keys.len == 0) return;
            defer self.push_buf.clearRetainingCapacity();

            self.push_alloc_buf.clearRetainingCapacity();
            for (self.push_active_set.items) |pubkey| {
                const peer = self.peers.getPtr(pubkey) orelse continue;
                const ignored = peer.ignoring.asBloomFilter(null, null);

                var value_buf: [PUSH_BUFFER_MAX]Value = undefined;
                var values: std.ArrayListUnmanaged(Value) = .initBuffer(&value_buf);
                assert(pushed_keys.len <= value_buf.len);

                var packet_size: usize = 4 + 32 + 8;
                for (pushed_keys) |key| {
                    if (ignored.contains(&key.from.data)) continue;
                    const v = self.table.getPtr(key) orelse continue;

                    // Would overflow push message. Send one out with whats collected so far.
                    if (packet_size + v.size > Packet.len) {
                        try self.sendMessage(peer.addr, .{ .push_message = .{
                            .from = self.identity(),
                            .values = .{ .items = values.items },
                        } });
                        self.push_alloc_buf.clearRetainingCapacity();
                        values.clearRetainingCapacity();
                        packet_size = 4 + 32 + 8;
                    }

                    // TODO: no need to actually deserialize here. Ideally, just write the v.values
                    // directly into the PushMessage packet being sent out.
                    const alloc_buf = self.push_alloc_buf.addManyAsSliceAssumeCapacity(16 * 1024);
                    var fba = std.heap.FixedBufferAllocator.init(alloc_buf);
                    var reader: std.Io.Reader = .fixed(v.value[0..v.size]);
                    const value = try bincode.read(&fba, &reader, Value);
                    values.appendAssumeCapacity(value);
                }

                // Send out remaining push message.
                if (values.items.len > 0) {
                    try self.sendMessage(peer.addr, .{ .push_message = .{
                        .from = self.identity(),
                        .values = .{ .items = values.items },
                    } });
                }
            }
        }

        fn sendPullRequests(self: *Self, now: u64) !void {
            const num_items: f64 = @floatFromInt(self.table.count() + self.expired.items.len);
            const mask_bits: u6 = blk: {
                comptime assert(std.math.isPowerOfTwo(MAX_PULL_REQUESTS));
                const n = @max(0, @ceil(@log2(num_items / FilterSet.max_items)));
                break :blk @intFromFloat(@min(n, @ctz(@as(usize, MAX_PULL_REQUESTS))));
            };

            var bloom_filter_buf: [MAX_PULL_REQUESTS]BloomFilter = undefined;
            var bloom_filters: std.ArrayListUnmanaged(BloomFilter) = .initBuffer(&bloom_filter_buf);

            for (0..@as(u64, 1) << mask_bits) |i| {
                const bf_block = &self.filter_set.blocks[i];
                bf_block.* = .init(self.prng.random());

                const bf = bloom_filters.addOneAssumeCapacity();
                bf.* = bf_block.asBloomFilter(FilterSet.num_keys, FilterSet.num_bits);
            }

            // Add the expired hashes to the filters, while also expiring old ones.
            var i: usize = 0;
            while (i < self.expired.items.len) {
                const item = &self.expired.items[i];
                const h: u64 = std.mem.readInt(u64, item.hash.data[0..8], .little);
                const idx: u64 = @intCast(@as(u65, h) >> (@as(u7, 64) - mask_bits));
                bloom_filters.items[idx].add(&item.hash.data);

                if (item.wallclock <= now -| STALE_EXPIRED_THRESHOLD_MS) {
                    _ = self.expired.swapRemove(i);
                } else {
                    i += 1;
                }
            }

            // Add the table hashes into filters, while also moving old/purged ones to `expired`
            i = 0;
            while (i < self.table.count()) {
                const v = &self.table.values()[i];
                const h: u64 = std.mem.readInt(u64, v.hash.data[0..8], .little);
                const idx: u64 = @intCast(@as(u65, h) >> (@as(u7, 64) - mask_bits));
                bloom_filters.items[idx].add(&v.hash.data);

                if (v.wallclock <= now -| STALE_TABLE_THRESHOLD_MS) {
                    self.addExpired(now, v.hash);
                    self.table.swapRemoveAt(i);
                } else {
                    i += 1;
                }
            }

            const signed_ci = try self.signData(now, self.config.contact_info);

            // Select random active peers to send pull requests to.
            i = 0;
            const peer_values = self.peers.values();
            if (peer_values.len > 0) {
                const rng_start = self.prng.random().uintLessThan(usize, peer_values.len);
                for (0..peer_values.len) |offset| {
                    const idx = (rng_start +% offset) % peer_values.len;
                    const peer = &peer_values[idx];

                    const last_pong = peer.last_pong orelse continue;
                    if (last_pong <= now -| ACTIVE_PONG_THRESHOLD_MS) continue;

                    const mask =
                        (@as(u65, i) << (@as(u7, 64) - mask_bits)) | (~@as(u64, 0) >> mask_bits);

                    try self.sendMessage(peer.addr, .{ .pull_request = .{
                        .ignoring = bloom_filters.items[i],
                        .mask = @intCast(mask),
                        .mask_bits = mask_bits,
                        .contact_info = signed_ci,
                    } });
                    i += 1;
                    if (i == bloom_filters.items.len) break;
                }
            }

            // Check if there were no peers & send to entrypoint (rate limited).
            // If reconnect to network, entrypoint will get our ContactInfo & ping us to start tracking.
            // We get pong, start tracking entrypoint, and start getting PullResponses from it in later
            // calls to `sendPullRequests`.
            //
            // Then processPushMessages will eventually trigger, send our ContactInfo, and gets us back
            // into the cluster receiving PushMessages from others.
            //
            // That, or the entrypoint PullResponses will give back other node's ContactInfos, which we
            // will ping in `insertValue`, they pong back, they become peers eligible to send
            // PullRequests to, we get more PullResponses back (of potentially other node ContactInfos)
            // & it repeats.
            if (i == 0) {
                if (self.no_peers_timeout <= now -| NO_PEERS_THRESHOLD_MS) {
                    self.no_peers_timeout = now + NO_PEERS_THRESHOLD_MS;
                    std.log.debug("No peers...", .{});

                    const mask =
                        (@as(u65, i) << (@as(u7, 64) - mask_bits)) | (~@as(u64, 0) >> mask_bits);

                    try self.sendMessage(self.config.entry_addr, .{ .pull_request = .{
                        .ignoring = bloom_filters.items[i],
                        .mask = @intCast(mask),
                        .mask_bits = mask_bits,
                        .contact_info = signed_ci,
                    } });
                }
            }
        }

        fn signData(self: *Self, now: u64, data_: Data) !Value {
            var data = data_;
            switch (std.meta.activeTag(data)) {
                .contact_info => data.contact_info.wallclock = .{ .value = now },
                inline else => |tag| {
                    @field(data, @tagName(tag)).wallclock = now;
                },
            }

            // TODO: serialize directly table.
            var buf: [Packet.len]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&buf);
            try bincode.write(&writer, data);
            return .{
                .signature = self.effects.sign(writer.buffered()),
                .data = data,
            };
        }

        fn insertOurOwnData(self: *Self, now: u64, data: Data) !void {
            const value = try self.signData(now, data);
            const key, _ = (try self.insertValue(now, .us, value)) orelse unreachable;
            assert(key.from.equals(&self.identity()));
        }

        fn insertValue(
            self: *Self,
            now: u64,
            caller: enum { us, pull, push },
            value: Value,
        ) !?struct { Key, u8 } {
            var deprecated = false;

            // Extract key information from the data.
            const from: Pubkey, const wallclock: u64, const index: u16 = switch (value.data) {
                inline .vote, .lowest_slot, .epoch_slots, .duplicate_shred => |v| blk: {
                    break :blk .{ v.from, v.wallclock, v.index };
                },
                inline .snapshot_hashes, .restart_last_voted_fork, .restart_heaviest_fork => |v| blk: {
                    break :blk .{ v.from, v.wallclock, 0 };
                },
                .contact_info => |ci| blk: {
                    break :blk .{ ci.from, ci.wallclock.value, 0 };
                },
                inline else => |v| blk: {
                    deprecated = true;
                    break :blk .{ v.from, v.wallclock, 0 };
                },
            };

            // Serialize the value & validate its signature.
            // TODO: verify directly from packet & memcpy from packet directly into table entry.
            var value_buf: [Packet.len]u8 = undefined;
            var value_writer: std.Io.Writer = .fixed(&value_buf);
            try bincode.write(&value_writer, value);

            const value_bytes = value_writer.buffered();
            try value.signature.verify(&from, value_bytes[64..]);
            const hash = Hash.init(value_bytes);

            // Check wallclock in general
            const key: Key = .{ .from = from, .tag = std.meta.activeTag(value.data), .index = index };
            const update_contact = switch (caller) {
                .us => true,
                .push => blk: {
                    if (wallclock <= (now -| STALE_PUSH_THRESHOLD_MS)) return null;
                    if (wallclock >= (now +| STALE_PUSH_THRESHOLD_MS)) return null;
                    if (from.equals(&self.identity())) return null;
                    break :blk false;
                },
                .pull => blk: {
                    // TODO: currently assumes all nodes are staked.
                    const stake = 1;

                    var threshold: u64 = 15 * 1000;
                    if (from.equals(&self.identity())) {
                        threshold = std.math.maxInt(u64);
                    } else if (stake > 0) {
                        threshold = 432_000 * 400; // slots_in_epoch * slot_ms
                    }

                    if (!deprecated) {
                        if (now <= wallclock +| threshold) break :blk true;
                        if (value.data == .contact_info) break :blk false;
                        try self.onDiscoveredValue(now, key, value);
                    }

                    // Value is deprecated, or too old while not being a ContactInfo.
                    // Record that we've seen it, but dont insert it.
                    self.addExpired(now, hash);
                    return null;
                },
            };

            const exists, const v = blk: {
                if (self.table.count() == self.table.capacity()) {
                    if (self.table.getPtr(key)) |v| break :blk .{ true, v };

                    // findOldest (TODO: replace with accompanied min-heap)
                    var i: usize = 0;
                    for (self.table.values()[1..], 1..) |*v, j| {
                        if (v.wallclock < self.table.values()[i].wallclock) i = j;
                    }
                    self.table.swapRemoveAt(i);
                }

                const gop = self.table.getOrPutAssumeCapacity(key);
                break :blk .{ gop.found_existing, gop.value_ptr };
            };

            try self.onDiscoveredValue(now, key, value);

            if (exists) {
                // duplicate
                if (hash.eql(&v.hash)) {
                    v.duplicates +|= 1;
                    return .{ key, v.duplicates };
                }
                // failed_push
                if (wallclock < v.wallclock or
                    (wallclock == v.wallclock and hash.order(&v.hash) == .lt))
                {
                    self.addExpired(now, hash);
                    return null;
                }
                // evicted
                self.addExpired(now, v.hash);
            }

            v.* = .{
                .hash = hash,
                .wallclock = wallclock,
                .last_updated = now,
                .duplicates = 0,
                .size = @intCast(value_bytes.len),
                .value = undefined,
            };
            @memcpy(v.value[0..v.size], value_bytes);

            // Inserting a new value updates the node's ContactInfo timestamp
            if (update_contact) b: {
                const ci_key: Key = .{ .from = from, .tag = .contact_info, .index = 0 };
                const ci = self.table.getPtr(ci_key) orelse break :b;
                ci.last_updated = now;
            }

            // Add them as push messages
            switch (caller) {
                .pull => {},
                .us, .push => {
                    if (self.push_buf.count() == self.push_buf.capacity())
                        try self.sendPushMessages();
                    self.push_buf.putAssumeCapacity(key, {});
                },
            }

            return .{ key, 0 };
        }

        fn onDiscoveredValue(self: *Self, now: u64, key: Key, value: Value) !void {
            std.log.debug("Discovered {f}", .{key});

            if (!key.from.equals(&self.identity())) {
                switch (value.data) {
                    .vote => {}, // TODO: send to consensus service
                    .lowest_slot => {}, // TODO: send to repair service
                    .epoch_slots => {}, // TODO: send to consensus service
                    .duplicate_shred => {}, // TODO: send to shred/consensus service
                    .snapshot_hashes => {}, // TODO: send to snapshot service
                    .contact_info => |ci| {
                        // read out socket map
                        var map: std.EnumMap(Data.SocketKey, std.net.Address) = .init(.{});
                        var port: u16 = 0;
                        for (ci.sockets.items) |s| {
                            if (s.ip_idx >= ci.ips.items.len)
                                return error.InvalidValue;

                            port += s.port_offset.value;
                            const maybe_addr: ?std.net.Address = switch (ci.ips.items[s.ip_idx]) {
                                inline else => |ip| b: {
                                    if (std.mem.allEqual(u8, &ip, 0)) break :b null;
                                    if (@sizeOf(@TypeOf(ip)) == 4) break :b .initIp4(ip, port);
                                    break :b .initIp6(ip, port, 0, 0);
                                },
                            };

                            const addr = maybe_addr orelse continue;
                            if (map.fetchPut(s.key, addr)) |_| // duplicate SocketKey
                                return error.InvalidValue;
                        }

                        if (map.get(.gossip)) |addr| {
                            if (try self.getOrTrackPeer(now, ci.shred_version, addr, key.from)) |peer| {
                                peer.addr = addr;
                                peer.shred_version = ci.shred_version;
                            }
                        }

                        // TODO: if map.get(.serve_repair): send to repair service
                        // TODO: if map.get(.tpu_vote): send to consensus service
                        // TODO: if map.get(.rpc): send to snapshot service
                    },
                    .restart_last_voted_fork => {}, // TODO: implement wen-restart protocol (SIMD-0046).
                    .restart_heaviest_fork => {}, // TODO: implement wen-restart protocol (SIMD-0046).
                    else => {},
                }
            }
        }

        fn addExpired(self: *Self, now: u64, hash: Hash) void {
            if (self.expired.items.len == self.expired.capacity) {
                // findOldest (TODO: replace with accompanied min-heap)
                var i: usize = 0;
                for (self.expired.items[1..], 1..) |*v, j| {
                    if (v.wallclock < self.expired.items[i].wallclock) i = j;
                }
                _ = self.expired.swapRemove(i);
            }

            self.expired.appendAssumeCapacity(.{ .hash = hash, .wallclock = now });
        }

        fn getOrTrackPeer(
            self: *Self,
            now: u64,
            maybe_shred_version: ?u16,
            addr: std.net.Address,
            from: Pubkey,
        ) !?*Peer {
            const exists, const peer = self.getOrPutPeer(from);
            if (!exists) {
                peer.* = .{
                    .addr = addr,
                    .shred_version = maybe_shred_version,
                    .last_ping = .{ .wallclock = now, .count_since_pong = 0 },
                    .last_pong = null,
                    .ignoring = .init(self.prng.random()),
                };
                try self.sendPing(addr);
                return null;
            }

            return peer;
        }

        fn getOrPutPeer(self: *Self, from: Pubkey) struct { bool, *Peer } {
            if (self.peers.count() == self.peers.capacity()) {
                if (self.peers.getPtr(from)) |peer| {
                    return .{ true, peer };
                }

                // findOldest (TODO: replace with accompanied min-heap)
                var i: usize = 0;
                for (self.peers.values()[1..], 1..) |*p, j| {
                    if (p.getExpiryWallclock() < self.peers.values()[i].getExpiryWallclock()) i = j;
                }
                self.peers.swapRemoveAt(i);
            }

            const gop = self.peers.getOrPutAssumeCapacity(from);
            return .{ gop.found_existing, gop.value_ptr };
        }

        fn identity(self: *const Self) Pubkey {
            return self.config.identity;
        }

        fn sendPing(self: *Self, addr: std.net.Address) !void {
            const token = &self.ping_token_window[1]; // latest ping token.
            return try self.sendMessage(addr, .{ .ping_message = .{
                .from = self.identity(),
                .token = token.*,
                .signature = self.effects.sign(token),
            } });
        }

        fn sendMessage(self: *Self, addr: std.net.Address, msg: Message) !void {
            std.log.debug("Sending {s} to {f}", .{ @tagName(msg), addr });
            try self.effects.sendMessage(addr, msg);
        }
    };
}

pub const ClusterInfo = extern struct {
    public_ip: Address,
    entry_addr: Address,
    shred_version: u16,

    // For std.meta.eql compatibility inside `serviceMap`
    pub const Address = extern struct {
        is_v6: bool,
        ip: [16]u8,
        port: u16,

        pub fn toNetAddress(self: *const Address) std.net.Address {
            if (self.is_v6) return .initIp6(self.ip, self.port, 0, 0);
            return .initIp4(self.ip[0..4].*, self.port);
        }
    };

    pub fn getFromEcho(gossip_port: u16, cluster: ClusterType) !ClusterInfo {
        for (cluster.getEntrypoints()) |entrypoint| {
            const split = std.mem.indexOfScalar(u8, entrypoint, ':') orelse continue;
            const port = std.fmt.parseInt(u16, entrypoint[split + 1 ..], 10) catch continue;

            var addr_buf: [4096]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&addr_buf);
            const addr_list =
                try std.net.getAddressList(fba.allocator(), entrypoint[0..split], port);
            defer addr_list.deinit();

            for (addr_list.addrs) |entry_addr| {
                const socket = try std.posix.socket(
                    entry_addr.any.family,
                    std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC,
                    std.posix.IPPROTO.TCP,
                );
                defer std.posix.close(socket);

                // set timeout of 1s for connect, read, write.
                const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
                try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv);
                std.posix.connect(socket, &entry_addr.any, entry_addr.getOsSockLen()) catch {
                    continue;
                };

                // Used for writing, then for reading.
                var io_buf: [4096]u8 = undefined;

                var stream_writer = std.net.Stream.writer(.{ .handle = socket }, &io_buf);
                const writer = &stream_writer.interface;
                try writer.splatByteAll(0, 4 + (4 * 2) + (4 * 2)); // hdr + tcp ports + udp ports
                try writer.writeByte('\n'); // trailer
                writer.flush() catch continue;

                var stream_reader = std.net.Stream.reader(.{ .handle = socket }, &io_buf);
                const reader: *std.Io.Reader = stream_reader.interface();
                reader.discardAll(@sizeOf(u32)) catch continue;

                const tag = reader.takeInt(u32, .little) catch continue;
                const is_v6 = (std.math.cast(u1, tag) orelse continue) == 1;
                var ip: [16]u8 = @splat(0);
                if (is_v6) {
                    ip = (reader.takeArray(16) catch continue).*;
                } else {
                    ip[0..4].* = (reader.takeArray(4) catch continue).*;
                }

                const shred_version: u16 = switch (reader.takeByte() catch continue) {
                    0 => 0,
                    1 => reader.takeInt(u16, .little) catch continue,
                    else => continue,
                };

                return .{
                    .public_ip = .{
                        .is_v6 = is_v6,
                        .ip = ip,
                        .port = gossip_port,
                    },
                    .entry_addr = .{
                        .is_v6 = entry_addr.any.family == std.posix.AF.INET6,
                        .ip = switch (entry_addr.any.family) {
                            std.posix.AF.INET6 => entry_addr.in6.sa.addr,
                            std.posix.AF.INET => @bitCast([_]u32{ entry_addr.in.sa.addr, 0, 0, 0 }),
                            else => unreachable,
                        },
                        .port = entry_addr.getPort(),
                    },
                    .shred_version = shred_version,
                };
            }
        }
        return error.NoValidEntrypoint;
    }
};

pub const bincode = struct {
    const read_func_overload = "bincodeRead";
    const write_func_overload = "bincodeWrite";

    pub fn read(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader, comptime T: type) !T {
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
            .@"union" => |info| switch (try read(fba, reader, info.tag_type.?)) {
                inline else => |tag| {
                    const Variant = @TypeOf(@field(@as(T, undefined), @tagName(tag)));
                    return @unionInit(T, @tagName(tag), try read(fba, reader, Variant));
                },
            },
            .@"struct" => |info| {
                if (@hasDecl(T, read_func_overload))
                    return @field(T, read_func_overload)(fba, reader);
                var value: T = undefined;
                inline for (info.fields) |f| @field(value, f.name) = try read(fba, reader, f.type);
                return value;
            },
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }

    pub fn write(writer: *std.Io.Writer, value: anytype) !void {
        const T = @TypeOf(value);

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
                if (@hasDecl(T, write_func_overload))
                    return @field(T, write_func_overload)(&value, writer);
                inline for (info.fields) |f| try write(writer, @field(value, f.name));
            },
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }
};

fn VarInt(comptime T: type) type {
    return struct {
        value: T,

        const Self = @This();

        pub fn bincodeRead(_: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            return .{ .value = try reader.takeLeb128(T) };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
            try writer.writeLeb128(self.value);
        }
    };
}

fn Vec(comptime T: type) type {
    return struct {
        items: []const T,

        const Self = @This();

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            const n = try reader.takeInt(u64, .little);
            const slice = try fba.allocator().alloc(T, n);
            if (@typeInfo(T) == .int) {
                try reader.readSliceAll(std.mem.sliceAsBytes(slice));
            } else {
                for (slice) |*v| v.* = try bincode.read(fba, reader, T);
            }
            return .{ .items = slice };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
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

        const Self = @This();

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            const n = try bincode.read(fba, reader, VarInt(u16));
            const slice = try fba.allocator().alloc(T, n.value);
            if (@typeInfo(T) == .int) {
                try reader.readSliceAll(std.mem.sliceAsBytes(slice));
            } else {
                for (slice) |*v| v.* = try bincode.read(fba, reader, T);
            }
            return .{ .items = slice };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
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

        const Self = @This();

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            const maybe_vec = try bincode.read(fba, reader, ?Vec(T));
            const capacity = try reader.takeInt(u64, .little);

            const words: []T = if (maybe_vec) |vec| @constCast(vec.items) else &.{};
            if (capacity > words.len * @bitSizeOf(T)) return error.InvalidBitCapacity;
            return .{ .words = words, .capacity = capacity };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
            const maybe_vec: ?Vec(T) =
                if (self.words.len > 0) Vec(T){ .items = self.words } else null;
            try bincode.write(writer, maybe_vec);
            try writer.writeInt(u64, self.capacity, .little);
        }

        pub fn get(self: *const Self, bit: usize) u1 {
            return @truncate(self.words[bit / @bitSizeOf(T)] >> @intCast(bit % @bitSizeOf(T)));
        }

        pub fn set(self: *Self, bit: usize) u1 {
            const mask = @as(T, 1) << @intCast(bit % @bitSizeOf(T));
            const word = &self.words[bit / @bitSizeOf(T)];
            defer word.* |= mask;
            return @intFromBool(word.* & mask > 0);
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
        if (self.bits.capacity == 0 or self.bits.words.len == 0) return;
        for (self.keys.items) |key| {
            const pos = self.getBitPos(key, bytes);
            self.bits_set += self.bits.set(pos);
        }
    }

    fn contains(self: *const BloomFilter, bytes: []const u8) bool {
        if (self.bits.capacity == 0 or self.bits.words.len == 0) return false;
        for (self.keys.items) |key| {
            const pos = self.getBitPos(key, bytes);
            if (self.bits.get(pos) == 0) return false;
        }
        return true;
    }
};

pub const Message = union(enum(u32)) {
    pull_request: struct {
        ignoring: BloomFilter,
        mask: u64,
        mask_bits: u32,
        contact_info: Value,
    },
    pull_response: struct {
        from: Pubkey,
        values: Vec(Value),
    },
    push_message: struct {
        from: Pubkey,
        values: Vec(Value),
    },
    prune_message: struct {
        from: Pubkey,
        data: struct {
            pubkey: Pubkey,
            prunes: Vec(Pubkey),
            signature: Signature,
            destination: Pubkey,
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

pub const Value = struct {
    signature: Signature,
    data: Data,
};

pub const Data = union(enum(u32)) {
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
        wallclock: u64,
        last_slot: SlotAndHash,
        observed_stake: u64,
        shred_version: u16,
    },

    pub const SocketKey = enum(u8) {
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

    pub const SocketEntry = struct {
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

const Testing = struct {
    const KeyPair = @import("keypair.zig").KeyPair;
    const Engine = Gossip(TestEffects);

    const SentMessage = struct {
        addr: std.net.Address,
        msg: Message,
    };

    const TestEffects = struct {
        allocator: std.mem.Allocator,
        signer: *const KeyPair,
        sent: std.ArrayListUnmanaged(SentMessage) = .empty,

        fn deinit(self: *TestEffects) void {
            for (self.sent.items) |sent| freeDeep(self.allocator, sent.msg);
            self.sent.deinit(self.allocator);
        }

        pub fn sendMessage(self: *TestEffects, addr: std.net.Address, msg: Message) !void {
            try self.sent.append(self.allocator, .{
                .addr = addr,
                .msg = try cloneDeep(Message, self.allocator, msg),
            });
        }

        pub fn sign(self: *TestEffects, msg: []const u8) Signature {
            return self.signer.sign(msg) catch unreachable;
        }
    };

    const Harness = struct {
        allocator: std.mem.Allocator,
        scratch: []u8,
        fba: std.heap.FixedBufferAllocator,
        effects: TestEffects,
        engine: Engine,
        identity: KeyPair,
        now: u64,
        gossip_addr: std.net.Address,
        entry_addr: std.net.Address,
        shred_version: u16,

        fn init(allocator: std.mem.Allocator) !Harness {
            const identity = KeyPair.fromKeyPair(std.crypto.sign.Ed25519.KeyPair.generate());
            const gossip_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8001);
            const entry_addr = std.net.Address.initIp4(.{ 127, 0, 0, 2 }, 8002);
            const shred_version = 1234;
            const now = 1_000_000;

            const scratch = try allocator.alloc(u8, 512 * 1024);
            var fba = std.heap.FixedBufferAllocator.init(scratch);

            var effects: TestEffects = .{
                .allocator = allocator,
                .signer = &identity,
            };
            errdefer effects.deinit();

            const engine = try Engine.init(&fba, &effects, .{
                .identity = identity.pubkey,
                .entry_addr = entry_addr,
                .contact_info = contactInfoData(identity.pubkey, gossip_addr, shred_version, now),
            });

            return .{
                .allocator = allocator,
                .scratch = scratch,
                .fba = fba,
                .effects = effects,
                .engine = engine,
                .identity = identity,
                .now = now,
                .gossip_addr = gossip_addr,
                .entry_addr = entry_addr,
                .shred_version = shred_version,
            };
        }

        fn deinit(self: *Harness) void {
            self.effects.deinit();
            self.allocator.free(self.scratch);
        }

        fn advance(self: *Harness, delta_ms: u64) void {
            self.now += delta_ms;
        }

        fn poll(self: *Harness) !void {
            try self.engine.poll(self.now);
        }

        fn clearSent(self: *Harness) void {
            self.effects.deinit();
            self.effects = .{
                .allocator = self.allocator,
                .signer = &self.identity,
            };
            self.engine.effects = &self.effects;
        }

        fn receivePacket(self: *Harness, addr: std.net.Address, msg: Message) !void {
            var packet: Packet = undefined;
            packet.addr = addr;

            var writer: std.Io.Writer = .fixed(&packet.data);
            try bincode.write(&writer, msg);
            packet.size = @intCast(writer.buffered().len);

            self.engine.handlePacket(self.now, &packet);
        }

        fn expectSentCount(self: *const Harness, expected: usize) !void {
            try std.testing.expectEqual(expected, self.effects.sent.items.len);
        }

        fn expectSent(self: *const Harness, index: usize, addr: std.net.Address, expected: Message) !void {
            const actual = self.effects.sent.items[index];
            try expectDeepEqual(std.net.Address, addr, actual.addr);
            try expectDeepEqual(Message, expected, actual.msg);
        }
    };

    fn contactInfoData(from: Pubkey, gossip_addr: std.net.Address, shred_version: u16, now: u64) Data {
        const ip = switch (gossip_addr.any.family) {
            std.posix.AF.INET => .{ .v4 = gossip_addr.in.sa.addr },
            std.posix.AF.INET6 => .{ .v6 = gossip_addr.in6.sa.addr },
            else => unreachable,
        };

        return .{ .contact_info = .{
            .from = from,
            .wallclock = .{ .value = now },
            .created = now,
            .shred_version = shred_version,
            .major = .{ .value = 0 },
            .minor = .{ .value = 0 },
            .patch = .{ .value = 0 },
            .commit = 0,
            .feature_set = 0,
            .client_id = .{ .value = 0 },
            .ips = .{ .items = &.{ip} },
            .sockets = .{ .items = &.{.{
                .key = .gossip,
                .ip_idx = 0,
                .port_offset = .{ .value = gossip_addr.getPort() },
            }} },
            .extensions = .{ .items = &.{} },
        } };
    }

    fn signedValue(keypair: *const KeyPair, data: Data) !Value {
        var buf: [Packet.len]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        try bincode.write(&writer, data);
        return .{
            .signature = try keypair.sign(writer.buffered()),
            .data = data,
        };
    }

    fn pingMessage(keypair: *const KeyPair, token: [32]u8) !Message {
        return .{ .ping_message = .{
            .from = keypair.pubkey,
            .token = token,
            .signature = try keypair.sign(&token),
        } };
    }

    fn pongMessage(keypair: *const KeyPair, hash: Hash) !Message {
        return .{ .pong_message = .{
            .from = keypair.pubkey,
            .hash = hash,
            .signature = try keypair.sign(&hash.data),
        } };
    }

    fn cloneDeep(comptime T: type, allocator: std.mem.Allocator, value: T) !T {
        switch (@typeInfo(T)) {
            .int, .float, .bool, .@"enum", .array, .vector => return value,
            .optional => {
                if (value) |v| return try cloneDeep(@TypeOf(v), allocator, v);
                return null;
            },
            .pointer => |info| {
                if (info.size != .slice) @compileError("unsupported pointer clone type: " ++ @typeName(T));

                const Child = info.child;
                const out = try allocator.alloc(Child, value.len);
                if (@typeInfo(Child) == .int) {
                    @memcpy(out, value);
                } else {
                    for (value, out) |item, *dest| dest.* = try cloneDeep(Child, allocator, item);
                }
                return out;
            },
            .@"struct" => |info| {
                var out: T = undefined;
                inline for (info.fields) |field| {
                    @field(out, field.name) = try cloneDeep(field.type, allocator, @field(value, field.name));
                }
                return out;
            },
            .@"union" => |_| switch (value) {
                inline else => |payload, tag| {
                    return @unionInit(T, @tagName(tag), try cloneDeep(@TypeOf(payload), allocator, payload));
                },
            },
            else => @compileError("unsupported clone type: " ++ @typeName(T)),
        }
    }

    fn freeDeep(allocator: std.mem.Allocator, value: anytype) void {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .int, .float, .bool, .@"enum", .array, .vector => {},
            .optional => if (value) |v| freeDeep(allocator, v),
            .pointer => |info| {
                if (info.size != .slice) @compileError("unsupported pointer free type: " ++ @typeName(T));

                const Child = info.child;
                if (@typeInfo(Child) != .int) {
                    for (value) |item| freeDeep(allocator, item);
                }
                allocator.free(value);
            },
            .@"struct" => |info| {
                inline for (info.fields) |field| {
                    freeDeep(allocator, @field(value, field.name));
                }
            },
            .@"union" => |_| switch (value) {
                inline else => |payload| freeDeep(allocator, payload),
            },
            else => @compileError("unsupported free type: " ++ @typeName(T)),
        }
    }

    fn expectDeepEqual(comptime T: type, expected: T, actual: T) !void {
        switch (@typeInfo(T)) {
            .int, .float, .bool, .@"enum" => try std.testing.expectEqual(expected, actual),
            .array => |info| {
                inline for (0..info.len) |i| try expectDeepEqual(info.child, expected[i], actual[i]);
            },
            .vector => try std.testing.expectEqual(expected, actual),
            .optional => {
                try std.testing.expectEqual(expected != null, actual != null);
                if (expected) |v| try expectDeepEqual(@TypeOf(v), v, actual.?);
            },
            .pointer => |info| {
                if (info.size != .slice) @compileError("unsupported pointer compare type: " ++ @typeName(T));
                try std.testing.expectEqual(expected.len, actual.len);
                for (expected, actual) |exp_item, act_item| {
                    try expectDeepEqual(info.child, exp_item, act_item);
                }
            },
            .@"struct" => |info| {
                inline for (info.fields) |field| {
                    try expectDeepEqual(field.type, @field(expected, field.name), @field(actual, field.name));
                }
            },
            .@"union" => |_| {
                try std.testing.expectEqual(std.meta.activeTag(expected), std.meta.activeTag(actual));
                switch (expected) {
                    inline else => |payload, tag| {
                        try expectDeepEqual(@TypeOf(payload), payload, @field(actual, @tagName(tag)));
                    },
                }
            },
            else => @compileError("unsupported compare type: " ++ @typeName(T)),
        }
    }
};

test "gossip harness captures ping response" {
    var harness = try Testing.Harness.init(std.testing.allocator);
    defer harness.deinit();

    const peer_addr = std.net.Address.initIp4(.{ 127, 0, 0, 3 }, 9001);
    const peer = Testing.KeyPair.fromKeyPair(std.crypto.sign.Ed25519.KeyPair.generate());
    const token: [32]u8 = @splat(7);

    try harness.receivePacket(peer_addr, try Testing.pingMessage(&peer, token));
    try harness.expectSentCount(2);
    const pong_hash = Hash.initMany(&.{ Testing.Engine.PING_PONG_PREFIX, &token });
    try harness.expectSent(0, peer_addr, .{ .pong_message = .{
        .from = harness.identity.pubkey,
        .hash = pong_hash,
        .signature = harness.identity.sign(&pong_hash.data) catch unreachable,
    } });
}

test "verified peer pull request gets contact info response" {
    var harness = try Testing.Harness.init(std.testing.allocator);
    defer harness.deinit();

    try harness.poll();
    harness.clearSent();

    const peer_addr = std.net.Address.initIp4(.{ 127, 0, 0, 4 }, 9002);
    const peer = Testing.KeyPair.fromKeyPair(std.crypto.sign.Ed25519.KeyPair.generate());

    const peer_ping = try Testing.pingMessage(&peer, @splat(9));
    try harness.receivePacket(peer_addr, peer_ping);
    try harness.expectSentCount(2);

    const ping_hash = Hash.initMany(&.{ Testing.Engine.PING_PONG_PREFIX, &@as([32]u8, @splat(0xff)) });
    try harness.receivePacket(peer_addr, try Testing.pongMessage(&peer, ping_hash));

    harness.clearSent();

    const peer_contact_info = try Testing.signedValue(&peer, Testing.contactInfoData(
        peer.pubkey,
        peer_addr,
        harness.shred_version,
        harness.now,
    ));

    try harness.receivePacket(peer_addr, .{ .pull_request = .{
        .ignoring = .{
            .keys = .{ .items = &.{} },
            .bits = .{ .words = &.{}, .capacity = 0 },
            .bits_set = 0,
        },
        .mask = 0,
        .mask_bits = 0,
        .contact_info = peer_contact_info,
    } });

    const our_contact_info = try Testing.signedValue(
        &harness.identity,
        Testing.contactInfoData(harness.identity.pubkey, harness.gossip_addr, harness.shred_version, harness.now),
    );
    try harness.expectSentCount(1);
    try harness.expectSent(0, peer_addr, .{ .pull_response = .{
        .from = harness.identity.pubkey,
        .values = .{ .items = &.{our_contact_info} },
    } });
}
