//! An implmentation of a gossip protocol instance. It uses the provided entrypoints and identity to send/recv messages,
//! ping other nodes, and participate in the cluster to share around GossipValues.

const std = @import("std");
const lib = @import("../lib.zig");
const tel = lib.telemetry;

const assert = std.debug.assert;

const Packet = lib.net.Packet;

const Signature = lib.solana.Signature;
const Pubkey = lib.solana.Pubkey;
const Hash = lib.solana.Hash;
const SlotAndHash = lib.solana.SlotAndHash;

const bincode = lib.solana.bincode;
const GossipMessage = lib.solana.gossip.GossipMessage;
const GossipData = lib.solana.gossip.GossipData;
const GossipValue = lib.solana.gossip.GossipValue;
const ContactInfo = lib.solana.gossip.ContactInfo;
const BloomFilter = lib.solana.gossip.BloomFilter;

pub fn GossipNode(comptime Effects: type) type {
    lib.util.assertInterface(Effects, struct {
        /// Prepare a packet to be written out.
        /// May be called multiple times before `flushWrittenPackets`.
        pub fn writePacket(self: Effects) *Packet {
            _ = .{self};
            return undefined;
        }

        /// Writes out any packets prepared with calls to `writePacket`, invalidating them from the caller.
        pub fn flushWrittenPackets(self: Effects) void {
            _ = .{self};
            return undefined;
        }

        /// Returns the node identity used for signatures
        pub fn getIdentity(self: Effects) Pubkey {
            _ = .{self};
            return undefined;
        }

        /// Signs gossip messages using the node identity
        pub fn sign(self: Effects, msg: []const u8) Signature {
            _ = .{ self, msg };
            return undefined;
        }

        /// Notifies caller that a snapshot was discovered at an address
        pub fn onSnapshot(self: Effects, slot_hash: SlotAndHash, rpc_addr: std.net.Address) void {
            _ = .{ self, slot_hash, rpc_addr };
            return undefined;
        }
    });

    return struct {
        table: Table,
        peers: Peers,
        expired: Expired,

        push_buf: PushBuf,
        push_alloc_buf: PushAllocBuf,
        filter_set: *FilterSet,
        push_active_set: PushActiveSet,
        signed_contact: GossipValue,
        ping_window: PingWindow,

        config: Config,
        created: u64,
        prng: std.Random.DefaultPrng,

        ping_timeout: u64 = 0,
        push_timeout: u64 = 0,
        pull_timeout: u64 = 0,
        no_peers_timeout: u64 = 0,

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

        const Self = @This();
        const Key = struct {
            from: Pubkey,
            tag: std.meta.Tag(GossipData),
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
                    const since = @as(u64, self.last_ping.count_since_pong) *
                        ACTIVE_PONG_THRESHOLD_MS;
                    return self.last_ping.wallclock -| since;
                };
            }
        };

        // Static memory for which to create a BloomFilter from.
        const BlockBloomFilter = struct {
            keys: [MAX_BLOOM_KEYS]u64,
            words: [MAX_BLOOM_BYTES / 8]u64,

            fn init(prng: std.Random) BlockBloomFilter {
                var keys: [MAX_BLOOM_KEYS]u64 = undefined;
                for (&keys) |*key| key.* = prng.int(u64);
                return .{ .keys = keys, .words = @splat(0) };
            }

            fn asBloomFilter(
                self: *BlockBloomFilter,
                num_keys: ?usize,
                num_bits: ?usize,
            ) BloomFilter {
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
                const x = @as(u64, 1.0) - @exp(@log(false_rate) / max_keys);
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

        // Optimization to cache Ping/Pong computes
        const PingWindow = struct {
            new: struct { token: [32]u8, hash: Hash, signature: Signature },
            old: struct { hash: Hash },

            fn refresh(self: *PingWindow, rng: std.Random, effects: Effects) void {
                self.old = .{ .hash = self.new.hash };
                rng.bytes(&self.new.token);
                self.new.hash = Hash.initMany(&.{ PING_PONG_PREFIX, &self.new.token });
                self.new.signature = effects.sign(&self.new.token);
            }

            fn contains(self: *const PingWindow, pong_hash: *const Hash) bool {
                return self.new.hash.eql(pong_hash) or self.old.hash.eql(pong_hash);
            }
        };

        pub const Config = struct {
            effects: Effects,
            shred_version: u16,
            socket_map: lib.solana.gossip.SocketMap,
            entrypoints: []const std.net.Address,
        };

        pub fn init(fba: *std.heap.FixedBufferAllocator, now: u64, config: Config) !Self {
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

            var prng = std.Random.DefaultPrng.init(0);

            var ping_window = std.mem.zeroes(PingWindow);
            ping_window.refresh(prng.random(), config.effects);

            const signed_contact = try signData(now, config.effects, .{ .contact_info = .{
                .from = config.effects.getIdentity(),
                .wallclock = .{ .value = now },
                .created = now,
                .shred_version = config.shred_version,
                .major = .{ .value = 0 },
                .minor = .{ .value = 0 },
                .patch = .{ .value = 0 },
                .commit = 0,
                .feature_set = 0,
                .client_id = .{ .value = 0 },
                .socket_map = config.socket_map,
                .extensions = .{ .items = &.{} },
            } });

            return .{
                .table = table,
                .peers = peers,
                .expired = expired,
                .push_buf = push_buf,
                .push_alloc_buf = push_alloc_buf,
                .filter_set = filter_set,
                .push_active_set = push_active_set,
                .ping_window = ping_window,
                .signed_contact = signed_contact,
                .prng = prng,
                .config = config,
                .created = now,
            };
        }

        pub fn poll(self: *Self, logger: tel.Logger("poll"), now: u64) !void {
            if (self.pull_timeout <= now) {
                self.pull_timeout = now + PULL_INTERVAL_MS;
                try self.sendPullRequests(.from(logger), now);
            }

            if (self.push_timeout <= now) {
                self.push_timeout = now + PUSH_INTERVAL_MS;
                try self.updatePushSet(.from(logger), now);
            }

            if (self.ping_timeout <= now) {
                self.ping_timeout = now + PING_INTERVAL_MS;
                try self.updatePeers(now);
            }
        }

        pub fn processPacket(
            self: *Self,
            logger: tel.Logger("processPacket"),
            now: u64,
            packet: *const Packet,
        ) void {
            var msg_buf: [16 * 1024]u8 = undefined;
            var msg_fba = std.heap.FixedBufferAllocator.init(&msg_buf);
            var msg_reader: std.Io.Reader = .fixed(packet.data[0..packet.size]);
            const msg = bincode.read(&msg_fba, &msg_reader, GossipMessage) catch |e| {
                logger.err().logf(
                    "invalid msg from ({f}, size={}): {}",
                    .{ packet.addr, packet.size, e },
                );
                return;
            };

            self.processMessage(.from(logger), now, packet.addr, msg) catch |e| {
                logger.err().logf(
                    "failed to process msg ({f}, {s}) {}",
                    .{ packet.addr, @tagName(msg), e },
                );
                return;
            };
        }

        fn processMessage(
            self: *Self,
            logger: tel.Logger("processMessage"),
            now: u64,
            addr: std.net.Address,
            msg: GossipMessage,
        ) !void {
            switch (msg) {
                .pull_request => |pr| {
                    const from, const shred_version = switch (pr.contact_info.data) {
                        .contact_info => |v| .{ v.from, v.shred_version },
                        else => return error.InvalidPullRequestContactInfo,
                    };

                    // Unverified peers must respond to a ping first.
                    const peer = try self.getOrTrackPeer(now, shred_version, addr, from) orelse
                        return error.PullRequestFromUnverifiedPeer;

                    // Update the ContactInfo
                    _ = try self.insertValue(.from(logger), now, .pull, pr.contact_info);

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
                    // PullResponse should only be returned from a peer that we couldve sent it to.
                    const peer = self.peers.getPtr(pr.from) orelse
                        return error.PullResponseFromUntrackedPeer;
                    const last_pong = peer.last_pong orelse
                        return error.PullResponseFromUnverifiedPeer;

                    // TODO: figure out what the correct cutoff is here.
                    //
                    // *1 for when selected during PullRequest. another *1 for recv window after that.
                    // if (last_pong <= now -| (ACTIVE_PONG_THRESHOLD_MS * 2))
                    //     return error.PullResponseFromExpiredPeer;
                    _ = last_pong;

                    for (pr.values.items) |value| {
                        _ = try self.insertValue(.from(logger), now, .pull, value);
                    }
                },
                .push_message => |push| {
                    // missing std.BoundedArray :(
                    var prune_buf: [64]Pubkey = undefined;
                    var prune_len: usize = 0;

                    for (push.values.items) |value| {
                        const key, const duplicates =
                            (try self.insertValue(.from(logger), now, .push, value)) orelse continue;

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
                        const prunes: bincode.Vec(Pubkey) = .{ .items = prune_buf[0..prune_len] };

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
                                .signature = self.sign(sign_writer.buffered()),
                                .destination = push.from,
                                .wallclock = now,
                            },
                        } });
                    }

                    // Push fanout.
                    try self.sendPushMessages();
                },
                .prune_message => |prune| {
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
                        .prefix = bincode.Vec(u8){ .items = PRUNE_PREFIX },
                        .pubkey = prune.data.pubkey,
                        .prunes = prune.data.prunes,
                        .destination = prune.data.destination,
                        .wallclock = prune.data.wallclock,
                    });

                    // PruneData can be signed with or without prefix...
                    prune.data.signature.verify(&prune.from, sign_writer.buffered()) catch {
                        sign_writer = .fixed(&sign_buf);
                        try bincode.write(&sign_writer, .{
                            .pubkey = prune.data.pubkey,
                            .prunes = prune.data.prunes,
                            .destination = prune.data.destination,
                            .wallclock = prune.data.wallclock,
                        });
                        prune.data.signature.verify(&prune.from, sign_writer.buffered()) catch {
                            return error.InvalidPruneSignature;
                        };
                    };

                    var bloom_filter = peer.ignoring.asBloomFilter(null, null);
                    for (prune.data.prunes.items) |*pubkey| {
                        bloom_filter.add(&pubkey.data);
                    }
                },
                .ping_message => |ping| {
                    ping.signature.verify(&ping.from, &ping.token) catch {
                        logger.err().logf(
                            "invalid Ping signature from {f}:{f}",
                            .{ ping.from, addr },
                        );
                        return;
                    };

                    const hash = Hash.initMany(&.{ PING_PONG_PREFIX, &ping.token });
                    try self.sendMessage(addr, .{ .pong_message = .{
                        .from = self.identity(),
                        .hash = hash,
                        .signature = self.sign(&hash.data),
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
                    // If not a hash in window (prev, current), not worth verifying the signature either
                    if (!self.ping_window.contains(&pong.hash)) {
                        logger.err().logf(
                            "invalid Pong hash from {f}:{f}",
                            .{ pong.from, addr },
                        );
                        return;
                    }

                    pong.signature.verify(&pong.from, &pong.hash.data) catch {
                        logger.err().logf(
                            "invalid Pong signature from {f}:{f}",
                            .{ pong.from, addr },
                        );
                        return;
                    };

                    const peer = self.peers.getPtr(pong.from) orelse {
                        logger.err().logf(
                            "pong from untracked peer {f}:{f}",
                            .{ pong.from, addr },
                        );
                        return;
                    };

                    peer.last_pong = now;
                    peer.last_ping.count_since_pong = 0;
                },
            }
        }

        fn updatePeers(self: *Self, now: u64) !void {
            // Update the ping tokens
            self.ping_window.refresh(self.prng.random(), self.config.effects);

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

        fn updatePushSet(self: *Self, logger: tel.Logger("updatePushSet"), now: u64) !void {
            // refresh what nodes we will be sending push messages to for the near future.
            self.refreshPushActiveSet(now);

            // Re-sign our contact info & update it to be pushed to active set.
            self.signed_contact = try signData(now, self.config.effects, self.signed_contact.data);
            try self.insertSigned(.from(logger), now, self.signed_contact);

            // Send out any queued values as push messages to active set.
            try self.sendPushMessages();
        }

        fn refreshPushActiveSet(self: *Self, now: u64) void {
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

                    // Passes the ping check
                    if (peer.last_pong == null)
                        continue;

                    // matching shred_version
                    if (peer.shred_version != self.config.shred_version)
                        continue;

                    // active-enough ContactInfo
                    const ci_key: Key = .{ .from = from, .tag = .contact_info, .index = 0 };
                    const ci = self.table.getPtr(ci_key) orelse continue;
                    if (ci.last_updated <= now -| ACTIVE_VALUE_THRESHOLD_MS)
                        continue;

                    self.push_active_set.appendAssumeCapacity(from);
                    if (self.push_active_set.items.len == self.push_active_set.capacity) break;
                }
            }
        }

        fn sendPushMessages(self: *Self) !void {
            // Consume pushed keys.
            const pushed_keys = self.push_buf.keys();
            if (pushed_keys.len == 0) return;
            defer self.push_buf.clearRetainingCapacity();

            // No active_set peers. Try to send PushMessages to entrypoints to get us into the cluster.
            if (self.push_active_set.items.len == 0) {
                for (self.config.entrypoints) |entry_addr| {
                    try self.sendPushMessagesTo(entry_addr, pushed_keys, null);
                }
                return;
            }

            self.push_alloc_buf.clearRetainingCapacity();
            for (self.push_active_set.items) |pubkey| {
                const peer = self.peers.getPtr(pubkey) orelse continue;
                const ignored = peer.ignoring.asBloomFilter(null, null);
                try self.sendPushMessagesTo(peer.addr, pushed_keys, &ignored);
            }
        }

        fn sendPushMessagesTo(
            self: *Self,
            addr: std.net.Address,
            pushed_keys: []const Key,
            maybe_ignore_filter: ?*const BloomFilter,
        ) !void {
            var value_buf: [PUSH_BUFFER_MAX]GossipValue = undefined;
            var values: std.ArrayListUnmanaged(GossipValue) = .initBuffer(&value_buf);
            assert(pushed_keys.len <= value_buf.len);

            var packet_size: usize = 4 + 32 + 8;
            self.push_alloc_buf.clearRetainingCapacity();
            for (pushed_keys) |key| {
                if (maybe_ignore_filter) |ignored| {
                    if (ignored.contains(&key.from.data)) continue;
                }

                // Key may have been removed from the table in the mean time: that's fine.
                const v = self.table.getPtr(key) orelse continue;

                // Would overflow push message. Send one out with whats collected so far.
                if (packet_size + v.size > Packet.len) {
                    try self.sendMessage(addr, .{ .push_message = .{
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
                const value = try bincode.read(&fba, &reader, GossipValue);
                values.appendAssumeCapacity(value);
            }

            // Send out remaining push message.
            if (values.items.len > 0) {
                try self.sendMessage(addr, .{ .push_message = .{
                    .from = self.identity(),
                    .values = .{ .items = values.items },
                } });
            }
        }

        fn sendPullRequests(self: *Self, logger: tel.Logger("sendPullRequests"), now: u64) !void {
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
                        .contact_info = self.signed_contact,
                    } });
                    i += 1;
                    if (i == bloom_filters.items.len) break;
                }
            }

            // Check if there were no peers & send to entrypoints (rate limited).
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
                    logger.debug().logf("No peers...", .{});

                    const mask =
                        (@as(u65, 0) << (@as(u7, 64) - mask_bits)) | (~@as(u64, 0) >> mask_bits);

                    for (self.config.entrypoints) |entry_addr| {
                        try self.sendMessage(entry_addr, .{ .pull_request = .{
                            .ignoring = bloom_filters.items[0],
                            .mask = @intCast(mask),
                            .mask_bits = mask_bits,
                            .contact_info = self.signed_contact,
                        } });
                    }
                }
            }
        }

        fn signData(now: u64, effects: Effects, data_: GossipData) !GossipValue {
            var data = data_;
            switch (std.meta.activeTag(data)) {
                .contact_info => data.contact_info.wallclock = .{ .value = now },
                inline .vote,
                .lowest_slot,
                .epoch_slots,
                .duplicate_shred,
                .snapshot_hashes,
                => |tag| {
                    @field(data, @tagName(tag)).wallclock = now;
                },
                else => return error.SigningDeprecatedValue,
            }

            // TODO: serialize directly table.
            var buf: [Packet.len]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&buf);
            try bincode.write(&writer, data);
            return .{
                .signature = effects.sign(writer.buffered()),
                .data = data,
            };
        }

        /// Sign and insert our own gossip data.
        pub fn insert(
            self: *Self,
            logger: tel.Logger("insert"),
            now: u64,
            data: GossipData,
        ) !void {
            const signed_value = try signData(now, self.config.effects, data);
            return try self.insertSigned(.from(logger), now, signed_value);
        }

        fn insertSigned(
            self: *Self,
            logger: tel.Logger("insertSigned"),
            now: u64,
            value: GossipValue,
        ) !void {
            const key, _ = (try self.insertValue(.from(logger), now, .us, value)) orelse unreachable;
            assert(key.from.equals(&self.identity()));
        }

        fn insertValue(
            self: *Self,
            logger: tel.Logger("insertValue"),
            now: u64,
            caller: enum { us, pull, push },
            value: GossipValue,
        ) !?struct { Key, u8 } {
            // Extract key information from the data.
            var deprecated = false;
            const from: Pubkey, const wallclock: u64, const index: u16 = switch (value.data) {
                inline .vote, .lowest_slot, .epoch_slots, .duplicate_shred => |v| blk: {
                    break :blk .{ v.from, v.wallclock, v.index };
                },
                .contact_info => |ci| blk: {
                    break :blk .{ ci.from, ci.wallclock.value, 0 };
                },
                inline .snapshot_hashes,
                .restart_heaviest_fork,
                .restart_last_voted_fork,
                => |v| blk: {
                    deprecated = value.data != .snapshot_hashes;
                    break :blk .{ v.from, v.wallclock, 0 };
                },
                inline else => |v| {
                    comptime std.debug.assert(@TypeOf(v) == bincode.Deprecated);
                    unreachable;
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
            const key: Key = .{
                .from = from,
                .tag = std.meta.activeTag(value.data),
                .index = index,
            };
            const update_contact = (switch (caller) {
                .us => blk: {
                    assert(!deprecated); // we should not be inserting our own deprecated data
                    break :blk true; // update our own ContactInfo's last_updated
                },
                .push => blk: {
                    if (wallclock <= (now -| STALE_PUSH_THRESHOLD_MS)) return null; // out of range
                    if (wallclock >= (now +| STALE_PUSH_THRESHOLD_MS)) return null; // out of range
                    if (from.equals(&self.identity())) return null; // push sent our own thing to us
                    if (deprecated) break :blk null; // discover, but dont insert
                    break :blk false; // push msgs dont update ContactInfo's last_updated
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
                        if (now <= wallclock +| threshold) break :blk true; // within threshold
                        if (value.data == .contact_info) break :blk false; // Contact outside threshold
                    }

                    // deprecated, or old non-Contact outside threshold
                    break :blk null;
                },
            }) orelse {
                // Record that we've seen it, but don't insert it.
                try self.onDiscoveredValue(.from(logger), now, key, value);
                self.addExpired(now, hash);
                return null;
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

            try self.onDiscoveredValue(.from(logger), now, key, value);

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

        fn onDiscoveredValue(
            self: *Self,
            logger: tel.Logger("onDiscoveredValue"),
            now: u64,
            key: Key,
            value: GossipValue,
        ) !void {
            if (!key.from.equals(&self.identity())) {
                logger.debug().logf("Discovered {f}", .{key});

                var alloc_buf: [16 * 1024]u8 = undefined;
                switch (value.data) {
                    .vote => {}, // TODO: send to consensus service
                    .lowest_slot => {}, // TODO: send to repair service
                    .epoch_slots => {}, // TODO: send to consensus service
                    .duplicate_shred => {}, // TODO: send to shred/consensus service
                    .snapshot_hashes => |s| {
                        // SnapshotHashes arrived after ContactInfo
                        if (try self.getTableValue(
                            .{ .from = s.from, .tag = .contact_info, .index = 0 },
                            &alloc_buf,
                        )) |ci_value| {
                            if (ci_value.data.contact_info.socket_map.get(.rpc)) |rpc_addr| {
                                self.config.effects.onSnapshot(s.full, rpc_addr);
                            }
                        }
                    },
                    .contact_info => |ci| {
                        if (ci.socket_map.get(.gossip)) |addr| {
                            if (try self.getOrTrackPeer(
                                now,
                                ci.shred_version,
                                addr,
                                key.from,
                            )) |peer| {
                                peer.addr = addr;
                                peer.shred_version = ci.shred_version;
                            }
                        }

                        // ContactInfo arrived after SnapshotHashes
                        if (ci.socket_map.get(.rpc)) |rpc_addr| {
                            if (try self.getTableValue(
                                .{ .from = ci.from, .tag = .snapshot_hashes, .index = 0 },
                                &alloc_buf,
                            )) |snapshot_value| {
                                self.config.effects.onSnapshot(
                                    snapshot_value.data.snapshot_hashes.full,
                                    rpc_addr,
                                );
                            }
                        }

                        // TODO: if ci.socket_map.get(.serve_repair): send to repair service
                        // TODO: if ci.socket_map.get(.tpu_vote): send to consensus service
                    },
                    .restart_heaviest_fork, .restart_last_voted_fork => {}, // deprecated
                    inline else => |v| {
                        comptime std.debug.assert(@TypeOf(v) == bincode.Deprecated);
                        unreachable;
                    },
                }
            }
        }

        fn getTableValue(self: *const Self, key: Key, alloc_buf: []u8) !?GossipValue {
            const v = self.table.getPtr(key) orelse return null;
            var fba = std.heap.FixedBufferAllocator.init(alloc_buf);
            var reader: std.Io.Reader = .fixed(v.value[0..v.size]);
            return try bincode.read(&fba, &reader, GossipValue);
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
            const exists, const peer = blk: {
                if (self.peers.count() == self.peers.capacity()) {
                    if (self.peers.getPtr(from)) |peer| {
                        break :blk .{ true, peer };
                    }

                    // findOldest (TODO: replace with accompanied min-heap)
                    var i: usize = 0;
                    for (self.peers.values()[1..], 1..) |*p, j| {
                        if (p.getExpiryWallclock() < self.peers.values()[i].getExpiryWallclock()) {
                            i = j;
                        }
                    }
                    self.peers.swapRemoveAt(i);
                }

                const gop = self.peers.getOrPutAssumeCapacity(from);
                break :blk .{ gop.found_existing, gop.value_ptr };
            };

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

        fn identity(self: *const Self) Pubkey {
            return self.config.effects.getIdentity();
        }

        fn sign(self: *Self, msg: []const u8) Signature {
            return self.config.effects.sign(msg);
        }

        fn sendPing(self: *Self, addr: std.net.Address) !void {
            const latest = &self.ping_window.new;
            return try self.sendMessage(addr, .{ .ping_message = .{
                .from = self.identity(),
                .token = latest.token,
                .signature = latest.signature,
            } });
        }

        fn sendMessage(self: *Self, addr: std.net.Address, msg: GossipMessage) !void {
            const packet: *Packet = self.config.effects.writePacket();
            packet.addr = addr;

            var writer: std.Io.Writer = .fixed(&packet.data);
            try bincode.write(&writer, msg);
            packet.size = @intCast(writer.buffered().len);

            self.config.effects.flushWrittenPackets();
        }
    };
}
