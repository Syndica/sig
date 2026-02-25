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

    const gossip_port = 8002;
    const keypair: KeyPair = .generate();
    const entrypoints: []const []const u8 = &.{
        "entrypoint.testnet.solana.com:8001",
        // "entrypoint2.testnet.solana.com:8001",
        // "entrypoint3.testnet.solana.com:8001",
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
                .tcp_ports = @splat(0),
                .udp_ports = .{ 0, 0, 0, 0 },
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
        .major = .{ .value = 0 },
        .minor = .{ .value = 0 },
        .patch = .{ .value = 0 },
        .commit = 0,
        .feature_set = 0,
        .client_id = .{ .value = 0 },
        .ips = .{ .items = &.{ echo.addr } },
        .sockets = .{ .items = &.{ .{ .key = .gossip, .idx = 0, .port_offset = .{ .value = gossip_port } } } },
        .extensions = .{ .items = &.{} },
    };

    // _ = entry_addr;
    const e_addr = entry_addr;

    // _ = entry_addr;
    // const e_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8001);

    try runGossip(gpa, e_addr, keypair, my_contact_info);
}

fn runGossip(
    gpa: std.mem.Allocator,
    entry_addr: std.net.Address,
    keypair: KeyPair,
    my_ci: ContactInfo,
) !void {
    var prng = std.Random.DefaultPrng.init(0);
    
    // Set addr ip to 0 for binding
    const my_sock_addr = try getGossipAddr(.{ .contact_info = my_ci });
    const my_addr: std.net.Address = switch (my_sock_addr) {
        .v4 => |s| .initIp4(@splat(0), s.port),
        .v6 => |s| .initIp6(@splat(0), s.port, 0, 0),
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

    // Gossip data structures
    var table: GossipTable = .{};
    try table.ensureTotalCapacity(gpa, 8192);
    defer table.deinit(gpa);

    var hashes: GossipHashes = .{};
    try hashes.ensureTotalCapacity(gpa, table.capacity());
    defer hashes.deinit(gpa);

    var peers: GossipPeers = .{};
    try peers.ensureTotalCapacity(gpa, max_peers);
    defer peers.deinit(gpa);

    // Initial state
    {
        // add our contact into to table.
        const signed_ci = try signData(keypair, .{ .contact_info = my_ci });
        _ = try tableInsert(&table, &hashes, signed_ci);

        // send out ping so entry responds with pong of their pubkey
        // _ = try sendPing(socket, entry_addr, keypair, prng.random());
        
        try sendGossipMessage(socket, entry_addr, .{ .push_message = .{
            .from = my_ci.from,
            .values = &.{ signed_ci },
        }});

        // try sendGossipMessage(socket, entry_addr, .{ .push_message = .{
        //     .from = my_ci.from,
        //     .values = &.{ try signData(keypair, .{
        //         .version = .{
        //             .from = my_ci.from,
        //             .wallclock = undefined, // set during signData
        //             .version = my_ci.version,
        //             .feature_set = my_ci.feature_set,
        //         } }),
        //     },
        // }});
        // try sendGossipMessage(socket, entry_addr, .{ .push_message = .{
        //     .from = my_ci.from,
        //     .values = &.{ try signData(keypair, .{
        //         .node_instance = .{
        //             .from = my_ci.from,
        //             .wallclock = undefined, // set during signData
        //             .created = my_ci.created,
        //             .token = prng.random().int(u64),
        //         } }), 
        //     },
        // }});
    }
    
    var pull_request_timer: Timestamp = 0;
    var push_message_timer: Timestamp = 0;
    while (true) {
        const now = realtime();

        if (push_message_timer <= now) b: {
            push_message_timer = now + (7 * 1000); // every 7s

            if (peers.count() == 0) {
                std.log.err("No peers..", .{});
                break :b;
            }

            // Send contact info.
            std.log.debug("Sending push contact_info", .{});
            const ci_value = try signData(keypair, .{ .contact_info = my_ci });
            _ = try tableInsert(&table, &hashes, ci_value);
            try sendPushes(socket, &peers, prng.random(), keypair, ci_value);
        }

        if (pull_request_timer <= now) {
            pull_request_timer = now + (2 * 1000); // every 2s

            const num_items = table.count() + hashes.items.len;
            const max_items = comptime blk: {
                const max_keys = 8.0;
                const x = @exp(@log(Bloom.false_rate) / max_keys);
                const n = (-max_keys / @log(@as(f64, 1.0) - x));
                break :blk @ceil(Bloom.max_bloom_bits / n);
            };

            const mask_bits = blk: {
                const x = @max(0, @ceil(@log2(@as(f64, @floatFromInt(num_items)) / max_items)));
                break :blk @as(u6, @intFromFloat(x));
            };
            std.log.debug("Sending pull request: num_items={} mask_bits={}", .{num_items, mask_bits});

            const num_bits = Bloom.numBits(num_items);
            const num_words = Bloom.numWords(num_bits);
            const num_keys = Bloom.numKeys(num_items, num_bits);
            
            var filters: std.ArrayListUnmanaged(struct{
                keys: []u64,
                words: []u64,
            }) = .{};
            defer {
                for (filters.items) |f| {
                    gpa.free(f.keys);
                    gpa.free(f.words);
                }
                filters.deinit(gpa);
            }
            for (0..@as(u64, 1) << mask_bits) |_| {
                const keys = try gpa.alloc(u64, num_keys);
                for (keys) |*k| k.* = prng.random().int(u64);
                const words = try gpa.alloc(u64, num_words);
                @memset(words, 0);
                try filters.append(gpa, .{ .keys = keys, .words = words });
            }

            for (table.values()) |*v| {
                const h = std.mem.readInt(u64, v.hash.data[0..8], .little);
                const i: usize = @intCast(@as(u65, h) >> @intCast(@as(u8, 64) - mask_bits));
                const f = &filters.items[i];
                Bloom.add(f.keys, f.words, &v.hash.data);
            }
            for (hashes.items) |*v| {
                const h = std.mem.readInt(u64, v.hash.data[0..8], .little);
                const i: usize = @intCast(@as(u65, h) >> @intCast(@as(u8, 64) - mask_bits));
                const f = &filters.items[i];
                Bloom.add(f.keys, f.words, &v.hash.data);
            }

            const max_pull_reqs = 256;
            const active_peers = getActivePeers(max_pull_reqs, &peers, my_ci.from, prng.random());
            for (active_peers.constSlice(), 0..) |addr, i| {
                const f = if (i >= filters.items.len) break else &filters.items[i];
                var n_bits: u64 = 0;
                for (f.words) |w| n_bits += @popCount(w);

                const m1 = (@as(u65, i) << @intCast(@as(u8, 64) - mask_bits)) | (~@as(u64, 0) >> mask_bits);
                const mask = std.math.lossyCast(u64, m1);

                try sendGossipMessage(socket, addr, .{ .pull_request = .{
                    .filter = .{
                        .keys = f.keys,
                        .words = .{
                            .bits = f.words,
                            .len = num_bits,
                        },
                        .num_bits = n_bits,
                    },
                    .mask = mask,
                    .mask_bits = mask_bits,
                    .contact_info = try signData(keypair, .{ .contact_info = my_ci }),
                }});
            } 
        }
        
        // Expire old hashes
        {
            var i: usize = 0;
            while (i < hashes.items.len) {
                const h = &hashes.items[i];
                if (h.wallclock <= (now -| (30 * 1000))) {
                    _ = hashes.swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }

        // Expire old table values
        {
            var i: usize = 0;
            while (i < table.count()) {
                const v = &table.values()[i];
                if (v.wallclock <= (now -| (30 * 1000))) {
                    std.log.debug("removing dead table entry: {}", .{table.keys()[i]});
                    pushHash(&hashes, v.hash, now);
                    table.swapRemoveAt(i);
                } else {
                    i += 1;
                }
            }
        }

        // Ping peers & expire old ones
        {
            var i: usize = 0;
            while (i < peers.values().len) {
                const p: *GossipPeer = &peers.values()[i];
                
                const cutoff = now -| (15 * 1000);
                if (@min(p.last_contact, p.last_pong) <= cutoff) {
                    std.log.debug("removing dead peer {}:{}", .{peers.keys()[i], p.addr});
                    peers.swapRemoveAt(i);
                    continue;
                }

                if (p.last_ping.expires <= now) {
                    const token = try sendPing(socket, p.addr, keypair, prng.random());
                    const expires =  // 2s-4s in the future
                        prng.random().intRangeLessThan(u64, now + (2 * 1000), now + (4 * 1000));
                    p.last_ping = .{ .token = token, .expires = expires };
                }

                i += 1;
            }
        }


        var buf: [MTU]u8 = undefined;
        var addr: std.net.Address = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr.in6));
        const n = std.posix.recvfrom(socket, &buf, 0, &addr.any, &addr_len) catch |e| switch (e) {
            error.WouldBlock => continue,
            else => |err| return err,
        };

        std.log.debug("recv:{} addr:{} entry:{}", .{n, addr, entry_addr});
        
        var fbs = std.io.fixedBufferStream(buf[0..n]);
        var alloc_buf: [8192]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
        const msg = bincode.read(fba.allocator(), fbs.reader(), GossipMessage) catch |e| {
            if (@errorReturnTrace()) |t| std.debug.dumpStackTrace(t.*);
            std.log.err("Invalid gossip msg: {}", .{e});
            continue;
        };

        std.log.debug("msg: {}\n", .{std.meta.activeTag(msg)});
        switch (msg) {
            .pull_request => |pr| {
                _ = pr;
            },
            inline .pull_response, .push_message => |add| {
                _ = add;
            },
            .prune_message => |prune| {
                _ = prune;
            },
            .ping_message => |ping| b: {
                ping.signature.verify(ping.from, &ping.token) catch {
                    std.log.err("invalid ping signature", .{});
                    break :b;
                };

                const p = getOrCreatePeer(&peers, ping.from, addr, prng.random(), now);

                const hash = Hash.initMany(&.{ "SOLANA_PING_PONG", &ping.token });
                try sendGossipMessage(socket, p.addr, .{ .pong_message = .{
                    .from = my_ci.from,
                    .hash = hash,
                    .signature = .fromBytes((try keypair.sign(&hash.data, null)).toBytes()),
                }});
            },
            .pong_message => |pong| b: {
                pong.signature.verify(pong.from, &pong.hash.data) catch {
                    std.log.err("invalid pong signature", .{});
                    break :b;
                };

                const p = getOrCreatePeer(&peers, pong.from, addr, prng.random(), now);
                p.last_pong = now;
            },
        }
    }
}

const GossipKey = struct {
    from: Pubkey,
    tag: std.meta.Tag(CrdsData),
    idx: u16, 
};

const GossipHashes = std.ArrayListUnmanaged(struct{ 
    hash: Hash,
    wallclock: Timestamp,
});
const GossipTable = std.AutoArrayHashMapUnmanaged(GossipKey, struct {
    hash: Hash,
    dupes: u8,
    wallclock: Timestamp,
    value: [MTU]u8,
    len: u16,
});

fn tableInsert(
    table: *GossipTable,
    hashes: *GossipHashes,
    value: CrdsValue,
) !struct{ GossipKey, u8 } {
    const tag = std.meta.activeTag(value.data);
    const wallclock: Timestamp, const key: GossipKey = switch (value.data) {
        .contact_info => |ci| .{ ci.wallclock.value, .{ .from = ci.from, .tag = .contact_info, .idx = 0 } },
        inline .vote, .epoch_slots, .duplicate_shred => |v| //
            .{ v.wallclock, .{ .from = v.from, .tag = tag, .idx = v.index } },
        inline else => |v| .{ v.wallclock, .{ .from = v.from, .tag = tag, .idx = 0 } },
    };

    const v, const exists = blk: {
        if (table.count() == table.capacity()) {
            if (table.getPtr(key)) |v| break :blk .{ v, true };
            const i = findOldest(table.values(), "wallclock");
            std.log.debug("evicting table value: {any}", .{table.keys()[i]});
            const v = &table.values()[i];
            pushHash(hashes, v.hash, v.wallclock);
            table.swapRemoveAt(i);
        }
        const gop = table.getOrPutAssumeCapacity(key);
        break :blk .{ gop.value_ptr, gop.found_existing };
    };

    var buf: [MTU]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try bincode.write(fbs.writer(), value);
    const hash = Hash.init(fbs.getWritten());

    if (exists and v.hash.eql(hash)) {
        v.dupes += 1;
        return .{ key, v.dupes };
    }

    if (exists and wallclock < v.wallclock) {
        if (wallclock >= (v.wallclock -| (30 * 1000))) 
            pushHash(hashes, hash, wallclock);
        return error.Expired;
    }

    v.* = .{
        .dupes = 0,
        .hash = hash,
        .wallclock = wallclock,
        .len = @intCast(fbs.getWritten().len),
        .value = undefined,
    };
    @memcpy(v.value[0..v.len], fbs.getWritten());
    return .{ key, v.dupes };
}

fn pushHash(hashes: *GossipHashes, hash: Hash, wallclock: Timestamp) void {
    if (hashes.items.len == hashes.capacity) {
        const j = findOldest(hashes.items, "wallclock");
        _ = hashes.swapRemove(j);
    }
    hashes.appendAssumeCapacity(.{ .hash = hash, .wallclock = wallclock }); // TODO: minheap
}

const max_peers = 65535;
const GossipPeers = std.AutoArrayHashMapUnmanaged(Pubkey, GossipPeer);
const GossipPeer = struct {
    addr: std.net.Address,
    last_ping: struct{ token: [32]u8, expires: Timestamp },
    last_pong: Timestamp,
    last_contact: Timestamp,
    pruned: struct {
        const n_bits = Bloom.numBits(max_peers);
        const n_keys = Bloom.numKeys(max_peers, n_bits);
        keys: [n_keys]u64,
        words: [Bloom.numWords(n_bits)]u64
    },
};

fn findOldest(slice: anytype, comptime ts_field: []const u8) usize {
    var oldest: usize = 0;
    var wallclock: Timestamp = std.math.maxInt(u64);
    for (slice, 0..) |*v, i| {
        const ts: Timestamp = @field(v, ts_field);
        if (ts < wallclock) {
            oldest = i;
            wallclock = ts;
        }
    }
    return oldest;
}

fn getOrCreatePeer(
    peers: *GossipPeers,
    pubkey: Pubkey,
    addr: std.net.Address,
    rng: std.Random,
    now: Timestamp,
) *GossipPeer {
    if (peers.count() == peers.capacity()) {
        if (peers.getPtr(pubkey)) |p| return p;
        const i = findOldest(peers.values(), "last_contact");
        std.log.debug("evicting peer {}:{}", .{peers.keys()[i], peers.values()[i].addr});
        peers.swapRemoveAt(i);
    }

    const gop = peers.getOrPutAssumeCapacity(pubkey);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{
            .addr = addr,
            .last_contact = now,
            .last_ping = .{ .token = @splat(0), .expires = now },
            .last_pong = now,
            .pruned = undefined,
        };
        rng.bytes(std.mem.asBytes(&gop.value_ptr.pruned.keys));
        @memset(&gop.value_ptr.pruned.words, 0);
    }
    return gop.value_ptr;
}

fn sendPushes(
    socket: std.posix.socket_t,
    peers: *const GossipPeers,
    rng: std.Random,
    keypair: KeyPair,
    value: CrdsValue,
) !void {
    const from = switch (value.data) {
        inline else => |v| v.from,
    };
    
    const max_push_fanout = 6;
    const active_peers = getActivePeers(max_push_fanout, peers, from, rng);

    for (active_peers.constSlice()) |addr| {
        try sendGossipMessage(socket, addr, .{ .push_message = .{
            .from = .{ .data = keypair.public_key.bytes },
            .values = &.{ value }, // TODO: batch multiple values per peer based on prunes
        }});
    }
}

fn getActivePeers(
    max: comptime_int,
    peers: *const GossipPeers,
    origin: Pubkey,
    rng: std.Random,
) std.BoundedArray(std.net.Address, max) {
    var active: std.BoundedArray(std.net.Address, max) = .{};
    const all_peers = peers.values();
    if (all_peers.len == 0) return active;

    var i = rng.uintLessThan(usize, all_peers.len);
    for (0..all_peers.len) |_| {
        const peer = &all_peers[i];
        defer i = (i + 1) % all_peers.len;
        if (Bloom.contains(&peer.pruned.keys, &peer.pruned.words, &origin.data)) continue;
        active.append(peer.addr) catch break;
    }
    return active;
}

const Bloom = struct {
    const max_bloom_bits = 928 * 8;
    const false_rate = 0.1;

    fn add(keys: []align(1) u64, words: []align(1) u64, bytes: []const u8) void {
        for (keys) |k| {
            var h = std.hash.Fnv1a_64{ .value = k };
            h.update(bytes);
            const bit = h.final() % (words.len * 8);
            words[bit / 64] |= @as(u64, 1) << @intCast(bit % 64);
        }
    }

    fn contains(keys: []align(1) const u64, words: []align(1) const u64, bytes: []const u8) bool {
        for (keys) |k| {
            var h = std.hash.Fnv1a_64{ .value = k };
            h.update(bytes);
            const bit = h.final() % (words.len * 8);
            if ((words[bit / 64] >> @intCast(bit % 64)) & 1 == 0) return false;
        }
        return true;
    }

    fn numWords(num_bits: u64) u64 {
        const i = num_bits;
        const n = std.math.ceilPowerOfTwo(u64, @max(64, i)) catch unreachable;
        return std.math.divCeil(u64, n, 64) catch unreachable;
    }

    fn numBits(num_items: u64) u64 {
        const d = @log(@as(f64, 1) / std.math.pow(f64, 2, @log(@as(f64, 2))));
        const n = std.math.ceil((@as(f64, @floatFromInt(num_items)) * @log(false_rate)) / d);
        return @intFromFloat(@max(1, @min(n, max_bloom_bits)));
    }

    fn numKeys(num_items: u64, num_bits: u64) u64 {
        if (num_items == 0) return 0;
        const n = @as(f64, @floatFromInt(num_bits)) / @as(f64, @floatFromInt(num_items));
        return @intFromFloat(@max(@as(f64, 1), @round(n * @log(@as(f64, 2)))));
    }
};

fn sendPing(socket: std.posix.socket_t, addr: std.net.Address, keypair: KeyPair, rng: std.Random) ![32]u8 {
    var token: [32]u8 = undefined;
    rng.bytes(&token);
    try sendGossipMessage(socket, addr, .{ .ping_message = .{
        .from = .{ .data = keypair.public_key.bytes },
        .token = token,
        .signature = .fromBytes((try keypair.sign(&token, null)).toBytes()),    
    }});
    return token;
}

fn sendGossipMessage(socket: std.posix.socket_t, addr: std.net.Address, msg: GossipMessage) !void {
    std.log.debug("Sending to {}: {}", .{ addr, msg });

    var buf: [MTU]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try bincode.write(fbs.writer(), msg);
    const sent = try std.posix.sendto(socket, fbs.getWritten(), 0, &addr.any, addr.getOsSockLen());
    std.debug.assert(sent == fbs.getWritten().len);
}

fn getGossipAddr(contact_info_data: CrdsData) !SocketAddr {
    switch (contact_info_data) {
        .legacy_contact_info => |ci| return ci.gossip,
        .contact_info => |ci| {
            var port: u16 = 0;
            for (ci.sockets.items) |s| {
                port += s.port_offset.value;
                return switch (ci.ips.items[s.idx]) {
                    .v4 => |ip| return .{ .v4 = .{ .ip = ip, .port = port } },
                    .v6 => |ip| return .{ .v6 = .{ .ip = ip, .port = port } },
                };
            }
            return error.InvalidContactInfo;
        },
        else => return error.InvalidContactInfo,
    }
}

fn signData(keypair: KeyPair, data_: CrdsData) !CrdsValue {
    var data = data_;
    switch (std.meta.activeTag(data)) {
        inline else => |tag| {
            @field(data, @tagName(tag)).from = .{ .data = keypair.public_key.bytes };
            switch (@TypeOf(@field(data, @tagName(tag)).wallclock)) {
                VarInt(u64) => @field(data, @tagName(tag)).wallclock = .{ .value = realtime() },
                u64 => @field(data, @tagName(tag)).wallclock = realtime(),
                else => @compileError("invalid wallclock field"),
            }
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
        std.debug.print(" reading {s}\n", .{@typeName(T)});
        switch (@typeInfo(T)) {
            .int => return reader.readInt(T, .little),
            .array => |info| {
                comptime std.debug.assert(@typeInfo(info.child) == .int);
                var v: T = undefined;
                _ = try reader.readAll(std.mem.asBytes(&v));
                return v;
            },
            .pointer => |info| {
                comptime std.debug.assert(info.size == .slice);
                const n = try reader.readInt(u64, .little);
                const slice = try gpa.alloc(info.child, n);
                switch (@typeInfo(info.child)) {
                    .int => _ = try reader.readAll(std.mem.sliceAsBytes(slice)),
                    else => {
                        for (0..n) |i| slice[i] = try read(gpa, reader, info.child);
                    },
                }
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
                if (@hasDecl(T, "bincodeRead")) return T.bincodeRead(gpa, reader);
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
            .array => {
                comptime std.debug.assert(@typeInfo(@TypeOf(value[0])) == .int);
                try writer.writeAll(std.mem.asBytes(&value));
            },
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
                if (@hasDecl(T, "bincodeWrite")) return value.bincodeWrite(writer);
                inline for (info.fields) |f| try write(writer, @field(value, f.name));
            },
            else => @compileError("invalid bincode type"),
        }
    }
};

fn VarInt(comptime T: type) type {
    return struct {
        value: T,

        pub fn bincodeRead(_: std.mem.Allocator, reader: anytype) !@This() {
            var v: T = 0;
            var i: std.math.Log2Int(T) = 0;
            while (true) : (i += 7) {
                const b = try reader.readByte();
                v |= @as(T, b) << i;
                if (b & 0x80 == 0) return .{ .value = v };
            }
        }

        pub fn bincodeWrite(self: @This(), writer: anytype) !void {
            var v = self.value;
            while (v > (v & 0x7f)) : (v >>= 7)
                try writer.writeByte(@intCast((v & 0x7f) | 0x80));
            try writer.writeByte(@as(u7, @intCast(v)));
        }
    };
}

const Timestamp = u64;
const ShredVersion = u16;

const EchoMessage = struct {
    _hidden_http_header: u32 = 0,
    tcp_ports: [4]u16,
    udp_ports: [4]u16,
    _hidden_trailer: u8 = '\n',
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
    pull_request: PullRequest,
    pull_response: PullResponse,
    push_message: PushMessage,
    prune_message: PruneMessage,
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

const PruneMessage = struct {
    from: Pubkey,
    data: struct {
        pubkey: Pubkey,
        prunes: []const Pubkey,
        signature: Signature,
        dest: Pubkey,
        wallclock: Timestamp,
    },
};

const PullResponse = struct {
    from: Pubkey,
    values: []const CrdsValue,
};

const PushMessage = struct {
    from: Pubkey,
    values: []const CrdsValue,
};

const PullRequest = struct {
    filter: struct {
        keys: []const u64,
        words: BitVec(u64),
        num_bits: u64,
    },
    mask: u64,
    mask_bits: u32,
    contact_info: CrdsValue,
};

const CrdsValue = struct {
    signature: Signature,
    data: CrdsData,
};

const LegacyContactInfo = struct {
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
};

const Vote = struct {
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
};

const LowestSlot = struct {
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
};

const EpochSlots = struct {
    index: u8,
    from: Pubkey,
    slots: []const union(enum(u32)) {
        flate2: Flate2,
        uncompressed: Uncompressed,
    },
    wallclock: Timestamp,
};

const Flate2 = struct {
    first_slot: Slot,
    num_slots: u64,
    compressed: []const u8,
};

const Uncompressed = struct {
    first_slot: Slot,
    num_slots: u64,
    slots: BitVec(u8),
};

const LegacyVersion = struct {
    from: Pubkey,
    wallclock: Timestamp,
    version: Version,
};

const LegacyVersion2 = struct {
    from: Pubkey,
    wallclock: Timestamp,
    version: Version,
    feature_set: u32,
}; 

const NodeInstance = struct {
    from: Pubkey,
    wallclock: Timestamp,
    created: Timestamp,
    token: u64,
};

const DuplicateShred = struct {
    index: u16,
    from: Pubkey,
    wallclock: Timestamp,
    slot: Slot,
    _unused: u32,
    _shred_type: enum(u8) {
        data = 0b10100101,
        code = 0b01011010,
    },
    num_chunks: u8,
    chunk_idx: u8,
    chunk: []const u8,
};

const SnapshotHashes = struct {
    from: Pubkey,
    full: SlotAndHash,
    incremental: []const SlotAndHash,
    wallclock: Timestamp,
};

const RestartLast = struct {
    from: Pubkey,
    wallclock: Timestamp,
    offsets: []const union(enum(u32)) {
        rle: []const VarInt(u16),
        raw: BitVec(u8),
    },
    last_voted: SlotAndHash,
    shred_version: ShredVersion,
};

const RestartHeaviest = struct {
    from: Pubkey,
    wallclock: Timestamp,
    last_slot: SlotAndHash,
    observed_stake: u64,
    shred_version: ShredVersion,
};

const CrdsData = union(enum(u32)) {
    legacy_contact_info: LegacyContactInfo,
    vote: Vote,
    lowest_slot: LowestSlot,
    legacy_snapshot_hashes: AccountHashes,
    account_hashes: AccountHashes,
    epoch_slots: EpochSlots,
    legacy_version: LegacyVersion,
    version: LegacyVersion2,
    node_instance: NodeInstance,
    duplicate_shred: DuplicateShred,
    snapshot_hashes: SnapshotHashes,
    contact_info: ContactInfo,
    restart_last_voted_fork_slots: RestartLast,
    restart_heaviest_fork: RestartHeaviest,
};

fn BitVec(comptime T: type) type {
    return struct {
        bits: ?[]const T,
        len: u64,
    };
}

fn ShortVec(comptime T: type) type {
    return struct {
        items: []const T,

        pub fn bincodeRead(gpa: std.mem.Allocator, reader: anytype) !@This() {
            const len = try bincode.read(gpa, reader, VarInt(u16));
            const items = try gpa.alloc(T, len.value);
            for (items) |*v| v.* = try bincode.read(gpa, reader, T);
            return .{ .items = items };
        }

        pub fn bincodeWrite(self: @This(), writer: anytype) !void {
            try bincode.write(writer, VarInt(u16){ .value = @intCast(self.items.len) });
            for (self.items) |v| try bincode.write(writer, v); 
        }
    };
}

const ContactInfo = struct {
    from: Pubkey,
    wallclock: VarInt(Timestamp),
    created: Timestamp,
    shred_version: ShredVersion,
    major: VarInt(u16),
    minor: VarInt(u16),
    patch: VarInt(u16),
    commit: u32,
    feature_set: u32,
    client_id: VarInt(u16),
    ips: ShortVec(IpAddr),
    sockets: ShortVec(struct {
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
        port_offset: VarInt(u16),
    }),
    extensions: ShortVec(struct{}),
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

