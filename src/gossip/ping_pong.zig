const std = @import("std");
const sig = @import("../lib.zig");

const testing = std.testing;

const DefaultPrng = std.rand.DefaultPrng;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const LruCache = sig.common.lru.LruCache;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const SocketAddr = sig.net.SocketAddr;
const Duration = sig.time.Duration;

const getWallclockMs = sig.gossip.data.getWallclockMs;

const PING_TOKEN_SIZE: usize = 32;
const PING_PONG_HASH_PREFIX: [16]u8 = .{
    'S', 'O', 'L', 'A', 'N', 'A', '_', 'P', 'I', 'N', 'G', '_', 'P', 'O', 'N', 'G',
};

const U256 = struct { inner: struct { u128, u128 } };

pub const Ping = struct {
    from: Pubkey,
    token: [PING_TOKEN_SIZE]u8,
    signature: Signature,

    const Self = @This();

    pub fn init(token: [PING_TOKEN_SIZE]u8, keypair: *const KeyPair) !Self {
        const signature = try keypair.sign(&token, null);
        const self = Self{
            .from = Pubkey.fromPublicKey(&keypair.public_key),
            .token = token,
            .signature = Signature.init(signature.toBytes()),
        };
        return self;
    }

    pub fn random(rng: std.rand.Random, keypair: *const KeyPair) !Self {
        var token: [PING_TOKEN_SIZE]u8 = undefined;
        rng.bytes(&token);
        var signature = keypair.sign(&token, null) catch unreachable; // TODO: do we need noise?

        return Self{
            .from = Pubkey.fromPublicKey(&keypair.public_key),
            .token = token,
            .signature = Signature.init(signature.toBytes()),
        };
    }

    pub fn verify(self: *const Self) !void {
        if (!self.signature.verify(self.from, &self.token)) {
            return error.InvalidSignature;
        }
    }
};

pub const Pong = struct {
    from: Pubkey,
    hash: Hash, // Hash of received ping token.
    signature: Signature,

    const Self = @This();

    pub fn init(ping: *const Ping, keypair: *const KeyPair) error{SignatureError}!Self {
        var token_with_prefix = PING_PONG_HASH_PREFIX ++ ping.token;
        var hash = Hash.generateSha256Hash(token_with_prefix[0..]);
        const signature = keypair.sign(&hash.data, null) catch return error.SignatureError;

        return Self{
            .from = Pubkey.fromPublicKey(&keypair.public_key),
            .hash = hash,
            .signature = Signature.init(signature.toBytes()),
        };
    }

    pub fn verify(self: *const Self) error{InvalidSignature}!void {
        if (!self.signature.verify(self.from, &self.hash.data)) {
            return error.InvalidSignature;
        }
    }

    pub fn random(rng: std.rand.Random, keypair: *const KeyPair) !Self {
        const ping = try Ping.random(rng, keypair);
        return try Pong.init(&ping, keypair);
    }

    pub fn eql(self: *const @This(), other: *const @This()) bool {
        return std.mem.eql(u8, &self.from.data, &other.from.data) and
            std.mem.eql(u8, &self.hash.data, &other.hash.data) and
            std.mem.eql(u8, &self.signature.data, &other.signature.data);
    }
};

/// `PubkeyAndSocketAddr` is a 2 element tuple: `.{ Pubkey, SocketAddr }`
pub const PubkeyAndSocketAddr = struct {
    pubkey: Pubkey,
    socket_addr: SocketAddr,
};

pub const PingAndSocketAddr = struct { ping: Ping, socket: SocketAddr };

/// Maintains records of remote nodes which have returned a valid response to a
/// ping message, and on-the-fly ping messages pending a pong response from the
/// remote node.
pub const PingCache = struct {
    // Time-to-live of received pong messages.
    ttl: sig.time.Duration,
    // Rate limit delay to generate pings for a given address
    rate_limit_delay: sig.time.Duration,
    // Timestamp of last ping message sent to a remote node.
    // Used to rate limit pings to remote nodes.
    pings: LruCache(.non_locking, PubkeyAndSocketAddr, std.time.Instant),
    // Verified pong responses from remote nodes.
    pongs: LruCache(.non_locking, PubkeyAndSocketAddr, std.time.Instant),
    // Hash of ping tokens sent out to remote nodes,
    // pending a pong response back.
    pending_cache: LruCache(.non_locking, Hash, PubkeyAndSocketAddr),
    // allocator
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        ttl: sig.time.Duration,
        rate_limit_delay: sig.time.Duration,
        cache_capacity: usize,
    ) error{OutOfMemory}!Self {
        std.debug.assert(rate_limit_delay.asNanos() <= ttl.asNanos() / 2);
        return Self{
            .ttl = ttl,
            .rate_limit_delay = rate_limit_delay,
            .pings = try LruCache(.non_locking, PubkeyAndSocketAddr, std.time.Instant).init(allocator, cache_capacity),
            .pongs = try LruCache(.non_locking, PubkeyAndSocketAddr, std.time.Instant).init(allocator, cache_capacity),
            .pending_cache = try LruCache(.non_locking, Hash, PubkeyAndSocketAddr).init(allocator, cache_capacity),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pending_cache.deinit();
        self.pings.deinit();
        self.pongs.deinit();
    }

    /// Records a `Pong` if corresponding `Ping` exists in `pending_cache`
    pub fn receviedPong(self: *Self, pong: *const Pong, socket: SocketAddr, now: std.time.Instant) bool {
        const peer_and_addr = PubkeyAndSocketAddr{ .pubkey = pong.from, .socket_addr = socket };
        if (self.pending_cache.peek(pong.hash)) |*pubkey_and_addr| {
            if (pubkey_and_addr.pubkey.equals(&pong.from) and pubkey_and_addr.socket_addr.eql(&socket)) {
                _ = self.pings.pop(peer_and_addr);
                _ = self.pongs.put(peer_and_addr, now);
                _ = self.pending_cache.pop(pong.hash);
                return true;
            }
        }
        return false;
    }

    pub fn maybePing(
        self: *Self,
        now: std.time.Instant,
        peer_and_addr: PubkeyAndSocketAddr,
        keypair: *const KeyPair,
    ) ?Ping {
        if (self.pings.peek(peer_and_addr)) |earlier| {
            // to prevent integer overflow
            std.debug.assert(now.order(earlier) != .lt);

            const elapsed: u64 = now.since(earlier);
            if (elapsed < self.rate_limit_delay.asNanos()) {
                return null;
            }
        }
        var rng = DefaultPrng.init(getWallclockMs());
        const ping = Ping.random(rng.random(), keypair) catch return null;
        var token_with_prefix = PING_PONG_HASH_PREFIX ++ ping.token;
        const hash = Hash.generateSha256Hash(token_with_prefix[0..]);
        _ = self.pending_cache.put(hash, peer_and_addr);
        _ = self.pings.put(peer_and_addr, now);
        return ping;
    }

    pub fn check(
        self: *Self,
        now: std.time.Instant,
        peer_and_addr: PubkeyAndSocketAddr,
        keypair: *const KeyPair,
    ) struct { passes_ping_check: bool, maybe_ping: ?Ping } {
        if (self.pongs.get(peer_and_addr)) |last_pong_time| {
            // to prevent integer overflow
            std.debug.assert(now.order(last_pong_time) != .lt);

            const age = now.since(last_pong_time);

            // if age is greater than time-to-live, remove pong
            if (age > self.ttl.asNanos()) {
                _ = self.pongs.pop(peer_and_addr);
            }

            // if age is greater than time-to-live divided by 8, we maybe ping again
            return .{ .passes_ping_check = true, .maybe_ping = if (age > self.ttl.asNanos() / 8) self.maybePing(now, peer_and_addr, keypair) else null };
        }
        return .{ .passes_ping_check = false, .maybe_ping = self.maybePing(now, peer_and_addr, keypair) };
    }

    /// Filters valid peers according to `PingCache` state and returns them along with any possible pings that need to be sent out.
    ///
    /// *Note*: caller is responsible for deinit `ArrayList`(s) returned!
    pub fn filterValidPeers(
        self: *Self,
        allocator: std.mem.Allocator,
        our_keypair: KeyPair,
        peers: []ThreadSafeContactInfo,
    ) error{OutOfMemory}!struct { valid_peers: std.ArrayList(usize), pings: std.ArrayList(PingAndSocketAddr) } {
        const now = std.time.Instant.now() catch @panic("time not supported by OS!");
        var valid_peers = std.ArrayList(usize).init(allocator);
        var pings = std.ArrayList(PingAndSocketAddr).init(allocator);

        for (peers, 0..) |*peer, i| {
            if (peer.gossip_addr) |gossip_addr| {
                const result = self.check(now, PubkeyAndSocketAddr{ .pubkey = peer.pubkey, .socket_addr = gossip_addr }, &our_keypair);
                if (result.passes_ping_check) {
                    try valid_peers.append(i);
                }
                if (result.maybe_ping) |ping| {
                    try pings.append(.{ .ping = ping, .socket = gossip_addr });
                }
            }
        }

        return .{ .valid_peers = valid_peers, .pings = pings };
    }

    // only used in tests/benchmarks
    pub fn _setPong(self: *Self, peer: Pubkey, socket_addr: SocketAddr) void {
        _ = self.pongs.put(PubkeyAndSocketAddr{
            .pubkey = peer,
            .socket_addr = socket_addr,
        }, std.time.Instant.now() catch unreachable);
    }
};

test "gossip.ping_pong: PingCache works" {
    var ping_cache = try PingCache.init(
        testing.allocator,
        Duration.fromNanos(10_000),
        Duration.fromNanos(1_000),
        1_024,
    );
    defer ping_cache.deinit();

    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    const the_node = PubkeyAndSocketAddr{ .pubkey = Pubkey.random(rng), .socket_addr = SocketAddr.UNSPECIFIED };
    const now1 = try std.time.Instant.now();
    var our_kp = try KeyPair.create(null);

    const ping = ping_cache.maybePing(
        now1,
        the_node,
        &our_kp,
    );

    const now2 = try std.time.Instant.now();

    const resp = ping_cache.check(now2, the_node, &our_kp);
    try testing.expect(!resp.passes_ping_check);
    try testing.expect(resp.maybe_ping != null);

    var result = try ping_cache.filterValidPeers(testing.allocator, our_kp, &[_]ThreadSafeContactInfo{});
    defer result.valid_peers.deinit();
    defer result.pings.deinit();

    try testing.expect(ping != null);
}

test "gossip.ping_pong: ping signatures match rust" {
    var keypair = try KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes([_]u8{
        125, 52,  162, 97,  231, 139, 58,  13,  185, 212, 57,  142, 136, 12,  21,  127, 228, 71,
        115, 126, 138, 52,  102, 69,  103, 185, 45,  255, 132, 222, 243, 138, 25,  117, 21,  11,
        61,  170, 38,  18,  67,  196, 242, 219, 50,  154, 4,   254, 79,  227, 253, 229, 188, 230,
        121, 12,  227, 248, 199, 156, 253, 144, 175, 67,
    }));
    var ping = Ping.init([_]u8{0} ** PING_TOKEN_SIZE, &keypair) catch unreachable;
    const signature = ping.signature.data;

    const rust_sig = [_]u8{ 52, 171, 91, 205, 183, 211, 38, 219, 53, 155, 163, 118, 202, 169, 15, 237, 147, 87, 209, 20, 6, 115, 24, 114, 196, 41, 217, 55, 123, 245, 35, 138, 126, 47, 233, 182, 90, 206, 13, 173, 212, 107, 94, 120, 167, 254, 14, 11, 253, 199, 158, 4, 203, 42, 173, 143, 214, 209, 132, 158, 223, 62, 214, 11 };
    try testing.expect(std.mem.eql(u8, &signature, &rust_sig));
    try ping.verify();
}
