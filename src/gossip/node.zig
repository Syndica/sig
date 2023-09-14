const std = @import("std");
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const network = @import("zig-network");
const Version = @import("../version/version.zig").Version;
const bincode = @import("../bincode/bincode.zig");

const var_int = @import("../utils/varint.zig");
const var_int_config_u16 = var_int.var_int_config_u16;
const var_int_config_u64 = var_int.var_int_config_u64;

const ShortVecArrayListConfig = @import("../utils/shortvec.zig").ShortVecArrayListConfig;
const SocketAddr = @import("../net/net.zig").SocketAddr;
const IpAddr = @import("../net/net.zig").IpAddr;
const gossip = @import("sig").gossip;
const ArrayList = std.ArrayList;
const testing = std.testing;
const NodeInstance = @import("crds.zig").NodeInstance;

const Socket = network.Socket;
const UdpSocket = network.Socket;
const TcpListener = network.Socket;
const net = std.net;

pub const SOCKET_TAG_GOSSIP: u8 = 0;
pub const SOCKET_TAG_REPAIR: u8 = 1;
pub const SOCKET_TAG_RPC: u8 = 2;
pub const SOCKET_TAG_RPC_PUBSUB: u8 = 3;
pub const SOCKET_TAG_SERVE_REPAIR: u8 = 4;
pub const SOCKET_TAG_TPU: u8 = 5;
pub const SOCKET_TAG_TPU_FORWARDS: u8 = 6;
pub const SOCKET_TAG_TPU_FORWARDS_QUIC: u8 = 7;
pub const SOCKET_TAG_TPU_QUIC: u8 = 8;
pub const SOCKET_TAG_TPU_VOTE: u8 = 9;
pub const SOCKET_TAG_TVU: u8 = 10;
pub const SOCKET_TAG_TVU_FORWARDS: u8 = 11;
pub const SOCKET_TAG_TVU_QUIC: u8 = 12;
pub const SOCKET_CACHE_SIZE: usize = SOCKET_TAG_TVU_QUIC + 1;

const Node = struct {
    contactInfo: ContactInfo,
    sockets: Sockets,

    const Self = @This();
};

pub const ContactInfo = struct {
    pubkey: Pubkey,
    wallclock: u64,
    outset: u64,
    shred_version: u16,
    version: Version,
    addrs: ArrayList(IpAddr),
    sockets: ArrayList(SocketEntry),
    cache: [SOCKET_CACHE_SIZE]SocketAddr = socket_addrs_unspecified(),

    pub const @"!bincode-config:cache" = bincode.FieldConfig([SOCKET_CACHE_SIZE]SocketAddr){ .skip = true };
    pub const @"!bincode-config:addrs" = ShortVecArrayListConfig(IpAddr);
    pub const @"!bincode-config:sockets" = ShortVecArrayListConfig(SocketEntry);
    pub const @"!bincode-config:wallclock" = var_int_config_u64;

    const Self = @This();

    pub fn toNodeInstance(self: *Self) NodeInstance {
        return NodeInstance.init(self.Pubkey, @intCast(std.time.milliTimestamp()));
    }

    pub fn deinit(self: Self) void {
        self.addrs.deinit();
        self.sockets.deinit();
    }

    pub fn initSpy(allocator: std.mem.Allocator, id: Pubkey, gossip_socket_addr: SocketAddr, shred_version: u16) !Self {
        var contact_info = Self.init(allocator, id, @intCast(std.time.microTimestamp()), shred_version);
        try contact_info.setSocket(SOCKET_TAG_GOSSIP, gossip_socket_addr);
        return contact_info;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
        wallclock: u64,
        shred_version: u16,
    ) Self {
        var outset = @as(u64, @intCast(std.time.microTimestamp()));
        return Self{
            .pubkey = pubkey,
            .wallclock = wallclock,
            .outset = outset,
            .shred_version = shred_version,
            .version = Version.default(),
            .addrs = ArrayList(IpAddr).init(allocator),
            .sockets = ArrayList(SocketEntry).init(allocator),
            .cache = socket_addrs_unspecified(),
        };
    }

    pub fn initDummyForTest(
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
        wallclock: u64,
        outset: u64,
        shred_version: u16,
    ) ContactInfo {
        var addrs = ArrayList(IpAddr).initCapacity(allocator, 4) catch unreachable;
        var sockets = ArrayList(SocketEntry).initCapacity(allocator, 6) catch unreachable;

        for (0..4) |_| {
            addrs.append(IpAddr.new_v4(127, 0, 0, 1)) catch unreachable;
        }

        for (0..6) |_| {
            sockets.append(.{ .key = 10, .index = 20, .offset = 30 }) catch unreachable;
        }

        return ContactInfo{
            .pubkey = pubkey,
            .wallclock = wallclock,
            .outset = outset,
            .shred_version = shred_version,
            .version = Version.new(1, 2, 3, 4, 5, 6),
            .addrs = addrs,
            .sockets = sockets,
        };
    }

    pub fn getSocket(self: *const Self, key: u8) ?SocketAddr {
        if (self.cache[key].eql(&SocketAddr.UNSPECIFIED)) {
            return null;
        }
        return self.cache[key];
    }

    pub fn setSocket(self: *Self, key: u8, socket_addr: SocketAddr) !void {
        self.removeSocket(key);

        var offset = socket_addr.port();
        var index: ?usize = null;
        for (self.sockets.items, 0..) |socket, idx| {
            offset = std.math.sub(u16, offset, socket.offset) catch {
                index = idx;
                break;
            };
        }

        var entry = SocketEntry.init(key, try self.pushAddr(socket_addr.ip()), offset);

        if (index) |i| {
            self.sockets.items[i].offset -= entry.offset;
            try self.sockets.insert(i, entry);
        } else {
            try self.sockets.append(entry);
        }

        self.cache[key] = socket_addr;
    }

    pub fn removeSocket(self: *Self, key: u8) void {
        // find existing socket index
        var existing_socket_index: ?usize = null;
        for (self.sockets.items, 0..) |socket, idx| {
            if (socket.key == key) {
                existing_socket_index = idx;
                break;
            }
        }
        // if found, remove it, it's associated IpAddr, set cache[key] to unspecified
        if (existing_socket_index) |index| {
            // first we remove this existing socket
            var removed_entry = self.sockets.orderedRemove(index);
            // reset the socket entry offset
            if (index < self.sockets.items.len - 1) {
                var next_entry = self.sockets.items[index];
                next_entry.offset += removed_entry.offset;
            }
            self.removeAddrIfUnused(removed_entry.index);
            self.cache[key] = SocketAddr.unspecified();
        }
    }

    // Add IpAddr if it doesn't already exist otherwise return index
    fn pushAddr(self: *Self, ip_addr: IpAddr) !u8 {
        for (self.addrs.items, 0..) |addr, index| {
            if (addr.eql(&ip_addr)) {
                return std.math.cast(u8, index) orelse return error.IpAddrsSaturated;
            }
        }
        try self.addrs.append(ip_addr);
        return std.math.cast(u8, self.addrs.items.len - 1) orelse return error.IpAddrsSaturated;
    }

    pub fn removeAddrIfUnused(self: *Self, index: usize) void {
        for (self.sockets.items) |socket| {
            if (socket.index == index) {
                // exit because there's an existing socket entry that refs that addr index
                return;
            }
        }
        _ = self.addrs.orderedRemove(index);
        // now we reorder indexes in socket entries that are greater than this index
        for (self.sockets.items) |*socket| {
            if (socket.index > index) {
                socket.index -= 1;
            }
        }
    }
};

const NodePort = union(enum) {
    gossip: network.EndPoint,
    repair: network.EndPoint,
    rpc: network.EndPoint,
    rpc_pubsub: network.EndPoint,
    serve_repair: network.EndPoint,
    tpu: network.EndPoint,
    tpu_forwards: network.EndPoint,
    tpu_forwards_quic: network.EndPoint,
    tpu_quic: network.EndPoint,
    tpu_vote: network.EndPoint,
    tvu: network.EndPoint,
    tvu_forwards: network.EndPoint,
    tvu_quic: network.EndPoint,
};

const Sockets = struct {
    gossip: UdpSocket,
    ip_echo: ?TcpListener,
    tvu: ArrayList(UdpSocket),
    tvu_forwards: ArrayList(UdpSocket),
    tpu: ArrayList(UdpSocket),
    tpu_forwards: ArrayList(UdpSocket),
    tpu_vote: ArrayList(UdpSocket),
    broadcast: ArrayList(UdpSocket),
    repair: UdpSocket,
    retransmit_sockets: ArrayList(UdpSocket),
    serve_repair: UdpSocket,
    ancestor_hashes_requests: UdpSocket,
    tpu_quic: UdpSocket,
    tpu_forwards_quic: UdpSocket,
};

pub const SocketEntry = struct {
    key: u8, // Protocol identifier, e.g. tvu, tpu, etc
    index: u8, // IpAddr index in the accompanying addrs vector.
    offset: u16, // Port offset with respect to the previous entry.

    pub const @"!bincode-config:offset" = var_int_config_u16;

    const Self = @This();

    pub fn init(key: u8, index: u8, offset: u16) Self {
        return Self{
            .key = key,
            .index = index,
            .offset = offset,
        };
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return self.key == other.key and
            self.index == other.index and
            self.offset == other.offset;
    }
};

fn socket_addrs_unspecified() [13]SocketAddr {
    return .{
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
    };
}

const logger = std.log.scoped(.node_tests);

test "new contact info" {
    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var ci = ContactInfo.init(testing.allocator, Pubkey.random(rng, .{}), @as(u64, @intCast(std.time.microTimestamp())), 1000);
    defer ci.deinit();
}

test "socketaddr bincode serialize matches rust" {
    const Tmp = struct {
        addr: SocketAddr,
    };
    const tmp = Tmp{ .addr = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 1234) };
    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(buf[0..], tmp, bincode.Params.standard);

    // #[derive(Serialize, Debug, Clone, Copy)]
    // pub struct Tmp {
    //     addr: SocketAddr
    // }
    // let tmp = Tmp { addr: socketaddr!(Ipv4Addr::LOCALHOST, 1234) };
    // println!("{:?}", bincode::serialize(&tmp).unwrap());

    // Enum discriminants are encoded as u32 (4 leading zeros)
    const rust_bytes = [_]u8{ 0, 0, 0, 0, 127, 0, 0, 1, 210, 4 };
    try testing.expectEqualSlices(u8, rust_bytes[0..rust_bytes.len], bytes);
}

test "set & get socket on contact info" {
    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var ci = ContactInfo.init(testing.allocator, Pubkey.random(rng, .{}), @as(u64, @intCast(std.time.microTimestamp())), 1000);
    defer ci.deinit();
    try ci.setSocket(SOCKET_TAG_RPC, SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 8899));

    var set_socket = ci.getSocket(SOCKET_TAG_RPC);
    try testing.expect(set_socket.?.eql(&SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 8899)));
    try testing.expect(ci.addrs.items[0].eql(&IpAddr.new_v4(127, 0, 0, 1)));
    try testing.expect(ci.sockets.items[0].eql(&SocketEntry.init(SOCKET_TAG_RPC, 0, 8899)));
}

test "contact info bincode serialize matches rust bincode" {
    var rust_contact_info_serialized_bytes = [_]u8{
        57,  54, 18,  6,  106, 202, 13, 245, 224, 235, 33,  252, 254, 251, 161, 17, 248, 108, 25,  214, 169,
        154, 91, 101, 17, 121, 235, 82, 175, 197, 144, 145, 100, 200, 0,   0,   0,  0,   0,   0,   0,   44,
        1,   1,  2,   3,  4,   0,   0,  0,   5,   0,   0,   0,   6,   4,   0,   0,  0,   0,   127, 0,   0,
        1,   0,  0,   0,  0,   127, 0,  0,   1,   0,   0,   0,   0,   127, 0,   0,  1,   0,   0,   0,   0,
        127, 0,  0,   1,  6,   10,  20, 30,  10,  20,  30,  10,  20,  30,  10,  20, 30,  10,  20,  30,  10,
        20,  30,
    };

    var pubkey = Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa") catch unreachable;
    var ci = ContactInfo.initDummyForTest(testing.allocator, pubkey, 100, 200, 300);
    defer ci.deinit();

    var buf = std.ArrayList(u8).init(testing.allocator);
    bincode.write(null, buf.writer(), ci, bincode.Params.standard) catch unreachable;
    defer buf.deinit();

    try testing.expect(std.mem.eql(u8, &rust_contact_info_serialized_bytes, buf.items));

    var stream = std.io.fixedBufferStream(buf.items);
    var ci2 = try bincode.read(testing.allocator, ContactInfo, stream.reader(), bincode.Params.standard);
    defer bincode.free(testing.allocator, ci2);

    try testing.expect(ci2.addrs.items.len == 4);
    try testing.expect(ci2.sockets.items.len == 6);
    try testing.expect(ci2.pubkey.equals(&ci.pubkey));
    try testing.expect(ci2.outset == ci.outset);
}

test "SocketEntry serializer works" {
    testing.log_level = .debug;

    var se = SocketEntry.init(3, 3, 30304);

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try bincode.write(null, buf.writer(), se, bincode.Params.standard);

    var stream = std.io.fixedBufferStream(buf.items);
    var other_se = try bincode.read(testing.allocator, SocketEntry, stream.reader(), bincode.Params.standard);

    try testing.expect(other_se.index == se.index);
    try testing.expect(other_se.key == se.key);
    try testing.expect(other_se.offset == se.offset);
}
