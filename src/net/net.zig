const std = @import("std");
const network = @import("zig-network");

pub const SocketAddr = union(enum(u8)) {
    V4: SocketAddrV4,
    V6: SocketAddrV6,

    const Self = @This();

    pub const UNSPECIFIED = Self{
        .V4 = .{
            .ip = Ipv4Addr{
                .octets = [4]u8{ 0, 0, 0, 0 },
            },
            .port = 0,
        },
    };

    pub fn parse(bytes: []const u8) !Self {
        // TODO: parse v6 if v4 fails
        return parseIpv4(bytes);
    }

    pub fn parseIpv4(bytes: []const u8) !Self {
        // parse v4
        var octs: [4]u8 = [_]u8{0} ** 4;
        var addr_port: u16 = 0;
        var octets_index: usize = 0;
        var parsed_digit: bool = false;
        var parsed_ip = false;

        for (bytes) |byte| {
            switch (byte) {
                '.' => {
                    if (!parsed_digit) return error.InvalidIpv4;
                    if (octets_index == 4) return error.InvalidIpv4;
                    octets_index += 1;
                    parsed_digit = false;
                },
                '0'...'9' => {
                    const value = byte - '0';

                    if (!parsed_ip) {
                        // octs[octets_index] = octs[octets_index] * 10 + value
                        const mul_result = @mulWithOverflow(octs[octets_index], 10);
                        if (mul_result[1] == 1) return error.InvalidIpv4;
                        const add_result = @addWithOverflow(mul_result[0], value);
                        if (add_result[1] == 1) return error.InvalidIpv4;
                        octs[octets_index] = add_result[0];
                    } else {
                        // addr_port = addr_port * 10 + value
                        const mul_result = @mulWithOverflow(addr_port, 10);
                        if (mul_result[1] == 1) return error.InvalidIpv4;
                        const add_result = @addWithOverflow(mul_result[0], value);
                        if (add_result[1] == 1) return error.InvalidIpv4;
                        addr_port = add_result[0];
                    }
                    parsed_digit = true;
                },
                ':' => {
                    if (octets_index != 3) return error.InvalidIpv4;
                    parsed_ip = true;
                },
                else => {
                    return error.InvalidIpv4;
                },
            }
        }
        if (!parsed_ip) return error.InvalidIpv4;

        return Self{ .V4 = .{
            .ip = Ipv4Addr.init(octs[0], octs[1], octs[2], octs[3]),
            .port = addr_port,
        } };
    }

    pub fn random(rng: std.rand.Random) Self {
        const pport = rng.int(u16);

        var version = rng.int(u8);
        if (version % 2 == 0) {
            var octets: [4]u8 = undefined;
            rng.bytes(&octets);
            return Self{
                .V4 = .{ .ip = Ipv4Addr.init(octets[0], octets[1], octets[2], octets[3]), .port = pport },
            };
        } else {
            var octets: [16]u8 = undefined;
            rng.bytes(&octets);
            return Self{
                .V6 = .{ .ip = Ipv6Addr.init(octets), .port = pport, .flowinfo = 0, .scope_id = 0 },
            };
        }
    }

    pub fn initIpv4(octets: [4]u8, portt: u16) Self {
        return Self{
            .V4 = .{ .ip = Ipv4Addr.init(octets[0], octets[1], octets[2], octets[3]), .port = portt },
        };
    }

    pub fn initIpv6(octets: [16]u8, portt: u16) Self {
        return Self{
            .V4 = .{ .ip = Ipv6Addr.init(octets), .port = portt },
        };
    }

    pub fn unspecified() Self {
        return UNSPECIFIED;
    }

    pub fn port(self: *const Self) u16 {
        switch (self.*) {
            .V4 => |v4| {
                return v4.port;
            },
            .V6 => |v6| {
                return v6.port;
            },
        }
    }

    pub fn ip(self: *const Self) IpAddr {
        switch (self.*) {
            .V4 => |v4| {
                return IpAddr{ .ipv4 = v4.ip };
            },
            .V6 => |v6| {
                return IpAddr{ .ipv6 = v6.ip };
            },
        }
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        switch (self.*) {
            .V4 => |self_v4| {
                switch (other.*) {
                    .V4 => |other_v4| {
                        return self_v4.ip.eql(&other_v4.ip) and self_v4.port == other_v4.port;
                    },
                    .V6 => |_| {
                        return false;
                    },
                }
            },
            .V6 => |self_v6| {
                switch (other.*) {
                    .V4 => |_| {
                        return false;
                    },
                    .V6 => |other_v6| {
                        return self_v6.ip.eql(&other_v6.ip) and
                            self_v6.port == other_v6.port;
                    },
                }
            },
        }
    }

    pub fn toEndpoint(self: *const Self) network.EndPoint {
        switch (self.*) {
            .V4 => |addr| {
                return network.EndPoint{
                    .address = .{ .ipv4 = network.Address.IPv4{ .value = addr.ip.octets } },
                    .port = self.port(),
                };
            },
            .V6 => |addr| {
                return network.EndPoint{
                    .address = .{ .ipv6 = network.Address.IPv6{ .value = addr.ip.octets, .scope_id = addr.scope_id } },
                    .port = self.port(),
                };
            },
        }
    }

    pub fn fromEndpoint(endpoint: *const network.EndPoint) Self {
        switch (endpoint.address) {
            .ipv4 => |v4| {
                return Self{
                    .V4 = SocketAddrV4{
                        .ip = Ipv4Addr.init(v4.value[0], v4.value[1], v4.value[2], v4.value[3]),
                        .port = endpoint.port,
                    },
                };
            },
            .ipv6 => |v6| {
                return Self{
                    .V6 = SocketAddrV6{
                        .ip = Ipv6Addr.init(v6.value),
                        .port = endpoint.port,
                        .flowinfo = 0,
                        .scope_id = v6.scope_id,
                    },
                };
            },
        }
    }

    pub fn isUnspecified(self: *const Self) bool {
        switch (self.*) {
            .V4 => |addr| {
                return std.mem.readIntBig(u32, &addr.ip.octets) == 0;
            },
            .V6 => |addr| {
                return std.mem.readIntBig(u128, &addr.ip.octets) == 0;
            },
        }
    }

    pub fn isMulticast(self: *const Self) bool {
        switch (self.*) {
            .V4 => |addr| {
                const octets = addr.ip.octets;
                return octets[0] >= 224 and octets[0] <= 239;
            },
            .V6 => |addr| {
                return addr.ip.isMulticast();
            },
        }
    }
};

pub const SocketAddrV4 = struct {
    ip: Ipv4Addr,
    port: u16,
};

pub const SocketAddrV6 = struct {
    ip: Ipv6Addr,
    port: u16,
    flowinfo: u32,
    scope_id: u32,
};

pub const Ipv4Addr = struct {
    octets: [4]u8,

    const Self = @This();

    pub fn init(a: u8, b: u8, c: u8, d: u8) Self {
        return Self{
            .octets = [4]u8{ a, b, c, d },
        };
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.octets[0..], other.octets[0..]);
    }
};

pub const Ipv6Addr = struct {
    octets: [16]u8,

    const Self = @This();

    pub fn init(octets: [16]u8) Self {
        return Self{
            .octets = octets,
        };
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.octets[0..], other.octets[0..]);
    }

    /// defined in https://tools.ietf.org/html/rfc4291
    pub fn isMulticast(self: *const Self) bool {
        return self.octets[0] == 255;
    }
};

pub const IpAddr = union(enum(u32)) {
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,

    const Self = @This();

    pub fn newIpv4(a: u8, b: u8, c: u8, d: u8) IpAddr {
        return .{
            .ipv4 = Ipv4Addr{
                .octets = [4]u8{ a, b, c, d },
            },
        };
    }

    pub fn asV4(self: *const Self) [4]u8 {
        return self.ipv4.octets;
    }

    pub fn eql(self: *const Self, other: *const IpAddr) bool {
        switch (self.*) {
            .ipv4 => |ip| {
                switch (other.*) {
                    .ipv4 => |other_ip| return std.mem.eql(u8, ip.octets[0..], other_ip.octets[0..]),
                    else => return false,
                }
            },
            .ipv6 => |ip| {
                switch (other.*) {
                    .ipv6 => |other_ip| return std.mem.eql(u8, ip.octets[0..], other_ip.octets[0..]),
                    else => return false,
                }
            },
        }
    }
};

test "gossip.net: invalid ipv4 socket parsing" {
    {
        var addr = "127.0.0.11234";
        var result = SocketAddr.parseIpv4(addr);
        try std.testing.expectError(error.InvalidIpv4, result);
    }
    {
        var addr = "127.0.0:1123";
        var result = SocketAddr.parseIpv4(addr);
        try std.testing.expectError(error.InvalidIpv4, result);
    }
}

test "gossip.net: valid ipv4 socket parsing" {
    var addr = "127.0.0.1:1234";
    var expected_addr = SocketAddr{ .V4 = SocketAddrV4{
        .ip = Ipv4Addr.init(127, 0, 0, 1),
        .port = 1234,
    } };
    var actual_addr = try SocketAddr.parseIpv4(addr);
    try std.testing.expectEqual(expected_addr, actual_addr);
}

test "gossip.net: test random" {
    var rng = std.rand.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    var addr = SocketAddr.random(rng.random());
    _ = addr;
}
