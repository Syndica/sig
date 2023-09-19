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
        return parseIpv4(bytes) catch parse_v6(bytes);
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
    pub fn parse_v6(buf: []const u8) !Self {
        if (buf[0] != '[') {
            return error.Incomplete;
        }
        var ip_port: u16 = 0;
        var result = Self{
            .V6 = SocketAddrV6{
                .scope_id = 0,
                .port = std.mem.nativeToBig(u16, ip_port),
                .flowinfo = 0,
                .ip = Ipv6Addr{ .octets = undefined },
            },
        };
        var new_buf = buf[1..];
        var ip_sep_index: usize = 0;
        while (ip_sep_index < buf.len) : (ip_sep_index += 1) {
            if (buf[ip_sep_index] == ']') {
                new_buf = buf[1..ip_sep_index];
                ip_port = try std.fmt.parseInt(u16, buf[ip_sep_index + 2 ..], 10);
                result.V6.port = ip_port;
                break;
            } else if (ip_sep_index == buf.len - 1) {
                return error.Incomplete;
            }
        }
        var ip_slice: *[16]u8 = result.V6.ip.octets[0..];

        var tail: [16]u8 = undefined;
        var x: u16 = 0;
        var saw_any_digits = false;
        var index: u8 = 0;
        var scope_id = false;
        var abbrv = false;
        for (new_buf, 0..) |c, i| {
            if (scope_id) {
                if (c >= '0' and c <= '9') {
                    const digit = c - '0';
                    {
                        const ov = @mulWithOverflow(result.V6.scope_id, 10);
                        if (ov[1] != 0) return error.Overflow;
                        result.V6.scope_id = ov[0];
                    }
                    {
                        const ov = @addWithOverflow(result.V6.scope_id, digit);
                        if (ov[1] != 0) return error.Overflow;
                        result.V6.scope_id = ov[0];
                    }
                } else {
                    return error.InvalidCharacter;
                }
            } else if (c == ':') {
                if (!saw_any_digits) {
                    if (abbrv) return error.InvalidCharacter; // ':::'
                    if (i != 0) abbrv = true;
                    @memset(ip_slice[index..], 0);
                    ip_slice = tail[0..];
                    index = 0;
                    continue;
                }
                if (index == 14) {
                    return error.InvalidEnd;
                }
                ip_slice[index] = @as(u8, @truncate(x >> 8));
                index += 1;
                ip_slice[index] = @as(u8, @truncate(x));
                index += 1;

                x = 0;
                saw_any_digits = false;
            } else if (c == '%') {
                if (!saw_any_digits) {
                    return error.InvalidCharacter;
                }
                scope_id = true;
                saw_any_digits = false;
            } else if (c == '.') {
                if (!abbrv or ip_slice[0] != 0xff or ip_slice[1] != 0xff) {
                    // must start with '::ffff:'
                    return error.InvalidIpv4Mapping;
                }
                const start_index = std.mem.lastIndexOfScalar(u8, buf[0..i], ':').? + 1;
                const addr = (std.net.Ip4Address.parse(buf[start_index..], 0) catch {
                    return error.InvalidIpv4Mapping;
                }).sa.addr;
                ip_slice = result.V6.ip.octets[0..];
                ip_slice[10] = 0xff;
                ip_slice[11] = 0xff;

                const ptr = std.mem.sliceAsBytes(@as(*const [1]u32, &addr)[0..]);

                ip_slice[12] = ptr[0];
                ip_slice[13] = ptr[1];
                ip_slice[14] = ptr[2];
                ip_slice[15] = ptr[3];
                return result;
            } else {
                const digit = try std.fmt.charToDigit(c, 16);
                {
                    const ov = @mulWithOverflow(x, 16);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                {
                    const ov = @addWithOverflow(x, digit);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                saw_any_digits = true;
            }
        }

        if (!saw_any_digits and !abbrv) {
            return error.Incomplete;
        }
        if (!abbrv and index < 14) {
            return error.Incomplete;
        }

        if (index == 14) {
            ip_slice[14] = @as(u8, @truncate(x >> 8));
            ip_slice[15] = @as(u8, @truncate(x));
            return result;
        } else {
            ip_slice[index] = @as(u8, @truncate(x >> 8));
            index += 1;
            ip_slice[index] = @as(u8, @truncate(x));
            index += 1;
            @memcpy(result.V6.ip.octets[16 - index ..][0..index], ip_slice[0..index]);
            return result;
        }
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
            .V6 = .{ .ip = Ipv6Addr.init(octets), .port = portt, .flowinfo = 0, .scope_id = 0 },
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

    pub fn fromEndpoint(endpoint: network.EndPoint) Self {
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

    pub fn to_hex(self: *const Self, alloc: std.mem.Allocator) ![]const u8 {
        const ipv6_hex = try std.fmt.allocPrint(
            alloc,
            "{s}:{s}:{s}:{s}",
            .{ std.fmt.fmtSliceHexLower(self.octets[0..4]), std.fmt.fmtSliceHexLower(self.octets[4..8]), std.fmt.fmtSliceHexLower(self.octets[8..12]), std.fmt.fmtSliceHexLower(self.octets[12..16]) },
        );
        return ipv6_hex;
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

test "gossip.ipv6 valid ipv6 socket parsing" {
    var address = "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443";
    var ipv6_addr = try SocketAddr.parse(address);

    var alloc = std.testing.allocator;

    var expected_addr = try ipv6_addr.V6.ip.to_hex(alloc);
    defer alloc.free(expected_addr);

    std.debug.print("ipv6 parse_v6: {!s}\nport: {d}", .{ expected_addr, ipv6_addr.port() });
    try std.testing.expect(std.mem.eql(u8, expected_addr, "20010db8:85a308d3:13198a2e:03707348"));
    try std.testing.expectEqual(ipv6_addr.V6.port, 443);
}

test "gossip.ipv6 invalid ipv6 socket parsing" {
    {
        var address = "[fe80:2030:31:24]:8080";

        var ipv6_addr = SocketAddr.parse(address);

        try std.testing.expectError(error.Incomplete, ipv6_addr);
    }
    {
        var address = "fe80:2030:31:24]:8080";

        var ipv6_addr = SocketAddr.parse(address);

        try std.testing.expectError(error.Incomplete, ipv6_addr);
    }
    {
        var address = "[fe80:2030:31:24:8080";
        var ipv6_addr = SocketAddr.parse(address);

        try std.testing.expectError(error.Incomplete, ipv6_addr);
    }
}

test "gossip.net: test random" {
    var rng = std.rand.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    var addr = SocketAddr.random(rng.random());
    _ = addr;
}
