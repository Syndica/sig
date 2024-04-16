const std = @import("std");
const network = @import("zig-network");
const builtin = @import("builtin");

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

    pub fn init(addr: IpAddr, portt: u16) Self {
        return switch (addr) {
            .ipv4 => |ipv4| .{ .V4 = .{ .ip = ipv4, .port = portt } },
            .ipv6 => |ipv6| .{
                .V6 = .{
                    .ip = ipv6,
                    .port = portt,
                    .flowinfo = 0,
                    .scope_id = 0,
                },
            },
        };
    }

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

    pub fn toAddress(self: Self) std.net.Address {
        return switch (self) {
            .V4 => |a| std.net.Address.initIp4(a.ip.octets, a.port),
            .V6 => |a| std.net.Address.initIp6(a.ip.octets, a.port, a.flowinfo, a.scope_id),
        };
    }

    pub fn fromIpV4Address(address: std.net.Address) Self {
        return Self.initIpv4(.{
            @as(u8, @intCast(address.in.sa.addr & 0xFF)),
            @as(u8, @intCast(address.in.sa.addr >> 8 & 0xFF)),
            @as(u8, @intCast(address.in.sa.addr >> 16 & 0xFF)),
            @as(u8, @intCast(address.in.sa.addr >> 24 & 0xFF)),
        }, address.getPort());
    }

    pub fn setPort(self: *Self, portt: u16) void {
        switch (self.*) {
            .V4 => |*v4| v4.port = portt,
            .V6 => |*v6| v6.port = portt,
        }
    }

    /// returns:
    /// - array: the string, plus some extra bytes at the end
    /// - integer: length of the string within the array
    pub fn toString(self: Self) struct { [53]u8, usize } {
        var buf: [53]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        self.toAddress().format("", .{}, stream.writer()) catch unreachable;
        return .{ buf, stream.pos };
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

    pub fn sanitize(socket: *const Self) !void {
        if (socket.port() == 0) {
            return error.InvalidPort;
        }
        if (socket.isUnspecified()) {
            return error.UnspecifiedAddress;
        }
        if (socket.isMulticast()) {
            return error.MulticastAddress;
        }
    }

    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        switch (self) {
            .V4 => |sav4| try sav4.format(fmt, options, writer),
            .V6 => |sav6| try sav6.format(fmt, options, writer),
        }
    }
};

pub const SocketAddrV4 = struct {
    ip: Ipv4Addr,
    port: u16,

    const Self = @This();

    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("{}:{d}", .{
            self.ip,
            self.port,
        });
    }
};

pub const SocketAddrV6 = struct {
    ip: Ipv6Addr,
    port: u16,
    flowinfo: u32,
    scope_id: u32,

    const Self = @This();

    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("{}:{d}", .{
            self.ip,
            self.port,
        });
    }
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

    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("{}.{}.{}.{}", .{
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
        });
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
        return std.mem.eql(u8, &self.octets, &other.octets);
    }

    /// defined in https://tools.ietf.org/html/rfc4291
    pub fn isMulticast(self: *const Self) bool {
        return self.octets[0] == 255;
    }

    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        if (std.mem.eql(u8, self.octets[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
            try std.fmt.format(writer, "[::ffff:{}.{}.{}.{}]", .{
                self.octets[12],
                self.octets[13],
                self.octets[14],
                self.octets[15],
            });
            return;
        }
        const big_endian_parts: *align(1) const [8]u16 = @ptrCast(&self.octets);
        const native_endian_parts = switch (builtin.target.cpu.arch.endian()) {
            .Big => big_endian_parts.*,
            .Little => blk: {
                var buf: [8]u16 = undefined;
                for (big_endian_parts, 0..) |part, i| {
                    buf[i] = std.mem.bigToNative(u16, part);
                }
                break :blk buf;
            },
        };
        try writer.writeAll("[");
        var i: usize = 0;
        var abbrv = false;
        while (i < native_endian_parts.len) : (i += 1) {
            if (native_endian_parts[i] == 0) {
                if (!abbrv) {
                    try writer.writeAll(if (i == 0) "::" else ":");
                    abbrv = true;
                }
                continue;
            }
            try std.fmt.format(writer, "{x}", .{native_endian_parts[i]});
            if (i != native_endian_parts.len - 1) {
                try writer.writeAll(":");
            }
        }
        try writer.writeAll("]");
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

    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        switch (self) {
            .ipv4 => |ipv4| try ipv4.format(fmt, options, writer),
            .ipv6 => |ipv6| try ipv6.format(fmt, options, writer),
        }
    }
};

pub fn endpointToString(allocator: std.mem.Allocator, endpoint: *const network.EndPoint) error{OutOfMemory}!std.ArrayList(u8) {
    var endpoint_buf = try std.ArrayList(u8).initCapacity(allocator, 14);
    try endpoint.format(&[_]u8{}, std.fmt.FormatOptions{}, endpoint_buf.writer());
    return endpoint_buf;
}

/// Socket.enablePortReuse does not actually enable SO_REUSEPORT. It sets SO_REUSEADDR.
/// This is the correct implementation to enable SO_REUSEPORT.
pub fn enablePortReuse(sock: *network.Socket, enabled: bool) !void {
    const setsockopt_fn = if (builtin.os.tag == .windows) @panic("windows not supported") else std.os.setsockopt; // TODO windows
    var opt: c_int = if (enabled) 1 else 0;
    try setsockopt_fn(sock.internal, std.os.SOL.SOCKET, std.os.SO.REUSEPORT, std.mem.asBytes(&opt));
}

test "net.net: invalid ipv4 socket parsing" {
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

test "net.net: valid ipv4 socket parsing" {
    var addr = "127.0.0.1:1234";
    var expected_addr = SocketAddr{ .V4 = SocketAddrV4{
        .ip = Ipv4Addr.init(127, 0, 0, 1),
        .port = 1234,
    } };
    var actual_addr = try SocketAddr.parseIpv4(addr);
    try std.testing.expectEqual(expected_addr, actual_addr);
}

test "net.net: test random" {
    var rng = std.rand.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    var addr = SocketAddr.random(rng.random());
    _ = addr;
}

test "net.net: set port works" {
    var sa1 = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    sa1.setPort(1001);
    try std.testing.expectEqual(@as(u16, 1001), sa1.port());
}
