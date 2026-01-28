const std = @import("std");
const builtin = @import("builtin");

const posix = std.posix;

pub const AddressFamily = enum(u32) {
    ipv4 = posix.AF.INET,
    ipv6 = posix.AF.INET6,

    fn fromNativeAddressFamily(domain: u32) ?AddressFamily {
        return std.meta.intToEnum(AddressFamily, domain) catch null;
    }

    fn toNativeAddressFamily(family: AddressFamily) u32 {
        return @intFromEnum(family);
    }
};

pub const UdpSocket = struct {
    family: AddressFamily,
    handle: posix.socket_t,

    pub fn create(family: AddressFamily) !UdpSocket {
        const socket_type = posix.SOCK.DGRAM | posix.SOCK.CLOEXEC;
        return .{
            .family = family,
            .handle = try posix.socket(family.toNativeAddressFamily(), socket_type, 0),
        };
    }

    pub fn close(self: *const UdpSocket) void {
        posix.close(self.handle);
    }

    pub fn bind(self: *const UdpSocket, endpoint: std.net.Address) posix.BindError!void {
        try posix.bind(
            self.handle,
            &endpoint.any,
            endpoint.getOsSockLen(),
        );
    }

    pub fn bindToPort(self: *const UdpSocket, port: u16) posix.BindError!void {
        return switch (self.family) {
            .ipv4 => try self.bind(.initIp4(@splat(0), port)),
            .ipv6 => try self.bind(.initIp6(@splat(0), port, 0, 0)),
        };
    }

    pub fn setReadTimeout(self: *const UdpSocket, read: ?u32) posix.SetSockOptError!void {
        std.debug.assert(read == null or read.? != 0);
        const micros = read orelse 0;
        const opt: posix.timeval = .{
            .sec = @intCast(@divTrunc(micros, std.time.us_per_s)),
            .usec = @intCast(@mod(micros, std.time.us_per_s)),
        };
        try posix.setsockopt(
            self.handle,
            posix.SOL.SOCKET,
            posix.SO.RCVTIMEO,
            std.mem.asBytes(&opt),
        );
    }

    pub fn receive(self: *const UdpSocket, data: []u8) posix.RecvFromError!usize {
        return try posix.recvfrom(self.handle, data, 0, null, null);
    }

    pub fn receiveFrom(
        self: *const UdpSocket,
        data: []u8,
    ) posix.RecvFromError!struct { usize, std.net.Address } {
        // Use the ipv6 sockaddr to guarantee data will fit.
        var addr: posix.sockaddr.in6 = undefined;
        var size: posix.socklen_t = @sizeOf(posix.sockaddr.in6);
        const addr_ptr: *posix.sockaddr = @ptrCast(&addr);
        const len = try posix.recvfrom(self.handle, data, 0, addr_ptr, &size);
        return .{ len, .{ .in6 = .{ .sa = addr } } };
    }

    pub fn sendTo(
        self: *const UdpSocket,
        receiver: std.net.Address,
        data: []const u8,
    ) posix.SendToError!usize {
        const flags = switch (builtin.target.os.tag) {
            .linux => posix.MSG.NOSIGNAL,
            else => 0,
        };
        return try posix.sendto(
            self.handle,
            data,
            flags,
            &receiver.any,
            receiver.getOsSockLen(),
        );
    }

    pub fn enablePortReuse(sock: *const UdpSocket, enabled: bool) !void {
        const opt: c_int = if (enabled) 1 else 0;
        try posix.setsockopt(
            sock.handle,
            posix.SOL.SOCKET,
            posix.SO.REUSEPORT,
            std.mem.asBytes(&opt),
        );
    }

    /// Retrieves the end point to which the socket is bound.
    pub fn getLocalEndPoint(self: *const UdpSocket) !std.net.Address {
        var addr: posix.sockaddr.in6 align(4) = undefined;
        var size: posix.socklen_t = @sizeOf(posix.sockaddr.in6);

        const src: *posix.sockaddr = @ptrCast(&addr);
        try posix.getsockname(self.handle, src, &size);

        const family = AddressFamily.fromNativeAddressFamily(src.family) orelse
            return error.UnsupportedAddressFamily;
        switch (family) {
            .ipv4 => {
                const value: *align(4) const posix.sockaddr.in = @ptrCast(@alignCast(src));
                return .initIp4(
                    @bitCast(value.addr),
                    std.mem.bigToNative(u16, value.port),
                );
            },
            .ipv6 => {
                const value: *align(4) const posix.sockaddr.in6 = @ptrCast(@alignCast(src));
                return .initIp6(
                    value.addr,
                    std.mem.bigToNative(u16, value.port),
                    value.flowinfo,
                    value.scope_id,
                );
            },
        }
    }
};

pub const SocketAddr = union(enum(u8)) {
    V4: SocketAddrV4,
    V6: SocketAddrV6,

    pub const UNSPECIFIED: SocketAddr = .{ .V4 = .{
        .ip = .{ .octets = .{ 0, 0, 0, 0 } },
        .port = 0,
    } };

    pub fn init(addr: IpAddr, portt: u16) SocketAddr {
        return switch (addr) {
            .ipv4 => |ipv4| .{ .V4 = .{ .ip = ipv4, .port = portt } },
            .ipv6 => |ipv6| .{ .V6 = .{
                .ip = ipv6,
                .port = portt,
                .flowinfo = 0,
                .scope_id = 0,
            } },
        };
    }

    pub fn initAddress(ip_addr: std.net.Address) SocketAddr {
        return switch (ip_addr.any.family) {
            posix.AF.INET => .{ .V4 = .{
                .ip = .init(@bitCast(ip_addr.in.sa.addr)),
                .port = ip_addr.getPort(),
            } },
            posix.AF.INET6 => .{ .V6 = .{
                .ip = .init(ip_addr.in6.sa.addr),
                .port = ip_addr.getPort(),
                .flowinfo = ip_addr.in6.sa.flowinfo,
                .scope_id = ip_addr.in6.sa.scope_id,
            } },
            else => unreachable,
        };
    }

    pub fn toAddress(self: SocketAddr) std.net.Address {
        return switch (self) {
            .V4 => |a| .initIp4(a.ip.octets, a.port),
            .V6 => |a| .initIp6(a.ip.octets, a.port, a.flowinfo, a.scope_id),
        };
    }

    pub fn initIpv4(octets: [4]u8, portt: u16) SocketAddr {
        return .{ .V4 = .{
            .ip = .init(octets),
            .port = portt,
        } };
    }

    pub fn initIpv6(octets: [16]u8, portt: u16) SocketAddr {
        return .{ .V6 = .{
            .ip = .init(octets),
            .port = portt,
            .flowinfo = 0,
            .scope_id = 0,
        } };
    }

    pub fn getPort(self: *const SocketAddr) u16 {
        return switch (self.*) {
            .V4 => |v4| v4.port,
            .V6 => |v6| v6.port,
        };
    }

    pub fn ip(self: *const SocketAddr) IpAddr {
        return switch (self.*) {
            .V4 => |a| .initIpv4(a.ip.octets),
            .V6 => |a| .initIpv6(a.ip.octets),
        };
    }

    pub fn eql(self: *const SocketAddr, other: *const SocketAddr) bool {
        if (self.* != std.meta.activeTag(other.*)) return false;
        return switch (self.*) {
            .V4 => |self_v4| self_v4.port == other.V4.port and self_v4.ip.eql(&other.V4.ip),
            .V6 => |self_v6| self_v6.port == other.V6.port and self_v6.ip.eql(&other.V6.ip),
        };
    }

    pub fn setPort(self: *SocketAddr, portt: u16) void {
        switch (self.*) {
            .V4 => |*v4| v4.port = portt,
            .V6 => |*v6| v6.port = portt,
        }
    }

    pub fn isUnspecified(self: *const SocketAddr) bool {
        return switch (self.*) {
            .V4 => |addr| std.mem.readInt(u32, &addr.ip.octets, .big) == 0,
            .V6 => |addr| std.mem.readInt(u128, &addr.ip.octets, .big) == 0,
        };
    }

    pub fn isMulticast(self: *const SocketAddr) bool {
        return switch (self.*) {
            .V4 => |addr| addr.ip.octets[0] >= 224 and addr.ip.octets[0] <= 239,
            .V6 => |addr| addr.ip.isMulticast(),
        };
    }

    pub fn sanitize(socket: *const SocketAddr) !void {
        if (socket.getPort() == 0) {
            return error.InvalidPort;
        }
        if (socket.isUnspecified()) {
            return error.UnspecifiedAddress;
        }
        if (socket.isMulticast()) {
            return error.MulticastAddress;
        }
    }

    pub const ParseIpError = error{InvalidIp};
    pub fn parse(bytes: []const u8) ParseIpError!SocketAddr {
        return parseIpv4(bytes) catch parseIpv6(bytes) catch error.InvalidIp;
    }

    pub const ParseIpv6Error = error{InvalidIpv6};
    pub fn parseIpv6(bytes: []const u8) ParseIpv6Error!SocketAddr {
        // https://ratfactor.com/zig/stdlib-browseable2/net.zig.html
        // ports with IPv6 are after square brackets, but stdlib has IPv6 parsing on only the address
        // so exploit stdlib for that portion, and parse the port afterwards.

        var maybe_address: ?std.net.Ip6Address = null;
        var portt: u16 = 0;
        const maybe_right_bracket_index = std.mem.indexOf(u8, bytes, &[_]u8{']'});
        const maybe_left_bracket_index = std.mem.indexOf(u8, bytes, &[_]u8{'['});
        // right_bracket_index + 2 should be less than the total length of bytes in order to proceed. Why?
        // Because if the string is [2001::1]:8000, then right_bracket_index would be 8, and 10 would be the start of the port
        //                          ~~~~~~~^++ <-- this is index + 2
        if (maybe_right_bracket_index) |right_bracket_index| {
            if (maybe_left_bracket_index) |left_bracket_index| {
                const addr_str = bytes[left_bracket_index + 1 .. right_bracket_index];
                var addr = std.net.Ip6Address.parse(addr_str, 0) catch
                    return error.InvalidIpv6;
                portt = std.fmt.parseUnsigned(u16, bytes[right_bracket_index + 2 ..], 10) catch
                    return error.InvalidIpv6;
                addr.setPort(portt);
                maybe_address = addr;
            }
        } else {
            maybe_address = std.net.Ip6Address.parse(bytes, 0) catch return error.InvalidIpv6;
        }

        if (maybe_address) |address| {
            return .{ .V6 = .{
                .ip = Ipv6Addr.init(address.sa.addr),
                .port = address.getPort(),
                .scope_id = address.sa.scope_id,
                .flowinfo = address.sa.flowinfo,
            } };
        } else {
            return error.InvalidIpv6;
        }
    }

    pub const ParseIpv4Error = error{InvalidIpv4};
    pub fn parseIpv4(bytes: []const u8) ParseIpv4Error!SocketAddr {
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

        return .{ .V4 = .{
            .ip = Ipv4Addr.init(octs),
            .port = addr_port,
        } };
    }

    pub fn toStringBuf(self: SocketAddr, buf: *[53]u8) std.math.IntFittingRange(0, 53) {
        var stream = std.io.fixedBufferStream(buf);
        self.toAddress().format("", .{}, stream.writer()) catch unreachable;
        return @intCast(stream.pos);
    }

    pub fn format(
        self: SocketAddr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .V4 => |sav4| try sav4.format(fmt, options, writer),
            .V6 => |sav6| try sav6.format(fmt, options, writer),
        }
    }

    pub fn initRandom(random: std.Random) SocketAddr {
        const pport = random.int(u16);

        const version = random.int(u8);
        if (version % 2 == 0) {
            var octets: [4]u8 = undefined;
            random.bytes(&octets);
            return .{ .V4 = .{
                .ip = Ipv4Addr.init(octets),
                .port = pport,
            } };
        } else {
            var octets: [16]u8 = undefined;
            random.bytes(&octets);
            return .{ .V6 = .{
                .ip = Ipv6Addr.init(octets),
                .port = pport,
                .flowinfo = 0,
                .scope_id = 0,
            } };
        }
    }
};

pub const SocketAddrV4 = struct {
    ip: Ipv4Addr,
    port: u16,

    pub fn format(
        self: SocketAddrV4,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
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

    pub fn format(
        self: SocketAddrV6,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
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

    pub fn init(octets: [4]u8) Ipv4Addr {
        return .{ .octets = octets };
    }

    pub fn eql(self: *const Ipv4Addr, other: *const Ipv4Addr) bool {
        return std.mem.eql(u8, self.octets[0..], other.octets[0..]);
    }

    pub fn format(
        self: Ipv4Addr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
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

    pub fn init(octets: [16]u8) Ipv6Addr {
        return .{
            .octets = octets,
        };
    }

    pub fn eql(self: *const Ipv6Addr, other: *const Ipv6Addr) bool {
        return std.mem.eql(u8, &self.octets, &other.octets);
    }

    /// defined in https://tools.ietf.org/html/rfc4291
    pub fn isMulticast(self: *const Ipv6Addr) bool {
        return self.octets[0] == 255;
    }

    pub fn format(
        self: Ipv6Addr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        if (std.mem.eql(
            u8,
            self.octets[0..12],
            &[12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff },
        )) {
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
            .big => big_endian_parts.*,
            .little => blk: {
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

    pub fn initIpv4(octets: [4]u8) IpAddr {
        return .{ .ipv4 = .init(octets) };
    }

    pub fn initIpv6(octets: [16]u8) IpAddr {
        return .{ .ipv6 = .init(octets) };
    }

    pub const ParseIpError = ParseIpv4Error || ParseIpv6Error;

    pub fn parse(bytes: []const u8) ParseIpError!IpAddr {
        if (std.mem.indexOfScalar(u8, bytes, '.')) |_| {
            // Probably IPv4.
            return parseIpv4(bytes);
        } else {
            // Probably IPv6.
            return parseIpv6(bytes);
        }
    }

    pub const ParseIpv4Error = std.net.IPv4ParseError || error{UnexpectedPort};

    pub fn parseIpv4(bytes: []const u8) ParseIpv4Error!IpAddr {
        if (std.mem.indexOfScalar(u8, bytes, ':')) |_| {
            return error.UnexpectedPort;
        }
        const address = try std.net.Ip4Address.parse(bytes, 0);
        return IpAddr{ .ipv4 = Ipv4Addr.init(@bitCast(address.sa.addr)) };
    }

    pub const ParseIpv6Error = std.net.IPv6ParseError || error{UnexpectedPort};

    pub fn parseIpv6(bytes: []const u8) ParseIpv6Error!IpAddr {
        if (std.mem.indexOfScalar(u8, bytes, ']')) |_| {
            return error.UnexpectedPort;
        }
        const address = try std.net.Ip6Address.parse(bytes, 0);
        return IpAddr{ .ipv6 = Ipv6Addr.init(address.sa.addr) };
    }

    pub fn eql(self: *const IpAddr, other: *const IpAddr) bool {
        return switch (self.*) {
            .ipv4 => |ip| switch (other.*) {
                .ipv4 => |other_ip| std.mem.eql(u8, ip.octets[0..], other_ip.octets[0..]),
                else => false,
            },
            .ipv6 => |ip| switch (other.*) {
                .ipv6 => |other_ip| std.mem.eql(u8, ip.octets[0..], other_ip.octets[0..]),
                else => false,
            },
        };
    }

    pub fn format(
        self: IpAddr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .ipv4 => |ipv4| try ipv4.format(fmt, options, writer),
            .ipv6 => |ipv6| try ipv6.format(fmt, options, writer),
        }
    }
};

pub fn resolveSocketAddr(allocator: std.mem.Allocator, host_and_port: []const u8) !SocketAddr {
    const domain_port_sep = std.mem.indexOfScalar(u8, host_and_port, ':') orelse {
        return error.PortMissing;
    };
    const domain_str = host_and_port[0..domain_port_sep];
    if (domain_str.len == 0) {
        return error.DomainNotValid;
    }
    // parse port from string
    const port = std.fmt.parseInt(u16, host_and_port[domain_port_sep + 1 ..], 10) catch {
        return error.PortNotValid;
    };

    // get dns address lists
    const addr_list = try std.net.getAddressList(allocator, domain_str, port);
    defer addr_list.deinit();

    if (addr_list.addrs.len == 0) {
        return error.DnsResolutionFailure;
    }

    // use first A record address
    const ipv4_addr = addr_list.addrs[0];

    const socket_addr: SocketAddr = .initAddress(ipv4_addr);
    std.debug.assert(socket_addr.getPort() == port);
    return socket_addr;
}

test "invalid ipv4 socket parsing" {
    {
        const addr = "127.0.0.11234";
        const result = SocketAddr.parseIpv4(addr);
        try std.testing.expectError(error.InvalidIpv4, result);
    }
    {
        const addr = "127.0.0:1123";
        const result = SocketAddr.parseIpv4(addr);
        try std.testing.expectError(error.InvalidIpv4, result);
    }
}

test "valid ipv4 socket parsing" {
    const addr = "127.0.0.1:1234";
    const expected_addr = SocketAddr{ .V4 = SocketAddrV4{
        .ip = Ipv4Addr.init(.{ 127, 0, 0, 1 }),
        .port = 1234,
    } };
    const actual_addr = try SocketAddr.parseIpv4(addr);
    try std.testing.expectEqual(expected_addr, actual_addr);
}

test "SocketAddr.initRandom" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const addr = SocketAddr.initRandom(prng.random());
    _ = addr;
}

test "set port works" {
    var sa1 = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 1000);
    sa1.setPort(1001);
    try std.testing.expectEqual(@as(u16, 1001), sa1.getPort());
}

test "parse IPv6 if IPv4 fails" {
    try std.testing.expectError(
        error.InvalidIp,
        SocketAddr.parse("[FE38:DCEq:124C:C1A2:BA03:6745:EF1C:683D]:8000"),
    );

    try std.testing.expectError(
        error.InvalidIp,
        SocketAddr.parse("[FE38:DCEE:124C:C1A2:BA03:6745:EF1C:683D]:"),
    );

    {
        const sa = try SocketAddr.parse("[FE38:DCE3:124C:C1A2:BA03:6745:EF1C:683D]:8000");
        const expected = SocketAddr.initIpv6(
            .{
                '\xFE', '\x38', '\xDC', '\xE3',
                '\x12', '\x4C', '\xC1', '\xA2',
                '\xBA', '\x03', '\x67', '\x45',
                '\xEF', '\x1C', '\x68', '\x3D',
            },
            @as(u16, 8000),
        );

        try std.testing.expectEqual(sa.V6, expected.V6);
    }

    {
        const sa = try SocketAddr.parse("[::1]:1234");
        const expected = SocketAddr.initIpv6(.{
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, '\x01',
        }, @as(u16, 1234));
        try std.testing.expectEqual(sa.V6, expected.V6);
    }

    {
        const sa = try SocketAddr.parse("[2001:0df8:00f2::06ee:0:0f11]:6500");
        const expected = SocketAddr.initIpv6(.{
            '\x20', '\x01', '\x0D', '\xF8',
            0,      '\xF2', 0,      0,
            0,      0,      '\x06', '\xEE',
            0,      0,      '\x0F', '\x11',
        }, @as(u16, 6500));
        try std.testing.expectEqual(sa.V6, expected.V6);
    }

    {
        const sa = try SocketAddr.parse("2001:0df8:00f2::06ee:0:0f11");
        const expected = SocketAddr.initIpv6(.{
            '\x20', '\x01', '\x0D', '\xF8',
            0,      '\xF2', 0,      0,
            0,      0,      '\x06', '\xEE',
            0,      0,      '\x0F', '\x11',
        }, @as(u16, 0));
        try std.testing.expectEqual(sa.V6, expected.V6);
    }
}

test "valid ipv4 address without port parsing" {
    const addr = "127.0.0.1";
    const expected_addr = IpAddr{ .ipv4 = Ipv4Addr.init(.{ 127, 0, 0, 1 }) };
    const actual_addr = try IpAddr.parseIpv4(addr);
    try std.testing.expectEqual(expected_addr, actual_addr);
}

test "valid ipv4 address with port inclusion parsing" {
    const addr = "127.0.0.1:1234";
    const result = IpAddr.parseIpv4(addr);
    try std.testing.expectError(error.UnexpectedPort, result);
}

test "invalid ipv4 address without port parsing" {
    const addr = "127.0.01";
    const result = IpAddr.parseIpv4(addr);
    try std.testing.expectError(error.NonCanonical, result);
}

test "valid ipv6 address without port parsing" {
    const addr = try IpAddr.parseIpv6("FE38:DCE3:124C:C1A2:BA03:6745:EF1C:683D");
    const expected = IpAddr{ .ipv6 = Ipv6Addr.init(.{
        '\xFE', '\x38', '\xDC', '\xE3',
        '\x12', '\x4C', '\xC1', '\xA2',
        '\xBA', '\x03', '\x67', '\x45',
        '\xEF', '\x1C', '\x68', '\x3D',
    }) };

    try std.testing.expectEqual(addr, expected);
}

test "invalid ipv6 address with port inclusion parsing" {
    const addr = "[FE38:DCE3:124C:C1A2:BA03:6745:EF1C:683D]:8000";
    const result = IpAddr.parseIpv6(addr);
    try std.testing.expectError(error.UnexpectedPort, result);
}

test "invalid ipv6 address without port parsing" {
    try std.testing.expectError(
        error.InvalidCharacter,
        IpAddr.parseIpv6("FE38:DCEq:124C:C1A2:BA03:6745:EF1C683D"),
    );
}

test "parse IPv6 addreess if IPv4 address fails" {
    {
        const addr = try IpAddr.parse("127.0.0.1");
        const expected: IpAddr = .{ .ipv4 = Ipv4Addr.init(.{ 127, 0, 0, 1 }) };
        try std.testing.expectEqual(addr.ipv4, expected.ipv4);
    }

    {
        const addr = try IpAddr.parse("FE38:DCE3:124C:C1A2:BA03:6745:EF1C:683D");
        const expected: IpAddr = .{ .ipv6 = Ipv6Addr.init(.{
            '\xFE', '\x38', '\xDC', '\xE3',
            '\x12', '\x4C', '\xC1', '\xA2',
            '\xBA', '\x03', '\x67', '\x45',
            '\xEF', '\x1C', '\x68', '\x3D',
        }) };

        try std.testing.expectEqual(addr.ipv6, expected.ipv6);
    }

    {
        const addr = try IpAddr.parse("::1");
        const expected: IpAddr = .{ .ipv6 = Ipv6Addr.init(.{
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, '\x01',
        }) };

        try std.testing.expectEqual(addr.ipv6, expected.ipv6);
    }

    {
        const addr = try IpAddr.parse("2001:0df8:00f2::06ee:0:0f11");
        const expected: IpAddr = .{ .ipv6 = Ipv6Addr.init(.{
            '\x20', '\x01', '\x0D', '\xF8',
            0,      '\xF2', 0,      0,
            0,      0,      '\x06', '\xEE',
            0,      0,      '\x0F', '\x11',
        }) };
        try std.testing.expectEqual(addr.ipv6, expected.ipv6);
    }

    {
        try std.testing.expectEqual(
            IpAddr.initIpv6(.{
                '\x20', '\x01', '\x0D', '\xF8',
                0,      '\xF2', 0,      0,
                0,      0,      '\x06', '\xEE',
                0,      0,      '\x0F', '\x11',
            }),
            IpAddr.parse("2001:0df8:00f2::06ee:0:0f11"),
        );
    }
}
