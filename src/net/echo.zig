const std = @import("std");
const Net = @import("zig-network");
const net = @import("net.zig");
const ShredVersion = @import("../core/shred.zig").ShredVersion;
const assert = std.debug.assert;

const MAX_PORT_COUNT_PER_MSG: usize = 4;

const IpEchoServerMessage = struct {
    tcp_ports: [MAX_PORT_COUNT_PER_MSG]u16,
    udp_ports: [MAX_PORT_COUNT_PER_MSG]u16,

    const Self = @This();

    pub fn init(tcp_ports: []u16, udp_ports: []u16) Self {
        assert(tcp_ports.len <= MAX_PORT_COUNT_PER_MSG and udp_ports.len <= MAX_PORT_COUNT_PER_MSG);
        var self = Self{
            .tcp_ports = [_]u16{0} ** MAX_PORT_COUNT_PER_MSG,
            .udp_ports = [_]u16{0} ** MAX_PORT_COUNT_PER_MSG,
        };

        std.mem.copyForwards(u16, &self.tcp_ports, tcp_ports);
        std.mem.copyForwards(u16, &self.udp_ports, udp_ports);

        return self;
    }
};

const IpEchoServerResponse = struct {
    // Public IP address of request echoed back to the node.
    address: net.IpAddr,
    // Cluster shred-version of the node running the server.
    shred_version: ?ShredVersion,

    const Self = @This();

    pub fn init(addr: net.IpAddr) Self {
        return Self{
            .address = addr,
            .shred_version = ShredVersion.init_manually_set(0),
        };
    }
};

const IpEchoServer = struct {
    listener: Net.Socket,

    const Self = @This();

    pub fn init() Self {
        var socket = net.Socket.create(.ipv4, Net.Protocol.tcp) catch @panic("could not create Socket!");
        return Self{
            .listener = socket,
        };
    }

    pub fn listen(self: *Self, port: u16) !void {
        try self.listener.bindToPort(port);
    }
};
