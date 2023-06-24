const std = @import("std");
const network = @import("zig-network");

pub const PACKET_DATA_SIZE: usize = 1232;

pub const Packet = struct {
    from: network.EndPoint,
    size: usize,
    data: [PACKET_DATA_SIZE]u8,

    const Self = @This();

    pub fn init(from: network.EndPoint, data: [PACKET_DATA_SIZE]u8, size: usize) Self {
        var self = Self{
            .from = from,
            .data = data,
            .size = size,
        };
        return self;
    }
};
