const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");

const BitFlags = sig.utils.bitflags.BitFlags;

pub const Packet = struct {
    buffer: [DATA_SIZE]u8,
    size: usize,
    addr: network.EndPoint,
    flags: Flags,

    pub const Flags = BitFlags(Flag);

    /// Maximum over-the-wire size of a Transaction
    ///   1280 is IPv6 minimum MTU
    ///   40 bytes is the size of the IPv6 header
    ///   8 bytes is the size of the fragment header
    pub const DATA_SIZE: usize = 1232;

    pub const ANY_EMPTY: Packet = .{
        .addr = .{ .port = 0, .address = .{ .ipv4 = network.Address.IPv4.any } },
        .buffer = .{0} ** DATA_SIZE,
        .size = 0,
        .flags = .{},
    };

    pub fn init(
        addr: network.EndPoint,
        data_init: [DATA_SIZE]u8,
        size: usize,
    ) Packet {
        return .{
            .addr = addr,
            .buffer = data_init,
            .size = size,
            .flags = .{},
        };
    }

    pub fn initFromBincode(
        maybe_dest: ?sig.net.SocketAddr,
        bincodable_data: anytype,
    ) !Packet {
        var result: Packet = ANY_EMPTY;
        try result.populateFromBincode(maybe_dest, bincodable_data);
        return result;
    }

    pub fn populateFromBincode(
        self: *Packet,
        maybe_dest: ?sig.net.SocketAddr,
        bincodable_data: anytype,
    ) !void {
        var fbs = std.io.fixedBufferStream(&self.buffer);
        try sig.bincode.write(fbs.writer(), bincodable_data, .{});
        self.size = fbs.pos;
        if (maybe_dest) |dest| {
            self.addr = dest.toEndpoint();
        }
    }

    pub fn data(self: *const Packet) []const u8 {
        return self.buffer[0..self.size];
    }

    pub fn dataMut(self: *Packet) []u8 {
        return self.buffer[0..self.size];
    }
};

/// TODO this violates separation of concerns. it's unusual for network-specific
/// type definitions to include information that's specific to application
/// components (like repair)
///
/// it would be nice to find another approach that is equally easy to use,
/// without sacrificing safety, performance, or readability.
pub const Flag = enum(u8) {
    // forwarded = 0b0000_0010,
    repair = 0b0000_0100,
    // simple_vote_tx = 0b0000_1000,
    // tracer_packet = 0b0001_0000,
    // round_compute_unit_price = 0b0010_0000,
};
