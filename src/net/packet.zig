const network = @import("zig-network");

/// Maximum over-the-wire size of a Transaction
///   1280 is IPv6 minimum MTU
///   40 bytes is the size of the IPv6 header
///   8 bytes is the size of the fragment header
pub const PACKET_DATA_SIZE: usize = 1232;

pub const Packet = struct {
    data: [PACKET_DATA_SIZE]u8,
    size: usize,
    addr: network.EndPoint,
    flags: u8 = 0,

    const Self = @This();

    pub fn init(addr: network.EndPoint, data: [PACKET_DATA_SIZE]u8, size: usize) Self {
        return .{
            .addr = addr,
            .data = data,
            .size = size,
        };
    }

    pub fn default() Self {
        return .{
            .addr = .{ .port = 0, .address = .{ .ipv4 = network.Address.IPv4.any } },
            .data = undefined,
            .size = 0,
        };
    }

    pub fn set(self: *Self, flag: Flag) void {
        self.flags |= @intFromEnum(flag);
    }

    pub fn isSet(self: *const Self, flag: Flag) bool {
        return self.flags & @intFromEnum(flag) == @intFromEnum(flag);
    }
};

/// TODO this violates separation of concerns. it's unusual for network-specific
/// type definitions to include information that's specific to application
/// components (like repair)
///
/// it would be nice to find another approach that is equally easy to use,
/// without sacrificing safety, performance, or readability.
pub const Flag = enum(u8) {
    discard = 0b0000_0001,
    // forwarded = 0b0000_0010,
    repair = 0b0000_0100,
    // simple_vote_tx = 0b0000_1000,
    // tracer_packet = 0b0001_0000,
    // round_compute_unit_price = 0b0010_0000,
};
