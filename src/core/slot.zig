const std = @import("std");
const testing = std.testing;
const bincode = @import("../bincode/bincode.zig");

pub const Slot = u64;

const logger = std.log.scoped(.slot_tests);

test "core.Slot: slot bincode serializes properly" {
    var rust_serialized = [_]u8{ 239, 16, 0, 0, 0, 0, 0, 0 };
    var slot: Slot = 4335;
    var buf = [_]u8{0} ** 1024;
    var ser = try bincode.writeToSlice(buf[0..], slot, bincode.Params.standard);

    try testing.expect(std.mem.eql(u8, ser, rust_serialized[0..]));
}
