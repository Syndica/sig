const std = @import("std");
test "asd" {
    var buf: [100]u8 = @splat(0);
    try std.base64.standard.Decoder.decode(&buf, "abbreviateo=");
    try std.base64.standard.Decoder.decode(&buf, "vKjHmRkP+co=");
    std.debug.print("{any}\n", .{&buf});
    _ = std.base64.standard.Encoder.encode(&buf, &.{ 105, 182, 235, 122, 248, 154, 181, 234 });
    // _ = std.base64.standard.Encoder.encode(&buf, &.{ 105, 182, 239, 110, 38, 218, 181, 231 });

    std.debug.print("{s}\n", .{&buf});
}
