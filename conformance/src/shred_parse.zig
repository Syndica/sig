const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");

const Shred = sig.ledger.shred.Shred;
const ShredBinary = pb.ShredBinary;
const AcceptsShred = pb.AcceptsShred;

export fn sol_compat_shred_parse_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    // var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 100 }){};
    // defer _ = gpa.deinit();
    // const allocator = gpa.allocator();
    const allocator = std.heap.c_allocator;

    const in_slice = in_ptr[0..in_size];
    var reader: std.Io.Reader = .fixed(in_slice);
    var shred_binary = ShredBinary.decode(&reader, allocator) catch return 0;
    defer shred_binary.deinit(allocator);

    const shred = Shred.fromPayload(allocator, shred_binary.data) catch null;
    defer if (shred) |s| s.deinit();

    var result: AcceptsShred = .{ .valid = shred != null };
    defer result.deinit(allocator);

    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try result.encode(&writer.writer, allocator);
    const result_bytes = writer.written();

    const out_slice = out_ptr[0..out_size.*];
    if (result_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..result_bytes.len], result_bytes);
    out_size.* = result_bytes.len;
    return 1;
}
