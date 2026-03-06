//! Minimal reproduction for a Zig 0.15.2 stdlib HTTP decompression panic.
//!
//! This script sends the same JSON-RPC request (`getLeaderSchedule`) twice to
//! a provided endpoint:
//! 1) with `Accept-Encoding: identity`
//! 2) with default encodings (compression enabled)
//!
//! Expected behavior on affected endpoints:
//! - identity request succeeds without panic
//! - compressed request may panic in stdlib flate decompression with
//!   `Writer.unreachableRebase`
//!
//! Usage:
//! `zig run scripts/repro_http_flate_panic.zig -- <rpc-url>`
const std = @import("std");

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();

    const url = args.next() orelse {
        std.debug.print(
            "usage: zig run scripts/repro_http_flate_panic.zig -- <rpc-url>\n",
            .{},
        );
        std.process.exit(1);
    };

    if (args.next()) |arg| {
        std.debug.print("unknown arg: {s}\n", .{arg});
        std.process.exit(1);
    }

    const payload =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLeaderSchedule\",\"params\":[null]}";

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    inline for (&.{ true, false }) |force_identity| {
        std.debug.print(
            "\ngetLeaderSchedule:\n\trequest: url={s}, identity={any}, payload={s}\n",
            .{ url, force_identity, payload },
        );

        var response = std.Io.Writer.Allocating.init(allocator);
        defer response.deinit();

        const result = try client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = payload,
            .response_writer = &response.writer,
            .headers = if (force_identity)
                .{
                    .content_type = .{ .override = "application/json" },
                    .accept_encoding = .{ .override = "identity" },
                    .user_agent = .{ .override = "sig-repro/0.1" },
                }
            else
                .{
                    .content_type = .{ .override = "application/json" },
                    .user_agent = .{ .override = "sig-repro/0.1" },
                },
        });

        const response_bytes = try response.toOwnedSlice();
        defer allocator.free(response_bytes);

        std.debug.print("\tresponse: status={} body-bytes={d}\n", .{ result.status, response_bytes.len });
    }
}
