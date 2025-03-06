// TODO: Consider moving this into the log_collector module?

const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const LogCollector = sig.runtime.LogCollector;

const BASE_64_ENCODER = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');

/// Log a program invoke.
///
/// The general form is:
///
/// ```notrust
/// "Program <address> invoke [<depth>]"
/// ```
///
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/stable_log.rs#L20
pub fn programInvoke(
    log_collector: *?LogCollector,
    program_id: Pubkey,
    invoke_depth: usize,
) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log(
            "Program {} invoke [{}]",
            .{ program_id, invoke_depth },
        );
    }
}

/// Log a message from the program itself.
///
/// The general form is:
///
/// ```notrust
/// "Program log: <program-generated output>"
/// ```
///
/// That is, any program-generated output is guaranteed to be prefixed by "Program log: "
///
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/stable_log.rs#L42
pub fn programLog(log_collector: *?LogCollector, message: []const u8) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log("Program log: {str}", .{message});
    }
}

/// Emit a program data.
///
/// The general form is:
///
/// ```notrust
/// "Program data: <binary-data-in-base64>*"
/// ```
///
/// That is, any program-generated output is guaranteed to be prefixed by "Program data: "
///
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/stable_log.rs#L55
pub fn programData(
    allocator: std.mem.Allocator,
    log_collector: *?LogCollector,
    data: []const []const u8,
) !void {
    if (log_collector.* != null) {
        var encoded = std.ArrayListUnmanaged(u8){};
        defer encoded.deinit(allocator);
        for (data) |chunk| {
            const buffer = try allocator.alloc(u8, BASE_64_ENCODER.calcSize(chunk.len));
            defer allocator.free(buffer);
            try encoded.appendSlice(allocator, BASE_64_ENCODER.encode(buffer, chunk));
            try encoded.append(allocator, ' ');
        }
        _ = encoded.pop();

        try log_collector.*.?.log(
            "Program data: {str}",
            .{encoded.items},
        );
    }
}

/// Log return data as from the program itself. This line will not be present if no return
/// data was set, or if the return data was set to zero length.
///
/// The general form is:
///
/// ```notrust
/// "Program return: <program-id> <program-generated-data-in-base64>"
/// ```
///
/// That is, any program-generated output is guaranteed to be prefixed by "Program return: "
///
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/stable_log.rs#L73
pub fn programReturn(
    allocator: std.mem.Allocator,
    log_collector: *?LogCollector,
    program_id: Pubkey,
    data: []const u8,
) !void {
    if (log_collector.* != null) {
        const buffer = try allocator.alloc(u8, BASE_64_ENCODER.calcSize(data.len));
        defer allocator.free(buffer);
        const encoded = BASE_64_ENCODER.encode(buffer, data);

        try log_collector.*.?.log(
            "Program return: {} {str}",
            .{ program_id, encoded },
        );
    }
}

/// Log successful program execution.
///
/// The general form is:
///
/// ```notrust
/// "Program <address> success"
/// ```
///
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/stable_log.rs#L93
pub fn programSuccess(log_collector: *?LogCollector, program_id: Pubkey) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log("Program {} success", .{program_id});
    }
}

/// Log program execution failure
///
/// The general form is:
///
/// ```notrust
/// "Program <address> failed: <program error details>"
/// ```
///
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/stable_log.rs#L104
pub fn programFailure(
    log_collector: *?LogCollector,
    program_id: Pubkey,
    err: anytype,
) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log("Program {} failed: {}", .{ program_id, err });
    }
}

test "stable_log" {
    const allocator = std.testing.allocator;

    var log_collector: ?LogCollector = LogCollector.default(allocator);
    defer log_collector.?.deinit();

    const program_id =
        Pubkey.parseBase58String("SigDefau1tPubkey111111111111111111111111111") catch unreachable;

    try programInvoke(&log_collector, program_id, 0);
    try programLog(&log_collector, "log");
    try programData(allocator, &log_collector, &.{ "data0", "data1" });
    try programReturn(allocator, &log_collector, program_id, "return");
    try programSuccess(&log_collector, program_id);
    try programFailure(&log_collector, program_id, error.Error);

    const expected: []const []const u8 = &.{
        "Program SigDefau1tPubkey111111111111111111111111111 invoke [0]",
        "Program log: log",
        "Program data: ZGF0YTA= ZGF0YTE=",
        "Program return: SigDefau1tPubkey111111111111111111111111111 cmV0dXJu",
        "Program SigDefau1tPubkey111111111111111111111111111 success",
        "Program SigDefau1tPubkey111111111111111111111111111 failed: error.Error",
    };
    const actual = log_collector.?.collect();

    try std.testing.expectEqualSlices(u8, expected[0], actual[0]);
    try std.testing.expectEqualSlices(u8, expected[1], actual[1]);
    try std.testing.expectEqualSlices(u8, expected[2], actual[2]);
    try std.testing.expectEqualSlices(u8, expected[3], actual[3]);
    try std.testing.expectEqualSlices(u8, expected[4], actual[4]);
    try std.testing.expectEqualSlices(u8, expected[5], actual[5]);
}
