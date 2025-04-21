// TODO: Consider moving this into the log_collector module?

const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const LogCollector = sig.runtime.LogCollector;
const TransactionContext = sig.runtime.TransactionContext;

pub const BASE_64_ENCODER =
    std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');

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
    tc: *TransactionContext,
    program_id: Pubkey,
    invoke_depth: usize,
) !void {
    if (tc.log_collector) |*lc| {
        try lc.log(
            tc.allocator,
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
pub fn programLog(tc: *TransactionContext, message: []const u8) !void {
    if (tc.log_collector) |*lc| {
        try lc.log(tc.allocator, "Program log: {str}", .{message});
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
    tc: *TransactionContext,
    data: []const []const u8,
) !void {
    if (tc.log_collector) |*lc| {
        var encoded = std.ArrayListUnmanaged(u8){};
        defer encoded.deinit(tc.allocator);
        for (data) |chunk| {
            const buffer = try tc.allocator.alloc(u8, BASE_64_ENCODER.calcSize(chunk.len));
            defer tc.allocator.free(buffer);
            try encoded.appendSlice(tc.allocator, BASE_64_ENCODER.encode(buffer, chunk));
            try encoded.append(tc.allocator, ' ');
        }
        _ = encoded.pop();

        try lc.log(
            tc.allocator,
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
    tc: *TransactionContext,
    program_id: Pubkey,
    data: []const u8,
) !void {
    if (tc.log_collector) |*lc| {
        const buffer = try tc.allocator.alloc(u8, BASE_64_ENCODER.calcSize(data.len));
        defer tc.allocator.free(buffer);
        const encoded = BASE_64_ENCODER.encode(buffer, data);

        try lc.log(
            tc.allocator,
            "Program return: {} {s}",
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
pub fn programSuccess(tc: *TransactionContext, program_id: Pubkey) !void {
    if (tc.log_collector) |*lc| {
        try lc.log(tc.allocator, "Program {} success", .{program_id});
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
    tc: *TransactionContext,
    program_id: Pubkey,
    err: []const u8,
) !void {
    if (tc.log_collector) |*lc| {
        try lc.log(tc.allocator, "Program {} failed: {s}", .{ program_id, err });
    }
}

test "stable_log" {
    const createExecutionContexts = sig.runtime.testing.createExecutionContexts;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    const ec, const sc, var tc = try createExecutionContexts(
        allocator,
        prng.random(),
        .{
            .log_collector = LogCollector.default(),
        },
    );
    defer {
        ec.deinit();
        allocator.destroy(ec);
        sc.deinit();
        allocator.destroy(sc);
        tc.deinit();
    }

    const program_id =
        Pubkey.parseBase58String("SigDefau1tPubkey111111111111111111111111111") catch unreachable;

    try programInvoke(&tc, program_id, 0);
    try programLog(&tc, "log");
    try programData(&tc, &.{ "data0", "data1" });
    try programReturn(&tc, program_id, "return");
    try programSuccess(&tc, program_id);
    try programFailure(&tc, program_id, "error");

    const expected: []const []const u8 = &.{
        "Program SigDefau1tPubkey111111111111111111111111111 invoke [0]",
        "Program log: log",
        "Program data: ZGF0YTA= ZGF0YTE=",
        "Program return: SigDefau1tPubkey111111111111111111111111111 cmV0dXJu",
        "Program SigDefau1tPubkey111111111111111111111111111 success",
        "Program SigDefau1tPubkey111111111111111111111111111 failed: error",
    };
    const actual = tc.log_collector.?.collect();

    try std.testing.expectEqualSlices(u8, expected[0], actual[0]);
    try std.testing.expectEqualSlices(u8, expected[1], actual[1]);
    try std.testing.expectEqualSlices(u8, expected[2], actual[2]);
    try std.testing.expectEqualSlices(u8, expected[3], actual[3]);
    try std.testing.expectEqualSlices(u8, expected[4], actual[4]);
    try std.testing.expectEqualSlices(u8, expected[5], actual[5]);
}
