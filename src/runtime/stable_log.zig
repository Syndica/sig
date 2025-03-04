const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const LogCollector = sig.runtime.LogCollector;

/// Log a program invoke.
///
/// The general form is:
///
/// ```notrust
/// "Program <address> invoke [<depth>]"
/// ```
///
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/stable_log.rs#L20
pub fn program_invoke(
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
pub fn program_log(log_collector: *?LogCollector, message: []const u8) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log("Program log: {}", .{message});
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
pub fn program_data(log_collector: *?LogCollector, data: []const []const u8) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log(
            log_collector,
            "Program data: {any}",
            .{data}, // TODO(native-cpi): Base64 encode
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
pub fn program_return(
    log_collector: *?LogCollector,
    program_id: Pubkey,
    data: []const u8,
) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log(
            log_collector,
            "Program return: {} {any}",
            .{
                program_id,
                data, // TODO(native-cpi): Base64 encode
            },
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
pub fn program_success(log_collector: *?LogCollector, program_id: Pubkey) !void {
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
pub fn program_failure(
    log_collector: *?LogCollector,
    program_id: Pubkey,
    err: anytype,
) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log("Program {} failed: {any}", .{ program_id, err });
    }
}
