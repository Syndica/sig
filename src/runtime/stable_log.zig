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
pub fn program_invoke(
    log_collector: *?LogCollector,
    program_pubkey: Pubkey,
    invoke_depth: usize,
) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log(
            "Program {} invoke [{}]",
            .{ program_pubkey, invoke_depth },
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
pub fn program_data(log_collector: *?LogCollector, data: []const []const u8) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log(
            log_collector,
            "Program data: {any}",
            .{data}, // TODO: Base64 encode
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
pub fn program_return(
    log_collector: *?LogCollector,
    program_pubkey: Pubkey,
    data: []const u8,
) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log(
            log_collector,
            "Program return: {} {any}",
            .{
                program_pubkey,
                data, // TODO: Base64 encode
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
pub fn program_success(log_collector: *?LogCollector, program_pubkey: Pubkey) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log("Program {} success", .{program_pubkey});
    }
}

/// Log program execution failure
///
/// The general form is:
///
/// ```notrust
/// "Program <address> failed: <program error details>"
/// ```
pub fn program_failure(
    log_collector: *?LogCollector,
    program_pubkey: Pubkey,
    err: anytype,
) !void {
    if (log_collector.* != null) {
        try log_collector.*.?.log("Program {} failed: {any}", .{ program_pubkey, err });
    }
}
