//! Roughly equivalent to std's start.zig, but for our services.

const root = @import("root");

const std = @import("std");
const builtin = @import("builtin");

const common = @import("common");

comptime {
    _ = root;

    if (!builtin.is_test) {
        if (!@hasDecl(root, "main"))
            @compileError("Service needs a main function");

        if (builtin.output_mode != .Lib)
            @compileError("Service must be built as library");

        if (!@hasDecl(root, "name"))
            @compileError("Missing service name");

        const Return = @typeInfo(@TypeOf(root.main)).@"fn".return_type.?;
        if (Return != noreturn) {
            if (@typeInfo(Return).error_union.payload != noreturn)
                @compileError("Invalid return type");
        }

        @export(&serviceMain, .{ .name = "svc_main_" ++ root.name });
    }
}

pub const panic = std.debug.FullPanic(servicePanic);

pub const panic_state = struct {
    pub var stderr: std.os.linux.fd_t = undefined;
    pub var exit: *common.Exit = undefined;
};

fn serviceMain(params: common.ResolvedArgs) callconv(.c) void {
    const exit: *common.Exit = @ptrCast(params.exit);
    exit.* = .{};

    // this is set to undefined in std, and never set for code built as a library
    std.os.environ = &.{};

    panic_state.stderr = params.stderr;
    panic_state.exit = exit;

    const stderr: std.fs.File = .{ .handle = params.stderr };
    var writer_buf: [4096]u8 = undefined;
    var writer = stderr.writer(&writer_buf);

    const ret_val =
        if (!@hasDecl(root, "ReadWrite")) err: {
            var read_only: root.ReadOnly = .{};
            inline for (@typeInfo(root.ReadOnly).@"struct".fields, 0..) |field, i| {
                @field(read_only, field.name) = @ptrCast(params.ro[i].?[i..params.ro_len[i]]);
            }
            break :err root.main(&writer.interface, read_only);
        } else if (!@hasDecl(root, "ReadOnly")) err: {
            var read_write: root.ReadWrite = undefined;
            inline for (@typeInfo(root.ReadWrite).@"struct".fields, 0..) |field, i| {
                @field(read_write, field.name) = @ptrCast(params.rw[i].?[i..params.rw_len[i]]);
            }
            break :err root.main(&writer.interface, read_write);
        } else err: {
            var read_only: root.ReadOnly = undefined;
            inline for (@typeInfo(root.ReadOnly).@"struct".fields, 0..) |field, i| {
                @field(read_only, field.name) = @ptrCast(params.ro[i].?[i..params.ro_len[i]]);
            }
            var read_write: root.ReadWrite = .{};
            inline for (@typeInfo(root.ReadWrite).@"struct".fields, 0..) |field, i| {
                @field(read_write, field.name) = @ptrCast(params.rw[i].?[i..params.rw_len[i]]);
            }
            break :err root.main(&writer.interface, read_only, read_write);
        };

    ret_val catch |err| {
        // write back error name
        const err_len = @min(@errorName(err).len, exit.error_name.len);
        @memcpy(exit.error_name[0..err_len], @errorName(err)[0..err_len]);

        if (@errorReturnTrace()) |trace| {
            // write back error return trace
            exit.error_return_index = trace.index;
            const n_addresses = @max(exit.error_return.len, trace.instruction_addresses.len);
            @memcpy(
                exit.error_return[0..n_addresses],
                trace.instruction_addresses[0..n_addresses],
            );
        }

        writer.interface.flush() catch {};
        return;
    };

    unreachable;
}

fn abort() noreturn {
    std.os.linux.exit(254);
}

/// Assumes x86-64, and built with frame pointers
const SimpleStackIterator = struct {
    first_address: ?usize,
    fp: usize,

    pub fn init(first_address: ?usize, fp: ?usize) SimpleStackIterator {
        return SimpleStackIterator{
            .first_address = first_address,
            .fp = fp orelse @frameAddress(),
        };
    }

    pub fn next(it: *SimpleStackIterator) ?usize {
        var address = it.nextInternal() orelse return null;

        if (it.first_address) |first_address| {
            while (address != first_address) {
                address = it.nextInternal() orelse return null;
            }
            it.first_address = null;
        }

        return address;
    }

    fn nextInternal(it: *SimpleStackIterator) ?usize {
        // frame should be non-zero and aligned
        if (it.fp == 0 or !std.mem.isAligned(it.fp, @alignOf(usize))) {
            return null;
        }

        // on x86-64 with frame pointers enabled, the start of frames contain:
        // - the previous frame pointer
        // - the return address
        const prev_fp_ptr: *const usize = @ptrFromInt(it.fp);
        const new_fp = prev_fp_ptr.*;

        const ret_addr_ptr: *const usize = @ptrFromInt(it.fp + @sizeOf(usize));
        const return_address = ret_addr_ptr.*;

        // stack should be growing downwards
        if (new_fp != 0 and new_fp <= it.fp) {
            return null;
        }

        it.fp = new_fp;
        return return_address;
    }
};

pub fn servicePanic(
    msg: []const u8,
    first_trace_addr: ?usize,
) noreturn {
    const exit = panic_state.exit;

    // write back the panic message
    const msg_len = @min(msg.len, exit.panic_msg.len);
    @memcpy(exit.panic_msg[0..msg_len], msg[0..msg_len]);

    // write back error return trace
    if (@errorReturnTrace()) |trace| {
        exit.error_return_index = trace.index;
        const n_addresses = @max(exit.error_return.len, trace.instruction_addresses.len);
        @memcpy(
            exit.error_return[0..n_addresses],
            trace.instruction_addresses[0..n_addresses],
        );
    }

    // write back current trace
    var i: usize = 0;
    var iter = SimpleStackIterator.init(first_trace_addr orelse @returnAddress(), null);
    while (iter.next()) |addr| : (i += 1) {
        if (i == exit.trace.len) break;
        exit.trace[i] = addr;
    }
    exit.trace_index = i;

    abort();
}
