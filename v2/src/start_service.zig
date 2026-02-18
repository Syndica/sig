//! Roughly equivalent to std's start.zig, but for our services.
//!
//! This code is responsible for:
//! - Exporting symbols
//! - Setting a panic handler
//! - Forwarding parameters
//! - Handling signals
//! - Reporting back errors + stack traces
//! - Exiting the process

const root = @import("root");

const std = @import("std");
const builtin = @import("builtin");

const common = @import("common");

const posix = std.posix;
const native_arch = builtin.cpu.arch;
const native_os = builtin.os.tag;

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
        @export(&handleSegfault, .{ .name = "svc_fault_handler_" ++ root.name });
    }
}

pub const panic = std.debug.FullPanic(servicePanic);

pub const panic_state = struct {
    pub var stderr: std.os.linux.fd_t = undefined;
    pub var exit: *common.Exit = undefined;
    var faulted: bool = false;
};

fn serviceMain(params: common.ResolvedArgs) callconv(.c) noreturn {
    const exit: *common.Exit = @ptrCast(params.exit);
    exit.* = .{};

    // this is set to undefined in std, and never set for code built as a library
    std.os.environ = &.{};

    panic_state.stderr = params.stderr;
    panic_state.exit = exit;

    const stderr: std.fs.File = .{ .handle = params.stderr };
    var writer_buf: [0]u8 = undefined;
    var writer = stderr.writer(&writer_buf);

    // Call main with args specified by ReadWrite/ReadOnly structs
    const ret_val =
        if (!@hasDecl(root, "ReadWrite")) err: {
            var read_only: root.ReadOnly = .{};
            const root_ro_fields = @typeInfo(root.ReadOnly).@"struct".fields;
            inline for (
                root_ro_fields,
                params.ro[0..root_ro_fields.len],
                params.ro_len[0..root_ro_fields.len],
            ) |field, data, data_len| {
                @field(read_only, field.name) = @ptrCast(data.?[0..data_len]);
            }

            break :err root.main(&writer.interface, read_only);
        } else if (!@hasDecl(root, "ReadOnly")) err: {
            var read_write: root.ReadWrite = undefined;
            const root_rw_fields = @typeInfo(root.ReadWrite).@"struct".fields;
            inline for (
                root_rw_fields,
                params.rw[0..root_rw_fields.len],
                params.rw_len[0..root_rw_fields.len],
            ) |field, data, data_len| {
                @field(read_write, field.name) = @ptrCast(data.?[0..data_len]);
            }

            break :err root.main(&writer.interface, read_write);
        } else err: {
            var read_only: root.ReadOnly = undefined;
            const root_ro_fields = @typeInfo(root.ReadOnly).@"struct".fields;
            inline for (
                root_ro_fields,
                params.ro[0..root_ro_fields.len],
                params.ro_len[0..root_ro_fields.len],
            ) |field, data, data_len| {
                @field(read_only, field.name) = @ptrCast(data.?[0..data_len]);
            }

            var read_write: root.ReadWrite = undefined;
            const root_rw_fields = @typeInfo(root.ReadWrite).@"struct".fields;
            inline for (
                root_rw_fields,
                params.rw[0..root_rw_fields.len],
                params.rw_len[0..root_rw_fields.len],
            ) |field, data, data_len| {
                @field(read_write, field.name) = @ptrCast(data.?[0..data_len]);
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
            const n_addresses = @min(exit.error_return.len, trace.instruction_addresses.len);
            @memcpy(
                exit.error_return[0..n_addresses],
                trace.instruction_addresses[0..n_addresses],
            );
        }

        writer.interface.flush() catch {};
        abort();
    };

    unreachable;
}

// Ported over from std.debug.handleSegfaultPosix
fn handleSegfault(
    sig: i32,
    info: *const posix.siginfo_t,
    ctx_ptr: ?*anyopaque,
) callconv(.c) noreturn {
    // stop recursive faults
    if (panic_state.faulted) abort();
    panic_state.faulted = true;

    const address = switch (native_os) {
        .linux => @intFromPtr(info.fields.sigfault.addr),
        .freebsd, .macos => @intFromPtr(info.addr),
        .netbsd => @intFromPtr(info.info.reason.fault.addr),
        .openbsd => @intFromPtr(info.data.fault.addr),
        .solaris, .illumos => @intFromPtr(info.reason.fault.addr),
        else => unreachable,
    };

    const code = if (native_os == .netbsd) info.info.code else info.code;

    const bufPrint = std.fmt.bufPrint;
    const exit = panic_state.exit;
    const SIG = posix.SIG;

    switch (sig) {
        SIG.SEGV => {
            // include/uapi/asm-generic/siginfo.h
            // "sent by the kernel from somewhere"
            const SI_KERNEL = 0x80;
            if (native_arch == .x86_64 and native_os == .linux and code == SI_KERNEL) {
                // x86_64 doesn't have a full 64-bit virtual address space.
                // Addresses outside of that address space are non-canonical
                // and the CPU won't provide the faulting address to us.
                // This happens when accessing memory addresses such as 0xaaaaaaaaaaaaaaaa
                // but can also happen when no addressable memory is involved;
                // for example when reading/writing model-specific registers
                // by executing `rdmsr` or `wrmsr` in user-space (unprivileged mode).
                const str = "General protection exception (no address available)\n";
                const copy_len = @min(str.len, exit.fault_msg.len);
                @memcpy(exit.fault_msg[0..copy_len], str[0..copy_len]);
                abort();
            } else {
                _ = bufPrint(
                    &exit.fault_msg,
                    "Illegal instruction at address 0x{x}\n",
                    .{address},
                ) catch {};
            }
        },
        SIG.ILL => _ = bufPrint(
            &exit.fault_msg,
            "Illegal instruction at address 0x{x}\n",
            .{address},
        ) catch {},
        SIG.BUS => _ = bufPrint(
            &exit.fault_msg,
            "Bus error at address 0x{x}\n",
            .{address},
        ) catch {},
        SIG.FPE => _ = bufPrint(
            &exit.fault_msg,
            "Arithmetic exception at address 0x{x}\n",
            .{address},
        ) catch {},
        SIG.SYS => _ = bufPrint(
            &exit.fault_msg,
            "Seccomp violation at address 0x{x}\n",
            .{address},
        ) catch {},

        else => unreachable,
    }

    const pc = pc: {
        // Some kernels don't align `ctx_ptr` properly. Handle this defensively.
        const ctx: *align(1) posix.ucontext_t = @ptrCast(ctx_ptr);
        var new_ctx: posix.ucontext_t = ctx.*;
        if (builtin.os.tag.isDarwin() and builtin.cpu.arch == .aarch64) {
            // The kernel incorrectly writes the contents of `__mcontext_data` right after `mcontext`,
            // rather than after the 8 bytes of padding that are supposed to sit between the two. Copy the
            // contents to the right place so that the `mcontext` pointer will be correct after the
            // `relocateContext` call below.
            new_ctx.__mcontext_data = @as(*align(1) extern struct {
                onstack: c_int,
                sigmask: std.c.sigset_t,
                stack: std.c.stack_t,
                link: ?*std.c.ucontext_t,
                mcsize: u64,
                mcontext: *std.c.mcontext_t,
                __mcontext_data: std.c.mcontext_t align(@sizeOf(usize)), // Disable padding after `mcontext`.
            }, @ptrCast(ctx)).__mcontext_data;
        }
        std.debug.relocateContext(&new_ctx);

        const ip_reg_num = std.debug.Dwarf.abi.ipRegNum(native_arch).?;
        break :pc std.debug.SelfInfo.stripInstructionPtrAuthCode(
            (std.debug.Dwarf.abi.regValueNative(&new_ctx, ip_reg_num, null) catch abort()).*,
        );
    };

    // write back current trace
    {
        var i: usize = 0;
        var iter = SimpleStackIterator.init(@returnAddress(), null);

        // add the faulting instruction as frame 0
        exit.fault[i] = pc;
        i += 1;

        while (iter.next()) |addr| : (i += 1) {
            if (i == exit.fault.len) break;
            exit.fault[i] = addr;
        }
        exit.fault_index = i;
    }

    abort();
}

fn abort() noreturn {
    std.os.linux.exit(255);
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
    // avoids case of recursive panic
    @setRuntimeSafety(false);

    const exit = panic_state.exit;

    // write back the panic message
    const msg_len = @min(msg.len, exit.panic_msg.len);
    @memcpy(exit.panic_msg[0..msg_len], msg[0..msg_len]);

    // write back error return trace
    if (@errorReturnTrace()) |trace| {
        exit.error_return_index = trace.index;
        const n_addresses = @min(exit.error_return.len, trace.instruction_addresses.len);
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
