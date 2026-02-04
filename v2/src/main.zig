const std = @import("std");
const common = @import("common");
const services = @import("services.zig");

const E = linux.E;
const e = E.init;
const linux = std.os.linux;
const page_size_min = std.heap.page_size_min;

const ResolvedArgs = common.ResolvedArgs;
const memfd = common.linux.memfd;

const ServiceArgs = struct {
    stderr: ?linux.fd_t = null,
    exit: memfd.RW,

    rw: []const memfd.RW,
    rw_load: []const ?[*]align(page_size_min) u8,

    ro: []const memfd.RO,
    ro_load: []const ?[*]align(page_size_min) u8,

    fn resolve(self: ServiceArgs) !ResolvedArgs {
        var resolved: ResolvedArgs = .{
            .stderr = self.stderr orelse -1,
            .exit = (try self.exit.mmap(null)).ptr,

            .rw = @splat(null),
            .rw_len = @splat(0),
            .ro = @splat(null),
            .ro_len = @splat(0),
        };

        for (self.rw, self.rw_load, 0..) |rw, load, i| {
            resolved.rw[i] = (try rw.mmap(load)).ptr;
            resolved.rw_len[i] = rw.size;
        }
        for (self.ro, self.ro_load, 0..) |ro, load, i| {
            resolved.ro[i] = (try ro.mmap(load)).ptr;
            resolved.ro_len[i] = ro.size;
        }

        return resolved;
    }
};

const ServiceDefinition = struct {
    name: []const u8,
    params: ServiceArgs,
    svc_main: common.ServiceFn,
    svc_fault_handler: linux.Sigaction.sigaction_fn,
};

pub fn main() !void {
    const stderr = std.fs.File.stderr().handle;

    // set up shared mem regions
    const rw = .{
        .prng = try memfd.RW.init(.{ .name = "prng-state", .size = 16 }),
    };
    const ro = .{
        .prng = try memfd.RO.fromRW(rw.prng),
    };

    const net = .{
        .ping = try memfd.RW.init(.{ .name = "net-ping", .size = @sizeOf(common.net.Pair) }),
    };

    const service_defs: []const ServiceDefinition = &.{
        .{
            .name = "Logger",
            .svc_main = services.logger,
            .svc_fault_handler = services.fault_handler.logger,
            .params = .{
                .stderr = stderr,
                .exit = try memfd.RW.init(.{ .name = "logger-exit", .size = @sizeOf(common.Exit) }),
                .ro = &.{ro.prng},
                .ro_load = &.{null},
                .rw = &.{},
                .rw_load = &.{},
            },
        },
        .{
            .name = "Prng",
            .svc_main = services.prng,
            .svc_fault_handler = services.fault_handler.prng,
            .params = .{
                .exit = try memfd.RW.init(.{ .name = "prng-exit", .size = @sizeOf(common.Exit) }),
                .rw = &.{rw.prng},
                .rw_load = &.{null},
                .ro = &.{},
                .ro_load = &.{},
            },
        },
        .{
            .name = "Net",
            .svc_main = services.net,
            .svc_fault_handler = services.fault_handler.net,
            .params = .{
                .exit = try memfd.RW.init(.{ .name = "net-exit", .size = @sizeOf(common.Exit) }),
                .rw = &.{net.ping},
                .rw_load = &.{null},
                .ro = &.{},
                .ro_load = &.{},
            },
        },
        .{
            .name = "Ping",
            .svc_main = services.ping,
            .svc_fault_handler = services.fault_handler.ping,
            .params = .{
                .stderr = stderr,
                .exit = try memfd.RW.init(.{ .name = "ping-exit", .size = @sizeOf(common.Exit) }),
                .rw = &.{net.ping},
                .rw_load = &.{null},
                .ro = &.{},
                .ro_load = &.{},
            },
        },
    };

    const Meta = struct { service: ServiceDefinition, pid: i32, exit: ?*common.Exit = null };
    var service_meta: std.MultiArrayList(Meta) = .{};

    for (service_defs) |svc| {
        try service_meta.append(std.heap.page_allocator, .{
            .service = svc,
            .pid = try startService(svc),
        });
    }

    // only mmap exit after spawning the child processes, we don't want this mapped in children
    for (service_defs, service_meta.items(.exit)) |svc, *exit| {
        const region = try svc.params.exit.mmap(null);
        exit.* = @ptrCast(region);
    }

    // wait for the first child to exit
    var status: u32 = 0;
    const exited_pid: i32 = pid: {
        const ret: usize = linux.waitpid(-1, &status, 0);
        std.debug.assert(ret != -1);
        break :pid @intCast(ret);
    };

    const exited_service_idx = std.mem.indexOfScalar(
        i32,
        service_meta.items(.pid),
        exited_pid,
    ) orelse std.debug.panic("Unknown child pid {} exited\n", .{exited_pid});

    dumpOnExit(
        service_meta.items(.exit)[exited_service_idx].?,
        service_meta.items(.service)[exited_service_idx],
        exited_pid,
        status,
    );
}

fn startService(svc: ServiceDefinition) !i32 {
    const parent_pid = std.os.linux.getpid();

    const maybe_child_pid = common.linux.clone3.clone3(&.{
        .flags = .{
            // NOTE: all FDs currently open will remain open in the child
            // There is no way around this, except
            // 1) Immediately closing all FDs in the child
            // 2) Making sure all FDs were created with CLOEXEC, and using exec in the child
        },
        .exit_signal = std.os.linux.SIG.CHLD,
    });

    if (maybe_child_pid) |child_pid| {
        // parent code
        std.debug.print("Starting Service `{s}`, pid: {}\n", .{ svc.name, child_pid });
        return child_pid;
    }

    // register fault handlers
    {
        const act: *const std.os.linux.Sigaction = &.{
            .handler = .{ .sigaction = svc.svc_fault_handler },
            .mask = std.posix.sigemptyset(),
            .flags = (std.posix.SA.SIGINFO | std.posix.SA.RESTART | std.posix.SA.RESETHAND),
        };

        // standard signals in std.debug.updateSegfaultHandler
        std.posix.sigaction(std.posix.SIG.SEGV, act, null);
        std.posix.sigaction(std.posix.SIG.ILL, act, null);
        std.posix.sigaction(std.posix.SIG.BUS, act, null);
        std.posix.sigaction(std.posix.SIG.FPE, act, null);

        // catch seccomp too
        std.posix.sigaction(std.posix.SIG.SYS, act, null);
    }

    // Make sure that the services die when the parent exits
    {
        const ret = linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), linux.SIG.KILL, 0, 0, 0);
        if (ret != 0) std.debug.panic("prctl failed with: {}\n", .{e(ret)});

        // NOTE: this check does not work if we spawn each service into a new pid namespace, as
        // getppid will return 0 (including when the parent is dead).
        const parent_pid_now = std.os.linux.getppid();
        if (parent_pid != parent_pid_now) {
            // The parent died. In case this happened before we set SET_PDEATHSIG, let's exit
            // ourselves.
            @branchHint(.cold);
            std.debug.panic(
                "Parent died, parent pid changed ({}->{})\n",
                .{ parent_pid, parent_pid_now },
            );
        }
    }

    // mmap in files
    const resolved_params = try svc.params.resolve();

    // mseal our shared VMAs (essentially making sure their mapping can't be tampered with)
    for (resolved_params.ro, resolved_params.ro_len) |ptr, len| mseal(ptr orelse continue, len);
    for (resolved_params.rw, resolved_params.rw_len) |ptr, len| mseal(ptr orelse continue, len);
    mseal(resolved_params.exit, 4);

    closeAllFdsExceptStderr(svc.params.stderr);

    // makes it impossible for the service to gain privileges
    std.debug.assert(try std.posix.prctl(.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 }) == 0);

    // install a basic seccomp filter that bans syscalls except write+sleep
    {
        const bpf_filters = common.linux.bpf.printSleepExit(svc.params.stderr);
        const program: common.linux.bpf.sock_fprog = .{
            .len = bpf_filters.len,
            .sock_filter = &bpf_filters,
        };

        const ret = linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &program);
        const err = e(ret);
        if (err != .SUCCESS) {
            std.debug.panic("seccomp err: {}", .{err});
            return;
        }
    }

    svc.svc_main(resolved_params);
    std.process.exit(255); // service exit implies an error / exit code not used
}

fn dumpOnExit(meta: *common.Exit, service: ServiceDefinition, pid: i32, status: u32) void {
    if (meta.panicMsg()) |panic_msg| {
        std.debug.print(
            "Service `{s}` (pid: {}) panicked with message: {s}\n",
            .{ service.name, pid, panic_msg },
        );
    }
    if (meta.errorName()) |error_string| {
        std.debug.print(
            "Service `{s}` (pid: {}) exited with error: {s}\n",
            .{ service.name, pid, error_string },
        );
    }
    if (meta.faultMsg()) |fault_msg| {
        std.debug.print(
            "Service `{s}` (pid: {}) faulted with message: {s}\n",
            .{ service.name, pid, fault_msg },
        );
    }

    if (linux.W.TERMSIG(status) != 0) {
        std.debug.print(
            "Service `{s}` (pid: {}) exited from signal {}\n",
            .{ service.name, pid, linux.W.TERMSIG(status) },
        );
    }

    if (meta.errorReturnStackTrace()) |trace| {
        std.debug.print("Error trace:\n", .{});
        std.debug.dumpStackTrace(trace);
    }

    if (meta.stackTrace()) |trace| {
        std.debug.print("Stack trace:\n", .{});
        std.debug.dumpStackTrace(trace);
    }

    if (meta.faultStackTrace()) |trace| {
        std.debug.print("Fault trace:\n", .{});
        std.debug.dumpStackTrace(trace);
    }
}

fn closeAllFdsExceptStderr(maybe_stderr: ?linux.fd_t) void {
    const max_fd = std.math.maxInt(linux.fd_t);

    if (maybe_stderr) |stderr| {
        // close (0..stderr, stderr+1..=max)
        if (std.os.linux.syscall3(.close_range, 0, @intCast(stderr - 1), 0) != 0)
            std.debug.panic("close_range failed\n", .{});
        if (std.os.linux.syscall3(.close_range, @intCast(stderr + 1), max_fd, 0) != 0)
            std.debug.panic("close_range failed\n", .{});
    } else {
        // close (0..=max)
        if (std.os.linux.syscall3(.close_range, 0, max_fd, 0) != 0)
            std.debug.panic("close_range failed\n", .{});
    }
}

fn mseal(address: [*]align(std.heap.page_size_min) const u8, len: usize) void {
    switch (std.os.linux.mseal(address, len, 0)) {
        0 => {},
        @intFromEnum(std.os.linux.E.NOSYS) => {}, // syscall unsupported (6.12+)
        else => |x| std.debug.panic("mseal failed: {}\n", .{x}),
    }
}
