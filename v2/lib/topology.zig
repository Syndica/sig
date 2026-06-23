//! Defines how the runner creates shared memory regions, spawns services, and waits
//! for them to exit.
//!
//! Flow:
//!  1. Create + initialize each region.
//!     - `Region(T).simple()` or `Region(T).sized(n)` allocates the memfd and mmaps it.
//!     - Initialize it with `region.ptr()`.
//!     - Call `r.finish()` to obtain a `Region(T).Initialized`, the handle that gets
//!       passed into the topology struct. This also unmaps the memfd.
//!  2. Define and initialize a topology struct describing every service. Each field is
//!     named after a service and has type `ServiceRegions(spec)`. `spec` is a
//!     `ServiceSpec` (typically declared in `init/services.zig`) whose
//!     `ReadOnly`/`ReadWrite` types list the typed pointers each service expects;
//!     `ServiceRegions` mirrors them with `Region(T).Initialized` fields.
//!  3. Call `spawn(&children, mode, topology)` once. It iterates every field of the
//!     topology, resolves regions in field-declaration order, spawns each service, and
//!     maps runner pages in the parent. Then drive `wait`/`cancel`/`isActive` on
//!     `children`.

const std = @import("std");
const lib = @import("lib.zig");
const tracy = @import("tracy");

const linux = std.os.linux;
const E = linux.E;
const e = E.init;
const SigactionFn = linux.Sigaction.sigaction_fn;

const Memfd = lib.linux.Memfd;

pub const ServiceFn = lib.ipc.ServiceFn;

/// Maximum number of services a single `Children` may track. Bump if needed.
pub const max_services = 16;

/// Limit imposed by `lib.ipc.ResolvedArgs`. Each service may bind at most this many
/// read-only regions, and at most this many read-write regions.
pub const max_regions_per_service = lib.ipc.ResolvedArgs.max_regions;

pub const Mode = enum { sandboxed, threaded };

/// Pair of structs declaring what regions a service consumes. `ReadOnly` and
/// `ReadWrite` are each a struct of typed pointers (e.g. `*const Config`, `*Pair`).
/// `ServiceRegions` mirrors them with corresponding `Region(T).Initialized` fields.
/// Typically declared inline in `init/services.zig`.
pub const ServiceSpec = struct {
    ReadOnly: type,
    ReadWrite: type,
};

/// Typed handle for a shared-memory region. Created by `Region(T).simple()` or
/// `Region(T).sized(n)`: the memfd is allocated and mmapped RW into `buf`. Populate
/// the buffer (typically via `ptr()`, but `buf` can also be accessed directly),
/// then call `finish()` to unmap and produce a `Region(T).Initialized` for the
/// topology.
///
/// `T` verifies a compatible type is used for initialization of both the memfd, and
/// the topology as a whole when passed into spawn.
pub fn Region(comptime T: type) type {
    return struct {
        memfd: Memfd,
        buf: ?[]align(std.heap.page_size_min) u8,

        /// Allocate a memfd of `@sizeOf(T)` bytes and mmap it RW.
        pub fn simple() !Region(T) {
            return sized(@sizeOf(T));
        }

        /// Allocate a memfd of `size` bytes and mmap it RW.
        pub fn sized(size: usize) !Region(T) {
            std.log.info("Initializing region '{s}' ({} bytes)", .{ @typeName(T), size });

            const memfd: Memfd = try .init(.{ .name = @typeName(T), .size = size });
            const buf = try memfd.mmapRaw(.rw, .{});

            return .{ .memfd = memfd, .buf = buf };
        }

        /// Unmap the writable view and return the typed handle to hand off to the topology.
        /// This function may be called multiple times. However, `ptr` and `buf` must not be
        /// used after calling this function.
        pub fn finish(self: *Region(T)) Region(T).Initialized {
            if (self.buf) |buf| {
                std.posix.munmap(buf);
                self.buf = null;
            }
            return .{ .memfd = self.memfd };
        }

        /// Cast `buf` to `*T`. Only valid when the region size is at least `@sizeOf(T)`
        pub fn ptr(self: Region(T)) *T {
            std.debug.assert(self.buf.?.len >= @sizeOf(T));
            return @ptrCast(self.buf.?);
        }

        /// Post-`finish` handle to a populated region. Carries only the memfd.
        /// The parent's writable mapping has been released. This is the type that
        /// goes into topology fields and is shared with services on spawn.
        ///
        /// You should not initialize this struct directly.
        /// Only create it using `finish`.
        pub const Initialized = struct { memfd: Memfd };
    };
}

/// Memfd container corresponding to a ServiceSpec. `ro` maps to `spec.ReadOnly` and
/// `rw` maps to `spec.ReadWrite`. For each `*T` (or `*const T`) in the spec, there
/// is a `Region(T).Initialized` in this struct.
///
/// For example, consider the following spec:
///
/// ```zig
/// const my_service: ServiceSpec = .{
///     .ReadOnly = struct {
///         config: *Config,
///     },
///     .ReadWrite = struct {
///         ring: *Ring,
///     },
/// };
/// ```
///
/// The corresponding `ServiceRegions(my_service)` is basically this:
///
/// ```zig
/// const ServiceRegions(my_service) = struct {
///     ro: struct {
///         config: Region(*Config).Initialized,
///     },
///     rw: struct {
///         ring: Region(*Ring).Initialized,
///     },
/// };
/// ```
pub fn ServiceRegions(comptime spec: ServiceSpec) type {
    return struct {
        ro: RegionsOf(spec.ReadOnly),
        rw: RegionsOf(spec.ReadWrite),

        /// Translates a struct of pointer fields like `{ foo: *T, bar: *const U }`
        /// into a struct of typed initialized regions:
        /// `{ foo: Region(T).Initialized, bar: Region(U).Initialized }`.
        fn RegionsOf(comptime PointerStruct: type) type {
            const fields = @typeInfo(PointerStruct).@"struct".fields;
            var new_fields: [fields.len]std.builtin.Type.StructField = undefined;
            for (fields, &new_fields) |old, *nf| {
                const InitializedRegion = Region(@typeInfo(old.type).pointer.child).Initialized;
                nf.* = .{
                    .name = old.name,
                    .type = InitializedRegion,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = @alignOf(InitializedRegion),
                };
            }
            return @Type(.{ .@"struct" = .{
                .layout = .auto,
                .fields = &new_fields,
                .decls = &.{},
                .is_tuple = false,
            } });
        }
    };
}

/// Count the number of times that RegionType appears within TopologyType, assuming
/// TopologyType is a struct with all fields of type ServiceRegions(spec)
pub fn countRegionShares(TopologyType: type, RegionType: type) comptime_int {
    comptime var count = 0;
    inline for (@typeInfo(TopologyType).@"struct".fields) |service_field| {
        inline for (@typeInfo(service_field.type).@"struct".fields) |access_field| {
            inline for (@typeInfo(access_field.type).@"struct".fields) |region_field| {
                if (region_field.type == Region(RegionType).Initialized) count += 1;
            }
        }
    }
    return count;
}

// -- Spawn and track Services -- //

/// State for one spawned service: pid (sandboxed) or thread (threaded), plus the
/// runner memfd we'll later map in the parent. Memfds and threads are owned by the parent.
pub const Service = struct {
    label: [:0]const u8,
    runner_memfd: Memfd,
    runner: *lib.runner.Region,
    activity_view: lib.runner.Activity.RunnerView,
    slot: union(Mode) {
        sandboxed: linux.pid_t,
        threaded: std.Thread,
    },
};

/// Represents every service in the topology once spawned, plus a `ThreadExit`
/// used in threaded mode. The address of this struct must be stable for the
/// lifetime of the services (threads point into it), which is why `spawn` takes
/// it as an out parameter rather than returning it by value.
///
/// Each field of `Topology` must be a `ServiceLayout(spec)`. Each field name is
/// used to look up the service's main function (`svc_main_<name>`) and fault
/// handler. Regions are passed in field declaration order, matching what
/// `start_service.zig` expects.
///
/// The usage flow is:
///  1. Create an undefined `Children` in a pinned memory location.
///  2. Call `spawn`. This initializes the struct and spawns every service. Do
///     not call spawn multiple times.
///  3. After `spawn` returns, the services are running and the caller can use
///     methods like `wait`, `cancel`, or `isActive` on the struct.
pub fn Children(Topo: type) type {
    return struct {
        mode: Mode,
        services_buf: [max_services]Service,
        services_len: usize,
        /// Used only in `.threaded` mode to wake up the parent on first service exit.
        thread_exit: ThreadExit,

        /// Spawn every service described by `topology` in one batch.
        ///
        /// This is effectively the init function for `Children`. `self` is
        /// treated as undefined on invocation. The caller's storage is what the
        /// threads (in threaded mode) hold pointers into, so it must outlive
        /// the services.
        pub fn spawn(self: *Children(Topo), mode: Mode, topology: Topo) !void {
            const fields = @typeInfo(@TypeOf(topology)).@"struct".fields;
            if (fields.len > max_services)
                @compileError("topology has more than max_services entries");

            self.* = .{
                .mode = mode,
                .services_buf = undefined,
                .services_len = 0,
                .thread_exit = .{},
            };

            inline for (fields, 0..) |svc_field, i| {
                const layout = @field(topology, svc_field.name);
                self.services_buf[i] =
                    try spawnOne(svc_field.name, layout, mode, &self.thread_exit, i);
            }
            self.services_len = fields.len;

            // Map runner regions in the parent. Sandboxed children fork without these
            // mappings, so the runner pages remain isolated to the parent.
            for (self.slice()) |*svc| {
                svc.runner = try svc.runner_memfd.mmapStaticSize(.rw, lib.runner.Region, .{});
                svc.activity_view = svc.runner.activity.runnerView();
            }
        }

        fn spawnOne(
            comptime svc_name: [:0]const u8,
            layout: @FieldType(Topo, svc_name),
            mode: Mode,
            thread_exit: *ThreadExit,
            service_idx: u16,
        ) !Service {
            var rw_buf: [max_regions_per_service]Memfd = undefined;
            var ro_buf: [max_regions_per_service]Memfd = undefined;
            const rw_count = collectRegions(@TypeOf(layout.rw), layout.rw, &rw_buf);
            const ro_count = collectRegions(@TypeOf(layout.ro), layout.ro, &ro_buf);

            const entrypoint = @extern(ServiceFn, .{ .name = "svc_main_" ++ svc_name });

            const runner_memfd: Memfd = try .init(.{
                .name = "runner_" ++ svc_name,
                .size = @sizeOf(lib.runner.Region),
            });

            const args: Args = .{
                .runner_memfd = runner_memfd,
                .rw = rw_buf[0..rw_count],
                .ro = ro_buf[0..ro_count],
            };

            return switch (mode) {
                .sandboxed => .{
                    .label = svc_name,
                    .runner_memfd = runner_memfd,
                    .runner = undefined, // initialized in `spawn` after all are spawned
                    .activity_view = undefined, // initialized in `spawn` after all are spawned
                    .slot = .{ .sandboxed = try spawnSandboxed(svc_name, entrypoint, args) },
                },
                .threaded => .{
                    .label = svc_name,
                    .runner_memfd = runner_memfd,
                    .runner = undefined, // initialized in `spawn` after all are spawned
                    .activity_view = undefined, // initialized in `spawn` after all are spawned
                    .slot = .{ .threaded = try spawnThreaded(
                        svc_name,
                        entrypoint,
                        args,
                        thread_exit,
                        service_idx,
                    ) },
                },
            };
        }

        /// Returns true if any service is still active.
        pub fn isActive(self: *Children(Topo)) bool {
            for (self.slice()) |*svc| {
                if (svc.activity_view.isActive()) return true;
            }
            return false;
        }

        /// Send a cancel signal to all services.
        pub fn cancel(self: *Children(Topo)) void {
            for (self.slice()) |*svc| svc.activity_view.cancel();
        }

        /// Block until the first service exits, then dump its diagnostics.
        /// If `timeout_ns_opt` is non-null, returns `error.Timeout` if no service exits in time.
        pub fn wait(self: *Children(Topo), timeout_ns_opt: ?u64) error{Timeout}!void {
            switch (self.mode) {
                .sandboxed => try self.waitSandboxed(timeout_ns_opt),
                .threaded => try self.waitThreaded(timeout_ns_opt),
            }
        }

        fn waitSandboxed(self: *Children(Topo), timeout_ns_opt: ?u64) error{Timeout}!void {
            const timeout_pid_opt = if (timeout_ns_opt) |timeout_ns|
                spawnSandboxedTimeout(timeout_ns)
            else
                null;

            // Wait for the first child to exit
            var status: u32 = 0;
            const exited_pid: linux.pid_t = pid: {
                const ret: usize = linux.waitpid(-1, &status, 0);
                std.debug.assert(e(ret) == .SUCCESS);
                break :pid @intCast(ret);
            };

            if (exited_pid == timeout_pid_opt) return error.Timeout;

            for (self.slice()) |*svc| {
                if (svc.slot.sandboxed != exited_pid) continue;
                dumpOnExit(&svc.runner.exit, svc.label, exited_pid, status);
                return;
            }
            std.debug.panic("Unknown child pid {} exited", .{exited_pid});
        }

        fn waitThreaded(self: *Children(Topo), timeout_ns_opt: ?u64) error{Timeout}!void {
            // Wait for first service to exit
            if (timeout_ns_opt) |timeout_ns| {
                self.thread_exit.reset_event.timedWait(timeout_ns) catch {};
            } else {
                self.thread_exit.reset_event.wait();
            }

            const exited_idx = self.thread_exit.finished_idx.load(.seq_cst);
            if (exited_idx == std.math.maxInt(u16)) return error.Timeout;

            const svc = &self.slice()[exited_idx];
            dumpOnExit(&svc.runner.exit, svc.label, 0, 0);
        }

        fn slice(self: *Children(Topo)) []Service {
            return self.services_buf[0..self.services_len];
        }
    };
}

fn collectRegions(
    comptime Layout: type,
    regions: Layout,
    buf: *[max_regions_per_service]Memfd,
) usize {
    var count: usize = 0;
    const fields = @typeInfo(Layout).@"struct".fields;
    if (fields.len > max_regions_per_service) @compileError("Too many regions for service");
    inline for (fields) |field| {
        const region = @field(regions, field.name);
        buf[count] = region.memfd;
        count += 1;
    }
    return count;
}

// -- Prepare a service's inputs -- //

const Args = struct {
    runner_memfd: Memfd,
    rw: []const Memfd,
    ro: []const Memfd,
};

/// Given a runner memfd plus `rw`/`ro` region lists, mmap each and pack into `ResolvedArgs`.
fn resolveArgs(params: Args) !lib.ipc.ResolvedArgs {
    var args: lib.ipc.ResolvedArgs = .{
        .stderr = std.posix.STDERR_FILENO,
        .runner = try params.runner_memfd.mmapStaticSize(.rw, lib.runner.Region, .{}),

        .rw = @splat(null),
        .rw_len = @splat(0),
        .ro = @splat(null),
        .ro_len = @splat(0),

        .thread_crash_ctx = null,
        .thread_crash_fn = null,
        .service_idx = std.math.maxInt(u16),
    };

    for (params.rw, 0..) |region, i| {
        const buf = try region.mmapRaw(.rw, .{ .populate = true });
        args.rw[i] = buf.ptr;
        args.rw_len[i] = region.size;
    }
    for (params.ro, 0..) |region, i| {
        const buf = try region.mmapRaw(.ro, .{ .populate = true });
        args.ro[i] = buf.ptr;
        args.ro_len[i] = region.size;
    }

    return args;
}

// -- Sandboxed Spawning -- //

fn spawnSandboxed(
    comptime svc_name: [:0]const u8,
    entrypoint: ServiceFn,
    args: Args,
) !linux.pid_t {
    const parent_pid = std.os.linux.getpid();

    const maybe_child_pid = lib.linux.clone3.clone3(&.{
        .flags = .{
            // NOTE: all FDs currently open will remain open in the child
            // There is no way around this, except
            // 1) Immediately closing all FDs in the child
            // 2) Making sure all FDs were created with CLOEXEC, and using exec in the child
        },
        .exit_signal = std.os.linux.SIG.CHLD,
    });

    if (maybe_child_pid) |child_pid| {
        std.log.info("Starting Service `{s}`, pid: {}", .{ svc_name, child_pid });
        return child_pid;
    }

    tracy.setThreadName("svc: " ++ svc_name);

    // register fault handlers
    {
        const fault_handler = @extern(SigactionFn, .{
            .name = "svc_fault_handler_" ++ svc_name,
        });
        const act: *const std.os.linux.Sigaction = &.{
            .handler = .{ .sigaction = fault_handler },
            .mask = std.os.linux.sigemptyset(),
            .flags = (std.posix.SA.SIGINFO | std.posix.SA.RESTART | std.posix.SA.RESETHAND),
        };

        const SIG = linux.SIG;
        // standard signals in std.debug.updateSegfaultHandler
        if (e(std.os.linux.sigaction(SIG.SEGV, act, null)) != .SUCCESS) @panic("sigaction SEGV");
        if (e(std.os.linux.sigaction(SIG.ILL, act, null)) != .SUCCESS) @panic("sigaction ILL");
        if (e(std.os.linux.sigaction(SIG.BUS, act, null)) != .SUCCESS) @panic("sigaction BUS");
        if (e(std.os.linux.sigaction(SIG.FPE, act, null)) != .SUCCESS) @panic("sigaction FPE");

        // catch seccomp too
        if (e(std.os.linux.sigaction(SIG.SYS, act, null)) != .SUCCESS) @panic("sigaction SYS");
    }

    // die when parent exits
    {
        const ret = linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), linux.SIG.KILL, 0, 0, 0);
        if (e(ret) != .SUCCESS) std.debug.panic("prctl failed: {}", .{e(ret)});

        // NOTE: this check does not work if we spawn each service into a new pid 
        // namespace, as getppid will return 0 (including when the parent is dead).
        const parent_pid_now = std.os.linux.getppid();
        if (parent_pid != parent_pid_now) {
            // The parent died. In case this happened before we set
            // SET_PDEATHSIG, let's exit ourselves.
            @branchHint(.cold);
            std.debug.panic(
                "Parent died, parent pid changed ({}->{})\n",
                .{ parent_pid, parent_pid_now },
            );
        }
    }

    const resolved = try resolveArgs(args);

    // mseal our shared VMAs (essentially making sure their mapping can't be tampered with)
    for (resolved.ro, resolved.ro_len) |ptr, len| mseal(ptr orelse continue, len);
    for (resolved.rw, resolved.rw_len) |ptr, len| mseal(ptr orelse continue, len);
    mseal(@ptrCast(resolved.runner), @sizeOf(lib.runner.Region));

    closeAllFdsExceptStderr(resolved.stderr);

    // makes it impossible for the service to gain privileges
    std.debug.assert(try std.posix.prctl(.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 }) == 0);

    // install a basic seccomp filter that bans syscalls except write+sleep
    {
        const bpf_filters = lib.linux.bpf.printSleepExit(resolved.stderr);
        const program: lib.linux.bpf.sock_fprog = .{
            .len = bpf_filters.len,
            .sock_filter = &bpf_filters,
        };
        const ret = linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &program);
        if (e(ret) != .SUCCESS) std.debug.panic("seccomp err: {}", .{e(ret)});
    }

    entrypoint(resolved);
    std.process.exit(255);
}

/// Spawn a sandboxed sleeper that exits after `timeout_ns`. Used as a `waitpid` timeout signal.
fn spawnSandboxedTimeout(timeout_ns: u64) linux.pid_t {
    const parent_pid = std.os.linux.getpid();

    const maybe_child_pid = lib.linux.clone3.clone3(&.{
        .flags = .{},
        .exit_signal = std.os.linux.SIG.CHLD,
    });

    if (maybe_child_pid) |child_pid| return child_pid;

    // die when parent exits
    {
        const ret = linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), linux.SIG.KILL, 0, 0, 0);
        if (e(ret) != .SUCCESS) std.debug.panic("prctl failed: {}", .{e(ret)});

        // NOTE: this check does not work if we spawn each service into a new pid 
        // namespace, as getppid will return 0 (including when the parent is dead).
        const parent_pid_now = std.os.linux.getppid();
        if (parent_pid != parent_pid_now) {
            // The parent died. In case this happened before we set
            // SET_PDEATHSIG, let's exit ourselves.
            @branchHint(.cold);
            std.debug.panic(
                "Parent died, parent pid changed ({}->{})\n",
                .{ parent_pid, parent_pid_now },
            );
        }
    }

    // wait the specified amount of time; if the service processes take longer
    // than this to finish, this will awaken and exit, causing the `waitpid` to
    // exit and thus terminate all processes.
    std.posix.nanosleep(
        timeout_ns / std.time.ns_per_s,
        timeout_ns % std.time.ns_per_s,
    );
    std.process.exit(255);
}

/// Prevents VMAs from being later modified
fn mseal(address: [*]align(std.heap.page_size_min) const u8, len: usize) void {
    switch (e(std.os.linux.mseal(address, len, 0))) {
        .SUCCESS => {},
        // syscall unsupported (6.12+). TODO: consider making this required.
        .NOSYS => {},
        else => |err| std.debug.panic("mseal failed: {}", .{err}),
    }
}

fn closeAllFdsExceptStderr(stderr: linux.fd_t) void {
    const max_fd = std.math.maxInt(linux.fd_t);
    if (std.os.linux.syscall3(.close_range, 0, @intCast(stderr -| 1), 0) != 0)
        std.debug.panic("close_range failed", .{});
    if (std.os.linux.syscall3(.close_range, @intCast(stderr +| 1), max_fd, 0) != 0)
        std.debug.panic("close_range failed", .{});
}

// -- Threaded Support -- //

fn spawnThreaded(
    comptime svc_name: [:0]const u8,
    entrypoint: ServiceFn,
    args: Args,
    thread_exit: *ThreadExit,
    service_idx: u16,
) !std.Thread {
    var threaded_args = try resolveArgs(args);
    threaded_args.thread_crash_ctx = thread_exit;
    threaded_args.thread_crash_fn = ThreadExit.signalCrashCallback;
    threaded_args.service_idx = service_idx;

    const ThreadEntry = struct {
        fn run(
            ep: ServiceFn,
            rargs: lib.ipc.ResolvedArgs,
            idx: u16,
            exit: *ThreadExit,
        ) void {
            tracy.setThreadName("svc: " ++ svc_name);
            ep(rargs);
            exit.signalExit(idx);
        }
    };

    return try std.Thread.spawn(
        .{},
        ThreadEntry.run,
        .{ entrypoint, threaded_args, service_idx, thread_exit },
    );
}

/// Used in threaded mode: services notify this on exit/crash so the parent can
/// wake up. Services receive it as opaque data and must not inspect it.
pub const ThreadExit = struct {
    finished_idx: std.atomic.Value(u16) = .init(std.math.maxInt(u16)),
    reset_event: std.Thread.ResetEvent = .{},

    fn signalExit(self: *ThreadExit, service_idx: u16) void {
        self.finished_idx.store(service_idx, .seq_cst);
        self.reset_event.set();
    }

    // Called by service threads in no-sandbox mode. Uses C calling convention
    // because the function pointer crosses service/init compilation units.
    fn signalCrashCallback(ctx: ?*anyopaque, service_idx: u16) callconv(.c) void {
        const self: *ThreadExit = @ptrCast(@alignCast(ctx orelse return));
        self.signalExit(service_idx);
    }
};

// -- Diagnostics -- //

fn dumpOnExit(
    meta: *lib.runner.Exit,
    label: [:0]const u8,
    pid: linux.pid_t,
    status: u32,
) void {
    if (meta.panicMsg()) |panic_msg| {
        std.log.err(
            "Service `{s}` (pid: {}) panicked with message: {s}",
            .{ label, pid, panic_msg },
        );
    }
    if (meta.errorName()) |error_string| {
        std.log.err(
            "Service `{s}` (pid: {}) exited with error: {s}",
            .{ label, pid, error_string },
        );
    }
    if (meta.faultMsg()) |fault_msg| {
        std.log.err(
            "Service `{s}` (pid: {}) faulted with message: {s}",
            .{ label, pid, fault_msg },
        );
    }
    if (linux.W.TERMSIG(status) != 0) {
        std.log.err(
            "Service `{s}` (pid: {}) exited from signal {}",
            .{ label, pid, linux.W.TERMSIG(status) },
        );
    }
    if (meta.errorReturnStackTrace()) |trace| {
        std.log.err("Error trace:", .{});
        std.debug.dumpStackTrace(trace);
    }
    if (meta.stackTrace()) |trace| {
        std.log.err("Stack trace:", .{});
        std.debug.dumpStackTrace(trace);
    }
    if (meta.faultStackTrace()) |trace| {
        std.log.err("Fault trace:", .{});
        std.debug.dumpStackTrace(trace);
    }
}
