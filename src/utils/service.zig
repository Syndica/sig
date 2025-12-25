const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Atomic = std.atomic.Value;

const Logger = sig.trace.Logger("service_manager");

/// High level manager for long-running threads and the state
/// shared by those threads.
///
/// You can add threads or state, then await all threads and
/// clean up their state.
pub const ServiceManager = struct {
    logger: Logger,
    /// Threads to join.
    threads: ArrayListUnmanaged(std.Thread),
    exit: *Atomic(bool),
    /// State to free after all threads join.
    arena: ArenaAllocator,
    /// Logic to run after all threads join.
    defers: DeferList,
    name: []const u8,
    default_run_config: RunConfig,

    const Self = @This();

    pub const LOG_SCOPE = "service_manager";

    pub fn init(
        backing_allocator: Allocator,
        logger: Logger,
        exit: *Atomic(bool),
        name: []const u8,
        default_run_config: RunConfig,
    ) Self {
        return .{
            .logger = logger,
            .exit = exit,
            .threads = .{},
            .arena = ArenaAllocator.init(backing_allocator),
            .defers = .{ .allocator = backing_allocator },
            .name = name,
            .default_run_config = default_run_config,
        };
    }

    /// Spawn a thread to be managed.
    /// The function may be restarted periodically, according to default_run_config.
    pub fn spawn(
        self: *Self,
        comptime name: []const u8,
        comptime function: anytype,
        args: anytype,
    ) !void {
        try self.spawnCustom(name, self.default_run_config, function, args);
    }

    /// Spawn a thread to be managed.
    /// The function may be restarted periodically, according to the provided config.
    pub fn spawnCustom(
        self: *Self,
        comptime name: []const u8,
        config: RunConfig,
        comptime function: anytype,
        args: anytype,
    ) !void {
        const thread = try spawnService(self.logger, self.exit, name, config, function, args);
        try self.threads.append(self.arena.allocator(), thread);
    }

    /// Wait for all threads to exit, then return.
    pub fn join(self: *Self) void {
        for (self.threads.items) |t| t.join();
        self.threads.clearAndFree(self.arena.allocator());
    }

    /// 1. Signal the threads to exit.
    /// 2. Wait for threads to exit.
    /// 3. Deinit the shared state from those threads.
    pub fn deinit(self: *Self) void {
        self.logger.info().logf("Cleaning up: {s}", .{self.name});
        self.join();
        self.defers.deinit();
        self.arena.deinit();
        self.logger.info().logf("Finished cleaning up: {s}", .{self.name});
    }
};

pub const RunConfig = struct {
    /// what to do when the task returns without error
    return_handler: ReturnHandler = .{},
    /// what to do when the task returns an error
    error_handler: ReturnHandler = .{},
    /// The minimum amount of time to spend on the entire loop,
    /// including the logic plus the pause.
    min_loop_duration_ns: u64 = 0,
    /// The minimum amount of time to pause after one iteration
    /// of the function completes, before restarting the function.
    min_pause_ns: u64 = 0,

    pub const loop: RunConfig = .{ .return_handler = .{ .log_return = false } };
};

pub const ReturnHandler = struct {
    /// Loop the task until the return event occurs this many times.
    /// null means an infinite loop.
    max_iterations: ?u64 = null,
    /// Whether to set the `exit` bool to true after max_iterations
    /// is reached.
    set_exit_on_completion: bool = false,
    /// Whether to log after each return.
    log_return: bool = true,
    /// Whether to log when exiting on the final return.
    log_exit: bool = true,
};

/// Spawn a thread with a looping/restart policy using runService.
/// The function may be restarted periodically, according to the provided config.
pub fn spawnService(
    logger: Logger,
    exit: *Atomic(bool),
    name: []const u8,
    config: RunConfig,
    function: anytype,
    args: anytype,
) std.Thread.SpawnError!std.Thread {
    var thread = try std.Thread.spawn(
        .{},
        runService,
        .{ logger, exit, name, config, function, args },
    );

    thread.setName(name[0..@min(name.len, std.Thread.max_name_len)]) catch |e|
        logger.err().logf("failed to set name for thread '{s}' - {}", .{ name, e });

    return thread;
}

/// Convert a short-lived task into a long-lived service by looping it,
/// or make a service resilient by restarting it on failure.
///
/// It's guaranteed to run at least once in order to not race initialization with
/// the `exit` flag.
pub fn runService(
    logger: Logger,
    exit: *Atomic(bool),
    maybe_name: ?[]const u8,
    config: RunConfig,
    function: anytype,
    args: anytype,
) !void {
    var buf: [16]u8 = undefined;
    const name = maybe_name orelse try std.fmt.bufPrint(
        &buf,
        "thread {d}",
        .{std.Thread.getCurrentId()},
    );
    logger.info().logf("starting {s}", .{name});
    var timer = try std.time.Timer.start();
    var last_iteration: u64 = 0;
    var num_oks: u64 = 0;
    var num_errors: u64 = 0;

    var first_run: bool = true;
    while (first_run or !exit.load(.acquire)) {
        first_run = false;

        const result = @call(.auto, function, args);

        // identify result
        if (result) |_| num_oks += 1 else |_| num_errors += 1;
        const handler, //
        const num_events, //
        const event_name, //
        const level_logger, //
        const maybe_trace: ?*std.builtin.StackTrace //
        = if (result) |_|
            .{ config.return_handler, num_oks, "return", logger.info(), null }
        else |_|
            .{ config.error_handler, num_errors, "error", logger.err(), @errorReturnTrace() };

        // handle result
        if (handler.log_return) {
            level_logger.logf(
                "{s} has {s}ed: {any} {?}",
                .{ name, event_name, result, maybe_trace },
            );
            // reset the stack trace so that if it returns an error in a loop it doesn't try to infinitely
            // increment the stack trace index and concatenate the previous traces.
            if (maybe_trace) |trace| trace.index = 0;
        }
        if (handler.max_iterations) |max| if (num_events >= max) {
            if (handler.set_exit_on_completion) {
                if (handler.log_exit) level_logger.logf(
                    "Signaling exit due to {} {s}s from {s}",
                    .{ num_events, event_name, name },
                );
                exit.store(true, .release);
            } else if (handler.log_exit) level_logger.logf(
                "Exiting {s} due to {} {s}s",
                .{ name, num_events, event_name },
            );
            return result;
        };

        // sleep before looping, if necessary
        last_iteration = timer.lap();
        std.Thread.sleep(@max(
            config.min_pause_ns,
            config.min_loop_duration_ns -| last_iteration,
        ));
    }

    logger.info().logf("Exiting {s} because the exit signal was received.", .{name});
}

/// Defer actions until later.
///
/// The `defer` keyword always defers to the end of the current
/// scope, which can sometimes be overly constraining.
///
/// Use `DeferList` when you need to defer actions to execute
/// in a broader scope.
///
/// 1. Add defers using `deferCall`.
/// 2. Return this struct to the broader scope.
/// 3. Call `deinit` to run all the defers.
pub const DeferList = struct {
    allocator: std.mem.Allocator,
    defers: std.ArrayListUnmanaged(DeferredCall) = .{},
    params: std.ArrayListUnmanaged(u8) = .{},

    const DeferredCall = struct {
        func: *const fn (args: *const anyopaque) void,
        params_start: usize,
    };

    /// If this fails to allocate, it will run `function(args...)` before returning the error.
    pub fn deferCall(
        self: *DeferList,
        comptime function: anytype,
        args: anytype,
    ) std.mem.Allocator.Error!void {
        const Args = @TypeOf(args);
        const S = struct {
            fn func(args_ptr: *const anyopaque) void {
                const params_ptr: *align(1) const Args = @ptrCast(args_ptr);
                @call(.auto, function, params_ptr.*);
            }
        };

        errdefer @call(.auto, function, args);
        try self.defers.ensureUnusedCapacity(self.allocator, 1);
        try self.params.ensureUnusedCapacity(self.allocator, @sizeOf(Args));

        self.defers.appendAssumeCapacity(.{
            .func = S.func,
            .params_start = self.params.items.len,
        });
        self.params.appendSliceAssumeCapacity(std.mem.asBytes(&args));
    }

    /// Invoke all deferred calls, emptying internal buffers without deinitializing.
    pub fn invoke(self: *DeferList) void {
        for (1..self.defers.items.len + 1) |fwd_i| {
            const rev_i = self.defers.items.len - fwd_i;
            const deferred = self.defers.items[rev_i];
            deferred.func(self.params.items.ptr + deferred.params_start);
        }
        self.defers.clearRetainingCapacity();
        self.params.clearRetainingCapacity();
    }

    /// Invoke all deferred calls, then deinit this struct.
    pub fn deinit(self: *DeferList) void {
        self.invoke();
        self.params.deinit(self.allocator);
        self.defers.deinit(self.allocator);
    }
};

test DeferList {
    const allocator = std.testing.allocator;
    var defers: DeferList = .{ .allocator = allocator };
    defer defers.deinit();

    {
        // if this leaks, that means something is wrong with
        // the implementation of `DeferList`.
        const leaky_allocation = try allocator.alloc(u8, 32);

        const S = struct {
            fn free(_allocator: std.mem.Allocator, buffer: []u8) void {
                _allocator.free(buffer);
            }
        };

        try defers.deferCall(S.free, .{ allocator, leaky_allocation });
        // defer outlives this block
    }

    var output: std.ArrayListUnmanaged(u8) = .{};
    defer output.deinit(allocator);

    // defers run in reverse order, just as normal defers
    for ([_][]const u8{ " world!", "Hello," }) |slice| {
        const S = struct {
            fn append(out: *std.ArrayListUnmanaged(u8), bytes: []const u8) void {
                out.appendSliceAssumeCapacity(bytes);
            }
        };

        try output.ensureUnusedCapacity(allocator, output.capacity + slice.len);
        try defers.deferCall(S.append, .{ &output, slice });
    }

    defers.invoke();
    try std.testing.expectEqualStrings("Hello, world!", output.items);
}
