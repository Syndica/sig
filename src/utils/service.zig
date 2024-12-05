const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Atomic = std.atomic.Value;

const Lazy = sig.utils.lazy.Lazy;
const Logger = sig.trace.Logger;
const ScopedLogger = sig.trace.ScopedLogger;

/// High level manager for long-running threads and the state
/// shared by those threads.
///
/// You can add threads or state, then await all threads and
/// clean up their state.
pub const ServiceManager = struct {
    logger: ScopedLogger(@typeName(Self)),
    /// Threads to join.
    threads: ArrayListUnmanaged(std.Thread),
    exit: *Atomic(bool),
    /// State to free after all threads join.
    arena: ArenaAllocator,
    /// Logic to run after all threads join.
    defers: DeferList,
    name: []const u8,
    default_run_config: RunConfig,
    default_spawn_config: std.Thread.SpawnConfig,

    const Self = @This();

    pub fn init(
        backing_allocator: Allocator,
        logger: Logger,
        exit: *Atomic(bool),
        name: []const u8,
        default_run_config: RunConfig,
        default_spawn_config: std.Thread.SpawnConfig,
    ) Self {
        return .{
            .logger = logger.withScope(@typeName(Self)),
            .exit = exit,
            .threads = .{},
            .arena = ArenaAllocator.init(backing_allocator),
            .defers = .{ .allocator = backing_allocator },
            .name = name,
            .default_run_config = default_run_config,
            .default_spawn_config = default_spawn_config,
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
        try self.spawnCustom(
            name,
            self.default_run_config,
            self.default_spawn_config,
            function,
            args,
        );
    }

    /// Spawn a thread to be managed.
    /// The function may be restarted periodically, according to the provided config.
    fn spawnCustom(
        self: *Self,
        comptime name: []const u8,
        run_config: ?RunConfig,
        spawn_config: std.Thread.SpawnConfig,
        comptime function: anytype,
        args: anytype,
    ) !void {
        const allocator = self.arena.allocator();

        var thread = try std.Thread.spawn(
            spawn_config,
            runService,
            .{
                self.logger,
                self.exit,
                name,
                run_config orelse self.default_run_config,
                function,
                args,
            },
        );

        thread.setName(name) catch {};
        try self.threads.append(allocator, thread);
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

/// Convert a short-lived task into a long-lived service by looping it,
/// or make a service resilient by restarting it on failure.
///
/// It's guaranteed to run at least once in order to not race initialization with
/// the `exit` flag.
pub fn runService(
    logger: ScopedLogger(@typeName(ServiceManager)),
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
    logger.info().logf("Starting {s}", .{name});
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
        const handler, const num_events, const event_name, const level_logger = if (result) |_|
            .{ config.return_handler, num_oks, "return", logger.info() }
        else |_|
            .{ config.error_handler, num_errors, "error", logger.warn() };

        // handle result
        if (handler.log_return) {
            level_logger.logf("{s} has {s}ed: {any}", .{ name, event_name, result });
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
        std.time.sleep(@max(
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
    allocator: Allocator,
    defers: ArrayListUnmanaged(Lazy(void)) = .{},

    const Self = @This();

    pub fn deferCall(
        self: *Self,
        comptime function: anytype,
        args: anytype,
    ) !void {
        const lazy = try Lazy(void).init(self.allocator, function, args);
        try self.defers.append(self.allocator, lazy);
    }

    /// Runs all the defers, then deinits this struct.
    pub fn deinit(self: *Self) void {
        for (1..self.defers.items.len + 1) |i| {
            self.defers.items[self.defers.items.len - i].call();
        }
        self.defers.deinit(self.allocator);
    }
};
