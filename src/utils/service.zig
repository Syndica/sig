const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Value;

const Lazy = sig.utils.lazy.Lazy;
const Level = sig.trace.Level;
const Logger = sig.trace.Logger;

/// High level manager for long-running threads and the state
/// shared by those threads.
///
/// You can add threads or state, then await all threads and
/// clean up their state.
pub const ServiceManager = struct {
    logger: *Logger,
    /// Signal that is expected to tell all threads to exit.
    exit: *Atomic(bool),
    /// Threads to join.
    threads: ArrayList(std.Thread),
    /// State to free after all threads join.
    _arena: ArenaAllocator,
    /// Logic to run after all threads join.
    defers: DeferList,
    name: []const u8,
    default_run_config: RunConfig,
    default_spawn_config: std.Thread.SpawnConfig,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: *Logger,
        exit: *Atomic(bool),
        name: []const u8,
        default_run_config: RunConfig,
        default_spawn_config: std.Thread.SpawnConfig,
    ) Self {
        return .{
            .logger = logger,
            .exit = exit,
            .threads = ArrayList(std.Thread).init(allocator),
            ._arena = ArenaAllocator.init(allocator),
            .defers = DeferList.init(allocator),
            .name = name,
            .default_run_config = default_run_config,
            .default_spawn_config = default_spawn_config,
        };
    }

    /// Allocator for state to manage with this struct.
    ///
    /// Use this for state that should outlive the managed threads,
    /// but may be freed as soon as those threads are joined.
    ///
    /// You must ensure that this is not used to allocate anything
    /// that will be used after this struct is deinitialized.
    pub fn arena(self: *Self) Allocator {
        return self._arena.allocator();
    }

    /// Spawn a thread to be managed.
    /// The function may be restarted periodically, according to default_run_config.
    pub fn spawn(
        self: *Self,
        name: ?[]const u8,
        comptime function: anytype,
        args: anytype,
    ) !void {
        return self.spawnCustom(name, self.default_run_config, self.default_spawn_config, function, args);
    }

    /// Spawn a thread to be managed.
    /// The function may be restarted periodically, according to the provided config.
    pub fn spawnCustom(
        self: *Self,
        maybe_name: ?[]const u8,
        run_config: ?RunConfig,
        spawn_config: std.Thread.SpawnConfig,
        comptime function: anytype,
        args: anytype,
    ) !void {
        var thread = try std.Thread.spawn(
            spawn_config,
            runService,
            .{ self.logger, self.exit, maybe_name, run_config orelse self.default_run_config, function, args },
        );
        if (maybe_name) |name| thread.setName(name) catch {};
        try self.threads.append(thread);
    }

    /// Wait for all threads to exit, then return.
    pub fn join(self: *Self) void {
        for (self.threads.items) |t| t.join();
        self.threads.clearRetainingCapacity();
    }

    /// 1. Signal the threads to exit.
    /// 2. Wait for threads to exit.
    /// 3. Deinit the shared state from those threads.
    pub fn deinit(self: Self) void {
        self.logger.infof("Cleaning up: {s}", .{self.name});
        self.exit.store(true, .monotonic);
        for (self.threads.items) |t| t.join();
        self.threads.deinit();
        self.defers.deinit();
        self._arena.deinit();
        self.logger.infof("Finished cleaning up: {s}", .{self.name});
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
pub fn runService(
    logger: *Logger,
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
    logger.infof("Starting {s}", .{name});
    var timer = try std.time.Timer.start();
    var last_iteration: u64 = 0;
    var num_oks: u64 = 0;
    var num_errors: u64 = 0;
    while (!exit.load(.unordered)) {
        const result = @call(.auto, function, args);

        // identify result
        if (result) |_| num_oks += 1 else |_| num_errors += 1;
        const handler, const num_events, const event_name, const level = if (result) |_|
            .{ config.return_handler, num_oks, "return", Level.info }
        else |_|
            .{ config.error_handler, num_errors, "error", Level.err };

        // handle result
        if (handler.log_return) {
            logger.logf(level, "{s} has {s}ed: {any}", .{ name, event_name, result });
        }
        if (handler.max_iterations) |max| if (num_events >= max) {
            if (handler.set_exit_on_completion) {
                if (handler.log_exit) logger.logf(
                    level,
                    "Signaling exit due to {} {s}s from {s}",
                    .{ num_events, event_name, name },
                );
                exit.store(true, .monotonic);
            } else if (handler.log_exit) logger.logf(
                level,
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
    logger.infof("Exiting {s} because the exit signal was received.", .{name});
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
    defers: ArrayList(Lazy(void)),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .defers = ArrayList(Lazy(void)).init(allocator) };
    }

    pub fn deferCall(
        self: *Self,
        comptime function: anytype,
        args: anytype,
    ) !void {
        const lazy = try Lazy(void).init(self.defers.allocator, function, args);
        try self.defers.append(lazy);
    }

    /// Runs all the defers, then deinits this struct.
    pub fn deinit(self: Self) void {
        for (1..self.defers.items.len + 1) |i| {
            self.defers.items[self.defers.items.len - i].call();
        }
        self.defers.deinit();
    }
};
