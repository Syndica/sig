const std = @import("std");
const network = @import("zig-network");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Value;

const Logger = sig.trace.Logger;
const Lazy = sig.utils.lazy.Lazy;

/// High level manager for long-running threads and the state
/// shared by those threads.
///
/// You can add threads or state, then await all threads and
/// clean up their state.
pub const ServiceManager = struct {
    logger: Logger,
    /// Signal that is expected to tell all threads to exit.
    exit: *Atomic(bool),
    /// Threads to join.
    threads: std.ArrayList(std.Thread),
    /// State to free after all threads join.
    _arena: ArenaAllocator,
    /// Logic to run after all threads join.
    defers: DeferList,

    const Self = @This();

    pub fn init(allocator: Allocator, logger: Logger, exit: *Atomic(bool)) Self {
        return .{
            .logger = logger,
            .exit = exit,
            .threads = std.ArrayList(std.Thread).init(allocator),
            ._arena = ArenaAllocator.init(allocator),
            .defers = DeferList.init(allocator),
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
    /// The function may be restarted periodically, according to the config.
    pub fn spawn(
        self: *Self,
        config: RunConfig,
        comptime function: anytype,
        args: anytype,
    ) !void {
        var thread = try std.Thread.spawn(
            .{},
            runService,
            .{ self.logger, self.exit, config, function, args },
        );
        if (config.name) |name| thread.setName(name) catch {};
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
        self.exit.store(true, .monotonic);
        for (self.threads.items) |t| t.join();
        self.threads.deinit();
        self.defers.deinit();
        self._arena.deinit();
    }
};

pub const RunConfig = struct {
    name: ?[]const u8 = null,
    /// what to do when the task returns without error
    return_handler: ReturnHandler = .keep_looping,
    /// what to do when the task returns with an error
    error_handler: ReturnHandler = .keep_looping,
    /// The minimum amount of time to spend on the entire loop,
    /// including the logic plus the pause.
    min_loop_duration_ns: u64 = 0,
    /// The minimum amount of time to pause after one iteration
    /// of the function completes, before restarting the function.
    min_pause_ns: u64 = 0,
};

pub const ReturnHandler = enum {
    keep_looping,
    just_return,
    set_exit_and_return,
};

/// Convert a short-lived task into a long-lived service by looping it,
/// or make a service resilient by restarting it on failure.
pub fn runService(
    logger: Logger,
    exit: *Atomic(bool),
    config: RunConfig,
    function: anytype,
    args: anytype,
) !void {
    var buf: [16]u8 = undefined;
    const name = config.name orelse try std.fmt.bufPrint(
        &buf,
        "thread {d}",
        .{std.Thread.getCurrentId()},
    );
    logger.infof("Starting {s}", .{name});
    var timer = try std.time.Timer.start();
    var last_iteration: u64 = 0;
    while (!exit.load(.unordered)) {
        if (@call(.auto, function, args)) |ok| {
            switch (config.error_handler) {
                .keep_looping => {},
                .just_return => {
                    logger.errf("Exiting {s} due to return", .{name});
                    return ok;
                },
                .set_exit_and_return => {
                    logger.errf("Signalling exit due to return from {s}", .{name});
                    exit.store(true, .monotonic);
                    return ok;
                },
            }
        } else |err| {
            switch (config.error_handler) {
                .keep_looping => logger.errf("Unhandled error in {s}: {}", .{ name, err }),
                .just_return => {
                    logger.errf("Exiting {s} due to error: {}", .{ name, err });
                    return err;
                },
                .set_exit_and_return => {
                    logger.errf("Signalling exit due to error in {s}: {}", .{ name, err });
                    exit.store(true, .monotonic);
                    return err;
                },
            }
        }
        last_iteration = timer.lap();
        std.time.sleep(@max(
            config.min_pause_ns,
            config.min_loop_duration_ns -| last_iteration,
        ));
    }
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
    defers: std.ArrayList(Lazy(void)),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .defers = std.ArrayList(Lazy(void)).init(allocator) };
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
