const std = @import("std");
const network = @import("zig-network");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Value;

const Logger = sig.trace.Logger;

/// High level manager for long-running threads and the state
/// shared by those threads.
///
/// Provides facilities to wait for the threads to complete,
/// and to clean up their shared state.
pub const ServiceManager = struct {
    allocator: Allocator,
    exit: *Atomic(bool),
    runner: ServiceRunner,
    threads: std.ArrayList(std.Thread),
    shared_state: std.ArrayList(AnonBox),

    const Self = @This();

    pub fn init(allocator: Allocator, logger: Logger, exit: *Atomic(bool)) Self {
        return .{
            .allocator = allocator,
            .exit = exit,
            .runner = .{ .logger = logger, .exit = exit },
            .threads = std.ArrayList(std.Thread).init(allocator),
            .shared_state = std.ArrayList(AnonBox).init(allocator),
        };
    }

    /// Allocate state to manage with this struct.
    /// Use for state that should outlive the managed threads.
    /// Typically this would be state that is shared by multiple threads,
    /// or state used to orchestrate an individual thread.
    pub fn create( // TODO: arena instead?
        self: *Self,
        comptime T: type,
        comptime deinitFn: ?fn (*T) void,
    ) Allocator.Error!*T {
        const ptr, const box = try AnonBox.init(T, deinitFn, self.allocator);
        try self.shared_state.append(box);
        return ptr;
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
            ServiceRunner.runService,
            .{ &self.runner, config, function, args },
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
        for (self.shared_state.items) |s| s.deinit();
        self.threads.deinit();
        self.shared_state.deinit();
    }
};

/// Convert a short-lived task into a long-lived service by looping it,
/// or make a service resilient by restarting it on failure.
pub const ServiceRunner = struct {
    logger: Logger,
    exit: *Atomic(bool),
    service_counter: Atomic(usize) = .{ .raw = 0 },

    const Self = @This();

    pub fn runService(
        self: *Self,
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
        self.logger.infof("Starting {s}", .{name});
        var timer = try std.time.Timer.start();
        var last_iteration: u64 = 0;
        while (!self.exit.load(.unordered)) {
            if (@call(.auto, function, args)) |ok| {
                switch (config.error_handler) {
                    .keep_looping => {},
                    .just_return => {
                        self.logger.errf("Exiting {s} due to return", .{name});
                        return ok;
                    },
                    .set_exit_and_return => {
                        self.logger.errf("Signalling exit due to return from {s}", .{name});
                        self.exit.store(true, .monotonic);
                        return ok;
                    },
                }
            } else |err| {
                switch (config.error_handler) {
                    .keep_looping => self.logger.errf("Unhandled error in {s}: {}", .{ name, err }),
                    .just_return => {
                        self.logger.errf("Exiting {s} due to error: {}", .{ name, err });
                        return err;
                    },
                    .set_exit_and_return => {
                        self.logger.errf("Signalling exit due to error in {s}: {}", .{ name, err });
                        self.exit.store(true, .monotonic);
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

/// Create a pointer and manage its lifetime, without concern for its type.
///
/// Useful when you need to manage the lifetime of data in a different
/// context from where it is allocated or used.
pub const AnonBox = struct {
    allocator: Allocator,
    state: *anyopaque,
    deinitFn: *const fn (*anyopaque) void,

    const Self = @This();

    pub fn init(
        comptime T: type,
        comptime deinitFn: ?fn (*T) void,
        allocator: Allocator,
    ) Allocator.Error!struct { *T, Self } {
        const ptr = try allocator.create(T);
        const self = .{
            .allocator = allocator,
            .state = @as(*anyopaque, @ptrCast(@alignCast(ptr))),
            .deinitFn = struct {
                fn deinit(opaque_ptr: *anyopaque) void {
                    if (deinitFn) |f| f(@ptrCast(@alignCast(opaque_ptr))) else {}
                }
            }.deinit,
        };
        return .{ ptr, self };
    }

    pub fn deinit(self: Self) void {
        self.deinitFn(self.state);
    }
};
