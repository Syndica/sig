//! Standard regions shared directly between services and the runner, and/or standard services.

const std = @import("std");

/// A service's view of its connection with the runner.
pub const Connection = struct {
    activity: *Activity.ServiceView,
};

pub const Region = extern struct {
    activity: Activity,
    exit: Exit,
};

/// Shared state between the service & the runner, for the service to notify the runner
/// about its activity (idle or active). It also allows the runner to send a cancel signal
/// to the service.
pub const Activity = extern struct {
    state: std.atomic.Value(State) = .init(.active),

    pub const State = enum(u8) {
        active,
        idle,
        canceled,
    };

    /// Should only be observed & used by the service.
    pub fn serviceView(activity: *Activity) ServiceView {
        return .{ .activity = activity };
    }

    /// Should only be observed & used by the service runner.
    pub fn runnerView(activity: *Activity) RunnerView {
        return .{ .activity = activity };
    }

    /// Should only be observed & used by the service.
    pub const ServiceView = struct {
        activity: *Activity,
        /// Number of times consecutive times the service
        /// has signalled idle since signalling activity.
        consecutive_idles: u32 = 0,

        /// Signal idle; the `threshold` parameter will be used so that the actual idle signal
        /// will only be sent if this function is called that many times consecutively without
        /// signalling activity.
        pub fn signalIdleAfterNCalls(self: *ServiceView, threshold: u32) error{Canceled}!void {
            if (self.consecutive_idles > threshold) {
                try Activity.signalIdle(.{
                    .state = &self.activity.state,
                });
            }
            self.consecutive_idles += 1;
        }

        pub fn signalActive(self: *ServiceView) error{Canceled}!void {
            try Activity.signalActive(.{
                .state = &self.activity.state,
            });
            self.consecutive_idles = 0;
        }
    };

    /// Should only be observed & used by the service runner.
    pub const RunnerView = struct {
        activity: *Activity,
        /// When this is set to `true`, the service runner is no longer allowed to read
        /// or write this service activity state.
        service_runner_is_done: bool = false,

        pub fn isActive(self: *const RunnerView) bool {
            return Activity.isActive(.{
                .state = &self.activity.state,
                .service_runner_is_done = &self.service_runner_is_done,
            });
        }

        pub fn cancel(self: *RunnerView) void {
            Activity.cancel(.{
                .state = &self.activity.state,
                .service_runner_is_done = &self.service_runner_is_done,
            });
        }
    };

    // -- Service API -- //

    /// Send signal to the runner that the service is idle.
    /// Also checks if the service runner has sent a cancelation signal.
    /// Also calls `std.atomic.spinLoopHint()`, unless a cancellation signal is received.
    fn signalIdle(params: struct {
        state: *std.atomic.Value(State),
    }) error{Canceled}!void {
        // we don't need a strong ordering on the exchange here, we mostly
        // just care about _eventually_ signalling that the service is idle.
        const prev_state = params.state.cmpxchgWeak(
            .active,
            .idle,
            .monotonic,
            .monotonic,
        ) orelse return;
        switch (prev_state) {
            .active, .idle => std.atomic.spinLoopHint(),
            .canceled => {
                @branchHint(.cold);
                return error.Canceled;
            },
        }
    }

    /// Called after `signalIdle` to indicate that activity is resuming.
    /// Also checks if the service runner has sent a cancellation signal.
    fn signalActive(params: struct {
        state: *std.atomic.Value(State),
    }) error{Canceled}!void {
        const prev_state = params.state.swap(.active, .monotonic);
        switch (prev_state) {
            .idle => {},
            .active => {
                // NOTE: permissively allow signalling active even if we haven't signalled idle.
            },
            .canceled => {
                @branchHint(.cold);
                return error.Canceled;
            },
        }
    }

    // -- Service Runner API -- //

    /// Called by the service runner to check whether the service is active.
    fn isActive(params: struct {
        state: *const std.atomic.Value(State),
        service_runner_is_done: *const bool,
    }) bool {
        if (params.service_runner_is_done.*) std.debug.panic(
            "The service runner is no longer allowed to read or write the service activity state.",
            .{},
        );
        return switch (params.state.load(.monotonic)) {
            .idle => false,
            .active => true,
            .canceled => std.debug.panic(
                "Invalid state; cancelation signal set by unknown means.",
                .{},
            ),
        };
    }

    /// Called by the service runner to signal to the service that it should cease operation.
    fn cancel(params: struct {
        state: *std.atomic.Value(State),
        service_runner_is_done: *bool,
    }) void {
        if (params.service_runner_is_done.*) std.debug.panic(
            "The service runner is no longer allowed to read or write the service activity state.",
            .{},
        );
        params.service_runner_is_done.* = true;
        params.state.store(.canceled, .monotonic);
    }
};

/// This value should be written to before a service exits. Multiple traces (e.g. error return, and
/// fault) may be written to.
/// Each one is equivalent to an std.builtin.StackTrace.
pub const Exit = extern struct {
    /// when the service returned in an error
    error_return: [max_depth:empty_entry]usize = @splat(empty_entry),
    error_return_index: usize = 0,

    /// for panics, segfaults, etc
    trace: [max_depth:empty_entry]usize = @splat(empty_entry),
    trace_index: usize = 0,

    fault: [max_depth:empty_entry]usize = @splat(empty_entry),
    fault_index: usize = 0,

    error_name: [max_error_name:0]u8 = @splat(0),
    panic_msg: [max_panic_msg:0]u8 = @splat(0),
    fault_msg: [max_fault_msg:0]u8 = @splat(0),

    const empty_entry = std.math.maxInt(usize);

    // chosen arbitrarily
    const max_depth = 31;
    const max_error_name = 127;
    const max_panic_msg = 127;
    const max_fault_msg = 127;

    pub fn errorReturnStackTrace(self: *Exit) ?std.builtin.StackTrace {
        const instruction_addresses: []usize = std.mem.span(@as(
            [*:empty_entry]usize,
            &self.error_return,
        ));
        if (instruction_addresses.len == 0) return null;
        return .{
            .index = self.error_return_index,
            .instruction_addresses = instruction_addresses,
        };
    }

    pub fn stackTrace(self: *Exit) ?std.builtin.StackTrace {
        const instruction_addresses: []usize = std.mem.span(@as(
            [*:empty_entry]usize,
            &self.trace,
        ));
        if (instruction_addresses.len == 0) return null;
        return .{
            .index = self.trace_index,
            .instruction_addresses = instruction_addresses,
        };
    }

    pub fn faultStackTrace(self: *Exit) ?std.builtin.StackTrace {
        const instruction_addresses: []usize = std.mem.span(@as(
            [*:empty_entry]usize,
            &self.fault,
        ));
        if (instruction_addresses.len == 0) return null;
        return .{
            .index = self.fault_index,
            .instruction_addresses = instruction_addresses,
        };
    }

    pub fn errorName(self: *const Exit) ?[]const u8 {
        const str = std.mem.span(@as([*:0]const u8, &self.error_name));
        if (str.len == 0) return null;
        return str;
    }

    pub fn panicMsg(self: *const Exit) ?[]const u8 {
        const str = std.mem.span(@as([*:0]const u8, &self.panic_msg));
        if (str.len == 0) return null;
        return str;
    }

    pub fn faultMsg(self: *const Exit) ?[]const u8 {
        const str = std.mem.span(@as([*:0]const u8, &self.fault_msg));
        if (str.len == 0) return null;
        return str;
    }
};
