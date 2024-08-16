const std = @import("std");

const Atomic = std.atomic.Value;

/// Thread-safe counter to track the lifetime of a shared resource.
/// This does not manage the resource directly. It is just a tool
/// that can be used by multiple contexts to communicate with each
/// other about the lifetime of a shared resource.
///
/// This can be used to determine whether a resource:
/// - is still alive and safe to use.
/// - is safe to deinitialize.
///
/// Initializes with refs = 1, assuming there is currently exactly
/// one valid reference, which will need `release` called when it
/// is no longer in use. Call `acquire` to register additional
/// references beyond the first.
pub const ReferenceCounter = struct {
    state: Atomic(u64) = Atomic(u64).init(@bitCast(State{ .refs = 1 })),

    /// If `refs > acquirers`, the resource is still alive.
    /// If `refs == acquirers`, the resource is dead.
    const State = packed struct {
        /// While the resource is still alive, this is the number of active references.
        /// After the resource dies, this value no longer has the same meaning.
        refs: i32 = 0,
        /// Number of threads currently in the process of attempting to acquire the resource.
        acquirers: i32 = 0,
    };

    const Self = @This();

    /// Acquire access to the shared resource in a new context.
    /// Call `release` when you are done using the resource in this context.
    ///
    /// If successfully acquired, the resource will be safe
    /// to use until you call `release` in the same context.
    ///
    /// Returns:
    /// - true: access granted, counter has incremented
    /// - false: access denied, already destroyed
    pub fn acquire(self: *Self) bool {
        const prior: State = @bitCast(self.state.fetchAdd(
            @bitCast(State{ .acquirers = 1, .refs = 1 }),
            .acquire,
        ));
        if (prior.refs > prior.acquirers) {
            _ = self.state.fetchSub(@bitCast(State{ .acquirers = 1 }), .monotonic);
            return true;
        }
        // resource was already destroyed
        _ = self.state.fetchSub(@bitCast(State{ .acquirers = 1, .refs = 1 }), .monotonic);
        return false;
    }

    /// Release a reference from a context where it is no longer in use.
    ///
    /// Returns:
    /// - true: this was the last reference. you should now destroy the resource.
    /// - false: there are still more references. don't do anything.
    pub fn release(self: *Self) bool {
        const prior: State = @bitCast(self.state.fetchSub(@bitCast(State{ .refs = 1 }), .acq_rel));
        // if this fails, the resource is already dead (analogous to double-free)
        std.debug.assert(prior.refs > prior.acquirers);
        return prior.refs == 1;
    }
};

test "sync.ref_counter: ReferenceCounter works" {
    var x = ReferenceCounter{};
    try std.testing.expect(x.acquire());
    try std.testing.expect(x.acquire());
    try std.testing.expect(x.acquire());
    try std.testing.expect(!x.release());
    try std.testing.expect(!x.release());
    try std.testing.expect(!x.release());
    try std.testing.expect(x.release());
}
