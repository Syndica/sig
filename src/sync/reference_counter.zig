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
pub const ReferenceCounter = extern struct {
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
            .monotonic,
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
        const prior: State = @bitCast(self.state.fetchSub(
            @bitCast(State{ .refs = 1 }),
            .release,
        ));
        // if this fails, the resource is already dead (analogous to double-free)
        std.debug.assert(prior.refs > prior.acquirers);

        if (prior.refs == 1) {
            _ = self.state.load(.acquire);
            return true;
        }
        return false;
    }
};

/// A reference counted slice that is only freed when the last
/// reference is deinitialized.
///
/// The reference counter exists behind the pointer that is freed
/// after checking the reference counter. To use this safely, you
/// must ensure that there are no races that may trigger a UAF.
///
/// In other words, you must ensure that the last copy of a slice
/// cannot possibly call `deinit` while another thread is calling
/// (or preparing to call) `acquire`. The final call to deinit must
/// coincide with a guarantee that the item will never be acquired
/// again. You may need some kind of synchronization mechanism to
/// provide this guarantee.
pub fn RcSlice(T: type) type {
    return struct {
        /// contains a reference counter followed by an array of T, as in:
        ///    { ReferenceCounter, T, T, T, T, ..., T }
        /// To access the contained data, use the methods `refCount` or `payload`.
        ptr: [*]align(alignment) u8,
        /// The number of T elements, *not* the number of bytes.
        /// For the total number of allocated bytes, use `totalSize`
        len: usize,

        const Self = @This();
        const Allocator = std.mem.Allocator;

        const alignment = @max(@alignOf(T), @alignOf(ReferenceCounter));
        const reserved_space = std.mem.alignForward(usize, @sizeOf(ReferenceCounter), @alignOf(T));

        pub fn alloc(allocator: Allocator, n: usize) Allocator.Error!Self {
            const total_size = totalSize(n) catch return error.OutOfMemory;
            const bytes = try allocator.alignedAlloc(u8, alignment, total_size);

            @as(*ReferenceCounter, @ptrCast(bytes.ptr)).* = .{};
            return .{ .ptr = @alignCast(bytes.ptr), .len = n };
        }

        pub fn deinit(self: Self, allocator: Allocator) void {
            if (self.refCount().release()) {
                const total_size = totalSize(self.len) catch unreachable;
                allocator.free(self.ptr[0..total_size]);
            }
        }

        /// value must be the exact original slice returned by `payload`
        /// otherwise this function has undefined behavior
        pub fn deinitPayload(value: []const T, allocator: Allocator) void {
            const value_ptr: [*]u8 = @constCast(@ptrCast(value.ptr));
            const self = Self{
                .ptr = @alignCast(value_ptr - reserved_space),
                .len = value.len,
            };

            self.deinit(allocator);
        }

        pub fn acquire(self: Self) Self {
            std.debug.assert(self.refCount().acquire());
            return self;
        }

        pub fn payload(self: Self) []T {
            const ptr: [*]T = @ptrCast(self.ptr[reserved_space..]);
            return ptr[0..self.len];
        }

        fn refCount(self: Self) *ReferenceCounter {
            return @ptrCast(self.ptr);
        }

        /// The total number of bytes that need to be allocated to support this many T's
        fn totalSize(num_of_T: usize) error{Overflow}!usize {
            const bytes_for_T = try std.math.mul(usize, @sizeOf(T), num_of_T);
            return try std.math.add(usize, reserved_space, bytes_for_T);
        }
    };
}

test ReferenceCounter {
    var x = ReferenceCounter{};
    try std.testing.expect(x.acquire());
    try std.testing.expect(x.acquire());
    try std.testing.expect(x.acquire());
    try std.testing.expect(!x.release());
    try std.testing.expect(!x.release());
    try std.testing.expect(!x.release());
    try std.testing.expect(x.release());
}

test "RcSlice payload has the correct data" {
    const sig = @import("../sig.zig");
    const slice = try RcSlice(u8).alloc(std.testing.allocator, 5);
    defer slice.deinit(std.testing.allocator);
    @memcpy(slice.payload(), "hello");
    const hello: *const [5]u8 = "hello";
    try std.testing.expectEqual(5, slice.payload().len);
    try std.testing.expect(sig.utils.types.eql(hello, slice.payload()[0..5]));
}
