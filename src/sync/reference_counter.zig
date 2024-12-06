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
        /// this is just the start of the data, with the payload bytes after it.
        ref_count: *ReferenceCounter,
        len: usize,

        const Self = @This();
        const Allocator = std.mem.Allocator;

        const alignment = @max(@alignOf(T), @alignOf(ReferenceCounter));
        const reserved_space = @max(@sizeOf(ReferenceCounter), alignment);

        pub fn alloc(allocator: Allocator, size: usize) Allocator.Error!Self {
            const data = try allocator
                .alignedAlloc(T, alignment, size + reserved_space);

            const ref_count: *ReferenceCounter = @ptrCast(@alignCast(data.ptr));
            ref_count.* = .{};

            return .{ .ref_count = ref_count, .len = data.len };
        }

        pub fn acquire(self: Self) Self {
            std.debug.assert(self.ref_count.acquire());
            return self;
        }

        pub fn deinit(self: Self, allocator: Allocator) void {
            if (self.ref_count.release()) {
                const ptr: [*]align(alignment) T = @ptrCast(self.ref_count);
                allocator.free(ptr[0..self.len]);
            }
        }

        /// value must be the exact original slice returned by `payload`
        pub fn deinitPayload(value: []const T, allocator: Allocator) void {
            const full_ptr_int = @intFromPtr(value.ptr) - reserved_space;
            const full_allocation_ptr: [*]align(alignment) T = @ptrFromInt(full_ptr_int);
            const self = Self{
                .ref_count = @ptrCast(full_allocation_ptr),
                .len = reserved_space + value.len,
            };

            self.deinit(allocator);
        }

        pub fn payload(self: Self) []T {
            const ptr: [*]align(alignment) T = @ptrCast(self.ref_count);
            return ptr[reserved_space..self.len];
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
