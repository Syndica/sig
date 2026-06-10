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

    pub const init: ReferenceCounter = .{ .state = .init(@bitCast(State{ .refs = 1 })) };

    /// If `refs > acquirers`, the resource is still alive.
    /// If `refs == acquirers`, the resource is dead.
    const State = packed struct {
        /// While the resource is still alive, this is the number of active references.
        /// After the resource dies, this value no longer has the same meaning.
        refs: i32 = 0,
        /// Number of threads currently in the process of attempting to acquire the resource.
        acquirers: i32 = 0,
    };

    /// Acquire access to the shared resource in a new context.
    /// Call `release` when you are done using the resource in this context.
    ///
    /// If successfully acquired, the resource will be safe
    /// to use until you call `release` in the same context.
    ///
    /// Returns:
    /// - true: access granted, counter has incremented
    /// - false: access denied, already destroyed
    pub fn acquire(self: *ReferenceCounter) bool {
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
    pub fn release(self: *ReferenceCounter) bool {
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

    /// Checks that our resource still has references.
    ///
    /// Returns:
    /// - true: there is at least 1 remaining reference
    /// - false: there are no more references
    pub fn isAlive(self: *ReferenceCounter) bool {
        const current: State = @bitCast(self.state.load(.seq_cst));
        return current.refs >= 1;
    }

    /// Resets a reference count representing a dead resource (rc=0) to one
    /// representing an alive resource (rc=1).
    pub fn reset(self: *ReferenceCounter) void {
        const prior: State = @bitCast(self.state.load(.acquire));
        if (prior.refs != 0) {
            unreachable; // tried to reset alive reference counter
        }
        self.state.store(@bitCast(State{ .refs = 1 }), .release);
    }
};

/// A reference counted item that is only freed when the last
/// reference is deinitialized.
///
/// See RcBase for lifetime requirements
pub fn Rc(T: type) type {
    return struct {
        ptr: RcBase(T),

        const Self = @This();
        const Allocator = std.mem.Allocator;

        pub fn create(allocator: Allocator) Allocator.Error!Self {
            return .{ .ptr = try RcBase(T).alloc(allocator, 1) };
        }

        pub fn deinit(self: Self, allocator: Allocator) void {
            self.ptr.deinit(allocator, 1);
        }

        pub fn acquire(self: Self) Self {
            _ = self.ptr.acquire();
            return self;
        }

        /// on the final release, returns the slice of bytes from
        /// the initial allocation which need to be freed.
        pub fn release(self: Self) ?[]align(RcBase(T).alignment) const u8 {
            return self.ptr.release(1);
        }

        pub fn payload(self: Self) *T {
            return @ptrCast(self.ptr.payload());
        }

        /// input must be the same pointer returned by `payload`
        /// otherwise this function has undefined behavior
        pub fn fromPayload(value: *const T) Self {
            return .{ .ptr = RcBase(T).fromPayload(@ptrCast(value)) };
        }
    };
}

/// A reference counted slice that is only freed when the last
/// reference is deinitialized.
///
/// See RcBase for lifetime requirements
pub fn RcSlice(T: type) type {
    return struct {
        ptr: RcBase(T),
        /// The number of T elements, *not* the number of bytes.
        /// For the total number of allocated bytes, use `totalSize`
        len: usize,

        const Self = @This();
        const Allocator = std.mem.Allocator;

        pub fn alloc(allocator: Allocator, n: usize) Allocator.Error!Self {
            return .{ .ptr = try RcBase(T).alloc(allocator, n), .len = n };
        }

        pub fn deinit(self: Self, allocator: Allocator) void {
            self.ptr.deinit(allocator, self.len);
        }

        pub fn acquire(self: Self) Self {
            _ = self.ptr.acquire();
            return self;
        }

        /// on the final release, returns the slice of bytes from
        /// the initial allocation which need to be freed.
        pub fn release(self: Self) ?[]align(RcBase(T).alignment) const u8 {
            return self.ptr.release(self.len);
        }

        pub fn payload(self: Self) []T {
            return self.ptr.payload()[0..self.len];
        }

        /// input must be the exact original slice returned by `payload`
        /// otherwise this function has undefined behavior
        pub fn fromPayload(value: []const T) Self {
            return .{ .ptr = RcBase(T).fromPayload(value.ptr), .len = value.len };
        }
    };
}

/// A reference counted pointer that can be composed for more
/// specific reference counted types like Rc and RcSlice.
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
fn RcBase(T: type) type {
    return struct {
        /// points to a reference counter followed by a number of Ts, as in:
        ///    { ReferenceCounter, T, T, T, T, ..., T }
        /// To access the contained data, use the methods `refCount` or `payload`.
        ptr: [*]align(alignment) u8,

        const Self = @This();
        const Allocator = std.mem.Allocator;

        const alignment = @max(@alignOf(T), @alignOf(ReferenceCounter));
        const alignment_enum = std.mem.Alignment.fromByteUnits(alignment);
        const reserved_space = std.mem.alignForward(usize, @sizeOf(ReferenceCounter), @alignOf(T));

        pub fn alloc(allocator: Allocator, n: usize) Allocator.Error!Self {
            const total_size = totalSize(n) catch return error.OutOfMemory;
            const bytes = try allocator.alignedAlloc(u8, alignment_enum, total_size);

            @as(*ReferenceCounter, @ptrCast(bytes.ptr)).* = .{};
            return .{ .ptr = @alignCast(bytes.ptr) };
        }

        /// pass the number of items that were originally allocated
        pub fn deinit(self: Self, allocator: Allocator, n: usize) void {
            if (self.release(n)) |to_free| allocator.free(to_free);
        }

        pub fn acquire(self: Self) Self {
            std.debug.assert(self.refCount().acquire());
            return self;
        }

        /// on the final release, returns the pointer to bytes from
        /// the initial allocation which need to be freed. You must
        /// pass the number of items that were originally allocated
        pub fn release(self: Self, n: usize) ?[]align(alignment) const u8 {
            if (self.refCount().release()) {
                return self.ptr[0 .. totalSize(n) catch unreachable];
            } else {
                return null;
            }
        }

        pub fn payload(self: Self) [*]T {
            return @ptrCast(self.ptr[reserved_space..]);
        }

        /// input must be the same pointer returned by `payload`
        /// otherwise this function has undefined behavior
        pub fn fromPayload(value: [*]const T) RcBase(T) {
            const value_ptr: [*]u8 = @ptrCast(@constCast(value));
            return Self{ .ptr = @alignCast(value_ptr - reserved_space) };
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

test "RcSlice reference counting" {
    const sig = @import("../sig.zig");

    const TestAllocator = struct {
        arena: std.heap.ArenaAllocator,
        was_freed: bool = false,
        fn free(ctx: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.was_freed = true;
        }
    };
    var test_allocator = TestAllocator{
        .arena = std.heap.ArenaAllocator.init(std.testing.allocator),
    };
    defer test_allocator.arena.deinit();
    const allocator: std.mem.Allocator = .{ .ptr = @ptrCast(&test_allocator), .vtable = &.{
        .alloc = test_allocator.arena.allocator().vtable.alloc,
        .resize = test_allocator.arena.allocator().vtable.resize,
        .remap = std.mem.Allocator.noRemap,
        .free = TestAllocator.free,
    } };

    const slice1 = try RcSlice(u8).alloc(allocator, 5);

    // Copy data into the slice1's payload
    @memcpy(slice1.payload(), "hello");

    // Acquire a second reference to the RcSlice
    const slice2 = slice1.acquire();

    // Assert that both slices see the same payload
    const hello: *const [5]u8 = "hello";
    try std.testing.expect(sig.utils.types.eql(hello, slice1.payload()[0..5]));
    try std.testing.expect(sig.utils.types.eql(hello, slice2.payload()[0..5]));

    // Modify the payload via the second reference
    slice2.payload()[0] = 'H';

    // Assert the change is visible through the first reference
    const hello2: *const [5]u8 = "Hello";
    try std.testing.expect(sig.utils.types.eql(hello2, slice1.payload()[0..5]));
    try std.testing.expect(sig.utils.types.eql(hello2, slice2.payload()[0..5]));

    // Release the first reference
    slice1.deinit(allocator);
    try std.testing.expect(!test_allocator.was_freed);

    // The second reference should still be valid
    try std.testing.expect(sig.utils.types.eql(hello2, slice2.payload()[0..5]));
    // Release the final reference
    slice2.deinit(allocator);
    try std.testing.expect(test_allocator.was_freed);
}
