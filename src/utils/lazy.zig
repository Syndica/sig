const std = @import("std");
const sig = @import("../sig.zig");
const testing = std.testing;

const Allocator = std.mem.Allocator;
const ParamsTuple = sig.utils.types.ParamsTuple;

/// A lazily evaluated instance of type T.
///
/// Initialized with a function and its arguments. T is
/// only evaluated when `call` is called, which calls the
/// function with the previously provided arguments,
/// and returns the value returned by the function.
///
/// Uses dynamic dispatch, so a context using a Lazy(T)
/// doesn't need to worry about how the T is created.
pub fn Lazy(comptime T: type) type {
    return struct {
        allocator: Allocator,
        genericFn: *const fn (*anyopaque) T,
        state: *anyopaque,
        destroy: *const fn (Allocator, *anyopaque) void,

        const Self = @This();

        pub fn init(
            allocator: Allocator,
            comptime function: anytype,
            args: ParamsTuple(function),
        ) Allocator.Error!Self {
            const args_ptr = try allocator.create(ParamsTuple(function));
            args_ptr.* = args;
            return .{
                .allocator = allocator,
                .genericFn = struct {
                    fn genericFn(opaque_ptr: *anyopaque) T {
                        const args_back: *ParamsTuple(function) = @ptrCast(@alignCast(opaque_ptr));
                        return @call(.auto, function, args_back.*);
                    }
                }.genericFn,
                .state = @as(*anyopaque, @ptrCast(@alignCast(args_ptr))),
                .destroy = struct {
                    fn destroy(alloc: Allocator, opaque_ptr: *anyopaque) void {
                        const ptr: *ParamsTuple(function) = @ptrCast(@alignCast(opaque_ptr));
                        alloc.destroy(ptr);
                    }
                }.destroy,
            };
        }

        pub fn call(self: Self) T {
            defer self.destroy(self.allocator, self.state);
            return self.genericFn(self.state);
        }
    };
}

test "Lazy void example" {
    const allocator = std.testing.allocator;
    var a = false;
    const lazy = try Lazy(void).init(allocator, set, .{&a});
    try testing.expect(!a);
    _ = lazy.call();
    try testing.expect(a);
}

test "Lazy void multiple arguments" {
    const allocator = std.testing.allocator;
    var a = false;
    var b = false;
    const lazy = try Lazy(void).init(allocator, set2, .{ &a, &b });
    try testing.expect(!a);
    try testing.expect(!b);
    _ = lazy.call();
    try testing.expect(a);
    try testing.expect(b);
}

test "Lazy non-void return type" {
    const allocator = std.testing.allocator;
    const lazy = try Lazy(i32).init(allocator, add, .{ 1, 41 });
    try testing.expectEqual(lazy.call(), 42);
}

fn set(x: *bool) void {
    x.* = true;
}

fn set2(x: *bool, y: *bool) void {
    x.* = true;
    y.* = true;
}

fn add(x: i32, y: i32) i32 {
    return x + y;
}
