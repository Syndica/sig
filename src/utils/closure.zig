/// Generically represents a function with two inputs:
/// 1. enclosed state that is passed on initialization (as a pointer).
/// 2. input that is passed at the call site.
///
/// The enclosed state's type is abstracted with dynamic dispatch.
///
/// Contains a pointer to data that is owned by another context. Ensure that
/// the lifetime of that data exceeds the lifetime of this struct.
pub fn PointerClosure(comptime Input: type, comptime Output: type) type {
    return struct {
        state: *anyopaque,
        genericFn: *const fn (*anyopaque, Input) Output,

        const Self = @This();

        pub fn init(state: anytype, func: anytype) Self {
            const functions = struct {
                fn call(generic_state: *anyopaque, input: Input) Output {
                    return func(@alignCast(@ptrCast(generic_state)), input);
                }
                fn callNoParams(generic_state: *anyopaque, _: Input) Output {
                    return func(@alignCast(@ptrCast(generic_state)));
                }
            };
            const genericFn = comptime switch (@typeInfo(@TypeOf(func)).Fn.params.len) {
                1 => functions.callNoParams,
                2 => functions.call,
                else => @compileError("not supported"),
            };
            return .{ .state = @alignCast(@ptrCast(state)), .genericFn = &genericFn };
        }

        pub fn call(self: Self, input: Input) Output {
            return self.genericFn(self.state, input);
        }
    };
}
