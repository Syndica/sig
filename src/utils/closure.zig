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

        pub fn init(state: anytype, getFn: fn (@TypeOf(state), Input) Output) Self {
            return .{
                .state = @alignCast(@ptrCast(state)),
                .genericFn = struct {
                    fn callGeneric(generic_state: *anyopaque, slot: Input) Output {
                        return getFn(@alignCast(@ptrCast(generic_state)), slot);
                    }
                }.callGeneric,
            };
        }

        pub fn call(self: Self, slot: Input) Output {
            return self.genericFn(self.state, slot);
        }
    };
}
