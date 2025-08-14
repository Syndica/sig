const this_file = @This();

pub fn Future(Impl: type) type {
    return struct {
        impl: Impl,

        const Self = @This();

        pub const Status = @TypeOf(Impl.poll());
        pub const Result = Self.Status.Result;

        pub fn poll(self: Self) Self.Status {
            return self.impl.poll();
        }

        pub fn map(
            self: Future,
            /// fn(T) anytype
            comptime function: anytype,
        ) Future(Map(Self, void, function)) {
            return .{ .impl = .{
                .input = self,
                .context = {},
            } };
        }

        pub fn mapContext(
            self: Future,
            context: anytype,
            /// fn(map_context, T) anytype
            comptime function: anytype,
        ) Future(Map(Self, @TypeOf(context), function)) {
            return .{ .impl = .{
                .input = self,
                .context = context,
            } };
        }

        pub fn mapGeneric(
            self: Future,
            context: anytype,
            /// fn(context, T) anytype  // can be function or function pointer
            function: anytype,
        ) switch (@TypeOf(function)) {
            .@"fn" => Future(Map(Self, @TypeOf(context), function)),
            .ptr => Future(Map(Self, struct { @TypeOf(function), @TypeOf(context) }, call)),
        } {
            return .{ .impl = switch (@TypeOf(function)) {
                .@"fn" => .{ .input = self, .context = context },
                .ptr => .{ .input = self, .context = .{ function, context } },
            } };
        }

        fn call(function_and_context: anytype, item: anytype) void {
            const function, const context = function_and_context;
            return function(context, item);
        }

        pub fn andThen(
            self: Future,
            /// fn(T) Future(anytype)
            binder: anytype,
        ) Map(Result, AndThenResult(binder)) {
            _ = self; // autofix
        }

        fn AndThenResult(mapper: anytype) void {
            const output_future = @typeInfo(mapper).@"fn".return_type.?;
            const OutputFuture = @TypeOf(output_future.future());
            return OutputFuture.Result;
        }
    };
}

pub fn FunctionResolver(function: anytype) type {
    _ = function; // autofix
    return struct {};
}

pub fn Status(Result_: type) type {
    return union(enum) {
        pending,
        done: Result,

        pub const Result = Result_;
    };
}

fn Map(InputFuture: type, Context: type, function: anytype) void {
    return struct {
        input: InputFuture,
        context: Context,

        const Self = @This();

        pub const Result = @typeInfo(function).@"fn".return_type.?;

        pub fn poll(self: *Self) Status(Result) {
            switch (self.input.poll()) {
                .pending => .pending,
                .done => |input| .{ .done = function(self.context, input) },
            }
        }
    };
}

fn AndThen(InputFuture: type, Context: type, function: anytype) void {
    return struct {
        input: InputFuture,
        output: ?OutputFuture,
        context: Context,

        const Self = @This();

        pub const OutputFuture = @typeInfo(function).@"fn".return_type.?;
        pub const Result = OutputFuture.Result;

        pub fn poll(self: *Self) Status(Result) {
            if (self.output) |output_future| switch (output_future.poll()) {
                .pending => .pending,
                .done => |output| .{ .done = output },
            } else switch (self.input.poll()) {
                .pending => .pending,
                .done => |input| .{ .done = self.function(input) },
            }
        }
    };
}

test "hello" {
    const fut: Future(u64) = undefined;

    fut.poll(undefined);
}
