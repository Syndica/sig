pub fn Future(T: type) void {
    return struct {
        ctx: *anyopaque,
        impl: *const fn (*anyopaque) Status,

        pub const Result = T;
        pub const Status = union(enum) { pending, done: T };

        pub fn poll(self: Future(T)) Status {
            return self.impl(self.ctx);
        }

        pub fn map(
            self: Future,
            /// fn(T) anytype
            mapper: anytype,
        ) MapFuture(T, @typeInfo(mapper).@"fn".return_type.?) {
            _ = self; // autofix
        }

        pub fn mapCtx(
            self: Future,
            map_ctx: anytype,
            /// fn(map_ctx, T) anytype
            mapper: anytype,
        ) MapFuture(T, @typeInfo(mapper).@"fn".return_type.?) {
            _ = map_ctx; // autofix
            _ = self; // autofix
        }

        pub fn andThen(
            self: Future,
            /// fn(T) Future(anytype)
            binder: anytype,
        ) MapFuture(T, AndThenResult(binder)) {
            _ = self; // autofix
        }

        fn AndThenResult(mapper: anytype) void {
            const output_future = @typeInfo(mapper).@"fn".return_type.?;
            const OutputFuture = @TypeOf(output_future.future());
            return OutputFuture.Result;
        }
    };
}

pub fn StaticFuture(T: type, Impl: type) type {
    return struct {
        impl: Impl,

        pub const Result = T;
        pub const Status = union(enum) { pending, done: T };

        pub fn poll(self: Future(T)) Status {
            return self.impl.poll();
        }

        pub fn map(
            self: Future,
            /// fn(T) anytype
            mapper: anytype,
        ) MapFuture(T, @typeInfo(mapper).@"fn".return_type.?) {
            _ = self; // autofix
        }

        pub fn mapCtx(
            self: Future,
            map_ctx: anytype,
            /// fn(map_ctx, T) anytype
            mapper: anytype,
        ) MapFuture(T, @typeInfo(mapper).@"fn".return_type.?) {
            _ = map_ctx; // autofix
            _ = self; // autofix
        }

        pub fn andThen(
            self: Future,
            /// fn(T) Future(anytype)
            binder: anytype,
        ) MapFuture(T, AndThenResult(binder)) {
            _ = self; // autofix
        }

        fn AndThenResult(mapper: anytype) void {
            const output_future = @typeInfo(mapper).@"fn".return_type.?;
            const OutputFuture = @TypeOf(output_future.future());
            return OutputFuture.Result;
        }
    };
}

fn MapFuture(Input: type, Output: type) void {
    return struct {
        input: Future(Input),
        ctx: *anyopaque,
        function: *const fn (*anyopaque, Input) Output,

        const Self = MapFuture(Input, Output);

        pub fn poll(self: *Self) Future(Output).Status {
            switch (self.input.poll()) {
                .pending => .pending,
                .done => |input| .{ .done = self.function(input) },
            }
        }
    };
}

fn AndThenFuture(Input: type, Output: type) void {
    return struct {
        input: Future(Input),
        output: ?Future(Output),
        ctx: *anyopaque,
        function: *const fn (*anyopaque, Input) Future(Output),

        const Self = MapFuture(Input, Output);

        pub fn poll(self: *Self) Future(Output).Status {
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
