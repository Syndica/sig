const builtin = @import("builtin");

const std = @import("std");
const io = std.io;
const testing = std.testing;
const assert = std.debug.assert;

/// Number of nanoseconds allowed per test, otherwise the test runner panics.
///
/// We only use timeouts as a final stop-gap, generally speaking they should
/// never be hit and are only an issue if the CI is having some major issue.
/// It is helpful to not have 3 hour long CI runs that don't even tell you
/// what test is hanging.
const TIMEOUT = 2 * 60 * std.time.ns_per_s;

pub const std_options: std.Options = .{
    .logFn = log,
};

var log_err_count: usize = 0;
var fba_buffer: [8192]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&fba_buffer);

pub fn main() void {
    @disableInstrumentation();

    const args = std.process.argsAlloc(fba.allocator()) catch
        @panic("unable to parse command line args");

    var listen = false;
    var opt_cache_dir: ?[]const u8 = null;

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--listen=-")) {
            listen = true;
        } else if (std.mem.startsWith(u8, arg, "--seed=")) {
            testing.random_seed = std.fmt.parseUnsigned(u32, arg["--seed=".len..], 0) catch
                @panic("unable to parse --seed command line argument");
        } else if (std.mem.startsWith(u8, arg, "--cache-dir")) {
            opt_cache_dir = arg["--cache-dir=".len..];
        } else {
            @panic("unrecognized command line argument");
        }
    }

    fba.reset();

    return mainServer() catch @panic("internal test runner failure");
}

fn mainServer() !void {
    @disableInstrumentation();
    var server = try std.zig.Server.init(.{
        .gpa = fba.allocator(),
        .in = std.io.getStdIn(),
        .out = std.io.getStdOut(),
        .zig_version = builtin.zig_version_string,
    });
    defer server.deinit();

    while (true) {
        const hdr = try server.receiveMessage();
        switch (hdr.tag) {
            .exit => return std.process.exit(0),
            .query_test_metadata => {
                testing.allocator_instance = .{};
                defer if (testing.allocator_instance.deinit() == .leak) {
                    @panic("internal test runner memory leak");
                };

                var string_bytes: std.ArrayListUnmanaged(u8) = .empty;
                defer string_bytes.deinit(testing.allocator);
                try string_bytes.append(testing.allocator, 0); // Reserve 0 for null.

                const test_fns = builtin.test_functions;
                const names = try testing.allocator.alloc(u32, test_fns.len);
                defer testing.allocator.free(names);
                const expected_panic_msgs = try testing.allocator.alloc(u32, test_fns.len);
                defer testing.allocator.free(expected_panic_msgs);

                for (test_fns, names, expected_panic_msgs) |test_fn, *name, *expected_panic_msg| {
                    name.* = @as(u32, @intCast(string_bytes.items.len));
                    try string_bytes.ensureUnusedCapacity(testing.allocator, test_fn.name.len + 1);
                    string_bytes.appendSliceAssumeCapacity(test_fn.name);
                    string_bytes.appendAssumeCapacity(0);
                    expected_panic_msg.* = 0;
                }

                try server.serveTestMetadata(.{
                    .names = names,
                    .expected_panic_msgs = expected_panic_msgs,
                    .string_bytes = string_bytes.items,
                });
            },

            .run_test => {
                testing.allocator_instance = .{};
                log_err_count = 0;
                const index = try server.receiveBody_u32();
                const test_fn = builtin.test_functions[index];

                const S = struct {
                    fn wrapper(
                        ptr: *const fn () anyerror!void,
                        cond: *std.Thread.Condition,
                        fail: *bool,
                        skip: *bool,
                    ) void {
                        const result = ptr();
                        cond.signal();
                        result catch |err| switch (err) {
                            error.SkipZigTest => skip.* = true,
                            else => fail.* = false,
                        };
                    }
                };

                var fail = false;
                var skip = false;

                var mutex: std.Thread.Mutex = .{};
                mutex.lock();

                var cond: std.Thread.Condition = .{};
                const t = try std.Thread.spawn(
                    .{},
                    S.wrapper,
                    .{ test_fn.func, &cond, &fail, &skip },
                );

                cond.timedWait(&mutex, TIMEOUT) catch {
                    t.detach();
                    std.debug.panic(
                        "test: '{s}' timed out after {}",
                        .{ test_fn.name, std.fmt.fmtDuration(TIMEOUT) },
                    );
                };
                // technically, `timedWait` can spuriously wake up even before the test
                // finishes executing. in that case, we just hit the `join`.
                // if it happens that that specific test is the one that hangs, there
                // isn't much we can do. there is no way to re-establish ordering with
                // the thread after the wait unblocks.
                // at least this method of timeouts should catch some bugs.
                t.join();

                const leak = testing.allocator_instance.deinit() == .leak;
                try server.serveTestResults(.{
                    .index = index,
                    .flags = .{
                        .fail = fail,
                        .skip = skip,
                        .leak = leak,
                        .fuzz = false,
                        .log_err_count = std.math.lossyCast(
                            @FieldType(std.zig.Server.Message.TestResults.Flags, "log_err_count"),
                            log_err_count,
                        ),
                    },
                });
            },
            else => {
                std.debug.print("unsupported message: {x}\n", .{@intFromEnum(hdr.tag)});
                std.process.exit(1);
            },
        }
    }
}

pub fn log(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    @disableInstrumentation();
    if (@intFromEnum(message_level) <= @intFromEnum(std.log.Level.err)) {
        log_err_count +|= 1;
    }
    if (@intFromEnum(message_level) <= @intFromEnum(testing.log_level)) {
        std.debug.print(
            "[" ++ @tagName(scope) ++ "] (" ++ @tagName(message_level) ++ "): " ++ format ++ "\n",
            args,
        );
    }
}
