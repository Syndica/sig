//! Default test runner for unit tests.
const std = @import("std");
const io = std.io;
const builtin = @import("builtin");

pub const std_options = .{
    .logFn = log,
};

var log_err_count: usize = 0;
var cmdline_buffer: [4096]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&cmdline_buffer);

pub fn main() void {
    if (builtin.zig_backend == .stage2_riscv64) return mainExtraSimple() catch @panic("test failure");

    if (builtin.zig_backend == .stage2_aarch64) {
        return mainSimple() catch @panic("test failure");
    }

    const args = std.process.argsAlloc(fba.allocator()) catch
        @panic("unable to parse command line args");

    var listen = false;

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--listen=-")) {
            listen = true;
        } else {
            @panic("unrecognized command line argument");
        }
    }

    if (listen) {
        return mainServer() catch @panic("internal test runner failure");
    } else {
        return mainTerminal();
    }
}

fn mainServer() !void {
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
            .exit => {
                return std.process.exit(0);
            },
            .query_test_metadata => {
                std.testing.allocator_instance = .{};
                defer if (std.testing.allocator_instance.deinit() == .leak) {
                    @panic("internal test runner memory leak");
                };

                var string_bytes: std.ArrayListUnmanaged(u8) = .{};
                defer string_bytes.deinit(std.testing.allocator);
                try string_bytes.append(std.testing.allocator, 0); // Reserve 0 for null.

                const test_fns = builtin.test_functions;
                const names = try std.testing.allocator.alloc(u32, test_fns.len);
                defer std.testing.allocator.free(names);
                const expected_panic_msgs = try std.testing.allocator.alloc(u32, test_fns.len);
                defer std.testing.allocator.free(expected_panic_msgs);

                for (test_fns, names, expected_panic_msgs) |test_fn, *name, *expected_panic_msg| {
                    name.* = @as(u32, @intCast(string_bytes.items.len));
                    try string_bytes.ensureUnusedCapacity(std.testing.allocator, test_fn.name.len + 1);
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
                std.testing.allocator_instance = .{};
                log_err_count = 0;
                const index = try server.receiveBody_u32();
                const test_fn = builtin.test_functions[index];
                var fail = false;
                var skip = false;
                var leak = false;
                test_fn.func() catch |err| switch (err) {
                    error.SkipZigTest => skip = true,
                    else => {
                        fail = true;
                        if (@errorReturnTrace()) |trace| {
                            std.debug.dumpStackTrace(trace.*);
                        }
                    },
                };
                leak = std.testing.allocator_instance.deinit() == .leak;
                try server.serveTestResults(.{
                    .index = index,
                    .flags = .{
                        .fail = fail,
                        .skip = skip,
                        .leak = leak,
                        .log_err_count = std.math.lossyCast(
                            @TypeOf(@as(std.zig.Server.Message.TestResults.Flags, undefined).log_err_count),
                            log_err_count,
                        ),
                    },
                });
            },

            else => {
                std.debug.print("unsupported message: {x}", .{@intFromEnum(hdr.tag)});
                std.process.exit(1);
            },
        }
    }
}

fn mainTerminal() void {
    const test_fn_list = builtin.test_functions;
    var ok_count: usize = 0;
    var skip_count: usize = 0;
    var fail_count: usize = 0;
    const root_node = std.Progress.start(.{
        .root_name = "Test",
        .estimated_total_items = test_fn_list.len,
    });
    const have_tty = std.io.getStdErr().isTty();

    var async_frame_buffer: []align(builtin.target.stackAlignment()) u8 = undefined;
    // TODO this is on the next line (using `undefined` above) because otherwise zig incorrectly
    // ignores the alignment of the slice.
    async_frame_buffer = &[_]u8{};

    var leaks: usize = 0;
    leaks = leaks;
    outer: for (test_fn_list, 0..) |test_fn, i| {
        std.testing.allocator_instance = .{};
        defer {
            if (std.testing.allocator_instance.deinit() == .leak) leaks += 1;
        }
        std.testing.log_level = .warn;

        const test_node = root_node.start(test_fn.name, 0);
        if (!have_tty) {
            std.debug.print("{d}/{d} {s}...", .{ i + 1, test_fn_list.len, test_fn.name });
        }

        const inverse_filters: []const []const u8 = &.{
            "shrink account file works",
            // thread 32535 panic: BufferPool deinitialised with alive handle: 2097144

            "streaming accounts",
            // [1/3] Test
            // Thread 1 "test" received signal SIGTERM, Terminated.
            // compiler_rt.memset.memset (dest=0x7fdff5bac000 '\252' <repeats 200 times>..., c=170 '\252', len=68719476736) at /usr/lib/zig/compiler_rt/memset.zig:19
            // 19                  d[0] = c;
            // (gdb) bt
            // #0  compiler_rt.memset.memset (dest=0x7fdff5bac000 '\252' <repeats 200 times>..., c=170 '\252', len=68719476736) at /usr/lib/zig/compiler_rt/memset.zig:19
            // #1  0x00000000032359d1 in mem.Allocator.allocBytesWithAlignment__anon_40945 (self=..., byte_count=68719476736, return_address=51831337) at /usr/lib/zig/std/mem/Allocator.zig:227
            // #2  0x000000000317444b in mem.Allocator.allocWithSizeAndAlignment__anon_36179 (self=..., n=68719476736, return_address=51831337) at /usr/lib/zig/std/mem/Allocator.zig:211
            // #3  0x00000000030a9b89 in mem.Allocator.allocAdvancedWithRetAddr () at /usr/lib/zig/std/mem/Allocator.zig:205
            // #4  mem.Allocator.alloc__anon_24864 (self=..., n=68719476736) at /usr/lib/zig/std/mem/Allocator.zig:129
            // #5  0x000000000316e229 in geyser.core.GeyserReader.readType__anon_36097 (self=0x7fffffffce50, expected_n_bytes=210) at ./src/geyser/core.zig:411
            // #6  0x000000000316e4a4 in geyser.core.GeyserReader.readPayload (self=0x7fffffffce50) at ./src/geyser/core.zig:362
            // #7  0x000000000316f1b2 in geyser.core.test.streaming accounts () at ./src/geyser/core.zig:579
            // #8  0x0000000003163c98 in test_runner.mainTerminal () at test_runner.zig:257

            "buf resizing",
            // [1/3] Test
            // Thread 1 "test" received signal SIGTERM, Terminated.
            // compiler_rt.memset.memset (dest=0x7fdff5bcc000 '\252' <repeats 200 times>..., c=170 '\252', len=68719476736) at /usr/lib/zig/compiler_rt/memset.zig:19
            // 19                  d[0] = c;
            // (gdb) bt
            // #0  compiler_rt.memset.memset (dest=0x7fdff5bcc000 '\252' <repeats 200 times>..., c=170 '\252', len=68719476736) at /usr/lib/zig/compiler_rt/memset.zig:19
            // #1  0x0000000003234931 in mem.Allocator.allocBytesWithAlignment__anon_40941 (self=..., byte_count=68719476736, return_address=51831401) at /usr/lib/zig/std/mem/Allocator.zig:227
            // #2  0x000000000317334b in mem.Allocator.allocWithSizeAndAlignment__anon_36175 (self=..., n=68719476736, return_address=51831401) at /usr/lib/zig/std/mem/Allocator.zig:211
            // #3  0x00000000030a9bc9 in mem.Allocator.allocAdvancedWithRetAddr () at /usr/lib/zig/std/mem/Allocator.zig:205
            // #4  mem.Allocator.alloc__anon_24864 (self=..., n=68719476736) at /usr/lib/zig/std/mem/Allocator.zig:129
            // #5  0x000000000316e269 in geyser.core.GeyserReader.readType__anon_36097 (self=0x7fffffffd1f0, expected_n_bytes=210) at ./src/geyser/core.zig:411
            // #6  0x000000000316e4e4 in geyser.core.GeyserReader.readPayload (self=0x7fffffffd1f0) at ./src/geyser/core.zig:362
            // #7  0x000000000316f232 in geyser.core.test.buf resizing () at ./src/geyser/core.zig:682
            // #8  0x0000000003163cd8 in test_runner.mainTerminal () at test_runner.zig:241
            // #9  0x000000000309cddc in test_runner.main () at test_runner.zig:37

            "stream on load",
            // panic: byte: 2e

            "load clock sysvar",
            // expected 1733349737, found 1733349736

            "read/write benchmark disk",
            // /usr/lib/zig/std/posix.zig:978:22: 0x34a1595 in pread (test)
            //             .BADF => return error.NotOpenForReading, // Can be a race condition.
            //                      ^
            // /usr/lib/zig/std/fs/File.zig:1159:5: 0x3396074 in pread (test)
            //     return posix.pread(self.handle, buffer, offset);
            //     ^
            // ./src/accountsdb/buffer_pool.zig:477:32: 0x326a22a in readBlocking (test)
            //             const bytes_read = try file.pread(&self.frames[f_idx.*], frame_aligned_file_offset);
            //                                ^
            // ./src/accountsdb/buffer_pool.zig:307:9: 0x317b9f4 in read (test)
            //         return if (use_io_uring)
            //         ^
            // ./src/accountsdb/accounts_file.zig:494:16: 0x317b816 in getSlice (test)
            //         return try buffer_pool.read(metadata_allocator, self.file, self.id, @intCast(start_index), @intCast(end_index));
            //                ^
            // ./src/accountsdb/accounts_file.zig:506:22: 0x317bace in getType__anon_35137 (test)
            //         const read = try self.getSlice(metadata_allocator, buffer_pool, start_index_ptr, length);
            //                      ^
            // ./src/accountsdb/accounts_file.zig:391:28: 0x317c55d in readAccount (test)
            //         const store_info = try self.getType(metadata_allocator, buffer_pool, &offset, AccountInFile.StorageInfo);
            //                            ^
            // ./src/accountsdb/db.zig:3245:25: 0x317dec7 in indexAndValidateAccountFile (test)
            //             else => |e| return e,
            //                         ^
            // ./src/accountsdb/db.zig:2393:9: 0x317d29e in putAccountFile (test)
            //         try indexAndValidateAccountFile(
            //         ^
            // ./src/accountsdb/db.zig:4899:25: 0x3185267 in readWriteAccounts (test)
            //                         try accounts_db.putAccountFile(account_file, n_accounts);
            //                         ^
            // ./src/accountsdb/db.zig:4982:9: 0x3188c15 in test.read/write benchmark disk (test)
            //     _ = try BenchmarkAccountsDB.readWriteAccounts(.nanos, .{
            //         ^
        };

        for (inverse_filters) |inv_filter| {
            if (std.mem.containsAtLeast(u8, test_fn.name, 1, inv_filter)) {
                skip_count += 1;
                if (have_tty) {
                    std.debug.print("{d}/{d} {s}...SKIP\n", .{ i + 1, test_fn_list.len, test_fn.name });
                } else {
                    std.debug.print("SKIP\n", .{});
                }
                std.time.sleep(std.time.ns_per_ms * 500);
                continue :outer;
            }
        }

        if (test_fn.func()) |_| {
            ok_count += 1;
            test_node.end();
            if (!have_tty) std.debug.print("OK\n", .{});
        } else |err| switch (err) {
            error.SkipZigTest => {
                skip_count += 1;
                if (have_tty) {
                    std.debug.print("{d}/{d} {s}...SKIP\n", .{ i + 1, test_fn_list.len, test_fn.name });
                } else {
                    std.debug.print("SKIP\n", .{});
                }
                test_node.end();
            },
            else => {
                @breakpoint();
                fail_count += 1;
                if (have_tty) {
                    std.debug.print("{d}/{d} {s}...FAIL ({s})\n", .{
                        i + 1, test_fn_list.len, test_fn.name, @errorName(err),
                    });
                } else {
                    std.debug.print("FAIL ({s})\n", .{@errorName(err)});
                }
                if (@errorReturnTrace()) |trace| {
                    std.debug.dumpStackTrace(trace.*);
                }
                test_node.end();
            },
        }
    }
    root_node.end();
    if (ok_count == test_fn_list.len) {
        std.debug.print("All {d} tests passed.\n", .{ok_count});
    } else {
        std.debug.print("{d} passed; {d} skipped; {d} failed.\n", .{ ok_count, skip_count, fail_count });
    }
    if (log_err_count != 0) {
        std.debug.print("{d} errors were logged.\n", .{log_err_count});
    }
    if (leaks != 0) {
        std.debug.print("{d} tests leaked memory.\n", .{leaks});
    }
    if (leaks != 0 or log_err_count != 0 or fail_count != 0) {
        std.process.exit(1);
    }
}

pub fn log(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) <= @intFromEnum(std.log.Level.err)) {
        log_err_count +|= 1;
    }
    if (@intFromEnum(message_level) <= @intFromEnum(std.testing.log_level)) {
        std.debug.print(
            "[" ++ @tagName(scope) ++ "] (" ++ @tagName(message_level) ++ "): " ++ format ++ "\n",
            args,
        );
    }
}

/// Simpler main(), exercising fewer language features, so that
/// work-in-progress backends can handle it.
pub fn mainSimple() anyerror!void {
    const enable_print = false;
    const print_all = false;

    var passed: u64 = 0;
    var skipped: u64 = 0;
    var failed: u64 = 0;
    const stderr = if (enable_print) std.io.getStdErr() else {};
    for (builtin.test_functions) |test_fn| {
        if (enable_print and print_all) {
            stderr.writeAll(test_fn.name) catch {};
            stderr.writeAll("... ") catch {};
        }
        test_fn.func() catch |err| {
            if (enable_print and !print_all) {
                stderr.writeAll(test_fn.name) catch {};
                stderr.writeAll("... ") catch {};
            }
            if (err != error.SkipZigTest) {
                if (enable_print) stderr.writeAll("FAIL\n") catch {};
                failed += 1;
                if (!enable_print) return err;
                continue;
            }
            if (enable_print) stderr.writeAll("SKIP\n") catch {};
            skipped += 1;
            continue;
        };
        if (enable_print and print_all) stderr.writeAll("PASS\n") catch {};
        passed += 1;
    }
    if (enable_print) {
        stderr.writer().print("{} passed, {} skipped, {} failed\n", .{ passed, skipped, failed }) catch {};
        if (failed != 0) std.process.exit(1);
    }
}

pub fn mainExtraSimple() !void {
    var fail_count: u8 = 0;

    for (builtin.test_functions) |test_fn| {
        test_fn.func() catch |err| {
            if (err != error.SkipZigTest) {
                fail_count += 1;
                continue;
            }
            continue;
        };
    }

    if (fail_count != 0) std.process.exit(1);
}
