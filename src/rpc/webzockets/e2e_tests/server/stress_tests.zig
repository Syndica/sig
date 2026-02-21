const std = @import("std");
const ws = @import("webzockets_lib");
const xev = @import("xev");

const testing = std.testing;
const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak_detector.zig");
const verifyServerFunctional = @import("../support/test_helpers.zig").verifyServerFunctional;

test "rapid connect/disconnect" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const num_clients = 20;

    var envs: [num_clients]clients.TestEnv = undefined;
    var handlers: [num_clients]clients.CloseOnOpenHandler = undefined;
    var conns: [num_clients]clients.TestCloseClient.Conn = undefined;
    var client_objs: [num_clients]clients.TestCloseClient = undefined;

    // Start all clients
    for (0..num_clients) |i| {
        envs[i] = undefined;
        try envs[i].start();
        handlers[i] = .{};
        client_objs[i] = envs[i].initClient(clients.TestCloseClient, &handlers[i], &conns[i], .{
            .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        });
        try client_objs[i].connect();
    }

    // Run all event loops
    for (0..num_clients) |i| {
        try envs[i].loop.run(.until_done);
    }

    // Cleanup runs even if assertions fail (avoids additional fd leak detector noise)
    defer for (0..num_clients) |i| {
        conns[i].deinit();
        envs[i].deinit();
    };

    for (0..num_clients) |i| {
        try testing.expect(handlers[i].open_called);
    }

    // Verify server is still healthy
    try verifyServerFunctional(ts.port);
}

test "many concurrent echo clients" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const num_loops = 4;
    const clients_per_loop = 5;

    const LoopContext = struct {
        env: clients.TestEnv,
        handlers: [clients_per_loop]clients.SequenceHandler,
        conns: [clients_per_loop]clients.TestSequenceClient.Conn,
        client_objs: [clients_per_loop]clients.TestSequenceClient,
        msg_specs: [clients_per_loop][]clients.SequenceHandler.MsgSpec,
    };

    var contexts: [num_loops]LoopContext = undefined;
    var threads: [num_loops]std.Thread = undefined;

    for (0..num_loops) |loop_idx| {
        contexts[loop_idx].env = undefined;
        try contexts[loop_idx].env.start();

        for (0..clients_per_loop) |client_idx| {
            const msg_specs = try testing.allocator.alloc(clients.SequenceHandler.MsgSpec, 2);
            msg_specs[0] = .{ .data = try std.fmt.allocPrint(
                testing.allocator,
                "loop{d}-client{d}-msg0",
                .{ loop_idx, client_idx },
            ) };
            msg_specs[1] = .{ .data = try std.fmt.allocPrint(
                testing.allocator,
                "loop{d}-client{d}-msg1",
                .{ loop_idx, client_idx },
            ) };
            contexts[loop_idx].msg_specs[client_idx] = msg_specs;

            contexts[loop_idx].handlers[client_idx] = .{
                .messages = msg_specs,
                .results = std.ArrayList(
                    clients.SequenceHandler.RecvResult,
                ).init(testing.allocator),
                .allocator = testing.allocator,
            };

            contexts[loop_idx].client_objs[client_idx] = contexts[loop_idx].env.initClient(
                clients.TestSequenceClient,
                &contexts[loop_idx].handlers[client_idx],
                &contexts[loop_idx].conns[client_idx],
                .{ .address = std.net.Address.initIp4(
                    .{ 127, 0, 0, 1 },
                    ts.port,
                ) },
            );
            try contexts[loop_idx].client_objs[client_idx].connect();
        }

        threads[loop_idx] = try std.Thread.spawn(
            .{},
            runLoopOnThread,
            .{&contexts[loop_idx].env.loop},
        );
    }

    // Join all threads
    for (0..num_loops) |loop_idx| {
        threads[loop_idx].join();
    }

    // Cleanup runs even if assertions fail (avoids additional fd leak detector noise)
    defer for (0..num_loops) |loop_idx| {
        for (0..clients_per_loop) |client_idx| {
            contexts[loop_idx].handlers[client_idx].deinit();
            contexts[loop_idx].conns[client_idx].deinit();
            const msg_specs = contexts[loop_idx].msg_specs[client_idx];
            for (msg_specs) |spec| {
                testing.allocator.free(spec.data);
            }
            testing.allocator.free(msg_specs);
        }
        contexts[loop_idx].env.deinit();
    };

    for (0..num_loops) |loop_idx| {
        for (0..clients_per_loop) |client_idx| {
            const handler = &contexts[loop_idx].handlers[client_idx];
            const msg_specs = contexts[loop_idx].msg_specs[client_idx];

            try testing.expect(handler.open_called);
            try testing.expectEqual(@as(usize, 2), handler.results.items.len);

            try testing.expectEqualSlices(u8, msg_specs[0].data, handler.results.items[0].data);
            try testing.expectEqualSlices(u8, msg_specs[1].data, handler.results.items[1].data);
        }
    }
}

test "rapid message burst" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const num_messages = 100;

    // Build message specs
    var spec_bufs: [num_messages][10]u8 = undefined;
    var specs: [num_messages]clients.SequenceHandler.MsgSpec = undefined;
    var spec_lens: [num_messages]usize = undefined;

    for (0..num_messages) |i| {
        const result = std.fmt.bufPrint(&spec_bufs[i], "msg-{d}", .{i}) catch unreachable;
        spec_lens[i] = result.len;
        specs[i] = .{ .data = spec_bufs[i][0..spec_lens[i]] };
    }

    var handler: clients.SequenceHandler = .{
        .messages = &specs,
        .results = std.ArrayList(clients.SequenceHandler.RecvResult).init(testing.allocator),
        .allocator = testing.allocator,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestSequenceClient.Conn = undefined;
    var client = env.initClient(clients.TestSequenceClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expectEqual(@as(usize, num_messages), handler.results.items.len);

    for (0..num_messages) |i| {
        const expected = std.fmt.bufPrint(&spec_bufs[i], "msg-{d}", .{i}) catch unreachable;
        try testing.expectEqualSlices(u8, expected, handler.results.items[i].data);
    }
}

test "mixed operations under load" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const num_loops = 4;

    // Each loop runs: 1 text echo, 1 binary echo, 1 ping, 1 close-on-open
    const MixedLoopContext = struct {
        env: clients.TestEnv,

        text_handler: clients.EchoTestHandler,
        text_conn: clients.TestEchoClient.Conn,
        text_client: clients.TestEchoClient,

        binary_handler: clients.EchoTestHandler,
        binary_conn: clients.TestEchoClient.Conn,
        binary_client: clients.TestEchoClient,

        ping_handler: clients.EchoTestHandler,
        ping_conn: clients.TestEchoClient.Conn,
        ping_client: clients.TestEchoClient,

        close_handler: clients.CloseOnOpenHandler,
        close_conn: clients.TestCloseClient.Conn,
        close_client: clients.TestCloseClient,
    };

    var contexts: [num_loops]MixedLoopContext = undefined;
    var threads: [num_loops]std.Thread = undefined;

    for (0..num_loops) |i| {
        contexts[i].env = undefined;
        try contexts[i].env.start();

        const opts = ws.Client(clients.EchoTestHandler, 4096).Config{
            .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        };

        // Text echo client
        contexts[i].text_handler = .{
            .send_kind = .text,
            .send_data = "text-echo",
            .allocator = testing.allocator,
        };
        contexts[i].text_client = contexts[i].env.initClient(
            clients.TestEchoClient,
            &contexts[i].text_handler,
            &contexts[i].text_conn,
            opts,
        );
        try contexts[i].text_client.connect();

        // Binary echo client
        contexts[i].binary_handler = .{
            .send_kind = .binary,
            .send_data = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF },
            .allocator = testing.allocator,
        };
        contexts[i].binary_client = contexts[i].env.initClient(
            clients.TestEchoClient,
            &contexts[i].binary_handler,
            &contexts[i].binary_conn,
            opts,
        );
        try contexts[i].binary_client.connect();

        // Ping client
        contexts[i].ping_handler = .{
            .send_kind = .ping,
            .send_data = "ping-data",
            .allocator = testing.allocator,
        };
        contexts[i].ping_client = contexts[i].env.initClient(
            clients.TestEchoClient,
            &contexts[i].ping_handler,
            &contexts[i].ping_conn,
            opts,
        );
        try contexts[i].ping_client.connect();

        // Close-on-open client
        contexts[i].close_handler = .{};
        contexts[i].close_client = contexts[i].env.initClient(
            clients.TestCloseClient,
            &contexts[i].close_handler,
            &contexts[i].close_conn,
            .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port) },
        );
        try contexts[i].close_client.connect();

        threads[i] = try std.Thread.spawn(.{}, runLoopOnThread, .{&contexts[i].env.loop});
    }

    // Join all threads
    for (0..num_loops) |i| {
        threads[i].join();
    }

    // Cleanup runs even if assertions fail (avoids additional fd leak detector noise)
    defer for (0..num_loops) |i| {
        contexts[i].text_handler.deinit();
        contexts[i].text_conn.deinit();
        contexts[i].binary_handler.deinit();
        contexts[i].binary_conn.deinit();
        contexts[i].ping_handler.deinit();
        contexts[i].ping_conn.deinit();
        contexts[i].close_conn.deinit();
        contexts[i].env.deinit();
    };

    for (0..num_loops) |i| {
        // Text echo
        try testing.expect(contexts[i].text_handler.open_called);
        const text_type = contexts[i].text_handler.received_type orelse return error.NoData;
        const text_data = contexts[i].text_handler.received_data orelse return error.NoData;
        try testing.expectEqual(.text, text_type);
        try testing.expectEqualSlices(u8, "text-echo", text_data);

        // Binary echo
        try testing.expect(contexts[i].binary_handler.open_called);
        const bin_type = contexts[i].binary_handler.received_type orelse return error.NoData;
        const bin_data = contexts[i].binary_handler.received_data orelse return error.NoData;
        try testing.expectEqual(.binary, bin_type);
        try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, bin_data);

        // Ping/pong
        try testing.expect(contexts[i].ping_handler.open_called);
        const ping_type = contexts[i].ping_handler.received_type orelse return error.NoData;
        const ping_data = contexts[i].ping_handler.received_data orelse return error.NoData;
        try testing.expectEqual(.pong, ping_type);
        try testing.expectEqualSlices(u8, "ping-data", ping_data);

        // Close-on-open
        try testing.expect(contexts[i].close_handler.open_called);
    }

    // Verify server still healthy
    try verifyServerFunctional(ts.port);
}

test "randomized concurrent echo" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    // Seed from crypto random for non-deterministic runs; log seed for reproducibility
    var seed_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&seed_bytes);
    const seed = std.mem.readInt(u64, &seed_bytes, .little);
    std.debug.print("\n[randomized concurrent echo] seed={d}\n", .{seed});

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    // Randomize dimensions
    const num_loops = random.intRangeAtMost(usize, 1, 4);
    const max_clients_per_loop = 5;
    const max_messages_per_client = 4;
    const max_payload_len = 256;

    const allocator = testing.allocator;

    const LoopState = struct {
        env: clients.TestEnv,
        num_clients: usize,
        handlers: [max_clients_per_loop]clients.SequenceHandler,
        conns: [max_clients_per_loop]clients.TestSequenceClient.Conn,
        client_objs: [max_clients_per_loop]clients.TestSequenceClient,
        num_messages: [max_clients_per_loop]usize,
        msg_specs: [max_clients_per_loop][]clients.SequenceHandler.MsgSpec,
        payload_bufs: [max_clients_per_loop][max_messages_per_client][]u8,
    };

    var loop_states = try allocator.alloc(LoopState, num_loops);
    defer allocator.free(loop_states);

    var threads = try allocator.alloc(std.Thread, num_loops);
    defer allocator.free(threads);

    for (0..num_loops) |loop_idx| {
        loop_states[loop_idx].env = undefined;
        try loop_states[loop_idx].env.start();

        const nc = random.intRangeAtMost(usize, 1, max_clients_per_loop);
        loop_states[loop_idx].num_clients = nc;

        for (0..nc) |client_idx| {
            const nm = random.intRangeAtMost(usize, 1, max_messages_per_client);
            loop_states[loop_idx].num_messages[client_idx] = nm;

            const msg_specs = try allocator.alloc(clients.SequenceHandler.MsgSpec, nm);
            loop_states[loop_idx].msg_specs[client_idx] = msg_specs;

            for (0..nm) |msg_idx| {
                const payload_len = random.intRangeAtMost(usize, 1, max_payload_len);
                const payload = try allocator.alloc(u8, payload_len);
                // Fill with random printable bytes to avoid UTF-8 issues with text frames
                for (payload) |*b| {
                    b.* = random.intRangeAtMost(u8, 0x20, 0x7E);
                }
                loop_states[loop_idx].payload_bufs[client_idx][msg_idx] = payload;
                msg_specs[msg_idx] = .{ .data = payload };
            }

            loop_states[loop_idx].handlers[client_idx] = .{
                .messages = msg_specs,
                .results = std.ArrayList(
                    clients.SequenceHandler.RecvResult,
                ).init(allocator),
                .allocator = allocator,
            };

            loop_states[loop_idx].client_objs[client_idx] = loop_states[loop_idx].env.initClient(
                clients.TestSequenceClient,
                &loop_states[loop_idx].handlers[client_idx],
                &loop_states[loop_idx].conns[client_idx],
                .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port) },
            );
            try loop_states[loop_idx].client_objs[client_idx].connect();
        }

        threads[loop_idx] = try std.Thread.spawn(
            .{},
            runLoopOnThread,
            .{&loop_states[loop_idx].env.loop},
        );
    }

    // Join all threads
    for (0..num_loops) |loop_idx| {
        threads[loop_idx].join();
    }

    // Cleanup runs even if assertions fail
    defer for (0..num_loops) |loop_idx| {
        const nc = loop_states[loop_idx].num_clients;
        for (0..nc) |client_idx| {
            loop_states[loop_idx].handlers[client_idx].deinit();
            if (loop_states[loop_idx].handlers[client_idx].open_called) {
                loop_states[loop_idx].conns[client_idx].deinit();
            }
            const nm = loop_states[loop_idx].num_messages[client_idx];
            for (0..nm) |msg_idx| {
                allocator.free(loop_states[loop_idx].payload_bufs[client_idx][msg_idx]);
            }
            allocator.free(loop_states[loop_idx].msg_specs[client_idx]);
        }
        loop_states[loop_idx].env.deinit();
    };

    for (0..num_loops) |loop_idx| {
        const nc = loop_states[loop_idx].num_clients;
        for (0..nc) |client_idx| {
            const handler = &loop_states[loop_idx].handlers[client_idx];
            const nm = loop_states[loop_idx].num_messages[client_idx];
            const msg_specs = loop_states[loop_idx].msg_specs[client_idx];

            try testing.expect(handler.open_called);
            try testing.expectEqual(nm, handler.results.items.len);

            for (0..nm) |msg_idx| {
                try testing.expectEqualSlices(
                    u8,
                    msg_specs[msg_idx].data,
                    handler.results.items[msg_idx].data,
                );
            }
        }
    }
}

fn runLoopOnThread(loop: *xev.Loop) void {
    loop.run(.until_done) catch |err| {
        std.debug.panic("event loop failed on thread: {}", .{err});
    };
}
