const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const sig = helpers.sig;
const Account = helpers.Account;
const Pubkey = helpers.Pubkey;
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const addTrackedSlot = helpers.addTrackedSlot;
const initTestClient = helpers.initTestClient;
const runBothLoops = helpers.runBothLoops;
const waitForMessages = helpers.waitForMessages;

test "programSubscribe confirmed publishes on rooted without confirmed event" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var owner_pk: Pubkey = undefined;
    @memset(&owner_pk.data, 0xAA);
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xBB);
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xCA;
    data_buf[1] = 0xFE;
    const account = Account{
        .lamports = 12345,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = owner_pk,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account.deinit(allocator);
    const account_shared = try sig.runtime.AccountSharedData.fromAccount(allocator, &account);
    defer account_shared.deinit(allocator);

    try addTrackedSlot(server, 88, 0, &.{88});
    try server.account_db.db.put(88, pk, account_shared);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"commitment":"confirmed"}]}
    );
    handler.close_after = 3;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 88, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 88 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"programNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":12345") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"slot\":88") != null);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"programUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
}

test "programSubscribe confirmed flushes frozen ancestors in order" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const program_id = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");

    var pk1: Pubkey = undefined;
    @memset(&pk1.data, 0xA1);
    const data_buf1 = try allocator.alloc(u8, 1);
    data_buf1[0] = 0x01;
    const account1 = Account{
        .lamports = 1_111,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf1),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account1.deinit(allocator);
    const account_shared1 = try sig.runtime.AccountSharedData.fromAccount(allocator, &account1);
    defer account_shared1.deinit(allocator);

    var pk2: Pubkey = undefined;
    @memset(&pk2.data, 0xA2);
    const data_buf2 = try allocator.alloc(u8, 1);
    data_buf2[0] = 0x02;
    const account2 = Account{
        .lamports = 2_222,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf2),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account2.deinit(allocator);
    const account_shared2 = try sig.runtime.AccountSharedData.fromAccount(allocator, &account2);
    defer account_shared2.deinit(allocator);

    var pk3: Pubkey = undefined;
    @memset(&pk3.data, 0xA3);
    const data_buf3 = try allocator.alloc(u8, 1);
    data_buf3[0] = 0x03;
    const account3 = Account{
        .lamports = 3_333,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf3),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account3.deinit(allocator);
    const account_shared3 = try sig.runtime.AccountSharedData.fromAccount(allocator, &account3);
    defer account_shared3.deinit(allocator);

    try addTrackedSlot(server, 1, 0, &.{1});
    try addTrackedSlot(server, 2, 1, &.{ 1, 2 });
    try addTrackedSlot(server, 3, 2, &.{ 1, 2, 3 });
    try server.account_db.db.put(1, pk1, account_shared1);
    try server.account_db.db.put(2, pk2, account_shared2);
    try server.account_db.db.put(3, pk3, account_shared3);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"commitment":"confirmed"}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 1, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_frozen = .{ .slot = 2, .parent = 1, .root = 0 } });
    server.injectEvent(.{ .slot_confirmed = 3 });
    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(@as(usize, 1), handler.received.items.len);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 3, .parent = 2, .root = 0 } });

    waitForMessages(server, &client_env, &handler, 4, 5000);
    try std.testing.expect(handler.received.items.len >= 4);

    const notif1 = handler.received.items[1];
    const notif2 = handler.received.items[2];
    const notif3 = handler.received.items[3];
    try std.testing.expect(std.mem.indexOf(u8, notif1, "\"slot\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif2, "\"slot\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif3, "\"slot\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif1, "\"lamports\":1111") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif2, "\"lamports\":2222") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif3, "\"lamports\":3333") != null);

    server.injectEvent(.{ .slot_rooted = 3 });
    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(@as(usize, 4), handler.received.items.len);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "programSubscribe processed only publishes frozen on-fork slots" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const program_id = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xBB);
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xCA;
    data_buf[1] = 0xFE;
    const account = Account{
        .lamports = 11111,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account.deinit(allocator);
    const account_shared = try sig.runtime.AccountSharedData.fromAccount(allocator, &account);
    defer account_shared.deinit(allocator);

    // Fork A: slot 10
    try addTrackedSlot(server, 10, 0, &.{10});
    try server.account_db.db.put(10, pk, account_shared);

    // Fork B: slot 20 (side fork, not an ancestor of tip)
    try addTrackedSlot(server, 20, 0, &.{20});
    try server.account_db.db.put(20, pk, account_shared);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"commitment":"processed"}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    // Set tip to slot 10.
    server.slot_tracker.latest_processed_slot.set(10);
    server.injectEvent(.{ .tip_changed = 10 });

    // Freeze slot 10 (on current fork) -> should publish.
    server.injectEvent(.{ .slot_frozen = .{ .slot = 10, .parent = 0, .root = 0 } });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"programNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":11111") != null);

    // Freeze slot 20 (off-fork) -> should NOT publish for processed.
    server.injectEvent(.{ .slot_frozen = .{ .slot = 20, .parent = 0, .root = 0 } });
    runBothLoops(server, &client_env, &handler, 300);
    // Still only 2 messages (subscribe response + 1 notification from on-fork slot 10).
    try std.testing.expectEqual(@as(usize, 2), handler.received.items.len);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "programSubscribe no backfill on pure tip change" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const program_id = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xBB);
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xCA;
    data_buf[1] = 0xFE;
    const account = Account{
        .lamports = 22222,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account.deinit(allocator);
    const account_shared = try sig.runtime.AccountSharedData.fromAccount(allocator, &account);
    defer account_shared.deinit(allocator);

    try addTrackedSlot(server, 10, 0, &.{10});
    try addTrackedSlot(server, 11, 10, &.{ 10, 11 });
    try server.account_db.db.put(10, pk, account_shared);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"commitment":"processed"}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    // Freeze slot 10 with tip at 10 -> should publish.
    server.slot_tracker.latest_processed_slot.set(10);
    server.injectEvent(.{ .tip_changed = 10 });
    server.injectEvent(.{ .slot_frozen = .{ .slot = 10, .parent = 0, .root = 0 } });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[1], "\"programNotification\"") != null,
    );

    // Pure tip change to slot 11 (no freeze of slot 11) -> should NOT backfill.
    server.slot_tracker.latest_processed_slot.set(11);
    server.injectEvent(.{ .tip_changed = 11 });
    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(@as(usize, 2), handler.received.items.len);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "programSubscribe finalized flushes all newly rooted slots" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const program_id = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xBB);

    // Put different accounts in slots 10 and 11 to distinguish notifications.
    const data_buf10 = try allocator.alloc(u8, 1);
    data_buf10[0] = 0x0A;
    const account10 = Account{
        .lamports = 10_000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf10),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account10.deinit(allocator);
    const account_shared10 = try sig.runtime.AccountSharedData.fromAccount(allocator, &account10);
    defer account_shared10.deinit(allocator);

    const data_buf11 = try allocator.alloc(u8, 1);
    data_buf11[0] = 0x0B;
    const account11 = Account{
        .lamports = 11_000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf11),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account11.deinit(allocator);
    const account_shared11 = try sig.runtime.AccountSharedData.fromAccount(allocator, &account11);
    defer account_shared11.deinit(allocator);

    try addTrackedSlot(server, 10, 0, &.{10});
    try addTrackedSlot(server, 11, 10, &.{ 10, 11 });
    try server.account_db.db.put(10, pk, account_shared10);
    try server.account_db.db.put(11, pk, account_shared11);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"commitment":"finalized"}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    // Freeze both slots, then root them individually in chain order.
    server.injectEvent(.{ .slot_frozen = .{ .slot = 10, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_frozen = .{ .slot = 11, .parent = 10, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 10 });
    server.injectEvent(.{ .slot_rooted = 11 });

    // Both rooted slots should produce finalized program notifications.
    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);

    // Both notifications are programNotification.
    const notif1 = handler.received.items[1];
    const notif2 = handler.received.items[2];
    try std.testing.expect(std.mem.indexOf(u8, notif1, "\"programNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif2, "\"programNotification\"") != null);

    // Verify both slot 10 and slot 11 produced notifications (check lamports to distinguish).
    const has_10k = std.mem.indexOf(u8, notif1, "\"lamports\":10000") != null or
        std.mem.indexOf(u8, notif2, "\"lamports\":10000") != null;
    const has_11k = std.mem.indexOf(u8, notif1, "\"lamports\":11000") != null or
        std.mem.indexOf(u8, notif2, "\"lamports\":11000") != null;
    try std.testing.expect(has_10k);
    try std.testing.expect(has_11k);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "programSubscribe filter dataSize applied" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const program_id = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");

    // Account with 4 bytes of data.
    var pk_match: Pubkey = undefined;
    @memset(&pk_match.data, 0xAA);
    const data_match = try allocator.alloc(u8, 4);
    @memset(data_match, 0x11);
    const acct_match = Account{
        .lamports = 100,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_match),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer acct_match.deinit(allocator);
    const shared_match = try sig.runtime.AccountSharedData.fromAccount(allocator, &acct_match);
    defer shared_match.deinit(allocator);

    // Account with 8 bytes of data (should be filtered out by dataSize:4).
    var pk_nomatch: Pubkey = undefined;
    @memset(&pk_nomatch.data, 0xBB);
    const data_nomatch = try allocator.alloc(u8, 8);
    @memset(data_nomatch, 0x22);
    const acct_nomatch = Account{
        .lamports = 200,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_nomatch),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer acct_nomatch.deinit(allocator);
    const shared_nomatch = try sig.runtime.AccountSharedData.fromAccount(allocator, &acct_nomatch);
    defer shared_nomatch.deinit(allocator);

    try addTrackedSlot(server, 50, 0, &.{50});
    try server.account_db.db.put(50, pk_match, shared_match);
    try server.account_db.db.put(50, pk_nomatch, shared_nomatch);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    // Subscribe with dataSize filter: only accounts with exactly 4 bytes.
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"filters":[{"dataSize":4}]}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 50, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 50 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    // Only the 4-byte account (lamports=100) should appear.
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":100") != null);

    // Give time for any extra messages, then verify no lamports:200 was published.
    runBothLoops(server, &client_env, &handler, 200);
    for (handler.received.items[1..]) |msg| {
        try std.testing.expect(std.mem.indexOf(u8, msg, "\"lamports\":200") == null);
    }

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "programSubscribe filter memcmp applied" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const program_id = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");

    // Account whose data starts with [0xDE, 0xAD] -> matches memcmp at offset 0.
    var pk_match: Pubkey = undefined;
    @memset(&pk_match.data, 0xAA);
    const data_match = try allocator.alloc(u8, 4);
    data_match[0] = 0xDE;
    data_match[1] = 0xAD;
    data_match[2] = 0x00;
    data_match[3] = 0x00;
    const acct_match = Account{
        .lamports = 300,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_match),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer acct_match.deinit(allocator);
    const shared_match = try sig.runtime.AccountSharedData.fromAccount(allocator, &acct_match);
    defer shared_match.deinit(allocator);

    // Account whose data starts with [0xBE, 0xEF] -> does NOT match.
    var pk_nomatch: Pubkey = undefined;
    @memset(&pk_nomatch.data, 0xBB);
    const data_nomatch = try allocator.alloc(u8, 4);
    data_nomatch[0] = 0xBE;
    data_nomatch[1] = 0xEF;
    data_nomatch[2] = 0x00;
    data_nomatch[3] = 0x00;
    const acct_nomatch = Account{
        .lamports = 400,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_nomatch),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer acct_nomatch.deinit(allocator);
    const shared_nomatch = try sig.runtime.AccountSharedData.fromAccount(allocator, &acct_nomatch);
    defer shared_nomatch.deinit(allocator);

    try addTrackedSlot(server, 60, 0, &.{60});
    try server.account_db.db.put(60, pk_match, shared_match);
    try server.account_db.db.put(60, pk_nomatch, shared_nomatch);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    // memcmp filter: offset=0, bytes [0xDE, 0xAD] encoded as base64 "3q0="
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"filters":[{"memcmp":{"offset":0,"bytes":"3q0=","encoding":"base64"}}]}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 60, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 60 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    // Only the matching account (lamports=300) should appear.
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":300") != null);

    runBothLoops(server, &client_env, &handler, 200);
    for (handler.received.items[1..]) |msg| {
        try std.testing.expect(std.mem.indexOf(u8, msg, "\"lamports\":400") == null);
    }

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "programSubscribe tokenAccountState matches account data without token owner check" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const program_id = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");

    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAC);
    const data = try allocator.alloc(u8, sig.rpc.account_codec.parse_token.TokenAccount.LEN);
    @memset(data, 0);
    data[108] = @intFromEnum(sig.rpc.account_codec.AccountState.initialized);
    const account = Account{
        .lamports = 500,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data),
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account.deinit(allocator);
    const shared_account = try sig.runtime.AccountSharedData.fromAccount(allocator, &account);
    defer shared_account.deinit(allocator);

    try addTrackedSlot(server, 65, 0, &.{65});
    try server.account_db.db.put(65, pk, shared_account);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"filters":[{"tokenAccountState":{}}]}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 65, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 65 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":500") != null);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "programSubscribe zero-lamport account with matching owner publishes" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const program_id = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xCC);

    // Zero-lamport (deleted) account still owned by program.
    const acct_shared: sig.runtime.AccountSharedData = .{
        .lamports = 0,
        .data = &.{},
        .owner = program_id,
        .executable = false,
        .rent_epoch = 0,
    };

    try addTrackedSlot(server, 70, 0, &.{70});
    try server.account_db.db.put(70, pk, acct_shared);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB"]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 70, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 70 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    // Zero-lamport account with matching owner should produce a concrete notification.
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"programNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":0") != null);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "programSubscribe account with non-matching owner does not publish" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xDD);

    // Account owned by a DIFFERENT program.
    var other_owner: Pubkey = undefined;
    @memset(&other_owner.data, 0xFF);
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0x01;
    data_buf[1] = 0x02;
    const acct = Account{
        .lamports = 999,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = other_owner,
        .executable = false,
        .rent_epoch = 0,
    };
    defer acct.deinit(allocator);
    const acct_shared = try sig.runtime.AccountSharedData.fromAccount(allocator, &acct);
    defer acct_shared.deinit(allocator);

    try addTrackedSlot(server, 80, 0, &.{80});
    try server.account_db.db.put(80, pk, acct_shared);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB"]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 80, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 80 });

    // Give time for processing.
    runBothLoops(server, &client_env, &handler, 300);
    // Should have no program notification (only subscribe response).
    for (handler.received.items[1..]) |msg| {
        try std.testing.expect(std.mem.indexOf(u8, msg, "\"programNotification\"") == null);
    }

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}
