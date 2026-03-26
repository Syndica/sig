const std = @import("std");
const sig = @import("../../sig.zig");
const ws = @import("webzockets");
const types = @import("types.zig");
const methods = @import("methods.zig");
const account_codec = sig.rpc.account_codec;
const NotifPayload = sig.sync.RcSlice(u8);

const Id = sig.rpc.request.Id;
/// Responses are small and infrequent, done on IO loop, we just reuse an ArrayList
const ResponseBuffer = std.ArrayList(u8);

/// Prepend a WebSocket text frame header to the response buffer contents.
fn prependFrameHeader(
    response_buf: *ResponseBuffer,
    allocator: std.mem.Allocator,
) !void {
    var header_buf: [10]u8 = undefined;
    const header = ws.frame.writeFrameHeader(&header_buf, .text, response_buf.items.len, false);
    const json_len = response_buf.items.len;
    try response_buf.resize(allocator, json_len + header.len);
    const dest = response_buf.items[header.len..][0..json_len];
    std.mem.copyBackwards(u8, dest, response_buf.items[0..json_len]);
    @memcpy(response_buf.items[0..header.len], header);
}

/// Two-pass serialization into a pre-framed WebSocket text payload.
/// Pass 1: count JSON bytes with a Discarding writer.
/// Pass 2: write frame header + JSON directly into the RcSlice.
fn serializeToPayload(allocator: std.mem.Allocator, value: anytype) !NotifPayload {
    var discarding: std.Io.Writer.Discarding = .init(&.{});
    try std.json.Stringify.value(value, .{}, &discarding.writer);
    const json_len = discarding.fullCount();

    var header_buf: [10]u8 = undefined;
    const header_len = ws.frame.writeFrameHeader(&header_buf, .text, json_len, false).len;

    const p = try NotifPayload.alloc(allocator, header_len + json_len);
    errdefer p.deinit(allocator);
    const payload = p.payload();

    @memcpy(payload[0..header_len], header_buf[0..header_len]);
    var fixed = std.Io.Writer.fixed(payload[header_len..][0..json_len]);
    try std.json.Stringify.value(value, .{}, &fixed);

    return p;
}

fn serializeToResponseBuf(
    response_buf: *ResponseBuffer,
    allocator: std.mem.Allocator,
    value: anytype,
) !void {
    response_buf.clearRetainingCapacity();
    {
        var aw: std.Io.Writer.Allocating = .fromArrayList(allocator, response_buf);
        errdefer response_buf.* = aw.toArrayList();
        try std.json.Stringify.value(value, .{}, &aw.writer);
        response_buf.* = aw.toArrayList();
    }
    try prependFrameHeader(response_buf, allocator);
}

pub fn serializeSubscribeResponse(
    response_buf: *ResponseBuffer,
    allocator: std.mem.Allocator,
    id: Id,
    sub_id: types.SubId,
) !void {
    return serializeToResponseBuf(response_buf, allocator, .{
        .jsonrpc = "2.0",
        .id = id,
        .result = sub_id,
    });
}

pub fn serializeUnsubscribeResponse(
    response_buf: *ResponseBuffer,
    allocator: std.mem.Allocator,
    id: Id,
) !void {
    return serializeToResponseBuf(response_buf, allocator, .{
        .jsonrpc = "2.0",
        .id = id,
        .result = true,
    });
}

pub fn serializeErrorResponse(
    response_buf: *ResponseBuffer,
    allocator: std.mem.Allocator,
    id: Id,
    code: i32,
    message: []const u8,
) !void {
    return serializeToResponseBuf(response_buf, allocator, .{
        .jsonrpc = "2.0",
        .id = id,
        .@"error" = .{ .code = code, .message = message },
    });
}

pub fn serializeSlotNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    data: types.SlotEventData,
) !NotifPayload {
    return serializeToPayload(allocator, .{
        .jsonrpc = "2.0",
        .method = "slotNotification",
        .params = .{
            .result = .{ .parent = data.parent, .root = data.root, .slot = data.slot },
            .subscription = sub_id,
        },
    });
}

pub fn serializeRootNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    data: types.RootEventData,
) !NotifPayload {
    return serializeToPayload(allocator, .{
        .jsonrpc = "2.0",
        .method = "rootNotification",
        .params = .{
            .result = data.root,
            .subscription = sub_id,
        },
    });
}

/// Helper type to seralize all the account fields for encoded RPC notification
const WireAccountValue = struct {
    acc: *const sig.core.Account,
    data: account_codec.AccountData,

    pub fn jsonStringify(self: WireAccountValue, jw: anytype) !void {
        try jw.write(.{
            .data = self.data,
            .executable = self.acc.executable,
            .lamports = self.acc.lamports,
            .owner = self.acc.owner,
            .rentEpoch = self.acc.rent_epoch,
            .space = self.acc.data.len(),
        });
    }
};

const BASE58_TOO_LARGE_MESSAGE = "error: data too large for bs58 encoding";

/// For Agave parity, websocket notifications must serialize oversize binary/base58
/// account data as Agave's legacy overflow string instead of failing the notification.
fn base58OverflowAccountData(
    arena: std.mem.Allocator,
    encoding: methods.AccountEncoding,
) !account_codec.AccountData {
    // Note: technically don't have to dupe here since the string is static and we don't attempt to
    // free it directly since everything is arena allocated, but this is the rare/weird case and
    // duping here prevents accidental bug later.
    const msg = try arena.dupe(u8, BASE58_TOO_LARGE_MESSAGE);
    return switch (encoding) {
        .binary => .{ .legacy_binary = msg },
        .base58 => .{ .encoded = .{ msg, .base58 } },
        else => unreachable,
    };
}

fn encodeNotificationAccountData(
    arena: std.mem.Allocator,
    data: types.AccountEventData,
    encoding: methods.AccountEncoding,
    data_slice: ?methods.DataSlice,
    read_ctx: ?types.SlotReadContext,
) !account_codec.AccountData {
    const awp = &data.account;
    return if (encoding == .jsonParsed) blk: {
        const ctx = read_ctx orelse return error.MissingReadContext;
        const slot_ref = ctx.slot_tracker.get(data.slot) orelse return error.SlotNotAvailable;
        defer slot_ref.release();
        const ancestors = &slot_ref.constants().ancestors;
        const slot_reader = ctx.account_reader.forSlot(ancestors);
        break :blk try account_codec.encodeJsonParsed(
            arena,
            awp.pubkey,
            awp.account,
            slot_reader,
            data_slice,
        );
    } else account_codec.encodeStandard(
        arena,
        awp.account,
        encoding,
        data_slice,
    ) catch |err| switch (err) {
        error.Base58DataTooLarge => switch (encoding) {
            .binary, .base58 => try base58OverflowAccountData(arena, encoding),
            else => return err,
        },
        else => return err,
    };
}

pub fn serializeAccountNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    data: types.AccountEventData,
    encoding: methods.AccountEncoding,
    data_slice: ?methods.DataSlice,
    read_ctx: ?types.SlotReadContext,
) !NotifPayload {
    const awp = &data.account;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const av = WireAccountValue{
        .acc = &awp.account,
        .data = try encodeNotificationAccountData(
            arena,
            data,
            encoding,
            data_slice,
            read_ctx,
        ),
    };
    return serializeToPayload(allocator, .{
        .jsonrpc = "2.0",
        .method = "accountNotification",
        .params = .{
            .result = .{
                .context = .{ .slot = data.slot },
                .value = av,
            },
            .subscription = sub_id,
        },
    });
}

pub fn serializeProgramNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    data: types.AccountEventData,
    encoding: methods.AccountEncoding,
    data_slice: ?methods.DataSlice,
    read_ctx: ?types.SlotReadContext,
) !NotifPayload {
    const awp = &data.account;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const av = WireAccountValue{
        .acc = &awp.account,
        .data = try encodeNotificationAccountData(
            arena,
            data,
            encoding,
            data_slice,
            read_ctx,
        ),
    };
    return serializeToPayload(allocator, .{
        .jsonrpc = "2.0",
        .method = "programNotification",
        .params = .{
            .result = .{
                .context = .{ .slot = data.slot },
                .value = .{
                    .pubkey = awp.pubkey,
                    .account = av,
                },
            },
            .subscription = sub_id,
        },
    });
}

const LogsValue = struct {
    signature: sig.core.Signature,
    err: ?sig.ledger.transaction_status.TransactionError,
    logs: []const []const u8,
};

pub fn serializeLogsNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    data: types.LogsNotificationData,
) !NotifPayload {
    return serializeToPayload(allocator, .{
        .jsonrpc = "2.0",
        .method = "logsNotification",
        .params = .{
            .result = .{
                .context = .{ .slot = data.slot },
                .value = LogsValue{
                    .signature = data.signature,
                    .err = data.err,
                    .logs = data.logs,
                },
            },
            .subscription = sub_id,
        },
    });
}

const SignatureNotificationValue = struct {
    value: types.SignatureNotificationData.Value,

    pub fn jsonStringify(self: SignatureNotificationValue, jw: anytype) !void {
        switch (self.value) {
            .received => try jw.write("receivedSignature"),
            .final => |result| try jw.write(.{ .err = result.err }),
        }
    }
};

pub fn serializeSignatureNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    data: types.SignatureNotificationData,
) !NotifPayload {
    return serializeToPayload(allocator, .{
        .jsonrpc = "2.0",
        .method = "signatureNotification",
        .params = .{
            .result = .{
                .context = .{ .slot = data.slot },
                .value = SignatureNotificationValue{ .value = data.value },
            },
            .subscription = sub_id,
        },
    });
}

pub fn serializeNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    job_type: types.SerializeJob.JobType,
) !NotifPayload {
    return switch (job_type) {
        .slot => |data| serializeSlotNotification(allocator, sub_id, data),
        .root => |data| serializeRootNotification(allocator, sub_id, data),
        .logs => |data| serializeLogsNotification(allocator, sub_id, data),
        .account => |job| serializeAccountNotification(
            allocator,
            sub_id,
            job.data,
            job.encoding,
            job.data_slice,
            job.read_ctx,
        ),
        .program => |job| serializeProgramNotification(
            allocator,
            sub_id,
            job.data,
            job.encoding,
            job.data_slice,
            job.read_ctx,
        ),
        .signature => |data| serializeSignatureNotification(allocator, sub_id, data),
    };
}

pub const ErrorCode = struct {
    pub const parse_error: i32 = -32700;
    pub const invalid_request: i32 = -32600;
    pub const method_not_found: i32 = -32601;
    pub const invalid_params: i32 = -32602;
    pub const internal_error: i32 = -32603;
};

/// Extract the JSON payload from a WebSocket text frame (skips frame header).
pub fn extractJson(data: []const u8) []const u8 {
    const len_byte = data[1] & 0x7F;
    if (len_byte <= 125) {
        return data[2..];
    } else if (len_byte == 126) {
        return data[4..];
    } else {
        return data[10..];
    }
}

const SerializedAccountNotification = struct {
    method: []const u8,
    params: struct {
        result: struct {
            context: struct {
                slot: u64,
            },
            value: struct {
                data: [2][]const u8,
                lamports: u64,
                rentEpoch: u64,
                space: u64,
            },
        },
    },
};

const SerializedProgramNotification = struct {
    method: []const u8,
    params: struct {
        result: struct {
            context: struct {
                slot: u64,
            },
            value: struct {
                pubkey: []const u8,
                account: struct {
                    data: [2][]const u8,
                    lamports: u64,
                    rentEpoch: u64,
                    space: u64,
                },
            },
        },
    },
};

test "serializeSubscribeResponse with int id" {
    const allocator = std.testing.allocator;
    var response_buf: ResponseBuffer = .{};
    defer response_buf.deinit(allocator);

    try serializeSubscribeResponse(
        &response_buf,
        allocator,
        .{ .int = 1 },
        42,
    );
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"result":42}
    , extractJson(response_buf.items));
}

test "serializeSubscribeResponse with string id" {
    const allocator = std.testing.allocator;
    var response_buf: ResponseBuffer = .{};
    defer response_buf.deinit(allocator);

    try serializeSubscribeResponse(
        &response_buf,
        allocator,
        .{ .str = "abc" },
        42,
    );
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":"abc","result":42}
    , extractJson(response_buf.items));
}

test "serializeSubscribeResponse with null id" {
    const allocator = std.testing.allocator;
    var response_buf: ResponseBuffer = .{};
    defer response_buf.deinit(allocator);

    try serializeSubscribeResponse(
        &response_buf,
        allocator,
        .null,
        42,
    );
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":null,"result":42}
    , extractJson(response_buf.items));
}

test "serializeUnsubscribeResponse" {
    const allocator = std.testing.allocator;
    var response_buf: ResponseBuffer = .{};
    defer response_buf.deinit(allocator);

    try serializeUnsubscribeResponse(
        &response_buf,
        allocator,
        .{ .int = 2 },
    );
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":2,"result":true}
    , extractJson(response_buf.items));
}

test "serializeErrorResponse" {
    const allocator = std.testing.allocator;
    var response_buf: ResponseBuffer = .{};
    defer response_buf.deinit(allocator);

    try serializeErrorResponse(
        &response_buf,
        allocator,
        .{ .int = 3 },
        -32600,
        "test error",
    );
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32600,"message":"test error"}}
    , extractJson(response_buf.items));
}

test "serializeErrorResponse escapes message" {
    const allocator = std.testing.allocator;
    var response_buf: ResponseBuffer = .{};
    defer response_buf.deinit(allocator);
    try serializeErrorResponse(
        &response_buf,
        allocator,
        .{ .int = 1 },
        -32600,
        "bad \"input\"",
    );
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad \"input\""}}
    , extractJson(response_buf.items));
}

test "serializeSlotNotification" {
    const allocator = std.testing.allocator;
    const p = try serializeSlotNotification(
        allocator,
        1,
        .{ .slot = 100, .parent = 99, .root = 90 },
    );
    defer p.deinit(allocator);
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"slotNotification","params":{"result":{"parent":99,"root":90,"slot":100},"subscription":1}}
    , extractJson(p.payload()));
}

test "serializeRootNotification" {
    const allocator = std.testing.allocator;
    const p = try serializeRootNotification(allocator, 3, .{ .root = 42 });
    defer p.deinit(allocator);
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"rootNotification","params":{"result":42,"subscription":3}}
    , extractJson(p.payload()));
}

test "serializeAccountNotification binary encoding" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xDE;
    data_buf[1] = 0xAD;
    const pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = pk,
        .executable = false,
        .rent_epoch = 42,
    };
    defer account.deinit(allocator);

    const p = try serializeAccountNotification(allocator, 7, .{
        .account = .{ .pubkey = pk, .account = account },
        .slot = 100,
    }, .binary, null, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":100},"value":{"data":"Hwr","executable":false,"lamports":1000,"owner":"11111111111111111111111111111111","rentEpoch":42,"space":2}},"subscription":7}}
    , extractJson(p.payload()));
}

test "serializeAccountNotification explicit base64" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 4);
    @memcpy(data_buf, &[_]u8{ 1, 2, 3, 4 });
    const pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 500,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = pk,
        .executable = true,
        .rent_epoch = 0,
    };
    defer account.deinit(allocator);

    const p = try serializeAccountNotification(allocator, 1, .{
        .account = .{ .pubkey = pk, .account = account },
        .slot = 50,
    }, .base64, null, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":50},"value":{"data":["AQIDBA==","base64"],"executable":true,"lamports":500,"owner":"11111111111111111111111111111111","rentEpoch":0,"space":4}},"subscription":1}}
    , extractJson(p.payload()));
}

test "serializeAccountNotification applies dataSlice" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 4);
    @memcpy(data_buf, &[_]u8{ 1, 2, 3, 4 });
    const pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 500,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = pk,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account.deinit(allocator);

    const p = try serializeAccountNotification(allocator, 2, .{
        .account = .{ .pubkey = pk, .account = account },
        .slot = 51,
    }, .base64, .{ .offset = 1, .length = 2 }, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":51},"value":{"data":["AgM=","base64"],"executable":false,"lamports":500,"owner":"11111111111111111111111111111111","rentEpoch":0,"space":4}},"subscription":2}}
    , extractJson(p.payload()));
}

test "serializeAccountNotification base58 encoding" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xDE;
    data_buf[1] = 0xAD;
    const pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = pk,
        .executable = false,
        .rent_epoch = 42,
    };
    defer account.deinit(allocator);

    const p = try serializeAccountNotification(allocator, 7, .{
        .account = .{ .pubkey = pk, .account = account },
        .slot = 100,
    }, .base58, null, null);
    defer p.deinit(allocator);

    // base58 of [0xDE, 0xAD] = "Hwr" (Bitcoin alphabet)
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":100},"value":{"data":["Hwr","base58"],"executable":false,"lamports":1000,"owner":"11111111111111111111111111111111","rentEpoch":42,"space":2}},"subscription":7}}
    , extractJson(p.payload()));
}

test "serializeAccountNotification binary encoding uses Agave overflow string" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 129);
    @memset(data_buf, 0xAB);
    const pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = pk,
        .executable = false,
        .rent_epoch = 42,
    };
    defer account.deinit(allocator);

    const p = try serializeAccountNotification(allocator, 7, .{
        .account = .{ .pubkey = pk, .account = account },
        .slot = 100,
    }, .binary, null, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":100},"value":{"data":"error: data too large for bs58 encoding","executable":false,"lamports":1000,"owner":"11111111111111111111111111111111","rentEpoch":42,"space":129}},"subscription":7}}
    , extractJson(p.payload()));
}

test "serializeAccountNotification base58 encoding uses Agave overflow string" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 129);
    @memset(data_buf, 0xAB);
    const pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = pk,
        .executable = false,
        .rent_epoch = 42,
    };
    defer account.deinit(allocator);

    const p = try serializeAccountNotification(allocator, 7, .{
        .account = .{ .pubkey = pk, .account = account },
        .slot = 100,
    }, .base58, null, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":100},"value":{"data":["error: data too large for bs58 encoding","base58"],"executable":false,"lamports":1000,"owner":"11111111111111111111111111111111","rentEpoch":42,"space":129}},"subscription":7}}
    , extractJson(p.payload()));
}

test "serializeAccountNotification base64+zstd encoding" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xDE;
    data_buf[1] = 0xAD;
    const pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = pk,
        .executable = false,
        .rent_epoch = 42,
    };
    defer account.deinit(allocator);

    const p = try serializeAccountNotification(allocator, 7, .{
        .account = .{ .pubkey = pk, .account = account },
        .slot = 100,
    }, .@"base64+zstd", null, null);
    defer p.deinit(allocator);

    const parsed = try std.json.parseFromSlice(
        SerializedAccountNotification,
        allocator,
        extractJson(p.payload()),
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const notification = parsed.value;

    try std.testing.expectEqualStrings("accountNotification", notification.method);
    try std.testing.expectEqualStrings("base64+zstd", notification.params.result.value.data[1]);
    try std.testing.expectEqual(1000, notification.params.result.value.lamports);
    try std.testing.expectEqual(42, notification.params.result.value.rentEpoch);
    try std.testing.expectEqual(2, notification.params.result.value.space);
    try std.testing.expectEqual(100, notification.params.result.context.slot);
}

test "serializeAccountNotification empty account data" {
    const allocator = std.testing.allocator;
    const pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 0,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(
            try allocator.alloc(u8, 0),
        ),
        .owner = pk,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account.deinit(allocator);

    const p = try serializeAccountNotification(allocator, 1, .{
        .account = .{ .pubkey = pk, .account = account },
        .slot = 1,
    }, .base64, null, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":1},"value":{"data":["","base64"],"executable":false,"lamports":0,"owner":"11111111111111111111111111111111","rentEpoch":0,"space":0}},"subscription":1}}
    , extractJson(p.payload()));
}

test "serializeProgramNotification wraps value with pubkey and account" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xCA;
    data_buf[1] = 0xFE;
    const account_pk = sig.core.Pubkey.ZEROES;
    const owner_pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 999,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = owner_pk,
        .executable = false,
        .rent_epoch = 7,
    };
    defer account.deinit(allocator);

    const p = try serializeProgramNotification(allocator, 3, .{
        .account = .{ .pubkey = account_pk, .account = account },
        .slot = 200,
    }, .base64, null, null);
    defer p.deinit(allocator);

    // base64 of [0xCA, 0xFE] = "yv4="
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"programNotification","params":{"result":{"context":{"slot":200},"value":{"pubkey":"11111111111111111111111111111111","account":{"data":["yv4=","base64"],"executable":false,"lamports":999,"owner":"11111111111111111111111111111111","rentEpoch":7,"space":2}}},"subscription":3}}
    , extractJson(p.payload()));
}

test "serializeProgramNotification applies dataSlice" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 4);
    @memcpy(data_buf, &[_]u8{ 1, 2, 3, 4 });
    const account_pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 999,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = sig.core.Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 7,
    };
    defer account.deinit(allocator);

    const p = try serializeProgramNotification(allocator, 3, .{
        .account = .{ .pubkey = account_pk, .account = account },
        .slot = 200,
    }, .base64, .{ .offset = 1, .length = 2 }, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"programNotification","params":{"result":{"context":{"slot":200},"value":{"pubkey":"11111111111111111111111111111111","account":{"data":["AgM=","base64"],"executable":false,"lamports":999,"owner":"11111111111111111111111111111111","rentEpoch":7,"space":4}}},"subscription":3}}
    , extractJson(p.payload()));
}

test "serializeProgramNotification base58 encoding" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xDE;
    data_buf[1] = 0xAD;
    const account_pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = sig.core.Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 42,
    };
    defer account.deinit(allocator);

    const p = try serializeProgramNotification(allocator, 7, .{
        .account = .{ .pubkey = account_pk, .account = account },
        .slot = 100,
    }, .base58, null, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"programNotification","params":{"result":{"context":{"slot":100},"value":{"pubkey":"11111111111111111111111111111111","account":{"data":["Hwr","base58"],"executable":false,"lamports":1000,"owner":"11111111111111111111111111111111","rentEpoch":42,"space":2}}},"subscription":7}}
    , extractJson(p.payload()));
}

test "serializeProgramNotification binary encoding uses Agave overflow string" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 129);
    @memset(data_buf, 0xAB);
    const account_pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = sig.core.Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 42,
    };
    defer account.deinit(allocator);

    const p = try serializeProgramNotification(allocator, 7, .{
        .account = .{ .pubkey = account_pk, .account = account },
        .slot = 100,
    }, .binary, null, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"programNotification","params":{"result":{"context":{"slot":100},"value":{"pubkey":"11111111111111111111111111111111","account":{"data":"error: data too large for bs58 encoding","executable":false,"lamports":1000,"owner":"11111111111111111111111111111111","rentEpoch":42,"space":129}}},"subscription":7}}
    , extractJson(p.payload()));
}

test "serializeProgramNotification base58 encoding uses Agave overflow string" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 129);
    @memset(data_buf, 0xAB);
    const account_pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = sig.core.Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 42,
    };
    defer account.deinit(allocator);

    const p = try serializeProgramNotification(allocator, 7, .{
        .account = .{ .pubkey = account_pk, .account = account },
        .slot = 100,
    }, .base58, null, null);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"programNotification","params":{"result":{"context":{"slot":100},"value":{"pubkey":"11111111111111111111111111111111","account":{"data":["error: data too large for bs58 encoding","base58"],"executable":false,"lamports":1000,"owner":"11111111111111111111111111111111","rentEpoch":42,"space":129}}},"subscription":7}}
    , extractJson(p.payload()));
}

test "serializeProgramNotification base64+zstd encoding" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xDE;
    data_buf[1] = 0xAD;
    const account_pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = sig.core.Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 42,
    };
    defer account.deinit(allocator);

    const p = try serializeProgramNotification(allocator, 7, .{
        .account = .{ .pubkey = account_pk, .account = account },
        .slot = 100,
    }, .@"base64+zstd", null, null);
    defer p.deinit(allocator);

    const parsed = try std.json.parseFromSlice(
        SerializedProgramNotification,
        allocator,
        extractJson(p.payload()),
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const notification = parsed.value;

    try std.testing.expectEqualStrings("programNotification", notification.method);
    try std.testing.expectEqualStrings(
        "base64+zstd",
        notification.params.result.value.account.data[1],
    );
    try std.testing.expectEqual(1000, notification.params.result.value.account.lamports);
    try std.testing.expectEqual(42, notification.params.result.value.account.rentEpoch);
    try std.testing.expectEqual(2, notification.params.result.value.account.space);
    try std.testing.expectEqual(100, notification.params.result.context.slot);
    try std.testing.expect(notification.params.result.value.pubkey.len != 0);
}

test "serializeLogsNotification success payload" {
    const allocator = std.testing.allocator;
    const p = try serializeLogsNotification(allocator, 5, .{
        .slot = 77,
        .signature = sig.core.Signature.ZEROES,
        .err = null,
        .is_vote = false,
        .logs = &.{ "Program log: hello", "Program consumed 1111 of 200000 compute units" },
        .mentioned_pubkeys = &.{},
    });
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"logsNotification","params":{"result":{"context":{"slot":77},"value":{"signature":"1111111111111111111111111111111111111111111111111111111111111111","err":null,"logs":["Program log: hello","Program consumed 1111 of 200000 compute units"]}},"subscription":5}}
    , extractJson(p.payload()));
}

test "serializeLogsNotification failure payload" {
    const allocator = std.testing.allocator;
    const p = try serializeLogsNotification(allocator, 9, .{
        .slot = 88,
        .signature = sig.core.Signature.ZEROES,
        .err = .AccountNotFound,
        .is_vote = false,
        .logs = &.{"Program log: failed"},
        .mentioned_pubkeys = &.{},
    });
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"logsNotification","params":{"result":{"context":{"slot":88},"value":{"signature":"1111111111111111111111111111111111111111111111111111111111111111","err":"AccountNotFound","logs":["Program log: failed"]}},"subscription":9}}
    , extractJson(p.payload()));
}

test "serializeLogsNotification zero logs" {
    const allocator = std.testing.allocator;
    const p = try serializeLogsNotification(allocator, 1, .{
        .slot = 1,
        .signature = sig.core.Signature.ZEROES,
        .err = null,
        .is_vote = false,
        .logs = &.{},
        .mentioned_pubkeys = &.{},
    });
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"logsNotification","params":{"result":{"context":{"slot":1},"value":{"signature":"1111111111111111111111111111111111111111111111111111111111111111","err":null,"logs":[]}},"subscription":1}}
    , extractJson(p.payload()));
}

test "serializeSignatureNotification received payload" {
    const allocator = std.testing.allocator;
    const p = try serializeSignatureNotification(allocator, 3, .{
        .slot = 123,
        .value = .received,
    });
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":123},"value":"receivedSignature"},"subscription":3}}
    , extractJson(p.payload()));
}

test "serializeSignatureNotification final payload with null err" {
    const allocator = std.testing.allocator;
    const p = try serializeSignatureNotification(allocator, 4, .{
        .slot = 124,
        .value = .{ .final = .{ .err = null } },
    });
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":124},"value":{"err":null}},"subscription":4}}
    , extractJson(p.payload()));
}

test "serializeSignatureNotification final payload with concrete err" {
    const allocator = std.testing.allocator;
    const p = try serializeSignatureNotification(allocator, 5, .{
        .slot = 125,
        .value = .{ .final = .{ .err = .AccountInUse } },
    });
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":125},"value":{"err":"AccountInUse"}},"subscription":5}}
    , extractJson(p.payload()));
}

test "serializeNotification dispatches program job type" {
    const allocator = std.testing.allocator;
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xDE;
    data_buf[1] = 0xAD;
    const pk = sig.core.Pubkey.ZEROES;
    const account = sig.core.Account{
        .lamports = 1000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = pk,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account.deinit(allocator);

    const p = try serializeNotification(allocator, 10, .{ .program = .{
        .data = .{ .account = .{ .pubkey = pk, .account = account }, .slot = 42 },
        .encoding = .base64,
        .read_ctx = undefined,
    } });
    defer p.deinit(allocator);

    const parsed = try std.json.parseFromSlice(
        SerializedProgramNotification,
        allocator,
        extractJson(p.payload()),
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const notification = parsed.value;

    try std.testing.expectEqualStrings("programNotification", notification.method);
    try std.testing.expect(notification.params.result.value.pubkey.len != 0);
    try std.testing.expectEqual(1000, notification.params.result.value.account.lamports);
    try std.testing.expectEqual(42, notification.params.result.context.slot);
}
