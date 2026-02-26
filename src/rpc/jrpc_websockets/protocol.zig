const std = @import("std");
const sig = @import("sig");
const ws = @import("webzockets");
const base58 = @import("base58");
const zstd = @import("zstd");
const types = @import("types.zig");
const methods = @import("methods.zig");
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

/// Helper struct to return encoded data and associated encoding name
const EncodedAccountData = struct {
    encoded: []const u8,
    encoding_name: []const u8,
};

fn encodeAccountData(
    allocator: std.mem.Allocator,
    account: *const sig.core.Account,
    encoding: methods.Encoding,
) !EncodedAccountData {
    // TODO: this is all likely placeholder, to be replaced by same code used for getAccountInfo
    const raw = try account.data.readAllAllocate(allocator);
    defer allocator.free(raw);

    const b64 = std.base64.standard.Encoder;

    const result: EncodedAccountData = switch (encoding) {
        // TODO: integrate jsonParsed encoding
        .base64, .jsonParsed => blk: {
            const buf = try allocator.alloc(u8, b64.calcSize(raw.len));
            const encoded = b64.encode(buf, raw);
            break :blk .{ .encoded = encoded, .encoding_name = "base64" };
        },
        .@"base64+zstd" => blk: {
            const compressor = zstd.Compressor.init(.{}) catch
                return error.ZstdCompressFailed;
            defer compressor.deinit();
            const bound = raw.len + (raw.len >> 8) + 128;
            const compressed = try allocator.alloc(u8, bound);
            defer allocator.free(compressed);
            const zstd_data = compressor.compress2(compressed, raw) catch
                return error.ZstdCompressFailed;
            const buf = try allocator.alloc(u8, b64.calcSize(zstd_data.len));
            const encoded = b64.encode(buf, zstd_data);
            break :blk .{ .encoded = encoded, .encoding_name = "base64+zstd" };
        },
        .base58 => if (raw.len <= 128) b58: {
            const buf = try allocator.alloc(u8, base58.encodedMaxSize(raw.len));
            const buf_len = base58.Table.BITCOIN.encode(buf, raw);
            break :b58 .{
                .encoded = buf[0..buf_len],
                .encoding_name = "base58",
            };
        } else blk: {
            const buf = try allocator.alloc(u8, b64.calcSize(raw.len));
            const encoded = b64.encode(buf, raw);
            break :blk .{ .encoded = encoded, .encoding_name = "base64" };
        },
    };

    return result;
}

const AccountValue = struct {
    acc: *const sig.core.Account,
    encoded: []const u8,
    encoding_name: []const u8,

    pub fn jsonStringify(self: AccountValue, jw: anytype) !void {
        try jw.write(.{
            .data = .{ self.encoded, self.encoding_name },
            .executable = self.acc.executable,
            .lamports = self.acc.lamports,
            .owner = self.acc.owner,
            .rentEpoch = self.acc.rent_epoch,
            .space = self.acc.data.len(),
        });
    }
};

pub fn serializeAccountNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    data: types.AccountEventData,
    encoding: methods.Encoding,
) !NotifPayload {
    const awp = data.rc.get();
    const enc = try encodeAccountData(allocator, &awp.account, encoding);
    defer allocator.free(enc.encoded);

    const av = AccountValue{
        .acc = &awp.account,
        .encoded = enc.encoded,
        .encoding_name = enc.encoding_name,
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
    encoding: methods.Encoding,
) !NotifPayload {
    const awp = data.rc.get();
    const enc = try encodeAccountData(allocator, &awp.account, encoding);
    defer allocator.free(enc.encoded);

    const av = AccountValue{
        .acc = &awp.account,
        .encoded = enc.encoded,
        .encoding_name = enc.encoding_name,
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
    num_logs: u32,

    pub fn jsonStringify(self: LogsValue, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("signature");
        try jw.write(self.signature);
        try jw.objectField("err");
        try jw.write(null);
        try jw.objectField("logs");
        try jw.beginArray();
        for (0..self.num_logs) |i| {
            try jw.print("\"log line {d}\"", .{i});
        }
        try jw.endArray();
        try jw.endObject();
    }
};

pub fn serializeLogsNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    data: types.LogsEventData,
) !NotifPayload {
    return serializeToPayload(allocator, .{
        .jsonrpc = "2.0",
        .method = "logsNotification",
        .params = .{
            .result = .{
                .context = .{ .slot = data.slot },
                .value = LogsValue{ .signature = data.signature, .num_logs = data.num_logs },
            },
            .subscription = sub_id,
        },
    });
}

pub fn serializeNotification(
    allocator: std.mem.Allocator,
    sub_id: types.SubId,
    event_data: types.EventData,
    encoding: methods.Encoding,
    sub_method: types.SubMethod,
) !NotifPayload {
    return switch (event_data) {
        .slot => |d| serializeSlotNotification(allocator, sub_id, d),
        .root => |d| serializeRootNotification(allocator, sub_id, d),
        .logs => |d| serializeLogsNotification(allocator, sub_id, d),
        .account => |d| switch (sub_method) {
            .account => serializeAccountNotification(allocator, sub_id, d, encoding),
            .program => serializeProgramNotification(allocator, sub_id, d, encoding),
            else => unreachable,
        },
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

test "serializeAccountNotification base64 default" {
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
    const rc = try types.RcAccountWithPubkey.init(allocator, pk, account);
    defer rc.release(allocator);

    const p = try serializeAccountNotification(allocator, 7, .{
        .rc = rc,
        .slot = 100,
    }, .base64);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":100},"value":{"data":["3q0=","base64"],"executable":false,"lamports":1000,"owner":"11111111111111111111111111111111","rentEpoch":42,"space":2}},"subscription":7}}
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
    const rc = try types.RcAccountWithPubkey.init(allocator, pk, account);
    defer rc.release(allocator);

    const p = try serializeAccountNotification(allocator, 1, .{
        .rc = rc,
        .slot = 50,
    }, .base64);
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":50},"value":{"data":["AQIDBA==","base64"],"executable":true,"lamports":500,"owner":"11111111111111111111111111111111","rentEpoch":0,"space":4}},"subscription":1}}
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
    const rc = try types.RcAccountWithPubkey.init(allocator, pk, account);
    defer rc.release(allocator);

    const p = try serializeAccountNotification(allocator, 7, .{
        .rc = rc,
        .slot = 100,
    }, .base58);
    defer p.deinit(allocator);

    // base58 of [0xDE, 0xAD] = "Hwr" (Bitcoin alphabet)
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"accountNotification","params":{"result":{"context":{"slot":100},"value":{"data":["Hwr","base58"],"executable":false,"lamports":1000,"owner":"11111111111111111111111111111111","rentEpoch":42,"space":2}},"subscription":7}}
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
    const rc = try types.RcAccountWithPubkey.init(allocator, pk, account);
    defer rc.release(allocator);

    const p = try serializeAccountNotification(allocator, 7, .{
        .rc = rc,
        .slot = 100,
    }, .@"base64+zstd");
    defer p.deinit(allocator);

    const json = extractJson(p.payload());
    // Verify envelope structure and encoding name.
    try std.testing.expect(std.mem.indexOf(u8, json, "\"base64+zstd\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"lamports\":1000") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rentEpoch\":42") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"space\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"slot\":100") != null);
    // Verify it starts correctly and is valid JSON.
    try std.testing.expect(
        std.mem.startsWith(u8, json, "{\"jsonrpc\":\"2.0\",\"method\":\"accountNotification\""),
    );
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
    const rc = try types.RcAccountWithPubkey.init(allocator, pk, account);
    defer rc.release(allocator);

    const p = try serializeAccountNotification(allocator, 1, .{
        .rc = rc,
        .slot = 1,
    }, .base64);
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
    const rc = try types.RcAccountWithPubkey.init(allocator, account_pk, account);
    defer rc.release(allocator);

    const p = try serializeProgramNotification(allocator, 3, .{
        .rc = rc,
        .slot = 200,
    }, .base64);
    defer p.deinit(allocator);

    // base64 of [0xCA, 0xFE] = "yv4="
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"programNotification","params":{"result":{"context":{"slot":200},"value":{"pubkey":"11111111111111111111111111111111","account":{"data":["yv4=","base64"],"executable":false,"lamports":999,"owner":"11111111111111111111111111111111","rentEpoch":7,"space":2}}},"subscription":3}}
    , extractJson(p.payload()));
}

test "serializeLogsNotification format" {
    const allocator = std.testing.allocator;
    const p = try serializeLogsNotification(allocator, 5, .{
        .signature = sig.core.Signature.ZEROES,
        .num_logs = 3,
        .slot = 77,
    });
    defer p.deinit(allocator);

    // Signature of all zeros → base58 = 64 '1' characters.
    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"logsNotification","params":{"result":{"context":{"slot":77},"value":{"signature":"1111111111111111111111111111111111111111111111111111111111111111","err":null,"logs":["log line 0","log line 1","log line 2"]}},"subscription":5}}
    , extractJson(p.payload()));
}

test "serializeLogsNotification zero logs" {
    const allocator = std.testing.allocator;
    const p = try serializeLogsNotification(allocator, 1, .{
        .signature = sig.core.Signature.ZEROES,
        .num_logs = 0,
        .slot = 1,
    });
    defer p.deinit(allocator);

    try std.testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"logsNotification","params":{"result":{"context":{"slot":1},"value":{"signature":"1111111111111111111111111111111111111111111111111111111111111111","err":null,"logs":[]}},"subscription":1}}
    , extractJson(p.payload()));
}

test "serializeNotification dispatches account with encoding and sub_method" {
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
    const rc = try types.RcAccountWithPubkey.init(allocator, pk, account);
    defer rc.release(allocator);

    // Dispatch as program notification via serializeNotification.
    const p = try serializeNotification(
        allocator,
        10,
        .{ .account = .{ .rc = rc, .slot = 42 } },
        .base64,
        .program,
    );
    defer p.deinit(allocator);

    const json = extractJson(p.payload());
    try std.testing.expect(
        std.mem.startsWith(u8, json, "{\"jsonrpc\":\"2.0\",\"method\":\"programNotification\""),
    );
    try std.testing.expect(std.mem.indexOf(u8, json, "\"pubkey\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"account\":") != null);
}
