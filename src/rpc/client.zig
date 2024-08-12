const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

pub const Client = struct {
    http_client: std.http.Client,
    http_endpoint: []const u8,

    const JSON_RPC_ID = 1;
    const JSON_RPC_VERSION = "2.0";
    const CONTENT_TYPE = "application/json";
    const USER_AGENT = "sig/0.1";

    const Error = struct {
        code: i64,
        message: []const u8,
    };

    const Request = struct {
        id: u64,
        jsonrpc: []const u8,
        method: []const u8,
        params: []const u8,
    };

    fn Response(comptime R: type) type {
        return struct {
            id: u64,
            jsonrpc: []const u8,
            result: ?R = null,
            @"error": ?Error = null,
        };
    }

    const Commitment = enum {
        Finalized,
        Confirmed,
        Processed,

        pub fn asString(self: Commitment) []const u8 {
            switch (self) {
                .Finalized => return "finalized",
                .Confirmed => return "confirmed",
                .Processed => return "processed",
            }
        }
    };

    fn SendFetchResponse(comptime R: type) type {
        return struct {
            parsed: std.json.Parsed(Response(R)),
            payload: std.ArrayList(u8),

            pub fn err(self: *const SendFetchResponse(R)) ?Error {
                return self.parsed.value.@"error";
            }

            pub fn result(self: SendFetchResponse(R)) R {
                return self.parsed.value.result.?;
            }

            pub fn maybeResult(self: SendFetchResponse(R)) ?R {
                return self.parsed.value.result;
            }

            pub fn deinit(self: SendFetchResponse(R)) void {
                self.parsed.deinit();
                self.payload.deinit();
            }
        };
    }

    pub fn init(allocator: std.mem.Allocator, http_endpoint: []const u8) Client {
        return Client{
            .http_client = std.http.Client{
                .allocator = allocator,
            },
            .http_endpoint = http_endpoint,
        };
    }

    pub fn deinit(self: *Client) void {
        self.http_client.deinit();
    }

    fn sendFetchRequest(
        self: *Client,
        allocator: std.mem.Allocator,
        comptime R: type,
        method: []const u8,
        params: ?[]const u8,
    ) !SendFetchResponse(R) {
        var response_payload = std.ArrayList(u8).init(allocator);
        const request_payload = try std.fmt.allocPrint(
            allocator,
            "{{\"id\":{},\"jsonrpc\":\"{s}\",\"method\":\"{s}\",\"params\":{s}}}",
            .{
                .id = JSON_RPC_ID,
                .jsonrpc = JSON_RPC_VERSION,
                .method = method,
                .params = params orelse "null",
            },
        );
        defer allocator.free(request_payload);

        // std.debug.print("Request: {s}\n", .{request_payload});

        const result = try self.http_client.fetch(.{
            .location = .{ .url = self.http_endpoint },
            .method = std.http.Method.POST,
            .headers = .{
                .content_type = .{ .override = CONTENT_TYPE },
                .user_agent = .{ .override = USER_AGENT },
            },
            .payload = request_payload,
            .response_storage = .{ .dynamic = &response_payload },
            .max_append_size = 100 * 1024 * 1024,
        });

        // std.debug.print("Response: {s}\n", .{response_payload.items});

        std.debug.assert(result.status == std.http.Status.ok); // TODO: handle error

        const parsed = try std.json.parseFromSlice(
            Response(R),
            allocator,
            response_payload.items,
            .{ .ignore_unknown_fields = true },
        );
        return .{
            .parsed = parsed,
            .payload = response_payload,
        };
    }

    pub fn getBlockHeight(self: *Client, allocator: std.mem.Allocator) !u64 {
        const response = try self.sendFetchRequest(allocator, u64, "getBlockHeight", null);
        defer response.deinit();
        return response.result(); // TODO: handle error
    }

    pub fn getSlot(self: *Client, allocator: std.mem.Allocator) !u64 {
        const response = try self.sendFetchRequest(allocator, u64, "getSlot", null);
        defer response.deinit();
        return response.result(); // TODO: handle error
    }

    pub fn getIdentity(self: *Client, allocator: std.mem.Allocator) !Pubkey {
        const response = try self.sendFetchRequest(allocator, std.json.Value, "getIdentity", null);
        defer response.deinit();
        return Pubkey.fromBase58String(response.result().object.get("identity").?.string); // TODO: handle error
    }

    pub const EpochInfo = struct {
        absoluteSlot: Slot,
        blockHeight: u64,
        epoch: Epoch,
        slotIndex: u64,
        slotsInEpoch: u64,
        transactionCount: u64,
    };

    pub const EpochInfoParams = struct {
        commitment: ?Commitment = null,
        minContextSlot: ?Slot = null,

        pub fn toJsonString(self: EpochInfoParams, allocator: std.mem.Allocator) ![]const u8 {
            var config = std.json.ObjectMap.init(allocator);
            defer config.deinit();
            if (self.commitment != null)
                try config.put("commitment", .{ .string = self.commitment.?.asString() });
            if (self.minContextSlot != null)
                try config.put("minContextSlot", .{ .integer = @intCast(self.minContextSlot.?) });
            var array = try std.ArrayList(std.json.Value).initCapacity(allocator, 2);
            defer array.deinit();
            try array.insert(0, .{ .object = config });
            return try std.json.stringifyAlloc(allocator, std.json.Value{ .array = array }, .{});
        }
    };

    pub fn getEpochInfo(self: *Client, allocator: std.mem.Allocator, params: EpochInfoParams) !EpochInfo {
        const params_json = try params.toJsonString(allocator);
        defer allocator.free(params_json);

        const response = try self.sendFetchRequest(
            allocator,
            EpochInfo,
            "getEpochInfo",
            params_json,
        );
        defer response.deinit();

        return response.result(); // TODO: handle error
    }

    pub const LatestBlockhash = struct {
        context: Context,
        value: Value,

        pub const Context = struct {
            slot: Slot,
        };

        pub const Value = struct {
            blockhash: Hash,
            lastValidBlockHeight: u64,
        };

        pub fn init(value: std.json.Value) !LatestBlockhash {
            const json_object = value.object;
            const json_context = json_object.get("context").?.object;
            const json_value = json_object.get("value").?.object;

            const context = Context{
                .slot = @intCast(json_context.get("slot").?.integer),
            };

            const blockhash = try Hash.fromBase58String(json_value.get("blockhash").?.string);
            const lastValidBlockHeight: u64 = @intCast(json_value.get("lastValidBlockHeight").?.integer);

            return .{
                .context = context,
                .value = Value{
                    .blockhash = blockhash,
                    .lastValidBlockHeight = lastValidBlockHeight,
                },
            };
        }
    };

    pub const LatestBlockhashParams = struct {
        commitment: ?Commitment = null,
        minContextSlot: ?Slot = null,

        pub fn toJsonString(self: LatestBlockhashParams, allocator: std.mem.Allocator) ![]const u8 {
            var config = std.json.ObjectMap.init(allocator);
            defer config.deinit();
            if (self.commitment != null)
                try config.put("commitment", .{ .string = self.commitment.?.asString() });
            if (self.minContextSlot != null)
                try config.put("minContextSlot", .{ .integer = @intCast(self.minContextSlot.?) });
            var array = try std.ArrayList(std.json.Value).initCapacity(allocator, 2);
            defer array.deinit();
            try array.insert(0, .{ .object = config });
            return try std.json.stringifyAlloc(allocator, std.json.Value{ .array = array }, .{});
        }
    };

    pub fn getLatestBlockhash(self: *Client, allocator: std.mem.Allocator, params: LatestBlockhashParams) !LatestBlockhash {
        const params_json = try params.toJsonString(allocator);
        defer allocator.free(params_json);

        const response = try self.sendFetchRequest(
            allocator,
            std.json.Value,
            "getLatestBlockhash",
            params_json,
        );
        defer response.deinit();

        return try LatestBlockhash.init(response.result()); // TODO: handle error
    }

    pub const LeaderSchedule = std.StringArrayHashMap([]const u64);

    pub const LeaderScheduleParams = struct {
        epoch: ?Epoch = null,
        identity: ?[]const u8 = null,
        commitment: ?Commitment = null,

        pub fn toJsonString(self: LeaderScheduleParams, allocator: std.mem.Allocator) ![]const u8 {
            var config = std.json.ObjectMap.init(allocator);
            defer config.deinit();
            if (self.commitment != null)
                try config.put("commitment", .{ .string = self.commitment.?.asString() });
            if (self.identity != null)
                try config.put("identity", .{ .string = self.identity.? });
            var array = try std.ArrayList(std.json.Value).initCapacity(allocator, 2);
            defer array.deinit();
            try array.insert(0, if (self.epoch != null) .{ .integer = @intCast(self.epoch.?) } else .null);
            try array.insert(1, .{ .object = config });
            return try std.json.stringifyAlloc(allocator, std.json.Value{ .array = array }, .{});
        }
    };

    pub fn getLeaderSchedule(self: *Client, allocator: std.mem.Allocator, params: LeaderScheduleParams) !LeaderSchedule {
        const params_json = try params.toJsonString(allocator);
        defer allocator.free(params_json);

        const response = try self.sendFetchRequest(
            allocator,
            std.json.Value,
            "getLeaderSchedule",
            params_json,
        );
        defer response.deinit();

        var leader_schedule = LeaderSchedule.init(allocator);
        var json_iter = response.result().object.iterator();
        while (json_iter.next()) |entry| {
            const key = try allocator.dupe(u8, entry.key_ptr.*);
            var slots = try allocator.alloc(u64, entry.value_ptr.*.array.items.len);
            for (entry.value_ptr.*.array.items, 0..) |slot, i| {
                slots[i] = @intCast(slot.integer);
            }
            try leader_schedule.put(key, slots);
        }

        return leader_schedule; // TODO: handle error
    }

    pub const SignatureStatuses = struct {
        allocator: std.mem.Allocator,
        context: Context,
        value: []const ?Status,

        pub const Context = struct {
            apiVersion: []const u8,
            slot: Slot,
        };

        pub const Status = struct {
            slot: Slot,
            confirmations: ?usize,
            err: bool, // TODO: Deserialse to TransactionError
            confirmationStatus: ?[]const u8,
        };

        pub fn init(allocator: std.mem.Allocator, value: std.json.Value) !SignatureStatuses {
            const json_object = value.object;
            const json_context = json_object.get("context").?.object;
            const json_values = json_object.get("value").?.array;

            const context = SignatureStatuses.Context{
                .apiVersion = try allocator.dupe(u8, json_context.get("apiVersion").?.string),
                .slot = @intCast(json_context.get("slot").?.integer),
            };

            var statuses = try allocator.alloc(?SignatureStatuses.Status, json_values.items.len);
            for (json_values.items, 0..) |json_value, i| {
                if (json_value == .null) {
                    statuses[i] = null;
                } else {
                    const obj = json_value.object;
                    const slot = obj.get("slot").?;
                    const confirmations = obj.get("confirmations").?;
                    const err = obj.get("err").?;
                    const confirmationStatus = obj.get("confirmationStatus").?;
                    statuses[i] = SignatureStatuses.Status{
                        .slot = @intCast(slot.integer),
                        .confirmations = if (confirmations == .null) null else @intCast(confirmations.integer),
                        .err = if (err == .null) false else true,
                        .confirmationStatus = if (confirmationStatus == .null) null else try allocator.dupe(u8, confirmationStatus.string),
                    };
                }
            }

            return .{
                .allocator = allocator,
                .context = context,
                .value = statuses,
            };
        }

        pub fn deinit(self: SignatureStatuses) void {
            self.allocator.free(self.context.apiVersion);
            for (self.value) |maybe_status| {
                if (maybe_status) |status| {
                    if (status.confirmationStatus) |confirmationStatus| self.allocator.free(confirmationStatus);
                }
            }
            self.allocator.free(self.value);
        }
    };

    pub const SignatureStatusesParams = struct {
        signatures: []const Signature,
        searchTransactionHistory: ?bool,

        const MAX_SIGNATURES: u8 = 256;

        pub fn toJsonString(self: SignatureStatusesParams, allocator: std.mem.Allocator) ![]const u8 {
            var config = std.json.ObjectMap.init(allocator);
            defer config.deinit();

            if (self.searchTransactionHistory) |sth|
                try config.put("searchTransactionHistory", .{ .bool = sth });

            var array = try std.ArrayList(std.json.Value).initCapacity(allocator, 2);
            defer array.deinit();

            var signatures_array = try std.ArrayList(std.json.Value).initCapacity(allocator, self.signatures.len);
            defer {
                for (signatures_array.items) |signature| {
                    allocator.free(signature.string);
                }
                signatures_array.deinit();
            }

            for (self.signatures) |signature| {
                const stack_base58 = signature.toBase58String().slice();
                const heap_base58 = try allocator.dupe(u8, stack_base58);
                try signatures_array.append(.{ .string = heap_base58 });
            }

            try array.insert(0, .{ .array = signatures_array });
            try array.insert(1, .{ .object = config });

            return try std.json.stringifyAlloc(allocator, std.json.Value{ .array = array }, .{});
        }
    };

    pub fn getSignatureStatuses(self: *Client, allocator: std.mem.Allocator, params: SignatureStatusesParams) !SignatureStatuses {
        const params_json = try params.toJsonString(allocator);
        defer allocator.free(params_json);

        const response = try self.sendFetchRequest(
            allocator,
            std.json.Value,
            "getSignatureStatuses",
            params_json,
        );
        defer response.deinit();

        return try SignatureStatuses.init(allocator, response.result());
    }

    pub const SendTransactionParams = struct {
        transaction: []const u8,
        encoding: ?[]const u8 = null,
        skipPreflight: ?bool = null,
        preflightCommitment: ?Commitment = null,
        maxRetries: ?u64 = null,
        minContextSlot: ?Slot = null,

        pub fn toJsonString(self: SendTransactionParams, allocator: std.mem.Allocator) ![]const u8 {
            var config = std.json.ObjectMap.init(allocator);
            defer config.deinit();
            if (self.encoding) |encoding|
                try config.put("encoding", .{ .string = encoding });
            if (self.skipPreflight) |skipPreflight|
                try config.put("skipPreflight", .{ .bool = skipPreflight });
            if (self.preflightCommitment) |preflightCommitment|
                try config.put("preflightCommitment", .{ .string = preflightCommitment.asString() });
            if (self.maxRetries) |maxRetries|
                try config.put("maxRetries", .{ .integer = @intCast(maxRetries) });
            if (self.minContextSlot) |minContextSlot|
                try config.put("minContextSlot", .{ .integer = @intCast(minContextSlot) });
            var array = try std.ArrayList(std.json.Value).initCapacity(allocator, 2);
            defer array.deinit();
            try array.insert(0, .{ .string = self.transaction });
            try array.insert(1, .{ .object = config });
            return try std.json.stringifyAlloc(allocator, std.json.Value{ .array = array }, .{});
        }
    };

    pub fn sendTransaction(self: *Client, allocator: std.mem.Allocator, params: SendTransactionParams) !Signature {
        const params_json = try params.toJsonString(allocator);
        defer allocator.free(params_json);

        const response = try self.sendFetchRequest(
            allocator,
            std.json.Value,
            "sendTransaction",
            params_json,
        );
        defer response.deinit();

        return try Signature.fromBase58String(response.result().string); // TODO: handle error
    }

    test "rpc.Client.getBlockHeight" {
        const allocator = std.testing.allocator;
        var client = Client{
            .http_client = std.http.Client{
                .allocator = std.heap.page_allocator,
            },
            .http_endpoint = "https://api.testnet.solana.com",
        };
        defer client.http_client.deinit();
        _ = try client.getBlockHeight(allocator);
    }

    test "rpc.Client.getSlot" {
        const allocator = std.testing.allocator;
        var client = Client{
            .http_client = std.http.Client{
                .allocator = std.heap.page_allocator,
            },
            .http_endpoint = "https://api.testnet.solana.com",
        };
        defer client.http_client.deinit();
        _ = try client.getSlot(allocator);
    }

    test "rpc.Client.getIdentity" {
        const allocator = std.testing.allocator;
        var client = Client{
            .http_client = std.http.Client{
                .allocator = std.heap.page_allocator,
            },
            .http_endpoint = "https://api.testnet.solana.com",
        };
        defer client.http_client.deinit();
        _ = try client.getIdentity(allocator);
    }

    test "rpc.Client.getEpochInfo" {
        const allocator = std.testing.allocator;
        var client = Client{
            .http_client = std.http.Client{
                .allocator = std.heap.page_allocator,
            },
            .http_endpoint = "https://api.testnet.solana.com",
        };
        defer client.http_client.deinit();
        const params = EpochInfoParams{};
        _ = try client.getEpochInfo(allocator, params);
    }

    test "rpc.Client.getLatestBlockhash" {
        const allocator = std.testing.allocator;
        var client = Client{
            .http_client = std.http.Client{
                .allocator = std.heap.page_allocator,
            },
            .http_endpoint = "https://api.testnet.solana.com",
        };
        defer client.http_client.deinit();
        const params = LatestBlockhashParams{};
        _ = try client.getLatestBlockhash(allocator, params);
    }

    test "rpc.Client.getLeaderSchedule" {
        const allocator = std.testing.allocator;
        var client = Client{
            .http_client = std.http.Client{
                .allocator = std.heap.page_allocator,
            },
            .http_endpoint = "https://api.testnet.solana.com",
        };
        defer client.http_client.deinit();
        var leader_schedule = try client.getLeaderSchedule(allocator, .{});
        defer {
            for (leader_schedule.keys()) |key| {
                allocator.free(key);
            }
            for (leader_schedule.values()) |slots| {
                allocator.free(slots);
            }
            leader_schedule.deinit();
        }
    }

    test "rpc.Client.getSignatureStatuses" {
        const allocator = std.testing.allocator;
        var client = Client{
            .http_client = std.http.Client{
                .allocator = std.heap.page_allocator,
            },
            .http_endpoint = "https://api.testnet.solana.com",
        };
        defer client.http_client.deinit();
        var signatures = try allocator.alloc(Signature, 2);
        defer allocator.free(signatures);
        signatures[0] = try Signature.fromBase58String(
            "56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",
        );
        signatures[1] = try Signature.fromBase58String(
            "4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz",
        );

        const params = SignatureStatusesParams{
            .signatures = signatures,
            .searchTransactionHistory = true,
        };

        const params_json = try params.toJsonString(allocator);
        defer allocator.free(params_json);

        var signature_statuses = try client.getSignatureStatuses(allocator, .{
            .signatures = signatures,
            .searchTransactionHistory = true,
        });
        defer signature_statuses.deinit();
    }

    test "rpc.Client.sendTransaction" {
        const base58 = @import("base58-zig");
        const KeyPair = std.crypto.sign.Ed25519.KeyPair;
        const BASE58_ENCODER = base58.Encoder.init(.{});

        // const allocator = std.testing.allocator;
        const allocator = std.heap.page_allocator;
        var client = Client{
            .http_client = std.http.Client{
                .allocator = std.heap.page_allocator,
            },
            .http_endpoint = "https://api.testnet.solana.com",
        };
        defer client.http_client.deinit();

        const blockhash_params = sig.rpc.Client.LatestBlockhashParams{};
        const latest_blockhash = try client.getLatestBlockhash(allocator, blockhash_params);

        const from_pubkey = try Pubkey.fromBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
        const from_keypair = KeyPair{
            .public_key = .{ .bytes = from_pubkey.data },
            .secret_key = .{ .bytes = [_]u8{ 76, 196, 192, 17, 40, 245, 120, 49, 64, 133, 213, 227, 12, 42, 183, 70, 235, 64, 235, 96, 246, 205, 78, 13, 173, 111, 254, 96, 210, 208, 121, 240, 159, 193, 185, 89, 227, 77, 234, 91, 232, 234, 253, 119, 162, 105, 200, 227, 123, 90, 111, 105, 72, 53, 60, 147, 76, 154, 44, 72, 29, 165, 2, 246 } },
        };
        const to_pubkey = try Pubkey.fromBase58String("GDFVa3uYXDcNhcNk8A4v28VeF4wcMn8mauZNwVWbpcN");
        const lamports: u64 = 100;

        const transaction = try sig.core.transaction.buildTransferTansaction(
            allocator,
            from_keypair,
            from_pubkey,
            to_pubkey,
            lamports,
            latest_blockhash.value.blockhash,
        );
        defer transaction.deinit(allocator);

        const transaction_bytes = try sig.bincode.writeToArray(allocator, transaction, .{});
        defer transaction_bytes.deinit();

        const transaction_base58 = try BASE58_ENCODER.encodeAlloc(allocator, transaction_bytes.items);
        defer allocator.free(transaction_base58);

        const params = SendTransactionParams{
            .transaction = transaction_base58,
        };

        const signature = try client.sendTransaction(allocator, params);

        _ = signature;
        // std.debug.print("Transfer Signature: {s}", .{try signature.toString()});
    }
};
