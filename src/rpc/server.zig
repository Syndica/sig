const httpz = @import("httpz");
const std = @import("std");
const GossipService = @import("../gossip/gossip_service.zig").GossipService;
const Logger = @import("../trace/log.zig").Logger;
const testing = std.testing;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const t = @import("types.zig");
const RpcRequestProcessor = @import("processor.zig").RpcRequestProcessor;
const Uuid = @import("../common/uuid.zig").Uuid;

pub const State = struct {
    rpc_request_processor: *RpcRequestProcessor,

    pub fn init(rpc_request_processor: *RpcRequestProcessor) State {
        return State{
            .rpc_request_processor = rpc_request_processor,
        };
    }
};

pub const ReqCtx = struct {
    id: Uuid,
    state: State,

    pub fn init(state: State) ReqCtx {
        return ReqCtx{
            .id = Uuid.init(),
            .state = state,
        };
    }
};

pub const JsonRpcServer = struct {
    server: Server,
    logger: Logger,
    port: u16,

    const Self = @This();
    const Server = httpz.ServerCtx(State, ReqCtx);

    pub fn init(alloc: std.mem.Allocator, state: State, logger: Logger, port: u16) !Self {
        var server = try Server.init(alloc, .{ .port = port }, state);

        server.notFound(notFound);
        server.errorHandler(errorHandler);

        // set a global dispatch for any routes defined from this point on
        server.dispatcher(dispatcher);

        var router = server.router();
        router.post("/", rpcHandler);

        return Self{
            .server = server,
            .logger = logger,
            .port = port,
        };
    }

    pub fn deinit(self: *Self) void {
        self.server.deinit();
    }

    pub fn listenAndServe(self: *Self) !void {
        self.logger.debugf("started rpc server listener on 0.0.0.0:{d}", .{self.port});
        return self.server.listen();
    }
};

fn dispatcher(global: State, action: httpz.Action(ReqCtx), req: *httpz.Request, res: *httpz.Response) !void {
    // If needed, req.arena is an std.mem.Allocator than can be used to allocate memory
    // and it'll exist for the life of this request.
    const context = ReqCtx.init(global);
    return action(context, req, res);
}

fn rpcHandler(ctx: ReqCtx, req: *httpz.Request, response: *httpz.Response) !void {
    if (req.body()) |body| {
        var jrpc_request = std.json.parseFromSlice(t.JsonRpcRequest, req.arena, body, .{}) catch |err| {
            return respondJsonRpcError(
                .null,
                response,
                t.jrpc_error_code_invalid_params,
                std.fmt.allocPrint(req.arena, "Invalid request body, expected type JsonRpcRequest: {any}", .{err}) catch unreachable,
            );
        };

        defer jrpc_request.deinit();
        return methodCall(req.arena, ctx.state.rpc_request_processor, &jrpc_request.value, response);
    } else {
        // return no body
        return respondJsonRpcError(
            .null,
            response,
            t.jrpc_error_code_invalid_request,
            "Missing request body, expected type JsonRpcRequest",
        );
    }
}

inline fn methodCall(allocator: std.mem.Allocator, processor: *RpcRequestProcessor, request: *t.JsonRpcRequest, response: *httpz.Response) !void {
    if (strEquals(request.method, "getAccountInfo")) {
        return RpcFunc(RpcRequestProcessor.getAccountInfo).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getBalance")) {
        return RpcFunc(RpcRequestProcessor.getBalance).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getBlock")) {
        return RpcFunc(RpcRequestProcessor.getBlock).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getBlockCommitment")) {
        return RpcFunc(RpcRequestProcessor.getBlockCommitment).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getBlockHeight")) {
        return RpcFunc(RpcRequestProcessor.getBlockHeight).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getBlockProduction")) {
        return RpcFunc(RpcRequestProcessor.getBlockProduction).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getBlocks")) {
        return RpcFunc(RpcRequestProcessor.getBlocks).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getBlocksWithLimit")) {
        return RpcFunc(RpcRequestProcessor.getBlocksWithLimit).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getBlockTime")) {
        return RpcFunc(RpcRequestProcessor.getBlockTime).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getClusterNodes")) {
        return RpcFunc(RpcRequestProcessor.getClusterNodes).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getConfirmedBlock")) {
        return RpcFunc(RpcRequestProcessor.getConfirmedBlock).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getConfirmedBlocks")) {
        return RpcFunc(RpcRequestProcessor.getConfirmedBlocks).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getConfirmedBlocksWithLimit")) {
        return RpcFunc(RpcRequestProcessor.getConfirmedBlocksWithLimit).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getConfirmedSignaturesForAddress2")) {
        return RpcFunc(RpcRequestProcessor.getConfirmedSignaturesForAddress2).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getConfirmedTransaction")) {
        return RpcFunc(RpcRequestProcessor.getConfirmedTransaction).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getEpochInfo")) {
        return RpcFunc(RpcRequestProcessor.getEpochInfo).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getEpochSchedule")) {
        return RpcFunc(RpcRequestProcessor.getEpochSchedule).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getFeeCalculatorForBlockhash")) {
        return RpcFunc(RpcRequestProcessor.getFeeCalculatorForBlockhash).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getFeeForMessage")) {
        return RpcFunc(RpcRequestProcessor.getFeeForMessage).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getFeeRateGovernor")) {
        return RpcFunc(RpcRequestProcessor.getFeeRateGovernor).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getFees")) {
        return RpcFunc(RpcRequestProcessor.getFees).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getFirstAvailableBlock")) {
        return RpcFunc(RpcRequestProcessor.getFirstAvailableBlock).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getGenesisHash")) {
        return RpcFunc(RpcRequestProcessor.getGenesisHash).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getHealth")) {
        return RpcFunc(RpcRequestProcessor.getHealth).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getHighestSnapshotSlot")) {
        return RpcFunc(RpcRequestProcessor.getHighestSnapshotSlot).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getIdentity")) {
        return RpcFunc(RpcRequestProcessor.getIdentity).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getInflationGovernor")) {
        return RpcFunc(RpcRequestProcessor.getInflationGovernor).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getInflationRate")) {
        return RpcFunc(RpcRequestProcessor.getInflationRate).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getInflationReward")) {
        return RpcFunc(RpcRequestProcessor.getInflationReward).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getLargestAccounts")) {
        return RpcFunc(RpcRequestProcessor.getLargestAccounts).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getLatestBlockhash")) {
        return RpcFunc(RpcRequestProcessor.getLatestBlockhash).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getLeaderSchedule")) {
        return RpcFunc(RpcRequestProcessor.getLeaderSchedule).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getMaxRetransmitSlot")) {
        return RpcFunc(RpcRequestProcessor.getMaxRetransmitSlot).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getMaxShredInsertSlot")) {
        return RpcFunc(RpcRequestProcessor.getMaxShredInsertSlot).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getMinimumBalanceForRentExemption")) {
        return RpcFunc(RpcRequestProcessor.getMinimumBalanceForRentExemption).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getMultipleAccounts")) {
        return RpcFunc(RpcRequestProcessor.getMultipleAccounts).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getProgramAccounts")) {
        return RpcFunc(RpcRequestProcessor.getProgramAccounts).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getRecentBlockhash")) {
        return RpcFunc(RpcRequestProcessor.getRecentBlockhash).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getRecentPerformanceSamples")) {
        return RpcFunc(RpcRequestProcessor.getRecentPerformanceSamples).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getRecentPrioritizationFees")) {
        return RpcFunc(RpcRequestProcessor.getRecentPrioritizationFees).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getSignaturesForAddress")) {
        return RpcFunc(RpcRequestProcessor.getSignaturesForAddress).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getSignatureStatuses")) {
        return RpcFunc(RpcRequestProcessor.getSignatureStatuses).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getSlot")) {
        return RpcFunc(RpcRequestProcessor.getSlot).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getSlotLeader")) {
        return RpcFunc(RpcRequestProcessor.getSlotLeader).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getSlotLeaders")) {
        return RpcFunc(RpcRequestProcessor.getSlotLeaders).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getSnapshotSlot")) {
        return RpcFunc(RpcRequestProcessor.getSnapshotSlot).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getStakeActivation")) {
        return RpcFunc(RpcRequestProcessor.getStakeActivation).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getStakeMinimumDelegation")) {
        return RpcFunc(RpcRequestProcessor.getStakeMinimumDelegation).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getSupply")) {
        return RpcFunc(RpcRequestProcessor.getSupply).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getTokenAccountBalance")) {
        return RpcFunc(RpcRequestProcessor.getTokenAccountBalance).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getTokenAccountsByDelegate")) {
        return RpcFunc(RpcRequestProcessor.getTokenAccountsByDelegate).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getTokenAccountsByOwner")) {
        return RpcFunc(RpcRequestProcessor.getTokenAccountsByOwner).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getTokenLargestAccounts")) {
        return RpcFunc(RpcRequestProcessor.getTokenLargestAccounts).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getTokenSupply")) {
        return RpcFunc(RpcRequestProcessor.getTokenSupply).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getTotalSupply")) {
        return RpcFunc(RpcRequestProcessor.getTotalSupply).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getTransaction")) {
        return RpcFunc(RpcRequestProcessor.getTransaction).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getTransactionCount")) {
        return RpcFunc(RpcRequestProcessor.getTransactionCount).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getVersion")) {
        return RpcFunc(RpcRequestProcessor.getVersion).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "getVoteAccounts")) {
        return RpcFunc(RpcRequestProcessor.getVoteAccounts).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "isBlockhashValid")) {
        return RpcFunc(RpcRequestProcessor.isBlockhashValid).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "minimumLedgerSlot")) {
        return RpcFunc(RpcRequestProcessor.minimumLedgerSlot).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "requestAirdrop")) {
        return RpcFunc(RpcRequestProcessor.requestAirdrop).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "sendTransaction")) {
        return RpcFunc(RpcRequestProcessor.sendTransaction).call(allocator, processor, request, response);
    }
    if (strEquals(request.method, "simulateTransaction")) {
        return RpcFunc(RpcRequestProcessor.simulateTransaction).call(allocator, processor, request, response);
    }

    return respondJsonRpcError(
        request.id,
        response,
        t.jrpc_error_code_internal_error,
        "not implemented",
    );
}

inline fn strEquals(value: []const u8, other: []const u8) bool {
    return std.mem.eql(u8, value, other);
}

pub fn RpcFunc(comptime func: anytype) type {
    const S = struct {
        fn call(allocator: std.mem.Allocator, processor: *RpcRequestProcessor, request: *t.JsonRpcRequest, response: *httpz.Response) !void {
            if (request.params != .array) {
                return respondJsonRpcError(
                    request.id,
                    response,
                    t.jrpc_error_code_invalid_params,
                    std.fmt.allocPrint(allocator, "Invalid params, expected type: array, got: {s} ", .{@tagName(request.params)}) catch unreachable,
                );
            }

            const Args = std.meta.ArgsTuple(@TypeOf(func));

            var args: Args = undefined;
            args[0] = processor;
            args[1] = allocator;
            inline for (std.meta.fields(Args)[2..], 2.., 0..) |field, argIndex, valueIndex| {
                if (valueIndex >= request.params.array.items.len) {
                    // if type is nullable, set to null
                    if (@typeInfo(field.type) == .Optional) {
                        args[argIndex] = null;
                    } else {
                        const type_name = switch (field.type) {
                            []const u8 => "string",
                            else => @typeName(field.type),
                        };

                        return respondJsonRpcError(
                            request.id,
                            response,
                            t.jrpc_error_code_invalid_params,
                            std.fmt.allocPrint(allocator, "Missing paramater position {any}, expected type: {s}", .{ valueIndex, type_name }) catch unreachable,
                        );
                    }
                } else {
                    var parsed = std.json.parseFromValue(field.type, allocator, request.params.array.items[valueIndex], .{}) catch |err| {
                        const type_name = switch (field.type) {
                            []const u8 => "string",
                            else => @typeName(field.type),
                        };

                        return respondJsonRpcError(
                            request.id,
                            response,
                            t.jrpc_error_code_invalid_params,
                            std.fmt.allocPrint(allocator, "Invalid paramater position {any}, expected type {s}: {any}", .{ valueIndex, type_name, err }) catch unreachable,
                        );
                    };

                    args[argIndex] = parsed.value;
                }
            }

            return respondWithJsonRpcResponse(@call(.auto, func, args), request, response);
        }
    };

    return S;
}

inline fn respondWithJsonRpcResponse(result: anytype, request: *t.JsonRpcRequest, response: *httpz.Response) !void {
    switch (result) {
        .Ok => |v| {
            var success_response: t.JsonRpcResponse(@TypeOf(result.Ok)) = .{
                .id = request.id,
                .jsonrpc = "2.0",
                .result = v,
                .@"error" = null,
            };

            return response.json(success_response, .{
                .emit_null_optional_fields = false,
                .emit_strings_as_arrays = false,
            });
        },
        .Err => |err| {
            var error_response: t.JsonRpcResponse(u0) = .{
                .id = request.id,
                .jsonrpc = "2.0",
                .@"error" = err.toErrorObject(),
                .result = null,
            };

            return response.json(error_response, .{
                .emit_null_optional_fields = false,
                .emit_strings_as_arrays = false,
            });
        },
    }
}

inline fn respondJsonRpcError(request_id: t.Id, response: *httpz.Response, code: i32, message: []const u8) !void {
    var error_response: t.JsonRpcResponse(u0) = .{
        .id = request_id,
        .jsonrpc = "2.0",
        .@"error" = t.ErrorObject.init(code, message),
        .result = null,
    };

    return response.json(error_response, .{
        .emit_null_optional_fields = false,
        .emit_strings_as_arrays = false,
    });
}

fn notFound(_: State, _: *httpz.Request, res: *httpz.Response) anyerror!void {
    res.status = 404;
    res.body = "Not Found";
}

// note that the error handler return `void` and not `!void`
fn errorHandler(_: State, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
    res.status = 500;
    res.body = "Internal Server Error";
    std.log.warn("unhandled exception for request: {s}\nErr: {}", .{ req.url.raw, err });
}
