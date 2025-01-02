const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const ErrorReturn = sig.utils.types.ErrorReturn;
const tryable = sig.utils.types.tryable;

const Response = rpc.Response;

pub fn StringMethodDispatch(
    Service: type,
    deserializeInputFn: anytype,
    serializeOutputFn: anytype,
) type {
    // TODO support Service pointer
    // - hold a pointer
    //   - still detect methods
    //   - support pass by value via copy?
    // - hold a value
    //   - support pass by pointer (what about mutable?)
    return struct {
        methods: MethodMap,
        service: Service,

        const MethodMap = std.StringHashMapUnmanaged(
            *const fn (Service, Allocator, []const u8) Error![]const u8,
        );

        const Self = @This();

        pub const Error = err: {
            var ErrorSet = error{};
            for (conformantMethods()) |method| ErrorSet |= method.ErrorReturn;
            rpc.request.deserializeLeaky;
            rpc.response.serialize;
            break :err ErrorSet;
        };

        pub fn init(allocator: Allocator, service: Service) Self {
            const methods = MethodMap{};
            inline for (conformantMethods()) |method| {
                try methods.put(allocator, method.name, genericMethod(method));
            }
            return .{ .methods = methods, .service = service };
        }

        const Method = struct {
            name: []const u8,
            Input: type,
            ErrorReturn: ?type,
        };

        fn conformantMethods() []const Method {
            var methods: []const []const u8 = &.{};
            for (std.meta.declarations(Service)) |decl| {
                const info = @typeInfo(@TypeOf(decl));
                if (info == .Fn and
                    info.Fn.return_type != null and
                    info.Fn.params.len == 3 and
                    info.Fn.params[0].type == Service)
                {
                    if (info.Fn.return_type == null) continue;
                    if (info.Fn.params[2] == null) continue;

                    const return_info = @typeInfo(info.Fn.return_type.?);
                    methods += .{
                        .name = decl.name,
                        .Input = info.Fn.params[2].type.?,
                        .ErrorReturn = if (return_info == .ErrorUnion)
                            return_info.ErrorUnion.error_set
                        else
                            null,
                    };
                }
            }
            return methods;
        }

        fn genericMethod(method: Method) fn (Service, Allocator, []const u8) Error![]const u8 {
            const function = @field(Service, method.name);
            return struct {
                pub fn generic(
                    service: Service,
                    allocator: Allocator,
                    input_string: []const u8,
                ) Error![]const u8 {
                    const input = try tryable(deserializeInputFn(method.Input, allocator, input_string));

                    const output = try tryable(function(service, allocator, input));

                    return try tryable(serializeOutputFn(allocator, output));
                }
            }.generic;
        }

        pub fn call(
            self: Self,
            allocator: Allocator,
            method_name: []const u8,
            request_json: []const u8,
        ) Error![]const u8 {
            const method = self.methods.get(method_name) orelse return error.UnsupportedMethod;
            return try method(self.service, allocator, request_json);
        }
    };
}

pub const RpcService = struct {
    const m = rpc.methods;
    const Self = @This();

    pub fn getBlockCommitment(
        self: *Self,
        allocator: Allocator,
        request: m.GetBlockCommitment,
    ) !m.GetBlockCommitment.Response {
        _ = allocator; // autofix
        _ = self; // autofix
        _ = request; // autofix
    }
};
