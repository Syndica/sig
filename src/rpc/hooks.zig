const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

pub const Hooks = struct {
    map: std.EnumMap(Method, MethodImpl) = .{},

    pub const Request = rpc.methods.MethodAndParams;
    pub const Method = Request.Tag;

    const MethodImpl = struct {
        ctx_ref: *ContextRef,
        callback: *const anyopaque,
    };

    // The context for a MethodImpl's callback needs to:
    // 1) live past the self.set(), at least until future self.calls (allocated)
    // 2) not double-free during deinit(), given its shared by multiple impls (ref_count)
    const ContextRef = struct {
        ref_count: usize,
        free: *const fn (*ContextRef, std.mem.Allocator) void,

        fn Typed(comptime T: type) type {
            return struct {
                value: T,
                ctx_ref: ContextRef,
            };
        }

        fn init(allocator: std.mem.Allocator, value: anytype) !*Typed(@TypeOf(value)) {
            const TypedRef = Typed(@TypeOf(value));
            const typed = try allocator.create(TypedRef);
            typed.* = .{
                .value = value,
                .ctx_ref = .{
                    .ref_count = 1,
                    .free = &(struct {
                        fn free(ctx_ref: *ContextRef, _allocator: std.mem.Allocator) void {
                            const t: *TypedRef = @alignCast(@fieldParentPtr("ctx_ref", ctx_ref));
                            _allocator.destroy(t);
                        }
                    }.free),
                },
            };
            return typed;
        }

        fn inc(self: *ContextRef) *ContextRef {
            self.ref_count += 1;
            return self;
        }

        fn dec(self: *ContextRef, allocator: std.mem.Allocator) void {
            self.ref_count -= 1;
            if (self.ref_count == 0) self.free(self, allocator);
        }
    };

    pub fn deinit(self: Hooks, allocator: std.mem.Allocator) void {
        var it = self.map.bits.iterator(.{});
        while (it.next()) |i| {
            self.map.values[i].ctx_ref.dec(allocator);
        }
    }

    /// Takes in an instance of a struct, where the struct has RPC methods in the form of:
    /// `fn {methodName}(ContextStruct, Allocator, {MethodInstance}) !{MethodInstance}.Response`
    /// where {methodName} is a field in `Request` and `MethodInstance` is the field's value.
    ///
    /// The struct instance is not allowed to have other methods besides RPC methods, but it is
    /// allowed to have other fields to hold relevant context for them.
    ///
    /// set() takes this struct instance, creates a heap allocated copy internally, and registers it
    /// to be called on when the corresponding methods are invoked via `call()`. Panics if theres
    /// already an instance registered to one of the RPC methods.
    pub fn set(
        self: *Hooks,
        allocator: std.mem.Allocator,
        context: anytype,
    ) std.mem.Allocator.Error!void {
        const cref = try ContextRef.init(allocator, context);
        defer cref.ctx_ref.dec(allocator);

        const RealContext = @TypeOf(context);
        const Context = switch (@typeInfo(RealContext)) {
            .pointer => |ty| ty.child,
            else => RealContext,
        };
        inline for (comptime std.meta.declarations(Context)) |decl| {
            const method = if (@hasField(Method, decl.name))
                @field(Method, decl.name)
            else
                // @compileError("No RPC method named: " ++ decl.name);
                continue;

            const callback = @field(Context, decl.name);
            if (self.map.contains(method)) {
                std.debug.panic("RPC method {s} already registered", .{decl.name});
            }

            const CRef = @TypeOf(cref.*);
            self.map.put(method, .{
                .ctx_ref = cref.ctx_ref.inc(), // keeps the cref alive.
                .callback = &(struct {
                    fn impl(
                        _allocator: std.mem.Allocator,
                        ctx_ref: *ContextRef,
                        args: sig.rpc.methods.Request(method),
                    ) sig.rpc.methods.Result(method) {
                        const _cref: *CRef = @alignCast(@fieldParentPtr("ctx_ref", ctx_ref));
                        if (@call(.auto, callback, .{ _cref.value, _allocator, args })) |response| {
                            return .{ .ok = response };
                        } else |err| {
                            // JSON RPC spec reserves error codes at or below -32_000. So the
                            // unsigned ones returned by `@intFromError` should be fine to use.
                            // Solana RPC docs also don't dictate exactly what the error codes
                            // should be, allowing them to be implementation-defined. This then
                            // serves as a way to allow the callback to not worry about error codes
                            // or error messages, while also letting it use `try`, `errdefer`, and
                            // return the Result directly (instead of wrapping it in a union).
                            return .{ .err = .{
                                .code = @enumFromInt(@intFromError(err)),
                                .message = @errorName(err),
                            } };
                        }
                    }
                }.impl),
            });
        }
    }

    pub const CallError = error{MethodNotImplemented};

    /// NOTE: Remember to free the result with the given allocator
    pub fn call(
        self: *const Hooks,
        allocator: std.mem.Allocator,
        comptime method: Method,
        args: sig.rpc.methods.Request(method),
    ) CallError!sig.rpc.methods.Result(method) {
        const method_impl = self.map.get(method) orelse return error.MethodNotImplemented;
        const impl: *const fn (
            _allocator: std.mem.Allocator,
            ctx_ref: *ContextRef,
            args: sig.rpc.methods.Request(method),
        ) sig.rpc.methods.Result(method) = @ptrCast(@alignCast(method_impl.callback));
        return impl(allocator, method_impl.ctx_ref, args);
    }
};
