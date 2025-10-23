const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const Allocator = std.mem.Allocator;

pub const Hooks = struct {
    map: std.EnumMap(Method, VTable),

    const VTable = struct {
        ptr: *anyopaque,
        callback: *const anyopaque,
        free: *const fn (Allocator, *anyopaque) void,
    };

    pub const Request = rpc.methods.MethodAndParams;
    pub const Method = @typeInfo(Request).@"enum".tag_type;

    fn ArgsType(comptime method: Method) type {
        const value = @unionInit(Request, @tagName(method), undefined);
        return switch (@TypeOf(@field(value, @tagName(method)))) {
            noreturn => @compileError("TODO: define " ++ @tagName(method) ++ " in methods.zig"),
            else => |T| T.Response, 
        };
    }

    fn ReturnType(comptime method: Method) type {
        const value = @unionInit(Request, @tagName(method), undefined);
        return switch (@TypeOf(@field(value, @tagName(method)))) {
            noreturn => noreturn,
            else => |T| T.Response, 
        };
    }

    pub fn deinit(self: Hooks, allocator: Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            entry.value.free(allocator, entry.value.ptr);
        }
    }

    pub fn set(
        self: *Hooks,
        allocator: std.mem.Allocator,
        comptime method: Method,
        context: anytype,
        comptime callback: anytype,
    ) !void {
        const Context = @TypeOf(context);
        const ctx_ptr = try allocator.create(Context);
        ctx_ptr.* = context;

        self.map.put(method, .{
            .ptr = ctx_ptr,
            .callback = &(struct {
                fn wrapper(
                    alloc: Allocator,
                    ctx: *anyopaque,
                    args: ArgsType(method),
                ) anyerror!ReturnType(method) {
                    const ptr: *Context = @ptrCast(@alignCast(ctx));
                    return @call(.auto, callback, .{ptr.*, alloc, args});
                }
            }.wrapper),
            .free = &(struct {
                fn freeContext(alloc: Allocator, ctx: *anyopaque) void {
                    const ptr: *Context = @ptrCast(@alignCast(ctx));
                    alloc.destroy(ptr);
                }
            }.freeContext),
        });
    }

    pub fn call(
        self: *const Hooks,
        allocator: std.mem.Allocator,
        comptime method: Method,
        args: ArgsType(method),
    ) !ReturnType(method) {
        const vtable = self.map.get(method) orelse return error.MethodNotImplemented;
        const wrapper: *const fn (
            Allocator,
            *anyopaque,
            ArgsType(method),
        ) anyerror!ReturnType(method) = @ptrCast(@alignCast(vtable.callback));
        return wrapper(allocator, vtable.ptr, args);
    }
};