const std = @import("std");
const xev = @import("xev");

/// Generic in-process WebSocket server runner for e2e tests.
///
/// Responsibilities:
/// - Creates a dedicated `xev.ThreadPool` and `xev.Loop`.
/// - Initializes the server with caller-provided init options.
/// - Binds to an ephemeral port (via init options) and exposes it as `port`.
/// - Runs the server loop on a dedicated thread.
/// - Provides `stop()` to shutdown server + loop + thread pool.
///
/// The `ServerType` must provide:
/// - `pub fn init(allocator: Allocator, loop: *xev.Loop, opts: anytype) !ServerType`
/// - `pub fn deinit(self: *ServerType) void`
/// - `pub fn accept(self: *ServerType) void`
/// - `pub fn shutdown(self: *ServerType, timeout_ms: u32, Ctx: type, ctx: ?*Ctx, cb: anytype) void`
/// - field `listen_socket.fd`
pub fn ServerRunner(comptime ServerType: type) type {
    return struct {
        const ServerRunnerSelf = @This();

        loop: *xev.Loop,
        thread_pool: xev.ThreadPool,
        server: *ServerType,
        stop_notifier: xev.Async,
        stop_completion: xev.Completion,
        thread: std.Thread,
        allocator: std.mem.Allocator,
        port: u16,

        fn runLoop(loop: *xev.Loop) void {
            loop.run(.until_done) catch {};
        }

        pub fn start(allocator: std.mem.Allocator, config: ServerType.Config) !*ServerRunnerSelf {
            const self = try allocator.create(ServerRunnerSelf);
            errdefer allocator.destroy(self);

            self.allocator = allocator;

            self.thread_pool = xev.ThreadPool.init(.{});
            errdefer {
                self.thread_pool.shutdown();
                self.thread_pool.deinit();
            }

            self.loop = try allocator.create(xev.Loop);
            errdefer allocator.destroy(self.loop);
            self.loop.* = try xev.Loop.init(.{ .thread_pool = &self.thread_pool });
            errdefer self.loop.deinit();

            self.server = try allocator.create(ServerType);
            errdefer allocator.destroy(self.server);
            self.server.* = try ServerType.init(allocator, self.loop, config);
            errdefer self.server.deinit();

            self.port = getAssignedPortFromFd(self.server.listen_socket.fd);

            self.stop_notifier = try xev.Async.init();
            errdefer self.stop_notifier.deinit();
            self.stop_completion = .{};
            self.stop_notifier.wait(
                self.loop,
                &self.stop_completion,
                ServerRunnerSelf,
                self,
                stopCallback,
            );

            self.server.accept();
            self.thread = try std.Thread.spawn(.{}, runLoop, .{self.loop});
            return self;
        }

        fn stopCallback(
            self_opt: ?*ServerRunnerSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.Async.WaitError!void,
        ) xev.CallbackAction {
            if (self_opt) |self| {
                self.server.shutdown(5000, ServerRunnerSelf, self, onShutdownComplete);
            }
            return .disarm;
        }

        fn onShutdownComplete(self_opt: ?*ServerRunnerSelf, _: ServerType.ShutdownResult) void {
            if (self_opt) |self| {
                self.loop.stop();
            }
        }

        pub fn stop(self: *ServerRunnerSelf) void {
            self.stop_notifier.notify() catch {};
            self.thread.join();

            self.server.deinit();
            self.stop_notifier.deinit();
            self.loop.deinit();
            self.thread_pool.shutdown();
            self.thread_pool.deinit();

            self.allocator.destroy(self.server);
            self.allocator.destroy(self.loop);
            self.allocator.destroy(self);
        }
    };
}

pub fn getAssignedPortFromFd(fd: std.posix.fd_t) u16 {
    var addr: std.posix.sockaddr.storage = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr));
    std.posix.getsockname(fd, @ptrCast(&addr), &addr_len) catch return 0;
    const sa4: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
    return std.mem.bigToNative(u16, sa4.port);
}
