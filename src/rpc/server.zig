const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const connection = @import("server/connection.zig");
const requests = @import("server/requests.zig");

const IoUring = std.os.linux.IoUring;

const SnapshotGenerationInfo = sig.accounts_db.AccountsDB.SnapshotGenerationInfo;
const FullSnapshotFileInfo = sig.accounts_db.snapshots.FullSnapshotFileInfo;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo;
const ThreadPool = sig.sync.ThreadPool;

pub const Server = struct {
    //! Basic usage:
    //! ```zig
    //! var server = try Server.init(.{...});
    //! defer server.joinDeinit();
    //!
    //! try server.serve(); // or `.serveSpawn` to spawn a thread and return its handle.
    //! ```

    allocator: std.mem.Allocator,
    logger: ScopedLogger,

    snapshot_dir: std.fs.Dir,
    latest_snapshot_gen_info: *sig.sync.RwMux(?SnapshotGenerationInfo),

    /// Wait group for all currently running tasks, used to wait for
    /// all of them to finish before deinitializing.
    wait_group: std.Thread.WaitGroup,
    work_pool: WorkPool,

    tcp: std.net.Server,
    /// Must not be mutated.
    read_buffer_size: usize,

    pub const LOGGER_SCOPE = "rpc.Server";
    pub const ScopedLogger = sig.trace.log.ScopedLogger(LOGGER_SCOPE);

    pub const MIN_READ_BUFFER_SIZE = 4096;

    pub const InitError =
        std.net.Address.ListenError ||
        std.posix.MMapError ||
        std.posix.UnexpectedError ||
        WorkPool.LinuxIoUring.InitError ||
        WorkPool.LinuxIoUring.EnterError ||
        error{
        SubmissionQueueFull,
        FailedToAcceptMultishot,
    };

    /// The returned result must be pinned to a memory location before calling any methods.
    pub fn init(params: struct {
        /// Must be a thread-safe allocator.
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,

        /// Not closed by the `Server`, but must live at least as long as it.
        snapshot_dir: std.fs.Dir,
        /// Should reflect the latest generated snapshot eligible for propagation at any
        /// given time with respect to the contents of the specified `snapshot_dir`.
        latest_snapshot_gen_info: *sig.sync.RwMux(?SnapshotGenerationInfo),

        /// The size for the read buffer allocated to every request.
        /// Clamped to be greater than or equal to `MIN_READ_BUFFER_SIZE`.
        read_buffer_size: u32,
        /// The socket address to listen on for incoming HTTP and/or RPC requests.
        socket_addr: std.net.Address,

        /// Set to true to disable taking advantage of native work pool strategies (ie io_uring).
        force_basic_work_pool: bool = false,
    }) InitError!Server {
        var tcp_server = try params.socket_addr.listen(.{
            // NOTE: ideally we would be doing this nonblockingly, however this doesn't work properly on mac,
            // so for testing purposes we can't test the `serve` functionality directly.
            .force_nonblocking = false,
        });
        errdefer tcp_server.deinit();

        var work_pool: WorkPool = if (params.force_basic_work_pool)
            .basic
        else switch (WorkPool.LinuxIoUring.can_use) {
            .no => .basic,
            .yes, .check => |can_use| blk: {
                var io_uring = IoUring.init(32, 0) catch |err| return switch (err) {
                    error.SystemOutdated,
                    error.PermissionDenied,
                    => |e| switch (can_use) {
                        .yes => e,
                        .check => break :blk .basic,
                        .no => comptime unreachable,
                    },
                    else => |e| e,
                };
                errdefer io_uring.deinit();

                _ = try io_uring.accept_multishot(
                    @bitCast(WorkPool.LinuxIoUring.Entry.ACCEPT),
                    tcp_server.stream.handle,
                    null,
                    null,
                    std.os.linux.SOCK.CLOEXEC,
                );
                if (try io_uring.submit() != 1) {
                    return error.FailedToAcceptMultishot;
                }

                break :blk .{ .linux_io_uring = .{ .io_uring = io_uring } };
            },
        };
        errdefer work_pool.deinit();

        return .{
            .allocator = params.allocator,
            .logger = params.logger.withScope(LOGGER_SCOPE),

            .snapshot_dir = params.snapshot_dir,
            .latest_snapshot_gen_info = params.latest_snapshot_gen_info,

            .wait_group = .{},
            .work_pool = work_pool,

            .read_buffer_size = @max(params.read_buffer_size, MIN_READ_BUFFER_SIZE),
            .tcp = tcp_server,
        };
    }

    /// Blocks until all tasks are completed, and then closes the server.
    /// Does not force the server to exit.
    pub fn joinDeinit(server: *Server) void {
        server.wait_group.wait();
        server.tcp.deinit();
    }

    /// Spawn the serve loop as a separate thread.
    pub fn serveSpawn(
        server: *Server,
        exit: *std.atomic.Value(bool),
    ) std.Thread.SpawnError!std.Thread {
        return std.Thread.spawn(.{}, serve, .{ server, exit });
    }

    /// Calls `acceptAndServeConnection` in a loop until `exit.load(.acquire)`.
    pub fn serve(
        server: *Server,
        exit: *std.atomic.Value(bool),
    ) AcceptAndServeConnectionError!void {
        while (!exit.load(.acquire)) {
            try server.acceptAndServeConnection(.{});
        }
    }

    pub const AcceptAndServeConnectionError =
        std.mem.Allocator.Error ||
        std.http.Server.ReceiveHeadError ||
        WorkPool.LinuxIoUring.EnterError ||
        WorkPool.LinuxIoUring.AcceptAndServeConnectionsError ||
        AcceptHandledError ||
        requests.HandleRequestError;

    pub fn acceptAndServeConnection(
        server: *Server,
        options: struct {
            /// The maximum number of connections to handle during this call.
            max_connections_to_handle: u8 = std.math.maxInt(u8),
        },
    ) AcceptAndServeConnectionError!void {
        switch (server.work_pool) {
            .basic => {
                const conn = try acceptHandled(&server.tcp);
                defer conn.stream.close();

                server.wait_group.start();
                defer server.wait_group.finish();

                const buffer = try server.allocator.alloc(u8, server.read_buffer_size);
                defer server.allocator.free(buffer);

                var http_server = std.http.Server.init(conn, buffer);
                var request = try http_server.receiveHead();

                try requests.handleRequest(
                    server.logger,
                    &request,
                    server.snapshot_dir,
                    server.latest_snapshot_gen_info,
                );
            },
            .linux_io_uring => |*linux| {
                try linux.acceptAndServeConnections(server, options.max_connections_to_handle);
            },
        }
    }
};

pub const WorkPool = union(enum) {
    basic,
    linux_io_uring: switch (LinuxIoUring.can_use) {
        .yes, .check => LinuxIoUring,
        .no => noreturn,
    },

    const LinuxIoUring = @import("server/LinuxIoUring.zig");

    pub fn deinit(wp: *WorkPool) void {
        switch (wp.*) {
            .basic => {},
            .linux_io_uring => |*linux| linux.deinit(),
        }
    }
};

const AcceptHandledError = connection.HandleAcceptError || error{ConnectionAborted};
fn acceptHandled(
    tcp_server: *std.net.Server,
) AcceptHandledError!std.net.Server.Connection {
    while (true) {
        var addr: std.net.Address = .{ .any = undefined };
        var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr.any));
        const rc = if (!builtin.target.isDarwin()) std.posix.system.accept4(
            tcp_server.stream.handle,
            &addr.any,
            &addr_len,
            std.posix.SOCK.CLOEXEC,
        ) else std.posix.system.accept(
            tcp_server.stream.handle,
            &addr.any,
            &addr_len,
        );

        return switch (try connection.handleAcceptResult(std.posix.errno(rc))) {
            .intr => continue,
            .conn_aborted => return error.ConnectionAborted,
            .again => std.debug.panic("We're not using nonblock, but encountered EAGAIN.", .{}),
            .success => return .{
                .stream = .{ .handle = rc },
                .address = addr,
            },
        };
    }
}

test Server {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // const logger: sig.trace.Logger = .{ .direct_print = .{ .max_level = .trace } };
    const logger: sig.trace.Logger = .noop;

    var test_data_dir = try std.fs.cwd().openDir("data/test-data", .{ .iterate = true });
    defer test_data_dir.close();

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    var snap_dir = try tmp_dir.makeOpenPath("snapshot", .{ .iterate = true });
    defer snap_dir.close();

    const SnapshotFiles = sig.accounts_db.snapshots.SnapshotFiles;
    const snap_files = try SnapshotFiles.find(allocator, test_data_dir);

    const full_snap_name_bounded = snap_files.full.snapshotArchiveName();
    const maybe_inc_snap_name_bounded =
        if (snap_files.incremental()) |inc| inc.snapshotArchiveName() else null;

    {
        const full_snap_name = full_snap_name_bounded.constSlice();

        try test_data_dir.copyFile(full_snap_name, snap_dir, full_snap_name, .{});
        const full_snap_file = try snap_dir.openFile(full_snap_name, .{});
        defer full_snap_file.close();

        const unpack = sig.accounts_db.snapshots.parallelUnpackZstdTarBall;
        try unpack(allocator, logger, full_snap_file, snap_dir, 1, true);
    }

    if (maybe_inc_snap_name_bounded) |inc_snap_name_bounded| {
        const inc_snap_name = inc_snap_name_bounded.constSlice();

        try test_data_dir.copyFile(inc_snap_name, snap_dir, inc_snap_name, .{});
        const inc_snap_file = try snap_dir.openFile(inc_snap_name, .{});
        defer inc_snap_file.close();

        const unpack = sig.accounts_db.snapshots.parallelUnpackZstdTarBall;
        try unpack(allocator, logger, inc_snap_file, snap_dir, 1, false);
    }

    var accountsdb = try sig.accounts_db.AccountsDB.init(.{
        .allocator = allocator,
        .logger = logger,
        .snapshot_dir = snap_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 4,
        .lru_size = null,
    });
    defer accountsdb.deinit();

    {
        const FullAndIncrementalManifest = sig.accounts_db.snapshots.FullAndIncrementalManifest;
        const all_snap_fields = try FullAndIncrementalManifest.fromFiles(
            allocator,
            logger,
            snap_dir,
            snap_files,
        );
        defer all_snap_fields.deinit(allocator);

        (try accountsdb.loadWithDefaults(
            allocator,
            all_snap_fields,
            1,
            true,
            300,
            false,
            false,
        )).deinit(allocator);
    }

    var thread_pool = sig.sync.ThreadPool.init(.{ .max_threads = 1 });
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

    const rpc_port = random.intRangeLessThan(u16, 8_000, 10_000);
    var rpc_server = try Server.init(.{
        .allocator = allocator,
        .logger = logger,
        .snapshot_dir = snap_dir,
        .latest_snapshot_gen_info = &accountsdb.latest_snapshot_gen_info,
        .socket_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, rpc_port),
        .read_buffer_size = 4096,
        .force_basic_work_pool = false,
    });
    defer rpc_server.joinDeinit();

    try testExpectSnapshotResponse(
        allocator,
        &rpc_server,
        &full_snap_name_bounded,
        snap_dir,
    );

    if (maybe_inc_snap_name_bounded) |inc_snap_name_bounded| {
        try testExpectSnapshotResponse(
            allocator,
            &rpc_server,
            &inc_snap_name_bounded,
            snap_dir,
        );
    }
}

fn testExpectSnapshotResponse(
    allocator: std.mem.Allocator,
    rpc_server: *Server,
    snap_name_bounded: anytype,
    snap_dir: std.fs.Dir,
) !void {
    const rpc_port = rpc_server.tcp.listen_address.getPort();
    const snap_url_str_bounded = sig.utils.fmt.boundedFmt(
        "http://localhost:{d}/{s}",
        .{ rpc_port, sig.utils.fmt.boundedString(snap_name_bounded) },
    );
    const snap_url = try std.Uri.parse(snap_url_str_bounded.constSlice());

    const serve_thread = try std.Thread.spawn(.{}, Server.acceptAndServeConnection, .{ rpc_server, .{} });
    const actual_data = try testDownloadSelfSnapshot(allocator, snap_url);
    defer allocator.free(actual_data);
    serve_thread.join();

    const snap_name = snap_name_bounded.constSlice();

    const expected_data = try snap_dir.readFileAlloc(allocator, snap_name, 1 << 32);
    defer allocator.free(expected_data);

    try std.testing.expectEqualSlices(u8, expected_data, actual_data);
}

fn testDownloadSelfSnapshot(
    allocator: std.mem.Allocator,
    snap_url: std.Uri,
) ![]const u8 {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var server_header_buffer: [4096 * 16]u8 = undefined;
    var request = try client.open(.GET, snap_url, .{
        .server_header_buffer = &server_header_buffer,
    });
    defer request.deinit();

    try request.send();
    try request.finish();
    try request.wait();

    const content_len = request.response.content_length.?;
    const reader = request.reader();

    const response_content = try reader.readAllAlloc(allocator, 1 << 32);
    errdefer allocator.free(response_content);

    try std.testing.expectEqual(content_len, response_content.len);

    return response_content;
}
