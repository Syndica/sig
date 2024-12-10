const std = @import("std");
const sig = @import("../sig.zig");

const SnapshotGenerationInfo = sig.accounts_db.AccountsDB.SnapshotGenerationInfo;
const FullSnapshotFileInfo = sig.accounts_db.snapshots.FullSnapshotFileInfo;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo;
const ThreadPool = sig.sync.ThreadPool;

const logger_scope = "rpc.Server";
const ScopedLogger = sig.trace.log.ScopedLogger(logger_scope);

pub const Server = struct {
    //! Basic usage:
    //! ```zig
    //! var server = try Server.init(.{...});
    //! defer server.joinDeinit();
    //!
    //! try server.serveSpawnDetached(); // or `.serveDirect`, if the caller can block or is managing the separate thread themselves.
    //! ```

    allocator: std.mem.Allocator,
    logger: ScopedLogger,

    snapshot_dir: std.fs.Dir,
    latest_snapshot_gen_info: *sig.sync.RwMux(?SnapshotGenerationInfo),

    /// Wait group for all currently running tasks, used to wait for
    /// all of them to finish before deinitializing.
    wait_group: std.Thread.WaitGroup,
    thread_pool: *ThreadPool,

    /// Must not be mutated.
    read_buffer_size: usize,
    tcp: std.net.Server,

    pub const MIN_READ_BUFFER_SIZE = 256;

    pub const InitError = std.net.Address.ListenError;

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

        thread_pool: *ThreadPool,

        /// The size for the read buffer allocated to every request.
        /// Clamped to be greater than or equal to `MIN_READ_BUFFER_SIZE`.
        read_buffer_size: u32,
        /// The socket address to listen on for incoming HTTP and/or RPC requests.
        socket_addr: std.net.Address,
    }) InitError!Server {
        var tcp_server = try params.socket_addr.listen(.{
            // NOTE: ideally we would be doing this nonblockingly, however this doesn't work properly on mac,
            // so for testing purposes we can't teste the `serve` functionality directly.
            .force_nonblocking = false,
        });
        errdefer tcp_server.deinit();

        return .{
            .allocator = params.allocator,
            .logger = params.logger.withScope(logger_scope),

            .snapshot_dir = params.snapshot_dir,
            .latest_snapshot_gen_info = params.latest_snapshot_gen_info,

            .wait_group = .{},
            .thread_pool = params.thread_pool,

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
            try server.acceptAndServeConnection();
        }
    }

    pub const AcceptAndServeConnectionError =
        std.mem.Allocator.Error ||
        std.http.Server.ReceiveHeadError ||
        AcceptConnectionError;

    pub fn acceptAndServeConnection(server: *Server) AcceptAndServeConnectionError!void {
        const conn = (try acceptConnection(&server.tcp, server.logger)).?;
        errdefer conn.stream.close();

        server.wait_group.start();
        errdefer server.wait_group.finish();

        const new_hct = try HandleConnectionTask.createAndReceiveHead(server, conn);
        errdefer new_hct.destroyAndClose();

        server.thread_pool.schedule(ThreadPool.Batch.from(&new_hct.task));
    }
};

const HandleConnectionTask = struct {
    task: ThreadPool.Task,
    server: *Server,
    http_server: std.http.Server,
    request: std.http.Server.Request,

    fn createAndReceiveHead(
        server: *Server,
        conn: std.net.Server.Connection,
    ) (std.http.Server.ReceiveHeadError || std.mem.Allocator.Error)!*HandleConnectionTask {
        const allocator = server.allocator;

        const hct_buf_align = @alignOf(HandleConnectionTask);
        const hct_buf_size = initBufferSize(server.read_buffer_size);

        const hct_buffer = try allocator.alignedAlloc(u8, hct_buf_align, hct_buf_size);
        errdefer server.allocator.free(hct_buffer);

        const hct: *HandleConnectionTask = std.mem.bytesAsValue(
            HandleConnectionTask,
            hct_buffer[0..@sizeOf(HandleConnectionTask)],
        );
        hct.* = .{
            .task = .{ .callback = callback },
            .server = server,
            .http_server = std.http.Server.init(conn, getReadBuffer(server.read_buffer_size, hct)),
            .request = try hct.http_server.receiveHead(),
        };

        return hct;
    }

    /// Does not release the connection.
    fn destroyAndClose(hct: *HandleConnectionTask) void {
        const allocator = hct.server.allocator;

        const full_buffer = getFullBuffer(hct.server.read_buffer_size, hct);
        defer allocator.free(full_buffer);

        const connection = hct.http_server.connection;
        defer connection.stream.close();
    }

    fn initBufferSize(read_buffer_size: usize) usize {
        return @sizeOf(HandleConnectionTask) + read_buffer_size;
    }

    fn getFullBuffer(
        read_buffer_size: usize,
        hct: *HandleConnectionTask,
    ) []align(@alignOf(HandleConnectionTask)) u8 {
        const ptr: [*]align(@alignOf(HandleConnectionTask)) u8 = @ptrCast(hct);
        return ptr[0..initBufferSize(read_buffer_size)];
    }

    fn getReadBuffer(
        read_buffer_size: usize,
        hct: *HandleConnectionTask,
    ) []u8 {
        return getFullBuffer(read_buffer_size, hct)[@sizeOf(HandleConnectionTask)..];
    }

    fn callback(task: *ThreadPool.Task) void {
        const hct: *HandleConnectionTask = @fieldParentPtr("task", task);
        defer hct.destroyAndClose();

        const server = hct.server;
        const logger = server.logger;

        const wait_group = &server.wait_group;
        defer wait_group.finish();

        handleRequest(
            logger,
            &hct.request,
            server.snapshot_dir,
            server.latest_snapshot_gen_info,
        ) catch |err| {
            if (@errorReturnTrace()) |stack_trace| {
                logger.err().logf("{s}\n{}", .{ @errorName(err), stack_trace });
            } else {
                logger.err().logf("{s}", .{@errorName(err)});
            }
        };
    }
};

fn handleRequest(
    logger: ScopedLogger,
    request: *std.http.Server.Request,
    snapshot_dir: std.fs.Dir,
    latest_snapshot_gen_info_rw: *sig.sync.RwMux(?SnapshotGenerationInfo),
) !void {
    const conn_address = request.server.connection.address;

    logger.info().logf("Responding to request from {}: {} {s}", .{
        conn_address, methodFmt(request.head.method), request.head.target,
    });
    switch (request.head.method) {
        .POST => {
            logger.err().logf("{} tried to invoke our RPC", .{conn_address});
            return try request.respond("RPCs are not yet implemented", .{
                .status = .service_unavailable,
                .keep_alive = false,
            });
        },
        .GET => get_blk: {
            if (!std.mem.startsWith(u8, request.head.target, "/")) break :get_blk;
            const path = request.head.target[1..];

            // we hold the lock for the entirety of this process in order to prevent
            // the snapshot generation process from deleting the associated snapshot.
            const maybe_latest_snapshot_gen_info, //
            var latest_snapshot_info_lg //
            = latest_snapshot_gen_info_rw.readWithLock();
            defer latest_snapshot_info_lg.unlock();

            const full_info: ?FullSnapshotFileInfo, //
            const inc_info: ?IncrementalSnapshotFileInfo //
            = blk: {
                const latest_snapshot_gen_info = maybe_latest_snapshot_gen_info.* orelse
                    break :blk .{ null, null };
                const latest_full = latest_snapshot_gen_info.full;
                const full_info: FullSnapshotFileInfo = .{
                    .slot = latest_full.slot,
                    .hash = latest_full.hash,
                };
                const latest_incremental = latest_snapshot_gen_info.inc orelse
                    break :blk .{ full_info, null };
                const inc_info: IncrementalSnapshotFileInfo = .{
                    .base_slot = latest_full.slot,
                    .slot = latest_incremental.slot,
                    .hash = latest_incremental.hash,
                };
                break :blk .{ full_info, inc_info };
            };

            logger.debug().logf("Available full: {?s}", .{
                if (full_info) |info| info.snapshotNameStr().constSlice() else null,
            });
            logger.debug().logf("Available inc: {?s}", .{
                if (inc_info) |info| info.snapshotNameStr().constSlice() else null,
            });

            if (full_info) |full| {
                const full_archive_name_bounded = full.snapshotNameStr();
                const full_archive_name = full_archive_name_bounded.constSlice();
                if (std.mem.eql(u8, path, full_archive_name)) {
                    const archive_file = try snapshot_dir.openFile(full_archive_name, .{});
                    defer archive_file.close();
                    var send_buffer: [4096]u8 = undefined;
                    try httpResponseSendFile(request, archive_file, &send_buffer);
                    return;
                }
            }

            if (inc_info) |inc| {
                const inc_archive_name_bounded = inc.snapshotNameStr();
                const inc_archive_name = inc_archive_name_bounded.constSlice();
                if (std.mem.eql(u8, path, inc_archive_name)) {
                    const archive_file = try snapshot_dir.openFile(inc_archive_name, .{});
                    defer archive_file.close();
                    var send_buffer: [4096]u8 = undefined;
                    try httpResponseSendFile(request, archive_file, &send_buffer);
                    return;
                }
            }
        },
        else => {},
    }

    logger.err().logf(
        "{} made an unrecognized request '{} {s}'",
        .{ conn_address, methodFmt(request.head.method), request.head.target },
    );
    try request.respond("", .{
        .status = .not_found,
        .keep_alive = false,
    });
}

fn httpResponseSendFile(
    request: *std.http.Server.Request,
    archive_file: std.fs.File,
    send_buffer: []u8,
) !void {
    const archive_len = try archive_file.getEndPos();

    var response = request.respondStreaming(.{
        .send_buffer = send_buffer,
        .content_length = archive_len,
    });
    const writer = sig.utils.io.narrowAnyWriter(
        response.writer(),
        std.http.Server.Response.WriteError,
    );

    const Fifo = std.fifo.LinearFifo(u8, .{ .Static = 1 });
    var fifo: Fifo = Fifo.init();
    try archive_file.seekTo(0);
    try fifo.pump(archive_file.reader(), writer);

    try response.end();
}

const AcceptConnectionError = error{
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    ProtocolFailure,
    BlockedByFirewall,
    NetworkSubsystemFailed,
} || std.posix.UnexpectedError;

fn acceptConnection(
    tcp_server: *std.net.Server,
    logger: ScopedLogger,
) AcceptConnectionError!?std.net.Server.Connection {
    const conn = tcp_server.accept() catch |err| switch (err) {
        error.Unexpected,
        => |e| return e,

        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SystemResources,
        error.ProtocolFailure,
        error.BlockedByFirewall,
        error.NetworkSubsystemFailed,
        => |e| return e,

        error.FileDescriptorNotASocket,
        error.SocketNotListening,
        error.OperationNotSupported,
        => unreachable, // Improperly initialized server.

        error.WouldBlock,
        => return null,

        error.ConnectionResetByPeer,
        error.ConnectionAborted,
        => |e| {
            logger.warn().logf("{}", .{e});
            return null;
        },
    };

    return conn;
}

fn methodFmt(method: std.http.Method) MethodFmt {
    return .{ .method = method };
}

const MethodFmt = struct {
    method: std.http.Method,
    pub fn format(
        fmt: MethodFmt,
        comptime fmt_str: []const u8,
        fmt_options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = fmt_options;
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, fmt);
        try fmt.method.write(writer);
    }
};

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

    const full_snap_name_bounded = snap_files.full_snapshot.snapshotNameStr();
    const maybe_inc_snap_name_bounded = if (snap_files.incremental_snapshot) |inc|
        inc.snapshotNameStr()
    else
        null;

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

    const AllSnapshotFields = sig.accounts_db.snapshots.AllSnapshotFields;
    var all_snap_fields = try AllSnapshotFields.fromFiles(
        allocator,
        logger,
        snap_dir,
        snap_files,
    );
    defer all_snap_fields.deinit(allocator);

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
    _ = try accountsdb.loadWithDefaults(allocator, &all_snap_fields, 1, true, 300, false, false);

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
        .thread_pool = &thread_pool,
        .socket_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, rpc_port),
        .read_buffer_size = 4096,
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

    const serve_thread = try std.Thread.spawn(.{}, Server.acceptAndServeConnection, .{rpc_server});
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
