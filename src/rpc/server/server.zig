//! RPC Server implementation.
//!
//! This file defines and exposes the relevant public API for
//! the RPC Server, as well as the internal API for backends
//! and any other internal code.

const std = @import("std");
const sig = @import("../../sig.zig");

pub const connection = @import("connection.zig");
pub const requests = @import("requests.zig");

pub const basic = @import("basic.zig");
pub const LinuxIoUring = @import("linux_io_uring.zig").LinuxIoUring;

comptime {
    _ = connection;
    _ = requests;

    _ = basic;
    _ = LinuxIoUring;
}

/// The minimum buffer read size.
pub const MIN_READ_BUFFER_SIZE = 4096;

const LOGGER_SCOPE = "rpc.server";

/// The work pool is a tagged union, representing one of various possible backends.
/// It acts merely as a reference to a specific backend's state, or a tag for stateless
/// backends.
pub const WorkPool = union(enum) {
    basic,
    linux_io_uring: if (LinuxIoUring.can_use) *LinuxIoUring else noreturn,
};

/// The basic state required for the server to operate.
pub const Context = struct {
    allocator: std.mem.Allocator,
    logger: sig.trace.log.ScopedLogger(LOGGER_SCOPE),
    accountsdb: *sig.accounts_db.AccountsDB,

    /// Wait group for all currently running tasks, used to wait for
    /// all of them to finish before deinitializing.
    wait_group: std.Thread.WaitGroup,
    tcp: std.net.Server,
    /// Must not be mutated.
    read_buffer_size: u32,

    /// The returned result must be pinned to a memory location before calling any methods.
    pub fn init(params: struct {
        /// Must be a thread-safe allocator.
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        accountsdb: *sig.accounts_db.AccountsDB,

        /// The size for the read buffer allocated to every request.
        /// Clamped to be greater than or equal to `MIN_READ_BUFFER_SIZE`.
        read_buffer_size: u32,
        /// The socket address to listen on for incoming HTTP and/or RPC requests.
        socket_addr: std.net.Address,
        /// See `@FieldType(std.net.Address.ListenOptions, "reuse_address")`.
        reuse_address: bool = false,
    }) std.net.Address.ListenError!Context {
        var tcp_server = try params.socket_addr.listen(.{
            .force_nonblocking = true,
            .reuse_address = params.reuse_address,
        });
        errdefer tcp_server.deinit();

        return .{
            .allocator = params.allocator,
            .logger = params.logger.withScope(LOGGER_SCOPE),
            .accountsdb = params.accountsdb,

            .wait_group = .{},
            .read_buffer_size = @max(params.read_buffer_size, MIN_READ_BUFFER_SIZE),
            .tcp = tcp_server,
        };
    }

    /// Blocks until all tasks are completed, and then closes the server context.
    /// Does not force the server to exit.
    pub fn joinDeinit(self: *Context) void {
        self.wait_group.wait();
        self.tcp.deinit();
    }
};

/// Spawn `serve` as a separate thread.
pub fn serveSpawn(
    exit: *std.atomic.Value(bool),
    ctx: *Context,
    work_pool: WorkPool,
) std.Thread.SpawnError!std.Thread {
    return try std.Thread.spawn(.{}, serve, .{ exit, ctx, work_pool });
}

pub const ServeError =
    basic.AcceptAndServeConnectionError ||
    LinuxIoUring.AcceptAndServeConnectionsError;

/// Until `exit.load(.acquire)`, accepts and serves connections in a loop.
pub fn serve(
    /// The exit condition.
    exit: *std.atomic.Value(bool),
    /// The context to operate with.
    ctx: *Context,
    /// The pool to dispatch work to.
    work_pool: WorkPool,
) ServeError!void {
    while (!exit.load(.acquire)) {
        switch (work_pool) {
            .basic => try basic.acceptAndServeConnection(ctx),
            .linux_io_uring => |linux| try linux.acceptAndServeConnections(ctx),
        }
    }
}

test "serveSpawn snapshots" {
    if (sig.build_options.no_network_tests) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // const logger_unscoped: sig.trace.Logger = .{ .direct_print = .{ .max_level = .trace } };
    const logger_unscoped: sig.trace.Logger = .noop;
    const logger = logger_unscoped.withScope(@src().fn_name);

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    // the directory into which the snapshots will be unpacked and copied to.
    var unpacked_snap_dir = try tmp_dir.makeOpenPath("snapshot", .{});
    defer unpacked_snap_dir.close();

    var accountsdb = try sig.accounts_db.AccountsDB.init(.{
        .allocator = allocator,
        .logger = logger.unscoped(),
        .snapshot_dir = unpacked_snap_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 1,
    });
    defer accountsdb.deinit();

    const snap_files = try sig.accounts_db.db.findAndUnpackTestSnapshots(
        std.Thread.getCpuCount() catch 1,
        unpacked_snap_dir,
    );

    {
        // the source from which `fundAndUnpackTestSnapshots` will unpack the snapshots.
        var test_data_dir = try std.fs.cwd().openDir(sig.TEST_DATA_DIR, .{ .iterate = true });
        defer test_data_dir.close();

        try test_data_dir.copyFile(
            snap_files.full.snapshotArchiveName().constSlice(),
            unpacked_snap_dir,
            snap_files.full.snapshotArchiveName().constSlice(),
            .{},
        );
        if (snap_files.incremental()) |incremental| {
            try test_data_dir.copyFile(
                incremental.snapshotArchiveName().constSlice(),
                unpacked_snap_dir,
                incremental.snapshotArchiveName().constSlice(),
                .{},
            );
        }

        const FullAndIncrementalManifest = sig.accounts_db.snapshots.FullAndIncrementalManifest;
        const full_inc_manifest = try FullAndIncrementalManifest.fromFiles(
            allocator,
            logger.unscoped(),
            unpacked_snap_dir,
            snap_files,
        );
        defer full_inc_manifest.deinit(allocator);

        const man = try accountsdb.loadFromSnapshotAndValidate(.{
            .allocator = allocator,
            .full_inc_manifest = full_inc_manifest,
            .n_threads = 1,
            .accounts_per_file_estimate = 1_500,
        });
        defer man.deinit(allocator);
    }

    const rpc_port = random.intRangeLessThan(u16, 8_000, 10_000);
    const sock_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, rpc_port);
    var server_ctx = try Context.init(.{
        .allocator = allocator,
        .logger = logger.unscoped(),
        .accountsdb = &accountsdb,
        .socket_addr = sock_addr,
        .read_buffer_size = 4096,
        .reuse_address = true,
    });
    defer server_ctx.joinDeinit();

    var maybe_liou = try LinuxIoUring.init(&server_ctx);
    defer if (maybe_liou) |*liou| liou.deinit();

    for ([_]?WorkPool{
        .basic,
        // TODO: see above TODO about `if (a) |*b|` on `?noreturn`.
        if (maybe_liou != null) .{ .linux_io_uring = &maybe_liou.? } else null,
    }) |maybe_work_pool| {
        const work_pool = maybe_work_pool orelse continue;
        logger.info().logf("Running with {s}", .{@tagName(work_pool)});

        var exit = std.atomic.Value(bool).init(false);
        const serve_thread = try serveSpawn(&exit, &server_ctx, work_pool);
        defer serve_thread.join();
        defer exit.store(true, .release);

        try testExpectSnapshotResponse(
            allocator,
            unpacked_snap_dir,
            server_ctx.tcp.listen_address.getPort(),
            .full,
            snap_files.full,
        );

        if (snap_files.incremental()) |inc| {
            try testExpectSnapshotResponse(
                allocator,
                unpacked_snap_dir,
                server_ctx.tcp.listen_address.getPort(),
                .incremental,
                inc,
            );
        }
    }
}

test "serveSpawn getAccountInfo" {
    if (sig.build_options.no_network_tests) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // const logger_unscoped: sig.trace.Logger = .{ .direct_print = .{ .max_level = .trace } };
    const logger_unscoped: sig.trace.Logger = .noop;
    const logger = logger_unscoped.withScope(@src().fn_name);

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    // the directory into which the snapshots will be unpacked.
    var unpacked_snap_dir = try tmp_dir.makeOpenPath("snapshot", .{});
    defer unpacked_snap_dir.close();

    var accountsdb = try sig.accounts_db.AccountsDB.init(.{
        .allocator = allocator,
        .logger = logger.unscoped(),
        .snapshot_dir = unpacked_snap_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 1,
    });
    defer accountsdb.deinit();

    const expected_account = try sig.core.Account.initRandom(
        allocator,
        random,
        random.uintLessThan(usize, 16),
    );
    defer expected_account.deinit(allocator);

    const expected_pubkey = sig.core.Pubkey.initRandom(random);
    const expected_slot: sig.core.Slot = 200;

    try accountsdb.account_index.expandRefCapacity(1);
    try accountsdb.putAccountSlice(
        &.{expected_account},
        &.{expected_pubkey},
        expected_slot,
    );

    const test_rpc_port = random.intRangeLessThan(u16, 8_000, 10_000);
    const test_sock_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, test_rpc_port);
    var server_ctx = try Context.init(.{
        .allocator = allocator,
        .logger = logger.unscoped(),
        .accountsdb = &accountsdb,
        .socket_addr = test_sock_addr,
        .read_buffer_size = 4096,
        .reuse_address = true,
    });
    defer server_ctx.joinDeinit();

    var maybe_liou = try LinuxIoUring.init(&server_ctx);
    defer if (maybe_liou) |*liou| liou.deinit();

    for ([_]?WorkPool{
        .basic,
        // TODO: see above TODO about `if (a) |*b|` on `?noreturn`.
        // if (maybe_liou != null) .{ .linux_io_uring = &maybe_liou.? } else null,
    }) |maybe_work_pool| {
        const work_pool = maybe_work_pool orelse continue;
        logger.info().logf("Running with {s}", .{@tagName(work_pool)});

        var exit = std.atomic.Value(bool).init(false);
        const serve_thread = try serveSpawn(&exit, &server_ctx, work_pool);
        defer serve_thread.join();
        defer exit.store(true, .release);

        const localhost_url_bounded = sig.utils.fmt.boundedFmt(
            "http://localhost:{d}/",
            .{server_ctx.tcp.listen_address.getPort()},
        );
        const localhost_url = try std.Uri.parse(localhost_url_bounded.constSlice());

        const request: sig.rpc.request.Request = .{
            .id = .null,
            .method = .{ .getAccountInfo = .{
                .pubkey = expected_pubkey,
                .config = .{
                    .encoding = .base64,
                },
            } },
        };
        const request_str = try std.json.stringifyAlloc(allocator, request, .{});
        defer allocator.free(request_str);

        const resp_str = try testHttpFetchSelf(allocator, .POST, localhost_url, .{
            .body = request_str,
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
        });
        defer allocator.free(resp_str);

        const Response = sig.rpc.methods.GetAccountInfo.Response;
        const resp_json = try sig.rpc.response.Response(Response).fromJson(allocator, resp_str);
        defer resp_json.deinit();

        const resp_value = try resp_json.result();
        try std.testing.expectEqual(expected_slot, resp_value.context.slot);
        try std.testing.expectEqualStrings("2.0.15", resp_value.context.apiVersion);

        const raw_data = try expected_account.data.readAllocate(
            allocator,
            0,
            expected_account.data.len(),
        );
        defer allocator.free(raw_data);

        const encoded_len = std.base64.standard.Encoder.calcSize(raw_data.len);
        const encoded_data_buf = try allocator.alloc(u8, encoded_len);
        defer allocator.free(encoded_data_buf);

        const expected_value: Response.Value = .{
            .data = .{ .encoded = .{
                std.base64.standard.Encoder.encode(encoded_data_buf, raw_data),
                .base64,
            } },
            .executable = expected_account.executable,
            .lamports = expected_account.lamports,
            .owner = expected_account.owner,
            .rentEpoch = expected_account.rent_epoch,
            .space = expected_account.data.len(),
        };
        try std.testing.expectEqualDeep(expected_value, resp_value.value);
    }
}

fn testExpectSnapshotResponse(
    allocator: std.mem.Allocator,
    snap_dir: std.fs.Dir,
    rpc_port: u16,
    comptime kind: enum { full, incremental },
    snap_info: switch (kind) {
        .full => sig.accounts_db.snapshots.FullSnapshotFileInfo,
        .incremental => sig.accounts_db.snapshots.IncrementalSnapshotFileInfo,
    },
) !void {
    const snap_name_bounded = snap_info.snapshotArchiveName();
    const snap_name = snap_name_bounded.constSlice();

    const expected_file = try snap_dir.openFile(snap_name, .{});
    defer expected_file.close();

    const expected_data: []align(std.heap.page_size_min) const u8 = try std.posix.mmap(
        null,
        try expected_file.getEndPos(),
        std.posix.PROT.READ,
        .{ .TYPE = .PRIVATE },
        expected_file.handle,
        0,
    );
    defer std.posix.munmap(expected_data);

    const snap_url_str_bounded = sig.utils.fmt.boundedFmt(
        "http://localhost:{d}/{s}",
        .{ rpc_port, sig.utils.fmt.boundedString(&snap_name_bounded) },
    );
    const snap_url = try std.Uri.parse(snap_url_str_bounded.constSlice());

    const actual_data = try testHttpFetchSelf(allocator, .GET, snap_url, .{});
    defer allocator.free(actual_data);

    try std.testing.expectEqualSlices(u8, expected_data, actual_data);
}

fn testHttpFetchSelf(
    allocator: std.mem.Allocator,
    http_method: std.http.Method,
    uri: std.Uri,
    opts: struct {
        headers: std.http.Client.Request.Headers = .{},
        extra_headers: []const std.http.Header = &.{},
        privileged_headers: []const std.http.Header = &.{},
        body: ?[]const u8 = null,
    },
) ![]const u8 {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var server_header_buffer: [4096 * 16]u8 = undefined;
    var request = try client.open(http_method, uri, .{
        .server_header_buffer = &server_header_buffer,
        .headers = opts.headers,
        .extra_headers = opts.extra_headers,
        .privileged_headers = opts.privileged_headers,
    });
    defer request.deinit();

    if (opts.body) |body| request.transfer_encoding = .{ .content_length = body.len };
    try request.send();
    if (opts.body) |body| try request.writer().writeAll(body);
    try request.finish();

    try request.wait();

    const reader = request.reader();

    const response_content = try reader.readAllAlloc(allocator, 1 << 32);
    errdefer allocator.free(response_content);

    if (request.response.content_length) |content_len| {
        try std.testing.expectEqual(content_len, response_content.len);
    }

    return response_content;
}
