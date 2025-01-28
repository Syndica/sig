const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const server = @import("server.zig");
const requests = server.requests;
const connection = server.connection;

const IoUring = std.os.linux.IoUring;

pub const LinuxIoUring = struct {
    io_uring: IoUring,
    multishot_accept_submitted: bool,
    pending_cqes_count: u8,
    pending_cqes_buf: [255]std.os.linux.io_uring_cqe,

    pub const can_use: enum { no, yes, check } = switch (builtin.os.getVersionRange()) {
        .linux => |version| can_use: {
            const min_version: std.SemanticVersion = .{ .major = 6, .minor = 0, .patch = 0 };
            const is_at_least = version.isAtLeast(min_version) orelse break :can_use .check;
            break :can_use if (is_at_least) .yes else .no;
        },
        else => .no,
    };

    pub const InitError = std.posix.MMapError || error{
        EntriesZero,
        EntriesNotPowerOfTwo,

        ParamsOutsideAccessibleAddressSpace,
        ArgumentsInvalid,
        ProcessFdQuotaExceeded,
        SystemFdQuotaExceeded,
        SystemResources,

        PermissionDenied,
        SystemOutdated,
    };

    // NOTE(ink): constructing the return type as `E!?T`, where `E` and `T` are resolved
    // separately seems to help ZLS with understanding the types involved better, which is
    // why I've done it like that here. If ZLS gets smarter in the future, you could probably
    // inline this into a single branch in the return type expression.
    const InitErrOrEmpty = if (can_use == .no) error{} else InitError;
    const InitResultOrNoreturn = if (can_use == .no) noreturn else LinuxIoUring;
    pub fn init() InitErrOrEmpty!?InitResultOrNoreturn {
        const need_runtime_check = switch (can_use) {
            .no => return null,
            .yes => false,
            .check => true,
        };

        var io_uring = IoUring.init(4096, 0) catch |err| return switch (err) {
            error.SystemOutdated,
            error.PermissionDenied,
            => |e| if (!need_runtime_check) e else return null,
            else => |e| e,
        };
        errdefer io_uring.deinit();

        return .{
            .io_uring = io_uring,
            .multishot_accept_submitted = false,
            .pending_cqes_count = 0,
            .pending_cqes_buf = undefined,
        };
    }

    pub fn deinit(self: *LinuxIoUring) void {
        self.io_uring.deinit();
    }

    pub const AcceptAndServeConnectionsError =
        IouGetSqeError ||
        IouSubmitError ||
        ConsumeOurCqeError ||
        std.mem.Allocator.Error;

    pub fn acceptAndServeConnections(
        self: *LinuxIoUring,
        server_ctx: *server.Context,
    ) AcceptAndServeConnectionsError!void {
        if (!self.multishot_accept_submitted) {
            self.multishot_accept_submitted = true;
            errdefer self.multishot_accept_submitted = false;
            _ = self.io_uring.accept_multishot(
                @bitCast(Entry.ACCEPT),
                server_ctx.tcp.stream.handle,
                null,
                null,
                std.os.linux.SOCK.CLOEXEC,
            ) catch |err| return switch (err) {
                error.SubmissionQueueFull => |e| {
                    server_ctx.logger.err().log(
                        "Under normal circumstances the accept_multishot would be" ++
                            " the first SQE to be queued, but somehow the queue was full.",
                    );
                    return e;
                },
            };
        }

        _ = try self.io_uring.submit();

        if (self.pending_cqes_count != self.pending_cqes_buf.len) {
            const unused = self.pending_cqes_buf[self.pending_cqes_count..];
            const new_cqe_count = try self.io_uring.copy_cqes(unused, 0);
            self.pending_cqes_count += @intCast(new_cqe_count);
        }
        const cqes_pending = self.pending_cqes_buf[0..self.pending_cqes_count];

        for (cqes_pending, 0..) |raw_cqe, i| {
            self.pending_cqes_count -= 1;
            errdefer std.mem.copyForwards(
                std.os.linux.io_uring_cqe,
                self.pending_cqes_buf[0..self.pending_cqes_count],
                self.pending_cqes_buf[i + 1 ..][0..self.pending_cqes_count],
            );
            const our_cqe = OurCqe.fromCqe(raw_cqe);
            switch (try consumeOurCqe(self, server_ctx, our_cqe)) {
                .ok => {},
                .signal_interrupted_operation,
                .misc_connection_failure,
                .http_head_parse_error,
                .splice_error,
                => {},
            }
        }
    }
};

const ConsumeOurCqeResult = enum {
    ok,

    /// Operation resulted in EINTR. In general there doesn't seem to be a very good way to handle or recover from interruptions,
    /// so we just fail and drop whatever connection is interrupted; however in theory, this should not be a huge issue in practice,
    /// with the assumption being that the RPC server will not be running in a process/thread that will be interrupted often enough
    /// for this to be a problem.
    signal_interrupted_operation,

    /// Connection was aborted, refused, reset, or it timed out.
    misc_connection_failure,

    /// Failed to parse the HTTP request head, perhaps because it was too big,
    /// the request target was too long, or because it was invalid in some way.
    http_head_parse_error,

    /// Somehow the splice arguments or their associated state were invalid.
    splice_error,
};

const ConsumeOurCqeError =
    IouGetSqeError ||
    HandleRecvBodyError ||
    std.mem.Allocator.Error ||
    connection.HandleAcceptError ||
    connection.HandleRecvError ||
    connection.HandleSendError ||
    connection.HandleSpliceError;

/// Panic message for handling `EAGAIN`; we're not using nonblocking sockets at all,
/// so it should be impossible to receive that error, or for such an error to be
/// triggered just from malicious connections.
const EAGAIN_PANIC_MSG =
    "The file/socket should not be in nonblocking mode;" ++
    " server or file/socket configuration error.";

/// On return, `cqe.user_data` is in an undefined state - this is to say,
/// it has either already been `deinit`ed, or it has been been re-submitted
/// in a new `SQE` and should not be modified; in either scenario, the caller
/// should not interact with it.
fn consumeOurCqe(
    liou: *LinuxIoUring,
    server_ctx: *server.Context,
    cqe: OurCqe,
) ConsumeOurCqeError!ConsumeOurCqeResult {
    const entry = cqe.user_data;
    errdefer entry.deinit(server_ctx.allocator);

    const entry_data: *EntryData = entry.ptr orelse {
        // `accept_multishot` cqe

        // we may need to re-submit the `accept_multishot` sqe.
        const accept_cancelled = cqe.flags & std.os.linux.IORING_CQE_F_MORE == 0;
        if (accept_cancelled) liou.multishot_accept_submitted = false;

        switch (try connection.handleAcceptResult(cqe.err())) {
            .success => {},
            // just quickly exit; if we need to re-issue, that's already handled above
            .again => return .ok,
            .intr => return .signal_interrupted_operation,
            .conn_aborted => return .misc_connection_failure,
        }

        const stream: std.net.Stream = .{ .handle = cqe.res };
        errdefer stream.close();

        server_ctx.wait_group.start();
        errdefer server_ctx.wait_group.finish();

        const buffer = try server_ctx.allocator.alloc(u8, server_ctx.read_buffer_size);
        errdefer server_ctx.allocator.free(buffer);

        const new_recv_entry: Entry = entry: {
            const data_ptr = try server_ctx.allocator.create(EntryData);
            errdefer comptime unreachable;

            data_ptr.* = .{
                .buffer = buffer,
                .stream = stream,
                .state = EntryState.INIT,
            };
            break :entry .{ .ptr = data_ptr };
        };
        errdefer if (new_recv_entry.ptr) |data_ptr| server_ctx.allocator.destroy(data_ptr);

        _ = liou.io_uring.recv(
            @bitCast(new_recv_entry),
            stream.handle,
            .{ .buffer = buffer },
            0,
        ) catch |err| switch (err) {
            error.SubmissionQueueFull => |e| {
                server_ctx.logger.err().logf(
                    "Failed to submit the SQE for the initial recv for the connection from '{!}'",
                    // if we fail to getSockName, just print the error in place of the address
                    .{connection.getSockName(stream.handle)},
                );
                return e;
            },
        };

        return .ok;
    };
    errdefer server_ctx.wait_group.finish();

    const addr_err_logger = server_ctx.logger.err().field(
        "address",
        // if we fail to getSockName, just print the error in place of the address;
        connection.getSockName(entry_data.stream.handle),
    );
    errdefer addr_err_logger.log("Dropping connection");

    switch (entry_data.state) {
        .recv_head => |*head| {
            switch (try connection.handleRecvResult(cqe.err())) {
                .success => {},
                .again => std.debug.panic(EAGAIN_PANIC_MSG, .{}),
                .intr => return .signal_interrupted_operation,
                .conn_refused,
                .conn_reset,
                .timed_out,
                => return .misc_connection_failure,
            }

            const recv_len: usize = @intCast(cqe.res);
            std.debug.assert(head.parser.state != .finished);

            const recv_start = head.end;
            const recv_end = recv_start + recv_len;
            head.end += head.parser.feed(entry_data.buffer[recv_start..recv_end]);

            if (head.parser.state != .finished) {
                std.debug.assert(head.end == recv_end);
                if (head.end == entry_data.buffer.len) {
                    return .http_head_parse_error;
                }

                _ = try liou.io_uring.recv(
                    @bitCast(entry),
                    entry_data.stream.handle,
                    .{ .buffer = entry_data.buffer[head.end..] },
                    0,
                );

                return .ok;
            }

            // copy relevant headers and information out of the buffer,
            // so we can use the buffer exclusively for the request body.
            const HeadInfo = requests.HeadInfo;
            const head_info: HeadInfo = head_info: {
                const head_bytes = entry_data.buffer[0..head.end];
                const std_head = std.http.Server.Request.Head.parse(head_bytes) catch
                    return .http_head_parse_error;
                // at the time of writing, this always holds true for the result of `Head.parse`.
                std.debug.assert(std_head.compression == .none);
                break :head_info HeadInfo.parseFromStdHead(std_head) catch |err| {
                    switch (err) {
                        error.RequestTargetTooLong => {
                            server_ctx.logger.err().logf("Request target was too long: '{}'", .{
                                std.zig.fmtEscapes(std_head.target),
                            });
                        },
                        else => {},
                    }
                    return .http_head_parse_error;
                };
            };

            // ^ we just copied the relevant head info, so we're going to move
            // the body content to the start of the buffer.
            const content_end = blk: {
                const old_content_bytes = entry_data.buffer[head.end..recv_end];
                std.mem.copyForwards(
                    u8,
                    entry_data.buffer[0..old_content_bytes.len],
                    old_content_bytes,
                );
                break :blk old_content_bytes.len;
            };

            entry_data.state = .{ .recv_body = .{
                .head_info = head_info,
                .content_end = content_end,
            } };
            const body = &entry_data.state.recv_body;
            try handleRecvBody(liou, server_ctx, entry, body);
            return .ok;
        },

        .recv_body => |*body| {
            switch (try connection.handleRecvResult(cqe.err())) {
                .success => {},
                .again => std.debug.panic(EAGAIN_PANIC_MSG, .{}),
                .intr => return .signal_interrupted_operation,
                .conn_refused,
                .conn_reset,
                .timed_out,
                => return .misc_connection_failure,
            }

            const recv_len: usize = @intCast(cqe.res);
            body.content_end += recv_len;
            try handleRecvBody(liou, server_ctx, entry, body);
            return .ok;
        },

        .send_file_head => |*sfh| {
            switch (try connection.handleSendResult(cqe.err())) {
                .success => {},
                .again => std.debug.panic(EAGAIN_PANIC_MSG, .{}),
                .intr => return .signal_interrupted_operation,
                .conn_reset => return .misc_connection_failure,
            }
            const sent_len: usize = @intCast(cqe.res);
            sfh.sent_bytes += sent_len;

            switch (try sfh.computeAndMaybePrepSend(entry, &liou.io_uring)) {
                .sending_more => return .ok,
                .all_sent => switch (sfh.data) {
                    .file_size => {
                        entry.deinit(server_ctx.allocator);
                        server_ctx.wait_group.finish();
                        return .ok;
                    },
                    .sfd => |sfd| {
                        entry_data.state = .{ .send_file_body = .{
                            .sfd = sfd,
                            .spliced_to_pipe = 0,
                            .spliced_to_socket = 0,
                            .which = .to_pipe,
                        } };
                        const sfb = &entry_data.state.send_file_body;
                        try sfb.prepSpliceFileToPipe(entry, &liou.io_uring);
                        return .ok;
                    },
                },
            }
        },

        .send_file_body => |*sfb| switch (sfb.which) {
            .to_pipe => {
                switch (try connection.handleSpliceResult(cqe.err())) {
                    .success => {},
                    .again => std.debug.panic(EAGAIN_PANIC_MSG, .{}),
                    .bad_file_descriptors,
                    .bad_fd_offset,
                    .invalid_splice,
                    => return .splice_error,
                }
                sfb.spliced_to_pipe += @intCast(cqe.res);

                sfb.which = .to_socket;
                try sfb.prepSplicePipeToSocket(entry, &liou.io_uring);

                return .ok;
            },
            .to_socket => {
                switch (try connection.handleSpliceResult(cqe.err())) {
                    .success => {},
                    .again => std.debug.panic(EAGAIN_PANIC_MSG, .{}),
                    .bad_file_descriptors,
                    .bad_fd_offset,
                    .invalid_splice,
                    => return .splice_error,
                }
                sfb.spliced_to_socket += @intCast(cqe.res);

                if (sfb.spliced_to_socket < sfb.sfd.file_size) {
                    sfb.which = .to_pipe;
                    try sfb.prepSpliceFileToPipe(entry, &liou.io_uring);
                } else {
                    std.debug.assert(sfb.spliced_to_socket == sfb.spliced_to_pipe);
                    entry.deinit(server_ctx.allocator);
                    server_ctx.wait_group.finish();
                }
                return .ok;
            },
        },

        .send_no_body => |*snb| {
            switch (try connection.handleSendResult(cqe.err())) {
                .success => {},
                .again => std.debug.panic(EAGAIN_PANIC_MSG, .{}),
                .intr => return .signal_interrupted_operation,
                .conn_reset => return .misc_connection_failure,
            }
            const sent_len: usize = @intCast(cqe.res);
            snb.end_index += sent_len;

            if (snb.end_index < snb.head.len) {
                try snb.prepSend(entry, &liou.io_uring);
                return .ok;
            } else std.debug.assert(snb.end_index == snb.head.len);

            entry.deinit(server_ctx.allocator);
            server_ctx.wait_group.finish();
            return .ok;
        },
    }

    comptime unreachable;
}

const HandleRecvBodyError =
    IouGetSqeError ||
    std.fs.Dir.StatFileError ||
    std.fs.File.OpenError ||
    std.fs.File.GetSeekPosError ||
    std.posix.PipeError;
fn handleRecvBody(
    liou: *LinuxIoUring,
    server_ctx: *server.Context,
    entry: Entry,
    body: *EntryState.RecvBody,
) !void {
    const entry_data = entry.ptr.?;
    std.debug.assert(body == &entry_data.state.recv_body);

    if (!body.head_info.method.requestHasBody()) {
        if (body.head_info.content_len) |content_len| {
            server_ctx.logger.err().logf(
                "{} request isn't expected to have a body, but got Content-Length: {d}",
                .{ requests.methodFmt(body.head_info.method), content_len },
            );
        }
    }

    switch (body.head_info.method) {
        .POST => {
            entry_data.state = .{
                .send_no_body = EntryState.SendNoBody.initHttStatus(
                    .@"HTTP/1.0",
                    .service_unavailable,
                ),
            };
            const snb = &entry_data.state.send_no_body;
            try snb.prepSend(entry, &liou.io_uring);
            return;
        },

        inline .HEAD, .GET => |method| switch (requests.getRequestTargetResolve(
            server_ctx.logger,
            body.head_info.target.constSlice(),
            server_ctx.latest_snapshot_gen_info,
        )) {
            inline .full_snapshot, .inc_snapshot => |pair| {
                const sfh_data: EntryState.SendFileHead.Data = switch (method) {
                    .HEAD => blk: {
                        const snap_info, var full_info_lg = pair;
                        defer full_info_lg.unlock();

                        const archive_name_bounded = snap_info.snapshotArchiveName();
                        const archive_name = archive_name_bounded.constSlice();

                        const snapshot_dir = server_ctx.snapshot_dir;
                        const snap_stat = try snapshot_dir.statFile(archive_name);
                        break :blk .{ .file_size = snap_stat.size };
                    },
                    .GET => blk: {
                        const snap_info, var full_info_lg = pair;
                        errdefer full_info_lg.unlock();

                        const archive_name_bounded = snap_info.snapshotArchiveName();
                        const archive_name = archive_name_bounded.constSlice();

                        const snapshot_dir = server_ctx.snapshot_dir;
                        const archive_file = try snapshot_dir.openFile(archive_name, .{});
                        errdefer archive_file.close();

                        const file_size = try archive_file.getEndPos();

                        const pipe_r, const pipe_w = try std.posix.pipe();
                        errdefer std.posix.close(pipe_w);
                        errdefer std.posix.close(pipe_r);

                        break :blk .{ .sfd = .{
                            .file_lg = full_info_lg,
                            .file = archive_file,
                            .file_size = file_size,

                            .pipe_w = pipe_w,
                            .pipe_r = pipe_r,
                        } };
                    },
                    else => comptime unreachable,
                };

                entry_data.state = .{ .send_file_head = .{
                    .sent_bytes = 0,
                    .data = sfh_data,
                } };
                const sfh = &entry_data.state.send_file_head;
                switch (try sfh.computeAndMaybePrepSend(entry, &liou.io_uring)) {
                    .all_sent => unreachable, // we know this for certain
                    .sending_more => {},
                }
                return;
            },
            .unrecognized => {},
        },

        else => {},
    }

    entry_data.state = .{
        .send_no_body = EntryState.SendNoBody.initHttStatus(
            .@"HTTP/1.0",
            .not_found,
        ),
    };
    const snb = &entry_data.state.send_no_body;
    try snb.prepSend(entry, &liou.io_uring);
    return;
}

const OurCqe = extern struct {
    user_data: Entry,
    res: i32,
    flags: u32,

    fn fromCqe(cqe: std.os.linux.io_uring_cqe) OurCqe {
        return .{
            .user_data = @bitCast(cqe.user_data),
            .res = cqe.res,
            .flags = cqe.flags,
        };
    }

    fn asCqe(self: OurCqe) std.os.linux.io_uring_cqe {
        return .{
            .user_data = @bitCast(self.user_data),
            .res = self.res,
            .flags = self.flags,
        };
    }

    fn err(self: OurCqe) std.os.linux.E {
        return self.asCqe().err();
    }
};

const Entry = packed struct(u64) {
    /// If null, this is an `accept` entry.
    ptr: ?*EntryData,

    const ACCEPT: Entry = .{ .ptr = null };

    fn deinit(self: Entry, allocator: std.mem.Allocator) void {
        const ptr = self.ptr orelse return;
        ptr.deinit(allocator);
        allocator.destroy(ptr);
    }
};

const EntryData = struct {
    buffer: []u8,
    stream: std.net.Stream,
    state: EntryState,

    fn deinit(self: *EntryData, allocator: std.mem.Allocator) void {
        self.state.deinit();
        allocator.free(self.buffer);
        self.stream.close();
    }
};

const EntryState = union(enum) {
    recv_head: RecvHead,
    recv_body: RecvBody,
    send_file_head: SendFileHead,
    send_file_body: SendFileBody,
    send_no_body: SendNoBody,

    const INIT: EntryState = .{
        .recv_head = .{
            .end = 0,
            .parser = .{},
        },
    };

    fn deinit(self: *EntryState) void {
        switch (self.*) {
            .recv_head => {},
            .recv_body => {},
            .send_file_head => |*sfh| sfh.deinit(),
            .send_file_body => |*sfb| sfb.deinit(),
            .send_no_body => {},
        }
    }

    const RecvHead = struct {
        end: usize,
        parser: std.http.HeadParser,
    };

    const RecvBody = struct {
        head_info: requests.HeadInfo,
        /// The current number of content bytes read into the buffer.
        content_end: usize,
    };

    const SendFileData = struct {
        file_lg: requests.GetRequestTargetResolved.SnapshotReadLock,
        file: std.fs.File,
        file_size: u64,

        pipe_w: std.os.linux.fd_t,
        pipe_r: std.os.linux.fd_t,

        fn deinit(self: *SendFileData) void {
            self.file.close();
            self.file_lg.unlock();
            std.posix.close(self.pipe_w);
            std.posix.close(self.pipe_r);
        }
    };

    const SendFileHead = struct {
        sent_bytes: u64,
        data: Data,

        const Data = union(enum) {
            /// Just responding to a HEAD request.
            file_size: u64,
            sfd: SendFileData,
        };

        fn deinit(self: *SendFileHead) void {
            switch (self.data) {
                .sfd => |*sfd| sfd.deinit(),
                .file_size => {},
            }
        }

        fn computeAndMaybePrepSend(
            self: *SendFileHead,
            entry: Entry,
            io_uring: *IoUring,
        ) IouGetSqeError!enum {
            /// The head has been fully sent already, no send was prepped.
            all_sent,
            /// There is still more head data to send.
            sending_more,
        } {
            const entry_data = entry.ptr.?;
            std.debug.assert(self == &entry_data.state.send_file_head);

            const rendered_len = blk: {
                // render segments of the head into our buffer,
                // sending them as they become rendered.

                var ww = sig.utils.io.WindowedWriter.init(entry_data.buffer, self.sent_bytes);
                var cw = std.io.countingWriter(ww.writer());
                const writer = cw.writer();

                const status: std.http.Status = .ok;
                writer.print("{[version]s} {[status]d}{[space]s}{[phrase]s}\r\n", .{
                    .version = @tagName(std.http.Version.@"HTTP/1.0"),
                    .status = @intFromEnum(status),
                    .space = if (status.phrase() != null) " " else "",
                    .phrase = if (status.phrase()) |str| str else "",
                }) catch |err| switch (err) {};

                const file_size = switch (self.data) {
                    .sfd => |sfd| sfd.file_size,
                    .file_size => |file_size| file_size,
                };
                writer.print("Content-Length: {d}\r\n", .{file_size}) catch |err| switch (err) {};

                writer.writeAll("\r\n") catch |err| switch (err) {};

                if (self.sent_bytes == cw.bytes_written) return .all_sent;
                std.debug.assert(self.sent_bytes < cw.bytes_written);
                break :blk ww.end_index;
            };

            _ = try io_uring.send(
                @bitCast(entry),
                entry_data.stream.handle,
                entry_data.buffer[0..rendered_len],
                0,
            );

            return .sending_more;
        }
    };

    const SendFileBody = struct {
        sfd: SendFileData,
        spliced_to_pipe: u64,
        spliced_to_socket: u64,
        which: Which,

        const Which = enum {
            to_pipe,
            to_socket,
        };

        fn deinit(self: *SendFileBody) void {
            self.sfd.deinit();
        }

        fn prepSpliceFileToPipe(
            self: *const SendFileBody,
            entry: Entry,
            io_uring: *IoUring,
        ) IouGetSqeError!void {
            const entry_ptr = entry.ptr.?;
            std.debug.assert(self == &entry_ptr.state.send_file_body);
            std.debug.assert(self.which == .to_pipe);

            _ = try io_uring.splice(
                @bitCast(entry),
                self.sfd.file.handle,
                self.spliced_to_pipe,
                self.sfd.pipe_w,
                std.math.maxInt(u64),
                self.sfd.file_size - self.spliced_to_pipe,
            );
        }

        fn prepSplicePipeToSocket(
            self: *const SendFileBody,
            entry: Entry,
            io_uring: *IoUring,
        ) IouGetSqeError!void {
            const entry_ptr = entry.ptr.?;
            std.debug.assert(self == &entry_ptr.state.send_file_body);
            std.debug.assert(self.which == .to_socket);

            const stream = entry_ptr.stream;
            _ = try io_uring.splice(
                @bitCast(entry),
                self.sfd.pipe_r,
                std.math.maxInt(u64),
                stream.handle,
                std.math.maxInt(u64),
                self.sfd.file_size - self.spliced_to_socket,
            );
        }
    };

    const SendNoBody = struct {
        /// Should be a statically-lived string.
        head: []const u8,
        end_index: usize,

        fn initString(comptime str: []const u8) SendNoBody {
            return .{
                .head = str,
                .end_index = 0,
            };
        }

        fn initHttStatus(
            comptime version: std.http.Version,
            comptime status: std.http.Status,
        ) SendNoBody {
            const head = comptime std.fmt.comptimePrint("{s} {d}{s}\r\n\r\n", .{
                @tagName(version),
                @intFromEnum(status),
                if (status.phrase()) |phrase| " " ++ phrase else "",
            });
            return initString(head);
        }

        fn prepSend(
            self: *const SendNoBody,
            entry: Entry,
            io_uring: *IoUring,
        ) IouGetSqeError!void {
            const entry_ptr = entry.ptr.?;
            std.debug.assert(self == &entry_ptr.state.send_no_body);
            _ = try io_uring.send(
                @bitCast(entry),
                entry_ptr.stream.handle,
                self.head[self.end_index..],
                0,
            );
        }
    };
};

const IouGetSqeError = error{SubmissionQueueFull};

/// Extracted from `std.os.linux.IoUring.submit`
const IouSubmitError = IouEnterError;

/// Extracted from `std.os.linux.IoUring.enter`.
const IouEnterError = error{
    /// The kernel was unable to allocate memory or ran out of resources for the request.
    /// The application should wait for some completions and try again.
    SystemResources,
    /// The SQE `fd` is invalid, or IOSQE_FIXED_FILE was set but no files were registered.
    FileDescriptorInvalid,
    /// The file descriptor is valid, but the ring is not in the right state.
    /// See io_uring_register(2) for how to enable the ring.
    FileDescriptorInBadState,
    /// The application attempted to overcommit the number of requests it can have pending.
    /// The application should wait for some completions and try again.
    CompletionQueueOvercommitted,
    /// The SQE is invalid, or valid but the ring was setup with IORING_SETUP_IOPOLL.
    SubmissionQueueEntryInvalid,
    /// The buffer is outside the process' accessible address space, or IORING_OP_READ_FIXED
    /// or IORING_OP_WRITE_FIXED was specified but no buffers were registered, or the range
    /// described by `addr` and `len` is not within the buffer registered at `buf_index`:
    BufferInvalid,
    RingShuttingDown,
    /// The kernel believes our `self.fd` does not refer to an io_uring instance,
    /// or the opcode is valid but not supported by this kernel (more likely):
    OpcodeNotSupported,
    /// The operation was interrupted by a delivery of a signal before it could complete.
    /// This can happen while waiting for events with IORING_ENTER_GETEVENTS:
    SignalInterrupt,
} || std.posix.UnexpectedError;
