const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");
const server = @import("server.zig");

const requests = server.requests;
const connection = server.connection;

const IoUring = std.os.linux.IoUring;

const LOGGER_SCOPE = "rpc.server.linux_io_uring";

const HTTP_VERSION: std.http.Version = .@"HTTP/1.0";

pub const LinuxIoUring = struct {
    io_uring: IoUring,

    pub const can_use: bool = builtin.os.tag == .linux;

    pub const InitError = IouInitError || GetSqeRetryError;

    // NOTE(ink): constructing the return type as `E!?T`, where `E` and `T` are resolved
    // separately seems to help ZLS with understanding the types involved better, which is
    // why I've done it like that here. If ZLS gets smarter in the future, you could probably
    // inline this into a single branch in the return type expression.
    const InitErrOrEmpty = if (!can_use) error{} else InitError;
    const InitResultOrNoreturn = if (!can_use) noreturn else LinuxIoUring;
    pub fn init(
        /// Not stored, only used for some initial SQE preps, the pointer needn't remain stable.
        server_ctx: *const server.Context,
    ) InitErrOrEmpty!?InitResultOrNoreturn {
        if (!can_use) return null;
        var io_uring = IoUring.init(4096, 0) catch |err| return switch (err) {
            error.SystemOutdated,
            error.PermissionDenied,
            => return null,
            else => |e| e,
        };
        errdefer io_uring.deinit();

        try prepMultishotAccept(&io_uring, server_ctx.tcp);
        return .{ .io_uring = io_uring };
    }

    pub fn deinit(self: *LinuxIoUring) void {
        self.io_uring.deinit();
    }

    pub const AcceptAndServeConnectionsError =
        GetSqeRetryError ||
        ConsumeOurCqeError ||
        std.mem.Allocator.Error;

    pub fn acceptAndServeConnections(
        self: *LinuxIoUring,
        server_ctx: *server.Context,
    ) AcceptAndServeConnectionsError!void {
        const timeout_ts: std.os.linux.kernel_timespec = comptime .{
            .sec = 1,
            .nsec = 0,
        };

        const timeout_sqe = try getSqeRetry(&self.io_uring);
        timeout_sqe.prep_timeout(&timeout_ts, 1, 0);
        timeout_sqe.user_data = @bitCast(Entry.TIMEOUT);

        _ = try self.io_uring.submit_and_wait(1);

        var pending_cqes_buf: [255]std.os.linux.io_uring_cqe = undefined;
        const pending_cqes_count = try self.io_uring.copy_cqes(&pending_cqes_buf, 0);
        const cqes_pending = pending_cqes_buf[0..pending_cqes_count];

        for (cqes_pending) |raw_cqe| {
            const our_cqe = OurCqe.fromCqe(raw_cqe);
            try consumeOurCqe(self, server_ctx, our_cqe);
        }
    }
};

fn prepMultishotAccept(
    io_uring: *IoUring,
    tcp: std.net.Server,
) GetSqeRetryError!void {
    const sqe = try getSqeRetry(io_uring);
    sqe.prep_multishot_accept(tcp.stream.handle, null, null, std.os.linux.SOCK.CLOEXEC);
    sqe.user_data = @bitCast(Entry.ACCEPT);
}

const ConnErrLogger =
    sig.trace.NewEntry(LOGGER_SCOPE)
        .Field("conn", std.posix.GetSockNameError!std.net.Address);

fn connErrLogger(
    logger: sig.trace.ScopedLogger(LOGGER_SCOPE),
    entry_data: *const EntryData,
) ConnErrLogger {
    return logger.err().field("conn", entry_data.getSocketName());
}

const ConsumeOurCqeError =
    HandleRecvBodyError ||
    std.mem.Allocator.Error ||
    connection.HandleAcceptError ||
    connection.HandleRecvError ||
    connection.HandleSendError ||
    connection.HandleSpliceError;

/// On return, `cqe.user_data` is in an undefined state - this is to say,
/// it has either already been `deinit`ed, or it has been been re-submitted
/// in a new `SQE` and should not be modified; in either scenario, the caller
/// should not interact with it.
fn consumeOurCqe(
    liou: *LinuxIoUring,
    server_ctx: *server.Context,
    cqe: OurCqe,
) ConsumeOurCqeError!void {
    const logger = server_ctx.logger.withScope(LOGGER_SCOPE);

    const entry = cqe.user_data;
    errdefer entry.deinit(server_ctx.allocator);

    const entry_data: *EntryData = switch (entry.tag) {
        _ => entry.ptr,
        .timeout => return,
        .accept => {
            // `accept_multishot` cqe

            // we may need to re-submit the `accept_multishot` sqe.
            const accept_cancelled = cqe.flags & std.os.linux.IORING_CQE_F_MORE == 0;
            if (accept_cancelled) {
                try prepMultishotAccept(&liou.io_uring, server_ctx.tcp);
            }

            switch (try connection.handleAcceptResult(cqe.err())) {
                .success => {},
                // just quickly exit; if we need to re-issue, that's already handled above
                .intr,
                .again,
                .conn_aborted,
                .proto_fail,
                => return,
            }

            server_ctx.wait_group.start();
            errdefer server_ctx.wait_group.finish();

            const stream: std.net.Stream = .{ .handle = cqe.res };
            errdefer stream.close();

            const buffer = try server_ctx.allocator.alloc(u8, server_ctx.read_buffer_size);
            errdefer server_ctx.allocator.free(buffer);

            const data_ptr = try server_ctx.allocator.create(EntryData);
            errdefer server_ctx.allocator.destroy(data_ptr);
            data_ptr.* = .{
                .buffer = buffer,
                .stream = stream,
                .state = EntryState.INIT,
            };

            const sqe = try getSqeRetry(&liou.io_uring);
            sqe.prep_recv(stream.handle, buffer, 0);
            sqe.user_data = @bitCast(Entry{ .ptr = data_ptr });
            return;
        },
    };
    errdefer server_ctx.wait_group.finish();

    // Panic message for handling `EAGAIN`; we're not using nonblocking sockets at all,
    // so it should be impossible to receive that error, or for such an error to be
    // triggered just from malicious connections.
    const eagain_panic_msg =
        "The file/socket should not be in nonblocking mode;" ++
        " server or file/socket configuration error.";

    switch (entry_data.state) {
        .recv_head => |*head| {
            switch (try connection.handleRecvResult(cqe.err())) {
                .success => {},

                .again => std.debug.panic(eagain_panic_msg, .{}),

                .intr => {
                    try head.prepRecv(entry, &liou.io_uring);
                    return;
                },

                .conn_refused,
                .conn_reset,
                .timed_out,
                => {
                    entry.deinit(server_ctx.allocator);
                    return;
                },
            }

            const recv_len: usize = @intCast(cqe.res);
            std.debug.assert(head.parser.state != .finished);

            const recv_start = head.end;
            const recv_end = recv_start + recv_len;
            head.end += head.parser.feed(entry_data.buffer[recv_start..recv_end]);

            if (head.parser.state != .finished) {
                std.debug.assert(head.end == recv_end);
                if (head.end == entry_data.buffer.len) {
                    entry.deinit(server_ctx.allocator);
                    return;
                }

                try head.prepRecv(entry, &liou.io_uring);
                return;
            }

            // copy relevant headers and information out of the buffer,
            // so we can use the buffer exclusively for the request body.
            const HeadInfo = requests.HeadInfo;
            const head_info: HeadInfo = head_info: {
                const head_bytes = entry_data.buffer[0..head.end];
                const std_head = std.http.Server.Request.Head.parse(head_bytes) catch |err| {
                    connErrLogger(logger, entry_data)
                        .logf("Head parse error: {s}", .{@errorName(err)});
                    entry.deinit(server_ctx.allocator);
                    return;
                };

                // at the time of writing, this always holds true for the result of `Head.parse`.
                std.debug.assert(std_head.compression == .none);
                break :head_info HeadInfo.parseFromStdHead(std_head) catch |err| {
                    defer entry.deinit(server_ctx.allocator);
                    switch (err) {
                        error.RequestTargetTooLong => connErrLogger(logger, entry_data).logf(
                            "Request target was too long: '{}'",
                            .{std.zig.fmtEscapes(std_head.target)},
                        ),
                        error.UnexpectedTransferEncoding => if (std_head.content_length == null) {
                            connErrLogger(logger, entry_data).log(
                                "Request missing content-length",
                            );
                            entry_data.state = .{
                                .send_static_string = EntryState.SendStaticString
                                    .initHttpStatusNoBody(.length_required),
                            };
                            const snb = &entry_data.state.send_static_string;
                            try snb.prepSend(entry, &liou.io_uring);
                        } else {
                            connErrLogger(logger, entry_data).log(
                                "Request contained both content-length and transfer-encoding",
                            );
                            entry_data.state = .{
                                .send_static_string = EntryState.SendStaticString
                                    .initHttpStatusNoBody(.bad_request),
                            };
                            const snb = &entry_data.state.send_static_string;
                            try snb.prepSend(entry, &liou.io_uring);
                        },
                        else => |e| connErrLogger(logger, entry_data)
                            .logf("Request error: {s}", .{@errorName(e)}),
                    }
                    return;
                };
            };

            if (head_info.content_len) |content_len| {
                if (content_len > requests.MAX_REQUEST_BODY_SIZE) {
                    entry_data.state = .{
                        .send_static_string = EntryState.SendStaticString.initHttpStatusNoBody(
                            .payload_too_large,
                        ),
                    };
                    const snb = &entry_data.state.send_static_string;
                    try snb.prepSend(entry, &liou.io_uring);
                    return;
                }
            }

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
            handleRecvBody(liou, server_ctx, entry, body) catch |err| {
                connErrLogger(logger, entry_data).logf("{s}", .{@errorName(err)});
                entry.deinit(server_ctx.allocator);
            };
            return;
        },

        .recv_body => |*body| {
            switch (try connection.handleRecvResult(cqe.err())) {
                .success => {},
                .again => std.debug.panic(eagain_panic_msg, .{}),
                .intr => @panic("TODO:"),
                .conn_refused,
                .conn_reset,
                .timed_out,
                => {
                    entry.deinit(server_ctx.allocator);
                    return;
                },
            }

            const recv_len: usize = @intCast(cqe.res);
            body.content_end += recv_len;
            handleRecvBody(liou, server_ctx, entry, body) catch |err| {
                connErrLogger(logger, entry_data).logf("handleRecvBody: {s}", .{@errorName(err)});
                entry.deinit(server_ctx.allocator);
            };
            return;
        },

        .send_file_head => |*sfh| {
            switch (try connection.handleSendResult(cqe.err())) {
                .success => {},
                .again => std.debug.panic(eagain_panic_msg, .{}),
                .intr => @panic("TODO:"),
                .conn_reset,
                .broken_pipe,
                => {
                    entry.deinit(server_ctx.allocator);
                    return;
                },
            }
            const sent_len: usize = @intCast(cqe.res);
            sfh.sent_bytes += sent_len;

            switch (try sfh.computeAndMaybePrepSend(entry, &liou.io_uring)) {
                .sending_more => return,
                .all_sent => switch (sfh.data) {
                    .file_size => {
                        entry.deinit(server_ctx.allocator);
                        server_ctx.wait_group.finish();
                        return;
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
                        return;
                    },
                },
            }
        },

        .send_file_body => |*sfb| switch (sfb.which) {
            .to_pipe => {
                switch (try connection.handleSpliceResult(cqe.err())) {
                    .success => {},
                    .again => std.debug.panic(eagain_panic_msg, .{}),
                    .bad_file_descriptors,
                    .bad_fd_offset,
                    .invalid_splice,
                    => {
                        entry.deinit(server_ctx.allocator);
                        return;
                    },
                }
                sfb.spliced_to_pipe += @intCast(cqe.res);

                sfb.which = .to_socket;
                try sfb.prepSplicePipeToSocket(entry, &liou.io_uring);

                return;
            },
            .to_socket => {
                switch (try connection.handleSpliceResult(cqe.err())) {
                    .success => {},
                    .again => std.debug.panic(eagain_panic_msg, .{}),
                    .bad_file_descriptors,
                    .bad_fd_offset,
                    .invalid_splice,
                    => {
                        entry.deinit(server_ctx.allocator);
                        return;
                    },
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
                return;
            },
        },

        .send_static_string => |*sss| {
            switch (try connection.handleSendResult(cqe.err())) {
                .success => {},
                .again => std.debug.panic(eagain_panic_msg, .{}),
                .intr => @panic("TODO:"),
                .conn_reset,
                .broken_pipe,
                => {
                    entry.deinit(server_ctx.allocator);
                    return;
                },
            }
            const sent_len: usize = @intCast(cqe.res);
            sss.end_index += sent_len;

            if (sss.end_index < sss.data.len) {
                try sss.prepSend(entry, &liou.io_uring);
                return;
            } else std.debug.assert(sss.end_index == sss.data.len);

            entry.deinit(server_ctx.allocator);
            server_ctx.wait_group.finish();
            return;
        },
    }

    comptime unreachable;
}

const HandleRecvBodyError =
    GetSqeRetryError ||
    std.fs.Dir.StatFileError ||
    std.fs.File.OpenError ||
    std.fs.File.GetSeekPosError ||
    std.posix.PipeError;

fn handleRecvBody(
    liou: *LinuxIoUring,
    server_ctx: *server.Context,
    entry: Entry,
    body: *EntryState.RecvBody,
) HandleRecvBodyError!void {
    const logger = server_ctx.logger.withScope(LOGGER_SCOPE);

    const entry_data = entry.ptr;
    std.debug.assert(body == &entry_data.state.recv_body);

    if (!body.head_info.method.requestHasBody()) {
        if (body.head_info.content_len) |content_len| {
            connErrLogger(logger, entry_data).logf(
                "{} request isn't expected to have a body, but got Content-Length: {d}",
                .{ requests.httpMethodFmt(body.head_info.method), content_len },
            );
        }
    }

    switch (body.head_info.method) {
        inline .HEAD, .GET => |method| switch (requests.getRequestTargetResolve(
            logger.unscoped(),
            body.head_info.target.constSlice(),
            &server_ctx.accountsdb.latest_snapshot_gen_info,
        )) {
            inline .full_snapshot, .inc_snapshot => |pair| {
                const sfh_data: EntryState.SendFileHead.Data = switch (method) {
                    .HEAD => blk: {
                        const snap_info, var full_info_lg = pair;
                        defer full_info_lg.unlock();

                        const archive_name_bounded = snap_info.snapshotArchiveName();
                        const archive_name = archive_name_bounded.constSlice();

                        const snapshot_dir = server_ctx.accountsdb.snapshot_dir;
                        const snap_stat = try snapshot_dir.statFile(archive_name);
                        break :blk .{ .file_size = snap_stat.size };
                    },
                    .GET => blk: {
                        const snap_info, var full_info_lg = pair;
                        errdefer full_info_lg.unlock();

                        const archive_name_bounded = snap_info.snapshotArchiveName();
                        const archive_name = archive_name_bounded.constSlice();

                        const snapshot_dir = server_ctx.accountsdb.snapshot_dir;
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
            .health => {
                entry_data.state = .{
                    .send_static_string = EntryState.SendStaticString.initHttpStatusString(
                        .ok,
                        "unknown",
                    ),
                };
                const snb = &entry_data.state.send_static_string;
                try snb.prepSend(entry, &liou.io_uring);
                return;
            },

            .genesis_file => {
                connErrLogger(logger, entry_data).logf("Attempt to get our genesis file", .{});
                entry_data.state = .{
                    .send_static_string = EntryState.SendStaticString.initHttpStatusNoBody(
                        .service_unavailable,
                    ),
                };
                const snb = &entry_data.state.send_static_string;
                try snb.prepSend(entry, &liou.io_uring);
                return;
            },

            .not_found => {},
        },

        .POST => {
            if (body.head_info.content_type != .@"application/json") {
                entry_data.state = .{
                    .send_static_string = EntryState.SendStaticString
                        .initHttpStatusNoBody(.not_acceptable),
                };
                const snb = &entry_data.state.send_static_string;
                try snb.prepSend(entry, &liou.io_uring);
                return;
            }

            connErrLogger(logger, entry_data).logf("Attempt to invoke our RPC service", .{});
            entry_data.state = .{
                .send_static_string = EntryState.SendStaticString.initHttpStatusNoBody(
                    .service_unavailable,
                ),
            };
            const snb = &entry_data.state.send_static_string;
            try snb.prepSend(entry, &liou.io_uring);
            return;
        },

        else => {},
    }

    logger.err().logf(
        "Unrecognized request '{} {s}'",
        .{ requests.httpMethodFmt(body.head_info.method), body.head_info.target.constSlice() },
    );
    entry_data.state = .{
        .send_static_string = EntryState.SendStaticString.initHttpStatusNoBody(
            .not_found,
        ),
    };
    const snb = &entry_data.state.send_static_string;
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

const Entry = packed union {
    /// Only valid if `tag` is an unnamed tag.
    ptr: *EntryData,
    tag: enum(u64) {
        //! Unnamed values correspond to the `ptr` field.

        accept = 0,
        timeout = 1,

        _,
    },

    const ACCEPT: Entry = .{ .tag = .accept };
    const TIMEOUT: Entry = .{ .tag = .timeout };

    fn deinit(self: Entry, allocator: std.mem.Allocator) void {
        const ptr = switch (self.tag) {
            .accept, .timeout => return,
            _ => self.ptr,
        };
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

    fn getSocketName(self: EntryData) std.posix.GetSockNameError!std.net.Address {
        var addr: std.net.Address = .{ .any = undefined };
        var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr.any));
        try std.posix.getsockname(self.stream.handle, &addr.any, &addr_len);
        return addr;
    }
};

const EntryState = union(enum) {
    recv_head: RecvHead,
    recv_body: RecvBody,
    send_file_head: SendFileHead,
    send_file_body: SendFileBody,
    send_static_string: SendStaticString,

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
            .send_static_string => {},
        }
    }

    const RecvHead = struct {
        end: usize,
        parser: std.http.HeadParser,

        fn prepRecv(
            self: *const RecvHead,
            entry: Entry,
            io_uring: *IoUring,
        ) GetSqeRetryError!void {
            const entry_ptr = entry.ptr;
            std.debug.assert(self == &entry_ptr.state.recv_head);

            const usable_buffer = entry_ptr.buffer[self.end..];
            const sqe = try getSqeRetry(io_uring);
            sqe.prep_recv(entry_ptr.stream.handle, usable_buffer, 0);
            sqe.user_data = @bitCast(entry);
        }
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

        /// If `self.sent_bytes` is equal to the number of rendered head bytes, this
        /// will return `.all_sent`, which means it won't have queued any SQEs; otherwise,
        /// it is guaranteed to return `.sending_more` - the latter would always be the
        /// case when `self.sent_bytes == 0` for example.
        fn computeAndMaybePrepSend(
            self: *SendFileHead,
            entry: Entry,
            io_uring: *IoUring,
        ) GetSqeRetryError!enum {
            /// The head has been fully sent already, no send was prepped.
            all_sent,
            /// There is still more head data to send.
            sending_more,
        } {
            const entry_data = entry.ptr;
            std.debug.assert(self == &entry_data.state.send_file_head);

            const rendered_len = blk: {
                // render segments of the head into our buffer,
                // sending them as they become rendered.

                var ww = sig.utils.io.WindowedWriter.init(entry_data.buffer, self.sent_bytes);
                var cw = std.io.countingWriter(ww.writer());
                const writer = cw.writer();

                const status: std.http.Status = .ok;
                writer.print("{[version]s} {[status]d}{[space]s}{[phrase]s}\r\n", .{
                    .version = @tagName(HTTP_VERSION),
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

            const sqe = try getSqeRetry(io_uring);
            sqe.prep_send(entry_data.stream.handle, entry_data.buffer[0..rendered_len], 0);
            sqe.user_data = @bitCast(entry);

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
        ) GetSqeRetryError!void {
            const entry_ptr = entry.ptr;
            std.debug.assert(self == &entry_ptr.state.send_file_body);
            std.debug.assert(self.which == .to_pipe);

            const sqe = try getSqeRetry(io_uring);
            sqe.prep_splice(
                self.sfd.file.handle,
                self.spliced_to_pipe,
                self.sfd.pipe_w,
                std.math.maxInt(u64),
                self.sfd.file_size - self.spliced_to_pipe,
            );
            sqe.user_data = @bitCast(entry);
        }

        fn prepSplicePipeToSocket(
            self: *const SendFileBody,
            entry: Entry,
            io_uring: *IoUring,
        ) GetSqeRetryError!void {
            const entry_ptr = entry.ptr;
            std.debug.assert(self == &entry_ptr.state.send_file_body);
            std.debug.assert(self.which == .to_socket);

            const stream = entry_ptr.stream;

            const sqe = try getSqeRetry(io_uring);
            sqe.prep_splice(
                self.sfd.pipe_r,
                std.math.maxInt(u64),
                stream.handle,
                std.math.maxInt(u64),
                self.sfd.file_size - self.spliced_to_socket,
            );
            sqe.user_data = @bitCast(entry);
        }
    };

    const SendStaticString = struct {
        /// Should be a statically-lived string.
        data: []const u8,
        end_index: usize,

        fn initRawString(comptime str: []const u8) SendStaticString {
            return .{
                .data = str,
                .end_index = 0,
            };
        }

        fn initHttpStatusNoBody(
            comptime status: std.http.Status,
        ) SendStaticString {
            return initRawString(statusLineStr(status) ++ "\r\n");
        }

        fn initHttpStatusString(
            comptime status: std.http.Status,
            comptime body: []const u8,
        ) SendStaticString {
            const str = comptime "" ++
                statusLineStr(status) ++
                std.fmt.comptimePrint("Content-Length: {d}\r\n", .{body.len}) ++
                "\r\n" ++
                body;
            return initRawString(str);
        }

        inline fn statusLineStr(
            comptime status: std.http.Status,
        ) []const u8 {
            comptime return std.fmt.comptimePrint("{s} {d}{s}\r\n", .{
                @tagName(HTTP_VERSION),
                @intFromEnum(status),
                if (status.phrase()) |phrase| " " ++ phrase else "",
            });
        }

        fn prepSend(
            self: *const SendStaticString,
            entry: Entry,
            io_uring: *IoUring,
        ) GetSqeRetryError!void {
            const entry_ptr = entry.ptr;
            std.debug.assert(self == &entry_ptr.state.send_static_string);

            const sqe = try getSqeRetry(io_uring);
            sqe.prep_send(entry_ptr.stream.handle, self.data[self.end_index..], 0);
            sqe.user_data = @bitCast(entry);
        }
    };
};

const GetSqeRetryError = IouEnterError;

/// Try to `get_sqe`; if the submission queue is too full for that, call `submit()`,
/// and then try again, and panic if there's still somehow no room.
fn getSqeRetry(io_uring: *std.os.linux.IoUring) GetSqeRetryError!*std.os.linux.io_uring_sqe {
    if (io_uring.get_sqe()) |sqe| return sqe else |_| {}
    _ = try io_uring.submit();
    return io_uring.get_sqe() catch
        std.debug.panic("Failed to queue entry after flushing submission queue", .{});
}

const IouInitError = std.posix.MMapError || error{
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
