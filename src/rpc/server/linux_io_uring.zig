const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const connection = @import("connection.zig");
const requests = @import("requests.zig");

const IoUring = std.os.linux.IoUring;
const ServerCtx = sig.rpc.server.Context;

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

    pub const AcceptAndServeConnectionsError = error{
        /// This was the first call, and we failed to prep, queue, and submit the multishot accept.
        FailedToAcceptMultishot,
        SubmissionQueueFull,
    } || IouSubmitError ||
        HandleOurCqeError ||
        std.mem.Allocator.Error;

    pub fn acceptAndServeConnections(
        self: *LinuxIoUring,
        server_ctx: *ServerCtx,
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
                error.SubmissionQueueFull => {
                    server_ctx.logger.err().log(
                        "Under normal circumstances the accept_multishot would be" ++
                            " the first SQE to be queued, but somehow the queue was full.",
                    );
                    return error.FailedToAcceptMultishot;
                },
            };
            if (try self.io_uring.submit() != 1) {
                return error.FailedToAcceptMultishot;
            }
            return;
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
            consumeOurCqe(self, server_ctx, our_cqe) catch |err| switch (err) {
                // connection errors
                error.ConnectionAborted,
                error.ConnectionRefused,
                error.ConnectionResetByPeer,
                error.ConnectionTimedOut,

                // our http parse errors
                error.RequestHeadersTooBig,
                error.RequestTargetTooLong,
                error.RequestContentTypeUnrecognized,

                // std http parse errors
                error.UnknownHttpMethod,
                error.HttpHeadersInvalid,
                error.InvalidContentLength,
                error.HttpHeaderContinuationsUnsupported,
                error.HttpTransferEncodingUnsupported,
                error.HttpConnectionHeaderUnsupported,
                error.CompressionUnsupported,
                error.MissingFinalNewline,

                // splice errors
                error.BadFileDescriptors,
                error.BadFdOffset,
                error.InvalidSplice,
                => |e| {
                    server_ctx.logger.err().logf("{s}", .{@errorName(e)});
                    continue;
                },

                error.SubmissionQueueFull => |e| return e,
                else => |e| return e,
            };
        }
    }
};

const HandleOurCqeError = error{
    SubmissionQueueFull,

    /// Connection was aborted; not necessarily critical.
    ConnectionAborted,
    /// A remote host refused to allow the network connection, typically because it is not
    /// running the requested service.
    ConnectionRefused,
    /// A remote host refused to allow the network connection, typically because it is not
    /// running the requested service.
    ConnectionResetByPeer,
    ConnectionTimedOut,

    /// The headers recv'd in a request were too big.
    RequestHeadersTooBig,
    /// The request line recv'd was too long.
    RequestTargetTooLong,
    /// The request 'Content-Type' did not match any recognized `ContentType`.
    RequestContentTypeUnrecognized,
} || connection.HandleAcceptError ||
    connection.HandleRecvError ||
    connection.HandleSendError ||
    connection.HandleSpliceError ||
    std.mem.Allocator.Error ||
    std.http.Server.Request.Head.ParseError ||
    std.fs.File.OpenError ||
    std.fs.File.GetSeekPosError;

/// On return, `cqe.user_data` is in an undefined state - this is to say,
/// it has either already been `deinit`ed, or it has been been re-submitted
/// in a new `SQE` and should not be modified; in either scenario, the caller
/// should not interact with it.
fn consumeOurCqe(
    liou: *LinuxIoUring,
    server_ctx: *ServerCtx,
    cqe: OurCqe,
) HandleOurCqeError!void {
    const entry = cqe.user_data;
    errdefer entry.deinit(server_ctx.allocator);

    const entry_data: *EntryData = entry.ptr orelse {
        // multishot accept cqe

        switch (try connection.handleAcceptResult(cqe.err())) {
            .success => {},

            // TODO: does this mean the multishot accept has stopped? If no, just warn. If yes, re-queue here and warn.
            .intr => std.debug.panic("TODO:", .{}),

            .again => std.debug.panic("The socket should not be in nonblocking mode.", .{}),
            .conn_aborted => return error.ConnectionAborted,
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
                    "Failed to submit the SQE for the initial recv" ++
                        " for the connection from '{!}'",
                    // if we fail to getSockName, just print the error in place of the address
                    .{connection.getSockName(stream.handle)},
                );
                return e;
            },
        };

        return;
    };
    errdefer server_ctx.wait_group.finish();

    const err_logger = server_ctx.logger.err().field(
        "address",
        // if we fail to getSockName, just print the error in place of the address;
        connection.getSockName(entry_data.stream.handle),
    );
    errdefer err_logger.logf("Dropping connection", .{});

    switch (entry_data.state) {
        .recv_head => |*head| {
            switch (try connection.handleRecvResult(cqe.err())) {
                .success => {},

                .intr => std.debug.panic("TODO: how to handle interrupts on this?", .{}), // TODO:
                .again => std.debug.panic("The socket should not be in nonblocking mode.", .{}),

                .conn_refused => return error.ConnectionRefused,
                .conn_reset => return error.ConnectionResetByPeer,
                .timed_out => return error.ConnectionTimedOut,
            }

            const recv_len: usize = @intCast(cqe.res);
            std.debug.assert(head.parser.state != .finished);

            const recv_start = head.end;
            const recv_end = recv_start + recv_len;
            head.end += head.parser.feed(entry_data.buffer[recv_start..recv_end]);

            if (head.parser.state != .finished) {
                std.debug.assert(head.end == recv_end);
                if (head.end == entry_data.buffer.len) {
                    return error.RequestHeadersTooBig;
                }

                _ = try liou.io_uring.recv(
                    @bitCast(entry),
                    entry_data.stream.handle,
                    .{ .buffer = entry_data.buffer[head.end..] },
                    0,
                );
                return;
            }

            // copy relevant headers and information out of the buffer,
            // so we can use the buffer exclusively for the request body.
            const HeadInfo = requests.HeadInfo;
            const head_info: HeadInfo = head_info: {
                const head_bytes = entry_data.buffer[0..head.end];
                const std_head = try std.http.Server.Request.Head.parse(head_bytes);
                // at the time of writing, this always holds true for the result of `Head.parse`.
                std.debug.assert(std_head.compression == .none);
                break :head_info HeadInfo.parseFromStdHead(std_head) catch |err| switch (err) {
                    error.RequestTargetTooLong => |e| {
                        err_logger.logf("Request target was too long: '{}'", .{
                            std.zig.fmtEscapes(std_head.target),
                        });
                        return e;
                    },
                    else => |e| return e,
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
                .need_to_check_cqe = false,
                .content_end = content_end,
            } };
            const body = &entry_data.state.recv_body;
            try handleRecvBody(liou, server_ctx, err_logger, entry, body);
            return;
        },

        .recv_body => |*body| {
            if (body.need_to_check_cqe) {
                switch (try connection.handleRecvResult(cqe.err())) {
                    .success => {},

                    // TODO: how to handle interrupts on this?
                    .intr => std.debug.panic("TODO:", .{}),

                    .again => std.debug.panic(
                        "The socket should not be in nonblocking mode.",
                        .{},
                    ),

                    .conn_refused => return error.ConnectionRefused,
                    .conn_reset => return error.ConnectionResetByPeer,
                    .timed_out => return error.ConnectionTimedOut,
                }

                const recv_len: usize = @intCast(cqe.res);
                body.content_end += recv_len;
            }

            try handleRecvBody(liou, server_ctx, err_logger, entry, body);
            return;
        },

        .send_file_head => |*sfh| {
            switch (try connection.handleSendResult(cqe.err())) {
                .success => {},
                .intr => std.debug.panic("TODO: how to handle interrupts on this?", .{}), // TODO:
                .again => std.debug.panic("The socket should not be in nonblocking mode.", .{}),
            }
            const sent_len: usize = @intCast(cqe.res);
            sfh.sent_bytes += sent_len;

            switch (try sfh.computeAndMaybePrepSend(entry, &liou.io_uring)) {
                .sending_more => return,
                .all_sent => {
                    const sfd = sfh.sfd;
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
            }
        },

        .send_file_body => |*sfb| switch (sfb.which) {
            .to_pipe => {
                switch (try connection.handleSpliceResult(cqe.err())) {
                    .success => {},
                    .again => std.debug.panic(
                        "The socket should not be in nonblocking mode.",
                        .{},
                    ),
                }
                sfb.spliced_to_pipe += @intCast(cqe.res);

                sfb.which = .to_socket;
                try sfb.prepSplicePipeToSocket(entry, &liou.io_uring);

                return;
            },
            .to_socket => {
                switch (try connection.handleSpliceResult(cqe.err())) {
                    .success => {},
                    .again => std.debug.panic(
                        "The socket should not be in nonblocking mode.",
                        .{},
                    ),
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

        .send_no_body => |*snb| {
            switch (try connection.handleSendResult(cqe.err())) {
                .success => {},
                .intr => std.debug.panic("TODO: how to handle interrupts on this?", .{}), // TODO:
                .again => std.debug.panic("The socket should not be in nonblocking mode.", .{}),
            }
            const sent_len: usize = @intCast(cqe.res);
            snb.end_index += sent_len;

            if (snb.end_index < snb.head.len) {
                try snb.prepSend(entry, &liou.io_uring);
            } else std.debug.assert(snb.end_index == snb.head.len);

            entry.deinit(server_ctx.allocator);
            server_ctx.wait_group.finish();
            return;
        },
    }
}

fn handleRecvBody(
    liou: *LinuxIoUring,
    server_ctx: *ServerCtx,
    err_logger: anytype,
    entry: Entry,
    body: *EntryState.RecvBody,
) !void {
    const entry_data = entry.ptr.?;
    std.debug.assert(body == &entry_data.state.recv_body);

    if (!body.head_info.method.requestHasBody()) {
        if (body.head_info.content_len) |content_len| {
            err_logger.logf(
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

        .GET => switch (requests.getRequestTargetResolve(
            server_ctx.logger,
            body.head_info.target.constSlice(),
            server_ctx.latest_snapshot_gen_info,
        )) {
            inline .full_snapshot, .inc_snapshot => |pair| {
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

                entry_data.state = .{ .send_file_head = .{
                    .sfd = .{
                        .file_lg = full_info_lg,
                        .file = archive_file,
                        .file_size = file_size,

                        .pipe_w = pipe_w,
                        .pipe_r = pipe_r,
                    },
                    .sent_bytes = 0,
                } };
                const sfh = &entry_data.state.send_file_head;
                switch (try sfh.computeAndMaybePrepSend(entry, &liou.io_uring)) {
                    .sending_more => return,
                    .all_sent => unreachable, // we know this for certain
                }
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

    fn deinit(entry: Entry, allocator: std.mem.Allocator) void {
        const ptr = entry.ptr orelse return;
        ptr.deinit(allocator);
        allocator.destroy(ptr);
    }
};

const EntryData = struct {
    buffer: []u8,
    stream: std.net.Stream,
    state: EntryState,

    fn deinit(data: *EntryData, allocator: std.mem.Allocator) void {
        data.state.deinit();
        allocator.free(data.buffer);
        data.stream.close();
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

    fn deinit(state: *EntryState) void {
        switch (state.*) {
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
        /// Should be true when submitting the SQE.
        /// Will be true when receving the CQE, and false when we've
        /// been `continue`'d into by another prong in the switch loop.
        need_to_check_cqe: bool,
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
        sfd: SendFileData,
        sent_bytes: u64,

        fn deinit(self: *SendFileHead) void {
            self.sfd.deinit();
        }

        fn computeAndMaybePrepSend(
            self: *SendFileHead,
            entry: Entry,
            io_uring: *IoUring,
        ) !enum {
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

                writer.print("Content-Length: {d}\r\n", .{
                    self.sfd.file_size,
                }) catch |err| switch (err) {};

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
        ) !void {
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
        ) !void {
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
        ) !void {
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
