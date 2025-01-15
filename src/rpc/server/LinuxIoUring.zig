const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const connection = @import("connection.zig");
const requests = @import("requests.zig");

const IoUring = std.os.linux.IoUring;

const Server = sig.rpc.Server;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo;

const LinuxIoUring = @This();
io_uring: IoUring,

fn deinit(linux: *LinuxIoUring) void {
    linux.io_uring.deinit();
}

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

pub const EnterError = error{
    SystemResources,
    FileDescriptorInvalid,
    FileDescriptorInBadState,
    CompletionQueueOvercommitted,
    SubmissionQueueEntryInvalid,
    BufferInvalid,
    RingShuttingDown,
    OpcodeNotSupported,
    SignalInterrupt,
};

pub const AcceptAndServeConnectionsError =
    // std.posix.GetSockNameError ||
    std.mem.Allocator.Error ||
    connection.HandleAcceptError ||
    connection.HandleRecvError ||
    EnterError ||
    std.http.Server.Request.Head.ParseError ||
    error{RequestBodyTooLong} ||
    error{SubmissionQueueFull};

pub fn acceptAndServeConnections(
    linux: *LinuxIoUring,
    server: *Server,
    max_connections_to_handle: u8,
) AcceptAndServeConnectionsError!void {
    std.debug.assert(linux == &server.work_pool.linux_io_uring);
    _ = try linux.io_uring.submit_and_wait(1);

    var cqes_buf: [255]std.os.linux.io_uring_cqe = undefined;
    const cqes = cqes: {
        const cqes_count = try linux.io_uring.copy_cqes(cqes_buf[0..max_connections_to_handle], 0);
        break :cqes cqes_buf[0..cqes_count];
    };

    var first_err: ?AcceptAndServeConnectionsError = null;

    cqe_loop: for (cqes, 0..) |cqe, i| {
        errdefer for (cqes[i..]) |next_cqe| { // including the current cqe
            const next_entry: Entry = @bitCast(next_cqe.user_data);
            next_entry.deinit(server.allocator);
        };

        const entry: Entry = @bitCast(cqe.user_data);
        const entry_data: *EntryData = entry.ptr orelse {
            // multishot accept cqe

            if (connection.handleAcceptResult(cqe.err())) |accept_result| switch (accept_result) {
                .success => {},
                .intr => std.debug.panic("TODO: does this mean the multishot accept has stopped? If no, just warn. If yes, re-queue here and warn.", .{}), // TODO:
                .again => std.debug.panic("The socket should not be in nonblocking mode.", .{}),
                .conn_aborted => return,
            } else |err| {
                first_err = first_err orelse err;
                continue :cqe_loop;
            }

            const stream: std.net.Stream = .{ .handle = cqe.res };
            errdefer stream.close();

            server.wait_group.start();
            errdefer server.wait_group.finish();

            const buffer = try server.allocator.alloc(u8, server.read_buffer_size);
            errdefer server.allocator.free(buffer);

            const new_recv_entry: Entry = entry: {
                const data_ptr = try server.allocator.create(EntryData);
                errdefer comptime unreachable;

                data_ptr.* = .{ .recv = EntryData.State.INIT };
                break :entry .{ .ptr = data_ptr };
            };
            errdefer if (new_recv_entry.ptr) |data_ptr| server.allocator.destroy(data_ptr);

            _ = try linux.io_uring.recv(
                @bitCast(new_recv_entry),
                stream.handle,
                .{ .buffer = buffer },
                0,
            );

            continue :cqe_loop;
        };

        switch (entry_data.state) {
            .recv => |*recv_data| {
                if (connection.handleRecvResult(cqe.err())) |accept_result| switch (accept_result) {
                    .success => {},

                    .intr => std.debug.panic("TODO: how to handle interrupts on this?", .{}), // TODO:
                    .again => std.debug.panic("The socket should not be in nonblocking mode.", .{}),

                    .conn_refused,
                    .conn_reset,
                    .timed_out,
                    => |tag| {
                        if (connection.getSockName(recv_data.stream.handle)) |addr|
                            server.logger.warn().logf("{s} ({})", .{ @tagName(tag), addr })
                        else |_|
                            server.logger.warn().logf("{s} (unnamed connection?)", .{@tagName(tag)});
                        entry.deinit(server.allocator);
                        continue :cqe_loop;
                    },
                } else |err| {
                    server.logger.err().logf("{s}", .{@errorName(err)});
                    first_err = first_err orelse err;
                    entry.deinit(server.allocator);
                    continue :cqe_loop;
                }

                const recv_len: usize = @intCast(cqe.res);
                const body = switch (recv_data.*) {
                    .head => |*head| body: {
                        std.debug.assert(head.parser.state != .finished);

                        const recv_start = head.end;
                        const recv_end = recv_start + recv_len;
                        head.end += head.parser.feed(recv_data.buffer[recv_start..recv_end]);

                        if (head.parser.state != .finished) {
                            std.debug.assert(head.end == recv_end);

                            if (head.end == recv_data.buffer.len) {
                                std.debug.panic("TODO: handle a too-big head", .{}); // TODO:
                            }

                            _ = try linux.io_uring.recv(
                                @bitCast(entry),
                                recv_data.stream.handle,
                                .{ .buffer = recv_data.buffer[head.end..] },
                                0,
                            );
                            continue :cqe_loop;
                        }

                        const method: std.http.Method, //
                        const target: std.BoundedArray(u8, requests.MAX_TARGET_LEN), //
                        const content_len: ?usize //
                        = blk: {
                            const head_bytes = recv_data.buffer[0..head.end];
                            const parsed_head = std.http.Server.Request.Head.parse(head_bytes) catch |err| {
                                server.logger.err().logf("{s}", .{@errorName(err)});
                                first_err = first_err orelse err;
                                entry.deinit(server.allocator);
                                continue :cqe_loop;
                            };

                            var target: std.BoundedArray(u8, requests.MAX_TARGET_LEN) = .{};
                            target.appendSlice(parsed_head.target) catch {
                                if (connection.getSockName(recv_data.stream.handle)) |addr|
                                    server.logger.err().logf("{} requested a target '{s}', too long", .{ addr, parsed_head.target })
                                else |_|
                                    server.logger.err().logf("Unnamed connection requested a target '{s}', too long", .{parsed_head.target});
                                entry.deinit(server.allocator);
                                continue :cqe_loop;
                            };

                            if (parsed_head.transfer_encoding != .none) std.debug.panic("TODO: handle", .{}); // TODO:
                            if (parsed_head.transfer_compression != .identity) std.debug.panic("TODO: handle", .{}); // TODO:

                            break :blk .{ parsed_head.method, target, parsed_head.content_length };
                        };

                        const content_end = blk: {
                            const old_content_bytes = recv_data.buffer[head.end..recv_end];
                            std.mem.copyForwards(
                                u8,
                                recv_data.buffer[0..old_content_bytes.len],
                                old_content_bytes,
                            );
                            break :blk old_content_bytes.len;
                        };

                        if (content_len) |len| {
                            if (len < content_end) {
                                server.logger.err().logf(
                                    "HTTP Request body ({}) longer than declared content_length {}",
                                    .{
                                        std.fmt.fmtIntSizeDec(content_end),
                                        std.fmt.fmtIntSizeDec(len),
                                    },
                                );
                                first_err = first_err orelse error.RequestBodyTooLong;
                                entry.deinit(server.allocator);
                                continue :cqe_loop;
                            }

                            if (len > recv_data.buffer.len) {
                                std.debug.assert(len >= content_end);
                                if (server.allocator.resize(recv_data.buffer, len)) {
                                    recv_data.buffer.len = len;
                                } else {
                                    const new_mem = try server.allocator.alloc(u8, len);
                                    server.allocator.free(recv_data.buffer);
                                    recv_data.buffer = new_mem;
                                }
                            }
                        }

                        recv_data.* = .{ .body = .{
                            .head_method = method,
                            .head_target = target,
                            .content_len = content_len,
                            .end = content_end,
                        } };
                        const body = &recv_data.state.body;

                        if (content_len) |len| {
                            if (len == body.end) break :body body;
                            _ = try linux.io_uring.recv(
                                @bitCast(entry),
                                recv_data.stream.handle,
                                .{ .buffer = recv_data.buffer[content_end..] },
                                0,
                            );
                            continue :cqe_loop;
                        } else {
                            if (body.end != 0) server.logger.warn().logf( //
                                "HTTP request sent unexpected body without content_length." ++
                                " Ignoring." //
                            , .{});
                            break :body body;
                        }
                    },
                    .body => |*body| body: {
                        body.end += recv_len;
                        break :body body;
                    },
                };

                if (body.content_len) |len| {
                    if (body.end < len) {
                        _ = try linux.io_uring.recv(
                            @bitCast(entry),
                            recv_data.stream.handle,
                            .{ .buffer = recv_data.buffer[body.end..len] },
                            0,
                        );
                        continue :cqe_loop;
                    }
                }

                const content_bytes: []const u8 = recv_data.buffer[0..body.end];
                switch (body.head_method) {
                    .GET => {
                        if (content_bytes.len != 0) {
                            if (connection.getSockName(recv_data.stream.handle)) |addr| {
                                server.logger.warn().logf(
                                    "{} sent a GET request with" ++
                                        " a non-empty body ({}).",
                                    .{ addr, std.fmt.fmtIntSizeDec(content_bytes.len) },
                                );
                            } else |_| {
                                server.logger.warn().logf(
                                    "Unnamed connection sent a GET request with" ++
                                        " a non-empty body ({}).",
                                    .{std.fmt.fmtIntSizeDec(content_bytes.len)},
                                );
                            }
                        }

                        switch (requests.getRequestTargetResolve(
                            server.logger,
                            body.head_target.constSlice(),
                            server.latest_snapshot_gen_info,
                        )) {
                            inline .full_snapshot, .inc_snapshot => |pair| {
                                const snap_info, var full_info_lg = pair;
                                errdefer full_info_lg.unlock();

                                const archive_name_bounded = snap_info.snapshotArchiveName();
                                const archive_name = archive_name_bounded.constSlice();

                                const snapshot_dir = server.snapshot_dir;
                                const archive_file = try snapshot_dir.openFile(archive_name, .{});
                                errdefer archive_file.close();
                                const file_size = try archive_file.getEndPos();

                                const pipe_r, const pipe_w = try std.posix.pipe();
                                errdefer std.posix.close(pipe_w);
                                errdefer std.posix.close(pipe_r);

                                entry_data.state = .{ .send = .{
                                    .file_lg = full_info_lg,
                                    .file = archive_file,
                                    .file_size = file_size,

                                    .pipe_w = pipe_w,
                                    .pipe_r = pipe_r,

                                    .spliced_to_pipe = 0,
                                    .spliced_to_socket = 0,
                                    .which = .to_pipe,
                                } };
                                const send_data = &entry_data.state.send;
                                try send_data.prepSpliceFileToSocket(entry, &linux.io_uring);

                                continue :cqe_loop;
                            },
                            .unrecognized => {},
                        }
                    },

                    .POST => {},
                    else => {},
                }

                @panic("TODO: handle unhandled"); // TODO:
            },
            .send => |*send_data| switch (send_data.which) {
                .to_pipe => {
                    if (connection.handleSpliceResult(cqe.err())) |accept_result| switch (accept_result) {
                        .success => {},
                        .again => std.debug.panic("The socket should not be in nonblocking mode.", .{}),
                    } else |err| {
                        server.logger.err().logf("{s}", .{@errorName(err)});
                        first_err = first_err orelse err;
                        entry.deinit(server.allocator);
                        continue :cqe_loop;
                    }

                    send_data.spliced_to_pipe += @intCast(cqe.res);
                    send_data.which = .to_socket;
                },
                .to_socket => {
                    if (connection.handleSpliceResult(cqe.err())) |accept_result| switch (accept_result) {
                        .success => {},
                        .again => std.debug.panic("The socket should not be in nonblocking mode.", .{}),
                    } else |err| {
                        server.logger.err().logf("{s}", .{@errorName(err)});
                        first_err = first_err orelse err;
                        entry.deinit(server.allocator);
                        continue :cqe_loop;
                    }

                    send_data.spliced_to_socket += @intCast(cqe.res);
                    send_data.which = .to_pipe;

                    if (send_data.spliced_to_socket == send_data.file_size) {
                        std.debug.assert(send_data.spliced_to_socket == send_data.spliced_to_pipe);
                        entry.deinit(server.allocator);
                    } else {
                        try send_data.prepSpliceFileToSocket(entry, &linux.io_uring);
                    }

                    continue :cqe_loop;
                },
            },
        }
    }

    return first_err orelse {};
}

pub const Entry = packed struct(u64) {
    /// If null, this is an `accept` entry.
    ptr: ?*EntryData,

    pub const ACCEPT: Entry = .{ .ptr = null };

    pub fn deinit(entry: Entry, allocator: std.mem.Allocator) void {
        const ptr = entry.ptr orelse return;
        ptr.deinit(allocator);
        allocator.destroy(ptr);
    }
};

pub const EntryData = struct {
    buffer: []u8,
    stream: std.net.Stream,
    state: State,

    fn init(buffer: []u8, stream: std.net.Stream) Entry {
        return .{
            .buffer = buffer,
            .stream = stream,
            .state = State.INIT,
        };
    }

    fn deinit(data: *EntryData, allocator: std.mem.Allocator) void {
        data.state.deinit();
        allocator.free(data.buffer);
        data.stream.close();
    }

    pub const State = union(enum) {
        recv: Recv,
        send: Send,

        pub const INIT: State = .{
            .recv = .{
                .head = .{
                    .end = 0,
                    .parser = .{},
                },
            },
        };

        pub fn deinit(state: *State) void {
            switch (state) {
                .recv => {},
                .send => |*send_data| send_data.deinit(),
            }
        }

        pub const Recv = union(enum) {
            head: Head,
            body: Body,

            pub const Head = struct {
                end: usize,
                parser: std.http.HeadParser,
            };

            pub const Body = struct {
                head_method: std.http.Method,
                head_target: std.BoundedArray(u8, requests.MAX_TARGET_LEN),
                content_len: ?usize,
                end: usize,
            };
        };

        pub const Send = struct {
            file_lg: requests.GetRequestTargetResolved.SnapshotReadLock,
            file: std.fs.File,
            file_size: u64,

            pipe_w: std.os.linux.fd_t,
            pipe_r: std.os.linux.fd_t,

            spliced_to_pipe: u64,
            spliced_to_socket: u64,
            which: Which,

            pub const Which = enum {
                to_pipe,
                to_socket,
            };

            pub fn deinit(self: *Send) void {
                self.file.close();
                self.file_lg.unlock();
                std.posix.close(self.pipe_w);
                std.posix.close(self.pipe_r);
            }

            fn prepSpliceFileToSocket(self: *const Send, entry: Entry, io_uring: *IoUring) !void {
                std.debug.assert(self == &entry.ptr.?.state.send);
                const stream = entry.ptr.?.stream;
                const splice1_sqe = try io_uring.splice(
                    @bitCast(entry),
                    self.file.handle,
                    self.spliced_to_pipe,
                    self.pipe_w,
                    std.math.maxInt(u64),
                    self.file_size - self.spliced_to_pipe,
                );
                splice1_sqe.flags |= std.os.linux.IOSQE_IO_LINK;

                const splice2_sqe = try io_uring.splice(
                    @bitCast(entry),
                    self.pipe_r,
                    std.math.maxInt(u64),
                    stream.handle,
                    std.math.maxInt(u64),
                    self.file_size - self.spliced_to_socket,
                );
                _ = splice2_sqe;
            }
        };
    };
};
