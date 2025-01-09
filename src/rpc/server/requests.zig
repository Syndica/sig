//! This file defines most of the shared logic for the bounds and handling
//! of RPC requests.

const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");
const connection = @import("connection.zig");

const IoUring = std.os.linux.IoUring;

const ServerCtx = sig.rpc.server.Context;
const SnapshotGenerationInfo = sig.accounts_db.AccountsDB.SnapshotGenerationInfo;
const FullSnapshotFileInfo = sig.accounts_db.snapshots.FullSnapshotFileInfo;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo;

/// A single request body cannot be larger than this;
/// a single chunk in a chunked request body cannot be larger than this,
/// but all together they may be allowed to be larger than this,
/// depending on the request.
pub const MAX_REQUEST_BODY_SIZE: usize = 50 * 1024; // 50 KiB

/// All of the relevant information from a request head parsed into a narrow
/// format that is comprised of bounded data and can be copied by value.
pub const HeadInfo = struct {
    method: std.http.Method,
    target: TargetBoundedStr,
    content_len: ?u64,
    content_type: ?ContentType,
    transfer_encoding: std.http.TransferEncoding,
    content_encoding: std.http.ContentEncoding,

    const StdHead = std.http.Server.Request.Head;

    pub const ParseError = StdHead.ParseError || ParseFromStdHeadError;

    pub fn parse(head_bytes: []const u8) ParseError!HeadInfo {
        const parsed_head = try StdHead.parse(head_bytes);
        std.debug.assert(parsed_head.compression == .none); // at the time of writing, this always holds true for the result of `Head.parse`.
        return try parseFromStdHead(parsed_head);
    }

    pub const ParseFromStdHeadError = error{
        RequestTargetTooLong,
        RequestContentTypeUnrecognized,
    };

    pub fn parseFromStdHead(std_head: StdHead) ParseFromStdHeadError!HeadInfo {
        // TODO: should we care about these?
        _ = std_head.version;
        _ = std_head.expect;
        _ = std_head.keep_alive;

        const target = TargetBoundedStr.fromSlice(std_head.target) catch
            return error.RequestTargetTooLong;

        const content_type: ?ContentType = ct: {
            const str = std_head.content_type orelse break :ct null;
            break :ct std.meta.stringToEnum(ContentType, str) orelse
                return error.RequestContentTypeUnrecognized;
        };

        return .{
            .method = std_head.method,
            .target = target,
            .content_len = std_head.content_length,
            .content_type = content_type,
            .transfer_encoding = std_head.transfer_encoding,
            .content_encoding = std_head.transfer_compression,
        };
    }
};

pub const ContentType = enum(u8) {
    @"application/json",
};

pub const MAX_TARGET_LEN: usize = blk: {
    const SnapSpec = IncrementalSnapshotFileInfo.SnapshotArchiveNameFmtSpec;
    break :blk "/".len + SnapSpec.fmtLenValue(.{
        .base_slot = std.math.maxInt(sig.core.Slot),
        .slot = std.math.maxInt(sig.core.Slot),
        .hash = sig.core.Hash.base58String(.{ .data = .{255} ** sig.core.Hash.size }).constSlice(),
    });
};
pub const TargetBoundedStr = std.BoundedArray(u8, MAX_TARGET_LEN);

pub const GetRequestTargetResolved = union(enum) {
    unrecognized,
    full_snapshot: struct { FullSnapshotFileInfo, SnapshotReadLock },
    inc_snapshot: struct { IncrementalSnapshotFileInfo, SnapshotReadLock },

    // TODO: also handle the snapshot archive aliases & other routes

    pub const SnapshotReadLock = sig.sync.RwMux(?SnapshotGenerationInfo).RLockGuard;
};

/// Resolve a `GET` request target.
pub fn getRequestTargetResolve(
    logger: ServerCtx.ScopedLogger,
    target: []const u8,
    latest_snapshot_gen_info_rw: *sig.sync.RwMux(?SnapshotGenerationInfo),
) GetRequestTargetResolved {
    if (!std.mem.startsWith(u8, target, "/")) return .unrecognized;
    const path = target[1..];

    const is_snapshot_archive_like =
        !std.meta.isError(FullSnapshotFileInfo.parseFileNameTarZst(path)) or
        !std.meta.isError(IncrementalSnapshotFileInfo.parseFileNameTarZst(path));

    if (is_snapshot_archive_like) {
        // we hold the lock for the entirety of this process in order to prevent
        // the snapshot generation process from deleting the associated snapshot.
        const maybe_latest_snapshot_gen_info, //
        var latest_snapshot_info_lg //
        = latest_snapshot_gen_info_rw.readWithLock();
        errdefer latest_snapshot_info_lg.unlock();

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
            if (full_info) |info| info.snapshotArchiveName().constSlice() else null,
        });
        logger.debug().logf("Available inc: {?s}", .{
            if (inc_info) |info| info.snapshotArchiveName().constSlice() else null,
        });

        if (full_info) |full| {
            const full_archive_name_bounded = full.snapshotArchiveName();
            const full_archive_name = full_archive_name_bounded.constSlice();
            if (std.mem.eql(u8, path, full_archive_name)) {
                return .{ .full_snapshot = .{ full, latest_snapshot_info_lg } };
            }
        }

        if (inc_info) |inc| {
            const inc_archive_name_bounded = inc.snapshotArchiveName();
            const inc_archive_name = inc_archive_name_bounded.constSlice();
            if (std.mem.eql(u8, path, inc_archive_name)) {
                return .{ .inc_snapshot = .{ inc, latest_snapshot_info_lg } };
            }
        }
    }

    return .unrecognized;
}

pub const HandleRequestError =
    std.fs.File.OpenError ||
    std.http.Server.Response.WriteError ||
    std.fs.File.GetSeekPosError ||
    std.fs.File.ReadError;

pub fn handleRequest(
    logger: ServerCtx.ScopedLogger,
    request: *std.http.Server.Request,
    snapshot_dir: std.fs.Dir,
    latest_snapshot_gen_info_rw: *sig.sync.RwMux(?SnapshotGenerationInfo),
) !void {
    const conn_address = request.server.connection.address;
    logger.info().logf("Responding to request from {}: {} {s}", .{
        conn_address, methodFmt(request.head.method), request.head.target,
    });

    switch (request.head.method) {
        .HEAD, .GET => switch (getRequestTargetResolve(
            logger,
            request.head.target,
            latest_snapshot_gen_info_rw,
        )) {
            inline .full_snapshot, .inc_snapshot => |pair| {
                const snap_info, var full_info_lg = pair;
                defer full_info_lg.unlock();

                const archive_name_bounded = snap_info.snapshotArchiveName();
                const archive_name = archive_name_bounded.constSlice();

                const archive_file = try snapshot_dir.openFile(archive_name, .{});
                defer archive_file.close();

                const archive_len = try archive_file.getEndPos();

                var send_buffer: [4096]u8 = undefined;
                var response = request.respondStreaming(.{
                    .send_buffer = &send_buffer,
                    .content_length = archive_len,
                    .respond_options = .{},
                });

                if (!response.elide_body) {
                    // use a length which is still a multiple of 2, greater than the send_buffer length,
                    // in order to almost always force the http server method to flush, instead of
                    // pointlessly copying data into the send buffer.
                    const read_buffer_len = comptime std.mem.alignForward(usize, send_buffer.len + 1, 2);
                    var read_buffer: [read_buffer_len]u8 = undefined;

                    while (true) {
                        const file_data_len = try archive_file.read(&read_buffer);
                        if (file_data_len == 0) break;
                        const file_data = read_buffer[0..file_data_len];
                        try response.writeAll(file_data);
                    }
                } else {
                    std.debug.assert(response.transfer_encoding.content_length == archive_len);
                    // NOTE: in order to avoid needing to actually spend time writing the response body,
                    // just trick the API into thinking we already wrote the entire thing by setting this
                    // to 0.
                    response.transfer_encoding.content_length = 0;
                }

                try response.end();
                return;
            },
            .unrecognized => {},
        },
        .POST => {
            logger.err().logf("{} tried to invoke our RPC", .{conn_address});
            return try request.respond("RPCs are not yet implemented", .{
                .status = .service_unavailable,
                .keep_alive = false,
            });
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

pub fn methodFmt(method: std.http.Method) MethodFmt {
    return .{ .method = method };
}

pub const MethodFmt = struct {
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
