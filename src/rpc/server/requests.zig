const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");
const connection = @import("connection.zig");

const IoUring = std.os.linux.IoUring;

const Server = sig.rpc.Server;
const SnapshotGenerationInfo = sig.accounts_db.AccountsDB.SnapshotGenerationInfo;
const FullSnapshotFileInfo = sig.accounts_db.snapshots.FullSnapshotFileInfo;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo;

pub const MAX_TARGET_LEN: usize = blk: {
    const SnapSpec = IncrementalSnapshotFileInfo.SnapshotArchiveNameFmtSpec;
    break :blk "/".len + SnapSpec.fmtLenValue(.{
        .base_slot = std.math.maxInt(sig.core.Slot),
        .slot = std.math.maxInt(sig.core.Slot),
        .hash = sig.core.Hash.base58String(.{ .data = .{255} ** sig.core.Hash.size }).constSlice(),
    });
};

pub const GetRequestTargetResolved = union(enum) {
    unrecognized,
    full_snapshot: struct { FullSnapshotFileInfo, SnapshotReadLock },
    inc_snapshot: struct { IncrementalSnapshotFileInfo, SnapshotReadLock },

    // TODO: also handle the snapshot archive aliases & other routes

    pub const SnapshotReadLock = sig.sync.RwMux(?SnapshotGenerationInfo).RLockGuard;
};

/// Resolve a `GET` request target.
pub fn getRequestTargetResolve(
    logger: Server.ScopedLogger,
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
    HttpResponseSendFileError;

pub fn handleRequest(
    logger: Server.ScopedLogger,
    request: *std.http.Server.Request,
    snapshot_dir: std.fs.Dir,
    latest_snapshot_gen_info_rw: *sig.sync.RwMux(?SnapshotGenerationInfo),
) !void {
    const conn_address = request.server.connection.address;
    logger.info().logf("Responding to request from {}: {} {s}", .{
        conn_address, methodFmt(request.head.method), request.head.target,
    });

    switch (request.head.method) {
        .GET => switch (getRequestTargetResolve(
            logger,
            request.head.target,
            latest_snapshot_gen_info_rw,
        )) {
            .unrecognized => {},
            inline .full_snapshot, .inc_snapshot => |pair| {
                const snap_info, var full_info_lg = pair;
                defer full_info_lg.unlock();

                const archive_name_bounded = snap_info.snapshotArchiveName();
                const archive_name = archive_name_bounded.constSlice();

                const archive_file = try snapshot_dir.openFile(archive_name, .{});
                defer archive_file.close();

                var send_buffer: [4096]u8 = undefined;
                try httpResponseSendFile(request, archive_file, &send_buffer);
                return;
            },
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

const HttpResponseSendFileError =
    std.fs.File.GetSeekPosError ||
    std.fs.File.SeekError ||
    std.http.Server.Response.WriteError ||
    std.fs.File.ReadError;

fn httpResponseSendFile(
    request: *std.http.Server.Request,
    archive_file: std.fs.File,
    send_buffer: []u8,
) HttpResponseSendFileError!void {
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
