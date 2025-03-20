//! This file defines most of the shared logic for the bounds and handling
//! of RPC requests.

const std = @import("std");
const sig = @import("../../sig.zig");

const SnapshotGenerationInfo = sig.accounts_db.AccountsDB.SnapshotGenerationInfo;
const FullSnapshotFileInfo = sig.accounts_db.snapshots.FullSnapshotFileInfo;
const IncrementalSnapshotFileInfo = sig.accounts_db.snapshots.IncrementalSnapshotFileInfo;

/// A single request body cannot be larger than this;
/// a single chunk in a chunked request body cannot be larger than this,
/// but all together they may be allowed to be larger than this,
/// depending on the request.
pub const MAX_REQUEST_BODY_SIZE: usize = 50 * 1024; // 50 KiB

const LOGGER_SCOPE = "rpc.server.requests";

pub const ContentType = enum(u8) {
    @"application/json",
};

pub const TargetBoundedStr = std.BoundedArray(u8, MAX_TARGET_LEN);
pub const MAX_TARGET_LEN: usize = blk: {
    const SnapSpec = IncrementalSnapshotFileInfo.SnapshotArchiveNameFmtSpec;
    break :blk "/".len + SnapSpec.fmtLenValue(.{
        .base_slot = std.math.maxInt(sig.core.Slot),
        .slot = std.math.maxInt(sig.core.Slot),
        .hash = sig.core.Hash.base58String(.{ .data = .{255} ** sig.core.Hash.SIZE }).constSlice(),
    });
};

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
        // at the time of writing, this always holds true for the result of `Head.parse`.
        std.debug.assert(parsed_head.compression == .none);
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

pub const GetRequestTargetResolved = union(enum) {
    full_snapshot: struct { FullSnapshotFileInfo, SnapshotReadLock },
    inc_snapshot: struct { IncrementalSnapshotFileInfo, SnapshotReadLock },

    /// https://github.com/Syndica/sig/issues/558
    health,

    /// https://github.com/Syndica/sig/issues/557
    genesis_file,

    not_found,

    pub const SnapshotReadLock = sig.sync.RwMux(?SnapshotGenerationInfo).RLockGuard;
};

/// Resolve a `GET` request target.
pub fn getRequestTargetResolve(
    unscoped_logger: sig.trace.Logger,
    path: []const u8,
    latest_snapshot_gen_info_rw: *sig.sync.RwMux(?SnapshotGenerationInfo),
) GetRequestTargetResolved {
    const logger = unscoped_logger.withScope(LOGGER_SCOPE);

    if (!std.mem.startsWith(u8, path, "/")) return .not_found;
    const target = path[1..];

    const is_snapshot_archive_like =
        !std.meta.isError(FullSnapshotFileInfo.parseFileNameTarZst(target)) or
        !std.meta.isError(IncrementalSnapshotFileInfo.parseFileNameTarZst(target));

    if (is_snapshot_archive_like) check_snapshots: {
        const maybe_latest_snapshot_gen_info, //
        var latest_snapshot_info_lg //
        = latest_snapshot_gen_info_rw.readWithLock();
        defer latest_snapshot_info_lg.unlock();

        const full_info: FullSnapshotFileInfo, //
        const inc_info: ?IncrementalSnapshotFileInfo //
        = blk: {
            const latest_snapshot_gen_info = maybe_latest_snapshot_gen_info.* orelse
                break :check_snapshots;
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
            full_info.snapshotArchiveName().constSlice(),
        });
        logger.debug().logf("Available inc: {?s}", .{
            if (inc_info) |info| info.snapshotArchiveName().constSlice() else null,
        });

        const full_archive_name_bounded = full_info.snapshotArchiveName();
        const full_archive_name = full_archive_name_bounded.constSlice();
        if (std.mem.eql(u8, target, full_archive_name)) {
            // acquire another lock on the rwmux, since the first one we got is going to unlock after we return.
            const latest_snapshot_info_lg_again = latest_snapshot_gen_info_rw.read();
            return .{
                .full_snapshot = .{
                    full_info,
                    latest_snapshot_info_lg_again,
                },
            };
        }

        if (inc_info) |inc| {
            const inc_archive_name_bounded = inc.snapshotArchiveName();
            const inc_archive_name = inc_archive_name_bounded.constSlice();
            if (std.mem.eql(u8, target, inc_archive_name)) {
                // acquire another lock on the rwmux, since the first one we got is going to unlock after we return.
                const latest_snapshot_info_lg_again = latest_snapshot_gen_info_rw.read();
                return .{ .inc_snapshot = .{ inc, latest_snapshot_info_lg_again } };
            }
        }
    }

    if (std.mem.eql(u8, target, "health")) {
        return .health;
    }

    return .not_found;
}

pub fn methodFmt(method: std.http.Method) MethodFmt {
    return .{ .method = method };
}

pub const MethodFmt = struct {
    method: std.http.Method,
    pub fn format(
        self: MethodFmt,
        comptime fmt_str: []const u8,
        fmt_options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = fmt_options;
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, self);
        try self.method.write(writer);
    }
};
