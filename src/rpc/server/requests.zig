//! This file defines most of the shared logic for the bounds and handling
//! of RPC requests.

const std = @import("std");
const std14 = @import("std14");
const sig = @import("../../sig.zig");

const IncrementalSnapshotFileInfo = sig.accounts_db.snapshot.data.IncrementalSnapshotFileInfo;

/// A single request body cannot be larger than this.
pub const MAX_REQUEST_BODY_SIZE: usize = 50 * 1024; // 50 KiB

const Logger = sig.trace.Logger("rpc.server.requests");

pub const ContentType = enum(u8) {
    @"application/json",
};

pub const TargetBoundedStr = std14.BoundedArray(u8, MAX_TARGET_LEN);
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
    content_encoding: std.http.ContentEncoding,

    const StdHead = std.http.Server.Request.Head;

    pub const ParseFromStdHeadError = error{
        RequestTargetTooLong,
        RequestContentTypeUnrecognized,
        UnexpectedTransferEncoding,
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

        if (std_head.transfer_encoding != .none) {
            return error.UnexpectedTransferEncoding;
        }

        return .{
            .method = std_head.method,
            .target = target,
            .content_len = std_head.content_length,
            .content_type = content_type,
            .content_encoding = std_head.transfer_compression,
        };
    }
};

pub fn httpMethodFmt(method: std.http.Method) MethodFmt {
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
