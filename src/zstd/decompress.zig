const std = @import("std");
const c = @import("c.zig");
const InBuffer = @import("types.zig").InBuffer;
const OutBuffer = @import("types.zig").OutBuffer;
const ResetDirective = @import("types.zig").ResetDirective;
const isError = @import("error.zig").isError;
const Error = @import("error.zig").Error;
const checkError = @import("error.zig").checkError;
const testing = std.testing;

/// When compressing many times,
/// it is recommended to allocate a context just once,
/// and re-use it for each successive compression operation.
/// This will make workload friendlier for system's memory.
/// NOTE:
/// - re-using context is just a speed / resource optimization.
///   It doesn't change the compression ratio, which remains identical.
/// - In multi-threaded environments,
///   use one different context per thread for parallel execution.
pub const Decompressor = struct {
    handle: *c.ZSTD_DCtx,

    pub const Parameters = struct {
        /// Select a size limit (in power of 2) beyond which
        /// the streaming API will refuse to allocate memory buffer
        /// in order to protect the host from unreasonable memory requirements.
        /// This parameter is only useful in streaming mode, since no internal buffer is allocated in single-pass mode.
        /// By default, a decompression context accepts window sizes <= (`1 << window_log_limit_default`).
        /// 0 means use default maximum window_log
        window_log_max: i32 = 0,
    };

    pub fn init(params: Parameters) error{ InvalidParameters, OutOfMemory }!Decompressor {
        const h = c.ZSTD_createDCtx() orelse return error.OutOfMemory;
        if (isError(c.ZSTD_DCtx_setParameter(h, 100, params.window_log_max))) return error.InvalidParameters;
        return Decompressor{ .handle = h };
    }

    pub fn deinit(self: Decompressor) void {
        _ = c.ZSTD_freeDCtx(self.handle);
    }

    // no worries. `error.Generic` is unreachable
    pub fn reset(self: Decompressor, directive: ResetDirective) error{WrongStage}!void {
        if (isError(c.ZSTD_DCtx_reset(self.handle, @intFromEnum(directive))))
            return error.WrongStage;
    }

    pub fn decompress(self: Decompressor, dest: []u8, src: []const u8) Error![]const u8 {
        return dest[0..try checkError(c.ZSTD_decompressDCtx(
            self.handle,
            @as(*anyopaque, @ptrCast(dest)),
            dest.len,
            @as(*const anyopaque, @ptrCast(src)),
            src.len,
        ))];
    }

    pub fn decompressUsingDict(self: Decompressor, dest: []u8, src: []const u8, dict: DDictionary) Error![]const u8 {
        return dest[0..try checkError(c.ZSTD_decompress_usingDDict(
            self.handle,
            @as(*anyopaque, @ptrCast(dest)),
            dest.len,
            @as(*const anyopaque, @ptrCast(src)),
            src.len,
            dict.handle,
        ))];
    }

    pub fn decompressStream(self: Decompressor, in: *InBuffer, out: *OutBuffer) Error!usize {
        return checkError(c.ZSTD_decompressStream(
            self.handle,
            @as([*c]c.ZSTD_outBuffer, @ptrCast(out)),
            @as([*c]c.ZSTD_inBuffer, @ptrCast(in)),
        ));
    }

    /// Recommended size for input buffer.
    pub fn recommInSize() usize {
        return c.ZSTD_DStreamInSize();
    }

    /// Recommended size for output buffer.
    /// Guarantee to successfully flush at least one complete block in all circumstances
    pub fn recommOutSize() usize {
        return c.ZSTD_DStreamOutSize();
    }
};

pub const DDictionary = struct {
    handle: *c.ZSTD_DDict,

    pub fn init(buf: []const u8) ?DDictionary {
        return .{ .handle = c.ZSTD_createDDict(@as(*const anyopaque, @ptrCast(buf)), buf.len) orelse return null };
    }

    pub fn deinit(self: DDictionary) void {
        _ = c.ZSTD_freeDDict(self.handle);
    }

    pub fn getID(self: DDictionary) u32 {
        return c.ZSTD_getDictID_fromDDict(self.handle);
    }
};

/// `src.len` must be the _exact_ size of some number of compressed and/or skippable frames.
/// `dest.len` is an upper bound of originalSize to regenerate.
/// If user cannot imply a maximum upper bound, it's better to use streaming mode to decompress data.
/// Returns an slice of written data, which points to `dest`
pub fn decompress(dest: []u8, src: []const u8) Error![]const u8 {
    return dest[0..try checkError(c.ZSTD_decompress(
        @as(*anyopaque, @ptrCast(dest)),
        dest.len,
        @as(*const anyopaque, @ptrCast(src)),
        src.len,
    ))];
}
