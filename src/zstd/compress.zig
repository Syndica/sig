const std = @import("std");
const c = @import("c.zig");
const InBuffer = @import("types.zig").InBuffer;
const OutBuffer = @import("types.zig").OutBuffer;
const ResetDirective = @import("types.zig").ResetDirective;
const EndDirective = @import("types.zig").EndDirective;
const isError = @import("error.zig").isError;
const Error = @import("error.zig").Error;
const checkError = @import("error.zig").checkError;
const testing = std.testing;

// TODO: https://github.com/ziglang/zig/issues/12465
const ZSTD_CONTENTSIZE_UNKNOWN = @as(c_ulonglong, 0) -% @as(c_int, 1);
const ZSTD_CONTENTSIZE_ERROR = @as(c_ulonglong, 0) -% @as(c_int, 2);

pub const Strategy = enum(u4) {
    fast = 1,
    dfast = 2,
    greedy = 3,
    lazy = 4,
    lazy2 = 5,
    btlazy2 = 6,
    btopt = 7,
    btultra = 8,
    btultra2 = 9,
};

/// When compressing many times,
/// it is recommended to allocate a context just once,
/// and re-use it for each successive compression operation.
/// This will make workload friendlier for system's memory.
/// NOTE:
/// - re-using context is just a speed / resource optimization.
///   It doesn't change the compression ratio, which remains identical.
/// - In multi-threaded environments,
///   use one different context per thread for parallel execution.
pub const Compressor = struct {
    pub const Parameters = struct {
        /// Note that exact compression parameters are dynamically determined,
        /// depending on both compression level and srcSize (when known).
        /// 0 means use default (`defaultCompressionLevel()`)
        compression_level: i32 = 0,

        //
        // --- Advanced compression parameters ---
        //

        /// Maximum allowed back-reference distance, expressed as power of 2.
        /// This will set a memory budget for streaming decompression,
        /// with larger values requiring more memory
        /// and typically compressing more.
        /// Must be clamped between `window_log_min` and `window_log_max`.
        /// NOTE: Using a windowLog greater than `window_log_limit_default`
        ///       requires explicitly allowing such size at streaming decompression stage.
        /// 0 means use default
        window_log: i32 = 0,

        /// Size of the initial probe table, as a power of 2.
        /// Resulting memory usage is (`1 << (hash_log + 2)`).
        /// Must be clamped between `hash_log_min` and `hash_log_max`.
        /// Larger tables improve compression ratio of strategies <= `.dfast`,
        /// and improve speed of strategies > `.dfast`.
        /// 0 means use default
        hash_log: i32 = 0,

        /// Size of the multi-probe search table, as a power of 2.
        /// Resulting memory usage is (1 << (chain_log+2)).
        /// Must be clamped between `chain_log_min` and `chain_log_max`.
        /// Larger tables result in better and slower compression.
        /// This parameter is useless for `.fast` strategy.
        /// It's still useful when using `.dfast` strategy,
        /// in which case it defines a secondary probe table.
        /// 0 means use default
        chain_log: i32 = 0,

        /// Number of search attempts, as a power of 2.
        /// More attempts result in better and slower compression.
        /// This parameter is useless for `.fast` and `.dfast` strategies.
        /// 0 means use default
        search_log: i32 = 0,

        /// Minimum size of searched matches.
        /// Note that Zstandard can still find matches of smaller size,
        /// it just tweaks its search algorithm to look for this size and larger.
        /// Larger values increase compression and decompression speed, but decrease ratio.
        /// Must be clamped between `min_match_min` and `min_match_max`.
        /// Note that currently, for all strategies < `.btopt`, effective minimum is 4.
        ///                    , for all strategies > `.fast`, effective maximum is 6.
        /// 0 means use default (`minMatchLength()`)
        min_match: i32 = 0,

        /// Impact of this field depends on strategy.
        /// For strategies `.btopt`, `.btultra` & `.btultra2`:
        ///     Length of Match considered "good enough" to stop search.
        ///     Larger values make compression stronger, and slower.
        /// For strategy `.fast`:
        ///     Distance between match sampling.
        ///     Larger values make compression faster, and weaker.
        /// 0 means use default
        target_length: i32 = 0,

        /// The higher the value of selected strategy, the more complex it is,
        /// resulting in stronger and slower compression.
        strategy: ?Strategy = null,

        //
        // --- LDM mode parameters ---
        //

        /// Enable long distance matching.
        /// This parameter is designed to improve compression ratio
        /// for large inputs, by finding large matches at long distance.
        /// It increases memory usage and window size.
        /// Note: enabling this parameter increases default `window_log` to 128 MB
        /// except when expressly set to a different value.
        /// Note: will be enabled by default if `window_log` >= 128 MB and
        /// compression strategy >= `.btopt` (== compression level 16+)
        enable_long_distance_matching: ?bool = null,

        /// Size of the table for long distance matching, as a power of 2.
        /// Larger values increase memory usage and compression ratio,
        /// but decrease compression speed.
        /// Must be clamped between `hash_log_min` and `hash_log_max`
        /// 0 means automatically determine hashlog and
        /// `null` means use default (`window_log - 7`).
        ldm_hash_Log: ?i32 = 0,

        /// Minimum match size for long distance matcher.
        /// Larger/too small values usually decrease compression ratio.
        /// Must be clamped between `ldm_min_match_min` and `ldm_min_match_max`.
        /// 0 means use default value (default: 64).
        ldm_min_match: i32 = 0,

        /// Log size of each bucket in the LDM hash table for collision resolution.
        /// Larger values improve collision resolution but decrease compression speed.
        /// The maximum value is `ldm_bucket_size_log_max`.
        /// 0 means use default value (default: 3).
        ldm_bucket_size_log: i32 = 0,

        /// Frequency of inserting/looking up entries into the LDM hash table.
        /// Must be clamped between 0 and (`window_log_max - hash_log_min`).
        /// Default is MAX(0, (`window_log - ldm_hash_log`)), optimizing hash table usage.
        /// Larger values improve compression speed.
        /// Deviating far from default value will likely result in a compression ratio decrease.
        /// 0 means automatically determine hash_rate_log.
        ldm_hash_rate_log: i32 = 0,

        //
        // --- frame parameters ---
        //

        /// Content size will be written into frame header _whenever known_ (default: 1)
        /// Content size must be known at the beginning of compression.
        /// This is automatically the case when using `compress2()`,
        /// For streaming scenarios, content size must be provided with `Compressor.setPledgedSrcSize()`
        content_size_flag: i32 = 1,

        /// A 32-bits checksum of content is written at end of frame (default: 0)
        checksum_flag: i32 = 0,

        /// When applicable, dictionary's ID is written into frame header (default: 1)
        dict_id_flag: i32 = 1,

        //
        // --- multi-threading parameters ---
        // These parameters are only active if multi-threading is enabled (compiled with build macro `Options.multi_threading`).
        // Otherwise, trying to set any other value than default (0) will be a no-op and return an error.
        // In a situation where it's unknown if the linked library supports multi-threading or not,
        // setting `nb_workers` to any value >= 1 and consulting the return value provides a quick way to check this property.
        //

        /// Select how many threads will be spawned to compress in parallel.
        /// When `nb_workers` >= 1, triggers asynchronous mode when invoking `compressStream()` :
        /// `compressStream()` consumes input and flush output if possible, but immediately gives back control to caller,
        /// while compression is performed in parallel, within worker thread(s).
        /// (note : a strong exception to this rule is when first invocation of `compressStream2()` sets `.end`
        ///  in which case, `compressStream2()` delegates to `compress2()`, which is always a blocking call).
        /// More workers improve speed, but also increase memory usage.
        /// Default value is `0`, aka "single-threaded mode" : no worker is spawned,
        /// compression is performed inside Caller's thread, and all invocations are blocking
        nb_workers: i32 = 0,

        /// Size of a compression job. This value is enforced only when `nb_workers` >= 1.
        /// Each compression job is completed in parallel, so this value can indirectly impact the nb of active threads.
        /// 0 means default, which is dynamically determined based on compression parameters.
        /// Job size must be a minimum of overlap size, or ZSTDMT_JOBSIZE_MIN (= 512 KB), whichever is largest.
        /// The minimum size is automatically and transparently enforced.
        job_size: i32 = 0,

        /// Control the overlap size, as a fraction of window size.
        /// The overlap size is an amount of data reloaded from previous job at the beginning of a new job.
        /// It helps preserve compression ratio, while each job is compressed in parallel.
        /// This value is enforced only when `nb_workers` >= 1.
        /// Larger values increase compression ratio, but decrease speed.
        /// Possible values range from 0 to 9 :
        /// - 0 means "default" : value will be determined by the library, depending on strategy
        /// - 1 means "no overlap"
        /// - 9 means "full overlap", using a full window size.
        /// Each intermediate rank increases/decreases load size by a factor 2 :
        /// 9: full window;  8: w/2;  7: w/4;  6: w/8;  5:w/16;  4: w/32;  3:w/64;  2:w/128;  1:no overlap;  0:default
        /// default value varies between 6 and 9, depending on strategy
        overlap_log: i32 = 0,
    };

    handle: *c.ZSTD_CCtx,

    pub fn init(params: Parameters) error{ InvalidParameters, OutOfMemory }!Compressor {
        const h = c.ZSTD_createCCtx() orelse return error.OutOfMemory;

        if (isError(c.ZSTD_CCtx_setParameter(h, 100, params.compression_level))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 101, params.window_log))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 102, params.hash_log))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 103, params.chain_log))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 104, params.search_log))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 105, params.min_match))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 106, params.target_length))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 107, if (params.strategy) |v| @intFromEnum(v) else 0))) return error.InvalidParameters;

        if (params.enable_long_distance_matching) |v| // https://sourcegraph.com/github.com/facebook/zstd@e47e674cd09583ff0503f0f6defd6d23d8b718d3/-/blob/lib/zstd.h?L1322
            if (isError(c.ZSTD_CCtx_setParameter(h, 160, if (v) 1 else 2))) return error.InvalidParameters;
        if (params.ldm_hash_Log) |v|
            if (isError(c.ZSTD_CCtx_setParameter(h, 161, v))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 162, params.ldm_min_match))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 163, params.ldm_bucket_size_log))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 164, params.ldm_hash_rate_log))) return error.InvalidParameters;

        if (isError(c.ZSTD_CCtx_setParameter(h, 200, params.content_size_flag))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 201, params.checksum_flag))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 202, params.dict_id_flag))) return error.InvalidParameters;

        if (isError(c.ZSTD_CCtx_setParameter(h, 400, params.nb_workers))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 401, params.job_size))) return error.InvalidParameters;
        if (isError(c.ZSTD_CCtx_setParameter(h, 402, params.overlap_log))) return error.InvalidParameters;

        return Compressor{ .handle = h };
    }

    pub fn deinit(self: Compressor) void {
        _ = c.ZSTD_freeCCtx(self.handle);
    }

    // no worries. `error.Generic` is unreachable
    pub fn reset(self: Compressor, directive: ResetDirective) error{WrongStage}!void {
        if (isError(c.ZSTD_CCtx_reset(self.handle, @intFromEnum(directive))))
            return error.WrongStage;
    }

    /// Important: in order to behave similarly to `compress()`,
    /// this function compresses at requested compression level,
    /// __ignoring any other parameter__.
    /// If any advanced parameter was set using the advanced API,
    /// they will all be reset. Only `compression_level` remains.
    pub fn compress(self: Compressor, dest: []u8, src: []const u8, compression_level: i32) Error![]const u8 {
        return dest[0..try checkError(c.ZSTD_compressCCtx(
            self.handle,
            @as(*anyopaque, @ptrCast(dest)),
            dest.len,
            @as(*const anyopaque, @ptrCast(src)),
            src.len,
            @as(c_int, @intCast(compression_level)),
        ))];
    }

    /// Behave the same as `Compressor.compress()`, but compression parameters are set using the advanced API.
    /// `Compressor.compress2()` always starts a new frame.
    /// Should `self` hold data from a previously unfinished frame, everything about it is forgotten.
    /// - Compression parameters are pushed into `Compressor` before starting compression
    /// - The function is always blocking, returns when compression is completed.
    /// Hint: compression runs faster if `dest.len` >=  `compressBound(src_size)`.
    /// Returns an slice of written data, which points to `dest`.
    pub fn compress2(self: Compressor, dest: []u8, src: []const u8) Error![]const u8 {
        return dest[0..try checkError(c.ZSTD_compress2(
            self.handle,
            @as(*anyopaque, @ptrCast(dest)),
            dest.len,
            @as(*const anyopaque, @ptrCast(src)),
            src.len,
        ))];
    }

    /// Compression using a digested Dictionary.
    /// Recommended when same dictionary is used multiple times.
    /// Note: compression level is _decided at dictionary creation time_,
    ///       and frame parameters are hardcoded (dictID=yes, contentSize=yes, checksum=no)
    pub fn compressUsingDict(self: Compressor, dest: []u8, src: []const u8, dict: CDictionary) Error![]const u8 {
        return dest[0..try checkError(c.ZSTD_compress_usingCDict(
            self.handle,
            @as(*anyopaque, @ptrCast(dest)),
            dest.len,
            @as(*const anyopaque, @ptrCast(src)),
            src.len,
            dict.handle,
        ))];
    }

    /// - Compression parameters cannot be changed once compression is started (save a list of exceptions in multi-threading mode)
    /// - `output.pos` must be <= dstCapacity, `input.pos` must be <= `src.len`
    /// - `output.pos` and `input.pos` will be updated. They are guaranteed to remain below their respective limit.
    /// - endOp must be a valid directive
    /// - When `nb_workers` == 0 (default), function is blocking : it completes its job before returning to caller.
    /// - When `nb_workers` >= 1, function is non-blocking: it copies a portion of input, distributes jobs to internal worker threads, flush to output whatever is available,
    ///                                                 and then immediately returns, just indicating that there is some data remaining to be flushed.
    ///                                                 The function nonetheless guarantees forward progress : it will return only after it reads or write at least 1+ byte.
    /// - Exception : if the first call requests a `.end` directive and provides enough dstCapacity, the function delegates to `Compressor.compress2()` which is always blocking.
    /// - Return provides a minimum amount of data remaining to be flushed from internal buffers
    ///           or an error code, which can be tested using `isError()`.
    ///           if _Return_ != 0, flush is not fully completed, there is still some data left within internal buffers.
    ///           This is useful for `.flush`, since in this case more flushes are necessary to empty all buffers.
    ///           For `.end`, _Return_ == 0 when internal buffers are fully flushed and frame is completed.
    /// - after a `.end` directive, if internal buffer is not fully flushed (_Return_ != 0),
    ///           only `.end` or `.flush` operations are allowed.
    ///           Before starting a new compression job, or changing compression parameters,
    ///           it is required to fully flush internal buffers.
    pub fn compressStream(self: Compressor, in: *InBuffer, out: *OutBuffer, end_directive: EndDirective) Error!usize {
        return checkError(c.ZSTD_compressStream2(
            self.handle,
            @as([*c]c.ZSTD_outBuffer, @ptrCast(out)),
            @as([*c]c.ZSTD_inBuffer, @ptrCast(in)),
            @intFromEnum(end_directive),
        ));
    }

    /// Recommended size for input buffer.
    pub fn recommInSize() usize {
        return c.ZSTD_CStreamInSize();
    }

    /// Recommended size for output buffer.
    /// Guarantee to successfully flush at least one complete compressed block.
    pub fn recommOutSize() usize {
        return c.ZSTD_CStreamOutSize();
    }

    pub fn setPledgedSrcSize(self: Compressor, size: usize) error{WrongStage}!void {
        if (isError(c.ZSTD_CCtx_setPledgedSrcSize(self.handle, size)))
            return error.WrongStage;
    }
};

pub const CDictionary = struct {
    handle: *c.ZSTD_CDict,

    /// When compressing multiple messages or blocks using the same dictionary,
    /// it's recommended to digest the dictionary only once, since it's a costly operation.
    /// `Dictionary.init()` will create a state from digesting a dictionary.
    /// The resulting state can be used for future compression operations with very limited startup cost.
    /// ZSTD_CDict can be created once and shared by multiple threads concurrently, since its usage is read-only.
    /// `buf` can be released after `Dictionary` creation, because its content is copied within CDict.
    /// Note: A `Dictionary` can be created from an empty `buf`,
    ///     in which case the only thing that it transports is the `compression_level`.
    ///     This can be useful in a pipeline featuring `Compressor.compressUsingDict()` exclusively,
    ///     expecting a `Dictionary` parameter with any data, including those without a known dictionary.
    pub fn init(buf: []const u8, compression_level: i32) ?CDictionary {
        return CDictionary{ .handle = c.ZSTD_createCDict(@as(*const anyopaque, @ptrCast(buf)), buf.len, compression_level) orelse return null };
    }

    pub fn deinit(self: CDictionary) void {
        _ = c.ZSTD_freeCDict(self.handle);
    }

    /// Provides the ID of the loaded dictionary.
    /// Returns null if the dictionary is not conformant to Zstandard specification, or empty.
    /// Non-conformant dictionaries can still be loaded, but as content-only dictionaries.
    pub fn getID(self: CDictionary) u32 {
        return c.ZSTD_getDictID_fromCDict(self.handle);
    }
};

/// Compresses `src` content as a single zstd compressed frame into already allocated `dest`.
/// Returns an slice of written data, which points to `dest`.
pub fn compress(dest: []u8, src: []const u8, compression_level: i32) Error![]const u8 {
    return dest[0..try checkError(c.ZSTD_compress(
        @as(*anyopaque, @ptrCast(dest)),
        dest.len,
        @as(*const anyopaque, @ptrCast(src)),
        src.len,
        @as(c_int, @intCast(compression_level)),
    ))];
}

/// `src` should point to the start of a ZSTD encoded frame.
/// `src.len` must be at least as large as the frame header.
/// hint: any size >= `frame_header_size_max` is large enough.
///
/// Returns:
/// - decompressed size of `src` frame content, if known
/// - error.Unknown if the size cannot be determined
/// - error.Generic if an error occurred (e.g. invalid magic number, `src.len` too small)
///
/// NOTE:
/// - a 0 return value means the frame is valid but "empty".
/// - decompressed size is an optional field, it may not be present, typically in streaming mode.
///   When `error.Unknown` returned, data to decompress could be any size.
///   In which case, it's necessary to use streaming mode to decompress data.
///   Optionally, application can rely on some implicit limit,
///   as `decompress()` only needs an upper bound of decompressed size.
///   (For example, data could be necessarily cut into blocks <= 16 KB).
/// - decompressed size is always present when compression is completed using single-pass functions,
///   such as `compress()`, `Compressor.compress()`, `compressUsingDict()` or `compressUsingCDict()`.
/// - decompressed size can be very large (64-bits value),
///   potentially larger than what local system can handle as a single memory segment.
///   In which case, it's necessary to use streaming mode to decompress data.
/// - If source is untrusted, decompressed size could be wrong or intentionally modified.
///   Always ensure return value fits within application's authorized limits.
///   Each application can set its own limits.
pub fn getFrameContentSize(src: []const u8) error{ Unknown, Generic }!usize {
    return switch (c.ZSTD_getFrameContentSize(@as(*const anyopaque, @ptrCast(src)), src.len)) {
        ZSTD_CONTENTSIZE_UNKNOWN => error.Unknown,
        ZSTD_CONTENTSIZE_ERROR => error.Generic,
        else => |v| v,
    };
}

/// `src` should point to the start of a ZSTD frame or skippable frame.
/// `src.len` must be >= first frame size
///
/// Returns the compressed size of the first frame starting at `src`,
/// suitable to pass as `srcSize` to `ZSTD_decompress` or similar,
/// or an error code if input is invalid
pub fn findFrameCompressedSize(src: []const u8) usize {
    return c.ZSTD_findFrameCompressedSize(@as(*const anyopaque, @ptrCast(src)), src.len);
}

pub fn minCompressionLevel() i32 {
    return @as(i32, @intCast(c.ZSTD_minCLevel()));
}

pub fn maxCompressionLevel() i32 {
    return @as(i32, @intCast(c.ZSTD_maxCLevel()));
}

pub fn defaultCompressionLevel() i32 {
    return @as(i32, @intCast(c.ZSTD_defaultCLevel()));
}

/// Returns maximum compressed size in worst case single-pass scenario
pub fn compressBound(src_size: usize) usize {
    return c.ZSTD_compressBound(src_size);
}
