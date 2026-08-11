//! Read-only random-access account store backed by independent zstd chunks.
//!
//! This is the Chimera SSD-constrained cold account path: a compact binary
//! pubkey index points into seekable compressed chunks containing
//! `SnapshotAccountHeader || account.data` records.
const std = @import("std");
const sig = @import("../sig.zig");
const CompressedAccountRadix = @import("CompressedAccountRadix.zig");

const CompressedAccountStore = @This();

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const AccountSharedData = sig.runtime.AccountSharedData;

const INDEX_MAGIC = "CHIMIDX1";
const CHUNK_MAGIC = "CHIMCHK1";
const INDEX_HEADER_LEN: usize = 64;
const DIRECTORY_RECORD_LEN: usize = 16;
const INDEX_FORMAT_VERSION_V1: u32 = 1;
const INDEX_FORMAT_VERSION_V2: u32 = 2;
const INDEX_RECORD_LEN_V1: usize = 64;
const INDEX_RECORD_LEN_V2: usize = 44;
const INDEX_RECORD_LEN_MAX: usize = @max(INDEX_RECORD_LEN_V1, INDEX_RECORD_LEN_V2);
const CHUNK_HEADER_LEN: usize = 64;
const CHUNK_RECORD_LEN: usize = 32;
const CHUNK_FORMAT_VERSION: u32 = 1;
const DEFAULT_MAX_CHUNK_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_CHUNK_CACHE_SLOTS: u64 = 128;
const DEFAULT_CHUNK_CACHE_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_LOOKUP_CACHE_ENTRIES: u64 = 1_000_000;
const DEFAULT_DECODED_ACCOUNT_CACHE_ENTRIES: u64 = 16_384;
const DEFAULT_DECODED_ACCOUNT_CACHE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_DECODED_ACCOUNT_CACHE_PRIORITY_ENTRIES: u64 = 0;
const DEFAULT_DECODED_ACCOUNT_CACHE_CLEAR_EACH_BATCH = true;
const DEFAULT_DECODED_ACCOUNT_CACHE_MOVE_BORROWED = false;
const MAX_BATCH_DECODE_THREADS: u64 = 64;

allocator: std.mem.Allocator,
index_file: std.fs.File,
index_mmap: ?[]align(std.heap.page_size_min) const u8,
radix_index: ?CompressedAccountRadix,
chunks_file: std.fs.File,
segments_file: std.fs.File,
directory: []DirectoryEntry,
chunk_table: []ChunkEntry,
overlay_store: ?*CompressedAccountStore = null,
persistent_batch_pool: ?sig.sync.ThreadPool = null,
chunk_cache: []ChunkCacheEntry,
chunk_cache_index: std.AutoHashMapUnmanaged(u32, usize),
chunk_cache_mutex: std.Thread.Mutex = .{},
chunk_cache_clock: u64 = 0,
chunk_cache_bytes: u64 = 0,
chunk_cache_insert_count: u64 = 0,
chunk_cache_eviction_count: u64 = 0,
chunk_cache_byte_limit_eviction_count: u64 = 0,
chunk_cache_entry_limit_eviction_count: u64 = 0,
chunk_cache_max_bytes: u64,
lookup_cache: sig.utils.collections.PubkeyMap(LookupCacheEntry),
lookup_cache_mutex: std.Thread.Mutex = .{},
lookup_cache_max_entries: usize,
decoded_account_cache: sig.utils.collections.PubkeyMap(*AccountSharedData),
decoded_account_cache_headers: std.heap.ArenaAllocator,
decoded_account_cache_mutex: std.Thread.Mutex = .{},
decoded_account_cache_max_entries: usize,
decoded_account_cache_priority_reserve_entries: usize,
decoded_account_cache_max_bytes: u64,
decoded_account_cache_clear_each_batch: bool,
decoded_account_cache_move_borrowed: bool,
decoded_account_cache_bytes: u64 = 0,
decoded_account_cache_priority_entries: u64 = 0,
decoded_account_cache_priority_insert_count: std.atomic.Value(u64) = .init(0),
decoded_account_cache_priority_skip_count: std.atomic.Value(u64) = .init(0),
decoded_account_cache_skip_entry_limit_count: std.atomic.Value(u64) = .init(0),
decoded_account_cache_skip_byte_limit_count: std.atomic.Value(u64) = .init(0),
decoded_account_cache_skip_oversize_count: std.atomic.Value(u64) = .init(0),
decoded_account_cache_skip_allocation_count: std.atomic.Value(u64) = .init(0),
index_record_read_count: std.atomic.Value(u64) = .init(0),
metrics: Metrics,
shard_prefix_bits: u32,
row_count: u64,
records_offset: u64,
index_format_version: u32,
index_record_len: u32,
max_chunk_bytes: u64,

const DirectoryEntry = struct {
    offset: u64,
    count: u32,
};

const ChunkEntry = struct {
    compressed_offset: u64,
    compressed_len: u32,
    uncompressed_len: u32,
    account_records: u32,
};

const ChunkCacheEntry = struct {
    occupied: bool = false,
    chunk_id: u32 = 0,
    bytes: []u8 = undefined,
    last_used: u64 = 0,
};

const Metrics = struct {
    get_count: *sig.prometheus.Counter,
    lookup_miss_count: *sig.prometheus.Counter,
    overlay_hit_count: *sig.prometheus.Counter,
    cache_hit_count: *sig.prometheus.Counter,
    cache_miss_count: *sig.prometheus.Counter,
    cache_insert_count: *sig.prometheus.Counter,
    cache_eviction_count: *sig.prometheus.Counter,
    decompress_count: *sig.prometheus.Counter,
    decompress_compressed_bytes: *sig.prometheus.Counter,
    decompress_uncompressed_bytes: *sig.prometheus.Counter,
    lookup_cache_hit_count: *sig.prometheus.Counter,
    lookup_cache_miss_count: *sig.prometheus.Counter,
    lookup_cache_insert_count: *sig.prometheus.Counter,
    cache_bytes: *sig.prometheus.Gauge(u64),
    cache_entries: *sig.prometheus.Gauge(u64),
    lookup_cache_entries: *sig.prometheus.Gauge(u64),
    index_mmap_enabled: *sig.prometheus.Gauge(u64),
    radix_index_enabled: *sig.prometheus.Gauge(u64),
    radix_index_prefix_bits: *sig.prometheus.Gauge(u64),
    index_record_read_count: *sig.prometheus.Counter,
    decoded_account_cache_hit_count: *sig.prometheus.Counter,
    decoded_account_cache_miss_count: *sig.prometheus.Counter,
    decoded_account_cache_insert_count: *sig.prometheus.Counter,
    decoded_account_cache_skip_count: *sig.prometheus.Counter,
    decoded_account_cache_priority_insert_count: *sig.prometheus.Counter,
    decoded_account_cache_priority_skip_count: *sig.prometheus.Counter,
    decoded_account_cache_skip_entry_limit_count: *sig.prometheus.Counter,
    decoded_account_cache_skip_byte_limit_count: *sig.prometheus.Counter,
    decoded_account_cache_skip_oversize_count: *sig.prometheus.Counter,
    decoded_account_cache_skip_allocation_count: *sig.prometheus.Counter,
    decoded_account_cache_entries: *sig.prometheus.Gauge(u64),
    decoded_account_cache_bytes: *sig.prometheus.Gauge(u64),
    decoded_account_cache_max_entries: *sig.prometheus.Gauge(u64),
    decoded_account_cache_priority_entries: *sig.prometheus.Gauge(u64),
    decoded_account_cache_priority_reserve_entries: *sig.prometheus.Gauge(u64),
    decoded_account_cache_effective_max_entries: *sig.prometheus.Gauge(u64),
    decoded_account_cache_max_bytes: *sig.prometheus.Gauge(u64),
    batch_decode_time: *sig.prometheus.Histogram,
    batch_decode_pubkeys: *sig.prometheus.Gauge(u64),
    batch_decode_compressed_pubkeys: *sig.prometheus.Gauge(u64),
    batch_decode_missing_pubkeys: *sig.prometheus.Gauge(u64),
    batch_decode_unique_chunks: *sig.prometheus.Gauge(u64),
    batch_decode_chunks_decoded: *sig.prometheus.Gauge(u64),
    batch_decode_chunks_cached: *sig.prometheus.Gauge(u64),
    batch_decode_accounts_loaded: *sig.prometheus.Gauge(u64),
    batch_decode_accounts_cached: *sig.prometheus.Gauge(u64),
    batch_decode_accounts_skipped: *sig.prometheus.Gauge(u64),
    batch_decode_index_records_read: *sig.prometheus.Gauge(u64),
    get_time: *sig.prometheus.Histogram,
    lookup_time: *sig.prometheus.Histogram,
    read_index_record_time: *sig.prometheus.Histogram,
    read_account_record_time: *sig.prometheus.Histogram,
    read_account_record_cache_time: *sig.prometheus.Histogram,
    read_account_record_decode_time: *sig.prometheus.Histogram,
    decompress_chunk_time: *sig.prometheus.Histogram,
    segments_pread_time: *sig.prometheus.Histogram,
    zstd_decode_time: *sig.prometheus.Histogram,

    pub const prefix = "accountsdb_compressed_store";
    pub const histogram_buckets = b: {
        const base = 100 * std.time.ns_per_ms;
        var buckets: [20]f64 = undefined;
        for (&buckets, 0..) |*bucket, i| bucket.* = i * base;
        break :b buckets;
    };
};

const IndexRecord = struct {
    pubkey: Pubkey,
    chunk_id: u32,
    uncompressed_offset: u32,
    record_len: u32,
    data_len: u32,
};

const LookupCacheEntry = struct {
    found: bool,
    record: IndexRecord = undefined,
};

pub const PrefetchResult = struct {
    pubkeys: u64 = 0,
    compressed_pubkeys: u64 = 0,
    missing_pubkeys: u64 = 0,
    unique_chunks: u64 = 0,
    chunks_loaded: u64 = 0,
    chunks_cached: u64 = 0,
    chunks_skipped: u64 = 0,
};

pub const BatchDecodeResult = struct {
    pubkeys: u64 = 0,
    compressed_pubkeys: u64 = 0,
    missing_pubkeys: u64 = 0,
    unique_chunks: u64 = 0,
    chunks_decoded: u64 = 0,
    chunks_cached: u64 = 0,
    accounts_loaded: u64 = 0,
    accounts_cached: u64 = 0,
    accounts_borrowed: u64 = 0,
    accounts_skipped: u64 = 0,
    materialized_data_bytes: u64 = 0,
    borrowed_data_bytes: u64 = 0,
    decoded_cache_entries: u64 = 0,
    decoded_cache_bytes: u64 = 0,
    decoded_cache_max_entries: u64 = 0,
    decoded_cache_priority_entries: u64 = 0,
    decoded_cache_priority_reserve_entries: u64 = 0,
    decoded_cache_effective_max_entries: u64 = 0,
    decoded_cache_max_bytes: u64 = 0,
    decoded_cache_move_borrowed: bool = false,
    persistent_batch_pool: bool = false,
    decoded_cache_priority_insert_total: u64 = 0,
    decoded_cache_priority_skip_total: u64 = 0,
    decoded_cache_skip_entry_limit_total: u64 = 0,
    decoded_cache_skip_byte_limit_total: u64 = 0,
    decoded_cache_skip_oversize_total: u64 = 0,
    decoded_cache_skip_allocation_total: u64 = 0,
    chunk_cache_entries: u64 = 0,
    chunk_cache_bytes: u64 = 0,
    chunk_cache_max_entries: u64 = 0,
    chunk_cache_max_bytes: u64 = 0,
    chunk_cache_insert_total: u64 = 0,
    chunk_cache_eviction_total: u64 = 0,
    chunk_cache_byte_limit_eviction_total: u64 = 0,
    chunk_cache_entry_limit_eviction_total: u64 = 0,
    total_ns: u64 = 0,
    index_lookup_ns: u64 = 0,
    index_records_read: u64 = 0,
    chunk_plan_ns: u64 = 0,
    cached_chunk_load_ns: u64 = 0,
    cold_chunk_load_ns: u64 = 0,
    cold_decompress_wall_ns: u64 = 0,
    cold_account_materialize_ns: u64 = 0,
    chunk_cache_insert_ns: u64 = 0,
};

const DecodedAccountCacheInsertPolicy = enum {
    normal,
    priority,
};

fn decodedAccountCacheHasCapacityForPolicy(
    base_entries: usize,
    priority_reserve_entries: usize,
    total_entries: usize,
    priority_entries: usize,
    policy: DecodedAccountCacheInsertPolicy,
) bool {
    std.debug.assert(priority_entries <= total_entries);
    if (priority_reserve_entries == 0) return total_entries < base_entries;

    return switch (policy) {
        .normal => total_entries - priority_entries < base_entries,
        .priority => priority_entries < priority_reserve_entries,
    };
}

const BatchDecodeCandidate = struct {
    pubkey: Pubkey,
    record: IndexRecord,

    fn lessThan(_: void, a: @This(), b: @This()) bool {
        if (a.record.chunk_id == b.record.chunk_id) {
            if (a.record.uncompressed_offset == b.record.uncompressed_offset)
                return comparePubkey(a.pubkey, b.pubkey) < 0;
            return a.record.uncompressed_offset < b.record.uncompressed_offset;
        }
        return a.record.chunk_id < b.record.chunk_id;
    }
};

const BatchChunkGroup = struct {
    chunk_id: u32,
    chunk: ChunkEntry,
    candidates: []const BatchDecodeCandidate,
};

const ParallelChunkDecodeResult = struct {
    decompressed: ?[]u8 = null,
    err: ?anyerror = null,
};

const ParallelChunkDecodeContext = struct {
    store: *CompressedAccountStore,
    groups: []const BatchChunkGroup,
    results: []ParallelChunkDecodeResult,
    next_index: std.atomic.Value(usize) = .init(0),
};

const BatchLookupResult = struct {
    pubkey: Pubkey,
    record: ?IndexRecord = null,
    err: ?anyerror = null,
};

const ParallelBatchLookupContext = struct {
    store: *CompressedAccountStore,
    results: []BatchLookupResult,
    next_index: std.atomic.Value(usize) = .init(0),
};

const PersistentBatchLookupTask = struct {
    task: sig.sync.ThreadPool.Task = .{ .callback = run },
    context: *ParallelBatchLookupContext,
    wait_group: *std.Thread.WaitGroup,

    fn run(task: *sig.sync.ThreadPool.Task) void {
        const self: *@This() = @alignCast(@fieldParentPtr("task", task));
        defer self.wait_group.finish();
        parallelBatchLookupWorker(self.context);
    }
};

const PersistentChunkDecodeTask = struct {
    task: sig.sync.ThreadPool.Task = .{ .callback = run },
    context: *ParallelChunkDecodeContext,
    wait_group: *std.Thread.WaitGroup,

    fn run(task: *sig.sync.ThreadPool.Task) void {
        const self: *@This() = @alignCast(@fieldParentPtr("task", task));
        defer self.wait_group.finish();
        parallelChunkDecodeWorker(self.context);
    }
};

const PrefetchChunkStatus = enum {
    loaded,
    cached,
    skipped,
};

const DecompressScratch = struct {
    compressed_buf: []u8,
    zstd_buf: []u8,

    fn init(allocator: std.mem.Allocator) !DecompressScratch {
        return .{
            .compressed_buf = &.{},
            .zstd_buf = try allocator.alloc(
                u8,
                std.compress.zstd.default_window_len + std.compress.zstd.block_size_max,
            ),
        };
    }

    fn deinit(self: *DecompressScratch, allocator: std.mem.Allocator) void {
        if (self.compressed_buf.len != 0) allocator.free(self.compressed_buf);
        allocator.free(self.zstd_buf);
        self.* = undefined;
    }

    fn compressedSlice(
        self: *DecompressScratch,
        allocator: std.mem.Allocator,
        len: usize,
    ) ![]u8 {
        if (self.compressed_buf.len < len) {
            if (self.compressed_buf.len != 0) allocator.free(self.compressed_buf);
            self.compressed_buf = try allocator.alloc(u8, len);
        }
        return self.compressed_buf[0..len];
    }
};

pub const Sample = struct {
    pubkey: Pubkey,
    data_len: u32,
    record_len: u32,
    chunk_id: u32,
};

const SnapshotAccountHeader = extern struct {
    write_version: u64,
    data_len: u64,
    pubkey: Pubkey,
    lamports: u64,
    rent_epoch: sig.core.Epoch,
    owner: Pubkey,
    executable: u8,
    _padding: [7]u8,
    hash: Hash,
};

pub fn init(
    allocator: std.mem.Allocator,
    index_path: []const u8,
    chunks_path: []const u8,
    segments_path: []const u8,
) !CompressedAccountStore {
    return initWithRadix(allocator, index_path, chunks_path, segments_path, null);
}

fn initWithRadix(
    allocator: std.mem.Allocator,
    index_path: []const u8,
    chunks_path: []const u8,
    segments_path: []const u8,
    radix_path: ?[]const u8,
) !CompressedAccountStore {
    var index_file = try std.fs.cwd().openFile(index_path, .{ .mode = .read_only });
    errdefer index_file.close();

    var chunks_file = try std.fs.cwd().openFile(chunks_path, .{ .mode = .read_only });
    errdefer chunks_file.close();

    var segments_file = try std.fs.cwd().openFile(segments_path, .{ .mode = .read_only });
    errdefer segments_file.close();

    var index_header: [INDEX_HEADER_LEN]u8 = undefined;
    if (try index_file.preadAll(&index_header, 0) != index_header.len)
        return error.InvalidCompressedAccountIndex;
    if (!std.mem.eql(u8, index_header[0..INDEX_MAGIC.len], INDEX_MAGIC))
        return error.InvalidCompressedAccountIndex;

    const index_version = readU32(&index_header, 8);
    const index_record_len = readU32(&index_header, 12);
    const shard_prefix_bits = readU32(&index_header, 16);
    const shard_count_u32 = readU32(&index_header, 20);
    const row_count = readU64(&index_header, 24);
    const directory_offset = readU64(&index_header, 32);
    const records_offset = readU64(&index_header, 40);

    if (!isSupportedIndexFormat(index_version, index_record_len))
        return error.InvalidCompressedAccountIndex;
    if (shard_prefix_bits == 0 or shard_prefix_bits > 16)
        return error.InvalidCompressedAccountIndex;
    const expected_shards = @as(u32, 1) << @intCast(shard_prefix_bits);
    if (shard_count_u32 != expected_shards)
        return error.InvalidCompressedAccountIndex;
    if (directory_offset != INDEX_HEADER_LEN)
        return error.InvalidCompressedAccountIndex;

    const index_file_size = try index_file.getEndPos();

    const shard_count: usize = @intCast(shard_count_u32);
    const directory_bytes_len = shard_count * DIRECTORY_RECORD_LEN;
    const directory_bytes = try allocator.alloc(u8, directory_bytes_len);
    defer allocator.free(directory_bytes);
    if (try index_file.preadAll(directory_bytes, directory_offset) != directory_bytes.len)
        return error.InvalidCompressedAccountIndex;

    const directory = try allocator.alloc(DirectoryEntry, shard_count);
    errdefer allocator.free(directory);
    for (directory, 0..) |*entry, shard_id| {
        const offset = shard_id * DIRECTORY_RECORD_LEN;
        entry.* = .{
            .offset = readU64(directory_bytes, offset),
            .count = readU32(directory_bytes, offset + 8),
        };
    }

    var radix_index: ?CompressedAccountRadix = null;
    if (radix_path) |path| {
        radix_index = try CompressedAccountRadix.load(allocator, path, .{
            .file_size = index_file_size,
            .row_count = row_count,
            .records_offset = records_offset,
            .record_len = index_record_len,
            .min_prefix_bits = shard_prefix_bits,
        });
    }
    errdefer if (radix_index) |*radix| radix.deinit(allocator);

    var chunks_header: [CHUNK_HEADER_LEN]u8 = undefined;
    if (try chunks_file.preadAll(&chunks_header, 0) != chunks_header.len)
        return error.InvalidCompressedAccountChunks;
    if (!std.mem.eql(u8, chunks_header[0..CHUNK_MAGIC.len], CHUNK_MAGIC))
        return error.InvalidCompressedAccountChunks;

    const chunk_version = readU32(&chunks_header, 8);
    const chunk_record_len = readU32(&chunks_header, 12);
    const chunk_count = readU64(&chunks_header, 16);
    const chunk_records_offset = readU64(&chunks_header, 24);
    if (chunk_version != CHUNK_FORMAT_VERSION or chunk_record_len != CHUNK_RECORD_LEN)
        return error.InvalidCompressedAccountChunks;
    if (chunk_records_offset != CHUNK_HEADER_LEN)
        return error.InvalidCompressedAccountChunks;
    if (chunk_count > std.math.maxInt(usize))
        return error.InvalidCompressedAccountChunks;

    const chunk_table_len: usize = @intCast(chunk_count);
    const chunk_bytes_len = chunk_table_len * CHUNK_RECORD_LEN;
    const chunk_bytes = try allocator.alloc(u8, chunk_bytes_len);
    defer allocator.free(chunk_bytes);
    if (try chunks_file.preadAll(chunk_bytes, chunk_records_offset) != chunk_bytes.len)
        return error.InvalidCompressedAccountChunks;

    const chunk_table = try allocator.alloc(ChunkEntry, chunk_table_len);
    errdefer allocator.free(chunk_table);
    for (chunk_table, 0..) |*entry, chunk_id| {
        const offset = chunk_id * CHUNK_RECORD_LEN;
        entry.* = .{
            .compressed_offset = readU64(chunk_bytes, offset),
            .compressed_len = readU32(chunk_bytes, offset + 8),
            .uncompressed_len = readU32(chunk_bytes, offset + 12),
            .account_records = readU32(chunk_bytes, offset + 16),
        };
    }

    const chunk_cache_max_bytes = envU64(
        "SIG_COMPRESSED_ACCOUNT_STORE_CHUNK_CACHE_BYTES",
        DEFAULT_CHUNK_CACHE_BYTES,
    );
    const chunk_cache_slot_count_u64 = if (chunk_cache_max_bytes == 0)
        0
    else
        envU64("SIG_COMPRESSED_ACCOUNT_STORE_CHUNK_CACHE_SLOTS", DEFAULT_CHUNK_CACHE_SLOTS);
    if (chunk_cache_slot_count_u64 > std.math.maxInt(usize))
        return error.InvalidCompressedAccountChunks;
    const chunk_cache = try allocator.alloc(ChunkCacheEntry, @intCast(chunk_cache_slot_count_u64));
    errdefer allocator.free(chunk_cache);
    @memset(chunk_cache, .{});
    var chunk_cache_index: std.AutoHashMapUnmanaged(u32, usize) = .{};
    errdefer chunk_cache_index.deinit(allocator);

    const lookup_cache_max_entries_u64 = envU64(
        "SIG_COMPRESSED_ACCOUNT_STORE_LOOKUP_CACHE_ENTRIES",
        DEFAULT_LOOKUP_CACHE_ENTRIES,
    );
    if (lookup_cache_max_entries_u64 > std.math.maxInt(usize))
        return error.InvalidCompressedAccountChunks;
    var lookup_cache: sig.utils.collections.PubkeyMap(LookupCacheEntry) = .{};
    errdefer lookup_cache.deinit(allocator);

    const decoded_account_cache_max_entries_u64 = envU64(
        "SIG_COMPRESSED_ACCOUNT_STORE_DECODED_ACCOUNT_CACHE_ENTRIES",
        DEFAULT_DECODED_ACCOUNT_CACHE_ENTRIES,
    );
    const decoded_account_cache_max_bytes = envU64(
        "SIG_COMPRESSED_ACCOUNT_STORE_DECODED_ACCOUNT_CACHE_BYTES",
        DEFAULT_DECODED_ACCOUNT_CACHE_BYTES,
    );
    const decoded_account_cache_priority_reserve_entries_u64 = envU64(
        "SIG_COMPRESSED_ACCOUNT_STORE_DECODED_ACCOUNT_CACHE_PRIORITY_ENTRIES",
        DEFAULT_DECODED_ACCOUNT_CACHE_PRIORITY_ENTRIES,
    );
    if (decoded_account_cache_max_entries_u64 > std.math.maxInt(usize) or
        decoded_account_cache_priority_reserve_entries_u64 >
            std.math.maxInt(usize) - decoded_account_cache_max_entries_u64)
    {
        return error.InvalidCompressedAccountChunks;
    }
    const decoded_account_cache_effective_max_entries_u64 =
        decoded_account_cache_max_entries_u64 + decoded_account_cache_priority_reserve_entries_u64;
    var decoded_account_cache: sig.utils.collections.PubkeyMap(*AccountSharedData) = .{};
    errdefer decoded_account_cache.deinit(allocator);
    var decoded_account_cache_headers = std.heap.ArenaAllocator.init(allocator);
    errdefer decoded_account_cache_headers.deinit();

    var index_mmap: ?[]align(std.heap.page_size_min) const u8 = null;
    if (envBool("SIG_COMPRESSED_ACCOUNT_STORE_MMAP_INDEX", false)) {
        if (index_file_size == 0 or index_file_size > std.math.maxInt(usize))
            return error.InvalidCompressedAccountIndex;
        index_mmap = try std.posix.mmap(
            null,
            @intCast(index_file_size),
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            index_file.handle,
            0,
        );
    }
    errdefer if (index_mmap) |mapped| std.posix.munmap(mapped);

    const metrics = try sig.prometheus.globalRegistry().initStruct(Metrics);
    metrics.cache_bytes.set(0);
    metrics.cache_entries.set(0);
    metrics.lookup_cache_entries.set(0);
    metrics.index_mmap_enabled.set(@intFromBool(index_mmap != null));
    metrics.radix_index_enabled.set(@intFromBool(radix_index != null));
    metrics.radix_index_prefix_bits.set(if (radix_index) |radix| radix.prefix_bits else 0);
    metrics.decoded_account_cache_entries.set(0);
    metrics.decoded_account_cache_bytes.set(0);
    metrics.decoded_account_cache_max_entries.set(decoded_account_cache_max_entries_u64);
    metrics.decoded_account_cache_priority_entries.set(0);
    metrics.decoded_account_cache_priority_reserve_entries.set(decoded_account_cache_priority_reserve_entries_u64);
    metrics.decoded_account_cache_effective_max_entries.set(decoded_account_cache_effective_max_entries_u64);
    metrics.decoded_account_cache_max_bytes.set(decoded_account_cache_max_bytes);

    const configured_decode_threads = @min(
        envU64("SIG_COMPRESSED_ACCOUNT_STORE_BATCH_DECODE_THREADS", 1),
        MAX_BATCH_DECODE_THREADS,
    );
    const configured_index_threads = @min(
        envU64(
            "SIG_COMPRESSED_ACCOUNT_STORE_BATCH_INDEX_THREADS",
            configured_decode_threads,
        ),
        MAX_BATCH_DECODE_THREADS,
    );
    const persistent_batch_pool_threads = @max(
        configured_decode_threads,
        configured_index_threads,
    );
    var persistent_batch_pool: ?sig.sync.ThreadPool =
        if (envBool("SIG_COMPRESSED_ACCOUNT_STORE_PERSISTENT_BATCH_POOL", false) and
        persistent_batch_pool_threads > 1)
            sig.sync.ThreadPool.init(.{
                .max_threads = @intCast(persistent_batch_pool_threads),
            })
        else
            null;
    errdefer if (persistent_batch_pool) |*pool| pool.deinit();

    return .{
        .allocator = allocator,
        .index_file = index_file,
        .index_mmap = index_mmap,
        .radix_index = radix_index,
        .chunks_file = chunks_file,
        .segments_file = segments_file,
        .directory = directory,
        .chunk_table = chunk_table,
        .overlay_store = null,
        .persistent_batch_pool = persistent_batch_pool,
        .chunk_cache = chunk_cache,
        .chunk_cache_index = chunk_cache_index,
        .chunk_cache_max_bytes = chunk_cache_max_bytes,
        .lookup_cache = lookup_cache,
        .lookup_cache_max_entries = @intCast(lookup_cache_max_entries_u64),
        .decoded_account_cache = decoded_account_cache,
        .decoded_account_cache_headers = decoded_account_cache_headers,
        .decoded_account_cache_max_entries = @intCast(decoded_account_cache_max_entries_u64),
        .decoded_account_cache_priority_reserve_entries = @intCast(
            decoded_account_cache_priority_reserve_entries_u64,
        ),
        .decoded_account_cache_max_bytes = decoded_account_cache_max_bytes,
        .decoded_account_cache_clear_each_batch = envBool(
            "SIG_COMPRESSED_ACCOUNT_STORE_DECODED_ACCOUNT_CACHE_CLEAR_EACH_BATCH",
            DEFAULT_DECODED_ACCOUNT_CACHE_CLEAR_EACH_BATCH,
        ),
        .decoded_account_cache_move_borrowed = envBool(
            "SIG_COMPRESSED_ACCOUNT_STORE_DECODED_ACCOUNT_CACHE_MOVE_BORROWED",
            DEFAULT_DECODED_ACCOUNT_CACHE_MOVE_BORROWED,
        ),
        .metrics = metrics,
        .shard_prefix_bits = shard_prefix_bits,
        .row_count = row_count,
        .records_offset = records_offset,
        .index_format_version = index_version,
        .index_record_len = index_record_len,
        .max_chunk_bytes = envU64("SIG_COMPRESSED_ACCOUNT_STORE_MAX_CHUNK_BYTES", DEFAULT_MAX_CHUNK_BYTES),
    };
}

pub fn initFromEnv(allocator: std.mem.Allocator) !?CompressedAccountStore {
    const index_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_INDEX");
    errdefer if (index_path) |path| allocator.free(path);

    const chunks_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_CHUNKS");
    errdefer if (chunks_path) |path| allocator.free(path);

    const segments_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_SEGMENTS");
    errdefer if (segments_path) |path| allocator.free(path);

    const radix_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_RADIX_INDEX");
    errdefer if (radix_path) |path| allocator.free(path);

    const overlay_index_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_OVERLAY_INDEX");
    errdefer if (overlay_index_path) |path| allocator.free(path);

    const overlay_chunks_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_OVERLAY_CHUNKS");
    errdefer if (overlay_chunks_path) |path| allocator.free(path);

    const overlay_segments_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_OVERLAY_SEGMENTS");
    errdefer if (overlay_segments_path) |path| allocator.free(path);

    const overlay_radix_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_OVERLAY_RADIX_INDEX");
    errdefer if (overlay_radix_path) |path| allocator.free(path);

    const base_missing = index_path == null and chunks_path == null and segments_path == null;
    const overlay_missing = overlay_index_path == null and overlay_chunks_path == null and overlay_segments_path == null;
    if (base_missing and overlay_missing) {
        if (radix_path != null or overlay_radix_path != null)
            return error.MissingCompressedAccountStoreEnv;
        return null;
    }
    if (index_path == null or chunks_path == null or segments_path == null)
        return error.MissingCompressedAccountStoreEnv;
    if (overlay_index_path == null or overlay_chunks_path == null or overlay_segments_path == null) {
        if (!overlay_missing) return error.MissingCompressedAccountStoreEnv;
    }
    if (overlay_missing and overlay_radix_path != null)
        return error.MissingCompressedAccountStoreEnv;

    defer allocator.free(index_path.?);
    defer allocator.free(chunks_path.?);
    defer allocator.free(segments_path.?);
    defer if (radix_path) |path| allocator.free(path);
    defer if (overlay_index_path) |path| allocator.free(path);
    defer if (overlay_chunks_path) |path| allocator.free(path);
    defer if (overlay_segments_path) |path| allocator.free(path);
    defer if (overlay_radix_path) |path| allocator.free(path);

    var store = try initWithRadix(
        allocator,
        index_path.?,
        chunks_path.?,
        segments_path.?,
        radix_path,
    );
    errdefer store.deinit();

    if (!overlay_missing) {
        const overlay = try allocator.create(CompressedAccountStore);
        errdefer allocator.destroy(overlay);
        overlay.* = try initWithRadix(
            allocator,
            overlay_index_path.?,
            overlay_chunks_path.?,
            overlay_segments_path.?,
            overlay_radix_path,
        );
        store.overlay_store = overlay;
    }

    store.metrics.index_mmap_enabled.set(@intFromBool(store.index_mmap != null));
    store.metrics.radix_index_enabled.set(@intFromBool(store.radix_index != null));
    store.metrics.radix_index_prefix_bits.set(if (store.radix_index) |radix| radix.prefix_bits else 0);

    return store;
}

pub fn deinit(self: *CompressedAccountStore) void {
    if (self.persistent_batch_pool) |*pool| pool.deinit();
    if (self.overlay_store) |overlay| {
        overlay.deinit();
        self.allocator.destroy(overlay);
        self.overlay_store = null;
    }
    if (self.index_mmap) |mapped| std.posix.munmap(mapped);
    if (self.radix_index) |*radix| radix.deinit(self.allocator);
    self.index_file.close();
    self.chunks_file.close();
    self.segments_file.close();
    for (self.chunk_cache) |*entry| {
        if (entry.occupied) self.allocator.free(entry.bytes);
    }
    self.chunk_cache_index.deinit(self.allocator);
    self.lookup_cache.deinit(self.allocator);
    self.decodedAccountCacheClearUnlocked();
    self.decoded_account_cache.deinit(self.allocator);
    self.decoded_account_cache_headers.deinit();
    self.allocator.free(self.chunk_cache);
    self.allocator.free(self.directory);
    self.allocator.free(self.chunk_table);
    self.* = undefined;
}

pub fn get(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    address: Pubkey,
) !?AccountSharedData {
    var timer = sig.time.Timer.start();
    defer self.metrics.get_time.observe(timer.read().asNanos());

    self.metrics.get_count.inc();
    if (self.overlay_store) |overlay| {
        if (try overlay.get(allocator, address)) |account| {
            self.metrics.overlay_hit_count.inc();
            return account;
        }
    }
    if (try self.decodedAccountCacheGet(allocator, address)) |account| return account;
    const record = try self.lookup(address) orelse {
        self.metrics.lookup_miss_count.inc();
        return null;
    };
    return try self.readAccountRecord(allocator, address, record);
}

pub fn accountDataLen(self: *CompressedAccountStore, address: Pubkey) !?usize {
    if (self.overlay_store) |overlay| {
        if (try overlay.accountDataLen(address)) |data_len| return data_len;
    }

    const record = try self.lookup(address) orelse return null;
    return record.data_len;
}

pub fn samplePubkeys(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    max_samples: usize,
) ![]Sample {
    if (self.overlay_store) |overlay| {
        const overlay_samples = try overlay.samplePubkeys(allocator, max_samples);
        if (overlay_samples.len > 0 or max_samples == 0) return overlay_samples;
        allocator.free(overlay_samples);
    }

    if (max_samples == 0 or self.row_count == 0) return try allocator.alloc(Sample, 0);

    const sample_count: usize = @min(max_samples, @as(usize, @intCast(self.row_count)));
    const stride = @max(@as(u64, 1), self.row_count / @as(u64, @intCast(sample_count)));
    const samples = try allocator.alloc(Sample, sample_count);
    errdefer allocator.free(samples);

    for (samples, 0..) |*sample, i| {
        var row_index = @as(u64, @intCast(i)) * stride;
        if (row_index >= self.row_count) row_index = self.row_count - 1;
        const record = try self.readIndexRecordAt(
            self.records_offset + row_index * @as(u64, self.index_record_len),
        );
        sample.* = .{
            .pubkey = record.pubkey,
            .data_len = record.data_len,
            .record_len = record.record_len,
            .chunk_id = record.chunk_id,
        };
    }

    return samples;
}

pub fn samplePubkeysFromChunks(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    max_samples: usize,
    accounts_per_chunk: usize,
) ![]Sample {
    if (self.overlay_store) |overlay| {
        const overlay_samples = try overlay.samplePubkeysFromChunks(allocator, max_samples, accounts_per_chunk);
        if (overlay_samples.len > 0 or max_samples == 0) return overlay_samples;
        allocator.free(overlay_samples);
    }

    if (max_samples == 0 or self.chunk_table.len == 0) return try allocator.alloc(Sample, 0);
    if (accounts_per_chunk == 0) return error.InvalidArgument;

    const samples = try allocator.alloc(Sample, max_samples);
    errdefer allocator.free(samples);

    const target_chunks = (max_samples + accounts_per_chunk - 1) / accounts_per_chunk;
    const stride = @max(@as(usize, 1), self.chunk_table.len / @max(@as(usize, 1), target_chunks));
    var scratch = try DecompressScratch.init(allocator);
    defer scratch.deinit(allocator);

    var sample_count: usize = 0;
    var chunk_index: usize = 0;
    while (sample_count < max_samples and chunk_index < self.chunk_table.len) : (chunk_index += stride) {
        const chunk = self.chunk_table[chunk_index];
        if (chunk.account_records == 0 or chunk.uncompressed_len == 0 or chunk.uncompressed_len > self.max_chunk_bytes)
            continue;

        const decompressed = try self.decompressChunkWithScratch(allocator, chunk, &scratch);
        defer allocator.free(decompressed);

        var offset: usize = 0;
        var chunk_samples: usize = 0;
        var records_seen: u32 = 0;
        while (offset < decompressed.len and records_seen < chunk.account_records and chunk_samples < accounts_per_chunk and sample_count < max_samples) {
            if (decompressed.len - offset < @sizeOf(SnapshotAccountHeader))
                return error.InvalidCompressedAccountRecord;
            const header = decodeSnapshotAccountHeader(decompressed[offset..][0..@sizeOf(SnapshotAccountHeader)]);
            if (header.executable > 1)
                return error.InvalidCompressedAccountRecord;
            if (header.data_len > sig.runtime.program.system.MAX_PERMITTED_DATA_LENGTH)
                return error.InvalidCompressedAccountRecord;
            if (header.data_len > std.math.maxInt(u32))
                return error.InvalidCompressedAccountRecord;

            const record_len_u64 = @as(u64, @intCast(@sizeOf(SnapshotAccountHeader))) + header.data_len;
            if (record_len_u64 > std.math.maxInt(u32) or record_len_u64 > std.math.maxInt(usize))
                return error.InvalidCompressedAccountRecord;
            const record_len: usize = @intCast(record_len_u64);
            if (record_len > decompressed.len - offset)
                return error.InvalidCompressedAccountRecord;

            samples[sample_count] = .{
                .pubkey = header.pubkey,
                .data_len = @intCast(header.data_len),
                .record_len = @intCast(record_len),
                .chunk_id = @intCast(chunk_index),
            };
            sample_count += 1;
            chunk_samples += 1;
            records_seen += 1;
            offset += record_len;
        }
    }

    if (sample_count == samples.len) return samples;
    return try allocator.realloc(samples, sample_count);
}

pub fn lookupChunkId(self: *CompressedAccountStore, address: Pubkey) !?u32 {
    if (self.overlay_store) |overlay| {
        if (try overlay.lookupChunkId(address)) |chunk_id| return chunk_id;
    }

    const record = try self.lookup(address) orelse return null;
    return record.chunk_id;
}

pub fn chunkCached(self: *CompressedAccountStore, chunk_id: u32) bool {
    if (self.chunkCachedLocal(chunk_id)) return true;
    if (self.overlay_store) |overlay| return overlay.chunkCached(chunk_id);
    return false;
}

pub fn prefetchChunksForPubkeys(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
) !PrefetchResult {
    var result: PrefetchResult = .{ .pubkeys = @intCast(pubkeys.len) };
    if (self.chunk_cache.len == 0 or self.chunk_cache_max_bytes == 0) return result;

    var unique_chunks: std.AutoHashMapUnmanaged(u32, void) = .{};
    defer unique_chunks.deinit(allocator);

    var chunk_ids: std.ArrayListUnmanaged(u32) = .{};
    defer chunk_ids.deinit(allocator);
    try chunk_ids.ensureTotalCapacity(allocator, pubkeys.len);

    for (pubkeys) |pubkey| {
        const record = try self.lookup(pubkey) orelse {
            result.missing_pubkeys += 1;
            continue;
        };
        const gop = try unique_chunks.getOrPut(allocator, record.chunk_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = {};
            chunk_ids.appendAssumeCapacity(record.chunk_id);
        }
        result.compressed_pubkeys += 1;
    }

    result.unique_chunks = @intCast(chunk_ids.items.len);
    std.mem.sort(u32, chunk_ids.items, {}, struct {
        fn lessThan(_: void, a: u32, b: u32) bool {
            return a < b;
        }
    }.lessThan);

    for (chunk_ids.items) |chunk_id| {
        switch (try self.prefetchChunkById(chunk_id)) {
            .loaded => result.chunks_loaded += 1,
            .cached => result.chunks_cached += 1,
            .skipped => result.chunks_skipped += 1,
        }
    }

    return result;
}

pub fn batchDecodeAccountsForPubkeys(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
) !BatchDecodeResult {
    var timer = sig.time.Timer.start();
    defer self.metrics.batch_decode_time.observe(timer.read().asNanos());

    var result: BatchDecodeResult = .{
        .pubkeys = @intCast(pubkeys.len),
        .persistent_batch_pool = self.persistent_batch_pool != null,
    };
    if (!self.decodedAccountCacheEnabled()) {
        result.accounts_skipped = @intCast(pubkeys.len);
        self.snapshotDecodedAccountCache(&result);
        self.snapshotChunkCache(&result);
        self.recordBatchDecodeResult(result);
        return result;
    }

    if (self.decoded_account_cache_clear_each_batch) {
        self.decoded_account_cache_mutex.lock();
        self.decodedAccountCacheClearLocked();
        self.decoded_account_cache_mutex.unlock();
    }

    var unique_pubkeys: sig.utils.collections.PubkeyMap(void) = .{};
    defer unique_pubkeys.deinit(allocator);

    var unique_chunks: std.AutoHashMapUnmanaged(u32, void) = .{};
    defer unique_chunks.deinit(allocator);

    var candidates: std.ArrayListUnmanaged(BatchDecodeCandidate) = .{};
    defer candidates.deinit(allocator);
    try candidates.ensureTotalCapacity(allocator, pubkeys.len);

    for (pubkeys) |pubkey| {
        const pubkey_gop = try unique_pubkeys.getOrPut(allocator, pubkey);
        if (pubkey_gop.found_existing) continue;
        pubkey_gop.value_ptr.* = {};

        if (try self.decodedAccountCacheContains(pubkey)) {
            result.accounts_cached += 1;
            continue;
        }

        const record = try self.lookup(pubkey) orelse {
            result.missing_pubkeys += 1;
            continue;
        };
        candidates.appendAssumeCapacity(.{ .pubkey = pubkey, .record = record });
        result.compressed_pubkeys += 1;
        const chunk_gop = try unique_chunks.getOrPut(allocator, record.chunk_id);
        if (!chunk_gop.found_existing) chunk_gop.value_ptr.* = {};
    }

    result.pubkeys = @intCast(unique_pubkeys.count());
    result.unique_chunks = @intCast(unique_chunks.count());

    std.mem.sort(BatchDecodeCandidate, candidates.items, {}, BatchDecodeCandidate.lessThan);
    var scratch = try DecompressScratch.init(self.allocator);
    defer scratch.deinit(self.allocator);

    var i: usize = 0;
    while (i < candidates.items.len) {
        const chunk_id = candidates.items[i].record.chunk_id;
        var end = i + 1;
        while (end < candidates.items.len and candidates.items[end].record.chunk_id == chunk_id) : (end += 1) {}

        if (try self.batchDecodeFromCachedChunk(allocator, candidates.items[i..end], &result)) {
            result.chunks_cached += 1;
            i = end;
            continue;
        }

        if (chunk_id >= self.chunk_table.len)
            return error.InvalidCompressedAccountRecord;
        const chunk = self.chunk_table[chunk_id];
        if (chunk.uncompressed_len == 0 or chunk.uncompressed_len > self.max_chunk_bytes)
            return error.InvalidCompressedAccountChunk;
        if (!self.shouldCacheChunk(chunk.uncompressed_len)) {
            result.accounts_skipped += @intCast(end - i);
            i = end;
            continue;
        }

        const decompressed = try self.decompressChunkWithScratch(self.allocator, chunk, &scratch);
        var owns_decompressed = true;
        errdefer if (owns_decompressed) self.allocator.free(decompressed);
        try self.batchDecodeFromChunkBytes(allocator, candidates.items[i..end], decompressed, &result);
        _ = try self.insertPrefetchedChunk(chunk_id, decompressed);
        owns_decompressed = false;
        result.chunks_decoded += 1;
        i = end;
    }

    self.snapshotDecodedAccountCache(&result);
    self.snapshotChunkCache(&result);
    self.recordBatchDecodeResult(result);
    return result;
}

pub fn batchLoadAccountsForPubkeys(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
) !BatchDecodeResult {
    return self.batchLoadAccountsForPubkeysInternal(
        allocator,
        pubkeys,
        accounts,
        null,
        .normal,
    );
}

pub fn batchLoadAccountsForPubkeysBorrowed(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: *sig.utils.collections.PubkeyMap(*const AccountSharedData),
) !BatchDecodeResult {
    return self.batchLoadAccountsForPubkeysInternal(
        allocator,
        pubkeys,
        accounts,
        borrowed_accounts,
        .normal,
    );
}

pub fn batchLoadAccountsForPubkeysBorrowedPriority(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: *sig.utils.collections.PubkeyMap(*const AccountSharedData),
) !BatchDecodeResult {
    return self.batchLoadAccountsForPubkeysInternal(
        allocator,
        pubkeys,
        accounts,
        borrowed_accounts,
        .priority,
    );
}

fn batchLoadAccountsForPubkeysInternal(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: ?*sig.utils.collections.PubkeyMap(*const AccountSharedData),
    cache_insert_policy: DecodedAccountCacheInsertPolicy,
) !BatchDecodeResult {
    const overlay = self.overlay_store orelse return self.batchLoadAccountsForPubkeysLocal(
        allocator,
        pubkeys,
        accounts,
        borrowed_accounts,
        cache_insert_policy,
    );

    var timer = sig.time.Timer.start();
    const overlay_result = try overlay.batchLoadAccountsForPubkeysLocal(
        allocator,
        pubkeys,
        accounts,
        borrowed_accounts,
        cache_insert_policy,
    );

    var base_pubkeys: std.ArrayListUnmanaged(Pubkey) = .{};
    defer base_pubkeys.deinit(allocator);
    try base_pubkeys.ensureTotalCapacity(allocator, pubkeys.len);
    for (pubkeys) |pubkey| {
        if (accounts.contains(pubkey)) continue;
        if (borrowed_accounts) |borrowed| {
            if (borrowed.contains(pubkey)) continue;
        }
        base_pubkeys.appendAssumeCapacity(pubkey);
    }

    const base_result = try self.batchLoadAccountsForPubkeysLocal(
        allocator,
        base_pubkeys.items,
        accounts,
        borrowed_accounts,
        cache_insert_policy,
    );
    const result = mergeLayeredBatchDecodeResults(
        overlay_result,
        base_result,
        timer.read().asNanos(),
    );
    self.recordBatchDecodeResult(result);
    return result;
}

/// Resolves one physical compressed store only. The public batch paths call
/// this once for the overlay and then once for the unresolved base pubkeys so
/// batched reads preserve the same overlay-first semantics as `get`.
fn batchLoadAccountsForPubkeysLocal(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: ?*sig.utils.collections.PubkeyMap(*const AccountSharedData),
    cache_insert_policy: DecodedAccountCacheInsertPolicy,
) !BatchDecodeResult {
    var timer = sig.time.Timer.start();
    defer self.metrics.batch_decode_time.observe(timer.read().asNanos());

    var result: BatchDecodeResult = .{
        .pubkeys = @intCast(pubkeys.len),
        .persistent_batch_pool = self.persistent_batch_pool != null,
    };

    var unique_pubkeys: sig.utils.collections.PubkeyMap(void) = .{};
    defer unique_pubkeys.deinit(allocator);

    var unique_chunks: std.AutoHashMapUnmanaged(u32, void) = .{};
    defer unique_chunks.deinit(allocator);

    var candidates: std.ArrayListUnmanaged(BatchDecodeCandidate) = .{};
    defer candidates.deinit(allocator);
    try candidates.ensureTotalCapacity(allocator, pubkeys.len);

    var lookup_results: std.ArrayListUnmanaged(BatchLookupResult) = .{};
    defer lookup_results.deinit(allocator);
    try lookup_results.ensureTotalCapacity(allocator, pubkeys.len);

    var phase_timer = sig.time.Timer.start();
    try unique_pubkeys.ensureTotalCapacity(allocator, pubkeys.len);
    for (pubkeys) |pubkey| {
        const pubkey_gop = try unique_pubkeys.getOrPut(allocator, pubkey);
        if (pubkey_gop.found_existing) continue;
        pubkey_gop.value_ptr.* = {};
    }

    result.pubkeys = @intCast(unique_pubkeys.count());

    if (borrowed_accounts) |borrowed| {
        if (self.decodedAccountCacheBatchLoadEnabled()) {
            try borrowed.ensureUnusedCapacity(allocator, unique_pubkeys.count());
            self.decoded_account_cache_mutex.lock();
            defer self.decoded_account_cache_mutex.unlock();

            for (unique_pubkeys.keys()) |pubkey| {
                if (self.decoded_account_cache.get(pubkey)) |cached_account| {
                    self.metrics.decoded_account_cache_hit_count.inc();
                    putBorrowedAccount(allocator, borrowed, pubkey, cached_account) catch |err|
                        return err;
                    result.accounts_cached += 1;
                    result.accounts_borrowed += 1;
                    result.borrowed_data_bytes += @intCast(cached_account.data.len);
                    continue;
                }
                self.metrics.decoded_account_cache_miss_count.inc();
                lookup_results.appendAssumeCapacity(.{ .pubkey = pubkey });
            }
        } else {
            for (unique_pubkeys.keys()) |pubkey| {
                lookup_results.appendAssumeCapacity(.{ .pubkey = pubkey });
            }
        }
    } else {
        for (unique_pubkeys.keys()) |pubkey| {
            if (self.decodedAccountCacheBatchLoadEnabled()) {
                if (try self.decodedAccountCacheGet(allocator, pubkey)) |cached_account| {
                    var account = cached_account;
                    try putLoadedAccount(allocator, accounts, pubkey, &account);
                    result.accounts_cached += 1;
                    continue;
                }
            }

            lookup_results.appendAssumeCapacity(.{ .pubkey = pubkey });
        }
    }

    const index_records_before = self.index_record_read_count.load(.monotonic);
    try self.resolveBatchLookups(allocator, lookup_results.items);
    result.index_records_read = self.index_record_read_count.load(.monotonic) -% index_records_before;
    for (lookup_results.items) |lookup_result| {
        if (lookup_result.err) |err| return err;
        const record = lookup_result.record orelse {
            result.missing_pubkeys += 1;
            continue;
        };
        candidates.appendAssumeCapacity(.{ .pubkey = lookup_result.pubkey, .record = record });
        result.compressed_pubkeys += 1;
        const chunk_gop = try unique_chunks.getOrPut(allocator, record.chunk_id);
        if (!chunk_gop.found_existing) chunk_gop.value_ptr.* = {};
    }
    result.index_lookup_ns = phase_timer.read().asNanos();
    result.unique_chunks = @intCast(unique_chunks.count());

    phase_timer.reset();
    std.mem.sort(BatchDecodeCandidate, candidates.items, {}, BatchDecodeCandidate.lessThan);
    var cold_groups: std.ArrayListUnmanaged(BatchChunkGroup) = .{};
    defer cold_groups.deinit(allocator);
    try cold_groups.ensureTotalCapacity(allocator, result.unique_chunks);

    var i: usize = 0;
    while (i < candidates.items.len) {
        const chunk_id = candidates.items[i].record.chunk_id;
        var end = i + 1;
        while (end < candidates.items.len and candidates.items[end].record.chunk_id == chunk_id) : (end += 1) {}

        var cached_chunk_timer = sig.time.Timer.start();
        const loaded_from_cached_chunk = try self.batchLoadFromCachedChunk(
            allocator,
            candidates.items[i..end],
            accounts,
            borrowed_accounts,
            cache_insert_policy,
            &result,
        );
        result.cached_chunk_load_ns += cached_chunk_timer.read().asNanos();
        if (loaded_from_cached_chunk) {
            result.chunks_cached += 1;
            i = end;
            continue;
        }

        if (chunk_id >= self.chunk_table.len)
            return error.InvalidCompressedAccountRecord;
        const chunk = self.chunk_table[chunk_id];
        if (chunk.uncompressed_len == 0 or chunk.uncompressed_len > self.max_chunk_bytes)
            return error.InvalidCompressedAccountChunk;
        if (!self.shouldCacheChunk(chunk.uncompressed_len)) {
            result.accounts_skipped += @intCast(end - i);
            i = end;
            continue;
        }

        cold_groups.appendAssumeCapacity(.{
            .chunk_id = chunk_id,
            .chunk = chunk,
            .candidates = candidates.items[i..end],
        });
        i = end;
    }
    const chunk_plan_elapsed_ns = phase_timer.read().asNanos();
    result.chunk_plan_ns = chunk_plan_elapsed_ns -
        @min(chunk_plan_elapsed_ns, result.cached_chunk_load_ns);

    phase_timer.reset();
    try self.batchLoadColdChunkGroups(
        allocator,
        cold_groups.items,
        accounts,
        borrowed_accounts,
        cache_insert_policy,
        &result,
    );
    result.cold_chunk_load_ns = phase_timer.read().asNanos();
    result.total_ns = timer.read().asNanos();

    self.snapshotDecodedAccountCache(&result);
    self.snapshotChunkCache(&result);
    self.recordBatchDecodeResult(result);
    return result;
}

fn mergeLayeredBatchDecodeResults(
    overlay: BatchDecodeResult,
    base: BatchDecodeResult,
    total_ns: u64,
) BatchDecodeResult {
    var result = base;
    result.pubkeys = overlay.pubkeys;
    result.compressed_pubkeys += overlay.compressed_pubkeys;
    // Overlay misses are fallthrough candidates, not final misses.
    result.missing_pubkeys = base.missing_pubkeys;
    result.unique_chunks += overlay.unique_chunks;
    result.chunks_decoded += overlay.chunks_decoded;
    result.chunks_cached += overlay.chunks_cached;
    result.accounts_loaded += overlay.accounts_loaded;
    result.accounts_cached += overlay.accounts_cached;
    result.accounts_borrowed += overlay.accounts_borrowed;
    result.accounts_skipped += overlay.accounts_skipped;
    result.materialized_data_bytes += overlay.materialized_data_bytes;
    result.borrowed_data_bytes += overlay.borrowed_data_bytes;
    result.decoded_cache_entries += overlay.decoded_cache_entries;
    result.decoded_cache_bytes += overlay.decoded_cache_bytes;
    result.decoded_cache_max_entries += overlay.decoded_cache_max_entries;
    result.decoded_cache_priority_entries += overlay.decoded_cache_priority_entries;
    result.decoded_cache_priority_reserve_entries += overlay.decoded_cache_priority_reserve_entries;
    result.decoded_cache_effective_max_entries += overlay.decoded_cache_effective_max_entries;
    result.decoded_cache_max_bytes += overlay.decoded_cache_max_bytes;
    result.decoded_cache_move_borrowed = result.decoded_cache_move_borrowed or
        overlay.decoded_cache_move_borrowed;
    result.persistent_batch_pool = result.persistent_batch_pool or overlay.persistent_batch_pool;
    result.decoded_cache_priority_insert_total += overlay.decoded_cache_priority_insert_total;
    result.decoded_cache_priority_skip_total += overlay.decoded_cache_priority_skip_total;
    result.decoded_cache_skip_entry_limit_total += overlay.decoded_cache_skip_entry_limit_total;
    result.decoded_cache_skip_byte_limit_total += overlay.decoded_cache_skip_byte_limit_total;
    result.decoded_cache_skip_oversize_total += overlay.decoded_cache_skip_oversize_total;
    result.decoded_cache_skip_allocation_total += overlay.decoded_cache_skip_allocation_total;
    result.chunk_cache_entries += overlay.chunk_cache_entries;
    result.chunk_cache_bytes += overlay.chunk_cache_bytes;
    result.chunk_cache_max_entries += overlay.chunk_cache_max_entries;
    result.chunk_cache_max_bytes += overlay.chunk_cache_max_bytes;
    result.chunk_cache_insert_total += overlay.chunk_cache_insert_total;
    result.chunk_cache_eviction_total += overlay.chunk_cache_eviction_total;
    result.chunk_cache_byte_limit_eviction_total += overlay.chunk_cache_byte_limit_eviction_total;
    result.chunk_cache_entry_limit_eviction_total += overlay.chunk_cache_entry_limit_eviction_total;
    result.total_ns = total_ns;
    result.index_lookup_ns += overlay.index_lookup_ns;
    result.index_records_read += overlay.index_records_read;
    result.chunk_plan_ns += overlay.chunk_plan_ns;
    result.cached_chunk_load_ns += overlay.cached_chunk_load_ns;
    result.cold_chunk_load_ns += overlay.cold_chunk_load_ns;
    result.cold_decompress_wall_ns += overlay.cold_decompress_wall_ns;
    result.cold_account_materialize_ns += overlay.cold_account_materialize_ns;
    result.chunk_cache_insert_ns += overlay.chunk_cache_insert_ns;
    return result;
}

fn resolveBatchLookups(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    results: []BatchLookupResult,
) !void {
    if (results.len == 0) return;

    const default_threads = envU64("SIG_COMPRESSED_ACCOUNT_STORE_BATCH_DECODE_THREADS", 1);
    const configured_threads = envU64(
        "SIG_COMPRESSED_ACCOUNT_STORE_BATCH_INDEX_THREADS",
        default_threads,
    );
    const max_threads: usize = @intCast(@min(configured_threads, MAX_BATCH_DECODE_THREADS));
    if (max_threads <= 1 or results.len == 1) {
        for (results) |*result| result.record = try self.lookup(result.pubkey);
        return;
    }

    var context: ParallelBatchLookupContext = .{
        .store = self,
        .results = results,
    };
    const worker_count = @min(max_threads, results.len);
    if (self.persistent_batch_pool) |*pool| {
        const tasks = try allocator.alloc(PersistentBatchLookupTask, worker_count);
        defer allocator.free(tasks);
        var wait_group = std.Thread.WaitGroup{};
        wait_group.startMany(worker_count);
        var batch = sig.sync.ThreadPool.Batch{};
        for (tasks) |*task| {
            task.* = .{
                .context = &context,
                .wait_group = &wait_group,
            };
            batch.push(.from(&task.task));
        }
        pool.schedule(batch);
        wait_group.wait();
    } else {
        const threads = try allocator.alloc(std.Thread, worker_count);
        defer allocator.free(threads);

        var spawned: usize = 0;
        errdefer {
            for (threads[0..spawned]) |*thread| thread.join();
        }
        while (spawned < worker_count) : (spawned += 1) {
            threads[spawned] = try std.Thread.spawn(.{}, parallelBatchLookupWorker, .{&context});
        }
        for (threads[0..spawned]) |*thread| thread.join();
    }
}

fn parallelBatchLookupWorker(context: *ParallelBatchLookupContext) void {
    while (true) {
        const index = context.next_index.fetchAdd(1, .monotonic);
        if (index >= context.results.len) return;
        context.results[index].record = context.store.lookup(
            context.results[index].pubkey,
        ) catch |err| {
            context.results[index].err = err;
            continue;
        };
    }
}

fn lookup(self: *CompressedAccountStore, address: Pubkey) !?IndexRecord {
    var timer = sig.time.Timer.start();
    defer self.metrics.lookup_time.observe(timer.read().asNanos());

    if (self.lookupCacheGet(address)) |cached| {
        if (cached.found) return cached.record;
        return null;
    }

    var base_offset: u64 = undefined;
    var lo: u64 = 0;
    var hi: u64 = undefined;
    if (self.radix_index) |*radix| {
        const range = radix.rangeForPubkey(&address.data);
        base_offset = self.records_offset;
        lo = range.lo;
        hi = range.hi;
    } else {
        const shard_id = shardPrefix(address, self.shard_prefix_bits);
        if (shard_id >= self.directory.len) return error.InvalidCompressedAccountIndex;
        const shard = self.directory[shard_id];
        base_offset = shard.offset;
        hi = shard.count;
    }

    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const offset = base_offset + mid * @as(u64, self.index_record_len);
        const record = try self.readIndexRecordAt(offset);
        const cmp = comparePubkey(record.pubkey, address);
        if (cmp == 0) {
            self.lookupCachePut(address, .{ .found = true, .record = record });
            return record;
        }
        if (cmp < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    self.lookupCachePut(address, .{ .found = false });
    return null;
}

fn lookupCacheGet(self: *CompressedAccountStore, address: Pubkey) ?LookupCacheEntry {
    if (self.lookup_cache_max_entries == 0) return null;

    self.lookup_cache_mutex.lock();
    defer self.lookup_cache_mutex.unlock();

    if (self.lookup_cache.get(address)) |entry| {
        self.metrics.lookup_cache_hit_count.inc();
        return entry;
    }
    self.metrics.lookup_cache_miss_count.inc();
    return null;
}

fn lookupCachePut(self: *CompressedAccountStore, address: Pubkey, entry: LookupCacheEntry) void {
    if (self.lookup_cache_max_entries == 0) return;

    self.lookup_cache_mutex.lock();
    defer self.lookup_cache_mutex.unlock();

    if (self.lookup_cache.contains(address)) return;
    if (self.lookup_cache.count() >= self.lookup_cache_max_entries) return;

    self.lookup_cache.put(self.allocator, address, entry) catch return;
    self.metrics.lookup_cache_insert_count.inc();
    self.metrics.lookup_cache_entries.set(@intCast(self.lookup_cache.count()));
}

fn decodedAccountCacheEnabled(self: *const CompressedAccountStore) bool {
    return self.decoded_account_cache_max_entries > 0 and self.decoded_account_cache_max_bytes > 0;
}

fn decodedAccountCacheBatchLoadEnabled(self: *const CompressedAccountStore) bool {
    return self.decodedAccountCacheEnabled() and !self.decoded_account_cache_clear_each_batch;
}

fn decodedAccountCacheHasEntryCapacity(
    self: *const CompressedAccountStore,
    policy: DecodedAccountCacheInsertPolicy,
) bool {
    return decodedAccountCacheHasCapacityForPolicy(
        self.decoded_account_cache_max_entries,
        self.decoded_account_cache_priority_reserve_entries,
        self.decoded_account_cache.count(),
        @intCast(self.decoded_account_cache_priority_entries),
        policy,
    );
}

fn decodedAccountCacheGet(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    address: Pubkey,
) !?AccountSharedData {
    if (!self.decodedAccountCacheEnabled()) return null;

    self.decoded_account_cache_mutex.lock();
    defer self.decoded_account_cache_mutex.unlock();

    if (self.decoded_account_cache.get(address)) |account| {
        self.metrics.decoded_account_cache_hit_count.inc();
        return try account.clone(allocator);
    }
    self.metrics.decoded_account_cache_miss_count.inc();
    return null;
}

fn decodedAccountCacheContains(
    self: *CompressedAccountStore,
    address: Pubkey,
) !bool {
    if (!self.decodedAccountCacheEnabled()) return false;

    self.decoded_account_cache_mutex.lock();
    defer self.decoded_account_cache_mutex.unlock();

    return self.decoded_account_cache.contains(address);
}

fn decodedAccountCachePutOwned(
    self: *CompressedAccountStore,
    address: Pubkey,
    account: *AccountSharedData,
    policy: DecodedAccountCacheInsertPolicy,
) !?*const AccountSharedData {
    if (!self.decodedAccountCacheEnabled()) return null;
    const account_bytes: u64 = @intCast(account.data.len);
    if (account_bytes > self.decoded_account_cache_max_bytes) {
        self.recordDecodedAccountCacheSkipReason(.oversize);
        self.recordDecodedAccountCachePrioritySkip(policy);
        return null;
    }

    self.decoded_account_cache_mutex.lock();
    defer self.decoded_account_cache_mutex.unlock();

    if (self.decoded_account_cache.get(address)) |stored| {
        account.deinit(self.allocator);
        account.* = undefined;
        return stored;
    }
    if (!self.decodedAccountCacheHasEntryCapacity(policy)) {
        self.recordDecodedAccountCacheSkipReason(.entry_limit);
        self.recordDecodedAccountCachePrioritySkip(policy);
        return null;
    }
    if (account_bytes > self.decoded_account_cache_max_bytes - self.decoded_account_cache_bytes) {
        self.recordDecodedAccountCacheSkipReason(.byte_limit);
        self.recordDecodedAccountCachePrioritySkip(policy);
        return null;
    }

    try self.decoded_account_cache.ensureUnusedCapacity(self.allocator, 1);
    const stored = try self.decoded_account_cache_headers.allocator().create(AccountSharedData);
    stored.* = account.*;
    account.* = undefined;
    self.decoded_account_cache.putAssumeCapacityNoClobber(address, stored);
    self.decoded_account_cache_bytes += account_bytes;

    self.metrics.decoded_account_cache_insert_count.inc();
    self.metrics.decoded_account_cache_entries.set(@intCast(self.decoded_account_cache.count()));
    self.metrics.decoded_account_cache_bytes.set(self.decoded_account_cache_bytes);
    if (policy == .priority) {
        self.decoded_account_cache_priority_entries += 1;
        _ = self.decoded_account_cache_priority_insert_count.fetchAdd(1, .monotonic);
        self.metrics.decoded_account_cache_priority_insert_count.inc();
        self.metrics.decoded_account_cache_priority_entries.set(self.decoded_account_cache_priority_entries);
    }
    return stored;
}

fn decodedAccountCacheClearLocked(self: *CompressedAccountStore) void {
    self.decodedAccountCacheClearUnlocked();
}

fn decodedAccountCacheClearUnlocked(self: *CompressedAccountStore) void {
    for (self.decoded_account_cache.values()) |account| {
        account.deinit(self.allocator);
    }
    self.decoded_account_cache.clearRetainingCapacity();
    _ = self.decoded_account_cache_headers.reset(.retain_capacity);
    self.decoded_account_cache_bytes = 0;
    self.decoded_account_cache_priority_entries = 0;
    self.metrics.decoded_account_cache_entries.set(0);
    self.metrics.decoded_account_cache_bytes.set(0);
    self.metrics.decoded_account_cache_priority_entries.set(0);
}

fn decodedAccountCachePutClone(
    self: *CompressedAccountStore,
    address: Pubkey,
    account: *const AccountSharedData,
    policy: DecodedAccountCacheInsertPolicy,
) ?*const AccountSharedData {
    if (!self.decodedAccountCacheBatchLoadEnabled()) return null;
    const account_bytes: u64 = @intCast(account.data.len);
    if (account_bytes > self.decoded_account_cache_max_bytes) {
        self.recordDecodedAccountCacheSkipReason(.oversize);
        self.metrics.decoded_account_cache_skip_count.inc();
        self.recordDecodedAccountCachePrioritySkip(policy);
        return null;
    }

    self.decoded_account_cache_mutex.lock();
    defer self.decoded_account_cache_mutex.unlock();

    if (self.decoded_account_cache.get(address)) |stored| return stored;
    if (!self.decodedAccountCacheHasEntryCapacity(policy)) {
        self.recordDecodedAccountCacheSkipReason(.entry_limit);
        self.metrics.decoded_account_cache_skip_count.inc();
        self.recordDecodedAccountCachePrioritySkip(policy);
        return null;
    }
    if (account_bytes > self.decoded_account_cache_max_bytes - self.decoded_account_cache_bytes) {
        self.recordDecodedAccountCacheSkipReason(.byte_limit);
        self.metrics.decoded_account_cache_skip_count.inc();
        self.recordDecodedAccountCachePrioritySkip(policy);
        return null;
    }

    self.decoded_account_cache.ensureUnusedCapacity(self.allocator, 1) catch {
        self.recordDecodedAccountCacheSkipReason(.allocation);
        self.metrics.decoded_account_cache_skip_count.inc();
        self.recordDecodedAccountCachePrioritySkip(policy);
        return null;
    };
    var cached_account = account.clone(self.allocator) catch {
        self.recordDecodedAccountCacheSkipReason(.allocation);
        self.metrics.decoded_account_cache_skip_count.inc();
        self.recordDecodedAccountCachePrioritySkip(policy);
        return null;
    };
    const stored = self.decoded_account_cache_headers.allocator().create(AccountSharedData) catch {
        cached_account.deinit(self.allocator);
        self.recordDecodedAccountCacheSkipReason(.allocation);
        self.metrics.decoded_account_cache_skip_count.inc();
        self.recordDecodedAccountCachePrioritySkip(policy);
        return null;
    };
    stored.* = cached_account;
    self.decoded_account_cache.putAssumeCapacityNoClobber(address, stored);
    self.decoded_account_cache_bytes += account_bytes;

    self.metrics.decoded_account_cache_insert_count.inc();
    self.metrics.decoded_account_cache_entries.set(@intCast(self.decoded_account_cache.count()));
    self.metrics.decoded_account_cache_bytes.set(self.decoded_account_cache_bytes);
    if (policy == .priority) {
        self.decoded_account_cache_priority_entries += 1;
        _ = self.decoded_account_cache_priority_insert_count.fetchAdd(1, .monotonic);
        self.metrics.decoded_account_cache_priority_insert_count.inc();
        self.metrics.decoded_account_cache_priority_entries.set(self.decoded_account_cache_priority_entries);
    }
    return stored;
}

fn recordDecodedAccountCachePrioritySkip(
    self: *CompressedAccountStore,
    policy: DecodedAccountCacheInsertPolicy,
) void {
    if (policy != .priority) return;
    _ = self.decoded_account_cache_priority_skip_count.fetchAdd(1, .monotonic);
    self.metrics.decoded_account_cache_priority_skip_count.inc();
}

const DecodedAccountCacheSkipReason = enum {
    entry_limit,
    byte_limit,
    oversize,
    allocation,
};

fn recordDecodedAccountCacheSkipReason(
    self: *CompressedAccountStore,
    reason: DecodedAccountCacheSkipReason,
) void {
    switch (reason) {
        .entry_limit => {
            _ = self.decoded_account_cache_skip_entry_limit_count.fetchAdd(1, .monotonic);
            self.metrics.decoded_account_cache_skip_entry_limit_count.inc();
        },
        .byte_limit => {
            _ = self.decoded_account_cache_skip_byte_limit_count.fetchAdd(1, .monotonic);
            self.metrics.decoded_account_cache_skip_byte_limit_count.inc();
        },
        .oversize => {
            _ = self.decoded_account_cache_skip_oversize_count.fetchAdd(1, .monotonic);
            self.metrics.decoded_account_cache_skip_oversize_count.inc();
        },
        .allocation => {
            _ = self.decoded_account_cache_skip_allocation_count.fetchAdd(1, .monotonic);
            self.metrics.decoded_account_cache_skip_allocation_count.inc();
        },
    }
}

fn snapshotDecodedAccountCache(
    self: *CompressedAccountStore,
    result: *BatchDecodeResult,
) void {
    self.decoded_account_cache_mutex.lock();
    result.decoded_cache_entries = @intCast(self.decoded_account_cache.count());
    result.decoded_cache_bytes = self.decoded_account_cache_bytes;
    result.decoded_cache_max_entries = @intCast(self.decoded_account_cache_max_entries);
    result.decoded_cache_priority_entries = self.decoded_account_cache_priority_entries;
    result.decoded_cache_priority_reserve_entries = @intCast(self.decoded_account_cache_priority_reserve_entries);
    result.decoded_cache_effective_max_entries = @intCast(
        self.decoded_account_cache_max_entries + self.decoded_account_cache_priority_reserve_entries,
    );
    result.decoded_cache_max_bytes = self.decoded_account_cache_max_bytes;
    result.decoded_cache_move_borrowed = self.decoded_account_cache_move_borrowed;
    self.decoded_account_cache_mutex.unlock();

    result.decoded_cache_skip_entry_limit_total =
        self.decoded_account_cache_skip_entry_limit_count.load(.monotonic);
    result.decoded_cache_skip_byte_limit_total =
        self.decoded_account_cache_skip_byte_limit_count.load(.monotonic);
    result.decoded_cache_skip_oversize_total =
        self.decoded_account_cache_skip_oversize_count.load(.monotonic);
    result.decoded_cache_skip_allocation_total =
        self.decoded_account_cache_skip_allocation_count.load(.monotonic);
    result.decoded_cache_priority_insert_total =
        self.decoded_account_cache_priority_insert_count.load(.monotonic);
    result.decoded_cache_priority_skip_total =
        self.decoded_account_cache_priority_skip_count.load(.monotonic);
}

fn snapshotChunkCache(
    self: *CompressedAccountStore,
    result: *BatchDecodeResult,
) void {
    self.chunk_cache_mutex.lock();
    defer self.chunk_cache_mutex.unlock();

    result.chunk_cache_entries = @intCast(self.chunk_cache_index.count());
    result.chunk_cache_bytes = self.chunk_cache_bytes;
    result.chunk_cache_max_entries = @intCast(self.chunk_cache.len);
    result.chunk_cache_max_bytes = self.chunk_cache_max_bytes;
    result.chunk_cache_insert_total = self.chunk_cache_insert_count;
    result.chunk_cache_eviction_total = self.chunk_cache_eviction_count;
    result.chunk_cache_byte_limit_eviction_total = self.chunk_cache_byte_limit_eviction_count;
    result.chunk_cache_entry_limit_eviction_total = self.chunk_cache_entry_limit_eviction_count;
}

fn batchDecodeFromCachedChunk(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    candidates: []const BatchDecodeCandidate,
    result: *BatchDecodeResult,
) !bool {
    _ = allocator;
    if (candidates.len == 0 or self.chunk_cache.len == 0) return false;
    const chunk_id = candidates[0].record.chunk_id;

    self.chunk_cache_mutex.lock();
    defer self.chunk_cache_mutex.unlock();

    const entry_index = self.chunk_cache_index.get(chunk_id) orelse return false;
    if (entry_index >= self.chunk_cache.len) {
        _ = self.chunk_cache_index.remove(chunk_id);
        return false;
    }
    const entry = &self.chunk_cache[entry_index];
    if (!entry.occupied or entry.chunk_id != chunk_id) {
        _ = self.chunk_cache_index.remove(chunk_id);
        return false;
    }

    self.chunk_cache_clock +%= 1;
    entry.last_used = self.chunk_cache_clock;
    for (candidates) |candidate| {
        var account = try self.decodeAccountRecordFromChunkWithMetrics(
            self.allocator,
            candidate.pubkey,
            candidate.record,
            entry.bytes,
        );
        var owns_account = true;
        errdefer if (owns_account) account.deinit(self.allocator);
        if (try self.decodedAccountCachePutOwned(candidate.pubkey, &account, .normal) != null) {
            owns_account = false;
            result.accounts_loaded += 1;
        } else {
            account.deinit(self.allocator);
            owns_account = false;
            self.metrics.decoded_account_cache_skip_count.inc();
            result.accounts_skipped += 1;
        }
    }
    return true;
}

fn batchDecodeFromChunkBytes(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    candidates: []const BatchDecodeCandidate,
    decompressed: []const u8,
    result: *BatchDecodeResult,
) !void {
    _ = allocator;
    for (candidates) |candidate| {
        var account = try self.decodeAccountRecordFromChunkWithMetrics(
            self.allocator,
            candidate.pubkey,
            candidate.record,
            decompressed,
        );
        var owns_account = true;
        errdefer if (owns_account) account.deinit(self.allocator);
        if (try self.decodedAccountCachePutOwned(candidate.pubkey, &account, .normal) != null) {
            owns_account = false;
            result.accounts_loaded += 1;
        } else {
            account.deinit(self.allocator);
            owns_account = false;
            self.metrics.decoded_account_cache_skip_count.inc();
            result.accounts_skipped += 1;
        }
    }
}

fn batchLoadFromCachedChunk(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    candidates: []const BatchDecodeCandidate,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: ?*sig.utils.collections.PubkeyMap(*const AccountSharedData),
    cache_insert_policy: DecodedAccountCacheInsertPolicy,
    result: *BatchDecodeResult,
) !bool {
    if (candidates.len == 0 or self.chunk_cache.len == 0) return false;
    const chunk_id = candidates[0].record.chunk_id;

    self.chunk_cache_mutex.lock();
    defer self.chunk_cache_mutex.unlock();

    const entry_index = self.chunk_cache_index.get(chunk_id) orelse return false;
    if (entry_index >= self.chunk_cache.len) {
        _ = self.chunk_cache_index.remove(chunk_id);
        return false;
    }
    const entry = &self.chunk_cache[entry_index];
    if (!entry.occupied or entry.chunk_id != chunk_id) {
        _ = self.chunk_cache_index.remove(chunk_id);
        return false;
    }

    self.chunk_cache_clock +%= 1;
    entry.last_used = self.chunk_cache_clock;
    for (candidates) |candidate| {
        var account = try self.decodeAccountRecordFromChunkWithMetrics(
            allocator,
            candidate.pubkey,
            candidate.record,
            entry.bytes,
        );
        try self.placeLoadedAccount(
            allocator,
            accounts,
            borrowed_accounts,
            candidate.pubkey,
            &account,
            cache_insert_policy,
            result,
        );
        result.accounts_loaded += 1;
    }
    return true;
}

fn batchLoadFromChunkBytes(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    candidates: []const BatchDecodeCandidate,
    decompressed: []const u8,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: ?*sig.utils.collections.PubkeyMap(*const AccountSharedData),
    cache_insert_policy: DecodedAccountCacheInsertPolicy,
    result: *BatchDecodeResult,
) !void {
    for (candidates) |candidate| {
        var account = try self.decodeAccountRecordFromChunkWithMetrics(
            allocator,
            candidate.pubkey,
            candidate.record,
            decompressed,
        );
        try self.placeLoadedAccount(
            allocator,
            accounts,
            borrowed_accounts,
            candidate.pubkey,
            &account,
            cache_insert_policy,
            result,
        );
        result.accounts_loaded += 1;
    }
}

fn batchLoadColdChunkGroups(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    groups: []const BatchChunkGroup,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: ?*sig.utils.collections.PubkeyMap(*const AccountSharedData),
    cache_insert_policy: DecodedAccountCacheInsertPolicy,
    result: *BatchDecodeResult,
) !void {
    if (groups.len == 0) return;

    const configured_threads = envU64("SIG_COMPRESSED_ACCOUNT_STORE_BATCH_DECODE_THREADS", 1);
    const max_threads_u64 = @min(configured_threads, MAX_BATCH_DECODE_THREADS);
    const max_threads: usize = @intCast(max_threads_u64);
    if (max_threads <= 1 or groups.len == 1) {
        return try self.batchLoadColdChunkGroupsSerial(
            allocator,
            groups,
            accounts,
            borrowed_accounts,
            cache_insert_policy,
            result,
        );
    }

    return try self.batchLoadColdChunkGroupsParallel(
        allocator,
        groups,
        accounts,
        borrowed_accounts,
        cache_insert_policy,
        result,
        @min(max_threads, groups.len),
    );
}

fn batchLoadColdChunkGroupsSerial(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    groups: []const BatchChunkGroup,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: ?*sig.utils.collections.PubkeyMap(*const AccountSharedData),
    cache_insert_policy: DecodedAccountCacheInsertPolicy,
    result: *BatchDecodeResult,
) !void {
    var scratch = try DecompressScratch.init(self.allocator);
    defer scratch.deinit(self.allocator);

    for (groups) |group| {
        var phase_timer = sig.time.Timer.start();
        const decompressed = try self.decompressChunkWithScratch(self.allocator, group.chunk, &scratch);
        result.cold_decompress_wall_ns += phase_timer.read().asNanos();
        var owns_decompressed = true;
        errdefer if (owns_decompressed) self.allocator.free(decompressed);
        phase_timer.reset();
        try self.batchLoadFromChunkBytes(
            allocator,
            group.candidates,
            decompressed,
            accounts,
            borrowed_accounts,
            cache_insert_policy,
            result,
        );
        result.cold_account_materialize_ns += phase_timer.read().asNanos();
        phase_timer.reset();
        _ = try self.insertPrefetchedChunk(group.chunk_id, decompressed);
        result.chunk_cache_insert_ns += phase_timer.read().asNanos();
        owns_decompressed = false;
        result.chunks_decoded += 1;
    }
}

fn batchLoadColdChunkGroupsParallel(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    groups: []const BatchChunkGroup,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: ?*sig.utils.collections.PubkeyMap(*const AccountSharedData),
    cache_insert_policy: DecodedAccountCacheInsertPolicy,
    result: *BatchDecodeResult,
    worker_count: usize,
) !void {
    std.debug.assert(worker_count > 1);
    std.debug.assert(worker_count <= groups.len);

    const parallel_results = try allocator.alloc(ParallelChunkDecodeResult, groups.len);
    defer {
        for (parallel_results) |*parallel_result| {
            if (parallel_result.decompressed) |decompressed| self.allocator.free(decompressed);
        }
        allocator.free(parallel_results);
    }
    @memset(parallel_results, .{});

    var context: ParallelChunkDecodeContext = .{
        .store = self,
        .groups = groups,
        .results = parallel_results,
    };

    var decompress_wall_timer = sig.time.Timer.start();
    if (self.persistent_batch_pool) |*pool| {
        const tasks = try allocator.alloc(PersistentChunkDecodeTask, worker_count);
        defer allocator.free(tasks);
        var wait_group = std.Thread.WaitGroup{};
        wait_group.startMany(worker_count);
        var batch = sig.sync.ThreadPool.Batch{};
        for (tasks) |*task| {
            task.* = .{
                .context = &context,
                .wait_group = &wait_group,
            };
            batch.push(.from(&task.task));
        }
        pool.schedule(batch);
        wait_group.wait();
    } else {
        const threads = try allocator.alloc(std.Thread, worker_count);
        defer allocator.free(threads);

        var spawned: usize = 0;
        errdefer {
            for (threads[0..spawned]) |*thread| thread.join();
        }
        while (spawned < worker_count) : (spawned += 1) {
            threads[spawned] = try std.Thread.spawn(.{}, parallelChunkDecodeWorker, .{&context});
        }
        for (threads[0..spawned]) |*thread| thread.join();
    }
    result.cold_decompress_wall_ns += decompress_wall_timer.read().asNanos();

    for (groups, parallel_results) |group, *parallel_result| {
        if (parallel_result.err) |err| return err;
        const decompressed = parallel_result.decompressed orelse return error.InvalidCompressedAccountChunk;
        var owns_decompressed = true;
        errdefer if (owns_decompressed) self.allocator.free(decompressed);
        var phase_timer = sig.time.Timer.start();
        try self.batchLoadFromChunkBytes(
            allocator,
            group.candidates,
            decompressed,
            accounts,
            borrowed_accounts,
            cache_insert_policy,
            result,
        );
        result.cold_account_materialize_ns += phase_timer.read().asNanos();
        phase_timer.reset();
        _ = try self.insertPrefetchedChunk(group.chunk_id, decompressed);
        result.chunk_cache_insert_ns += phase_timer.read().asNanos();
        parallel_result.decompressed = null;
        owns_decompressed = false;
        result.chunks_decoded += 1;
    }
}

fn parallelChunkDecodeWorker(context: *ParallelChunkDecodeContext) void {
    var scratch = DecompressScratch.init(context.store.allocator) catch |err| {
        while (true) {
            const index = context.next_index.fetchAdd(1, .monotonic);
            if (index >= context.groups.len) return;
            context.results[index].err = err;
        }
    };
    defer scratch.deinit(context.store.allocator);

    while (true) {
        const index = context.next_index.fetchAdd(1, .monotonic);
        if (index >= context.groups.len) return;
        const decompressed = context.store.decompressChunkWithScratch(
            context.store.allocator,
            context.groups[index].chunk,
            &scratch,
        ) catch |err| {
            context.results[index].err = err;
            continue;
        };
        context.results[index].decompressed = decompressed;
    }
}

fn placeLoadedAccount(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: ?*sig.utils.collections.PubkeyMap(*const AccountSharedData),
    pubkey: Pubkey,
    account: *AccountSharedData,
    cache_insert_policy: DecodedAccountCacheInsertPolicy,
    result: *BatchDecodeResult,
) !void {
    result.materialized_data_bytes += @intCast(account.data.len);

    if (borrowed_accounts) |borrowed| {
        const move_borrowed = self.decoded_account_cache_move_borrowed and
            self.decodedAccountCacheBatchLoadEnabled();
        const cached_account = if (move_borrowed)
            self.decodedAccountCachePutOwned(pubkey, account, cache_insert_policy) catch blk: {
                self.recordDecodedAccountCacheSkipReason(.allocation);
                self.recordDecodedAccountCachePrioritySkip(cache_insert_policy);
                break :blk null;
            }
        else
            self.decodedAccountCachePutClone(pubkey, account, cache_insert_policy);
        if (cached_account) |stable_account| {
            putBorrowedAccount(allocator, borrowed, pubkey, stable_account) catch |err| {
                if (!move_borrowed) {
                    account.deinit(allocator);
                    account.* = undefined;
                }
                return err;
            };
            result.accounts_borrowed += 1;
            result.borrowed_data_bytes += @intCast(stable_account.data.len);
            if (!move_borrowed) {
                account.deinit(allocator);
                account.* = undefined;
            }
            return;
        }
        if (move_borrowed) {
            self.metrics.decoded_account_cache_skip_count.inc();
        }
    } else {
        _ = self.decodedAccountCachePutClone(pubkey, account, cache_insert_policy);
    }

    try putLoadedAccount(allocator, accounts, pubkey, account);
}

fn putBorrowedAccount(
    allocator: std.mem.Allocator,
    accounts: *sig.utils.collections.PubkeyMap(*const AccountSharedData),
    pubkey: Pubkey,
    account: *const AccountSharedData,
) !void {
    const gop = try accounts.getOrPut(allocator, pubkey);
    gop.value_ptr.* = account;
}

fn putLoadedAccount(
    allocator: std.mem.Allocator,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    pubkey: Pubkey,
    account: *AccountSharedData,
) !void {
    errdefer account.deinit(allocator);

    const gop = try accounts.getOrPut(allocator, pubkey);
    if (gop.found_existing) gop.value_ptr.deinit(allocator);
    gop.value_ptr.* = account.*;
    account.* = undefined;
}

fn recordBatchDecodeResult(self: *CompressedAccountStore, result: BatchDecodeResult) void {
    self.metrics.batch_decode_pubkeys.set(result.pubkeys);
    self.metrics.batch_decode_compressed_pubkeys.set(result.compressed_pubkeys);
    self.metrics.batch_decode_missing_pubkeys.set(result.missing_pubkeys);
    self.metrics.batch_decode_unique_chunks.set(result.unique_chunks);
    self.metrics.batch_decode_chunks_decoded.set(result.chunks_decoded);
    self.metrics.batch_decode_chunks_cached.set(result.chunks_cached);
    self.metrics.batch_decode_accounts_loaded.set(result.accounts_loaded);
    self.metrics.batch_decode_accounts_cached.set(result.accounts_cached);
    self.metrics.batch_decode_accounts_skipped.set(result.accounts_skipped);
    self.metrics.batch_decode_index_records_read.set(result.index_records_read);
}

fn readIndexRecordAt(self: *CompressedAccountStore, offset: u64) !IndexRecord {
    var timer = sig.time.Timer.start();
    defer self.metrics.read_index_record_time.observe(timer.read().asNanos());

    _ = self.index_record_read_count.fetchAdd(1, .monotonic);
    self.metrics.index_record_read_count.inc();
    const index_record_len: usize = @intCast(self.index_record_len);

    if (self.index_mmap) |mapped| {
        if (offset > std.math.maxInt(usize)) return error.InvalidCompressedAccountIndex;
        const start: usize = @intCast(offset);
        if (start > mapped.len or index_record_len > mapped.len - start)
            return error.InvalidCompressedAccountIndex;
        return decodeIndexRecord(
            self.index_format_version,
            mapped[start..][0..index_record_len],
        );
    }

    var bytes: [INDEX_RECORD_LEN_MAX]u8 = undefined;
    const record_bytes = bytes[0..index_record_len];
    if (try self.index_file.preadAll(record_bytes, offset) != record_bytes.len)
        return error.InvalidCompressedAccountIndex;

    return decodeIndexRecord(self.index_format_version, record_bytes);
}

fn decodeIndexRecord(index_format_version: u32, bytes: []const u8) !IndexRecord {
    if (!isSupportedIndexFormat(index_format_version, @intCast(bytes.len)))
        return error.InvalidCompressedAccountIndex;
    const data_len = if (index_format_version == INDEX_FORMAT_VERSION_V2)
        readU32(bytes, 40)
    else
        readU32(bytes, 44);
    const record_len = if (index_format_version == INDEX_FORMAT_VERSION_V2)
        std.math.add(u32, @intCast(@sizeOf(SnapshotAccountHeader)), data_len) catch
            return error.InvalidCompressedAccountIndex
    else
        readU32(bytes, 40);
    return .{
        .pubkey = .{ .data = bytes[0..Pubkey.SIZE].* },
        .chunk_id = readU32(bytes, 32),
        .uncompressed_offset = readU32(bytes, 36),
        .record_len = record_len,
        .data_len = data_len,
    };
}

fn readAccountRecord(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    address: Pubkey,
    record: IndexRecord,
) !AccountSharedData {
    var timer = sig.time.Timer.start();
    defer self.metrics.read_account_record_time.observe(timer.read().asNanos());

    if (record.chunk_id >= self.chunk_table.len)
        return error.InvalidCompressedAccountRecord;
    const chunk = self.chunk_table[record.chunk_id];
    if (chunk.uncompressed_len == 0 or chunk.uncompressed_len > self.max_chunk_bytes)
        return error.InvalidCompressedAccountChunk;
    if (record.uncompressed_offset > chunk.uncompressed_len)
        return error.InvalidCompressedAccountRecord;
    if (record.record_len > chunk.uncompressed_len - record.uncompressed_offset)
        return error.InvalidCompressedAccountRecord;

    if (try self.readAccountRecordFromCache(allocator, address, record)) |account| return account;

    const decompressed = try self.decompressChunk(self.allocator, chunk);
    if (self.shouldCacheChunk(decompressed.len)) {
        return try self.insertChunkAndReadAccountRecord(allocator, address, record, decompressed);
    }
    defer self.allocator.free(decompressed);
    return try self.decodeAccountRecordFromChunkWithMetrics(allocator, address, record, decompressed);
}

fn readAccountRecordFromCache(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    address: Pubkey,
    record: IndexRecord,
) !?AccountSharedData {
    var timer = sig.time.Timer.start();
    defer self.metrics.read_account_record_cache_time.observe(timer.read().asNanos());

    if (self.chunk_cache.len == 0) return null;

    self.chunk_cache_mutex.lock();
    defer self.chunk_cache_mutex.unlock();

    if (self.chunk_cache_index.get(record.chunk_id)) |entry_index| {
        if (entry_index < self.chunk_cache.len) {
            const entry = &self.chunk_cache[entry_index];
            if (entry.occupied and entry.chunk_id == record.chunk_id) {
                self.chunk_cache_clock +%= 1;
                entry.last_used = self.chunk_cache_clock;
                self.metrics.cache_hit_count.inc();
                return try self.decodeAccountRecordFromChunkWithMetrics(allocator, address, record, entry.bytes);
            }
        }
        _ = self.chunk_cache_index.remove(record.chunk_id);
    }
    self.metrics.cache_miss_count.inc();
    return null;
}

fn chunkCachedLocal(self: *CompressedAccountStore, chunk_id: u32) bool {
    if (self.chunk_cache.len == 0) return false;

    self.chunk_cache_mutex.lock();
    defer self.chunk_cache_mutex.unlock();

    if (self.chunk_cache_index.get(chunk_id)) |entry_index| {
        if (entry_index < self.chunk_cache.len) {
            const entry = &self.chunk_cache[entry_index];
            if (entry.occupied and entry.chunk_id == chunk_id) return true;
        }
        _ = self.chunk_cache_index.remove(chunk_id);
    }
    return false;
}

fn cacheRemoveEntry(self: *CompressedAccountStore, index: usize) void {
    const entry = &self.chunk_cache[index];
    if (!entry.occupied) return;
    _ = self.chunk_cache_index.remove(entry.chunk_id);
    self.chunk_cache_bytes -= entry.bytes.len;
    self.allocator.free(entry.bytes);
    entry.* = .{};
    self.metrics.cache_bytes.set(self.chunk_cache_bytes);
    self.metrics.cache_entries.set(@intCast(self.chunk_cache_index.count()));
    self.metrics.cache_eviction_count.inc();
    self.chunk_cache_eviction_count +%= 1;
}

fn cacheAdoptEntry(
    self: *CompressedAccountStore,
    index: usize,
    chunk_id: u32,
    bytes: []u8,
) !void {
    if (self.chunk_cache[index].occupied) self.cacheRemoveEntry(index);

    self.chunk_cache_clock +%= 1;
    self.chunk_cache[index] = .{
        .occupied = true,
        .chunk_id = chunk_id,
        .bytes = bytes,
        .last_used = self.chunk_cache_clock,
    };
    self.chunk_cache_bytes += bytes.len;
    errdefer {
        self.chunk_cache_bytes -= self.chunk_cache[index].bytes.len;
        self.allocator.free(self.chunk_cache[index].bytes);
        self.chunk_cache[index] = .{};
        self.metrics.cache_bytes.set(self.chunk_cache_bytes);
        self.metrics.cache_entries.set(@intCast(self.chunk_cache_index.count()));
    }
    try self.chunk_cache_index.put(self.allocator, chunk_id, index);
    self.metrics.cache_bytes.set(self.chunk_cache_bytes);
    self.metrics.cache_entries.set(@intCast(self.chunk_cache_index.count()));
    self.metrics.cache_insert_count.inc();
    self.chunk_cache_insert_count +%= 1;
}

fn cacheRefreshExisting(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    address: Pubkey,
    record: IndexRecord,
) !?AccountSharedData {
    if (self.chunk_cache_index.get(record.chunk_id)) |entry_index| {
        if (entry_index < self.chunk_cache.len) {
            const entry = &self.chunk_cache[entry_index];
            if (entry.occupied and entry.chunk_id == record.chunk_id) {
                self.chunk_cache_clock +%= 1;
                entry.last_used = self.chunk_cache_clock;
                self.metrics.cache_hit_count.inc();
                return try decodeAccountRecordFromChunk(allocator, address, record, entry.bytes);
            }
        }
        _ = self.chunk_cache_index.remove(record.chunk_id);
    }
    return null;
}

fn insertChunkAndReadAccountRecord(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    address: Pubkey,
    record: IndexRecord,
    decompressed: []u8,
) !AccountSharedData {
    errdefer self.allocator.free(decompressed);

    self.chunk_cache_mutex.lock();
    defer self.chunk_cache_mutex.unlock();

    if (try self.cacheRefreshExisting(allocator, address, record)) |account| {
        self.allocator.free(decompressed);
        return account;
    }

    while (self.chunk_cache_bytes + decompressed.len > self.chunk_cache_max_bytes) {
        const victim = self.oldestCacheEntry() orelse break;
        self.cacheRemoveEntry(victim);
        self.chunk_cache_byte_limit_eviction_count +%= 1;
    }

    const empty_target = self.emptyCacheEntry();
    const target = empty_target orelse self.oldestCacheEntry() orelse {
        const account = try self.decodeAccountRecordFromChunkWithMetrics(allocator, address, record, decompressed);
        self.allocator.free(decompressed);
        return account;
    };
    if (empty_target == null) self.chunk_cache_entry_limit_eviction_count +%= 1;
    try self.cacheAdoptEntry(target, record.chunk_id, decompressed);
    errdefer self.cacheRemoveEntry(target);
    return try self.decodeAccountRecordFromChunkWithMetrics(allocator, address, record, self.chunk_cache[target].bytes);
}

fn shouldCacheChunk(self: *const CompressedAccountStore, len: usize) bool {
    return self.chunk_cache.len > 0 and len <= self.chunk_cache_max_bytes;
}

fn emptyCacheEntry(self: *CompressedAccountStore) ?usize {
    for (self.chunk_cache, 0..) |entry, i| {
        if (!entry.occupied) return i;
    }
    return null;
}

fn oldestCacheEntry(self: *CompressedAccountStore) ?usize {
    var victim: ?usize = null;
    var oldest: u64 = std.math.maxInt(u64);
    for (self.chunk_cache, 0..) |entry, i| {
        if (!entry.occupied) continue;
        if (victim == null or entry.last_used < oldest) {
            victim = i;
            oldest = entry.last_used;
        }
    }
    return victim;
}

fn prefetchChunkById(self: *CompressedAccountStore, chunk_id: u32) !PrefetchChunkStatus {
    if (chunk_id >= self.chunk_table.len)
        return error.InvalidCompressedAccountRecord;
    const chunk = self.chunk_table[chunk_id];
    if (chunk.uncompressed_len == 0 or chunk.uncompressed_len > self.max_chunk_bytes)
        return error.InvalidCompressedAccountChunk;
    if (!self.shouldCacheChunk(chunk.uncompressed_len)) return .skipped;
    if (self.touchCachedChunk(chunk_id)) return .cached;

    const decompressed = try self.decompressChunk(self.allocator, chunk);
    return try self.insertPrefetchedChunk(chunk_id, decompressed);
}

fn touchCachedChunk(self: *CompressedAccountStore, chunk_id: u32) bool {
    self.chunk_cache_mutex.lock();
    defer self.chunk_cache_mutex.unlock();

    if (self.chunk_cache_index.get(chunk_id)) |entry_index| {
        if (entry_index < self.chunk_cache.len) {
            const entry = &self.chunk_cache[entry_index];
            if (entry.occupied and entry.chunk_id == chunk_id) {
                self.chunk_cache_clock +%= 1;
                entry.last_used = self.chunk_cache_clock;
                return true;
            }
        }
        _ = self.chunk_cache_index.remove(chunk_id);
    }
    return false;
}

fn insertPrefetchedChunk(
    self: *CompressedAccountStore,
    chunk_id: u32,
    decompressed: []u8,
) !PrefetchChunkStatus {
    self.chunk_cache_mutex.lock();
    defer self.chunk_cache_mutex.unlock();

    if (self.chunk_cache_index.get(chunk_id)) |entry_index| {
        if (entry_index < self.chunk_cache.len) {
            const entry = &self.chunk_cache[entry_index];
            if (entry.occupied and entry.chunk_id == chunk_id) {
                self.chunk_cache_clock +%= 1;
                entry.last_used = self.chunk_cache_clock;
                self.allocator.free(decompressed);
                return .cached;
            }
        }
        _ = self.chunk_cache_index.remove(chunk_id);
    }

    while (self.chunk_cache_bytes + decompressed.len > self.chunk_cache_max_bytes) {
        const victim = self.oldestCacheEntry() orelse break;
        self.cacheRemoveEntry(victim);
        self.chunk_cache_byte_limit_eviction_count +%= 1;
    }

    const empty_target = self.emptyCacheEntry();
    const target = empty_target orelse self.oldestCacheEntry() orelse {
        self.allocator.free(decompressed);
        return .skipped;
    };
    if (empty_target == null) self.chunk_cache_entry_limit_eviction_count +%= 1;
    try self.cacheAdoptEntry(target, chunk_id, decompressed);
    return .loaded;
}

fn decompressChunk(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    chunk: ChunkEntry,
) ![]u8 {
    var timer = sig.time.Timer.start();
    defer self.metrics.decompress_chunk_time.observe(timer.read().asNanos());

    self.metrics.decompress_count.inc();
    self.metrics.decompress_compressed_bytes.add(chunk.compressed_len);
    self.metrics.decompress_uncompressed_bytes.add(chunk.uncompressed_len);

    const compressed = try allocator.alloc(u8, chunk.compressed_len);
    defer allocator.free(compressed);
    {
        var pread_timer = sig.time.Timer.start();
        defer self.metrics.segments_pread_time.observe(pread_timer.read().asNanos());
        if (try self.segments_file.preadAll(compressed, chunk.compressed_offset) != compressed.len)
            return error.InvalidCompressedAccountChunk;
    }

    const decompressed = try allocator.alloc(u8, chunk.uncompressed_len);
    errdefer allocator.free(decompressed);
    {
        var zstd_timer = sig.time.Timer.start();
        defer self.metrics.zstd_decode_time.observe(zstd_timer.read().asNanos());
        try decompressZstdFrame(allocator, compressed, decompressed);
    }
    return decompressed;
}

fn decompressChunkWithScratch(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    chunk: ChunkEntry,
    scratch: *DecompressScratch,
) ![]u8 {
    var timer = sig.time.Timer.start();
    defer self.metrics.decompress_chunk_time.observe(timer.read().asNanos());

    self.metrics.decompress_count.inc();
    self.metrics.decompress_compressed_bytes.add(chunk.compressed_len);
    self.metrics.decompress_uncompressed_bytes.add(chunk.uncompressed_len);

    const compressed = try scratch.compressedSlice(allocator, chunk.compressed_len);
    {
        var pread_timer = sig.time.Timer.start();
        defer self.metrics.segments_pread_time.observe(pread_timer.read().asNanos());
        if (try self.segments_file.preadAll(compressed, chunk.compressed_offset) != compressed.len)
            return error.InvalidCompressedAccountChunk;
    }

    const decompressed = try allocator.alloc(u8, chunk.uncompressed_len);
    errdefer allocator.free(decompressed);
    {
        var zstd_timer = sig.time.Timer.start();
        defer self.metrics.zstd_decode_time.observe(zstd_timer.read().asNanos());
        try decompressZstdFrameWithBuffer(compressed, decompressed, scratch.zstd_buf);
    }
    return decompressed;
}

fn decodeAccountRecordFromChunkWithMetrics(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    address: Pubkey,
    record: IndexRecord,
    decompressed: []const u8,
) !AccountSharedData {
    var timer = sig.time.Timer.start();
    defer self.metrics.read_account_record_decode_time.observe(timer.read().asNanos());
    return try decodeAccountRecordFromChunk(allocator, address, record, decompressed);
}

fn decodeAccountRecordFromChunk(
    allocator: std.mem.Allocator,
    address: Pubkey,
    record: IndexRecord,
    decompressed: []const u8,
) !AccountSharedData {
    const start: usize = record.uncompressed_offset;
    const end = start + record.record_len;
    const account_record = decompressed[start..end];
    if (account_record.len < @sizeOf(SnapshotAccountHeader))
        return error.InvalidCompressedAccountRecord;

    const header = decodeSnapshotAccountHeader(account_record[0..@sizeOf(SnapshotAccountHeader)]);
    if (!header.pubkey.equals(&address))
        return error.InvalidCompressedAccountRecord;
    if (header.executable > 1)
        return error.InvalidCompressedAccountRecord;
    if (header.data_len > sig.runtime.program.system.MAX_PERMITTED_DATA_LENGTH)
        return error.InvalidCompressedAccountRecord;
    if (header.data_len != record.data_len)
        return error.InvalidCompressedAccountRecord;
    if (@as(u64, @intCast(account_record.len)) != @sizeOf(SnapshotAccountHeader) + header.data_len)
        return error.InvalidCompressedAccountRecord;

    const data_len: usize = @intCast(header.data_len);
    const data = try allocator.alloc(u8, data_len);
    errdefer allocator.free(data);
    @memcpy(data, account_record[@sizeOf(SnapshotAccountHeader)..][0..data_len]);

    return .{
        .lamports = header.lamports,
        .data = data,
        .owner = header.owner,
        .executable = header.executable == 1,
        .rent_epoch = header.rent_epoch,
    };
}

fn decompressZstdFrame(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    decompressed: []u8,
) !void {
    const zstd_buf = try allocator.alloc(
        u8,
        std.compress.zstd.default_window_len + std.compress.zstd.block_size_max,
    );
    defer allocator.free(zstd_buf);

    try decompressZstdFrameWithBuffer(compressed, decompressed, zstd_buf);
}

fn decompressZstdFrameWithBuffer(
    compressed: []const u8,
    decompressed: []u8,
    zstd_buf: []u8,
) !void {
    var input = std.io.Reader.fixed(compressed);
    var stream: std.compress.zstd.Decompress = .init(&input, zstd_buf, .{});
    try stream.reader.readSliceAll(decompressed);
}

fn decodeSnapshotAccountHeader(bytes: *const [@sizeOf(SnapshotAccountHeader)]u8) SnapshotAccountHeader {
    var offset: usize = 0;
    const write_version = std.mem.readInt(u64, bytes[offset..][0..8], .little);
    offset += 8;
    const data_len = std.mem.readInt(u64, bytes[offset..][0..8], .little);
    offset += 8;
    const pubkey: Pubkey = .{ .data = bytes[offset..][0..Pubkey.SIZE].* };
    offset += Pubkey.SIZE;
    const lamports = std.mem.readInt(u64, bytes[offset..][0..8], .little);
    offset += 8;
    const rent_epoch = std.mem.readInt(sig.core.Epoch, bytes[offset..][0..8], .little);
    offset += 8;
    const owner: Pubkey = .{ .data = bytes[offset..][0..Pubkey.SIZE].* };
    offset += Pubkey.SIZE;
    const executable = bytes[offset];
    offset += 1;
    const padding = bytes[offset..][0..7].*;
    offset += 7;
    const hash: Hash = .{ .data = bytes[offset..][0..Hash.SIZE].* };

    return .{
        .write_version = write_version,
        .data_len = data_len,
        .pubkey = pubkey,
        .lamports = lamports,
        .rent_epoch = rent_epoch,
        .owner = owner,
        .executable = executable,
        ._padding = padding,
        .hash = hash,
    };
}

fn shardPrefix(pubkey: Pubkey, bits: u32) usize {
    var value: u32 = 0;
    var remaining = bits;
    var offset: usize = 0;
    while (remaining > 0) {
        const take = @min(@as(u32, 8), remaining);
        const take_shift: u5 = @intCast(take);
        const right_shift: u5 = @intCast(8 - take);
        value = (value << take_shift) | (@as(u32, pubkey.data[offset]) >> right_shift);
        remaining -= take;
        offset += 1;
    }
    return @intCast(value);
}

fn comparePubkey(left: Pubkey, right: Pubkey) i32 {
    for (left.data, right.data) |left_byte, right_byte| {
        if (left_byte < right_byte) return -1;
        if (left_byte > right_byte) return 1;
    }
    return 0;
}

fn envPath(allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    const raw = std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    errdefer allocator.free(raw);

    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) {
        allocator.free(raw);
        return null;
    }
    if (trimmed.len == raw.len) return raw;

    const copy = try allocator.dupe(u8, trimmed);
    allocator.free(raw);
    return copy;
}

fn envU64(key: []const u8, default_value: u64) u64 {
    const allocator = std.heap.page_allocator;
    const raw = std.process.getEnvVarOwned(allocator, key) catch return default_value;
    defer allocator.free(raw);

    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return default_value;
    return std.fmt.parseInt(u64, trimmed, 10) catch default_value;
}

fn envBool(key: []const u8, default_value: bool) bool {
    const allocator = std.heap.page_allocator;
    const raw = std.process.getEnvVarOwned(allocator, key) catch return default_value;
    defer allocator.free(raw);

    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return default_value;
    if (std.mem.eql(u8, trimmed, "1")) return true;
    if (std.mem.eql(u8, trimmed, "0")) return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "true")) return true;
    if (std.ascii.eqlIgnoreCase(trimmed, "false")) return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(trimmed, "no")) return false;
    return default_value;
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn readU64(bytes: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, bytes[offset..][0..8], .little);
}

fn isSupportedIndexFormat(version: u32, record_len: u32) bool {
    return (version == INDEX_FORMAT_VERSION_V1 and record_len == @as(u32, @intCast(INDEX_RECORD_LEN_V1))) or
        (version == INDEX_FORMAT_VERSION_V2 and record_len == @as(u32, @intCast(INDEX_RECORD_LEN_V2)));
}

test "compressed account index v1 and v2 records decode equivalently" {
    var v1 = [_]u8{0} ** INDEX_RECORD_LEN_V1;
    var v2 = [_]u8{0} ** INDEX_RECORD_LEN_V2;
    for (0..Pubkey.SIZE) |i| {
        v1[i] = @intCast(i + 1);
        v2[i] = @intCast(i + 1);
    }
    std.mem.writeInt(u32, v1[32..36], 17, .little);
    std.mem.writeInt(u32, v1[36..40], 4096, .little);
    std.mem.writeInt(u32, v1[40..44], 392, .little);
    std.mem.writeInt(u32, v1[44..48], 256, .little);
    std.mem.writeInt(u32, v2[32..36], 17, .little);
    std.mem.writeInt(u32, v2[36..40], 4096, .little);
    std.mem.writeInt(u32, v2[40..44], 256, .little);

    const decoded_v1 = try decodeIndexRecord(INDEX_FORMAT_VERSION_V1, &v1);
    const decoded_v2 = try decodeIndexRecord(INDEX_FORMAT_VERSION_V2, &v2);
    try std.testing.expectEqualSlices(u8, &decoded_v1.pubkey.data, &decoded_v2.pubkey.data);
    try std.testing.expectEqual(decoded_v1.chunk_id, decoded_v2.chunk_id);
    try std.testing.expectEqual(decoded_v1.uncompressed_offset, decoded_v2.uncompressed_offset);
    try std.testing.expectEqual(decoded_v1.record_len, decoded_v2.record_len);
    try std.testing.expectEqual(decoded_v1.data_len, decoded_v2.data_len);
    try std.testing.expectError(
        error.InvalidCompressedAccountIndex,
        decodeIndexRecord(INDEX_FORMAT_VERSION_V2, &v1),
    );
}

test "decoded account cache priority reserve preserves the normal quota" {
    try std.testing.expect(decodedAccountCacheHasCapacityForPolicy(4, 2, 0, 0, .normal));
    try std.testing.expect(decodedAccountCacheHasCapacityForPolicy(4, 2, 0, 0, .priority));
    try std.testing.expect(decodedAccountCacheHasCapacityForPolicy(4, 2, 4, 1, .normal));
    try std.testing.expect(!decodedAccountCacheHasCapacityForPolicy(4, 2, 5, 1, .normal));
    try std.testing.expect(decodedAccountCacheHasCapacityForPolicy(4, 2, 5, 1, .priority));
    try std.testing.expect(!decodedAccountCacheHasCapacityForPolicy(4, 2, 6, 2, .priority));

    try std.testing.expect(decodedAccountCacheHasCapacityForPolicy(4, 0, 3, 3, .normal));
    try std.testing.expect(decodedAccountCacheHasCapacityForPolicy(4, 0, 3, 3, .priority));
    try std.testing.expect(!decodedAccountCacheHasCapacityForPolicy(4, 0, 4, 4, .normal));
    try std.testing.expect(!decodedAccountCacheHasCapacityForPolicy(4, 0, 4, 4, .priority));
}

test "decoded account cache adopts owned data without cloning" {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var store: CompressedAccountStore = undefined;
    store.allocator = allocator;
    store.decoded_account_cache = .{};
    defer store.decoded_account_cache.deinit(allocator);
    store.decoded_account_cache_headers = std.heap.ArenaAllocator.init(allocator);
    defer store.decoded_account_cache_headers.deinit();
    store.decoded_account_cache_mutex = .{};
    store.decoded_account_cache_max_entries = 2;
    store.decoded_account_cache_priority_reserve_entries = 0;
    store.decoded_account_cache_max_bytes = 1024;
    store.decoded_account_cache_bytes = 0;
    store.decoded_account_cache_priority_entries = 0;
    store.metrics = try registry.initStruct(Metrics);

    const address = Pubkey.ZEROES;
    var account: AccountSharedData = .{
        .lamports = 42,
        .data = try allocator.dupe(u8, "owned-root-account"),
        .owner = Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 7,
    };
    var account_owned = true;
    defer if (account_owned) account.deinit(allocator);
    const original_data_ptr = account.data.ptr;

    const stored = (try store.decodedAccountCachePutOwned(
        address,
        &account,
        .normal,
    )).?;
    account_owned = false;
    defer stored.deinit(allocator);

    try std.testing.expectEqual(original_data_ptr, stored.data.ptr);
    try std.testing.expectEqualSlices(u8, "owned-root-account", stored.data);
    try std.testing.expectEqual(@as(usize, 1), store.decoded_account_cache.count());
    try std.testing.expectEqual(@as(u64, stored.data.len), store.decoded_account_cache_bytes);

    var duplicate: AccountSharedData = .{
        .lamports = 99,
        .data = try allocator.dupe(u8, "duplicate"),
        .owner = Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 8,
    };
    var duplicate_owned = true;
    defer if (duplicate_owned) duplicate.deinit(allocator);
    const existing = (try store.decodedAccountCachePutOwned(
        address,
        &duplicate,
        .normal,
    )).?;
    duplicate_owned = false;
    try std.testing.expectEqual(stored, existing);
    try std.testing.expectEqual(@as(usize, 1), store.decoded_account_cache.count());
}

test "layered batch result treats overlay misses as base fallthrough" {
    const overlay: BatchDecodeResult = .{
        .pubkeys = 3,
        .compressed_pubkeys = 2,
        .missing_pubkeys = 1,
        .unique_chunks = 2,
        .chunks_decoded = 2,
        .accounts_loaded = 2,
        .index_records_read = 10,
        .index_lookup_ns = 20,
    };
    const base: BatchDecodeResult = .{
        .pubkeys = 1,
        .compressed_pubkeys = 1,
        .missing_pubkeys = 0,
        .unique_chunks = 1,
        .chunks_decoded = 1,
        .accounts_loaded = 1,
        .index_records_read = 5,
        .index_lookup_ns = 10,
    };

    const result = mergeLayeredBatchDecodeResults(overlay, base, 42);
    try std.testing.expectEqual(@as(u64, 3), result.pubkeys);
    try std.testing.expectEqual(@as(u64, 3), result.compressed_pubkeys);
    try std.testing.expectEqual(@as(u64, 0), result.missing_pubkeys);
    try std.testing.expectEqual(@as(u64, 3), result.unique_chunks);
    try std.testing.expectEqual(@as(u64, 3), result.accounts_loaded);
    try std.testing.expectEqual(@as(u64, 15), result.index_records_read);
    try std.testing.expectEqual(@as(u64, 30), result.index_lookup_ns);
    try std.testing.expectEqual(@as(u64, 42), result.total_ns);
}
