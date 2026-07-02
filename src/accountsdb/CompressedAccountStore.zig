//! Read-only random-access account store backed by independent zstd chunks.
//!
//! This is the Chimera SSD-constrained cold account path: a compact binary
//! pubkey index points into seekable compressed chunks containing
//! `SnapshotAccountHeader || account.data` records.
const std = @import("std");
const sig = @import("../sig.zig");

const CompressedAccountStore = @This();

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const AccountSharedData = sig.runtime.AccountSharedData;

const INDEX_MAGIC = "CHIMIDX1";
const CHUNK_MAGIC = "CHIMCHK1";
const INDEX_HEADER_LEN: usize = 64;
const DIRECTORY_RECORD_LEN: usize = 16;
const INDEX_RECORD_LEN: usize = 64;
const CHUNK_HEADER_LEN: usize = 64;
const CHUNK_RECORD_LEN: usize = 32;
const FORMAT_VERSION: u32 = 1;
const DEFAULT_MAX_CHUNK_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_CHUNK_CACHE_SLOTS: u64 = 128;
const DEFAULT_CHUNK_CACHE_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_LOOKUP_CACHE_ENTRIES: u64 = 1_000_000;
const DEFAULT_DECODED_ACCOUNT_CACHE_ENTRIES: u64 = 16_384;
const DEFAULT_DECODED_ACCOUNT_CACHE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_DECODED_ACCOUNT_CACHE_CLEAR_EACH_BATCH = true;

allocator: std.mem.Allocator,
index_file: std.fs.File,
chunks_file: std.fs.File,
segments_file: std.fs.File,
directory: []DirectoryEntry,
chunk_table: []ChunkEntry,
overlay_store: ?*CompressedAccountStore = null,
chunk_cache: []ChunkCacheEntry,
chunk_cache_index: std.AutoHashMapUnmanaged(u32, usize),
chunk_cache_mutex: std.Thread.Mutex = .{},
chunk_cache_clock: u64 = 0,
chunk_cache_bytes: u64 = 0,
chunk_cache_max_bytes: u64,
lookup_cache: sig.utils.collections.PubkeyMap(LookupCacheEntry),
lookup_cache_mutex: std.Thread.Mutex = .{},
lookup_cache_max_entries: usize,
decoded_account_cache: sig.utils.collections.PubkeyMap(AccountSharedData),
decoded_account_cache_mutex: std.Thread.Mutex = .{},
decoded_account_cache_max_entries: usize,
decoded_account_cache_max_bytes: u64,
decoded_account_cache_clear_each_batch: bool,
decoded_account_cache_bytes: u64 = 0,
metrics: Metrics,
shard_prefix_bits: u32,
row_count: u64,
records_offset: u64,
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
    decoded_account_cache_hit_count: *sig.prometheus.Counter,
    decoded_account_cache_miss_count: *sig.prometheus.Counter,
    decoded_account_cache_insert_count: *sig.prometheus.Counter,
    decoded_account_cache_skip_count: *sig.prometheus.Counter,
    decoded_account_cache_entries: *sig.prometheus.Gauge(u64),
    decoded_account_cache_bytes: *sig.prometheus.Gauge(u64),
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
    slot: Slot,
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
    accounts_skipped: u64 = 0,
};

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

const PrefetchChunkStatus = enum {
    loaded,
    cached,
    skipped,
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

    if (index_version != FORMAT_VERSION or index_record_len != INDEX_RECORD_LEN)
        return error.InvalidCompressedAccountIndex;
    if (shard_prefix_bits == 0 or shard_prefix_bits > 16)
        return error.InvalidCompressedAccountIndex;
    const expected_shards = @as(u32, 1) << @intCast(shard_prefix_bits);
    if (shard_count_u32 != expected_shards)
        return error.InvalidCompressedAccountIndex;
    if (directory_offset != INDEX_HEADER_LEN)
        return error.InvalidCompressedAccountIndex;

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

    var chunks_header: [CHUNK_HEADER_LEN]u8 = undefined;
    if (try chunks_file.preadAll(&chunks_header, 0) != chunks_header.len)
        return error.InvalidCompressedAccountChunks;
    if (!std.mem.eql(u8, chunks_header[0..CHUNK_MAGIC.len], CHUNK_MAGIC))
        return error.InvalidCompressedAccountChunks;

    const chunk_version = readU32(&chunks_header, 8);
    const chunk_record_len = readU32(&chunks_header, 12);
    const chunk_count = readU64(&chunks_header, 16);
    const chunk_records_offset = readU64(&chunks_header, 24);
    if (chunk_version != FORMAT_VERSION or chunk_record_len != CHUNK_RECORD_LEN)
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
    if (decoded_account_cache_max_entries_u64 > std.math.maxInt(usize))
        return error.InvalidCompressedAccountChunks;
    var decoded_account_cache: sig.utils.collections.PubkeyMap(AccountSharedData) = .{};
    errdefer decoded_account_cache.deinit(allocator);

    const metrics = try sig.prometheus.globalRegistry().initStruct(Metrics);
    metrics.cache_bytes.set(0);
    metrics.cache_entries.set(0);
    metrics.lookup_cache_entries.set(0);
    metrics.decoded_account_cache_entries.set(0);
    metrics.decoded_account_cache_bytes.set(0);

    return .{
        .allocator = allocator,
        .index_file = index_file,
        .chunks_file = chunks_file,
        .segments_file = segments_file,
        .directory = directory,
        .chunk_table = chunk_table,
        .overlay_store = null,
        .chunk_cache = chunk_cache,
        .chunk_cache_index = chunk_cache_index,
        .chunk_cache_max_bytes = chunk_cache_max_bytes,
        .lookup_cache = lookup_cache,
        .lookup_cache_max_entries = @intCast(lookup_cache_max_entries_u64),
        .decoded_account_cache = decoded_account_cache,
        .decoded_account_cache_max_entries = @intCast(decoded_account_cache_max_entries_u64),
        .decoded_account_cache_max_bytes = envU64(
            "SIG_COMPRESSED_ACCOUNT_STORE_DECODED_ACCOUNT_CACHE_BYTES",
            DEFAULT_DECODED_ACCOUNT_CACHE_BYTES,
        ),
        .decoded_account_cache_clear_each_batch = envBool(
            "SIG_COMPRESSED_ACCOUNT_STORE_DECODED_ACCOUNT_CACHE_CLEAR_EACH_BATCH",
            DEFAULT_DECODED_ACCOUNT_CACHE_CLEAR_EACH_BATCH,
        ),
        .metrics = metrics,
        .shard_prefix_bits = shard_prefix_bits,
        .row_count = row_count,
        .records_offset = records_offset,
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

    const overlay_index_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_OVERLAY_INDEX");
    errdefer if (overlay_index_path) |path| allocator.free(path);

    const overlay_chunks_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_OVERLAY_CHUNKS");
    errdefer if (overlay_chunks_path) |path| allocator.free(path);

    const overlay_segments_path = try envPath(allocator, "SIG_COMPRESSED_ACCOUNT_STORE_OVERLAY_SEGMENTS");
    errdefer if (overlay_segments_path) |path| allocator.free(path);

    const base_missing = index_path == null and chunks_path == null and segments_path == null;
    const overlay_missing = overlay_index_path == null and overlay_chunks_path == null and overlay_segments_path == null;
    if (base_missing and overlay_missing) return null;
    if (index_path == null or chunks_path == null or segments_path == null)
        return error.MissingCompressedAccountStoreEnv;
    if (overlay_index_path == null or overlay_chunks_path == null or overlay_segments_path == null) {
        if (!overlay_missing) return error.MissingCompressedAccountStoreEnv;
    }

    defer allocator.free(index_path.?);
    defer allocator.free(chunks_path.?);
    defer allocator.free(segments_path.?);
    defer if (overlay_index_path) |path| allocator.free(path);
    defer if (overlay_chunks_path) |path| allocator.free(path);
    defer if (overlay_segments_path) |path| allocator.free(path);

    var store = try init(allocator, index_path.?, chunks_path.?, segments_path.?);
    errdefer store.deinit();

    if (!overlay_missing) {
        const overlay = try allocator.create(CompressedAccountStore);
        errdefer allocator.destroy(overlay);
        overlay.* = try init(allocator, overlay_index_path.?, overlay_chunks_path.?, overlay_segments_path.?);
        store.overlay_store = overlay;
    }

    return store;
}

pub fn deinit(self: *CompressedAccountStore) void {
    if (self.overlay_store) |overlay| {
        overlay.deinit();
        self.allocator.destroy(overlay);
        self.overlay_store = null;
    }
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
        const record = try self.readIndexRecordAt(self.records_offset + row_index * INDEX_RECORD_LEN);
        sample.* = .{
            .pubkey = record.pubkey,
            .data_len = record.data_len,
            .record_len = record.record_len,
            .chunk_id = record.chunk_id,
        };
    }

    return samples;
}

pub fn lookupChunkId(self: *CompressedAccountStore, address: Pubkey) !?u32 {
    if (self.overlay_store) |overlay| {
        if (try overlay.lookupChunkId(address)) |chunk_id| return chunk_id;
    }

    const record = try self.lookup(address) orelse return null;
    return record.chunk_id;
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

    var result: BatchDecodeResult = .{ .pubkeys = @intCast(pubkeys.len) };
    if (!self.decodedAccountCacheEnabled()) {
        result.accounts_skipped = @intCast(pubkeys.len);
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

        const decompressed = try self.decompressChunk(self.allocator, chunk);
        var owns_decompressed = true;
        errdefer if (owns_decompressed) self.allocator.free(decompressed);
        try self.batchDecodeFromChunkBytes(allocator, candidates.items[i..end], decompressed, &result);
        _ = try self.insertPrefetchedChunk(chunk_id, decompressed);
        owns_decompressed = false;
        result.chunks_decoded += 1;
        i = end;
    }

    self.recordBatchDecodeResult(result);
    return result;
}

pub fn batchLoadAccountsForPubkeys(
    self: *CompressedAccountStore,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
) !BatchDecodeResult {
    var timer = sig.time.Timer.start();
    defer self.metrics.batch_decode_time.observe(timer.read().asNanos());

    var result: BatchDecodeResult = .{ .pubkeys = @intCast(pubkeys.len) };

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

    var i: usize = 0;
    while (i < candidates.items.len) {
        const chunk_id = candidates.items[i].record.chunk_id;
        var end = i + 1;
        while (end < candidates.items.len and candidates.items[end].record.chunk_id == chunk_id) : (end += 1) {}

        if (try self.batchLoadFromCachedChunk(
            allocator,
            candidates.items[i..end],
            accounts,
            &result,
        )) {
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

        const decompressed = try self.decompressChunk(self.allocator, chunk);
        var owns_decompressed = true;
        errdefer if (owns_decompressed) self.allocator.free(decompressed);
        try self.batchLoadFromChunkBytes(
            allocator,
            candidates.items[i..end],
            decompressed,
            accounts,
            &result,
        );
        _ = try self.insertPrefetchedChunk(chunk_id, decompressed);
        owns_decompressed = false;
        result.chunks_decoded += 1;
        i = end;
    }

    self.recordBatchDecodeResult(result);
    return result;
}

fn lookup(self: *CompressedAccountStore, address: Pubkey) !?IndexRecord {
    var timer = sig.time.Timer.start();
    defer self.metrics.lookup_time.observe(timer.read().asNanos());

    if (self.lookupCacheGet(address)) |cached| {
        if (cached.found) return cached.record;
        return null;
    }

    const shard_id = shardPrefix(address, self.shard_prefix_bits);
    if (shard_id >= self.directory.len) return error.InvalidCompressedAccountIndex;
    const shard = self.directory[shard_id];

    var lo: usize = 0;
    var hi: usize = shard.count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const offset = shard.offset + @as(u64, @intCast(mid)) * INDEX_RECORD_LEN;
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
    account: AccountSharedData,
) !bool {
    if (!self.decodedAccountCacheEnabled()) return false;
    const account_bytes: u64 = @intCast(account.data.len);
    if (account_bytes > self.decoded_account_cache_max_bytes) return false;

    self.decoded_account_cache_mutex.lock();
    defer self.decoded_account_cache_mutex.unlock();

    if (self.decoded_account_cache.getPtr(address)) |existing| {
        const existing_bytes: u64 = @intCast(existing.data.len);
        const projected = self.decoded_account_cache_bytes - existing_bytes + account_bytes;
        if (projected > self.decoded_account_cache_max_bytes) return false;
        existing.deinit(self.allocator);
        existing.* = account;
        self.decoded_account_cache_bytes = projected;
    } else {
        if (self.decoded_account_cache.count() >= self.decoded_account_cache_max_entries)
            return false;
        if (self.decoded_account_cache_bytes + account_bytes > self.decoded_account_cache_max_bytes)
            return false;
        try self.decoded_account_cache.put(self.allocator, address, account);
        self.decoded_account_cache_bytes += account_bytes;
    }

    self.metrics.decoded_account_cache_insert_count.inc();
    self.metrics.decoded_account_cache_entries.set(@intCast(self.decoded_account_cache.count()));
    self.metrics.decoded_account_cache_bytes.set(self.decoded_account_cache_bytes);
    return true;
}

fn decodedAccountCacheClearLocked(self: *CompressedAccountStore) void {
    self.decodedAccountCacheClearUnlocked();
}

fn decodedAccountCacheClearUnlocked(self: *CompressedAccountStore) void {
    for (self.decoded_account_cache.values()) |*account| {
        account.deinit(self.allocator);
    }
    self.decoded_account_cache.clearRetainingCapacity();
    self.decoded_account_cache_bytes = 0;
    self.metrics.decoded_account_cache_entries.set(0);
    self.metrics.decoded_account_cache_bytes.set(0);
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
        if (try self.decodedAccountCachePutOwned(candidate.pubkey, account)) {
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
        if (try self.decodedAccountCachePutOwned(candidate.pubkey, account)) {
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
        try putLoadedAccount(allocator, accounts, candidate.pubkey, &account);
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
    result: *BatchDecodeResult,
) !void {
    for (candidates) |candidate| {
        var account = try self.decodeAccountRecordFromChunkWithMetrics(
            allocator,
            candidate.pubkey,
            candidate.record,
            decompressed,
        );
        try putLoadedAccount(allocator, accounts, candidate.pubkey, &account);
        result.accounts_loaded += 1;
    }
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
}

fn readIndexRecordAt(self: *CompressedAccountStore, offset: u64) !IndexRecord {
    var timer = sig.time.Timer.start();
    defer self.metrics.read_index_record_time.observe(timer.read().asNanos());

    var bytes: [INDEX_RECORD_LEN]u8 = undefined;
    if (try self.index_file.preadAll(&bytes, offset) != bytes.len)
        return error.InvalidCompressedAccountIndex;

    return .{
        .pubkey = .{ .data = bytes[0..Pubkey.SIZE].* },
        .chunk_id = readU32(&bytes, 32),
        .uncompressed_offset = readU32(&bytes, 36),
        .record_len = readU32(&bytes, 40),
        .data_len = readU32(&bytes, 44),
        .slot = readU64(&bytes, 48),
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
    }

    const target = self.emptyCacheEntry() orelse self.oldestCacheEntry() orelse {
        const account = try self.decodeAccountRecordFromChunkWithMetrics(allocator, address, record, decompressed);
        self.allocator.free(decompressed);
        return account;
    };
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
    }

    const target = self.emptyCacheEntry() orelse self.oldestCacheEntry() orelse {
        self.allocator.free(decompressed);
        return .skipped;
    };
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
    var input = std.io.Reader.fixed(compressed);
    const zstd_buf = try allocator.alloc(
        u8,
        std.compress.zstd.default_window_len + std.compress.zstd.block_size_max,
    );
    defer allocator.free(zstd_buf);

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
