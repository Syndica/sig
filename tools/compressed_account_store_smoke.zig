const std = @import("std");
const sig = @import("sig");

const Rooted = sig.accounts_db.Rooted;
const AccountSharedData = sig.runtime.AccountSharedData;
const Pubkey = sig.core.Pubkey;

const DEFAULT_ROOTED_DB = "/private/tmp/chimera-compressed-rooted-smoke/accounts.db";

const Args = struct {
    rooted_db: []u8,
    pubkey: ?Pubkey = null,
    print_data_base64: bool = false,
    sample_count: usize = 1000,
    print_samples: usize = 5,
    batch_size: usize = 0,
    batch_only: bool = false,
    chunk_local: bool = false,
    accounts_per_chunk: usize = 16,
    batch_repeats: usize = 1,
    lookup_only: bool = false,
    lookup_repeats: usize = 5,
    lookup_warmup_repeats: usize = 1,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try parseArgs(allocator);
    defer allocator.free(args.rooted_db);
    const rooted_db_z = try allocator.dupeZ(u8, args.rooted_db);
    defer allocator.free(rooted_db_z);

    const rooted_dir = std.fs.path.dirname(args.rooted_db) orelse ".";
    try std.fs.cwd().makePath(rooted_dir);

    var rooted: Rooted = try .init(rooted_db_z);
    defer rooted.deinit();
    defer Rooted.deinitThreadLocals();

    if (!rooted.hasCompressedAccountStore()) return error.MissingCompressedAccountStore;
    if (rooted.count() != 0) return error.RootedSmokeDbMustBeEmpty;
    if (rooted.snapshotRefCount() != 0) return error.RootedSmokeDbMustNotHaveSnapshotRefs;

    if (args.pubkey) |pubkey| {
        const maybe_account = try rooted.get(allocator, pubkey);
        var account = maybe_account orelse {
            std.debug.print(
                "compressed_account_store_query pubkey={s} status=missing\n",
                .{pubkey.base58String().constSlice()},
            );
            return;
        };
        defer account.deinit(allocator);
        const data_tag = if (account.data.len >= 1) account.data[0] else 0;
        const data_u64_le = if (account.data.len >= 9)
            std.mem.readInt(u64, account.data[1..9], .little)
        else
            0;
        std.debug.print(
            "compressed_account_store_query pubkey={s} status=found lamports={} data_len={} data_tag={} data_u64_le={} owner={s} executable={} rent_epoch={}\n",
            .{
                pubkey.base58String().constSlice(),
                account.lamports,
                account.data.len,
                data_tag,
                data_u64_le,
                account.owner.base58String().constSlice(),
                account.executable,
                account.rent_epoch,
            },
        );
        if (args.print_data_base64) {
            const data = account.data;
            const encoded_len = std.base64.standard.Encoder.calcSize(data.len);
            const encoded = try allocator.alloc(u8, encoded_len);
            defer allocator.free(encoded);
            _ = std.base64.standard.Encoder.encode(encoded, data);
            std.debug.print("compressed_account_store_query_data_base64={s}\n", .{encoded});
        }
        return;
    }

    const samples = if (args.chunk_local)
        try rooted.compressedStoreSamplePubkeysFromChunks(allocator, args.sample_count, args.accounts_per_chunk)
    else
        try rooted.compressedStoreSamplePubkeys(allocator, args.sample_count);
    defer allocator.free(samples);
    if (samples.len == 0) return error.NoCompressedAccountSamples;

    var failures: usize = 0;
    if (args.lookup_only) {
        failures += try runLookupSmoke(
            allocator,
            &rooted,
            samples,
            args.lookup_repeats,
            args.lookup_warmup_repeats,
        );
        if (failures != 0) return error.CompressedAccountStoreSmokeFailed;
        return;
    }
    if (args.batch_size != 0) {
        failures += try runBatchSmoke(
            allocator,
            &rooted,
            args.rooted_db,
            samples,
            args.batch_size,
            args.batch_repeats,
            args.print_samples,
            !args.chunk_local,
        );
    }
    if (args.batch_only) {
        if (failures != 0) return error.CompressedAccountStoreSmokeFailed;
        return;
    }

    const latencies = try allocator.alloc(u64, samples.len);
    defer allocator.free(latencies);

    var zero_lamports: usize = 0;
    var zero_owner: usize = 0;
    var total_data_bytes: u64 = 0;
    var timer = try std.time.Timer.start();

    std.debug.print(
        "compressed_account_store_smoke_start rooted_db={s} samples={}\n",
        .{ args.rooted_db, samples.len },
    );

    for (samples, 0..) |sample, i| {
        timer.reset();
        const maybe_account = rooted.get(allocator, sample.pubkey) catch |err| {
            failures += 1;
            latencies[i] = timer.read();
            std.debug.print(
                "sample_fail index={} pubkey={s} error={}\n",
                .{ i, sample.pubkey.base58String().constSlice(), err },
            );
            continue;
        };
        latencies[i] = timer.read();

        var account = maybe_account orelse {
            failures += 1;
            std.debug.print(
                "sample_fail index={} pubkey={s} error=missing\n",
                .{ i, sample.pubkey.base58String().constSlice() },
            );
            continue;
        };
        defer account.deinit(allocator);

        if (!args.chunk_local and account.data.len != sample.data_len) {
            failures += 1;
            std.debug.print(
                "sample_fail index={} pubkey={s} error=data_len_mismatch expected={} actual={}\n",
                .{ i, sample.pubkey.base58String().constSlice(), sample.data_len, account.data.len },
            );
            continue;
        }
        if (account.lamports == 0) zero_lamports += 1;
        if (account.owner.isZeroed()) zero_owner += 1;
        total_data_bytes += account.data.len;

        if (i < args.print_samples) {
            std.debug.print(
                "sample_ok index={} pubkey={s} lamports={} data_len={} owner={s} chunk_id={} record_len={} latency_ms={d:.3}\n",
                .{
                    i,
                    sample.pubkey.base58String().constSlice(),
                    account.lamports,
                    account.data.len,
                    account.owner.base58String().constSlice(),
                    sample.chunk_id,
                    sample.record_len,
                    nsToMs(latencies[i]),
                },
            );
        }
    }

    var negative_pubkey: Pubkey = .{ .data = [_]u8{0xff} ** Pubkey.SIZE };
    if (samples.len > 0 and samples[0].pubkey.equals(&negative_pubkey)) {
        negative_pubkey = samples[0].pubkey;
        negative_pubkey.data[0] ^= 0xff;
    }
    const negative = try rooted.get(allocator, negative_pubkey);
    if (negative) |account| {
        defer account.deinit(allocator);
        failures += 1;
        std.debug.print(
            "negative_lookup_fail pubkey={s} unexpectedly_found=true\n",
            .{negative_pubkey.base58String().constSlice()},
        );
    } else {
        std.debug.print(
            "negative_lookup_ok pubkey={s}\n",
            .{negative_pubkey.base58String().constSlice()},
        );
    }

    std.mem.sort(u64, latencies, {}, std.sort.asc(u64));
    const p50 = percentile(latencies, 50, 100);
    const p95 = percentile(latencies, 95, 100);
    const p99 = percentile(latencies, 99, 100);

    std.debug.print(
        "compressed_account_store_smoke_result pass={} samples={} failures={} zero_lamports={} zero_owner={} total_data_bytes={} latency_p50_ms={d:.3} latency_p95_ms={d:.3} latency_p99_ms={d:.3}\n",
        .{
            failures == 0,
            samples.len,
            failures,
            zero_lamports,
            zero_owner,
            total_data_bytes,
            nsToMs(p50),
            nsToMs(p95),
            nsToMs(p99),
        },
    );

    if (failures != 0) return error.CompressedAccountStoreSmokeFailed;
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    var args: Args = .{
        .rooted_db = try allocator.dupe(u8, DEFAULT_ROOTED_DB),
    };
    errdefer allocator.free(args.rooted_db);

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--rooted-db") and i + 1 < argv.len) {
            i += 1;
            allocator.free(args.rooted_db);
            args.rooted_db = try allocator.dupe(u8, argv[i]);
        } else if (std.mem.eql(u8, arg, "--pubkey") and i + 1 < argv.len) {
            i += 1;
            args.pubkey = try Pubkey.parseRuntime(argv[i]);
        } else if (std.mem.eql(u8, arg, "--print-data-base64")) {
            args.print_data_base64 = true;
        } else if (std.mem.eql(u8, arg, "--sample") and i + 1 < argv.len) {
            i += 1;
            args.sample_count = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--print-samples") and i + 1 < argv.len) {
            i += 1;
            args.print_samples = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--batch-size") and i + 1 < argv.len) {
            i += 1;
            args.batch_size = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--batch-only")) {
            args.batch_only = true;
        } else if (std.mem.eql(u8, arg, "--chunk-local")) {
            args.chunk_local = true;
        } else if (std.mem.eql(u8, arg, "--accounts-per-chunk") and i + 1 < argv.len) {
            i += 1;
            args.accounts_per_chunk = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--batch-repeats") and i + 1 < argv.len) {
            i += 1;
            args.batch_repeats = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--lookup-only")) {
            args.lookup_only = true;
        } else if (std.mem.eql(u8, arg, "--lookup-repeats") and i + 1 < argv.len) {
            i += 1;
            args.lookup_repeats = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--lookup-warmup-repeats") and i + 1 < argv.len) {
            i += 1;
            args.lookup_warmup_repeats = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--help")) {
            printHelp();
            std.process.exit(0);
        } else {
            printHelp();
            return error.InvalidArgument;
        }
    }
    if (args.sample_count == 0) return error.InvalidArgument;
    if (args.batch_only and args.batch_size == 0) return error.InvalidArgument;
    if (args.chunk_local and args.accounts_per_chunk == 0) return error.InvalidArgument;
    if (args.batch_repeats == 0) return error.InvalidArgument;
    if (args.lookup_repeats == 0) return error.InvalidArgument;
    if (args.lookup_only and (args.batch_size != 0 or args.batch_only or args.chunk_local))
        return error.InvalidArgument;
    return args;
}

fn printHelp() void {
    std.debug.print(
        \\Usage:
        \\  zig build compressed_store_smoke -- --rooted-db /private/tmp/chimera-smoke/accounts.db --sample 1000
        \\  zig build compressed_store_smoke -- --rooted-db /private/tmp/chimera-smoke/accounts.db --pubkey <base58-pubkey> --print-data-base64
        \\  zig build compressed_store_smoke -- --rooted-db /private/tmp/chimera-smoke/accounts.db --sample 16384 --batch-size 4096 --batch-only
        \\  zig build compressed_store_smoke -- --rooted-db /private/tmp/chimera-smoke/accounts.db --sample 16384 --batch-size 4096 --batch-only --chunk-local --accounts-per-chunk 16 --batch-repeats 2
        \\  zig build compressed_store_smoke -- --rooted-db /private/tmp/chimera-smoke/accounts.db --sample 131072 --lookup-only --lookup-repeats 5 --lookup-warmup-repeats 1
        \\
        \\Required env:
        \\  SIG_COMPRESSED_ACCOUNT_STORE_INDEX=/path/account-index.bin
        \\  SIG_COMPRESSED_ACCOUNT_STORE_CHUNKS=/path/account-chunks.bin
        \\  SIG_COMPRESSED_ACCOUNT_STORE_SEGMENTS=/path/segments.zstframes
        \\
        \\The rooted DB must be empty so Rooted.get is forced through the cold path.
        \\Use --batch-size to measure grouped compressed-store reads without replay.
        \\Use --chunk-local to sample multiple accounts from each selected compressed chunk.
        \\Use --batch-repeats to rerun the same grouped loads in one process and measure chunk-cache hits.
        \\Use --lookup-only for deterministic randomized compressed-index lookups without chunk reads.
        \\Disable SIG_COMPRESSED_ACCOUNT_STORE_LOOKUP_CACHE and mmap for raw pread comparisons.
        \\
    , .{});
}

fn runLookupSmoke(
    allocator: std.mem.Allocator,
    rooted: *Rooted,
    samples: []const sig.accounts_db.CompressedAccountStore.Sample,
    repeats: usize,
    warmup_repeats: usize,
) !usize {
    const timing_count = try std.math.mul(usize, samples.len, repeats);
    const latencies = try allocator.alloc(u64, timing_count);
    defer allocator.free(latencies);
    const order = try allocator.alloc(usize, samples.len);
    defer allocator.free(order);
    for (order, 0..) |*entry, i| entry.* = i;
    shuffleLookupOrder(order);

    var failures: usize = 0;
    var warmup: usize = 0;
    while (warmup < warmup_repeats) : (warmup += 1) {
        for (order) |sample_index| {
            const sample = samples[sample_index];
            const actual = try rooted.compressedAccountChunkId(sample.pubkey);
            if (actual == null or actual.? != sample.chunk_id) failures += 1;
        }
    }

    var lookup_timer = try std.time.Timer.start();
    var total_timer = try std.time.Timer.start();
    var timing_index: usize = 0;
    var repeat: usize = 0;
    while (repeat < repeats) : (repeat += 1) {
        const rotation = if (order.len == 0) 0 else (repeat *% 8191) % order.len;
        for (0..order.len) |position| {
            const sample_index = order[(position + rotation) % order.len];
            const sample = samples[sample_index];
            lookup_timer.reset();
            const actual = try rooted.compressedAccountChunkId(sample.pubkey);
            latencies[timing_index] = lookup_timer.read();
            timing_index += 1;
            if (actual == null or actual.? != sample.chunk_id) failures += 1;
        }
    }
    const total_ns = total_timer.read();

    std.mem.sort(u64, latencies, {}, std.sort.asc(u64));
    const p50 = percentile(latencies, 50, 100);
    const p95 = percentile(latencies, 95, 100);
    const p99 = percentile(latencies, 99, 100);
    const lookup_count = samples.len * repeats;
    const lookups_per_second = if (total_ns == 0)
        0.0
    else
        @as(f64, @floatFromInt(lookup_count)) * @as(f64, std.time.ns_per_s) /
            @as(f64, @floatFromInt(total_ns));

    std.debug.print(
        "compressed_account_store_lookup_result pass={} samples={} repeats={} warmup_repeats={} lookups={} failures={} lookup_total_ms={d:.3} lookups_per_second={d:.3} latency_p50_us={d:.3} latency_p95_us={d:.3} latency_p99_us={d:.3}\n",
        .{
            failures == 0,
            samples.len,
            repeats,
            warmup_repeats,
            lookup_count,
            failures,
            nsToMs(total_ns),
            lookups_per_second,
            nsToUs(p50),
            nsToUs(p95),
            nsToUs(p99),
        },
    );
    return failures;
}

fn shuffleLookupOrder(order: []usize) void {
    var state: u64 = 0x9e3779b97f4a7c15;
    var upper = order.len;
    while (upper > 1) {
        upper -= 1;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const other: usize = @intCast(state % @as(u64, @intCast(upper + 1)));
        std.mem.swap(usize, &order[upper], &order[other]);
    }
}

fn runBatchSmoke(
    allocator: std.mem.Allocator,
    rooted: *Rooted,
    rooted_db: []const u8,
    samples: []const sig.accounts_db.CompressedAccountStore.Sample,
    batch_size: usize,
    repeats: usize,
    print_batches: usize,
    validate_sample_data_len: bool,
) !usize {
    if (batch_size == 0) return error.InvalidArgument;

    const batch_count = (samples.len + batch_size - 1) / batch_size;
    const timing_count = batch_count * repeats;
    const batch_latencies = try allocator.alloc(u64, timing_count);
    defer allocator.free(batch_latencies);
    const per_account_latencies = try allocator.alloc(u64, timing_count);
    defer allocator.free(per_account_latencies);
    const pubkeys = try allocator.alloc(Pubkey, samples.len);
    defer allocator.free(pubkeys);
    for (samples, pubkeys) |sample, *pubkey| pubkey.* = sample.pubkey;

    var failures: usize = 0;
    var loaded: u64 = 0;
    var missing: u64 = 0;
    var unique_chunks: u64 = 0;
    var chunks_decoded: u64 = 0;
    var chunks_cached: u64 = 0;
    var accounts_cached: u64 = 0;
    var accounts_skipped: u64 = 0;
    var total_data_bytes: u64 = 0;
    var index_lookup_ns: u64 = 0;
    var index_records_read: u64 = 0;
    var timer = try std.time.Timer.start();

    std.debug.print(
        "compressed_account_store_batch_smoke_start rooted_db={s} samples={} batch_size={} batches={} repeats={}\n",
        .{ rooted_db, samples.len, batch_size, batch_count, repeats },
    );

    var timing_index: usize = 0;
    var repeat: usize = 0;
    while (repeat < repeats) : (repeat += 1) {
        var batch_index: usize = 0;
        var start: usize = 0;
        while (start < samples.len) : (batch_index += 1) {
            const end = @min(samples.len, start + batch_size);
            const batch_len = end - start;
            defer start = end;

            var accounts: sig.utils.collections.PubkeyMap(AccountSharedData) = .{};
            defer deinitAccountMap(allocator, &accounts);

            timer.reset();
            const result = rooted.batchLoadCompressedAccountsForPubkeys(
                allocator,
                pubkeys[start..end],
                &accounts,
            ) catch |err| {
                failures += batch_len;
                const elapsed = timer.read();
                batch_latencies[timing_index] = elapsed;
                per_account_latencies[timing_index] = elapsed / batch_len;
                timing_index += 1;
                std.debug.print(
                    "batch_fail repeat={} index={} pubkeys={} error={}\n",
                    .{ repeat, batch_index, batch_len, err },
                );
                continue;
            };
            const elapsed = timer.read();
            batch_latencies[timing_index] = elapsed;
            per_account_latencies[timing_index] = elapsed / batch_len;
            timing_index += 1;

            loaded += result.accounts_loaded;
            missing += result.missing_pubkeys;
            unique_chunks += result.unique_chunks;
            chunks_decoded += result.chunks_decoded;
            chunks_cached += result.chunks_cached;
            accounts_cached += result.accounts_cached;
            accounts_skipped += result.accounts_skipped;
            index_lookup_ns += result.index_lookup_ns;
            index_records_read += result.index_records_read;

            if (result.accounts_loaded != batch_len or result.missing_pubkeys != 0) {
                failures += batch_len;
                std.debug.print(
                    "batch_fail repeat={} index={} pubkeys={} loaded={} missing={} skipped={}\n",
                    .{
                        repeat,
                        batch_index,
                        batch_len,
                        result.accounts_loaded,
                        result.missing_pubkeys,
                        result.accounts_skipped,
                    },
                );
                continue;
            }

            for (samples[start..end]) |sample| {
                const account = accounts.get(sample.pubkey) orelse {
                    failures += 1;
                    std.debug.print(
                        "batch_sample_fail repeat={} batch={} pubkey={s} error=missing_loaded_account\n",
                        .{ repeat, batch_index, sample.pubkey.base58String().constSlice() },
                    );
                    continue;
                };
                if (validate_sample_data_len and account.data.len != sample.data_len) {
                    failures += 1;
                    std.debug.print(
                        "batch_sample_fail repeat={} batch={} pubkey={s} error=data_len_mismatch expected={} actual={}\n",
                        .{ repeat, batch_index, sample.pubkey.base58String().constSlice(), sample.data_len, account.data.len },
                    );
                    continue;
                }
                total_data_bytes += account.data.len;
            }

            if (batch_index < print_batches) {
                std.debug.print(
                    "batch_ok repeat={} index={} pubkeys={} loaded={} unique_chunks={} chunks_decoded={} chunks_cached={} latency_ms={d:.3} per_account_ms={d:.6} index_lookup_ms={d:.3} index_records_read={}\n",
                    .{
                        repeat,
                        batch_index,
                        batch_len,
                        result.accounts_loaded,
                        result.unique_chunks,
                        result.chunks_decoded,
                        result.chunks_cached,
                        nsToMs(elapsed),
                        nsToMs(elapsed / batch_len),
                        nsToMs(result.index_lookup_ns),
                        result.index_records_read,
                    },
                );
            }
        }
    }

    std.mem.sort(u64, batch_latencies, {}, std.sort.asc(u64));
    std.mem.sort(u64, per_account_latencies, {}, std.sort.asc(u64));
    const batch_p50 = percentile(batch_latencies, 50, 100);
    const batch_p95 = percentile(batch_latencies, 95, 100);
    const batch_p99 = percentile(batch_latencies, 99, 100);
    const account_p50 = percentile(per_account_latencies, 50, 100);
    const account_p95 = percentile(per_account_latencies, 95, 100);
    const account_p99 = percentile(per_account_latencies, 99, 100);

    std.debug.print(
        "compressed_account_store_batch_smoke_result pass={} samples={} batches={} batch_size={} repeats={} failures={} loaded={} missing={} total_data_bytes={} unique_chunks_sum={} chunks_decoded={} chunks_cached={} accounts_cached={} accounts_skipped={} index_lookup_total_ms={d:.3} index_records_read={} index_records_per_loaded={d:.3} batch_latency_p50_ms={d:.3} batch_latency_p95_ms={d:.3} batch_latency_p99_ms={d:.3} account_latency_p50_ms={d:.6} account_latency_p95_ms={d:.6} account_latency_p99_ms={d:.6}\n",
        .{
            failures == 0,
            samples.len,
            batch_count,
            batch_size,
            repeats,
            failures,
            loaded,
            missing,
            total_data_bytes,
            unique_chunks,
            chunks_decoded,
            chunks_cached,
            accounts_cached,
            accounts_skipped,
            nsToMs(index_lookup_ns),
            index_records_read,
            if (loaded == 0)
                0.0
            else
                @as(f64, @floatFromInt(index_records_read)) / @as(f64, @floatFromInt(loaded)),
            nsToMs(batch_p50),
            nsToMs(batch_p95),
            nsToMs(batch_p99),
            nsToMs(account_p50),
            nsToMs(account_p95),
            nsToMs(account_p99),
        },
    );

    return failures;
}

fn deinitAccountMap(
    allocator: std.mem.Allocator,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
) void {
    for (accounts.values()) |*account| account.deinit(allocator);
    accounts.deinit(allocator);
}

fn percentile(sorted: []const u64, numerator: usize, denominator: usize) u64 {
    if (sorted.len == 0) return 0;
    const rank = (sorted.len * numerator + denominator - 1) / denominator;
    const index = if (rank == 0) 0 else @min(sorted.len - 1, rank - 1);
    return sorted[index];
}

fn nsToMs(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
}

fn nsToUs(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000.0;
}
