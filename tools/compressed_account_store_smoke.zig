const std = @import("std");
const sig = @import("sig");

const Rooted = sig.accounts_db.Rooted;
const Pubkey = sig.core.Pubkey;

const DEFAULT_ROOTED_DB = "/private/tmp/chimera-compressed-rooted-smoke/accounts.db";

const Args = struct {
    rooted_db: []u8,
    sample_count: usize = 1000,
    print_samples: usize = 5,
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

    const samples = try rooted.compressedStoreSamplePubkeys(allocator, args.sample_count);
    defer allocator.free(samples);
    if (samples.len == 0) return error.NoCompressedAccountSamples;

    const latencies = try allocator.alloc(u64, samples.len);
    defer allocator.free(latencies);

    var failures: usize = 0;
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

        if (account.data.len != sample.data_len) {
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
        } else if (std.mem.eql(u8, arg, "--sample") and i + 1 < argv.len) {
            i += 1;
            args.sample_count = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--print-samples") and i + 1 < argv.len) {
            i += 1;
            args.print_samples = try std.fmt.parseInt(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--help")) {
            printHelp();
            std.process.exit(0);
        } else {
            printHelp();
            return error.InvalidArgument;
        }
    }
    if (args.sample_count == 0) return error.InvalidArgument;
    return args;
}

fn printHelp() void {
    std.debug.print(
        \\Usage:
        \\  zig build compressed_store_smoke -- --rooted-db /private/tmp/chimera-smoke/accounts.db --sample 1000
        \\
        \\Required env:
        \\  SIG_COMPRESSED_ACCOUNT_STORE_INDEX=/path/account-index.bin
        \\  SIG_COMPRESSED_ACCOUNT_STORE_CHUNKS=/path/account-chunks.bin
        \\  SIG_COMPRESSED_ACCOUNT_STORE_SEGMENTS=/path/segments.zstframes
        \\
        \\The rooted DB must be empty so Rooted.get is forced through the cold path.
        \\
    , .{});
}

fn percentile(sorted: []const u64, numerator: usize, denominator: usize) u64 {
    if (sorted.len == 0) return 0;
    const index = @min(sorted.len - 1, ((sorted.len - 1) * numerator) / denominator);
    return sorted[index];
}

fn nsToMs(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
}
