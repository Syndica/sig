/// Captures account writes during replay for offline analysis and load testing.
///
/// When `enable_account_capture` is true, every account modified during transaction
/// commit is cloned and sent over a bounded channel to a background writer thread.
/// The writer serializes accounts in a flat binary format and compresses the output
/// with zstd.
///
/// The capture is size-bounded (default 1 GiB of uncompressed account data) to
/// prevent unbounded disk usage. When the limit is reached, new records are dropped.
///
/// ## File format
///
/// The output is a zstd-compressed stream of the following structure:
///
/// ```
/// Header (16 bytes):
///   magic:    [4]u8  = "ACAP"
///   version:  u32    = 1  (little-endian)
///   flags:    u64    = 0  (reserved)
///
/// Records (repeated):
///   record_len:  u32     -- byte length of the rest of this record
///   slot:        u64
///   pubkey:      [32]u8
///   lamports:    u64
///   owner:       [32]u8
///   executable:  u8
///   rent_epoch:  u64
///   data_len:    u32
///   data:        [data_len]u8
/// ```
///
/// `record_len` = 8 + 32 + 8 + 32 + 1 + 8 + 4 + data_len
///
/// ## Comptime gating
///
/// Set `enable_account_capture = true` in this file to compile in the capture
/// path. When false (default), all capture code is eliminated and the Committer
/// field is a zero-size `void`.
const std = @import("std");
const sig = @import("../sig.zig");
const zstd = @import("zstd");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const Channel = sig.sync.Channel;
const ExitCondition = sig.sync.ExitCondition;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const Logger = sig.trace.Logger("replay.account_capture");

/// Master switch. When false, all capture types become zero-size/no-ops so the
/// compiler eliminates every capture code path.
pub const enable = false;

/// Maximum uncompressed account data bytes to capture before dropping records.
pub const default_capture_limit: u64 = 1 * 1024 * 1024 * 1024; // 1 GiB

/// Bounded channel capacity. If the writer can't keep up, sends beyond this
/// depth are dropped (non-blocking).
pub const channel_bound: usize = 4096;

/// Default output file path.
pub const default_output_path = "account_capture.zst";

pub const CapturedAccount = struct {
    slot: Slot,
    pubkey: Pubkey,
    lamports: u64,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []u8, // owned allocation

    pub fn deinit(self: CapturedAccount, allocator: Allocator) void {
        allocator.free(self.data);
    }

    /// The fixed-size portion of a serialized record (everything except `data`).
    pub const fixed_size: u32 = 8 + 32 + 8 + 32 + 1 + 8 + 4; // = 93
};

pub const file_magic = [4]u8{ 'A', 'C', 'A', 'P' };
pub const file_version: u32 = 1;
pub const file_header_size: usize = 4 + 4 + 8; // magic + version + flags

pub const BoundedSender = struct {
    channel: *Channel(CapturedAccount),
    pending: Atomic(usize),

    pub fn init(channel: *Channel(CapturedAccount)) BoundedSender {
        return .{
            .channel = channel,
            .pending = Atomic(usize).init(0),
        };
    }

    /// Try to enqueue `item`. Returns true if sent, false if dropped.
    /// On drop, the caller is responsible for freeing the item.
    pub fn trySend(self: *BoundedSender, item: CapturedAccount) bool {
        const current = self.pending.load(.monotonic);
        if (current >= channel_bound) {
            return false;
        }
        // Optimistic increment — if two senders race past the check we might
        // briefly exceed the bound, which is acceptable for a best-effort capture.
        _ = self.pending.fetchAdd(1, .monotonic);
        self.channel.send(item) catch {
            _ = self.pending.fetchSub(1, .monotonic);
            return false;
        };
        return true;
    }

    /// Called by the receiver after consuming an item.
    pub fn ack(self: *BoundedSender) void {
        _ = self.pending.fetchSub(1, .monotonic);
    }
};

pub const SenderField = if (enable) *BoundedSender else void;
pub const sender_disabled: SenderField = if (enable) unreachable else {};

pub fn writerThread(
    sender: *BoundedSender,
    allocator: Allocator,
    output_path: []const u8,
    capture_limit: u64,
    exit: ExitCondition,
    logger: Logger,
) void {
    writerThreadInner(sender, allocator, output_path, capture_limit, exit, logger) catch |err| {
        logger.err().logf("account capture writer failed: {}", .{err});
    };
}

fn writerThreadInner(
    sender: *BoundedSender,
    allocator: Allocator,
    output_path: []const u8,
    capture_limit: u64,
    exit: ExitCondition,
    logger: Logger,
) !void {
    const channel = sender.channel;

    const file = try std.fs.cwd().createFile(output_path, .{});
    defer file.close();

    // Set up zstd streaming compression
    const compressor = try zstd.Compressor.init(.{});
    defer compressor.deinit();
    const zstd_buffer = try allocator.alloc(u8, zstd.Compressor.recommOutSize());
    defer allocator.free(zstd_buffer);

    const zstd_ctx = zstd.writerCtx(file.writer(), &compressor, zstd_buffer);
    const writer = zstd_ctx.writer();

    // Write file header
    try writer.writeAll(&file_magic);
    try writer.writeInt(u32, file_version, .little);
    try writer.writeInt(u64, 0, .little); // flags (reserved)

    var bytes_written: u64 = file_header_size;
    var records_written: u64 = 0;
    var records_dropped: u64 = 0;

    logger.info().logf("account capture started, writing to: {s}, limit: {} bytes", .{
        output_path,
        capture_limit,
    });

    while (exit.shouldRun()) {
        // Wait for data with periodic exit checks
        channel.waitToReceive(exit) catch break;

        // Drain available items
        while (channel.tryReceive()) |item| {
            defer item.deinit(allocator);
            defer sender.ack();

            const record_len: u32 = CapturedAccount.fixed_size + @as(u32, @intCast(item.data.len));
            const total_record_bytes: u64 = @sizeOf(u32) + record_len;

            // Check capture limit
            if (bytes_written + total_record_bytes > capture_limit) {
                records_dropped += 1;
                continue;
            }

            // Write record
            writer.writeInt(u32, record_len, .little) catch break;
            writer.writeInt(u64, item.slot, .little) catch break;
            writer.writeAll(&item.pubkey.data) catch break;
            writer.writeInt(u64, item.lamports, .little) catch break;
            writer.writeAll(&item.owner.data) catch break;
            writer.writeAll(&[1]u8{if (item.executable) 1 else 0}) catch break;
            writer.writeInt(u64, item.rent_epoch, .little) catch break;
            writer.writeInt(u32, @intCast(item.data.len), .little) catch break;
            writer.writeAll(item.data) catch break;

            bytes_written += total_record_bytes;
            records_written += 1;
        }
    }

    // Drain any remaining items after exit signal
    while (channel.tryReceive()) |item| {
        defer item.deinit(allocator);
        defer sender.ack();

        const record_len: u32 = CapturedAccount.fixed_size + @as(u32, @intCast(item.data.len));
        const total_record_bytes: u64 = @sizeOf(u32) + record_len;

        if (bytes_written + total_record_bytes > capture_limit) {
            records_dropped += 1;
            continue;
        }

        writer.writeInt(u32, record_len, .little) catch break;
        writer.writeInt(u64, item.slot, .little) catch break;
        writer.writeAll(&item.pubkey.data) catch break;
        writer.writeInt(u64, item.lamports, .little) catch break;
        writer.writeAll(&item.owner.data) catch break;
        writer.writeAll(&[1]u8{if (item.executable) 1 else 0}) catch break;
        writer.writeInt(u64, item.rent_epoch, .little) catch break;
        writer.writeInt(u32, @intCast(item.data.len), .little) catch break;
        writer.writeAll(item.data) catch break;

        bytes_written += total_record_bytes;
        records_written += 1;
    }

    // Flush zstd
    zstd_ctx.finish() catch |err| {
        logger.err().logf("account capture: zstd finish failed: {}", .{err});
    };

    logger.info().logf(
        "account capture complete: {} records written ({} bytes uncompressed), {} dropped",
        .{ records_written, bytes_written, records_dropped },
    );
}
