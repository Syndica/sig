const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");
const bincode = sig.bincode;

const c = @cImport({
    // used to set/modify the pipe size
    @cDefine("_GNU_SOURCE", {});
    @cInclude("fcntl.h");

    // used for mkfifo syscall
    @cInclude("sys/types.h");
    @cInclude("sys/stat.h");
});

const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const RecycleFBA = sig.utils.allocators.RecycleFBA;
const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const Atomic = std.atomic.Value;

const globalRegistry = sig.prometheus.globalRegistry;

const PIPE_MAX_SIZE_PATH = "/proc/sys/fs/pipe-max-size";

pub const AccountPayload = struct {
    /// used to know how much to allocate to read the full data slice
    len: u64,
    payload: VersionedAccountPayload,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.payload.deinit(allocator);
    }
};

// TODO: https://github.com/Syndica/sig/pull/209#discussion_r1719858112
pub const VersionedAccountPayload = union(enum(u8)) {
    AccountPayloadV1: AccountPayloadV1,
    EndOfSnapshotLoading: void,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .AccountPayloadV1 => self.AccountPayloadV1.deinit(allocator),
            .EndOfSnapshotLoading => {},
        }
    }
};

pub const AccountPayloadV1 = struct {
    slot: Slot,
    pubkeys: []const Pubkey,
    // PERF: the data slice per account is the biggest to read,
    // we can probably put it into its own field (data: [][]u8)
    // and read it all in on i/o
    accounts: []const Account,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (self.accounts) |*account| {
            account.deinit(allocator);
        }
        allocator.free(self.accounts);
        allocator.free(self.pubkeys);
    }
};

pub const GeyserWriterMetrics = struct {
    recycle_fba_empty_loop_count: *Counter,
    pipe_full_count: *Counter,
    n_payloads: *Counter,
    total_bytes: *Counter,

    pub const prefix = "geyser_writer";

    pub fn init() !GeyserWriterMetrics {
        return try globalRegistry().initStruct(GeyserWriterMetrics);
    }
};

pub const GeyserWriter = struct {
    /// used to allocate a buf for serialization
    allocator: std.mem.Allocator,
    /// used to alloc/free the data being streamed
    io_allocator: std.mem.Allocator,
    /// backing state for io_allocator
    io_allocator_state: *RecycleFBA(.{}),
    /// pipe to write to
    file: std.fs.File,
    /// channel which data is streamed into and then written to the pipe
    io_channel: *sig.sync.Channel([]u8),
    exit: *std.atomic.Value(bool),
    metrics: GeyserWriterMetrics,

    /// set when the writer thread is running
    io_handle: ?std.Thread = null,

    const Self = @This();

    pub const WritePipeError = error{
        PipeBlockedWithExitSignaled,
        PipeClosed,
    } || std.posix.WriteError;

    /// initializes a linux pipe to stream data to
    pub fn init(
        allocator: std.mem.Allocator,
        pipe_path: []const u8,
        exit: *std.atomic.Value(bool),
        // used to allocate/free memory for the io channel
        io_fba_bytes: u64,
    ) !Self {
        const file = try openPipe(pipe_path);
        const io_channel = try sig.sync.Channel([]u8).create(allocator);
        const io_allocator_state = try allocator.create(RecycleFBA(.{}));
        io_allocator_state.* = try RecycleFBA(.{}).init(.{
            .records_allocator = allocator,
            .bytes_allocator = allocator,
        }, io_fba_bytes);
        const metrics = try GeyserWriterMetrics.init();

        return .{
            .allocator = allocator,
            .io_allocator = io_allocator_state.allocator(),
            .io_allocator_state = io_allocator_state,
            .io_channel = io_channel,
            .file = file,
            .metrics = metrics,
            .exit = exit,
        };
    }

    pub fn deinit(self: *Self) void {
        self.exit.store(true, .release);
        if (self.io_handle) |*handle| handle.join();

        self.file.close();
        self.io_channel.deinit();
        self.allocator.destroy(self.io_channel);
        self.io_allocator_state.deinit();
        self.allocator.destroy(self.io_allocator_state);
    }

    pub fn spawnIOLoop(self: *Self) !void {
        const handle = try std.Thread.spawn(.{}, IOStreamLoop, .{self});
        self.io_handle = handle;
    }

    pub fn IOStreamLoop(self: *Self) !void {
        while (true) {
            self.io_channel.waitToReceive(.{ .unordered = self.exit }) catch break;

            while (self.io_channel.tryReceive()) |payload| {
                _ = self.writeToPipe(payload) catch |err| {
                    if (err == WritePipeError.PipeBlockedWithExitSignaled) {
                        return;
                    } else {
                        std.debug.print("error writing to pipe: {}\n", .{err});
                        return err;
                    }
                };
                self.metrics.n_payloads.inc();
                self.io_allocator.free(payload);
            }
        }
    }

    /// serializes the payload and sends it through the IO channel
    /// to eventually be written to the pipe.
    pub fn writePayloadToPipe(
        self: *Self,
        versioned_payload: VersionedAccountPayload,
    ) !void {
        const buf = try self.writePayloadToSlice(versioned_payload);
        try self.io_channel.send(buf);
    }

    /// serializes the payload into a recycled buffer to be eventually written to
    /// the pipe. NOTE: this is thread safe.
    pub fn writePayloadToSlice(
        self: *Self,
        versioned_payload: VersionedAccountPayload,
    ) ![]u8 {
        const len = bincode.sizeOf(versioned_payload, .{});
        const payload = sig.geyser.core.AccountPayload{
            .len = len,
            .payload = versioned_payload,
        };
        const total_len = bincode.sizeOf(payload, .{});

        // obtain a memory to write to
        const buf = blk: while (true) {
            const buf = self.io_allocator.alloc(u8, total_len) catch {
                // no memory available rn - unlock and wait
                self.metrics.recycle_fba_empty_loop_count.inc();
                std.Thread.sleep(std.time.ns_per_ms);
                if (self.exit.load(.acquire)) {
                    return error.MemoryBlockedWithExitSignaled;
                }
                continue;
            };
            break :blk buf;
        };
        errdefer {
            self.io_allocator.free(buf);
        }

        // serialize the payload
        const data = try bincode.writeToSlice(buf, payload, .{});
        return data;
    }

    /// streams a buffer of bytes to the pipe and returns the number of bytes wrote.
    ///
    /// NOTE: this will block if the pipe is not big enough, which is why we
    /// have the exit flag to signal to stop writing.
    pub fn writeToPipe(
        self: *Self,
        buf: []u8,
    ) WritePipeError!u64 {
        var n_bytes_written_total: u64 = 0;
        while (n_bytes_written_total < buf.len) {
            const n_bytes_written = self.file.write(buf[n_bytes_written_total..]) catch |err| {
                if (err == std.posix.WriteError.WouldBlock) {
                    if (self.exit.load(.acquire)) {
                        return WritePipeError.PipeBlockedWithExitSignaled;
                    } else {
                        // pipe is full but we dont need to exit, so we try again
                        self.metrics.pipe_full_count.inc();
                        continue;
                    }
                } else {
                    return err;
                }
            };

            if (n_bytes_written == 0) {
                return WritePipeError.PipeClosed;
            }
            n_bytes_written_total += n_bytes_written;
            self.metrics.total_bytes.add(n_bytes_written);
        }

        std.debug.assert(n_bytes_written_total == buf.len);
        return n_bytes_written_total;
    }
};

pub fn createGeyserWriter(
    allocator: std.mem.Allocator,
    pipe_path: []const u8,
    writer_fba_bytes: usize,
) !*GeyserWriter {
    const exit = try allocator.create(Atomic(bool));
    errdefer allocator.destroy(exit);
    exit.* = Atomic(bool).init(false);

    const geyser_writer = try allocator.create(GeyserWriter);
    errdefer allocator.destroy(geyser_writer);

    geyser_writer.* = try GeyserWriter.init(
        allocator,
        pipe_path,
        exit,
        writer_fba_bytes,
    );
    errdefer geyser_writer.deinit();

    // start the geyser writer
    try geyser_writer.spawnIOLoop();
    return geyser_writer;
}

pub const GeyserReaderMetrics = struct {
    io_buf_size: *GaugeU64,
    bincode_buf_size: *GaugeU64,
    pipe_empty_count: *Counter,
    total_payloads: *Counter,
    total_bytes: *Counter,

    const GaugeU64 = Gauge(u64);

    pub const prefix = "geyser_reader";

    pub fn init() !GeyserReaderMetrics {
        return try globalRegistry().initStruct(GeyserReaderMetrics);
    }
};

pub const GeyserReader = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    /// read from pipe into this
    io_buf: []u8,
    /// use this for bincode allocations (and is the underlying memory for fb_allocator)
    bincode_buf: []u8,
    /// NOTE: not thread-safe
    bincode_allocator: std.heap.FixedBufferAllocator,
    metrics: GeyserReaderMetrics,
    exit: ?*std.atomic.Value(bool),

    const Self = @This();

    pub const AllocatorConfig = struct {
        // pipe -> io_buf
        io_buf_len: u64 = 1 << 18, // 256kb
        // io_buf -> bincode_deser_buf -> Payload struct
        bincode_buf_len: u64 = 1 << 30, // 1gb
    };

    pub fn init(
        allocator: std.mem.Allocator,
        pipe_path: []const u8,
        exit: ?*std.atomic.Value(bool),
        allocator_config: AllocatorConfig,
    ) !Self {
        const file = try openPipe(pipe_path);
        errdefer file.close();

        const io_buf = try allocator.alloc(u8, allocator_config.io_buf_len);
        errdefer allocator.free(io_buf);

        const bincode_buf = try allocator.alloc(u8, allocator_config.bincode_buf_len);
        errdefer allocator.free(bincode_buf);

        const fba = std.heap.FixedBufferAllocator.init(bincode_buf);

        const metrics = try GeyserReaderMetrics.init();
        metrics.io_buf_size.set(allocator_config.io_buf_len);
        metrics.bincode_buf_size.set(allocator_config.bincode_buf_len);

        return .{
            .file = file,
            .allocator = allocator,
            .io_buf = io_buf,
            .bincode_buf = bincode_buf,
            .bincode_allocator = fba,
            .metrics = metrics,
            .exit = exit,
        };
    }

    pub fn deinit(self: Self) void {
        self.file.close();
        self.allocator.free(self.io_buf);
        self.allocator.free(self.bincode_buf);
    }

    /// this should be called after each payload so we dont run OOM.
    /// NOTE: bincode.free doesnt work with FBA since alloc and dealloc occurs as (field1 -> fieldN)
    /// so we would need dealloc to happen as (fieldN -> field1) so we have to drop the
    /// entire FBA
    /// TODO(x19): improve this
    pub fn resetMemory(self: *Self) void {
        self.bincode_allocator.reset();
    }

    /// reads a payload from the pipe and returns the total bytes read with the data
    pub fn readPayload(self: *GeyserReader) !struct { u64, VersionedAccountPayload } {
        const len = try self.readType(u64, 8);
        const versioned_payload = try self.readType(VersionedAccountPayload, len);
        self.metrics.total_payloads.inc();
        return .{ 8 + len, versioned_payload };
    }

    /// reads size number of bytes from the pipe and deserializes it into T.
    /// size is required to ensure we read unknown-length data slices into our buf.
    pub fn readType(self: *Self, comptime T: type, expected_n_bytes: u64) !T {
        // make sure we have enough space in the buffer
        if (expected_n_bytes > self.io_buf.len) {
            const new_buf = try self.allocator.alloc(u8, expected_n_bytes);
            self.allocator.free(self.io_buf);
            self.io_buf = new_buf;
            self.metrics.io_buf_size.set(expected_n_bytes);
        }

        var total_bytes_read: u64 = 0;
        while (total_bytes_read < expected_n_bytes) {
            const n_bytes_read = self.file.read(
                self.io_buf[total_bytes_read..expected_n_bytes],
            ) catch |err| {
                if (err == std.posix.ReadError.WouldBlock) {
                    if (self.exit != null and self.exit.?.load(.acquire)) {
                        return error.PipeBlockedWithExitSignaled;
                    } else {
                        // pipe is empty but we dont need to exit, so we try again
                        self.metrics.pipe_empty_count.inc();
                        continue;
                    }
                } else {
                    return err;
                }
            };

            if (n_bytes_read == 0) {
                return error.PipeClosed;
            }
            total_bytes_read += n_bytes_read;
        }
        self.metrics.total_bytes.add(expected_n_bytes);

        while (true) {
            const data = bincode.readFromSlice(
                self.bincode_allocator.allocator(),
                T,
                self.io_buf[0..expected_n_bytes],
                .{},
            ) catch |err| {
                if (err == std.mem.Allocator.Error.OutOfMemory) {
                    // resize the bincode allocator and try again
                    const new_size = self.bincode_buf.len * 2;
                    const new_buf = try self.allocator.alloc(u8, new_size);
                    self.allocator.free(self.bincode_buf);
                    self.bincode_buf = new_buf;
                    self.bincode_allocator = std.heap.FixedBufferAllocator.init(self.bincode_buf);

                    self.metrics.bincode_buf_size.set(new_size);
                    continue;
                } else {
                    return err;
                }
            };

            return data;
        }
    }
};

pub fn openPipe(pipe_path: []const u8) !std.fs.File {
    // setup the pipe
    const rc = c.mkfifo(@ptrCast(pipe_path), c.S_IRWXU);
    if (rc != 0) {
        const err = std.posix.errno(rc);
        switch (err) {
            // if the pipe already exists, thats ok
            .EXIST => {},
            else => {
                std.debug.print("Failed to create pipe: {}\n", .{err});
                return error.FailedToCreatePipe;
            },
        }
    }

    const file = try std.fs.cwd().openFile(pipe_path, .{ .mode = .read_write });

    // set to nonblocking
    // TODO(x19): use F_GETFL | NON_BLOCK
    const rc2 = c.fcntl(@intCast(file.handle), c.F_SETFL, c.O_NONBLOCK);
    if (rc2 == -1) {
        std.log.warn("Failed to set pipe to non-blocking: errno={}\n", .{std.posix.errno(rc2)});
        return error.FailedToSetNonBlocking;
    }

    if (builtin.os.tag == .linux) blk: {
        var buf: [512]u8 = undefined;
        const pipe_size = std.fs.cwd().readFile(PIPE_MAX_SIZE_PATH, &buf) catch {
            std.debug.print("could not read {s}...\n", .{PIPE_MAX_SIZE_PATH});
            break :blk;
        };
        // remove last character if new line
        var end_index = pipe_size.len;
        if (pipe_size[pipe_size.len - 1] == '\n') {
            end_index -= 1;
        }
        const pipe_size_int = std.fmt.parseInt(u64, pipe_size[0..end_index], 10) catch unreachable;

        const rc3 = c.fcntl(@intCast(file.handle), c.F_SETPIPE_SZ, pipe_size_int);
        if (rc3 == -1) {
            std.log.warn("Failed to set pipe size: errno={}\n", .{std.posix.errno(rc3)});
            return error.FailedToSetPipeSize;
        }
    }

    return file;
}

pub const Logger = sig.trace.Logger("geyser");

pub fn streamReader(
    reader: *GeyserReader,
    logger: Logger,
    exit: *std.atomic.Value(bool),
    measure_rate: ?sig.time.Duration,
) !void {
    var bytes_read: usize = 0;
    var timer = sig.time.Timer.start();

    while (!exit.load(.acquire)) {
        const n, const payload = reader.readPayload() catch |err| {
            if (err == error.PipeBlockedWithExitSignaled) {
                break;
            } else {
                logger.err().logf("error reading from pipe: {}", .{err});
                return err;
            }
        };
        bytes_read += n;

        // just drop the data
        std.mem.doNotOptimizeAway(payload);
        reader.resetMemory();

        // mb/sec reading
        if (measure_rate != null and timer.read().asNanos() > measure_rate.?.asNanos()) {
            // print mb/sec
            const elapsed = timer.read().asSecs();
            const bytes_per_sec = bytes_read / elapsed;
            const mb_per_sec = bytes_per_sec / 1_000_000;
            const mb_per_sec_dec = (bytes_per_sec - mb_per_sec * 1_000_000) / (1_000_000 / 100);
            logger.debug().logf("read mb/sec: {}.{}", .{ mb_per_sec, mb_per_sec_dec });

            bytes_read = 0;
            timer.reset();
        }
    }
}

test "streaming accounts" {
    const allocator = std.testing.allocator;
    const batch_len = 2;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    // generate some data
    const accounts = try allocator.alloc(Account, batch_len);
    defer {
        for (accounts) |*account| account.deinit(allocator);
        allocator.free(accounts);
    }
    const pubkeys = try allocator.alloc(Pubkey, batch_len);
    defer allocator.free(pubkeys);

    for (0..batch_len) |i| {
        accounts[i] = try Account.initRandom(allocator, random, 10);
        pubkeys[i] = Pubkey.initRandom(random);
    }

    var exit = std.atomic.Value(bool).init(false);

    // setup writer
    var stream_writer = try GeyserWriter.init(
        allocator,
        sig.TEST_DATA_DIR ++ "stream_test.pipe",
        &exit,
        1 << 18,
    );
    defer stream_writer.deinit();

    try stream_writer.spawnIOLoop();

    // setup reader
    var stream_reader = try GeyserReader.init(
        allocator,
        sig.TEST_DATA_DIR ++ "stream_test.pipe",
        null,
        .{
            .bincode_buf_len = 1 << 18,
            .io_buf_len = 1 << 18,
        },
    );
    defer stream_reader.deinit();

    // write to the pipe
    const v_payload = VersionedAccountPayload{
        .AccountPayloadV1 = .{
            .accounts = accounts,
            .pubkeys = pubkeys,
            .slot = 100,
        },
    };
    try stream_writer.writePayloadToPipe(v_payload);

    // read from the pipe
    _, const data = try stream_reader.readPayload();

    try expectEqualPayloads(v_payload, data);
    stream_reader.resetMemory();

    // write to the pipe twice
    // #1
    try stream_writer.writePayloadToPipe(v_payload);

    const accounts2 = try allocator.alloc(Account, batch_len);
    defer {
        for (accounts2) |*account| account.deinit(allocator);
        allocator.free(accounts2);
    }
    const pubkeys2 = try allocator.alloc(Pubkey, batch_len);
    defer allocator.free(pubkeys2);
    for (0..batch_len) |i| {
        accounts2[i] = try Account.initRandom(allocator, random, 10);
        pubkeys2[i] = Pubkey.initRandom(random);
    }

    // #2
    const v_payload2 = VersionedAccountPayload{
        .AccountPayloadV1 = .{
            .accounts = accounts2,
            .pubkeys = pubkeys2,
            .slot = 100,
        },
    };
    try stream_writer.writePayloadToPipe(v_payload2);

    // first payload matches
    _, const data2 = try stream_reader.readPayload();
    try expectEqualPayloads(v_payload, data2);
    stream_reader.resetMemory();

    // second payload matches
    _, const data3 = try stream_reader.readPayload();
    try expectEqualPayloads(v_payload2, data3);
    stream_reader.resetMemory();
}

test "buf resizing" {
    const allocator = std.testing.allocator;
    const batch_len = 2;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    // generate some data
    const accounts = try allocator.alloc(Account, batch_len);
    defer {
        for (accounts) |*account| account.deinit(allocator);
        allocator.free(accounts);
    }
    const pubkeys = try allocator.alloc(Pubkey, batch_len);
    defer allocator.free(pubkeys);

    for (0..batch_len) |i| {
        accounts[i] = try Account.initRandom(allocator, random, 10);
        pubkeys[i] = Pubkey.initRandom(random);
    }

    // setup writer
    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    // setup writer
    var stream_writer = try GeyserWriter.init(
        allocator,
        sig.TEST_DATA_DIR ++ "stream_test.pipe",
        exit,
        1 << 18,
    );
    defer stream_writer.deinit();

    try stream_writer.spawnIOLoop();

    // setup reader
    var stream_reader = try GeyserReader.init(
        allocator,
        sig.TEST_DATA_DIR ++ "stream_test.pipe",
        null,
        .{
            .bincode_buf_len = 1,
            .io_buf_len = 1,
        },
    );
    defer stream_reader.deinit();

    const v_payload = VersionedAccountPayload{
        .AccountPayloadV1 = .{
            .accounts = accounts,
            .pubkeys = pubkeys,
            .slot = 100,
        },
    };

    // write to the pipe
    try stream_writer.writePayloadToPipe(v_payload);

    // read from the pipe
    _, const data = try stream_reader.readPayload();

    try expectEqualPayloads(v_payload, data);

    stream_reader.resetMemory();

    // check that the buffers have been resized
    try std.testing.expect(stream_reader.io_buf.len > 1);
    try std.testing.expect(stream_reader.bincode_buf.len > 1);
}

// std.testing.expectEqualDeep internally uses "{}" which is ambiguous for types
// with format methods (Pubkey). work around by comparing fields manually.
fn expectEqualPayloads(expected: VersionedAccountPayload, actual: VersionedAccountPayload) !void {
    const exp = expected.AccountPayloadV1;
    const act = actual.AccountPayloadV1;
    try std.testing.expectEqual(exp.slot, act.slot);
    try std.testing.expectEqual(exp.pubkeys.len, act.pubkeys.len);
    try std.testing.expectEqual(exp.accounts.len, act.accounts.len);
    for (exp.pubkeys, act.pubkeys) |e, a| {
        try std.testing.expectEqual(e.data, a.data);
    }
    for (exp.accounts, act.accounts) |e, a| {
        try std.testing.expectEqual(e.lamports, a.lamports);
        try std.testing.expectEqual(e.executable, a.executable);
        try std.testing.expectEqual(e.rent_epoch, a.rent_epoch);
        try std.testing.expect(e.data.eql(a.data));
        try std.testing.expectEqual(e.owner.data, a.owner.data);
    }
}
