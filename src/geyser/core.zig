const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../lib.zig");
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
const AccountWithoutData = sig.core.account.AccountWithoutData;
const RecycleFBA = sig.utils.allocators.RecycleFBA;

const PIPE_MAX_SIZE_PATH = "/proc/sys/fs/pipe-max-size";

pub const AccountPayload = struct {
    // used to know how much to allocate to read the full data slice
    len: u64,
    payload: VersionedAccountPayload,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.payload.deinit(allocator);
    }
};

pub const VersionedAccountPayload = union(enum(u8)) {
    AccountPayloadV1: AccountPayloadV1,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .AccountPayloadV1 => self.AccountPayloadV1.deinit(allocator),
        }
    }
};

pub const AccountPayloadV1 = struct {
    slot: Slot,
    pubkeys: []Pubkey,
    // PERF: the data slice per account is the biggest to read,
    // we can probably put it into its own field (data: [][]u8)
    // and read it all in on i/o
    accounts: []Account,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (self.accounts) |*account| {
            account.deinit(allocator);
        }
        allocator.free(self.accounts);
        allocator.free(self.pubkeys);
    }
};

pub const GeyserWriter = struct {
    // used to allocate a buf for serialization
    allocator: std.mem.Allocator,
    // allocator to free memory from
    io_free_fba: RecycleFBA,
    // pipe to write to
    file: std.fs.File,
    // channel which data is streamed into and then written to the pipe
    io_channel: *sig.sync.Channel([]u8),
    exit: *std.atomic.Value(bool),

    // set when the writer thread is running
    io_handle: ?std.Thread = null,

    const Self = @This();

    /// initializes a linux pipe to stream data to
    pub fn init(
        allocator: std.mem.Allocator,
        pipe_path: []const u8,
        exit: *std.atomic.Value(bool),
        // used to allocate/free memory for the io channel
        io_fba_bytes: u64,
    ) !Self {
        const file = try openPipe(pipe_path);
        const io_channel = sig.sync.Channel([]u8).init(allocator, 1_000);
        const io_free_fba = try RecycleFBA.init(allocator, io_fba_bytes);

        return .{
            .allocator = allocator,
            .io_free_fba = io_free_fba,
            .io_channel = io_channel,
            .file = file,
            .exit = exit,
        };
    }

    pub fn deinit(self: *Self) void {
        self.exit.store(true, .unordered);
        if (self.io_handle) |*handle| handle.join();

        self.file.close();
        self.io_channel.close();
        self.io_channel.deinit();
        self.io_free_fba.deinit();
    }

    pub fn spawnIOLoop(self: *Self) !void {
        const handle = try std.Thread.spawn(.{}, IOStreamLoop, .{self});
        self.io_handle = handle;
    }

    pub fn IOStreamLoop(self: *Self) !void {
        var payloads = std.ArrayList([]u8).init(self.allocator);
        defer payloads.deinit();

        while (!self.exit.load(.unordered)) {
            try self.io_channel.tryDrainRecycle(&payloads);

            for (payloads.items) |payload| {
                _ = try self.writeToPipe(payload);

                self.io_free_fba.mux.lock();
                self.io_free_fba.allocator().free(payload);
                self.io_free_fba.mux.unlock();
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
        self.io_free_fba.mux.lock();
        const buf = blk: while (true) {
            const buf = self.io_free_fba.allocator().alloc(u8, total_len) catch {
                // no memory available rn - unlock and wait
                self.io_free_fba.mux.unlock();
                std.time.sleep(std.time.ns_per_ms);
                self.io_free_fba.mux.lock();
                continue;
            };
            break :blk buf;
        };
        self.io_free_fba.mux.unlock();

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
    ) !u64 {
        var pipe_full_count: usize = 0;

        var n_bytes_written_total: u64 = 0;
        while (n_bytes_written_total < buf.len) {
            const n_bytes_written = self.file.write(buf[n_bytes_written_total..]) catch |err| {
                if (err == std.posix.WriteError.WouldBlock) {
                    if (self.exit.load(.unordered)) {
                        return error.PipeBlockedWithExitSignaled;
                    } else {
                        // pipe is full but we dont need to exit, so we try again
                        // TODO(metrics): prometheus metrics on pipe_full_count
                        pipe_full_count += 1;
                        continue;
                    }
                } else {
                    return err;
                }
            };

            if (n_bytes_written == 0) {
                return error.PipeClosed;
            }
            // TODO(metrics): prometheus metrics on total_bytes_written
            n_bytes_written_total += n_bytes_written;
            pipe_full_count = 0;
        }

        std.debug.assert(n_bytes_written_total == buf.len);
        return n_bytes_written_total;
    }
};

pub const GeyserReader = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    // read from pipe into this
    io_buf: []u8,
    // use this for bincode allocations (and is the underlying memory for fb_allocator)
    bincode_buf: []u8,
    // NOTE: not thread-safe
    bincode_allocator: std.heap.FixedBufferAllocator,
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

        return .{
            .file = file,
            .allocator = allocator,
            .io_buf = io_buf,
            .bincode_buf = bincode_buf,
            .bincode_allocator = fba,
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
    pub fn readPayload(self: *Self) !struct { u64, VersionedAccountPayload } {
        const len = try self.readType(u64, 8);
        // std.debug.print("reading {} bytes from pipe\n", .{len});
        const versioned_payload = try self.readType(VersionedAccountPayload, len);
        return .{ 8 + len, versioned_payload };
    }

    /// reads size number of bytes from the pipe and deserializes it into T.
    /// size is required to ensure we read unknown-length data slices into our buf.
    pub fn readType(self: *Self, comptime T: type, expected_n_bytes: u64) !T {
        // make sure we have enough space in the buffer
        if (expected_n_bytes > self.io_buf.len) {
            // TODO(metrics): prometheus metrics on io_buf size
            const new_buf = try self.allocator.alloc(u8, expected_n_bytes);
            self.allocator.free(self.io_buf);
            self.io_buf = new_buf;
        }

        var total_bytes_read: u64 = 0;
        while (total_bytes_read < expected_n_bytes) {
            const n_bytes_read = self.file.read(self.io_buf[total_bytes_read..expected_n_bytes]) catch |err| {
                if (err == std.posix.ReadError.WouldBlock) {
                    if (self.exit != null and self.exit.?.load(.unordered)) {
                        return error.BlockWithExit;
                    } else {
                        // pipe is empty but we dont need to exit, so we try again
                        // TODO(metrics): prometheus metrics on empty loop count
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
            // TODO(metrics): prometheus metrics on total_bytes_read + expected_n_bytes
        }

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
                    // TODO(metrics): prometheus metrics on bincode_buf resize
                    const new_buf = try self.allocator.alloc(u8, new_size);
                    self.allocator.free(self.bincode_buf);
                    self.bincode_buf = new_buf;
                    self.bincode_allocator = std.heap.FixedBufferAllocator.init(self.bincode_buf);
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

test "streaming accounts" {
    const allocator = std.testing.allocator;
    const batch_len = 2;

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    // generate some data
    const accounts = try allocator.alloc(Account, batch_len);
    defer {
        for (accounts) |*account| account.deinit(allocator);
        allocator.free(accounts);
    }
    const pubkeys = try allocator.alloc(Pubkey, batch_len);
    defer allocator.free(pubkeys);

    for (0..batch_len) |i| {
        accounts[i] = try Account.random(allocator, rng, 10);
        pubkeys[i] = Pubkey.random(rng);
    }

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    // setup writer
    var stream_writer = try GeyserWriter.init(
        allocator,
        "test_data/stream_test.pipe",
        exit,
        1 << 18,
    );
    defer stream_writer.deinit();

    try stream_writer.spawnIOLoop();

    // setup reader
    var stream_reader = try GeyserReader.init(
        allocator,
        "test_data/stream_test.pipe",
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

    try std.testing.expectEqualDeep(v_payload, data);
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
        accounts2[i] = try Account.random(allocator, rng, 10);
        pubkeys2[i] = Pubkey.random(rng);
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
    try std.testing.expectEqualDeep(v_payload, data2);
    stream_reader.resetMemory();

    // second payload matches
    _, const data3 = try stream_reader.readPayload();
    try std.testing.expectEqualDeep(v_payload2, data3);
    stream_reader.resetMemory();
}

test "buf resizing" {
    const allocator = std.testing.allocator;
    const batch_len = 2;

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    // generate some data
    const accounts = try allocator.alloc(Account, batch_len);
    defer {
        for (accounts) |*account| account.deinit(allocator);
        allocator.free(accounts);
    }
    const pubkeys = try allocator.alloc(Pubkey, batch_len);
    defer allocator.free(pubkeys);

    for (0..batch_len) |i| {
        accounts[i] = try Account.random(allocator, rng, 10);
        pubkeys[i] = Pubkey.random(rng);
    }

    // setup writer
    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    // setup writer
    var stream_writer = try GeyserWriter.init(
        allocator,
        "test_data/stream_test.pipe",
        exit,
        1 << 18,
    );
    defer stream_writer.deinit();

    try stream_writer.spawnIOLoop();

    // setup reader
    var stream_reader = try GeyserReader.init(
        allocator,
        "test_data/stream_test.pipe",
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

    try std.testing.expectEqualDeep(v_payload, data);
    stream_reader.resetMemory();

    // check that the buffers have been resized
    try std.testing.expect(stream_reader.io_buf.len > 1);
    try std.testing.expect(stream_reader.bincode_buf.len > 1);
}
