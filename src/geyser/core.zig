const std = @import("std");
const sig = @import("../lib.zig");
const bincode = sig.bincode;
const builtin = @import("builtin");

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

const PIPE_MAX_SIZE_PATH = "/proc/sys/fs/pipe-max-size";

pub const AccountPayload = struct {
    // used to know how much to allocate to read the full data slice
    len: u64,
    payload: VersionedAccountPayload,
};

pub const VersionedAccountPayload = union(enum(u8)) {
    AccountPayloadV1: AccountPayloadV1,
};

pub const AccountPayloadV1 = struct {
    slot: Slot,
    pubkeys: []Pubkey,
    // PERF: the data slice per account is the biggest to read,
    // we can probably put it into its own field (data: [][]u8)
    // and read it all in on i/o
    accounts: []Account,
};

pub const GeyserWriter = struct {
    // used to allocate a buf for serialization
    allocator: std.mem.Allocator,
    file: std.fs.File,
    io_buf: []u8,
    exit: ?*std.atomic.Value(bool),

    const Self = @This();

    /// initializes a linux pipe to stream data to
    pub fn init(
        allocator: std.mem.Allocator,
        pipe_path: []const u8,
        exit: ?*std.atomic.Value(bool),
        allocator_config: WriterAllocatorConfig,
    ) !Self {
        const file = try openPipe(pipe_path);
        const io_buf = try allocator.alloc(u8, allocator_config.io_buf_len);
        return .{
            .file = file,
            .allocator = allocator,
            .io_buf = io_buf,
            .exit = exit,
        };
    }

    pub fn deinit(self: Self) void {
        self.file.close();
        self.allocator.free(self.io_buf);
    }

    /// streams a batch of accounts to the pipe using bincode serialization.
    /// returns the number of bytes wrote.
    /// NOTE: this will block if the pipe is not big enough
    pub fn writePayload(
        self: *Self,
        versioned_payload: VersionedAccountPayload,
    ) !u64 {
        const len = bincode.sizeOf(versioned_payload, .{});
        const payload = AccountPayload{ .len = len, .payload = versioned_payload };

        // ensure we have enough space in the buffer
        const size = bincode.sizeOf(payload, .{});
        if (size > self.io_buf.len) {
            const new_buf = try self.allocator.alloc(u8, size);
            self.allocator.free(self.io_buf);
            self.io_buf = new_buf;
        }

        const written_buf = try bincode.writeToSlice(self.io_buf, payload, .{});

        var i: u64 = 0;
        while (i < written_buf.len) {
            const n = self.file.write(written_buf[i..written_buf.len]) catch |err| {
                if (err == std.posix.WriteError.WouldBlock) {
                    if (self.exit != null and self.exit.?.load(.unordered)) {
                        return error.BlockWithExit;
                    } else {
                        // pipe is full but we dont need to exit, so we try again
                        continue;
                    }
                } else {
                    return err;
                }
            };

            if (n == 0) {
                return error.PipeClosed;
            }
            i += n;
        }

        return written_buf.len;
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

    pub fn init(
        allocator: std.mem.Allocator,
        pipe_path: []const u8,
        exit: ?*std.atomic.Value(bool),
        allocator_config: ReaderAllocatorConfig,
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
        const versioned_payload = try self.readType(VersionedAccountPayload, len);
        return .{ 8 + len, versioned_payload };
    }

    /// reads size number of bytes from the pipe and deserializes it into T.
    /// size is required to ensure we read unknown-length data slices into our buf.
    pub fn readType(self: *Self, comptime T: type, size: u64) !T {
        // make sure we have enough space in the buffer
        if (size > self.io_buf.len) {
            const new_buf = try self.allocator.alloc(u8, size);
            self.allocator.free(self.io_buf);
            self.io_buf = new_buf;
        }

        var i: u64 = 0;
        while (i < size) {
            const n = self.file.read(self.io_buf[i..size]) catch |err| {
                if (err == std.posix.ReadError.WouldBlock) {
                    if (self.exit != null and self.exit.?.load(.unordered)) {
                        return error.BlockWithExit;
                    } else {
                        // pipe is empty but we dont need to exit, so we try again
                        continue;
                    }
                } else {
                    return err;
                }
            };

            if (n == 0) {
                return error.PipeClosed;
            }
            i += n;
        }

        while (true) {
            const data = bincode.readFromSlice(self.bincode_allocator.allocator(), T, self.io_buf[0..size], .{}) catch |err| {
                if (err == std.mem.Allocator.Error.OutOfMemory) {
                    // resize the bincode allocator and try again
                    const new_size = self.bincode_buf.len * 2;
                    const new_buf = try self.allocator.alloc(u8, new_size);
                    self.allocator.free(self.bincode_buf);
                    self.bincode_buf = new_buf;
                    self.bincode_allocator = std.heap.FixedBufferAllocator.init(self.bincode_buf);
                    continue;
                } else {
                    return err;
                }
            };

            // return the data
            return data;
        }
    }
};

pub const WriterAllocatorConfig = struct {
    // - bincode.writeToSlice -> io_buf - io.write -> pipe
    io_buf_len: u64 = 1 << 19, // 512kb
};

pub const ReaderAllocatorConfig = struct {
    // pipe -> io_buf
    io_buf_len: u64 = 1 << 18, // 256kb
    // io_buf -> bincode_deser_buf -> Payload struct
    bincode_buf_len: u64 = 1 << 30, // 1gb
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

    // setup writer
    var stream_writer = try GeyserWriter.init(
        allocator,
        "test_data/stream_test.pipe",
        null,
        .{
            .io_buf_len = 1 << 18,
        },
    );
    defer stream_writer.deinit();

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
    _ = try stream_writer.writePayload(v_payload);

    // read from the pipe
    _, const data = try stream_reader.readPayload();

    try std.testing.expectEqualDeep(v_payload, data);
    stream_reader.resetMemory();

    // write to the pipe twice
    // #1
    _ = try stream_writer.writePayload(v_payload);

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
    _ = try stream_writer.writePayload(v_payload2);

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
    var stream_writer = try GeyserWriter.init(
        allocator,
        "test_data/stream_test.pipe",
        null,
        .{ .io_buf_len = 1 },
    );
    defer stream_writer.deinit();

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
    _ = try stream_writer.writePayload(v_payload);

    // read from the pipe
    _, const data = try stream_reader.readPayload();

    try std.testing.expectEqualDeep(v_payload, data);
    stream_reader.resetMemory();

    try std.testing.expect(stream_writer.io_buf.len > 1);
    try std.testing.expect(stream_reader.io_buf.len > 1);
    try std.testing.expect(stream_reader.bincode_buf.len > 1);
}

pub const BenchmarkAccountStream = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 1;

    pub const BenchmarkArgs = struct {
        name: []const u8 = "",
        n_accounts: u64,
        data_len: u64,
        slots: u64,
    };

    pub const args = [_]BenchmarkArgs{
        .{
            .name = "accounts_1k_data_len_100",
            .n_accounts = 1_000,
            .data_len = 100,
            .slots = 100,
        },
        .{
            .name = "accounts_1k_data_len_200",
            .n_accounts = 1_000,
            .data_len = 200,
            .slots = 100,
        },
        .{
            .name = "accounts_1k_data_len_200",
            .n_accounts = 1_000,
            .data_len = 400,
            .slots = 100,
        },
        .{
            .name = "accounts_1k_data_len_1k",
            .n_accounts = 1_000,
            .data_len = 1_000,
            .slots = 100,
        },
        .{
            .name = "accounts_10k_data_len_100",
            .n_accounts = 10_000,
            .data_len = 100,
            .slots = 100,
        },
    };

    pub fn benchmarkAccountStreaming(bench_args: BenchmarkArgs) !u64 {
        const allocator = std.heap.page_allocator;

        var random = std.rand.DefaultPrng.init(19);
        const rng = random.random();

        // generate some data
        const accounts = try allocator.alloc(Account, bench_args.n_accounts);
        defer {
            for (accounts) |*account| {
                account.deinit(allocator);
            }
            allocator.free(accounts);
        }
        const pubkeys = try allocator.alloc(Pubkey, bench_args.n_accounts);
        defer allocator.free(pubkeys);

        for (0..bench_args.n_accounts) |i| {
            accounts[i] = try Account.random(allocator, rng, bench_args.data_len);
            pubkeys[i] = Pubkey.random(rng);
        }

        // setup writer
        var stream_writer = try GeyserWriter.init(allocator, "test_data/bench_test.pipe", null, .{});
        defer stream_writer.deinit();

        // setup reader
        const stream_reader = try allocator.create(GeyserReader);
        stream_reader.* = try GeyserReader.init(allocator, "test_data/bench_test.pipe", null, .{});
        defer {
            stream_reader.deinit();
            allocator.destroy(stream_reader);
        }

        const read_handle = try std.Thread.spawn(.{}, readLoop, .{ stream_reader, bench_args.slots });

        var start = try sig.time.Timer.start();
        for (0..bench_args.slots) |slot| {
            _ = try stream_writer.writePayload(.{
                .AccountPayloadV1 = .{
                    .accounts = accounts,
                    .pubkeys = pubkeys,
                    .slot = slot,
                },
            });
        }
        // when reader is done reading, we can stop the timer
        read_handle.join();
        const end = start.read().asNanos();

        return end;
    }
};

pub fn readLoop(stream_reader: *GeyserReader, n_payloads: usize) !void {
    var count: usize = 0;
    while (count < n_payloads) {
        _, const payload = try stream_reader.readPayload();

        std.mem.doNotOptimizeAway(payload);
        stream_reader.resetMemory();

        count += 1;
    }
}
